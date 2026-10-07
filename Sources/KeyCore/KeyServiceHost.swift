import Foundation

/// Lazily composes the selected runtime. Init runs behind an exclusive barrier
/// before configuration exists, without bootstrapping a legacy vault first.
public final class KeyServiceHost {
    private let queue = DispatchQueue(label: "work.tvr.key.service-host", attributes: .concurrent)
    private let compositionLock = NSLock()
    private let hasConfiguration: () throws -> Bool
    private let makeHandler: () throws -> (KeyServiceRequest) -> KeyServiceResponse
    private let initialize: (String) throws -> String
    private let updateVaultDirectory: ((String) throws -> Void)?
    private let configuredDirectory: (() throws -> URL)?
    private let enroll: ((KeyShareRequest, String) throws -> KeyServiceResponse)?
    private let recover: ((KeyRecoveryRequest, KeyRecoveryRequestScope) throws -> KeyServiceResponse)?
    private let recoveryLock = NSLock()
    private let recoveryAuthentication = V3DeviceWrappedVaultKeySessionStore()
    private var recoveryRequest: KeyRecoveryRequestScope?
    private var activeRecovery: UUID?
    private var handler: ((KeyServiceRequest) -> KeyServiceResponse)?
    private var restartPending = false
    // Process-local uncertainty guard, not durable ownership. Live composition
    // must also admit setup against saved ownership across helper restarts.
    private var recoveryPending = false

    init(
        hasConfiguration: @escaping () throws -> Bool,
        makeHandler: @escaping () throws -> (KeyServiceRequest) -> KeyServiceResponse,
        initialize: @escaping (String) throws -> String,
        updateVaultDirectory: ((String) throws -> Void)? = nil,
        configuredDirectory: (() throws -> URL)? = nil,
        enroll: ((KeyShareRequest, String) throws -> KeyServiceResponse)? = nil,
        recover: ((KeyRecoveryRequest, KeyRecoveryRequestScope) throws -> KeyServiceResponse)? = nil
    ) {
        self.hasConfiguration = hasConfiguration
        self.makeHandler = makeHandler
        self.initialize = initialize
        self.updateVaultDirectory = updateVaultDirectory
        self.configuredDirectory = configuredDirectory
        self.enroll = enroll
        self.recover = recover
    }

    public static func live(
        keyStore: VaultKeyStoring,
        configStore: KeyConfigStore,
        runtimeConfiguration: RuntimeConfiguration
    ) -> KeyServiceHost {
        let initialization = V3VaultInitializationService.live(
            configStore: configStore,
            runtimeConfiguration: runtimeConfiguration
        )
        let enrollment = V3UnconfiguredEnrollmentService.live(
            configStore: configStore, keyStore: keyStore,
            runtimeConfiguration: runtimeConfiguration
        )
        return KeyServiceHost(
            hasConfiguration: { try configStore.hasConfiguration() },
            makeHandler: {
                let handler = try KeyServiceHandler.live(
                    keyStore: keyStore,
                    keyConfiguration: configStore.load(),
                    configStore: configStore,
                    runtimeConfiguration: runtimeConfiguration
                )
                return handler.handle
            },
            initialize: initialization.initialize,
            updateVaultDirectory: { path in
                _ = try configStore.setValue(path, for: .vaultDir)
                keyStore.invalidate()
            },
            configuredDirectory: { try configStore.load().vaultDirectoryURL },
            enroll: { request, path in try enrollment.handle(request, path: path) }
        )
    }

    public func handle(
        _ request: KeyServiceRequest, connection: KeyServiceConnection? = nil
    ) -> KeyServiceResponse {
        if request == .lock, cancelRecoveryRequests() {
            // Active recovery was admitted only with no configured handler.
            // Cancel before the exclusive queue, even if native UI has not
            // drained. Its scope blocks all later authority transitions.
            return .success()
        }
        if case let .recovery(action) = request {
            return handleRecovery(action, connection: connection)
        }
        if case let .shareInDirectory(action, path) = request {
            return queue.sync(flags: .barrier) {
                respond {
                    guard !restartPending else { return restarting() }
                    try requireNoRecoveryPending()
                    guard action.supportsDirectorySelection,
                          path.hasPrefix("/"), !path.utf8.contains(0)
                    else {
                        throw AppError.operationRefused("Invalid directory-scoped enrollment request.")
                    }
                    if try hasConfiguration() {
                        guard let configuredDirectory,
                              try configuredDirectory().standardizedFileURL.path
                                == URL(fileURLWithPath: path, isDirectory: true).standardizedFileURL.path
                        else {
                            throw AppError.operationRefused("This Mac already has a configured vault. --vault-dir cannot switch it to another folder.")
                        }
                        let resolved = try compositionLock.withLock {
                            if let handler { return handler }
                            let composed = try makeHandler()
                            handler = composed
                            return composed
                        }
                        return resolved(.share(action))
                    }
                    guard handler == nil, let enroll else {
                        throw AppError.operationRefused("Unconfigured enrollment is unavailable while a configured runtime is active. Run `key lock`, then retry.")
                    }
                    let response = try enroll(action, path)
                    if case .accept = action, response.exitCode == EXIT_SUCCESS {
                        restartPending = true
                    }
                    return response
                }
            }
        }
        if case let .initializeVault(path) = request {
            return queue.sync(flags: .barrier) {
                respond {
                    guard !restartPending else { return restarting() }
                    try requireNoRecoveryPending()
                    guard try !hasConfiguration(), handler == nil else {
                        throw AppError.operationRefused("Key already has a configuration or an active runtime. Init never replaces a vault. Run `key status`; use migration for v2 or enrollment for an existing v3 vault.")
                    }
                    let message = try initialize(path)
                    restartPending = true
                    return .success(message)
                }
            }
        }
        let flags: DispatchWorkItemFlags
        if case .setVaultDirectory = request {
            flags = .barrier
        } else {
            flags = []
        }
        return queue.sync(flags: flags) {
            respond {
                if restartPending {
                    return request == .lock ? .success() : restarting()
                }
                if case .setVaultDirectory = request { try requireNoRecoveryPending() }
                let resolved = try compositionLock.withLock {
                    if let handler { return handler }
                    if request == .lock { return { _ in .success() } }
                    if try !hasConfiguration() {
                        // Opening the app polls this endpoint. It must not
                        // accidentally select v2 before the first `key init`.
                        if request == .status {
                            return { _ in .success(helperStatus: .locked(inactivityTimeoutSeconds: 15 * 60)) }
                        }
                        return { _ in .failure(KeyConfigStore.notInitializedError) }
                    }
                    // A moved vault cannot compose its old runtime. Correct
                    // only an existing selection, without opening the old root.
                    if case let .setVaultDirectory(path) = request,
                       let updateVaultDirectory {
                        try updateVaultDirectory(path)
                        restartPending = true
                        return { _ in .success() }
                    }
                    let composed = try makeHandler()
                    handler = composed
                    return composed
                }
                return resolved(request)
            }
        }
    }

    private func handleRecovery(
        _ request: KeyRecoveryRequest, connection: KeyServiceConnection?
    ) -> KeyServiceResponse {
        // No live capability is installed yet. Stable and ordinary Preview
        // refuse without composing a runtime, reading a card or touching files.
        guard let recover else {
            return .failure("Recovery is not enabled in this product build.")
        }
        let pending = recoveryLock.withLock { () -> KeyRecoveryRequestScope? in
            guard recoveryRequest == nil else { return nil }
            let scope = KeyRecoveryRequestScope(
                authentication: recoveryAuthentication,
                deadline: .now() + .seconds(KeyRecoveryRequest.maximumDurationSeconds))
            recoveryRequest = scope
            return scope
        }
        guard let scope = pending else {
            return .failure("Another recovery request is running or waiting. No new recovery operation was started; wait for it to finish before explicitly trying again.")
        }
        connection?.register(scope)
        defer {
            connection?.remove(scope)
            recoveryLock.withLock { recoveryRequest = nil }
            scope.cancellation.cancel()
        }
        return queue.sync(flags: .barrier) {
            respond {
                try scope.requireCurrent()
                guard !restartPending else { return restarting() }
                try request.validate()
                guard handler == nil else {
                    throw AppError.operationRefused("Recovery cannot run alongside a configured runtime. Run `key lock`, then explicitly resume the saved attempt after Key Agent restarts.")
                }
                if request.isInitialRestore {
                    try requireNoRecoveryPending()
                    guard try !hasConfiguration() else {
                        throw AppError.operationRefused("Restore requires an unconfigured Mac and never replaces its selected vault.")
                    }
                }
                try recoveryLock.withLock {
                    try scope.requireCurrent()
                    activeRecovery = scope.id
                }
                defer {
                    recoveryLock.withLock { activeRecovery = nil }
                    // Selection may have committed before a failed/lost reply.
                    // Never compose a runtime or start init after uncertainty.
                    do { if try hasConfiguration() { restartPending = true } }
                    catch { restartPending = true }
                }
                recoveryPending = true
                let response = try recover(request, scope)
                try scope.requireCurrent()
                if response.exitCode == EXIT_SUCCESS, try !hasConfiguration() {
                    throw AppError.operationRefused("Recovery returned without selecting a vault. Leave the attempt intact and explicitly resume; do not start another restore.")
                }
                try scope.requireCurrent()
                return response
            }
        }
    }

    /// Out-of-band cancellation must not wait for the exclusive host queue.
    /// Cancels the queued scope too; a stale request cannot capture fresh consent
    /// merely because its turn at the barrier begins after lock.
    private func cancelRecoveryRequests() -> Bool {
        let state = recoveryLock.withLock {
            recoveryAuthentication.invalidate()
            return (activeRecovery != nil, recoveryRequest)
        }
        state.1?.cancellation.cancel()
        return state.0
    }

    private func requireNoRecoveryPending() throws {
        guard !recoveryPending else {
            throw AppError.operationRefused("A recovery request may have left a saved attempt. Leave its records and folders intact and explicitly resume or inspect it; do not initialize, enroll or change vault configuration.")
        }
    }

    private func respond(_ operation: () throws -> KeyServiceResponse) -> KeyServiceResponse {
        do { return try operation() }
        catch let error as AppError { return .failure(error) }
        catch { return .failure(error.localizedDescription) }
    }

    private func restarting() -> KeyServiceResponse {
        .failure("The vault configuration changed and Key Agent is restarting. Run `key lock`, then `key status`; do not initialize another vault.")
    }
}
