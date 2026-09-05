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
    private var handler: ((KeyServiceRequest) -> KeyServiceResponse)?
    private var restartPending = false

    init(
        hasConfiguration: @escaping () throws -> Bool,
        makeHandler: @escaping () throws -> (KeyServiceRequest) -> KeyServiceResponse,
        initialize: @escaping (String) throws -> String,
        updateVaultDirectory: ((String) throws -> Void)? = nil
    ) {
        self.hasConfiguration = hasConfiguration
        self.makeHandler = makeHandler
        self.initialize = initialize
        self.updateVaultDirectory = updateVaultDirectory
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
            }
        )
    }

    public func handle(_ request: KeyServiceRequest) -> KeyServiceResponse {
        if case let .initializeVault(path) = request {
            return queue.sync(flags: .barrier) {
                respond {
                    guard !restartPending else { return restarting() }
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

    private func respond(_ operation: () throws -> KeyServiceResponse) -> KeyServiceResponse {
        do { return try operation() }
        catch let error as AppError { return .failure(error) }
        catch { return .failure(error.localizedDescription) }
    }

    private func restarting() -> KeyServiceResponse {
        .failure("The vault configuration changed and Key Agent is restarting. Run `key lock`, then `key status`; do not initialize another vault.")
    }
}
