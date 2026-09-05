import Foundation

/// Lazily composes the selected runtime. Init runs behind an exclusive barrier
/// before configuration exists, without bootstrapping a legacy vault first.
public final class KeyServiceHost {
    private let queue = DispatchQueue(label: "work.tvr.key.service-host", attributes: .concurrent)
    private let compositionLock = NSLock()
    private let hasConfiguration: () throws -> Bool
    private let makeHandler: () throws -> (KeyServiceRequest) -> KeyServiceResponse
    private let initialize: (String) throws -> String
    private var handler: ((KeyServiceRequest) -> KeyServiceResponse)?
    private var restartPending = false

    init(
        hasConfiguration: @escaping () throws -> Bool,
        makeHandler: @escaping () throws -> (KeyServiceRequest) -> KeyServiceResponse,
        initialize: @escaping (String) throws -> String
    ) {
        self.hasConfiguration = hasConfiguration
        self.makeHandler = makeHandler
        self.initialize = initialize
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
            initialize: initialization.initialize
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
        return queue.sync {
            respond {
                if restartPending {
                    return request == .lock ? .success() : restarting()
                }
                let resolved = try compositionLock.withLock {
                    if let handler { return handler }
                    if try !hasConfiguration() {
                        // Opening the app polls this endpoint. It must not
                        // accidentally select v2 before the first `key init`.
                        if request == .status {
                            return { _ in .success(helperStatus: .locked(inactivityTimeoutSeconds: 15 * 60)) }
                        }
                        if request == .lock { return { _ in .success() } }
                        if request == .vaultStatus {
                            return { _ in .failure("No vault is configured. Run `key init [directory]` for a new vault, or use device enrollment for an existing vault.", code: .operationRefused) }
                        }
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
        .failure("The new vault was selected and Key Agent is restarting. Run `key lock`, then `key status`; do not initialize another vault.")
    }
}
