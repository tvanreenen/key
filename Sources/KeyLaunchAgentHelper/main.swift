import AppKit
import Foundation
import KeyCore
import OSLog

private final class KeyAgentDelegate: NSObject, NSXPCListenerDelegate {
    private let handler: KeyServiceHost
    private let lifecycleController: HelperLifecycleController
    private let role: KeyXPCClientRole
    private let logger: Logger

    init(
        handler: KeyServiceHost,
        lifecycleController: HelperLifecycleController,
        role: KeyXPCClientRole,
        logger: Logger
    ) {
        self.handler = handler
        self.lifecycleController = lifecycleController
        self.role = role
        self.logger = logger
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        let connection = KeyServiceConnection()
        newConnection.interruptionHandler = { connection.invalidate() }
        newConnection.invalidationHandler = { connection.invalidate() }
        let exportedObject = KeyAgentService(
            handler: handler,
            lifecycleController: lifecycleController,
            role: role,
            logger: logger,
            connection: connection,
            xpc: newConnection
        )
        newConnection.exportedInterface = NSXPCInterface(with: KeyXPCProtocol.self)
        newConnection.exportedObject = exportedObject
        if role == .fullCLI {
            newConnection.remoteObjectInterface = NSXPCInterface(with: KeyXPCRecoveryProgressProtocol.self)
        }
        newConnection.resume()
        logger.notice("Accepted authenticated XPC client with role \(self.role.rawValue, privacy: .public)")
        return true
    }
}

private final class KeyAgentService: NSObject, KeyXPCProtocol, @unchecked Sendable {
    private let handler: KeyServiceHost
    private let lifecycleController: HelperLifecycleController
    private let role: KeyXPCClientRole
    private let logger: Logger
    private let decoder = JSONDecoder()
    private let encoder = JSONEncoder()
    private let stateLock = NSLock()
    private let connection: KeyServiceConnection
    private var shutdownAuthorized = false
    private var recoveryProgressClaimed = false
    private weak var xpc: NSXPCConnection?

    init(
        handler: KeyServiceHost,
        lifecycleController: HelperLifecycleController,
        role: KeyXPCClientRole,
        logger: Logger,
        connection: KeyServiceConnection,
        xpc: NSXPCConnection
    ) {
        self.handler = handler
        self.lifecycleController = lifecycleController
        self.role = role
        self.logger = logger
        self.connection = connection
        self.xpc = xpc
    }

    func sendRequest(_ requestData: NSData, withReply reply: @escaping (NSData?, NSString?) -> Void) {
        let request: KeyServiceRequest
        do {
            request = try decoder.decode(KeyServiceRequest.self, from: requestData as Data)
        } catch {
            reply(nil, "Failed to decode request." as NSString)
            return
        }

        guard role.authorizes(request) else {
            logger.error(
                "Denied XPC request for client role \(self.role.rawValue, privacy: .public)"
            )
            do {
                let response = KeyServiceResponse.failure("This client is not authorized to perform that operation.")
                reply(try encoder.encode(response) as NSData, nil)
            } catch {
                reply(nil, "Failed to encode authorization response." as NSString)
            }
            return
        }

        guard !request.supportsRecoveryProgress else {
            reply(nil, "Recovery requires a matching Key CLI and helper with staged progress support. No request was dispatched." as NSString)
            return
        }

        let extendsIdleDeadline = request != .status
        lifecycleController.beginRequest(extendsIdleDeadline: extendsIdleDeadline)
        defer {
            lifecycleController.endRequest(extendsIdleDeadline: extendsIdleDeadline)
        }

        do {
            let response = handler.handle(request, connection: connection)
            let responseData = try encoder.encode(response)
            if request.requiresHelperShutdownAfterSuccess,
               response.exitCode == EXIT_SUCCESS {
                markShutdownAuthorized()
            }
            reply(responseData as NSData, nil)
        } catch {
            reply(nil, "Failed to encode response." as NSString)
        }
    }

    func sendRecoveryRequest(_ requestData: NSData, operationID: NSUUID,
                             withReply reply: @escaping @Sendable (NSData?, NSString?) -> Void) {
        guard requestData.length <= 65_536,
              let request = try? JSONDecoder().decode(KeyServiceRequest.self, from: requestData as Data),
              role == .fullCLI, role.authorizes(request), request.supportsRecoveryProgress,
              stateLock.withLock({
                  guard !recoveryProgressClaimed else { return false }
                  recoveryProgressClaimed = true
                  return true
              }) else {
            reply(nil, "Recovery progress request refused. No automatic retry was made." as NSString)
            return
        }
        let prompt = KeyRecoveryTouchPrompt { [connection] in connection.invalidate() }
        let progress = KeyRecoveryProgress(operationID: operationID as UUID) { [weak self] event in
            guard let self else { return }
            prompt.receive(event.stage)
            guard let data = try? JSONEncoder().encode(event), data.count <= 1_024,
                  let remote = self.xpc?.remoteObjectProxyWithErrorHandler({ [connection] _ in
                      connection.invalidate()
                  }) as? KeyXPCRecoveryProgressProtocol else {
                self.connection.invalidate()
                return
            }
            remote.recoveryProgress(data as NSData)
        }
        lifecycleController.beginRequest(extendsIdleDeadline: true)
        // Do not block the XPC delivery queue during native approval; connection
        // invalidation must still be able to cancel the scoped operation.
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            defer {
                progress.close()
                prompt.finish()
                lifecycleController.endRequest(extendsIdleDeadline: true)
            }
            let response = handler.handle(request, connection: connection, progress: progress)
            guard let data = try? JSONEncoder().encode(response) else {
                reply(nil, "Failed to encode recovery response." as NSString)
                return
            }
            if request.requiresHelperShutdownAfterSuccess, response.exitCode == EXIT_SUCCESS {
                markShutdownAuthorized()
            }
            progress.close()
            prompt.finish()
            reply(data as NSData, nil)
        }
    }

    func completeShutdown() {
        stateLock.lock()
        let shouldShutdown = shutdownAuthorized
        shutdownAuthorized = false
        stateLock.unlock()

        if shouldShutdown {
            lifecycleController.shutdown()
        } else {
            logger.error("Denied helper shutdown because this connection has not completed a shutdown-authorizing request.")
        }
    }

    private func markShutdownAuthorized() {
        stateLock.lock()
        shutdownAuthorized = true
        stateLock.unlock()
    }
}

@MainActor private func run() -> Never {
    let configuration = RuntimeConfiguration.live()
    let logger = Logger(subsystem: configuration.helperBundleIdentifier, category: "XPC")

    let configStore = KeyConfigStore(
        productIdentity: configuration.productIdentity
    )
    let sessionKeyStore = SessionVaultKeyStore(
        underlying: VaultKeyStore(configuration: configuration)
    )
    let lifecycleController = HelperLifecycleController(idleTimeout: 15 * 60) {
        sessionKeyStore.invalidate()
        exit(EXIT_SUCCESS)
    }
    let handler = KeyServiceHost.live(
        keyStore: sessionKeyStore,
        configStore: configStore,
        runtimeConfiguration: configuration
    )
    #if DEBUG
    let signingPolicy = KeyXPCCodeSigningPolicy.development
    logger.warning("Key Agent is using the explicit development XPC signing policy.")
    #else
    let signingPolicy = KeyXPCCodeSigningPolicy.production
    #endif

    let cliDelegate = KeyAgentDelegate(
        handler: handler,
        lifecycleController: lifecycleController,
        role: .fullCLI,
        logger: logger
    )
    let utilityDelegate = KeyAgentDelegate(
        handler: handler,
        lifecycleController: lifecycleController,
        role: .utilityStatus,
        logger: logger
    )
    let cliListener = NSXPCListener(machServiceName: configuration.helperMachServiceName)
    let utilityListener = NSXPCListener(machServiceName: configuration.helperStatusMachServiceName)

    cliListener.setConnectionCodeSigningRequirement(
        KeyXPCSecurityPolicy.codeSigningRequirement(
            for: .fullCLI,
            productIdentity: configuration.productIdentity,
            policy: signingPolicy
        )
    )
    utilityListener.setConnectionCodeSigningRequirement(
        KeyXPCSecurityPolicy.codeSigningRequirement(
            for: .utilityStatus,
            productIdentity: configuration.productIdentity,
            policy: signingPolicy
        )
    )

    lifecycleController.start()
    cliListener.delegate = cliDelegate
    utilityListener.delegate = utilityDelegate
    cliListener.activate()
    utilityListener.activate()

    withExtendedLifetime((cliDelegate, utilityDelegate, cliListener, utilityListener)) {
        if configuration.experimentalRecoveryEnabled {
            _ = NSApplication.shared.setActivationPolicy(.accessory)
            NSApplication.shared.run()
        } else {
            RunLoop.current.run()
        }
    }
    fatalError("Key Agent run loop exited unexpectedly.")
}

run()
