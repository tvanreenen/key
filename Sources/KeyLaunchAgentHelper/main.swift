import Foundation
import KeyCore

private final class HelperLifecycleController {
    private let idleTimeout: TimeInterval
    private let queue = DispatchQueue(label: "work.tvr.key.helper-lifecycle")
    private let onIdle: () -> Void
    private var timer: DispatchSourceTimer?

    init(idleTimeout: TimeInterval, onIdle: @escaping () -> Void) {
        self.idleTimeout = idleTimeout
        self.onIdle = onIdle
    }

    func start() {
        recordActivity()
    }

    func recordActivity() {
        queue.sync {
            rescheduleTimer()
        }
    }

    func shutdown() {
        queue.async {
            self.timer?.cancel()
            self.timer = nil
            self.onIdle()
        }
    }

    private func rescheduleTimer() {
        timer?.cancel()

        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + idleTimeout)
        timer.setEventHandler(handler: onIdle)
        timer.resume()
        self.timer = timer
    }
}

private final class KeyAgentDelegate: NSObject, NSXPCListenerDelegate {
    private let exportedObject: KeyAgentService

    init(exportedObject: KeyAgentService) {
        self.exportedObject = exportedObject
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        newConnection.exportedInterface = NSXPCInterface(with: KeyXPCProtocol.self)
        newConnection.exportedObject = exportedObject
        newConnection.resume()
        return true
    }
}

private final class KeyAgentService: NSObject, KeyXPCProtocol {
    private let handler: KeyServiceHandler
    private let lifecycleController: HelperLifecycleController
    private let decoder = JSONDecoder()
    private let encoder = JSONEncoder()

    init(handler: KeyServiceHandler, lifecycleController: HelperLifecycleController) {
        self.handler = handler
        self.lifecycleController = lifecycleController
    }

    func sendRequest(_ requestData: NSData, withReply reply: @escaping (NSData?, NSString?) -> Void) {
        let request: KeyServiceRequest
        do {
            request = try decoder.decode(KeyServiceRequest.self, from: requestData as Data)
        } catch {
            reply(nil, "Failed to decode request." as NSString)
            return
        }

        if request != .status {
            lifecycleController.recordActivity()
        }

        do {
            let response = handler.handle(request)
            let responseData = try encoder.encode(response)
            reply(responseData as NSData, nil)
            if request == .lock, response.exitCode == EXIT_SUCCESS {
                lifecycleController.shutdown()
            }
        } catch {
            reply(nil, "Failed to encode response." as NSString)
        }
    }
}

private func run() -> Never {
    let configuration = RuntimeConfiguration.live()

    do {
        let rootURL = try EntryStore.defaultRootURL()
        let sessionKeyStore = SessionVaultKeyStore(
            underlying: VaultKeyStore(configuration: configuration)
        )
        let lifecycleController = HelperLifecycleController(idleTimeout: 15 * 60) {
            sessionKeyStore.invalidate()
            exit(EXIT_SUCCESS)
        }
        let handler = KeyServiceHandler(
            keyStore: sessionKeyStore,
            entryStore: EntryStore(rootURL: rootURL)
        )
        let service = KeyAgentService(handler: handler, lifecycleController: lifecycleController)
        let delegate = KeyAgentDelegate(exportedObject: service)
        let listener = NSXPCListener(machServiceName: configuration.helperMachServiceName)

        lifecycleController.start()
        listener.delegate = delegate
        listener.resume()
        RunLoop.current.run()
    } catch {
        fputs("Key Agent failed to resolve vault location: \(error.localizedDescription)\n", stderr)
        exit(EXIT_FAILURE)
    }
}

run()
