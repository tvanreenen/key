import Foundation

final class KeyXPCReplyState: @unchecked Sendable {
    let semaphore = DispatchSemaphore(value: 0)

    private let lock = NSLock()
    private var isCompleted = false
    private var data: Data?
    private var error: String?

    func complete(data: Data?, error: String?) {
        lock.lock()
        guard !isCompleted else {
            lock.unlock()
            return
        }
        self.data = data
        self.error = error
        isCompleted = true
        lock.unlock()
        semaphore.signal()
    }

    func result() -> (data: Data?, error: String?) {
        lock.lock()
        defer {
            lock.unlock()
        }
        return (data, error)
    }
}

@objc public protocol KeyXPCProtocol {
    func sendRequest(_ requestData: NSData, withReply reply: @escaping (NSData?, NSString?) -> Void)
    func completeShutdown()
}

public final class KeyXPCClientTransport: KeyServiceTransport {
    private let machServiceName: String
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(machServiceName: String) {
        self.machServiceName = machServiceName
    }

    public func send(_ request: KeyServiceRequest) throws -> KeyServiceResponse {
        let requestData = try encoder.encode(request)
        let connection = NSXPCConnection(machServiceName: machServiceName, options: [])
        connection.remoteObjectInterface = NSXPCInterface(with: KeyXPCProtocol.self)
        #if DEBUG
        let signingPolicy = KeyXPCCodeSigningPolicy.development
        #else
        let signingPolicy = KeyXPCCodeSigningPolicy.production
        #endif
        connection.setCodeSigningRequirement(
            KeyXPCSecurityPolicy.helperCodeSigningRequirement(policy: signingPolicy)
        )
        connection.resume()
        var invalidatesOnReturn = true
        defer {
            if invalidatesOnReturn {
                connection.invalidate()
            }
        }

        let replyState = KeyXPCReplyState()

        let remote = connection.remoteObjectProxyWithErrorHandler { error in
            replyState.complete(data: nil, error: error.localizedDescription)
        }

        guard let proxy = remote as? KeyXPCProtocol else {
            throw AppError.service("Failed to connect to the Key service.")
        }

        proxy.sendRequest(requestData as NSData) { responseData, errorMessage in
            replyState.complete(data: responseData as Data?, error: errorMessage as String?)
        }

        if let timeoutSeconds = request.responseTimeoutSeconds {
            if replyState.semaphore.wait(timeout: .now() + .seconds(timeoutSeconds)) == .timedOut {
                connection.invalidate()
                throw AppError.service(
                    "Timed out after \(timeoutSeconds) seconds waiting for the Key service to handle \(request.operationName)."
                )
            }
        } else {
            replyState.semaphore.wait()
        }

        let result = replyState.result()
        if let capturedError = result.error {
            throw AppError.service("Key service error: \(capturedError)")
        }

        guard let capturedData = result.data else {
            throw AppError.service("Key service returned no response.")
        }

        do {
            let response = try decoder.decode(KeyServiceResponse.self, from: capturedData)
            if request.requiresHelperShutdownAfterSuccess,
               response.exitCode == EXIT_SUCCESS {
                invalidatesOnReturn = false
                proxy.completeShutdown()
                connection.scheduleSendBarrierBlock {
                    connection.invalidate()
                }
            }
            return response
        } catch {
            throw AppError.service("Key service returned an invalid response.")
        }
    }
}

private extension KeyServiceRequest {
    var operationName: String {
        switch self {
        case .unlock: "unlock"
        case .lock: "lock"
        case .status: "status"
        case .list: "list"
        case .migrationPreflight: "migration preflight"
        case .setVaultDirectory: "vault directory configuration"
        case .setKeychainMode: "keychain configuration"
        case .get: "get"
        case .addManual: "add"
        case .editManual: "edit"
        case .copyEntry: "copy"
        case .moveEntry: "move"
        case .removeEntry: "remove"
        }
    }
}
