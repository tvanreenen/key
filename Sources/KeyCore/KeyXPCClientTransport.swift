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

final class KeyXPCConnectionEndState: @unchecked Sendable {
    private let semaphore = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var isCompleted = false

    func complete() {
        lock.lock()
        guard !isCompleted else {
            lock.unlock()
            return
        }
        isCompleted = true
        lock.unlock()
        semaphore.signal()
    }

    func wait(timeoutSeconds: Int) -> Bool {
        semaphore.wait(
            timeout: .now() + .seconds(timeoutSeconds)
        ) == .success
    }
}

@objc public protocol KeyXPCProtocol {
    func sendRequest(_ requestData: NSData, withReply reply: @escaping (NSData?, NSString?) -> Void)
    func completeShutdown()
}

public final class KeyXPCClientTransport: KeyServiceTransport {
    static let helperShutdownTimeoutSeconds = 30

    private let machServiceName: String
    private let productIdentity: KeyProductIdentity
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(
        machServiceName: String,
        productIdentity: KeyProductIdentity
    ) {
        self.machServiceName = machServiceName
        self.productIdentity = productIdentity
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
            KeyXPCSecurityPolicy.helperCodeSigningRequirement(
                productIdentity: productIdentity,
                policy: signingPolicy
            )
        )
        let connectionEndState = KeyXPCConnectionEndState()
        connection.interruptionHandler = {
            connectionEndState.complete()
        }
        connection.invalidationHandler = {
            connectionEndState.complete()
        }
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

        let response: KeyServiceResponse
        do {
            response = try decoder.decode(
                KeyServiceResponse.self,
                from: capturedData
            )
        } catch {
            throw AppError.service("Key service returned an invalid response.")
        }
        if request.requiresHelperShutdownAfterSuccess,
           response.exitCode == EXIT_SUCCESS {
            invalidatesOnReturn = false
            proxy.completeShutdown()
            do {
                try Self.requireHelperTermination(
                    connectionEndState,
                    after: request,
                    helperName: productIdentity.helperName,
                    timeoutSeconds: Self.helperShutdownTimeoutSeconds
                )
            } catch {
                connection.invalidate()
                throw error
            }
        }
        return response
    }

    static func requireHelperTermination(
        _ connectionEndState: KeyXPCConnectionEndState,
        after request: KeyServiceRequest,
        helperName: String,
        timeoutSeconds: Int
    ) throws {
        guard connectionEndState.wait(timeoutSeconds: timeoutSeconds) else {
            throw helperRestartTimeoutError(
                for: request,
                helperName: helperName,
                timeoutSeconds: timeoutSeconds
            )
        }
    }

    static func helperRestartTimeoutError(
        for request: KeyServiceRequest,
        helperName: String,
        timeoutSeconds: Int
    ) -> AppError {
        if case .initializeVault = request {
            return AppError.service("Vault initialization completed, but \(helperName) is still restarting after \(timeoutSeconds) seconds. Run `key status` after the helper restarts; do not initialize another vault.")
        }
        return AppError.service(
            "The \(request.completedOperationDescription) completed, but \(helperName) is still restarting after \(timeoutSeconds) seconds. Run the same command again; Key will resume safely from the completed state."
        )
    }
}

private extension KeyServiceRequest {
    var operationName: String {
        switch self {
        case .unlock: "unlock"
        case .lock: "lock"
        case .status: "status"
        case .vaultStatus: "vault status"
        case .listConflicts: "conflict list"
        case .showConflict: "conflict show"
        case .getConflictValue: "conflict get"
        case .resolveConflicts: "conflict resolve"
        case .share, .shareInDirectory: "device sharing"
        case .list: "list"
        case .migrationPreflight: "migration preflight"
        case .migrationApply: "migration"
        case .initializeVault: "vault initialization"
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

    var completedOperationDescription: String {
        switch self {
        case .lock:
            "vault lock"
        case .migrationApply:
            "vault migration"
        case .setVaultDirectory:
            "vault directory update"
        case .share(.accept), .shareInDirectory(.accept, _):
            "enrollment acceptance"
        case .share(.replaceCurrentDevice):
            "revoked-device cleanup"
        default:
            operationName
        }
    }
}
