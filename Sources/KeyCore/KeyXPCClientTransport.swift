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
    var hasResult: Bool { lock.withLock { isCompleted } }
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
    func sendRecoveryRequest(_ requestData: NSData, operationID: NSUUID,
                             withReply reply: @escaping @Sendable (NSData?, NSString?) -> Void)
    func completeShutdown()
}

@objc public protocol KeyXPCRecoveryProgressProtocol {
    func recoveryProgress(_ event: NSData)
}

/// XPC callbacks enqueue at most three finite stages. User callbacks run only
/// on send's calling thread and never after it returns, including after timeout.
final class KeyXPCRecoveryProgressReceiver: NSObject, KeyXPCRecoveryProgressProtocol, @unchecked Sendable {
    let operationID = UUID()
    private let lock = NSLock()
    private var open = true
    private var next = 0
    private var pending: [KeyRecoveryStage] = []
    private let wake: DispatchSemaphore
    init(wake: DispatchSemaphore) { self.wake = wake }
    func recoveryProgress(_ data: NSData) {
        guard data.length <= 1_024,
              let event = try? JSONDecoder().decode(KeyRecoveryProgressEvent.self, from: data as Data),
              event.operationID == operationID else { return }
        let accepted = lock.withLock {
            guard open, next < KeyRecoveryStage.allCases.count,
                  KeyRecoveryStage.allCases[next] == event.stage else { return false }
            next += 1
            pending.append(event.stage)
            return true
        }
        if accepted { wake.signal() }
    }
    func take() -> [KeyRecoveryStage] {
        lock.withLock { let values = pending; pending.removeAll(); return values }
    }
    func close() { lock.withLock { open = false; pending.removeAll() } }
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
        try send(request, progress: { _ in })
    }

    public func send(_ request: KeyServiceRequest, progress: @escaping (KeyRecoveryStage) -> Void) throws -> KeyServiceResponse {
        let requestData = try encoder.encode(request)
        let replyState = KeyXPCReplyState()
        let progressReceiver = KeyXPCRecoveryProgressReceiver(wake: replyState.semaphore)
        defer { progressReceiver.close() }
        let connection = NSXPCConnection(machServiceName: machServiceName, options: [])
        connection.remoteObjectInterface = NSXPCInterface(with: KeyXPCProtocol.self)
        if request.supportsRecoveryProgress {
            connection.exportedInterface = NSXPCInterface(with: KeyXPCRecoveryProgressProtocol.self)
            connection.exportedObject = progressReceiver
        }
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
            replyState.complete(data: nil, error: "The helper connection was interrupted. Preserve recovery state; no retry was made.")
        }
        connection.invalidationHandler = {
            connectionEndState.complete()
            replyState.complete(data: nil, error: "The helper connection closed. Preserve recovery state; no retry was made.")
        }
        connection.resume()
        var invalidatesOnReturn = true
        defer {
            if invalidatesOnReturn {
                connection.invalidate()
            }
        }

        let remote = connection.remoteObjectProxyWithErrorHandler { error in
            replyState.complete(data: nil, error: error.localizedDescription)
        }

        guard let proxy = remote as? KeyXPCProtocol else {
            throw AppError.service("Failed to connect to the Key service.")
        }

        let receiveReply: @Sendable (NSData?, NSString?) -> Void = { responseData, errorMessage in
            progressReceiver.close()
            replyState.complete(data: responseData as Data?, error: errorMessage as String?)
        }
        if request.supportsRecoveryProgress {
            // Additive selector: an older helper fails before dispatch. Never
            // fall back to an un-staged request after an uncertain reply.
            proxy.sendRecoveryRequest(requestData as NSData,
                operationID: progressReceiver.operationID as NSUUID, withReply: receiveReply)
        } else {
            proxy.sendRequest(requestData as NSData, withReply: receiveReply)
        }
        let deadline = request.responseTimeoutSeconds.map { DispatchTime.now() + .seconds($0) } ?? .distantFuture
        while !replyState.hasResult {
            for stage in progressReceiver.take() { progress(stage) }
            if replyState.semaphore.wait(timeout: deadline) == .timedOut {
                connection.invalidate()
                throw AppError.service(
                    "Timed out waiting for the Key service to handle \(request.operationName)."
                )
            }
        }
        progressReceiver.close()

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
            return AppError.service("Your new vault is ready, but \(helperName) is still restarting after \(timeoutSeconds) seconds. Run `key status` after it restarts. Do not run init again.")
        }
        switch request {
        case .recoveryRotation:
            return AppError.service("Key rotation returned success, but \(helperName) is still restarting after \(timeoutSeconds) seconds. Preserve all state and inspect status after restart; do not request a replacement rotation.")
        case .recoveryRegistration:
            return AppError.service("Recovery setup returned success, but \(helperName) is still restarting after \(timeoutSeconds) seconds. Preserve all state and inspect registration status after restart; do not start replacement setup.")
        case .recovery:
            return AppError.service("The restored vault is selected, but \(helperName) is still restarting after \(timeoutSeconds) seconds. Run `key status` after it restarts. Do not start another restore.")
        case .share(.accept), .shareInDirectory(.accept, _):
            return AppError.service("This Mac has joined the vault, but \(helperName) is still restarting after \(timeoutSeconds) seconds. Run `key status` after it restarts. You do not need to accept the invitation again.")
        case .migrationApply:
            return AppError.service("Migration completed and this Mac now uses the new vault, but \(helperName) is still restarting after \(timeoutSeconds) seconds. Run `key status` after it restarts. Do not run migration again.")
        default:
            break
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
        case .recovery: "vault recovery"
        case .recoveryReview: "public recovery review"
        case .recoveryRegistration: "recovery registration"
        case .recoveryRotation: "recovery-profile key rotation"
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
