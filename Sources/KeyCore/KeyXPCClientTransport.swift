import Foundation

@objc public protocol KeyXPCProtocol {
    func sendRequest(_ requestData: NSData, withReply reply: @escaping (NSData?, NSString?) -> Void)
}

public final class KeyXPCClientTransport: KeyServiceTransport {
    private let serviceName: String
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(serviceName: String) {
        self.serviceName = serviceName
    }

    public func send(_ request: KeyServiceRequest) throws -> KeyServiceResponse {
        let requestData = try encoder.encode(request)
        let connection = NSXPCConnection(serviceName: serviceName)
        connection.remoteObjectInterface = NSXPCInterface(with: KeyXPCProtocol.self)
        connection.resume()
        defer {
            connection.invalidate()
        }

        let semaphore = DispatchSemaphore(value: 0)
        var capturedData: Data?
        var capturedError: String?

        let remote = connection.remoteObjectProxyWithErrorHandler { error in
            capturedError = error.localizedDescription
            semaphore.signal()
        }

        guard let proxy = remote as? KeyXPCProtocol else {
            throw AppError.service("Failed to connect to the Key service.")
        }

        proxy.sendRequest(requestData as NSData) { responseData, errorMessage in
            capturedData = responseData as Data?
            capturedError = errorMessage as String?
            semaphore.signal()
        }

        if semaphore.wait(timeout: .now() + .seconds(30)) == .timedOut {
            throw AppError.service("Timed out waiting for the Key service.")
        }

        if let capturedError {
            throw AppError.service("Key service error: \(capturedError)")
        }

        guard let capturedData else {
            throw AppError.service("Key service returned no response.")
        }

        do {
            return try decoder.decode(KeyServiceResponse.self, from: capturedData)
        } catch {
            throw AppError.service("Key service returned an invalid response.")
        }
    }
}
