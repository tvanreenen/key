import Foundation
import KeyCore

private final class KeyXPCServiceDelegate: NSObject, NSXPCListenerDelegate {
    private let exportedObject: KeyXPCService

    init(handler: KeyServiceHandler) {
        self.exportedObject = KeyXPCService(handler: handler)
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        newConnection.exportedInterface = NSXPCInterface(with: KeyXPCProtocol.self)
        newConnection.exportedObject = exportedObject
        newConnection.resume()
        return true
    }
}

private final class KeyXPCService: NSObject, KeyXPCProtocol {
    private let handler: KeyServiceHandler
    private let decoder = JSONDecoder()
    private let encoder = JSONEncoder()

    init(handler: KeyServiceHandler) {
        self.handler = handler
    }

    func sendRequest(_ requestData: NSData, withReply reply: @escaping (NSData?, NSString?) -> Void) {
        let request: KeyServiceRequest
        do {
            request = try decoder.decode(KeyServiceRequest.self, from: requestData as Data)
        } catch {
            reply(nil, "Failed to decode request." as NSString)
            return
        }

        do {
            let response = handler.handle(request)
            let responseData = try encoder.encode(response)
            reply(responseData as NSData, nil)
        } catch {
            reply(nil, "Failed to encode response." as NSString)
        }
    }
}

private let delegate = KeyXPCServiceDelegate(handler: .live())
private let listener = NSXPCListener.service()
listener.delegate = delegate
listener.resume()
RunLoop.current.run()
