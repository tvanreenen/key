import Foundation
import Testing

@testable import KeyCore

/// Exercises actual NSXPC encoding/callbacks on an anonymous test endpoint.
/// This is protocol interoperability, not production signing/UI qualification.
struct RecoveryProgressXPCTests {
  @Test(arguments: [false, true])
  func additiveSelectorCarriesScopedProgressAndFinalReplyOverXPC(restore: Bool) throws {
    let expected = KeyRecoveryStage.hardwareStages + (restore
      ? [.preparingRestoredVault, .preparationSaved, .publishingRestoredVault, .activatingRestoredVault] : [])
    let service = Service(stages: expected)
    let delegate = Delegate(service: service)
    let listener = NSXPCListener.anonymous()
    listener.delegate = delegate
    listener.activate()
    let client = NSXPCConnection(listenerEndpoint: listener.endpoint)
    let wake = DispatchSemaphore(value: 0)
    let progress = KeyXPCRecoveryProgressReceiver(wake: wake)
    let response = KeyXPCReplyState()
    client.remoteObjectInterface = NSXPCInterface(with: KeyXPCProtocol.self)
    client.exportedInterface = NSXPCInterface(with: KeyXPCRecoveryProgressProtocol.self)
    client.exportedObject = progress
    client.resume()
    defer {
      progress.close()
      service.allowReply.signal()
      client.invalidate()
      service.connection?.invalidate()
      listener.invalidate()
      withExtendedLifetime(delegate) {}
    }
    let remote = try #require(client.remoteObjectProxyWithErrorHandler { error in
      response.complete(data: nil, error: error.localizedDescription)
      wake.signal()
    } as? KeyXPCProtocol)
    let request = KeyServiceRequest.recoveryRegistration(.finish(tokenID: "fixture",
      recipientID: Base64URL.encode(Data(repeating: 7, count: 32))))
    remote.sendRecoveryRequest(try JSONEncoder().encode(request) as NSData,
      operationID: progress.operationID as NSUUID) { data, error in
        response.complete(data: data as Data?, error: error as String?)
        wake.signal()
      }
    var stages: [KeyRecoveryStage] = []
    let deadline = DispatchTime.now() + .seconds(10)
    while stages.count < expected.count {
      guard wake.wait(timeout: deadline) == .success else {
        Issue.record("XPC delivered \(stages.count) of \(expected.count) progress stages before the deadline")
        return
      }
      stages += progress.take()
      if response.hasResult, stages.count < expected.count {
        Issue.record("XPC replied before all progress arrived: \(response.result().error ?? "no error")")
        return
      }
    }
    #expect(stages == expected)
    service.allowReply.signal()
    #expect(response.semaphore.wait(timeout: deadline) == .success)
    let result = response.result()
    #expect(result.error == nil)
    let data = try #require(result.data)
    #expect(try JSONDecoder().decode(KeyServiceResponse.self, from: data).exitCode == EXIT_SUCCESS)
  }

  private final class Delegate: NSObject, NSXPCListenerDelegate {
    let service: Service
    init(service: Service) { self.service = service }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
      service.connection = connection
      connection.exportedInterface = NSXPCInterface(with: KeyXPCProtocol.self)
      connection.exportedObject = service
      connection.remoteObjectInterface = NSXPCInterface(with: KeyXPCRecoveryProgressProtocol.self)
      connection.resume()
      return true
    }
  }

  private final class Service: NSObject, KeyXPCProtocol, @unchecked Sendable {
    let stages: [KeyRecoveryStage]
    init(stages: [KeyRecoveryStage]) { self.stages = stages }
    weak var connection: NSXPCConnection?
    let allowReply = DispatchSemaphore(value: 0)
    func sendRequest(_ data: NSData, withReply reply: @escaping (NSData?, NSString?) -> Void) {
      reply(nil, "Legacy route is not this test's contract")
    }
    func completeShutdown() {}
    func sendRecoveryRequest(_ data: NSData, operationID: NSUUID,
      withReply reply: @escaping @Sendable (NSData?, NSString?) -> Void) {
      // Match the production helper: never wait on the XPC delivery queue.
      DispatchQueue.global(qos: .userInitiated).async { [self] in
        guard let request = try? JSONDecoder().decode(KeyServiceRequest.self, from: data as Data),
          request.supportsRecoveryProgress,
          let sink = connection?.remoteObjectProxy as? KeyXPCRecoveryProgressProtocol else {
          reply(nil, "Invalid fixture request")
          return
        }
        for stage in stages {
          let event = KeyRecoveryProgressEvent(operationID: operationID as UUID, stage: stage)
          guard let data = try? JSONEncoder().encode(event) else { return }
          sink.recoveryProgress(data as NSData)
        }
        guard allowReply.wait(timeout: .now() + .seconds(10)) == .success,
          let result = try? JSONEncoder().encode(KeyServiceResponse.success()) else {
          reply(nil, "Fixture reply gate did not open")
          return
        }
        reply(result as NSData, nil)
      }
    }
  }
}
