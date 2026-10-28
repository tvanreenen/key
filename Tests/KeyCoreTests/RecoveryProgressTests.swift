import Foundation
import Testing

@testable import KeyCore

struct RecoveryProgressTests {
  @Test func receiverBoundsAndOrdersStagesWithinOneOperation() throws {
    let receiver = KeyXPCRecoveryProgressReceiver(wake: .init(value: 0))
    func send(_ stage: KeyRecoveryStage, id: UUID? = nil) throws {
      receiver.recoveryProgress(try JSONEncoder().encode(
        KeyRecoveryProgressEvent(operationID: id ?? receiver.operationID, stage: stage)) as NSData)
    }
    try send(.authenticating, id: UUID())
    try send(.touchRequired)
    receiver.recoveryProgress(Data(repeating: 0, count: 1_025) as NSData)
    receiver.recoveryProgress(Data("{\"stage\":\"PIN-secret\"}".utf8) as NSData)
    #expect(receiver.take().isEmpty)
    try send(.authenticating)
    try send(.authenticating)
    try send(.hardwareCompleted)
    #expect(receiver.take() == [.authenticating])
    try send(.touchRequired)
    try send(.hardwareCompleted)
    try send(.authenticating)
    #expect(receiver.take() == [.touchRequired, .hardwareCompleted])
    receiver.close()
    try send(.authenticating)
    #expect(receiver.take().isEmpty)
  }

  @Test func closingBeforeFinalReplyDropsQueuedAndLatePresentation() throws {
    let receiver = KeyXPCRecoveryProgressReceiver(wake: .init(value: 0))
    let event = try JSONEncoder().encode(KeyRecoveryProgressEvent(
      operationID: receiver.operationID, stage: .authenticating)) as NSData
    receiver.recoveryProgress(event)
    receiver.close()
    #expect(receiver.take().isEmpty)
    receiver.recoveryProgress(event)
    #expect(receiver.take().isEmpty)
  }

  @Test func connectionCancellationClosesHostProgressBeforeLaterStages() throws {
    let connection = KeyServiceConnection()
    let received = Events()
    let progress = KeyRecoveryProgress(operationID: UUID()) { received.append($0.stage) }
    let host = KeyServiceHost(hasConfiguration: { true }, makeHandler: { { _ in .success() } },
      initialize: { _ in "unused" }, registerRecovery: { _, scope in
        scope.progress?.emit(.authenticating)
        connection.invalidate()
        scope.progress?.emit(.touchRequired)
        try scope.requireCurrent()
        return .success()
      })
    let result = host.handle(.recoveryRegistration(.finish(tokenID: "fixture", recipientID:
      Base64URL.encode(Data(repeating: 1, count: 32)))), connection: connection, progress: progress)
    #expect(result.exitCode != EXIT_SUCCESS)
    #expect(received.values == [.authenticating])
    progress.emit(.touchRequired)
    #expect(received.values == [.authenticating])
  }

  @Test func registrationProgressUsesStderrAndNeverReplacesFinalFailure() {
    let recipient = Base64URL.encode(Data(repeating: 7, count: 32))
    let io = MemoryIO(stdinIsTTY: true, lineInput: "REGISTER")
    let transport = MemoryTransport(stages: KeyRecoveryStage.hardwareStages) { _ in
      .failure("Fixture final validation failed.")
    }
    let app = KeyCLIApplication(transport: transport, io: io, clipboard: MemoryClipboard())
    #expect(app.run(arguments: ["recovery", "register", "finish", "--token", "fixture",
      "--recipient", recipient]) != EXIT_SUCCESS)
    #expect(transport.requests.count == 1 && transport.progressRequests == 1)
    #expect(io.stdout.isEmpty)
    for stage in KeyRecoveryStage.hardwareStages { #expect(io.stderr.contains(stage.instruction)) }
    #expect(io.stderr.contains("Fixture final validation failed."))
    #expect(io.stderr.contains("Preserve token"))
  }

  @Test func progressIsOnlyAvailableForHardwareRequests() {
    #expect(KeyServiceRequest.recovery(.resume(source: "/a", destination: "/b",
      tokenID: "fixture", recipientID: "fixture")).supportsRecoveryProgress)
    #expect(KeyServiceRequest.recoveryRegistration(.finish(tokenID: "fixture",
      recipientID: "fixture")).supportsRecoveryProgress)
    for request: KeyServiceRequest in [.status, .unlock, .recoveryReview(.tokens),
      .recoveryRegistration(.pending), .recoveryRegistration(.status),
      .recoveryRegistration(.prepare(tokenID: "fixture", recipientID: "fixture")),
      .recoveryRotation(.rotate)] {
      #expect(!request.supportsRecoveryProgress)
    }
  }

  @Test(arguments: [false, true], [false, true])
  func restoreBranchesStayOrderedBoundedAndRejectSkippedOrRepeatedStages(resume: Bool, selected: Bool) throws {
    let receiver = KeyXPCRecoveryProgressReceiver(wake: .init(value: 0))
    func send(_ stage: KeyRecoveryStage) throws {
      receiver.recoveryProgress(try JSONEncoder().encode(
        KeyRecoveryProgressEvent(operationID: receiver.operationID, stage: stage)) as NSData)
    }
    try send(.preparationSaved)
    for stage in KeyRecoveryStage.hardwareStages { try send(stage) }
    let branch: KeyRecoveryStage = resume ? .openingSavedPreparation : .preparingRestoredVault
    try send(.activatingRestoredVault)
    try send(branch)
    try send(resume ? .preparingRestoredVault : .openingSavedPreparation)
    try send(.preparationSaved)
    try send(.preparationSaved)
    if !selected { try send(.publishingRestoredVault) }
    try send(.activatingRestoredVault)
    for stage in KeyRecoveryStage.allCases { try send(stage) }
    #expect(receiver.take() == KeyRecoveryStage.hardwareStages + [branch, .preparationSaved]
      + (selected ? [] : [.publishingRestoredVault]) + [.activatingRestoredVault])
  }

  private final class Events: @unchecked Sendable {
    private let lock = NSLock()
    private var stages: [KeyRecoveryStage] = []
    var values: [KeyRecoveryStage] { lock.withLock { stages } }
    func append(_ value: KeyRecoveryStage) { lock.withLock { stages.append(value) } }
  }
}
