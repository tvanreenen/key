import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct PIVRecoveryTokenReaderTests {
  // Public certificate from an archived disposable software fixture. It is
  // expired and self-issued; neither issuer nor expiry is recovery authority.
  private static let certificate = Data(
    base64Encoded:
      "MIIBiTCCATCgAwIBAgIUMw8ODdlTgTIgtSKw44Ql3zmMG4MwCgYIKoZIzj0EAwIwKzEpMCcGA1UEAwwgRGlzcG9zYWJsZS1QdWJsaWMtUmVhZGVyLUZpeHR1cmUwHhcNMjYxMDAyMjI1NzUwWhcNMjYxMDAzMjI1NzUwWjArMSkwJwYDVQQDDCBEaXNwb3NhYmxlLVB1YmxpYy1SZWFkZXItRml4dHVyZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABP6BbLGMaCO43s4BegokVD3FbytbyMSCeayyDxGJm+N+XEAO+9DcDAJf27UcWZKd0TdckqDLOu3+1ScQTREFi+6jMjAwMB0GA1UdDgQWBBTexRlA2He6kVY2UL3NTJi6MrvRTzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIB0VsnglpNS75gEdXOCCUlUC7wlzxUBBjeAbBQWWRC96AiAs0cUQFMuh68hj7v/MQWjH3JcgD4QDmUUId7Dt2Xwb3Q=="
  )!

  @Test
  func inventoryDoesNotReadOrAutomaticallySelectAToken() throws {
    let a = FakeConnection(tokenID: "token-a", reader: "reader A")
    let b = FakeConnection(tokenID: "token-b", reader: "reader B")
    let reader = makeReader([b, a])
    let candidates = try reader.candidates()
    #expect(candidates.map(\.tokenID) == ["token-a", "token-b"])
    #expect(a.commands.isEmpty && b.commands.isEmpty)
    #expect(a.sessionCount == 0 && b.sessionCount == 0)
    #expect(try makeReader([]).candidates().isEmpty)
  }

  @Test
  func explicitCandidateReadsCertificateAndAnchorInOneSession() throws {
    let anchor = try Self.anchor()
    let a = FakeConnection(tokenID: "other token", reader: "other reader")
    let b = try Self.connection(anchor: .available(anchor.canonicalBytes))
    let reader = makeReader([a, b])
    let candidate = try #require(reader.candidates().first { $0.tokenID == b.tokenID })
    let observation = try reader.read(candidate)
    #expect(observation.anchor == .recognized(anchor))
    #expect(try observation.publicKey == Self.publicKey())
    #expect(observation.recipientID == anchor.recipientID)
    #expect(b.commands == [.selectApplication, .keyManagementCertificate, .recoveryAnchor])
    #expect(b.sessionCount == 1 && b.closeCount == 1)
    #expect(a.commands.isEmpty)
    try reader.revalidate(observation)
    #expect(b.sessionCount == 2 && b.closeCount == 2)
  }

  @Test
  func absentEmptyAndUnknownOccupiedAnchorsRemainDistinct() throws {
    for input in [
      ObjectInput.absent, .available(Data()), .available(Data("unknown public fixture".utf8)),
    ] {
      let connection = try Self.connection(anchor: input)
      let reader = makeReader([connection])
      let observation = try reader.read(try #require(reader.candidates().first))
      #expect(observation.anchor == (input == .absent ? .absent : .unrecognized))
      #expect(connection.closeCount == 1)
    }
  }

  @Test
  func anchorForADifferentPublicCredentialIsRejected() throws {
    let other = try V3RecoveryRecipientID.derive(
      publicKey: P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
    let connection = try Self.connection(
      anchor: .available(Self.anchor(recipientID: other).canonicalBytes))
    let reader = makeReader([connection])
    #expect(throws: PIVRecoveryTokenError.anchorCredentialMismatch) {
      try reader.read(try #require(reader.candidates().first))
    }
    #expect(connection.commands.count == 3)
    #expect(connection.closeCount == 1)
  }

  @Test
  func invalidCertificateStopsBeforeAnchorRead() throws {
    let connection = try Self.connection(anchor: .absent)
    connection.setReply(
      .keyManagementCertificate,
      value: PIVPublicReadReply(
        data: Self.tlv(0x53, Self.tlv(0x70, Data([1, 2, 3])) + Self.tlv(0x71, Data([0]))),
        status: 0x9000))
    let reader = makeReader([connection])
    #expect(throws: PIVRecoveryTokenError.invalidCertificate) {
      try reader.read(try #require(reader.candidates().first))
    }
    #expect(connection.commands == [.selectApplication, .keyManagementCertificate])
    #expect(connection.closeCount == 1)
    for der in [Data(), Data([0]), Data(repeating: 0, count: 65_537)] {
      #expect(throws: PIVRecoveryTokenError.invalidCertificate) {
        try PIVRecoveryTokenReader.certificatePublicKey(der)
      }
    }
  }

  @Test
  func foreignReaderCandidateCannotStartASession() throws {
    let connection = try Self.connection(anchor: .absent)
    let reader = makeReader([connection])
    let candidate = try #require(reader.candidates().first)
    #expect(throws: PIVRecoveryTokenError.invalidSelection) {
      try makeReader([connection]).read(candidate)
    }
    #expect(connection.sessionCount == 0)
  }

  @Test
  func ambiguousOversizeAndMalformedInventoryNeverBeginsARead() throws {
    let a = FakeConnection(tokenID: "a", reader: "reader")
    let sameReader = FakeConnection(tokenID: "b", reader: "reader")
    let sameID = FakeConnection(tokenID: "a", reader: "another reader")
    for inventory in [[a, sameReader], [a, sameID]] {
      #expect(throws: PIVRecoveryTokenError.ambiguousInventory) {
        try makeReader(inventory).candidates()
      }
    }
    let tooMany = (0...PIVRecoveryTokenReader.maximumCandidates).map {
      FakeConnection(tokenID: "token-\($0)", reader: "reader-\($0)")
    }
    #expect(throws: PIVRecoveryTokenError.resourceLimit) { try makeReader(tooMany).candidates() }
    for identifier in ["", "reader\nname", String(repeating: "x", count: 1_025)] {
      #expect(throws: PIVRecoveryTokenError.tokenChanged) {
        try makeReader([FakeConnection(tokenID: identifier, reader: "reader")]).candidates()
      }
    }
    #expect(a.sessionCount == 0 && sameReader.sessionCount == 0 && sameID.sessionCount == 0)
  }

  @Test
  func removalAndSameNamedReplacementCannotReviveOldObservation() throws {
    let connection = try Self.connection(anchor: .absent)
    let inventory = FakeInventory([connection])
    let reader = PIVRecoveryTokenReader(inventory: inventory, gate: PIVTokenOperationGate())
    let observation = try reader.read(try #require(reader.candidates().first))
    connection.remove()
    let replacement = try Self.connection(anchor: .absent)
    inventory.replace(with: [replacement])
    #expect(throws: PIVRecoveryTokenError.tokenChanged) { try reader.revalidate(observation) }
    #expect(connection.sessionCount == 1)
    #expect(replacement.sessionCount == 0)
    #expect(try reader.read(try #require(reader.candidates().first)).anchor == .absent)
  }

  @Test
  func removalDuringEachReadStopsWithoutFurtherCommandsOrRetry() throws {
    for stage in PIVPublicReadCommand.allCases {
      let connection = try Self.connection(anchor: .absent)
      connection.afterCommand { [weak connection] command in
        if command == stage { connection?.remove() }
      }
      let reader = makeReader([connection])
      #expect(throws: PIVRecoveryTokenError.tokenChanged) {
        try reader.read(try #require(reader.candidates().first))
      }
      #expect(connection.commands.last == stage)
      #expect(connection.commands.filter { $0 == stage }.count == 1)
      #expect(connection.closeCount == 1)
    }
  }

  @Test
  func failedReadsAndUncertainStatusesAreNotRetried() throws {
    for stage in PIVPublicReadCommand.allCases {
      let connection = try Self.connection(anchor: .absent)
      connection.fail(at: stage)
      let reader = makeReader([connection])
      #expect(throws: PIVPublicObjectError.unavailable) {
        try reader.read(try #require(reader.candidates().first))
      }
      #expect(connection.commands.last == stage)
      #expect(connection.commands.filter { $0 == stage }.count == 1)
      #expect(connection.closeCount == 1)
    }
    for status: UInt16 in [0, 0x6982, 0x6a80, 0x6100] {
      let connection = try Self.connection(anchor: .absent)
      connection.setReply(.recoveryAnchor, value: PIVPublicReadReply(data: nil, status: status))
      let reader = makeReader([connection])
      #expect(throws: PIVPublicObjectError.unexpectedStatus) {
        try reader.read(try #require(reader.candidates().first))
      }
      #expect(connection.closeCount == 1)
    }
  }

  @Test
  func malformedAbsentAndOversizeObjectResponsesRefuseObservation() throws {
    for reply in [
      PIVPublicReadReply(data: Data([1]), status: 0x6a82),
      PIVPublicReadReply(data: Data([0x53]), status: 0x9000),
      PIVPublicReadReply(data: Self.tlv(0x53, Data(repeating: 0, count: 1_025)), status: 0x9000),
    ] {
      let connection = try Self.connection(anchor: .absent)
      connection.setReply(.recoveryAnchor, value: reply)
      let reader = makeReader([connection])
      #expect(throws: PIVPublicObjectError.invalidResponse) {
        try reader.read(try #require(reader.candidates().first))
      }
      #expect(connection.closeCount == 1)
    }
  }

  @Test
  func changedAnchorAndChangedUnknownBytesInvalidateObservation() throws {
    for input in [
      ObjectInput.absent, .available(try Self.anchor().canonicalBytes),
      .available(Data("unknown A".utf8)),
    ] {
      let connection = try Self.connection(anchor: input)
      let reader = makeReader([connection])
      let observation = try reader.read(try #require(reader.candidates().first))
      connection.setReply(
        .recoveryAnchor,
        value: PIVPublicReadReply(data: Self.tlv(0x53, Data("unknown B".utf8)), status: 0x9000))
      #expect(throws: PIVRecoveryTokenError.tokenChanged) { try reader.revalidate(observation) }
      #expect(connection.sessionCount == 2 && connection.closeCount == 2)
    }
  }

  @Test
  func busyProcessGateStopsDiscoveryAndReadBeforeAnyNativeSession() throws {
    let connection = try Self.connection(anchor: .absent)
    let gate = PIVTokenOperationGate()
    let reader = PIVRecoveryTokenReader(inventory: FakeInventory([connection]), gate: gate)
    let candidate = try #require(reader.candidates().first)
    let held = try gate.acquire()
    defer { withExtendedLifetime(held) {} }
    #expect(throws: PIVRecoveryTokenError.operationInProgress) { try reader.candidates() }
    #expect(throws: PIVRecoveryTokenError.operationInProgress) { try reader.read(candidate) }
    #expect(connection.sessionCount == 0)
  }

  @Test
  func closedCommandSurfaceHasOnlyTheApprovedPublicReads() {
    #expect(PIVPublicReadCommand.allCases.count == 3)
    #expect(PIVPublicReadCommand.selectApplication.instruction == 0xa4)
    #expect(PIVPublicReadCommand.selectApplication.p1 == 4)
    for command in [PIVPublicReadCommand.keyManagementCertificate, .recoveryAnchor] {
      #expect(command.instruction == 0xcb && command.p1 == 0x3f && command.p2 == 0xff)
    }
    #expect(
      PIVPublicReadCommand.keyManagementCertificate.data == Data([0x5c, 3, 0x5f, 0xc1, 0x0b]))
    #expect(PIVPublicReadCommand.recoveryAnchor.data == Data([0x5c, 3, 0x5f, 0x4b, 0x59]))
  }

  @Test
  func normalAndFailedSessionLifetimesReleaseLeaseAndCloseOnlySuccessfulBegin() throws {
    for success in [true, false] {
      let gate = PIVTokenOperationGate()
      let counter = Counter()
      var lease: PIVTokenOperationLease? = try gate.acquire()
      let lifetime = PIVPublicReadSessionLifetime(lease: try #require(lease)) {
        counter.increment()
      }
      lease = nil
      #expect(!lifetime.canSend)
      lifetime.didBegin(success: success)
      #expect(lifetime.canSend == success)
      lifetime.finish()
      lifetime.finish()
      lifetime.didBegin(success: success)
      #expect(!lifetime.canSend)
      #expect(counter.value == (success ? 1 : 0))
      let next = try gate.acquire()
      withExtendedLifetime(next) {}
    }
  }

  @Test
  func lateBeginAndLateSendKeepGateBusyUntilNativeCompletion() throws {
    for pendingBegin in [true, false] {
      let gate = PIVTokenOperationGate()
      let counter = Counter()
      var lease: PIVTokenOperationLease? = try gate.acquire()
      let lifetime = PIVPublicReadSessionLifetime(lease: try #require(lease)) {
        counter.increment()
      }
      lease = nil
      if !pendingBegin {
        lifetime.didBegin(success: true)
        #expect(lifetime.willSend())
        #expect(!lifetime.willSend())
      }
      lifetime.finish()  // Deadline/caller exit; the native callback is still pending.
      #expect(counter.value == 0)
      #expect(!lifetime.canSend)
      #expect(throws: PIVRecoveryTokenError.operationInProgress) { try gate.acquire() }
      if pendingBegin { lifetime.didBegin(success: true) } else { lifetime.didSend() }
      #expect(counter.value == 1)
      lifetime.finish()
      #expect(!lifetime.willSend())
      let next = try gate.acquire()
      withExtendedLifetime(next) {}
    }
  }

  @Test
  func leaseRemainsClaimedDuringSessionClosureAndLateFailedBeginClosesNothing() throws {
    let gate = PIVTokenOperationGate()
    var lease: PIVTokenOperationLease? = try gate.acquire()
    let lifetime = PIVPublicReadSessionLifetime(lease: try #require(lease)) {
      #expect(throws: PIVRecoveryTokenError.operationInProgress) { try gate.acquire() }
    }
    lease = nil
    lifetime.didBegin(success: true)
    lifetime.finish()
    do {
      let next = try gate.acquire()
      withExtendedLifetime(next) {}
    }
    let counter = Counter()
    var pending: PIVTokenOperationLease? = try gate.acquire()
    let failed = PIVPublicReadSessionLifetime(lease: try #require(pending)) { counter.increment() }
    pending = nil
    failed.finish()
    #expect(throws: PIVRecoveryTokenError.operationInProgress) { try gate.acquire() }
    failed.didBegin(success: false)
    #expect(counter.value == 0)
    let next = try gate.acquire()
    withExtendedLifetime(next) {}
  }

  private func makeReader(_ connections: [FakeConnection]) -> PIVRecoveryTokenReader {
    PIVRecoveryTokenReader(inventory: FakeInventory(connections), gate: PIVTokenOperationGate())
  }
  private static func publicKey() throws -> Data {
    try PIVRecoveryTokenReader.certificatePublicKey(certificate)
  }
  private static func anchor(recipientID: V3RecoveryRecipientID? = nil) throws -> V3RecoveryAnchor {
    try V3RecoveryAnchor(
      floor: V3VaultHead(
        vaultID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3",
        envelopeDigest: Data(repeating: 1, count: 32)),
      recipientID: recipientID ?? V3RecoveryRecipientID.derive(publicKey: publicKey()),
      registrationID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b6", slot: .keyManagement)
  }
  private enum ObjectInput: Equatable {
    case absent
    case available(Data)
  }
  private static func connection(anchor: ObjectInput) throws -> FakeConnection {
    let value = FakeConnection(tokenID: "explicit-token", reader: "arbitrary native reader name")
    value.setReply(.selectApplication, value: PIVPublicReadReply(data: Data(), status: 0x9000))
    value.setReply(
      .keyManagementCertificate,
      value: PIVPublicReadReply(
        data: tlv(0x53, tlv(0x70, certificate) + tlv(0x71, Data([0]))), status: 0x9000))
    switch anchor {
    case .absent:
      value.setReply(.recoveryAnchor, value: PIVPublicReadReply(data: nil, status: 0x6a82))
    case .available(let bytes):
      value.setReply(
        .recoveryAnchor, value: PIVPublicReadReply(data: tlv(0x53, bytes), status: 0x9000))
    }
    return value
  }
  private static func tlv(_ tag: UInt8, _ bytes: Data) -> Data {
    let count = bytes.count
    let length: [UInt8] =
      count < 128
      ? [UInt8(count)]
      : count <= 255
        ? [0x81, UInt8(count)] : [0x82, UInt8(count >> 8), UInt8(count & 0xff)]
    return Data([tag] + length) + bytes
  }
  private final class FakeInventory: PIVRecoveryTokenInventoryProviding, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [FakeConnection]
    init(_ values: [FakeConnection]) { self.values = values }
    func replace(with values: [FakeConnection]) { lock.withLock { self.values = values } }
    func connections(maximumCount: Int) throws -> [any PIVRecoveryTokenConnection] {
      lock.withLock { values }
    }
  }
  private final class FakeConnection: PIVRecoveryTokenConnection, @unchecked Sendable {
    let tokenID: String
    let readerSlotName: String
    private let lock = NSLock()
    private var valid = true
    private var readCommands: [PIVPublicReadCommand] = []
    private var sessions = 0
    private var closes = 0
    private var replies: [PIVPublicReadCommand: PIVPublicReadReply] = [:]
    private var failure: PIVPublicReadCommand?
    private var after: @Sendable (PIVPublicReadCommand) -> Void = { _ in }
    init(tokenID: String, reader: String) {
      self.tokenID = tokenID
      readerSlotName = reader
    }
    var isValid: Bool { lock.withLock { valid } }
    var commands: [PIVPublicReadCommand] { lock.withLock { readCommands } }
    var sessionCount: Int { lock.withLock { sessions } }
    var closeCount: Int { lock.withLock { closes } }
    func remove() { lock.withLock { valid = false } }
    func fail(at command: PIVPublicReadCommand) { lock.withLock { failure = command } }
    func afterCommand(_ operation: @escaping @Sendable (PIVPublicReadCommand) -> Void) {
      lock.withLock { after = operation }
    }
    func setReply(_ command: PIVPublicReadCommand, value: PIVPublicReadReply) {
      lock.withLock { replies[command] = value }
    }
    func withPublicReadSession<T>(
      lease: PIVTokenOperationLease,
      _ consume: ((PIVPublicReadCommand) throws -> PIVPublicReadReply) throws -> T
    ) throws -> T {
      lock.withLock { sessions += 1 }
      defer {
        lock.withLock { closes += 1 }
        withExtendedLifetime(lease) {}
      }
      return try consume { command in
        let (reply, fail, after) = lock.withLock {
          readCommands.append(command)
          return (replies[command], failure == command, self.after)
        }
        if fail { throw PIVPublicObjectError.unavailable }
        let result = try #require(reply)
        after(command)
        return result
      }
    }
  }
  private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    var value: Int { lock.withLock { count } }
    func increment() { lock.withLock { count += 1 } }
  }
}
