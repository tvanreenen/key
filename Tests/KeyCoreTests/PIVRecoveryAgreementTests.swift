import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct PIVRecoveryAgreementTests {
  // Expired public software certificate, not the owner's hardware credential.
  private static let certificate = Data(
    base64Encoded:
      "MIIBiTCCATCgAwIBAgIUMw8ODdlTgTIgtSKw44Ql3zmMG4MwCgYIKoZIzj0EAwIwKzEpMCcGA1UEAwwgRGlzcG9zYWJsZS1QdWJsaWMtUmVhZGVyLUZpeHR1cmUwHhcNMjYxMDAyMjI1NzUwWhcNMjYxMDAzMjI1NzUwWjArMSkwJwYDVQQDDCBEaXNwb3NhYmxlLVB1YmxpYy1SZWFkZXItRml4dHVyZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABP6BbLGMaCO43s4BegokVD3FbytbyMSCeayyDxGJm+N+XEAO+9DcDAJf27UcWZKd0TdckqDLOu3+1ScQTREFi+6jMjAwMB0GA1UdDgQWBBTexRlA2He6kVY2UL3NTJi6MrvRTzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIB0VsnglpNS75gEdXOCCUlUC7wlzxUBBjeAbBQWWRC96AiAs0cUQFMuh68hj7v/MQWjH3JcgD4QDmUUId7Dt2Xwb3Q=="
  )!

  @Test func unusedScopeDoesNotLookUpOrRequestAnything() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    try f.adapter.withReceiver(observation: f.observation) { _ in }
    #expect(f.session.lookups == 0 && f.session.requests == 0)
    #expect(f.connection.sessions == 1)
  }

  @Test func scopedAgreementChecksBindingAndClosesReadsBeforeRequest() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    let peer = P256.KeyAgreement.PrivateKey()
    let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: f.observation.publicKey)
    let expected = try peer.sharedSecretFromKeyAgreement(with: publicKey).withUnsafeBytes {
      Data($0)
    }
    f.session.result = expected
    f.session.onAgree = {
      #expect(!f.connection.inSession)
      #expect(throws: PIVRecoveryTokenError.operationInProgress) { try f.reader.candidates() }
    }
    try f.adapter.withReceiver(observation: f.observation) { receiver in
      let secret = try receiver.decapsulate(peer.publicKey.x963Representation)
      let expectedKEM = try pivKEMSecret(
        dh: expected, enc: peer.publicKey.x963Representation, recipient: f.observation.publicKey)
      #expect(secret.withUnsafeBytes { Data($0) } == expectedKEM.withUnsafeBytes { Data($0) })
      #expect(throws: PIVRecoveryAgreementError.alreadyRequested) {
        try receiver.agree(peer.publicKey.x963Representation)
      }
    }
    #expect(f.session.lookups == 1 && f.session.requests == 1)
    #expect(f.connection.sessions == 4 && !f.connection.inSession)
    let lease = try f.gate.acquire()
    withExtendedLifetime(lease) {}
  }

  @Test func escapedReceiverIsClosed() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    let receiver = try f.adapter.withReceiver(observation: f.observation) { $0 }
    #expect(throws: PIVRecoveryAgreementError.scopeClosed) { try receiver.agree(Self.peer) }
    #expect(f.session.lookups == 0 && f.session.requests == 0)
  }

  @Test func closingScopeStopsAnOutstandingRequestAndRefusesConcurrentReuse() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    let entered = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    let returned = DispatchSemaphore(value: 0)
    f.session.onAgree = {
      entered.signal()
      _ = release.wait(timeout: .now() + .seconds(10))
    }
    defer { release.signal() }
    try f.adapter.withReceiver(observation: f.observation) { receiver in
      DispatchQueue.global().async {
        #expect(throws: PIVRecoveryAgreementError.scopeClosed) { try receiver.agree(Self.peer) }
        returned.signal()
      }
      #expect(entered.wait(timeout: .now() + .seconds(3)) == .success)
      #expect(throws: PIVRecoveryAgreementError.alreadyRequested) { try receiver.agree(Self.peer) }
    }
    #expect(returned.wait(timeout: .now() + .seconds(3)) == .success)
    #expect(throws: PIVRecoveryTokenError.operationInProgress) { try f.reader.candidates() }
    release.signal()
    try Self.requireGateReleased(f.gate)
    #expect(f.session.requests == 1 && f.session.invalidations == 1)
  }

  @Test func invalidPeerNeverReachesTheProviderAndCannotRetry() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    try f.adapter.withReceiver(observation: f.observation) { receiver in
      #expect(throws: PIVRecoveryAgreementError.invalidPeer) { try receiver.agree(Data([4])) }
      #expect(throws: PIVRecoveryAgreementError.alreadyRequested) { try receiver.agree(Self.peer) }
    }
    #expect(f.session.lookups == 0 && f.session.requests == 0)
  }

  @Test func missingAmbiguousMismatchedAndUnsupportedKeysDoNotRequestAgreement() throws {
    guard #available(macOS 26.0, *) else { return }
    for variant in 0..<6 {
      let f = try Fixture()
      switch variant {
      case 0: f.session.values = []
      case 1: f.session.values.append(f.session.values[0])
      case 2: f.session.values[0].tokenID = "other-token"
      case 3: f.session.values[0].publicKey = Self.peer
      case 4: f.session.values[0].isP256PrivateKey = false
      default: f.session.values[0].supportsStandardECDH = false
      }
      let expected: PIVRecoveryAgreementError =
        variant < 2 ? .ambiguousKey : variant == 5 ? .unsupportedKey : .invalidBinding
      #expect(throws: expected) {
        try f.adapter.withReceiver(observation: f.observation) { try $0.agree(Self.peer) }
      }
      #expect(f.session.requests == 0)
    }
  }

  @Test func providerFailureAndInvalidResultDoNotRetry() throws {
    guard #available(macOS 26.0, *) else { return }
    for length in [-1, 0, 31, 33] {
      let f = try Fixture()
      if length == -1 {
        f.session.failure = .providerFailure
      } else {
        f.session.result = Data(repeating: 0, count: length)
      }
      try f.adapter.withReceiver(observation: f.observation) { receiver in
        #expect(throws: length == -1 ? PIVRecoveryAgreementError.providerFailure : .invalidResult) {
          try receiver.agree(Self.peer)
        }
        #expect(throws: PIVRecoveryAgreementError.alreadyRequested) {
          try receiver.agree(Self.peer)
        }
      }
      #expect(f.session.requests == 1)
      let lease = try f.gate.acquire()
      withExtendedLifetime(lease) {}
    }
  }

  @Test func foreignObservationCannotReachTheProvider() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    let other = PIVRecoveryAgreement(
      reader: PIVRecoveryTokenReader(inventory: Inventory(f.connection), gate: f.gate),
      provider: Provider(f.session))
    #expect(throws: PIVRecoveryTokenError.invalidSelection) {
      try other.withReceiver(observation: f.observation) { try $0.agree(Self.peer) }
    }
    #expect(f.session.lookups == 0 && f.session.requests == 0)
  }

  @Test func removalBeforeLookupAfterLookupAndAfterAgreementFailsClosed() throws {
    guard #available(macOS 26.0, *) else { return }
    for stage in 0..<3 {
      let f = try Fixture()
      if stage == 0 { f.connection.remove() }
      if stage == 1 { f.session.onLookup = { f.connection.remove() } }
      if stage == 2 { f.session.onAgree = { f.connection.remove() } }
      #expect(throws: PIVRecoveryTokenError.tokenChanged) {
        try f.adapter.withReceiver(observation: f.observation) { try $0.agree(Self.peer) }
      }
      #expect(f.session.requests == (stage == 2 ? 1 : 0))
    }
  }

  @Test func changedAnchorBeforeOrAfterAgreementDiscardsTheResult() throws {
    guard #available(macOS 26.0, *) else { return }
    for before in [true, false] {
      let f = try Fixture()
      if before {
        f.session.onLookup = { f.connection.changeAnchor() }
      } else {
        f.session.onAgree = { f.connection.changeAnchor() }
      }
      #expect(throws: PIVRecoveryTokenError.tokenChanged) {
        try f.adapter.withReceiver(observation: f.observation) { try $0.agree(Self.peer) }
      }
      #expect(f.session.requests == (before ? 0 : 1))
    }
  }

  @Test func busyGateRefusesBeforeLookup() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    let lease = try f.gate.acquire()
    #expect(throws: PIVRecoveryTokenError.operationInProgress) {
      try f.adapter.withReceiver(observation: f.observation) { try $0.agree(Self.peer) }
    }
    #expect(f.session.lookups == 0 && f.session.requests == 0)
    withExtendedLifetime(lease) {}
  }

  @Test func preCancelledOrExpiredAttemptDoesNotStartWork() throws {
    guard #available(macOS 26.0, *) else { return }
    for expired in [true, false] {
      let f = try Fixture()
      let cancellation = PIVRecoveryCancellation()
      if !expired { cancellation.cancel() }
      #expect(throws: expired ? PIVRecoveryAgreementError.deadlineExceeded : .cancelled) {
        try f.adapter.withReceiver(
          observation: f.observation, cancellation: cancellation,
          deadline: expired ? .now() : .now() + .seconds(10)
        ) { try $0.agree(Self.peer) }
      }
      #expect(f.session.lookups == 0 && f.session.requests == 0)
      #expect(f.connection.sessions == 1)
    }
  }

  @Test func cancellationDuringLookupPreventsAgreement() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    let cancellation = PIVRecoveryCancellation()
    f.session.onLookup = { cancellation.cancel() }
    #expect(throws: PIVRecoveryAgreementError.cancelled) {
      try f.adapter.withReceiver(observation: f.observation, cancellation: cancellation) {
        try $0.agree(Self.peer)
      }
    }
    #expect(f.session.requests == 0)
  }

  @Test func pendingProviderRemainsExcludedAfterCancellationOrDeadline() throws {
    guard #available(macOS 26.0, *) else { return }
    for timeout in [false, true] {
      let f = try Fixture()
      let cancellation = PIVRecoveryCancellation()
      let entered = DispatchSemaphore(value: 0)
      let release = DispatchSemaphore(value: 0)
      let returned = DispatchSemaphore(value: 0)
      f.session.onAgree = {
        entered.signal()
        // Scripted pending native call ignores cancellation until released.
        _ = release.wait(timeout: .now() + .seconds(10))
      }
      defer { release.signal() }
      DispatchQueue.global().async {
        #expect(throws: timeout ? PIVRecoveryAgreementError.deadlineExceeded : .cancelled) {
          try f.adapter.withReceiver(
            observation: f.observation, cancellation: cancellation,
            deadline: .now() + .seconds(timeout ? 1 : 10)
          ) { try $0.agree(Self.peer) }
        }
        returned.signal()
      }
      #expect(entered.wait(timeout: .now() + .seconds(3)) == .success)
      if !timeout { cancellation.cancel() }
      #expect(returned.wait(timeout: .now() + .seconds(3)) == .success)
      #expect(throws: PIVRecoveryTokenError.operationInProgress) { try f.reader.candidates() }
      #expect(f.session.requests == 1)
      release.signal()
      try Self.requireGateReleased(f.gate)
      #expect(f.session.invalidations == 1)
    }
  }

  @Test func cancellationHandlersAreOneShotRemovableAndLateAware() {
    let cancellation = PIVRecoveryCancellation()
    let counter = Counter()
    let removed = cancellation.register { counter.increment() }
    cancellation.remove(removed)
    _ = cancellation.register { counter.increment() }
    cancellation.cancel()
    cancellation.cancel()
    _ = cancellation.register { counter.increment() }
    #expect(counter.value == 2 && cancellation.isCancelled)
  }

  private static var peer: Data { P256.KeyAgreement.PrivateKey().publicKey.x963Representation }

  // Poll only the in-memory exclusion gate, never token discovery or a private
  // operation. Completion of a cancelled worker has no result notification.
  private static func requireGateReleased(_ gate: PIVTokenOperationGate) throws {
    let deadline = DispatchTime.now() + .seconds(3)
    while DispatchTime.now() < deadline {
      do {
        let lease = try gate.acquire()
        withExtendedLifetime(lease) {}
        return
      } catch PIVRecoveryTokenError.operationInProgress {
        Thread.sleep(forTimeInterval: 0.001)
      }
    }
    Issue.record("Operation gate remained held after scripted provider completion")
  }

  private struct Fixture: Sendable {
    let connection: Connection
    let gate = PIVTokenOperationGate()
    let reader: PIVRecoveryTokenReader
    let observation: PIVRecoveryTokenObservation
    let session: Session
    let adapter: PIVRecoveryAgreement
    init() throws {
      connection = Connection()
      reader = PIVRecoveryTokenReader(inventory: Inventory(connection), gate: gate)
      observation = try reader.read(try #require(reader.candidates().first))
      session = Session(publicKey: observation.publicKey)
      adapter = PIVRecoveryAgreement(reader: reader, provider: Provider(session))
    }
  }
  private struct Inventory: PIVRecoveryTokenInventoryProviding {
    let connection: Connection
    init(_ connection: Connection) { self.connection = connection }
    func connections(maximumCount: Int) throws -> [any PIVRecoveryTokenConnection] { [connection] }
  }
  private final class Connection: PIVRecoveryTokenConnection, @unchecked Sendable {
    let tokenID = "fixture-token"
    let readerSlotName = "fixture-reader"
    private let lock = NSLock()
    private var valid = true
    private var count = 0
    private var active = false
    private var changed = false
    var isValid: Bool { lock.withLock { valid } }
    var sessions: Int { lock.withLock { count } }
    var inSession: Bool { lock.withLock { active } }
    func remove() { lock.withLock { valid = false } }
    func changeAnchor() { lock.withLock { changed = true } }
    func withPublicReadSession<T>(
      lease: PIVTokenOperationLease,
      _ consume: ((PIVPublicReadCommand) throws -> PIVPublicReadReply) throws -> T
    ) throws -> T {
      lock.withLock {
        count += 1
        active = true
      }
      defer {
        lock.withLock { active = false }
        withExtendedLifetime(lease) {}
      }
      return try consume { command in
        switch command {
        case .selectApplication: return PIVPublicReadReply(data: nil, status: 0x9000)
        case .keyManagementCertificate:
          return PIVPublicReadReply(
            data: Self.tlv(0x53, Self.tlv(0x70, certificate) + Self.tlv(0x71, Data([0]))),
            status: 0x9000)
        case .recoveryAnchor:
          return self.lock.withLock {
            self.changed
              ? PIVPublicReadReply(data: Self.tlv(0x53, Data([1])), status: 0x9000)
              : PIVPublicReadReply(data: nil, status: 0x6a82)
          }
        }
      }
    }
    private static func tlv(_ tag: UInt8, _ value: Data) -> Data {
      let count = value.count
      let size: [UInt8] =
        count < 128 ? [UInt8(count)] : [0x82, UInt8(count >> 8), UInt8(count & 255)]
      return Data([tag] + size) + value
    }
  }
  private struct Key: PIVRecoveryAgreementKey {
    var tokenID = "fixture-token"
    var publicKey: Data
    var isP256PrivateKey = true
    var supportsStandardECDH = true
  }
  private struct Provider: PIVRecoveryAgreementProviding {
    let session: Session
    init(_ session: Session) { self.session = session }
    func makeSession() -> any PIVRecoveryAgreementSession { session }
  }
  // Test configuration is set before dispatch; observed counters are locked.
  private final class Session: PIVRecoveryAgreementSession, @unchecked Sendable {
    var values: [Key]
    var result = Data(repeating: 7, count: 32)
    var failure: PIVRecoveryAgreementError?
    var onLookup: @Sendable () -> Void = {}
    var onAgree: @Sendable () -> Void = {}
    private let lock = NSLock()
    private var lookupCount = 0
    private var requestCount = 0
    private var invalidationCount = 0
    init(publicKey: Data) { values = [Key(publicKey: publicKey)] }
    var lookups: Int { lock.withLock { lookupCount } }
    var requests: Int { lock.withLock { requestCount } }
    var invalidations: Int { lock.withLock { invalidationCount } }
    func keys(tokenID: String, publicKey: Data) throws -> [any PIVRecoveryAgreementKey] {
      lock.withLock { lookupCount += 1 }
      onLookup()
      return values
    }
    func agree(key: any PIVRecoveryAgreementKey, peer: Data) throws -> Data {
      lock.withLock { requestCount += 1 }
      onAgree()
      if let failure { throw failure }
      return result
    }
    func invalidate() { lock.withLock { invalidationCount = 1 } }
  }
  private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    var value: Int { lock.withLock { count } }
    func increment() { lock.withLock { count += 1 } }
  }
}
