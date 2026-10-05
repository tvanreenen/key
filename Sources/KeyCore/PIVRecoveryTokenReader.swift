import CryptoKit
import CryptoTokenKit
import Foundation
import Security

enum PIVRecoveryTokenError: Error, Equatable {
  case unavailable
  case resourceLimit
  case ambiguousInventory
  case invalidSelection
  case tokenChanged
  case operationInProgress
  case invalidCertificate
  case anchorCredentialMismatch
}

/// Closed public-read surface. No PIN, management authentication, write,
/// signing, agreement, reset, or caller-supplied APDU can be expressed.
enum PIVPublicReadCommand: CaseIterable, Sendable {
  case selectApplication
  case keyManagementCertificate
  case recoveryAnchor

  var instruction: UInt8 { self == .selectApplication ? 0xa4 : 0xcb }
  var p1: UInt8 { self == .selectApplication ? 4 : 0x3f }
  var p2: UInt8 { self == .selectApplication ? 0 : 0xff }
  var data: Data {
    switch self {
    case .selectApplication: Data([0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0, 1, 0])
    case .keyManagementCertificate: Data([0x5c, 3, 0x5f, 0xc1, 0x0b])
    case .recoveryAnchor: Data([0x5c, 3, 0x5f, 0x4b, 0x59])
    }
  }
}

struct PIVPublicReadReply: Sendable {
  let data: Data?
  let status: UInt16
}

/// The native boundary owns the card instance and exclusive session. A token
/// removal permanently invalidates that instance, even after reinsertion.
protocol PIVRecoveryTokenConnection: Sendable {
  var tokenID: String { get }
  var readerSlotName: String { get }
  var isValid: Bool { get }
  func withPublicReadSession<T>(
    lease: PIVTokenOperationLease,
    _ consume: ((PIVPublicReadCommand) throws -> PIVPublicReadReply) throws -> T
  ) throws -> T
}

protocol PIVRecoveryTokenInventoryProviding: Sendable {
  func connections(maximumCount: Int) throws -> [any PIVRecoveryTokenConnection]
}

/// Operation exclusion is process-wide in live use. A pending native callback
/// retains its lease after a caller's deadline; timeout is not cancellation.
final class PIVTokenOperationGate: @unchecked Sendable {
  static let shared = PIVTokenOperationGate()
  private let lock = NSLock()
  private var claimed = false

  func acquire() throws -> PIVTokenOperationLease {
    try lock.withLock {
      guard !claimed else { throw PIVRecoveryTokenError.operationInProgress }
      claimed = true
      return PIVTokenOperationLease(gate: self)
    }
  }

  fileprivate func release() { lock.withLock { claimed = false } }
}

final class PIVTokenOperationLease: Sendable {
  private let gate: PIVTokenOperationGate
  fileprivate init(gate: PIVTokenOperationGate) { self.gate = gate }
  deinit { gate.release() }
}

struct PIVRecoveryTokenCandidate: Sendable {
  let tokenID: String
  let readerSlotName: String
  fileprivate let owner: UUID
  fileprivate let connection: any PIVRecoveryTokenConnection
}

enum PIVRecoveryAnchorOccupancy: Equatable, Sendable {
  case absent
  case recognized(V3RecoveryAnchor)
  case unrecognized
}

/// Public native observation, not possession proof, protected administration,
/// registration readiness or a restorable snapshot. Unknown bytes are withheld.
struct PIVRecoveryTokenObservation: Sendable {
  let candidate: PIVRecoveryTokenCandidate
  let publicKey: Data
  let recipientID: V3RecoveryRecipientID
  let anchor: PIVRecoveryAnchorOccupancy
  fileprivate let owner: UUID
  fileprivate let objectDigest: Data?
}

/// Internal, unconnected product foundation. Services must review an explicit
/// candidate; no automatic selection, prompts or cryptographic operation here.
final class PIVRecoveryTokenReader: Sendable {
  static let maximumCandidates = 64
  private let owner = UUID()
  private let inventory: any PIVRecoveryTokenInventoryProviding
  private let gate: PIVTokenOperationGate

  init(inventory: any PIVRecoveryTokenInventoryProviding, gate: PIVTokenOperationGate) {
    self.inventory = inventory
    self.gate = gate
  }

  static func live() -> PIVRecoveryTokenReader {
    PIVRecoveryTokenReader(inventory: PIVNativeTokenInventory(), gate: .shared)
  }

  func candidates() throws -> [PIVRecoveryTokenCandidate] {
    let lease = try gate.acquire()
    defer { withExtendedLifetime(lease) {} }
    let connections = try inventory.connections(maximumCount: Self.maximumCandidates)
    guard connections.count <= Self.maximumCandidates else {
      throw PIVRecoveryTokenError.resourceLimit
    }
    guard Set(connections.map(\.tokenID)).count == connections.count,
      Set(connections.map(\.readerSlotName)).count == connections.count
    else { throw PIVRecoveryTokenError.ambiguousInventory }
    return try connections.map { connection in
      guard Self.validIdentifier(connection.tokenID),
        Self.validIdentifier(connection.readerSlotName),
        connection.isValid
      else { throw PIVRecoveryTokenError.tokenChanged }
      return PIVRecoveryTokenCandidate(
        tokenID: connection.tokenID, readerSlotName: connection.readerSlotName,
        owner: owner, connection: connection)
    }.sorted { $0.tokenID.utf8.lexicographicallyPrecedes($1.tokenID.utf8) }
  }

  func read(_ candidate: PIVRecoveryTokenCandidate) throws -> PIVRecoveryTokenObservation {
    guard candidate.owner == owner else { throw PIVRecoveryTokenError.invalidSelection }
    let lease = try gate.acquire()
    defer { withExtendedLifetime(lease) {} }
    return try read(candidate, lease: lease)
  }

  private func read(
    _ candidate: PIVRecoveryTokenCandidate, lease: PIVTokenOperationLease
  ) throws -> PIVRecoveryTokenObservation {
    let connection = candidate.connection
    guard connection.isValid, connection.tokenID == candidate.tokenID,
      connection.readerSlotName == candidate.readerSlotName
    else { throw PIVRecoveryTokenError.tokenChanged }
    let result = try connection.withPublicReadSession(lease: lease) { nativeSend in
      func send(_ command: PIVPublicReadCommand) throws -> PIVPublicReadReply {
        guard connection.isValid else { throw PIVRecoveryTokenError.tokenChanged }
        return try nativeSend(command)
      }
      guard try send(.selectApplication).status == 0x9000 else {
        throw PIVPublicObjectError.unexpectedStatus
      }
      let certificate = try send(.keyManagementCertificate)
      guard certificate.status == 0x9000, let certificateData = certificate.data else {
        throw PIVPublicObjectError.unexpectedStatus
      }
      let publicKey = try Self.certificatePublicKey(
        PIVPublicObjectCodec.certificate(certificateData))
      let recipientID = try V3RecoveryRecipientID.derive(publicKey: publicKey)
      let reply = try send(.recoveryAnchor)
      let occupancy: PIVRecoveryAnchorOccupancy
      let objectDigest: Data?
      if reply.status == 0x6a82 {
        guard reply.data == nil || reply.data?.isEmpty == true else {
          throw PIVPublicObjectError.invalidResponse
        }
        occupancy = .absent
        objectDigest = nil
      } else {
        guard reply.status == 0x9000, let response = reply.data else {
          throw PIVPublicObjectError.unexpectedStatus
        }
        let object = try PIVPublicObjectCodec.object(
          response, maximumBytes: V3RecoveryAnchor.maximumBytes)
        objectDigest = Data(SHA256.hash(data: object))
        if let anchor = try? V3RecoveryAnchorCodec().parseCanonical(object) {
          guard anchor.recipientID == recipientID, anchor.slot == .keyManagement else {
            throw PIVRecoveryTokenError.anchorCredentialMismatch
          }
          occupancy = .recognized(anchor)
        } else {
          occupancy = .unrecognized
        }
      }
      guard connection.isValid else { throw PIVRecoveryTokenError.tokenChanged }
      return PIVRecoveryTokenObservation(
        candidate: candidate, publicKey: publicKey, recipientID: recipientID, anchor: occupancy,
        owner: owner, objectDigest: objectDigest)
    }
    guard connection.isValid else { throw PIVRecoveryTokenError.tokenChanged }
    return result
  }

  /// Re-read from the same retained card instance. Renewed certificates with
  /// the same key are permitted; changed key/anchor/occupancy is not equivalent.
  func revalidate(_ observation: PIVRecoveryTokenObservation) throws {
    guard observation.owner == owner else { throw PIVRecoveryTokenError.invalidSelection }
    let current = try read(observation.candidate)
    try requireEquivalent(current, observation)
  }

  /// One operation lease spans closed public sessions and the provider call.
  /// The worker retains it if its caller stops waiting for native completion.
  func withVerifiedObservation<T>(
    _ observation: PIVRecoveryTokenObservation,
    _ consume: (_ revalidate: () throws -> Void) throws -> T
  ) throws -> T {
    guard observation.owner == owner else { throw PIVRecoveryTokenError.invalidSelection }
    let lease = try gate.acquire()
    defer { withExtendedLifetime(lease) {} }
    func validate() throws {
      let current = try read(observation.candidate, lease: lease)
      try requireEquivalent(current, observation)
    }
    try validate()
    let result = try consume(validate)
    try validate()
    return result
  }

  private func requireEquivalent(
    _ current: PIVRecoveryTokenObservation, _ observation: PIVRecoveryTokenObservation
  ) throws {
    guard current.publicKey == observation.publicKey, current.anchor == observation.anchor,
      current.objectDigest == observation.objectDigest
    else {
      throw PIVRecoveryTokenError.tokenChanged
    }
  }

  static func certificatePublicKey(_ der: Data) throws -> Data {
    guard !der.isEmpty, der.count <= 65_536,
      let certificate = SecCertificateCreateWithData(nil, der as CFData),
      let key = SecCertificateCopyKey(certificate),
      let attributes = SecKeyCopyAttributes(key) as? [String: Any],
      attributes[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeECSECPrimeRandom as String,
      attributes[kSecAttrKeySizeInBits as String] as? Int == 256
    else { throw PIVRecoveryTokenError.invalidCertificate }
    var error: Unmanaged<CFError>?
    guard let bytes = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
      if let error { _ = error.takeRetainedValue() }
      throw PIVRecoveryTokenError.invalidCertificate
    }
    if let error { _ = error.takeRetainedValue() }
    do { _ = try P256.KeyAgreement.PublicKey(x963Representation: bytes) } catch {
      throw PIVRecoveryTokenError.invalidCertificate
    }
    // Public-key container only: no issuer, expiry or attestation trust claim.
    return bytes
  }

  private static func validIdentifier(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= 1_024
      && !value.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
  }
}

/// Lifecycle accounts for every outstanding native call. Finish closes a
/// successful session exactly once, only after pending callbacks complete.
final class PIVPublicReadSessionLifetime: @unchecked Sendable {
  private let lock = NSLock()
  private var lease: PIVTokenOperationLease?
  private let end: @Sendable () -> Void
  private var beginning = true
  private var started = false
  private var finished = false
  private var inFlight = 0
  private var drained = false

  init(lease: PIVTokenOperationLease, end: @escaping @Sendable () -> Void) {
    self.lease = lease
    self.end = end
  }

  func didBegin(success: Bool) {
    let action = lock.withLock {
      guard beginning else { return nil as Drain? }
      beginning = false
      started = success
      return drain()
    }
    action?.perform()
  }

  func willSend() -> Bool {
    lock.withLock {
      guard started, !finished, !drained, inFlight == 0 else { return false }
      inFlight += 1
      return true
    }
  }

  func didSend() {
    let action = lock.withLock {
      guard inFlight > 0 else { return nil as Drain? }
      inFlight -= 1
      return drain()
    }
    action?.perform()
  }

  var canSend: Bool { lock.withLock { started && !finished && !drained } }

  func finish() {
    let action = lock.withLock {
      finished = true
      return drain()
    }
    action?.perform()
  }

  private struct Drain {
    let lease: PIVTokenOperationLease?
    let end: (@Sendable () -> Void)?
    func perform() {
      end?()
      withExtendedLifetime(lease) {}
    }
  }

  // Called only under lock; native side effects are executed outside it.
  private func drain() -> Drain? {
    guard finished, !beginning, inFlight == 0, !drained else { return nil }
    drained = true
    let action = Drain(lease: lease, end: started ? end : nil)
    lease = nil
    return action
  }
}

private struct PIVNativeTokenInventory: PIVRecoveryTokenInventoryProviding {
  func connections(maximumCount: Int) throws -> [any PIVRecoveryTokenConnection] {
    let watcher = TKTokenWatcher()
    let tokens = watcher.tokenIDs
    guard tokens.count <= maximumCount else { throw PIVRecoveryTokenError.resourceLimit }
    guard let manager = TKSmartCardSlotManager.default else {
      throw PIVRecoveryTokenError.unavailable
    }
    var result: [any PIVRecoveryTokenConnection] = []
    for tokenID in tokens {
      guard let info = watcher.tokenInfo(forTokenID: tokenID), info.tokenID == tokenID,
        let name = info.slotName, !name.isEmpty
      else { continue }
      guard manager.slotNames.contains(name), let slot = manager.slotNamed(name),
        slot.name == name, slot.state == .validCard, let card = slot.makeSmartCard(), card.isValid
      else { throw PIVRecoveryTokenError.tokenChanged }
      result.append(
        PIVNativeTokenConnection(tokenID: tokenID, name: name, watcher: watcher, card: card))
    }
    return result
  }
}

/// TKSmartCard and watcher references stay inside this closed native boundary.
/// Calls are serialized by the shared operation gate; callbacks use locked state.
private final class PIVNativeTokenConnection: PIVRecoveryTokenConnection, @unchecked Sendable {
  let tokenID: String
  let readerSlotName: String
  private let watcher: TKTokenWatcher
  private let card: TKSmartCard
  private let removal = Removal()
  private final class Removal: @unchecked Sendable {
    private let lock = NSLock()
    private var removed = false
    var isPresent: Bool { lock.withLock { !removed } }
    func markRemoved() { lock.withLock { removed = true } }
  }

  init(tokenID: String, name: String, watcher: TKTokenWatcher, card: TKSmartCard) {
    self.tokenID = tokenID
    readerSlotName = name
    self.watcher = watcher
    self.card = card
    let removal = removal
    watcher.addRemovalHandler({ _ in removal.markRemoved() }, forTokenID: tokenID)
  }

  var isValid: Bool {
    removal.isPresent && card.isValid && card.slot.name == readerSlotName
      && watcher.tokenInfo(forTokenID: tokenID)?.slotName == readerSlotName
  }

  func withPublicReadSession<T>(
    lease: PIVTokenOperationLease,
    _ consume: ((PIVPublicReadCommand) throws -> PIVPublicReadReply) throws -> T
  ) throws -> T {
    let session = NativeSession(connection: self, lease: lease)
    defer { session.finish() }
    try session.begin()
    let result = try consume(session.send)
    guard session.withinDeadline else { throw PIVPublicObjectError.deadlineExceeded }
    guard isValid else { throw PIVRecoveryTokenError.tokenChanged }
    return result
  }

  private final class NativeSession: @unchecked Sendable {
    private let connection: PIVNativeTokenConnection
    private let lifetime: PIVPublicReadSessionLifetime
    private let deadline = DispatchTime.now() + .seconds(25)
    init(connection: PIVNativeTokenConnection, lease: PIVTokenOperationLease) {
      self.connection = connection
      lifetime = PIVPublicReadSessionLifetime(lease: lease) { connection.card.endSession() }
    }
    var withinDeadline: Bool { DispatchTime.now() < deadline }
    func begin() throws {
      guard withinDeadline else {
        lifetime.didBegin(success: false)
        throw PIVPublicObjectError.deadlineExceeded
      }
      guard connection.isValid else {
        lifetime.didBegin(success: false)
        throw PIVRecoveryTokenError.tokenChanged
      }
      let gate = DispatchSemaphore(value: 0)
      let lifetime = lifetime
      connection.card.beginSession { success, _ in
        lifetime.didBegin(success: success)
        gate.signal()
      }
      guard gate.wait(timeout: deadline) == .success else {
        throw PIVPublicObjectError.deadlineExceeded
      }
      guard lifetime.canSend, connection.isValid else { throw PIVRecoveryTokenError.tokenChanged }
    }
    func finish() { lifetime.finish() }
    func send(_ command: PIVPublicReadCommand) throws -> PIVPublicReadReply {
      guard withinDeadline else { throw PIVPublicObjectError.deadlineExceeded }
      guard connection.isValid else { throw PIVRecoveryTokenError.tokenChanged }
      guard lifetime.willSend() else { throw PIVPublicObjectError.unavailable }
      let reply = Reply()
      let gate = DispatchSemaphore(value: 0)
      let lifetime = lifetime
      connection.card.send(
        ins: command.instruction, p1: command.p1, p2: command.p2,
        data: command.data, le: 0
      ) { data, status, error in
        reply.complete(
          PIVPublicReadReply(
            data: data,
            status: error == nil || status == 0x6a82 ? status : 0))
        lifetime.didSend()
        gate.signal()
      }
      guard gate.wait(timeout: deadline) == .success, let value = reply.value else {
        throw PIVPublicObjectError.deadlineExceeded
      }
      guard withinDeadline else { throw PIVPublicObjectError.deadlineExceeded }
      guard connection.isValid else { throw PIVRecoveryTokenError.tokenChanged }
      return value
    }
    private final class Reply: @unchecked Sendable {
      private let lock = NSLock()
      private var result: PIVPublicReadReply?
      var value: PIVPublicReadReply? { lock.withLock { result } }
      func complete(_ value: PIVPublicReadReply) { lock.withLock { result = value } }
    }
  }
}
