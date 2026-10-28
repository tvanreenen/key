import CryptoKit
import Foundation
import LocalAuthentication
import OSLog
import Security

enum PIVRecoveryAgreementError: Error, Equatable {
  case invalidPeer
  case invalidBinding
  case ambiguousKey
  case unavailable
  case unsupportedKey
  case invalidResult
  case alreadyRequested
  case scopeClosed
  case cancelled
  case deadlineExceeded
  case providerFailure
  case accessControlUnavailable
  case authenticationFailed
}

extension PIVRecoveryAgreementError: LocalizedError {
  var errorDescription: String? {
    switch self {
    case .invalidPeer, .invalidResult: "Recovery data did not match the required key-agreement format."
    case .invalidBinding: "The selected recovery credential no longer matches. No replacement key was used."
    case .ambiguousKey: "Could not select exactly one matching recovery key."
    case .unavailable: "The recovery key provider is unavailable."
    case .unsupportedKey: "The selected key does not support the required P-256 agreement."
    case .alreadyRequested: "This recovery request cannot start another key operation."
    case .scopeClosed: "The recovery request is no longer active."
    case .cancelled: "Recovery was cancelled. Preserve saved recovery state; no automatic retry was made."
    case .deadlineExceeded: "The recovery request timed out. Preserve saved recovery state; no automatic retry was made. Cancel any remaining macOS PIN dialog without entering a PIN before using the key again."
    case .providerFailure: "The recovery key operation did not complete. No automatic retry was made."
    case .accessControlUnavailable: "macOS did not expose this key's access-control policy. No authentication or agreement was attempted."
    case .authenticationFailed: "macOS did not approve the recovery key. No key agreement was requested."
    }
  }
}

/// Native Security ownership boundary. Implementations must keep lookup
/// noninteractive and must never export a private key or retry authentication.
protocol PIVRecoveryAgreementKey: Sendable {
  var tokenID: String { get }
  var publicKey: Data { get }
  var isP256PrivateKey: Bool { get }
  var supportsStandardECDH: Bool { get }
}

protocol PIVRecoveryAgreementSession: Sendable {
  func keys(tokenID: String, publicKey: Data) throws -> [any PIVRecoveryAgreementKey]
  func authenticate(key: any PIVRecoveryAgreementKey) throws
  func agree(key: any PIVRecoveryAgreementKey, peer: Data) throws -> Data
  func invalidate()
}

protocol PIVRecoveryAgreementProviding: Sendable {
  func makeSession() -> any PIVRecoveryAgreementSession
}

/// Explicit cancellation without PIN data. Handlers run outside the lock; late
/// registration observes cancellation immediately. Native termination is not
/// guaranteed by notification or authentication-context invalidation.
final class PIVRecoveryCancellation: @unchecked Sendable {
  private let lock = NSLock()
  private var stopped = false
  private var handlers: [UUID: @Sendable () -> Void] = [:]
  var isCancelled: Bool { lock.withLock { stopped } }

  func cancel() {
    let actions: [@Sendable () -> Void] = lock.withLock {
      guard !stopped else { return [] }
      stopped = true
      let actions = Array(handlers.values)
      handlers.removeAll()
      return actions
    }
    for action in actions { action() }
  }

  func register(_ action: @escaping @Sendable () -> Void) -> UUID {
    let id = UUID()
    let run = lock.withLock {
      if stopped { return true }
      handlers[id] = action
      return false
    }
    if run { action() }
    return id
  }

  func remove(_ id: UUID) { _ = lock.withLock { handlers.removeValue(forKey: id) } }
}

/// Internal product foundation; no caller, setup-policy assertion or prompt
/// qualification yet. The receiver cannot initiate an operation after its
/// scope ends, or initiate a second operation, including after an error.
final class PIVRecoveryAgreement: Sendable {
  private let reader: PIVRecoveryTokenReader
  private let provider: any PIVRecoveryAgreementProviding

  init(reader: PIVRecoveryTokenReader, provider: any PIVRecoveryAgreementProviding) {
    self.reader = reader
    self.provider = provider
  }

  static func live(reader: PIVRecoveryTokenReader) -> PIVRecoveryAgreement {
    PIVRecoveryAgreement(reader: reader, provider: PIVNativeAgreementProvider())
  }

  @available(macOS 26.0, *)
  func withReceiver<T>(
    observation: PIVRecoveryTokenObservation,
    cancellation: PIVRecoveryCancellation = PIVRecoveryCancellation(),
    deadline: DispatchTime = .now() + .seconds(60),
    progress: KeyRecoveryProgress? = nil,
    _ consume: (PIVHPKEReceiver) throws -> T
  ) throws -> T {
    let scope = Scope()
    defer { scope.close(); progress?.close() }
    let receiver = try PIVHPKEReceiver(publicBytes: observation.publicKey) { [self] peer in
      let attempt = Attempt(deadline: deadline)
      try scope.claim(attempt)
      try observation.keyMetadata.requireRecoveryPolicy()
      do { _ = try P256.KeyAgreement.PublicKey(x963Representation: peer) } catch {
        throw PIVRecoveryAgreementError.invalidPeer
      }
      let registration = cancellation.register { attempt.stop(.cancelled) }
      defer { cancellation.remove(registration) }
      _ = attempt.cancellation.register { progress?.close() }
      try attempt.check()
      DispatchQueue.global(qos: .userInitiated).async { [self] in
        attempt.complete(
          Result {
            try attempt.check()
            let secret = try reader.withVerifiedObservation(observation) { validate in
              try attempt.check()
              let session = provider.makeSession()
              let stop = attempt.cancellation.register { session.invalidate() }
              defer {
                attempt.cancellation.remove(stop)
                session.invalidate()
              }
              try attempt.check()
              let keys = try session.keys(
                tokenID: observation.candidate.tokenID, publicKey: observation.publicKey)
              try attempt.check()
              guard keys.count == 1, let key = keys.first else {
                throw PIVRecoveryAgreementError.ambiguousKey
              }
              guard key.tokenID == observation.candidate.tokenID,
                key.publicKey == observation.publicKey, key.isP256PrivateKey
              else { throw PIVRecoveryAgreementError.invalidBinding }
              guard key.supportsStandardECDH else { throw PIVRecoveryAgreementError.unsupportedKey }
              // Lookup may take time. Recheck the exact card/key/anchor before
              // enabling one private operation, with no public session open.
              try validate()
              try attempt.check()
              progress?.emit(.authenticating)
              try attempt.check()
              try session.authenticate(key: key)
              try attempt.check()
              progress?.emit(.touchRequired)
              try attempt.check()
              let secret = try session.agree(key: key, peer: peer)
              try attempt.check()
              guard secret.count == 32 else { throw PIVRecoveryAgreementError.invalidResult }
              return secret
            }
            try attempt.check()
            progress?.emit(.hardwareCompleted)
            return secret
          })
      }
      return try attempt.wait()
    }
    return try consume(receiver)
  }

  private final class Scope: @unchecked Sendable {
    private let lock = NSLock()
    private var closed = false
    private var requested = false
    private var attempt: Attempt?
    func claim(_ attempt: Attempt) throws {
      try lock.withLock {
        guard !closed else { throw PIVRecoveryAgreementError.scopeClosed }
        guard !requested else { throw PIVRecoveryAgreementError.alreadyRequested }
        requested = true
        self.attempt = attempt
      }
    }
    func close() {
      let pending = lock.withLock {
        closed = true
        let pending = attempt
        attempt = nil
        return pending
      }
      pending?.stop(.scopeClosed)
    }
  }

  private final class Attempt: @unchecked Sendable {
    let cancellation = PIVRecoveryCancellation()
    private let deadline: DispatchTime
    private let lock = NSLock()
    private let ready = DispatchSemaphore(value: 0)
    private var result: Result<Data, Error>?
    private var stopped: PIVRecoveryAgreementError?
    init(deadline: DispatchTime) { self.deadline = deadline }

    func stop(_ reason: PIVRecoveryAgreementError) {
      let changed = lock.withLock {
        guard stopped == nil else { return false }
        stopped = reason
        result = nil
        return true
      }
      if changed {
        ready.signal()
        cancellation.cancel()
      }
    }
    func check() throws {
      if DispatchTime.now() >= deadline { stop(.deadlineExceeded) }
      if let error = lock.withLock({ stopped }) { throw error }
    }
    func complete(_ value: Result<Data, Error>) {
      let accepted = lock.withLock {
        guard stopped == nil else { return false }
        result = value
        return true
      }
      if accepted { ready.signal() }
    }
    func wait() throws -> Data {
      if ready.wait(timeout: deadline) != .success { stop(.deadlineExceeded) }
      try check()
      return try lock.withLock {
        guard let result else { throw PIVRecoveryAgreementError.unavailable }
        return try result.get()
      }
    }
  }
}

private struct PIVNativeAgreementProvider: PIVRecoveryAgreementProviding {
  func makeSession() -> any PIVRecoveryAgreementSession { PIVNativeAgreementSession() }
}

/// The context and SecKey stay inside one native session. Only the public part
/// is exported. No caller-controlled query, algorithm, reason or retry is used.
private final class PIVNativeAgreementSession: PIVRecoveryAgreementSession, @unchecked Sendable {
  private let context = LAContext()
  private let lock = NSLock()
  private var invalidated = false
  private var requested = false
  private var authenticating = false
  private var approved = false
  private let owner = UUID()
  private let approval = PIVRecoveryAuthenticationReply()
  private let logger = Logger(
    subsystem: Bundle.main.bundleIdentifier ?? "work.tvr.key", category: "PIVAuthentication")

  init() {
    context.interactionNotAllowed = true
    context.localizedReason = "Open the selected Key vault recovery credential"
  }

  func invalidate() {
    let shouldInvalidate = lock.withLock {
      guard !invalidated else { return false }
      invalidated = true
      return true
    }
    if shouldInvalidate {
      approval.invalidate {
        logger.notice("Native authentication context invalidation requested")
        context.invalidate()
        logger.notice("Native authentication context invalidation returned")
      }
    }
  }

  func keys(tokenID: String, publicKey: Data) throws -> [any PIVRecoveryAgreementKey] {
    guard lock.withLock({ !invalidated && !requested }) else {
      throw PIVRecoveryAgreementError.cancelled
    }
    let publicReference = try Self.importPublicKey(publicKey)
    guard let attributes = SecKeyCopyAttributes(publicReference) as? [String: Any],
      let label = attributes[kSecAttrApplicationLabel as String] as? Data
    else { throw PIVRecoveryAgreementError.invalidBinding }
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: tokenID,
      kSecAttrApplicationLabel as String: label,
      kSecUseDataProtectionKeychain as String: true,
      kSecUseAuthenticationContext as String: context,
      kSecMatchLimit as String: kSecMatchLimitAll,
      kSecReturnRef as String: true,
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { return [] }
    guard status == errSecSuccess, let keys = result as? [SecKey] else {
      throw PIVRecoveryAgreementError.unavailable
    }
    // Check all matches, not the first usable one. The framework may allocate
    // its full result first; this is a processing bound, not an allocation cap.
    guard keys.count <= PIVRecoveryTokenReader.maximumCandidates else {
      throw PIVRecoveryTokenError.resourceLimit
    }
    return try keys.map { key in
      guard let attributes = SecKeyCopyAttributes(key) as? [String: Any],
        let actualToken = attributes[kSecAttrTokenID as String] as? String,
        let publicReference = SecKeyCopyPublicKey(key)
      else { throw PIVRecoveryAgreementError.invalidBinding }
      var error: Unmanaged<CFError>?
      defer { if let error { _ = error.takeRetainedValue() } }
      guard let bytes = SecKeyCopyExternalRepresentation(publicReference, &error) as Data?, error == nil else {
        throw PIVRecoveryAgreementError.invalidBinding
      }
      _ = try P256.KeyAgreement.PublicKey(x963Representation: bytes)
      return NativeKey(
        owner: owner, reference: key, tokenID: actualToken, publicKey: bytes,
        isP256PrivateKey:
          attributes[kSecAttrKeyClass as String] as? String == kSecAttrKeyClassPrivate as String
          && attributes[kSecAttrKeyType as String] as? String
            == kSecAttrKeyTypeECSECPrimeRandom as String
          && attributes[kSecAttrKeySizeInBits as String] as? Int == 256,
        supportsStandardECDH: SecKeyIsAlgorithmSupported(
          key, .keyExchange, .ecdhKeyExchangeStandard),
        accessControl: Self.accessControl(attributes[kSecAttrAccessControl as String]))
    }
  }

  func authenticate(key: any PIVRecoveryAgreementKey) throws {
    guard let key = key as? NativeKey, key.owner == owner else {
      throw PIVRecoveryAgreementError.invalidBinding
    }
    guard let accessControl = key.accessControl else {
      throw PIVRecoveryAgreementError.accessControlUnavailable
    }
    try lock.withLock {
      guard !invalidated else { throw PIVRecoveryAgreementError.cancelled }
      guard !authenticating && !requested else { throw PIVRecoveryAgreementError.alreadyRequested }
      authenticating = true
      context.interactionNotAllowed = false
      // Evaluate this key's actual ACL, never a replacement or PIN credential.
      // The callback touches only the reply, so even an inline reply is safe.
      logger.notice("Native access-control evaluation started")
      context.evaluateAccessControl(accessControl, operation: .useKeyKeyExchange,
        localizedReason: "Approve the selected Key vault recovery credential") { [approval, logger] success, error in
          // Fixed labels/booleans and numeric code only; never native text.
          let native = error as NSError?
          let localAuthentication = native?.domain == LAError.errorDomain
          let code = native?.code ?? 0
          logger.notice("Native authentication callback received: success=\(success, privacy: .public), error=\(error != nil, privacy: .public), local-authentication=\(localAuthentication, privacy: .public), code=\(code, privacy: .public)")
          approval.complete(success && error == nil)
        }
    }
    let success = approval.wait()
    try lock.withLock {
      context.interactionNotAllowed = true
      guard !invalidated else { throw PIVRecoveryAgreementError.cancelled }
      guard success else { throw PIVRecoveryAgreementError.authenticationFailed }
      approved = true
    }
  }

  func agree(key: any PIVRecoveryAgreementKey, peer: Data) throws -> Data {
    guard let key = key as? NativeKey, key.owner == owner else {
      throw PIVRecoveryAgreementError.invalidBinding
    }
    let peerReference = try Self.importPublicKey(peer)
    try lock.withLock {
      guard !invalidated else { throw PIVRecoveryAgreementError.cancelled }
      guard !requested else { throw PIVRecoveryAgreementError.alreadyRequested }
      guard approved else { throw PIVRecoveryAgreementError.authenticationFailed }
      requested = true
      // No further PIN prompt is permitted after the separate approval step.
      context.interactionNotAllowed = true
    }
    var error: Unmanaged<CFError>?
    defer { if let error { _ = error.takeRetainedValue() } }
    guard
      let value = SecKeyCopyKeyExchangeResult(
        key.reference, .ecdhKeyExchangeStandard, peerReference, [:] as CFDictionary, &error
      ) as Data?, error == nil
    else { throw PIVRecoveryAgreementError.providerFailure }
    return value
  }

  private static func accessControl(_ value: Any?) -> SecAccessControl? {
    guard let value, CFGetTypeID(value as CFTypeRef) == SecAccessControlGetTypeID() else { return nil }
    return (value as! SecAccessControl)
  }

  private static func importPublicKey(_ bytes: Data) throws -> SecKey {
    _ = try P256.KeyAgreement.PublicKey(x963Representation: bytes)
    var error: Unmanaged<CFError>?
    defer { if let error { _ = error.takeRetainedValue() } }
    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
      kSecAttrKeySizeInBits as String: 256,
    ]
    guard let key = SecKeyCreateWithData(bytes as CFData, attributes as CFDictionary, &error), error == nil else {
      throw PIVRecoveryAgreementError.invalidPeer
    }
    return key
  }

  private struct NativeKey: PIVRecoveryAgreementKey, @unchecked Sendable {
    let owner: UUID
    let reference: SecKey
    let tokenID: String
    let publicKey: Data
    let isP256PrivateKey: Bool
    let supportsStandardECDH: Bool
    let accessControl: SecAccessControl?
  }
}

/// Joins one native authentication callback while retaining the worker's card
/// lease. The enclosing request owns its separate bounded cancellation wait.
final class PIVRecoveryAuthenticationReply: @unchecked Sendable {
  private let lock = NSLock()
  private let ready = DispatchSemaphore(value: 0)
  private var result: Bool?
  private var invalidated = false

  func invalidate(_ invalidateContext: () -> Void) {
    let first = lock.withLock {
      guard !invalidated else { return false }
      invalidated = true
      return true
    }
    // Requesting cancellation is not observing native completion. Only the
    // framework callback may release wait() and therefore the operation lease.
    if first { invalidateContext() }
  }

  func complete(_ success: Bool) {
    let first = lock.withLock {
      guard result == nil else { return false }
      result = success && !invalidated
      return true
    }
    if first { ready.signal() }
  }

  /// One native worker waits; duplicate replies cannot release another waiter.
  func wait() -> Bool {
    ready.wait()
    return lock.withLock { result == true && !invalidated }
  }
}
