import Foundation

/// Public selectors and locations only. Credentials and recovered keys never
/// cross the service protocol. A selector is not a native observation or consent.
public enum KeyRecoveryRequest: Codable, Equatable, Sendable {
  case restore(
    source: String, destination: String, tokenID: String, recipientID: String,
    deviceName: String)
  case resume(
    source: String, destination: String, tokenID: String, recipientID: String)

  static let maximumDurationSeconds = 90

  var isInitialRestore: Bool {
    if case .restore = self { true } else { false }
  }

  func validate() throws {
    let source: String
    let destination: String
    let tokenID: String
    let recipientID: String
    switch self {
    case .restore(let from, let to, let token, let digest, let name):
      guard isValidV3DeviceDisplayName(name) else { throw invalidRequest() }
      (source, destination, tokenID, recipientID) = (from, to, token, digest)
    case .resume(let from, let to, let token, let digest):
      (source, destination, tokenID, recipientID) = (from, to, token, digest)
    }
    guard
      [source, destination].allSatisfy({
        $0.hasPrefix("/") && $0.utf8.count <= 4_096 && !$0.utf8.contains(0)
      }), !tokenID.isEmpty, tokenID.utf8.count <= 1_024, !tokenID.utf8.contains(0),
      (try? V3RecoveryRecipientID(rawValue: recipientID)) != nil
    else { throw invalidRequest() }
  }

  private func invalidRequest() -> AppError {
    .operationRefused(
      "Recovery requires absolute source/destination paths, an explicit token and its complete recovery recipient ID."
    )
  }
}

/// One authenticated XPC connection's lifetime. Disconnect cancellation is
/// permanent for that connection and never authorizes another attempt.
public final class KeyServiceConnection: @unchecked Sendable {
  private let lock = NSLock()
  private var closed = false
  private var requests: [UUID: PIVRecoveryCancellation] = [:]

  public init() {}

  public func invalidate() {
    let pending: [PIVRecoveryCancellation] = lock.withLock {
      closed = true
      let pending = Array(requests.values)
      requests.removeAll()
      return pending
    }
    for request in pending { request.cancel() }
  }

  func register(_ scope: KeyRecoveryRequestScope) {
    let cancel = lock.withLock {
      guard !closed else { return true }
      requests[scope.id] = scope.cancellation
      return false
    }
    if cancel { scope.cancellation.cancel() }
  }

  func remove(_ scope: KeyRecoveryRequestScope) {
    _ = lock.withLock { requests.removeValue(forKey: scope.id) }
  }
}

/// Captured before queue admission, not a retained authentication capability.
/// The composed service must use these exact cancellation/generation/deadline
/// dependencies. No recovered key is installed in this authentication store.
struct KeyRecoveryRequestScope: Sendable {
  let id = UUID()
  let cancellation = PIVRecoveryCancellation()
  let authentication: V3DeviceWrappedVaultKeySessionStore
  let deadline: DispatchTime
  private let ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket

  init(authentication: V3DeviceWrappedVaultKeySessionStore, deadline: DispatchTime) {
    self.authentication = authentication
    self.deadline = deadline
    ticket = authentication.beginAuthentication()
  }

  func requireCurrent() throws {
    guard !cancellation.isCancelled else { throw PIVRecoveryAgreementError.cancelled }
    guard DispatchTime.now() < deadline else { throw PIVRecoveryAgreementError.deadlineExceeded }
    try authentication.requireCurrent(ticket)
  }
}
