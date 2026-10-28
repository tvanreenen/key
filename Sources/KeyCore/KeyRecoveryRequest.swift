import Foundation

/// Presentation only. These stages never authorize an operation or establish
/// completion of registration/restore; only the service's final reply does.
public enum KeyRecoveryStage: String, Codable, Sendable, CaseIterable {
  case authenticating, touchRequired, hardwareCompleted
  case preparingRestoredVault, openingSavedPreparation, preparationSaved
  case publishingRestoredVault, activatingRestoredVault

  static let hardwareStages: [Self] = [.authenticating, .touchRequired, .hardwareCompleted]

  /// A bounded acyclic presentation sequence shared by sender and receiver.
  /// Registration ends after hardware approval; restore/resume take distinct
  /// branches before converging on complete saved preparation.
  func canFollow(_ previous: Self?) -> Bool {
    switch (previous, self) {
    case (nil, .authenticating), (.authenticating?, .touchRequired),
      (.touchRequired?, .hardwareCompleted),
      (.hardwareCompleted?, .preparingRestoredVault),
      (.hardwareCompleted?, .openingSavedPreparation),
      (.preparingRestoredVault?, .preparationSaved),
      (.openingSavedPreparation?, .preparationSaved),
      (.preparationSaved?, .publishingRestoredVault),
      (.preparationSaved?, .activatingRestoredVault),
      (.publishingRestoredVault?, .activatingRestoredVault): true
    default: false
    }
  }

  public var instruction: String {
    switch self {
    case .authenticating: "Approve the recovery key in the macOS dialog. Enter your PIN only there."
    case .touchRequired: "Touch your flashing YubiKey's metal contact now."
    case .hardwareCompleted: "Hardware approval completed. Finishing the recovery request."
    case .preparingRestoredVault: "Mac approval: Prepare restored vault on this Mac. Complete recovery preparation has not been saved yet."
    case .openingSavedPreparation: "Mac approval: Reopen saved restore preparation on this Mac."
    case .preparationSaved: "Complete encrypted recovery preparation is saved. An interrupted restore can now be explicitly resumed."
    case .publishingRestoredVault: "Mac approval: Publish prepared restored vault. This uses the saved preparation."
    case .activatingRestoredVault: "Finishing restored-vault verification and activation. Further Mac approval may be required."
    }
  }
}

public struct KeyRecoveryProgressEvent: Codable, Sendable {
  public let operationID: UUID
  public let stage: KeyRecoveryStage
}

/// One connection/request's finite progress channel. Callbacks run outside its
/// lock; consumers must close their own presentation before returning a reply.
public final class KeyRecoveryProgress: @unchecked Sendable {
  public let operationID: UUID
  private let lock = NSLock()
  private var previous: KeyRecoveryStage?
  private var closed = false
  private let receive: @Sendable (KeyRecoveryProgressEvent) -> Void

  public init(operationID: UUID, receive: @escaping @Sendable (KeyRecoveryProgressEvent) -> Void) {
    self.operationID = operationID
    self.receive = receive
  }

  func emit(_ stage: KeyRecoveryStage) {
    let accepted = lock.withLock {
      guard !closed, stage.canFollow(previous) else { return false }
      previous = stage
      return true
    }
    if accepted { receive(.init(operationID: operationID, stage: stage)) }
  }

  public func close() { lock.withLock { closed = true } }
}

/// Explicit configured key change; no token selector or credential is involved.
public enum KeyRecoveryRotationRequest: Codable, Equatable, Sendable {
  case rotate
  case resume(operationID: String)

  func validate() throws {
    if case .resume(let operation) = self,
      (try? VaultTransactionOperationID(validating: operation)) == nil
    {
      throw AppError.operationRefused(
        "Rotation resume requires the complete original operation ID.")
    }
  }
}

public enum KeyRecoveryRotationResult: Codable, Equatable, Sendable {
  case completed(vaultID: String, manifestDigest: String, cleanupPending: Bool)
  case abandoned(vaultID: String)
}

/// Configured-vault setup requests carry public selectors only. They never
/// contain a PIN, management credential, vault key or native approval.
public enum KeyRecoveryRegistrationRequest: Codable, Equatable, Sendable {
  case status
  case pending
  case prepare(tokenID: String, recipientID: String)
  case resumeExport(tokenID: String, recipientID: String)
  case finish(tokenID: String, recipientID: String)
  case adopt
  case resumeAdoption(operationID: String)

  var changesCheckpoint: Bool {
    switch self {
    case .finish, .adopt, .resumeAdoption: true
    default: false
    }
  }

  func validate() throws {
    switch self {
    case .status, .pending, .adopt: break
    case .resumeAdoption(let operation):
      guard (try? VaultTransactionOperationID(validating: operation)) != nil else {
        throw AppError.operationRefused(
          "Adoption resume requires the complete original operation ID.")
      }
    case .prepare(let token, let recipient), .resumeExport(let token, let recipient),
      .finish(let token, let recipient):
      guard !token.isEmpty, token.utf8.count <= 1_024,
        !token.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
        (try? V3RecoveryRecipientID(rawValue: recipient)) != nil
      else {
        throw AppError.operationRefused(
          "Registration requires one complete token ID and its complete recovery recipient ID.")
      }
    }
  }
}

/// Public setup output. Exported anchor bytes contain commitments, not secrets
/// or approval. Only a later authenticated finish can activate registration.
public enum KeyRecoveryRegistrationResult: Codable, Equatable, Sendable {
  public struct PendingOperation: Codable, Equatable, Sendable {
    public enum Namespace: String, Codable, Sendable { case transaction, registration, adoption }
    public let namespace: Namespace
    public let operationID: String
  }
  public enum State: String, Codable, Equatable, Sendable {
    case unregistered, registered, pending, attentionRequired
  }
  case status(state: State, vaultID: String, recipients: [String], activationCommitted: Bool)
  case export(operationID: String, vaultID: String, recipientID: String, anchor: String)
  case completed(vaultID: String, manifestDigest: String, cleanupPending: Bool)
  case pending(vaultID: String, operations: [PendingOperation])
}

/// Public selectors and locations only. Credentials and recovered keys never
/// cross the service protocol. A selector is not a native observation or consent.
public enum KeyRecoveryRequest: Codable, Equatable, Sendable {
  case restore(
    source: String, destination: String, tokenID: String, recipientID: String,
    deviceName: String)
  case resume(
    source: String, destination: String, tokenID: String, recipientID: String)
  case abandon(
    source: String, destination: String, sourceVaultID: String, operationID: String)

  static let maximumDurationSeconds = 90

  var isInitialRestore: Bool {
    if case .restore = self { true } else { false }
  }

  var isAbandonment: Bool {
    if case .abandon = self { true } else { false }
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
    case .abandon(let from, let to, let vault, let operation):
      guard [from, to].allSatisfy({ $0.hasPrefix("/") && $0.utf8.count <= 4_096 && !$0.utf8.contains(0) }),
        isValidV3UUID(vault), (try? VaultTransactionOperationID(validating: operation)) != nil
      else {
        throw AppError.operationRefused("Abandon requires absolute original source/destination paths and complete source vault and operation IDs.")
      }
      return
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
  let progress: KeyRecoveryProgress?
  private let ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket

  init(authentication: V3DeviceWrappedVaultKeySessionStore, deadline: DispatchTime,
       progress: KeyRecoveryProgress? = nil) {
    self.authentication = authentication
    self.deadline = deadline
    self.progress = progress
    ticket = authentication.beginAuthentication()
  }

  func requireCurrent() throws {
    guard !cancellation.isCancelled else { throw PIVRecoveryAgreementError.cancelled }
    guard DispatchTime.now() < deadline else { throw PIVRecoveryAgreementError.deadlineExceeded }
    try authentication.requireCurrent(ticket)
  }
}

/// Recovery dispatch and durable setup admission are installed together. A
/// host cannot enable recovery with only the process-local uncertainty guard.
struct KeyRecoveryCapability {
  let ownership: any V3RecoveryRestoreOwnershipChecking
  let recover: (KeyRecoveryRequest, KeyRecoveryRequestScope) throws -> KeyServiceResponse

  func requireNoPendingRestore() throws {
    let pending: Bool
    do {
      pending = try ownership.hasPendingRestore()
    } catch {
      throw AppError.operationRefused(
        "Could not inspect saved recovery ownership. No setup or runtime selection was authorized. Leave the existing state intact and explicitly resume or inspect it. \(error.localizedDescription)"
      )
    }
    guard !pending else {
      throw AppError.operationRefused(
        "A saved recovery attempt requires explicit resume or inspection. Leave its records and folders intact; do not initialize, enroll or change vault configuration."
      )
    }
  }
}
