import Foundation

/// Local, authenticated roster status, not a current hardware qualification.
/// No result grants publication, resume, setup or runtime admission authority.
enum V3RecoveryRegistrationStatus: Equatable, Sendable {
  case unregistered(checkpoint: V3ManifestCheckpoint)
  case registered(checkpoint: V3ManifestCheckpoint, recipients: [V3RecoveryRecipientID])
  case pending(checkpoint: V3ManifestCheckpoint, activationCommitted: Bool)
  case attentionRequired
}

/// Inspect the configured checkpoint using its already authenticated helper key.
/// Kept separate from registration so inspection has no identity, token reader,
/// agreement or writer dependency. It never authenticates by opening a wrapper,
/// repairs ownership, selects a provider head or adopts an unowned bundle.
struct V3RecoveryRegistrationStatusService: Sendable {
  private let vaultID: String
  private let owner: any VaultTransactionMutationOwning
  private let checkpoints: any V3ManifestCheckpointStoring
  private let ownership: any V3ImmutableTransactionRecoveryAnchorStoring
  private let otherOwnership: [any V3ImmutableTransactionRecoveryAnchorStoring]
  private let journal: V3RecoveryRegistrationJournal
  private let repository: V3RecoveryRegistrationRepository

  init(
    vaultID: String, mutationOwner: any VaultTransactionMutationOwning,
    source: any V3ImmutableObjectReading & V3RecoveryRegistrationBundleStoring,
    checkpointStore: any V3ManifestCheckpointStoring,
    registrationOwnershipStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    transactionOwnershipStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    adoptionOwnershipStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    limits: V3ManifestRepositoryLimits = .standard
  ) {
    self.vaultID = vaultID
    owner = mutationOwner
    checkpoints = checkpointStore
    ownership = registrationOwnershipStore
    otherOwnership = [transactionOwnershipStore, adoptionOwnershipStore]
    journal = V3RecoveryRegistrationJournal(
      bundleStore: source, ownershipStore: registrationOwnershipStore, limits: limits)
    repository = V3RecoveryRegistrationRepository(source: source, limits: limits)
  }

  /// Inspection failures are attention-required, never absence of protection.
  /// The caller retains responsibility for connection/lock/deadline admission.
  /// Serializing with registration prevents an intermediate local phase from
  /// being presented as a completed status. No operation identifier is persisted.
  func status(currentVaultKey: Data) throws -> V3RecoveryRegistrationStatus {
    try owner.perform(.registerRecoveryRecipient) { _ in
      do { return try inspect(currentVaultKey: currentVaultKey) } catch {
        return .attentionRequired
      }
    }
  }

  private func inspect(currentVaultKey: Data) throws -> V3RecoveryRegistrationStatus {
    try requireNoOtherPending()
    let checkpoint = try loadCheckpoint()
    let ownershipBytes = try ownership.loadRecoveryAnchor(vaultID: vaultID)
    let preparation = try journal.loadPending(vaultID: vaultID)
    guard (ownershipBytes == nil) == (preparation == nil) else {
      throw V3RecoveryRegistrationServiceError.pendingCandidateChanged
    }

    let activationCommitted = preparation.map { $0.candidate.digest == checkpoint.envelopeDigest }
    if let preparation, activationCommitted != true {
      guard preparation.intent.expectedCheckpoint == checkpoint else {
        throw V3RecoveryRegistrationServiceError.checkpointChanged
      }
      // A parsed provider preparation is not evidence of an authorized attempt.
      // Authenticate its exact intent before reporting pending against this floor.
      try preparation.intent.authenticate(currentVaultKey: currentVaultKey)
    }
    let candidate = activationCommitted == true ? nil : preparation
    let observed = try repository.observe(
      checkpoint: checkpoint, currentVaultKey: currentVaultKey, candidate: candidate)
    if let preparation {
      if activationCommitted == true {
        guard observed.base == preparation.candidate else {
          throw V3RecoveryRegistrationServiceError.invalidPublishedObject
        }
      } else {
        try V3RecoveryEpochBoundary().verifyBoundary(preparation.candidate, parent: observed.base)
      }
    }

    try requireUnchanged(checkpoint: checkpoint, ownershipBytes: ownershipBytes)
    guard try journal.loadPending(vaultID: vaultID) == preparation,
      try repository.observe(
        checkpoint: checkpoint, currentVaultKey: currentVaultKey, candidate: candidate) == observed,
      try journal.loadPending(vaultID: vaultID) == preparation
    else { throw V3RecoveryValidationError.sourceChanged }
    try requireUnchanged(checkpoint: checkpoint, ownershipBytes: ownershipBytes)

    if let activationCommitted {
      // Pending is not a claim that the encrypted candidate can be completed or
      // that an external anchor write succeeded. Finish must revalidate both.
      return .pending(checkpoint: checkpoint, activationCommitted: activationCommitted)
    }
    let recipients = observed.base.body.recovery.recipients
      .filter { $0.status == .active }.map(\.recipientID)
    return recipients.isEmpty
      ? .unregistered(checkpoint: checkpoint)
      : .registered(checkpoint: checkpoint, recipients: recipients)
  }

  private func loadCheckpoint() throws -> V3ManifestCheckpoint {
    guard let bytes = try checkpoints.loadCheckpoint(vaultID: vaultID), bytes.count <= 1_024,
      let checkpoint = try? V3ManifestCheckpoint(canonicalBytes: bytes),
      checkpoint.vaultID == vaultID
    else { throw V3RecoveryRegistrationServiceError.checkpointUnavailable }
    return checkpoint
  }

  private func requireUnchanged(checkpoint: V3ManifestCheckpoint, ownershipBytes: Data?) throws {
    try requireNoOtherPending()
    guard try loadCheckpoint() == checkpoint,
      try ownership.loadRecoveryAnchor(vaultID: vaultID) == ownershipBytes
    else { throw V3RecoveryRegistrationServiceError.pendingCandidateChanged }
    try requireNoOtherPending()
  }

  private func requireNoOtherPending() throws {
    for store in otherOwnership where try store.loadRecoveryAnchor(vaultID: vaultID) != nil {
      throw V3RecoveryRegistrationServiceError.otherMutationPending
    }
  }
}
