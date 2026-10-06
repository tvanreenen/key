import CryptoKit
import Foundation

/// Internal, explicitly requested unchanged-roster rotation from an unlocked
/// session. The helper owns serialization and supplies one operation ID. This
/// service never provisions a token, opens a recovery credential or resumes a
/// different pending operation. Cold-start rotation routing is separate work.
struct V3RecoveryKeyRotationService: Sendable {
  typealias Identity = any V3EnrollmentMessageSigning & V3DeviceWrappedVaultKeyUnwrapping

  private let vaultID: String
  private let identity: Identity
  private let session: V3DeviceWrappedVaultKeySessionStore
  private let store: any V3TransactionArtifactStore
  private let checkpoints: any V3ManifestCheckpointStoring
  private let ownership: any V3ImmutableTransactionRecoveryAnchorStoring
  private let registration: any V3ImmutableTransactionRecoveryAnchorStoring
  private let adoption: any V3ImmutableTransactionRecoveryAnchorStoring
  private let cache: any V3CheckpointManifestCaching
  private let limits: V3ManifestRepositoryLimits
  private let phaseObserver: any V3ImmutableTransactionPhaseObserving

  init(
    vaultID: String, identity: Identity, session: V3DeviceWrappedVaultKeySessionStore,
    objectStore: any V3TransactionArtifactStore,
    checkpointStore: any V3ManifestCheckpointStoring,
    recoveryAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    registrationAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    adoptionAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    cache: any V3CheckpointManifestCaching, limits: V3ManifestRepositoryLimits = .standard,
    phaseObserver: any V3ImmutableTransactionPhaseObserving =
      V3NoopContentTransactionPhaseObserver()
  ) {
    self.vaultID = vaultID
    self.identity = identity
    self.session = session
    store = objectStore
    checkpoints = checkpointStore
    ownership = recoveryAnchorStore
    registration = registrationAnchorStore
    adoption = adoptionAnchorStore
    self.cache = cache
    self.limits = limits
    self.phaseObserver = phaseObserver
  }

  /// Authenticated review data only. This neither saves approval nor signs,
  /// generates a key or reserves durable work. Execution rechecks the checkpoint.
  func prepare() throws -> V3RecoveryKeyRotationCommit {
    try loadCurrent().commit
  }

  func rotate(
    expectedCheckpoint: V3ManifestCheckpoint, operationID: VaultTransactionOperationID
  ) throws -> V3RecoveryKeyRotationCommit {
    do {
      guard expectedCheckpoint.vaultID == vaultID else {
        throw V3RecoveryKeyRotationError.invalidCandidate
      }
      try requireCheckpoint(expectedCheckpoint)
      let base = try loadCurrent()
      guard base.commit.checkpoint == expectedCheckpoint else {
        throw V3ImmutableTransactionError.expectedHeadsChanged
      }
      let nextKey = try freshKey(excluding: base.commit.envelope.body.fields.keyID)
      let candidate = try V3RecoveryKeyRotationBuilder(limits: limits).build(
        checkpoint: expectedCheckpoint, parent: base.commit.envelope,
        currentEntries: base.source.entries, currentVaultKey: base.key, nextVaultKey: nextKey,
        owner: identity, reason: "Change the vault's encryption key without changing access.")
      // A signer may present authentication UI. Recheck before another private
      // operation, and do not continue from a session locked during that UI.
      try requireNoPending()
      try requireCheckpoint(expectedCheckpoint)
      let fresh = try objects.observe(
        checkpoint: expectedCheckpoint, expectedBase: base.commit.envelope.canonicalBytes)
      guard fresh == base.source,
        try session.load(vaultID: vaultID, keyID: base.commit.envelope.body.fields.keyID)
          == base.key
      else { throw V3RecoveryValidationError.sourceChanged }

      let commit = try V3RecoveryKeyRotationPublisher(
        mutationOwner: DirectVaultTransactionMutationOwner(operationID: operationID),
        objectStore: store, checkpointStore: checkpoints, recoveryAnchorStore: ownership,
        registrationAnchorStore: registration, adoptionAnchorStore: adoption, cache: cache,
        limits: limits, phaseObserver: phaseObserver
      ).publish(
        candidate, currentVaultKey: base.key, nextVaultKey: nextKey, identity: identity,
        reason: "Verify this Mac can open the changed vault encryption key.")

      try requireNoAuthorityWork()
      try requireCheckpoint(commit.checkpoint)
      try V3RecoveryEpochBoundary().verifyCurrentAuthentication(commit.envelope, vaultKey: nextKey)
      let current = try objects.observe(
        checkpoint: commit.checkpoint, expectedBase: commit.envelope.canonicalBytes)
      _ = try V3EntrySnapshotValidator(limits: limits).plaintexts(
        fields: commit.envelope.body.fields, entries: current.entries, vaultKey: nextKey)
      try requireNoAuthorityWork()
      try requireCheckpoint(commit.checkpoint)
      try session.replace(
        nextKey, vaultID: vaultID, keyID: commit.envelope.body.fields.keyID,
        expectedKeyID: base.commit.envelope.body.fields.keyID)
      return commit
    } catch {
      // Failure is not proof that commitment failed. Retain the old session only
      // if its reviewed checkpoint is still exact. Never install from an error
      // path or erase durable intent here; restart reconciliation owns that work.
      if (try? checkpoints.loadCheckpoint(vaultID: vaultID)) != expectedCheckpoint.canonicalBytes {
        session.invalidate()
      }
      throw error
    }
  }

  private struct Base {
    let commit: V3RecoveryKeyRotationCommit
    let key: Data
    let source: V3ExactTransitionRepositoryState
  }
  private var objects: V3ExactTransitionRepository { .init(source: store, limits: limits) }

  private func loadCurrent() throws -> Base {
    try requireNoPending()
    guard isValidV3UUID(vaultID), identity.vaultID == vaultID,
      let bytes = try checkpoints.loadCheckpoint(vaultID: vaultID), bytes.count <= 1_024,
      let checkpoint = try? V3ManifestCheckpoint(canonicalBytes: bytes),
      checkpoint.vaultID == vaultID
    else { throw V3RecoveryKeyRotationError.invalidOwner }
    let manifest = try objects.readManifest(checkpoint.envelopeDigest)
    let envelope = try V3RecoveryManifestCodec().parseEnvelope(manifest)
    guard
      envelope.body.fields.devices.contains(
        .init(identity: identity.publicIdentity, status: .active))
    else { throw V3RecoveryKeyRotationError.invalidOwner }
    let key = try session.load(vaultID: vaultID, keyID: envelope.body.fields.keyID)
    try V3RecoveryContentMutationValidator(limits: limits).validateParent(
      envelope, checkpoint: checkpoint, vaultKey: key)
    let source = try objects.observe(checkpoint: checkpoint, expectedBase: manifest)
    _ = try V3EntrySnapshotValidator(limits: limits).plaintexts(
      fields: envelope.body.fields, entries: source.entries, vaultKey: key)
    try requireNoPending()
    try requireCheckpoint(checkpoint)
    return .init(
      commit: .init(checkpoint: checkpoint, envelope: envelope), key: key, source: source)
  }

  private func freshKey(excluding currentID: V3VaultKeyID) throws -> Data {
    for _ in 0..<16 {
      let key = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
      if try V3VaultKeyID.derive(vaultKey: key, vaultID: vaultID) != currentID { return key }
    }
    throw V3RecoveryKeyRotationError.invalidCandidate
  }
  private func requireCheckpoint(_ checkpoint: V3ManifestCheckpoint) throws {
    guard try checkpoints.loadCheckpoint(vaultID: vaultID) == checkpoint.canonicalBytes else {
      throw V3ImmutableTransactionError.expectedHeadsChanged
    }
  }
  private func requireNoAuthorityWork() throws {
    guard try registration.loadRecoveryAnchor(vaultID: vaultID) == nil,
      try adoption.loadRecoveryAnchor(vaultID: vaultID) == nil
    else { throw V3RecoveryContentPublicationError.otherMutationPending }
  }
  private func requireNoPending() throws {
    try requireNoAuthorityWork()
    if let bytes = try ownership.loadRecoveryAnchor(vaultID: vaultID) {
      guard bytes.count <= 1_024,
        let anchor = try? V3ImmutableTransactionRecoveryAnchor(canonicalBytes: bytes),
        anchor.vaultID == vaultID
      else {
        throw V3ImmutableTransactionRecoveryError.invalidRecoveryAnchor(vaultID: vaultID)
      }
      throw V3ImmutableTransactionRecoveryError.interruptedTransactionPending(
        operationID: anchor.operationID.rawValue)
    }
  }
}
