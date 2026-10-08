import CryptoKit
import Foundation

struct V3RecoveryKeyRotationCommit: Sendable {
  let checkpoint: V3ManifestCheckpoint
  let envelope: V3RecoveryManifestEnvelope
}

/// Internal unchanged-roster publication only. The helper supplies scoped keys;
/// they are never persisted in the intent, passed over CLI/XPC or obtained from
/// a recovery token here. Native/session routing remains a service responsibility.
struct V3RecoveryKeyRotationPublisher: Sendable {
  private let mutationOwner: any VaultTransactionMutationOwning
  private let objectStore: any V3TransactionArtifactStore
  private let checkpointStore: any V3ManifestCheckpointStoring
  private let recoveryAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring
  private let registrationAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring
  private let adoptionAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring
  private let cache: any V3CheckpointManifestCaching
  private let limits: V3ManifestRepositoryLimits
  private let phaseObserver: any V3ImmutableTransactionPhaseObserving

  init(
    mutationOwner: any VaultTransactionMutationOwning, objectStore: any V3TransactionArtifactStore,
    checkpointStore: any V3ManifestCheckpointStoring,
    recoveryAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    registrationAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    adoptionAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    cache: any V3CheckpointManifestCaching, limits: V3ManifestRepositoryLimits = .standard,
    phaseObserver: any V3ImmutableTransactionPhaseObserving =
      V3NoopContentTransactionPhaseObserver()
  ) {
    self.mutationOwner = mutationOwner
    self.objectStore = objectStore
    self.checkpointStore = checkpointStore
    self.recoveryAnchorStore = recoveryAnchorStore
    self.registrationAnchorStore = registrationAnchorStore
    self.adoptionAnchorStore = adoptionAnchorStore
    self.cache = cache
    self.limits = limits
    self.phaseObserver = phaseObserver
  }

  func publish(
    _ candidate: V3RecoveryKeyRotationCandidate, currentVaultKey: Data, nextVaultKey: Data,
    identity: any V3DeviceWrappedVaultKeyUnwrapping, reason: String
  ) throws -> V3RecoveryKeyRotationCommit {
    try mutationOwner.perform(.rotateVaultKey) { context in
      guard identity.vaultID == candidate.expectedCheckpoint.vaultID, !reason.isEmpty else {
        throw V3RecoveryKeyRotationError.invalidOwner
      }
      let validator = validator(
        currentVaultKey: currentVaultKey, expectedOwner: identity.publicIdentity)
      let input = V3ContentTransactionInput(
        kind: .rotateVaultKey, expectedCheckpoint: candidate.expectedCheckpoint,
        manifestData: candidate.envelope.canonicalBytes, manifestDigest: candidate.envelope.digest,
        stagedEntries: candidate.stagedEntries)
      try validator.requireAvailable(vaultID: identity.vaultID)
      try requireFreshStart(candidate.expectedCheckpoint)
      let checked = try validator.validate(input, vaultKey: nextVaultKey, alreadyCommitted: false)
      guard checked.envelope == candidate.envelope else {
        throw V3RecoveryKeyRotationError.invalidCandidate
      }
      try requireFreshStart(candidate.expectedCheckpoint)
      try V3RecoveryEpochSnapshotValidator(limits: limits).validateLocalWrapper(
        checked.envelope, nextVaultKey: nextVaultKey, identity: identity, reason: reason)
      // Private-operation cancellation never arms an intent. Recheck everything
      // that could have changed while authentication was being presented.
      try validator.recheck(
        input, validated: checked, vaultKey: nextVaultKey, alreadyCommitted: false)
      try requireFreshStart(candidate.expectedCheckpoint)
      let result = try publisher(validator, operationID: context.operationID).publish(
        input, vaultKey: nextVaultKey)
      return V3RecoveryKeyRotationCommit(
        checkpoint: try .init(vaultID: identity.vaultID, envelopeDigest: result.envelope.digest),
        envelope: result.envelope)
    }
  }

  /// Before local commitment, both keys and complete snapshots are required.
  /// After commitment, exact pinned current objects suffice for cleanup; no old
  /// ciphertext or old key is needed. This never re-signs or constructs an epoch.
  func recoverInterruptedTransaction(
    vaultID: String, currentVaultKey: Data?, nextVaultKey: Data,
    expectedOwner: V3EnrollmentDeviceIdentity, expectedAnchor: Data? = nil
  ) throws -> V3ImmutableTransactionRecoveryOutcome {
    try mutationOwner.perform(.recoverInterruptedTransaction) { context in
      try publisher(
        validator(currentVaultKey: currentVaultKey, expectedOwner: expectedOwner),
        operationID: context.operationID
      ).recoverInterruptedTransaction(
        vaultID: vaultID, vaultKey: nextVaultKey, expectedAnchor: expectedAnchor)
    }
  }

  /// Select exact pending ciphertext and safely abandon incomplete work before
  /// the service requests native authentication. This establishes no authority.
  func prepareInterruptedTransaction(
    vaultID: String, expectedOwner: V3EnrollmentDeviceIdentity, expectedAnchor: Data? = nil
  ) throws -> V3ContentTransactionRecoveryPreparation {
    try mutationOwner.perform(.recoverInterruptedTransaction) { context in
      try publisher(
        validator(currentVaultKey: nil, expectedOwner: expectedOwner),
        operationID: context.operationID
      ).prepareInterruptedTransaction(vaultID: vaultID, expectedAnchor: expectedAnchor)
    }
  }

  private func requireFreshStart(_ checkpoint: V3ManifestCheckpoint) throws {
    if let bytes = try recoveryAnchorStore.loadRecoveryAnchor(vaultID: checkpoint.vaultID) {
      guard let anchor = try? V3ImmutableTransactionRecoveryAnchor(canonicalBytes: bytes),
        anchor.vaultID == checkpoint.vaultID
      else {
        throw V3ImmutableTransactionRecoveryError.invalidRecoveryAnchor(vaultID: checkpoint.vaultID)
      }
      throw V3ImmutableTransactionRecoveryError.interruptedTransactionPending(
        operationID: anchor.operationID.rawValue)
    }
    guard
      try checkpointStore.loadCheckpoint(vaultID: checkpoint.vaultID) == checkpoint.canonicalBytes
    else { throw V3ImmutableTransactionError.expectedHeadsChanged }
  }

  private func validator(currentVaultKey: Data?, expectedOwner: V3EnrollmentDeviceIdentity)
    -> V3RecoveryKeyRotationTransactionValidator
  {
    .init(
      objectStore: objectStore, registrationAnchorStore: registrationAnchorStore,
      adoptionAnchorStore: adoptionAnchorStore, currentVaultKey: currentVaultKey,
      expectedOwner: expectedOwner, limits: limits)
  }

  private func publisher(
    _ validator: V3RecoveryKeyRotationTransactionValidator, operationID: VaultTransactionOperationID
  ) -> V3ContentTransactionPublisher<V3RecoveryKeyRotationTransactionValidator> {
    .init(
      mutationOwner: DirectVaultTransactionMutationOwner(operationID: operationID),
      objectStore: objectStore, checkpointStore: checkpointStore,
      recoveryAnchorStore: recoveryAnchorStore, cache: cache, validator: validator,
      limits: limits, phaseObserver: phaseObserver)
  }
}

/// Reuses the durable transaction kernel, not ordinary content semantics. This
/// validator accepts only unchanged-roster rotations. Other lifecycle approvals
/// and the shipping profile-2 validators cannot be inferred from this intent.
struct V3RecoveryKeyRotationTransactionValidator: V3ContentTransactionValidating {
  let objectStore: any V3TransactionArtifactStore
  let registrationAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring
  let adoptionAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring
  let currentVaultKey: Data?
  let expectedOwner: V3EnrollmentDeviceIdentity
  let limits: V3ManifestRepositoryLimits
  private var objects: V3ExactTransitionRepository { .init(source: objectStore, limits: limits) }
  private var snapshots: V3EntrySnapshotValidator { .init(limits: limits) }

  func requireAvailable(vaultID: String) throws {
    for store in [registrationAnchorStore, adoptionAnchorStore] {
      guard try store.loadRecoveryAnchor(vaultID: vaultID) == nil else {
        throw V3RecoveryContentPublicationError.otherMutationPending
      }
    }
  }

  func keyID(manifestData: Data) throws -> V3VaultKeyID {
    try V3RecoveryManifestCodec().parseEnvelope(manifestData).body.fields.keyID
  }

  func validateRecoveryIntent(_ intent: V3ImmutableTransactionRecoveryIntent) throws {
    guard intent.kind == .rotateVaultKey,
      intent.expectedHeads == [intent.expectedCheckpoint.envelopeDigest],
      intent.enrollmentTranscriptDigest == nil, intent.recoveryMergeResolutions == nil
    else {
      throw V3ImmutableTransactionRecoveryError.invalidIntent(
        operationID: intent.operationID.rawValue)
    }
  }

  func validate(
    _ input: V3ContentTransactionInput, vaultKey: Data, alreadyCommitted: Bool
  ) throws -> V3RecoveryValidatedContentTransaction {
    try requireAvailable(vaultID: input.expectedCheckpoint.vaultID)
    guard input.kind == .rotateVaultKey, input.recoveryMerge == nil,
      input.manifestData.count <= limits.maximumManifestBytes,
      input.manifestDigest.count == 32,
      Data(SHA256.hash(data: input.manifestData)) == input.manifestDigest,
      input.stagedEntries.count <= limits.maximumReferencedEntryObjects
    else { throw V3RecoveryKeyRotationError.invalidCandidate }
    let envelope = try V3RecoveryManifestCodec().parseEnvelope(input.manifestData)
    guard envelope.body.fields.vaultID == input.expectedCheckpoint.vaultID,
      envelope.parents == [input.expectedCheckpoint.envelopeDigest],
      envelope.authorizations.map(\.signerDeviceID) == [expectedOwner.deviceID],
      envelope.body.fields.devices.contains(.init(identity: expectedOwner, status: .active))
    else { throw V3RecoveryKeyRotationError.invalidCandidate }
    let staged = try snapshots.entryMap(input.stagedEntries)
    let source: V3ExactTransitionRepositoryState
    if alreadyCommitted {
      try V3RecoveryEpochBoundary().verifyCurrentAuthentication(envelope, vaultKey: vaultKey)
      source = try objects.observe(
        checkpoint: .init(
          vaultID: input.expectedCheckpoint.vaultID, envelopeDigest: input.manifestDigest),
        expectedBase: input.manifestData)
      _ = try snapshots.plaintexts(
        fields: envelope.body.fields, entries: source.entries, vaultKey: vaultKey)
      guard staged == source.entries else { throw V3RecoveryKeyRotationError.invalidCandidate }
    } else {
      let parentBytes = try objects.readManifest(input.expectedCheckpoint.envelopeDigest)
      let parent = try V3RecoveryManifestCodec().parseEnvelope(parentBytes)
      guard let currentVaultKey else {
        throw V3ImmutableTransactionRecoveryError.vaultKeyUnavailable(
          keyID: parent.body.fields.keyID.rawValue)
      }
      try V3RecoveryContentMutationValidator(limits: limits).validateParent(
        parent, checkpoint: input.expectedCheckpoint, vaultKey: currentVaultKey)
      source = try objects.observe(
        checkpoint: input.expectedCheckpoint, expectedBase: parentBytes,
        candidate: envelope, stagedEntries: input.stagedEntries)
      try V3RecoveryKeyRotationValidator(limits: limits).validate(
        .init(
          expectedCheckpoint: input.expectedCheckpoint, envelope: envelope,
          stagedEntries: input.stagedEntries),
        parent: parent, currentEntries: source.entries, currentVaultKey: currentVaultKey,
        nextVaultKey: vaultKey, expectedOwner: expectedOwner)
      try objects.requireProjectedUsage(
        source, candidate: envelope, stagedEntries: input.stagedEntries)
    }
    try requireAvailable(vaultID: input.expectedCheckpoint.vaultID)
    return .init(envelope: envelope, stagedEntries: staged, completeEntries: staged, source: source)
  }

  func recheck(
    _ input: V3ContentTransactionInput, validated: V3RecoveryValidatedContentTransaction,
    vaultKey: Data, alreadyCommitted: Bool
  ) throws {
    let fresh = try validate(input, vaultKey: vaultKey, alreadyCommitted: alreadyCommitted)
    guard fresh.envelope == validated.envelope, fresh.stagedEntries == validated.stagedEntries,
      fresh.completeEntries == validated.completeEntries
    else { throw V3RecoveryValidationError.sourceChanged }
    try objects.requireUnchangedSource(
      validated.source, fresh.source, candidateDigest: input.manifestDigest)
  }

  func validateStagedObjects(
    _ validated: V3RecoveryValidatedContentTransaction, operationID: VaultTransactionOperationID
  ) throws {
    for (key, entry) in validated.stagedEntries {
      try exact(
        objectStore.readStagedEntry(
          entryID: key.entryID, digest: key.digest, operationID: operationID,
          maximumBytes: limits.maximumEntryBytes), entry.canonicalBytes)
    }
  }
  func validatePublishedEntries(_ validated: V3RecoveryValidatedContentTransaction) throws {
    for (key, entry) in validated.completeEntries {
      try exact(
        objectStore.readEntry(
          entryID: key.entryID, digest: key.digest, maximumBytes: limits.maximumEntryBytes),
        entry.canonicalBytes)
    }
  }
  func validatePublishedManifest(_ validated: V3RecoveryValidatedContentTransaction) throws {
    try exact(
      objectStore.readManifest(
        digest: validated.envelope.digest, maximumBytes: limits.maximumManifestBytes),
      validated.envelope.canonicalBytes)
  }
  private func exact(_ read: V3RepositoryObjectRead, _ expected: Data) throws {
    guard case .available(let bytes) = read, bytes == expected else {
      throw V3RecoveryValidationError.sourceChanged
    }
  }
}
