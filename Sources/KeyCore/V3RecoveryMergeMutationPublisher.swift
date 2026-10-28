import CryptoKit
import Foundation

/// Explicit all-parent profile 3 publication. Ordinary saves retain their
/// single-parent validator and cannot resume these intents. No private-key or
/// recovery-token operation is available to this publisher.
struct V3RecoveryMergeMutationPublisher: Sendable {
  private let publisher: V3ContentTransactionPublisher<V3RecoveryMergeTransactionValidator>
  private let limits: V3ManifestRepositoryLimits

  init(
    mutationOwner: any VaultTransactionMutationOwning,
    objectStore: any V3TransactionArtifactStore,
    checkpointStore: any V3ManifestCheckpointStoring,
    recoveryAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    registrationAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    adoptionAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    cache: any V3CheckpointManifestCaching,
    limits: V3ManifestRepositoryLimits = .standard,
    phaseObserver: any V3ImmutableTransactionPhaseObserving =
      V3NoopContentTransactionPhaseObserver()
  ) {
    self.limits = limits
    publisher = V3ContentTransactionPublisher(
      mutationOwner: mutationOwner, objectStore: objectStore, checkpointStore: checkpointStore,
      recoveryAnchorStore: recoveryAnchorStore, cache: cache,
      validator: V3RecoveryMergeTransactionValidator(
        objectStore: objectStore, registrationAnchorStore: registrationAnchorStore,
        adoptionAnchorStore: adoptionAnchorStore, limits: limits),
      limits: limits, phaseObserver: phaseObserver)
  }

  func publish(_ candidate: V3RecoveryMergeMutationCandidate, vaultKey: Data) throws
    -> V3RecoveryContentCommit
  {
    guard candidate.envelope.canonicalBytes.count <= limits.maximumManifestBytes,
      try V3RecoveryManifestCodec().parseEnvelope(candidate.envelope.canonicalBytes)
        == candidate.envelope
    else { throw V3RecoveryMergeMutationError.invalidCandidate }
    let checked = try publisher.publish(
      V3ContentTransactionInput(
        kind: candidate.kind, expectedCheckpoint: candidate.expectedCheckpoint,
        manifestData: candidate.envelope.canonicalBytes, manifestDigest: candidate.envelope.digest,
        stagedEntries: candidate.stagedEntries,
        recoveryMerge: V3RecoveryMergeTransactionContext(
          expectedHeads: candidate.expectedHeads,
          resolutions: candidate.resolutions.sorted { $0.conflictID < $1.conflictID })),
      vaultKey: vaultKey)
    return V3RecoveryContentCommit(
      checkpoint: try V3ManifestCheckpoint(
        vaultID: candidate.expectedCheckpoint.vaultID, envelopeDigest: checked.envelope.digest),
      envelope: checked.envelope)
  }

  func recoverInterruptedTransaction(vaultID: String, vaultKey: Data, expectedAnchor: Data? = nil)
    throws
    -> V3ImmutableTransactionRecoveryOutcome
  {
    try publisher.recoverInterruptedTransaction(
      vaultID: vaultID, vaultKey: vaultKey, expectedAnchor: expectedAnchor)
  }
}

private enum V3RecoveryMergeSource: Equatable, Sendable {
  case parents(V3RecoverySameEpochObservation)
  case committed(V3ExactTransitionRepositoryState)
}

struct V3RecoveryValidatedMergeTransaction: V3ValidatedContentTransaction {
  let envelope: V3RecoveryManifestEnvelope
  let stagedEntries: [V3EntryObjectKey: V3EncryptedEntry]
  let completeEntries: [V3EntryObjectKey: V3EncryptedEntry]
  fileprivate let source: V3RecoveryMergeSource
}

/// Authentication and content policy stay separate from manifest-last ordering.
/// The exact candidate alone can be excluded from pre-commit head discovery;
/// its bytes still count toward bounds and its complete snapshot is verified.
struct V3RecoveryMergeTransactionValidator: V3ContentTransactionValidating {
  let objectStore: any V3TransactionArtifactStore
  let registrationAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring
  let adoptionAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring
  let limits: V3ManifestRepositoryLimits
  private var objects: V3ExactTransitionRepository { .init(source: objectStore, limits: limits) }

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
    guard intent.recoveryMergeResolutions != nil, intent.enrollmentTranscriptDigest == nil,
      intent.expectedHeads.count > 1, intent.kind == .mergeHeads || intent.kind == .resolveConflict
    else {
      throw V3ImmutableTransactionRecoveryError.invalidIntent(
        operationID: intent.operationID.rawValue)
    }
  }

  func recoveryIntent(
    for input: V3ContentTransactionInput, operationID: VaultTransactionOperationID,
    stagedEntries: [V3ImmutableTransactionRecoveryEntry]
  ) throws -> V3ImmutableTransactionRecoveryIntent {
    guard let context = input.recoveryMerge else {
      throw V3RecoveryMergeMutationError.invalidCandidate
    }
    return try V3ImmutableTransactionRecoveryIntent(
      operationID: operationID, kind: input.kind, vaultID: input.expectedCheckpoint.vaultID,
      expectedCheckpoint: input.expectedCheckpoint, expectedHeads: context.expectedHeads,
      candidateManifestDigest: input.manifestDigest, stagedEntries: stagedEntries,
      recoveryMergeResolutions: context.resolutions)
  }

  func recoveryInput(
    intent: V3ImmutableTransactionRecoveryIntent, manifestData: Data,
    stagedEntries: [V3EncryptedEntry]
  ) throws -> V3ContentTransactionInput {
    try validateRecoveryIntent(intent)
    guard let resolutions = intent.recoveryMergeResolutions else {
      throw V3RecoveryMergeMutationError.invalidCandidate
    }
    return V3ContentTransactionInput(
      kind: intent.kind, expectedCheckpoint: intent.expectedCheckpoint,
      manifestData: manifestData, manifestDigest: intent.candidateManifestDigest,
      stagedEntries: stagedEntries,
      recoveryMerge: V3RecoveryMergeTransactionContext(
        expectedHeads: intent.expectedHeads, resolutions: resolutions))
  }

  func validate(_ input: V3ContentTransactionInput, vaultKey: Data, alreadyCommitted: Bool) throws
    -> V3RecoveryValidatedMergeTransaction
  {
    try requireAvailable(vaultID: input.expectedCheckpoint.vaultID)
    guard let context = input.recoveryMerge,
      input.manifestData.count <= limits.maximumManifestBytes,
      input.manifestDigest.count == 32,
      Data(SHA256.hash(data: input.manifestData)) == input.manifestDigest,
      input.stagedEntries.count <= limits.maximumReferencedEntryObjects
    else { throw V3RecoveryMergeMutationError.invalidCandidate }
    let envelope = try V3RecoveryManifestCodec().parseEnvelope(input.manifestData)
    guard envelope.body.fields.vaultID == input.expectedCheckpoint.vaultID,
      context.expectedHeads.count > 1, context.expectedHeads == envelope.parents,
      envelope.authorizations.isEmpty
    else { throw V3RecoveryMergeMutationError.invalidCandidate }
    // Use the same strict shape checks for publication and persisted resume.
    try V3ImmutableTransactionRecoveryIntent.validateRecoveryMerge(
      kind: input.kind, expectedHeads: context.expectedHeads, resolutions: context.resolutions)
    try V3RecoveryEpochBoundary().verifyCurrentAuthentication(envelope, vaultKey: vaultKey)
    let snapshots = V3EntrySnapshotValidator(limits: limits)
    let staged = try snapshots.entryMap(input.stagedEntries)
    for entry in input.stagedEntries {
      guard try V3EntryCipher().parse(entry.canonicalBytes) == entry else {
        throw V3RecoveryMergeMutationError.invalidCandidate
      }
    }
    let complete: [V3EntryObjectKey: V3EncryptedEntry]
    let source: V3RecoveryMergeSource
    if alreadyCommitted {
      let checkpoint = try V3ManifestCheckpoint(
        vaultID: input.expectedCheckpoint.vaultID, envelopeDigest: input.manifestDigest)
      let current = try objects.observe(checkpoint: checkpoint, expectedBase: input.manifestData)
      complete = current.entries
      _ = try snapshots.plaintexts(
        fields: envelope.body.fields, entries: complete, vaultKey: vaultKey)
      guard staged.allSatisfy({ complete[$0.key] == $0.value }) else {
        throw V3RecoveryMergeMutationError.invalidCandidate
      }
      source = .committed(current)
    } else {
      let floor = try V3RecoveryManifestCodec().parseEnvelope(
        objects.readManifest(input.expectedCheckpoint.envelopeDigest))
      let observed = try V3RecoverySameEpochRepositoryObserver(source: objectStore, limits: limits)
        .observeMergeParents(
          from: V3RecoveryContentCommit(checkpoint: input.expectedCheckpoint, envelope: floor),
          vaultKey: vaultKey, candidate: envelope)
      complete = try V3RecoveryMergeMutationValidator(limits: limits).validate(
        V3RecoveryMergeMutationCandidate(
          kind: input.kind, expectedCheckpoint: input.expectedCheckpoint,
          expectedHeads: context.expectedHeads, resolutions: context.resolutions,
          envelope: envelope, stagedEntries: input.stagedEntries),
        observed: observed, vaultKey: vaultKey)
      source = .parents(observed)
    }
    try requireAvailable(vaultID: input.expectedCheckpoint.vaultID)
    return V3RecoveryValidatedMergeTransaction(
      envelope: envelope, stagedEntries: staged, completeEntries: complete, source: source)
  }

  func recheck(
    _ input: V3ContentTransactionInput, validated: V3RecoveryValidatedMergeTransaction,
    vaultKey: Data, alreadyCommitted: Bool
  ) throws {
    let fresh = try validate(input, vaultKey: vaultKey, alreadyCommitted: alreadyCommitted)
    guard fresh.envelope == validated.envelope, fresh.stagedEntries == validated.stagedEntries,
      fresh.completeEntries == validated.completeEntries
    else { throw V3RecoveryValidationError.sourceChanged }
    switch (validated.source, fresh.source) {
    case (.parents(let before), .parents(let after)):
      var oldBytes = before.observedManifestBytes
      var newBytes = after.observedManifestBytes
      let oldPublished = oldBytes.removeValue(forKey: input.manifestDigest) != nil
      let newPublished = newBytes.removeValue(forKey: input.manifestDigest) != nil
      let oldListing = before.listedDigests.filter { $0 != input.manifestDigest }
      let newListing = after.listedDigests.filter { $0 != input.manifestDigest }
      guard before.checkpoint == after.checkpoint, before.graphFloor == after.graphFloor,
        before.committedAncestorDigests == after.committedAncestorDigests,
        before.envelopes == after.envelopes,
        before.order == after.order, before.heads == after.heads,
        before.entryObjects == after.entryObjects, oldBytes == newBytes, oldListing == newListing,
        before.listedObjectCount - (before.listedDigests.contains(input.manifestDigest) ? 1 : 0)
          == after.listedObjectCount - (after.listedDigests.contains(input.manifestDigest) ? 1 : 0),
        !oldPublished || newPublished
      else { throw V3RecoveryValidationError.sourceChanged }
    case (.committed(let before), .committed(let after)):
      guard before == after else { throw V3RecoveryValidationError.sourceChanged }
    default: throw V3RecoveryValidationError.sourceChanged
    }
  }

  func validateStagedObjects(
    _ validated: V3RecoveryValidatedMergeTransaction, operationID: VaultTransactionOperationID
  ) throws {
    for (key, entry) in validated.stagedEntries {
      try exact(
        objectStore.readStagedEntry(
          entryID: key.entryID, digest: key.digest, operationID: operationID,
          maximumBytes: limits.maximumEntryBytes), entry.canonicalBytes)
    }
  }

  func validatePublishedEntries(_ validated: V3RecoveryValidatedMergeTransaction) throws {
    for (key, entry) in validated.completeEntries {
      try exact(
        objectStore.readEntry(
          entryID: key.entryID, digest: key.digest, maximumBytes: limits.maximumEntryBytes),
        entry.canonicalBytes)
    }
  }

  func validatePublishedManifest(_ validated: V3RecoveryValidatedMergeTransaction) throws {
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
