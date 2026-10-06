import CryptoKit
import Foundation

enum V3RecoveryContentPublicationError: Error, Equatable {
  case otherMutationPending
}

struct V3RecoveryContentCommit: Sendable {
  let checkpoint: V3ManifestCheckpoint
  let envelope: V3RecoveryManifestEnvelope
}

/// Internal profile-3 entry point, not shipping CLI/XPC composition. Ordinary
/// saves use an already unlocked session key; no private-device/token operation
/// or provider-specific key administration is available to this publisher.
struct V3RecoveryContentMutationPublisher: Sendable {
  private let publisher: V3ContentTransactionPublisher<V3RecoveryContentTransactionValidator>
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
      mutationOwner: mutationOwner, objectStore: objectStore,
      checkpointStore: checkpointStore, recoveryAnchorStore: recoveryAnchorStore, cache: cache,
      validator: V3RecoveryContentTransactionValidator(
        objectStore: objectStore,
        registrationAnchorStore: registrationAnchorStore, adoptionAnchorStore: adoptionAnchorStore,
        limits: limits),
      limits: limits, phaseObserver: phaseObserver)
  }

  func publish(
    _ candidate: V3RecoveryContentMutationCandidate, vaultKey: Data
  ) throws -> V3RecoveryContentCommit {
    guard candidate.envelope.canonicalBytes.count <= limits.maximumManifestBytes,
      try V3RecoveryManifestCodec().parseEnvelope(candidate.envelope.canonicalBytes)
        == candidate.envelope
    else { throw V3RecoveryContentMutationError.invalidCandidate }
    let input = V3ContentTransactionInput(
      kind: candidate.kind, expectedCheckpoint: candidate.expectedCheckpoint,
      manifestData: candidate.envelope.canonicalBytes, manifestDigest: candidate.envelope.digest,
      stagedEntries: candidate.stagedEntries)
    let checked = try publisher.publish(input, vaultKey: vaultKey)
    return V3RecoveryContentCommit(
      checkpoint: try V3ManifestCheckpoint(
        vaultID: candidate.expectedCheckpoint.vaultID, envelopeDigest: checked.envelope.digest),
      envelope: checked.envelope)
  }

  func recoverInterruptedTransaction(
    vaultID: String, vaultKey: Data, expectedAnchor: Data? = nil
  ) throws -> V3ImmutableTransactionRecoveryOutcome {
    try publisher.recoverInterruptedTransaction(
      vaultID: vaultID, vaultKey: vaultKey, expectedAnchor: expectedAnchor)
  }
}

struct V3RecoveryValidatedContentTransaction: V3ValidatedContentTransaction {
  let envelope: V3RecoveryManifestEnvelope
  let stagedEntries: [V3EntryObjectKey: V3EncryptedEntry]
  let completeEntries: [V3EntryObjectKey: V3EncryptedEntry]
  let source: V3ExactTransitionRepositoryState
}

/// Source authentication stays here, separate from durable transaction ordering.
/// Before commitment, both snapshots and the exact single-parent edit are
/// checked. After local commitment, reconciliation checks the current snapshot
/// and pinned immutable bytes without reopening removed historical entries.
struct V3RecoveryContentTransactionValidator: V3ContentTransactionValidating {
  let objectStore: any V3TransactionArtifactStore
  let registrationAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring
  let adoptionAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring
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

  func validate(
    _ input: V3ContentTransactionInput, vaultKey: Data, alreadyCommitted: Bool
  ) throws -> V3RecoveryValidatedContentTransaction {
    try requireAvailable(vaultID: input.expectedCheckpoint.vaultID)
    guard input.recoveryMerge == nil, input.manifestData.count <= limits.maximumManifestBytes,
      input.manifestDigest.count == 32,
      Data(SHA256.hash(data: input.manifestData)) == input.manifestDigest,
      input.stagedEntries.count <= limits.maximumReferencedEntryObjects
    else { throw V3RecoveryContentMutationError.resourceLimit }
    let envelope = try V3RecoveryManifestCodec().parseEnvelope(input.manifestData)
    guard envelope.body.fields.vaultID == input.expectedCheckpoint.vaultID,
      envelope.parents == [input.expectedCheckpoint.envelopeDigest], envelope.authorizations.isEmpty
    else { throw V3RecoveryContentMutationError.invalidCandidate }
    switch input.kind {
    case .addEntry, .editEntry, .copyEntry, .moveEntry, .removeEntry: break
    default: throw V3ImmutableTransactionError.invalidAncestryProof
    }
    let staged = try snapshots.entryMap(input.stagedEntries)
    for entry in input.stagedEntries {
      guard try V3EntryCipher().parse(entry.canonicalBytes) == entry else {
        throw V3RecoveryContentMutationError.invalidCandidate
      }
    }
    let complete: [V3EntryObjectKey: V3EncryptedEntry]
    let source: V3ExactTransitionRepositoryState
    if alreadyCommitted {
      try V3RecoveryEpochBoundary().verifyCurrentAuthentication(envelope, vaultKey: vaultKey)
      let checkpoint = try V3ManifestCheckpoint(
        vaultID: input.expectedCheckpoint.vaultID, envelopeDigest: input.manifestDigest)
      source = try objects.observe(checkpoint: checkpoint, expectedBase: input.manifestData)
      complete = source.entries
      _ = try snapshots.plaintexts(
        fields: envelope.body.fields, entries: complete, vaultKey: vaultKey)
      guard staged.allSatisfy({ complete[$0.key] == $0.value }) else {
        throw V3RecoveryContentMutationError.invalidCandidate
      }
    } else {
      // The local floor must be visible for this bounded source inventory.
      // A missing provider floor is a refusal, not permission to pick a head.
      let parentBytes = try objects.readManifest(input.expectedCheckpoint.envelopeDigest)
      let parent = try V3RecoveryManifestCodec().parseEnvelope(parentBytes)
      try V3RecoveryContentMutationValidator(limits: limits).validateParent(
        parent, checkpoint: input.expectedCheckpoint, vaultKey: vaultKey)
      let currentEntries = try loadEntries(parent.body.fields)
      // The exact candidate may already be published during anchored resume.
      complete = try V3RecoveryContentMutationValidator(limits: limits).validate(
        V3RecoveryContentMutationCandidate(
          kind: input.kind, expectedCheckpoint: input.expectedCheckpoint, envelope: envelope,
          stagedEntries: input.stagedEntries),
        parent: parent, currentEntries: currentEntries, vaultKey: vaultKey)
      source = try objects.observe(
        checkpoint: input.expectedCheckpoint, expectedBase: parentBytes,
        candidate: envelope, stagedEntries: Array(complete.values))
      try objects.requireProjectedUsage(
        source, candidate: envelope, stagedEntries: Array(complete.values))
    }
    try requireAvailable(vaultID: input.expectedCheckpoint.vaultID)
    return V3RecoveryValidatedContentTransaction(
      envelope: envelope, stagedEntries: staged, completeEntries: complete, source: source)
  }

  func recheck(
    _ input: V3ContentTransactionInput, validated: V3RecoveryValidatedContentTransaction,
    vaultKey: Data, alreadyCommitted: Bool
  ) throws {
    let fresh = try validate(input, vaultKey: vaultKey, alreadyCommitted: alreadyCommitted)
    var before = validated.source.manifestBytes
    var after = fresh.source.manifestBytes
    let removedBefore = before.removeValue(forKey: input.manifestDigest) != nil
    let removedAfter = after.removeValue(forKey: input.manifestDigest) != nil
    guard fresh.envelope == validated.envelope,
      fresh.stagedEntries == validated.stagedEntries,
      fresh.completeEntries == validated.completeEntries,
      fresh.source.baseBytes == validated.source.baseBytes,
      fresh.source.entries == validated.source.entries,
      before == after,
      fresh.source.listedObjectCount - (removedAfter ? 1 : 0)
        == validated.source.listedObjectCount - (removedBefore ? 1 : 0),
      !removedBefore || removedAfter
    else { throw V3RecoveryValidationError.sourceChanged }
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
  private func loadEntries(_ fields: V3DeviceWrappedManifestFields) throws -> [V3EntryObjectKey:
    V3EncryptedEntry]
  {
    guard fields.entries.count <= limits.maximumReferencedEntryObjects else {
      throw V3RecoveryContentMutationError.resourceLimit
    }
    var entries: [V3EncryptedEntry] = []
    var total = 0
    for record in fields.entries {
      guard let digest = Base64URL.decodeCanonical(record.ciphertextDigest), digest.count == 32
      else {
        throw V3RecoveryContentMutationError.invalidParent
      }
      let bytes = try objects.readEntry(V3EntryObjectKey(entryID: record.entryID, digest: digest))
      guard bytes.count <= limits.maximumTotalEntryBytes - total else {
        throw V3RecoveryContentMutationError.resourceLimit
      }
      total += bytes.count
      entries.append(try V3EntryCipher().parse(bytes))
    }
    return try snapshots.entryMap(entries)
  }
}
