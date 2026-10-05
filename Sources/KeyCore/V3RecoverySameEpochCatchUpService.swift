import CryptoKit
import Foundation

enum V3RecoveryContentCatchUpError: Error, Equatable {
  case checkpointChanged
  case localMutationPending
  case epochTransitionRequired
}

enum V3RecoverySameEpochCatchUpOutcome: Sendable {
  case upToDate(V3RecoveryContentCommit)
  case advancedOneStep(V3RecoveryContentCommit)
  case contentConflict([Data])
}

/// A bounded authenticated forward graph, not checkpoint-write authority or
/// proof of provider-global freshness. Construction is confined to the observer.
struct V3RecoverySameEpochObservation: Equatable, Sendable {
  let checkpoint: V3ManifestCheckpoint
  let envelopes: [Data: V3RecoveryManifestEnvelope]
  let order: [Data]
  let heads: [Data]
  let entryObjects: [V3EntryObjectKey: V3EncryptedEntry]
  let observedManifestBytes: [Data: Data]
  let listedDigests: [Data]
  let listedObjectCount: Int

  fileprivate init(
    checkpoint: V3ManifestCheckpoint, envelopes: [Data: V3RecoveryManifestEnvelope],
    order: [Data], heads: [Data], entryObjects: [V3EntryObjectKey: V3EncryptedEntry],
    observedManifestBytes: [Data: Data], listedDigests: [Data], listedObjectCount: Int
  ) {
    self.checkpoint = checkpoint
    self.envelopes = envelopes
    self.order = order
    self.heads = heads
    self.entryObjects = entryObjects
    self.observedManifestBytes = observedManifestBytes
    self.listedDigests = listedDigests
    self.listedObjectCount = listedObjectCount
  }
}

/// Ordinary authentication starts at an exact local checkpoint and session key,
/// never a fabricated recovery-token anchor. All visible forward same-epoch
/// manifests and complete snapshots authenticate before a head is reported.
struct V3RecoverySameEpochRepositoryObserver: Sendable {
  let source: any V3ImmutableObjectReading
  let limits: V3ManifestRepositoryLimits
  let maximumParentEdges: Int

  init(
    source: any V3ImmutableObjectReading, limits: V3ManifestRepositoryLimits = .standard,
    maximumParentEdges: Int = 16_384
  ) {
    precondition(maximumParentEdges > 0)
    self.source = source
    self.limits = limits
    self.maximumParentEdges = maximumParentEdges
  }

  func observe(from floor: V3RecoveryContentCommit, vaultKey: Data) throws
    -> V3RecoverySameEpochObservation
  {
    try V3RecoveryContentMutationValidator(limits: limits).validateParent(
      floor.envelope, checkpoint: floor.checkpoint, vaultKey: vaultKey)
    var graph = V3RecoveryManifestGraph(
      source: source, limits: limits, maximumParentEdges: maximumParentEdges)
    let inventory = try graph.loadInventory(floor: floor.checkpoint.envelopeDigest)
    guard graph.objects[floor.checkpoint.envelopeDigest]?.bytes == floor.envelope.canonicalBytes
    else {
      throw V3RecoveryValidationError.sourceChanged
    }
    let order = try graph.anchoredOrder(
      floor: floor.checkpoint.envelopeDigest, vaultID: floor.checkpoint.vaultID)
    let boundary = V3RecoveryEpochBoundary()
    let snapshots = V3EntrySnapshotValidator(limits: limits)
    var envelopes: [Data: V3RecoveryManifestEnvelope] = [:]
    var objects: [V3EntryObjectKey: V3EncryptedEntry] = [:]
    var totalEntryBytes = 0
    for digest in order {
      let envelope = try graph.envelope(digest)
      guard envelope.body.fields.vaultID == floor.checkpoint.vaultID else {
        throw V3RecoveryValidationError.invalidTransition
      }
      guard envelope.body.fields.keyID == floor.envelope.body.fields.keyID else {
        // This path cannot authenticate a new epoch with the current session
        // key. Refuse it without a private unwrap, fallback or key retry.
        throw V3RecoveryContentCatchUpError.epochTransitionRequired
      }
      try boundary.verifyCurrentAuthentication(envelope, vaultKey: vaultKey)
      if digest != floor.checkpoint.envelopeDigest {
        guard envelope.parents.count == 1, let parentDigest = envelope.parents.first,
          let parent = envelopes[parentDigest],
          envelope.body.fields.entries != parent.body.fields.entries
        else { throw V3RecoveryValidationError.invalidTransition }
        try boundary.verifySameEpochMetadata(envelope, parents: [parent])
        try V3RecoveryContentProgressValidator().validate(envelope, parents: [parent])
      }
      var current: [V3EntryObjectKey: V3EncryptedEntry] = [:]
      for record in envelope.body.fields.entries {
        guard let digest = Base64URL.decodeCanonical(record.ciphertextDigest), digest.count == 32
        else {
          throw V3RecoveryValidationError.invalidObject
        }
        let key = V3EntryObjectKey(entryID: record.entryID, digest: digest)
        let entry: V3EncryptedEntry
        if let retained = objects[key] {
          entry = retained
        } else {
          guard objects.count < limits.maximumReferencedEntryObjects else {
            throw V3RecoveryValidationError.resourceLimit
          }
          let bytes = try readEntry(key)
          guard bytes.count <= limits.maximumTotalEntryBytes - totalEntryBytes else {
            throw V3RecoveryValidationError.resourceLimit
          }
          guard Data(SHA256.hash(data: bytes)) == key.digest else {
            throw V3RecoveryValidationError.invalidObject
          }
          totalEntryBytes += bytes.count
          entry = try V3EntryCipher().parse(bytes)
          objects[key] = entry
        }
        guard current.updateValue(entry, forKey: key) == nil else {
          throw V3RecoveryValidationError.invalidObject
        }
      }
      _ = try snapshots.plaintexts(
        fields: envelope.body.fields, entries: current, vaultKey: vaultKey)
      envelopes[digest] = envelope
    }
    let referencedParents = Set(envelopes.values.flatMap { $0.parents })
    let heads = envelopes.keys.filter { !referencedParents.contains($0) }.sorted {
      $0.lexicographicallyPrecedes($1)
    }
    guard !heads.isEmpty else { throw V3RecoveryValidationError.invalidTransition }
    return V3RecoverySameEpochObservation(
      checkpoint: floor.checkpoint, envelopes: envelopes, order: order, heads: heads,
      entryObjects: objects, observedManifestBytes: graph.objects.mapValues(\.bytes),
      listedDigests: inventory.digests, listedObjectCount: inventory.objectCount)
  }

  private func readEntry(_ key: V3EntryObjectKey) throws -> Data {
    switch try source.readEntry(
      entryID: key.entryID, digest: key.digest, maximumBytes: limits.maximumEntryBytes)
    {
    case .available(let data):
      guard data.count <= limits.maximumEntryBytes else {
        throw V3RecoveryValidationError.resourceLimit
      }
      return data
    case .unavailable: throw V3RecoveryValidationError.entryUnavailable
    case .invalid: throw V3RecoveryValidationError.invalidObject
    case .tooLarge: throw V3RecoveryValidationError.resourceLimit
    }
  }
}

/// One serialized, exact local trust advancement. Full same-epoch forward
/// authentication and a fresh equal observation precede checkpoint CAS. No
/// provider writes, native authentication or token capability are available.
/// Key transitions, merged histories and product/session composition remain
/// separate work; the caller must rediscover after every advanced step.
struct V3RecoverySameEpochCatchUpService: Sendable {
  private let mutationOwner: any VaultTransactionMutationOwning
  private let checkpoints: any V3ManifestCheckpointStoring
  private let ownership: [any V3ImmutableTransactionRecoveryAnchorStoring]
  private let cache: any V3CheckpointManifestCaching
  private let observer: V3RecoverySameEpochRepositoryObserver

  init(
    mutationOwner: any VaultTransactionMutationOwning,
    source: any V3ImmutableObjectReading,
    checkpointStore: any V3ManifestCheckpointStoring,
    recoveryAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    registrationAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    adoptionAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    cache: any V3CheckpointManifestCaching,
    limits: V3ManifestRepositoryLimits = .standard,
    maximumParentEdges: Int = 16_384
  ) {
    self.mutationOwner = mutationOwner
    checkpoints = checkpointStore
    ownership = [recoveryAnchorStore, registrationAnchorStore, adoptionAnchorStore]
    self.cache = cache
    observer = V3RecoverySameEpochRepositoryObserver(
      source: source, limits: limits, maximumParentEdges: maximumParentEdges)
  }

  func advanceOneStep(from floor: V3RecoveryContentCommit, vaultKey: Data) throws
    -> V3RecoverySameEpochCatchUpOutcome
  {
    try mutationOwner.perform(.catchUpVault) { _ in
      try requireState(floor.checkpoint)
      let observed = try observer.observe(from: floor, vaultKey: vaultKey)
      try requireState(floor.checkpoint)
      guard try observer.observe(from: floor, vaultKey: vaultKey) == observed else {
        throw V3RecoveryValidationError.sourceChanged
      }
      try requireState(floor.checkpoint)
      if observed.heads.count > 1 { return .contentConflict(observed.heads) }
      guard observed.order.count > 1 else { return .upToDate(floor) }
      let digest = observed.order[1]
      guard let envelope = observed.envelopes[digest],
        envelope.parents == [floor.checkpoint.envelopeDigest]
      else { throw V3RecoveryValidationError.invalidTransition }
      let next = try V3ManifestCheckpoint(vaultID: floor.checkpoint.vaultID, envelopeDigest: digest)
      do {
        try checkpoints.replaceCheckpoint(
          next.canonicalBytes, expectedCheckpoint: floor.checkpoint.canonicalBytes,
          vaultID: floor.checkpoint.vaultID)
      } catch V3ManifestCheckpointStoreError.conflict {
        throw V3RecoveryContentCatchUpError.checkpointChanged
      }
      // Exact checkpoint authority survives cache failure. This result promises
      // one committed step, not a still-current provider head or session install.
      try? cache.store(envelope.canonicalBytes, for: next)
      return .advancedOneStep(V3RecoveryContentCommit(checkpoint: next, envelope: envelope))
    }
  }

  private func requireState(_ expected: V3ManifestCheckpoint) throws {
    for store in ownership where try store.loadRecoveryAnchor(vaultID: expected.vaultID) != nil {
      throw V3RecoveryContentCatchUpError.localMutationPending
    }
    guard try checkpoints.loadCheckpoint(vaultID: expected.vaultID) == expected.canonicalBytes
    else {
      throw V3RecoveryContentCatchUpError.checkpointChanged
    }
  }
}
