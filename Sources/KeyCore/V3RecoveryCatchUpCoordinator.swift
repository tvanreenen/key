import Foundation

struct V3RecoveryCatchUpProgress: Equatable, Sendable {
  // Counts checkpoint replacements, not every snapshot inspected or skipped
  // by an epoch step's fully validated prefix.
  let contentManifestCount: Int
  let keyEpochCount: Int
  var totalStepCount: Int { contentManifestCount + keyEpochCount }
}

enum V3RecoveryCatchUpCoordinatorOutcome: Sendable {
  case current(V3RecoveryContentCommit, progress: V3RecoveryCatchUpProgress)
  case contentConflict(
    V3RecoveryContentCommit, manifestDigests: [Data], progress: V3RecoveryCatchUpProgress)
}

/// A process-local continuation, not persisted authority or reusable consent.
struct V3RecoveryCatchUpSessionResult: Sendable {
  enum Selection: Sendable {
    case verified(V3RecoveryCatchUpCoordinatorOutcome)
    case incomplete(V3RecoveryContentCommit)
  }
  let selection: Selection
  let ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket
  // Exact observed ciphertext/manifest bytes only; no old vault key is retained.
  let revalidatePublishedSource: @Sendable () throws -> Void

  fileprivate init(
    selection: Selection, ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket,
    revalidatePublishedSource: @escaping @Sendable () throws -> Void = {}
  ) {
    self.selection = selection
    self.ticket = ticket
    self.revalidatePublishedSource = revalidatePublishedSource
  }
}

/// Coordinates ordinary catch-up from an exact unlocked Mac floor. One mutation
/// owner surrounds concrete existing steps; their direct owners reuse its ID
/// without nesting the serial queue. A fixed, fully observed source is checked
/// across all epochs and at return, so a late sibling below an advanced floor
/// cannot disappear. Source changes require explicit rediscovery, not a retry.
struct V3RecoveryCatchUpCoordinator: Sendable {
  private enum Observation: Equatable {
    case content(V3RecoverySameEpochObservation)
    case epochs(V3RecoveryKeyTransitionObservation)

    var heads: [Data] {
      switch self {
      case .content(let value): return value.heads
      case .epochs(let value): return [value.head.digest]
      }
    }

    func envelope(_ digest: Data) -> V3RecoveryManifestEnvelope? {
      switch self {
      case .content(let value): return value.envelopes[digest]
      case .epochs(let value): return value.envelopes[digest]
      }
    }
  }

  private let mutationOwner: any VaultTransactionMutationOwning
  private let identity: any V3DeviceWrappedVaultKeyUnwrapping
  private let session: V3DeviceWrappedVaultKeySessionStore
  private let source: any V3ImmutableObjectReading
  private let checkpoints: any V3ManifestCheckpointStoring
  private let ownership: [any V3ImmutableTransactionRecoveryAnchorStoring]
  private let cache: any V3CheckpointManifestCaching
  private let limits: V3ManifestRepositoryLimits
  private let maximumParentEdges: Int
  private let maximumStepCount: Int

  init(
    mutationOwner: any VaultTransactionMutationOwning,
    identity: any V3DeviceWrappedVaultKeyUnwrapping,
    session: V3DeviceWrappedVaultKeySessionStore, source: any V3ImmutableObjectReading,
    checkpointStore: any V3ManifestCheckpointStoring,
    recoveryAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    registrationAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    adoptionAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    cache: any V3CheckpointManifestCaching, limits: V3ManifestRepositoryLimits = .standard,
    maximumParentEdges: Int = 16_384,
    maximumStepCount: Int = V3ManifestRepositoryLimits.standard.maximumManifestObjects
  ) {
    precondition(maximumParentEdges > 0 && maximumStepCount > 0)
    self.mutationOwner = mutationOwner
    self.identity = identity
    self.session = session
    self.source = source
    checkpoints = checkpointStore
    ownership = [recoveryAnchorStore, registrationAnchorStore, adoptionAnchorStore]
    self.cache = cache
    self.limits = limits
    self.maximumParentEdges = maximumParentEdges
    self.maximumStepCount = maximumStepCount
  }

  func catchUp(from floor: V3RecoveryContentCommit) throws -> V3RecoveryCatchUpCoordinatorOutcome {
    let result = try catchUp(
      from: floor, continuing: session.beginAuthentication(), allowStale: false)
    guard case .verified(let outcome) = result.selection else {
      throw V3RecoveryValidationError.sourceUnavailable
    }
    return outcome
  }

  func catchUp(
    from floor: V3RecoveryContentCommit,
    continuing admission: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket,
    allowStale: Bool
  ) throws -> V3RecoveryCatchUpSessionResult {
    try mutationOwner.perform(.catchUpVault) { context in
      do {
        var ticket = admission
        try requireState(floor.checkpoint, ticket: ticket)
        guard identity.vaultID == floor.checkpoint.vaultID,
          floor.envelope.body.fields.devices.contains(
            .init(identity: identity.publicIdentity, status: .active))
        else { throw V3RecoveryKeyTransitionCatchUpError.invalidDevice }
        // Retained only for this bounded operation's original-floor rechecks.
        // No old key or plaintext snapshot is persisted or installed again.
        let originalKey = try session.load(
          vaultID: floor.checkpoint.vaultID, keyID: floor.envelope.body.fields.keyID)
        guard floor.envelope.digest == floor.checkpoint.envelopeDigest,
          floor.envelope.body.fields.vaultID == floor.checkpoint.vaultID
        else { throw V3RecoveryValidationError.invalidObject }
        // Transport fallback still requires an authenticated exact local floor.
        try V3RecoveryEpochBoundary().verifyCurrentAuthentication(
          floor.envelope, vaultKey: originalKey)
        let original = try observe(from: floor, key: originalKey)
        let direct = DirectVaultTransactionMutationOwner(operationID: context.operationID)
        let content = V3RecoverySameEpochCatchUpService(
          mutationOwner: direct, source: source, checkpointStore: checkpoints,
          recoveryAnchorStore: ownership[0], registrationAnchorStore: ownership[1],
          adoptionAnchorStore: ownership[2], cache: cache, limits: limits,
          maximumParentEdges: maximumParentEdges)
        let epochs = V3RecoveryKeyTransitionCatchUpService(
          mutationOwner: direct, identity: identity, session: session, source: source,
          checkpointStore: checkpoints, recoveryAnchorStore: ownership[0],
          registrationAnchorStore: ownership[1], adoptionAnchorStore: ownership[2],
          cache: cache, limits: limits, maximumParentEdges: maximumParentEdges)
        var current = floor
        var contentCount = 0
        var epochCount = 0
        while true {
          try requireStable(
            original, from: floor, key: originalKey, current: current, ticket: ticket)
          let progress = V3RecoveryCatchUpProgress(
            contentManifestCount: contentCount, keyEpochCount: epochCount)
          if original.heads.count > 1 {
            return verified(
              .contentConflict(current, manifestDigests: original.heads, progress: progress),
              observed: original, ticket: ticket)
          }
          guard let headDigest = original.heads.first, let head = original.envelope(headDigest)
          else { throw V3RecoveryValidationError.invalidTransition }
          guard
            head.body.fields.devices.contains(
              .init(identity: identity.publicIdentity, status: .active))
          else { throw V3RecoveryKeyTransitionCatchUpError.deviceRevoked }
          if current.envelope.digest == headDigest {
            return verified(
              .current(current, progress: progress), observed: original, ticket: ticket)
          }
          guard progress.totalStepCount < maximumStepCount else {
            throw V3RecoveryContentCatchUpError.stepLimitExceeded
          }
          if current.envelope.body.fields.keyID != head.body.fields.keyID {
            let advanced = try epochs.advanceOneEpoch(from: current, continuing: ticket)
            guard case .advancedOneEpoch(let next) = advanced.outcome else {
              throw V3RecoveryValidationError.invalidTransition
            }
            current = next
            ticket = advanced.ticket
            epochCount += 1
          } else {
            let key = try session.load(
              vaultID: current.checkpoint.vaultID, keyID: current.envelope.body.fields.keyID)
            guard
              case .advancedOneStep(let next) = try content.advanceOneStep(
                from: current, vaultKey: key)
            else { throw V3RecoveryValidationError.sourceChanged }
            current = next
            contentCount += 1
          }
          // Successful steps do not authorize a later lock or replacement to
          // be treated as continuation. Epoch tickets originate at installation.
          try requireState(current.checkpoint, ticket: ticket)
        }
      } catch {
        // Only transport incompleteness at the unchanged admission floor may
        // preserve stale access. Partial advances, locks and replacements fail
        // these exact checks; invalidity/source changes never enter this path.
        if allowStale, let validation = error as? V3RecoveryValidationError,
          validation == .sourceUnavailable || validation == .entryUnavailable
        {
          do {
            try requireState(floor.checkpoint, ticket: admission)
            return .init(selection: .incomplete(floor), ticket: admission)
          } catch {
            session.invalidate()
            throw error
          }
        }
        session.invalidate()
        throw error
      }
    }
  }

  private func verified(
    _ outcome: V3RecoveryCatchUpCoordinatorOutcome, observed: Observation,
    ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket
  ) -> V3RecoveryCatchUpSessionResult {
    .init(
      selection: .verified(outcome), ticket: ticket,
      revalidatePublishedSource: { try requirePublishedSource(observed) })
  }

  /// Recheck already-verified immutable bytes, not another cryptographic history
  /// walk. Inventory is checked on both sides so additions during reads refuse.
  private func requirePublishedSource(_ observed: Observation) throws {
    let digests: [Data]
    let count: Int
    let manifests: [Data: Data]
    let entries: [V3EntryObjectKey: V3EncryptedEntry]
    switch observed {
    case .content(let value):
      digests = value.listedDigests
      count = value.listedObjectCount
      manifests = value.observedManifestBytes
      entries = value.entryObjects
    case .epochs(let value):
      digests = value.listedDigests
      count = value.listedObjectCount
      manifests = value.manifestBytes
      entries = value.entries
    }
    func requireInventory() throws {
      guard
        case .available(let listed, let objectCount) = try source.manifestDigests(
          maximumCount: limits.maximumManifestObjects),
        objectCount == count, listed.count == digests.count, Set(listed) == Set(digests)
      else { throw V3RecoveryValidationError.sourceChanged }
    }
    try requireInventory()
    let repository = V3ExactTransitionRepository(source: source, limits: limits)
    for (digest, bytes) in manifests {
      guard try repository.readManifest(digest) == bytes else {
        throw V3RecoveryValidationError.sourceChanged
      }
    }
    for (address, entry) in entries {
      guard try repository.readEntry(address) == entry.canonicalBytes else {
        throw V3RecoveryValidationError.sourceChanged
      }
    }
    try requireInventory()
  }

  private func observe(from floor: V3RecoveryContentCommit, key: Data) throws -> Observation {
    do {
      return .content(
        try V3RecoverySameEpochRepositoryObserver(
          source: source, limits: limits, maximumParentEdges: maximumParentEdges
        ).observe(from: floor, vaultKey: key))
    } catch V3RecoveryContentCatchUpError.epochTransitionRequired {
      return .epochs(
        try V3RecoveryKeyTransitionRepositoryObserver(
          source: source, limits: limits, maximumParentEdges: maximumParentEdges
        ).observe(from: floor, vaultKey: key))
    }
  }

  private func requireStable(
    _ observed: Observation, from floor: V3RecoveryContentCommit, key: Data,
    current: V3RecoveryContentCommit,
    ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket
  ) throws {
    try requireState(current.checkpoint, ticket: ticket)
    guard observed.envelope(current.checkpoint.envelopeDigest) == current.envelope,
      try observe(from: floor, key: key) == observed
    else { throw V3RecoveryValidationError.sourceChanged }
    try requireState(current.checkpoint, ticket: ticket)
  }

  private func requireState(
    _ checkpoint: V3ManifestCheckpoint,
    ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket
  ) throws {
    try session.requireCurrent(ticket)
    for store in ownership where try store.loadRecoveryAnchor(vaultID: checkpoint.vaultID) != nil {
      throw V3RecoveryContentCatchUpError.localMutationPending
    }
    guard try checkpoints.loadCheckpoint(vaultID: checkpoint.vaultID) == checkpoint.canonicalBytes
    else { throw V3RecoveryContentCatchUpError.checkpointChanged }
    try session.requireCurrent(ticket)
  }
}
