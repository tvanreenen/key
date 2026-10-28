import CryptoKit
import Foundation

struct V3RecoveryAdoptionCommit: Equatable, Sendable {
  let operationID: VaultTransactionOperationID
  let checkpoint: V3ManifestCheckpoint
  let alreadyAdopted: Bool
  let cleanupPending: Bool
}

enum V3RecoveryAdoptionPhase: Equatable, Sendable {
  case candidateConstructed, ownershipReserved, bundlePersisted, bundleVerified, ownershipArmed
  case localWrapperVerified, artifactsStaged
  case entryPublished(index: Int)
  case entriesVerified
  case manifestPublished, manifestVerified, checkpointAdvanced, sessionUpdated, ownershipCleared
}

protocol V3RecoveryAdoptionPhaseObserving: Sendable {
  func didReach(_ phase: V3RecoveryAdoptionPhase) throws
}

private struct V3NoopAdoptionObserver: V3RecoveryAdoptionPhaseObserving {
  func didReach(_: V3RecoveryAdoptionPhase) throws {}
}

/// Internal explicit profile adoption, not shipping dispatch or a CLI/XPC route.
/// One shared mutation boundary spans signing, durable preparation, one local
/// unwrap and manifest-last publication. No token dependency or admin writer.
struct V3RecoveryAdoptionService: Sendable {
  private let vaultID: String
  private let identity: any V3EnrollmentMessageSigning & V3DeviceWrappedVaultKeyUnwrapping
  private let mutationOwner: any VaultTransactionMutationOwning
  private let store: any V3ImmutableObjectPublishing & V3RecoveryAdoptionPreparationStoring
  private let checkpoints: any V3ManifestCheckpointStoring
  private let ownership: any V3ImmutableTransactionRecoveryAnchorStoring
  private let otherOwnership: [any V3ImmutableTransactionRecoveryAnchorStoring]
  private let limits: V3ManifestRepositoryLimits
  private let observer: any V3RecoveryAdoptionPhaseObserving
  private var objects: V3ExactTransitionRepository { .init(source: store, limits: limits) }
  private var validator: V3RecoveryProfileAdoptionValidator { .init(limits: limits) }

  init(
    vaultID: String, identity: any V3EnrollmentMessageSigning & V3DeviceWrappedVaultKeyUnwrapping,
    mutationOwner: any VaultTransactionMutationOwning,
    objectStore: any V3ImmutableObjectPublishing & V3RecoveryAdoptionPreparationStoring,
    checkpointStore: any V3ManifestCheckpointStoring,
    adoptionOwnershipStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    transactionOwnershipStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    registrationOwnershipStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    limits: V3ManifestRepositoryLimits = .standard,
    observer: any V3RecoveryAdoptionPhaseObserving = V3NoopAdoptionObserver()
  ) {
    self.vaultID = vaultID
    self.identity = identity
    self.mutationOwner = mutationOwner
    store = objectStore
    checkpoints = checkpointStore
    ownership = adoptionOwnershipStore
    otherOwnership = [transactionOwnershipStore, registrationOwnershipStore]
    self.limits = limits
    self.observer = observer
  }

  func adopt(
    currentVaultKey: Data,
    afterCheckpointAdvance: (V3ManifestCheckpoint, Data) throws -> Void = { _, _ in }
  ) throws -> V3RecoveryAdoptionCommit {
    try mutationOwner.perform(.adoptRecoveryProfile) { context in
      try requireNoOtherPending()
      guard try loadOwnership() == nil else { throw V3RecoveryAdoptionServiceError.adoptionPending }
      let checkpoint = try loadCheckpoint()
      let (parent, initial) = try authenticatedBase(checkpoint, key: currentVaultKey)
      let nextKey = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
      let candidate = try V3RecoveryProfileAdoptionBuilder(limits: limits).build(
        from: parent, currentEntries: initial.entries, currentVaultKey: currentVaultKey,
        nextVaultKey: nextKey, owner: identity, reason: "Adopt Key's recovery-capable vault format")
      let preparation = try V3RecoveryAdoptionPreparation(
        operationID: context.operationID,
        ownerDeviceID: identity.publicIdentity.deviceID, candidate: candidate, limits: limits)
      try objects.requireProjectedUsage(
        initial, candidate: candidate.envelope,
        stagedEntries: candidate.stagedEntries)
      try observer.didReach(.candidateConstructed)
      try requireState(initial, checkpoint: checkpoint)
      let reserved = try anchor(preparation, phase: .prepared)
      try ownership.replaceRecoveryAnchor(
        reserved.canonicalBytes, expectedAnchor: nil, vaultID: vaultID)
      try observer.didReach(.ownershipReserved)
      try store.persistAdoptionPreparation(
        preparation.canonicalBytes, operationID: preparation.operationID)
      try observer.didReach(.bundlePersisted)
      try requirePreparation(preparation)
      return try finish(
        preparation, parent: parent, initial: initial, currentKey: currentVaultKey,
        expectedNextKey: nextKey, afterCheckpointAdvance: afterCheckpointAdvance)
    }
  }

  /// The exact operation must be explicitly selected. Provider preparations
  /// cannot create local ownership or advance a checkpoint. Without ownership,
  /// only a preparation matching the already-committed local checkpoint can
  /// reconcile a lost reply; it cannot authorize another publication.
  func resume(
    operationID: VaultTransactionOperationID, currentVaultKey: Data,
    afterCheckpointAdvance: (V3ManifestCheckpoint, Data) throws -> Void = { _, _ in }
  ) throws -> V3RecoveryAdoptionCommit {
    try mutationOwner.perform(.adoptRecoveryProfile) { _ in
      try requireNoOtherPending()
      let local = try loadOwnership()
      if let local, local.operationID != operationID {
        throw V3RecoveryAdoptionServiceError.ownershipChanged
      }
      let preparation = try loadPreparation(operationID, expected: local)
      let checkpoint = try loadCheckpoint()
      if checkpoint.envelopeDigest == preparation.candidate.envelope.digest {
        guard local == nil || local?.phase == .recoverable else {
          throw V3RecoveryAdoptionServiceError.ownershipChanged
        }
        return try reconcile(
          preparation, checkpoint: checkpoint, local: local,
          afterCheckpointAdvance: afterCheckpointAdvance)
      }
      guard local != nil else { throw V3RecoveryAdoptionServiceError.noPendingAdoption }
      guard checkpoint == preparation.candidate.expectedCheckpoint else {
        throw V3RecoveryAdoptionServiceError.checkpointChanged
      }
      let (parent, initial) = try authenticatedBase(
        checkpoint, key: currentVaultKey,
        preparation: preparation)
      return try finish(
        preparation, parent: parent, initial: initial, currentKey: currentVaultKey,
        expectedNextKey: nil, afterCheckpointAdvance: afterCheckpointAdvance)
    }
  }

  /// Explicit pre-publication abandonment only. A prepared reservation cannot
  /// have authorized publication; recoverable or unfamiliar state is retained.
  /// Encrypted files stay inert for audit; no provider data is deleted.
  func abandonUnarmedPreparation(operationID: VaultTransactionOperationID) throws {
    try mutationOwner.perform(.adoptRecoveryProfile) { _ in
      guard let local = try loadOwnership(), local.operationID == operationID,
        local.phase == .prepared
      else { throw V3RecoveryAdoptionServiceError.ownershipChanged }
      try ownership.replaceRecoveryAnchor(
        nil, expectedAnchor: local.canonicalBytes, vaultID: vaultID)
    }
  }

  private func finish(
    _ preparation: V3RecoveryAdoptionPreparation, parent: V3DeviceWrappedTrustedCheckpoint,
    initial: V3ExactTransitionRepositoryState, currentKey: Data, expectedNextKey: Data?,
    afterCheckpointAdvance: (V3ManifestCheckpoint, Data) throws -> Void
  ) throws -> V3RecoveryAdoptionCommit {
    let candidate = preparation.candidate
    try requirePreparation(preparation)
    try requireIdentity(preparation)
    try validator.preflight(
      candidate, parent: parent, currentVaultKey: currentKey,
      expectedOwner: identity.publicIdentity)
    try objects.requireProjectedUsage(
      initial, candidate: candidate.envelope,
      stagedEntries: candidate.stagedEntries)
    try requireState(initial, checkpoint: parent.checkpoint, preparation: preparation)
    let nextKey = try openLocal(candidate.envelope, reason: "Verify Key vault format adoption")
    if let expectedNextKey, nextKey != expectedNextKey {
      throw V3RecoveryProfileAdoptionError.localWrapperMismatch
    }
    try validator.validate(
      candidate, parent: parent, currentEntries: initial.entries,
      currentVaultKey: currentKey, nextVaultKey: nextKey, expectedOwner: identity.publicIdentity)
    try observer.didReach(.localWrapperVerified)
    try requirePreparation(preparation)
    try requireState(initial, checkpoint: parent.checkpoint, preparation: preparation)
    // Confirmation repeats synchronization after any ambiguous prior install.
    // Readability alone never promotes a prepared reservation.
    try observer.didReach(.bundleVerified)
    try store.confirmAdoptionPreparation(
      preparation.canonicalBytes, operationID: preparation.operationID)
    guard let local = try loadOwnership() else {
      throw V3RecoveryAdoptionServiceError.ownershipChanged
    }
    if local.phase == .prepared {
      let armed = try anchor(preparation, phase: .recoverable)
      try ownership.replaceRecoveryAnchor(
        armed.canonicalBytes, expectedAnchor: local.canonicalBytes,
        vaultID: vaultID)
    }
    try observer.didReach(.ownershipArmed)
    try requirePreparation(preparation, recoverable: true)
    try requireState(initial, checkpoint: parent.checkpoint, preparation: preparation)
    return try publish(
      preparation, parent: parent, initial: initial, currentKey: currentKey,
      nextKey: nextKey, afterCheckpointAdvance: afterCheckpointAdvance)
  }

  private func publish(
    _ preparation: V3RecoveryAdoptionPreparation, parent: V3DeviceWrappedTrustedCheckpoint,
    initial: V3ExactTransitionRepositoryState, currentKey: Data, nextKey: Data,
    afterCheckpointAdvance: (V3ManifestCheckpoint, Data) throws -> Void
  ) throws -> V3RecoveryAdoptionCommit {
    let candidate = preparation.candidate
    let operation = preparation.operationID
    for entry in candidate.stagedEntries {
      try store.stageEntry(
        entry.canonicalBytes, entryID: entry.context.entryID,
        digest: Data(SHA256.hash(data: entry.canonicalBytes)), operationID: operation)
    }
    try store.stageManifest(
      candidate.envelope.canonicalBytes, digest: candidate.envelope.digest,
      operationID: operation)
    try observer.didReach(.artifactsStaged)
    try requirePreparation(preparation, recoverable: true)
    try requireState(initial, checkpoint: parent.checkpoint, preparation: preparation)
    for (index, entry) in candidate.stagedEntries.enumerated() {
      try store.publishStagedEntry(
        entry.canonicalBytes, entryID: entry.context.entryID,
        digest: Data(SHA256.hash(data: entry.canonicalBytes)), operationID: operation)
      try observer.didReach(.entryPublished(index: index))
    }
    try requirePublishedEntries(candidate)
    try observer.didReach(.entriesVerified)
    try requireState(initial, checkpoint: parent.checkpoint, preparation: preparation)
    try requirePreparation(preparation, recoverable: true)
    try requirePublishedEntries(candidate)
    try store.publishStagedManifest(
      candidate.envelope.canonicalBytes, digest: candidate.envelope.digest,
      operationID: operation)
    try observer.didReach(.manifestPublished)
    guard try objects.readManifest(candidate.envelope.digest) == candidate.envelope.canonicalBytes
    else {
      throw V3RecoveryAdoptionServiceError.invalidPublishedObject
    }
    try requirePublishedEntries(candidate)
    let published = try objects.observe(
      checkpoint: parent.checkpoint, expectedBase: initial.baseBytes,
      candidate: candidate.envelope, stagedEntries: candidate.stagedEntries)
    var expected = initial.manifestBytes
    let added =
      expected.updateValue(candidate.envelope.canonicalBytes, forKey: candidate.envelope.digest)
      == nil
    guard published.candidatePublished, published.manifestBytes == expected,
      published.listedObjectCount == initial.listedObjectCount + (added ? 1 : 0)
    else { throw V3RecoveryValidationError.sourceChanged }
    try validator.validate(
      candidate, parent: parent, currentEntries: published.entries,
      currentVaultKey: currentKey, nextVaultKey: nextKey, expectedOwner: identity.publicIdentity)
    try observer.didReach(.manifestVerified)
    try requireState(published, checkpoint: parent.checkpoint, preparation: preparation)
    try requirePreparation(preparation, recoverable: true)
    let next = try V3ManifestCheckpoint(vaultID: vaultID, envelopeDigest: candidate.envelope.digest)
    try checkpoints.replaceCheckpoint(
      next.canonicalBytes, expectedCheckpoint: parent.checkpoint.canonicalBytes,
      vaultID: vaultID)
    try observer.didReach(.checkpointAdvanced)
    try afterCheckpointAdvance(next, nextKey)
    try observer.didReach(.sessionUpdated)
    return try complete(preparation, checkpoint: next, alreadyAdopted: false, clear: true)
  }

  private func reconcile(
    _ preparation: V3RecoveryAdoptionPreparation, checkpoint: V3ManifestCheckpoint,
    local: V3ImmutableTransactionRecoveryAnchor?,
    afterCheckpointAdvance: (V3ManifestCheckpoint, Data) throws -> Void
  ) throws -> V3RecoveryAdoptionCommit {
    try requireIdentity(preparation)
    let envelope = preparation.candidate.envelope
    let initial = try objects.observe(checkpoint: checkpoint, expectedBase: envelope.canonicalBytes)
    let nextKey = try openLocal(envelope, reason: "Reconcile committed Key vault format adoption")
    try V3RecoveryEpochBoundary().verifyCurrentAuthentication(envelope, vaultKey: nextKey)
    _ = try V3EntrySnapshotValidator(limits: limits).plaintexts(
      fields: envelope.body.fields,
      entries: initial.entries, vaultKey: nextKey)
    try requirePublishedEntries(preparation.candidate)
    try requireState(initial, checkpoint: checkpoint)
    guard try loadOwnership() == local else {
      throw V3RecoveryAdoptionServiceError.ownershipChanged
    }
    try afterCheckpointAdvance(checkpoint, nextKey)
    try observer.didReach(.sessionUpdated)
    return try complete(
      preparation, checkpoint: checkpoint, alreadyAdopted: true, clear: local != nil)
  }

  private func complete(
    _ preparation: V3RecoveryAdoptionPreparation, checkpoint: V3ManifestCheckpoint,
    alreadyAdopted: Bool, clear: Bool
  ) throws -> V3RecoveryAdoptionCommit {
    try requireCheckpoint(checkpoint)
    var cleanupPending = false
    if clear {
      try requirePreparation(preparation, recoverable: true)
      let local = try anchor(preparation, phase: .recoverable)
      do {
        try ownership.replaceRecoveryAnchor(
          nil, expectedAnchor: local.canonicalBytes, vaultID: vaultID)
      } catch { cleanupPending = true }
      if !cleanupPending { try observer.didReach(.ownershipCleared) }
    }
    return V3RecoveryAdoptionCommit(
      operationID: preparation.operationID, checkpoint: checkpoint,
      alreadyAdopted: alreadyAdopted, cleanupPending: cleanupPending)
  }

  private func authenticatedBase(
    _ checkpoint: V3ManifestCheckpoint, key: Data,
    preparation: V3RecoveryAdoptionPreparation? = nil
  ) throws -> (V3DeviceWrappedTrustedCheckpoint, V3ExactTransitionRepositoryState) {
    let bytes = try objects.readManifest(checkpoint.envelopeDigest)
    let parent = try V3DeviceWrappedTrustedCheckpoint(
      checkpoint: checkpoint,
      envelope: V3DeviceWrappedManifestEnvelopeCodec().parse(bytes))
    try validator.validateParent(parent, currentVaultKey: key)
    let state = try objects.observe(
      checkpoint: checkpoint, expectedBase: bytes,
      candidate: preparation?.candidate.envelope,
      stagedEntries: preparation?.candidate.stagedEntries ?? [])
    _ = try V3EntrySnapshotValidator(limits: limits).plaintexts(
      fields: parent.envelope.body.fields,
      entries: state.entries, vaultKey: key)
    return (parent, state)
  }
  private func requireIdentity(_ preparation: V3RecoveryAdoptionPreparation) throws {
    guard identity.vaultID == vaultID,
      preparation.ownerDeviceID == identity.publicIdentity.deviceID,
      preparation.candidate.expectedCheckpoint.vaultID == vaultID,
      preparation.candidate.envelope.body.fields.devices.contains(where: {
        $0.identity == identity.publicIdentity && $0.status == .active
      })
    else { throw V3RecoveryProfileAdoptionError.invalidOwner }
  }
  private func openLocal(_ envelope: V3RecoveryManifestEnvelope, reason: String) throws -> Data {
    guard
      let local = envelope.body.fields.wrappedKeys.first(where: {
        $0.recipientDeviceID == identity.publicIdentity.deviceID
      })
    else { throw V3RecoveryProfileAdoptionError.localWrapperMismatch }
    return try identity.unwrapDeviceWrappedVaultKey(
      local.wrappedKey,
      context: envelope.body.deviceContext(recipientDeviceID: identity.publicIdentity.deviceID),
      reason: reason)
  }
  private func requirePublishedEntries(_ candidate: V3RecoveryProfileAdoptionCandidate) throws {
    for entry in candidate.stagedEntries {
      guard
        try objects.readEntry(
          V3EntryObjectKey(
            entryID: entry.context.entryID,
            digest: Data(SHA256.hash(data: entry.canonicalBytes)))) == entry.canonicalBytes
      else { throw V3RecoveryAdoptionServiceError.invalidPublishedObject }
    }
  }
  private func requireState(
    _ state: V3ExactTransitionRepositoryState, checkpoint: V3ManifestCheckpoint,
    preparation: V3RecoveryAdoptionPreparation? = nil
  ) throws {
    try requireNoOtherPending()
    try requireCheckpoint(checkpoint)
    guard
      try objects.observe(
        checkpoint: checkpoint, expectedBase: state.baseBytes,
        candidate: preparation?.candidate.envelope,
        stagedEntries: preparation?.candidate.stagedEntries ?? []) == state
    else { throw V3RecoveryValidationError.sourceChanged }
    try requireCheckpoint(checkpoint)
  }
  private func requireNoOtherPending() throws {
    for store in otherOwnership where try store.loadRecoveryAnchor(vaultID: vaultID) != nil {
      throw V3RecoveryAdoptionServiceError.otherMutationPending
    }
  }
  private func loadCheckpoint() throws -> V3ManifestCheckpoint {
    guard let bytes = try checkpoints.loadCheckpoint(vaultID: vaultID), bytes.count <= 1_024,
      let checkpoint = try? V3ManifestCheckpoint(canonicalBytes: bytes),
      checkpoint.vaultID == vaultID
    else { throw V3RecoveryAdoptionServiceError.checkpointChanged }
    return checkpoint
  }
  private func requireCheckpoint(_ expected: V3ManifestCheckpoint) throws {
    guard try loadCheckpoint() == expected else {
      throw V3RecoveryAdoptionServiceError.checkpointChanged
    }
  }
  private func anchor(
    _ preparation: V3RecoveryAdoptionPreparation,
    phase: V3ImmutableTransactionRecoveryAnchorPhase
  ) throws -> V3ImmutableTransactionRecoveryAnchor {
    try V3ImmutableTransactionRecoveryAnchor(
      operationID: preparation.operationID, vaultID: vaultID,
      intentDigest: preparation.digest, phase: phase)
  }
  private func loadOwnership() throws -> V3ImmutableTransactionRecoveryAnchor? {
    guard let bytes = try ownership.loadRecoveryAnchor(vaultID: vaultID) else { return nil }
    guard bytes.count <= 1_024,
      let local = try? V3ImmutableTransactionRecoveryAnchor(canonicalBytes: bytes),
      local.vaultID == vaultID
    else { throw V3RecoveryAdoptionServiceError.ownershipChanged }
    return local
  }
  private func loadPreparation(
    _ operation: VaultTransactionOperationID,
    expected: V3ImmutableTransactionRecoveryAnchor?
  ) throws -> V3RecoveryAdoptionPreparation {
    let bytes: Data
    switch try store.readAdoptionPreparation(
      operationID: operation,
      maximumBytes: V3RecoveryAdoptionPreparation.maximumBytes(limits))
    {
    case .available(let value): bytes = value
    case .unavailable: throw V3RecoveryAdoptionServiceError.preparationUnavailable
    case .invalid: throw V3RecoveryAdoptionServiceError.invalidPreparation
    case .tooLarge: throw V3RecoveryProfileAdoptionError.resourceLimit
    }
    let preparation = try V3RecoveryAdoptionPreparation(canonicalBytes: bytes, limits: limits)
    guard preparation.operationID == operation,
      preparation.candidate.expectedCheckpoint.vaultID == vaultID,
      expected == nil || expected?.intentDigest == preparation.digest
    else { throw V3RecoveryAdoptionServiceError.invalidPreparation }
    return preparation
  }
  private func requirePreparation(
    _ preparation: V3RecoveryAdoptionPreparation, recoverable: Bool = false
  ) throws {
    guard let local = try loadOwnership(), local.operationID == preparation.operationID,
      !recoverable || local.phase == .recoverable,
      try loadPreparation(local.operationID, expected: local) == preparation
    else { throw V3RecoveryAdoptionServiceError.ownershipChanged }
  }
}
