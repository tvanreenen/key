import Foundation

enum V3RecoveryRestoreFinalizationPhase: Equatable, Sendable {
  case completionVerified, reservationCleared, preparationCleared, completionConfirmed
}

protocol V3RecoveryRestoreFinalizationPhaseObserving: Sendable {
  func didReach(_ phase: V3RecoveryRestoreFinalizationPhase) throws
}

private struct V3NoopRestoreFinalizationObserver: V3RecoveryRestoreFinalizationPhaseObserving {
  func didReach(_: V3RecoveryRestoreFinalizationPhase) throws {}
}

struct V3RecoveryRestoreFinalizationReport: Equatable, Sendable {
  let checkpoint: V3ManifestCheckpoint
  let entryCount: Int
  let reservationWasAlreadyCleared: Bool
}

/// Explicit selected-vault finalization. One fresh ordinary Mac wrapper proves
/// access before exact reservation/preparation CAS removal, in that order.
/// No source mutation, publication, config selection, credential creation,
/// token operation, file deletion, saved consent or automatic retry.
/// Caller supplies fresh source/authentication scope and serializes this call.
struct V3RecoveryRestoreFinalizer: Sendable {
  private let journal: V3RecoveryRestoreJournal
  private let checkpoints: any V3ManifestCheckpointStoring
  private let cache: any V3CheckpointManifestCaching
  private let identities: any V3DeviceWrappedIdentityLoading
  private let observer: any V3RecoveryRestoreFinalizationPhaseObserving

  init(
    journal: V3RecoveryRestoreJournal, checkpoints: any V3ManifestCheckpointStoring,
    cache: any V3CheckpointManifestCaching, identities: any V3DeviceWrappedIdentityLoading,
    observer: any V3RecoveryRestoreFinalizationPhaseObserving = V3NoopRestoreFinalizationObserver()
  ) {
    self.journal = journal
    self.checkpoints = checkpoints
    self.cache = cache
    self.identities = identities
    self.observer = observer
  }

  /// Nil means only "no locally owned pending attempt", never a success claim.
  func finalize(
    sourceVaultID: String, snapshot: V3RecoveryVerifiedSnapshot, vaultKey: Data,
    source: VaultRootDirectoryHandle, destination: VaultRootDirectoryHandle,
    parent: VaultRootDirectoryHandle, configStore: KeyConfigStore
  ) throws -> V3RecoveryRestoreFinalizationReport? {
    guard var state = try journal.loadFinalization(sourceVaultID: sourceVaultID),
      let bundle = state.pending.preparation
    else { return nil }
    let checkpoint = bundle.intent.destinationCheckpoint
    let environment = try V3RecoveryRestoreEnvironment.reopenForCompletion(
      source: source, destination: destination, parent: parent, configStore: configStore,
      expected: bundle.intent.locations, vaultID: checkpoint.vaultID)
    guard environment.hasSelectedConfiguration else {
      throw V3RecoveryRestoreError.configurationRequired
    }
    func requireLocalTrust() throws {
      guard try checkpoints.loadCheckpoint(vaultID: checkpoint.vaultID) == checkpoint.canonicalBytes
      else { throw V3RecoveryRestoreTrustError.conflictingCheckpoint }
      guard case .available(let bytes) = try cache.load(for: checkpoint),
        bytes == bundle.manifest.canonicalBytes
      else { throw V3RecoveryRestoreTrustError.cacheUnavailable }
    }
    func recheck(_ expected: V3RecoveryRestoreFinalizationState) throws {
      try requireLocalTrust()
      guard
        try V3RecoveryRestorePublisher(journal: journal).confirmFinalization(
          expected, snapshot: snapshot, environment: environment, vaultKey: vaultKey,
          expectedOwner: bundle.manifest.body.devices[0].identity
        ).canonicalBytes == bundle.canonicalBytes
      else { throw V3RecoveryRestoreTrustError.preparationUnavailable }
      try requireLocalTrust()
      try environment.requireCurrent(bundle.intent.locations)
    }
    let initial = state
    try recheck(initial)
    try V3RecoveryRestoreOrdinaryReopener(
      checkpoints: checkpoints, cache: cache, identities: identities
    ).verify(bundle: bundle, snapshot: snapshot, environment: environment, vaultKey: vaultKey) {
      try recheck(initial)
    }
    try observer.didReach(.completionVerified)
    try recheck(state)
    state = try journal.clearFinalizationReservation(state)
    try observer.didReach(.reservationCleared)
    try recheck(state)
    state = try journal.clearFinalizationPreparation(state)
    try observer.didReach(.preparationCleared)
    try recheck(state)
    try observer.didReach(.completionConfirmed)
    try recheck(state)
    return .init(
      checkpoint: checkpoint, entryCount: snapshot.entries.count,
      reservationWasAlreadyCleared: initial.stage == .reservationCleared)
  }
}
