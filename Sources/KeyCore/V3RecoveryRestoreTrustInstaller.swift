import Foundation

enum V3RecoveryRestoreTrustError: Error, Equatable {
  case preparationUnavailable, conflictingCheckpoint, identityUnavailable, reopenMismatch,
    cacheUnavailable
}

enum V3RecoveryRestoreTrustPhase: Equatable, Sendable {
  case publishedSnapshotVerified, deviceWrapperVerified, manifestCached, checkpointInstalled
  case ordinaryReopenVerified
}

protocol V3RecoveryRestoreTrustPhaseObserving: Sendable {
  func didReach(_ phase: V3RecoveryRestoreTrustPhase) throws
}

struct V3NoopRestoreTrustObserver: V3RecoveryRestoreTrustPhaseObserving {
  func didReach(_: V3RecoveryRestoreTrustPhase) throws {}
}

/// Exact local trust/reopen evidence, not saved approval or config selection.
struct V3RecoveryRestoreTrustReport: Equatable, Sendable {
  let checkpoint: V3ManifestCheckpoint
  let ownerDeviceID: String
  let entryCount: Int
}

/// Insert-only first trust followed by a fresh ordinary permanent-profile read.
/// Caller owns serialization and fresh source/key/identity authentication scope.
/// No publication, key creation, configuration, cleanup or shared session.
struct V3RecoveryRestoreTrustInstaller: Sendable {
  private let journal: V3RecoveryRestoreJournal
  private let checkpoints: any V3ManifestCheckpointStoring
  private let cache: any V3CheckpointManifestCaching
  private let identities: any V3DeviceWrappedIdentityLoading
  private let observer: any V3RecoveryRestoreTrustPhaseObserving

  init(
    journal: V3RecoveryRestoreJournal, checkpoints: any V3ManifestCheckpointStoring,
    cache: any V3CheckpointManifestCaching, identities: any V3DeviceWrappedIdentityLoading,
    observer: any V3RecoveryRestoreTrustPhaseObserving = V3NoopRestoreTrustObserver()
  ) {
    self.journal = journal
    self.checkpoints = checkpoints
    self.cache = cache
    self.identities = identities
    self.observer = observer
  }

  func install(
    sourceVaultID: String, snapshot: V3RecoveryVerifiedSnapshot,
    environment: V3RecoveryRestoreEnvironment, vaultKey: Data,
    validateScope: () throws -> Void = {}
  ) throws -> V3RecoveryRestoreTrustReport {
    try validateScope()
    guard let pending = try journal.loadPending(sourceVaultID: sourceVaultID),
      let saved = pending.preparation, pending.preparationOwnership?.phase == .recoverable
    else { throw V3RecoveryRestoreTrustError.preparationUnavailable }
    let checkpoint = saved.intent.destinationCheckpoint
    try environment.requireSelectionMatches(vaultID: checkpoint.vaultID)
    let prior = try checkpoints.loadCheckpoint(vaultID: checkpoint.vaultID)
    // Config cannot justify reconstructing missing trust after selection.
    guard !environment.hasSelectedConfiguration || prior == checkpoint.canonicalBytes else {
      throw V3RecoveryRestoreTrustError.conflictingCheckpoint
    }
    guard prior == nil || prior == checkpoint.canonicalBytes else {
      throw V3RecoveryRestoreTrustError.conflictingCheckpoint
    }
    try pending.reservation.requireSnapshot(snapshot)
    try environment.requireCurrent(saved.intent.locations)
    try environment.requireSnapshot(snapshot)
    try validateScope()
    guard
      let identity = try identities.loadDeviceIdentity(
        vaultID: checkpoint.vaultID, reason: "Load this Mac's saved restored-vault credentials."),
      identity.vaultID == checkpoint.vaultID,
      identity.publicIdentity == saved.manifest.body.devices[0].identity
    else { throw V3RecoveryRestoreTrustError.identityUnavailable }
    let publisher = V3RecoveryRestorePublisher(journal: journal)
    let bundle = try publisher.confirmPublished(
      sourceVaultID: sourceVaultID, snapshot: snapshot, environment: environment,
      vaultKey: vaultKey, expectedOwner: identity.publicIdentity)
    func recheck(_ expectedCheckpoint: Data?, requireCache: Bool = false) throws {
      try validateScope()
      guard try checkpoints.loadCheckpoint(vaultID: checkpoint.vaultID) == expectedCheckpoint else {
        throw V3RecoveryRestoreTrustError.conflictingCheckpoint
      }
      guard
        try publisher.confirmPublished(
          sourceVaultID: sourceVaultID, snapshot: snapshot, environment: environment,
          vaultKey: vaultKey, expectedOwner: identity.publicIdentity
        ).canonicalBytes == bundle.canonicalBytes
      else { throw V3RecoveryRestoreTrustError.preparationUnavailable }
      if requireCache {
        guard case .available(let bytes) = try cache.load(for: checkpoint),
          bytes == bundle.manifest.canonicalBytes
        else { throw V3RecoveryRestoreTrustError.cacheUnavailable }
      }
      guard try checkpoints.loadCheckpoint(vaultID: checkpoint.vaultID) == expectedCheckpoint else {
        throw V3RecoveryRestoreTrustError.conflictingCheckpoint
      }
      try validateScope()
    }
    try observer.didReach(.publishedSnapshotVerified)
    try recheck(prior)
    let validation = V3DeviceWrappedVaultKeySessionStore()
    defer { validation.invalidate() }
    _ = try V3DeviceWrappedCheckpointUnlocker().unlock(
      checkpoint: checkpoint, manifestData: bundle.manifest.canonicalBytes,
      identity: identity, session: validation,
      reason: "Verify this Mac's saved restored-vault access before installing local trust.",
      validateBeforeSessionInstall: { try recheck(prior) })
    guard
      try validation.load(vaultID: checkpoint.vaultID, keyID: bundle.intent.destinationKeyID)
        == vaultKey
    else { throw V3RecoveryRestoreTrustError.reopenMismatch }
    try observer.didReach(.deviceWrapperVerified)
    try recheck(prior)
    // Cache is encrypted, non-authoritative and replaceable. Trust is insert-only.
    try cache.store(bundle.manifest.canonicalBytes, for: checkpoint)
    try observer.didReach(.manifestCached)
    try recheck(prior, requireCache: true)
    if prior == nil {
      try validateScope()
      try checkpoints.replaceCheckpoint(
        checkpoint.canonicalBytes, expectedCheckpoint: nil, vaultID: checkpoint.vaultID)
    }
    try observer.didReach(.checkpointInstalled)
    try recheck(checkpoint.canonicalBytes, requireCache: true)
    validation.invalidate()

    try V3RecoveryRestoreOrdinaryReopener(
      checkpoints: checkpoints, cache: cache, identities: identities
    ).verify(bundle: bundle, snapshot: snapshot, environment: environment, vaultKey: vaultKey) {
      try recheck(checkpoint.canonicalBytes, requireCache: true)
    }
    try observer.didReach(.ordinaryReopenVerified)
    try recheck(checkpoint.canonicalBytes, requireCache: true)
    return .init(
      checkpoint: checkpoint, ownerDeviceID: bundle.intent.ownerDeviceID,
      entryCount: snapshot.entries.count)
  }
}

/// Shared ordinary-access proof for first trust and selected finalization.
/// The caller's recheck spans the independent private operation and item reads.
struct V3RecoveryRestoreOrdinaryReopener: Sendable {
  let checkpoints: any V3ManifestCheckpointStoring
  let cache: any V3CheckpointManifestCaching
  let identities: any V3DeviceWrappedIdentityLoading

  func verify(
    bundle: V3RecoveryRestoreBundle, snapshot: V3RecoveryVerifiedSnapshot,
    environment: V3RecoveryRestoreEnvironment, vaultKey: Data,
    recheck: () throws -> Void
  ) throws {
    let checkpoint = bundle.intent.destinationCheckpoint
    try recheck()
    // No prepared key is injected into this new session. The ordinary runtime
    // must independently load the identity and open the published Mac wrapper.
    let session = V3DeviceWrappedVaultKeySessionStore()
    defer { session.invalidate() }
    let source = V3FilesystemTransactionArtifactStore(rootHandle: environment.destination)
    let unlock = V3DeviceWrappedVaultUnlockRuntime(
      vaultID: checkpoint.vaultID, checkpointStore: checkpoints, source: source, cache: cache,
      identityLoader: identities, session: session)
    let runtime = V3DeviceWrappedReadOnlyVaultRuntime(source: source, unlockRuntime: unlock)
    try runtime.unlock()
    try recheck()
    let expected = snapshot.entries.sorted {
      Data($0.name.utf8).lexicographicallyPrecedes(Data($1.name.utf8))
    }
    guard try runtime.list(allowStale: false) == expected.map(\.name),
      try session.load(vaultID: checkpoint.vaultID, keyID: bundle.intent.destinationKeyID)
        == vaultKey
    else { throw V3RecoveryRestoreTrustError.reopenMismatch }
    for entry in expected {
      let value = try runtime.read(name: entry.name, allowStale: false)
      guard value.type == entry.type, Data(value.plaintext.utf8) == Data(entry.plaintext.utf8)
      else {
        throw V3RecoveryRestoreTrustError.reopenMismatch
      }
    }
    try recheck()
  }
}
