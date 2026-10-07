import Foundation

enum V3RecoveryRestoreSelectionPhase: Equatable, Sendable {
  case restoreVerified, configurationSelected, selectionConfirmed
}

protocol V3RecoveryRestoreSelectionPhaseObserving: Sendable {
  func didReach(_ phase: V3RecoveryRestoreSelectionPhase) throws
}

private struct V3NoopRestoreSelectionObserver: V3RecoveryRestoreSelectionPhaseObserving {
  func didReach(_: V3RecoveryRestoreSelectionPhase) throws {}
}

struct V3RecoveryRestoreSelectionReport: Equatable, Sendable {
  let trust: V3RecoveryRestoreTrustReport
  let wasAlreadySelected: Bool
}

/// Freshly verifies trust and ordinary access before no-overwrite selection.
/// Explicit continuation accepts only exact selected bytes and existing trust.
/// Retains both ownership pins and records; this is not final cleanup or consent.
/// Caller supplies current authentication scope and serializes the whole call.
struct V3RecoveryRestoreSelectionInstaller: Sendable {
  private let journal: V3RecoveryRestoreJournal
  private let checkpoints: any V3ManifestCheckpointStoring
  private let cache: any V3CheckpointManifestCaching
  private let identities: any V3DeviceWrappedIdentityLoading
  private let observer: any V3RecoveryRestoreSelectionPhaseObserving
  private let writeObserver: any V3AtomicStagedObjectWriteObserving

  init(
    journal: V3RecoveryRestoreJournal, checkpoints: any V3ManifestCheckpointStoring,
    cache: any V3CheckpointManifestCaching, identities: any V3DeviceWrappedIdentityLoading,
    observer: any V3RecoveryRestoreSelectionPhaseObserving = V3NoopRestoreSelectionObserver(),
    writeObserver: any V3AtomicStagedObjectWriteObserving = V3NoopAtomicStagedObjectWriteObserver()
  ) {
    self.journal = journal
    self.checkpoints = checkpoints
    self.cache = cache
    self.identities = identities
    self.observer = observer
    self.writeObserver = writeObserver
  }

  func select(
    sourceVaultID: String, snapshot: V3RecoveryVerifiedSnapshot, vaultKey: Data,
    source: VaultRootDirectoryHandle, destination: VaultRootDirectoryHandle,
    parent: VaultRootDirectoryHandle, configStore: KeyConfigStore
  ) throws -> V3RecoveryRestoreSelectionReport {
    guard let pending = try journal.loadPending(sourceVaultID: sourceVaultID),
      let bundle = pending.preparation,
      pending.reservationOwnership.phase == .recoverable,
      pending.preparationOwnership?.phase == .recoverable
    else { throw V3RecoveryRestoreTrustError.preparationUnavailable }
    let environment = try V3RecoveryRestoreEnvironment.reopenForCompletion(
      source: source, destination: destination, parent: parent, configStore: configStore,
      expected: bundle.intent.locations, vaultID: bundle.intent.destinationCheckpoint.vaultID)
    let wasAlreadySelected = environment.hasSelectedConfiguration
    let trust = try V3RecoveryRestoreTrustInstaller(
      journal: journal, checkpoints: checkpoints, cache: cache, identities: identities
    ).install(
      sourceVaultID: sourceVaultID, snapshot: snapshot, environment: environment, vaultKey: vaultKey
    )
    let verification = Verification(
      journal: journal, checkpoints: checkpoints, cache: cache,
      sourceVaultID: sourceVaultID, snapshot: snapshot, vaultKey: vaultKey,
      pending: pending, environment: environment)
    try observer.didReach(.restoreVerified)
    try verification.requireCurrent()
    let selected = try environment.selectConfiguration(
      configStore: configStore, vaultID: trust.checkpoint.vaultID,
      beforePublication: { try verification.requireCurrent() }, writeObserver: writeObserver)
    let selectedVerification = Verification(
      journal: journal, checkpoints: checkpoints, cache: cache,
      sourceVaultID: sourceVaultID, snapshot: snapshot, vaultKey: vaultKey,
      pending: pending, environment: selected)
    try observer.didReach(.configurationSelected)
    try selectedVerification.requireCurrent()
    try observer.didReach(.selectionConfirmed)
    try selectedVerification.requireCurrent()
    return .init(trust: trust, wasAlreadySelected: wasAlreadySelected)
  }

  private struct Verification: Sendable {
    let journal: V3RecoveryRestoreJournal
    let checkpoints: any V3ManifestCheckpointStoring
    let cache: any V3CheckpointManifestCaching
    let sourceVaultID: String
    let snapshot: V3RecoveryVerifiedSnapshot
    let vaultKey: Data
    let pending: V3RecoveryRestorePending
    let environment: V3RecoveryRestoreEnvironment

    func requireCurrent() throws {
      guard let bundle = pending.preparation else {
        throw V3RecoveryRestoreTrustError.preparationUnavailable
      }
      let checkpoint = bundle.intent.destinationCheckpoint
      guard
        try checkpoints.loadCheckpoint(vaultID: checkpoint.vaultID) == checkpoint.canonicalBytes,
        case .available(let bytes) = try cache.load(for: checkpoint),
        bytes == bundle.manifest.canonicalBytes,
        try journal.loadPending(sourceVaultID: sourceVaultID) == pending
      else { throw V3RecoveryRestoreTrustError.preparationUnavailable }
      guard
        try V3RecoveryRestorePublisher(journal: journal).confirmPublished(
          sourceVaultID: sourceVaultID, snapshot: snapshot, environment: environment,
          vaultKey: vaultKey, expectedOwner: bundle.manifest.body.devices[0].identity
        ).canonicalBytes == bundle.canonicalBytes,
        try checkpoints.loadCheckpoint(vaultID: checkpoint.vaultID) == checkpoint.canonicalBytes,
        case .available(let finalBytes) = try cache.load(for: checkpoint),
        finalBytes == bundle.manifest.canonicalBytes,
        try journal.loadPending(sourceVaultID: sourceVaultID) == pending
      else { throw V3RecoveryRestoreTrustError.preparationUnavailable }
      try environment.requireCurrent(bundle.intent.locations)
    }
  }
}
