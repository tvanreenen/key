import CryptoKit
import Foundation

enum V3RecoveryRegistrationJournalError: Error, Equatable {
  case registrationPending
  case preparationUnavailable
  case invalidOwnership
  case invalidPreparation
  case ownershipChanged
}

/// A complete bundle becomes durable without overwrite before this returns.
/// The registration namespace is separate from ordinary transaction discovery.
protocol V3RecoveryRegistrationBundleStoring: Sendable {
  func persistRegistrationBundle(_ data: Data, operationID: VaultTransactionOperationID) throws
  func readRegistrationBundle(
    operationID: VaultTransactionOperationID, maximumBytes: Int
  ) throws -> V3RepositoryObjectRead
  /// Confirm exact bytes and local durability, including after an interrupted
  /// installation. Availability alone is not evidence of completed fsync.
  func confirmRegistrationBundle(_ data: Data, operationID: VaultTransactionOperationID) throws
}

enum V3RecoveryRegistrationJournalPhase: Equatable, Sendable {
  case ownershipReserved
  case bundlePersisted
  case bundleVerified
  case exportReady
}

protocol V3RecoveryRegistrationJournalPhaseObserving: Sendable {
  func didReach(_ phase: V3RecoveryRegistrationJournalPhase) throws
}

private struct V3NoopRegistrationJournalObserver: V3RecoveryRegistrationJournalPhaseObserving {
  func didReach(_: V3RecoveryRegistrationJournalPhase) throws {}
}

/// Stages one locally owned candidate and reloads it without new randomness.
///
/// Call under the helper's mutation owner, with fresh checkpoint/source checks.
/// Supply a dedicated non-synchronizing registration ownership store, not the
/// ordinary transaction store. This component does not scan provider records,
/// clear incomplete state, publish, save possession approval or contact a token.
struct V3RecoveryRegistrationJournal: Sendable {
  private let bundleStore: any V3RecoveryRegistrationBundleStoring
  private let ownershipStore: any V3ImmutableTransactionRecoveryAnchorStoring
  private let validator: V3RecoveryRegistrationValidator
  private let limits: V3ManifestRepositoryLimits
  private let observer: any V3RecoveryRegistrationJournalPhaseObserving

  init(
    bundleStore: any V3RecoveryRegistrationBundleStoring,
    ownershipStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    limits: V3ManifestRepositoryLimits = .standard,
    observer: any V3RecoveryRegistrationJournalPhaseObserving = V3NoopRegistrationJournalObserver()
  ) {
    self.bundleStore = bundleStore
    self.ownershipStore = ownershipStore
    self.limits = limits
    validator = V3RecoveryRegistrationValidator(limits: limits)
    self.observer = observer
  }

  /// Full crypto/source validation precedes any reservation or disk write.
  /// Returns only the exact public anchor, never registration readiness.
  func stageAndExport(
    _ preparation: V3RecoveryRegistrationPreparation, checkpoint: V3ManifestCheckpoint,
    parent: V3RecoveryManifestEnvelope, currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
    currentVaultKey: Data, nextVaultKey: Data, expectedOwner: V3EnrollmentDeviceIdentity
  ) throws -> Data {
    guard try ownershipStore.loadRecoveryAnchor(vaultID: checkpoint.vaultID) == nil else {
      throw V3RecoveryRegistrationJournalError.registrationPending
    }
    try validator.validate(
      preparation, checkpoint: checkpoint, parent: parent, currentEntries: currentEntries,
      currentVaultKey: currentVaultKey, nextVaultKey: nextVaultKey, expectedOwner: expectedOwner)
    let bundle = try V3RecoveryRegistrationBundle(preparation: preparation, limits: limits)
    let anchor = try ownership(preparation.intent, phase: .prepared)
    try ownershipStore.replaceRecoveryAnchor(
      anchor.canonicalBytes, expectedAnchor: nil, vaultID: checkpoint.vaultID)
    try observer.didReach(.ownershipReserved)
    try bundleStore.persistRegistrationBundle(
      bundle.canonicalBytes, operationID: preparation.intent.operationID)
    try observer.didReach(.bundlePersisted)
    return try resumeAndExport(
      checkpoint: checkpoint, parent: parent, currentEntries: currentEntries,
      currentVaultKey: currentVaultKey, nextVaultKey: nextVaultKey, expectedOwner: expectedOwner)
  }

  /// Local ownership selects one exact bundle. No record means no pending work,
  /// even if provider files exist. This is parsed evidence, not trusted content.
  /// Before opening the candidate's local wrapper, a service must authenticate
  /// the intent and bind the fresh parent/owner. It must fully revalidate before
  /// export/completion, and never publish this parsed result.
  func loadPending(vaultID: String) throws -> V3RecoveryRegistrationPreparation? {
    guard let bytes = try ownershipStore.loadRecoveryAnchor(vaultID: vaultID) else { return nil }
    let anchor = try decodeOwnership(bytes, vaultID: vaultID)
    return try loadBundle(anchor).preparation
  }

  /// The service must first verify the durable candidate checkpoint and
  /// published contents. Only local ownership is removed; the encrypted bundle
  /// remains inert for audit and cannot be adopted by another device.
  func clearCompleted(_ preparation: V3RecoveryRegistrationPreparation) throws {
    let vaultID = preparation.intent.expectedCheckpoint.vaultID
    guard let bytes = try ownershipStore.loadRecoveryAnchor(vaultID: vaultID) else {
      throw V3RecoveryRegistrationJournalError.invalidOwnership
    }
    let anchor = try decodeOwnership(bytes, vaultID: vaultID)
    guard anchor.phase == .recoverable,
      try loadBundle(anchor).preparation == preparation
    else { throw V3RecoveryRegistrationJournalError.invalidPreparation }
    try ownershipStore.replaceRecoveryAnchor(nil, expectedAnchor: bytes, vaultID: vaultID)
  }

  /// Revalidates complete old/new plaintexts and dual authorization after a
  /// restart. The caller supplies newly authenticated keys, not saved approval.
  /// No bundle is regenerated or rewritten, including when data is unavailable.
  func resumeAndExport(
    checkpoint: V3ManifestCheckpoint, parent: V3RecoveryManifestEnvelope,
    currentEntries: [V3EntryObjectKey: V3EncryptedEntry], currentVaultKey: Data,
    nextVaultKey: Data, expectedOwner: V3EnrollmentDeviceIdentity
  ) throws -> Data {
    guard let bytes = try ownershipStore.loadRecoveryAnchor(vaultID: checkpoint.vaultID) else {
      throw V3RecoveryRegistrationJournalError.invalidOwnership
    }
    let anchor = try decodeOwnership(bytes, vaultID: checkpoint.vaultID)
    let bundle = try loadBundle(anchor)
    let preparation = bundle.preparation
    try validator.validate(
      preparation, checkpoint: checkpoint, parent: parent, currentEntries: currentEntries,
      currentVaultKey: currentVaultKey, nextVaultKey: nextVaultKey, expectedOwner: expectedOwner)
    try observer.didReach(.bundleVerified)
    try bundleStore.confirmRegistrationBundle(
      bundle.canonicalBytes, operationID: anchor.operationID)
    let exportOwnership: Data
    if anchor.phase == .prepared {
      let recoverable = try ownership(preparation.intent, phase: .recoverable)
      try ownershipStore.replaceRecoveryAnchor(
        recoverable.canonicalBytes, expectedAnchor: bytes, vaultID: checkpoint.vaultID)
      exportOwnership = recoverable.canonicalBytes
    } else {
      exportOwnership = bytes
    }
    try requireOwnership(exportOwnership, vaultID: checkpoint.vaultID)
    try observer.didReach(.exportReady)
    try requireOwnership(exportOwnership, vaultID: checkpoint.vaultID)
    return preparation.exportedAnchor
  }

  private func ownership(
    _ intent: V3RecoveryRegistrationIntent, phase: V3ImmutableTransactionRecoveryAnchorPhase
  ) throws -> V3ImmutableTransactionRecoveryAnchor {
    try V3ImmutableTransactionRecoveryAnchor(
      operationID: intent.operationID, vaultID: intent.expectedCheckpoint.vaultID,
      intentDigest: Data(SHA256.hash(data: intent.canonicalBytes)), phase: phase)
  }

  private func decodeOwnership(_ bytes: Data, vaultID: String) throws
    -> V3ImmutableTransactionRecoveryAnchor
  {
    guard bytes.count <= 1_024,
      let anchor = try? V3ImmutableTransactionRecoveryAnchor(canonicalBytes: bytes),
      anchor.vaultID == vaultID
    else { throw V3RecoveryRegistrationJournalError.invalidOwnership }
    return anchor
  }

  private func loadBundle(_ anchor: V3ImmutableTransactionRecoveryAnchor) throws
    -> V3RecoveryRegistrationBundle
  {
    let bytes: Data
    switch try bundleStore.readRegistrationBundle(
      operationID: anchor.operationID,
      maximumBytes: V3RecoveryRegistrationBundle.maximumBytes(limits: limits))
    {
    case .unavailable: throw V3RecoveryRegistrationJournalError.preparationUnavailable
    case .invalid: throw V3RecoveryRegistrationJournalError.invalidPreparation
    case .tooLarge: throw V3RecoveryRegistrationError.resourceLimit
    case .available(let value): bytes = value
    }
    let bundle = try V3RecoveryRegistrationBundle(canonicalBytes: bytes, limits: limits)
    let intent = bundle.preparation.intent
    guard intent.operationID == anchor.operationID,
      intent.expectedCheckpoint.vaultID == anchor.vaultID,
      Data(SHA256.hash(data: intent.canonicalBytes)) == anchor.intentDigest
    else { throw V3RecoveryRegistrationJournalError.invalidPreparation }
    return bundle
  }

  private func requireOwnership(_ expected: Data, vaultID: String) throws {
    guard try ownershipStore.loadRecoveryAnchor(vaultID: vaultID) == expected else {
      throw V3RecoveryRegistrationJournalError.ownershipChanged
    }
  }
}
