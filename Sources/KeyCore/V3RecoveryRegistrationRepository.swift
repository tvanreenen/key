import CryptoKit
import Foundation

/// Exact observed bytes, not an authorization to advance a checkpoint.
struct V3RecoveryRegistrationRepositoryState: Equatable, Sendable {
  let base: V3RecoveryManifestEnvelope
  let entries: [V3EntryObjectKey: V3EncryptedEntry]
  let manifestBytes: [Data: Data]
  let listedObjectCount: Int
  let candidatePublished: Bool
  let referencedEntries: [V3EntryObjectKey: V3EncryptedEntry]
  let usage: V3ManifestRepositoryUsage
}

/// Authenticate profile-3 registration observations around the shared bounded
/// exact-transition reader. No reduced recovery replay authorizes publication.
struct V3RecoveryRegistrationRepository: Sendable {
  let source: any V3ImmutableObjectReading
  let limits: V3ManifestRepositoryLimits
  private var objects: V3ExactTransitionRepository {
    V3ExactTransitionRepository(source: source, limits: limits)
  }

  func observe(
    checkpoint: V3ManifestCheckpoint, currentVaultKey: Data,
    candidate: V3RecoveryRegistrationPreparation? = nil, nextVaultKey: Data? = nil
  ) throws -> V3RecoveryRegistrationRepositoryState {
    let state = try objects.observe(
      checkpoint: checkpoint, expectedBase: objects.readManifest(checkpoint.envelopeDigest),
      candidate: candidate?.candidate, stagedEntries: candidate?.stagedEntries ?? [])
    let base = try V3RecoveryManifestCodec().parseEnvelope(state.baseBytes)
    let validator = V3RecoveryRegistrationValidator(limits: limits)
    try validator.validateParent(base, checkpoint: checkpoint, vaultKey: currentVaultKey)
    _ = try validator.plaintexts(base, entries: state.entries, vaultKey: currentVaultKey)
    if let candidate, state.candidatePublished {
      try V3RecoveryEpochBoundary().verifyBoundary(candidate.candidate, parent: base)
      if let nextVaultKey {
        try V3RecoveryEpochBoundary().verifyCurrentAuthentication(
          candidate.candidate, vaultKey: nextVaultKey)
        let staged = try V3EntrySnapshotValidator(limits: limits).entryMap(candidate.stagedEntries)
        _ = try validator.plaintexts(candidate.candidate, entries: staged, vaultKey: nextVaultKey)
      }
    }
    return V3RecoveryRegistrationRepositoryState(
      base: base, entries: state.entries, manifestBytes: state.manifestBytes,
      listedObjectCount: state.listedObjectCount, candidatePublished: state.candidatePublished,
      referencedEntries: state.referencedEntries, usage: state.usage)
  }

  func requireProjectedUsage(
    _ state: V3RecoveryRegistrationRepositoryState, candidate: V3RecoveryRegistrationPreparation
  ) throws {
    try objects.requireProjectedUsage(
      V3ExactTransitionRepositoryState(
        baseBytes: state.base.canonicalBytes, entries: state.entries,
        manifestBytes: state.manifestBytes,
        listedObjectCount: state.listedObjectCount, candidatePublished: state.candidatePublished,
        referencedEntries: state.referencedEntries, usage: state.usage),
      candidate: candidate.candidate, stagedEntries: candidate.stagedEntries)
  }

  func readManifest(_ digest: Data) throws -> Data { try objects.readManifest(digest) }
  func readEntry(_ key: V3EntryObjectKey) throws -> Data { try objects.readEntry(key) }
}
