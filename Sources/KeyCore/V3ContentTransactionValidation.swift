import Foundation

/// Profile-neutral transaction bytes, not an authenticated manifest or a
/// persisted authorization. Callers select one concrete profile validator.
struct V3ContentTransactionInput: Sendable {
  let kind: VaultTransactionMutationKind
  let expectedCheckpoint: V3ManifestCheckpoint
  let manifestData: Data
  let manifestDigest: Data
  let stagedEntries: [V3EncryptedEntry]
  let recoveryMerge: V3RecoveryMergeTransactionContext?

  init(
    kind: VaultTransactionMutationKind, expectedCheckpoint: V3ManifestCheckpoint,
    manifestData: Data, manifestDigest: Data, stagedEntries: [V3EncryptedEntry],
    recoveryMerge: V3RecoveryMergeTransactionContext? = nil
  ) {
    self.kind = kind
    self.expectedCheckpoint = expectedCheckpoint
    self.manifestData = manifestData
    self.manifestDigest = manifestDigest
    self.stagedEntries = stagedEntries
    self.recoveryMerge = recoveryMerge
  }
}

/// Exact selectors only. The locally pinned intent binds these bytes; neither
/// selectors nor synchronized intents authorize publication by themselves.
struct V3RecoveryMergeTransactionContext: Equatable, Sendable {
  let expectedHeads: [Data]
  let resolutions: [VaultConflictResolution]
}

protocol V3ValidatedContentTransaction: Sendable {
  var stagedEntries: [V3EntryObjectKey: V3EncryptedEntry] { get }
}

/// The shared durability kernel owns ordering and local intent/checkpoint CAS.
/// Profile validators own authentication, transition semantics and source
/// policy. There is deliberately no profile detection or token capability here.
protocol V3ContentTransactionValidating: Sendable {
  associatedtype Validated: V3ValidatedContentTransaction
  func requireAvailable(vaultID: String) throws
  func keyID(manifestData: Data) throws -> V3VaultKeyID
  func validateRecoveryIntent(_ intent: V3ImmutableTransactionRecoveryIntent) throws
  func recoveryIntent(
    for input: V3ContentTransactionInput, operationID: VaultTransactionOperationID,
    stagedEntries: [V3ImmutableTransactionRecoveryEntry]
  ) throws -> V3ImmutableTransactionRecoveryIntent
  func recoveryInput(
    intent: V3ImmutableTransactionRecoveryIntent, manifestData: Data,
    stagedEntries: [V3EncryptedEntry]
  ) throws -> V3ContentTransactionInput
  func validate(
    _ input: V3ContentTransactionInput, vaultKey: Data, alreadyCommitted: Bool
  ) throws -> Validated
  func recheck(
    _ input: V3ContentTransactionInput, validated: Validated, vaultKey: Data,
    alreadyCommitted: Bool
  ) throws
  func validateStagedObjects(_ validated: Validated, operationID: VaultTransactionOperationID)
    throws
  func validatePublishedEntries(_ validated: Validated) throws
  func validatePublishedManifest(_ validated: Validated) throws
}

extension V3ContentTransactionValidating {
  func validateRecoveryIntent(_ intent: V3ImmutableTransactionRecoveryIntent) throws {
    guard [.addEntry, .editEntry, .copyEntry, .moveEntry, .removeEntry].contains(intent.kind),
      intent.expectedHeads == [intent.expectedCheckpoint.envelopeDigest],
      intent.enrollmentTranscriptDigest == nil, intent.recoveryMergeResolutions == nil
    else {
      throw V3ImmutableTransactionRecoveryError.invalidIntent(
        operationID: intent.operationID.rawValue)
    }
  }
  func recoveryIntent(
    for input: V3ContentTransactionInput, operationID: VaultTransactionOperationID,
    stagedEntries: [V3ImmutableTransactionRecoveryEntry]
  ) throws -> V3ImmutableTransactionRecoveryIntent {
    guard input.recoveryMerge == nil else { throw V3ImmutableTransactionError.invalidAncestryProof }
    return try V3ImmutableTransactionRecoveryIntent(
      operationID: operationID, kind: input.kind, vaultID: input.expectedCheckpoint.vaultID,
      expectedCheckpoint: input.expectedCheckpoint,
      expectedHeads: [input.expectedCheckpoint.envelopeDigest],
      candidateManifestDigest: input.manifestDigest, stagedEntries: stagedEntries)
  }

  func recoveryInput(
    intent: V3ImmutableTransactionRecoveryIntent, manifestData: Data,
    stagedEntries: [V3EncryptedEntry]
  ) throws -> V3ContentTransactionInput {
    try validateRecoveryIntent(intent)
    return V3ContentTransactionInput(
      kind: intent.kind, expectedCheckpoint: intent.expectedCheckpoint,
      manifestData: manifestData, manifestDigest: intent.candidateManifestDigest,
      stagedEntries: stagedEntries)
  }
}

extension V3DeviceWrappedValidatedContentMutation: V3ValidatedContentTransaction {}

extension V3DeviceWrappedTransactionValidator: V3ContentTransactionValidating {
  func requireAvailable(vaultID _: String) throws {}
  func keyID(manifestData: Data) throws -> V3VaultKeyID {
    try V3DeviceWrappedManifestEnvelopeCodec().parse(manifestData).body.keyID
  }
  func validate(
    _ input: V3ContentTransactionInput, vaultKey: Data, alreadyCommitted _: Bool
  ) throws -> V3DeviceWrappedValidatedContentMutation {
    guard input.recoveryMerge == nil else { throw V3ImmutableTransactionError.invalidAncestryProof }
    return try validate(
      manifestData: input.manifestData, manifestDigest: input.manifestDigest,
      expectedCheckpoint: input.expectedCheckpoint, kind: input.kind,
      stagedEntries: input.stagedEntries, vaultKey: vaultKey)
  }
  func recheck(
    _ input: V3ContentTransactionInput, validated: V3DeviceWrappedValidatedContentMutation,
    vaultKey: Data, alreadyCommitted: Bool
  ) throws {
    let fresh = try validate(input, vaultKey: vaultKey, alreadyCommitted: alreadyCommitted)
    guard fresh.envelope == validated.envelope, fresh.stagedEntries == validated.stagedEntries
    else {
      throw V3ImmutableTransactionError.invalidAncestryProof
    }
  }
  func validatePublishedEntries(_ validated: V3DeviceWrappedValidatedContentMutation) throws {
    try validatePublishedEntries(validated.envelope)
  }
}
