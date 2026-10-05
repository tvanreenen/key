import Foundation

/// Profile-neutral transaction bytes, not an authenticated manifest or a
/// persisted authorization. Callers select one concrete profile validator.
struct V3ContentTransactionInput: Sendable {
  let kind: VaultTransactionMutationKind
  let expectedCheckpoint: V3ManifestCheckpoint
  let manifestData: Data
  let manifestDigest: Data
  let stagedEntries: [V3EncryptedEntry]
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

extension V3DeviceWrappedValidatedContentMutation: V3ValidatedContentTransaction {}

extension V3DeviceWrappedTransactionValidator: V3ContentTransactionValidating {
  func requireAvailable(vaultID _: String) throws {}
  func keyID(manifestData: Data) throws -> V3VaultKeyID {
    try V3DeviceWrappedManifestEnvelopeCodec().parse(manifestData).body.keyID
  }
  func validate(
    _ input: V3ContentTransactionInput, vaultKey: Data, alreadyCommitted _: Bool
  ) throws -> V3DeviceWrappedValidatedContentMutation {
    try validate(
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
