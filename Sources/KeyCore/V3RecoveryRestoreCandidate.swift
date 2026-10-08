import CryptoKit
import Foundation

enum V3RecoveryRestoreCandidateError: Error, Equatable {
  case reusedSourceAuthority
  case invalidCandidate
}

/// An unpublished permanent-profile replacement for one verified snapshot.
/// Plaintext is scoped memory, not restore intent. Directory/token binding,
/// durable ownership, publication and configuration selection belong to restore
/// orchestration. This value grants none of those authorities.
struct V3RecoveryRestoreCandidate: Sendable {
  let snapshot: V3RecoveryVerifiedSnapshot
  let publication: V3DeviceWrappedGenesisPublicationCandidate
  fileprivate init(
    snapshot: V3RecoveryVerifiedSnapshot, publication: V3DeviceWrappedGenesisPublicationCandidate
  ) {
    self.snapshot = snapshot
    self.publication = publication
  }
}

/// Source-bound preparation and independent full candidate validation. The
/// future restore owner supplies freshly generated IDs/key/device credentials;
/// this component neither generates nor persists them, and performs no private
/// operation. Existing genesis/entry crypto remains the only encoding path.
struct V3RecoveryRestoreCandidateBuilder: Sendable {
  private let verifier: V3RecoverySnapshotVerifier
  private let limits: V3ManifestRepositoryLimits

  init(
    source: any V3ImmutableObjectReading, limits: V3ManifestRepositoryLimits = .standard,
    maximumParentEdges: Int = 16_384
  ) {
    verifier = .init(source: source, limits: limits, maximumParentEdges: maximumParentEdges)
    self.limits = limits
  }

  func build(
    restoring snapshot: V3RecoveryVerifiedSnapshot, vaultID: String,
    authorityTransitionID: String, entryIDs: [String], vaultKey: Data,
    ownerIdentity: V3EnrollmentDeviceIdentity
  ) throws -> V3RecoveryRestoreCandidate {
    try revalidate(snapshot)
    try requireFreshAuthority(
      vaultID: vaultID, transitionID: authorityTransitionID, entryIDs: entryIDs,
      snapshot: snapshot, owner: ownerIdentity)
    let publication = try V3DeviceWrappedGenesisBuilder().buildPublicationCandidate(
      vaultID: vaultID, authorityTransitionID: authorityTransitionID, entryIDs: entryIDs,
      snapshotEntries: snapshot.entries, vaultKey: vaultKey, ownerIdentity: ownerIdentity)
    try validate(
      publication, restoring: snapshot, vaultKey: vaultKey, expectedOwner: ownerIdentity)
    return .init(snapshot: snapshot, publication: publication)
  }

  /// Also usable when an owned resume path reconstructs its exact encrypted
  /// artifacts. This verifies contents, not directory ownership or a resume pin.
  /// The destination wrapper still needs an addressed Mac opening before trust.
  func validate(
    _ publication: V3DeviceWrappedGenesisPublicationCandidate,
    restoring snapshot: V3RecoveryVerifiedSnapshot, vaultKey: Data,
    expectedOwner: V3EnrollmentDeviceIdentity
  ) throws {
    try revalidate(snapshot)
    let genesis = publication.genesis
    let fields = genesis.body.fields
    try requireFreshAuthority(
      vaultID: fields.vaultID, transitionID: fields.authorityTransitionID,
      entryIDs: fields.entries.map(\.entryID), snapshot: snapshot, owner: expectedOwner)
    guard genesis.manifestData.count <= limits.maximumManifestBytes else {
      throw V3RecoveryValidationError.resourceLimit
    }
    let envelope = try V3DeviceWrappedManifestEnvelopeCodec().parse(genesis.manifestData)
    guard Data(SHA256.hash(data: genesis.manifestData)) == genesis.manifestDigest,
      envelope.body == genesis.body, envelope.parents.isEmpty, envelope.authorizations.isEmpty,
      fields.devices == [.init(identity: expectedOwner, status: .active)],
      fields.wrappedKeys.count == 1,
      fields.wrappedKeys[0].recipientDeviceID == expectedOwner.deviceID,
      fields.keyID == (try V3VaultKeyID.derive(vaultKey: vaultKey, vaultID: fields.vaultID)),
      try V3ManifestAuthenticator.isValidAuthenticationTag(
        envelope.authenticationTag, canonicalContent: envelope.canonicalContentBytes,
        vaultID: fields.vaultID, vaultKey: vaultKey),
      publication.entries.map(\.manifestEntry) == fields.entries
    else { throw V3RecoveryRestoreCandidateError.invalidCandidate }

    let validator = V3EntrySnapshotValidator(limits: limits)
    let entries = try validator.entryMap(publication.entries.map(\.encryptedEntry))
    let plaintexts = try validator.plaintexts(fields: fields, entries: entries, vaultKey: vaultKey)
    guard publication.entries.count == snapshot.entries.count else {
      throw V3RecoveryRestoreCandidateError.invalidCandidate
    }
    let expected = Dictionary(
      uniqueKeysWithValues: snapshot.entries.map { (Data($0.name.utf8), $0) })
    for entry in publication.entries {
      guard let original = expected[Data(entry.manifestEntry.name.utf8)],
        original.type == entry.manifestEntry.type, entry.manifestEntry.revision == 1,
        entry.source.type == original.type,
        Data(entry.source.name.utf8) == Data(original.name.utf8),
        Data(entry.source.plaintext.utf8) == Data(original.plaintext.utf8),
        plaintexts[entry.manifestEntry.entryID] == Data(original.plaintext.utf8),
        entry.digest == Data(SHA256.hash(data: entry.encryptedEntry.canonicalBytes))
      else { throw V3RecoveryRestoreCandidateError.invalidCandidate }
    }
    // A synchronous crypto step does not freeze a concurrently delivered source.
    try revalidate(snapshot)
  }

  /// Reconstitutes the verifier-only value from exact saved artifacts, never
  /// resealing or generating a new wrapper. Full validation remains mandatory.
  func validateAndBind(
    _ publication: V3DeviceWrappedGenesisPublicationCandidate,
    restoring snapshot: V3RecoveryVerifiedSnapshot, vaultKey: Data,
    expectedOwner: V3EnrollmentDeviceIdentity
  ) throws -> V3RecoveryRestoreCandidate {
    try validate(publication, restoring: snapshot, vaultKey: vaultKey, expectedOwner: expectedOwner)
    return .init(snapshot: snapshot, publication: publication)
  }

  private func revalidate(_ snapshot: V3RecoveryVerifiedSnapshot) throws {
    try verifier.revalidate(
      snapshot, boundAnchor: snapshot.selection.anchor,
      credentialPublicKey: snapshot.selection.credentialPublicKey)
  }

  private func requireFreshAuthority(
    vaultID: String, transitionID: String, entryIDs: [String],
    snapshot: V3RecoveryVerifiedSnapshot,
    owner: V3EnrollmentDeviceIdentity
  ) throws {
    let original = snapshot.selection.head.body.fields
    let sourceIDs = Set(original.entries.map(\.entryID))
    let newIDs = [vaultID, transitionID] + entryIDs
    let sourceKeys = Set(
      original.devices.flatMap { [$0.identity.signingPublicKey, $0.identity.wrappingPublicKey] }
        + snapshot.selection.head.body.recovery.recipients.map(\.publicKey))
    guard vaultID != original.vaultID,
      transitionID != original.authorityTransitionID,
      Set(newIDs).count == newIDs.count,
      entryIDs.allSatisfy({ !sourceIDs.contains($0) }),
      !sourceKeys.contains(owner.signingPublicKey), !sourceKeys.contains(owner.wrappingPublicKey)
    else { throw V3RecoveryRestoreCandidateError.reusedSourceAuthority }
  }
}
