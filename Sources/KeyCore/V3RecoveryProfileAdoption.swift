import CryptoKit
import Foundation
internal import JSONCanonicalization

enum V3RecoveryProfileAdoptionError: Error, Equatable {
  case invalidParent
  case invalidOwner
  case invalidCandidate
  case resourceLimit
  case localWrapperMismatch
}

/// One unpublished, signed profile-2 to profile-3 transition. No raw keys,
/// plaintext, recovery credential or saved approval is retained here.
struct V3RecoveryProfileAdoptionCandidate: Equatable, Sendable {
  let expectedCheckpoint: V3ManifestCheckpoint
  let envelope: V3RecoveryManifestEnvelope
  let stagedEntries: [V3EncryptedEntry]
}

/// Explicit format adoption is separate from registration and new genesis.
/// Preserve the exact roster and all entry metadata, rotate the vault key and
/// establish a fresh epoch capsule with no recovery recipients. The old active
/// Mac signs the complete child, including its exact old-profile parent digest.
/// No old epoch signature exists; no token or storage operation occurs here.
struct V3RecoveryProfileAdoptionBuilder: Sendable {
  private let limits: V3ManifestRepositoryLimits
  private let validator: V3RecoveryProfileAdoptionValidator

  init(limits: V3ManifestRepositoryLimits = .standard) {
    self.limits = limits
    validator = V3RecoveryProfileAdoptionValidator(limits: limits)
  }

  func build(
    from parent: V3DeviceWrappedTrustedCheckpoint,
    currentEntries: [V3EntryObjectKey: V3EncryptedEntry], currentVaultKey: Data,
    nextVaultKey: Data, owner: any V3EnrollmentMessageSigning, reason: String,
    authorityTransitionID: String = UUID().uuidString.lowercased(),
    generationID: String = UUID().uuidString.lowercased()
  ) throws -> V3RecoveryProfileAdoptionCandidate {
    try validator.validateParent(parent, currentVaultKey: currentVaultKey)
    let old = parent.envelope.body.fields
    guard !reason.isEmpty, owner.vaultID == old.vaultID,
      old.devices.contains(where: { $0.identity == owner.publicIdentity && $0.status == .active })
    else { throw V3RecoveryProfileAdoptionError.invalidOwner }
    let nextID = try V3VaultKeyID.derive(vaultKey: nextVaultKey, vaultID: old.vaultID)
    guard nextID != old.keyID, authorityTransitionID != old.authorityTransitionID,
      isValidV3UUID(authorityTransitionID), isValidV3UUID(generationID)
    else { throw V3RecoveryProfileAdoptionError.invalidCandidate }
    let snapshot = V3EntrySnapshotValidator(limits: limits)
    let plaintexts = try snapshot.plaintexts(
      fields: old, entries: currentEntries, vaultKey: currentVaultKey)
    let staged = try old.entries.map { record in
      guard let plaintext = plaintexts[record.entryID] else {
        throw V3EntrySnapshotValidationError.incompleteSnapshot
      }
      return try V3EntryCipher().seal(
        plaintext,
        context: V3EntryAuthenticationContext(
          vaultID: old.vaultID, entryID: record.entryID, name: record.name, type: record.type,
          keyID: nextID, revision: record.revision),
        vaultKey: nextVaultKey, nonce: AES.GCM.Nonce())
    }
    _ = try snapshot.entryMap(staged)
    let wrappers = try old.devices.compactMap { device -> V3DeviceWrappedManifestKey? in
      guard device.status == .active else { return nil }
      return try V3DeviceWrappedManifestKey(
        recipientDeviceID: device.identity.deviceID,
        wrappedKey: V3VaultKeyHPKE().wrap(
          vaultKey: nextVaultKey, recipientPublicKey: device.identity.wrappingPublicKey,
          context: V3VaultKeyHPKEContext(
            vaultID: old.vaultID, keyID: nextID, authorityTransitionID: authorityTransitionID,
            recipientDeviceID: device.identity.deviceID, wrappingProfile: .recovery)))
    }
    let body = try V3RecoveryManifestBody(
      fields: V3DeviceWrappedManifestFields(
        vaultID: old.vaultID, keyID: nextID, authorityTransitionID: authorityTransitionID,
        devices: old.devices, wrappedKeys: wrappers,
        entries: staged.map { V3ResealedEntry(encryptedEntry: $0).manifestEntry }),
      epochSigningKey: V3EpochSigningKeyCipher().prepare(
        context: V3EpochSigningKeyContext(
          vaultID: old.vaultID, keyID: nextID, authorityTransitionID: authorityTransitionID),
        vaultKey: nextVaultKey), transitionProof: nil,
      recovery: V3RecoveryRoster(generationID: generationID, recipients: [], wrappedKeys: []))
    // Bound and strictly parse all unsigned output before a private signature.
    guard limits.maximumManifestBytes >= 2_048,
      body.canonicalBytes.count <= limits.maximumManifestBytes - 2_048,
      try V3RecoveryManifestCodec().parseCanonicalBody(body.canonicalBytes) == .recovery(body)
    else { throw V3RecoveryProfileAdoptionError.resourceLimit }
    let boundary = V3RecoveryEpochBoundary()
    let unsigned = try boundary.encode(
      body: body, parents: [parent.checkpoint.envelopeDigest], vaultKey: nextVaultKey,
      authorizations: [])
    try boundary.verifyCurrentAuthentication(unsigned, vaultKey: nextVaultKey)
    let signature = try V3P256Signature.canonicalize(
      owner.signature(
        for: V3ManifestAuthenticator.authenticationInput(for: unsigned.canonicalContentBytes),
        reason: reason))
    let envelope = try boundary.encode(
      body: body, parents: unsigned.parents, vaultKey: nextVaultKey,
      authorizations: [
        V3ManifestAuthorization(
          signerDeviceID: owner.publicIdentity.deviceID, signature: Base64URL.encode(signature))
      ])
    let result = V3RecoveryProfileAdoptionCandidate(
      expectedCheckpoint: parent.checkpoint, envelope: envelope, stagedEntries: staged)
    try validator.validate(
      result, parent: parent, currentEntries: currentEntries, currentVaultKey: currentVaultKey,
      nextVaultKey: nextVaultKey, expectedOwner: owner.publicIdentity)
    return result
  }
}

/// Independent migration verification, not a provider-origin trust selector.
/// A service must guard its fresh local checkpoint, observed heads, resource
/// projection, durable intent and manifest-last publication outside this API.
struct V3RecoveryProfileAdoptionValidator: Sendable {
  private let limits: V3ManifestRepositoryLimits
  init(limits: V3ManifestRepositoryLimits = .standard) { self.limits = limits }

  func validate(
    _ candidate: V3RecoveryProfileAdoptionCandidate, parent: V3DeviceWrappedTrustedCheckpoint,
    currentEntries: [V3EntryObjectKey: V3EncryptedEntry], currentVaultKey: Data,
    nextVaultKey: Data, expectedOwner: V3EnrollmentDeviceIdentity
  ) throws {
    try validateParent(parent, currentVaultKey: currentVaultKey)
    let envelope = candidate.envelope
    let old = parent.envelope.body.fields
    let new = envelope.body.fields
    guard candidate.expectedCheckpoint == parent.checkpoint,
      envelope.canonicalBytes.count <= limits.maximumManifestBytes,
      try V3RecoveryManifestCodec().parseEnvelope(envelope.canonicalBytes) == envelope,
      envelope.parents == [parent.checkpoint.envelopeDigest],
      envelope.authorizations.map(\.signerDeviceID) == [expectedOwner.deviceID],
      old.devices.contains(where: { $0.identity == expectedOwner && $0.status == .active }),
      new.vaultID == old.vaultID, new.keyID != old.keyID,
      new.authorityTransitionID != old.authorityTransitionID, new.devices == old.devices,
      envelope.body.transitionProof == nil, envelope.body.recovery.recipients.isEmpty,
      envelope.body.recovery.wrappedKeys.isEmpty,
      try V3DeviceWrappedEnrollmentTransitionValidator(limits: limits)
        .isOwnerAuthorizedDirectChildEnvelope(
          manifestData: envelope.canonicalBytes, manifestDigest: envelope.digest, parent: parent,
          currentVaultKey: currentVaultKey)
    else { throw V3RecoveryProfileAdoptionError.invalidCandidate }
    try V3RecoveryEpochBoundary().verifyCurrentAuthentication(envelope, vaultKey: nextVaultKey)
    guard old.entries.count == new.entries.count,
      zip(old.entries, new.entries).allSatisfy({
        $0.entryID == $1.entryID && $0.name == $1.name && $0.type == $1.type
          && $0.revision == $1.revision && $0.ciphertextDigest != $1.ciphertextDigest
      })
    else { throw V3RecoveryProfileAdoptionError.invalidCandidate }
    let snapshot = V3EntrySnapshotValidator(limits: limits)
    let before = try snapshot.plaintexts(
      fields: old, entries: currentEntries, vaultKey: currentVaultKey)
    let after = try snapshot.plaintexts(
      fields: new, entries: snapshot.entryMap(candidate.stagedEntries), vaultKey: nextVaultKey)
    guard before == after else { throw V3RecoveryProfileAdoptionError.invalidCandidate }
  }

  /// Full software checks precede one local wrapper opening. Cancellation or
  /// mismatch prevents publication; this output stores no approval to reuse.
  func validateForPublication(
    _ candidate: V3RecoveryProfileAdoptionCandidate, parent: V3DeviceWrappedTrustedCheckpoint,
    currentEntries: [V3EntryObjectKey: V3EncryptedEntry], currentVaultKey: Data,
    nextVaultKey: Data, identity: any V3DeviceWrappedVaultKeyUnwrapping, reason: String
  ) throws {
    guard !reason.isEmpty, identity.vaultID == parent.checkpoint.vaultID else {
      throw V3RecoveryProfileAdoptionError.invalidOwner
    }
    try validate(
      candidate, parent: parent, currentEntries: currentEntries, currentVaultKey: currentVaultKey,
      nextVaultKey: nextVaultKey, expectedOwner: identity.publicIdentity)
    guard
      let local = candidate.envelope.body.fields.wrappedKeys.first(where: {
        $0.recipientDeviceID == identity.publicIdentity.deviceID
      })
    else { throw V3RecoveryProfileAdoptionError.localWrapperMismatch }
    let opened = try identity.unwrapDeviceWrappedVaultKey(
      local.wrappedKey,
      context: candidate.envelope.body.deviceContext(
        recipientDeviceID: identity.publicIdentity.deviceID), reason: reason)
    guard opened == nextVaultKey else { throw V3RecoveryProfileAdoptionError.localWrapperMismatch }
  }

  func validateParent(_ parent: V3DeviceWrappedTrustedCheckpoint, currentVaultKey: Data) throws {
    let data = parent.envelope.canonicalBytes
    guard data.count <= limits.maximumManifestBytes,
      parent.checkpoint.vaultID == parent.envelope.body.vaultID,
      parent.checkpoint.envelopeDigest == Data(SHA256.hash(data: data)),
      try V3DeviceWrappedManifestEnvelopeCodec().parse(data) == parent.envelope,
      try V3VaultKeyID.derive(vaultKey: currentVaultKey, vaultID: parent.checkpoint.vaultID)
        == parent.envelope.body.keyID,
      try V3ManifestAuthenticator.isValidAuthenticationTag(
        parent.envelope.authenticationTag, canonicalContent: parent.envelope.canonicalContentBytes,
        vaultID: parent.checkpoint.vaultID, vaultKey: currentVaultKey)
    else { throw V3RecoveryProfileAdoptionError.invalidParent }
  }
}
