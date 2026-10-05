import CryptoKit
import Foundation

enum V3RecoveryKeyRotationError: Error, Equatable {
  case invalidCandidate, invalidOwner, resourceLimit, localWrapperMismatch
}

/// Unpublished encrypted output only, not saved approval or checkpoint authority.
struct V3RecoveryKeyRotationCandidate: Equatable, Sendable {
  let expectedCheckpoint: V3ManifestCheckpoint
  let envelope: V3RecoveryManifestEnvelope
  let stagedEntries: [V3EncryptedEntry]
}

/// Common unsigned material for profile-3 registration and key epochs. Callers
/// authenticate the exact source snapshot and enforce their roster policy first;
/// independent transition validators still compare complete old/new plaintexts.
/// No plaintext or raw key survives in the returned material.
struct V3RecoveryEpochMaterialBuilder: Sendable {
  struct Material: Sendable {
    let body: V3RecoveryManifestBody
    let stagedEntries: [V3EncryptedEntry]
  }
  let limits: V3ManifestRepositoryLimits

  func build(
    fields old: V3DeviceWrappedManifestFields, plaintexts: [String: Data], nextVaultKey: Data,
    authorityTransitionID: String, devices: [V3DeviceWrappedManifestDevice],
    generationID: String, recipients: [V3RecoveryRecipient]
  ) throws -> Material {
    let nextID = try V3VaultKeyID.derive(vaultKey: nextVaultKey, vaultID: old.vaultID)
    guard nextID != old.keyID, authorityTransitionID != old.authorityTransitionID,
      isValidV3UUID(authorityTransitionID), isValidV3UUID(generationID),
      Set(plaintexts.keys) == Set(old.entries.map(\.entryID))
    else { throw V3RecoveryKeyRotationError.invalidCandidate }
    guard old.entries.count <= limits.maximumReferencedEntryObjects else {
      throw V3EntrySnapshotValidationError.resourceLimit
    }
    var plaintextBytes = 0
    for bytes in plaintexts.values {
      guard bytes.count <= limits.maximumEntryBytes,
        bytes.count <= limits.maximumTotalEntryBytes - plaintextBytes
      else { throw V3EntrySnapshotValidationError.resourceLimit }
      plaintextBytes += bytes.count
    }
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
    _ = try V3EntrySnapshotValidator(limits: limits).entryMap(staged)
    let wrappers = try devices.compactMap { device -> V3DeviceWrappedManifestKey? in
      guard device.status == .active else { return nil }
      return try V3DeviceWrappedManifestKey(
        recipientDeviceID: device.identity.deviceID,
        wrappedKey: V3VaultKeyHPKE().wrap(
          vaultKey: nextVaultKey, recipientPublicKey: device.identity.wrappingPublicKey,
          context: V3VaultKeyHPKEContext(
            vaultID: old.vaultID, keyID: nextID, authorityTransitionID: authorityTransitionID,
            recipientDeviceID: device.identity.deviceID, wrappingProfile: .recovery)))
    }
    let recoveryWrappers = try recipients.compactMap { recipient -> V3RecoveryWrappedKey? in
      guard recipient.status == .active else { return nil }
      return try V3RecoveryVaultKeyHPKE().wrap(
        vaultKey: nextVaultKey,
        context: V3RecoveryHPKEContext(
          vaultID: old.vaultID, keyID: nextID, authorityTransitionID: authorityTransitionID,
          recoveryGenerationID: generationID, recipient: recipient))
    }
    let body = try V3RecoveryManifestBody(
      fields: V3DeviceWrappedManifestFields(
        vaultID: old.vaultID, keyID: nextID, authorityTransitionID: authorityTransitionID,
        devices: devices, wrappedKeys: wrappers,
        entries: staged.map { V3ResealedEntry(encryptedEntry: $0).manifestEntry }),
      epochSigningKey: V3EpochSigningKeyCipher().prepare(
        context: V3EpochSigningKeyContext(
          vaultID: old.vaultID, keyID: nextID, authorityTransitionID: authorityTransitionID),
        vaultKey: nextVaultKey), transitionProof: nil,
      recovery: V3RecoveryRoster(
        generationID: generationID, recipients: recipients, wrappedKeys: recoveryWrappers))
    guard limits.maximumManifestBytes >= 2_048,
      body.canonicalBytes.count <= limits.maximumManifestBytes - 2_048,
      try V3RecoveryManifestCodec().parseCanonicalBody(body.canonicalBytes) == .recovery(body)
    else { throw V3RecoveryKeyRotationError.resourceLimit }
    return Material(body: body, stagedEntries: staged)
  }
}

/// Pure rotation with unchanged device/recipient authority. Stored public keys
/// create every active wrapper; no token, hardware agreement or admin operation.
struct V3RecoveryKeyRotationBuilder: Sendable {
  let limits: V3ManifestRepositoryLimits
  init(limits: V3ManifestRepositoryLimits = .standard) { self.limits = limits }

  func build(
    checkpoint: V3ManifestCheckpoint, parent: V3RecoveryManifestEnvelope,
    currentEntries: [V3EntryObjectKey: V3EncryptedEntry], currentVaultKey: Data,
    nextVaultKey: Data, owner: any V3EnrollmentMessageSigning, reason: String,
    authorityTransitionID: String = UUID().uuidString.lowercased()
  ) throws -> V3RecoveryKeyRotationCandidate {
    try V3RecoveryContentMutationValidator(limits: limits).validateParent(
      parent, checkpoint: checkpoint, vaultKey: currentVaultKey)
    guard owner.vaultID == checkpoint.vaultID, !reason.isEmpty,
      parent.body.fields.devices.contains(where: {
        $0.identity == owner.publicIdentity && $0.status == .active
      })
    else { throw V3RecoveryKeyRotationError.invalidOwner }
    let plaintexts = try V3EntrySnapshotValidator(limits: limits).plaintexts(
      fields: parent.body.fields, entries: currentEntries, vaultKey: currentVaultKey)
    let material = try V3RecoveryEpochMaterialBuilder(limits: limits).build(
      fields: parent.body.fields, plaintexts: plaintexts, nextVaultKey: nextVaultKey,
      authorityTransitionID: authorityTransitionID, devices: parent.body.fields.devices,
      generationID: parent.body.recovery.generationID, recipients: parent.body.recovery.recipients)
    let envelope = try V3RecoveryEpochBoundary().authorize(
      candidate: material.body, parent: parent, currentVaultKey: currentVaultKey,
      nextVaultKey: nextVaultKey, signer: owner, reason: reason)
    let candidate = V3RecoveryKeyRotationCandidate(
      expectedCheckpoint: checkpoint, envelope: envelope, stagedEntries: material.stagedEntries)
    try V3RecoveryKeyRotationValidator(limits: limits).validate(
      candidate, parent: parent, currentEntries: currentEntries,
      currentVaultKey: currentVaultKey, nextVaultKey: nextVaultKey,
      expectedOwner: owner.publicIdentity)
    return candidate
  }
}

/// Full normal-publication validation, not recovery's historical replay policy.
/// Source/checkpoint/head/pending/durability guards remain the publisher's work.
struct V3RecoveryKeyRotationValidator: Sendable {
  let limits: V3ManifestRepositoryLimits
  init(limits: V3ManifestRepositoryLimits = .standard) { self.limits = limits }

  func preflight(
    _ candidate: V3RecoveryKeyRotationCandidate, parent: V3RecoveryManifestEnvelope,
    currentVaultKey: Data, expectedOwner: V3EnrollmentDeviceIdentity
  ) throws {
    try V3RecoveryContentMutationValidator(limits: limits).validateParent(
      parent, checkpoint: candidate.expectedCheckpoint, vaultKey: currentVaultKey)
    let envelope = candidate.envelope
    guard envelope.canonicalBytes.count <= limits.maximumManifestBytes,
      candidate.stagedEntries.count <= limits.maximumReferencedEntryObjects,
      envelope.body.fields.devices == parent.body.fields.devices,
      envelope.body.recovery.recipients == parent.body.recovery.recipients,
      envelope.body.recovery.generationID == parent.body.recovery.generationID,
      parent.body.fields.devices.contains(where: {
        $0.identity == expectedOwner && $0.status == .active
      }), envelope.authorizations.map(\.signerDeviceID) == [expectedOwner.deviceID]
    else { throw V3RecoveryKeyRotationError.invalidCandidate }
    try V3RecoveryEpochBoundary().verifyBoundary(envelope, parent: parent)
    let old = parent.body.fields.entries
    let new = envelope.body.fields.entries
    guard old.count == new.count,
      zip(old, new).allSatisfy({
        $0.entryID == $1.entryID && $0.name == $1.name && $0.type == $1.type
          && $0.revision == $1.revision && $0.ciphertextDigest != $1.ciphertextDigest
      })
    else { throw V3RecoveryKeyRotationError.invalidCandidate }
  }

  func validate(
    _ candidate: V3RecoveryKeyRotationCandidate, parent: V3RecoveryManifestEnvelope,
    currentEntries: [V3EntryObjectKey: V3EncryptedEntry], currentVaultKey: Data,
    nextVaultKey: Data, expectedOwner: V3EnrollmentDeviceIdentity
  ) throws {
    try preflight(
      candidate, parent: parent, currentVaultKey: currentVaultKey,
      expectedOwner: expectedOwner)
    let snapshots = V3EntrySnapshotValidator(limits: limits)
    let staged = try snapshots.entryMap(candidate.stagedEntries)
    try V3RecoveryEpochBoundary().verifyCurrentAuthentication(
      candidate.envelope, vaultKey: nextVaultKey)
    for entry in candidate.stagedEntries {
      guard try V3EntryCipher().parse(entry.canonicalBytes) == entry else {
        throw V3RecoveryKeyRotationError.invalidCandidate
      }
    }
    let before = try snapshots.plaintexts(
      fields: parent.body.fields, entries: currentEntries, vaultKey: currentVaultKey)
    let after = try snapshots.plaintexts(
      fields: candidate.envelope.body.fields, entries: staged,
      vaultKey: nextVaultKey)
    guard before == after else { throw V3RecoveryKeyRotationError.invalidCandidate }
  }

  func validateForPublication(
    _ candidate: V3RecoveryKeyRotationCandidate, parent: V3RecoveryManifestEnvelope,
    currentEntries: [V3EntryObjectKey: V3EncryptedEntry], currentVaultKey: Data,
    nextVaultKey: Data, identity: any V3DeviceWrappedVaultKeyUnwrapping, reason: String
  ) throws {
    guard !reason.isEmpty, identity.vaultID == candidate.expectedCheckpoint.vaultID else {
      throw V3RecoveryKeyRotationError.invalidOwner
    }
    try validate(
      candidate, parent: parent, currentEntries: currentEntries,
      currentVaultKey: currentVaultKey, nextVaultKey: nextVaultKey,
      expectedOwner: identity.publicIdentity)
    guard
      let wrapped = candidate.envelope.body.fields.wrappedKeys.first(where: {
        $0.recipientDeviceID == identity.publicIdentity.deviceID
      })
    else { throw V3RecoveryKeyRotationError.localWrapperMismatch }
    let opened = try identity.unwrapDeviceWrappedVaultKey(
      wrapped.wrappedKey,
      context: candidate.envelope.body.deviceContext(
        recipientDeviceID: identity.publicIdentity.deviceID),
      reason: reason)
    guard opened == nextVaultKey else { throw V3RecoveryKeyRotationError.localWrapperMismatch }
  }
}
