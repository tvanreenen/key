import CryptoKit
import Foundation

/// Encrypted candidate objects plus an authenticated public pending record.
/// Product code must durably stage these exact bytes before exposing the export.
/// This value does not establish token provenance or activate a registration.
struct V3RecoveryRegistrationPreparation: Equatable, Sendable {
  let intent: V3RecoveryRegistrationIntent
  let candidate: V3RecoveryManifestEnvelope
  let stagedEntries: [V3EncryptedEntry]

  var exportedAnchor: Data { intent.anchor.canonicalBytes }
}

/// Pure profile-3 recipient-addition construction. No token writer, credential
/// collector, subprocess, storage, profile-2 adoption or product caller exists.
struct V3RecoveryRegistrationBuilder: Sendable {
  private let validator: V3RecoveryRegistrationValidator

  init(limits: V3ManifestRepositoryLimits = .standard) {
    validator = V3RecoveryRegistrationValidator(limits: limits)
  }

  func prepare(
    checkpoint: V3ManifestCheckpoint, parent: V3RecoveryManifestEnvelope,
    currentEntries: [V3EntryObjectKey: V3EncryptedEntry], currentVaultKey: Data,
    nextVaultKey: Data, credential: PIVRecoveryKeyMetadata,
    occupancy: PIVRecoveryAnchorOccupancy, owner: any V3EnrollmentMessageSigning,
    reason: String, operationID: VaultTransactionOperationID = VaultTransactionOperationID(),
    registrationID: String = UUID().uuidString.lowercased(),
    authorityTransitionID: String = UUID().uuidString.lowercased(),
    generationID: String = UUID().uuidString.lowercased()
  ) throws -> V3RecoveryRegistrationPreparation {
    guard occupancy == .absent else { throw V3RecoveryRegistrationError.occupiedAnchor }
    try credential.requireRecoveryPolicy()
    try validator.validateParent(parent, checkpoint: checkpoint, vaultKey: currentVaultKey)
    guard owner.vaultID == checkpoint.vaultID, !reason.isEmpty else {
      throw V3RecoveryRegistrationError.invalidOwner
    }
    try validator.requireOwner(owner.publicIdentity, in: parent)
    let keyID = try V3VaultKeyID.derive(vaultKey: nextVaultKey, vaultID: checkpoint.vaultID)
    guard keyID != parent.body.fields.keyID,
      authorityTransitionID != parent.body.fields.authorityTransitionID,
      generationID != parent.body.recovery.generationID
    else { throw V3RecoveryRegistrationError.invalidCandidate }
    let recipient = try V3RecoveryRecipient(
      registrationID: registrationID, publicKey: credential.publicKey,
      slot: .keyManagement, status: .active)
    guard recipient.publicKey != parent.body.epochSigningKey.publicKey,
      !parent.body.recovery.recipients.contains(where: {
        $0.recipientID == recipient.recipientID || $0.registrationID == recipient.registrationID
      })
    else { throw V3RecoveryRegistrationError.invalidCredential }
    let recipients = (parent.body.recovery.recipients + [recipient]).sorted {
      $0.recipientID.rawValue < $1.recipientID.rawValue
    }
    // Authenticate the entire old snapshot before signing or exporting anything.
    let plaintexts = try validator.plaintexts(
      parent, entries: currentEntries, vaultKey: currentVaultKey)
    let material: V3RecoveryEpochMaterialBuilder.Material
    do {
      material = try validator.withSnapshotErrors {
        try V3RecoveryEpochMaterialBuilder(limits: validator.limits).build(
          fields: parent.body.fields, plaintexts: plaintexts, nextVaultKey: nextVaultKey,
          authorityTransitionID: authorityTransitionID, devices: parent.body.fields.devices,
          generationID: generationID, recipients: recipients)
      }
    } catch V3RecoveryKeyRotationError.resourceLimit {
      throw V3RecoveryRegistrationError.resourceLimit
    } catch V3RecoveryKeyRotationError.invalidCandidate {
      throw V3RecoveryRegistrationError.invalidCandidate
    }
    let body = material.body
    let staged = material.stagedEntries
    // Bounds and round-trip parsing must pass before the Mac signer is invoked.
    try validator.requireBodyBounds(body)
    let candidate = try V3RecoveryEpochBoundary().authorize(
      candidate: body, parent: parent, currentVaultKey: currentVaultKey,
      nextVaultKey: nextVaultKey, signer: owner, reason: reason)
    let anchor = try V3RecoveryAnchor(
      floor: V3VaultHead(vaultID: checkpoint.vaultID, envelopeDigest: candidate.digest),
      recipientID: recipient.recipientID, registrationID: recipient.registrationID,
      slot: .keyManagement)
    let intent = try V3RecoveryRegistrationIntent(
      operationID: operationID, expectedCheckpoint: checkpoint,
      ownerDeviceID: owner.publicIdentity.deviceID, publicKey: recipient.publicKey,
      anchor: anchor, stagedEntries: validator.addresses(staged), currentVaultKey: currentVaultKey)
    let result = V3RecoveryRegistrationPreparation(
      intent: intent, candidate: candidate, stagedEntries: staged)
    try validator.validate(
      result, checkpoint: checkpoint, parent: parent, currentEntries: currentEntries,
      currentVaultKey: currentVaultKey, nextVaultKey: nextVaultKey,
      expectedOwner: owner.publicIdentity)
    return result
  }
}

/// Independent checks shared by initial preparation and resumed completion.
/// An ordinary product service must supply a freshly authenticated checkpoint,
/// source objects and native token observation, and guard publication afterward.
struct V3RecoveryRegistrationValidator: Sendable {
  fileprivate let limits: V3ManifestRepositoryLimits

  init(limits: V3ManifestRepositoryLimits = .standard) { self.limits = limits }

  func validate(
    _ preparation: V3RecoveryRegistrationPreparation, checkpoint: V3ManifestCheckpoint,
    parent: V3RecoveryManifestEnvelope, currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
    currentVaultKey: Data, nextVaultKey: Data, expectedOwner: V3EnrollmentDeviceIdentity
  ) throws {
    let intent = preparation.intent
    let candidate = preparation.candidate
    try intent.authenticate(currentVaultKey: currentVaultKey)
    guard intent.expectedCheckpoint == checkpoint else {
      throw V3RecoveryRegistrationError.invalidParent
    }
    try validateParent(parent, checkpoint: checkpoint, vaultKey: currentVaultKey)
    try requireOwner(expectedOwner, in: parent)
    try requireOwner(expectedOwner, in: candidate)
    try requireBodyBounds(candidate.body)
    guard candidate.canonicalBytes.count <= limits.maximumManifestBytes,
      intent.ownerDeviceID == expectedOwner.deviceID,
      intent.anchor.floor.envelopeDigest == candidate.digest,
      intent.anchor.floor.vaultID == checkpoint.vaultID,
      candidate.authorizations.map(\.signerDeviceID) == [expectedOwner.deviceID],
      candidate.body.fields.devices == parent.body.fields.devices,
      intent.stagedEntries == (try addresses(preparation.stagedEntries))
    else { throw V3RecoveryRegistrationError.invalidCandidate }
    let recipient = try V3RecoveryRecipient(
      registrationID: intent.anchor.registrationID, publicKey: intent.publicKey,
      slot: .keyManagement, status: .active)
    guard recipient.publicKey != parent.body.epochSigningKey.publicKey else {
      throw V3RecoveryRegistrationError.invalidCredential
    }
    let expectedRecipients = (parent.body.recovery.recipients + [recipient]).sorted {
      $0.recipientID.rawValue < $1.recipientID.rawValue
    }
    guard candidate.body.recovery.recipients == expectedRecipients,
      candidate.body.recovery.generationID != parent.body.recovery.generationID
    else { throw V3RecoveryRegistrationError.invalidCandidate }
    try V3RecoveryEpochBoundary().verifyBoundary(candidate, parent: parent)
    try V3RecoveryEpochBoundary().verifyCurrentAuthentication(candidate, vaultKey: nextVaultKey)
    let old = parent.body.fields.entries
    let new = candidate.body.fields.entries
    guard old.count == new.count,
      zip(old, new).allSatisfy({
        $0.entryID == $1.entryID && $0.name == $1.name && $0.type == $1.type
          && $0.revision == $1.revision && $0.ciphertextDigest != $1.ciphertextDigest
      })
    else { throw V3RecoveryRegistrationError.invalidCandidate }
    let before = try plaintexts(parent, entries: currentEntries, vaultKey: currentVaultKey)
    let after = try plaintexts(
      candidate, entries: entryMap(preparation.stagedEntries), vaultKey: nextVaultKey)
    guard before == after else { throw V3RecoveryRegistrationError.invalidEntry }
  }

  /// One exact candidate wrapper is opened, after all software/source checks.
  /// No proof object is returned or stored, and no old epoch/fallback is tried.
  /// This does not publish, advance a checkpoint or establish native provenance.
  @available(macOS 26.0, *)
  func verifyForCompletion(
    _ preparation: V3RecoveryRegistrationPreparation, checkpoint: V3ManifestCheckpoint,
    parent: V3RecoveryManifestEnvelope, currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
    currentVaultKey: Data, identity: any V3DeviceWrappedVaultKeyUnwrapping,
    credential: PIVRecoveryKeyMetadata, installedAnchor: V3RecoveryAnchor,
    receiver: PIVHPKEReceiver, reason: String
  ) throws {
    try withCompletionKey(
      preparation, checkpoint: checkpoint, parent: parent, currentEntries: currentEntries,
      currentVaultKey: currentVaultKey, identity: identity, credential: credential,
      installedAnchor: installedAnchor, receiver: receiver, reason: reason
    ) { _ in () }
  }

  /// The service consumes the key only in this synchronous scope. It can
  /// recheck source/native state after local approval and before agreement,
  /// then publish without a second local unwrap or retaining a proof object.
  @available(macOS 26.0, *)
  func withCompletionKey<Result>(
    _ preparation: V3RecoveryRegistrationPreparation, checkpoint: V3ManifestCheckpoint,
    parent: V3RecoveryManifestEnvelope, currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
    currentVaultKey: Data, identity: any V3DeviceWrappedVaultKeyUnwrapping,
    credential: PIVRecoveryKeyMetadata, installedAnchor: V3RecoveryAnchor,
    receiver: PIVHPKEReceiver, reason: String,
    validateBeforeAgreement: (Data) throws -> Void = { _ in },
    _ consume: (Data) throws -> Result
  ) throws -> Result {
    try preparation.intent.authenticate(currentVaultKey: currentVaultKey)
    try credential.requireRecoveryPolicy()
    guard credential.publicKey == preparation.intent.publicKey,
      receiver.publicKey.bytes == credential.publicKey,
      installedAnchor == preparation.intent.anchor
    else { throw V3RecoveryRegistrationError.anchorMismatch }
    guard !reason.isEmpty, identity.vaultID == checkpoint.vaultID,
      identity.publicIdentity.deviceID == preparation.intent.ownerDeviceID
    else { throw V3RecoveryRegistrationError.invalidOwner }
    try validateParent(parent, checkpoint: checkpoint, vaultKey: currentVaultKey)
    guard checkpoint == preparation.intent.expectedCheckpoint else {
      throw V3RecoveryRegistrationError.invalidParent
    }
    try requireOwner(identity.publicIdentity, in: parent)
    let candidate = preparation.candidate
    // Reject substitutions before the local private unwrap, not merely before
    // the hardware operation. The authenticated intent pins all candidate bytes.
    guard candidate.canonicalBytes.count <= limits.maximumManifestBytes,
      candidate.digest == preparation.intent.anchor.floor.envelopeDigest,
      try V3RecoveryManifestCodec().parseEnvelope(candidate.canonicalBytes) == candidate,
      preparation.intent.stagedEntries == (try addresses(preparation.stagedEntries)),
      let local = candidate.body.fields.wrappedKeys.first(where: {
        $0.recipientDeviceID == identity.publicIdentity.deviceID
      })
    else { throw V3RecoveryRegistrationError.invalidCandidate }
    try V3RecoveryEpochBoundary().verifyBoundary(candidate, parent: parent)
    let nextKey = try identity.unwrapDeviceWrappedVaultKey(
      local.wrappedKey,
      context: candidate.body.deviceContext(recipientDeviceID: identity.publicIdentity.deviceID),
      reason: reason)
    try validate(
      preparation, checkpoint: checkpoint, parent: parent, currentEntries: currentEntries,
      currentVaultKey: currentVaultKey, nextVaultKey: nextKey,
      expectedOwner: identity.publicIdentity)
    guard
      let recipient = candidate.body.recovery.recipients.first(where: {
        $0.recipientID == installedAnchor.recipientID
          && $0.registrationID == installedAnchor.registrationID && $0.status == .active
      }),
      let wrapped = candidate.body.recovery.wrappedKeys.first(where: {
        $0.recipientID == recipient.recipientID && $0.registrationID == recipient.registrationID
      })
    else { throw V3RecoveryRegistrationError.invalidCandidate }
    try validateBeforeAgreement(nextKey)
    let opened = try V3RecoveryVaultKeyHPKE().unwrap(
      wrapped, recipientPrivateKey: receiver,
      context: V3RecoveryHPKEContext(
        vaultID: checkpoint.vaultID, keyID: candidate.body.fields.keyID,
        authorityTransitionID: candidate.body.fields.authorityTransitionID,
        recoveryGenerationID: candidate.body.recovery.generationID, recipient: recipient))
    guard opened == nextKey else { throw V3RecoveryRegistrationError.possessionMismatch }
    return try consume(nextKey)
  }

  func validateParent(
    _ parent: V3RecoveryManifestEnvelope, checkpoint: V3ManifestCheckpoint, vaultKey: Data
  ) throws {
    guard parent.canonicalBytes.count <= limits.maximumManifestBytes,
      parent.body.fields.vaultID == checkpoint.vaultID,
      parent.digest == checkpoint.envelopeDigest
    else { throw V3RecoveryRegistrationError.invalidParent }
    try V3RecoveryEpochBoundary().verifyCurrentAuthentication(parent, vaultKey: vaultKey)
  }

  func requireOwner(
    _ owner: V3EnrollmentDeviceIdentity, in envelope: V3RecoveryManifestEnvelope
  ) throws {
    guard
      envelope.body.fields.devices.contains(where: {
        $0.identity == owner && $0.status == .active
      })
    else { throw V3RecoveryRegistrationError.invalidOwner }
  }

  fileprivate func requireBodyBounds(_ body: V3RecoveryManifestBody) throws {
    // Allow room for the proof and envelope framing before requesting a signature.
    guard limits.maximumManifestBytes >= 2_048,
      body.canonicalBytes.count <= limits.maximumManifestBytes - 2_048
    else { throw V3RecoveryRegistrationError.resourceLimit }
  }

  fileprivate func addresses(_ entries: [V3EncryptedEntry]) throws
    -> [V3ImmutableTransactionRecoveryEntry]
  {
    let map = try entryMap(entries)
    return map.keys.map {
      V3ImmutableTransactionRecoveryEntry(entryID: $0.entryID, digest: $0.digest)
    }
    .sorted { $0.entryID < $1.entryID }
  }

  private func entryMap(_ entries: [V3EncryptedEntry]) throws -> [V3EntryObjectKey:
    V3EncryptedEntry]
  {
    try withSnapshotErrors {
      try V3EntrySnapshotValidator(limits: limits).entryMap(entries)
    }
  }

  func plaintexts(
    _ envelope: V3RecoveryManifestEnvelope, entries: [V3EntryObjectKey: V3EncryptedEntry],
    vaultKey: Data
  ) throws -> [String: Data] {
    try withSnapshotErrors {
      try V3EntrySnapshotValidator(limits: limits).plaintexts(
        fields: envelope.body.fields, entries: entries, vaultKey: vaultKey)
    }
  }

  fileprivate func withSnapshotErrors<T>(_ operation: () throws -> T) throws -> T {
    do { return try operation() } catch let error as V3EntrySnapshotValidationError {
      switch error {
      case .resourceLimit: throw V3RecoveryRegistrationError.resourceLimit
      case .incompleteSnapshot: throw V3RecoveryRegistrationError.incompleteSnapshot
      case .invalidEntry: throw V3RecoveryRegistrationError.invalidEntry
      }
    }
  }
}
