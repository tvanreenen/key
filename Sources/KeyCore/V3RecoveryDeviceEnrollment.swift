import Foundation

enum V3RecoveryDeviceEnrollmentError: Error, Equatable {
  case invalidCeremony, invalidOwner, joiningIdentityConflict, invalidCandidate
}

/// Exact encrypted output of one compared-device addition, not saved approval.
struct V3RecoveryDeviceEnrollmentCandidate: Equatable, Sendable {
  let expectedCheckpoint: V3ManifestCheckpoint
  let envelope: V3RecoveryManifestEnvelope
  let stagedEntries: [V3EncryptedEntry]
  let transcriptDigest: Data
}

/// Pure enrollment construction. No token, administration, ceremony consumption,
/// publication, checkpoint movement or joining-Mac adoption occurs here.
struct V3RecoveryDeviceEnrollmentBuilder: Sendable {
  let limits: V3ManifestRepositoryLimits
  init(limits: V3ManifestRepositoryLimits = .standard) { self.limits = limits }

  func build(
    checkpoint: V3ManifestCheckpoint, parent: V3RecoveryManifestEnvelope,
    currentEntries: [V3EntryObjectKey: V3EncryptedEntry], state: V3EnrollmentCeremonyState,
    currentVaultKey: Data, nextVaultKey: Data, owner: any V3EnrollmentMessageSigning,
    at unixTime: UInt64, reason: String
  ) throws -> V3RecoveryDeviceEnrollmentCandidate {
    try V3RecoveryContentMutationValidator(limits: limits).validateParent(
      parent, checkpoint: checkpoint, vaultKey: currentVaultKey)
    guard !reason.isEmpty, owner.vaultID == checkpoint.vaultID else {
      throw V3RecoveryDeviceEnrollmentError.invalidOwner
    }
    let policy = V3RecoveryDeviceEnrollmentValidator(limits: limits)
    let transcript = try policy.validateCeremony(
      state, checkpoint: checkpoint, parent: parent, expectedOwner: owner.publicIdentity,
      at: unixTime)
    let devices = try policy.resultingDevices(
      parent: parent.body.fields.devices, joining: transcript.joinRequest.joiningDevice)
    let plaintexts = try V3EntrySnapshotValidator(limits: limits).plaintexts(
      fields: parent.body.fields, entries: currentEntries, vaultKey: currentVaultKey)
    let material = try V3RecoveryEpochMaterialBuilder(limits: limits).build(
      fields: parent.body.fields, plaintexts: plaintexts, nextVaultKey: nextVaultKey,
      authorityTransitionID: v3EnrollmentAuthorityTransitionID(transcriptDigest: transcript.digest),
      devices: devices, generationID: parent.body.recovery.generationID,
      recipients: parent.body.recovery.recipients)
    let envelope = try V3RecoveryEpochBoundary().authorize(
      candidate: material.body, parent: parent, currentVaultKey: currentVaultKey,
      nextVaultKey: nextVaultKey, signer: owner, reason: reason)
    let candidate = V3RecoveryDeviceEnrollmentCandidate(
      expectedCheckpoint: checkpoint, envelope: envelope, stagedEntries: material.stagedEntries,
      transcriptDigest: transcript.digest)
    try policy.validate(
      candidate, parent: parent, currentEntries: currentEntries, state: state,
      currentVaultKey: currentVaultKey, nextVaultKey: nextVaultKey,
      expectedOwner: owner.publicIdentity, at: unixTime)
    return candidate
  }
}

/// Independently requires one exact compared addition and unchanged recovery
/// authority. Shared epoch checks cannot authorize this device-roster decision.
struct V3RecoveryDeviceEnrollmentValidator: Sendable {
  let limits: V3ManifestRepositoryLimits
  init(limits: V3ManifestRepositoryLimits = .standard) { self.limits = limits }

  func preflight(
    _ candidate: V3RecoveryDeviceEnrollmentCandidate, parent: V3RecoveryManifestEnvelope,
    state: V3EnrollmentCeremonyState, currentVaultKey: Data,
    expectedOwner: V3EnrollmentDeviceIdentity, at unixTime: UInt64
  ) throws {
    try preflight(
      candidate, parent: parent, state: state, currentVaultKey: currentVaultKey,
      expectedOwner: expectedOwner, freshAt: unixTime)
  }

  private func preflight(
    _ candidate: V3RecoveryDeviceEnrollmentCandidate, parent: V3RecoveryManifestEnvelope,
    state: V3EnrollmentCeremonyState, currentVaultKey: Data,
    expectedOwner: V3EnrollmentDeviceIdentity, freshAt unixTime: UInt64?
  ) throws {
    try validatePolicy(
      candidate, parent: parent, state: state,
      expectedOwner: expectedOwner, freshAt: unixTime)
    try V3RecoveryEpochSnapshotValidator(limits: limits).preflight(
      candidate.envelope, checkpoint: candidate.expectedCheckpoint, parent: parent,
      stagedEntryCount: candidate.stagedEntries.count, currentVaultKey: currentVaultKey,
      expectedOwner: expectedOwner)
  }

  /// Public provenance/policy checks before opening Mac wrappers for exact
  /// anchored work. This does not replace MAC/capsule or plaintext validation.
  func preflightPublicAnchored(
    _ candidate: V3RecoveryDeviceEnrollmentCandidate, parent: V3RecoveryManifestEnvelope,
    state: V3EnrollmentCeremonyState, expectedOwner: V3EnrollmentDeviceIdentity
  ) throws {
    try validatePolicy(
      candidate, parent: parent, state: state,
      expectedOwner: expectedOwner, freshAt: nil)
    try V3RecoveryEpochSnapshotValidator(limits: limits).preflightPublic(
      candidate.envelope, checkpoint: candidate.expectedCheckpoint, parent: parent,
      stagedEntryCount: candidate.stagedEntries.count, expectedOwner: expectedOwner)
  }

  private func validatePolicy(
    _ candidate: V3RecoveryDeviceEnrollmentCandidate, parent: V3RecoveryManifestEnvelope,
    state: V3EnrollmentCeremonyState, expectedOwner: V3EnrollmentDeviceIdentity,
    freshAt unixTime: UInt64?
  ) throws {
    let transcript = try validateCeremony(
      state, checkpoint: candidate.expectedCheckpoint, parent: parent,
      expectedOwner: expectedOwner, at: unixTime)
    let body = candidate.envelope.body
    guard candidate.transcriptDigest == transcript.digest,
      body.fields.authorityTransitionID
        == (try v3EnrollmentAuthorityTransitionID(transcriptDigest: transcript.digest)),
      body.fields.devices
        == (try resultingDevices(
          parent: parent.body.fields.devices, joining: transcript.joinRequest.joiningDevice)),
      body.recovery.recipients == parent.body.recovery.recipients,
      body.recovery.generationID == parent.body.recovery.generationID
    else { throw V3RecoveryDeviceEnrollmentError.invalidCandidate }
  }

  /// Only for exact locally anchored work. Expiry prevents fresh approvals,
  /// not finishing an approval whose candidate has already been pinned.
  func validateAnchored(
    _ candidate: V3RecoveryDeviceEnrollmentCandidate, parent: V3RecoveryManifestEnvelope,
    currentEntries: [V3EntryObjectKey: V3EncryptedEntry], state: V3EnrollmentCeremonyState,
    currentVaultKey: Data, nextVaultKey: Data, expectedOwner: V3EnrollmentDeviceIdentity
  ) throws {
    try preflight(
      candidate, parent: parent, state: state, currentVaultKey: currentVaultKey,
      expectedOwner: expectedOwner, freshAt: nil)
    try V3RecoveryEpochSnapshotValidator(limits: limits).validateSnapshots(
      candidate.envelope, stagedEntries: candidate.stagedEntries, parent: parent,
      currentEntries: currentEntries, currentVaultKey: currentVaultKey, nextVaultKey: nextVaultKey)
  }

  func validate(
    _ candidate: V3RecoveryDeviceEnrollmentCandidate, parent: V3RecoveryManifestEnvelope,
    currentEntries: [V3EntryObjectKey: V3EncryptedEntry], state: V3EnrollmentCeremonyState,
    currentVaultKey: Data, nextVaultKey: Data, expectedOwner: V3EnrollmentDeviceIdentity,
    at unixTime: UInt64
  ) throws {
    try preflight(
      candidate, parent: parent, state: state, currentVaultKey: currentVaultKey,
      expectedOwner: expectedOwner, at: unixTime)
    try V3RecoveryEpochSnapshotValidator(limits: limits).validateSnapshots(
      candidate.envelope, stagedEntries: candidate.stagedEntries, parent: parent,
      currentEntries: currentEntries, currentVaultKey: currentVaultKey, nextVaultKey: nextVaultKey)
  }

  func validateForPublication(
    _ candidate: V3RecoveryDeviceEnrollmentCandidate, parent: V3RecoveryManifestEnvelope,
    currentEntries: [V3EntryObjectKey: V3EncryptedEntry], state: V3EnrollmentCeremonyState,
    currentVaultKey: Data, nextVaultKey: Data, identity: any V3DeviceWrappedVaultKeyUnwrapping,
    at unixTime: UInt64, reason: String
  ) throws {
    guard !reason.isEmpty, identity.vaultID == candidate.expectedCheckpoint.vaultID else {
      throw V3RecoveryDeviceEnrollmentError.invalidOwner
    }
    try validate(
      candidate, parent: parent, currentEntries: currentEntries, state: state,
      currentVaultKey: currentVaultKey, nextVaultKey: nextVaultKey,
      expectedOwner: identity.publicIdentity, at: unixTime)
    try V3RecoveryEpochSnapshotValidator(limits: limits).validateLocalWrapper(
      candidate.envelope, nextVaultKey: nextVaultKey, identity: identity, reason: reason)
  }

  func validateCeremony(
    _ state: V3EnrollmentCeremonyState, checkpoint: V3ManifestCheckpoint,
    parent: V3RecoveryManifestEnvelope, expectedOwner: V3EnrollmentDeviceIdentity,
    at unixTime: UInt64?
  ) throws -> V3EnrollmentTranscript {
    guard state.role == .inviter, state.phase == .awaitingComparison,
      let join = state.signedJoinRequest, let transcript = state.transcript,
      transcript.invitation.vaultID == checkpoint.vaultID,
      transcript.invitation.vaultID == parent.body.fields.vaultID,
      transcript.invitation.parentManifestDigest == checkpoint.envelopeDigest,
      checkpoint.envelopeDigest == parent.digest,
      transcript.invitation.invitingDevice == expectedOwner,
      parent.body.fields.devices.contains(where: {
        $0.identity == expectedOwner && $0.status == .active
      })
    else { throw V3RecoveryDeviceEnrollmentError.invalidCeremony }
    let authenticator = V3EnrollmentMessageAuthenticator()
    _ = try authenticator.verify(state.signedInvitation)
    _ = try authenticator.verify(join)
    if let unixTime { try transcript.invitation.requireUnexpired(at: unixTime) }
    return transcript
  }

  func resultingDevices(
    parent: [V3DeviceWrappedManifestDevice], joining: V3EnrollmentDeviceIdentity
  ) throws -> [V3DeviceWrappedManifestDevice] {
    guard !parent.contains(where: { $0.identity.deviceID == joining.deviceID }),
      parent.allSatisfy({
        $0.identity.signingPublicKey != joining.signingPublicKey
          && $0.identity.wrappingPublicKey != joining.wrappingPublicKey
          && $0.identity.signingPublicKey != joining.wrappingPublicKey
          && $0.identity.wrappingPublicKey != joining.signingPublicKey
      })
    else { throw V3RecoveryDeviceEnrollmentError.joiningIdentityConflict }
    return (parent + [.init(identity: joining, status: .active)]).sorted {
      Data($0.identity.deviceID.utf8).lexicographicallyPrecedes(Data($1.identity.deviceID.utf8))
    }
  }
}
