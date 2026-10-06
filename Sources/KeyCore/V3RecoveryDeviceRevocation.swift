import Foundation

enum V3RecoveryDeviceRevocationError: Error, Equatable {
  case invalidPlan, invalidOwner, invalidCandidate
}

/// Profile-3 parent authentication followed by the established roster policy.
struct V3RecoveryDeviceRevocationPlanner: Sendable {
  let limits: V3ManifestRepositoryLimits
  init(limits: V3ManifestRepositoryLimits = .standard) { self.limits = limits }

  func plan(
    checkpoint: V3ManifestCheckpoint, parent: V3RecoveryManifestEnvelope,
    currentVaultKey: Data, authorizingDeviceID: String, revoking revokedDeviceID: String
  ) throws -> V3DeviceWrappedRevocationPlan {
    try V3RecoveryContentMutationValidator(limits: limits).validateParent(
      parent, checkpoint: checkpoint, vaultKey: currentVaultKey)
    return try V3DeviceRevocationRosterPolicy().plan(
      checkpoint: checkpoint, devices: parent.body.fields.devices,
      authorizingDeviceID: authorizingDeviceID, revoking: revokedDeviceID)
  }
}

/// Unpublished encrypted output bound to the exact reviewed device/checkpoint.
/// No raw vault key, private recipient key or durable approval is retained.
struct V3RecoveryDeviceRevocationCandidate: Equatable, Sendable {
  let plan: V3DeviceWrappedRevocationPlan
  let envelope: V3RecoveryManifestEnvelope
  let stagedEntries: [V3EncryptedEntry]
}

/// Pure complete resealing and public-key wrapping. No token, storage operation,
/// revocation confirmation, checkpoint movement or remaining-Mac catch-up.
struct V3RecoveryDeviceRevocationBuilder: Sendable {
  let limits: V3ManifestRepositoryLimits
  init(limits: V3ManifestRepositoryLimits = .standard) { self.limits = limits }

  func build(
    parent: V3RecoveryManifestEnvelope, currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
    plan: V3DeviceWrappedRevocationPlan, currentVaultKey: Data, nextVaultKey: Data,
    owner: any V3EnrollmentMessageSigning, reason: String,
    authorityTransitionID: String = UUID().uuidString.lowercased()
  ) throws -> V3RecoveryDeviceRevocationCandidate {
    let reviewed = try V3RecoveryDeviceRevocationPlanner(limits: limits).plan(
      checkpoint: plan.expectedCheckpoint, parent: parent, currentVaultKey: currentVaultKey,
      authorizingDeviceID: plan.authorizingDevice.identity.deviceID,
      revoking: plan.revokedDevice.identity.deviceID)
    guard reviewed == plan else { throw V3RecoveryDeviceRevocationError.invalidPlan }
    guard owner.vaultID == plan.expectedCheckpoint.vaultID,
      owner.publicIdentity == plan.authorizingDevice.identity, !reason.isEmpty
    else { throw V3RecoveryDeviceRevocationError.invalidOwner }
    let values = try V3EntrySnapshotValidator(limits: limits).plaintexts(
      fields: parent.body.fields, entries: currentEntries, vaultKey: currentVaultKey)
    let material = try V3RecoveryEpochMaterialBuilder(limits: limits).build(
      fields: parent.body.fields, plaintexts: values, nextVaultKey: nextVaultKey,
      authorityTransitionID: authorityTransitionID, devices: plan.resultingDevices,
      generationID: parent.body.recovery.generationID, recipients: parent.body.recovery.recipients)
    let envelope = try V3RecoveryEpochBoundary().authorize(
      candidate: material.body, parent: parent, currentVaultKey: currentVaultKey,
      nextVaultKey: nextVaultKey, signer: owner, reason: reason)
    let candidate = V3RecoveryDeviceRevocationCandidate(
      plan: plan, envelope: envelope, stagedEntries: material.stagedEntries)
    try V3RecoveryDeviceRevocationValidator(limits: limits).validate(
      candidate, parent: parent, currentEntries: currentEntries, currentVaultKey: currentVaultKey,
      nextVaultKey: nextVaultKey, expectedOwner: owner.publicIdentity)
    return candidate
  }
}

/// Independently reconstructs the reviewed one-device revocation; shared epoch
/// cryptography cannot authorize a different roster or recipient decision.
struct V3RecoveryDeviceRevocationValidator: Sendable {
  let limits: V3ManifestRepositoryLimits
  init(limits: V3ManifestRepositoryLimits = .standard) { self.limits = limits }

  func preflight(
    _ candidate: V3RecoveryDeviceRevocationCandidate, parent: V3RecoveryManifestEnvelope,
    currentVaultKey: Data, expectedOwner: V3EnrollmentDeviceIdentity
  ) throws {
    try V3RecoveryContentMutationValidator(limits: limits).validateParent(
      parent, checkpoint: candidate.plan.expectedCheckpoint, vaultKey: currentVaultKey)
    try preflightPublic(candidate, parent: parent, expectedOwner: expectedOwner)
  }

  /// Exact metadata/roster and public proofs only. Not current MAC/snapshot
  /// authentication, review approval or permission to publish.
  func preflightPublic(
    _ candidate: V3RecoveryDeviceRevocationCandidate, parent: V3RecoveryManifestEnvelope,
    expectedOwner: V3EnrollmentDeviceIdentity
  ) throws {
    let plan = candidate.plan
    let reviewed = try V3DeviceRevocationRosterPolicy().plan(
      checkpoint: plan.expectedCheckpoint, devices: parent.body.fields.devices,
      authorizingDeviceID: plan.authorizingDevice.identity.deviceID,
      revoking: plan.revokedDevice.identity.deviceID)
    guard reviewed == plan, expectedOwner == plan.authorizingDevice.identity else {
      throw V3RecoveryDeviceRevocationError.invalidPlan
    }
    let body = candidate.envelope.body
    guard body.fields.devices == plan.resultingDevices,
      body.recovery.recipients == parent.body.recovery.recipients,
      body.recovery.generationID == parent.body.recovery.generationID
    else { throw V3RecoveryDeviceRevocationError.invalidCandidate }
    try V3RecoveryEpochSnapshotValidator(limits: limits).preflightPublic(
      candidate.envelope, checkpoint: plan.expectedCheckpoint, parent: parent,
      stagedEntryCount: candidate.stagedEntries.count,
      expectedOwner: expectedOwner)
  }

  func validate(
    _ candidate: V3RecoveryDeviceRevocationCandidate, parent: V3RecoveryManifestEnvelope,
    currentEntries: [V3EntryObjectKey: V3EncryptedEntry], currentVaultKey: Data,
    nextVaultKey: Data, expectedOwner: V3EnrollmentDeviceIdentity
  ) throws {
    try preflight(
      candidate, parent: parent, currentVaultKey: currentVaultKey, expectedOwner: expectedOwner)
    try V3RecoveryEpochSnapshotValidator(limits: limits).validateSnapshots(
      candidate.envelope, stagedEntries: candidate.stagedEntries, parent: parent,
      currentEntries: currentEntries, currentVaultKey: currentVaultKey, nextVaultKey: nextVaultKey)
  }

  func validateForPublication(
    _ candidate: V3RecoveryDeviceRevocationCandidate, parent: V3RecoveryManifestEnvelope,
    currentEntries: [V3EntryObjectKey: V3EncryptedEntry], currentVaultKey: Data,
    nextVaultKey: Data, identity: any V3DeviceWrappedVaultKeyUnwrapping, reason: String
  ) throws {
    guard !reason.isEmpty, identity.vaultID == candidate.plan.expectedCheckpoint.vaultID else {
      throw V3RecoveryDeviceRevocationError.invalidOwner
    }
    try validate(
      candidate, parent: parent, currentEntries: currentEntries, currentVaultKey: currentVaultKey,
      nextVaultKey: nextVaultKey, expectedOwner: identity.publicIdentity)
    try V3RecoveryEpochSnapshotValidator(limits: limits).validateLocalWrapper(
      candidate.envelope, nextVaultKey: nextVaultKey, identity: identity, reason: reason)
  }
}
