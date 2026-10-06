import Foundation

enum V3RecoveryRecipientRemovalError: Error, Equatable {
  case invalidOwner, recipientNotFound, recipientAlreadyRevoked
  case invalidPlan, invalidCandidate, invalidGeneration
  case protectionLossAcknowledgementRequired, invalidAcknowledgement
}

/// Public decision data for one recipient at one authenticated checkpoint.
struct V3RecoveryRecipientRemovalPlan: Equatable, Sendable {
  let expectedCheckpoint: V3ManifestCheckpoint
  let authorizingDevice: V3DeviceWrappedManifestDevice
  let removedRecipient: V3RecoveryRecipient
  let resultingRecipients: [V3RecoveryRecipient]

  var remainingActiveRecipients: Int {
    resultingRecipients.filter { $0.status == .active }.count
  }
  var removesLastActiveRecipient: Bool { remainingActiveRecipients == 0 }
}

struct V3RecoveryRecipientRemovalPlanner: Sendable {
  let limits: V3ManifestRepositoryLimits
  init(limits: V3ManifestRepositoryLimits = .standard) { self.limits = limits }

  func plan(
    checkpoint: V3ManifestCheckpoint, parent: V3RecoveryManifestEnvelope,
    currentVaultKey: Data, authorizingDeviceID: String, removing recipientID: V3RecoveryRecipientID
  ) throws -> V3RecoveryRecipientRemovalPlan {
    try V3RecoveryContentMutationValidator(limits: limits).validateParent(
      parent, checkpoint: checkpoint, vaultKey: currentVaultKey)
    return try planMetadata(
      checkpoint: checkpoint, parent: parent, authorizingDeviceID: authorizingDeviceID,
      removing: recipientID)
  }

  /// Roster decision only. Callers must authenticate the checkpoint before
  /// review or publication; public restart preflight separately checks its proof.
  func planMetadata(
    checkpoint: V3ManifestCheckpoint, parent: V3RecoveryManifestEnvelope,
    authorizingDeviceID: String, removing recipientID: V3RecoveryRecipientID
  ) throws -> V3RecoveryRecipientRemovalPlan {
    guard
      let owner = parent.body.fields.devices.first(where: {
        $0.identity.deviceID == authorizingDeviceID && $0.status == .active
      })
    else { throw V3RecoveryRecipientRemovalError.invalidOwner }
    guard
      let recipient = parent.body.recovery.recipients.first(where: {
        $0.recipientID == recipientID
      })
    else { throw V3RecoveryRecipientRemovalError.recipientNotFound }
    guard recipient.status == .active else {
      throw V3RecoveryRecipientRemovalError.recipientAlreadyRevoked
    }
    let resulting = try parent.body.recovery.recipients.map { record in
      guard record.recipientID == recipientID else { return record }
      return try V3RecoveryRecipient(
        registrationID: record.registrationID, publicKey: record.publicKey, slot: record.slot,
        status: .revoked)
    }
    return .init(
      expectedCheckpoint: checkpoint, authorizingDevice: owner, removedRecipient: recipient,
      resultingRecipients: resulting)
  }
}

/// The product must collect an informed user decision before constructing this.
/// Exact-plan binding is not proof of human consent, saved approval or authority
/// to resume later. This value is not persisted in the candidate or manifest.
struct V3RecoveryProtectionLossAcknowledgement: Equatable, Sendable {
  let plan: V3RecoveryRecipientRemovalPlan

  init(plan: V3RecoveryRecipientRemovalPlan) throws {
    guard plan.removesLastActiveRecipient else {
      throw V3RecoveryRecipientRemovalError.invalidAcknowledgement
    }
    self.plan = plan
  }

  static func validate(
    _ acknowledgement: Self?, for plan: V3RecoveryRecipientRemovalPlan
  ) throws {
    if plan.removesLastActiveRecipient {
      guard let acknowledgement else {
        throw V3RecoveryRecipientRemovalError.protectionLossAcknowledgementRequired
      }
      guard acknowledgement.plan == plan else {
        throw V3RecoveryRecipientRemovalError.invalidAcknowledgement
      }
    } else if acknowledgement != nil {
      throw V3RecoveryRecipientRemovalError.invalidAcknowledgement
    }
  }
}

/// Unpublished encrypted output only. No raw vault keys, private credentials or
/// durable consent are retained.
struct V3RecoveryRecipientRemovalCandidate: Equatable, Sendable {
  let plan: V3RecoveryRecipientRemovalPlan
  let envelope: V3RecoveryManifestEnvelope
  let stagedEntries: [V3EncryptedEntry]
}

/// Fresh key epoch and recovery generation, preserving every other authority
/// and all plaintext. Never operates on or clears the removed hardware token.
struct V3RecoveryRecipientRemovalBuilder: Sendable {
  let limits: V3ManifestRepositoryLimits
  init(limits: V3ManifestRepositoryLimits = .standard) { self.limits = limits }

  func build(
    parent: V3RecoveryManifestEnvelope, currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
    plan: V3RecoveryRecipientRemovalPlan, currentVaultKey: Data, nextVaultKey: Data,
    owner: any V3EnrollmentMessageSigning, reason: String,
    protectionLossAcknowledgement: V3RecoveryProtectionLossAcknowledgement? = nil,
    authorityTransitionID: String = UUID().uuidString.lowercased(),
    generationID: String = UUID().uuidString.lowercased()
  ) throws -> V3RecoveryRecipientRemovalCandidate {
    let reviewed = try V3RecoveryRecipientRemovalPlanner(limits: limits).plan(
      checkpoint: plan.expectedCheckpoint, parent: parent, currentVaultKey: currentVaultKey,
      authorizingDeviceID: plan.authorizingDevice.identity.deviceID,
      removing: plan.removedRecipient.recipientID)
    guard reviewed == plan else { throw V3RecoveryRecipientRemovalError.invalidPlan }
    guard owner.vaultID == plan.expectedCheckpoint.vaultID,
      owner.publicIdentity == plan.authorizingDevice.identity, !reason.isEmpty
    else { throw V3RecoveryRecipientRemovalError.invalidOwner }
    try V3RecoveryProtectionLossAcknowledgement.validate(protectionLossAcknowledgement, for: plan)
    guard isValidV3UUID(generationID), generationID != parent.body.recovery.generationID else {
      throw V3RecoveryRecipientRemovalError.invalidGeneration
    }
    let values = try V3EntrySnapshotValidator(limits: limits).plaintexts(
      fields: parent.body.fields, entries: currentEntries, vaultKey: currentVaultKey)
    let material = try V3RecoveryEpochMaterialBuilder(limits: limits).build(
      fields: parent.body.fields, plaintexts: values, nextVaultKey: nextVaultKey,
      authorityTransitionID: authorityTransitionID, devices: parent.body.fields.devices,
      generationID: generationID, recipients: plan.resultingRecipients)
    let envelope = try V3RecoveryEpochBoundary().authorize(
      candidate: material.body, parent: parent, currentVaultKey: currentVaultKey,
      nextVaultKey: nextVaultKey, signer: owner, reason: reason)
    let candidate = V3RecoveryRecipientRemovalCandidate(
      plan: plan, envelope: envelope, stagedEntries: material.stagedEntries)
    try V3RecoveryRecipientRemovalValidator(limits: limits).validate(
      candidate, parent: parent, currentEntries: currentEntries, currentVaultKey: currentVaultKey,
      nextVaultKey: nextVaultKey, expectedOwner: owner.publicIdentity,
      protectionLossAcknowledgement: protectionLossAcknowledgement)
    return candidate
  }
}

/// Reconstructs the exact recipient decision independently of the builder, then
/// checks the complete old/new snapshots. Publication durability is separate.
struct V3RecoveryRecipientRemovalValidator: Sendable {
  let limits: V3ManifestRepositoryLimits
  init(limits: V3ManifestRepositoryLimits = .standard) { self.limits = limits }

  func preflight(
    _ candidate: V3RecoveryRecipientRemovalCandidate, parent: V3RecoveryManifestEnvelope,
    currentVaultKey: Data, expectedOwner: V3EnrollmentDeviceIdentity,
    protectionLossAcknowledgement: V3RecoveryProtectionLossAcknowledgement? = nil
  ) throws {
    try preflightTransition(
      candidate, parent: parent, currentVaultKey: currentVaultKey, expectedOwner: expectedOwner)
    try V3RecoveryProtectionLossAcknowledgement.validate(
      protectionLossAcknowledgement, for: candidate.plan)
  }

  private func preflightTransition(
    _ candidate: V3RecoveryRecipientRemovalCandidate, parent: V3RecoveryManifestEnvelope,
    currentVaultKey: Data, expectedOwner: V3EnrollmentDeviceIdentity
  ) throws {
    try V3RecoveryContentMutationValidator(limits: limits).validateParent(
      parent, checkpoint: candidate.plan.expectedCheckpoint, vaultKey: currentVaultKey)
    try preflightPublic(candidate, parent: parent, expectedOwner: expectedOwner)
  }

  /// Public proof and exact recipient delta only. This does not authenticate a
  /// snapshot, infer protection-loss consent or authorize a fresh removal.
  func preflightPublic(
    _ candidate: V3RecoveryRecipientRemovalCandidate, parent: V3RecoveryManifestEnvelope,
    expectedOwner: V3EnrollmentDeviceIdentity
  ) throws {
    let plan = candidate.plan
    let reviewed = try V3RecoveryRecipientRemovalPlanner(limits: limits).planMetadata(
      checkpoint: plan.expectedCheckpoint, parent: parent,
      authorizingDeviceID: plan.authorizingDevice.identity.deviceID,
      removing: plan.removedRecipient.recipientID)
    guard reviewed == plan, expectedOwner == plan.authorizingDevice.identity else {
      throw V3RecoveryRecipientRemovalError.invalidPlan
    }
    let body = candidate.envelope.body
    guard body.fields.devices == parent.body.fields.devices,
      body.recovery.recipients == plan.resultingRecipients,
      body.recovery.generationID != parent.body.recovery.generationID
    else { throw V3RecoveryRecipientRemovalError.invalidCandidate }
    try V3RecoveryEpochSnapshotValidator(limits: limits).preflightPublic(
      candidate.envelope, checkpoint: plan.expectedCheckpoint, parent: parent,
      stagedEntryCount: candidate.stagedEntries.count,
      expectedOwner: expectedOwner)
  }

  /// Transition authentication only, not approval or ownership. The durable
  /// kernel must establish exact local ownership before using this for restart.
  /// Fresh publication still requires the separately reviewed plan and explicit
  /// protection-loss acknowledgment through validate/preflight.
  func validatePinnedTransition(
    _ candidate: V3RecoveryRecipientRemovalCandidate, parent: V3RecoveryManifestEnvelope,
    currentEntries: [V3EntryObjectKey: V3EncryptedEntry], currentVaultKey: Data,
    nextVaultKey: Data, expectedOwner: V3EnrollmentDeviceIdentity
  ) throws {
    try preflightTransition(
      candidate, parent: parent, currentVaultKey: currentVaultKey, expectedOwner: expectedOwner)
    try V3RecoveryEpochSnapshotValidator(limits: limits).validateSnapshots(
      candidate.envelope, stagedEntries: candidate.stagedEntries, parent: parent,
      currentEntries: currentEntries, currentVaultKey: currentVaultKey, nextVaultKey: nextVaultKey)
  }

  func validate(
    _ candidate: V3RecoveryRecipientRemovalCandidate, parent: V3RecoveryManifestEnvelope,
    currentEntries: [V3EntryObjectKey: V3EncryptedEntry], currentVaultKey: Data,
    nextVaultKey: Data, expectedOwner: V3EnrollmentDeviceIdentity,
    protectionLossAcknowledgement: V3RecoveryProtectionLossAcknowledgement? = nil
  ) throws {
    try preflight(
      candidate, parent: parent, currentVaultKey: currentVaultKey, expectedOwner: expectedOwner,
      protectionLossAcknowledgement: protectionLossAcknowledgement)
    try V3RecoveryEpochSnapshotValidator(limits: limits).validateSnapshots(
      candidate.envelope, stagedEntries: candidate.stagedEntries, parent: parent,
      currentEntries: currentEntries, currentVaultKey: currentVaultKey, nextVaultKey: nextVaultKey)
  }

  func validateForPublication(
    _ candidate: V3RecoveryRecipientRemovalCandidate, parent: V3RecoveryManifestEnvelope,
    currentEntries: [V3EntryObjectKey: V3EncryptedEntry], currentVaultKey: Data,
    nextVaultKey: Data, identity: any V3DeviceWrappedVaultKeyUnwrapping, reason: String,
    protectionLossAcknowledgement: V3RecoveryProtectionLossAcknowledgement? = nil
  ) throws {
    guard !reason.isEmpty, identity.vaultID == candidate.plan.expectedCheckpoint.vaultID else {
      throw V3RecoveryRecipientRemovalError.invalidOwner
    }
    try validate(
      candidate, parent: parent, currentEntries: currentEntries, currentVaultKey: currentVaultKey,
      nextVaultKey: nextVaultKey, expectedOwner: identity.publicIdentity,
      protectionLossAcknowledgement: protectionLossAcknowledgement)
    try V3RecoveryEpochSnapshotValidator(limits: limits).validateLocalWrapper(
      candidate.envelope, nextVaultKey: nextVaultKey, identity: identity, reason: reason)
  }
}
