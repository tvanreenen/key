import CryptoKit
import Foundation

struct V3RecoveryRecipientRemovalCommit: Sendable {
  let checkpoint: V3ManifestCheckpoint
  let envelope: V3RecoveryManifestEnvelope
}

/// Internal publication of one reviewed recovery-recipient removal. Initial
/// last-recipient removal requires exact protection-loss acknowledgment before
/// local ownership is reserved. Restart pins bytes, not renewed consent. No token
/// administration, session installation or product routing occurs.
struct V3RecoveryRecipientRemovalPublisher: Sendable {
  private let mutationOwner: any VaultTransactionMutationOwning
  private let objectStore: any V3TransactionArtifactStore
  private let checkpointStore: any V3ManifestCheckpointStoring
  private let recoveryAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring
  private let registrationAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring
  private let adoptionAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring
  private let cache: any V3CheckpointManifestCaching
  private let limits: V3ManifestRepositoryLimits
  private let phaseObserver: any V3ImmutableTransactionPhaseObserving

  init(
    mutationOwner: any VaultTransactionMutationOwning, objectStore: any V3TransactionArtifactStore,
    checkpointStore: any V3ManifestCheckpointStoring,
    recoveryAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    registrationAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    adoptionAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    cache: any V3CheckpointManifestCaching, limits: V3ManifestRepositoryLimits = .standard,
    phaseObserver: any V3ImmutableTransactionPhaseObserving =
      V3NoopContentTransactionPhaseObserver()
  ) {
    self.mutationOwner = mutationOwner
    self.objectStore = objectStore
    self.checkpointStore = checkpointStore
    self.recoveryAnchorStore = recoveryAnchorStore
    self.registrationAnchorStore = registrationAnchorStore
    self.adoptionAnchorStore = adoptionAnchorStore
    self.cache = cache
    self.limits = limits
    self.phaseObserver = phaseObserver
  }

  func publish(
    _ candidate: V3RecoveryRecipientRemovalCandidate, approvedPlan: V3RecoveryRecipientRemovalPlan,
    currentVaultKey: Data, nextVaultKey: Data,
    identity: any V3DeviceWrappedVaultKeyUnwrapping, reason: String,
    protectionLossAcknowledgement: V3RecoveryProtectionLossAcknowledgement? = nil
  ) throws -> V3RecoveryRecipientRemovalCommit {
    try mutationOwner.perform(.removeRecoveryRecipient) { context in
      guard candidate.plan == approvedPlan else {
        throw V3RecoveryRecipientRemovalError.invalidPlan
      }
      guard identity.vaultID == approvedPlan.expectedCheckpoint.vaultID, !reason.isEmpty,
        identity.publicIdentity == approvedPlan.authorizingDevice.identity
      else { throw V3RecoveryRecipientRemovalError.invalidOwner }
      try V3RecoveryProtectionLossAcknowledgement.validate(
        protectionLossAcknowledgement, for: approvedPlan)
      let validator = validator(
        currentVaultKey: currentVaultKey, expectedOwner: identity.publicIdentity,
        approvedPlan: approvedPlan, protectionLossAcknowledgement: protectionLossAcknowledgement)
      let input = V3ContentTransactionInput(
        kind: .removeRecoveryRecipient, expectedCheckpoint: approvedPlan.expectedCheckpoint,
        manifestData: candidate.envelope.canonicalBytes, manifestDigest: candidate.envelope.digest,
        stagedEntries: candidate.stagedEntries)
      try validator.requireAvailable(vaultID: identity.vaultID)
      try requireFreshStart(approvedPlan.expectedCheckpoint)
      let checked = try validator.validate(input, vaultKey: nextVaultKey, alreadyCommitted: false)
      guard checked.envelope == candidate.envelope else {
        throw V3RecoveryRecipientRemovalError.invalidCandidate
      }
      try requireFreshStart(approvedPlan.expectedCheckpoint)
      try V3RecoveryEpochSnapshotValidator(limits: limits).validateLocalWrapper(
        checked.envelope, nextVaultKey: nextVaultKey, identity: identity, reason: reason)
      // Cancellation never reserves work. Source/plan/ownership must still be
      // exact when native authentication returns, before the intent is pinned.
      try validator.recheck(
        input, validated: checked, vaultKey: nextVaultKey, alreadyCommitted: false)
      try requireFreshStart(approvedPlan.expectedCheckpoint)
      let result = try publisher(validator, operationID: context.operationID).publish(
        input, vaultKey: nextVaultKey)
      return .init(
        checkpoint: try .init(vaultID: identity.vaultID, envelopeDigest: result.envelope.digest),
        envelope: result.envelope)
    }
  }

  /// Uncommitted work still requires both complete snapshots and keys. Exact
  /// committed cleanup authenticates only the current epoch. Neither path signs,
  /// changes the reviewed recipient, generates an epoch or invokes a token.
  func recoverInterruptedTransaction(
    vaultID: String, currentVaultKey: Data?, nextVaultKey: Data,
    expectedOwner: V3EnrollmentDeviceIdentity, expectedAnchor: Data? = nil
  ) throws -> V3ImmutableTransactionRecoveryOutcome {
    try mutationOwner.perform(.recoverInterruptedTransaction) { context in
      try publisher(
        validator(currentVaultKey: currentVaultKey, expectedOwner: expectedOwner),
        operationID: context.operationID
      ).recoverInterruptedTransaction(
        vaultID: vaultID, vaultKey: nextVaultKey, expectedAnchor: expectedAnchor)
    }
  }

  /// Bounded selection, not authentication or fresh removal/protection-loss approval.
  func prepareInterruptedTransaction(
    vaultID: String, expectedOwner: V3EnrollmentDeviceIdentity, expectedAnchor: Data? = nil
  ) throws -> V3ContentTransactionRecoveryPreparation {
    try mutationOwner.perform(.recoverInterruptedTransaction) { context in
      try publisher(
        validator(currentVaultKey: nil, expectedOwner: expectedOwner),
        operationID: context.operationID
      ).prepareInterruptedTransaction(vaultID: vaultID, expectedAnchor: expectedAnchor)
    }
  }

  private func requireFreshStart(_ checkpoint: V3ManifestCheckpoint) throws {
    if let bytes = try recoveryAnchorStore.loadRecoveryAnchor(vaultID: checkpoint.vaultID) {
      guard let anchor = try? V3ImmutableTransactionRecoveryAnchor(canonicalBytes: bytes),
        anchor.vaultID == checkpoint.vaultID
      else {
        throw V3ImmutableTransactionRecoveryError.invalidRecoveryAnchor(vaultID: checkpoint.vaultID)
      }
      throw V3ImmutableTransactionRecoveryError.interruptedTransactionPending(
        operationID: anchor.operationID.rawValue)
    }
    guard
      try checkpointStore.loadCheckpoint(vaultID: checkpoint.vaultID) == checkpoint.canonicalBytes
    else { throw V3ImmutableTransactionError.expectedHeadsChanged }
  }

  private func validator(
    currentVaultKey: Data?, expectedOwner: V3EnrollmentDeviceIdentity,
    approvedPlan: V3RecoveryRecipientRemovalPlan? = nil,
    protectionLossAcknowledgement: V3RecoveryProtectionLossAcknowledgement? = nil
  ) -> V3RecoveryRecipientRemovalTransactionValidator {
    .init(
      objectStore: objectStore, registrationAnchorStore: registrationAnchorStore,
      adoptionAnchorStore: adoptionAnchorStore, currentVaultKey: currentVaultKey,
      expectedOwner: expectedOwner, approvedPlan: approvedPlan,
      protectionLossAcknowledgement: protectionLossAcknowledgement, limits: limits)
  }
  private func publisher(
    _ validator: V3RecoveryRecipientRemovalTransactionValidator,
    operationID: VaultTransactionOperationID
  ) -> V3ContentTransactionPublisher<V3RecoveryRecipientRemovalTransactionValidator> {
    .init(
      mutationOwner: DirectVaultTransactionMutationOwner(operationID: operationID),
      objectStore: objectStore, checkpointStore: checkpointStore,
      recoveryAnchorStore: recoveryAnchorStore,
      cache: cache, validator: validator, limits: limits, phaseObserver: phaseObserver)
  }
}

/// Only one exact recipient removal is accepted. Initial review is checked
/// independently; restart reconstructs the locally pinned recipient delta,
/// without inferring a new user acknowledgment from provider bytes.
struct V3RecoveryRecipientRemovalTransactionValidator: V3ContentTransactionValidating {
  let objectStore: any V3TransactionArtifactStore
  let registrationAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring
  let adoptionAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring
  let currentVaultKey: Data?
  let expectedOwner: V3EnrollmentDeviceIdentity
  let approvedPlan: V3RecoveryRecipientRemovalPlan?
  let protectionLossAcknowledgement: V3RecoveryProtectionLossAcknowledgement?
  let limits: V3ManifestRepositoryLimits
  private var objects: V3ExactTransitionRepository { .init(source: objectStore, limits: limits) }
  private var snapshots: V3EntrySnapshotValidator { .init(limits: limits) }

  func requireAvailable(vaultID: String) throws {
    for store in [registrationAnchorStore, adoptionAnchorStore] {
      guard try store.loadRecoveryAnchor(vaultID: vaultID) == nil else {
        throw V3RecoveryContentPublicationError.otherMutationPending
      }
    }
  }
  func keyID(manifestData: Data) throws -> V3VaultKeyID {
    try V3RecoveryManifestCodec().parseEnvelope(manifestData).body.fields.keyID
  }
  func validateRecoveryIntent(_ intent: V3ImmutableTransactionRecoveryIntent) throws {
    guard intent.kind == .removeRecoveryRecipient,
      intent.expectedHeads == [intent.expectedCheckpoint.envelopeDigest],
      intent.enrollmentTranscriptDigest == nil, intent.recoveryMergeResolutions == nil
    else {
      throw V3ImmutableTransactionRecoveryError.invalidIntent(
        operationID: intent.operationID.rawValue)
    }
  }

  func validate(
    _ input: V3ContentTransactionInput, vaultKey: Data, alreadyCommitted: Bool
  ) throws -> V3RecoveryValidatedContentTransaction {
    try requireAvailable(vaultID: input.expectedCheckpoint.vaultID)
    guard input.kind == .removeRecoveryRecipient, input.recoveryMerge == nil,
      input.manifestData.count <= limits.maximumManifestBytes, input.manifestDigest.count == 32,
      Data(SHA256.hash(data: input.manifestData)) == input.manifestDigest,
      input.stagedEntries.count <= limits.maximumReferencedEntryObjects
    else { throw V3RecoveryRecipientRemovalError.invalidCandidate }
    let envelope = try V3RecoveryManifestCodec().parseEnvelope(input.manifestData)
    guard envelope.body.fields.vaultID == input.expectedCheckpoint.vaultID,
      envelope.parents == [input.expectedCheckpoint.envelopeDigest],
      envelope.authorizations.map(\.signerDeviceID) == [expectedOwner.deviceID],
      envelope.body.fields.devices.contains(.init(identity: expectedOwner, status: .active))
    else { throw V3RecoveryRecipientRemovalError.invalidCandidate }
    if let approvedPlan {
      guard approvedPlan.expectedCheckpoint == input.expectedCheckpoint,
        approvedPlan.authorizingDevice.identity == expectedOwner,
        envelope.body.recovery.recipients == approvedPlan.resultingRecipients
      else { throw V3RecoveryRecipientRemovalError.invalidPlan }
    }
    let staged = try snapshots.entryMap(input.stagedEntries)
    let source: V3ExactTransitionRepositoryState
    if alreadyCommitted {
      // The kernel established the exact candidate checkpoint and local intent.
      // Cleanup cannot authorize a different removal or replay old epochs.
      try V3RecoveryEpochBoundary().verifyCurrentAuthentication(envelope, vaultKey: vaultKey)
      source = try objects.observe(
        checkpoint: .init(
          vaultID: input.expectedCheckpoint.vaultID, envelopeDigest: input.manifestDigest),
        expectedBase: input.manifestData)
      _ = try snapshots.plaintexts(
        fields: envelope.body.fields, entries: source.entries, vaultKey: vaultKey)
      guard staged == source.entries else { throw V3RecoveryRecipientRemovalError.invalidCandidate }
    } else {
      let parentBytes = try objects.readManifest(input.expectedCheckpoint.envelopeDigest)
      let parent = try V3RecoveryManifestCodec().parseEnvelope(parentBytes)
      guard let currentVaultKey else {
        throw V3ImmutableTransactionRecoveryError.vaultKeyUnavailable(
          keyID: parent.body.fields.keyID.rawValue)
      }
      try V3RecoveryContentMutationValidator(limits: limits).validateParent(
        parent, checkpoint: input.expectedCheckpoint, vaultKey: currentVaultKey)
      let plan = try reconstructPublicPlan(input, envelope: envelope, parent: parent)
      if let approvedPlan, plan != approvedPlan {
        throw V3RecoveryRecipientRemovalError.invalidPlan
      }
      source = try objects.observe(
        checkpoint: input.expectedCheckpoint, expectedBase: parentBytes,
        candidate: envelope, stagedEntries: input.stagedEntries)
      let candidate = V3RecoveryRecipientRemovalCandidate(
        plan: plan, envelope: envelope, stagedEntries: input.stagedEntries)
      let policy = V3RecoveryRecipientRemovalValidator(limits: limits)
      if approvedPlan != nil {
        try policy.validate(
          candidate, parent: parent, currentEntries: source.entries,
          currentVaultKey: currentVaultKey, nextVaultKey: vaultKey, expectedOwner: expectedOwner,
          protectionLossAcknowledgement: protectionLossAcknowledgement)
      } else {
        // The kernel pins exact local intent and kind before selecting restart
        // input. Authenticate that transition, not a new consent decision.
        try policy.validatePinnedTransition(
          candidate, parent: parent, currentEntries: source.entries,
          currentVaultKey: currentVaultKey, nextVaultKey: vaultKey, expectedOwner: expectedOwner)
      }
      try objects.requireProjectedUsage(
        source, candidate: envelope, stagedEntries: input.stagedEntries)
    }
    try requireAvailable(vaultID: input.expectedCheckpoint.vaultID)
    return .init(envelope: envelope, stagedEntries: staged, completeEntries: staged, source: source)
  }

  /// Exact roster metadata only, not authenticated review or renewed consent.
  /// Full validation separately authenticates both keys and complete snapshots.
  func reconstructPublicPlan(
    _ input: V3ContentTransactionInput, envelope: V3RecoveryManifestEnvelope,
    parent: V3RecoveryManifestEnvelope
  ) throws -> V3RecoveryRecipientRemovalPlan {
    let old = parent.body.recovery.recipients
    let new = envelope.body.recovery.recipients
    guard old.count == new.count else { throw V3RecoveryRecipientRemovalError.invalidCandidate }
    let changes = zip(old, new).filter { $0 != $1 }
    guard changes.count == 1, let (before, after) = changes.first,
      before.registrationID == after.registrationID, before.publicKey == after.publicKey,
      before.slot == after.slot, before.status == .active, after.status == .revoked
    else { throw V3RecoveryRecipientRemovalError.invalidCandidate }
    let plan = try V3RecoveryRecipientRemovalPlanner(limits: limits).planMetadata(
      checkpoint: input.expectedCheckpoint, parent: parent,
      authorizingDeviceID: expectedOwner.deviceID, removing: before.recipientID)
    guard plan.resultingRecipients == new, plan.authorizingDevice.identity == expectedOwner else {
      throw V3RecoveryRecipientRemovalError.invalidPlan
    }
    return plan
  }

  func recheck(
    _ input: V3ContentTransactionInput, validated: V3RecoveryValidatedContentTransaction,
    vaultKey: Data, alreadyCommitted: Bool
  ) throws {
    let fresh = try validate(input, vaultKey: vaultKey, alreadyCommitted: alreadyCommitted)
    guard fresh.envelope == validated.envelope, fresh.stagedEntries == validated.stagedEntries,
      fresh.completeEntries == validated.completeEntries
    else { throw V3RecoveryValidationError.sourceChanged }
    try objects.requireUnchangedSource(
      validated.source, fresh.source, candidateDigest: input.manifestDigest)
  }
  func validateStagedObjects(
    _ validated: V3RecoveryValidatedContentTransaction, operationID: VaultTransactionOperationID
  ) throws {
    for (key, entry) in validated.stagedEntries {
      try exact(
        objectStore.readStagedEntry(
          entryID: key.entryID, digest: key.digest, operationID: operationID,
          maximumBytes: limits.maximumEntryBytes), entry.canonicalBytes)
    }
  }
  func validatePublishedEntries(_ validated: V3RecoveryValidatedContentTransaction) throws {
    for (key, entry) in validated.completeEntries {
      try exact(
        objectStore.readEntry(
          entryID: key.entryID, digest: key.digest, maximumBytes: limits.maximumEntryBytes),
        entry.canonicalBytes)
    }
  }
  func validatePublishedManifest(_ validated: V3RecoveryValidatedContentTransaction) throws {
    try exact(
      objectStore.readManifest(
        digest: validated.envelope.digest, maximumBytes: limits.maximumManifestBytes),
      validated.envelope.canonicalBytes)
  }
  private func exact(_ read: V3RepositoryObjectRead, _ expected: Data) throws {
    guard case .available(let bytes) = read, bytes == expected else {
      throw V3RecoveryValidationError.sourceChanged
    }
  }
}
