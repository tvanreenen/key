import CryptoKit
import Foundation

struct V3RecoveryDeviceEnrollmentCommit: Sendable {
  let checkpoint: V3ManifestCheckpoint
  let envelope: V3RecoveryManifestEnvelope
}

/// Internal publication of an explicitly approved, locally pinned transcript.
/// No comparison UI, key generation, session installation or token operation.
struct V3RecoveryDeviceEnrollmentPublisher: Sendable {
  private let mutationOwner: any VaultTransactionMutationOwning
  private let objectStore: any V3TransactionArtifactStore
  private let checkpointStore: any V3ManifestCheckpointStoring
  private let recoveryAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring
  private let registrationAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring
  private let adoptionAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring
  private let ceremonyStore: any V3EnrollmentCeremonyStateStoring
  private let cache: any V3CheckpointManifestCaching
  private let limits: V3ManifestRepositoryLimits
  private let phaseObserver: any V3ImmutableTransactionPhaseObserving

  init(
    mutationOwner: any VaultTransactionMutationOwning, objectStore: any V3TransactionArtifactStore,
    checkpointStore: any V3ManifestCheckpointStoring,
    recoveryAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    registrationAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    adoptionAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    ceremonyStore: any V3EnrollmentCeremonyStateStoring,
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
    self.ceremonyStore = ceremonyStore
    self.cache = cache
    self.limits = limits
    self.phaseObserver = phaseObserver
  }

  func publish(
    _ candidate: V3RecoveryDeviceEnrollmentCandidate, state: V3EnrollmentCeremonyState,
    approvedTranscriptDigest: Data, currentVaultKey: Data, nextVaultKey: Data,
    identity: any V3DeviceWrappedVaultKeyUnwrapping, at unixTime: UInt64, reason: String
  ) throws -> V3RecoveryDeviceEnrollmentCommit {
    try mutationOwner.perform(.enrollDevice) { context in
      guard identity.vaultID == candidate.expectedCheckpoint.vaultID, !reason.isEmpty,
        state.phase == .awaitingComparison,
        candidate.transcriptDigest == approvedTranscriptDigest
      else { throw V3RecoveryDeviceEnrollmentError.invalidCeremony }
      let validator = validator(
        state: state, approvedTranscriptDigest: approvedTranscriptDigest,
        currentVaultKey: currentVaultKey, expectedOwner: identity.publicIdentity)
      try validator.requireAvailable(vaultID: identity.vaultID)
      try requireFreshStart(candidate.expectedCheckpoint)
      let input = V3ContentTransactionInput(
        kind: .enrollDevice, expectedCheckpoint: candidate.expectedCheckpoint,
        manifestData: candidate.envelope.canonicalBytes, manifestDigest: candidate.envelope.digest,
        stagedEntries: candidate.stagedEntries)
      let checked = try validator.validate(input, vaultKey: nextVaultKey, alreadyCommitted: false)
      let parent = try V3RecoveryManifestCodec().parseEnvelope(
        V3ExactTransitionRepository(source: objectStore, limits: limits).readManifest(
          candidate.expectedCheckpoint.envelopeDigest))
      try V3RecoveryDeviceEnrollmentValidator(limits: limits).preflight(
        candidate, parent: parent, state: state, currentVaultKey: currentVaultKey,
        expectedOwner: identity.publicIdentity, at: unixTime)
      try requireFreshStart(candidate.expectedCheckpoint)
      try V3RecoveryEpochSnapshotValidator(limits: limits).validateLocalWrapper(
        checked.envelope, nextVaultKey: nextVaultKey, identity: identity, reason: reason)
      try validator.recheck(
        input, validated: checked, vaultKey: nextVaultKey, alreadyCommitted: false)
      try requireFreshStart(candidate.expectedCheckpoint)
      let result = try publisher(validator, operationID: context.operationID).publish(
        input, vaultKey: nextVaultKey)
      return .init(
        checkpoint: try .init(vaultID: identity.vaultID, envelopeDigest: result.envelope.digest),
        envelope: result.envelope)
    }
  }

  /// Resumes only the stored transcript and exact locally anchored intent.
  /// Expiry is not reapplied and no new signing or private operation occurs.
  func recoverInterruptedTransaction(
    vaultID: String, state: V3EnrollmentCeremonyState, approvedTranscriptDigest: Data,
    currentVaultKey: Data?, nextVaultKey: Data, expectedOwner: V3EnrollmentDeviceIdentity,
    expectedAnchor: Data? = nil
  ) throws -> V3ImmutableTransactionRecoveryOutcome {
    try mutationOwner.perform(.recoverInterruptedTransaction) { context in
      try publisher(
        validator(
          state: state, approvedTranscriptDigest: approvedTranscriptDigest,
          currentVaultKey: currentVaultKey, expectedOwner: expectedOwner),
        operationID: context.operationID
      ).recoverInterruptedTransaction(
        vaultID: vaultID, vaultKey: nextVaultKey, expectedAnchor: expectedAnchor)
    }
  }

  func prepareInterruptedTransaction(
    vaultID: String, state: V3EnrollmentCeremonyState, approvedTranscriptDigest: Data,
    expectedOwner: V3EnrollmentDeviceIdentity, expectedAnchor: Data? = nil
  ) throws -> V3ContentTransactionRecoveryPreparation {
    try mutationOwner.perform(.recoverInterruptedTransaction) { context in
      try publisher(
        validator(
          state: state, approvedTranscriptDigest: approvedTranscriptDigest,
          currentVaultKey: nil, expectedOwner: expectedOwner), operationID: context.operationID
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
    state: V3EnrollmentCeremonyState, approvedTranscriptDigest: Data,
    currentVaultKey: Data?, expectedOwner: V3EnrollmentDeviceIdentity
  ) -> V3RecoveryDeviceEnrollmentTransactionValidator {
    .init(
      objectStore: objectStore, registrationAnchorStore: registrationAnchorStore,
      adoptionAnchorStore: adoptionAnchorStore, ceremonyStore: ceremonyStore, state: state,
      approvedTranscriptDigest: approvedTranscriptDigest, currentVaultKey: currentVaultKey,
      expectedOwner: expectedOwner, limits: limits)
  }
  private func publisher(
    _ validator: V3RecoveryDeviceEnrollmentTransactionValidator,
    operationID: VaultTransactionOperationID
  ) -> V3ContentTransactionPublisher<V3RecoveryDeviceEnrollmentTransactionValidator> {
    .init(
      mutationOwner: DirectVaultTransactionMutationOwner(operationID: operationID),
      objectStore: objectStore, checkpointStore: checkpointStore,
      recoveryAnchorStore: recoveryAnchorStore, cache: cache, validator: validator,
      limits: limits, phaseObserver: phaseObserver)
  }
}

/// Enrollment alone can approve the exact joining identity. Local ceremony
/// state and its transcript digest are selectors, not cryptographic authority.
struct V3RecoveryDeviceEnrollmentTransactionValidator: V3ContentTransactionValidating {
  let objectStore: any V3TransactionArtifactStore
  let registrationAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring
  let adoptionAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring
  let ceremonyStore: any V3EnrollmentCeremonyStateStoring
  let state: V3EnrollmentCeremonyState
  let approvedTranscriptDigest: Data
  let currentVaultKey: Data?
  let expectedOwner: V3EnrollmentDeviceIdentity
  let limits: V3ManifestRepositoryLimits
  private var objects: V3ExactTransitionRepository { .init(source: objectStore, limits: limits) }
  private var snapshots: V3EntrySnapshotValidator { .init(limits: limits) }

  func requireAvailable(vaultID: String) throws {
    for store in [registrationAnchorStore, adoptionAnchorStore] {
      guard try store.loadRecoveryAnchor(vaultID: vaultID) == nil else {
        throw V3RecoveryContentPublicationError.otherMutationPending
      }
    }
    _ = try localState(vaultID: vaultID)
  }
  func keyID(manifestData: Data) throws -> V3VaultKeyID {
    try V3RecoveryManifestCodec().parseEnvelope(manifestData).body.fields.keyID
  }

  func validateRecoveryIntent(_ intent: V3ImmutableTransactionRecoveryIntent) throws {
    try requireAvailable(vaultID: intent.vaultID)
    guard intent.kind == .enrollDevice,
      intent.expectedHeads == [intent.expectedCheckpoint.envelopeDigest],
      intent.expectedCheckpoint.envelopeDigest
        == state.signedInvitation.invitation.parentManifestDigest,
      intent.enrollmentTranscriptDigest == approvedTranscriptDigest,
      intent.recoveryMergeResolutions == nil
    else {
      throw V3ImmutableTransactionRecoveryError.invalidIntent(
        operationID: intent.operationID.rawValue)
    }
  }

  func recoveryIntent(
    for input: V3ContentTransactionInput, operationID: VaultTransactionOperationID,
    stagedEntries: [V3ImmutableTransactionRecoveryEntry]
  ) throws -> V3ImmutableTransactionRecoveryIntent {
    let intent = try V3ImmutableTransactionRecoveryIntent(
      operationID: operationID, kind: input.kind, vaultID: input.expectedCheckpoint.vaultID,
      expectedCheckpoint: input.expectedCheckpoint,
      expectedHeads: [input.expectedCheckpoint.envelopeDigest],
      candidateManifestDigest: input.manifestDigest, stagedEntries: stagedEntries,
      enrollmentTranscriptDigest: approvedTranscriptDigest)
    try validateRecoveryIntent(intent)
    return intent
  }

  func validate(
    _ input: V3ContentTransactionInput, vaultKey: Data, alreadyCommitted: Bool
  ) throws -> V3RecoveryValidatedContentTransaction {
    try requireAvailable(vaultID: input.expectedCheckpoint.vaultID)
    let local = try localState(vaultID: input.expectedCheckpoint.vaultID)
    guard input.kind == .enrollDevice, input.recoveryMerge == nil,
      input.expectedCheckpoint.envelopeDigest
        == state.signedInvitation.invitation.parentManifestDigest,
      input.manifestData.count <= limits.maximumManifestBytes,
      input.manifestDigest.count == 32,
      Data(SHA256.hash(data: input.manifestData)) == input.manifestDigest,
      input.stagedEntries.count <= limits.maximumReferencedEntryObjects,
      alreadyCommitted || local.phase == .awaitingComparison,
      let transcript = local.transcript
    else { throw V3RecoveryDeviceEnrollmentError.invalidCandidate }
    let envelope = try V3RecoveryManifestCodec().parseEnvelope(input.manifestData)
    guard envelope.body.fields.vaultID == input.expectedCheckpoint.vaultID,
      envelope.parents == [input.expectedCheckpoint.envelopeDigest],
      envelope.body.fields.authorityTransitionID
        == (try v3EnrollmentAuthorityTransitionID(transcriptDigest: approvedTranscriptDigest)),
      envelope.authorizations.map(\.signerDeviceID) == [expectedOwner.deviceID],
      envelope.body.fields.devices.contains(.init(identity: expectedOwner, status: .active)),
      envelope.body.fields.devices.contains(
        .init(identity: transcript.joinRequest.joiningDevice, status: .active))
    else { throw V3RecoveryDeviceEnrollmentError.invalidCandidate }
    let staged = try snapshots.entryMap(input.stagedEntries)
    let source: V3ExactTransitionRepositoryState
    if alreadyCommitted {
      try V3RecoveryEpochBoundary().verifyCurrentAuthentication(envelope, vaultKey: vaultKey)
      source = try objects.observe(
        checkpoint: .init(
          vaultID: input.expectedCheckpoint.vaultID, envelopeDigest: input.manifestDigest),
        expectedBase: input.manifestData)
      _ = try snapshots.plaintexts(
        fields: envelope.body.fields, entries: source.entries, vaultKey: vaultKey)
      guard staged == source.entries else { throw V3RecoveryDeviceEnrollmentError.invalidCandidate }
    } else {
      let parentBytes = try objects.readManifest(input.expectedCheckpoint.envelopeDigest)
      let parent = try V3RecoveryManifestCodec().parseEnvelope(parentBytes)
      guard let currentVaultKey else {
        throw V3ImmutableTransactionRecoveryError.vaultKeyUnavailable(
          keyID: parent.body.fields.keyID.rawValue)
      }
      try V3RecoveryContentMutationValidator(limits: limits).validateParent(
        parent, checkpoint: input.expectedCheckpoint, vaultKey: currentVaultKey)
      source = try objects.observe(
        checkpoint: input.expectedCheckpoint, expectedBase: parentBytes,
        candidate: envelope, stagedEntries: input.stagedEntries)
      try V3RecoveryDeviceEnrollmentValidator(limits: limits).validateAnchored(
        .init(
          expectedCheckpoint: input.expectedCheckpoint, envelope: envelope,
          stagedEntries: input.stagedEntries, transcriptDigest: approvedTranscriptDigest),
        parent: parent, currentEntries: source.entries, state: local,
        currentVaultKey: currentVaultKey, nextVaultKey: vaultKey, expectedOwner: expectedOwner)
      try objects.requireProjectedUsage(
        source, candidate: envelope, stagedEntries: input.stagedEntries)
    }
    try requireAvailable(vaultID: input.expectedCheckpoint.vaultID)
    return .init(envelope: envelope, stagedEntries: staged, completeEntries: staged, source: source)
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

  func finishCommitted(
    _ input: V3ContentTransactionInput, validated: V3RecoveryValidatedContentTransaction,
    vaultKey: Data
  ) throws {
    // Reopen the authenticated current snapshot, not historical ciphertext.
    let current = try validate(input, vaultKey: vaultKey, alreadyCommitted: true)
    guard current.envelope == validated.envelope,
      current.completeEntries == validated.completeEntries
    else { throw V3RecoveryValidationError.sourceChanged }
    let local = try localState(vaultID: input.expectedCheckpoint.vaultID)
    if local.phase == .consumed { return }
    let consumed = try V3EnrollmentCeremonyState(
      vaultID: local.vaultID, invitationDigest: local.invitationDigest, role: .inviter,
      phase: .consumed, signedInvitation: local.signedInvitation,
      signedJoinRequest: local.signedJoinRequest)
    try ceremonyStore.replaceState(
      consumed.canonicalBytes, expectedState: local.canonicalBytes,
      vaultID: local.vaultID, invitationDigest: local.invitationDigest)
  }

  private func localState(vaultID: String) throws -> V3EnrollmentCeremonyState {
    guard state.vaultID == vaultID, state.role == .inviter, state.ownerApproval == nil,
      [.awaitingComparison, .consumed].contains(state.phase),
      approvedTranscriptDigest.count == 32, state.transcript?.digest == approvedTranscriptDigest,
      state.signedInvitation.invitation.invitingDevice == expectedOwner,
      let bytes = try ceremonyStore.loadState(
        vaultID: vaultID, invitationDigest: state.invitationDigest),
      bytes.count <= V3EnrollmentCeremonyState.maximumBytes,
      let local = try? V3EnrollmentCeremonyState(canonicalBytes: bytes),
      local.vaultID == state.vaultID, local.invitationDigest == state.invitationDigest,
      local.role == .inviter, local.ownerApproval == nil,
      local.signedInvitation == state.signedInvitation,
      local.signedJoinRequest == state.signedJoinRequest,
      local.phase == state.phase
        || (state.phase == .awaitingComparison && local.phase == .consumed),
      let join = local.signedJoinRequest
    else { throw V3RecoveryDeviceEnrollmentError.invalidCeremony }
    let authenticator = V3EnrollmentMessageAuthenticator()
    _ = try authenticator.verify(local.signedInvitation)
    _ = try authenticator.verify(join)
    return local
  }

  func validateStagedObjects(
    _ validated: V3RecoveryValidatedContentTransaction, operationID: VaultTransactionOperationID
  ) throws {
    for (key, entry) in validated.stagedEntries {
      try exact(
        objectStore.readStagedEntry(
          entryID: key.entryID, digest: key.digest,
          operationID: operationID, maximumBytes: limits.maximumEntryBytes), entry.canonicalBytes)
    }
  }
  func validatePublishedEntries(_ validated: V3RecoveryValidatedContentTransaction) throws {
    for (key, entry) in validated.completeEntries {
      try exact(
        objectStore.readEntry(
          entryID: key.entryID, digest: key.digest,
          maximumBytes: limits.maximumEntryBytes), entry.canonicalBytes)
    }
  }
  func validatePublishedManifest(_ validated: V3RecoveryValidatedContentTransaction) throws {
    try exact(
      objectStore.readManifest(
        digest: validated.envelope.digest,
        maximumBytes: limits.maximumManifestBytes), validated.envelope.canonicalBytes)
  }
  private func exact(_ read: V3RepositoryObjectRead, _ expected: Data) throws {
    guard case .available(let bytes) = read, bytes == expected else {
      throw V3RecoveryValidationError.sourceChanged
    }
  }
}
