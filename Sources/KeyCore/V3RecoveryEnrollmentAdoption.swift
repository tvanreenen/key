import Foundation

enum V3RecoveryEnrollmentAdoptionError: Error, Equatable {
  case invalidCeremony, identityUnavailable, approvalUnavailable, ambiguousApproval
  case conflictingCheckpoint, pendingWork
}

/// Verified local joining state, not product selection or a recovery capability.
struct V3RecoveryEnrollmentAdoptionCommit: Equatable, Sendable {
  let checkpoint: V3ManifestCheckpoint
  let envelope: V3RecoveryManifestEnvelope
}

/// Exact first trust on a joining Mac. The caller owns helper mutation
/// serialization. Public comparison/proofs precede the one Mac wrapper operation;
/// current authentication and all entries precede insert-only checkpoint trust.
/// No shared publication, configuration selection, token access or provisioning.
struct V3RecoveryEnrollmentAdoptionService: Sendable {
  private let vaultID: String
  private let identity: any V3DeviceWrappedVaultKeyUnwrapping
  private let source: any V3ImmutableObjectReading
  private let checkpoints: any V3ManifestCheckpointStoring
  private let ownership: any V3ImmutableTransactionRecoveryAnchorStoring
  private let registration: any V3ImmutableTransactionRecoveryAnchorStoring
  private let adoption: any V3ImmutableTransactionRecoveryAnchorStoring
  private let ceremonies: any V3EnrollmentCeremonyStateStoring
  private let cache: any V3CheckpointManifestCaching
  private let session: V3DeviceWrappedVaultKeySessionStore
  private let limits: V3ManifestRepositoryLimits
  private let phaseObserver: any V3EnrollmentAdoptionPhaseObserving

  init(
    vaultID: String, identity: any V3DeviceWrappedVaultKeyUnwrapping,
    source: any V3ImmutableObjectReading, checkpointStore: any V3ManifestCheckpointStoring,
    recoveryAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    registrationAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    adoptionAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    ceremonyStore: any V3EnrollmentCeremonyStateStoring, cache: any V3CheckpointManifestCaching,
    session: V3DeviceWrappedVaultKeySessionStore,
    limits: V3ManifestRepositoryLimits = .standard,
    phaseObserver: any V3EnrollmentAdoptionPhaseObserving =
      V3RecoveryEnrollmentNoopAdoptionObserver()
  ) {
    self.vaultID = vaultID
    self.identity = identity
    self.source = source
    checkpoints = checkpointStore
    ownership = recoveryAnchorStore
    registration = registrationAnchorStore
    adoption = adoptionAnchorStore
    ceremonies = ceremonyStore
    self.cache = cache
    self.session = session
    self.limits = limits
    self.phaseObserver = phaseObserver
  }

  /// Explicit comparison is required on every call. Expiry does not discard an
  /// already published owner approval. Retry never replaces a different floor.
  func adopt(
    invitationDigest: Data, approvedTranscriptDigest: Data,
    operationID: VaultTransactionOperationID
  ) throws -> V3RecoveryEnrollmentAdoptionCommit {
    do {
      try requireNoPending()
      let ceremony = try loadCeremony(invitationDigest)
      guard let transcript = ceremony.transcript, approvedTranscriptDigest.count == 32,
        transcript.digest == approvedTranscriptDigest
      else { throw V3RecoveryEnrollmentAdoptionError.invalidCeremony }
      guard identity.vaultID == vaultID,
        identity.publicIdentity == transcript.joinRequest.joiningDevice
      else { throw V3RecoveryEnrollmentAdoptionError.identityUnavailable }
      let selected = try select(transcript)
      let existingCheckpoint = try checkpoints.loadCheckpoint(vaultID: vaultID)
      guard existingCheckpoint == nil || existingCheckpoint == selected.checkpoint.canonicalBytes
      else { throw V3RecoveryEnrollmentAdoptionError.conflictingCheckpoint }
      let ticket = session.beginAuthentication()
      let cached =
        session.hasResidentKey
        ? try session.load(vaultID: vaultID, keyID: selected.envelope.body.fields.keyID) : nil
      try recheck(selected, ceremony: ceremony, checkpoint: existingCheckpoint, ticket: ticket)
      let key: Data
      if let cached {
        key = cached
      } else {
        guard
          let wrapper = selected.envelope.body.fields.wrappedKeys.first(where: {
            $0.recipientDeviceID == identity.publicIdentity.deviceID
          })
        else { throw V3RecoveryEnrollmentAdoptionError.identityUnavailable }
        key = try identity.unwrapDeviceWrappedVaultKey(
          wrapper.wrappedKey,
          context: selected.envelope.body.deviceContext(
            recipientDeviceID: identity.publicIdentity.deviceID),
          reason: "Unlock the vault key approved for this Mac in the compared enrollment.")
      }
      try session.requireCurrent(ticket)
      try V3RecoveryEpochBoundary().verifyCurrentAuthentication(selected.envelope, vaultKey: key)
      _ = try V3EntrySnapshotValidator(limits: limits).plaintexts(
        fields: selected.envelope.body.fields, entries: selected.repository.entries, vaultKey: key)
      try recheck(selected, ceremony: ceremony, checkpoint: existingCheckpoint, ticket: ticket)
      try phaseObserver.didReach(.approvalVerified, operationID: operationID)
      try recheck(selected, ceremony: ceremony, checkpoint: existingCheckpoint, ticket: ticket)
      // Cache is non-authoritative and contains only exact encrypted bytes.
      try cache.store(selected.envelope.canonicalBytes, for: selected.checkpoint)
      try recheck(selected, ceremony: ceremony, checkpoint: existingCheckpoint, ticket: ticket)
      if existingCheckpoint == nil {
        try checkpoints.replaceCheckpoint(
          selected.checkpoint.canonicalBytes, expectedCheckpoint: nil, vaultID: vaultID)
      }
      try phaseObserver.didReach(.checkpointInstalled, operationID: operationID)
      try recheck(
        selected, ceremony: ceremony, checkpoint: selected.checkpoint.canonicalBytes, ticket: ticket
      )
      let consumed = try consume(ceremony)
      try phaseObserver.didReach(.ceremonyConsumed, operationID: operationID)
      try recheck(
        selected, ceremony: consumed, checkpoint: selected.checkpoint.canonicalBytes, ticket: ticket
      )
      // Final authority installation is guarded atomically against a lock,
      // expiry or even same-key session replacement during authentication.
      try session.install(
        key, vaultID: vaultID, keyID: selected.envelope.body.fields.keyID,
        authenticationTicket: ticket)
      return .init(checkpoint: selected.checkpoint, envelope: selected.envelope)
    } catch {
      session.invalidate()
      // Retain any exact checkpoint/ceremony already committed for safe retry.
      throw error
    }
  }

  private struct Selection {
    let checkpoint: V3ManifestCheckpoint
    let envelope: V3RecoveryManifestEnvelope
    let repository: V3ExactTransitionRepositoryState
  }

  private func select(_ transcript: V3EnrollmentTranscript) throws -> Selection {
    let parentDigest = transcript.invitation.parentManifestDigest
    var graph = V3RecoveryManifestGraph(source: source, limits: limits, maximumParentEdges: 16_384)
    let inventory = try graph.loadInventory(floor: parentDigest)
    guard inventory.digests.contains(parentDigest) else {
      throw V3RecoveryValidationError.sourceUnavailable
    }
    let parent = try graph.envelope(parentDigest)
    let transitionID = try v3EnrollmentAuthorityTransitionID(transcriptDigest: transcript.digest)
    var matches: [V3RecoveryManifestEnvelope] = []
    for digest in inventory.digests {
      guard let object = graph.objects[digest], object.vaultID == vaultID,
        object.parents == [parentDigest]
      else { continue }
      let envelope = try graph.envelope(digest)
      if envelope.body.fields.authorityTransitionID == transitionID { matches.append(envelope) }
    }
    guard !matches.isEmpty else { throw V3RecoveryEnrollmentAdoptionError.approvalUnavailable }
    guard matches.count == 1, let envelope = matches.first else {
      throw V3RecoveryEnrollmentAdoptionError.ambiguousApproval
    }
    // No catch-up or branch choice is hidden in first trust. The exact approved
    // addition must be the sole visible successor, within the graph budgets.
    guard
      try graph.anchoredOrder(floor: parentDigest, vaultID: vaultID) == [
        parentDigest, envelope.digest,
      ]
    else { throw V3RecoveryValidationError.sourceChanged }
    let checkpoint = try V3ManifestCheckpoint(vaultID: vaultID, envelopeDigest: envelope.digest)
    let repository = try objects.observe(
      checkpoint: checkpoint, expectedBase: envelope.canonicalBytes)
    guard repository.manifestBytes == graph.objects.mapValues(\.bytes),
      repository.listedObjectCount == inventory.objectCount
    else { throw V3RecoveryValidationError.sourceChanged }
    let candidate = V3RecoveryDeviceEnrollmentCandidate(
      expectedCheckpoint: try .init(vaultID: vaultID, envelopeDigest: parentDigest),
      envelope: envelope,
      stagedEntries: Array(repository.entries.values), transcriptDigest: transcript.digest)
    try V3RecoveryDeviceEnrollmentValidator(limits: limits).preflightComparedEnrollment(
      candidate, parent: parent, transcript: transcript)
    return .init(checkpoint: checkpoint, envelope: envelope, repository: repository)
  }

  private var objects: V3ExactTransitionRepository { .init(source: source, limits: limits) }

  private func recheck(
    _ selected: Selection, ceremony: V3EnrollmentCeremonyState, checkpoint: Data?,
    ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket
  ) throws {
    try session.requireCurrent(ticket)
    try requireNoPending()
    guard try checkpoints.loadCheckpoint(vaultID: vaultID) == checkpoint else {
      throw V3RecoveryEnrollmentAdoptionError.conflictingCheckpoint
    }
    guard
      try ceremonies.loadState(vaultID: vaultID, invitationDigest: ceremony.invitationDigest)
        == ceremony.canonicalBytes
    else { throw V3RecoveryEnrollmentAdoptionError.invalidCeremony }
    guard
      try objects.observe(
        checkpoint: selected.checkpoint, expectedBase: selected.envelope.canonicalBytes)
        == selected.repository
    else { throw V3RecoveryValidationError.sourceChanged }
    try session.requireCurrent(ticket)
  }

  private func loadCeremony(_ invitationDigest: Data) throws -> V3EnrollmentCeremonyState {
    guard isValidV3UUID(vaultID), invitationDigest.count == 32,
      let bytes = try ceremonies.loadState(vaultID: vaultID, invitationDigest: invitationDigest),
      bytes.count <= V3EnrollmentCeremonyState.maximumBytes
    else { throw V3RecoveryEnrollmentAdoptionError.invalidCeremony }
    let state = try V3EnrollmentCeremonyState(canonicalBytes: bytes)
    guard state.vaultID == vaultID, state.invitationDigest == invitationDigest,
      state.role == .joiner, state.phase == .awaitingComparison || state.phase == .consumed,
      state.ownerApproval == nil, let join = state.signedJoinRequest
    else { throw V3RecoveryEnrollmentAdoptionError.invalidCeremony }
    let authenticator = V3EnrollmentMessageAuthenticator()
    _ = try authenticator.verify(state.signedInvitation)
    _ = try authenticator.verify(join)
    return state
  }

  private func consume(_ state: V3EnrollmentCeremonyState) throws -> V3EnrollmentCeremonyState {
    if state.phase == .consumed { return state }
    let consumed = try V3EnrollmentCeremonyState(
      vaultID: vaultID, invitationDigest: state.invitationDigest, role: .joiner, phase: .consumed,
      signedInvitation: state.signedInvitation, signedJoinRequest: state.signedJoinRequest)
    try ceremonies.replaceState(
      consumed.canonicalBytes, expectedState: state.canonicalBytes, vaultID: vaultID,
      invitationDigest: state.invitationDigest)
    return consumed
  }

  private func requireNoPending() throws {
    for store in [ownership, registration, adoption] {
      guard try store.loadRecoveryAnchor(vaultID: vaultID) == nil else {
        throw V3RecoveryEnrollmentAdoptionError.pendingWork
      }
    }
  }
}

struct V3RecoveryEnrollmentNoopAdoptionObserver: V3EnrollmentAdoptionPhaseObserving {
  func didReach(_: V3EnrollmentAdoptionPhase, operationID _: VaultTransactionOperationID) throws {}
}
