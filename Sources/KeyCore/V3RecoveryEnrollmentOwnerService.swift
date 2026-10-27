import CryptoKit
import Foundation

/// Authenticated comparison data, not evidence that the user approved it.
struct V3RecoveryEnrollmentReview: Equatable, Sendable {
  let checkpoint: V3ManifestCheckpoint
  let transcript: V3EnrollmentTranscript
}

/// Helper-owned enrollment orchestration. Initial approval requires an unlocked
/// exact session and the explicitly compared digest. Restart finishes only pinned
/// work. Neither path provisions a token, adopts a joiner or implements cold unlock.
struct V3RecoveryEnrollmentOwnerService: Sendable {
  typealias Identity = any V3EnrollmentMessageSigning & V3DeviceWrappedVaultKeyUnwrapping
  private let vaultID: String
  private let identity: Identity
  private let session: V3DeviceWrappedVaultKeySessionStore
  private let store: any V3TransactionArtifactStore
  private let checkpoints: any V3ManifestCheckpointStoring
  private let ownership: any V3ImmutableTransactionRecoveryAnchorStoring
  private let registration: any V3ImmutableTransactionRecoveryAnchorStoring
  private let adoption: any V3ImmutableTransactionRecoveryAnchorStoring
  private let ceremonies: any V3EnrollmentCeremonyStateStoring
  private let cache: any V3CheckpointManifestCaching
  private let limits: V3ManifestRepositoryLimits
  private let phaseObserver: any V3ImmutableTransactionPhaseObserving
  private let validateScope: @Sendable () throws -> Void

  init(
    vaultID: String, identity: Identity, session: V3DeviceWrappedVaultKeySessionStore,
    objectStore: any V3TransactionArtifactStore, checkpointStore: any V3ManifestCheckpointStoring,
    recoveryAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    registrationAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    adoptionAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    ceremonyStore: any V3EnrollmentCeremonyStateStoring,
    cache: any V3CheckpointManifestCaching, limits: V3ManifestRepositoryLimits = .standard,
    phaseObserver: any V3ImmutableTransactionPhaseObserving =
      V3NoopContentTransactionPhaseObserver(),
    validateScope: @escaping @Sendable () throws -> Void = {}
  ) {
    self.vaultID = vaultID
    self.identity = identity
    self.session = session
    store = objectStore
    checkpoints = checkpointStore
    ownership = recoveryAnchorStore
    registration = registrationAnchorStore
    adoption = adoptionAnchorStore
    ceremonies = ceremonyStore
    self.cache = cache
    self.limits = limits
    self.phaseObserver = phaseObserver
    self.validateScope = validateScope
  }

  func prepare(
    invitationDigest: Data, at unixTime: UInt64,
    continuing ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket? = nil
  ) throws -> V3RecoveryEnrollmentReview {
    try loadBase(
      invitationDigest: invitationDigest, at: unixTime,
      continuing: ticket ?? session.beginAuthentication()
    ).review
  }

  func approve(
    invitationDigest: Data, approvedTranscriptDigest: Data,
    expectedCheckpoint: V3ManifestCheckpoint, at unixTime: UInt64,
    operationID: VaultTransactionOperationID,
    continuing admission: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket? = nil
  ) throws -> V3RecoveryDeviceEnrollmentCommit {
    do {
      guard expectedCheckpoint.vaultID == vaultID else {
        throw V3RecoveryDeviceEnrollmentError.invalidCandidate
      }
      try lifecycle.requireCheckpoint(expectedCheckpoint)
      let ticket = admission ?? session.beginAuthentication()
      try session.requireCurrent(ticket)
      let base = try loadBase(
        invitationDigest: invitationDigest, at: unixTime, continuing: ticket)
      guard base.review.checkpoint == expectedCheckpoint,
        approvedTranscriptDigest.count == 32,
        base.review.transcript.digest == approvedTranscriptDigest
      else { throw V3RecoveryDeviceEnrollmentError.invalidCeremony }
      try session.requireCurrent(ticket)
      let nextKey = try freshKey(excluding: base.current.envelope.body.fields.keyID)
      let candidate = try V3RecoveryDeviceEnrollmentBuilder(limits: limits).build(
        checkpoint: expectedCheckpoint, parent: base.current.envelope,
        currentEntries: base.current.source.entries,
        state: base.ceremony, currentVaultKey: base.current.key, nextVaultKey: nextKey,
        owner: identity,
        at: unixTime,
        reason: "Give the Mac whose code you compared access and change the vault key.")
      try requireSameCeremony(base.ceremony, consumed: false)
      try lifecycle.revalidate(base.current)
      let publisher = publisher(operationID)
      let commit = try publisher.publish(
        candidate, state: base.ceremony, approvedTranscriptDigest: approvedTranscriptDigest,
        currentVaultKey: base.current.key, nextVaultKey: nextKey,
        identity: SessionBoundUnwrapper(base: identity, session: session, ticket: ticket),
        at: unixTime, reason: "Verify this Mac can open the approved enrollment's new vault key.")
      try installCommitted(
        commit.envelope, ceremony: base.ceremony, vaultKey: nextKey, continuing: ticket,
        operationID: operationID, publisher: publisher)
      return commit
    } catch {
      // Never install from an error, undo commitment or erase pending approval.
      if (try? checkpoints.loadCheckpoint(vaultID: vaultID)) != expectedCheckpoint.canonicalBytes {
        session.invalidate()
      }
      throw error
    }
  }

  /// A lost reply is acknowledged only when the exact compared enrollment is
  /// still the authenticated local floor. Never interpret a newer head as the
  /// same approval, or sign another transition for a consumed ceremony.
  func confirmCompletedEnrollment(
    invitationDigest: Data, approvedTranscriptDigest: Data,
    continuing ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket
  ) throws {
    let ceremony = try loadCeremony(invitationDigest)
    let compared = try transcript(ceremony)
    guard ceremony.phase == .consumed, compared.digest == approvedTranscriptDigest else {
      throw V3RecoveryDeviceEnrollmentError.invalidCeremony
    }
    let current = try lifecycle.current(continuing: ticket)
    let parentCheckpoint = try V3ManifestCheckpoint(
      vaultID: vaultID, envelopeDigest: compared.invitation.parentManifestDigest)
    let parent = try V3RecoveryManifestCodec().parseEnvelope(
      objects.readManifest(parentCheckpoint.envelopeDigest))
    let candidate = V3RecoveryDeviceEnrollmentCandidate(
      expectedCheckpoint: parentCheckpoint, envelope: current.envelope,
      stagedEntries: Array(current.source.entries.values), transcriptDigest: compared.digest)
    try V3RecoveryDeviceEnrollmentValidator(limits: limits).preflightComparedEnrollment(
      candidate, parent: parent, transcript: compared)
    try requireSameCeremony(ceremony, consumed: true)
    try lifecycle.revalidate(current)
  }

  func recoverInterruptedEnrollment(
    invitationDigest: Data, operationID: VaultTransactionOperationID
  ) throws -> V3ImmutableTransactionRecoveryOutcome {
    do {
      let ceremony = try loadCeremony(invitationDigest)
      let digest = try transcript(ceremony).digest
      let publisher = publisher(operationID)
      let state: V3ContentTransactionRecoveryState
      switch try publisher.prepareInterruptedTransaction(
        vaultID: vaultID, state: ceremony, approvedTranscriptDigest: digest,
        expectedOwner: identity.publicIdentity)
      {
      case .finished(let outcome):
        if case .abandoned = outcome { session.invalidate() }
        return outcome
      case .ready(let ready): state = ready
      }
      let checked = try preflight(state, ceremony: ceremony)
      let ticket = session.beginAuthentication()
      let currentID =
        checked.parent?.body.fields.keyID ?? checked.candidate.envelope.body.fields.keyID
      let cached =
        session.hasResidentKey ? try? session.load(vaultID: vaultID, keyID: currentID) : nil
      try session.requireCurrent(ticket)
      try requireRecoveryState(state, ceremony: ceremony)
      var oldKey: Data?
      if let parent = checked.parent {
        let key =
          try cached
          ?? openMacKey(
            parent, ticket: ticket,
            reason: "Authenticate the current vault before finishing its exact approved enrollment."
          )
        try V3RecoveryContentMutationValidator(limits: limits).validateParent(
          parent, checkpoint: state.intent.expectedCheckpoint, vaultKey: key)
        _ = try snapshots.plaintexts(
          fields: parent.body.fields, entries: checked.source.entries, vaultKey: key)
        oldKey = key
        try recheck(state, checked: checked, ceremony: ceremony, publisher: publisher)
        try session.requireCurrent(ticket)
      }
      let nextKey: Data
      if state.alreadyCommitted, let cached {
        nextKey = cached
      } else {
        nextKey = try openMacKey(
          checked.candidate.envelope, ticket: ticket,
          reason:
            "Open this Mac's exact pending enrollment key to finish the approved device addition.")
      }
      try session.requireCurrent(ticket)
      try recheck(state, checked: checked, ceremony: ceremony, publisher: publisher)
      let outcome = try publisher.recoverInterruptedTransaction(
        vaultID: vaultID, state: ceremony, approvedTranscriptDigest: digest,
        currentVaultKey: oldKey, nextVaultKey: nextKey, expectedOwner: identity.publicIdentity,
        expectedAnchor: state.anchorData)
      switch outcome {
      case .completed, .alreadyCompleted:
        try lifecycle.requireNoPending()
        try installCommitted(
          checked.candidate.envelope, ceremony: ceremony, vaultKey: nextKey,
          continuing: ticket, operationID: state.intent.operationID, publisher: publisher)
      case .nothingToRecover, .abandoned: session.invalidate()
      }
      return outcome
    } catch {
      session.invalidate()
      throw error
    }
  }

  private struct Base {
    let review: V3RecoveryEnrollmentReview
    let ceremony: V3EnrollmentCeremonyState
    let current: V3RecoveryLifecycleContext.Current
  }
  private var objects: V3ExactTransitionRepository { .init(source: store, limits: limits) }
  private var snapshots: V3EntrySnapshotValidator { .init(limits: limits) }
  private var lifecycle: V3RecoveryLifecycleContext {
    .init(
      vaultID: vaultID, identity: identity.publicIdentity, session: session, source: store,
      checkpoints: checkpoints, ownership: ownership, registration: registration,
      adoption: adoption,
      limits: limits, validateScope: validateScope)
  }

  private func loadBase(
    invitationDigest: Data, at unixTime: UInt64,
    continuing ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket
  ) throws -> Base {
    try lifecycle.requireNoPending()
    let ceremony = try loadCeremony(invitationDigest)
    let compared = try transcript(ceremony)
    let checkpoint = try V3ManifestCheckpoint(
      vaultID: vaultID, envelopeDigest: compared.invitation.parentManifestDigest)
    try lifecycle.requireCheckpoint(checkpoint)
    let envelope = try V3RecoveryManifestCodec().parseEnvelope(
      objects.readManifest(checkpoint.envelopeDigest))
    let policy = V3RecoveryDeviceEnrollmentValidator(limits: limits)
    _ = try policy.validateCeremony(
      ceremony, checkpoint: checkpoint, parent: envelope,
      expectedOwner: identity.publicIdentity, at: unixTime)
    _ = try policy.resultingDevices(
      parent: envelope.body.fields.devices, joining: compared.joinRequest.joiningDevice)
    let current: V3RecoveryLifecycleContext.Current
    do { current = try lifecycle.current(continuing: ticket) } catch V3RecoveryLifecycleContextError
      .invalidOwner
    {
      throw V3RecoveryDeviceEnrollmentError.invalidOwner
    }
    guard current.checkpoint == checkpoint, current.envelope == envelope else {
      throw V3RecoveryValidationError.sourceChanged
    }
    try requireSameCeremony(ceremony, consumed: false)
    try session.requireCurrent(ticket)
    return .init(
      review: .init(checkpoint: checkpoint, transcript: compared), ceremony: ceremony,
      current: current)
  }

  private struct RecoverySource {
    let candidate: V3RecoveryDeviceEnrollmentCandidate
    let parent: V3RecoveryManifestEnvelope?
    let source: V3ExactTransitionRepositoryState
  }
  private func preflight(
    _ state: V3ContentTransactionRecoveryState, ceremony: V3EnrollmentCeremonyState
  ) throws
    -> RecoverySource
  {
    try requireRecoveryState(state, ceremony: ceremony)
    let compared = try transcript(ceremony)
    let envelope = try V3RecoveryManifestCodec().parseEnvelope(state.manifestData)
    guard envelope.body.fields.vaultID == vaultID,
      envelope.parents == [state.intent.expectedCheckpoint.envelopeDigest],
      envelope.authorizations.map(\.signerDeviceID) == [identity.publicIdentity.deviceID],
      envelope.body.fields.authorityTransitionID
        == (try v3EnrollmentAuthorityTransitionID(transcriptDigest: compared.digest)),
      envelope.body.fields.devices.contains(
        .init(identity: identity.publicIdentity, status: .active)),
      envelope.body.fields.devices.contains(
        .init(identity: compared.joinRequest.joiningDevice, status: .active))
    else { throw V3RecoveryDeviceEnrollmentError.invalidCandidate }
    let staged = try snapshots.entryMap(state.availableEntries)
    let addresses = try envelope.body.fields.entries.map {
      try V3RecoveryMergeMutationValidator.address($0)
    }
    guard Set(addresses) == Set(staged.keys) else {
      throw V3RecoveryDeviceEnrollmentError.invalidCandidate
    }
    for (record, address) in zip(envelope.body.fields.entries, addresses) {
      guard
        staged[address]?.context
          == (try V3EntryAuthenticationContext(vaultID: vaultID, entry: record))
      else { throw V3RecoveryDeviceEnrollmentError.invalidCandidate }
    }
    let candidate = V3RecoveryDeviceEnrollmentCandidate(
      expectedCheckpoint: state.intent.expectedCheckpoint,
      envelope: envelope, stagedEntries: state.availableEntries, transcriptDigest: compared.digest)
    let parent: V3RecoveryManifestEnvelope?
    let source: V3ExactTransitionRepositoryState
    if state.alreadyCommitted {
      parent = nil
      source = try objects.observe(
        checkpoint: state.candidateCheckpoint, expectedBase: state.manifestData)
      guard staged == source.entries else { throw V3RecoveryDeviceEnrollmentError.invalidCandidate }
    } else {
      let before = try V3RecoveryManifestCodec().parseEnvelope(
        objects.readManifest(state.intent.expectedCheckpoint.envelopeDigest))
      try V3RecoveryDeviceEnrollmentValidator(limits: limits).preflightPublicAnchored(
        candidate,
        parent: before, state: ceremony, expectedOwner: identity.publicIdentity)
      parent = before
      source = try objects.observe(
        checkpoint: state.intent.expectedCheckpoint,
        expectedBase: before.canonicalBytes, candidate: envelope,
        stagedEntries: state.availableEntries)
      try objects.requireProjectedUsage(
        source, candidate: envelope, stagedEntries: state.availableEntries)
    }
    try requireRecoveryState(state, ceremony: ceremony)
    return .init(candidate: candidate, parent: parent, source: source)
  }

  private func recheck(
    _ state: V3ContentTransactionRecoveryState, checked: RecoverySource,
    ceremony: V3EnrollmentCeremonyState, publisher: V3RecoveryDeviceEnrollmentPublisher
  ) throws {
    try requireRecoveryState(state, ceremony: ceremony)
    guard
      case .ready(let fresh) = try publisher.prepareInterruptedTransaction(
        vaultID: vaultID,
        state: ceremony, approvedTranscriptDigest: transcript(ceremony).digest,
        expectedOwner: identity.publicIdentity, expectedAnchor: state.anchorData),
      fresh.intent == state.intent, fresh.currentCheckpoint == state.currentCheckpoint,
      fresh.manifestData == state.manifestData, fresh.availableEntries == state.availableEntries
    else { throw V3RecoveryValidationError.sourceChanged }
    let observed = try preflight(fresh, ceremony: ceremony)
    try objects.requireUnchangedSource(
      checked.source, observed.source, candidateDigest: state.intent.candidateManifestDigest)
  }

  private func installCommitted(
    _ envelope: V3RecoveryManifestEnvelope, ceremony: V3EnrollmentCeremonyState,
    vaultKey: Data, continuing ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket,
    operationID: VaultTransactionOperationID, publisher: V3RecoveryDeviceEnrollmentPublisher
  ) throws {
    try lifecycle.installCommitted(envelope, vaultKey: vaultKey, continuing: ticket) { pending in
      try requireSameCeremony(ceremony, consumed: true)
      if let pending {
        let addresses = try envelope.body.fields.entries.map {
          try V3RecoveryMergeMutationValidator.address($0)
        }.sorted(by: entryObjectKeyPrecedes)
        let expectedIntent = try V3ImmutableTransactionRecoveryIntent(
          operationID: operationID, kind: .enrollDevice, vaultID: vaultID,
          expectedCheckpoint: .init(
            vaultID: vaultID, envelopeDigest: transcript(ceremony).invitation.parentManifestDigest),
          expectedHeads: [transcript(ceremony).invitation.parentManifestDigest],
          candidateManifestDigest: envelope.digest,
          stagedEntries: addresses.map { .init(entryID: $0.entryID, digest: $0.digest) },
          enrollmentTranscriptDigest: transcript(ceremony).digest)
        guard pending.count <= 1_024,
          let anchor = try? V3ImmutableTransactionRecoveryAnchor(canonicalBytes: pending),
          anchor.vaultID == vaultID, anchor.operationID == operationID,
          anchor.intentDigest == Data(SHA256.hash(data: expectedIntent.canonicalBytes))
        else { throw V3ImmutableTransactionRecoveryError.invalidRecoveryAnchor(vaultID: vaultID) }
        guard
          case .ready(let selected) = try publisher.prepareInterruptedTransaction(
            vaultID: vaultID,
            state: ceremony, approvedTranscriptDigest: transcript(ceremony).digest,
            expectedOwner: identity.publicIdentity, expectedAnchor: pending),
          selected.alreadyCommitted, selected.intent.operationID == operationID,
          selected.manifestData == envelope.canonicalBytes
        else { throw V3RecoveryValidationError.sourceChanged }
      }
      try requireSameCeremony(ceremony, consumed: true)
    }
  }

  private func loadCeremony(_ invitationDigest: Data) throws -> V3EnrollmentCeremonyState {
    guard isValidV3UUID(vaultID), identity.vaultID == vaultID, invitationDigest.count == 32,
      let bytes = try ceremonies.loadState(vaultID: vaultID, invitationDigest: invitationDigest),
      bytes.count <= V3EnrollmentCeremonyState.maximumBytes,
      let state = try? V3EnrollmentCeremonyState(canonicalBytes: bytes),
      state.vaultID == vaultID, state.invitationDigest == invitationDigest,
      state.role == .inviter, state.ownerApproval == nil,
      [.awaitingComparison, .consumed].contains(state.phase),
      state.signedInvitation.invitation.invitingDevice == identity.publicIdentity,
      let join = state.signedJoinRequest
    else { throw V3RecoveryDeviceEnrollmentError.invalidCeremony }
    let authenticator = V3EnrollmentMessageAuthenticator()
    _ = try authenticator.verify(state.signedInvitation)
    _ = try authenticator.verify(join)
    return state
  }
  private func transcript(_ state: V3EnrollmentCeremonyState) throws -> V3EnrollmentTranscript {
    guard let transcript = state.transcript else {
      throw V3RecoveryDeviceEnrollmentError.invalidCeremony
    }
    return transcript
  }
  private func requireSameCeremony(_ expected: V3EnrollmentCeremonyState, consumed: Bool) throws {
    let actual = try loadCeremony(expected.invitationDigest)
    guard actual.signedInvitation == expected.signedInvitation,
      actual.signedJoinRequest == expected.signedJoinRequest,
      actual.phase == (consumed ? .consumed : expected.phase)
    else { throw V3RecoveryDeviceEnrollmentError.invalidCeremony }
  }
  private func requireRecoveryState(
    _ state: V3ContentTransactionRecoveryState,
    ceremony: V3EnrollmentCeremonyState
  ) throws {
    try lifecycle.requireNoAuthorityWork()
    try requireSameCeremony(ceremony, consumed: false)
    try lifecycle.requireCheckpoint(state.currentCheckpoint)
    guard try ownership.loadRecoveryAnchor(vaultID: vaultID) == state.anchorData else {
      throw V3ImmutableTransactionRecoveryError.invalidRecoveryAnchor(vaultID: vaultID)
    }
  }
  private func openMacKey(
    _ envelope: V3RecoveryManifestEnvelope,
    ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket, reason: String
  ) throws -> Data {
    try session.requireCurrent(ticket)
    guard
      let wrapper = envelope.body.fields.wrappedKeys.first(where: {
        $0.recipientDeviceID == identity.publicIdentity.deviceID
      })
    else { throw V3RecoveryKeyRotationError.localWrapperMismatch }
    let key = try identity.unwrapDeviceWrappedVaultKey(
      wrapper.wrappedKey,
      context: envelope.body.deviceContext(recipientDeviceID: identity.publicIdentity.deviceID),
      reason: reason)
    try session.requireCurrent(ticket)
    try V3RecoveryEpochBoundary().verifyCurrentAuthentication(envelope, vaultKey: key)
    return key
  }
  private func freshKey(excluding currentID: V3VaultKeyID) throws -> Data {
    for _ in 0 ..< 16 {
      let key = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
      if try V3VaultKeyID.derive(vaultKey: key, vaultID: vaultID) != currentID { return key }
    }
    throw V3RecoveryDeviceEnrollmentError.invalidCandidate
  }
  private func publisher(_ operationID: VaultTransactionOperationID)
    -> V3RecoveryDeviceEnrollmentPublisher
  {
    .init(
      mutationOwner: DirectVaultTransactionMutationOwner(operationID: operationID),
      objectStore: store, checkpointStore: checkpoints, recoveryAnchorStore: ownership,
      registrationAnchorStore: registration, adoptionAnchorStore: adoption,
      ceremonyStore: ceremonies,
      cache: cache, limits: limits, phaseObserver: phaseObserver, validateScope: validateScope)
  }
  private struct SessionBoundUnwrapper: V3DeviceWrappedVaultKeyUnwrapping {
    let base: Identity
    let session: V3DeviceWrappedVaultKeySessionStore
    let ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket
    var vaultID: String { base.vaultID }
    var publicIdentity: V3EnrollmentDeviceIdentity { base.publicIdentity }
    func unwrapDeviceWrappedVaultKey(
      _ wrappedKey: V3HPKEWrappedVaultKey,
      context: V3VaultKeyHPKEContext, reason: String
    ) throws -> Data {
      try session.requireCurrent(ticket)
      let key = try base.unwrapDeviceWrappedVaultKey(wrappedKey, context: context, reason: reason)
      try session.requireCurrent(ticket)
      return key
    }
  }
}
