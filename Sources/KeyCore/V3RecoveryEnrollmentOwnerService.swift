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

  init(
    vaultID: String, identity: Identity, session: V3DeviceWrappedVaultKeySessionStore,
    objectStore: any V3TransactionArtifactStore, checkpointStore: any V3ManifestCheckpointStoring,
    recoveryAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    registrationAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    adoptionAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    ceremonyStore: any V3EnrollmentCeremonyStateStoring,
    cache: any V3CheckpointManifestCaching, limits: V3ManifestRepositoryLimits = .standard,
    phaseObserver: any V3ImmutableTransactionPhaseObserving =
      V3NoopContentTransactionPhaseObserver()
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
  }

  func prepare(invitationDigest: Data, at unixTime: UInt64) throws -> V3RecoveryEnrollmentReview {
    try loadBase(invitationDigest: invitationDigest, at: unixTime).review
  }

  func approve(
    invitationDigest: Data, approvedTranscriptDigest: Data,
    expectedCheckpoint: V3ManifestCheckpoint, at unixTime: UInt64,
    operationID: VaultTransactionOperationID
  ) throws -> V3RecoveryDeviceEnrollmentCommit {
    do {
      guard expectedCheckpoint.vaultID == vaultID else {
        throw V3RecoveryDeviceEnrollmentError.invalidCandidate
      }
      try requireCheckpoint(expectedCheckpoint)
      let ticket = session.beginAuthentication()
      let base = try loadBase(invitationDigest: invitationDigest, at: unixTime)
      guard base.review.checkpoint == expectedCheckpoint,
        approvedTranscriptDigest.count == 32,
        base.review.transcript.digest == approvedTranscriptDigest
      else { throw V3RecoveryDeviceEnrollmentError.invalidCeremony }
      try session.requireCurrent(ticket)
      let nextKey = try freshKey(excluding: base.envelope.body.fields.keyID)
      let candidate = try V3RecoveryDeviceEnrollmentBuilder(limits: limits).build(
        checkpoint: expectedCheckpoint, parent: base.envelope, currentEntries: base.source.entries,
        state: base.ceremony, currentVaultKey: base.key, nextVaultKey: nextKey, owner: identity,
        at: unixTime,
        reason: "Give the Mac whose code you compared access and change the vault key.")
      try session.requireCurrent(ticket)
      try requireNoPending()
      try requireCheckpoint(expectedCheckpoint)
      try requireSameCeremony(base.ceremony, consumed: false)
      guard
        try objects.observe(
          checkpoint: expectedCheckpoint, expectedBase: base.envelope.canonicalBytes)
          == base.source,
        try session.load(vaultID: vaultID, keyID: base.envelope.body.fields.keyID) == base.key
      else { throw V3RecoveryValidationError.sourceChanged }
      let publisher = publisher(operationID)
      let commit = try publisher.publish(
        candidate, state: base.ceremony, approvedTranscriptDigest: approvedTranscriptDigest,
        currentVaultKey: base.key, nextVaultKey: nextKey,
        identity: SessionBoundUnwrapper(base: identity, session: session, ticket: ticket),
        at: unixTime, reason: "Verify this Mac can open the approved enrollment's new vault key.")
      try requireCommitted(
        commit.envelope, ceremony: base.ceremony, vaultKey: nextKey, operationID: operationID,
        publisher: publisher)
      try session.install(
        nextKey, vaultID: vaultID, keyID: commit.envelope.body.fields.keyID,
        authenticationTicket: ticket)
      return commit
    } catch {
      // Never install from an error, undo commitment or erase pending approval.
      if (try? checkpoints.loadCheckpoint(vaultID: vaultID)) != expectedCheckpoint.canonicalBytes {
        session.invalidate()
      }
      throw error
    }
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
        try requireNoPending()
        try requireCommitted(
          checked.candidate.envelope, ceremony: ceremony, vaultKey: nextKey,
          operationID: state.intent.operationID, publisher: publisher)
        try session.install(
          nextKey, vaultID: vaultID,
          keyID: checked.candidate.envelope.body.fields.keyID, authenticationTicket: ticket)
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
    let envelope: V3RecoveryManifestEnvelope
    let key: Data
    let source: V3ExactTransitionRepositoryState
  }
  private var objects: V3ExactTransitionRepository { .init(source: store, limits: limits) }
  private var snapshots: V3EntrySnapshotValidator { .init(limits: limits) }

  private func loadBase(invitationDigest: Data, at unixTime: UInt64) throws -> Base {
    try requireNoPending()
    let ceremony = try loadCeremony(invitationDigest)
    let compared = try transcript(ceremony)
    let checkpoint = try V3ManifestCheckpoint(
      vaultID: vaultID,
      envelopeDigest: compared.invitation.parentManifestDigest)
    try requireCheckpoint(checkpoint)
    let envelope = try V3RecoveryManifestCodec().parseEnvelope(
      objects.readManifest(checkpoint.envelopeDigest))
    let policy = V3RecoveryDeviceEnrollmentValidator(limits: limits)
    _ = try policy.validateCeremony(
      ceremony, checkpoint: checkpoint, parent: envelope,
      expectedOwner: identity.publicIdentity, at: unixTime)
    _ = try policy.resultingDevices(
      parent: envelope.body.fields.devices,
      joining: compared.joinRequest.joiningDevice)
    let key = try session.load(vaultID: vaultID, keyID: envelope.body.fields.keyID)
    try V3RecoveryContentMutationValidator(limits: limits).validateParent(
      envelope, checkpoint: checkpoint, vaultKey: key)
    let source = try objects.observe(checkpoint: checkpoint, expectedBase: envelope.canonicalBytes)
    _ = try snapshots.plaintexts(
      fields: envelope.body.fields, entries: source.entries, vaultKey: key)
    try requireNoPending()
    try requireCheckpoint(checkpoint)
    try requireSameCeremony(ceremony, consumed: false)
    return .init(
      review: .init(checkpoint: checkpoint, transcript: compared), ceremony: ceremony,
      envelope: envelope, key: key, source: source)
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

  private func requireCommitted(
    _ envelope: V3RecoveryManifestEnvelope, ceremony: V3EnrollmentCeremonyState,
    vaultKey: Data, operationID: VaultTransactionOperationID,
    publisher: V3RecoveryDeviceEnrollmentPublisher
  ) throws {
    let checkpoint = try V3ManifestCheckpoint(vaultID: vaultID, envelopeDigest: envelope.digest)
    try requireNoAuthorityWork()
    try requireCheckpoint(checkpoint)
    try requireSameCeremony(ceremony, consumed: true)
    try V3RecoveryEpochBoundary().verifyCurrentAuthentication(envelope, vaultKey: vaultKey)
    let source = try objects.observe(checkpoint: checkpoint, expectedBase: envelope.canonicalBytes)
    _ = try snapshots.plaintexts(
      fields: envelope.body.fields, entries: source.entries, vaultKey: vaultKey)
    // Initial publication may leave exact committed cleanup pending. That is
    // not permission to install a session over a different local operation.
    let pending = try ownership.loadRecoveryAnchor(vaultID: vaultID)
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
    try requireNoAuthorityWork()
    try requireSameCeremony(ceremony, consumed: true)
    try requireCheckpoint(checkpoint)
    guard try ownership.loadRecoveryAnchor(vaultID: vaultID) == pending else {
      throw V3RecoveryValidationError.sourceChanged
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
    try requireNoAuthorityWork()
    try requireSameCeremony(ceremony, consumed: false)
    try requireCheckpoint(state.currentCheckpoint)
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
    for _ in 0..<16 {
      let key = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
      if try V3VaultKeyID.derive(vaultKey: key, vaultID: vaultID) != currentID { return key }
    }
    throw V3RecoveryDeviceEnrollmentError.invalidCandidate
  }
  private func requireCheckpoint(_ checkpoint: V3ManifestCheckpoint) throws {
    guard try checkpoints.loadCheckpoint(vaultID: vaultID) == checkpoint.canonicalBytes
    else { throw V3ImmutableTransactionError.expectedHeadsChanged }
  }
  private func requireNoAuthorityWork() throws {
    guard try registration.loadRecoveryAnchor(vaultID: vaultID) == nil,
      try adoption.loadRecoveryAnchor(vaultID: vaultID) == nil
    else { throw V3RecoveryContentPublicationError.otherMutationPending }
  }
  private func requireNoPending() throws {
    try requireNoAuthorityWork()
    if let bytes = try ownership.loadRecoveryAnchor(vaultID: vaultID) {
      guard bytes.count <= 1_024,
        let anchor = try? V3ImmutableTransactionRecoveryAnchor(canonicalBytes: bytes),
        anchor.vaultID == vaultID
      else { throw V3ImmutableTransactionRecoveryError.invalidRecoveryAnchor(vaultID: vaultID) }
      throw V3ImmutableTransactionRecoveryError.interruptedTransactionPending(
        operationID: anchor.operationID.rawValue)
    }
  }
  private func publisher(_ operationID: VaultTransactionOperationID)
    -> V3RecoveryDeviceEnrollmentPublisher
  {
    .init(
      mutationOwner: DirectVaultTransactionMutationOwner(operationID: operationID),
      objectStore: store, checkpointStore: checkpoints, recoveryAnchorStore: ownership,
      registrationAnchorStore: registration, adoptionAnchorStore: adoption,
      ceremonyStore: ceremonies,
      cache: cache, limits: limits, phaseObserver: phaseObserver)
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
