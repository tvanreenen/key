import CryptoKit
import Foundation

/// Internal, explicitly requested unchanged-roster rotation from an unlocked
/// session. The helper owns serialization and supplies one operation ID. This
/// service never provisions a token, opens a recovery credential or resumes a
/// different pending operation. Restart uses only an exact locally pinned rotation.
struct V3RecoveryKeyRotationService: Sendable {
  typealias Identity = any V3EnrollmentMessageSigning & V3DeviceWrappedVaultKeyUnwrapping

  private let vaultID: String
  private let identity: Identity
  private let session: V3DeviceWrappedVaultKeySessionStore
  private let store: any V3TransactionArtifactStore
  private let checkpoints: any V3ManifestCheckpointStoring
  private let ownership: any V3ImmutableTransactionRecoveryAnchorStoring
  private let registration: any V3ImmutableTransactionRecoveryAnchorStoring
  private let adoption: any V3ImmutableTransactionRecoveryAnchorStoring
  private let cache: any V3CheckpointManifestCaching
  private let limits: V3ManifestRepositoryLimits
  private let phaseObserver: any V3ImmutableTransactionPhaseObserving
  private let validateScope: @Sendable () throws -> Void

  init(
    vaultID: String, identity: Identity, session: V3DeviceWrappedVaultKeySessionStore,
    objectStore: any V3TransactionArtifactStore,
    checkpointStore: any V3ManifestCheckpointStoring,
    recoveryAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    registrationAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    adoptionAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
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
    self.cache = cache
    self.limits = limits
    self.phaseObserver = phaseObserver
    self.validateScope = validateScope
  }

  /// Authenticated review data only. This neither saves approval nor signs,
  /// generates a key or reserves durable work. Execution rechecks the checkpoint.
  func prepare() throws -> V3RecoveryKeyRotationCommit {
    try loadCurrent().commit
  }

  /// Resume exact ciphertext without signing or generating another epoch. Public
  /// preflight precedes each native operation; actual authority and both complete
  /// snapshots still authenticate before an uncommitted checkpoint can advance.
  func recoverInterruptedRotation(
    operationID: VaultTransactionOperationID, expectedAnchor: Data? = nil
  ) throws
    -> V3ImmutableTransactionRecoveryOutcome
  {
    do {
      guard identity.vaultID == vaultID else { throw V3RecoveryKeyRotationError.invalidOwner }
      let publisher = publisher(operationID)
      let state: V3ContentTransactionRecoveryState
      switch try publisher.prepareInterruptedTransaction(
        vaultID: vaultID, expectedOwner: identity.publicIdentity, expectedAnchor: expectedAnchor)
      {
      case .finished(let outcome):
        if case .abandoned = outcome { session.invalidate() }
        return outcome
      case .ready(let ready): state = ready
      }
      let checked = try preflightRecovery(state)
      let currentID =
        checked.parent?.body.fields.keyID ?? checked.candidate.envelope.body.fields.keyID
      let ticket = session.beginAuthentication()
      let cached =
        session.hasResidentKey ? try? session.load(vaultID: vaultID, keyID: currentID) : nil
      try session.requireCurrent(ticket)
      try requireRecoveryState(state)
      var oldKey: Data?
      if let parent = checked.parent {
        let key =
          try cached
          ?? openMacKey(
            parent,
            reason: "Authenticate the current vault before resuming its interrupted key change.")
        try V3RecoveryKeyRotationValidator(limits: limits).preflight(
          checked.candidate, parent: parent, currentVaultKey: key,
          expectedOwner: identity.publicIdentity)
        _ = try V3EntrySnapshotValidator(limits: limits).plaintexts(
          fields: parent.body.fields, entries: checked.source.entries, vaultKey: key)
        oldKey = key
        try recheckRecovery(state, checked: checked, publisher: publisher)
        try session.requireCurrent(ticket)
      }
      let nextKey: Data
      if state.alreadyCommitted, let cached {
        nextKey = cached
      } else {
        nextKey = try openMacKey(
          checked.candidate.envelope,
          reason:
            "Open this Mac's exact pending vault-key wrapper to finish the interrupted key change.")
      }
      try session.requireCurrent(ticket)
      try recheckRecovery(state, checked: checked, publisher: publisher)
      let validator = V3RecoveryKeyRotationTransactionValidator(
        objectStore: store, registrationAnchorStore: registration, adoptionAnchorStore: adoption,
        currentVaultKey: oldKey, expectedOwner: identity.publicIdentity, limits: limits,
        validateScope: validateScope)
      _ = try validator.validate(
        input(state), vaultKey: nextKey, alreadyCommitted: state.alreadyCommitted)
      try requireRecoveryState(state)
      let outcome = try publisher.recoverInterruptedTransaction(
        vaultID: vaultID, currentVaultKey: oldKey, nextVaultKey: nextKey,
        expectedOwner: identity.publicIdentity, expectedAnchor: state.anchorData)
      switch outcome {
      case .completed, .alreadyCompleted:
        try requireNoPending()
        try requireCheckpoint(state.candidateCheckpoint)
        let envelope = checked.candidate.envelope
        try V3RecoveryEpochBoundary().verifyCurrentAuthentication(envelope, vaultKey: nextKey)
        let current = try objects.observe(
          checkpoint: state.candidateCheckpoint, expectedBase: envelope.canonicalBytes)
        _ = try V3EntrySnapshotValidator(limits: limits).plaintexts(
          fields: envelope.body.fields, entries: current.entries, vaultKey: nextKey)
        try requireNoPending()
        try requireCheckpoint(state.candidateCheckpoint)
        try session.install(
          nextKey, vaultID: vaultID, keyID: envelope.body.fields.keyID,
          authenticationTicket: ticket)
      case .nothingToRecover, .abandoned:
        session.invalidate()
      }
      return outcome
    } catch {
      session.invalidate()
      throw error
    }
  }

  private struct RecoverySource {
    let candidate: V3RecoveryKeyRotationCandidate
    let parent: V3RecoveryManifestEnvelope?
    let source: V3ExactTransitionRepositoryState
  }

  private func input(_ state: V3ContentTransactionRecoveryState) -> V3ContentTransactionInput {
    .init(
      kind: state.intent.kind, expectedCheckpoint: state.intent.expectedCheckpoint,
      manifestData: state.manifestData, manifestDigest: state.intent.candidateManifestDigest,
      stagedEntries: state.availableEntries)
  }

  private func preflightRecovery(_ state: V3ContentTransactionRecoveryState) throws
    -> RecoverySource
  {
    try requireRecoveryState(state)
    let envelope = try V3RecoveryManifestCodec().parseEnvelope(state.manifestData)
    guard envelope.body.fields.vaultID == vaultID,
      envelope.parents == [state.intent.expectedCheckpoint.envelopeDigest],
      envelope.authorizations.map(\.signerDeviceID) == [identity.publicIdentity.deviceID],
      envelope.body.fields.devices.contains(
        .init(identity: identity.publicIdentity, status: .active))
    else { throw V3RecoveryKeyRotationError.invalidOwner }
    let staged = try V3EntrySnapshotValidator(limits: limits).entryMap(state.availableEntries)
    let addresses = try envelope.body.fields.entries.map {
      try V3RecoveryMergeMutationValidator.address($0)
    }
    guard Set(addresses) == Set(staged.keys) else {
      throw V3RecoveryKeyRotationError.invalidCandidate
    }
    for (record, address) in zip(envelope.body.fields.entries, addresses) {
      guard
        staged[address]?.context
          == (try V3EntryAuthenticationContext(vaultID: vaultID, entry: record))
      else { throw V3RecoveryKeyRotationError.invalidCandidate }
    }
    let candidate = V3RecoveryKeyRotationCandidate(
      expectedCheckpoint: state.intent.expectedCheckpoint,
      envelope: envelope, stagedEntries: state.availableEntries)
    let parent: V3RecoveryManifestEnvelope?
    let source: V3ExactTransitionRepositoryState
    if state.alreadyCommitted {
      parent = nil
      source = try objects.observe(
        checkpoint: state.candidateCheckpoint, expectedBase: state.manifestData)
      guard staged == source.entries else { throw V3RecoveryKeyRotationError.invalidCandidate }
    } else {
      let before = try V3RecoveryManifestCodec().parseEnvelope(
        objects.readManifest(state.intent.expectedCheckpoint.envelopeDigest))
      try V3RecoveryKeyRotationValidator(limits: limits).preflightPublic(
        candidate, parent: before, expectedOwner: identity.publicIdentity)
      parent = before
      source = try objects.observe(
        checkpoint: state.intent.expectedCheckpoint,
        expectedBase: before.canonicalBytes, candidate: envelope,
        stagedEntries: state.availableEntries)
      try objects.requireProjectedUsage(
        source, candidate: envelope, stagedEntries: state.availableEntries)
    }
    try requireRecoveryState(state)
    return .init(candidate: candidate, parent: parent, source: source)
  }

  private func recheckRecovery(
    _ state: V3ContentTransactionRecoveryState,
    checked: RecoverySource, publisher: V3RecoveryKeyRotationPublisher
  ) throws {
    try requireRecoveryState(state)
    guard
      case .ready(let fresh) = try publisher.prepareInterruptedTransaction(
        vaultID: vaultID, expectedOwner: identity.publicIdentity, expectedAnchor: state.anchorData),
      fresh.intent == state.intent, fresh.currentCheckpoint == state.currentCheckpoint,
      fresh.manifestData == state.manifestData, fresh.availableEntries == state.availableEntries
    else { throw V3RecoveryValidationError.sourceChanged }
    let observed = try preflightRecovery(fresh)
    try objects.requireUnchangedSource(
      checked.source, observed.source,
      candidateDigest: state.intent.candidateManifestDigest)
  }

  private func requireRecoveryState(_ state: V3ContentTransactionRecoveryState) throws {
    try requireNoAuthorityWork()
    try requireCheckpoint(state.currentCheckpoint)
    guard try ownership.loadRecoveryAnchor(vaultID: vaultID) == state.anchorData else {
      throw V3ImmutableTransactionRecoveryError.invalidRecoveryAnchor(vaultID: vaultID)
    }
  }

  private func openMacKey(_ envelope: V3RecoveryManifestEnvelope, reason: String) throws -> Data {
    guard
      let wrapper = envelope.body.fields.wrappedKeys.first(where: {
        $0.recipientDeviceID == identity.publicIdentity.deviceID
      })
    else { throw V3RecoveryKeyRotationError.localWrapperMismatch }
    let key = try identity.unwrapDeviceWrappedVaultKey(
      wrapper.wrappedKey,
      context: envelope.body.deviceContext(recipientDeviceID: identity.publicIdentity.deviceID),
      reason: reason)
    try V3RecoveryEpochBoundary().verifyCurrentAuthentication(envelope, vaultKey: key)
    return key
  }

  private func publisher(_ operationID: VaultTransactionOperationID)
    -> V3RecoveryKeyRotationPublisher
  {
    .init(
      mutationOwner: DirectVaultTransactionMutationOwner(operationID: operationID),
      objectStore: store, checkpointStore: checkpoints, recoveryAnchorStore: ownership,
      registrationAnchorStore: registration, adoptionAnchorStore: adoption, cache: cache,
      limits: limits, phaseObserver: phaseObserver, validateScope: validateScope)
  }

  func rotate(
    expectedCheckpoint: V3ManifestCheckpoint, operationID: VaultTransactionOperationID
  ) throws -> V3RecoveryKeyRotationCommit {
    do {
      guard expectedCheckpoint.vaultID == vaultID else {
        throw V3RecoveryKeyRotationError.invalidCandidate
      }
      try requireCheckpoint(expectedCheckpoint)
      let base = try loadCurrent()
      guard base.commit.checkpoint == expectedCheckpoint else {
        throw V3ImmutableTransactionError.expectedHeadsChanged
      }
      let nextKey = try freshKey(excluding: base.commit.envelope.body.fields.keyID)
      let candidate = try V3RecoveryKeyRotationBuilder(limits: limits).build(
        checkpoint: expectedCheckpoint, parent: base.commit.envelope,
        currentEntries: base.source.entries, currentVaultKey: base.key, nextVaultKey: nextKey,
        owner: identity, reason: "Change the vault's encryption key without changing access.")
      // A signer may present authentication UI. Recheck before another private
      // operation, and do not continue from a session locked during that UI.
      try requireNoPending()
      try requireCheckpoint(expectedCheckpoint)
      let fresh = try objects.observe(
        checkpoint: expectedCheckpoint, expectedBase: base.commit.envelope.canonicalBytes)
      try session.requireCurrent(base.ticket)
      guard fresh == base.source,
        try session.load(vaultID: vaultID, keyID: base.commit.envelope.body.fields.keyID)
          == base.key
      else { throw V3RecoveryValidationError.sourceChanged }

      let commit = try publisher(operationID).publish(
        candidate, currentVaultKey: base.key, nextVaultKey: nextKey, identity: identity,
        reason: "Verify this Mac can open the changed vault encryption key.")

      try requireCommittedState(commit, previous: expectedCheckpoint, operationID: operationID)
      try V3RecoveryEpochBoundary().verifyCurrentAuthentication(commit.envelope, vaultKey: nextKey)
      let current = try objects.observe(
        checkpoint: commit.checkpoint, expectedBase: commit.envelope.canonicalBytes)
      _ = try V3EntrySnapshotValidator(limits: limits).plaintexts(
        fields: commit.envelope.body.fields, entries: current.entries, vaultKey: nextKey)
      try requireCommittedState(commit, previous: expectedCheckpoint, operationID: operationID)
      try session.install(
        nextKey, vaultID: vaultID, keyID: commit.envelope.body.fields.keyID,
        authenticationTicket: base.ticket)
      return commit
    } catch {
      // Failure is not proof that commitment failed. Retain the old session only
      // if its reviewed checkpoint is still exact. Never install from an error
      // path or erase durable intent here; restart reconciliation owns that work.
      if (try? checkpoints.loadCheckpoint(vaultID: vaultID)) != expectedCheckpoint.canonicalBytes {
        session.invalidate()
      }
      throw error
    }
  }

  private struct Base {
    let commit: V3RecoveryKeyRotationCommit
    let key: Data
    let source: V3ExactTransitionRepositoryState
    let ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket
  }
  private var objects: V3ExactTransitionRepository { .init(source: store, limits: limits) }

  private func loadCurrent() throws -> Base {
    try requireNoPending()
    guard isValidV3UUID(vaultID), identity.vaultID == vaultID,
      let bytes = try checkpoints.loadCheckpoint(vaultID: vaultID), bytes.count <= 1_024,
      let checkpoint = try? V3ManifestCheckpoint(canonicalBytes: bytes),
      checkpoint.vaultID == vaultID
    else { throw V3RecoveryKeyRotationError.invalidOwner }
    let manifest = try objects.readManifest(checkpoint.envelopeDigest)
    let envelope = try V3RecoveryManifestCodec().parseEnvelope(manifest)
    guard
      envelope.body.fields.devices.contains(
        .init(identity: identity.publicIdentity, status: .active))
    else { throw V3RecoveryKeyRotationError.invalidOwner }
    let ticket = session.beginAuthentication()
    let key = try session.load(vaultID: vaultID, keyID: envelope.body.fields.keyID)
    try V3RecoveryContentMutationValidator(limits: limits).validateParent(
      envelope, checkpoint: checkpoint, vaultKey: key)
    let source = try objects.observe(checkpoint: checkpoint, expectedBase: manifest)
    _ = try V3EntrySnapshotValidator(limits: limits).plaintexts(
      fields: envelope.body.fields, entries: source.entries, vaultKey: key)
    try requireNoPending()
    try requireCheckpoint(checkpoint)
    try session.requireCurrent(ticket)
    return .init(
      commit: .init(checkpoint: checkpoint, envelope: envelope), key: key, source: source,
      ticket: ticket)
  }

  private func requireCommittedState(
    _ commit: V3RecoveryKeyRotationCommit, previous: V3ManifestCheckpoint,
    operationID: VaultTransactionOperationID
  ) throws {
    try requireNoAuthorityWork()
    try requireCheckpoint(commit.checkpoint)
    if let bytes = try ownership.loadRecoveryAnchor(vaultID: vaultID) {
      // Best-effort cleanup may retain only this exact committed rotation.
      guard bytes.count <= 1_024,
        let anchor = try? V3ImmutableTransactionRecoveryAnchor(canonicalBytes: bytes),
        anchor.vaultID == vaultID, anchor.operationID == operationID, anchor.phase == .recoverable,
        case .available(let data) = try store.readRecoveryIntent(
          operationID: operationID, maximumBytes: V3ImmutableTransactionRecoveryIntent.maximumBytes),
        Data(SHA256.hash(data: data)) == anchor.intentDigest,
        let intent = try? V3ImmutableTransactionRecoveryIntent(canonicalBytes: data),
        intent.operationID == operationID, intent.vaultID == vaultID,
        intent.kind == .rotateVaultKey,
        intent.expectedCheckpoint == previous, intent.expectedHeads == [previous.envelopeDigest],
        intent.candidateManifestDigest == commit.envelope.digest,
        intent.enrollmentTranscriptDigest == nil, intent.recoveryMergeResolutions == nil
      else { throw V3ImmutableTransactionRecoveryError.invalidRecoveryAnchor(vaultID: vaultID) }
    }
  }

  private func freshKey(excluding currentID: V3VaultKeyID) throws -> Data {
    for _ in 0..<16 {
      let key = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
      if try V3VaultKeyID.derive(vaultKey: key, vaultID: vaultID) != currentID { return key }
    }
    throw V3RecoveryKeyRotationError.invalidCandidate
  }
  private func requireCheckpoint(_ checkpoint: V3ManifestCheckpoint) throws {
    try validateScope()
    guard try checkpoints.loadCheckpoint(vaultID: vaultID) == checkpoint.canonicalBytes else {
      throw V3ImmutableTransactionError.expectedHeadsChanged
    }
  }
  private func requireNoAuthorityWork() throws {
    try validateScope()
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
      else {
        throw V3ImmutableTransactionRecoveryError.invalidRecoveryAnchor(vaultID: vaultID)
      }
      throw V3ImmutableTransactionRecoveryError.interruptedTransactionPending(
        operationID: anchor.operationID.rawValue)
    }
  }
}
