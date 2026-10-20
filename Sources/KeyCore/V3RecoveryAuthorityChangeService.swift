import CryptoKit
import Foundation

enum V3RecoveryAuthorityChangeError: Error, Equatable {
  case invalidOwner, invalidNextVaultKey
}

/// Internal execution of separately reviewed authority changes from an
/// unlocked session. The helper supplies serialization and the operation ID.
/// Device and recipient policies stay independent; only their shared session,
/// source and failure handling live here. No token or product routing is used.
struct V3RecoveryAuthorityChangeService: Sendable {
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

  init(
    vaultID: String, identity: Identity, session: V3DeviceWrappedVaultKeySessionStore,
    objectStore: any V3TransactionArtifactStore,
    checkpointStore: any V3ManifestCheckpointStoring,
    recoveryAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    registrationAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    adoptionAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
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
    self.cache = cache
    self.limits = limits
    self.phaseObserver = phaseObserver
  }

  /// Authenticated review only. Neither preparation saves consent, signs,
  /// generates an epoch, invokes hardware or reserves work.
  func prepareRevocation(revoking deviceID: String) throws -> V3DeviceWrappedRevocationPlan {
    let base = try loadCurrent()
    return try revocationPlan(base, deviceID: deviceID)
  }

  func prepareRemoval(removing recipientID: V3RecoveryRecipientID) throws
    -> V3RecoveryRecipientRemovalPlan
  {
    let base = try loadCurrent()
    return try removalPlan(base, recipientID: recipientID)
  }

  func revoke(
    _ plan: V3DeviceWrappedRevocationPlan, operationID: VaultTransactionOperationID
  ) throws -> V3RecoveryDeviceRevocationCommit {
    let committed = try change(
      checkpoint: plan.expectedCheckpoint, kind: .revokeDevice, operationID: operationID,
      review: { base in
        guard try revocationPlan(base, deviceID: plan.revokedDevice.identity.deviceID) == plan
        else {
          throw V3RecoveryDeviceRevocationError.invalidPlan
        }
      },
      publish: { base, nextKey in
        let candidate = try V3RecoveryDeviceRevocationBuilder(limits: limits).build(
          parent: base.envelope, currentEntries: base.source.entries, plan: plan,
          currentVaultKey: base.key, nextVaultKey: nextKey, owner: identity,
          reason: "Remove the reviewed Mac's access and change the vault's encryption key.")
        try requireUnchanged(base)
        let commit = try revocationPublisher(operationID).publish(
          candidate, approvedPlan: plan, currentVaultKey: base.key, nextVaultKey: nextKey,
          identity: identity, reason: "Verify this Mac can open the vault after removing access.")
        return .init(checkpoint: commit.checkpoint, envelope: commit.envelope)
      })
    return .init(checkpoint: committed.checkpoint, envelope: committed.envelope)
  }

  func remove(
    _ plan: V3RecoveryRecipientRemovalPlan, operationID: VaultTransactionOperationID,
    protectionLossAcknowledgement: V3RecoveryProtectionLossAcknowledgement? = nil
  ) throws -> V3RecoveryRecipientRemovalCommit {
    let committed = try change(
      checkpoint: plan.expectedCheckpoint, kind: .removeRecoveryRecipient, operationID: operationID,
      review: { base in
        guard try removalPlan(base, recipientID: plan.removedRecipient.recipientID) == plan else {
          throw V3RecoveryRecipientRemovalError.invalidPlan
        }
        try V3RecoveryProtectionLossAcknowledgement.validate(
          protectionLossAcknowledgement, for: plan)
      },
      publish: { base, nextKey in
        let candidate = try V3RecoveryRecipientRemovalBuilder(limits: limits).build(
          parent: base.envelope, currentEntries: base.source.entries, plan: plan,
          currentVaultKey: base.key, nextVaultKey: nextKey, owner: identity,
          reason: "Remove the reviewed recovery key and change the vault's encryption key.",
          protectionLossAcknowledgement: protectionLossAcknowledgement)
        try requireUnchanged(base)
        let commit = try removalPublisher(operationID).publish(
          candidate, approvedPlan: plan, currentVaultKey: base.key, nextVaultKey: nextKey,
          identity: identity,
          reason: "Verify this Mac can open the vault after removing the recovery key.",
          protectionLossAcknowledgement: protectionLossAcknowledgement)
        return .init(checkpoint: commit.checkpoint, envelope: commit.envelope)
      })
    return .init(checkpoint: committed.checkpoint, envelope: committed.envelope)
  }

  /// Exact locally owned work only. No new review, signing, key generation or
  /// token operation. The optional routed anchor prevents switching reservations.
  func recoverInterruptedRevocation(
    operationID: VaultTransactionOperationID, expectedAnchor: Data? = nil
  ) throws -> V3ImmutableTransactionRecoveryOutcome {
    try recover(.device, operationID: operationID, expectedAnchor: expectedAnchor)
  }

  func recoverInterruptedRemoval(
    operationID: VaultTransactionOperationID, expectedAnchor: Data? = nil
  ) throws -> V3ImmutableTransactionRecoveryOutcome {
    try recover(.recipient, operationID: operationID, expectedAnchor: expectedAnchor)
  }

  private enum PendingChange {
    case device, recipient
    var intentKind: VaultTransactionMutationKind {
      self == .device ? .revokeDevice : .removeRecoveryRecipient
    }
  }
  private struct RecoverySource {
    let envelope: V3RecoveryManifestEnvelope
    let parent: V3RecoveryManifestEnvelope?
    let source: V3ExactTransitionRepositoryState
  }

  private func recover(
    _ kind: PendingChange, operationID: VaultTransactionOperationID, expectedAnchor: Data?
  ) throws -> V3ImmutableTransactionRecoveryOutcome {
    do {
      guard identity.vaultID == vaultID else { throw V3RecoveryAuthorityChangeError.invalidOwner }
      let state: V3ContentTransactionRecoveryState
      switch try prepareRecovery(kind, operationID: operationID, expectedAnchor: expectedAnchor) {
      case .finished(let outcome):
        if case .abandoned = outcome { session.invalidate() }
        return outcome
      case .ready(let ready): state = ready
      }
      let checked = try preflightRecovery(state, kind: kind)
      let currentID = checked.parent?.body.fields.keyID ?? checked.envelope.body.fields.keyID
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
            reason: "Authenticate the current vault before resuming its interrupted access change.")
        try session.requireCurrent(ticket)
        try V3RecoveryContentMutationValidator(limits: limits).validateParent(
          parent, checkpoint: state.intent.expectedCheckpoint, vaultKey: key)
        _ = try V3EntrySnapshotValidator(limits: limits).plaintexts(
          fields: parent.body.fields, entries: checked.source.entries, vaultKey: key)
        oldKey = key
        try recheckRecovery(state, checked: checked, kind: kind, operationID: operationID)
        try session.requireCurrent(ticket)
      }
      let nextKey: Data
      if state.alreadyCommitted, let cached {
        nextKey = cached
      } else {
        nextKey = try openMacKey(
          checked.envelope,
          reason:
            "Open this Mac's exact pending vault-key wrapper to finish the interrupted access change."
        )
      }
      try session.requireCurrent(ticket)
      try recheckRecovery(state, checked: checked, kind: kind, operationID: operationID)
      try validateRecovery(state, kind: kind, oldKey: oldKey, nextKey: nextKey)
      try requireRecoveryState(state)
      let outcome: V3ImmutableTransactionRecoveryOutcome
      switch kind {
      case .device:
        outcome = try revocationPublisher(operationID).recoverInterruptedTransaction(
          vaultID: vaultID, currentVaultKey: oldKey, nextVaultKey: nextKey,
          expectedOwner: identity.publicIdentity, expectedAnchor: state.anchorData)
      case .recipient:
        outcome = try removalPublisher(operationID).recoverInterruptedTransaction(
          vaultID: vaultID, currentVaultKey: oldKey, nextVaultKey: nextKey,
          expectedOwner: identity.publicIdentity, expectedAnchor: state.anchorData)
      }
      switch outcome {
      case .completed, .alreadyCompleted:
        try requireNoPending()
        try requireCheckpoint(state.candidateCheckpoint)
        try V3RecoveryEpochBoundary().verifyCurrentAuthentication(
          checked.envelope, vaultKey: nextKey)
        let source = try objects.observe(
          checkpoint: state.candidateCheckpoint, expectedBase: checked.envelope.canonicalBytes)
        _ = try V3EntrySnapshotValidator(limits: limits).plaintexts(
          fields: checked.envelope.body.fields, entries: source.entries, vaultKey: nextKey)
        try requireNoPending()
        try requireCheckpoint(state.candidateCheckpoint)
        try session.install(
          nextKey, vaultID: vaultID, keyID: checked.envelope.body.fields.keyID,
          authenticationTicket: ticket)
      case .nothingToRecover, .abandoned: session.invalidate()
      }
      return outcome
    } catch {
      session.invalidate()
      throw error
    }
  }

  private func prepareRecovery(
    _ kind: PendingChange, operationID: VaultTransactionOperationID, expectedAnchor: Data?
  ) throws -> V3ContentTransactionRecoveryPreparation {
    switch kind {
    case .device:
      return try revocationPublisher(operationID).prepareInterruptedTransaction(
        vaultID: vaultID, expectedOwner: identity.publicIdentity, expectedAnchor: expectedAnchor)
    case .recipient:
      return try removalPublisher(operationID).prepareInterruptedTransaction(
        vaultID: vaultID, expectedOwner: identity.publicIdentity, expectedAnchor: expectedAnchor)
    }
  }

  private func input(_ state: V3ContentTransactionRecoveryState) -> V3ContentTransactionInput {
    .init(
      kind: state.intent.kind, expectedCheckpoint: state.intent.expectedCheckpoint,
      manifestData: state.manifestData, manifestDigest: state.intent.candidateManifestDigest,
      stagedEntries: state.availableEntries)
  }

  private func preflightRecovery(_ state: V3ContentTransactionRecoveryState, kind: PendingChange)
    throws -> RecoverySource
  {
    try requireRecoveryState(state)
    let envelope = try V3RecoveryManifestCodec().parseEnvelope(state.manifestData)
    guard state.intent.kind == kind.intentKind, envelope.body.fields.vaultID == vaultID,
      envelope.parents == [state.intent.expectedCheckpoint.envelopeDigest],
      envelope.authorizations.map(\.signerDeviceID) == [identity.publicIdentity.deviceID],
      envelope.body.fields.devices.contains(
        .init(identity: identity.publicIdentity, status: .active))
    else { throw V3RecoveryAuthorityChangeError.invalidOwner }
    let staged = try V3EntrySnapshotValidator(limits: limits).entryMap(state.availableEntries)
    let addresses = try envelope.body.fields.entries.map {
      try V3RecoveryMergeMutationValidator.address($0)
    }
    guard Set(addresses) == Set(staged.keys) else { throw V3RecoveryValidationError.sourceChanged }
    for (record, address) in zip(envelope.body.fields.entries, addresses) {
      guard
        staged[address]?.context
          == (try V3EntryAuthenticationContext(vaultID: vaultID, entry: record))
      else { throw V3RecoveryValidationError.sourceChanged }
    }
    let parent: V3RecoveryManifestEnvelope?
    let source: V3ExactTransitionRepositoryState
    if state.alreadyCommitted {
      parent = nil
      source = try objects.observe(
        checkpoint: state.candidateCheckpoint, expectedBase: state.manifestData)
      guard staged == source.entries else { throw V3RecoveryValidationError.sourceChanged }
    } else {
      let before = try V3RecoveryManifestCodec().parseEnvelope(
        objects.readManifest(state.intent.expectedCheckpoint.envelopeDigest))
      switch kind {
      case .device:
        let plan = try revocationValidator(oldKey: nil).reconstructPublicPlan(
          input(state), envelope: envelope, parent: before)
        try V3RecoveryDeviceRevocationValidator(limits: limits).preflightPublic(
          .init(plan: plan, envelope: envelope, stagedEntries: state.availableEntries),
          parent: before, expectedOwner: identity.publicIdentity)
      case .recipient:
        let plan = try removalValidator(oldKey: nil).reconstructPublicPlan(
          input(state), envelope: envelope, parent: before)
        try V3RecoveryRecipientRemovalValidator(limits: limits).preflightPublic(
          .init(plan: plan, envelope: envelope, stagedEntries: state.availableEntries),
          parent: before, expectedOwner: identity.publicIdentity)
      }
      parent = before
      source = try objects.observe(
        checkpoint: state.intent.expectedCheckpoint,
        expectedBase: before.canonicalBytes, candidate: envelope,
        stagedEntries: state.availableEntries)
      try objects.requireProjectedUsage(
        source, candidate: envelope, stagedEntries: state.availableEntries)
    }
    try requireRecoveryState(state)
    return .init(envelope: envelope, parent: parent, source: source)
  }

  private func recheckRecovery(
    _ state: V3ContentTransactionRecoveryState, checked: RecoverySource, kind: PendingChange,
    operationID: VaultTransactionOperationID
  ) throws {
    try requireRecoveryState(state)
    guard
      case .ready(let fresh) = try prepareRecovery(
        kind, operationID: operationID, expectedAnchor: state.anchorData),
      fresh.intent == state.intent, fresh.currentCheckpoint == state.currentCheckpoint,
      fresh.manifestData == state.manifestData, fresh.availableEntries == state.availableEntries
    else { throw V3RecoveryValidationError.sourceChanged }
    let observed = try preflightRecovery(fresh, kind: kind)
    try objects.requireUnchangedSource(
      checked.source, observed.source, candidateDigest: state.intent.candidateManifestDigest)
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
      let wrapped = envelope.body.fields.wrappedKeys.first(where: {
        $0.recipientDeviceID == identity.publicIdentity.deviceID
      })
    else { throw V3RecoveryKeyRotationError.localWrapperMismatch }
    let key = try identity.unwrapDeviceWrappedVaultKey(
      wrapped.wrappedKey,
      context: envelope.body.deviceContext(recipientDeviceID: identity.publicIdentity.deviceID),
      reason: reason)
    try V3RecoveryEpochBoundary().verifyCurrentAuthentication(envelope, vaultKey: key)
    return key
  }
  private func validateRecovery(
    _ state: V3ContentTransactionRecoveryState, kind: PendingChange,
    oldKey: Data?, nextKey: Data
  ) throws {
    switch kind {
    case .device:
      _ = try revocationValidator(oldKey: oldKey).validate(
        input(state), vaultKey: nextKey, alreadyCommitted: state.alreadyCommitted)
    case .recipient:
      _ = try removalValidator(oldKey: oldKey).validate(
        input(state), vaultKey: nextKey, alreadyCommitted: state.alreadyCommitted)
    }
  }
  private func revocationValidator(oldKey: Data?) -> V3RecoveryDeviceRevocationTransactionValidator
  {
    .init(
      objectStore: store, registrationAnchorStore: registration, adoptionAnchorStore: adoption,
      currentVaultKey: oldKey, expectedOwner: identity.publicIdentity, approvedPlan: nil,
      limits: limits)
  }
  private func removalValidator(oldKey: Data?) -> V3RecoveryRecipientRemovalTransactionValidator {
    .init(
      objectStore: store, registrationAnchorStore: registration, adoptionAnchorStore: adoption,
      currentVaultKey: oldKey, expectedOwner: identity.publicIdentity, approvedPlan: nil,
      protectionLossAcknowledgement: nil, limits: limits)
  }
  private func revocationPublisher(_ operationID: VaultTransactionOperationID)
    -> V3RecoveryDeviceRevocationPublisher
  {
    .init(
      mutationOwner: DirectVaultTransactionMutationOwner(operationID: operationID),
      objectStore: store, checkpointStore: checkpoints, recoveryAnchorStore: ownership,
      registrationAnchorStore: registration, adoptionAnchorStore: adoption, cache: cache,
      limits: limits, phaseObserver: phaseObserver)
  }
  private func removalPublisher(_ operationID: VaultTransactionOperationID)
    -> V3RecoveryRecipientRemovalPublisher
  {
    .init(
      mutationOwner: DirectVaultTransactionMutationOwner(operationID: operationID),
      objectStore: store, checkpointStore: checkpoints, recoveryAnchorStore: ownership,
      registrationAnchorStore: registration, adoptionAnchorStore: adoption, cache: cache,
      limits: limits, phaseObserver: phaseObserver)
  }

  private struct CommittedEpoch {
    let checkpoint: V3ManifestCheckpoint
    let envelope: V3RecoveryManifestEnvelope
  }
  private struct Base {
    let checkpoint: V3ManifestCheckpoint
    let envelope: V3RecoveryManifestEnvelope
    let key: Data
    let source: V3ExactTransitionRepositoryState
    let ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket
  }
  private var objects: V3ExactTransitionRepository { .init(source: store, limits: limits) }

  private func change(
    checkpoint: V3ManifestCheckpoint, kind: VaultTransactionMutationKind,
    operationID: VaultTransactionOperationID, review: (Base) throws -> Void,
    publish: (Base, Data) throws -> CommittedEpoch
  ) throws -> CommittedEpoch {
    do {
      guard checkpoint.vaultID == vaultID else { throw V3RecoveryAuthorityChangeError.invalidOwner }
      try requireCheckpoint(checkpoint)
      let base = try loadCurrent()
      guard base.checkpoint == checkpoint else {
        throw V3ImmutableTransactionError.expectedHeadsChanged
      }
      // Acknowledgment and independent plan comparison precede random-key
      // generation, signing and publication. This is not restart dispatch.
      try review(base)
      let nextKey = try freshKey(excluding: base.envelope.body.fields.keyID)
      let committed = try publish(base, nextKey)
      try requireCommittedState(
        committed, previous: checkpoint, kind: kind, operationID: operationID)
      try V3RecoveryEpochBoundary().verifyCurrentAuthentication(
        committed.envelope, vaultKey: nextKey)
      let current = try objects.observe(
        checkpoint: committed.checkpoint, expectedBase: committed.envelope.canonicalBytes)
      _ = try V3EntrySnapshotValidator(limits: limits).plaintexts(
        fields: committed.envelope.body.fields, entries: current.entries, vaultKey: nextKey)
      try requireCommittedState(
        committed, previous: checkpoint, kind: kind, operationID: operationID)
      // The ticket also rejects lock followed by reinstallation of the same old
      // key during native UI. A key-ID-only replacement cannot distinguish that.
      try session.install(
        nextKey, vaultID: vaultID, keyID: committed.envelope.body.fields.keyID,
        authenticationTicket: base.ticket)
      return committed
    } catch {
      // An error does not imply rollback. Keep the old session only while its
      // reviewed checkpoint is exact; never erase pending work in an error path.
      if (try? checkpoints.loadCheckpoint(vaultID: vaultID)) != checkpoint.canonicalBytes {
        session.invalidate()
      }
      throw error
    }
  }

  private func loadCurrent() throws -> Base {
    try requireNoPending()
    guard isValidV3UUID(vaultID), identity.vaultID == vaultID,
      let bytes = try checkpoints.loadCheckpoint(vaultID: vaultID), bytes.count <= 1_024,
      let checkpoint = try? V3ManifestCheckpoint(canonicalBytes: bytes),
      checkpoint.vaultID == vaultID
    else { throw V3RecoveryAuthorityChangeError.invalidOwner }
    let manifest = try objects.readManifest(checkpoint.envelopeDigest)
    let envelope = try V3RecoveryManifestCodec().parseEnvelope(manifest)
    guard
      envelope.body.fields.devices.contains(
        .init(identity: identity.publicIdentity, status: .active))
    else { throw V3RecoveryAuthorityChangeError.invalidOwner }
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
      checkpoint: checkpoint, envelope: envelope, key: key, source: source, ticket: ticket)
  }

  private func revocationPlan(_ base: Base, deviceID: String) throws
    -> V3DeviceWrappedRevocationPlan
  {
    try V3RecoveryDeviceRevocationPlanner(limits: limits).plan(
      checkpoint: base.checkpoint, parent: base.envelope, currentVaultKey: base.key,
      authorizingDeviceID: identity.publicIdentity.deviceID, revoking: deviceID)
  }
  private func removalPlan(_ base: Base, recipientID: V3RecoveryRecipientID) throws
    -> V3RecoveryRecipientRemovalPlan
  {
    try V3RecoveryRecipientRemovalPlanner(limits: limits).plan(
      checkpoint: base.checkpoint, parent: base.envelope, currentVaultKey: base.key,
      authorizingDeviceID: identity.publicIdentity.deviceID, removing: recipientID)
  }
  private func requireUnchanged(_ base: Base) throws {
    try requireNoPending()
    try requireCheckpoint(base.checkpoint)
    guard
      try objects.observe(checkpoint: base.checkpoint, expectedBase: base.envelope.canonicalBytes)
        == base.source
    else { throw V3RecoveryValidationError.sourceChanged }
    try session.requireCurrent(base.ticket)
    guard try session.load(vaultID: vaultID, keyID: base.envelope.body.fields.keyID) == base.key
    else {
      throw V3RecoveryValidationError.sourceChanged
    }
  }
  private func requireCommittedState(
    _ commit: CommittedEpoch, previous: V3ManifestCheckpoint, kind: VaultTransactionMutationKind,
    operationID: VaultTransactionOperationID
  ) throws {
    try requireNoAuthorityWork()
    try requireCheckpoint(commit.checkpoint)
    if let bytes = try ownership.loadRecoveryAnchor(vaultID: vaultID) {
      // Best-effort cleanup may leave this exact committed operation pending.
      // It must not admit another operation or malformed replacement ownership.
      guard bytes.count <= 1_024,
        let anchor = try? V3ImmutableTransactionRecoveryAnchor(canonicalBytes: bytes),
        anchor.vaultID == vaultID, anchor.operationID == operationID, anchor.phase == .recoverable,
        case .available(let data) = try store.readRecoveryIntent(
          operationID: operationID, maximumBytes: V3ImmutableTransactionRecoveryIntent.maximumBytes),
        Data(SHA256.hash(data: data)) == anchor.intentDigest,
        let intent = try? V3ImmutableTransactionRecoveryIntent(canonicalBytes: data),
        intent.operationID == operationID, intent.vaultID == vaultID, intent.kind == kind,
        intent.expectedCheckpoint == previous, intent.expectedHeads == [previous.envelopeDigest],
        intent.candidateManifestDigest == commit.envelope.digest,
        intent.enrollmentTranscriptDigest == nil, intent.recoveryMergeResolutions == nil
      else { throw V3ImmutableTransactionRecoveryError.invalidRecoveryAnchor(vaultID: vaultID) }
    }
  }
  private func freshKey(excluding current: V3VaultKeyID) throws -> Data {
    for _ in 0..<16 {
      let key = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
      if try V3VaultKeyID.derive(vaultKey: key, vaultID: vaultID) != current { return key }
    }
    throw V3RecoveryAuthorityChangeError.invalidNextVaultKey
  }
  private func requireCheckpoint(_ checkpoint: V3ManifestCheckpoint) throws {
    guard try checkpoints.loadCheckpoint(vaultID: vaultID) == checkpoint.canonicalBytes else {
      throw V3ImmutableTransactionError.expectedHeadsChanged
    }
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
}
