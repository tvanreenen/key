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

  /// Authenticated review only. Neither preparation saves consent, signs,
  /// generates an epoch, invokes hardware or reserves work.
  func prepareRevocation(
    revoking deviceID: String,
    continuing ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket? = nil
  ) throws -> V3DeviceWrappedRevocationPlan {
    let base = try loadCurrent(continuing: ticket)
    return try revocationPlan(base, deviceID: deviceID)
  }

  func prepareRemoval(
    removing recipientID: V3RecoveryRecipientID,
    continuing ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket? = nil
  ) throws -> V3RecoveryRecipientRemovalPlan {
    let base = try loadCurrent(continuing: ticket)
    return try removalPlan(base, recipientID: recipientID)
  }

  func revoke(
    _ plan: V3DeviceWrappedRevocationPlan, operationID: VaultTransactionOperationID,
    continuing ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket? = nil
  ) throws -> V3RecoveryDeviceRevocationCommit {
    let committed = try change(
      checkpoint: plan.expectedCheckpoint, kind: .revokeDevice, operationID: operationID,
      continuing: ticket,
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
        try lifecycle.revalidate(base)
        let commit = try revocationPublisher(operationID, continuing: base.ticket).publish(
          candidate, approvedPlan: plan, currentVaultKey: base.key, nextVaultKey: nextKey,
          identity: identity, reason: "Verify this Mac can open the vault after removing access.")
        return .init(checkpoint: commit.checkpoint, envelope: commit.envelope)
      })
    return .init(checkpoint: committed.checkpoint, envelope: committed.envelope)
  }

  func remove(
    _ plan: V3RecoveryRecipientRemovalPlan, operationID: VaultTransactionOperationID,
    protectionLossAcknowledgement: V3RecoveryProtectionLossAcknowledgement? = nil,
    continuing ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket? = nil
  ) throws -> V3RecoveryRecipientRemovalCommit {
    let committed = try change(
      checkpoint: plan.expectedCheckpoint, kind: .removeRecoveryRecipient, operationID: operationID,
      continuing: ticket,
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
        try lifecycle.revalidate(base)
        let commit = try removalPublisher(operationID, continuing: base.ticket).publish(
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

  struct PendingRevocation: Sendable {
    let plan: V3DeviceWrappedRevocationPlan
    let anchor: Data
    let checkpoint: V3ManifestCheckpoint
  }

  /// Public preflight of exact locally owned work, so the product can compare
  /// its review token before requesting a Mac private operation. No new grant.
  func pendingRevocation(operationID: VaultTransactionOperationID) throws -> PendingRevocation? {
    try validateScope()
    switch try prepareRecovery(.device, operationID: operationID, expectedAnchor: nil) {
    case .finished(.nothingToRecover): return nil
    case .finished:
      throw AppError.operationRefused(
        "The incomplete access change was released without publication. Review the device list again before a new attempt."
      )
    case .ready(let state):
      let checked = try preflightRecovery(state, kind: .device)
      let parent = try V3RecoveryManifestCodec().parseEnvelope(
        objects.readManifest(state.intent.expectedCheckpoint.envelopeDigest))
      let plan = try revocationValidator(oldKey: nil).reconstructPublicPlan(
        input(state), envelope: checked.envelope, parent: parent)
      try V3RecoveryDeviceRevocationValidator(limits: limits).preflightPublic(
        .init(plan: plan, envelope: checked.envelope, stagedEntries: state.availableEntries),
        parent: parent, expectedOwner: identity.publicIdentity)
      try requireRecoveryState(state)
      return .init(plan: plan, anchor: state.anchorData, checkpoint: state.candidateCheckpoint)
    }
  }

  struct PendingRemoval: Sendable {
    let plan: V3RecoveryRecipientRemovalPlan
    let anchor: Data
    let checkpoint: V3ManifestCheckpoint
    let operationID: VaultTransactionOperationID
  }

  /// Exact owned removal metadata for informed product confirmation. It is not
  /// authentication of the pending contents or permission to start a new epoch.
  func pendingRemoval(operationID: VaultTransactionOperationID) throws -> PendingRemoval? {
    try validateScope()
    switch try prepareRecovery(.recipient, operationID: operationID, expectedAnchor: nil) {
    case .finished(.nothingToRecover): return nil
    case .finished:
      throw AppError.operationRefused(
        "The incomplete removal was released without publication. Review the recovery keys again before a new attempt."
      )
    case .ready(let state):
      let checked = try preflightRecovery(state, kind: .recipient)
      let parent = try V3RecoveryManifestCodec().parseEnvelope(
        objects.readManifest(state.intent.expectedCheckpoint.envelopeDigest))
      let plan = try removalValidator(oldKey: nil).reconstructPublicPlan(
        input(state), envelope: checked.envelope, parent: parent)
      try V3RecoveryRecipientRemovalValidator(limits: limits).preflightPublic(
        .init(plan: plan, envelope: checked.envelope, stagedEntries: state.availableEntries),
        parent: parent, expectedOwner: identity.publicIdentity)
      try requireRecoveryState(state)
      return .init(
        plan: plan, anchor: state.anchorData, checkpoint: state.candidateCheckpoint,
        operationID: state.intent.operationID)
    }
  }

  /// A completed retry must still be the exact authenticated revocation floor;
  /// a later edit or unrelated authority change cannot acknowledge that token.
  func completedRevocationPlan(
    continuing ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket
  ) throws -> V3DeviceWrappedRevocationPlan {
    let current = try loadCurrent(continuing: ticket)
    guard current.envelope.parents.count == 1, let digest = current.envelope.parents.first else {
      throw V3RecoveryDeviceRevocationError.invalidCandidate
    }
    let checkpoint = try V3ManifestCheckpoint(vaultID: vaultID, envelopeDigest: digest)
    let parent = try V3RecoveryManifestCodec().parseEnvelope(objects.readManifest(digest))
    let input = V3ContentTransactionInput(
      kind: .revokeDevice, expectedCheckpoint: checkpoint,
      manifestData: current.envelope.canonicalBytes, manifestDigest: current.envelope.digest,
      stagedEntries: Array(current.source.entries.values))
    let plan = try revocationValidator(oldKey: nil).reconstructPublicPlan(
      input, envelope: current.envelope, parent: parent)
    try V3RecoveryDeviceRevocationValidator(limits: limits).preflightPublic(
      .init(plan: plan, envelope: current.envelope, stagedEntries: input.stagedEntries),
      parent: parent, expectedOwner: identity.publicIdentity)
    try lifecycle.revalidate(current)
    return plan
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
        outcome = try revocationPublisher(operationID, continuing: ticket)
          .recoverInterruptedTransaction(
            vaultID: vaultID, currentVaultKey: oldKey, nextVaultKey: nextKey,
            expectedOwner: identity.publicIdentity, expectedAnchor: state.anchorData)
      case .recipient:
        outcome = try removalPublisher(operationID, continuing: ticket)
          .recoverInterruptedTransaction(
            vaultID: vaultID, currentVaultKey: oldKey, nextVaultKey: nextKey,
            expectedOwner: identity.publicIdentity, expectedAnchor: state.anchorData)
      }
      switch outcome {
      case .completed, .alreadyCompleted:
        try lifecycle.installCommitted(
          checked.envelope, vaultKey: nextKey, continuing: ticket
        ) { _ in try lifecycle.requireNoPending() }
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
    try lifecycle.requireNoAuthorityWork()
    try lifecycle.requireCheckpoint(state.currentCheckpoint)
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
  private func revocationPublisher(
    _ operationID: VaultTransactionOperationID,
    continuing ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket? = nil
  )
    -> V3RecoveryDeviceRevocationPublisher
  {
    .init(
      mutationOwner: DirectVaultTransactionMutationOwner(operationID: operationID),
      objectStore: store, checkpointStore: checkpoints, recoveryAnchorStore: ownership,
      registrationAnchorStore: registration, adoptionAnchorStore: adoption, cache: cache,
      limits: limits, phaseObserver: phaseObserver,
      validateScope: {
        try validateScope()
        if let ticket { try session.requireCurrent(ticket) }
      })
  }
  private func removalPublisher(
    _ operationID: VaultTransactionOperationID,
    continuing ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket? = nil
  )
    -> V3RecoveryRecipientRemovalPublisher
  {
    .init(
      mutationOwner: DirectVaultTransactionMutationOwner(operationID: operationID),
      objectStore: store, checkpointStore: checkpoints, recoveryAnchorStore: ownership,
      registrationAnchorStore: registration, adoptionAnchorStore: adoption, cache: cache,
      limits: limits, phaseObserver: phaseObserver,
      validateScope: {
        try validateScope()
        if let ticket { try session.requireCurrent(ticket) }
      })
  }

  private struct CommittedEpoch {
    let checkpoint: V3ManifestCheckpoint
    let envelope: V3RecoveryManifestEnvelope
  }
  private typealias Base = V3RecoveryLifecycleContext.Current
  private var objects: V3ExactTransitionRepository { .init(source: store, limits: limits) }
  private var lifecycle: V3RecoveryLifecycleContext {
    .init(
      vaultID: vaultID, identity: identity.publicIdentity, session: session, source: store,
      checkpoints: checkpoints, ownership: ownership, registration: registration,
      adoption: adoption,
      limits: limits, validateScope: validateScope)
  }

  private func change(
    checkpoint: V3ManifestCheckpoint, kind: VaultTransactionMutationKind,
    operationID: VaultTransactionOperationID,
    continuing ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket? = nil,
    review: (Base) throws -> Void,
    publish: (Base, Data) throws -> CommittedEpoch
  ) throws -> CommittedEpoch {
    do {
      guard checkpoint.vaultID == vaultID else { throw V3RecoveryAuthorityChangeError.invalidOwner }
      try lifecycle.requireCheckpoint(checkpoint)
      let base = try loadCurrent(continuing: ticket)
      guard base.checkpoint == checkpoint else {
        throw V3ImmutableTransactionError.expectedHeadsChanged
      }
      // Acknowledgment and independent plan comparison precede random-key
      // generation, signing and publication. This is not restart dispatch.
      try review(base)
      let nextKey = try freshKey(excluding: base.envelope.body.fields.keyID)
      let committed = try publish(base, nextKey)
      try lifecycle.installCommitted(
        committed.envelope, vaultKey: nextKey, continuing: base.ticket
      ) { pending in
        try verifyCommittedOwnership(
          pending, commit: committed, previous: checkpoint, kind: kind, operationID: operationID)
      }
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

  private func loadCurrent(
    continuing ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket? = nil
  ) throws -> Base {
    guard identity.vaultID == vaultID else { throw V3RecoveryAuthorityChangeError.invalidOwner }
    do {
      return try lifecycle.current(continuing: ticket ?? session.beginAuthentication())
    } catch V3RecoveryLifecycleContextError.invalidOwner {
      throw V3RecoveryAuthorityChangeError.invalidOwner
    }
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
  private func verifyCommittedOwnership(
    _ pending: Data?, commit: CommittedEpoch, previous: V3ManifestCheckpoint,
    kind: VaultTransactionMutationKind,
    operationID: VaultTransactionOperationID
  ) throws {
    if let bytes = pending {
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
    for _ in 0 ..< 16 {
      let key = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
      if try V3VaultKeyID.derive(vaultKey: key, vaultID: vaultID) != current { return key }
    }
    throw V3RecoveryAuthorityChangeError.invalidNextVaultKey
  }
}
