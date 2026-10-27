import CryptoKit
import Foundation

/// Informed product confirmation over the independent recipient-removal policy.
/// Review can catch up ordinary state. Execution first checks the exact public
/// decision and last-key acknowledgment, then authenticates that same floor.
struct KeyRecoveryRecipientRemovalWorkflow: Sendable {
  typealias Identity = V3RecoveryAuthorityChangeService.Identity
  let vaultID: String
  let identity: Identity
  let session: V3DeviceWrappedVaultKeySessionStore
  let source: any V3TransactionArtifactStore
  let checkpoints: any V3ManifestCheckpointStoring
  let transaction: any V3ImmutableTransactionRecoveryAnchorStoring
  let registration: any V3ImmutableTransactionRecoveryAnchorStoring
  let adoption: any V3ImmutableTransactionRecoveryAnchorStoring
  let cache: any V3CheckpointManifestCaching
  let owner: any VaultTransactionMutationOwning
  var validateScope: @Sendable () throws -> Void = {}
  private var binding: V3RecoveryRecipientRemovalReviewBinding { .init() }

  func handle(_ request: KeyRecoveryRecipientRemovalRequest) throws
    -> KeyRecoveryRecipientRemovalResult
  {
    do { return try translatingV3RecoveryRuntimeErrors { try perform(request) } } catch let error
      as V3RecoveryRecipientRemovalError
    {
      switch error {
      case .recipientNotFound, .recipientAlreadyRevoked:
        throw AppError.operationRefused(
          "That recovery key is not active in the reviewed vault. Inspect recovery registration status."
        )
      case .protectionLossAcknowledgementRequired, .invalidAcknowledgement:
        throw AppError.operationRefused(
          "Removing the last recovery key needs explicit acknowledgment of losing recovery protection."
        )
      default: throw VaultUXServiceError.recoveryRequired
      }
    }
  }

  private func perform(_ request: KeyRecoveryRecipientRemovalRequest) throws
    -> KeyRecoveryRecipientRemovalResult
  {
    try validateScope()
    try request.validate()
    let recipient = try V3RecoveryRecipientID(rawValue: request.recipientID)
    let kind: VaultTransactionMutationKind
    switch request {
    case .review: kind = .catchUpVault
    case .remove: kind = .removeRecoveryRecipient
    }
    return try owner.perform(kind) { context in
      try validateScope()
      let service = makeService()
      let pending = try service.pendingRemoval(operationID: context.operationID)
      if let pending {
        guard pending.plan.removedRecipient.recipientID == recipient else { throw changedReview() }
        let review = binding.review(pending.plan, operationID: pending.operationID.rawValue)
        if case .review = request {
          try validateScope()
          return .review(review)
        }
        try requireDecision(request, plan: pending.plan, operation: pending.operationID.rawValue)
        let outcome = try service.recoverInterruptedRemoval(
          operationID: context.operationID, expectedAnchor: pending.anchor)
        switch outcome {
        case .completed, .alreadyCompleted:
          try validateScope()
          return try completed(
            pending.checkpoint, recipient: recipient, operationID: pending.operationID)
        case .abandoned, .nothingToRecover:
          throw AppError.operationRefused(
            "The saved removal did not complete. Inspect its retained state before another attempt."
          )
        }
      }
      if case .review = request {
        let current = try authenticated(
          catchUp: true, operationID: context.operationID,
          reason: "Review this vault's recovery keys.")
        let ticket = try current.authenticationTicket()
        if current.current.envelope.body.recovery.recipients.contains(where: {
          $0.recipientID == recipient && $0.status == .revoked
        }) {
          // Status, not acknowledgment of an arbitrary operation or publication.
          _ = try V3RecoveryReadOnlyVaultRuntime(source: source, unlockRuntime: unlock)
            .list(allowStale: false, context: current)
          try current.revalidate()
          try validateScope()
          return try completed(current.current.checkpoint, recipient: recipient, already: true)
        }
        let plan = try makeService(continuing: ticket).prepareRemoval(
          removing: recipient, continuing: ticket)
        try current.revalidate()
        try validateScope()
        return .review(binding.review(plan))
      }
      // This hash-bound public plan grants nothing. It prevents a missing
      // protection-loss acknowledgment from requesting any Mac private work.
      let selected = try v3SelectedCheckpointProfile(
        vaultID: vaultID, checkpoints: checkpoints,
        source: source, cache: cache)
      guard case .recovery(let body) = selected.profile else { throw changedReview() }
      let envelope = try V3RecoveryManifestCodec().parseEnvelope(
        V3ExactTransitionRepository(source: source, limits: .standard).readManifest(
          selected.checkpoint.envelopeDigest))
      guard envelope.body == body, body.fields.vaultID == vaultID else {
        throw V3RecoveryValidationError.sourceChanged
      }
      let proposed = try V3RecoveryRecipientRemovalPlanner().planMetadata(
        checkpoint: selected.checkpoint, parent: envelope,
        authorizingDeviceID: identity.publicIdentity.deviceID, removing: recipient)
      try requireDecision(request, plan: proposed, operation: nil)
      let reason =
        proposed.removesLastActiveRecipient
        ? "Remove the LAST recovery key from this vault. Recovery will be unavailable."
        : "Remove the recovery key whose removal you reviewed."
      let current = try authenticated(
        catchUp: false, operationID: context.operationID, reason: reason)
      let ticket = try current.authenticationTicket()
      let bound = makeService(continuing: ticket)
      let plan = try bound.prepareRemoval(removing: recipient, continuing: ticket)
      guard plan == proposed else { throw changedReview() }
      try requireDecision(request, plan: plan, operation: nil)
      let acknowledgement =
        plan.removesLastActiveRecipient
        ? try V3RecoveryProtectionLossAcknowledgement(plan: plan) : nil
      let commit = try bound.remove(
        plan, operationID: context.operationID,
        protectionLossAcknowledgement: acknowledgement, continuing: ticket)
      try validateScope()
      return try completed(
        commit.checkpoint, recipient: recipient, operationID: context.operationID)
    }
  }

  private var guardedIdentity: Identity {
    V3ScopedEnrollmentIdentity(base: identity, validate: validateScope)
  }
  private var unlock: V3RecoveryVaultUnlockRuntime {
    .init(
      vaultID: vaultID, checkpointStore: checkpoints, source: source, cache: cache,
      identityLoader: Loader(identity: guardedIdentity), session: session,
      transactionOwnershipStore: transaction, registrationOwnershipStore: registration,
      adoptionOwnershipStore: adoption)
  }
  private func authenticated(
    catchUp: Bool, operationID: VaultTransactionOperationID, reason: String
  ) throws
    -> V3RecoveryVaultUnlockRuntime.ReadContext
  {
    try validateScope()
    let current = try unlock.authenticatedReadContext(reason: reason)
    guard catchUp else { return current }
    let result = try V3RecoveryCatchUpCoordinator(
      mutationOwner: DirectVaultTransactionMutationOwner(operationID: operationID),
      identity: guardedIdentity, session: session, source: source, checkpointStore: checkpoints,
      recoveryAnchorStore: transaction, registrationAnchorStore: registration,
      adoptionAnchorStore: adoption, cache: cache, validateScope: validateScope
    ).catchUp(from: current.current, continuing: current.authenticationTicket(), allowStale: false)
    guard case .verified(.current(let floor, _)) = result.selection else {
      throw VaultUXServiceError.catchUpContentConflict
    }
    try result.revalidatePublishedSource()
    try validateScope()
    return try unlock.continuedReadContext(current: floor, ticket: result.ticket)
  }
  private func makeService(
    continuing ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket? = nil
  )
    -> V3RecoveryAuthorityChangeService
  {
    let bound = V3ScopedEnrollmentIdentity(
      base: identity,
      validate: {
        try validateScope()
        if let ticket { try session.requireCurrent(ticket) }
      })
    return .init(
      vaultID: vaultID, identity: bound, session: session, objectStore: source,
      checkpointStore: checkpoints, recoveryAnchorStore: transaction,
      registrationAnchorStore: registration,
      adoptionAnchorStore: adoption, cache: cache, validateScope: validateScope)
  }
  private func requireDecision(
    _ request: KeyRecoveryRecipientRemovalRequest, plan: V3RecoveryRecipientRemovalPlan,
    operation: String?
  ) throws {
    guard case .remove(let recipient, let token, let expectedOperation, let acknowledges) = request,
      recipient == plan.removedRecipient.recipientID.rawValue, token == binding.token(plan),
      expectedOperation == operation
    else { throw changedReview() }
    guard acknowledges == plan.removesLastActiveRecipient else {
      throw AppError.operationRefused(
        plan.removesLastActiveRecipient
          ? "Removing the last recovery key needs explicit acknowledgment that recovery will be unavailable."
          : "The recovery-key removal decision changed. Review it again.")
    }
    try validateScope()
  }
  private func completed(
    _ checkpoint: V3ManifestCheckpoint, recipient: V3RecoveryRecipientID,
    operationID: VaultTransactionOperationID? = nil, already: Bool = false
  ) throws -> KeyRecoveryRecipientRemovalResult {
    try validateScope()
    let pending = try transaction.loadRecoveryAnchor(vaultID: vaultID)
    if let pending {
      guard !already, let operationID, pending.count <= 1_024,
        let anchor = try? V3ImmutableTransactionRecoveryAnchor(canonicalBytes: pending),
        anchor.vaultID == vaultID, anchor.operationID == operationID,
        case .available(let bytes) = try source.readRecoveryIntent(
          operationID: operationID,
          maximumBytes: V3ImmutableTransactionRecoveryIntent.maximumBytes),
        Data(SHA256.hash(data: bytes)) == anchor.intentDigest,
        let intent = try? V3ImmutableTransactionRecoveryIntent(canonicalBytes: bytes),
        intent.kind == .removeRecoveryRecipient, intent.operationID == operationID,
        intent.vaultID == vaultID, intent.candidateManifestDigest == checkpoint.envelopeDigest
      else { throw V3RecoveryValidationError.sourceChanged }
    }
    guard try checkpoints.loadCheckpoint(vaultID: vaultID) == checkpoint.canonicalBytes,
      try transaction.loadRecoveryAnchor(vaultID: vaultID) == pending
    else {
      throw V3RecoveryValidationError.sourceChanged
    }
    try validateScope()
    return .completed(
      vaultID: vaultID, recipientID: recipient.rawValue,
      manifestDigest: v3LowercaseHex(checkpoint.envelopeDigest), cleanupPending: pending != nil,
      alreadyRemoved: already)
  }
  private func changedReview() -> AppError {
    .operationRefused(
      "The recovery-key removal review changed. Review the current state before trying again.")
  }
  private struct Loader: V3DeviceWrappedIdentityLoading {
    let identity: any V3DeviceWrappedVaultKeyUnwrapping
    func loadDeviceIdentity(vaultID: String, reason: String) throws -> (
      any V3DeviceWrappedVaultKeyUnwrapping
    )? { identity }
  }
}

extension KeyRecoveryRecipientRemovalWorkflow {
  static func live(
    configStore: KeyConfigStore, configuration: RuntimeConfiguration,
    scope: KeyRecoveryRequestScope
  ) throws -> Self {
    try scope.requireCurrent()
    guard #available(macOS 26.0, *) else {
      throw AppError.operationRefused("Recovery-capable vaults require macOS 26 or later.")
    }
    let selected = try configStore.load()
    guard case .v3(let vaultID) = selected.authority else {
      throw AppError.operationRefused("Removal requires a configured recovery-capable vault.")
    }
    let root = try VaultRootDirectoryHandle(opening: selected.vaultDirectoryURL)
    let verifySelection = configStore.selectionValidator(expected: selected)
    let validate: @Sendable () throws -> Void = {
      try scope.requireCurrent()
      try root.requireConfiguredRootIdentity()
      try verifySelection()
      try V3ReplacementEnrollmentAdmission(
        intentStore: V3ReplacementEnrollmentIntentKeychainStore(
          configuration: configuration)
      ).requireInactive(vaultID: vaultID)
    }
    try validate()
    let source = V3FilesystemTransactionArtifactStore(rootHandle: root)
    let checkpoints = V3ManifestCheckpointKeychainStore(configuration: configuration)
    let cache = try KeyServiceHandler.makeV3CheckpointManifestCache(keyConfiguration: selected)
    guard
      case .recovery = try v3SelectedCheckpointProfile(
        vaultID: vaultID, checkpoints: checkpoints,
        source: source, cache: cache
      ).profile
    else {
      throw AppError.operationRefused(
        "Recovery key removal requires the recovery-capable format. Adoption and registration are separate steps."
      )
    }
    let identities = V3EnrollmentDeviceIdentityManager(
      recordStore: V3EnrollmentDeviceKeyRecordKeychainStore(configuration: configuration),
      keyOperations: V3SecureEnclaveEnrollmentDeviceKeyOperations(), validateScope: validate)
    guard
      let identity = try identities.loadIdentity(
        vaultID: vaultID, reason: "Use this Mac's recovery-management credentials.")
    else {
      throw V3RecoveryVaultUnlockError.identityUnavailable
    }
    let session = V3DeviceWrappedVaultKeySessionStore()
    _ = scope.cancellation.register { session.invalidate() }
    return .init(
      vaultID: vaultID, identity: identity, session: session,
      source: source, checkpoints: checkpoints,
      transaction: V3ImmutableTransactionRecoveryAnchorKeychainStore(configuration: configuration),
      registration: V3ImmutableTransactionRecoveryAnchorKeychainStore(
        configuration: configuration, namespace: .registration),
      adoption: V3ImmutableTransactionRecoveryAnchorKeychainStore(
        configuration: configuration, namespace: .adoption),
      cache: cache,
      owner: VaultTransactionMutationOwner(), validateScope: validate)
  }
}
