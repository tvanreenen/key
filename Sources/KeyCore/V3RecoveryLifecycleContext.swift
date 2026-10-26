import Foundation

enum V3RecoveryLifecycleContextError: Error {
  case invalidOwner
}

/// Shared state validation for already-admitted profile-3 lifecycle operations.
/// Services retain approval policy, private operations, publication, exact resume
/// selection and failure handling. This context never authenticates or retries.
struct V3RecoveryLifecycleContext: Sendable {
  struct Current: Sendable {
    let checkpoint: V3ManifestCheckpoint
    let envelope: V3RecoveryManifestEnvelope
    let key: Data
    let source: V3ExactTransitionRepositoryState
    let ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket

    fileprivate init(
      checkpoint: V3ManifestCheckpoint, envelope: V3RecoveryManifestEnvelope,
      key: Data, source: V3ExactTransitionRepositoryState,
      ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket
    ) {
      self.checkpoint = checkpoint
      self.envelope = envelope
      self.key = key
      self.source = source
      self.ticket = ticket
    }
  }

  let vaultID: String
  let identity: V3EnrollmentDeviceIdentity
  let session: V3DeviceWrappedVaultKeySessionStore
  let source: any V3ImmutableObjectReading
  let checkpoints: any V3ManifestCheckpointStoring
  let ownership: any V3ImmutableTransactionRecoveryAnchorStoring
  let registration: any V3ImmutableTransactionRecoveryAnchorStoring
  let adoption: any V3ImmutableTransactionRecoveryAnchorStoring
  let limits: V3ManifestRepositoryLimits
  let validateScope: @Sendable () throws -> Void

  private var objects: V3ExactTransitionRepository { .init(source: source, limits: limits) }

  /// The supplied generation was captured by the caller before key access or
  /// approval. Never obtain fresh consent while loading or rechecking state.
  func current(
    continuing ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket
  ) throws -> Current {
    try requireNoPending()
    try session.requireCurrent(ticket)
    guard isValidV3UUID(vaultID),
      let bytes = try checkpoints.loadCheckpoint(vaultID: vaultID), bytes.count <= 1_024,
      let checkpoint = try? V3ManifestCheckpoint(canonicalBytes: bytes),
      checkpoint.vaultID == vaultID
    else { throw V3RecoveryLifecycleContextError.invalidOwner }
    let manifest = try objects.readManifest(checkpoint.envelopeDigest)
    let envelope = try V3RecoveryManifestCodec().parseEnvelope(manifest)
    guard envelope.body.fields.devices.contains(.init(identity: identity, status: .active))
    else { throw V3RecoveryLifecycleContextError.invalidOwner }
    try session.requireCurrent(ticket)
    let key = try session.load(vaultID: vaultID, keyID: envelope.body.fields.keyID)
    try V3RecoveryContentMutationValidator(limits: limits).validateParent(
      envelope, checkpoint: checkpoint, vaultKey: key)
    let observed = try objects.observe(checkpoint: checkpoint, expectedBase: manifest)
    _ = try V3EntrySnapshotValidator(limits: limits).plaintexts(
      fields: envelope.body.fields, entries: observed.entries, vaultKey: key)
    try requireNoPending()
    try requireCheckpoint(checkpoint)
    try session.requireCurrent(ticket)
    return .init(
      checkpoint: checkpoint, envelope: envelope, key: key, source: observed, ticket: ticket)
  }

  func revalidate(_ current: Current) throws {
    try requireNoPending()
    try requireCheckpoint(current.checkpoint)
    try session.requireCurrent(current.ticket)
    let fresh = try objects.observe(
      checkpoint: current.checkpoint, expectedBase: current.envelope.canonicalBytes)
    try session.requireCurrent(current.ticket)
    guard fresh == current.source,
      try session.load(vaultID: vaultID, keyID: current.envelope.body.fields.keyID) == current.key
    else { throw V3RecoveryValidationError.sourceChanged }
    try requireNoPending()
    try requireCheckpoint(current.checkpoint)
    try session.requireCurrent(current.ticket)
  }

  /// The mandatory policy check runs even with no retained ownership. Enrollment
  /// still checks its consumed ceremony; other services check their exact kind
  /// and intent. Pin stability and snapshot authentication belong to this owner.
  func installCommitted(
    _ envelope: V3RecoveryManifestEnvelope, vaultKey: Data,
    continuing ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket,
    verifyOperation: (Data?) throws -> Void
  ) throws {
    guard envelope.body.fields.vaultID == vaultID else {
      throw V3RecoveryLifecycleContextError.invalidOwner
    }
    let checkpoint = try V3ManifestCheckpoint(vaultID: vaultID, envelopeDigest: envelope.digest)
    func checkedOwnership() throws -> Data? {
      try requireNoAuthorityWork()
      try requireCheckpoint(checkpoint)
      try session.requireCurrent(ticket)
      let pending = try ownership.loadRecoveryAnchor(vaultID: vaultID)
      try verifyOperation(pending)
      try requireNoAuthorityWork()
      try requireCheckpoint(checkpoint)
      try session.requireCurrent(ticket)
      return pending
    }
    let pending = try checkedOwnership()
    try V3RecoveryEpochBoundary().verifyCurrentAuthentication(envelope, vaultKey: vaultKey)
    let observed = try objects.observe(
      checkpoint: checkpoint, expectedBase: envelope.canonicalBytes)
    _ = try V3EntrySnapshotValidator(limits: limits).plaintexts(
      fields: envelope.body.fields, entries: observed.entries, vaultKey: vaultKey)
    guard try checkedOwnership() == pending,
      try ownership.loadRecoveryAnchor(vaultID: vaultID) == pending
    else { throw V3RecoveryValidationError.sourceChanged }
    try requireNoAuthorityWork()
    try requireCheckpoint(checkpoint)
    try session.install(
      vaultKey, vaultID: vaultID, keyID: envelope.body.fields.keyID,
      authenticationTicket: ticket)
  }

  func requireCheckpoint(_ checkpoint: V3ManifestCheckpoint) throws {
    try validateScope()
    guard checkpoint.vaultID == vaultID,
      try checkpoints.loadCheckpoint(vaultID: vaultID) == checkpoint.canonicalBytes
    else { throw V3ImmutableTransactionError.expectedHeadsChanged }
  }

  func requireNoAuthorityWork() throws {
    try validateScope()
    guard try registration.loadRecoveryAnchor(vaultID: vaultID) == nil,
      try adoption.loadRecoveryAnchor(vaultID: vaultID) == nil
    else { throw V3RecoveryContentPublicationError.otherMutationPending }
  }

  func requireNoPending() throws {
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
