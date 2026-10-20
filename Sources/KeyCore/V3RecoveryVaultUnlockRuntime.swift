import CryptoKit
import Foundation

enum V3RecoveryVaultUnlockError: Error, Equatable {
  case locked, temporaryUnavailable, recoveryRequired, checkpointChanged
  case mutationPending, identityUnavailable, deviceRevoked, unsupportedProfile
}

/// Routine profile-3 Mac unlock from exact device-local authority, not token
/// recovery, adoption, catch-up or a shipping factory. No key/checkpoint is saved.
/// The returned floor authenticates manifest/capsule only, not entry availability.
final class V3RecoveryVaultUnlockRuntime: @unchecked Sendable {
  /// Process-local read authority bound to the authentication that produced it.
  /// It contains no key and cannot survive lock, expiry or session replacement.
  struct ReadContext: Sendable {
    let current: V3RecoveryContentCommit
    private let runtime: V3RecoveryVaultUnlockRuntime
    private let ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket
    private let pending: PendingSelection?

    fileprivate init(
      current: V3RecoveryContentCommit, runtime: V3RecoveryVaultUnlockRuntime,
      ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket,
      pending: PendingSelection? = nil
    ) {
      self.current = current
      self.runtime = runtime
      self.ticket = ticket
      self.pending = pending
    }

    func revalidate() throws {
      try runtime.requireState(current.checkpoint, ticket: ticket, pending: pending)
    }

    func authenticationTicket() throws -> V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket {
      try revalidate()
      return ticket
    }

    func loadVaultKey(keyID: V3VaultKeyID) throws -> Data {
      guard keyID == current.envelope.body.fields.keyID else {
        throw V3RecoveryVaultUnlockError.locked
      }
      try revalidate()
      let key = try runtime.session.load(vaultID: current.checkpoint.vaultID, keyID: keyID)
      try revalidate()
      return key
    }
  }

  /// Cannot be passed to an ordinary reader. Exact local ownership permits
  /// authentication of the floor, not publication or access to pending values.
  struct PendingContext: Sendable {
    let anchor: V3ImmutableTransactionRecoveryAnchor
    private let context: ReadContext
    var current: V3RecoveryContentCommit { context.current }
    fileprivate init(anchor: V3ImmutableTransactionRecoveryAnchor, context: ReadContext) {
      self.anchor = anchor
      self.context = context
    }
    func revalidate() throws { try context.revalidate() }
    func authenticationTicket() throws -> V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket {
      try context.authenticationTicket()
    }
    func loadVaultKey() throws -> Data {
      try context.loadVaultKey(keyID: current.envelope.body.fields.keyID)
    }
  }

  fileprivate struct PendingSelection: Sendable {
    let index: Int
    let anchor: V3ImmutableTransactionRecoveryAnchor
  }

  private let vaultID: String
  private let checkpoints: any V3ManifestCheckpointStoring
  private let source: any V3ImmutableObjectReading
  private let cache: any V3CheckpointManifestCaching
  private let identities: any V3DeviceWrappedIdentityLoading
  private let session: V3DeviceWrappedVaultKeySessionStore
  private let ownership: [any V3ImmutableTransactionRecoveryAnchorStoring]
  private let requests = NSLock()

  init(
    vaultID: String, checkpointStore: any V3ManifestCheckpointStoring,
    source: any V3ImmutableObjectReading, cache: any V3CheckpointManifestCaching,
    identityLoader: any V3DeviceWrappedIdentityLoading,
    session: V3DeviceWrappedVaultKeySessionStore,
    transactionOwnershipStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    registrationOwnershipStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    adoptionOwnershipStore: any V3ImmutableTransactionRecoveryAnchorStoring
  ) {
    precondition(isValidV3UUID(vaultID))
    self.vaultID = vaultID
    checkpoints = checkpointStore
    self.source = source
    self.cache = cache
    identities = identityLoader
    self.session = session
    ownership = [transactionOwnershipStore, registrationOwnershipStore, adoptionOwnershipStore]
  }

  /// Explicit unlock discards any prior key before identity access. Requests
  /// capture their ticket before serialization, so a lock also cancels waiters.
  func unlock(reason: String) throws -> V3RecoveryContentCommit {
    try authenticate(reason: reason, explicitly: true).current
  }

  /// Reuse only a matching resident key. Cold access performs one local unwrap;
  /// a malformed or mismatched resident session refuses without an automatic retry.
  func authenticatedCheckpoint(reason: String) throws -> V3RecoveryContentCommit {
    try authenticatedReadContext(reason: reason).current
  }

  func authenticatedReadContext(reason: String) throws -> ReadContext {
    try authenticate(reason: reason, explicitly: false)
  }

  /// Retain admission captured before an outer serialization queue. A lock
  /// while waiting must not become a new request's authentication grant.
  func authenticatedReadContext(
    reason: String, explicitly: Bool,
    continuing admission: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket
  ) throws -> ReadContext {
    try authenticate(reason: reason, explicitly: explicitly, admission: admission)
  }

  /// Only a bounded device-local record selects this path. No shared intent
  /// scan, caller-supplied exemption or cold retry after a cancelled admission.
  func authenticatedPendingContext(
    namespace: V3RecoveryOwnershipNamespace, reason: String, explicitly: Bool = false,
    continuing admission: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket
  ) throws -> PendingContext {
    do {
      try session.requireCurrent(admission)
      let index: Int
      switch namespace {
      case .transaction: index = 0
      case .registration: index = 1
      case .adoption: index = 2
      default: throw V3RecoveryVaultUnlockError.recoveryRequired
      }
      guard let bytes = try ownership[index].loadRecoveryAnchor(vaultID: vaultID),
        bytes.count <= 1_024,
        let anchor = try? V3ImmutableTransactionRecoveryAnchor(canonicalBytes: bytes),
        anchor.vaultID == vaultID
      else { throw V3RecoveryVaultUnlockError.recoveryRequired }
      let selected = PendingSelection(index: index, anchor: anchor)
      try requireOwnership(selected)
      let context = try authenticate(
        reason: reason, explicitly: explicitly, admission: admission, pending: selected)
      return .init(anchor: anchor, context: context)
    } catch {
      session.invalidate()
      throw error
    }
  }

  /// Continue a coordinator's exact committed floor and installation receipt.
  /// No cold fallback or new private operation is permitted at this hand-off.
  func continuedReadContext(
    current: V3RecoveryContentCommit,
    ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket
  ) throws -> ReadContext {
    guard current.checkpoint.vaultID == vaultID,
      current.envelope.body.fields.vaultID == vaultID,
      current.envelope.digest == current.checkpoint.envelopeDigest
    else { throw V3RecoveryVaultUnlockError.recoveryRequired }
    let context = ReadContext(current: current, runtime: self, ticket: ticket)
    let key = try context.loadVaultKey(keyID: current.envelope.body.fields.keyID)
    try V3RecoveryEpochBoundary().verifyCurrentAuthentication(current.envelope, vaultKey: key)
    try context.revalidate()
    return context
  }

  /// Independent of the request mutex, so native UI cannot delay cancellation.
  func lock() { session.invalidate() }

  private func authenticate(
    reason: String, explicitly: Bool,
    admission suppliedAdmission: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket? = nil,
    pending: PendingSelection? = nil
  ) throws -> ReadContext {
    let admission = suppliedAdmission ?? session.beginAuthentication()
    return try requests.withLock {
      do {
        try session.requireCurrent(admission)
        let ticket =
          try explicitly
          ? session.beginFreshAuthentication(continuing: admission) : admission
        try requireOwnership(pending)
        let checkpoint = try loadCheckpoint()
        let loaded = try loadManifest(checkpoint)
        let envelope = try parse(loaded.bytes, checkpoint: checkpoint)
        try requireState(checkpoint, ticket: ticket, pending: pending)

        if !explicitly, session.hasResidentKey {
          let key = try session.load(vaultID: vaultID, keyID: envelope.body.fields.keyID)
          try V3RecoveryEpochBoundary().verifyCurrentAuthentication(envelope, vaultKey: key)
          try requireState(checkpoint, ticket: ticket, pending: pending)
          if loaded.shouldCache { try? cache.store(loaded.bytes, for: checkpoint) }
          try requireState(checkpoint, ticket: ticket, pending: pending)
          return .init(
            current: .init(checkpoint: checkpoint, envelope: envelope), runtime: self,
            ticket: ticket, pending: pending)
        }

        guard !reason.isEmpty else { throw V3RecoveryVaultUnlockError.recoveryRequired }
        guard let identity = try identities.loadDeviceIdentity(vaultID: vaultID, reason: reason)
        else { throw V3RecoveryVaultUnlockError.identityUnavailable }
        try requireState(checkpoint, ticket: ticket, pending: pending)
        guard identity.vaultID == vaultID,
          let device = envelope.body.fields.devices.first(where: {
            $0.identity.deviceID == identity.publicIdentity.deviceID
          }), device.identity == identity.publicIdentity
        else { throw V3RecoveryVaultUnlockError.identityUnavailable }
        guard device.status == .active else { throw V3RecoveryVaultUnlockError.deviceRevoked }
        guard
          let wrapped = envelope.body.fields.wrappedKeys.first(where: {
            $0.recipientDeviceID == device.identity.deviceID
          })
        else { throw V3RecoveryVaultUnlockError.recoveryRequired }
        let key = try identity.unwrapDeviceWrappedVaultKey(
          wrapped.wrappedKey,
          context: envelope.body.deviceContext(recipientDeviceID: device.identity.deviceID),
          reason: reason)
        try V3RecoveryEpochBoundary().verifyCurrentAuthentication(envelope, vaultKey: key)
        try requireState(checkpoint, ticket: ticket, pending: pending)
        if loaded.shouldCache { try? cache.store(loaded.bytes, for: checkpoint) }
        try requireState(checkpoint, ticket: ticket, pending: pending)
        let installed = try session.install(
          key, vaultID: vaultID, keyID: envelope.body.fields.keyID, authenticationTicket: ticket)
        try requireState(checkpoint, ticket: installed, pending: pending)
        return .init(
          current: .init(checkpoint: checkpoint, envelope: envelope), runtime: self,
          ticket: installed, pending: pending)
      } catch {
        session.invalidate()
        switch error {
        case let error as V3RecoveryVaultUnlockError: throw error
        case V3EnrollmentDeviceIdentityStoreError.authenticationCancelled,
          is V3DeviceWrappedVaultKeySessionError:
          throw V3RecoveryVaultUnlockError.locked
        case V3RecoveryManifestError.unsupportedProfileVersion:
          throw V3RecoveryVaultUnlockError.unsupportedProfile
        default: throw V3RecoveryVaultUnlockError.recoveryRequired
        }
      }
    }
  }

  private func parse(_ bytes: Data, checkpoint: V3ManifestCheckpoint) throws
    -> V3RecoveryManifestEnvelope
  {
    guard !bytes.isEmpty, bytes.count <= V3ManifestRepositoryLimits.standard.maximumManifestBytes,
      Data(SHA256.hash(data: bytes)) == checkpoint.envelopeDigest
    else { throw V3RecoveryVaultUnlockError.recoveryRequired }
    // This existing codec explicitly refuses permanent and unknown profiles.
    let envelope = try V3RecoveryManifestCodec().parseEnvelope(bytes)
    guard envelope.body.fields.vaultID == vaultID else {
      throw V3RecoveryVaultUnlockError.recoveryRequired
    }
    return envelope
  }

  private func loadManifest(_ checkpoint: V3ManifestCheckpoint) throws
    -> (bytes: Data, shouldCache: Bool)
  {
    if case .available(let bytes) = try? cache.load(for: checkpoint) { return (bytes, false) }
    switch try source.readManifest(
      digest: checkpoint.envelopeDigest,
      maximumBytes: V3ManifestRepositoryLimits.standard.maximumManifestBytes)
    {
    case .available(let bytes): return (bytes, true)
    case .unavailable: throw V3RecoveryVaultUnlockError.temporaryUnavailable
    case .invalid, .tooLarge: throw V3RecoveryVaultUnlockError.recoveryRequired
    }
  }

  private func loadCheckpoint() throws -> V3ManifestCheckpoint {
    guard let bytes = try checkpoints.loadCheckpoint(vaultID: vaultID), bytes.count <= 1_024,
      let checkpoint = try? V3ManifestCheckpoint(canonicalBytes: bytes),
      checkpoint.vaultID == vaultID
    else { throw V3RecoveryVaultUnlockError.recoveryRequired }
    return checkpoint
  }

  private func requireState(
    _ checkpoint: V3ManifestCheckpoint,
    ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket,
    pending: PendingSelection? = nil
  ) throws {
    try session.requireCurrent(ticket)
    try requireOwnership(pending)
    guard try loadCheckpoint() == checkpoint else {
      throw V3RecoveryVaultUnlockError.checkpointChanged
    }
    try requireOwnership(pending)
    try session.requireCurrent(ticket)
  }

  private func requireOwnership(_ pending: PendingSelection?) throws {
    for (index, store) in ownership.enumerated() {
      let expected = pending?.index == index ? pending?.anchor.canonicalBytes : nil
      guard try store.loadRecoveryAnchor(vaultID: vaultID) == expected else {
        throw V3RecoveryVaultUnlockError.mutationPending
      }
    }
  }
}
