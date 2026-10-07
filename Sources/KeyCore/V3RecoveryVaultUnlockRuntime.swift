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
    try authenticate(reason: reason, explicitly: true)
  }

  /// Reuse only a matching resident key. Cold access performs one local unwrap;
  /// a malformed or mismatched resident session refuses without an automatic retry.
  func authenticatedCheckpoint(reason: String) throws -> V3RecoveryContentCommit {
    try authenticate(reason: reason, explicitly: false)
  }

  /// Independent of the request mutex, so native UI cannot delay cancellation.
  func lock() { session.invalidate() }

  private func authenticate(reason: String, explicitly: Bool) throws -> V3RecoveryContentCommit {
    let admission = session.beginAuthentication()
    return try requests.withLock {
      do {
        try session.requireCurrent(admission)
        let ticket =
          try explicitly
          ? session.beginFreshAuthentication(continuing: admission) : admission
        try requireNoPending()
        let checkpoint = try loadCheckpoint()
        let loaded = try loadManifest(checkpoint)
        let envelope = try parse(loaded.bytes, checkpoint: checkpoint)
        try requireState(checkpoint, ticket: ticket)

        if !explicitly, session.hasResidentKey {
          let key = try session.load(vaultID: vaultID, keyID: envelope.body.fields.keyID)
          try V3RecoveryEpochBoundary().verifyCurrentAuthentication(envelope, vaultKey: key)
          try requireState(checkpoint, ticket: ticket)
          if loaded.shouldCache { try? cache.store(loaded.bytes, for: checkpoint) }
          try requireState(checkpoint, ticket: ticket)
          return .init(checkpoint: checkpoint, envelope: envelope)
        }

        guard !reason.isEmpty else { throw V3RecoveryVaultUnlockError.recoveryRequired }
        guard let identity = try identities.loadDeviceIdentity(vaultID: vaultID, reason: reason)
        else { throw V3RecoveryVaultUnlockError.identityUnavailable }
        try requireState(checkpoint, ticket: ticket)
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
        try requireState(checkpoint, ticket: ticket)
        if loaded.shouldCache { try? cache.store(loaded.bytes, for: checkpoint) }
        try requireState(checkpoint, ticket: ticket)
        let installed = try session.install(
          key, vaultID: vaultID, keyID: envelope.body.fields.keyID, authenticationTicket: ticket)
        try requireState(checkpoint, ticket: installed)
        return .init(checkpoint: checkpoint, envelope: envelope)
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
    ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket
  ) throws {
    try session.requireCurrent(ticket)
    try requireNoPending()
    guard try loadCheckpoint() == checkpoint else {
      throw V3RecoveryVaultUnlockError.checkpointChanged
    }
    try requireNoPending()
    try session.requireCurrent(ticket)
  }

  private func requireNoPending() throws {
    for store in ownership where try store.loadRecoveryAnchor(vaultID: vaultID) != nil {
      throw V3RecoveryVaultUnlockError.mutationPending
    }
  }
}
