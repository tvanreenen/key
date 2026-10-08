import CryptoKit
import Foundation

/// Internal profile-3 workflow behind the ordinary mutation interface. Like
/// V3VaultMutationService, the helper must own serialization and supply a fresh
/// operation ID. Direct owners reuse that boundary without nesting its queue.
/// The existing in-memory Mac-bound session supplies only the exact current key;
/// there is no signer, unwrap, token, administration or shipping dispatch here.
struct V3RecoveryVaultMutationService: VaultMutationServicing, Sendable {
  typealias EntryIDGenerator = @Sendable () -> String
  private struct Base {
    let current: V3RecoveryContentCommit
    let key: Data
    let observed: V3RecoverySameEpochObservation
  }
  private let vaultID: String
  private let session: V3DeviceWrappedVaultKeySessionStore
  private let store: any V3TransactionArtifactStore
  private let checkpoints: any V3ManifestCheckpointStoring
  private let ownership: any V3ImmutableTransactionRecoveryAnchorStoring
  private let registration: any V3ImmutableTransactionRecoveryAnchorStoring
  private let adoption: any V3ImmutableTransactionRecoveryAnchorStoring
  private let cache: any V3CheckpointManifestCaching
  private let limits: V3ManifestRepositoryLimits
  private let makeEntryID: EntryIDGenerator

  init(
    vaultID: String, session: V3DeviceWrappedVaultKeySessionStore,
    objectStore: any V3TransactionArtifactStore,
    checkpointStore: any V3ManifestCheckpointStoring,
    recoveryAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    registrationAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    adoptionAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    cache: any V3CheckpointManifestCaching,
    limits: V3ManifestRepositoryLimits = .standard,
    makeEntryID: @escaping EntryIDGenerator = { UUID().uuidString.lowercased() }
  ) {
    self.vaultID = vaultID
    self.session = session
    store = objectStore
    checkpoints = checkpointStore
    ownership = recoveryAnchorStore
    registration = registrationAnchorStore
    adoption = adoptionAnchorStore
    self.cache = cache
    self.limits = limits
    self.makeEntryID = makeEntryID
  }

  func authorizeMutation() throws {
    try translated {
      try requireNoAuthorityWork()
      _ = try loadCurrent()
    }
  }

  func add(
    name: String, secret: String, type: SecretEntryType, operationID: VaultTransactionOperationID
  )
    throws
  {
    let name = try normalizedV3EntryName(name)
    let plaintext = try normalizedSecret(secret, type: type)
    try mutate(operationID) { base in
      .add(entryID: try freshEntryID(base), name: name, type: type, plaintext: plaintext)
    }
  }

  /// Reuse the existing publication kernel for the exact local content intent.
  /// The runtime authenticates its floor under that same ownership first.
  func reconcilePendingContent(
    operationID: VaultTransactionOperationID, vaultKey: Data, expectedAnchor: Data
  ) throws {
    try translated {
      try requireNoAuthorityWork()
      guard try ownership.loadRecoveryAnchor(vaultID: vaultID) == expectedAnchor else {
        throw VaultUXServiceError.expectedHeadsChanged
      }
      try resumePinned(operationID, key: vaultKey)
      try requireNoPending()
    }
  }

  func edit(
    name: String, secret: String, type: SecretEntryType, operationID: VaultTransactionOperationID
  )
    throws
  {
    let name = try normalizedV3EntryName(name)
    let plaintext = try normalizedSecret(secret, type: type)
    try mutate(operationID) { _ in .edit(name: name, type: type, plaintext: plaintext) }
  }

  func copy(
    source: String, destination: String, overwrite: Bool, operationID: VaultTransactionOperationID
  )
    throws
  {
    let source = try normalizedV3EntryName(source)
    let destination = try normalizedV3EntryName(destination)
    guard source != destination else {
      throw AppError.operationRefused("A duplicate needs a different destination name.")
    }
    try mutate(operationID) { base in
      .copy(
        sourceName: source, sourceData: try sourceData(source, base: base),
        destinationEntryID: try freshEntryID(base), destinationName: destination,
        overwrite: overwrite)
    }
  }

  func move(
    source: String, destination: String, overwrite: Bool, operationID: VaultTransactionOperationID
  )
    throws
  {
    let source = try normalizedV3EntryName(source)
    let destination = try normalizedV3EntryName(destination)
    guard source != destination else {
      throw AppError.operationRefused("A rename needs a different destination name.")
    }
    try mutate(operationID) { base in
      .move(
        sourceName: source, sourceData: try sourceData(source, base: base),
        destinationName: destination, overwrite: overwrite)
    }
  }

  func remove(name: String, operationID: VaultTransactionOperationID) throws {
    let name = try normalizedV3EntryName(name)
    try mutate(operationID) { _ in .remove(name: name) }
  }

  /// Metadata-only conflict projection. Caller owns the same serialized helper
  /// boundary as mutations because pinned recovery/catch-up may advance trust.
  func conflicts(operationID: VaultTransactionOperationID) throws -> [VaultConflictDetail] {
    try translated {
      let base = try prepareObserved(operationID)
      return try V3ConflictObservationBuilder().build(base.observed)?.conflicts ?? []
    }
  }

  func resolve(_ resolutions: [VaultConflictResolution], operationID: VaultTransactionOperationID)
    throws
  {
    try translated {
      let base = try prepareObserved(operationID)
      guard case .contentConflict = try V3RecoveryManifestReconciler().reconcile(base.observed)
      else {
        throw VaultUXServiceError.expectedHeadsChanged
      }
      let candidate = try V3RecoveryMergeMutationBuilder(limits: limits).buildResolution(
        resolutions, from: base.observed, vaultKey: base.key)
      _ = try mergePublisher(operationID).publish(candidate, vaultKey: base.key)
    }
  }

  private func mutate(
    _ operationID: VaultTransactionOperationID, request: (Base) throws -> V3EntryMutationRequest
  ) throws {
    try translated {
      var base = try prepareObserved(operationID)
      switch try V3RecoveryManifestReconciler().reconcile(base.observed) {
      case .noMergeRequired: break
      case .automaticMerge:
        let candidate = try V3RecoveryMergeMutationBuilder(limits: limits).buildAutomatic(
          from: base.observed, vaultKey: base.key)
        _ = try mergePublisher(VaultTransactionOperationID()).publish(candidate, vaultKey: base.key)
        base = try prepareObserved(operationID)
      case .contentConflict: throw VaultUXServiceError.contentConflict
      case .historyConflict: throw VaultUXServiceError.recoveryRequired
      }
      guard base.observed.heads == [base.current.checkpoint.envelopeDigest] else {
        throw VaultUXServiceError.expectedHeadsChanged
      }
      let candidate = try V3RecoveryContentMutationBuilder(limits: limits).build(
        request(base), checkpoint: base.current.checkpoint, parent: base.current.envelope,
        currentEntries: base.observed.entryObjects, vaultKey: base.key)
      _ = try ordinaryPublisher(operationID).publish(candidate, vaultKey: base.key)
    }
  }

  private func prepareObserved(_ operationID: VaultTransactionOperationID) throws -> Base {
    try requireNoAuthorityWork()
    var (current, key) = try loadCurrent()
    try resumePinned(operationID, key: key)
    try requireNoPending()
    (current, key) = try loadCurrent()
    let caught = try V3RecoverySameEpochCatchUpService(
      mutationOwner: DirectVaultTransactionMutationOwner(operationID: operationID), source: store,
      checkpointStore: checkpoints, recoveryAnchorStore: ownership,
      registrationAnchorStore: registration, adoptionAnchorStore: adoption, cache: cache,
      limits: limits
    ).catchUp(from: current, vaultKey: key)
    switch caught {
    case .current(let commit, _), .contentConflict(let commit, _, _): current = commit
    }
    try requireNoPending()
    try requireCheckpoint(current.checkpoint)
    let observer = V3RecoverySameEpochRepositoryObserver(source: store, limits: limits)
    let observed = try observer.observe(from: current, vaultKey: key)
    try requireNoPending()
    try requireCheckpoint(current.checkpoint)
    guard try observer.observe(from: current, vaultKey: key) == observed else {
      throw V3RecoveryValidationError.sourceChanged
    }
    try requireNoPending()
    try requireCheckpoint(current.checkpoint)
    return Base(current: current, key: key, observed: observed)
  }

  private func loadCurrent() throws -> (V3RecoveryContentCommit, Data) {
    guard isValidV3UUID(vaultID), let data = try checkpoints.loadCheckpoint(vaultID: vaultID),
      data.count <= 1_024, let checkpoint = try? V3ManifestCheckpoint(canonicalBytes: data),
      checkpoint.vaultID == vaultID
    else { throw VaultUXServiceError.recoveryRequired }
    let bytes = try V3ExactTransitionRepository(source: store, limits: limits).readManifest(
      checkpoint.envelopeDigest)
    guard Data(SHA256.hash(data: bytes)) == checkpoint.envelopeDigest else {
      throw VaultUXServiceError.recoveryRequired
    }
    let envelope = try V3RecoveryManifestCodec().parseEnvelope(bytes)
    guard envelope.body.fields.vaultID == vaultID else {
      throw VaultUXServiceError.recoveryRequired
    }
    let key = try session.load(vaultID: vaultID, keyID: envelope.body.fields.keyID)
    try V3RecoveryContentMutationValidator(limits: limits).validateParent(
      envelope, checkpoint: checkpoint, vaultKey: key)
    try requireCheckpoint(checkpoint)
    return (V3RecoveryContentCommit(checkpoint: checkpoint, envelope: envelope), key)
  }

  /// Select only the exact intent pinned by local ownership. There is no scan,
  /// guessed validator, provider-intent authority or retry with another key.
  private func resumePinned(_ operationID: VaultTransactionOperationID, key: Data) throws {
    guard let data = try ownership.loadRecoveryAnchor(vaultID: vaultID) else { return }
    guard data.count <= 1_024,
      let anchor = try? V3ImmutableTransactionRecoveryAnchor(canonicalBytes: data),
      anchor.vaultID == vaultID
    else { throw VaultUXServiceError.recoveryRequired }
    let merge: Bool
    switch try store.readRecoveryIntent(
      operationID: anchor.operationID,
      maximumBytes: V3ImmutableTransactionRecoveryIntent.maximumBytes)
    {
    case .unavailable where anchor.phase == .prepared:
      merge = false  // Shared kernel may abandon this locally reserved, unstaged operation.
    case .unavailable: throw VaultUXServiceError.vaultIncomplete
    case .available(let bytes):
      guard bytes.count <= V3ImmutableTransactionRecoveryIntent.maximumBytes,
        Data(SHA256.hash(data: bytes)) == anchor.intentDigest,
        let intent = try? V3ImmutableTransactionRecoveryIntent(canonicalBytes: bytes),
        intent.operationID == anchor.operationID, intent.vaultID == vaultID,
        intent.enrollmentTranscriptDigest == nil
      else { throw VaultUXServiceError.recoveryRequired }
      merge = intent.recoveryMergeResolutions != nil
    case .invalid, .tooLarge: throw VaultUXServiceError.recoveryRequired
    }
    guard try ownership.loadRecoveryAnchor(vaultID: vaultID) == data else {
      throw VaultUXServiceError.expectedHeadsChanged
    }
    if merge {
      _ = try mergePublisher(operationID).recoverInterruptedTransaction(
        vaultID: vaultID, vaultKey: key, expectedAnchor: data)
    } else {
      _ = try ordinaryPublisher(operationID).recoverInterruptedTransaction(
        vaultID: vaultID, vaultKey: key, expectedAnchor: data)
    }
  }

  private func ordinaryPublisher(_ id: VaultTransactionOperationID)
    -> V3RecoveryContentMutationPublisher
  {
    .init(
      mutationOwner: DirectVaultTransactionMutationOwner(operationID: id), objectStore: store,
      checkpointStore: checkpoints, recoveryAnchorStore: ownership,
      registrationAnchorStore: registration,
      adoptionAnchorStore: adoption, cache: cache, limits: limits)
  }
  private func mergePublisher(_ id: VaultTransactionOperationID) -> V3RecoveryMergeMutationPublisher
  {
    .init(
      mutationOwner: DirectVaultTransactionMutationOwner(operationID: id), objectStore: store,
      checkpointStore: checkpoints, recoveryAnchorStore: ownership,
      registrationAnchorStore: registration,
      adoptionAnchorStore: adoption, cache: cache, limits: limits)
  }
  private func requireCheckpoint(_ expected: V3ManifestCheckpoint) throws {
    guard try checkpoints.loadCheckpoint(vaultID: vaultID) == expected.canonicalBytes else {
      throw VaultUXServiceError.expectedHeadsChanged
    }
  }
  private func requireNoAuthorityWork() throws {
    guard try registration.loadRecoveryAnchor(vaultID: vaultID) == nil,
      try adoption.loadRecoveryAnchor(vaultID: vaultID) == nil
    else { throw VaultUXServiceError.vaultIncomplete }
  }
  private func requireNoPending() throws {
    try requireNoAuthorityWork()
    guard try ownership.loadRecoveryAnchor(vaultID: vaultID) == nil else {
      throw VaultUXServiceError.vaultIncomplete
    }
  }
  private func freshEntryID(_ base: Base) throws -> String {
    for _ in 0..<16 {
      let id = makeEntryID()
      guard isValidV3UUID(id) else { throw V3DeviceWrappedContentMutationError.invalidEntryID }
      if !base.current.envelope.body.fields.entries.contains(where: { $0.entryID == id }) {
        return id
      }
    }
    throw V3DeviceWrappedContentMutationError.invalidEntryID
  }
  private func sourceData(_ name: String, base: Base) throws -> Data {
    guard let record = base.current.envelope.body.fields.entries.first(where: { $0.name == name })
    else {
      throw V3DeviceWrappedContentMutationError.entryNotFound
    }
    let address = try V3RecoveryMergeMutationValidator.address(record)
    guard let entry = base.observed.entryObjects[address] else {
      throw VaultUXServiceError.vaultIncomplete
    }
    return entry.canonicalBytes
  }
  private func normalizedSecret(_ secret: String, type: SecretEntryType) throws -> String {
    guard secret.utf8.count <= limits.maximumEntryBytes else {
      throw VaultUXServiceError.recoveryRequired
    }
    return try type == .totp ? TOTPGenerator.normalizeBase32Seed(secret) : secret
  }

  private func translated<T>(_ body: () throws -> T) throws -> T {
    do { return try body() } catch let error as V3DeviceWrappedContentMutationError {
      switch error {
      case .entryNotFound: throw AppError.entryNotFound(error.localizedDescription)
      case .entryExists: throw AppError.entryExists(error.localizedDescription)
      case .unchangedName, .invalidEntryName, .revisionOverflow:
        throw AppError.operationRefused(error.localizedDescription)
      default: throw VaultUXServiceError.recoveryRequired
      }
    } catch let error as V3RecoveryValidationError {
      switch error {
      case .sourceUnavailable, .entryUnavailable: throw VaultUXServiceError.vaultIncomplete
      case .sourceChanged: throw VaultUXServiceError.expectedHeadsChanged
      default: throw VaultUXServiceError.recoveryRequired
      }
    } catch let error as V3RecoveryContentCatchUpError {
      switch error {
      case .checkpointChanged: throw VaultUXServiceError.expectedHeadsChanged
      case .localMutationPending, .stepLimitExceeded: throw VaultUXServiceError.vaultIncomplete
      case .epochTransitionRequired: throw VaultUXServiceError.recoveryRequired
      }
    } catch let error as V3ImmutableTransactionRecoveryError {
      switch error {
      case .transactionDirectoryUnavailable, .interruptedTransactionPending:
        throw VaultUXServiceError.vaultIncomplete
      default: throw VaultUXServiceError.recoveryRequired
      }
    } catch let error as V3ManifestCheckpointStoreError {
      if error == .conflict { throw VaultUXServiceError.expectedHeadsChanged }
      throw VaultUXServiceError.recoveryRequired
    } catch let error as V3ImmutableTransactionError {
      switch error {
      case .expectedHeadsChanged: throw VaultUXServiceError.expectedHeadsChanged
      case .referencedEntryUnavailable, .publishedManifestUnavailable:
        throw VaultUXServiceError.vaultIncomplete
      case .unresolvedConflict: throw VaultUXServiceError.contentConflict
      default: throw VaultUXServiceError.recoveryRequired
      }
    } catch is V3DeviceWrappedVaultKeySessionError {
      throw AppError.authFailed("Unlock this vault on this Mac before saving a change.")
    } catch is V3RecoveryManifestError {
      throw VaultUXServiceError.recoveryRequired
    } catch is V3RecoveryContentMutationError {
      throw VaultUXServiceError.recoveryRequired
    } catch is V3RecoveryMergeMutationError {
      throw VaultUXServiceError.recoveryRequired
    } catch is V3EntrySnapshotValidationError {
      throw VaultUXServiceError.recoveryRequired
    } catch is V3ImmutableTransactionRecoveryAnchorError {
      throw VaultUXServiceError.recoveryRequired
    } catch is V3RecoveryContentPublicationError { throw VaultUXServiceError.vaultIncomplete }
  }
}
