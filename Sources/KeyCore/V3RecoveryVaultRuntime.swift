import Foundation

/// Profile-3 composition, gated off in shipping builds. Reads/catch-up use
/// the helper's mutation owner. Mutation methods run inside that same owner and
/// reuse the supplied operation ID, so they never nest its serialization queue.
struct V3RecoveryVaultRuntime:
  VaultReadServicing, VaultMutationServicing, VaultUXServicing, VaultSessionServicing, Sendable
{
  private struct Prepared {
    let context: V3RecoveryVaultUnlockRuntime.ReadContext
    let selection: V3RecoveryCatchUpSessionResult.Selection
    let revalidatePublishedSource: @Sendable () throws -> Void
  }
  private let vaultID: String
  private let store: any V3TransactionArtifactStore
  private let checkpoints: any V3ManifestCheckpointStoring
  private let ownership: [any V3ImmutableTransactionRecoveryAnchorStoring]
  private let cache: any V3CheckpointManifestCaching
  private let identities: any V3DeviceWrappedIdentityLoading
  private let session: V3DeviceWrappedVaultKeySessionStore
  private let mutationOwner: any VaultTransactionMutationOwning
  private let unlockRuntime: V3RecoveryVaultUnlockRuntime
  private let reader: V3RecoveryReadOnlyVaultRuntime
  private let mutations: V3RecoveryVaultMutationService
  private let limits: V3ManifestRepositoryLimits

  init(
    vaultID: String, objectStore: any V3TransactionArtifactStore,
    checkpointStore: any V3ManifestCheckpointStoring,
    transactionOwnershipStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    registrationOwnershipStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    adoptionOwnershipStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    cache: any V3CheckpointManifestCaching, identityLoader: any V3DeviceWrappedIdentityLoading,
    session: V3DeviceWrappedVaultKeySessionStore,
    mutationOwner: any VaultTransactionMutationOwning,
    limits: V3ManifestRepositoryLimits = .standard
  ) {
    self.vaultID = vaultID
    store = objectStore
    checkpoints = checkpointStore
    ownership = [transactionOwnershipStore, registrationOwnershipStore, adoptionOwnershipStore]
    self.cache = cache
    identities = identityLoader
    self.session = session
    self.mutationOwner = mutationOwner
    self.limits = limits
    let unlock = V3RecoveryVaultUnlockRuntime(
      vaultID: vaultID, checkpointStore: checkpointStore, source: objectStore, cache: cache,
      identityLoader: identityLoader, session: session,
      transactionOwnershipStore: transactionOwnershipStore,
      registrationOwnershipStore: registrationOwnershipStore,
      adoptionOwnershipStore: adoptionOwnershipStore)
    unlockRuntime = unlock
    reader = .init(source: objectStore, unlockRuntime: unlock, limits: limits)
    mutations = .init(
      vaultID: vaultID, session: session, objectStore: objectStore,
      checkpointStore: checkpointStore, recoveryAnchorStore: transactionOwnershipStore,
      registrationAnchorStore: registrationOwnershipStore,
      adoptionAnchorStore: adoptionOwnershipStore,
      cache: cache, limits: limits)
  }

  func unlock() throws {
    try withRead(explicitly: true) { prepared, _ in
      try requireCurrent(prepared, allowStale: false)
      try prepared.context.revalidate()
    }
  }

  func read(name: String, allowStale: Bool) throws -> VaultReadValue {
    let name = try normalizedV3EntryName(name)
    return try withRead(allowStale: allowStale) { prepared, _ in
      try requireCurrent(prepared, allowStale: allowStale)
      return try reader.read(name: name, context: prepared.context)
    }
  }

  func list(allowStale: Bool) throws -> [String] {
    try withRead(allowStale: allowStale) { prepared, _ in
      try requireCurrent(prepared, allowStale: allowStale)
      return try reader.list(allowStale: allowStale, context: prepared.context)
    }
  }

  func status() throws -> VaultStatus {
    try withRead(allowStale: true) { prepared, _ in
      let floorStatus = try reader.status(context: prepared.context)
      // Invalid local closure takes precedence over a provider-graph diagnosis.
      guard floorStatus.health == .ready else { return floorStatus }
      let health: VaultHealth
      let issue: VaultIssue
      switch prepared.selection {
      case .verified(.current): return floorStatus
      case .verified(.contentConflict):
        health = .contentConflicted
        issue = .init(
          code: .ambiguousHistory,
          message:
            "Vault history contains competing edits. The next save must reconcile them. Use --allow-stale only to read the last complete version already verified on this Mac; it may be out of date."
        )
      case .incomplete:
        health = .incomplete
        issue = .init(
          code: .referencedObjectUnavailable,
          message:
            "Newer vault files are unavailable. Only the saved checkpoint has been verified on this Mac."
        )
      }
      try prepared.context.revalidate()
      return .init(
        format: .version3, health: health,
        entries: .lastTrusted(prepared.context.current.envelope.body.fields.entries.count),
        trustedVersionID: floorStatus.trustedVersionID, issues: [issue])
    }
  }

  func authorizeRead(name: String, allowStale: Bool) throws {
    let name = try normalizedV3EntryName(name)
    try withRead(allowStale: allowStale) { prepared, _ in
      try requireCurrent(prepared, allowStale: allowStale)
      try reader.authorizeRead(name: name, context: prepared.context)
    }
  }

  /// Helper-owned mutation admission only. Actual publication independently
  /// catches up and revalidates; this metadata observation is not authority.
  func authorizeMutation() throws {
    try translatingV3RecoveryRuntimeErrors {
      let context = try unlockRuntime.authenticatedReadContext(
        reason: "Unlock the vault to save your change.")
      try mutations.authorizeMutation()
      try context.revalidate()
    }
  }

  func add(
    name: String, secret: String, type: SecretEntryType, operationID: VaultTransactionOperationID
  ) throws {
    _ = try normalizedV3EntryName(name)
    try withMutation(operationID) {
      try mutations.add(name: name, secret: secret, type: type, operationID: operationID)
    }
  }
  func edit(
    name: String, secret: String, type: SecretEntryType, operationID: VaultTransactionOperationID
  ) throws {
    _ = try normalizedV3EntryName(name)
    try withMutation(operationID) {
      try mutations.edit(name: name, secret: secret, type: type, operationID: operationID)
    }
  }
  func copy(
    source: String, destination: String, overwrite: Bool, operationID: VaultTransactionOperationID
  ) throws {
    _ = try normalizedV3EntryName(source)
    _ = try normalizedV3EntryName(destination)
    try withMutation(operationID) {
      try mutations.copy(
        source: source, destination: destination, overwrite: overwrite, operationID: operationID)
    }
  }
  func move(
    source: String, destination: String, overwrite: Bool, operationID: VaultTransactionOperationID
  ) throws {
    _ = try normalizedV3EntryName(source)
    _ = try normalizedV3EntryName(destination)
    try withMutation(operationID) {
      try mutations.move(
        source: source, destination: destination, overwrite: overwrite, operationID: operationID)
    }
  }
  func remove(name: String, operationID: VaultTransactionOperationID) throws {
    _ = try normalizedV3EntryName(name)
    try withMutation(operationID) { try mutations.remove(name: name, operationID: operationID) }
  }
  func resolve(_ resolutions: [VaultConflictResolution], operationID: VaultTransactionOperationID)
    throws
  {
    try withMutation(operationID) {
      try mutations.resolve(resolutions, operationID: operationID)
    }
  }

  func conflicts() throws -> [VaultConflictSummary] { try conflictDetails().map(\.summary) }
  func conflict(id: String) throws -> VaultConflictDetail {
    guard let detail = try conflictDetails().first(where: { $0.summary.id == id }) else {
      throw VaultUXServiceError.conflictNotFound
    }
    return detail
  }
  func conflictValue(id: String, versionID: String) throws -> String {
    try withRead { prepared, _ in
      let context = prepared.context
      let observer = V3RecoverySameEpochRepositoryObserver(source: store, limits: limits)
      let observed = try observer.observe(
        from: context.current,
        vaultKey: context.loadVaultKey(keyID: context.current.envelope.body.fields.keyID))
      try context.revalidate()
      let plan = try V3AuthenticatedReadPlanner().planRecoveryConflictRead(
        conflictID: id, versionID: versionID, observed: observed)
      return try V3AuthenticatedReadExecutor(
        source: store, maximumEntryBytes: limits.maximumEntryBytes,
        vaultKeyProvider: { try context.loadVaultKey(keyID: $0) },
        authorityValidator: .init(
          currentStateProvider: { checkpoint in
            guard checkpoint == context.current.checkpoint else {
              throw V3AuthenticatedReadError.authorityChanged
            }
            try context.revalidate()
            let fresh = try observer.observe(
              from: context.current,
              vaultKey: context.loadVaultKey(keyID: context.current.envelope.body.fields.keyID))
            guard fresh == observed else { throw V3AuthenticatedReadError.authorityChanged }
            try context.revalidate()
            return .init(
              checkpoint: fresh.checkpoint,
              heads: try fresh.heads.map {
                try V3VaultHead(vaultID: fresh.checkpoint.vaultID, envelopeDigest: $0)
              })
          }, checkpointProvider: { _ in throw V3AuthenticatedReadError.authorityChanged })
      ).execute(plan)
    }
  }
  func resolve(_ resolutions: [VaultConflictResolution]) throws {
    throw AppError.operationRefused(
      "Conflict publication requires the helper-owned mutation operation.")
  }

  func lock() { unlockRuntime.lock() }
  func sessionStatus(at date: Date?) -> KeyHelperStatus { session.sessionStatus(at: date) }

  private func conflictDetails() throws -> [VaultConflictDetail] {
    try withRead { prepared, operationID in
      let result = try mutations.conflicts(operationID: operationID)
      try prepared.context.revalidate()
      return result
    }
  }

  private func withRead<T>(
    explicitly: Bool = false, allowStale: Bool = false,
    _ operation: (Prepared, VaultTransactionOperationID) throws -> T
  ) throws -> T {
    let admission = session.beginAuthentication()
    return try translatingV3RecoveryRuntimeErrors {
      try mutationOwner.perform(.catchUpVault) { scope in
        let prepared = try prepare(
          explicitly: explicitly, admission: admission,
          operationID: scope.operationID, allowStale: allowStale)
        let result = try operation(prepared, scope.operationID)
        try prepared.context.revalidate()
        try prepared.revalidatePublishedSource()
        try prepared.context.revalidate()
        return result
      }
    }
  }

  private func withMutation<T>(
    _ operationID: VaultTransactionOperationID,
    _ operation: () throws -> T
  ) throws -> T {
    try translatingV3RecoveryRuntimeErrors {
      let prepared = try prepare(
        explicitly: false, admission: session.beginAuthentication(),
        operationID: operationID, allowStale: false)
      // The existing mutation reconciler distinguishes automatic merges from
      // unresolved conflicts. Do not reject every multi-head graph here.
      let ticket = try prepared.context.authenticationTicket()
      let result = try operation()
      // Ordinary publication may advance the checkpoint but not the key epoch.
      // A cancellation after durable publication cannot undo the saved bytes.
      try session.requireCurrent(ticket)
      for store in ownership where try store.loadRecoveryAnchor(vaultID: vaultID) != nil {
        throw V3RecoveryVaultUnlockError.mutationPending
      }
      return result
    }
  }

  private func prepare(
    explicitly: Bool, admission: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket,
    operationID: VaultTransactionOperationID, allowStale: Bool
  ) throws -> Prepared {
    do {
      var continuation = admission
      var fresh = explicitly
      if try ownership[0].loadRecoveryAnchor(vaultID: vaultID) != nil {
        let pending = try unlockRuntime.authenticatedPendingContext(
          namespace: .transaction, reason: "Authenticate this Mac's interrupted vault save.",
          explicitly: explicitly, continuing: admission)
        continuation = try pending.authenticationTicket()
        let key = try pending.loadVaultKey()
        try mutations.reconcilePendingContent(
          operationID: operationID, vaultKey: key, expectedAnchor: pending.anchor.canonicalBytes)
        // Reconciliation can advance the checkpoint, but cannot replace the
        // same-epoch session or turn cancellation into a fresh authentication.
        try session.requireCurrent(continuation)
        fresh = false
      }
      let opened = try unlockRuntime.authenticatedReadContext(
        reason: "Unlock the vault.",
        explicitly: fresh, continuing: continuation)
      let ticket = try opened.authenticationTicket()
      guard
        let identity = try identities.loadDeviceIdentity(
          vaultID: vaultID,
          reason: "Open synchronized changes to the vault.")
      else {
        throw V3RecoveryVaultUnlockError.identityUnavailable
      }
      try opened.revalidate()
      let result = try V3RecoveryCatchUpCoordinator(
        mutationOwner: DirectVaultTransactionMutationOwner(operationID: operationID),
        identity: identity,
        session: session, source: store, checkpointStore: checkpoints,
        recoveryAnchorStore: ownership[0],
        registrationAnchorStore: ownership[1], adoptionAnchorStore: ownership[2], cache: cache,
        limits: limits
      ).catchUp(from: opened.current, continuing: ticket, allowStale: allowStale)
      let current: V3RecoveryContentCommit
      switch result.selection {
      case .verified(.current(let floor, _)), .verified(.contentConflict(let floor, _, _)),
        .incomplete(let floor):
        current = floor
      }
      return .init(
        context: try unlockRuntime.continuedReadContext(current: current, ticket: result.ticket),
        selection: result.selection, revalidatePublishedSource: result.revalidatePublishedSource)
    } catch {
      session.invalidate()
      throw error
    }
  }

  private func requireCurrent(_ prepared: Prepared, allowStale: Bool) throws {
    switch prepared.selection {
    case .verified(.current): return
    case .verified(.contentConflict):
      guard allowStale else { throw VaultUXServiceError.catchUpContentConflict }
    case .incomplete:
      guard allowStale else { throw VaultUXServiceError.vaultIncomplete }
    }
  }
}
