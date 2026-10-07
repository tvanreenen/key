import CryptoKit
import Foundation

enum V3RecoveryRestoreServiceError: Error, Equatable {
  case recognizedAnchorRequired, identityUnavailable, savedIdentityMismatch, wrapperMismatch
  case noPendingRestore, incompletePreparation
}

enum V3RecoveryRestoreServicePhase: Equatable, Sendable {
  case sourceAuthenticated, reservationDurable, identitySaved, savedWrapperVerified
  case preparationDurable
  case publication(V3RecoveryRestorePublicationPhase)
  case trust(V3RecoveryRestoreTrustPhase)
  case selection(V3RecoveryRestoreSelectionPhase)
  case finalization(V3RecoveryRestoreFinalizationPhase)
  case completionConfirmed
}

protocol V3RecoveryRestoreServicePhaseObserving: Sendable {
  func didReach(_ phase: V3RecoveryRestoreServicePhase) throws
}

private struct V3NoopRestoreServiceObserver: V3RecoveryRestoreServicePhaseObserving {
  func didReach(_: V3RecoveryRestoreServicePhase) throws {}
}

/// Public result only, not a saved source approval or permission to publish.
struct V3RecoveryRestoreReport: Equatable, Sendable {
  let operationID: VaultTransactionOperationID
  let checkpoint: V3ManifestCheckpoint
  let destinationPath: String
  let entryCount: Int
}

/// Internal authenticated new-vault restore. The shared source mutation
/// owner spans the call. The future product host must also serialize destination
/// and configuration work against init/enrollment and invalidate the supplied
/// authentication generation on lock/disconnect. No shipping route is enabled.
/// No source Mac credentials, token administration or shipping route.
struct V3RecoveryRestoreService {
  private let configStore: KeyConfigStore
  private let journal: V3RecoveryRestoreJournal
  private let identities: any V3DeviceWrappedGenesisIdentityManaging
  private let owner: any VaultTransactionMutationOwning
  private let reader: PIVRecoveryTokenReader
  private let agreement: PIVRecoveryAgreement
  private let authentication: V3DeviceWrappedVaultKeySessionStore
  private let limits: V3ManifestRepositoryLimits
  private let observer: any V3RecoveryRestoreServicePhaseObserving
  private let checkpoints: any V3ManifestCheckpointStoring
  private let cache: any V3CheckpointManifestCaching
  private let writeObserver: any V3AtomicStagedObjectWriteObserving

  init(
    configStore: KeyConfigStore, journal: V3RecoveryRestoreJournal,
    identities: any V3DeviceWrappedGenesisIdentityManaging,
    checkpoints: any V3ManifestCheckpointStoring, cache: any V3CheckpointManifestCaching,
    mutationOwner: any VaultTransactionMutationOwning,
    reader: PIVRecoveryTokenReader, agreement: PIVRecoveryAgreement,
    authentication: V3DeviceWrappedVaultKeySessionStore,
    limits: V3ManifestRepositoryLimits = .standard,
    observer: any V3RecoveryRestoreServicePhaseObserving = V3NoopRestoreServiceObserver(),
    writeObserver: any V3AtomicStagedObjectWriteObserving = V3NoopAtomicStagedObjectWriteObserver()
  ) {
    self.configStore = configStore
    self.journal = journal
    self.identities = identities
    owner = mutationOwner
    self.reader = reader
    self.agreement = agreement
    self.authentication = authentication
    self.limits = limits
    self.observer = observer
    self.checkpoints = checkpoints
    self.cache = cache
    self.writeObserver = writeObserver
  }

  /// One fresh native-bound recovery agreement. Complete encrypted preparation
  /// is pinned only after independently loading and opening the saved Mac
  /// credentials. An interrupted reservation can never authorize recreation.
  @available(macOS 26.0, *)
  func prepare(
    source: VaultRootDirectoryHandle, parent: VaultRootDirectoryHandle, name: String,
    deviceName: String, observation: PIVRecoveryTokenObservation,
    cancellation: PIVRecoveryCancellation = PIVRecoveryCancellation(),
    deadline: DispatchTime = .now() + .seconds(60)
  ) throws -> V3RecoveryRestoreReport {
    try begin(
      source: source, parent: parent, name: name, deviceName: deviceName, observation: observation,
      cancellation: cancellation, deadline: deadline, finish: false)
  }

  @available(macOS 26.0, *)
  func restore(
    source: VaultRootDirectoryHandle, parent: VaultRootDirectoryHandle, name: String,
    deviceName: String, observation: PIVRecoveryTokenObservation,
    cancellation: PIVRecoveryCancellation = PIVRecoveryCancellation(),
    deadline: DispatchTime = .now() + .seconds(60)
  ) throws -> V3RecoveryRestoreReport {
    try begin(
      source: source, parent: parent, name: name, deviceName: deviceName, observation: observation,
      cancellation: cancellation, deadline: deadline, finish: true)
  }

  @available(macOS 26.0, *)
  private func begin(
    source: VaultRootDirectoryHandle, parent: VaultRootDirectoryHandle, name: String,
    deviceName: String, observation: PIVRecoveryTokenObservation,
    cancellation: PIVRecoveryCancellation, deadline: DispatchTime, finish: Bool
  ) throws -> V3RecoveryRestoreReport {
    try withSnapshot(
      source: source, parent: parent, observation: observation,
      cancellation: cancellation, deadline: deadline,
      preflight: { anchor in
        try journal.requireConfigurationRoot(configStore.unconfiguredRestoreRoot())
        guard isValidV3DeviceDisplayName(deviceName) else {
          throw V3EnrollmentDeviceIdentityStoreError.invalidIdentityRequest
        }
        guard try journal.loadPending(sourceVaultID: anchor.floor.vaultID) == nil else {
          throw V3RecoveryRestoreJournalError.attemptPending
        }
      },
      consume: { context, snapshot, recheck in
        let store = V3FilesystemTransactionArtifactStore(rootHandle: source)
        let anchor = snapshot.selection.anchor
        let environment = try V3RecoveryRestoreEnvironment.create(
          source: source, in: parent, name: name, configStore: configStore)
        let reservation = try journal.reserve(
          environment: environment, snapshot: snapshot, operationID: context.operationID,
          vaultID: UUID().uuidString.lowercased(), transitionID: UUID().uuidString.lowercased(),
          entryIDs: snapshot.entries.map { _ in UUID().uuidString.lowercased() },
          validateScope: recheck)
        func requireReservation() throws {
          try recheck()
          try environment.requireCurrent(reservation.locations)
          guard let pending = try journal.loadPending(sourceVaultID: anchor.floor.vaultID),
            pending.reservation == reservation,
            pending.reservationOwnership.phase == .recoverable,
            pending.preparation == nil, pending.preparationOwnership == nil
          else { throw V3RecoveryRestoreJournalError.ownershipChanged }
        }
        try observer.didReach(.reservationDurable)
        try requireReservation()
        let created = try identities.createDeviceWrappedIdentity(
          vaultID: reservation.vaultID, displayName: deviceName,
          reason: "Create this Mac's credentials for the restored vault.")
        try observer.didReach(.identitySaved)
        try requireReservation()
        guard
          let saved = try identities.loadDeviceIdentity(
            vaultID: reservation.vaultID,
            reason: "Load this Mac's saved restored-vault credentials.")
        else { throw V3RecoveryRestoreServiceError.identityUnavailable }
        guard created.vaultID == reservation.vaultID, saved.vaultID == reservation.vaultID,
          created.publicIdentity == saved.publicIdentity
        else { throw V3RecoveryRestoreServiceError.savedIdentityMismatch }
        try requireReservation()
        let key = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        let candidate = try V3RecoveryRestoreCandidateBuilder(source: store, limits: limits)
          .build(
            restoring: snapshot, vaultID: reservation.vaultID,
            authorityTransitionID: reservation.transitionID, entryIDs: reservation.entryIDs,
            vaultKey: key, ownerIdentity: saved.publicIdentity)
        try requireReservation()
        let session = V3DeviceWrappedVaultKeySessionStore()
        defer { session.invalidate() }
        let genesis = candidate.publication.genesis
        let checkpoint = try V3ManifestCheckpoint(
          vaultID: reservation.vaultID, envelopeDigest: genesis.manifestDigest)
        _ = try V3DeviceWrappedCheckpointUnlocker().unlock(
          checkpoint: checkpoint, manifestData: genesis.manifestData, identity: saved,
          session: session, reason: "Verify this Mac's saved restored-vault access.",
          validateBeforeSessionInstall: requireReservation)
        guard try session.load(vaultID: reservation.vaultID, keyID: genesis.body.keyID) == key
        else {
          throw V3RecoveryRestoreServiceError.wrapperMismatch
        }
        session.invalidate()
        try observer.didReach(.savedWrapperVerified)
        try requireReservation()
        let bundle = try journal.stage(
          candidate, reservation: reservation, environment: environment, vaultKey: key,
          expectedOwner: saved.publicIdentity, validateScope: recheck)
        try observer.didReach(.preparationDurable)
        try recheck()
        try environment.requireCurrent(reservation.locations)
        _ = try journal.confirmPreparation(
          sourceVaultID: anchor.floor.vaultID, snapshot: snapshot, environment: environment,
          vaultKey: key, expectedOwner: saved.publicIdentity, validateScope: recheck)
        if finish {
          try complete(
            snapshot: snapshot, environment: environment, vaultKey: key, identity: saved,
            source: source, parent: parent, validateScope: recheck)
        }
        return .init(
          operationID: reservation.operationID, checkpoint: bundle.intent.destinationCheckpoint,
          destinationPath: environment.destination.rootURL.path,
          entryCount: snapshot.entries.count)
      })
  }

  /// Locally pinned complete bytes are mandatory before authentication. An
  /// incomplete reservation never recreates a credential or a destination.
  /// Every explicit request gets one fresh source agreement; no pins is not a
  /// retrospective success claim after a lost final reply.
  @available(macOS 26.0, *)
  func resume(
    source: VaultRootDirectoryHandle, destination: VaultRootDirectoryHandle,
    parent: VaultRootDirectoryHandle, observation: PIVRecoveryTokenObservation,
    cancellation: PIVRecoveryCancellation = PIVRecoveryCancellation(),
    deadline: DispatchTime = .now() + .seconds(60)
  ) throws -> V3RecoveryRestoreReport {
    var pending: V3RecoveryRestorePending?
    var captured: V3RecoveryRestoreEnvironment?
    return try withSnapshot(
      source: source, parent: parent, observation: observation,
      cancellation: cancellation, deadline: deadline,
      preflight: { anchor in
        try journal.requireConfigurationRoot(configStore.restoreCompletionRoot())
        guard let owned = try journal.loadForCompletion(sourceVaultID: anchor.floor.vaultID) else {
          throw V3RecoveryRestoreServiceError.noPendingRestore
        }
        guard let bundle = owned.preparation, owned.reservationOwnership.phase == .recoverable
        else {
          throw V3RecoveryRestoreServiceError.incompletePreparation
        }
        let environment = try V3RecoveryRestoreEnvironment.reopenForCompletion(
          source: source, destination: destination, parent: parent, configStore: configStore,
          expected: bundle.intent.locations, vaultID: bundle.intent.destinationCheckpoint.vaultID)
        if environment.hasSelectedConfiguration {
          guard try journal.loadFinalization(sourceVaultID: anchor.floor.vaultID)?.pending == owned
          else {
            throw V3RecoveryRestoreJournalError.invalidOwnership
          }
          try requireSelectedTrust(bundle)
        } else {
          guard try journal.loadPending(sourceVaultID: anchor.floor.vaultID) == owned else {
            throw V3RecoveryRestoreJournalError.invalidOwnership
          }
        }
        pending = owned
        captured = environment
      },
      validateSelection: { selection in
        guard let reservation = pending?.reservation,
          reservation.sourceAnchor == selection.anchor,
          reservation.sourcePublicKey == selection.credentialPublicKey,
          reservation.sourceHeadDigest == selection.head.digest,
          reservation.sourceObservationDigest
            == V3RecoveryRestoreIntent.observationDigest(selection)
        else { throw V3RecoveryValidationError.sourceChanged }
      },
      consume: { _, snapshot, recheck in
        guard let owned = pending, let bundle = owned.preparation, let environment = captured else {
          throw V3RecoveryRestoreServiceError.incompletePreparation
        }
        let sourceID = snapshot.selection.anchor.floor.vaultID
        func requirePending() throws {
          try recheck()
          try environment.requireCurrent(bundle.intent.locations)
          try owned.reservation.requireSnapshot(snapshot)
          guard try journal.loadForCompletion(sourceVaultID: sourceID) == owned else {
            throw V3RecoveryRestoreJournalError.ownershipChanged
          }
          if environment.hasSelectedConfiguration { try requireSelectedTrust(bundle) }
        }
        try requirePending()
        guard
          let identity = try identities.loadDeviceIdentity(
            vaultID: bundle.intent.destinationCheckpoint.vaultID,
            reason: "Load this Mac's saved restored-vault credentials.")
        else { throw V3RecoveryRestoreServiceError.identityUnavailable }
        guard identity.vaultID == bundle.intent.destinationCheckpoint.vaultID,
          identity.publicIdentity == bundle.manifest.body.devices[0].identity
        else { throw V3RecoveryRestoreServiceError.savedIdentityMismatch }
        try requirePending()
        let session = V3DeviceWrappedVaultKeySessionStore()
        defer { session.invalidate() }
        _ = try V3DeviceWrappedCheckpointUnlocker().unlock(
          checkpoint: bundle.intent.destinationCheckpoint,
          manifestData: bundle.manifest.canonicalBytes,
          identity: identity, session: session,
          reason: "Open this Mac's saved restored-vault preparation.",
          validateBeforeSessionInstall: requirePending)
        let key = try session.load(
          vaultID: bundle.intent.destinationCheckpoint.vaultID,
          keyID: bundle.intent.destinationKeyID)
        session.invalidate()
        try requirePending()
        try complete(
          snapshot: snapshot, environment: environment, vaultKey: key, identity: identity,
          source: source, parent: parent, validateScope: recheck)
        return .init(
          operationID: owned.reservation.operationID,
          checkpoint: bundle.intent.destinationCheckpoint,
          destinationPath: destination.rootURL.path, entryCount: snapshot.entries.count)
      })
  }

  private func requireSelectedTrust(_ bundle: V3RecoveryRestoreBundle) throws {
    let checkpoint = bundle.intent.destinationCheckpoint
    guard try checkpoints.loadCheckpoint(vaultID: checkpoint.vaultID) == checkpoint.canonicalBytes
    else {
      throw V3RecoveryRestoreTrustError.conflictingCheckpoint
    }
    guard case .available(let bytes) = try cache.load(for: checkpoint),
      bytes == bundle.manifest.canonicalBytes
    else { throw V3RecoveryRestoreTrustError.cacheUnavailable }
  }

  private func complete(
    snapshot: V3RecoveryVerifiedSnapshot, environment: V3RecoveryRestoreEnvironment, vaultKey: Data,
    identity: any V3DeviceWrappedVaultKeyUnwrapping, source: VaultRootDirectoryHandle,
    parent: VaultRootDirectoryHandle, validateScope: () throws -> Void
  ) throws {
    let sourceID = snapshot.selection.anchor.floor.vaultID
    try validateScope()
    if !environment.hasSelectedConfiguration {
      _ = try V3RecoveryRestorePublisher(
        journal: journal, limits: limits, observer: PublicationObserver(observer: observer),
        writeObserver: writeObserver
      ).publish(
        sourceVaultID: sourceID, snapshot: snapshot, environment: environment, vaultKey: vaultKey,
        identity: identity, validateScope: validateScope)
      _ = try V3RecoveryRestoreSelectionInstaller(
        journal: journal, checkpoints: checkpoints, cache: cache, identities: identities,
        observer: SelectionObserver(observer: observer), writeObserver: writeObserver,
        trustObserver: TrustObserver(observer: observer)
      ).select(
        sourceVaultID: sourceID, snapshot: snapshot, vaultKey: vaultKey, source: source,
        destination: environment.destination, parent: parent, configStore: configStore,
        validateScope: validateScope)
    }
    guard
      try V3RecoveryRestoreFinalizer(
        journal: journal, checkpoints: checkpoints, cache: cache, identities: identities,
        observer: FinalizationObserver(observer: observer)
      ).finalize(
        sourceVaultID: sourceID, snapshot: snapshot, vaultKey: vaultKey, source: source,
        destination: environment.destination, parent: parent, configStore: configStore,
        validateScope: validateScope) != nil
    else { throw V3RecoveryRestoreServiceError.noPendingRestore }
    try observer.didReach(.completionConfirmed)
    try validateScope()
  }

  @available(macOS 26.0, *)
  private func withSnapshot<T>(
    source: VaultRootDirectoryHandle, parent: VaultRootDirectoryHandle,
    observation: PIVRecoveryTokenObservation, cancellation: PIVRecoveryCancellation,
    deadline: DispatchTime, preflight: (V3RecoveryAnchor) throws -> Void,
    validateSelection: (V3RecoveryPublicSelection) throws -> Void = { _ in },
    consume:
      @escaping (VaultTransactionMutationContext, V3RecoveryVerifiedSnapshot, () throws -> Void)
      throws
      -> T
  ) throws -> T {
    let ticket = authentication.beginAuthentication()
    func requireAuthentication() throws {
      if cancellation.isCancelled { throw PIVRecoveryAgreementError.cancelled }
      guard DispatchTime.now() < deadline else { throw PIVRecoveryAgreementError.deadlineExceeded }
      try authentication.requireCurrent(ticket)
      try source.requireConfiguredRootIdentity()
      try parent.requireConfiguredRootIdentity()
    }
    return try owner.perform(.restoreVault) { context in
      try requireAuthentication()
      try reader.revalidate(observation)
      try observation.keyMetadata.requireRecoveryPolicy()
      guard case .recognized(let anchor) = observation.anchor else {
        throw V3RecoveryRestoreServiceError.recognizedAnchorRequired
      }
      try preflight(anchor)
      let store = V3FilesystemTransactionArtifactStore(rootHandle: source)
      let selection = try V3RecoveryHistorySelector(source: store, limits: limits).select(
        anchor: anchor, credentialPublicKey: observation.publicKey)
      try validateSelection(selection)
      let verifier = V3RecoverySnapshotVerifier(source: store, limits: limits)
      try requireAuthentication()
      return try agreement.withReceiver(
        observation: observation, cancellation: cancellation, deadline: deadline
      ) { receiver in
        let snapshot = try verifier.open(selection, boundAnchor: anchor, receiver: receiver)
        try requireAuthentication()
        return try reader.withVerifiedObservation(observation) { revalidateToken in
          func recheck() throws {
            try requireAuthentication()
            try revalidateToken()
            try verifier.revalidate(
              snapshot, boundAnchor: anchor, credentialPublicKey: observation.publicKey)
            try requireAuthentication()
          }
          try observer.didReach(.sourceAuthenticated)
          try recheck()
          let result = try consume(context, snapshot, recheck)
          try recheck()
          return result
        }
      }
    }
  }

  private struct PublicationObserver: V3RecoveryRestorePublicationPhaseObserving {
    let observer: any V3RecoveryRestoreServicePhaseObserving
    func didReach(_ phase: V3RecoveryRestorePublicationPhase) throws {
      try observer.didReach(.publication(phase))
    }
  }
  private struct TrustObserver: V3RecoveryRestoreTrustPhaseObserving {
    let observer: any V3RecoveryRestoreServicePhaseObserving
    func didReach(_ phase: V3RecoveryRestoreTrustPhase) throws {
      try observer.didReach(.trust(phase))
    }
  }
  private struct SelectionObserver: V3RecoveryRestoreSelectionPhaseObserving {
    let observer: any V3RecoveryRestoreServicePhaseObserving
    func didReach(_ phase: V3RecoveryRestoreSelectionPhase) throws {
      try observer.didReach(.selection(phase))
    }
  }
  private struct FinalizationObserver: V3RecoveryRestoreFinalizationPhaseObserving {
    let observer: any V3RecoveryRestoreServicePhaseObserving
    func didReach(_ phase: V3RecoveryRestoreFinalizationPhase) throws {
      try observer.didReach(.finalization(phase))
    }
  }
}
