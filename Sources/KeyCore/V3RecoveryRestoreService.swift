import CryptoKit
import Foundation

enum V3RecoveryRestoreServiceError: Error, Equatable {
  case recognizedAnchorRequired, identityUnavailable, savedIdentityMismatch, wrapperMismatch
}

enum V3RecoveryRestoreServicePhase: Equatable, Sendable {
  case sourceAuthenticated, reservationDurable, identitySaved, savedWrapperVerified
  case preparationDurable
}

protocol V3RecoveryRestoreServicePhaseObserving: Sendable {
  func didReach(_ phase: V3RecoveryRestoreServicePhase) throws
}

private struct V3NoopRestoreServiceObserver: V3RecoveryRestoreServicePhaseObserving {
  func didReach(_: V3RecoveryRestoreServicePhase) throws {}
}

/// Public result only, not a saved source approval or permission to publish.
struct V3RecoveryRestorePreparationReport: Equatable, Sendable {
  let operationID: VaultTransactionOperationID
  let checkpoint: V3ManifestCheckpoint
  let destinationPath: String
  let entryCount: Int
}

/// Internal authenticated new-vault preparation. The shared source mutation
/// owner spans the call. The future product host must also serialize destination
/// and configuration work against init/enrollment and invalidate the supplied
/// authentication generation on lock/disconnect. No shipping route is enabled.
/// No source Mac credentials, token administration, publication or selection.
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

  init(
    configStore: KeyConfigStore, journal: V3RecoveryRestoreJournal,
    identities: any V3DeviceWrappedGenesisIdentityManaging,
    mutationOwner: any VaultTransactionMutationOwning,
    reader: PIVRecoveryTokenReader, agreement: PIVRecoveryAgreement,
    authentication: V3DeviceWrappedVaultKeySessionStore,
    limits: V3ManifestRepositoryLimits = .standard,
    observer: any V3RecoveryRestoreServicePhaseObserving = V3NoopRestoreServiceObserver()
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
  ) throws -> V3RecoveryRestorePreparationReport {
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
      try journal.requireConfigurationRoot(configStore.unconfiguredRestoreRoot())
      guard isValidV3DeviceDisplayName(deviceName) else {
        throw V3EnrollmentDeviceIdentityStoreError.invalidIdentityRequest
      }
      try reader.revalidate(observation)
      try observation.keyMetadata.requireRecoveryPolicy()
      guard case .recognized(let anchor) = observation.anchor else {
        throw V3RecoveryRestoreServiceError.recognizedAnchorRequired
      }
      guard try journal.loadPending(sourceVaultID: anchor.floor.vaultID) == nil else {
        throw V3RecoveryRestoreJournalError.attemptPending
      }
      let store = V3FilesystemTransactionArtifactStore(rootHandle: source)
      let selector = V3RecoveryHistorySelector(source: store, limits: limits)
      let verifier = V3RecoverySnapshotVerifier(source: store, limits: limits)
      let selection = try selector.select(
        anchor: anchor, credentialPublicKey: observation.publicKey)
      try requireAuthentication()
      return try agreement.withReceiver(
        observation: observation, cancellation: cancellation, deadline: deadline
      ) { receiver in
        let snapshot = try verifier.open(selection, boundAnchor: anchor, receiver: receiver)
        try requireAuthentication()
        // The native operation has drained before this lease is acquired. One
        // lease now excludes other token work throughout credential preparation;
        // its public-read sessions are closed before any Mac private operation.
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
          return .init(
            operationID: reservation.operationID, checkpoint: bundle.intent.destinationCheckpoint,
            destinationPath: environment.destination.rootURL.path,
            entryCount: snapshot.entries.count)
        }
      }
    }
  }
}
