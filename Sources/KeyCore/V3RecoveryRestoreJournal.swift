import CryptoKit
import Foundation

enum V3RecoveryRestoreJournalError: Error, Equatable {
  case attemptPending
  case invalidOwnership
  case recordUnavailable
  case invalidRecord
  case ownershipChanged
}

enum V3RecoveryRestoreJournalPhase: Equatable, Sendable {
  case reservationPinned
  case reservationWritten
  case reservationDurable
  case preparationPinned
  case preparationWritten
  case preparationVerified
  case preparationDurable
}

protocol V3RecoveryRestoreJournalPhaseObserving: Sendable {
  func didReach(_ phase: V3RecoveryRestoreJournalPhase) throws
}

private struct V3NoopRestoreJournalObserver: V3RecoveryRestoreJournalPhaseObserving {
  func didReach(_: V3RecoveryRestoreJournalPhase) throws {}
}

/// Parsed, locally pinned evidence, not saved authentication or publication
/// authority. A reservation alone must never recreate a platform credential.
struct V3RecoveryRestorePending: Equatable, Sendable {
  let reservation: V3RecoveryRestoreReservation
  let reservationOwnership: V3ImmutableTransactionRecoveryAnchor
  let preparation: V3RecoveryRestoreBundle?
  let preparationOwnership: V3ImmutableTransactionRecoveryAnchor?
}

enum V3RecoveryRestoreFinalizationStage: Equatable, Sendable {
  case owned, reservationCleared, cleared
}

/// The complete preparation pin survives the first cleanup step. `cleared`
/// exists only within the current authenticated call, never as disk authority.
struct V3RecoveryRestoreFinalizationState: Equatable, Sendable {
  let pending: V3RecoveryRestorePending
  let stage: V3RecoveryRestoreFinalizationStage
}

/// Local-only restore journal over existing atomic contained filesystem writes
/// and two dedicated non-synchronizing ownership stores, keyed by SOURCE vault.
/// One attempt per source per Mac; no scans, publication, credential
/// creation or automatic regeneration. Caller serializes the entire ceremony.
/// Explicit selected completion can clear exact pins; files remain inert.
struct V3RecoveryRestoreJournal: Sendable {
  private let store: V3FilesystemTransactionArtifactStore
  private let reservations: any V3ImmutableTransactionRecoveryAnchorStoring
  private let preparations: any V3ImmutableTransactionRecoveryAnchorStoring
  private let limits: V3ManifestRepositoryLimits
  private let observer: any V3RecoveryRestoreJournalPhaseObserving

  init(
    configurationRoot: VaultRootDirectoryHandle,
    reservationOwnership: any V3ImmutableTransactionRecoveryAnchorStoring,
    preparationOwnership: any V3ImmutableTransactionRecoveryAnchorStoring,
    limits: V3ManifestRepositoryLimits = .standard,
    observer: any V3RecoveryRestoreJournalPhaseObserving = V3NoopRestoreJournalObserver(),
    writeObserver: any V3AtomicStagedObjectWriteObserving = V3NoopAtomicStagedObjectWriteObserver()
  ) {
    store = .init(rootHandle: configurationRoot, writeObserver: writeObserver)
    reservations = reservationOwnership
    preparations = preparationOwnership
    self.limits = limits
    self.observer = observer
  }

  /// Both namespaces are explicitly outside synchronization. Merely composing
  /// this internal journal writes no Keychain item or filesystem object.
  static func local(
    configurationRoot: VaultRootDirectoryHandle, configuration: RuntimeConfiguration
  ) -> Self {
    .init(
      configurationRoot: configurationRoot,
      reservationOwnership: V3ImmutableTransactionRecoveryAnchorKeychainStore(
        configuration: configuration, namespace: .restoreReservation),
      preparationOwnership: V3ImmutableTransactionRecoveryAnchorKeychainStore(
        configuration: configuration, namespace: .restorePreparation))
  }

  /// Must finish before any platform credential is created. No raw key or
  /// identity is needed. A returned reservation is not a restart permission.
  func reserve(
    environment: V3RecoveryRestoreEnvironment, snapshot: V3RecoveryVerifiedSnapshot,
    operationID: VaultTransactionOperationID, vaultID: String, transitionID: String,
    entryIDs: [String]
  ) throws -> V3RecoveryRestoreReservation {
    guard snapshot.entries.count <= limits.maximumReferencedEntryObjects else {
      throw V3RecoveryRestoreError.resourceLimit
    }
    let reservation = try V3RecoveryRestoreReservation(
      operationID: operationID, environment: environment, snapshot: snapshot,
      vaultID: vaultID, transitionID: transitionID, entryIDs: entryIDs)
    try reservation.locations.configuration.requireMatch(store.rootHandle)
    let sourceID = reservation.sourceAnchor.floor.vaultID
    guard try reservations.loadRecoveryAnchor(vaultID: sourceID) == nil,
      try preparations.loadRecoveryAnchor(vaultID: sourceID) == nil
    else { throw V3RecoveryRestoreJournalError.attemptPending }
    try environment.beginReservation()
    let pin = try ownership(reservation, bytes: reservation.canonicalBytes, phase: .prepared)
    try reservations.replaceRecoveryAnchor(
      pin.canonicalBytes, expectedAnchor: nil, vaultID: sourceID)
    try observer.didReach(.reservationPinned)
    try requirePins(reservation: pin, preparation: nil)
    try environment.requireSnapshot(snapshot)
    let path = reservationPath(operationID)
    try store.writeStagedObject(reservation.canonicalBytes, at: path)
    try observer.didReach(.reservationWritten)
    try requirePins(reservation: pin, preparation: nil)
    try environment.requireSnapshot(snapshot)
    try confirm(reservation.canonicalBytes, at: path, operationID: operationID)
    let durable = try ownership(reservation, bytes: reservation.canonicalBytes, phase: .recoverable)
    try requirePins(reservation: pin, preparation: nil)
    try environment.requireSnapshot(snapshot)
    try reservations.replaceRecoveryAnchor(
      durable.canonicalBytes, expectedAnchor: pin.canonicalBytes, vaultID: sourceID)
    try observer.didReach(.reservationDurable)
    try requirePins(reservation: durable, preparation: nil)
    guard
      try loadPending(sourceVaultID: sourceID)
        == .init(
          reservation: reservation, reservationOwnership: durable,
          preparation: nil, preparationOwnership: nil)
    else { throw V3RecoveryRestoreJournalError.invalidRecord }
    try environment.requireSnapshot(snapshot)
    return reservation
  }

  /// Requires the exact durable reservation, validates all plaintext/ciphertext
  /// before pinning complete bytes, then writes without overwrite. Once a
  /// preparation pin exists, use explicit confirmation, never stage anew.
  func stage(
    _ candidate: V3RecoveryRestoreCandidate, reservation: V3RecoveryRestoreReservation,
    environment: V3RecoveryRestoreEnvironment, vaultKey: Data,
    expectedOwner: V3EnrollmentDeviceIdentity
  ) throws -> V3RecoveryRestoreBundle {
    try environment.requireUnselectedConfiguration()
    let sourceID = reservation.sourceAnchor.floor.vaultID
    let pending = try requirePending(sourceID)
    guard pending.reservation == reservation, pending.reservationOwnership.phase == .recoverable,
      pending.preparationOwnership == nil
    else { throw V3RecoveryRestoreJournalError.attemptPending }
    try environment.requireCurrent(reservation.locations)
    try reservation.requireSnapshot(candidate.snapshot)
    _ = try environment.validateCandidate(
      candidate.publication, restoring: candidate.snapshot, vaultKey: vaultKey,
      expectedOwner: expectedOwner, limits: limits)
    let intent = try V3RecoveryRestoreIntent(
      operationID: reservation.operationID, candidate: candidate,
      environment: environment, destinationVaultKey: vaultKey)
    let bundle = try V3RecoveryRestoreBundle(intent: intent, candidate: candidate, limits: limits)
    try reservation.requireBundle(bundle)
    try requirePins(reservation: pending.reservationOwnership, preparation: nil)
    try environment.requireSnapshot(candidate.snapshot)
    let pin = try ownership(reservation, bytes: bundle.canonicalBytes, phase: .prepared)
    try preparations.replaceRecoveryAnchor(
      pin.canonicalBytes, expectedAnchor: nil, vaultID: sourceID)
    try observer.didReach(.preparationPinned)
    try requirePins(reservation: pending.reservationOwnership, preparation: pin)
    try environment.requireSnapshot(candidate.snapshot)
    try store.writeStagedObject(bundle.canonicalBytes, at: preparationPath(reservation.operationID))
    try observer.didReach(.preparationWritten)
    return try confirmPreparation(
      sourceVaultID: sourceID, snapshot: candidate.snapshot, environment: environment,
      vaultKey: vaultKey, expectedOwner: expectedOwner)
  }

  /// Only trusted local pins select records. Source/destination paths from the
  /// record are never opened here; no pin means no discovery or adoption.
  /// SHA checks happen before returning any candidate wrapper to a caller.
  func loadPending(sourceVaultID: String) throws -> V3RecoveryRestorePending? {
    guard isValidV3UUID(sourceVaultID) else { throw V3RecoveryRestoreJournalError.invalidOwnership }
    guard let bytes = try reservations.loadRecoveryAnchor(vaultID: sourceVaultID) else {
      guard try preparations.loadRecoveryAnchor(vaultID: sourceVaultID) == nil else {
        throw V3RecoveryRestoreJournalError.invalidOwnership
      }
      return nil
    }
    let pin = try decodePin(bytes, sourceVaultID: sourceVaultID)
    let raw = try read(
      reservationPath(pin.operationID), maximumBytes: V3RecoveryRestoreReservation.maximumBytes)
    guard Data(SHA256.hash(data: raw)) == pin.intentDigest else {
      throw V3RecoveryRestoreJournalError.invalidRecord
    }
    let reservation = try V3RecoveryRestoreReservation(canonicalBytes: raw)
    guard reservation.operationID == pin.operationID,
      reservation.sourceAnchor.floor.vaultID == sourceVaultID
    else { throw V3RecoveryRestoreJournalError.invalidRecord }
    try reservation.locations.configuration.requireMatch(store.rootHandle)
    let preparationPin: V3ImmutableTransactionRecoveryAnchor?
    let bundle: V3RecoveryRestoreBundle?
    if let bytes = try preparations.loadRecoveryAnchor(vaultID: sourceVaultID) {
      let next = try decodePin(bytes, sourceVaultID: sourceVaultID)
      guard pin.phase == .recoverable, next.operationID == pin.operationID else {
        throw V3RecoveryRestoreJournalError.invalidOwnership
      }
      let raw = try read(
        preparationPath(pin.operationID),
        maximumBytes: V3RecoveryRestoreBundle.maximumBytes(limits: limits))
      guard Data(SHA256.hash(data: raw)) == next.intentDigest else {
        throw V3RecoveryRestoreJournalError.invalidRecord
      }
      let parsed = try V3RecoveryRestoreBundle(canonicalBytes: raw, limits: limits)
      try reservation.requireBundle(parsed)
      bundle = parsed
      preparationPin = next
    } else {
      bundle = nil
      preparationPin = nil
    }
    try requirePins(reservation: pin, preparation: preparationPin)
    return .init(
      reservation: reservation, reservationOwnership: pin,
      preparation: bundle, preparationOwnership: preparationPin)
  }

  /// Preparation-only ownership is admissible ONLY for selected finalization,
  /// not normal preparation, publication, trust insertion or config selection.
  /// No pins means no discovery and no retrospective completion claim.
  func loadFinalization(sourceVaultID: String) throws -> V3RecoveryRestoreFinalizationState? {
    guard isValidV3UUID(sourceVaultID) else { throw V3RecoveryRestoreJournalError.invalidOwnership }
    if try reservations.loadRecoveryAnchor(vaultID: sourceVaultID) != nil {
      guard let pending = try loadPending(sourceVaultID: sourceVaultID),
        pending.reservationOwnership.phase == .recoverable,
        pending.preparationOwnership?.phase == .recoverable, pending.preparation != nil
      else { throw V3RecoveryRestoreJournalError.recordUnavailable }
      return .init(pending: pending, stage: .owned)
    }
    guard let bytes = try preparations.loadRecoveryAnchor(vaultID: sourceVaultID) else {
      try requireNoOwnership(sourceVaultID: sourceVaultID)
      return nil
    }
    let pin = try decodePin(bytes, sourceVaultID: sourceVaultID)
    guard pin.phase == .recoverable else { throw V3RecoveryRestoreJournalError.invalidOwnership }
    let raw = try read(
      preparationPath(pin.operationID),
      maximumBytes: V3RecoveryRestoreBundle.maximumBytes(limits: limits))
    guard Data(SHA256.hash(data: raw)) == pin.intentDigest else {
      throw V3RecoveryRestoreJournalError.invalidRecord
    }
    let bundle = try V3RecoveryRestoreBundle(canonicalBytes: raw, limits: limits)
    let reservation = try V3RecoveryRestoreReservation(pinnedBundle: bundle)
    guard reservation.operationID == pin.operationID,
      reservation.sourceAnchor.floor.vaultID == sourceVaultID
    else { throw V3RecoveryRestoreJournalError.invalidRecord }
    try reservation.locations.configuration.requireMatch(store.rootHandle)
    guard
      try read(
        reservationPath(pin.operationID), maximumBytes: V3RecoveryRestoreReservation.maximumBytes
      ) == reservation.canonicalBytes
    else { throw V3RecoveryRestoreJournalError.invalidRecord }
    let original = try ownership(
      reservation, bytes: reservation.canonicalBytes, phase: .recoverable)
    let state = V3RecoveryRestoreFinalizationState(
      pending: .init(
        reservation: reservation, reservationOwnership: original,
        preparation: bundle, preparationOwnership: pin), stage: .reservationCleared)
    try requireFinalizationOwnership(state)
    return state
  }

  /// Revalidates retained records and current source/candidate even after the
  /// first pin was cleared. Never writes a file or rearms an ownership record.
  func confirmFinalization(
    _ state: V3RecoveryRestoreFinalizationState, snapshot: V3RecoveryVerifiedSnapshot,
    environment: V3RecoveryRestoreEnvironment, vaultKey: Data,
    expectedOwner: V3EnrollmentDeviceIdentity
  ) throws -> V3RecoveryRestoreBundle {
    let pending = state.pending
    guard let bundle = pending.preparation,
      pending.reservationOwnership.phase == .recoverable,
      pending.preparationOwnership?.phase == .recoverable,
      environment.hasSelectedConfiguration
    else { throw V3RecoveryRestoreJournalError.invalidOwnership }
    try requireFinalizationOwnership(state)
    try environment.requireSelectionMatches(vaultID: bundle.intent.destinationCheckpoint.vaultID)
    try environment.requireCurrent(pending.reservation.locations)
    try pending.reservation.requireBundle(bundle)
    try pending.reservation.requireSnapshot(snapshot)
    try bundle.intent.authenticate(destinationVaultKey: vaultKey)
    let candidate = try environment.validateCandidate(
      bundle.publication(restoring: snapshot), restoring: snapshot, vaultKey: vaultKey,
      expectedOwner: expectedOwner, limits: limits)
    try bundle.intent.requireCandidate(candidate)
    try confirm(
      pending.reservation.canonicalBytes,
      at: reservationPath(pending.reservation.operationID),
      operationID: pending.reservation.operationID)
    try confirm(
      bundle.canonicalBytes,
      at: preparationPath(pending.reservation.operationID),
      operationID: pending.reservation.operationID)
    try requireFinalizationOwnership(state)
    try environment.requireSnapshot(snapshot)
    return bundle
  }

  /// The higher-level finalizer must freshly verify selected config, actual
  /// published contents, trust/cache and ordinary access before each removal.
  func clearFinalizationReservation(_ state: V3RecoveryRestoreFinalizationState) throws
    -> V3RecoveryRestoreFinalizationState
  {
    guard state.stage != .cleared else { throw V3RecoveryRestoreJournalError.invalidOwnership }
    try requireFinalizationOwnership(state)
    if state.stage == .owned {
      let pin = state.pending.reservationOwnership
      try reservations.replaceRecoveryAnchor(
        nil, expectedAnchor: pin.canonicalBytes, vaultID: pin.vaultID)
    }
    let next = V3RecoveryRestoreFinalizationState(
      pending: state.pending, stage: .reservationCleared)
    try requireFinalizationOwnership(next)
    return next
  }

  func clearFinalizationPreparation(_ state: V3RecoveryRestoreFinalizationState) throws
    -> V3RecoveryRestoreFinalizationState
  {
    guard state.stage == .reservationCleared, let pin = state.pending.preparationOwnership else {
      throw V3RecoveryRestoreJournalError.invalidOwnership
    }
    try requireFinalizationOwnership(state)
    try preparations.replaceRecoveryAnchor(
      nil, expectedAnchor: pin.canonicalBytes, vaultID: pin.vaultID)
    let next = V3RecoveryRestoreFinalizationState(pending: state.pending, stage: .cleared)
    try requireFinalizationOwnership(next)
    return next
  }

  private func requireFinalizationOwnership(_ state: V3RecoveryRestoreFinalizationState) throws {
    let pending = state.pending
    guard let preparation = pending.preparation, let pin = pending.preparationOwnership,
      pin.phase == .recoverable, pending.reservationOwnership.phase == .recoverable,
      pin.vaultID == pending.reservation.sourceAnchor.floor.vaultID,
      pin.vaultID == pending.reservationOwnership.vaultID,
      pin.operationID == pending.reservation.operationID,
      pending.reservationOwnership.operationID == pin.operationID,
      pin.intentDigest == Data(SHA256.hash(data: preparation.canonicalBytes)),
      pending.reservationOwnership.intentDigest
        == Data(SHA256.hash(data: pending.reservation.canonicalBytes)),
      try reservations.loadRecoveryAnchor(vaultID: pin.vaultID)
        == (state.stage == .owned ? pending.reservationOwnership.canonicalBytes : nil),
      try preparations.loadRecoveryAnchor(vaultID: pin.vaultID)
        == (state.stage == .cleared ? nil : pin.canonicalBytes)
    else { throw V3RecoveryRestoreJournalError.ownershipChanged }
  }

  private func requireNoOwnership(sourceVaultID: String) throws {
    guard try reservations.loadRecoveryAnchor(vaultID: sourceVaultID) == nil,
      try preparations.loadRecoveryAnchor(vaultID: sourceVaultID) == nil
    else { throw V3RecoveryRestoreJournalError.ownershipChanged }
  }

  /// Caller supplies freshly authenticated source snapshot and destination key.
  /// Reconstructs exact saved objects, never reruns encryption or key creation.
  /// Does not publish, open a credential, cache a key, or select configuration.
  func confirmPreparation(
    sourceVaultID: String, snapshot: V3RecoveryVerifiedSnapshot,
    environment: V3RecoveryRestoreEnvironment, vaultKey: Data,
    expectedOwner: V3EnrollmentDeviceIdentity
  ) throws -> V3RecoveryRestoreBundle {
    let pending = try requirePending(sourceVaultID)
    let reservation = pending.reservation
    guard pending.reservationOwnership.phase == .recoverable,
      let pin = pending.preparationOwnership, let bundle = pending.preparation
    else { throw V3RecoveryRestoreJournalError.recordUnavailable }
    try environment.requireCurrent(reservation.locations)
    try reservation.requireSnapshot(snapshot)
    try bundle.intent.authenticate(destinationVaultKey: vaultKey)
    let candidate = try environment.validateCandidate(
      bundle.publication(restoring: snapshot), restoring: snapshot,
      vaultKey: vaultKey, expectedOwner: expectedOwner, limits: limits)
    try bundle.intent.requireCandidate(candidate)
    try observer.didReach(.preparationVerified)
    try requirePins(reservation: pending.reservationOwnership, preparation: pin)
    try environment.requireSnapshot(snapshot)
    try confirm(
      reservation.canonicalBytes, at: reservationPath(pin.operationID), operationID: pin.operationID
    )
    try confirm(
      bundle.canonicalBytes, at: preparationPath(pin.operationID), operationID: pin.operationID)
    try requirePins(reservation: pending.reservationOwnership, preparation: pin)
    try environment.requireSnapshot(snapshot)
    let durable = try ownership(reservation, bytes: bundle.canonicalBytes, phase: .recoverable)
    if pin.phase == .prepared {
      try preparations.replaceRecoveryAnchor(
        durable.canonicalBytes, expectedAnchor: pin.canonicalBytes, vaultID: sourceVaultID)
    }
    try observer.didReach(.preparationDurable)
    try requirePins(reservation: pending.reservationOwnership, preparation: durable)
    guard
      try loadPending(sourceVaultID: sourceVaultID)
        == .init(
          reservation: reservation, reservationOwnership: pending.reservationOwnership,
          preparation: bundle, preparationOwnership: durable)
    else { throw V3RecoveryRestoreJournalError.invalidRecord }
    try environment.requireSnapshot(snapshot)
    return bundle
  }

  private func requirePending(_ sourceID: String) throws -> V3RecoveryRestorePending {
    guard let pending = try loadPending(sourceVaultID: sourceID) else {
      throw V3RecoveryRestoreJournalError.invalidOwnership
    }
    return pending
  }
  private func requirePins(
    reservation: V3ImmutableTransactionRecoveryAnchor,
    preparation: V3ImmutableTransactionRecoveryAnchor?
  ) throws {
    guard
      try reservations.loadRecoveryAnchor(vaultID: reservation.vaultID)
        == reservation.canonicalBytes,
      try preparations.loadRecoveryAnchor(vaultID: reservation.vaultID)
        == preparation?.canonicalBytes
    else { throw V3RecoveryRestoreJournalError.ownershipChanged }
  }
  private func ownership(
    _ reservation: V3RecoveryRestoreReservation, bytes: Data,
    phase: V3ImmutableTransactionRecoveryAnchorPhase
  ) throws -> V3ImmutableTransactionRecoveryAnchor {
    try .init(
      operationID: reservation.operationID, vaultID: reservation.sourceAnchor.floor.vaultID,
      intentDigest: Data(SHA256.hash(data: bytes)), phase: phase)
  }
  private func decodePin(_ bytes: Data, sourceVaultID: String) throws
    -> V3ImmutableTransactionRecoveryAnchor
  {
    guard bytes.count <= 1_024,
      let pin = try? V3ImmutableTransactionRecoveryAnchor(canonicalBytes: bytes),
      pin.vaultID == sourceVaultID
    else { throw V3RecoveryRestoreJournalError.invalidOwnership }
    return pin
  }
  private func read(_ path: String, maximumBytes: Int) throws -> Data {
    switch try store.readRecoveryObject(at: path, maximumBytes: maximumBytes) {
    case .available(let bytes): return bytes
    case .unavailable: throw V3RecoveryRestoreJournalError.recordUnavailable
    case .invalid: throw V3RecoveryRestoreJournalError.invalidRecord
    case .tooLarge: throw V3RecoveryRestoreError.resourceLimit
    }
  }
  private func confirm(_ bytes: Data, at path: String, operationID: VaultTransactionOperationID)
    throws
  {
    try store.confirmDurableRecoveryObject(
      bytes, at: path,
      directories: ["v3-restore-attempts/\(operationID)", "v3-restore-attempts"])
  }
  private func reservationPath(_ operationID: VaultTransactionOperationID) -> String {
    "v3-restore-attempts/\(operationID)/reservation.json"
  }
  private func preparationPath(_ operationID: VaultTransactionOperationID) -> String {
    "v3-restore-attempts/\(operationID)/preparation.json"
  }
}
