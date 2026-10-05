import CryptoKit
import Foundation

enum V3RecoveryRegistrationServiceError: Error, Equatable {
  case checkpointUnavailable
  case checkpointChanged
  case noPendingRegistration
  case pendingCandidateChanged
  case invalidPublishedObject
  case otherMutationPending
}

struct V3RecoveryRegistrationExport: Equatable, Sendable {
  let operationID: VaultTransactionOperationID
  let anchor: Data
  let recipientID: V3RecoveryRecipientID
}

struct V3RecoveryRegistrationCommit: Equatable, Sendable {
  let checkpoint: V3ManifestCheckpoint
  let alreadyActivated: Bool
  let cleanupPending: Bool
}

enum V3RecoveryRegistrationServicePhase: Equatable, Sendable {
  case candidatePrepared
  case exportPrepared
  case possessionVerified
  case artifactsStaged
  case entryPublished(index: Int)
  case entriesVerified
  case manifestPublished
  case manifestVerified
  case checkpointAdvanced
  case localSessionUpdated
  case ownershipCleared
}

protocol V3RecoveryRegistrationServicePhaseObserving: Sendable {
  func didReach(_ phase: V3RecoveryRegistrationServicePhase) throws
}

private struct V3NoopRegistrationServiceObserver: V3RecoveryRegistrationServicePhaseObserving {
  func didReach(_: V3RecoveryRegistrationServicePhase) throws {}
}

/// Internal helper workflow for an already-current experimental profile-3
/// checkpoint. No shipping dispatch, CLI/XPC route, adoption or hardware writer.
/// Current keys are scoped helper inputs, not caller-supplied CLI/XPC secrets.
/// The shared mutation owner spans each request; the native reader/agreement
/// adapter owns token leases and exactly one possession operation.
struct V3RecoveryRegistrationService: Sendable {
  private let vaultID: String
  private let identity: any V3EnrollmentMessageSigning & V3DeviceWrappedVaultKeyUnwrapping
  private let owner: any VaultTransactionMutationOwning
  private let objectStore: any V3ImmutableObjectPublishing & V3RecoveryRegistrationBundleStoring
  private let checkpointStore: any V3ManifestCheckpointStoring
  private let otherOwnership: [any V3ImmutableTransactionRecoveryAnchorStoring]
  private let journal: V3RecoveryRegistrationJournal
  private let repository: V3RecoveryRegistrationRepository
  private let reader: PIVRecoveryTokenReader
  private let agreement: PIVRecoveryAgreement
  private let validator: V3RecoveryRegistrationValidator
  private let limits: V3ManifestRepositoryLimits
  private let observer: any V3RecoveryRegistrationServicePhaseObserving

  init(
    vaultID: String,
    identity: any V3EnrollmentMessageSigning & V3DeviceWrappedVaultKeyUnwrapping,
    mutationOwner: any VaultTransactionMutationOwning,
    objectStore: any V3ImmutableObjectPublishing & V3RecoveryRegistrationBundleStoring,
    checkpointStore: any V3ManifestCheckpointStoring,
    registrationOwnershipStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    transactionOwnershipStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    adoptionOwnershipStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    reader: PIVRecoveryTokenReader, agreement: PIVRecoveryAgreement,
    limits: V3ManifestRepositoryLimits = .standard,
    observer: any V3RecoveryRegistrationServicePhaseObserving = V3NoopRegistrationServiceObserver()
  ) {
    self.vaultID = vaultID
    self.identity = identity
    owner = mutationOwner
    self.objectStore = objectStore
    self.checkpointStore = checkpointStore
    otherOwnership = [transactionOwnershipStore, adoptionOwnershipStore]
    journal = V3RecoveryRegistrationJournal(
      bundleStore: objectStore, ownershipStore: registrationOwnershipStore, limits: limits)
    repository = V3RecoveryRegistrationRepository(source: objectStore, limits: limits)
    self.reader = reader
    self.agreement = agreement
    validator = V3RecoveryRegistrationValidator(limits: limits)
    self.limits = limits
    self.observer = observer
  }

  func prepare(
    observation: PIVRecoveryTokenObservation, currentVaultKey: Data
  ) throws -> V3RecoveryRegistrationExport {
    try owner.perform(.registerRecoveryRecipient) { context in
      try requireNoOtherPending()
      guard try journal.loadPending(vaultID: vaultID) == nil else {
        throw V3RecoveryRegistrationJournalError.registrationPending
      }
      try reader.revalidate(observation)
      try observation.keyMetadata.requireRecoveryPolicy()
      guard observation.anchor == .absent else { throw V3RecoveryRegistrationError.occupiedAnchor }
      let checkpoint = try loadCheckpoint()
      let initial = try repository.observe(checkpoint: checkpoint, currentVaultKey: currentVaultKey)
      try validator.requireOwner(identity.publicIdentity, in: initial.base)
      try requireCheckpoint(checkpoint)
      let nextKey = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
      let preparation = try V3RecoveryRegistrationBuilder(limits: limits).prepare(
        checkpoint: checkpoint, parent: initial.base, currentEntries: initial.entries,
        currentVaultKey: currentVaultKey, nextVaultKey: nextKey,
        credential: observation.keyMetadata, occupancy: observation.anchor, owner: identity,
        reason: "Prepare Key vault recovery registration", operationID: context.operationID)
      try repository.requireProjectedUsage(initial, candidate: preparation)
      try observer.didReach(.candidatePrepared)
      try requireState(initial, checkpoint: checkpoint, currentKey: currentVaultKey)
      try reader.revalidate(observation)
      try requireCheckpoint(checkpoint)
      let bytes = try journal.stageAndExport(
        preparation, checkpoint: checkpoint, parent: initial.base, currentEntries: initial.entries,
        currentVaultKey: currentVaultKey, nextVaultKey: nextKey,
        expectedOwner: identity.publicIdentity)
      try observer.didReach(.exportPrepared)
      try requireState(initial, checkpoint: checkpoint, currentKey: currentVaultKey)
      try reader.revalidate(observation)
      try requireCheckpoint(checkpoint)
      return V3RecoveryRegistrationExport(
        operationID: preparation.intent.operationID, anchor: bytes,
        recipientID: preparation.intent.anchor.recipientID)
    }
  }

  /// Explicit resume/export never constructs a replacement or repeats a vendor
  /// write. The native record must be absent or this exact installed anchor.
  func resumeExport(
    observation: PIVRecoveryTokenObservation, currentVaultKey: Data
  ) throws -> V3RecoveryRegistrationExport {
    try owner.perform(.registerRecoveryRecipient) { _ in
      try requireNoOtherPending()
      let preparation = try pending()
      try requireCredential(observation, preparation: preparation, requireInstalled: false)
      let checkpoint = try loadCheckpoint()
      guard checkpoint == preparation.intent.expectedCheckpoint else {
        throw V3RecoveryRegistrationServiceError.checkpointChanged
      }
      let initial = try repository.observe(
        checkpoint: checkpoint, currentVaultKey: currentVaultKey, candidate: preparation)
      let nextKey = try openLocalCandidate(
        preparation, parent: initial.base, currentKey: currentVaultKey)
      try requireCheckpoint(checkpoint)
      let bytes = try journal.resumeAndExport(
        checkpoint: checkpoint, parent: initial.base, currentEntries: initial.entries,
        currentVaultKey: currentVaultKey, nextVaultKey: nextKey,
        expectedOwner: identity.publicIdentity)
      try requireState(
        initial, checkpoint: checkpoint, currentKey: currentVaultKey,
        preparation: preparation, nextKey: nextKey)
      try requirePending(preparation)
      try reader.revalidate(observation)
      try requireCheckpoint(checkpoint)
      return V3RecoveryRegistrationExport(
        operationID: preparation.intent.operationID, anchor: bytes,
        recipientID: preparation.intent.anchor.recipientID)
    }
  }

  @available(macOS 26.0, *)
  func finish(
    observation: PIVRecoveryTokenObservation, currentVaultKey: Data,
    cancellation: PIVRecoveryCancellation = PIVRecoveryCancellation(),
    deadline: DispatchTime = .now() + .seconds(60),
    afterCheckpointAdvance: (V3ManifestCheckpoint, Data) throws -> Void = { _, _ in }
  ) throws -> V3RecoveryRegistrationCommit {
    try owner.perform(.registerRecoveryRecipient) { _ in
      try requireNoOtherPending()
      try checkCancellation(cancellation)
      guard DispatchTime.now() < deadline else { throw PIVRecoveryAgreementError.deadlineExceeded }
      guard let preparation = try journal.loadPending(vaultID: vaultID) else {
        return try recognizeCompleted(
          observation: observation, cancellation: cancellation,
          afterCheckpointAdvance: afterCheckpointAdvance)
      }
      try requireCredential(observation, preparation: preparation, requireInstalled: true)
      let checkpoint = try loadCheckpoint()
      let candidateCheckpoint = try V3ManifestCheckpoint(
        vaultID: vaultID, envelopeDigest: preparation.candidate.digest)
      if checkpoint == candidateCheckpoint {
        return try reconcileCommitted(
          preparation, observation: observation, checkpoint: checkpoint,
          cancellation: cancellation, afterCheckpointAdvance: afterCheckpointAdvance)
      }
      guard checkpoint == preparation.intent.expectedCheckpoint else {
        throw V3RecoveryRegistrationServiceError.checkpointChanged
      }
      let initial = try repository.observe(
        checkpoint: checkpoint, currentVaultKey: currentVaultKey, candidate: preparation)
      try requireCheckpoint(checkpoint)
      return try agreement.withReceiver(
        observation: observation, cancellation: cancellation, deadline: deadline
      ) { receiver in
        try validator.withCompletionKey(
          preparation, checkpoint: checkpoint, parent: initial.base,
          currentEntries: initial.entries, currentVaultKey: currentVaultKey, identity: identity,
          credential: observation.keyMetadata, installedAnchor: preparation.intent.anchor,
          receiver: receiver, reason: "Complete Key vault recovery registration",
          validateBeforeAgreement: { nextKey in
            try checkCancellation(cancellation)
            guard DispatchTime.now() < deadline else {
              throw PIVRecoveryAgreementError.deadlineExceeded
            }
            try requirePending(preparation)
            try requireState(
              initial, checkpoint: checkpoint, currentKey: currentVaultKey,
              preparation: preparation, nextKey: nextKey)
            try reader.revalidate(observation)
          }
        ) { nextKey in
          try observer.didReach(.possessionVerified)
          try checkCancellation(cancellation)
          return try reader.withVerifiedObservation(observation) { revalidateToken in
            try activate(
              preparation, initial: initial, currentKey: currentVaultKey, nextKey: nextKey,
              cancellation: cancellation, revalidateToken: revalidateToken,
              afterCheckpointAdvance: afterCheckpointAdvance)
          }
        }
      }
    }
  }

  /// Lost replies after ownership cleanup cannot be resumed from a preparation.
  /// Recognize only the exact locally committed token floor and authenticated
  /// active recipient. This is status/session repair, not adoption from a token
  /// or a provider bundle, and performs no hardware agreement or publication.
  private func recognizeCompleted(
    observation: PIVRecoveryTokenObservation, cancellation: PIVRecoveryCancellation,
    afterCheckpointAdvance: (V3ManifestCheckpoint, Data) throws -> Void
  ) throws -> V3RecoveryRegistrationCommit {
    try reader.revalidate(observation)
    try observation.keyMetadata.requireRecoveryPolicy()
    let checkpoint = try loadCheckpoint()
    guard case .recognized(let anchor) = observation.anchor,
      anchor.floor.vaultID == vaultID,
      anchor.floor.envelopeDigest == checkpoint.envelopeDigest
    else { throw V3RecoveryRegistrationServiceError.noPendingRegistration }
    let bytes = try repository.readManifest(checkpoint.envelopeDigest)
    guard Data(SHA256.hash(data: bytes)) == checkpoint.envelopeDigest else {
      throw V3RecoveryRegistrationServiceError.invalidPublishedObject
    }
    let envelope = try V3RecoveryManifestCodec().parseEnvelope(bytes)
    try validator.requireOwner(identity.publicIdentity, in: envelope)
    guard identity.vaultID == vaultID, envelope.body.fields.vaultID == vaultID,
      envelope.body.recovery.recipients.contains(where: {
        $0.status == .active && $0.recipientID == anchor.recipientID
          && $0.registrationID == anchor.registrationID && $0.slot == anchor.slot
          && $0.publicKey == observation.publicKey
      }),
      let wrapped = envelope.body.fields.wrappedKeys.first(where: {
        $0.recipientDeviceID == identity.publicIdentity.deviceID
      })
    else { throw V3RecoveryRegistrationServiceError.noPendingRegistration }
    try requireCheckpoint(checkpoint)
    let key = try identity.unwrapDeviceWrappedVaultKey(
      wrapped.wrappedKey,
      context: envelope.body.deviceContext(recipientDeviceID: identity.publicIdentity.deviceID),
      reason: "Confirm completed Key recovery registration")
    try checkCancellation(cancellation)
    let state = try repository.observe(checkpoint: checkpoint, currentVaultKey: key)
    guard state.base == envelope, try journal.loadPending(vaultID: vaultID) == nil else {
      throw V3RecoveryRegistrationServiceError.pendingCandidateChanged
    }
    try requireState(state, checkpoint: checkpoint, currentKey: key)
    try reader.revalidate(observation)
    try requireCheckpoint(checkpoint)
    try afterCheckpointAdvance(checkpoint, key)
    return V3RecoveryRegistrationCommit(
      checkpoint: checkpoint, alreadyActivated: true, cleanupPending: false)
  }

  private func activate(
    _ preparation: V3RecoveryRegistrationPreparation,
    initial: V3RecoveryRegistrationRepositoryState,
    currentKey: Data, nextKey: Data, cancellation: PIVRecoveryCancellation,
    revalidateToken: () throws -> Void,
    afterCheckpointAdvance: (V3ManifestCheckpoint, Data) throws -> Void
  ) throws -> V3RecoveryRegistrationCommit {
    let checkpoint = preparation.intent.expectedCheckpoint
    let operation = preparation.intent.operationID
    try requireState(
      initial, checkpoint: checkpoint, currentKey: currentKey,
      preparation: preparation, nextKey: nextKey)
    try repository.requireProjectedUsage(initial, candidate: preparation)
    _ = try journal.resumeAndExport(
      checkpoint: checkpoint, parent: initial.base, currentEntries: initial.entries,
      currentVaultKey: currentKey, nextVaultKey: nextKey, expectedOwner: identity.publicIdentity)
    for entry in preparation.stagedEntries {
      try objectStore.stageEntry(
        entry.canonicalBytes, entryID: entry.context.entryID,
        digest: Data(SHA256.hash(data: entry.canonicalBytes)), operationID: operation)
    }
    try objectStore.stageManifest(
      preparation.candidate.canonicalBytes, digest: preparation.candidate.digest,
      operationID: operation)
    try observer.didReach(.artifactsStaged)
    try requireState(
      initial, checkpoint: checkpoint, currentKey: currentKey,
      preparation: preparation, nextKey: nextKey)
    try revalidateToken()
    try checkCancellation(cancellation)
    for (index, entry) in preparation.stagedEntries.enumerated() {
      try objectStore.publishStagedEntry(
        entry.canonicalBytes, entryID: entry.context.entryID,
        digest: Data(SHA256.hash(data: entry.canonicalBytes)), operationID: operation)
      try observer.didReach(.entryPublished(index: index))
    }
    try requirePublishedEntries(preparation)
    try observer.didReach(.entriesVerified)
    try requireState(
      initial, checkpoint: checkpoint, currentKey: currentKey,
      preparation: preparation, nextKey: nextKey)
    try requirePending(preparation)
    try revalidateToken()
    try checkCancellation(cancellation)
    try requirePublishedEntries(preparation)
    try requireCheckpoint(checkpoint)
    try objectStore.publishStagedManifest(
      preparation.candidate.canonicalBytes, digest: preparation.candidate.digest,
      operationID: operation)
    try observer.didReach(.manifestPublished)
    try requirePublishedManifest(preparation)
    try requirePublishedEntries(preparation)
    try observer.didReach(.manifestVerified)
    try requireCheckpoint(checkpoint)
    let published = try repository.observe(
      checkpoint: checkpoint, currentVaultKey: currentKey, candidate: preparation,
      nextVaultKey: nextKey)
    var expectedManifests = initial.manifestBytes
    let addedManifest =
      expectedManifests.updateValue(
        preparation.candidate.canonicalBytes, forKey: preparation.candidate.digest) == nil
    guard published.candidatePublished, published.manifestBytes == expectedManifests,
      published.listedObjectCount == initial.listedObjectCount + (addedManifest ? 1 : 0)
    else {
      throw V3RecoveryValidationError.sourceChanged
    }
    try readerCheck(revalidateToken, cancellation: cancellation)
    try requireCheckpoint(checkpoint)
    let next = try V3ManifestCheckpoint(
      vaultID: vaultID, envelopeDigest: preparation.candidate.digest)
    try checkpointStore.replaceCheckpoint(
      next.canonicalBytes, expectedCheckpoint: checkpoint.canonicalBytes, vaultID: vaultID)
    try observer.didReach(.checkpointAdvanced)
    try requireCheckpoint(next)
    try afterCheckpointAdvance(next, nextKey)
    try observer.didReach(.localSessionUpdated)
    let cleanupPending = try completeOwnership(preparation, checkpoint: next)
    return V3RecoveryRegistrationCommit(
      checkpoint: next, alreadyActivated: false, cleanupPending: cleanupPending)
  }

  /// A durable exact candidate checkpoint is already committed authority, not
  /// a saved hardware approval. Reauthenticate its local wrapper/current bytes
  /// and repair only local session/ownership state; never republish or agree.
  private func reconcileCommitted(
    _ preparation: V3RecoveryRegistrationPreparation, observation: PIVRecoveryTokenObservation,
    checkpoint: V3ManifestCheckpoint, cancellation: PIVRecoveryCancellation,
    afterCheckpointAdvance: (V3ManifestCheckpoint, Data) throws -> Void
  ) throws -> V3RecoveryRegistrationCommit {
    try validator.requireOwner(identity.publicIdentity, in: preparation.candidate)
    guard identity.vaultID == vaultID,
      identity.publicIdentity.deviceID == preparation.intent.ownerDeviceID,
      let wrapped = preparation.candidate.body.fields.wrappedKeys.first(where: {
        $0.recipientDeviceID == identity.publicIdentity.deviceID
      })
    else { throw V3RecoveryRegistrationError.invalidOwner }
    try requireCheckpoint(checkpoint)
    let nextKey = try identity.unwrapDeviceWrappedVaultKey(
      wrapped.wrappedKey,
      context: preparation.candidate.body.deviceContext(
        recipientDeviceID: identity.publicIdentity.deviceID),
      reason: "Reconcile committed Key recovery registration")
    try checkCancellation(cancellation)
    let state = try repository.observe(checkpoint: checkpoint, currentVaultKey: nextKey)
    guard state.base == preparation.candidate else {
      throw V3RecoveryRegistrationServiceError.invalidPublishedObject
    }
    try requirePublishedEntries(preparation)
    try requirePending(preparation)
    try requireState(state, checkpoint: checkpoint, currentKey: nextKey)
    try reader.revalidate(observation)
    try requireCheckpoint(checkpoint)
    try afterCheckpointAdvance(checkpoint, nextKey)
    try observer.didReach(.localSessionUpdated)
    let cleanupPending = try completeOwnership(preparation, checkpoint: checkpoint)
    return V3RecoveryRegistrationCommit(
      checkpoint: checkpoint, alreadyActivated: true, cleanupPending: cleanupPending)
  }

  private func completeOwnership(
    _ preparation: V3RecoveryRegistrationPreparation, checkpoint: V3ManifestCheckpoint
  ) throws -> Bool {
    try requireCheckpoint(checkpoint)
    do { try journal.clearCompleted(preparation) } catch { return true }
    try observer.didReach(.ownershipCleared)
    return false
  }

  private func pending() throws -> V3RecoveryRegistrationPreparation {
    guard let preparation = try journal.loadPending(vaultID: vaultID) else {
      throw V3RecoveryRegistrationServiceError.noPendingRegistration
    }
    return preparation
  }

  private func requirePending(_ preparation: V3RecoveryRegistrationPreparation) throws {
    guard try pending() == preparation else {
      throw V3RecoveryRegistrationServiceError.pendingCandidateChanged
    }
  }

  private func openLocalCandidate(
    _ preparation: V3RecoveryRegistrationPreparation, parent: V3RecoveryManifestEnvelope,
    currentKey: Data
  ) throws -> Data {
    try preparation.intent.authenticate(currentVaultKey: currentKey)
    try validator.requireOwner(identity.publicIdentity, in: parent)
    guard identity.vaultID == vaultID,
      identity.publicIdentity.deviceID == preparation.intent.ownerDeviceID,
      let wrapped = preparation.candidate.body.fields.wrappedKeys.first(where: {
        $0.recipientDeviceID == identity.publicIdentity.deviceID
      })
    else { throw V3RecoveryRegistrationError.invalidOwner }
    try V3RecoveryEpochBoundary().verifyBoundary(preparation.candidate, parent: parent)
    try requireNoOtherPending()
    return try identity.unwrapDeviceWrappedVaultKey(
      wrapped.wrappedKey,
      context: preparation.candidate.body.deviceContext(
        recipientDeviceID: identity.publicIdentity.deviceID),
      reason: "Resume Key vault recovery registration preparation")
  }

  private func requireCredential(
    _ observation: PIVRecoveryTokenObservation, preparation: V3RecoveryRegistrationPreparation,
    requireInstalled: Bool
  ) throws {
    try reader.revalidate(observation)
    try observation.keyMetadata.requireRecoveryPolicy()
    guard observation.publicKey == preparation.intent.publicKey,
      observation.anchor == .recognized(preparation.intent.anchor)
        || (!requireInstalled && observation.anchor == .absent)
    else { throw V3RecoveryRegistrationError.anchorMismatch }
  }

  private func loadCheckpoint() throws -> V3ManifestCheckpoint {
    guard let data = try checkpointStore.loadCheckpoint(vaultID: vaultID), data.count <= 1_024,
      let checkpoint = try? V3ManifestCheckpoint(canonicalBytes: data),
      checkpoint.vaultID == vaultID
    else { throw V3RecoveryRegistrationServiceError.checkpointUnavailable }
    return checkpoint
  }

  // Durable pending-state guards complement, not replace, the shared mutation
  // owner. Check both namespaces around the exact checkpoint read at effects.
  private func requireCheckpoint(_ checkpoint: V3ManifestCheckpoint) throws {
    try requireNoOtherPending()
    guard try loadCheckpoint() == checkpoint else {
      throw V3RecoveryRegistrationServiceError.checkpointChanged
    }
    try requireNoOtherPending()
  }

  private func requireNoOtherPending() throws {
    for store in otherOwnership where try store.loadRecoveryAnchor(vaultID: vaultID) != nil {
      throw V3RecoveryRegistrationServiceError.otherMutationPending
    }
  }

  private func requireState(
    _ expected: V3RecoveryRegistrationRepositoryState, checkpoint: V3ManifestCheckpoint,
    currentKey: Data, preparation: V3RecoveryRegistrationPreparation? = nil, nextKey: Data? = nil
  ) throws {
    try requireCheckpoint(checkpoint)
    guard
      try repository.observe(
        checkpoint: checkpoint, currentVaultKey: currentKey,
        candidate: preparation, nextVaultKey: nextKey) == expected
    else { throw V3RecoveryValidationError.sourceChanged }
    try requireCheckpoint(checkpoint)
  }

  private func requirePublishedManifest(_ preparation: V3RecoveryRegistrationPreparation) throws {
    guard
      try repository.readManifest(preparation.candidate.digest)
        == preparation.candidate.canonicalBytes
    else {
      throw V3RecoveryRegistrationServiceError.invalidPublishedObject
    }
  }

  private func requirePublishedEntries(_ preparation: V3RecoveryRegistrationPreparation) throws {
    for entry in preparation.stagedEntries {
      let key = V3EntryObjectKey(
        entryID: entry.context.entryID, digest: Data(SHA256.hash(data: entry.canonicalBytes)))
      guard try repository.readEntry(key) == entry.canonicalBytes else {
        throw V3RecoveryRegistrationServiceError.invalidPublishedObject
      }
    }
  }

  private func checkCancellation(_ cancellation: PIVRecoveryCancellation) throws {
    guard !cancellation.isCancelled else { throw PIVRecoveryAgreementError.cancelled }
  }

  private func readerCheck(_ revalidate: () throws -> Void, cancellation: PIVRecoveryCancellation)
    throws
  {
    try checkCancellation(cancellation)
    try revalidate()
    try requireNoOtherPending()
  }
}
