import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Restart with the actual random-key service's exact durable bytes and an empty
/// session. Mac private operations use software keys; no PIV operation is involved.
struct V3RecoveryKeyRotationRecoveryTests {
  private typealias Core = V3RecoveryRegistrationTests
  private typealias Fixture = V3RecoveryContentMutationPublisherTests.Fixture
  private typealias Stop = V3RecoveryContentMutationPublisherTests.Stop
  private static let phases: [V3ImmutableTransactionPhase] = [
    .recoveryAnchorPrepared, .recoveryIntentPersisted, .recoveryArmed,
    .entryStaged(index: 0), .entryStaged(index: 1), .manifestStaged,
    .repositoryStateRechecked, .entryPublished(index: 0), .entryPublished(index: 1),
    .publishedEntriesValidated, .manifestPublished, .publishedManifestValidated,
    .checkpointAdvanced, .cleanupCompleted,
  ]

  @Test(arguments: 0..<14)
  func freshSessionRestartsEveryPublicationBoundaryWithoutSigningAgain(phase: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    try interrupt(f, phase: Self.phases[phase])
    let session = V3DeviceWrappedVaultKeySessionStore()
    let s = service(f, session: session)
    let outcome = try VaultTransactionMutationOwner().perform(.recoverInterruptedTransaction) { c in
      try s.recoverInterruptedRotation(operationID: c.operationID)
    }
    if phase < 5 {
      #expect(outcome == .abandoned(operationID: f.operationID))
      #expect(f.checkpoints.value == f.checkpoint.canonicalBytes && !session.hasResidentKey)
      #expect(f.core.owner.unwraps == 1)
    } else if phase == 13 {
      #expect(outcome == .nothingToRecover && !session.hasResidentKey)
      #expect(f.core.owner.unwraps == 1)
    } else {
      #expect(
        outcome
          == (phase == 12
            ? .alreadyCompleted(operationID: f.operationID)
            : .completed(operationID: f.operationID)))
      let current = try current(f)
      let key = try session.load(vaultID: Core.vaultID, keyID: current.envelope.body.fields.keyID)
      #expect(key != Core.nextKey && key.count == 32)
      #expect(current.envelope.body.recovery.recipients == f.parent.body.recovery.recipients)
      #expect(current.envelope.body.recovery.generationID == f.parent.body.recovery.generationID)
      #expect(f.core.owner.unwraps == (phase == 12 ? 2 : 3))
      let ordinary = V3RecoveryVaultMutationService(
        vaultID: Core.vaultID, session: session, objectStore: f.store,
        checkpointStore: f.checkpoints,
        recoveryAnchorStore: f.ownership, registrationAnchorStore: f.registration,
        adoptionAnchorStore: f.adoption, cache: f.cache)
      try ordinary.add(
        name: "after/restart", secret: "recovered", type: .secret, operationID: .init())
      #expect(try self.current(f).envelope.body.fields.keyID == current.envelope.body.fields.keyID)
    }
    #expect(f.ownership.value == nil && f.core.owner.signatures == 2)
  }

  @Test func committedRestartNeedsNoOldCiphertextManifestOrCache() throws {
    let f = try Fixture()
    defer { f.remove() }
    try interrupt(f, phase: .checkpointAdvanced)
    let checkpoint = f.checkpoints.value
    for entry in Array(f.entries.values) + Array(f.core.entries.values) {
      try FileManager.default.removeItem(at: f.entryURL(entry))
    }
    try FileManager.default.removeItem(at: f.manifestURL(f.parent.digest))
    try FileManager.default.removeItem(at: f.manifestURL(f.core.parent.digest))
    try FileManager.default.removeItem(
      at: f.cacheRoot.appendingPathComponent("\(Core.vaultID).json"))
    let session = V3DeviceWrappedVaultKeySessionStore()
    #expect(
      try service(f, session: session).recoverInterruptedRotation(operationID: .init())
        == .alreadyCompleted(operationID: f.operationID))
    #expect(f.checkpoints.value == checkpoint && f.ownership.value == nil)
    #expect(session.hasResidentKey && f.core.owner.unwraps == 2 && f.core.owner.signatures == 2)
  }

  @Test(arguments: [false, true])
  func warmExactSessionReusesOnlyItsMatchingKey(committed: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let session = try unlocked(f)
    if committed {
      f.ownership.rejectClear = true
      _ = try service(f, session: session).rotate(
        expectedCheckpoint: f.checkpoint, operationID: f.operationID)
      f.ownership.rejectClear = false
    } else {
      try interrupt(f, phase: .manifestStaged, session: session)
    }
    let before = f.core.owner.unwraps
    let outcome = try service(f, session: session).recoverInterruptedRotation(operationID: .init())
    #expect(
      outcome
        == (committed
          ? .alreadyCompleted(operationID: f.operationID) : .completed(operationID: f.operationID)))
    #expect(f.core.owner.unwraps == before + (committed ? 0 : 1))
    #expect(session.hasResidentKey && f.ownership.value == nil && f.core.owner.signatures == 2)
  }

  @Test(arguments: [1, 2])
  func cancellationAtEitherColdWrapperPreservesPinnedWorkWithoutRetry(operation: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    try interrupt(f, phase: .manifestStaged)
    let pending = f.ownership.value
    f.core.owner.onUnwrap = {
      if f.core.owner.unwraps == 1 + operation { f.core.owner.cancelUnwrap = true }
    }
    let session = V3DeviceWrappedVaultKeySessionStore()
    #expect(throws: Core.FixtureError.cancelled) {
      try service(f, session: session).recoverInterruptedRotation(operationID: .init())
    }
    #expect(f.ownership.value == pending && f.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(
      !session.hasResidentKey && f.core.owner.unwraps == 1 + operation
        && f.core.owner.signatures == 2)
    f.core.owner.cancelUnwrap = false
    f.core.owner.onUnwrap = {}
    #expect(
      try service(f, session: session).recoverInterruptedRotation(operationID: .init())
        == .completed(operationID: f.operationID))
  }

  @Test(arguments: [1, 2])
  func explicitLockDuringAuthenticationStopsBeforeAnotherOperationOrCommit(operation: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    try interrupt(f, phase: .manifestStaged)
    let pending = f.ownership.value
    let session = V3DeviceWrappedVaultKeySessionStore()
    f.core.owner.onUnwrap = { if f.core.owner.unwraps == 1 + operation { session.invalidate() } }
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
      try service(f, session: session).recoverInterruptedRotation(operationID: .init())
    }
    #expect(!session.hasResidentKey && f.ownership.value == pending)
    #expect(
      f.checkpoints.value == f.checkpoint.canonicalBytes && f.core.owner.unwraps == 1 + operation)
  }

  @Test(arguments: 0..<5)
  func changesDuringOldWrapperRefuseBeforeOpeningNewWrapper(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    try interrupt(f, phase: .manifestStaged)
    let pending = f.ownership.value
    let branch = try f.build(.remove(name: "fixture/totp"))
    f.core.owner.onUnwrap = {
      switch variant {
      case 0: f.registration.value = Data([1])
      case 1: f.adoption.value = Data([1])
      case 2: f.ownership.value = Data([1])
      case 3: f.checkpoints.value = Data([1])
      default: try f.seed(branch.envelope, entries: branch.stagedEntries)
      }
    }
    let session = V3DeviceWrappedVaultKeySessionStore()
    #expect(throws: (any Error).self) {
      try service(f, session: session).recoverInterruptedRotation(operationID: .init())
    }
    #expect(f.core.owner.unwraps == 2 && f.core.owner.signatures == 2 && !session.hasResidentKey)
    if variant != 2 { #expect(f.ownership.value == pending) }
    if variant != 3 { #expect(f.checkpoints.value == f.checkpoint.canonicalBytes) }
  }

  @Test(arguments: 0..<4)
  func invalidPendingSourceOrOwnerRefusesBeforePrivateOperations(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    try interrupt(f, phase: .manifestStaged)
    let pending = f.ownership.value
    if variant == 0 { f.registration.value = Data([1]) }
    if variant == 1 { f.adoption.value = Data([1]) }
    if variant == 2 {
      try FileManager.default.removeItem(at: f.entryURL(try #require(f.entries.values.first)))
    }
    let identity = variant == 3 ? try Core.Owner() : f.core.owner
    let session = V3DeviceWrappedVaultKeySessionStore()
    #expect(throws: (any Error).self) {
      try service(f, session: session, identity: identity).recoverInterruptedRotation(
        operationID: .init())
    }
    #expect(f.ownership.value == pending && f.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(f.core.owner.unwraps == 1 && !session.hasResidentKey)
    if variant == 3 { #expect(identity.unwraps == 0) }
  }

  @Test(arguments: [1, 2, 3])
  func selectedAndProjectedObjectBudgetsRefuseBeforeAuthentication(count: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    try interrupt(f, phase: .manifestStaged)
    let pending = f.ownership.value
    let limits: V3ManifestRepositoryLimits
    if count == 3 {
      let total = try ready(f).availableEntries.reduce(0) { $0 + $1.canonicalBytes.count }
      limits = Core.Fixture.limits(totalBytes: total - 1)
    } else {
      limits = Core.Fixture.limits(entries: count)
    }
    #expect(throws: (any Error).self) {
      try service(f, session: .init(), limits: limits)
        .recoverInterruptedRotation(operationID: .init())
    }
    #expect(f.core.owner.unwraps == 1 && f.ownership.value == pending)
  }

  @Test func ordinaryPendingIntentCannotRouteAsRotationEvenWhenCheckpointChanged() throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try f.build(.remove(name: "fixture/totp"))
    #expect(throws: Stop.interrupted) {
      try f.publisher(observer: Observer { if $0 == .manifestStaged { throw Stop.interrupted } })
        .publish(candidate, vaultKey: Core.nextKey)
    }
    let pending = f.ownership.value
    f.checkpoints.value = Data([1])
    #expect(throws: (any Error).self) {
      try service(f, session: .init()).recoverInterruptedRotation(operationID: .init())
    }
    #expect(
      f.ownership.value == pending && f.core.owner.unwraps == 0 && f.core.owner.signatures == 1)
  }

  @Test func incompletePublishedSnapshotWaitsWithoutAuthenticationUntilExactBytesReturn() throws {
    let f = try Fixture()
    defer { f.remove() }
    try interrupt(f, phase: .manifestPublished)
    let state = try ready(f)
    let entry = try #require(state.availableEntries.first)
    try FileManager.default.removeItem(at: f.entryURL(entry))
    let pending = f.ownership.value
    let session = V3DeviceWrappedVaultKeySessionStore()
    #expect(throws: V3ImmutableTransactionRecoveryError.transactionDirectoryUnavailable) {
      try service(f, session: session).recoverInterruptedRotation(operationID: .init())
    }
    #expect(f.ownership.value == pending && f.core.owner.unwraps == 1 && !session.hasResidentKey)
    let address = V3EntryObjectKey(
      entryID: entry.context.entryID, digest: Data(SHA256.hash(data: entry.canonicalBytes)))
    try f.store.stageEntry(
      entry.canonicalBytes, entryID: address.entryID, digest: address.digest,
      operationID: f.operationID)
    try f.store.publishStagedEntry(
      entry.canonicalBytes, entryID: address.entryID, digest: address.digest,
      operationID: f.operationID)
    #expect(
      try service(f, session: session).recoverInterruptedRotation(operationID: .init())
        == .completed(operationID: f.operationID))
    #expect(session.hasResidentKey && f.core.owner.unwraps == 3 && f.core.owner.signatures == 2)
  }

  @Test func failedResumeCheckpointCASLocksAndRetainsExactCandidateForNextRestart() throws {
    let f = try Fixture()
    defer { f.remove() }
    try interrupt(f, phase: .manifestStaged)
    let pending = f.ownership.value
    let candidate = try ready(f).manifestData
    f.checkpoints.rejectAdvance = true
    let session = V3DeviceWrappedVaultKeySessionStore()
    #expect(throws: Stop.interrupted) {
      try service(f, session: session).recoverInterruptedRotation(operationID: .init())
    }
    #expect(
      f.ownership.value == pending && f.checkpoints.value == f.checkpoint.canonicalBytes
        && !session.hasResidentKey)
    f.checkpoints.rejectAdvance = false
    #expect(
      try service(f, session: session).recoverInterruptedRotation(operationID: .init())
        == .completed(operationID: f.operationID))
    #expect(try current(f).envelope.canonicalBytes == candidate && f.core.owner.signatures == 2)
  }

  @Test func cleanupFailureAfterResumeCommitLocksThenRequiresOnlyNewWrapper() throws {
    let f = try Fixture()
    defer { f.remove() }
    try interrupt(f, phase: .manifestStaged)
    let pending = f.ownership.value
    let session = V3DeviceWrappedVaultKeySessionStore()
    f.ownership.rejectClear = true
    #expect(throws: Stop.interrupted) {
      try service(f, session: session).recoverInterruptedRotation(operationID: .init())
    }
    #expect(
      f.ownership.value == pending && f.checkpoints.value != f.checkpoint.canonicalBytes
        && !session.hasResidentKey)
    f.ownership.rejectClear = false
    #expect(
      try service(f, session: session).recoverInterruptedRotation(operationID: .init())
        == .alreadyCompleted(operationID: f.operationID))
    #expect(f.core.owner.unwraps == 4 && f.core.owner.signatures == 2 && session.hasResidentKey)
  }

  @Test func malformedCandidateRefusesBeforeAuthenticationAndRetainsLocalPin() throws {
    let f = try Fixture()
    defer { f.remove() }
    let data = Data("{}".utf8)
    let digest = Data(SHA256.hash(data: data))
    let intent = try V3ImmutableTransactionRecoveryIntent(
      operationID: f.operationID, kind: .rotateVaultKey,
      vaultID: Core.vaultID, expectedCheckpoint: f.checkpoint,
      expectedHeads: [f.checkpoint.envelopeDigest],
      candidateManifestDigest: digest, stagedEntries: [])
    try f.store.persistRecoveryIntent(intent.canonicalBytes, operationID: f.operationID)
    try f.store.stageManifest(data, digest: digest, operationID: f.operationID)
    f.ownership.value = try V3ImmutableTransactionRecoveryAnchor(
      operationID: f.operationID, vaultID: Core.vaultID,
      intentDigest: Data(SHA256.hash(data: intent.canonicalBytes)), phase: .recoverable
    ).canonicalBytes
    let pending = f.ownership.value
    #expect(throws: (any Error).self) {
      try service(f, session: .init()).recoverInterruptedRotation(operationID: .init())
    }
    #expect(
      f.ownership.value == pending && f.core.owner.unwraps == 0 && f.core.owner.signatures == 1)
  }

  @Test(arguments: [1, 2])
  func providerResultsAuthenticateBeforeAnotherPrivateOperationOrCommit(operation: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    try interrupt(f, phase: .manifestStaged)
    let pending = f.ownership.value
    let identity = ResultIdentity(base: f.core.owner, incorrectOperation: operation + 1)
    let session = V3DeviceWrappedVaultKeySessionStore()
    #expect(throws: (any Error).self) {
      try service(f, session: session, identity: identity).recoverInterruptedRotation(
        operationID: .init())
    }
    #expect(f.ownership.value == pending && f.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(
      !session.hasResidentKey && f.core.owner.unwraps == 1 + operation
        && f.core.owner.signatures == 2)
  }

  @Test(arguments: 0..<3)
  func changesAfterResumeCommitCannotInstallAStaleOrLockedSession(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    try interrupt(f, phase: .manifestStaged)
    let state = try ready(f)
    let entry = try #require(state.availableEntries.first)
    let session = V3DeviceWrappedVaultKeySessionStore()
    let checkpoints = ObservedCheckpoints(base: f.checkpoints) {
      switch variant {
      case 0: try FileManager.default.removeItem(at: f.entryURL(entry))
      case 1: session.invalidate()
      default: f.registration.value = Data([1])
      }
    }
    #expect(throws: (any Error).self) {
      try service(f, session: session, checkpoints: checkpoints).recoverInterruptedRotation(
        operationID: .init())
    }
    #expect(
      f.checkpoints.value == state.candidateCheckpoint.canonicalBytes && !session.hasResidentKey)
    #expect((f.ownership.value != nil) == (variant == 2))
    #expect(f.core.owner.unwraps == 3 && f.core.owner.signatures == 2)
  }

  private func interrupt(
    _ f: Fixture, phase: V3ImmutableTransactionPhase,
    session: V3DeviceWrappedVaultKeySessionStore? = nil
  ) throws {
    let active = try session ?? unlocked(f)
    #expect(throws: Stop.interrupted) {
      try service(
        f, session: active, observer: Observer { if $0 == phase { throw Stop.interrupted } }
      ).rotate(
        expectedCheckpoint: f.checkpoint, operationID: f.operationID)
    }
  }
  private func unlocked(_ f: Fixture) throws -> V3DeviceWrappedVaultKeySessionStore {
    let session = V3DeviceWrappedVaultKeySessionStore()
    try session.install(Core.nextKey, vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID)
    return session
  }
  private func service(
    _ f: Fixture, session: V3DeviceWrappedVaultKeySessionStore,
    identity: V3RecoveryKeyRotationService.Identity? = nil,
    checkpoints: (any V3ManifestCheckpointStoring)? = nil,
    limits: V3ManifestRepositoryLimits = .standard,
    observer: any V3ImmutableTransactionPhaseObserving = V3NoopContentTransactionPhaseObserver()
  ) -> V3RecoveryKeyRotationService {
    .init(
      vaultID: Core.vaultID, identity: identity ?? f.core.owner, session: session,
      objectStore: f.store, checkpointStore: checkpoints ?? f.checkpoints,
      recoveryAnchorStore: f.ownership,
      registrationAnchorStore: f.registration, adoptionAnchorStore: f.adoption, cache: f.cache,
      limits: limits, phaseObserver: observer)
  }
  private func ready(_ f: Fixture) throws -> V3ContentTransactionRecoveryState {
    let publisher = V3RecoveryKeyRotationPublisher(
      mutationOwner: DirectVaultTransactionMutationOwner(operationID: .init()),
      objectStore: f.store, checkpointStore: f.checkpoints, recoveryAnchorStore: f.ownership,
      registrationAnchorStore: f.registration, adoptionAnchorStore: f.adoption, cache: f.cache)
    guard
      case .ready(let state) = try publisher.prepareInterruptedTransaction(
        vaultID: Core.vaultID, expectedOwner: f.core.owner.publicIdentity)
    else { throw Stop.interrupted }
    return state
  }
  private func current(_ f: Fixture) throws -> V3RecoveryKeyRotationCommit {
    let checkpoint = try V3ManifestCheckpoint(canonicalBytes: #require(f.checkpoints.value))
    return .init(
      checkpoint: checkpoint,
      envelope: try V3RecoveryManifestCodec().parseEnvelope(
        Data(contentsOf: f.manifestURL(checkpoint.envelopeDigest))))
  }
  private struct Observer: V3ImmutableTransactionPhaseObserving {
    let action: @Sendable (V3ImmutableTransactionPhase) throws -> Void
    init(_ action: @escaping @Sendable (V3ImmutableTransactionPhase) throws -> Void) {
      self.action = action
    }
    func didReach(_ phase: V3ImmutableTransactionPhase, operationID _: VaultTransactionOperationID)
      throws
    { try action(phase) }
  }

  private struct ResultIdentity: V3EnrollmentMessageSigning, V3DeviceWrappedVaultKeyUnwrapping {
    let base: Core.Owner
    let incorrectOperation: Int
    var vaultID: String { base.vaultID }
    var publicIdentity: V3EnrollmentDeviceIdentity { base.publicIdentity }
    func signature(for input: Data, reason: String) throws -> Data {
      try base.signature(for: input, reason: reason)
    }
    func unwrapDeviceWrappedVaultKey(
      _ wrappedKey: V3HPKEWrappedVaultKey, context: V3VaultKeyHPKEContext, reason: String
    ) throws -> Data {
      let key = try base.unwrapDeviceWrappedVaultKey(wrappedKey, context: context, reason: reason)
      return base.unwraps == incorrectOperation ? Data(repeating: 0, count: 32) : key
    }
  }
  private struct ObservedCheckpoints: V3ManifestCheckpointStoring {
    let base: V3RecoveryContentMutationPublisherTests.Checkpoints
    let action: @Sendable () throws -> Void
    func loadCheckpoint(vaultID: String) throws -> Data? {
      try base.loadCheckpoint(vaultID: vaultID)
    }
    func replaceCheckpoint(_ checkpoint: Data, expectedCheckpoint: Data?, vaultID: String) throws {
      try base.replaceCheckpoint(
        checkpoint, expectedCheckpoint: expectedCheckpoint, vaultID: vaultID)
      try action()
    }
  }
}
