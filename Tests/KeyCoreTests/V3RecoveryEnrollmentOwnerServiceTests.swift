import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Actual random-key service, signed ceremonies, session guards and contained
/// filesystem publication. Private operations use only owned software keys.
struct V3RecoveryEnrollmentOwnerServiceTests {
  private typealias Core = V3RecoveryRegistrationTests
  private typealias Publication = V3RecoveryContentMutationPublisherTests
  private typealias Fixture = V3RecoveryDeviceEnrollmentPublisherTests.Fixture
  private typealias Stop = Publication.Stop
  private static let now: UInt64 = 4_102_444_800
  private static let phases: [V3ImmutableTransactionPhase] = [
    .recoveryAnchorPrepared, .recoveryIntentPersisted, .recoveryArmed,
    .entryStaged(index: 0), .entryStaged(index: 1), .manifestStaged,
    .repositoryStateRechecked, .entryPublished(index: 0), .entryPublished(index: 1),
    .publishedEntriesValidated, .manifestPublished, .publishedManifestValidated,
    .checkpointAdvanced, .cleanupCompleted,
  ]

  @Test func prepareAuthenticatesExactComparisonAndSnapshotWithoutPrivateOperations() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let session = try unlocked(f)
    let review = try service(f, session).prepare(
      invitationDigest: f.state.invitationDigest, at: Self.now)
    #expect(review.checkpoint == f.disk.checkpoint && review.transcript == f.state.transcript)
    #expect(f.disk.core.owner.signatures == f.signatures && f.disk.core.owner.unwraps == 0)
    #expect(try f.savedState().phase == .awaitingComparison && f.disk.ownership.value == nil)
  }

  @Test(arguments: [false, true])
  func approvedAdditionInstallsFreshKeyAndContinuesOrdinarySaving(empty: Bool) throws {
    let f = try Fixture(empty: empty)
    defer { f.disk.remove() }
    let session = try unlocked(f)
    let s = service(f, session)
    let review = try s.prepare(invitationDigest: f.state.invitationDigest, at: Self.now)
    let owner = VaultTransactionMutationOwner()
    let commit = try owner.perform(.enrollDevice) { context in
      try s.approve(
        invitationDigest: f.state.invitationDigest,
        approvedTranscriptDigest: review.transcript.digest,
        expectedCheckpoint: review.checkpoint, at: Self.now, operationID: context.operationID)
    }
    let key = try session.load(vaultID: Core.vaultID, keyID: commit.envelope.body.fields.keyID)
    #expect(key.count == 32 && key != Core.nextKey)
    #expect(try f.savedState().phase == .consumed && f.disk.ownership.value == nil)
    #expect(f.disk.checkpoints.value == commit.checkpoint.canonicalBytes)
    #expect(commit.envelope.body.recovery.recipients == f.disk.parent.body.recovery.recipients)
    #expect(commit.envelope.body.recovery.generationID == f.disk.parent.body.recovery.generationID)
    let wrapper = try #require(
      commit.envelope.body.fields.wrappedKeys.first {
        $0.recipientDeviceID == f.joiner.publicIdentity.deviceID
      })
    #expect(
      try V3VaultKeyHPKE().unwrap(
        wrapper.wrappedKey, recipientPrivateKey: f.joiner.wrappingKey,
        context: commit.envelope.body.deviceContext(
          recipientDeviceID: f.joiner.publicIdentity.deviceID)) == key)
    try ordinary(f, session).add(
      name: "after/owner", secret: "continued", type: .secret, operationID: .init())
    #expect(try current(f).body.fields.keyID == commit.envelope.body.fields.keyID)
    #expect(f.disk.core.owner.signatures == f.signatures + 1 && f.disk.core.owner.unwraps == 1)
    #expect(f.joiner.unwraps == 0 && f.joiner.signatures == 1)
  }

  @Test(arguments: 0..<14)
  func allBoundariesRestartExactRandomEpochAndNeverRepeatComparisonOrSigning(phase: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let old = try unlocked(f)
    try interrupt(f, old, phase: Self.phases[phase])
    if phase < 12 {
      #expect(
        try old.load(vaultID: Core.vaultID, keyID: f.disk.parent.body.fields.keyID) == Core.nextKey)
    } else {
      #expect(!old.hasResidentKey)
    }
    let selected = phase >= 5 && phase < 13 ? try ready(f) : nil
    let session = V3DeviceWrappedVaultKeySessionStore()
    let outcome = try service(f, session).recoverInterruptedEnrollment(
      invitationDigest: f.state.invitationDigest, operationID: .init())
    if phase < 5 {
      #expect(outcome == .abandoned(operationID: f.disk.operationID) && !session.hasResidentKey)
      #expect(try f.savedState().phase == .awaitingComparison && f.disk.core.owner.unwraps == 1)
    } else if phase == 13 {
      #expect(
        outcome == .nothingToRecover && !session.hasResidentKey && f.disk.core.owner.unwraps == 1)
    } else {
      #expect(
        outcome
          == (phase == 12
            ? .alreadyCompleted(operationID: f.disk.operationID)
            : .completed(operationID: f.disk.operationID)))
      let envelope = try current(f)
      #expect(envelope.canonicalBytes == selected?.manifestData)
      let key = try session.load(vaultID: Core.vaultID, keyID: envelope.body.fields.keyID)
      #expect(key != Core.nextKey && key.count == 32)
      #expect(try f.savedState().phase == .consumed)
      #expect(f.disk.core.owner.unwraps == (phase == 12 ? 2 : 3))
      try ordinary(f, session).add(
        name: "after/restart", secret: "continued", type: .secret, operationID: .init())
    }
    #expect(f.disk.ownership.value == nil && f.disk.core.owner.signatures == f.signatures + 1)
  }

  @Test(arguments: [false, true])
  func exactWarmSessionAvoidsUnnecessaryWrapperOperations(committed: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let session = try unlocked(f)
    if committed {
      f.disk.ownership.rejectClear = true
      _ = try approve(f, session)
      f.disk.ownership.rejectClear = false
    } else {
      try interrupt(f, session)
    }
    let before = f.disk.core.owner.unwraps
    #expect(
      try service(f, session).recoverInterruptedEnrollment(
        invitationDigest: f.state.invitationDigest,
        operationID: .init())
        == (committed
          ? .alreadyCompleted(operationID: f.disk.operationID)
          : .completed(operationID: f.disk.operationID)))
    #expect(f.disk.core.owner.unwraps == before + (committed ? 0 : 1))
    #expect(session.hasResidentKey && f.disk.ownership.value == nil)
  }

  @Test(arguments: [false, true])
  func privateCancellationNeverReservesOrReplacesOldSession(signing: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let session = try unlocked(f)
    f.disk.core.owner.cancelSigning = signing
    f.disk.core.owner.cancelUnwrap = !signing
    #expect(throws: Core.FixtureError.cancelled) { try approve(f, session) }
    #expect(
      f.disk.ownership.value == nil && f.disk.checkpoints.value == f.disk.checkpoint.canonicalBytes)
    #expect(
      try session.load(vaultID: Core.vaultID, keyID: f.disk.parent.body.fields.keyID)
        == Core.nextKey)
    #expect(
      f.disk.core.owner.signatures == f.signatures + 1
        && f.disk.core.owner.unwraps == (signing ? 0 : 1))
  }

  @Test(arguments: 0..<9)
  func invalidComparisonSessionSourceOrPendingWorkRefusesBeforeSigning(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let session = try unlocked(f)
    if variant == 0 { session.invalidate() }
    if variant == 1 { f.disk.ownership.value = Data([1]) }
    if variant == 2 { f.disk.registration.value = Data([1]) }
    if variant == 3 { f.disk.adoption.value = Data([1]) }
    if variant == 4 { f.local.value = nil }
    if variant == 5 { f.local.value = Data([1]) }
    if variant == 6 {
      try FileManager.default.removeItem(
        at: f.disk.entryURL(try #require(f.disk.entries.values.first)))
    }
    let pending = f.disk.ownership.value
    #expect(throws: (any Error).self) {
      try service(f, session).approve(
        invitationDigest: f.state.invitationDigest,
        approvedTranscriptDigest: variant == 7
          ? Data(repeating: 1, count: 32) : #require(f.state.transcript?.digest),
        expectedCheckpoint: f.disk.checkpoint, at: variant == 8 ? Self.now + 1 : Self.now,
        operationID: .init())
    }
    #expect(f.disk.core.owner.signatures == f.signatures && f.disk.core.owner.unwraps == 0)
    #expect(
      f.disk.ownership.value == pending
        && f.disk.checkpoints.value == f.disk.checkpoint.canonicalBytes)
  }

  @Test(arguments: 0..<7)
  func changesDuringSigningStopBeforeWrapperVerification(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let session = try unlocked(f)
    let branch = try f.disk.build(.remove(name: "fixture/totp"))
    let identity = ObservedIdentity(
      base: f.disk.core.owner,
      onSign: {
        switch variant {
        case 0: try f.disk.seed(branch.envelope, entries: branch.stagedEntries)
        case 1: f.disk.registration.value = Data([1])
        case 2: f.disk.adoption.value = Data([1])
        case 3: f.disk.checkpoints.value = Data([1])
        case 4: session.invalidate()
        case 5: f.local.value = nil
        default:
          try session.install(
            Core.nextKey, vaultID: Core.vaultID, keyID: f.disk.parent.body.fields.keyID)
        }
      })
    #expect(throws: (any Error).self) { try approve(f, session, identity: identity) }
    #expect(f.disk.ownership.value == nil && f.disk.core.owner.unwraps == 0)
    #expect(f.disk.core.owner.signatures == f.signatures + 1)
  }

  @Test(arguments: [false, true])
  func lockOrSameKeySessionReplacementDuringInitialUnwrapStopsBeforeReservation(replace: Bool)
    throws
  {
    let f = try Fixture()
    defer { f.disk.remove() }
    let session = try unlocked(f)
    f.disk.core.owner.onUnwrap = {
      if replace {
        try session.install(
          Core.nextKey, vaultID: Core.vaultID, keyID: f.disk.parent.body.fields.keyID)
      } else {
        session.invalidate()
      }
    }
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) { try approve(f, session) }
    #expect(f.disk.core.owner.unwraps == 1 && f.disk.ownership.value == nil)
    #expect(f.disk.checkpoints.value == f.disk.checkpoint.canonicalBytes)
    #expect(session.hasResidentKey == replace)
  }

  @Test func failedCompletionLocksThenColdRestartNeedsOnlyNewEpoch() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let session = try unlocked(f)
    f.local.rejectConsume = true
    #expect(throws: Stop.interrupted) { try approve(f, session) }
    let pending = try #require(f.disk.ownership.value)
    #expect(!session.hasResidentKey && f.disk.checkpoints.value != f.disk.checkpoint.canonicalBytes)
    #expect(try f.savedState().phase == .awaitingComparison)
    for entry in Array(f.disk.entries.values) + Array(f.disk.core.entries.values) {
      try FileManager.default.removeItem(at: f.disk.entryURL(entry))
    }
    try FileManager.default.removeItem(at: f.disk.manifestURL(f.disk.parent.digest))
    try FileManager.default.removeItem(at: f.disk.manifestURL(f.disk.core.parent.digest))
    try FileManager.default.removeItem(
      at: f.disk.cacheRoot.appendingPathComponent("\(Core.vaultID).json"))
    f.local.rejectConsume = false
    #expect(
      try service(f, session).recoverInterruptedEnrollment(
        invitationDigest: f.state.invitationDigest,
        operationID: .init()) == .alreadyCompleted(operationID: f.disk.operationID))
    #expect(
      f.disk.core.owner.unwraps == 2 && f.disk.ownership.value == nil && session.hasResidentKey)
    #expect(try f.savedState().phase == .consumed && f.local.consumptions == 1)
    #expect(pending != Data())
  }

  @Test func failedCheckpointCASRetainsOldSessionAndDoesNotConsumeCeremony() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let session = try unlocked(f)
    f.disk.checkpoints.rejectAdvance = true
    #expect(throws: Stop.interrupted) { try approve(f, session) }
    #expect(try f.savedState().phase == .awaitingComparison && f.disk.ownership.value != nil)
    #expect(
      try session.load(vaultID: Core.vaultID, keyID: f.disk.parent.body.fields.keyID)
        == Core.nextKey)
    f.disk.checkpoints.rejectAdvance = false
    #expect(
      try service(f, session).recoverInterruptedEnrollment(
        invitationDigest: f.state.invitationDigest,
        operationID: .init()) == .completed(operationID: f.disk.operationID))
  }

  @Test(arguments: [false, true])
  func replacedPostPublicationAnchorIsNotCleanedOrUsedToInstallSession(sameOperation: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let session = try unlocked(f)
    let replacement = try V3ImmutableTransactionRecoveryAnchor(
      operationID: sameOperation ? f.disk.operationID : .init(), vaultID: Core.vaultID,
      intentDigest: Data(repeating: 3, count: 32), phase: .prepared
    ).canonicalBytes
    #expect(
      throws: V3ImmutableTransactionRecoveryError.invalidRecoveryAnchor(vaultID: Core.vaultID)
    ) {
      try approve(
        f, session,
        observer: Observer {
          if $0 == .cleanupCompleted {
            f.disk.ownership.value = replacement
          }
        })
    }
    #expect(f.disk.ownership.value == replacement && !session.hasResidentKey)
    #expect(
      try f.savedState().phase == .consumed
        && f.disk.checkpoints.value != f.disk.checkpoint.canonicalBytes)
  }

  @Test(arguments: [1, 2])
  func cancellationAtEitherColdWrapperRetainsApprovalAndLocks(operation: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    try interrupt(f, unlocked(f))
    let pending = f.disk.ownership.value
    f.disk.core.owner.onUnwrap = {
      if f.disk.core.owner.unwraps == 1 + operation { f.disk.core.owner.cancelUnwrap = true }
    }
    let session = V3DeviceWrappedVaultKeySessionStore()
    #expect(throws: Core.FixtureError.cancelled) {
      try service(f, session).recoverInterruptedEnrollment(
        invitationDigest: f.state.invitationDigest, operationID: .init())
    }
    #expect(f.disk.ownership.value == pending && !session.hasResidentKey)
    #expect(
      f.disk.core.owner.unwraps == 1 + operation && f.disk.core.owner.signatures == f.signatures + 1
    )
    f.disk.core.owner.cancelUnwrap = false
    f.disk.core.owner.onUnwrap = {}
    #expect(
      try service(f, session).recoverInterruptedEnrollment(
        invitationDigest: f.state.invitationDigest,
        operationID: .init()) == .completed(operationID: f.disk.operationID))
  }

  @Test(arguments: [1, 2])
  func lockDuringEitherColdWrapperCannotAdvanceOrInstall(operation: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    try interrupt(f, unlocked(f))
    let pending = f.disk.ownership.value
    let session = V3DeviceWrappedVaultKeySessionStore()
    f.disk.core.owner.onUnwrap = {
      if f.disk.core.owner.unwraps == 1 + operation { session.invalidate() }
    }
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
      try service(f, session).recoverInterruptedEnrollment(
        invitationDigest: f.state.invitationDigest, operationID: .init())
    }
    #expect(f.disk.core.owner.unwraps == 1 + operation && !session.hasResidentKey)
    #expect(
      f.disk.ownership.value == pending
        && f.disk.checkpoints.value == f.disk.checkpoint.canonicalBytes)
  }

  @Test(arguments: 0..<6)
  func changesAfterOldWrapperRefuseBeforeNewPrivateOperation(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    try interrupt(f, unlocked(f))
    let branch = try f.disk.build(.remove(name: "fixture/totp"))
    let pending = f.disk.ownership.value
    f.disk.core.owner.onUnwrap = {
      switch variant {
      case 0: f.local.value = nil
      case 1: f.disk.registration.value = Data([1])
      case 2: f.disk.adoption.value = Data([1])
      case 3: f.disk.checkpoints.value = Data([1])
      case 4: f.disk.ownership.value = Data([1])
      default: try f.disk.seed(branch.envelope, entries: branch.stagedEntries)
      }
    }
    let session = V3DeviceWrappedVaultKeySessionStore()
    #expect(throws: (any Error).self) {
      try service(f, session).recoverInterruptedEnrollment(
        invitationDigest: f.state.invitationDigest, operationID: .init())
    }
    #expect(f.disk.core.owner.unwraps == 2 && !session.hasResidentKey)
    if variant != 4 { #expect(f.disk.ownership.value == pending) }
  }

  @Test(arguments: [1, 2])
  func wrongProviderResultsAuthenticateBeforeFurtherOperationsOrCommit(operation: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    try interrupt(f, unlocked(f))
    let pending = f.disk.ownership.value
    let identity = ObservedIdentity(base: f.disk.core.owner, incorrectUnwrap: 1 + operation)
    let session = V3DeviceWrappedVaultKeySessionStore()
    #expect(throws: (any Error).self) {
      try service(f, session, identity: identity)
        .recoverInterruptedEnrollment(
          invitationDigest: f.state.invitationDigest, operationID: .init())
    }
    #expect(f.disk.core.owner.unwraps == 1 + operation && !session.hasResidentKey)
    #expect(
      f.disk.ownership.value == pending
        && f.disk.checkpoints.value == f.disk.checkpoint.canonicalBytes)
  }

  @Test(arguments: 0..<4)
  func invalidSourceOrOwnerRefusesRestartBeforeAuthentication(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    try interrupt(f, unlocked(f))
    let pending = f.disk.ownership.value
    if variant == 0 { f.local.value = Data([1]) }
    if variant == 1 { f.disk.adoption.value = Data([1]) }
    if variant == 2 {
      try FileManager.default.removeItem(
        at: f.disk.entryURL(try #require(f.disk.entries.values.first)))
    }
    let identity = variant == 3 ? try Core.Owner() : f.disk.core.owner
    #expect(throws: (any Error).self) {
      try service(f, .init(), identity: identity)
        .recoverInterruptedEnrollment(
          invitationDigest: f.state.invitationDigest, operationID: .init())
    }
    #expect(f.disk.core.owner.unwraps == 1 && f.disk.ownership.value == pending)
    if variant == 3 { #expect(identity.unwraps == 0) }
  }

  @Test(arguments: [false, true])
  func selectedAndProjectedBudgetsRefuseBeforeNativeAuthentication(projected: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    try interrupt(f, unlocked(f))
    let pending = f.disk.ownership.value
    let limits = Core.Fixture.limits(entries: projected ? 3 : 1)
    #expect(throws: (any Error).self) {
      try service(f, .init(), limits: limits)
        .recoverInterruptedEnrollment(
          invitationDigest: f.state.invitationDigest, operationID: .init())
    }
    #expect(f.disk.core.owner.unwraps == 1 && f.disk.ownership.value == pending)
  }

  @Test func ordinaryPendingWorkCannotResumeAsEnrollmentEvenIfCheckpointChanged() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try f.disk.build(.remove(name: "fixture/totp"))
    #expect(throws: Stop.interrupted) {
      try f.disk.publisher(
        observer: Observer {
          if $0 == .manifestStaged { throw Stop.interrupted }
        }
      ).publish(candidate, vaultKey: Core.nextKey)
    }
    let pending = f.disk.ownership.value
    f.disk.checkpoints.value = Data([1])
    #expect(
      throws: V3ImmutableTransactionRecoveryError.invalidIntent(
        operationID: f.disk.operationID.rawValue)
    ) {
      try service(f, .init()).recoverInterruptedEnrollment(
        invitationDigest: f.state.invitationDigest, operationID: .init())
    }
    #expect(f.disk.ownership.value == pending && f.disk.core.owner.unwraps == 0)
  }

  @Test func resumeCleanupFailureLocksAndNextRestartOpensOnlyCommittedWrapper() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    try interrupt(f, unlocked(f))
    let session = V3DeviceWrappedVaultKeySessionStore()
    f.disk.ownership.rejectClear = true
    #expect(throws: Stop.interrupted) {
      try service(f, session).recoverInterruptedEnrollment(
        invitationDigest: f.state.invitationDigest, operationID: .init())
    }
    #expect(!session.hasResidentKey && f.disk.ownership.value != nil)
    #expect(try f.savedState().phase == .consumed && f.disk.core.owner.unwraps == 3)
    f.disk.ownership.rejectClear = false
    #expect(
      try service(f, session).recoverInterruptedEnrollment(
        invitationDigest: f.state.invitationDigest,
        operationID: .init()) == .alreadyCompleted(operationID: f.disk.operationID))
    #expect(f.disk.core.owner.unwraps == 4 && session.hasResidentKey && f.local.consumptions == 1)
  }

  @Test(arguments: 0..<3)
  func changesAfterResumeCheckpointCannotInstallSession(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    try interrupt(f, unlocked(f))
    let selected = try ready(f)
    let entry = try #require(selected.availableEntries.first)
    let session = V3DeviceWrappedVaultKeySessionStore()
    let checkpoints = ObservedCheckpoints(
      base: f.disk.checkpoints,
      action: {
        switch variant {
        case 0: session.invalidate()
        case 1: try FileManager.default.removeItem(at: f.disk.entryURL(entry))
        default: f.local.value = nil
        }
      })
    #expect(throws: (any Error).self) {
      try service(f, session, checkpoints: checkpoints)
        .recoverInterruptedEnrollment(
          invitationDigest: f.state.invitationDigest, operationID: .init())
    }
    #expect(
      f.disk.checkpoints.value == selected.candidateCheckpoint.canonicalBytes
        && !session.hasResidentKey)
    if variant != 0 { #expect(f.disk.ownership.value != nil) }
  }

  @Test func noPendingStateDoesNotSignReapproveOrColdUnlockConsumedCeremony() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    _ = try approve(f, unlocked(f))
    let session = V3DeviceWrappedVaultKeySessionStore()
    #expect(
      try service(f, session).recoverInterruptedEnrollment(
        invitationDigest: f.state.invitationDigest,
        operationID: .init()) == .nothingToRecover)
    #expect(!session.hasResidentKey && f.disk.core.owner.unwraps == 1)
    #expect(throws: (any Error).self) { try approve(f, session) }
    #expect(f.disk.core.owner.signatures == f.signatures + 1)
  }

  @Test func malformedPinnedCandidateRefusesBeforePrivateAuthentication() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let bytes = Data("{}".utf8)
    let digest = Data(SHA256.hash(data: bytes))
    let intent = try V3ImmutableTransactionRecoveryIntent(
      operationID: f.disk.operationID,
      kind: .enrollDevice, vaultID: Core.vaultID, expectedCheckpoint: f.disk.checkpoint,
      expectedHeads: [f.disk.parent.digest], candidateManifestDigest: digest, stagedEntries: [],
      enrollmentTranscriptDigest: #require(f.state.transcript?.digest))
    try f.disk.store.persistRecoveryIntent(intent.canonicalBytes, operationID: f.disk.operationID)
    try f.disk.store.stageManifest(bytes, digest: digest, operationID: f.disk.operationID)
    let pending = try V3ImmutableTransactionRecoveryAnchor(
      operationID: f.disk.operationID,
      vaultID: Core.vaultID, intentDigest: Data(SHA256.hash(data: intent.canonicalBytes)),
      phase: .recoverable
    ).canonicalBytes
    f.disk.ownership.value = pending
    #expect(throws: (any Error).self) {
      try service(f, .init()).recoverInterruptedEnrollment(
        invitationDigest: f.state.invitationDigest, operationID: .init())
    }
    #expect(f.disk.ownership.value == pending && f.disk.core.owner.unwraps == 0)
    #expect(f.disk.core.owner.signatures == f.signatures)
  }

  @Test(arguments: [false, true])
  func primaryAndBackupRecoverAfterRandomOwnerApprovalAndSave(backup: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.disk.remove() }
    let session = try unlocked(f)
    _ = try approve(f, session)
    try ordinary(f, session).edit(
      name: "fixture/secret", secret: "after owner service", type: .secret,
      operationID: .init())
    session.invalidate()
    for entry in Array(f.disk.entries.values) + Array(f.disk.core.entries.values) {
      try FileManager.default.removeItem(at: f.disk.entryURL(entry))
    }
    let recipient = try #require(f.disk.core.parent.body.recovery.recipients.first)
    let backupAnchor = try V3RecoveryAnchor(
      floor: .init(
        vaultID: Core.vaultID,
        envelopeDigest: f.disk.core.parent.digest), recipientID: recipient.recipientID,
      registrationID: recipient.registrationID, slot: .keyManagement)
    let anchor = backup ? backupAnchor : f.disk.anchor
    let token = backup ? f.disk.core.backupToken : f.disk.core.token
    let selected = try V3RecoveryHistorySelector(source: f.disk.store).select(
      anchor: anchor,
      credentialPublicKey: token.publicKey.x963Representation)
    let calls = Core.Counter()
    let receiver = try PIVHPKEReceiver(publicBytes: token.publicKey.x963Representation) { peer in
      calls.increment()
      return try token.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: peer)
      )
      .withUnsafeBytes { Data($0) }
    }
    let opened = try V3RecoverySnapshotVerifier(source: f.disk.store).open(
      selected,
      boundAnchor: anchor, receiver: receiver)
    #expect(calls.value == 1)
    #expect(
      opened.entries.first { $0.name == "fixture/secret" }?.plaintext == "after owner service")
    #expect(opened.entries.first { $0.name == "fixture/totp" }?.plaintext == "JBSWY3DPEHPK3PXP")
    #expect(f.disk.core.owner.signatures == f.signatures + 1 && f.disk.core.owner.unwraps == 1)
  }

  private func service(
    _ f: Fixture, _ session: V3DeviceWrappedVaultKeySessionStore,
    identity: V3RecoveryEnrollmentOwnerService.Identity? = nil,
    checkpoints: (any V3ManifestCheckpointStoring)? = nil,
    limits: V3ManifestRepositoryLimits = .standard,
    observer: any V3ImmutableTransactionPhaseObserving = V3NoopContentTransactionPhaseObserver()
  ) -> V3RecoveryEnrollmentOwnerService {
    .init(
      vaultID: Core.vaultID, identity: identity ?? f.disk.core.owner, session: session,
      objectStore: f.disk.store, checkpointStore: checkpoints ?? f.disk.checkpoints,
      recoveryAnchorStore: f.disk.ownership, registrationAnchorStore: f.disk.registration,
      adoptionAnchorStore: f.disk.adoption, ceremonyStore: f.local, cache: f.disk.cache,
      limits: limits, phaseObserver: observer)
  }
  private func approve(
    _ f: Fixture, _ session: V3DeviceWrappedVaultKeySessionStore,
    identity: V3RecoveryEnrollmentOwnerService.Identity? = nil,
    observer: any V3ImmutableTransactionPhaseObserving = V3NoopContentTransactionPhaseObserver()
  ) throws -> V3RecoveryDeviceEnrollmentCommit {
    try service(f, session, identity: identity, observer: observer).approve(
      invitationDigest: f.state.invitationDigest,
      approvedTranscriptDigest: #require(f.state.transcript?.digest),
      expectedCheckpoint: f.disk.checkpoint,
      at: Self.now, operationID: f.disk.operationID)
  }
  private func interrupt(
    _ f: Fixture, _ session: V3DeviceWrappedVaultKeySessionStore,
    phase: V3ImmutableTransactionPhase = .manifestStaged
  ) throws {
    #expect(throws: Stop.interrupted) {
      try approve(
        f, session,
        observer: Observer { if $0 == phase { throw Stop.interrupted } })
    }
  }
  private func unlocked(_ f: Fixture) throws -> V3DeviceWrappedVaultKeySessionStore {
    let session = V3DeviceWrappedVaultKeySessionStore()
    try session.install(Core.nextKey, vaultID: Core.vaultID, keyID: f.disk.parent.body.fields.keyID)
    return session
  }
  private func ordinary(_ f: Fixture, _ session: V3DeviceWrappedVaultKeySessionStore)
    -> V3RecoveryVaultMutationService
  {
    .init(
      vaultID: Core.vaultID, session: session, objectStore: f.disk.store,
      checkpointStore: f.disk.checkpoints,
      recoveryAnchorStore: f.disk.ownership, registrationAnchorStore: f.disk.registration,
      adoptionAnchorStore: f.disk.adoption, cache: f.disk.cache)
  }
  private func current(_ f: Fixture) throws -> V3RecoveryManifestEnvelope {
    let checkpoint = try V3ManifestCheckpoint(canonicalBytes: #require(f.disk.checkpoints.value))
    return try V3RecoveryManifestCodec().parseEnvelope(
      V3ExactTransitionRepository(source: f.disk.store, limits: .standard).readManifest(
        checkpoint.envelopeDigest))
  }
  private func ready(_ f: Fixture) throws -> V3ContentTransactionRecoveryState {
    let state = try f.savedState()
    let publisher = V3RecoveryDeviceEnrollmentPublisher(
      mutationOwner: VaultTransactionMutationOwner(),
      objectStore: f.disk.store, checkpointStore: f.disk.checkpoints,
      recoveryAnchorStore: f.disk.ownership,
      registrationAnchorStore: f.disk.registration, adoptionAnchorStore: f.disk.adoption,
      ceremonyStore: f.local, cache: f.disk.cache)
    guard
      case .ready(let ready) = try publisher.prepareInterruptedTransaction(
        vaultID: Core.vaultID,
        state: state, approvedTranscriptDigest: #require(state.transcript?.digest),
        expectedOwner: f.disk.core.owner.publicIdentity)
    else { throw Stop.interrupted }
    return ready
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
  private struct ObservedIdentity: V3EnrollmentMessageSigning, V3DeviceWrappedVaultKeyUnwrapping {
    let base: Core.Owner
    var onSign: @Sendable () throws -> Void = {}
    var incorrectUnwrap: Int? = nil
    var vaultID: String { base.vaultID }
    var publicIdentity: V3EnrollmentDeviceIdentity { base.publicIdentity }
    func signature(for input: Data, reason: String) throws -> Data {
      let signature = try base.signature(for: input, reason: reason)
      try onSign()
      return signature
    }
    func unwrapDeviceWrappedVaultKey(
      _ wrappedKey: V3HPKEWrappedVaultKey, context: V3VaultKeyHPKEContext, reason: String
    ) throws -> Data {
      let key = try base.unwrapDeviceWrappedVaultKey(wrappedKey, context: context, reason: reason)
      return base.unwraps == incorrectUnwrap ? Data(repeating: 9, count: 32) : key
    }
  }
  private struct ObservedCheckpoints: V3ManifestCheckpointStoring {
    let base: Publication.Checkpoints
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
