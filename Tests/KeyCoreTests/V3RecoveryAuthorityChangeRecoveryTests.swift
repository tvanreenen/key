import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Actual random-key authority services, immutable files and cold/warm sessions.
/// Private Mac operations use software identities; no PIV operation is involved.
struct V3RecoveryAuthorityChangeRecoveryTests {
  typealias Action = V3RecoveryAuthorityChangeServiceTests.Action
  private typealias Fixture = V3RecoveryAuthorityChangeServiceTests.Fixture
  private typealias Core = V3RecoveryRegistrationTests
  private typealias Publication = V3RecoveryContentMutationPublisherTests
  private typealias Stop = Publication.Stop
  private static let phases: [V3ImmutableTransactionPhase] = [
    .recoveryAnchorPrepared, .recoveryIntentPersisted, .recoveryArmed,
    .entryStaged(index: 0), .entryStaged(index: 1), .manifestStaged,
    .repositoryStateRechecked, .entryPublished(index: 0), .entryPublished(index: 1),
    .publishedEntriesValidated, .manifestPublished, .publishedManifestValidated,
    .checkpointAdvanced, .cleanupCompleted,
  ]

  @Test(arguments: Action.allCases, 0..<14)
  func coldSessionRestartsEveryBoundaryWithoutSigningOrRenewedConsent(action: Action, phase: Int)
    throws
  {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    try interrupt(f, phase: Self.phases[phase])
    let session = V3DeviceWrappedVaultKeySessionStore()
    let outcome = try VaultTransactionMutationOwner().perform(.recoverInterruptedTransaction) { c in
      try resume(f, session: session, operationID: c.operationID)
    }
    if phase < 5 {
      #expect(outcome == .abandoned(operationID: f.disk.operationID))
      #expect(f.disk.checkpoints.value == f.checkpoint.canonicalBytes && !session.hasResidentKey)
      #expect(f.owner.unwraps == f.unwraps + 1)
    } else if phase == 13 {
      #expect(outcome == .nothingToRecover && !session.hasResidentKey)
      #expect(f.owner.unwraps == f.unwraps + 1)
    } else {
      #expect(
        outcome
          == (phase == 12
            ? .alreadyCompleted(operationID: f.disk.operationID)
            : .completed(operationID: f.disk.operationID)))
      let envelope = try current(f)
      let key = try session.load(vaultID: Core.vaultID, keyID: envelope.body.fields.keyID)
      #expect(key.count == 32 && key != f.key)
      #expect(f.owner.unwraps == f.unwraps + (phase == 12 ? 2 : 3))
      try ordinary(f, session: session).add(
        name: "after/restart", secret: "recovered", type: .secret, operationID: .init())
      #expect(try current(f).body.fields.keyID == envelope.body.fields.keyID)
    }
    #expect(f.disk.ownership.value == nil && f.owner.signatures == f.signatures + 1)
  }

  @Test(arguments: Action.allCases)
  func committedRestartNeedsNoOldCiphertextManifestOrCache(action: Action) throws {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    try interrupt(f, phase: .checkpointAdvanced)
    let checkpoint = f.disk.checkpoints.value
    let urls = Set(
      (Array(f.entries.values) + Array(f.disk.entries.values) + Array(f.disk.core.entries.values))
        .map { f.disk.entryURL($0) })
    for url in urls { try FileManager.default.removeItem(at: url) }
    for digest in Set([f.parent.digest, f.disk.parent.digest, f.disk.core.parent.digest]) {
      try FileManager.default.removeItem(at: f.disk.manifestURL(digest))
    }
    try FileManager.default.removeItem(
      at: f.disk.cacheRoot.appendingPathComponent("\(Core.vaultID).json"))
    let session = V3DeviceWrappedVaultKeySessionStore()
    #expect(try resume(f, session: session) == .alreadyCompleted(operationID: f.disk.operationID))
    #expect(
      f.disk.checkpoints.value == checkpoint && f.disk.ownership.value == nil
        && session.hasResidentKey)
    #expect(f.owner.unwraps == f.unwraps + 2 && f.owner.signatures == f.signatures + 1)
  }

  @Test(arguments: Action.allCases, [false, true])
  func exactWarmSessionReusesOnlyTheMatchingEpochKey(action: Action, committed: Bool) throws {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    let session = try unlocked(f)
    if committed {
      f.disk.ownership.rejectClear = true
      let s = service(f, session: session)
      _ = try f.execute(s, review: f.prepare(s))
      f.disk.ownership.rejectClear = false
    } else {
      try interrupt(f, phase: .manifestStaged, session: session)
    }
    let before = f.owner.unwraps
    #expect(
      try resume(f, session: session)
        == (committed
          ? .alreadyCompleted(operationID: f.disk.operationID)
          : .completed(operationID: f.disk.operationID)))
    #expect(f.owner.unwraps == before + (committed ? 0 : 1))
    #expect(
      f.disk.ownership.value == nil && session.hasResidentKey
        && f.owner.signatures == f.signatures + 1)
  }

  @Test(arguments: Action.allCases, [1, 2])
  func cancellationAtEitherColdWrapperRetainsExactWorkWithoutRetry(action: Action, operation: Int)
    throws
  {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    try interrupt(f, phase: .manifestStaged)
    let pending = f.disk.ownership.value
    f.owner.onUnwrap = {
      if f.owner.unwraps == f.unwraps + 1 + operation { f.owner.cancelUnwrap = true }
    }
    let session = V3DeviceWrappedVaultKeySessionStore()
    #expect(throws: Core.FixtureError.cancelled) { try resume(f, session: session) }
    #expect(
      f.disk.ownership.value == pending && f.disk.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(
      !session.hasResidentKey && f.owner.unwraps == f.unwraps + 1 + operation
        && f.owner.signatures == f.signatures + 1)
    f.owner.cancelUnwrap = false
    f.owner.onUnwrap = {}
    #expect(try resume(f, session: session) == .completed(operationID: f.disk.operationID))
  }

  @Test(arguments: Action.allCases, [(1, false), (1, true), (2, false), (2, true)])
  func lockOrSameKeyReauthenticationDuringEitherWrapperCannotBeUndone(
    action: Action, scenario: (Int, Bool)
  ) throws {
    let (operation, reinstall) = scenario
    let f = try Fixture(action)
    defer { f.disk.remove() }
    try interrupt(f, phase: .manifestStaged)
    let pending = f.disk.ownership.value
    let session = V3DeviceWrappedVaultKeySessionStore()
    f.owner.onUnwrap = {
      if f.owner.unwraps == f.unwraps + 1 + operation {
        session.invalidate()
        if reinstall {
          try session.install(f.key, vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID)
        }
      }
    }
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
      try resume(f, session: session)
    }
    #expect(!session.hasResidentKey && f.disk.ownership.value == pending)
    #expect(
      f.disk.checkpoints.value == f.checkpoint.canonicalBytes
        && f.owner.unwraps == f.unwraps + 1 + operation)
  }

  @Test(arguments: Action.allCases, 0..<6)
  func changesDuringOldWrapperStopBeforeOpeningNewWrapper(action: Action, variant: Int) throws {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    try interrupt(f, phase: .manifestStaged)
    let pending = f.disk.ownership.value
    f.owner.onUnwrap = {
      switch variant {
      case 0: f.disk.registration.value = Data([1])
      case 1: f.disk.adoption.value = Data([1])
      case 2: f.disk.ownership.value = Data([1])
      case 3: f.disk.checkpoints.value = Data([1])
      case 4: try f.addBranch()
      default:
        try FileManager.default.removeItem(
          at: f.disk.entryURL(try #require(f.entries.values.first)))
      }
    }
    let session = V3DeviceWrappedVaultKeySessionStore()
    #expect(throws: (any Error).self) { try resume(f, session: session) }
    #expect(
      f.owner.unwraps == f.unwraps + 2 && f.owner.signatures == f.signatures + 1
        && !session.hasResidentKey)
    if variant != 2 { #expect(f.disk.ownership.value == pending) }
    if variant != 3 { #expect(f.disk.checkpoints.value == f.checkpoint.canonicalBytes) }
  }

  @Test(arguments: Action.allCases, 0..<6)
  func invalidPendingSourceOwnerOrResidentEpochRefusesBeforePrivateWork(
    action: Action, variant: Int
  ) throws {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    try interrupt(f, phase: .manifestStaged)
    let pending = f.disk.ownership.value
    let session = V3DeviceWrappedVaultKeySessionStore()
    switch variant {
    case 0: f.disk.registration.value = Data([1])
    case 1: f.disk.adoption.value = Data([1])
    case 2:
      try FileManager.default.removeItem(at: f.disk.entryURL(try #require(f.entries.values.first)))
    case 4:
      let key = Data(repeating: 0xff, count: 32)
      try session.install(
        key, vaultID: Core.vaultID, keyID: .derive(vaultKey: key, vaultID: Core.vaultID))
    default: break
    }
    let other = try Core.Owner()
    #expect(throws: (any Error).self) {
      try resume(
        f, session: session, identity: variant == 3 ? other : nil,
        vaultID: variant == 5 ? UUID().uuidString.lowercased() : Core.vaultID)
    }
    #expect(
      f.disk.ownership.value == pending && f.disk.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(f.owner.unwraps == f.unwraps + 1 && !session.hasResidentKey && other.unwraps == 0)
  }

  @Test(arguments: Action.allCases, 0..<4)
  func selectedAndProjectedBudgetsRefuseBeforeAuthentication(action: Action, variant: Int) throws {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    try interrupt(f, phase: .manifestStaged)
    let pending = f.disk.ownership.value
    let total = try ready(f).availableEntries.reduce(0) { $0 + $1.canonicalBytes.count }
    let limits = [
      Core.Fixture.limits(entries: 1), Core.Fixture.limits(entries: 2),
      Core.Fixture.limits(entryBytes: 1), Core.Fixture.limits(totalBytes: total - 1),
    ][variant]
    #expect(throws: (any Error).self) { try resume(f, session: .init(), limits: limits) }
    #expect(f.disk.ownership.value == pending && f.owner.unwraps == f.unwraps + 1)
  }

  @Test(arguments: Action.allCases)
  func otherAuthorityRouteCannotResumeOrAbandonEvenAfterCheckpointChange(action: Action) throws {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    try interrupt(f, phase: .manifestStaged)
    let pending = f.disk.ownership.value
    f.disk.checkpoints.value = try V3ManifestCheckpoint(
      vaultID: Core.vaultID, envelopeDigest: Data(repeating: 0x99, count: 32)
    ).canonicalBytes
    let s = service(f, session: .init())
    #expect(throws: (any Error).self) {
      if action == .revoke { return try s.recoverInterruptedRemoval(operationID: .init()) }
      return try s.recoverInterruptedRevocation(operationID: .init())
    }
    #expect(f.disk.ownership.value == pending && f.owner.unwraps == f.unwraps + 1)
  }

  @Test(arguments: Action.allCases, [false, true])
  func routedAnchorMustMatchBeforePreparedCleanupOrAuthentication(action: Action, prepared: Bool)
    throws
  {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    try interrupt(f, phase: prepared ? .recoveryAnchorPrepared : .manifestStaged)
    let pending = try #require(f.disk.ownership.value)
    #expect(throws: (any Error).self) { try resume(f, session: .init(), expectedAnchor: Data([1])) }
    #expect(f.disk.ownership.value == pending && f.owner.unwraps == f.unwraps + 1)
    #expect(
      try resume(f, session: .init(), expectedAnchor: pending)
        == (prepared
          ? .abandoned(operationID: f.disk.operationID)
          : .completed(operationID: f.disk.operationID)))
    #expect(f.owner.signatures == f.signatures + 1)
  }

  @Test(arguments: Action.allCases)
  func incompletePublishedSnapshotWaitsForExactBytesWithoutAuthentication(action: Action) throws {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    try interrupt(f, phase: .manifestPublished)
    let entry = try #require(ready(f).availableEntries.first)
    try FileManager.default.removeItem(at: f.disk.entryURL(entry))
    let pending = f.disk.ownership.value
    let session = V3DeviceWrappedVaultKeySessionStore()
    #expect(throws: V3ImmutableTransactionRecoveryError.transactionDirectoryUnavailable) {
      try resume(f, session: session)
    }
    #expect(
      f.disk.ownership.value == pending && f.owner.unwraps == f.unwraps + 1
        && !session.hasResidentKey)
    let digest = Data(SHA256.hash(data: entry.canonicalBytes))
    try f.disk.store.stageEntry(
      entry.canonicalBytes, entryID: entry.context.entryID, digest: digest,
      operationID: f.disk.operationID)
    try f.disk.store.publishStagedEntry(
      entry.canonicalBytes, entryID: entry.context.entryID, digest: digest,
      operationID: f.disk.operationID)
    #expect(try resume(f, session: session) == .completed(operationID: f.disk.operationID))
    #expect(session.hasResidentKey && f.owner.signatures == f.signatures + 1)
  }

  @Test(arguments: Action.allCases)
  func failedResumeCheckpointCASLocksAndKeepsExactCandidateForRetry(action: Action) throws {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    try interrupt(f, phase: .manifestStaged)
    let state = try ready(f)
    let session = V3DeviceWrappedVaultKeySessionStore()
    f.disk.checkpoints.rejectAdvance = true
    #expect(throws: Stop.interrupted) { try resume(f, session: session) }
    #expect(
      f.disk.ownership.value == state.anchorData
        && f.disk.checkpoints.value == f.checkpoint.canonicalBytes && !session.hasResidentKey)
    f.disk.checkpoints.rejectAdvance = false
    #expect(try resume(f, session: session) == .completed(operationID: f.disk.operationID))
    #expect(
      try current(f).canonicalBytes == state.manifestData && f.owner.signatures == f.signatures + 1)
  }

  @Test(arguments: Action.allCases)
  func resumeCleanupFailureLocksThenRequiresOnlyCurrentWrapper(action: Action) throws {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    try interrupt(f, phase: .manifestStaged)
    let pending = f.disk.ownership.value
    let session = V3DeviceWrappedVaultKeySessionStore()
    f.disk.ownership.rejectClear = true
    #expect(throws: Stop.interrupted) { try resume(f, session: session) }
    #expect(
      f.disk.ownership.value == pending && f.disk.checkpoints.value != f.checkpoint.canonicalBytes
        && !session.hasResidentKey)
    f.disk.ownership.rejectClear = false
    #expect(try resume(f, session: session) == .alreadyCompleted(operationID: f.disk.operationID))
    #expect(
      f.owner.unwraps == f.unwraps + 4 && f.owner.signatures == f.signatures + 1
        && session.hasResidentKey)
  }

  @Test(arguments: Action.allCases, [1, 2])
  func providerOutputAuthenticatesBeforeAnotherOperationOrCommit(action: Action, operation: Int)
    throws
  {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    try interrupt(f, phase: .manifestStaged)
    let pending = f.disk.ownership.value
    let session = V3DeviceWrappedVaultKeySessionStore()
    let identity = ResultIdentity(base: f.owner, incorrectOperation: f.unwraps + 1 + operation)
    #expect(throws: (any Error).self) { try resume(f, session: session, identity: identity) }
    #expect(
      f.disk.ownership.value == pending && f.disk.checkpoints.value == f.checkpoint.canonicalBytes
        && !session.hasResidentKey)
    #expect(f.owner.unwraps == f.unwraps + 1 + operation && f.owner.signatures == f.signatures + 1)
  }

  @Test(arguments: Action.allCases, 0..<6)
  func changesAfterResumeCommitCannotInstallStaleOrLockedSession(action: Action, variant: Int)
    throws
  {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    try interrupt(f, phase: .manifestStaged)
    let state = try ready(f)
    let entry = try #require(state.availableEntries.first)
    let session = V3DeviceWrappedVaultKeySessionStore()
    let checkpoints = ObservedCheckpoints(base: f.disk.checkpoints) {
      switch variant {
      case 0: try FileManager.default.removeItem(at: f.disk.entryURL(entry))
      case 1: session.invalidate()
      case 2: f.disk.registration.value = Data([1])
      case 3: f.disk.adoption.value = Data([1])
      case 4: f.disk.ownership.value = Data([1])
      default: f.disk.checkpoints.value = Data([1])
      }
    }
    #expect(throws: (any Error).self) { try resume(f, session: session, checkpoints: checkpoints) }
    #expect(
      !session.hasResidentKey && f.owner.unwraps == f.unwraps + 3
        && f.owner.signatures == f.signatures + 1)
    if variant != 5 {
      #expect(f.disk.checkpoints.value == state.candidateCheckpoint.canonicalBytes)
    }
    #expect((f.disk.ownership.value != nil) == (variant >= 2))
  }

  @Test(arguments: Action.allCases, 0..<3)
  func wrongPolicyKindOrMalformedPendingFixtureRefusesBeforePrivateWork(
    action: Action, variant: Int
  ) throws {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    if variant == 2 {
      let data = Data("{}".utf8)
      try pin(
        f, data: data, entries: [],
        kind: action == .revoke ? .revokeDevice : .removeRecoveryRecipient)
    } else {
      let candidate = try V3RecoveryKeyRotationBuilder().build(
        checkpoint: f.checkpoint, parent: f.parent, currentEntries: f.entries,
        currentVaultKey: f.key, nextVaultKey: Data(repeating: 0x66, count: 32),
        owner: f.owner, reason: "Owned wrong-policy fixture")
      try pin(
        f, data: candidate.envelope.canonicalBytes, entries: candidate.stagedEntries,
        kind: variant == 0
          ? (action == .revoke ? .revokeDevice : .removeRecoveryRecipient) : .rotateVaultKey)
      if variant == 1 {
        f.disk.checkpoints.value = try V3ManifestCheckpoint(
          vaultID: Core.vaultID, envelopeDigest: Data(repeating: 0x99, count: 32)
        ).canonicalBytes
      }
    }
    let pending = f.disk.ownership.value
    let signed = f.owner.signatures
    #expect(throws: (any Error).self) { try resume(f, session: .init()) }
    #expect(
      f.disk.ownership.value == pending && f.owner.unwraps == f.unwraps
        && f.owner.signatures == signed)
  }

  @Test(arguments: Action.allCases)
  func restartedChangeAndOrdinarySaveRetainOnlyContinuingSoftwareRecovery(action: Action) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture(action)
    defer { f.disk.remove() }
    try interrupt(f, phase: .manifestStaged)
    let session = V3DeviceWrappedVaultKeySessionStore()
    #expect(try resume(f, session: session) == .completed(operationID: f.disk.operationID))
    try ordinary(f, session: session).add(
      name: "after/restart", secret: "restored through restart", type: .secret, operationID: .init()
    )
    session.invalidate()
    if action == .removeLast {
      #expect(throws: (any Error).self) {
        try V3RecoveryHistorySelector(source: f.disk.store).select(
          anchor: f.disk.anchor, credentialPublicKey: f.disk.core.token.publicKey.x963Representation
        )
      }
    } else {
      let backup = try #require(f.disk.core.parent.body.recovery.recipients.first)
      let backupAnchor = try V3RecoveryAnchor(
        floor: .init(vaultID: Core.vaultID, envelopeDigest: f.disk.core.parent.digest),
        recipientID: backup.recipientID, registrationID: backup.registrationID, slot: .keyManagement
      )
      let anchors = action == .revoke ? [f.disk.anchor, backupAnchor] : [backupAnchor]
      let tokens =
        action == .revoke
        ? [f.disk.core.token, f.disk.core.backupToken] : [f.disk.core.backupToken]
      for (anchor, token) in zip(anchors, tokens) {
        let selection = try V3RecoveryHistorySelector(source: f.disk.store).select(
          anchor: anchor, credentialPublicKey: token.publicKey.x963Representation)
        let calls = Core.Counter()
        let receiver = try PIVHPKEReceiver(publicBytes: token.publicKey.x963Representation) {
          peer in
          calls.increment()
          return try token.sharedSecretFromKeyAgreement(
            with: P256.KeyAgreement.PublicKey(x963Representation: peer)
          ).withUnsafeBytes { Data($0) }
        }
        let opened = try V3RecoverySnapshotVerifier(source: f.disk.store).open(
          selection, boundAnchor: anchor, receiver: receiver)
        #expect(
          calls.value == 1
            && opened.entries.first { $0.name == "after/restart" }?.plaintext
              == "restored through restart"
        )
      }
      if action == .remove {
        #expect(throws: (any Error).self) {
          try V3RecoveryHistorySelector(source: f.disk.store).select(
            anchor: f.disk.anchor,
            credentialPublicKey: f.disk.core.token.publicKey.x963Representation)
        }
      }
    }
    #expect(f.owner.signatures == f.signatures + 1 && f.owner.unwraps == f.unwraps + 3)
  }

  @Test(arguments: Action.allCases)
  func nothingToResumeDoesNotUnlockOrDiscardAnExactLiveSession(action: Action) throws {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    let session = try unlocked(f)
    #expect(try resume(f, session: session) == .nothingToRecover)
    #expect(try session.load(vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID) == f.key)
    session.invalidate()
    #expect(try resume(f, session: session) == .nothingToRecover)
    #expect(
      !session.hasResidentKey && f.owner.unwraps == f.unwraps && f.owner.signatures == f.signatures)
  }

  private func interrupt(
    _ f: Fixture, phase: V3ImmutableTransactionPhase,
    session: V3DeviceWrappedVaultKeySessionStore? = nil
  ) throws {
    let active = try session ?? unlocked(f)
    let s = service(
      f, session: active, observer: Observer { if $0 == phase { throw Stop.interrupted } })
    let reviewed = try f.prepare(s)
    #expect(throws: Stop.interrupted) { try f.execute(s, review: reviewed) }
  }
  private func unlocked(_ f: Fixture) throws -> V3DeviceWrappedVaultKeySessionStore {
    let session = V3DeviceWrappedVaultKeySessionStore()
    try session.install(f.key, vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID)
    return session
  }
  private func service(
    _ f: Fixture, session: V3DeviceWrappedVaultKeySessionStore,
    identity: V3RecoveryAuthorityChangeService.Identity? = nil, vaultID: String = Core.vaultID,
    checkpoints: (any V3ManifestCheckpointStoring)? = nil,
    limits: V3ManifestRepositoryLimits = .standard,
    observer: any V3ImmutableTransactionPhaseObserving = V3NoopContentTransactionPhaseObserver()
  ) -> V3RecoveryAuthorityChangeService {
    .init(
      vaultID: vaultID, identity: identity ?? f.owner, session: session,
      objectStore: f.disk.store, checkpointStore: checkpoints ?? f.disk.checkpoints,
      recoveryAnchorStore: f.disk.ownership, registrationAnchorStore: f.disk.registration,
      adoptionAnchorStore: f.disk.adoption, cache: f.disk.cache, limits: limits,
      phaseObserver: observer)
  }
  private func resume(
    _ f: Fixture, session: V3DeviceWrappedVaultKeySessionStore,
    identity: V3RecoveryAuthorityChangeService.Identity? = nil, vaultID: String = Core.vaultID,
    checkpoints: (any V3ManifestCheckpointStoring)? = nil,
    limits: V3ManifestRepositoryLimits = .standard,
    operationID: VaultTransactionOperationID = .init(),
    expectedAnchor: Data? = nil
  ) throws -> V3ImmutableTransactionRecoveryOutcome {
    let s = service(
      f, session: session, identity: identity, vaultID: vaultID, checkpoints: checkpoints,
      limits: limits)
    if f.action == .revoke {
      return try s.recoverInterruptedRevocation(
        operationID: operationID, expectedAnchor: expectedAnchor)
    }
    return try s.recoverInterruptedRemoval(operationID: operationID, expectedAnchor: expectedAnchor)
  }
  private func ready(_ f: Fixture) throws -> V3ContentTransactionRecoveryState {
    let result: V3ContentTransactionRecoveryPreparation
    if f.action == .revoke {
      result = try V3RecoveryDeviceRevocationPublisher(
        mutationOwner: DirectVaultTransactionMutationOwner(operationID: .init()),
        objectStore: f.disk.store, checkpointStore: f.disk.checkpoints,
        recoveryAnchorStore: f.disk.ownership,
        registrationAnchorStore: f.disk.registration, adoptionAnchorStore: f.disk.adoption,
        cache: f.disk.cache
      )
      .prepareInterruptedTransaction(vaultID: Core.vaultID, expectedOwner: f.owner.publicIdentity)
    } else {
      result = try V3RecoveryRecipientRemovalPublisher(
        mutationOwner: DirectVaultTransactionMutationOwner(operationID: .init()),
        objectStore: f.disk.store, checkpointStore: f.disk.checkpoints,
        recoveryAnchorStore: f.disk.ownership,
        registrationAnchorStore: f.disk.registration, adoptionAnchorStore: f.disk.adoption,
        cache: f.disk.cache
      )
      .prepareInterruptedTransaction(vaultID: Core.vaultID, expectedOwner: f.owner.publicIdentity)
    }
    guard case .ready(let state) = result else { throw Stop.interrupted }
    return state
  }
  private func current(_ f: Fixture) throws -> V3RecoveryManifestEnvelope {
    let checkpoint = try V3ManifestCheckpoint(canonicalBytes: #require(f.disk.checkpoints.value))
    return try V3RecoveryManifestCodec().parseEnvelope(
      Data(contentsOf: f.disk.manifestURL(checkpoint.envelopeDigest)))
  }
  private func ordinary(_ f: Fixture, session: V3DeviceWrappedVaultKeySessionStore)
    -> V3RecoveryVaultMutationService
  {
    .init(
      vaultID: Core.vaultID, session: session, objectStore: f.disk.store,
      checkpointStore: f.disk.checkpoints,
      recoveryAnchorStore: f.disk.ownership, registrationAnchorStore: f.disk.registration,
      adoptionAnchorStore: f.disk.adoption, cache: f.disk.cache)
  }
  private func pin(
    _ f: Fixture, data: Data, entries: [V3EncryptedEntry], kind: VaultTransactionMutationKind
  ) throws {
    let digest = Data(SHA256.hash(data: data))
    let selectors = entries.map {
      V3ImmutableTransactionRecoveryEntry(
        entryID: $0.context.entryID, digest: Data(SHA256.hash(data: $0.canonicalBytes)))
    }.sorted { $0.entryID < $1.entryID }
    let intent = try V3ImmutableTransactionRecoveryIntent(
      operationID: f.disk.operationID, kind: kind,
      vaultID: Core.vaultID, expectedCheckpoint: f.checkpoint, expectedHeads: [f.parent.digest],
      candidateManifestDigest: digest, stagedEntries: selectors)
    try f.disk.store.persistRecoveryIntent(intent.canonicalBytes, operationID: f.disk.operationID)
    try f.disk.store.stageManifest(data, digest: digest, operationID: f.disk.operationID)
    for entry in entries {
      try f.disk.store.stageEntry(
        entry.canonicalBytes, entryID: entry.context.entryID,
        digest: Data(SHA256.hash(data: entry.canonicalBytes)), operationID: f.disk.operationID)
    }
    f.disk.ownership.value = try V3ImmutableTransactionRecoveryAnchor(
      operationID: f.disk.operationID,
      vaultID: Core.vaultID, intentDigest: Data(SHA256.hash(data: intent.canonicalBytes)),
      phase: .recoverable
    ).canonicalBytes
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
