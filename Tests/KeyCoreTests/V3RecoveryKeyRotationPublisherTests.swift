import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Genuine profile crypto and contained filesystem durability. Only local
/// persistence failures and interruption boundaries are scripted.
struct V3RecoveryKeyRotationPublisherTests {
  private typealias Core = V3RecoveryRegistrationTests
  private typealias Fixture = V3RecoveryContentMutationPublisherTests.Fixture
  private typealias Stop = V3RecoveryContentMutationPublisherTests.Stop
  private static let nextKey = Data(repeating: 0x44, count: 32)
  private static let phases: [V3ImmutableTransactionPhase] = [
    .recoveryAnchorPrepared, .recoveryIntentPersisted, .recoveryArmed,
    .entryStaged(index: 0), .entryStaged(index: 1), .manifestStaged,
    .repositoryStateRechecked, .entryPublished(index: 0), .entryPublished(index: 1),
    .publishedEntriesValidated, .manifestPublished, .publishedManifestValidated,
    .checkpointAdvanced, .cleanupCompleted,
  ]

  @Test(arguments: [false, true])
  func manifestLastRotationPreservesCoverageAndCachesExactCommittedBytes(empty: Bool) throws {
    let f = try Fixture(empty: empty)
    defer { f.remove() }
    let candidate = try build(f)
    let recorded = Phases()
    let commit = try publish(f, candidate, observer: Observer { recorded.append($0) })
    let expected =
      empty
      ? Self.phases.filter {
        switch $0 {
        case .entryStaged, .entryPublished: false
        default: true
        }
      } : Self.phases
    #expect(recorded.value == expected)
    #expect(commit.envelope == candidate.envelope && f.ownership.value == nil)
    #expect(f.checkpoints.value == commit.checkpoint.canonicalBytes)
    #expect(
      try f.cache.load(for: commit.checkpoint) == .available(candidate.envelope.canonicalBytes))
    #expect(
      try Data(contentsOf: f.manifestURL(candidate.envelope.digest))
        == candidate.envelope.canonicalBytes)
    #expect(commit.envelope.body.recovery.recipients == f.parent.body.recovery.recipients)
    #expect(f.core.owner.signatures == 2 && f.core.owner.unwraps == 1)
  }

  @Test(arguments: 0..<14)
  func everyPublicationBoundaryResumesExactEpochOrRetainsOldCheckpoint(phase: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try build(f)
    #expect(throws: Stop.interrupted) {
      try publish(
        f, candidate, observer: Observer { if $0 == Self.phases[phase] { throw Stop.interrupted } })
    }
    let outcome = try resume(f, currentKey: phase >= 12 ? nil : Core.nextKey)
    if phase < 5 {
      #expect(outcome == .abandoned(operationID: f.operationID))
      #expect(f.checkpoints.value == f.checkpoint.canonicalBytes)
      #expect(
        !FileManager.default.fileExists(atPath: f.manifestURL(candidate.envelope.digest).path))
    } else {
      #expect(
        outcome
          == (phase == 13
            ? .nothingToRecover
            : (phase == 12
              ? .alreadyCompleted(operationID: f.operationID)
              : .completed(operationID: f.operationID))))
      #expect(
        f.checkpoints.value
          == (try V3ManifestCheckpoint(
            vaultID: Core.vaultID, envelopeDigest: candidate.envelope.digest)).canonicalBytes)
      #expect(
        try Data(contentsOf: f.manifestURL(candidate.envelope.digest))
          == candidate.envelope.canonicalBytes)
    }
    #expect(f.ownership.value == nil && f.core.owner.signatures == 2 && f.core.owner.unwraps == 1)
  }

  @Test func failedCheckpointCASResumesWithoutCreatingOrSigningAnotherEpoch() throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try build(f)
    f.checkpoints.rejectAdvance = true
    #expect(throws: Stop.interrupted) { try publish(f, candidate) }
    #expect(f.ownership.value != nil && f.checkpoints.value == f.checkpoint.canonicalBytes)
    f.checkpoints.rejectAdvance = false
    #expect(try resume(f) == .completed(operationID: f.operationID))
    #expect(
      try Data(contentsOf: f.manifestURL(candidate.envelope.digest))
        == candidate.envelope.canonicalBytes)
    #expect(f.core.owner.signatures == 2 && f.core.owner.unwraps == 1)
  }

  @Test func committedCleanupRequiresOnlyPinnedCurrentSnapshotNotOldKeysOrCiphertext() throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try build(f)
    f.ownership.rejectClear = true
    let commit = try publish(f, candidate)
    #expect(f.ownership.value != nil)
    for entry in Array(f.entries.values) + Array(f.core.entries.values) {
      try FileManager.default.removeItem(at: f.entryURL(entry))
    }
    try FileManager.default.removeItem(at: f.manifestURL(f.parent.digest))
    try FileManager.default.removeItem(at: f.manifestURL(f.core.parent.digest))
    try FileManager.default.removeItem(
      at: f.cacheRoot.appendingPathComponent("\(Core.vaultID).json"))
    f.ownership.rejectClear = false
    #expect(try resume(f, currentKey: nil) == .alreadyCompleted(operationID: f.operationID))
    #expect(f.ownership.value == nil && f.checkpoints.value == commit.checkpoint.canonicalBytes)
    #expect(
      try f.cache.load(for: commit.checkpoint) == .available(candidate.envelope.canonicalBytes))
  }

  @Test(arguments: 0..<4)
  func uncommittedResumeRefusesMissingWrongKeysAndWrongOwnerWithoutLosingIntent(variant: Int) throws
  {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try build(f)
    #expect(throws: Stop.interrupted) {
      try publish(
        f, candidate, observer: Observer { if $0 == .manifestStaged { throw Stop.interrupted } })
    }
    let pending = f.ownership.value
    #expect(throws: (any Error).self) {
      try resume(
        f, currentKey: variant == 0 ? nil : (variant == 1 ? Self.nextKey : Core.nextKey),
        nextKey: variant == 2 ? Core.nextKey : Self.nextKey,
        owner: variant == 3 ? Core.Owner().publicIdentity : f.core.owner.publicIdentity)
    }
    #expect(f.ownership.value == pending && f.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(try resume(f) == .completed(operationID: f.operationID))
  }

  @Test(arguments: 0..<3)
  func invalidInputsAndCheckpointRefuseBeforePrivateOperationOrReservation(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try build(f)
    if variant == 2 { f.checkpoints.value = Data([1]) }
    #expect(throws: (any Error).self) {
      try publisher(f).publish(
        candidate, currentVaultKey: variant == 0 ? Self.nextKey : Core.nextKey,
        nextVaultKey: variant == 1 ? Core.nextKey : Self.nextKey,
        identity: f.core.owner, reason: "Software fixture")
    }
    #expect(f.ownership.value == nil && f.core.owner.unwraps == 0)
  }

  @Test func cancellationAndChangedSourceDuringPrivateApprovalNeverReserveWork() throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try build(f)
    f.core.owner.cancelUnwrap = true
    #expect(throws: Core.FixtureError.cancelled) { try publish(f, candidate) }
    #expect(f.ownership.value == nil && f.core.owner.unwraps == 1)
    f.core.owner.cancelUnwrap = false
    let branch = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "other edit"))
    f.core.owner.onUnwrap = { try f.seed(branch.envelope, entries: branch.stagedEntries) }
    #expect(throws: V3RecoveryValidationError.sourceChanged) { try publish(f, candidate) }
    #expect(f.ownership.value == nil && f.core.owner.unwraps == 2)
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes)
  }

  @Test(arguments: [false, true])
  func pendingRegistrationOrAdoptionBlocksPublicationAndResume(registration: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try build(f)
    let other = registration ? f.registration : f.adoption
    other.value = Data([1])
    #expect(throws: V3RecoveryContentPublicationError.otherMutationPending) {
      try publish(f, candidate)
    }
    #expect(f.core.owner.unwraps == 0 && f.ownership.value == nil)
    other.value = nil
    #expect(throws: Stop.interrupted) {
      try publish(
        f, candidate, observer: Observer { if $0 == .manifestStaged { throw Stop.interrupted } })
    }
    let pending = f.ownership.value
    other.value = Data([1])
    #expect(throws: V3RecoveryContentPublicationError.otherMutationPending) { try resume(f) }
    #expect(f.ownership.value == pending)
  }

  @Test(arguments: [
    V3ImmutableTransactionPhase.repositoryStateRechecked,
    .publishedEntriesValidated, .publishedManifestValidated,
  ])
  func concurrentBranchNeverAdvancesTheLocalCheckpoint(phase: V3ImmutableTransactionPhase) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try build(f)
    let branch = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "other edit"))
    #expect(throws: V3RecoveryValidationError.sourceChanged) {
      try publish(
        f, candidate,
        observer: Observer {
          if $0 == phase {
            try f.seed(branch.envelope, entries: branch.stagedEntries)
          }
        })
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes && f.ownership.value != nil)
    #expect(throws: (any Error).self) { try resume(f) }
    #expect(f.ownership.value != nil)
  }

  @Test(arguments: [false, true])
  func changedOwnershipOrCheckpointStopsBeforeFurtherWrites(checkpoint: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try build(f)
    let replacement = Data([1])
    #expect(throws: (any Error).self) {
      try publish(
        f, candidate,
        observer: Observer {
          if $0 == .repositoryStateRechecked {
            if checkpoint {
              f.checkpoints.value = replacement
            } else {
              f.ownership.value = replacement
            }
          }
        })
    }
    #expect(!FileManager.default.fileExists(atPath: f.manifestURL(candidate.envelope.digest).path))
    #expect(checkpoint ? f.checkpoints.value == replacement : f.ownership.value == replacement)
  }

  @Test(arguments: [
    V3ImmutableTransactionPhase.repositoryStateRechecked, .publishedEntriesValidated,
    .publishedManifestValidated,
  ])
  func authorityWorkAppearingDuringPublicationStopsBeforeCheckpointAdvance(
    phase: V3ImmutableTransactionPhase
  ) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try build(f)
    #expect(throws: V3RecoveryContentPublicationError.otherMutationPending) {
      try publish(
        f, candidate,
        observer: Observer {
          if $0 == phase { f.adoption.value = Data([1]) }
        })
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes && f.ownership.value != nil)
    #expect(f.core.owner.unwraps == 1)
  }

  @Test func unavailablePublishedEntryRetainsPendingRotationUntilExactBytesReturn() throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try build(f)
    let entry = try #require(candidate.stagedEntries.first)
    #expect(throws: V3RecoveryValidationError.sourceUnavailable) {
      try publish(
        f, candidate,
        observer: Observer {
          if $0 == .manifestPublished { try FileManager.default.removeItem(at: f.entryURL(entry)) }
        })
    }
    let pending = f.ownership.value
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes && pending != nil)
    #expect(throws: V3ImmutableTransactionRecoveryError.transactionDirectoryUnavailable) {
      try resume(f)
    }
    #expect(f.ownership.value == pending)
    try f.store.stageEntry(
      entry.canonicalBytes, entryID: entry.context.entryID,
      digest: Data(SHA256.hash(data: entry.canonicalBytes)), operationID: f.operationID)
    try f.store.publishStagedEntry(
      entry.canonicalBytes, entryID: entry.context.entryID,
      digest: Data(SHA256.hash(data: entry.canonicalBytes)), operationID: f.operationID)
    #expect(try resume(f) == .completed(operationID: f.operationID))
    #expect(f.core.owner.signatures == 2 && f.core.owner.unwraps == 1)
  }

  @Test func routedAnchorMustRemainExactEvenBeforePreparedIntentCleanup() throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try build(f)
    #expect(throws: Stop.interrupted) {
      try publish(
        f, candidate,
        observer: Observer { if $0 == .recoveryAnchorPrepared { throw Stop.interrupted } })
    }
    let pending = try #require(f.ownership.value)
    #expect(throws: (any Error).self) { try resume(f, expectedAnchor: Data([1])) }
    #expect(f.ownership.value == pending)
    #expect(try resume(f, expectedAnchor: pending) == .abandoned(operationID: f.operationID))
  }

  @Test func lifecycleAndOrdinaryIntentsCannotBeResumedThroughEachOthersValidator() throws {
    let f = try Fixture()
    defer { f.remove() }
    let ordinary = try f.build(.remove(name: "fixture/totp"))
    #expect(throws: Stop.interrupted) {
      try f.publisher(observer: Observer { if $0 == .manifestStaged { throw Stop.interrupted } })
        .publish(ordinary, vaultKey: Core.nextKey)
    }
    let pending = f.ownership.value
    #expect(
      throws: V3ImmutableTransactionRecoveryError.invalidIntent(operationID: f.operationID.rawValue)
    ) {
      try resume(f)
    }
    #expect(f.ownership.value == pending)
    #expect(
      try f.publisher().recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
        == .completed(operationID: f.operationID))
    let g = try Fixture()
    defer { g.remove() }
    let rotated = try build(g)
    #expect(throws: Stop.interrupted) {
      try publish(
        g, rotated, observer: Observer { if $0 == .manifestStaged { throw Stop.interrupted } })
    }
    let rotationPending = g.ownership.value
    #expect(
      throws: V3ImmutableTransactionRecoveryError.invalidIntent(operationID: g.operationID.rawValue)
    ) {
      try g.publisher().recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Self.nextKey)
    }
    #expect(g.ownership.value == rotationPending)
    let permanentPublisher = V3DeviceWrappedContentMutationPublisher(
      mutationOwner: VaultTransactionMutationOwner(), objectStore: g.store,
      checkpointStore: g.checkpoints, recoveryAnchorStore: g.ownership, cache: g.cache)
    #expect(
      throws: V3ImmutableTransactionRecoveryError.invalidIntent(
        operationID: g.operationID.rawValue)
    ) {
      try permanentPublisher.recoverInterruptedTransaction(
        vaultID: Core.vaultID, vaultKey: Self.nextKey)
    }
    #expect(g.ownership.value == rotationPending)
    #expect(try resume(g) == .completed(operationID: g.operationID))
  }

  @Test func recipientRemovalCannotBePublishedAsAnUnchangedRosterRotation() throws {
    let f = try Fixture()
    defer { f.remove() }
    let plan = try V3RecoveryRecipientRemovalPlanner().plan(
      checkpoint: f.checkpoint, parent: f.parent, currentVaultKey: Core.nextKey,
      authorizingDeviceID: f.core.owner.publicIdentity.deviceID, removing: f.anchor.recipientID)
    let removed = try V3RecoveryRecipientRemovalBuilder().build(
      parent: f.parent, currentEntries: f.entries, plan: plan, currentVaultKey: Core.nextKey,
      nextVaultKey: Self.nextKey, owner: f.core.owner, reason: "Owned policy fixture")
    #expect(throws: V3RecoveryKeyRotationError.invalidCandidate) {
      try publish(
        f,
        .init(
          expectedCheckpoint: f.checkpoint,
          envelope: removed.envelope, stagedEntries: removed.stagedEntries))
    }
    #expect(f.ownership.value == nil && f.core.owner.unwraps == 0)
  }

  @Test(arguments: 0..<3)
  func sourceAndProjectedBudgetsRefuseBeforePrivateOperation(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try build(f)
    let limits =
      [
        Core.Fixture.limits(entries: 3), Core.Fixture.limits(entryBytes: 1),
        Core.Fixture.limits(totalBytes: 1),
      ][variant]
    #expect(throws: (any Error).self) {
      try publisher(f, limits: limits).publish(
        candidate, currentVaultKey: Core.nextKey, nextVaultKey: Self.nextKey,
        identity: f.core.owner, reason: "Software fixture")
    }
    #expect(f.core.owner.unwraps == 0 && f.ownership.value == nil)
  }

  @Test(arguments: [false, true])
  func primaryAndBackupRecoverAfterDurableRotationAndOrdinarySave(backup: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let (anchors, tokens, digest) = try publishedChain(root)
    let store = V3FilesystemTransactionArtifactStore(
      rootHandle: try VaultRootDirectoryHandle(opening: root))
    let index = backup ? 1 : 0
    let token = tokens[index]
    let selected = try V3RecoveryHistorySelector(source: store).select(
      anchor: anchors[index], credentialPublicKey: token.publicKey.x963Representation)
    let calls = Core.Counter()
    let receiver = try PIVHPKEReceiver(publicBytes: token.publicKey.x963Representation) { peer in
      calls.increment()
      return try token.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: peer)
      ).withUnsafeBytes { Data($0) }
    }
    let snapshot = try V3RecoverySnapshotVerifier(source: store).open(
      selected, boundAnchor: anchors[index], receiver: receiver)
    #expect(calls.value == 1 && selected.head.digest == digest)
    #expect(
      snapshot.entries.first { $0.name == "fixture/secret" }?.plaintext == "after durable rotation")
    #expect(snapshot.entries.first { $0.name == "fixture/totp" }?.plaintext == "JBSWY3DPEHPK3PXP")
  }

  private func publishedChain(_ root: URL) throws -> (
    [V3RecoveryAnchor], [P256.KeyAgreement.PrivateKey], Data
  ) {
    let f = try Fixture(root: root)
    let backup = try #require(f.core.parent.body.recovery.recipients.first)
    let backupAnchor = try V3RecoveryAnchor(
      floor: .init(vaultID: Core.vaultID, envelopeDigest: f.core.parent.digest),
      recipientID: backup.recipientID, registrationID: backup.registrationID, slot: .keyManagement)
    let candidate = try build(f)
    let commit = try publish(f, candidate)
    let entries = try V3EntrySnapshotValidator(limits: .standard).entryMap(candidate.stagedEntries)
    let session = V3DeviceWrappedVaultKeySessionStore()
    try session.install(
      Self.nextKey, vaultID: Core.vaultID, keyID: commit.envelope.body.fields.keyID)
    let service = V3RecoveryVaultMutationService(
      vaultID: Core.vaultID, session: session, objectStore: f.store, checkpointStore: f.checkpoints,
      recoveryAnchorStore: f.ownership, registrationAnchorStore: f.registration,
      adoptionAnchorStore: f.adoption, cache: f.cache)
    try VaultTransactionMutationOwner().perform(.editEntry) { context in
      try service.edit(
        name: "fixture/secret", secret: "after durable rotation", type: .secret,
        operationID: context.operationID)
    }
    session.invalidate()
    let obsolete =
      Array(f.core.entries.values) + Array(f.entries.values)
      + entries.values.filter { $0.context.name == "fixture/secret" }
    for entry in obsolete { try FileManager.default.removeItem(at: f.entryURL(entry)) }
    let last = try V3ManifestCheckpoint(canonicalBytes: #require(f.checkpoints.value))
    return ([f.anchor, backupAnchor], [f.core.token, f.core.backupToken], last.envelopeDigest)
  }

  private func build(_ f: Fixture) throws -> V3RecoveryKeyRotationCandidate {
    try V3RecoveryKeyRotationBuilder().build(
      checkpoint: f.checkpoint, parent: f.parent, currentEntries: f.entries,
      currentVaultKey: Core.nextKey, nextVaultKey: Self.nextKey, owner: f.core.owner,
      reason: "Software fixture")
  }
  private func publisher(
    _ f: Fixture,
    observer: any V3ImmutableTransactionPhaseObserving = V3NoopContentTransactionPhaseObserver(),
    limits: V3ManifestRepositoryLimits = .standard
  )
    -> V3RecoveryKeyRotationPublisher
  {
    .init(
      mutationOwner: VaultTransactionMutationOwner(makeOperationID: { f.operationID }),
      objectStore: f.store, checkpointStore: f.checkpoints, recoveryAnchorStore: f.ownership,
      registrationAnchorStore: f.registration, adoptionAnchorStore: f.adoption, cache: f.cache,
      limits: limits, phaseObserver: observer)
  }
  private func publish(
    _ f: Fixture, _ candidate: V3RecoveryKeyRotationCandidate,
    observer: any V3ImmutableTransactionPhaseObserving = V3NoopContentTransactionPhaseObserver()
  ) throws -> V3RecoveryKeyRotationCommit {
    try publisher(f, observer: observer).publish(
      candidate, currentVaultKey: Core.nextKey,
      nextVaultKey: Self.nextKey, identity: f.core.owner, reason: "Software wrapper fixture")
  }
  private func resume(
    _ f: Fixture, currentKey: Data? = Core.nextKey, nextKey: Data = Self.nextKey,
    owner: V3EnrollmentDeviceIdentity? = nil, expectedAnchor: Data? = nil
  ) throws -> V3ImmutableTransactionRecoveryOutcome {
    try publisher(f).recoverInterruptedTransaction(
      vaultID: Core.vaultID, currentVaultKey: currentKey,
      nextVaultKey: nextKey, expectedOwner: owner ?? f.core.owner.publicIdentity,
      expectedAnchor: expectedAnchor)
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
  private final class Phases: @unchecked Sendable {
    private let lock = NSLock()
    private var data: [V3ImmutableTransactionPhase] = []
    var value: [V3ImmutableTransactionPhase] { lock.withLock { data } }
    func append(_ phase: V3ImmutableTransactionPhase) { lock.withLock { data.append(phase) } }
  }
}
