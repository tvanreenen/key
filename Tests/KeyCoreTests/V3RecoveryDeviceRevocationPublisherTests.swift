import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Actual enrollment/revocation cryptography and contained filesystem storage.
/// Only local persistence failures, interruption and Mac operations are scripted.
struct V3RecoveryDeviceRevocationPublisherTests {
  private typealias Core = V3RecoveryRegistrationTests
  private typealias Publication = V3RecoveryContentMutationPublisherTests
  private typealias Enrollment = V3RecoveryDeviceEnrollmentPublisherTests
  private typealias Stop = Publication.Stop
  private static let currentKey = Data(repeating: 0x33, count: 32)
  private static let nextKey = Data(repeating: 0x44, count: 32)
  private static let phases: [V3ImmutableTransactionPhase] = [
    .recoveryAnchorPrepared, .recoveryIntentPersisted, .recoveryArmed,
    .entryStaged(index: 0), .entryStaged(index: 1), .manifestStaged,
    .repositoryStateRechecked, .entryPublished(index: 0), .entryPublished(index: 1),
    .publishedEntriesValidated, .manifestPublished, .publishedManifestValidated,
    .checkpointAdvanced, .cleanupCompleted,
  ]

  @Test(arguments: [false, true])
  func publishesOnlyReviewedDeviceAndPreservesRecoveryCoverage(empty: Bool) throws {
    let f = try Fixture(empty: empty)
    defer { f.enrollment.disk.remove() }
    let candidate = try f.build()
    let commit = try publish(f, candidate)
    #expect(commit.envelope == candidate.envelope && f.enrollment.disk.ownership.value == nil)
    #expect(f.enrollment.disk.checkpoints.value == commit.checkpoint.canonicalBytes)
    #expect(
      try f.enrollment.disk.cache.load(for: commit.checkpoint)
        == .available(candidate.envelope.canonicalBytes))
    #expect(commit.envelope.body.fields.devices == candidate.plan.resultingDevices)
    #expect(commit.envelope.body.recovery.recipients == f.parent.body.recovery.recipients)
    #expect(commit.envelope.body.recovery.generationID == f.parent.body.recovery.generationID)
    #expect(
      !commit.envelope.body.fields.wrappedKeys.contains {
        $0.recipientDeviceID == f.enrollment.joiner.publicIdentity.deviceID
      })
    #expect(f.owner.signatures == f.signatures + 1 && f.owner.unwraps == f.unwraps + 1)
    #expect(f.enrollment.joiner.unwraps == 0)
    #expect(throws: (any Error).self) { try publish(f, candidate) }
    #expect(f.owner.unwraps == f.unwraps + 1)
  }

  @Test(arguments: 0..<14)
  func everyBoundaryResumesExactReviewedRevocationWithoutSigningAgain(phase: Int) throws {
    let f = try Fixture()
    defer { f.enrollment.disk.remove() }
    let candidate = try f.build()
    #expect(throws: Stop.interrupted) {
      try publish(
        f, candidate, observer: Observer { if $0 == Self.phases[phase] { throw Stop.interrupted } })
    }
    let outcome = try resume(f, currentKey: phase >= 12 ? nil : Self.currentKey)
    if phase < 5 {
      #expect(outcome == .abandoned(operationID: f.enrollment.disk.operationID))
      #expect(f.enrollment.disk.checkpoints.value == f.checkpoint.canonicalBytes)
      #expect(
        !FileManager.default.fileExists(
          atPath: f.enrollment.disk.manifestURL(candidate.envelope.digest).path))
    } else {
      #expect(
        outcome
          == (phase == 13
            ? .nothingToRecover
            : (phase == 12
              ? .alreadyCompleted(operationID: f.enrollment.disk.operationID)
              : .completed(operationID: f.enrollment.disk.operationID))))
      #expect(
        f.enrollment.disk.checkpoints.value
          == (try V3ManifestCheckpoint(
            vaultID: Core.vaultID, envelopeDigest: candidate.envelope.digest)).canonicalBytes)
      #expect(
        try Data(contentsOf: f.enrollment.disk.manifestURL(candidate.envelope.digest))
          == candidate.envelope.canonicalBytes)
    }
    #expect(f.enrollment.disk.ownership.value == nil)
    #expect(f.owner.signatures == f.signatures + 1 && f.owner.unwraps == f.unwraps + 1)
  }

  @Test func intentPinsExactRosterBytesWithoutDuplicatingReviewOrPersistingKeys() throws {
    let f = try Fixture()
    defer { f.enrollment.disk.remove() }
    let candidate = try f.build()
    try interrupt(f, candidate)
    let anchor = try V3ImmutableTransactionRecoveryAnchor(
      canonicalBytes: #require(f.enrollment.disk.ownership.value))
    guard
      case .available(let bytes) = try f.enrollment.disk.store.readRecoveryIntent(
        operationID: anchor.operationID,
        maximumBytes: V3ImmutableTransactionRecoveryIntent.maximumBytes)
    else { throw Stop.interrupted }
    let intent = try V3ImmutableTransactionRecoveryIntent(canonicalBytes: bytes)
    #expect(
      intent.kind == .revokeDevice && intent.candidateManifestDigest == candidate.envelope.digest)
    #expect(intent.expectedCheckpoint == candidate.plan.expectedCheckpoint)
    #expect(intent.enrollmentTranscriptDigest == nil && intent.recoveryMergeResolutions == nil)
    #expect(Data(SHA256.hash(data: bytes)) == anchor.intentDigest)
    #expect(!String(decoding: bytes, as: UTF8.self).contains(Base64URL.encode(Self.nextKey)))
    guard
      case .ready(let selected) = try publisher(f).prepareInterruptedTransaction(
        vaultID: Core.vaultID, expectedOwner: f.owner.publicIdentity,
        expectedAnchor: anchor.canonicalBytes)
    else { throw Stop.interrupted }
    #expect(selected.manifestData == candidate.envelope.canonicalBytes)
    #expect(f.owner.unwraps == f.unwraps + 1)
    #expect(
      try resume(f, expectedAnchor: anchor.canonicalBytes)
        == .completed(operationID: anchor.operationID))
  }

  @Test(arguments: 0..<3)
  func independentApprovedPlanMustMatchCandidateExactly(variant: Int) throws {
    let f = try Fixture()
    defer { f.enrollment.disk.remove() }
    let candidate = try f.build()
    let original = candidate.plan
    let changed = V3DeviceWrappedRevocationPlan(
      expectedCheckpoint: variant == 0 ? f.enrollment.disk.checkpoint : original.expectedCheckpoint,
      authorizingDevice: variant == 1 ? original.revokedDevice : original.authorizingDevice,
      revokedDevice: variant == 2 ? original.authorizingDevice : original.revokedDevice,
      resultingDevices: original.resultingDevices)
    #expect(throws: V3RecoveryDeviceRevocationError.invalidPlan) {
      try publisher(f).publish(
        candidate, approvedPlan: changed, currentVaultKey: Self.currentKey,
        nextVaultKey: Self.nextKey, identity: f.owner, reason: "Owned review fixture")
    }
    #expect(f.owner.unwraps == f.unwraps && f.enrollment.disk.ownership.value == nil)
  }

  @Test func failedCheckpointCASFinishesPinnedCandidateWithoutAnotherReviewOrSignature() throws {
    let f = try Fixture()
    defer { f.enrollment.disk.remove() }
    let candidate = try f.build()
    f.enrollment.disk.checkpoints.rejectAdvance = true
    #expect(throws: Stop.interrupted) { try publish(f, candidate) }
    #expect(f.enrollment.disk.checkpoints.value == f.checkpoint.canonicalBytes)
    f.enrollment.disk.checkpoints.rejectAdvance = false
    #expect(try resume(f) == .completed(operationID: f.enrollment.disk.operationID))
    #expect(f.owner.signatures == f.signatures + 1 && f.owner.unwraps == f.unwraps + 1)
  }

  @Test func committedCleanupNeedsNoOldKeySnapshotManifestOrCache() throws {
    let f = try Fixture()
    defer { f.enrollment.disk.remove() }
    let candidate = try f.build()
    f.enrollment.disk.ownership.rejectClear = true
    let commit = try publish(f, candidate)
    let disk = f.enrollment.disk
    for entry in Array(f.entries.values) + Array(disk.entries.values)
      + Array(disk.core.entries.values)
    {
      try FileManager.default.removeItem(at: disk.entryURL(entry))
    }
    for envelope in [f.parent, disk.parent, disk.core.parent] {
      try FileManager.default.removeItem(at: disk.manifestURL(envelope.digest))
    }
    try FileManager.default.removeItem(
      at: disk.cacheRoot.appendingPathComponent("\(Core.vaultID).json"))
    disk.ownership.rejectClear = false
    #expect(try resume(f, currentKey: nil) == .alreadyCompleted(operationID: disk.operationID))
    #expect(
      disk.ownership.value == nil && disk.checkpoints.value == commit.checkpoint.canonicalBytes)
    #expect(
      try disk.cache.load(for: commit.checkpoint) == .available(candidate.envelope.canonicalBytes))
    #expect(f.owner.signatures == f.signatures + 1 && f.owner.unwraps == f.unwraps + 1)
  }

  @Test(arguments: 0..<4)
  func uncommittedResumeRefusesMissingOrWrongKeysAndWrongOwnerRetainingIntent(variant: Int) throws {
    let f = try Fixture()
    defer { f.enrollment.disk.remove() }
    let candidate = try f.build()
    try interrupt(f, candidate)
    let pending = f.enrollment.disk.ownership.value
    #expect(throws: (any Error).self) {
      try resume(
        f, currentKey: variant == 0 ? nil : (variant == 1 ? Self.nextKey : Self.currentKey),
        nextKey: variant == 2 ? Self.currentKey : Self.nextKey,
        owner: variant == 3 ? Core.Owner().publicIdentity : nil)
    }
    #expect(
      f.enrollment.disk.ownership.value == pending
        && f.enrollment.disk.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(try resume(f) == .completed(operationID: f.enrollment.disk.operationID))
  }

  @Test(arguments: 0..<4)
  func invalidKeyOwnerOrCheckpointRefusesBeforeMacOperation(variant: Int) throws {
    let f = try Fixture()
    defer { f.enrollment.disk.remove() }
    let candidate = try f.build()
    if variant == 3 { f.enrollment.disk.checkpoints.value = Data([1]) }
    #expect(throws: (any Error).self) {
      try publisher(f).publish(
        candidate, approvedPlan: candidate.plan,
        currentVaultKey: variant == 0 ? Self.nextKey : Self.currentKey,
        nextVaultKey: variant == 1 ? Self.currentKey : Self.nextKey,
        identity: variant == 2 ? Core.Owner() : f.owner, reason: "Owned validation fixture")
    }
    #expect(f.enrollment.disk.ownership.value == nil && f.owner.unwraps == f.unwraps)
  }

  @Test func cancelledMacVerificationDoesNotReserveOrRetry() throws {
    let f = try Fixture()
    defer { f.enrollment.disk.remove() }
    let candidate = try f.build()
    f.owner.cancelUnwrap = true
    #expect(throws: Core.FixtureError.cancelled) { try publish(f, candidate) }
    #expect(f.enrollment.disk.ownership.value == nil && f.owner.unwraps == f.unwraps + 1)
  }

  @Test func mismatchedMacWrapperResultCannotReserveWork() throws {
    let f = try Fixture()
    defer { f.enrollment.disk.remove() }
    let candidate = try f.build()
    #expect(throws: V3RecoveryKeyRotationError.localWrapperMismatch) {
      try publisher(f).publish(
        candidate, approvedPlan: candidate.plan, currentVaultKey: Self.currentKey,
        nextVaultKey: Self.nextKey, identity: IncorrectUnwrapper(base: f.owner),
        reason: "Owned provider-result fixture")
    }
    #expect(f.enrollment.disk.ownership.value == nil && f.owner.unwraps == f.unwraps + 1)
  }

  @Test(arguments: [false, true])
  func missingRequiredSnapshotRetainsUncommittedOrCommittedIntent(committed: Bool) throws {
    let f = try Fixture()
    defer { f.enrollment.disk.remove() }
    let candidate = try f.build()
    let disk = f.enrollment.disk
    if committed {
      disk.ownership.rejectClear = true
      _ = try publish(f, candidate)
      disk.ownership.rejectClear = false
    } else {
      try interrupt(f, candidate)
    }
    let pending = disk.ownership.value
    let checkpoint = disk.checkpoints.value
    let missing =
      try committed ? #require(candidate.stagedEntries.first) : #require(f.entries.values.first)
    try FileManager.default.removeItem(at: disk.entryURL(missing))
    #expect(throws: (any Error).self) {
      try resume(f, currentKey: committed ? nil : Self.currentKey)
    }
    #expect(disk.ownership.value == pending && disk.checkpoints.value == checkpoint)
  }

  @Test(arguments: [false, true])
  func otherWellFormedEpochPoliciesAreNotRevocationApproval(removal: Bool) throws {
    let f = try Fixture()
    defer { f.enrollment.disk.remove() }
    let envelope: V3RecoveryManifestEnvelope
    let staged: [V3EncryptedEntry]
    if removal {
      let reviewed = try V3RecoveryRecipientRemovalPlanner().plan(
        checkpoint: f.checkpoint, parent: f.parent, currentVaultKey: Self.currentKey,
        authorizingDeviceID: f.owner.publicIdentity.deviceID,
        removing: f.enrollment.disk.anchor.recipientID)
      let candidate = try V3RecoveryRecipientRemovalBuilder().build(
        parent: f.parent, currentEntries: f.entries, plan: reviewed,
        currentVaultKey: Self.currentKey, nextVaultKey: Self.nextKey,
        owner: f.owner, reason: "Owned recipient-policy fixture")
      envelope = candidate.envelope
      staged = candidate.stagedEntries
    } else {
      let candidate = try V3RecoveryKeyRotationBuilder().build(
        checkpoint: f.checkpoint, parent: f.parent, currentEntries: f.entries,
        currentVaultKey: Self.currentKey, nextVaultKey: Self.nextKey,
        owner: f.owner, reason: "Owned rotation-policy fixture")
      envelope = candidate.envelope
      staged = candidate.stagedEntries
    }
    let plan = try f.plan()
    #expect(throws: V3RecoveryDeviceRevocationError.invalidPlan) {
      try publish(f, .init(plan: plan, envelope: envelope, stagedEntries: staged))
    }
    #expect(f.owner.unwraps == f.unwraps && f.enrollment.disk.ownership.value == nil)
    // A pinned selector cannot substitute the kind name for the required
    // one-device policy. All bytes here are owned signed software fixtures.
    let disk = f.enrollment.disk
    let references = staged.map {
      V3ImmutableTransactionRecoveryEntry(
        entryID: $0.context.entryID, digest: Data(SHA256.hash(data: $0.canonicalBytes)))
    }.sorted {
      $0.entryID == $1.entryID
        ? $0.digest.lexicographicallyPrecedes($1.digest) : $0.entryID < $1.entryID
    }
    let intent = try V3ImmutableTransactionRecoveryIntent(
      operationID: disk.operationID, kind: .revokeDevice, vaultID: Core.vaultID,
      expectedCheckpoint: f.checkpoint, expectedHeads: [f.parent.digest],
      candidateManifestDigest: envelope.digest, stagedEntries: references)
    try disk.store.persistRecoveryIntent(intent.canonicalBytes, operationID: disk.operationID)
    for entry in staged {
      try disk.store.stageEntry(
        entry.canonicalBytes, entryID: entry.context.entryID,
        digest: Data(SHA256.hash(data: entry.canonicalBytes)), operationID: disk.operationID)
    }
    try disk.store.stageManifest(
      envelope.canonicalBytes, digest: envelope.digest, operationID: disk.operationID)
    let anchor = try V3ImmutableTransactionRecoveryAnchor(
      operationID: disk.operationID, vaultID: Core.vaultID,
      intentDigest: Data(SHA256.hash(data: intent.canonicalBytes)), phase: .recoverable)
    disk.ownership.value = anchor.canonicalBytes
    guard
      case .ready(let selected) = try publisher(f).prepareInterruptedTransaction(
        vaultID: Core.vaultID, expectedOwner: f.owner.publicIdentity)
    else { throw Stop.interrupted }
    #expect(selected.manifestData == envelope.canonicalBytes)
    let validator = V3RecoveryDeviceRevocationTransactionValidator(
      objectStore: disk.store, registrationAnchorStore: disk.registration,
      adoptionAnchorStore: disk.adoption, currentVaultKey: Self.currentKey,
      expectedOwner: f.owner.publicIdentity, approvedPlan: nil, limits: .standard)
    let input = try validator.recoveryInput(
      intent: selected.intent, manifestData: selected.manifestData,
      stagedEntries: selected.availableEntries)
    #expect(throws: V3RecoveryDeviceRevocationError.invalidCandidate) {
      try validator.validate(input, vaultKey: Self.nextKey, alreadyCommitted: false)
    }
    #expect(
      throws: V3ImmutableTransactionRecoveryError.invalidRecoveryState(
        operationID: disk.operationID.rawValue)
    ) {
      try resume(f)
    }
    #expect(
      disk.ownership.value == anchor.canonicalBytes
        && disk.checkpoints.value == f.checkpoint.canonicalBytes)
  }

  @Test(arguments: 0..<4)
  func changesDuringMacVerificationStopBeforeReservation(variant: Int) throws {
    let f = try Fixture()
    defer { f.enrollment.disk.remove() }
    let candidate = try f.build()
    f.owner.onUnwrap = {
      switch variant {
      case 0: try f.addBranch()
      case 1: f.enrollment.disk.checkpoints.value = Data([1])
      case 2: f.enrollment.disk.registration.value = Data([1])
      default: f.enrollment.disk.adoption.value = Data([1])
      }
    }
    #expect(throws: (any Error).self) { try publish(f, candidate) }
    #expect(f.enrollment.disk.ownership.value == nil && f.owner.unwraps == f.unwraps + 1)
  }

  @Test(arguments: [false, true])
  func reciprocalPendingRegistrationOrAdoptionBlocksInitialAndResumedWork(registration: Bool) throws
  {
    let f = try Fixture()
    defer { f.enrollment.disk.remove() }
    let candidate = try f.build()
    let other = registration ? f.enrollment.disk.registration : f.enrollment.disk.adoption
    other.value = Data([1])
    #expect(throws: V3RecoveryContentPublicationError.otherMutationPending) {
      try publish(f, candidate)
    }
    #expect(f.owner.unwraps == f.unwraps && f.enrollment.disk.ownership.value == nil)
    other.value = nil
    try interrupt(f, candidate)
    let pending = f.enrollment.disk.ownership.value
    other.value = Data([1])
    #expect(throws: V3RecoveryContentPublicationError.otherMutationPending) { try resume(f) }
    #expect(f.enrollment.disk.ownership.value == pending)
    #expect(throws: V3RecoveryContentPublicationError.otherMutationPending) {
      try publisher(f).prepareInterruptedTransaction(
        vaultID: Core.vaultID, expectedOwner: f.owner.publicIdentity)
    }
  }

  @Test(arguments: [
    V3ImmutableTransactionPhase.repositoryStateRechecked,
    .publishedEntriesValidated, .publishedManifestValidated,
  ])
  func visibleBranchNeverAdvancesCheckpoint(phase: V3ImmutableTransactionPhase)
    throws
  {
    let f = try Fixture()
    defer { f.enrollment.disk.remove() }
    let candidate = try f.build()
    #expect(throws: (any Error).self) {
      try publish(
        f, candidate,
        observer: Observer {
          if $0 == phase { try f.addBranch() }
        })
    }
    #expect(
      f.enrollment.disk.checkpoints.value == f.checkpoint.canonicalBytes
        && f.enrollment.disk.ownership.value != nil)
    #expect(throws: (any Error).self) { try resume(f) }
  }

  @Test func routedAnchorIsCheckedBeforePreparedReservationCanBeAbandoned() throws {
    let f = try Fixture()
    defer { f.enrollment.disk.remove() }
    let candidate = try f.build()
    #expect(throws: Stop.interrupted) {
      try publish(
        f, candidate,
        observer: Observer { if $0 == .recoveryAnchorPrepared { throw Stop.interrupted } })
    }
    let pending = try #require(f.enrollment.disk.ownership.value)
    #expect(throws: (any Error).self) { try resume(f, expectedAnchor: Data([1])) }
    #expect(f.enrollment.disk.ownership.value == pending)
    #expect(
      try resume(f, expectedAnchor: pending)
        == .abandoned(operationID: f.enrollment.disk.operationID))
  }

  @Test(arguments: [VaultTransactionMutationKind.rotateVaultKey, .editEntry, .enrollDevice])
  func anotherKindCannotBeAbandonedOrResumedEvenWithChangedCheckpoint(
    kind: VaultTransactionMutationKind
  ) throws {
    let f = try Fixture()
    defer { f.enrollment.disk.remove() }
    let candidate = try f.build()
    let intent = try V3ImmutableTransactionRecoveryIntent(
      operationID: f.enrollment.disk.operationID, kind: kind, vaultID: Core.vaultID,
      expectedCheckpoint: f.checkpoint, expectedHeads: [f.parent.digest],
      candidateManifestDigest: candidate.envelope.digest, stagedEntries: [],
      enrollmentTranscriptDigest: kind == .enrollDevice ? Data(repeating: 1, count: 32) : nil)
    try f.enrollment.disk.store.persistRecoveryIntent(
      intent.canonicalBytes, operationID: intent.operationID)
    let anchor = try V3ImmutableTransactionRecoveryAnchor(
      operationID: intent.operationID, vaultID: Core.vaultID,
      intentDigest: Data(SHA256.hash(data: intent.canonicalBytes)), phase: .recoverable)
    f.enrollment.disk.ownership.value = anchor.canonicalBytes
    f.enrollment.disk.checkpoints.value = f.enrollment.disk.checkpoint.canonicalBytes
    #expect(
      throws: V3ImmutableTransactionRecoveryError.invalidIntent(
        operationID: intent.operationID.rawValue)
    ) {
      try resume(f)
    }
    #expect(f.enrollment.disk.ownership.value == anchor.canonicalBytes)
    #expect(f.owner.unwraps == f.unwraps)
  }

  @Test func revocationIntentCannotBeResumedAsRotationOrOrdinaryMutation() throws {
    let f = try Fixture()
    defer { f.enrollment.disk.remove() }
    let candidate = try f.build()
    try interrupt(f, candidate)
    let pending = f.enrollment.disk.ownership.value
    let disk = f.enrollment.disk
    let rotation = V3RecoveryKeyRotationPublisher(
      mutationOwner: VaultTransactionMutationOwner(), objectStore: disk.store,
      checkpointStore: disk.checkpoints, recoveryAnchorStore: disk.ownership,
      registrationAnchorStore: disk.registration, adoptionAnchorStore: disk.adoption,
      cache: disk.cache)
    #expect(
      throws: V3ImmutableTransactionRecoveryError.invalidIntent(
        operationID: disk.operationID.rawValue)
    ) {
      try rotation.recoverInterruptedTransaction(
        vaultID: Core.vaultID,
        currentVaultKey: Self.currentKey, nextVaultKey: Self.nextKey,
        expectedOwner: f.owner.publicIdentity)
    }
    #expect(
      throws: V3ImmutableTransactionRecoveryError.invalidIntent(
        operationID: disk.operationID.rawValue)
    ) {
      try disk.publisher().recoverInterruptedTransaction(
        vaultID: Core.vaultID, vaultKey: Self.nextKey)
    }
    #expect(disk.ownership.value == pending)
    #expect(try resume(f) == .completed(operationID: disk.operationID))
  }

  @Test(arguments: 0..<3)
  func sourceAndProjectedSnapshotBudgetsRefuseBeforeMacOperation(variant: Int) throws {
    let f = try Fixture()
    defer { f.enrollment.disk.remove() }
    let candidate = try f.build()
    let limits = [
      Core.Fixture.limits(entries: 3), Core.Fixture.limits(entryBytes: 1),
      Core.Fixture.limits(totalBytes: 1),
    ][variant]
    #expect(throws: (any Error).self) {
      try publisher(f, limits: limits).publish(
        candidate, approvedPlan: candidate.plan,
        currentVaultKey: Self.currentKey, nextVaultKey: Self.nextKey, identity: f.owner,
        reason: "Owned bound fixture")
    }
    #expect(f.owner.unwraps == f.unwraps && f.enrollment.disk.ownership.value == nil)
  }

  @Test(arguments: [false, true])
  func primaryAndBackupRecoverAfterDurableRevocationAndOrdinarySave(backup: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.enrollment.disk.remove() }
    let candidate = try f.build()
    let commit = try publish(f, candidate)
    let disk = f.enrollment.disk
    let session = V3DeviceWrappedVaultKeySessionStore()
    try session.install(
      Self.nextKey, vaultID: Core.vaultID, keyID: commit.envelope.body.fields.keyID)
    try V3RecoveryVaultMutationService(
      vaultID: Core.vaultID, session: session,
      objectStore: disk.store, checkpointStore: disk.checkpoints,
      recoveryAnchorStore: disk.ownership,
      registrationAnchorStore: disk.registration, adoptionAnchorStore: disk.adoption,
      cache: disk.cache
    ).edit(
      name: "fixture/secret", secret: "after durable revocation", type: .secret,
      operationID: .init())
    session.invalidate()
    let obsolete =
      Array(f.entries.values) + Array(disk.entries.values) + Array(disk.core.entries.values)
      + candidate.stagedEntries.filter { $0.context.name == "fixture/secret" }
    for entry in obsolete { try FileManager.default.removeItem(at: disk.entryURL(entry)) }
    let recipient = try #require(disk.core.parent.body.recovery.recipients.first)
    let backupAnchor = try V3RecoveryAnchor(
      floor: .init(vaultID: Core.vaultID, envelopeDigest: disk.core.parent.digest),
      recipientID: recipient.recipientID, registrationID: recipient.registrationID,
      slot: .keyManagement)
    let anchor = backup ? backupAnchor : disk.anchor
    let token = backup ? disk.core.backupToken : disk.core.token
    let selected = try V3RecoveryHistorySelector(source: disk.store).select(
      anchor: anchor, credentialPublicKey: token.publicKey.x963Representation)
    let calls = Core.Counter()
    let receiver = try PIVHPKEReceiver(publicBytes: token.publicKey.x963Representation) { peer in
      calls.increment()
      return try token.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: peer)
      )
      .withUnsafeBytes { Data($0) }
    }
    let opened = try V3RecoverySnapshotVerifier(source: disk.store).open(
      selected, boundAnchor: anchor, receiver: receiver)
    #expect(calls.value == 1)
    #expect(
      opened.entries.first { $0.name == "fixture/secret" }?.plaintext == "after durable revocation")
    #expect(opened.entries.first { $0.name == "fixture/totp" }?.plaintext == "JBSWY3DPEHPK3PXP")
    #expect(f.owner.signatures == f.signatures + 1 && f.owner.unwraps == f.unwraps + 1)
    #expect(f.enrollment.joiner.unwraps == 0)
  }

  private struct Fixture: Sendable {
    let enrollment: Enrollment.Fixture
    let parent: V3RecoveryManifestEnvelope
    let checkpoint: V3ManifestCheckpoint
    let entries: [V3EntryObjectKey: V3EncryptedEntry]
    let signatures: Int
    let unwraps: Int
    var owner: Core.Owner { enrollment.disk.core.owner }
    init(empty: Bool = false) throws {
      enrollment = try Enrollment.Fixture(empty: empty)
      let disk = enrollment.disk
      let joined = try V3RecoveryDeviceEnrollmentBuilder().build(
        checkpoint: disk.checkpoint, parent: disk.parent, currentEntries: disk.entries,
        state: enrollment.state, currentVaultKey: Core.nextKey, nextVaultKey: SelfKey.current,
        owner: disk.core.owner, at: 4_102_444_800, reason: "Owned enrollment fixture")
      let commit = try V3RecoveryDeviceEnrollmentPublisher(
        mutationOwner: VaultTransactionMutationOwner(), objectStore: disk.store,
        checkpointStore: disk.checkpoints, recoveryAnchorStore: disk.ownership,
        registrationAnchorStore: disk.registration, adoptionAnchorStore: disk.adoption,
        ceremonyStore: enrollment.local, cache: disk.cache
      ).publish(
        joined, state: enrollment.state, approvedTranscriptDigest: joined.transcriptDigest,
        currentVaultKey: Core.nextKey, nextVaultKey: SelfKey.current, identity: disk.core.owner,
        at: 4_102_444_800, reason: "Owned enrollment wrapper fixture")
      parent = commit.envelope
      checkpoint = commit.checkpoint
      entries = try V3EntrySnapshotValidator(limits: .standard).entryMap(joined.stagedEntries)
      signatures = disk.core.owner.signatures
      unwraps = disk.core.owner.unwraps
    }
    func plan() throws -> V3DeviceWrappedRevocationPlan {
      try V3RecoveryDeviceRevocationPlanner().plan(
        checkpoint: checkpoint, parent: parent,
        currentVaultKey: SelfKey.current, authorizingDeviceID: owner.publicIdentity.deviceID,
        revoking: enrollment.joiner.publicIdentity.deviceID)
    }
    func build() throws -> V3RecoveryDeviceRevocationCandidate {
      try V3RecoveryDeviceRevocationBuilder().build(
        parent: parent, currentEntries: entries,
        plan: plan(), currentVaultKey: SelfKey.current, nextVaultKey: SelfKey.next,
        owner: owner, reason: "Owned revocation fixture")
    }
    func addBranch() throws {
      let branch = try V3RecoveryContentMutationBuilder().build(
        .edit(name: "fixture/secret", type: .secret, plaintext: "other branch"),
        checkpoint: checkpoint, parent: parent, currentEntries: entries, vaultKey: SelfKey.current)
      try enrollment.disk.seed(branch.envelope, entries: branch.stagedEntries)
    }
  }
  private enum SelfKey {
    static let current = V3RecoveryDeviceRevocationPublisherTests.currentKey
    static let next = V3RecoveryDeviceRevocationPublisherTests.nextKey
  }
  private func publisher(
    _ f: Fixture,
    observer: any V3ImmutableTransactionPhaseObserving = V3NoopContentTransactionPhaseObserver(),
    limits: V3ManifestRepositoryLimits = .standard
  ) -> V3RecoveryDeviceRevocationPublisher {
    let disk = f.enrollment.disk
    return .init(
      mutationOwner: VaultTransactionMutationOwner(makeOperationID: { disk.operationID }),
      objectStore: disk.store, checkpointStore: disk.checkpoints,
      recoveryAnchorStore: disk.ownership,
      registrationAnchorStore: disk.registration, adoptionAnchorStore: disk.adoption,
      cache: disk.cache,
      limits: limits, phaseObserver: observer)
  }
  private func publish(
    _ f: Fixture, _ candidate: V3RecoveryDeviceRevocationCandidate,
    observer: any V3ImmutableTransactionPhaseObserving = V3NoopContentTransactionPhaseObserver()
  ) throws -> V3RecoveryDeviceRevocationCommit {
    try publisher(f, observer: observer).publish(
      candidate, approvedPlan: candidate.plan,
      currentVaultKey: Self.currentKey, nextVaultKey: Self.nextKey, identity: f.owner,
      reason: "Owned wrapper verification fixture")
  }
  private func resume(
    _ f: Fixture, currentKey: Data? = Self.currentKey,
    nextKey: Data = Self.nextKey, owner: V3EnrollmentDeviceIdentity? = nil,
    expectedAnchor: Data? = nil
  ) throws -> V3ImmutableTransactionRecoveryOutcome {
    try publisher(f).recoverInterruptedTransaction(
      vaultID: Core.vaultID, currentVaultKey: currentKey,
      nextVaultKey: nextKey, expectedOwner: owner ?? f.owner.publicIdentity,
      expectedAnchor: expectedAnchor)
  }
  private func interrupt(_ f: Fixture, _ candidate: V3RecoveryDeviceRevocationCandidate) throws {
    #expect(throws: Stop.interrupted) {
      try publish(
        f, candidate, observer: Observer { if $0 == .manifestStaged { throw Stop.interrupted } })
    }
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
  private struct IncorrectUnwrapper: V3DeviceWrappedVaultKeyUnwrapping {
    let base: Core.Owner
    var vaultID: String { base.vaultID }
    var publicIdentity: V3EnrollmentDeviceIdentity { base.publicIdentity }
    func unwrapDeviceWrappedVaultKey(
      _ wrappedKey: V3HPKEWrappedVaultKey, context: V3VaultKeyHPKEContext, reason: String
    ) throws -> Data {
      _ = try base.unwrapDeviceWrappedVaultKey(wrappedKey, context: context, reason: reason)
      return SelfKey.current
    }
  }
}
