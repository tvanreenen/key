import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Real profile cryptography and contained immutable storage. Only local CAS
/// failures, cancellation and interruption boundaries are scripted.
struct V3RecoveryDeviceEnrollmentPublisherTests {
  typealias Core = V3RecoveryRegistrationTests
  typealias Publication = V3RecoveryContentMutationPublisherTests
  private typealias Stop = Publication.Stop
  private static let nextKey = Data(repeating: 0x55, count: 32)
  private static let now: UInt64 = 4_102_444_800
  private static let phases: [V3ImmutableTransactionPhase] = [
    .recoveryAnchorPrepared, .recoveryIntentPersisted, .recoveryArmed,
    .entryStaged(index: 0), .entryStaged(index: 1), .manifestStaged,
    .repositoryStateRechecked, .entryPublished(index: 0), .entryPublished(index: 1),
    .publishedEntriesValidated, .manifestPublished, .publishedManifestValidated,
    .checkpointAdvanced, .cleanupCompleted,
  ]

  @Test(arguments: [false, true])
  func publicationAddsOnlyComparedMacAndConsumesCeremonyAfterCommit(empty: Bool) throws {
    let f = try Fixture(empty: empty)
    defer { f.disk.remove() }
    let candidate = try build(f)
    let commit = try publish(
      f, candidate,
      observer: Observer { phase in
        if phase != .cleanupCompleted {
          let saved = try f.savedState()
          #expect(saved.phase == .awaitingComparison)
        }
        if phase == .manifestPublished {
          #expect(f.disk.checkpoints.value == f.disk.checkpoint.canonicalBytes)
        }
      })
    #expect(commit.envelope == candidate.envelope && f.disk.ownership.value == nil)
    #expect(try f.savedState().phase == .consumed)
    #expect(f.disk.checkpoints.value == commit.checkpoint.canonicalBytes)
    #expect(
      try f.disk.cache.load(for: commit.checkpoint) == .available(candidate.envelope.canonicalBytes)
    )
    #expect(commit.envelope.body.recovery.recipients == f.disk.parent.body.recovery.recipients)
    #expect(
      commit.envelope.body.fields.devices.count == f.disk.parent.body.fields.devices.count + 1)
    let wrapper = try #require(
      commit.envelope.body.fields.wrappedKeys.first {
        $0.recipientDeviceID == f.joiner.publicIdentity.deviceID
      })
    #expect(
      try V3VaultKeyHPKE().unwrap(
        wrapper.wrappedKey, recipientPrivateKey: f.joiner.wrappingKey,
        context: commit.envelope.body.deviceContext(
          recipientDeviceID: f.joiner.publicIdentity.deviceID)) == Self.nextKey)
    #expect(f.disk.core.owner.signatures == f.signatures + 1 && f.disk.core.owner.unwraps == 1)
    #expect(f.joiner.signatures == 1 && f.joiner.unwraps == 0)
    #expect(throws: (any Error).self) { try publish(f, candidate) }
    #expect(f.disk.core.owner.unwraps == 1 && f.disk.ownership.value == nil)
  }

  @Test(arguments: 0..<14)
  func everyBoundaryResumesExactApprovalWithoutNewComparisonOrSigning(phase: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try build(f)
    #expect(throws: Stop.interrupted) {
      try publish(
        f, candidate, observer: Observer { if $0 == Self.phases[phase] { throw Stop.interrupted } })
    }
    let outcome = try resume(f, currentKey: phase >= 12 ? nil : Core.nextKey)
    if phase < 5 {
      #expect(outcome == .abandoned(operationID: f.disk.operationID))
      #expect(f.disk.checkpoints.value == f.disk.checkpoint.canonicalBytes)
      #expect(try f.savedState().phase == .awaitingComparison)
    } else {
      #expect(
        outcome
          == (phase == 13
            ? .nothingToRecover
            : (phase == 12
              ? .alreadyCompleted(operationID: f.disk.operationID)
              : .completed(operationID: f.disk.operationID))))
      #expect(try f.savedState().phase == .consumed)
      #expect(
        try Data(contentsOf: f.disk.manifestURL(candidate.envelope.digest))
          == candidate.envelope.canonicalBytes)
      #expect(
        f.disk.checkpoints.value
          == (try V3ManifestCheckpoint(
            vaultID: Core.vaultID, envelopeDigest: candidate.envelope.digest)).canonicalBytes)
    }
    #expect(f.disk.ownership.value == nil && f.disk.core.owner.unwraps == 1)
    #expect(f.disk.core.owner.signatures == f.signatures + 1 && f.joiner.signatures == 1)
  }

  @Test func exactIntentContainsTranscriptButNoKeyOrApprovalCarrier() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try build(f)
    try interrupt(f, candidate)
    let anchor = try V3ImmutableTransactionRecoveryAnchor(
      canonicalBytes: #require(f.disk.ownership.value))
    let read = try f.disk.store.readRecoveryIntent(
      operationID: anchor.operationID,
      maximumBytes: V3ImmutableTransactionRecoveryIntent.maximumBytes)
    guard case .available(let bytes) = read else {
      Issue.record("Missing exact intent")
      return
    }
    let intent = try V3ImmutableTransactionRecoveryIntent(canonicalBytes: bytes)
    #expect(Data(SHA256.hash(data: bytes)) == anchor.intentDigest)
    #expect(
      intent.kind == .enrollDevice
        && intent.enrollmentTranscriptDigest == f.state.transcript?.digest)
    #expect(
      intent.candidateManifestDigest == candidate.envelope.digest
        && intent.recoveryMergeResolutions == nil)
    #expect(!String(decoding: bytes, as: UTF8.self).contains(Base64URL.encode(Self.nextKey)))
    #expect(f.state.ownerApproval == nil)
    #expect(try resume(f) == .completed(operationID: f.disk.operationID))
  }

  @Test func expiryBlocksFreshWorkButNotExactPendingApproval() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try build(f)
    #expect(throws: (any Error).self) { try publish(f, candidate, at: Self.now + 1) }
    #expect(f.disk.core.owner.unwraps == 0 && f.disk.ownership.value == nil)
    try interrupt(f, candidate)
    // Resume has no clock parameter and cannot create a new approval.
    #expect(try resume(f) == .completed(operationID: f.disk.operationID))
    #expect(try f.savedState().phase == .consumed && f.disk.core.owner.unwraps == 1)
  }

  @Test(arguments: [false, true])
  func failedLocalCompletionRetainsIntentAndCanFinishWithOnlyCurrentSnapshot(onResume: Bool) throws
  {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try build(f)
    if onResume { try interrupt(f, candidate) }
    f.local.rejectConsume = true
    #expect(throws: Stop.interrupted) {
      if onResume { _ = try resume(f) } else { _ = try publish(f, candidate) }
    }
    #expect(
      f.disk.ownership.value != nil && f.disk.checkpoints.value != f.disk.checkpoint.canonicalBytes)
    #expect(try f.savedState().phase == .awaitingComparison)
    for entry in Array(f.disk.entries.values) + Array(f.disk.core.entries.values) {
      try FileManager.default.removeItem(at: f.disk.entryURL(entry))
    }
    try FileManager.default.removeItem(at: f.disk.manifestURL(f.disk.parent.digest))
    try FileManager.default.removeItem(at: f.disk.manifestURL(f.disk.core.parent.digest))
    f.local.rejectConsume = false
    #expect(try resume(f, currentKey: nil) == .alreadyCompleted(operationID: f.disk.operationID))
    #expect(try f.savedState().phase == .consumed && f.disk.ownership.value == nil)
  }

  @Test func consumedMarkerRemainsIdempotentWhenOwnershipCleanupFails() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try build(f)
    f.disk.ownership.rejectClear = true
    let commit = try publish(f, candidate)
    let consumed = try f.savedState()
    #expect(consumed.phase == .consumed && f.disk.ownership.value != nil)
    f.disk.ownership.rejectClear = false
    #expect(
      try resume(f, state: consumed, currentKey: nil)
        == .alreadyCompleted(operationID: f.disk.operationID))
    #expect(
      f.disk.checkpoints.value == commit.checkpoint.canonicalBytes && f.disk.ownership.value == nil)
    #expect(f.local.consumptions == 1)
  }

  @Test func missingPublishedEntryRetainsIntentAndDoesNotConsumeUntilExactBytesReturn() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try build(f)
    let entry = try #require(candidate.stagedEntries.first)
    #expect(throws: (any Error).self) {
      try publish(
        f, candidate,
        observer: Observer {
          if $0 == .manifestPublished {
            try FileManager.default.removeItem(at: f.disk.entryURL(entry))
          }
        })
    }
    let pending = try #require(f.disk.ownership.value)
    #expect(throws: V3ImmutableTransactionRecoveryError.transactionDirectoryUnavailable) {
      try resume(f)
    }
    #expect(try f.savedState().phase == .awaitingComparison && f.disk.ownership.value == pending)
    let digest = Data(SHA256.hash(data: entry.canonicalBytes))
    try f.disk.store.stageEntry(
      entry.canonicalBytes, entryID: entry.context.entryID,
      digest: digest, operationID: f.disk.operationID)
    try f.disk.store.publishStagedEntry(
      entry.canonicalBytes, entryID: entry.context.entryID,
      digest: digest, operationID: f.disk.operationID)
    #expect(try resume(f) == .completed(operationID: f.disk.operationID))
    #expect(try f.savedState().phase == .consumed && f.disk.ownership.value == nil)
  }

  @Test(arguments: [false, true])
  func changedCeremonyOrAuthorityAfterCheckpointRetainsCompletionWork(authority: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try build(f)
    #expect(throws: (any Error).self) {
      try publish(
        f, candidate,
        observer: Observer {
          if $0 == .checkpointAdvanced {
            if authority { f.disk.registration.value = Data([1]) } else { f.local.value = nil }
          }
        })
    }
    let pending = try #require(f.disk.ownership.value)
    #expect(
      f.disk.checkpoints.value != f.disk.checkpoint.canonicalBytes && f.local.consumptions == 0)
    #expect(throws: (any Error).self) { try resume(f, currentKey: nil) }
    #expect(f.disk.ownership.value == pending)
    f.local.value = f.state.canonicalBytes
    f.disk.registration.value = nil
    #expect(try resume(f, currentKey: nil) == .alreadyCompleted(operationID: f.disk.operationID))
    #expect(f.local.consumptions == 1)
  }

  @Test func failedCheckpointCASDoesNotConsumeAndResumesIdenticalBytes() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try build(f)
    f.disk.checkpoints.rejectAdvance = true
    #expect(throws: Stop.interrupted) { try publish(f, candidate) }
    #expect(try f.savedState().phase == .awaitingComparison && f.disk.ownership.value != nil)
    f.disk.checkpoints.rejectAdvance = false
    #expect(try resume(f) == .completed(operationID: f.disk.operationID))
    #expect(
      try f.savedState().phase == .consumed && f.disk.core.owner.signatures == f.signatures + 1)
  }

  @Test(arguments: 0..<5)
  func changedLocalTranscriptConsentOrOwnerRetainsPendingWork(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try build(f)
    try interrupt(f, candidate)
    let pending = f.disk.ownership.value
    let other = try V3RecoveryDeviceEnrollmentTests().ceremony(
      parentDigest: f.disk.parent.digest, owner: f.disk.core.owner, joiner: Core.Owner())
    if variant == 0 { f.local.value = other.canonicalBytes }
    if variant == 1 { f.local.value = nil }
    if variant == 2 { f.local.value = Data([1]) }
    #expect(throws: (any Error).self) {
      try resume(
        f, approved: variant == 3 ? Data(repeating: 1, count: 32) : nil,
        owner: variant == 4 ? Core.Owner().publicIdentity : nil)
    }
    #expect(
      f.disk.ownership.value == pending
        && f.disk.checkpoints.value == f.disk.checkpoint.canonicalBytes)
    f.local.value = f.state.canonicalBytes
    #expect(try resume(f) == .completed(operationID: f.disk.operationID))
  }

  @Test(arguments: 0..<4)
  func wrongOrMissingScopedKeyRefusesWithoutConsuming(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try build(f)
    try interrupt(f, candidate)
    let pending = f.disk.ownership.value
    #expect(throws: (any Error).self) {
      try resume(
        f, currentKey: variant == 0 ? nil : (variant == 1 ? Self.nextKey : Core.nextKey),
        nextKey: variant == 2 ? Core.nextKey : (variant == 3 ? Data([1]) : Self.nextKey))
    }
    #expect(try f.savedState().phase == .awaitingComparison && f.disk.ownership.value == pending)
  }

  @Test(arguments: 0..<3)
  func cancellationOrChangedLocalStateDuringPrivateVerificationNeverArmsIntent(variant: Int) throws
  {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try build(f)
    if variant == 0 { f.disk.core.owner.cancelUnwrap = true }
    if variant == 1 { f.disk.core.owner.onUnwrap = { f.local.value = nil } }
    if variant == 2 { f.disk.core.owner.onUnwrap = { f.disk.adoption.value = Data([1]) } }
    #expect(throws: (any Error).self) { try publish(f, candidate) }
    #expect(f.disk.core.owner.unwraps == 1 && f.disk.ownership.value == nil)
    #expect(f.disk.checkpoints.value == f.disk.checkpoint.canonicalBytes)
  }

  @Test(arguments: [
    V3ImmutableTransactionPhase.repositoryStateRechecked,
    .publishedEntriesValidated, .publishedManifestValidated, .checkpointAdvanced,
  ])
  func competingBranchPreventsCompletionAndConsumption(phase: V3ImmutableTransactionPhase) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try build(f)
    let branch = try f.disk.build(
      .edit(name: "fixture/secret", type: .secret, plaintext: "concurrent"))
    #expect(throws: (any Error).self) {
      try publish(
        f, candidate,
        observer: Observer {
          if $0 == phase {
            try f.disk.seed(branch.envelope, entries: branch.stagedEntries)
          }
        })
    }
    #expect(try f.savedState().phase == .awaitingComparison && f.disk.ownership.value != nil)
    #expect(throws: (any Error).self) {
      try resume(f, currentKey: phase == .checkpointAdvanced ? nil : Core.nextKey)
    }
    #expect(f.disk.ownership.value != nil)
  }

  @Test(arguments: [false, true])
  func pendingAuthorityWorkBlocksPublishAndResume(registration: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try build(f)
    let other = registration ? f.disk.registration : f.disk.adoption
    other.value = Data([1])
    #expect(throws: V3RecoveryContentPublicationError.otherMutationPending) {
      try publish(f, candidate)
    }
    #expect(f.disk.core.owner.unwraps == 0 && f.disk.ownership.value == nil)
    other.value = nil
    try interrupt(f, candidate)
    let pending = f.disk.ownership.value
    other.value = Data([1])
    #expect(throws: V3RecoveryContentPublicationError.otherMutationPending) { try resume(f) }
    #expect(f.disk.ownership.value == pending)
  }

  @Test func preparationPinsExactCiphertextWithoutConsumingOrOpeningKeys() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try build(f)
    try interrupt(f, candidate)
    let pending = try #require(f.disk.ownership.value)
    guard
      case .ready(let prepared) = try publisher(f).prepareInterruptedTransaction(
        vaultID: Core.vaultID, state: f.state,
        approvedTranscriptDigest: #require(f.state.transcript?.digest),
        expectedOwner: f.disk.core.owner.publicIdentity, expectedAnchor: pending)
    else {
      Issue.record("Expected exact prepared work")
      return
    }
    #expect(
      prepared.manifestData == candidate.envelope.canonicalBytes && prepared.anchorData == pending)
    #expect(prepared.intent.enrollmentTranscriptDigest == f.state.transcript?.digest)
    #expect(try f.savedState().phase == .awaitingComparison && f.disk.core.owner.unwraps == 1)
    #expect(throws: (any Error).self) { try resume(f, expectedAnchor: Data([1])) }
    #expect(f.disk.ownership.value == pending)
    #expect(try resume(f, expectedAnchor: pending) == .completed(operationID: f.disk.operationID))
  }

  @Test(arguments: [false, true])
  func ordinaryAndRotationValidatorsCannotConsumeEnrollmentEvenWithChangedCheckpoint(rotation: Bool)
    throws
  {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try build(f)
    try interrupt(f, candidate)
    let pending = f.disk.ownership.value
    f.disk.checkpoints.value = try V3ManifestCheckpoint(
      vaultID: Core.vaultID, envelopeDigest: Data(repeating: 4, count: 32)
    ).canonicalBytes
    #expect(
      throws: V3ImmutableTransactionRecoveryError.invalidIntent(
        operationID: f.disk.operationID.rawValue)
    ) {
      if rotation {
        _ = try V3RecoveryKeyRotationPublisher(
          mutationOwner: VaultTransactionMutationOwner(), objectStore: f.disk.store,
          checkpointStore: f.disk.checkpoints, recoveryAnchorStore: f.disk.ownership,
          registrationAnchorStore: f.disk.registration, adoptionAnchorStore: f.disk.adoption,
          cache: f.disk.cache
        ).recoverInterruptedTransaction(
          vaultID: Core.vaultID,
          currentVaultKey: Core.nextKey, nextVaultKey: Self.nextKey,
          expectedOwner: f.disk.core.owner.publicIdentity)
      } else {
        _ = try f.disk.publisher().recoverInterruptedTransaction(
          vaultID: Core.vaultID, vaultKey: Self.nextKey)
      }
    }
    #expect(try f.savedState().phase == .awaitingComparison && f.disk.ownership.value == pending)
    f.disk.checkpoints.value = f.disk.checkpoint.canonicalBytes
    #expect(try resume(f) == .completed(operationID: f.disk.operationID))
  }

  @Test func enrollmentCannotResumeOrdinaryIntentOrPublishAnUnchangedRosterRotation() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let ordinary = try f.disk.build(.remove(name: "fixture/totp"))
    #expect(throws: Stop.interrupted) {
      try f.disk.publisher(
        observer: Observer { if $0 == .manifestStaged { throw Stop.interrupted } }
      )
      .publish(ordinary, vaultKey: Core.nextKey)
    }
    let pending = f.disk.ownership.value
    #expect(
      throws: V3ImmutableTransactionRecoveryError.invalidIntent(
        operationID: f.disk.operationID.rawValue)
    ) {
      try resume(f)
    }
    #expect(f.disk.ownership.value == pending)
    #expect(
      try f.disk.publisher().recoverInterruptedTransaction(
        vaultID: Core.vaultID,
        vaultKey: Core.nextKey) == .completed(operationID: f.disk.operationID))
    let g = try Fixture()
    defer { g.disk.remove() }
    let rotated = try V3RecoveryKeyRotationBuilder().build(
      checkpoint: g.disk.checkpoint,
      parent: g.disk.parent, currentEntries: g.disk.entries, currentVaultKey: Core.nextKey,
      nextVaultKey: Self.nextKey, owner: g.disk.core.owner, reason: "Software rotation fixture")
    #expect(throws: (any Error).self) {
      try publish(
        g,
        .init(
          expectedCheckpoint: rotated.expectedCheckpoint, envelope: rotated.envelope,
          stagedEntries: rotated.stagedEntries,
          transcriptDigest: #require(g.state.transcript?.digest)))
    }
    #expect(g.disk.core.owner.unwraps == 0 && g.disk.ownership.value == nil)
  }

  @Test(arguments: 0..<3)
  func boundedSourceAndProjectedUsageRefuseBeforePrivateVerification(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try build(f)
    let limits = [
      Core.Fixture.limits(entries: 3), Core.Fixture.limits(entryBytes: 1),
      Core.Fixture.limits(totalBytes: 1),
    ][variant]
    #expect(throws: (any Error).self) {
      try publisher(f, limits: limits).publish(
        candidate,
        state: f.state, approvedTranscriptDigest: #require(f.state.transcript?.digest),
        currentVaultKey: Core.nextKey, nextVaultKey: Self.nextKey, identity: f.disk.core.owner,
        at: Self.now, reason: "Software fixture")
    }
    #expect(f.disk.core.owner.unwraps == 0 && f.disk.ownership.value == nil)
  }

  @Test(arguments: [false, true])
  func primaryAndBackupRecoverAfterActualEnrollmentAndSave(backup: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.disk.remove() }
    let backupRecipient = try #require(f.disk.core.parent.body.recovery.recipients.first)
    let backupAnchor = try V3RecoveryAnchor(
      floor: .init(
        vaultID: Core.vaultID,
        envelopeDigest: f.disk.core.parent.digest), recipientID: backupRecipient.recipientID,
      registrationID: backupRecipient.registrationID, slot: .keyManagement)
    let commit = try publish(f, build(f))
    let session = V3DeviceWrappedVaultKeySessionStore()
    try session.install(
      Self.nextKey, vaultID: Core.vaultID, keyID: commit.envelope.body.fields.keyID)
    let service = V3RecoveryVaultMutationService(
      vaultID: Core.vaultID, session: session,
      objectStore: f.disk.store, checkpointStore: f.disk.checkpoints,
      recoveryAnchorStore: f.disk.ownership,
      registrationAnchorStore: f.disk.registration, adoptionAnchorStore: f.disk.adoption,
      cache: f.disk.cache)
    try VaultTransactionMutationOwner().perform(.editEntry) { context in
      try service.edit(
        name: "fixture/secret", secret: "after durable enrollment", type: .secret,
        operationID: context.operationID)
    }
    session.invalidate()
    for entry in Array(f.disk.core.entries.values) + Array(f.disk.entries.values) {
      try FileManager.default.removeItem(at: f.disk.entryURL(entry))
    }
    let token = backup ? f.disk.core.backupToken : f.disk.core.token
    let anchor = backup ? backupAnchor : f.disk.anchor
    let selected = try V3RecoveryHistorySelector(source: f.disk.store).select(
      anchor: anchor, credentialPublicKey: token.publicKey.x963Representation)
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
      opened.entries.first { $0.name == "fixture/secret" }?.plaintext == "after durable enrollment")
    #expect(opened.entries.first { $0.name == "fixture/totp" }?.plaintext == "JBSWY3DPEHPK3PXP")
  }

  private func build(_ f: Fixture) throws -> V3RecoveryDeviceEnrollmentCandidate {
    try V3RecoveryDeviceEnrollmentBuilder().build(
      checkpoint: f.disk.checkpoint,
      parent: f.disk.parent, currentEntries: f.disk.entries, state: f.state,
      currentVaultKey: Core.nextKey, nextVaultKey: Self.nextKey, owner: f.disk.core.owner,
      at: Self.now, reason: "Software compared enrollment fixture")
  }
  private func publisher(
    _ f: Fixture,
    observer: any V3ImmutableTransactionPhaseObserving = V3NoopContentTransactionPhaseObserver(),
    limits: V3ManifestRepositoryLimits = .standard
  ) -> V3RecoveryDeviceEnrollmentPublisher {
    .init(
      mutationOwner: VaultTransactionMutationOwner(makeOperationID: { f.disk.operationID }),
      objectStore: f.disk.store, checkpointStore: f.disk.checkpoints,
      recoveryAnchorStore: f.disk.ownership,
      registrationAnchorStore: f.disk.registration, adoptionAnchorStore: f.disk.adoption,
      ceremonyStore: f.local, cache: f.disk.cache, limits: limits, phaseObserver: observer)
  }
  private func publish(
    _ f: Fixture, _ candidate: V3RecoveryDeviceEnrollmentCandidate,
    at: UInt64 = Self.now,
    observer: any V3ImmutableTransactionPhaseObserving = V3NoopContentTransactionPhaseObserver()
  ) throws -> V3RecoveryDeviceEnrollmentCommit {
    try publisher(f, observer: observer).publish(
      candidate, state: f.state,
      approvedTranscriptDigest: #require(f.state.transcript?.digest), currentVaultKey: Core.nextKey,
      nextVaultKey: Self.nextKey, identity: f.disk.core.owner, at: at,
      reason: "Software wrapper fixture")
  }
  private func interrupt(_ f: Fixture, _ candidate: V3RecoveryDeviceEnrollmentCandidate) throws {
    #expect(throws: Stop.interrupted) {
      try publish(
        f, candidate,
        observer: Observer { if $0 == .manifestStaged { throw Stop.interrupted } })
    }
  }
  private func resume(
    _ f: Fixture, state: V3EnrollmentCeremonyState? = nil,
    approved: Data? = nil, currentKey: Data? = Core.nextKey, nextKey: Data = Self.nextKey,
    owner: V3EnrollmentDeviceIdentity? = nil, expectedAnchor: Data? = nil
  ) throws -> V3ImmutableTransactionRecoveryOutcome {
    try publisher(f).recoverInterruptedTransaction(
      vaultID: Core.vaultID, state: state ?? f.state,
      approvedTranscriptDigest: approved ?? #require(f.state.transcript?.digest),
      currentVaultKey: currentKey, nextVaultKey: nextKey,
      expectedOwner: owner ?? f.disk.core.owner.publicIdentity, expectedAnchor: expectedAnchor)
  }

  struct Fixture: Sendable {
    let disk: Publication.Fixture
    let joiner: Core.Owner
    let state: V3EnrollmentCeremonyState
    let local: StateStore
    let signatures: Int
    init(empty: Bool = false) throws {
      disk = try Publication.Fixture(empty: empty)
      joiner = try Core.Owner()
      state = try V3RecoveryDeviceEnrollmentTests().ceremony(
        parentDigest: disk.parent.digest, owner: disk.core.owner, joiner: joiner)
      local = StateStore(state.canonicalBytes)
      signatures = disk.core.owner.signatures
    }
    func savedState() throws -> V3EnrollmentCeremonyState {
      try .init(canonicalBytes: #require(local.value))
    }
  }
  final class StateStore: V3EnrollmentCeremonyStateStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var bytes: Data?
    private var rejected = false
    private var count = 0
    init(_ value: Data) { bytes = value }
    var value: Data? {
      get { lock.withLock { bytes } }
      set { lock.withLock { bytes = newValue } }
    }
    var rejectConsume: Bool {
      get { lock.withLock { rejected } }
      set { lock.withLock { rejected = newValue } }
    }
    var consumptions: Int { lock.withLock { count } }
    func loadState(vaultID _: String, invitationDigest _: Data) throws -> Data? { value }
    func replaceState(
      _ state: Data, expectedState: Data?, vaultID _: String, invitationDigest _: Data
    ) throws {
      try lock.withLock {
        guard bytes == expectedState else { throw V3EnrollmentCeremonyStateError.conflict }
        if rejected { throw Stop.interrupted }
        bytes = state
        count += 1
      }
    }
  }
  private struct Observer: V3ImmutableTransactionPhaseObserving {
    let action: @Sendable (V3ImmutableTransactionPhase) throws -> Void
    init(_ action: @escaping @Sendable (V3ImmutableTransactionPhase) throws -> Void) {
      self.action = action
    }
    func didReach(_ phase: V3ImmutableTransactionPhase, operationID _: VaultTransactionOperationID)
      throws
    {
      try action(phase)
    }
  }
}
