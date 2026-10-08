import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

/// Owned software credentials and real disposable filesystem/crypto only.
/// Local checkpoint/ownership failures and Mac operations are scripted.
struct V3RecoveryRecipientRemovalPublisherTests {
  private typealias Core = V3RecoveryRegistrationTests
  private typealias Publication = V3RecoveryContentMutationPublisherTests
  private typealias Stop = Publication.Stop
  private static let nextKey = Data(repeating: 0x44, count: 32)
  private static let phases: [V3ImmutableTransactionPhase] = [
    .recoveryAnchorPrepared, .recoveryIntentPersisted, .recoveryArmed,
    .entryStaged(index: 0), .entryStaged(index: 1), .manifestStaged,
    .repositoryStateRechecked, .entryPublished(index: 0), .entryPublished(index: 1),
    .publishedEntriesValidated, .manifestPublished, .publishedManifestValidated,
    .checkpointAdvanced, .cleanupCompleted,
  ]

  @Test(arguments: [false, true], [false, true])
  func publishesExactReviewedRemovalAndCurrentSnapshot(last: Bool, empty: Bool) throws {
    let f = try Fixture(last: last, empty: empty)
    defer { f.disk.remove() }
    let candidate = try f.build()
    let commit = try publish(f, candidate)
    #expect(commit.envelope == candidate.envelope && f.disk.ownership.value == nil)
    #expect(f.disk.checkpoints.value == commit.checkpoint.canonicalBytes)
    #expect(
      try f.disk.cache.load(for: commit.checkpoint) == .available(candidate.envelope.canonicalBytes)
    )
    #expect(commit.envelope.body.fields.devices == f.disk.parent.body.fields.devices)
    #expect(commit.envelope.body.recovery.recipients == candidate.plan.resultingRecipients)
    #expect(commit.envelope.body.recovery.generationID != f.disk.parent.body.recovery.generationID)
    #expect(commit.envelope.body.recovery.wrappedKeys.count == (last ? 0 : 1))
    #expect(f.owner.signatures == 2 && f.owner.unwraps == 1)
    #expect(throws: (any Error).self) { try publish(f, candidate) }
    #expect(f.owner.unwraps == 1)
  }

  @Test(arguments: [false, true], 0..<14)
  func everyBoundaryResumesPinnedRemovalWithoutNewApprovalOrSigning(last: Bool, phase: Int) throws {
    let f = try Fixture(last: last)
    defer { f.disk.remove() }
    let candidate = try f.build()
    #expect(throws: Stop.interrupted) {
      try publish(
        f, candidate, observer: Observer { if $0 == Self.phases[phase] { throw Stop.interrupted } })
    }
    // Restart deliberately accepts no fresh protection-loss acknowledgment.
    let outcome = try resume(f, currentKey: phase >= 12 ? nil : Core.nextKey)
    if phase < 5 {
      #expect(outcome == .abandoned(operationID: f.disk.operationID))
      #expect(f.disk.checkpoints.value == f.disk.checkpoint.canonicalBytes)
      #expect(
        !FileManager.default.fileExists(atPath: f.disk.manifestURL(candidate.envelope.digest).path))
    } else {
      #expect(
        outcome
          == (phase == 13
            ? .nothingToRecover
            : phase == 12
              ? .alreadyCompleted(operationID: f.disk.operationID)
              : .completed(operationID: f.disk.operationID)))
      #expect(
        f.disk.checkpoints.value
          == (try V3ManifestCheckpoint(
            vaultID: Core.vaultID, envelopeDigest: candidate.envelope.digest)).canonicalBytes)
      #expect(
        try Data(contentsOf: f.disk.manifestURL(candidate.envelope.digest))
          == candidate.envelope.canonicalBytes)
    }
    #expect(f.disk.ownership.value == nil && f.owner.signatures == 2 && f.owner.unwraps == 1)
  }

  @Test(arguments: 0..<2)
  func differentAuthenticatedEpochPoliciesAreNotRecipientRemoval(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let plan = try f.build().plan
    let envelope: V3RecoveryManifestEnvelope
    let staged: [V3EncryptedEntry]
    if variant == 0 {
      let rotation = try V3RecoveryKeyRotationBuilder().build(
        checkpoint: f.disk.checkpoint, parent: f.disk.parent, currentEntries: f.disk.entries,
        currentVaultKey: Core.nextKey, nextVaultKey: Self.nextKey, owner: f.owner,
        reason: "Owned different-policy fixture")
      envelope = rotation.envelope
      staged = rotation.stagedEntries
    } else {
      let recipients = try f.disk.parent.body.recovery.recipients.map {
        try V3RecoveryRecipient(
          registrationID: $0.registrationID, publicKey: $0.publicKey,
          slot: $0.slot, status: .revoked)
      }
      let material = try V3RecoveryEpochMaterialBuilder(limits: .standard).build(
        fields: f.disk.parent.body.fields,
        plaintexts: V3EntrySnapshotValidator(limits: .standard).plaintexts(
          fields: f.disk.parent.body.fields, entries: f.disk.entries, vaultKey: Core.nextKey),
        nextVaultKey: Self.nextKey, authorityTransitionID: UUID().uuidString.lowercased(),
        devices: f.disk.parent.body.fields.devices, generationID: UUID().uuidString.lowercased(),
        recipients: recipients)
      envelope = try V3RecoveryEpochBoundary().authorize(
        candidate: material.body, parent: f.disk.parent, currentVaultKey: Core.nextKey,
        nextVaultKey: Self.nextKey, signer: f.owner, reason: "Owned two-recipient policy fixture")
      staged = material.stagedEntries
    }
    #expect(throws: V3RecoveryRecipientRemovalError.invalidPlan) {
      try publish(f, .init(plan: plan, envelope: envelope, stagedEntries: staged))
    }
    #expect(f.owner.unwraps == 0 && f.disk.ownership.value == nil)
    let references = staged.map {
      V3ImmutableTransactionRecoveryEntry(
        entryID: $0.context.entryID,
        digest: Data(SHA256.hash(data: $0.canonicalBytes)))
    }.sorted {
      $0.entryID == $1.entryID
        ? $0.digest.lexicographicallyPrecedes($1.digest) : $0.entryID < $1.entryID
    }
    let intent = try V3ImmutableTransactionRecoveryIntent(
      operationID: f.disk.operationID, kind: .removeRecoveryRecipient, vaultID: Core.vaultID,
      expectedCheckpoint: f.disk.checkpoint, expectedHeads: [f.disk.parent.digest],
      candidateManifestDigest: envelope.digest, stagedEntries: references)
    try f.disk.store.persistRecoveryIntent(intent.canonicalBytes, operationID: f.disk.operationID)
    for entry in staged {
      try f.disk.store.stageEntry(
        entry.canonicalBytes, entryID: entry.context.entryID,
        digest: Data(SHA256.hash(data: entry.canonicalBytes)), operationID: f.disk.operationID)
    }
    try f.disk.store.stageManifest(
      envelope.canonicalBytes, digest: envelope.digest,
      operationID: f.disk.operationID)
    let anchor = try V3ImmutableTransactionRecoveryAnchor(
      operationID: f.disk.operationID,
      vaultID: Core.vaultID, intentDigest: Data(SHA256.hash(data: intent.canonicalBytes)),
      phase: .recoverable)
    f.disk.ownership.value = anchor.canonicalBytes
    #expect(
      throws: V3ImmutableTransactionRecoveryError.invalidRecoveryState(
        operationID: f.disk.operationID.rawValue)
    ) { try resume(f) }
    #expect(
      f.disk.ownership.value == anchor.canonicalBytes
        && f.disk.checkpoints.value == f.disk.checkpoint.canonicalBytes && f.owner.unwraps == 0)
  }

  @Test(arguments: 0..<4)
  func initialLastRemovalRequiresExactAcknowledgementBeforeMacOperation(variant: Int) throws {
    let f = try Fixture(last: variant != 3)
    defer { f.disk.remove() }
    let candidate = try f.build()
    let plan = candidate.plan
    let changed = V3RecoveryRecipientRemovalPlan(
      expectedCheckpoint: variant == 1 ? f.disk.core.checkpoint : plan.expectedCheckpoint,
      authorizingDevice: variant == 2
        ? .init(identity: try Core.Owner().publicIdentity, status: .active)
        : plan.authorizingDevice,
      removedRecipient: plan.removedRecipient,
      resultingRecipients: variant == 3 ? [] : plan.resultingRecipients)
    let acknowledgement =
      variant == 0 ? nil : try V3RecoveryProtectionLossAcknowledgement(plan: changed)
    #expect(
      throws: variant == 0
        ? V3RecoveryRecipientRemovalError.protectionLossAcknowledgementRequired
        : V3RecoveryRecipientRemovalError.invalidAcknowledgement
    ) {
      try publisher(f).publish(
        candidate, approvedPlan: plan, currentVaultKey: Core.nextKey, nextVaultKey: Self.nextKey,
        identity: f.owner, reason: "Owned protection-loss review",
        protectionLossAcknowledgement: acknowledgement)
    }
    #expect(f.owner.unwraps == 0 && f.disk.ownership.value == nil)
  }

  @Test(arguments: 0..<3)
  func independentlyReviewedPlanCannotBeSubstituted(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try f.build()
    let p = candidate.plan
    let other = try Core.Owner()
    let changed = V3RecoveryRecipientRemovalPlan(
      expectedCheckpoint: variant == 0 ? f.disk.core.checkpoint : p.expectedCheckpoint,
      authorizingDevice: variant == 1
        ? .init(identity: other.publicIdentity, status: .active) : p.authorizingDevice,
      removedRecipient: variant == 2
        ? try #require(f.disk.core.parent.body.recovery.recipients.first) : p.removedRecipient,
      resultingRecipients: p.resultingRecipients)
    #expect(throws: V3RecoveryRecipientRemovalError.invalidPlan) {
      try publisher(f).publish(
        candidate, approvedPlan: changed, currentVaultKey: Core.nextKey,
        nextVaultKey: Self.nextKey, identity: f.owner, reason: "Owned plan review")
    }
    #expect(f.owner.unwraps == 0 && f.disk.ownership.value == nil)
  }

  @Test func intentUsesVersionOneAndPinsBytesNotKeysOrConsent() throws {
    let f = try Fixture(last: true)
    defer { f.disk.remove() }
    let candidate = try f.build()
    try interrupt(f, candidate)
    let anchor = try V3ImmutableTransactionRecoveryAnchor(
      canonicalBytes: #require(f.disk.ownership.value))
    guard
      case .available(let bytes) = try f.disk.store.readRecoveryIntent(
        operationID: anchor.operationID,
        maximumBytes: V3ImmutableTransactionRecoveryIntent.maximumBytes)
    else { throw Stop.interrupted }
    let intent = try V3ImmutableTransactionRecoveryIntent(canonicalBytes: bytes)
    let fields = try #require(CanonicalJSON.parse(bytes).objectValue)
    #expect(fields.first { $0.0 == "version" }?.1.integerValue == 1)
    #expect(fields.count == 9 && intent.kind == .removeRecoveryRecipient)
    #expect(
      intent.candidateManifestDigest == candidate.envelope.digest
        && intent.expectedCheckpoint == candidate.plan.expectedCheckpoint)
    #expect(intent.enrollmentTranscriptDigest == nil && intent.recoveryMergeResolutions == nil)
    #expect(!String(decoding: bytes, as: UTF8.self).contains(Base64URL.encode(Self.nextKey)))
    #expect(throws: V3ImmutableTransactionRecoveryIntentError.invalidFormat) {
      try V3ImmutableTransactionRecoveryIntent(
        canonicalBytes: Data(
          String(decoding: bytes, as: UTF8.self)
            .replacingOccurrences(of: "removeRecoveryRecipient", with: "unknownRecoveryKind").utf8))
    }
    guard
      case .ready(let selected) = try publisher(f).prepareInterruptedTransaction(
        vaultID: Core.vaultID, expectedOwner: f.owner.publicIdentity,
        expectedAnchor: anchor.canonicalBytes)
    else { throw Stop.interrupted }
    #expect(selected.manifestData == candidate.envelope.canonicalBytes && f.owner.unwraps == 1)
    #expect(
      try resume(f, expectedAnchor: anchor.canonicalBytes)
        == .completed(operationID: anchor.operationID))
  }

  @Test(arguments: [false, true])
  func failedCheckpointCASResumesWithoutRenewedAcknowledgement(last: Bool) throws {
    let f = try Fixture(last: last)
    defer { f.disk.remove() }
    let candidate = try f.build()
    f.disk.checkpoints.rejectAdvance = true
    #expect(throws: Stop.interrupted) { try publish(f, candidate) }
    #expect(f.disk.checkpoints.value == f.disk.checkpoint.canonicalBytes)
    f.disk.checkpoints.rejectAdvance = false
    #expect(try resume(f) == .completed(operationID: f.disk.operationID))
    #expect(f.owner.signatures == 2 && f.owner.unwraps == 1)
  }

  @Test(arguments: [false, true])
  func committedCleanupNeedsOnlyCurrentKeyAndSnapshot(last: Bool) throws {
    let f = try Fixture(last: last)
    defer { f.disk.remove() }
    let candidate = try f.build()
    f.disk.ownership.rejectClear = true
    let commit = try publish(f, candidate)
    for entry in Array(f.disk.entries.values) + Array(f.disk.core.entries.values) {
      try FileManager.default.removeItem(at: f.disk.entryURL(entry))
    }
    for manifest in [f.disk.parent, f.disk.core.parent] {
      try FileManager.default.removeItem(at: f.disk.manifestURL(manifest.digest))
    }
    try FileManager.default.removeItem(
      at: f.disk.cacheRoot.appendingPathComponent("\(Core.vaultID).json"))
    f.disk.ownership.rejectClear = false
    #expect(try resume(f, currentKey: nil) == .alreadyCompleted(operationID: f.disk.operationID))
    #expect(
      f.disk.ownership.value == nil && f.disk.checkpoints.value == commit.checkpoint.canonicalBytes)
    #expect(
      try f.disk.cache.load(for: commit.checkpoint) == .available(candidate.envelope.canonicalBytes)
    )
    #expect(f.owner.signatures == 2 && f.owner.unwraps == 1)
  }

  @Test(arguments: 0..<4)
  func uncommittedMissingOrWrongKeysAndOwnerRetainIntent(variant: Int) throws {
    let f = try Fixture(last: true)
    defer { f.disk.remove() }
    try interrupt(f, f.build())
    let pending = f.disk.ownership.value
    #expect(throws: (any Error).self) {
      try resume(
        f, currentKey: variant == 0 ? nil : variant == 1 ? Self.nextKey : Core.nextKey,
        nextKey: variant == 2 ? Core.nextKey : Self.nextKey,
        owner: variant == 3 ? Core.Owner().publicIdentity : nil)
    }
    #expect(
      f.disk.ownership.value == pending
        && f.disk.checkpoints.value == f.disk.checkpoint.canonicalBytes)
    #expect(try resume(f) == .completed(operationID: f.disk.operationID))
    #expect(f.owner.signatures == 2 && f.owner.unwraps == 1)
  }

  @Test(arguments: [false, true])
  func missingRequiredSnapshotCannotClearPendingWork(committed: Bool) throws {
    let f = try Fixture(last: true)
    defer { f.disk.remove() }
    let candidate = try f.build()
    if committed {
      f.disk.ownership.rejectClear = true
      _ = try publish(f, candidate)
      f.disk.ownership.rejectClear = false
    } else {
      try interrupt(f, candidate)
    }
    let pending = f.disk.ownership.value
    let checkpoint = f.disk.checkpoints.value
    let missing =
      try committed
      ? #require(candidate.stagedEntries.first) : #require(f.disk.entries.values.first)
    try FileManager.default.removeItem(at: f.disk.entryURL(missing))
    #expect(throws: (any Error).self) { try resume(f, currentKey: committed ? nil : Core.nextKey) }
    #expect(f.disk.ownership.value == pending && f.disk.checkpoints.value == checkpoint)
  }

  @Test(arguments: 0..<4)
  func badKeyOwnerOrCheckpointRefusesBeforePrivateOperation(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try f.build()
    if variant == 3 { f.disk.checkpoints.value = Data([1]) }
    #expect(throws: (any Error).self) {
      try publisher(f).publish(
        candidate, approvedPlan: candidate.plan,
        currentVaultKey: variant == 0 ? Self.nextKey : Core.nextKey,
        nextVaultKey: variant == 1 ? Core.nextKey : Self.nextKey,
        identity: variant == 2 ? Core.Owner() : f.owner, reason: "Owned input review")
    }
    #expect(f.disk.ownership.value == nil && f.owner.unwraps == 0)
  }

  @Test(arguments: [false, true])
  func cancelledOrMismatchedMacResultCannotReserveOrRetry(mismatch: Bool) throws {
    let f = try Fixture(last: true)
    defer { f.disk.remove() }
    let candidate = try f.build()
    f.owner.cancelUnwrap = !mismatch
    #expect(throws: (any Error).self) {
      try publisher(f).publish(
        candidate, approvedPlan: candidate.plan, currentVaultKey: Core.nextKey,
        nextVaultKey: Self.nextKey,
        identity: mismatch ? IncorrectUnwrapper(base: f.owner) : f.owner,
        reason: "Owned provider-result review",
        protectionLossAcknowledgement: acknowledgement(candidate.plan))
    }
    #expect(f.owner.unwraps == 1 && f.disk.ownership.value == nil)
  }

  @Test(arguments: 0..<4)
  func changesDuringMacVerificationStopBeforeReservation(variant: Int) throws {
    let f = try Fixture(last: true)
    defer { f.disk.remove() }
    let candidate = try f.build()
    f.owner.onUnwrap = {
      switch variant {
      case 0: try f.addBranch()
      case 1: f.disk.checkpoints.value = Data([1])
      case 2: f.disk.registration.value = Data([1])
      default: f.disk.adoption.value = Data([1])
      }
    }
    #expect(throws: (any Error).self) { try publish(f, candidate) }
    #expect(f.disk.ownership.value == nil && f.owner.unwraps == 1)
  }

  @Test(arguments: [false, true])
  func reciprocalAuthorityPendingWorkBlocksPublishPrepareAndResume(registration: Bool) throws {
    let f = try Fixture(last: true)
    defer { f.disk.remove() }
    let candidate = try f.build()
    let other = registration ? f.disk.registration : f.disk.adoption
    other.value = Data([1])
    #expect(throws: V3RecoveryContentPublicationError.otherMutationPending) {
      try publish(f, candidate)
    }
    #expect(f.owner.unwraps == 0 && f.disk.ownership.value == nil)
    other.value = nil
    try interrupt(f, candidate)
    let pending = f.disk.ownership.value
    other.value = Data([1])
    #expect(throws: V3RecoveryContentPublicationError.otherMutationPending) { try resume(f) }
    #expect(throws: V3RecoveryContentPublicationError.otherMutationPending) {
      try publisher(f).prepareInterruptedTransaction(
        vaultID: Core.vaultID, expectedOwner: f.owner.publicIdentity)
    }
    #expect(f.disk.ownership.value == pending)
  }

  @Test(arguments: [
    VaultTransactionMutationKind.rotateVaultKey, .revokeDevice, .enrollDevice, .editEntry,
  ])
  func otherKindsCannotBeResumedOrAbandonedBeforeCheckpointGuard(kind: VaultTransactionMutationKind)
    throws
  {
    let f = try Fixture()
    defer { f.disk.remove() }
    let bytes = try V3ImmutableTransactionRecoveryIntent(
      operationID: f.disk.operationID, kind: kind, vaultID: Core.vaultID,
      expectedCheckpoint: f.disk.checkpoint, expectedHeads: [f.disk.parent.digest],
      candidateManifestDigest: Data(repeating: 7, count: 32), stagedEntries: []
    ).canonicalBytes
    try f.disk.store.persistRecoveryIntent(bytes, operationID: f.disk.operationID)
    let anchor = try V3ImmutableTransactionRecoveryAnchor(
      operationID: f.disk.operationID,
      vaultID: Core.vaultID, intentDigest: Data(SHA256.hash(data: bytes)), phase: .prepared)
    f.disk.ownership.value = anchor.canonicalBytes
    f.disk.checkpoints.value = f.disk.core.checkpoint.canonicalBytes
    #expect(
      throws: V3ImmutableTransactionRecoveryError.invalidIntent(
        operationID: f.disk.operationID.rawValue)
    ) { try resume(f) }
    #expect(f.disk.ownership.value == anchor.canonicalBytes && f.owner.unwraps == 0)
  }

  @Test func removalIntentCannotBeResumedByOtherPolicies() throws {
    let f = try Fixture(last: true)
    defer { f.disk.remove() }
    try interrupt(f, f.build())
    let pending = f.disk.ownership.value
    let rotation = V3RecoveryKeyRotationPublisher(
      mutationOwner: VaultTransactionMutationOwner(),
      objectStore: f.disk.store, checkpointStore: f.disk.checkpoints,
      recoveryAnchorStore: f.disk.ownership,
      registrationAnchorStore: f.disk.registration, adoptionAnchorStore: f.disk.adoption,
      cache: f.disk.cache)
    let revocation = V3RecoveryDeviceRevocationPublisher(
      mutationOwner: VaultTransactionMutationOwner(),
      objectStore: f.disk.store, checkpointStore: f.disk.checkpoints,
      recoveryAnchorStore: f.disk.ownership,
      registrationAnchorStore: f.disk.registration, adoptionAnchorStore: f.disk.adoption,
      cache: f.disk.cache)
    let expected = V3ImmutableTransactionRecoveryError.invalidIntent(
      operationID: f.disk.operationID.rawValue)
    #expect(throws: expected) {
      try rotation.recoverInterruptedTransaction(
        vaultID: Core.vaultID,
        currentVaultKey: Core.nextKey, nextVaultKey: Self.nextKey,
        expectedOwner: f.owner.publicIdentity)
    }
    #expect(throws: expected) {
      try revocation.recoverInterruptedTransaction(
        vaultID: Core.vaultID,
        currentVaultKey: Core.nextKey, nextVaultKey: Self.nextKey,
        expectedOwner: f.owner.publicIdentity)
    }
    #expect(throws: expected) {
      try f.disk.publisher().recoverInterruptedTransaction(
        vaultID: Core.vaultID, vaultKey: Self.nextKey)
    }
    #expect(f.disk.ownership.value == pending)
    #expect(try resume(f) == .completed(operationID: f.disk.operationID))
  }

  @Test func routedAnchorMismatchCannotAbandonPreparedWork() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try f.build()
    #expect(throws: Stop.interrupted) {
      try publish(
        f, candidate,
        observer: Observer { if $0 == .recoveryAnchorPrepared { throw Stop.interrupted } })
    }
    let pending = f.disk.ownership.value
    #expect(throws: (any Error).self) {
      try publisher(f).prepareInterruptedTransaction(
        vaultID: Core.vaultID, expectedOwner: f.owner.publicIdentity, expectedAnchor: Data([1]))
    }
    #expect(f.disk.ownership.value == pending)
    #expect(try resume(f) == .abandoned(operationID: f.disk.operationID))
  }

  @Test(arguments: 0..<3)
  func visibleBranchDuringPublicationRetainsPendingAndOldCheckpoint(phase: Int) throws {
    let f = try Fixture(last: true)
    defer { f.disk.remove() }
    let candidate = try f.build()
    let stop: V3ImmutableTransactionPhase =
      phase == 0
      ? .repositoryStateRechecked : phase == 1 ? .entryPublished(index: 0) : .manifestPublished
    #expect(throws: (any Error).self) {
      try publish(
        f, candidate,
        observer: Observer { if $0 == stop { try f.addBranch() } })
    }
    #expect(
      f.disk.ownership.value != nil && f.disk.checkpoints.value == f.disk.checkpoint.canonicalBytes)
  }

  @Test(arguments: 0..<3)
  func resourceBudgetsRefuseBeforePrivateOperation(variant: Int) throws {
    let f = try Fixture(last: true)
    defer { f.disk.remove() }
    let candidate = try f.build()
    let limits = [
      Core.Fixture.limits(entries: 3), Core.Fixture.limits(entryBytes: 1),
      Core.Fixture.limits(totalBytes: 1),
    ][variant]
    #expect(throws: (any Error).self) {
      try publisher(f, limits: limits).publish(
        candidate, approvedPlan: candidate.plan, currentVaultKey: Core.nextKey,
        nextVaultKey: Self.nextKey,
        identity: f.owner, reason: "Owned budget review",
        protectionLossAcknowledgement: acknowledgement(candidate.plan))
    }
    #expect(f.owner.unwraps == 0 && f.disk.ownership.value == nil)
  }

  @Test(arguments: 0..<3)
  func durableRemovalThenOrdinarySaveAllowsOnlyContinuingRecipients(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let (anchors, tokens, digest) = try removalChain(root, variant: variant)
    let store = V3FilesystemTransactionArtifactStore(
      rootHandle: try VaultRootDirectoryHandle(opening: root))
    for index in 0..<2 {
      let token = tokens[index]
      if variant == 2 || index == variant {
        #expect(throws: V3RecoveryValidationError.recipientRevoked) {
          try V3RecoveryHistorySelector(source: store).select(
            anchor: anchors[index], credentialPublicKey: token.publicKey.x963Representation)
        }
        continue
      }
      let selected = try V3RecoveryHistorySelector(source: store).select(
        anchor: anchors[index], credentialPublicKey: token.publicKey.x963Representation)
      let calls = Core.Counter()
      let receiver = try PIVHPKEReceiver(publicBytes: token.publicKey.x963Representation) { peer in
        calls.increment()
        return try token.sharedSecretFromKeyAgreement(
          with: P256.KeyAgreement.PublicKey(x963Representation: peer)
        )
        .withUnsafeBytes { Data($0) }
      }
      let opened = try V3RecoverySnapshotVerifier(source: store).open(
        selected, boundAnchor: anchors[index], receiver: receiver)
      #expect(selected.head.digest == digest && calls.value == 1)
      #expect(
        opened.entries.first { $0.name == "fixture/secret" }?.plaintext == "after durable removal")
      #expect(opened.entries.first { $0.name == "fixture/totp" }?.plaintext == "JBSWY3DPEHPK3PXP")
    }
  }

  private func removalChain(_ root: URL, variant: Int) throws -> (
    [V3RecoveryAnchor], [P256.KeyAgreement.PrivateKey], Data
  ) {
    let f = try Publication.Fixture(root: root)
    let backup = try #require(f.core.parent.body.recovery.recipients.first)
    let backupAnchor = try V3RecoveryAnchor(
      floor: .init(vaultID: Core.vaultID, envelopeDigest: f.core.parent.digest),
      recipientID: backup.recipientID, registrationID: backup.registrationID, slot: .keyManagement)
    let targets =
      variant == 2
      ? [f.anchor.recipientID, backup.recipientID]
      : [variant == 0 ? f.anchor.recipientID : backup.recipientID]
    var parent = f.parent
    var entries = f.entries
    var key = Core.nextKey
    var obsolete = Array(f.core.entries.values) + Array(f.entries.values)
    var latestEntries: [V3EncryptedEntry] = []
    for (index, target) in targets.enumerated() {
      let plan = try V3RecoveryRecipientRemovalPlanner().plan(
        checkpoint: .init(vaultID: Core.vaultID, envelopeDigest: parent.digest), parent: parent,
        currentVaultKey: key, authorizingDeviceID: f.core.owner.publicIdentity.deviceID,
        removing: target)
      let next = Data(repeating: index == 0 ? 0x44 : 0x55, count: 32)
      let acknowledgement = try acknowledgement(plan)
      let candidate = try V3RecoveryRecipientRemovalBuilder().build(
        parent: parent, currentEntries: entries,
        plan: plan, currentVaultKey: key, nextVaultKey: next, owner: f.core.owner,
        reason: "Owned chain construction",
        protectionLossAcknowledgement: acknowledgement)
      let publisher = V3RecoveryRecipientRemovalPublisher(
        mutationOwner: VaultTransactionMutationOwner(),
        objectStore: f.store, checkpointStore: f.checkpoints, recoveryAnchorStore: f.ownership,
        registrationAnchorStore: f.registration, adoptionAnchorStore: f.adoption, cache: f.cache)
      _ = try publisher.publish(
        candidate, approvedPlan: plan, currentVaultKey: key, nextVaultKey: next,
        identity: f.core.owner, reason: "Owned chain review",
        protectionLossAcknowledgement: acknowledgement)
      if index < targets.count - 1 { obsolete += candidate.stagedEntries }
      latestEntries = candidate.stagedEntries
      parent = candidate.envelope
      entries = try V3EntrySnapshotValidator(limits: .standard).entryMap(latestEntries)
      key = next
    }
    let session = V3DeviceWrappedVaultKeySessionStore()
    try session.install(key, vaultID: Core.vaultID, keyID: parent.body.fields.keyID)
    try V3RecoveryVaultMutationService(
      vaultID: Core.vaultID, session: session,
      objectStore: f.store, checkpointStore: f.checkpoints, recoveryAnchorStore: f.ownership,
      registrationAnchorStore: f.registration, adoptionAnchorStore: f.adoption, cache: f.cache
    )
    .edit(
      name: "fixture/secret", secret: "after durable removal", type: .secret, operationID: .init())
    session.invalidate()
    obsolete += latestEntries.filter { $0.context.name == "fixture/secret" }
    for entry in obsolete { try FileManager.default.removeItem(at: f.entryURL(entry)) }
    let last = try V3ManifestCheckpoint(canonicalBytes: #require(f.checkpoints.value))
    #expect(f.core.owner.signatures == targets.count + 1 && f.core.owner.unwraps == targets.count)
    return ([f.anchor, backupAnchor], [f.core.token, f.core.backupToken], last.envelopeDigest)
  }

  private struct Fixture: Sendable {
    let disk: Publication.Fixture
    var owner: Core.Owner { disk.core.owner }
    init(last: Bool = false, empty: Bool = false) throws {
      disk = try .init(empty: empty, backup: !last)
    }
    func build() throws -> V3RecoveryRecipientRemovalCandidate {
      let plan = try V3RecoveryRecipientRemovalPlanner().plan(
        checkpoint: disk.checkpoint,
        parent: disk.parent, currentVaultKey: Core.nextKey,
        authorizingDeviceID: owner.publicIdentity.deviceID,
        removing: disk.anchor.recipientID)
      return try V3RecoveryRecipientRemovalBuilder().build(
        parent: disk.parent, currentEntries: disk.entries,
        plan: plan, currentVaultKey: Core.nextKey,
        nextVaultKey: V3RecoveryRecipientRemovalPublisherTests.nextKey,
        owner: owner, reason: "Owned construction fixture",
        protectionLossAcknowledgement: plan.removesLastActiveRecipient
          ? V3RecoveryProtectionLossAcknowledgement(plan: plan) : nil)
    }
    func addBranch() throws {
      let branch = try disk.build(
        .edit(name: "fixture/secret", type: .secret, plaintext: "other branch"))
      try disk.seed(branch.envelope, entries: branch.stagedEntries)
    }
  }
  private func acknowledgement(_ plan: V3RecoveryRecipientRemovalPlan) throws
    -> V3RecoveryProtectionLossAcknowledgement?
  {
    try plan.removesLastActiveRecipient ? .init(plan: plan) : nil
  }
  private func publisher(
    _ f: Fixture,
    observer: any V3ImmutableTransactionPhaseObserving = V3NoopContentTransactionPhaseObserver(),
    limits: V3ManifestRepositoryLimits = .standard
  ) -> V3RecoveryRecipientRemovalPublisher {
    .init(
      mutationOwner: VaultTransactionMutationOwner(makeOperationID: { f.disk.operationID }),
      objectStore: f.disk.store, checkpointStore: f.disk.checkpoints,
      recoveryAnchorStore: f.disk.ownership,
      registrationAnchorStore: f.disk.registration, adoptionAnchorStore: f.disk.adoption,
      cache: f.disk.cache, limits: limits, phaseObserver: observer)
  }
  private func publish(
    _ f: Fixture, _ candidate: V3RecoveryRecipientRemovalCandidate,
    observer: any V3ImmutableTransactionPhaseObserving = V3NoopContentTransactionPhaseObserver()
  ) throws -> V3RecoveryRecipientRemovalCommit {
    try publisher(f, observer: observer).publish(
      candidate, approvedPlan: candidate.plan,
      currentVaultKey: Core.nextKey, nextVaultKey: Self.nextKey, identity: f.owner,
      reason: "Owned publication review",
      protectionLossAcknowledgement: acknowledgement(candidate.plan))
  }
  private func resume(
    _ f: Fixture, currentKey: Data? = Core.nextKey, nextKey: Data = Self.nextKey,
    owner: V3EnrollmentDeviceIdentity? = nil, expectedAnchor: Data? = nil
  ) throws -> V3ImmutableTransactionRecoveryOutcome {
    try publisher(f).recoverInterruptedTransaction(
      vaultID: Core.vaultID, currentVaultKey: currentKey,
      nextVaultKey: nextKey, expectedOwner: owner ?? f.owner.publicIdentity,
      expectedAnchor: expectedAnchor)
  }
  private func interrupt(_ f: Fixture, _ candidate: V3RecoveryRecipientRemovalCandidate) throws {
    #expect(throws: Stop.interrupted) {
      try publish(
        f, candidate,
        observer: Observer { if $0 == .manifestStaged { throw Stop.interrupted } })
    }
  }
  private struct Observer: V3ImmutableTransactionPhaseObserving {
    let action: @Sendable (V3ImmutableTransactionPhase) throws -> Void
    func didReach(_ phase: V3ImmutableTransactionPhase, operationID _: VaultTransactionOperationID)
      throws
    { try action(phase) }
  }
  private struct IncorrectUnwrapper: V3DeviceWrappedVaultKeyUnwrapping {
    let base: Core.Owner
    var vaultID: String { base.vaultID }
    var publicIdentity: V3EnrollmentDeviceIdentity { base.publicIdentity }
    func unwrapDeviceWrappedVaultKey(
      _ wrappedKey: V3HPKEWrappedVaultKey,
      context: V3VaultKeyHPKEContext, reason: String
    ) throws -> Data {
      _ = try base.unwrapDeviceWrappedVaultKey(wrappedKey, context: context, reason: reason)
      return Core.nextKey
    }
  }
}
