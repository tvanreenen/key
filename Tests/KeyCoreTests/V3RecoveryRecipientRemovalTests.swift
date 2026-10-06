import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Owned software credentials and disposable storage only. Lifecycle setup is
/// materialized here; these tests do not provide a removal publisher or consent UI.
struct V3RecoveryRecipientRemovalTests {
  private typealias Core = V3RecoveryRegistrationTests
  private static let nextKey = Data(repeating: 0x44, count: 32)
  private static let lastKey = Data(repeating: 0x55, count: 32)

  @Test(arguments: [false, true])
  func exactRemovalPreservesOtherAuthoritiesAndEveryPlaintext(empty: Bool) throws {
    let f = try Fixture(empty: empty)
    let plan = try f.plan()
    let candidate = try f.build(plan: plan)
    let old = f.parent.body
    let new = candidate.envelope.body
    #expect(candidate.plan == plan && candidate.envelope.parents == [f.parent.digest])
    #expect(plan.expectedCheckpoint == f.checkpoint && plan.remainingActiveRecipients == 1)
    #expect(!plan.removesLastActiveRecipient && plan.removedRecipient.status == .active)
    #expect(new.fields.devices == old.fields.devices)
    #expect(new.recovery.recipients == plan.resultingRecipients)
    #expect(new.recovery.generationID != old.recovery.generationID)
    #expect(new.fields.keyID != old.fields.keyID)
    #expect(new.epochSigningKey.publicKey != old.epochSigningKey.publicKey)
    let tombstone = try V3RecoveryRecipient(
      registrationID: plan.removedRecipient.registrationID,
      publicKey: plan.removedRecipient.publicKey, slot: plan.removedRecipient.slot,
      status: .revoked)
    #expect(
      new.recovery.recipients.first { $0.recipientID == plan.removedRecipient.recipientID }
        == tombstone)
    #expect(
      new.recovery.wrappedKeys.map(\.recipientID)
        == plan.resultingRecipients.filter { $0.status == .active }.map(\.recipientID))
    #expect(
      zip(old.fields.entries, new.fields.entries).allSatisfy {
        $0.entryID == $1.entryID && $0.name == $1.name && $0.type == $1.type
          && $0.revision == $1.revision && $0.ciphertextDigest != $1.ciphertextDigest
      })
    let snapshots = V3EntrySnapshotValidator(limits: .standard)
    #expect(
      try snapshots.plaintexts(fields: old.fields, entries: f.entries, vaultKey: Core.nextKey)
        == snapshots.plaintexts(
          fields: new.fields, entries: snapshots.entryMap(candidate.stagedEntries),
          vaultKey: Self.nextKey))
    #expect(candidate.stagedEntries.isEmpty == empty)
    #expect(f.core.owner.signatures == f.signatures + 1 && f.core.owner.unwraps == 0)
  }

  @Test func lastRemovalRequiresTheExactAcknowledgementAtBuildAndValidation() throws {
    let f = try Fixture(backup: false)
    let plan = try f.plan()
    #expect(plan.removesLastActiveRecipient && plan.remainingActiveRecipients == 0)
    #expect(throws: V3RecoveryRecipientRemovalError.protectionLossAcknowledgementRequired) {
      try f.build(plan: plan)
    }
    #expect(f.core.owner.signatures == f.signatures)
    let acknowledgement = try V3RecoveryProtectionLossAcknowledgement(plan: plan)
    let candidate = try f.build(plan: plan, acknowledgement: acknowledgement)
    #expect(candidate.envelope.body.recovery.wrappedKeys.isEmpty)
    #expect(candidate.envelope.body.recovery.recipients.allSatisfy { $0.status == .revoked })
    #expect(throws: V3RecoveryRecipientRemovalError.protectionLossAcknowledgementRequired) {
      try f.verifyLocalWrapper(candidate)
    }
    #expect(f.core.owner.unwraps == 0)
    try f.verifyLocalWrapper(candidate, acknowledgement: acknowledgement)
    #expect(f.core.owner.unwraps == 1)
    let rotation = try V3RecoveryKeyRotationBuilder().build(
      checkpoint: .init(vaultID: Core.vaultID, envelopeDigest: candidate.envelope.digest),
      parent: candidate.envelope,
      currentEntries: V3EntrySnapshotValidator(limits: .standard).entryMap(candidate.stagedEntries),
      currentVaultKey: Self.nextKey, nextVaultKey: Self.lastKey,
      owner: f.core.owner, reason: "Software fixture")
    #expect(
      rotation.envelope.body.recovery.recipients == candidate.envelope.body.recovery.recipients)
    #expect(
      rotation.envelope.body.recovery.generationID == candidate.envelope.body.recovery.generationID)
    #expect(rotation.envelope.body.recovery.wrappedKeys.isEmpty)
  }

  @Test(arguments: 0..<3)
  func acknowledgementCannotBeTransferredToAnotherPlan(variant: Int) throws {
    let f = try Fixture(backup: false)
    let plan = try f.plan()
    let other = try Core.Owner()
    let changed = V3RecoveryRecipientRemovalPlan(
      expectedCheckpoint: variant == 0
        ? try .init(vaultID: Core.vaultID, envelopeDigest: Data(repeating: 0x99, count: 32))
        : plan.expectedCheckpoint,
      authorizingDevice: variant == 1
        ? .init(identity: other.publicIdentity, status: .active) : plan.authorizingDevice,
      removedRecipient: variant == 2
        ? try .init(
          registrationID: UUID().uuidString.lowercased(),
          publicKey: plan.removedRecipient.publicKey,
          slot: .keyManagement, status: .active) : plan.removedRecipient,
      resultingRecipients: plan.resultingRecipients)
    let acknowledgement = try V3RecoveryProtectionLossAcknowledgement(plan: changed)
    #expect(throws: V3RecoveryRecipientRemovalError.invalidAcknowledgement) {
      try f.build(plan: plan, acknowledgement: acknowledgement)
    }
    #expect(f.core.owner.signatures == f.signatures && f.core.owner.unwraps == 0)
    let candidate = try f.build(
      plan: plan, acknowledgement: V3RecoveryProtectionLossAcknowledgement(plan: plan))
    #expect(throws: V3RecoveryRecipientRemovalError.invalidAcknowledgement) {
      try f.verifyLocalWrapper(candidate, acknowledgement: acknowledgement)
    }
    #expect(f.core.owner.unwraps == 0)
  }

  @Test func ordinaryRemovalDoesNotAcceptALossOfProtectionOverride() throws {
    let f = try Fixture()
    #expect(throws: V3RecoveryRecipientRemovalError.invalidAcknowledgement) {
      try V3RecoveryProtectionLossAcknowledgement(plan: f.plan())
    }
    let last = try Fixture(backup: false)
    let acknowledgement = try V3RecoveryProtectionLossAcknowledgement(plan: last.plan())
    #expect(throws: V3RecoveryRecipientRemovalError.invalidAcknowledgement) {
      try f.build(acknowledgement: acknowledgement)
    }
    #expect(f.core.owner.signatures == f.signatures)
  }

  @Test(arguments: 0..<4)
  func changedReviewedPlansRefuseBeforeSigning(variant: Int) throws {
    let f = try Fixture()
    let plan = try f.plan()
    let other = try Core.Owner()
    let changed = V3RecoveryRecipientRemovalPlan(
      expectedCheckpoint: variant == 0
        ? try .init(vaultID: Core.vaultID, envelopeDigest: Data(repeating: 0x99, count: 32))
        : plan.expectedCheckpoint,
      authorizingDevice: variant == 1
        ? .init(identity: other.publicIdentity, status: .active) : plan.authorizingDevice,
      removedRecipient: variant == 2
        ? try .init(
          registrationID: plan.removedRecipient.registrationID,
          publicKey: plan.removedRecipient.publicKey, slot: .keyManagement, status: .revoked)
        : plan.removedRecipient,
      resultingRecipients: variant == 3
        ? f.parent.body.recovery.recipients : plan.resultingRecipients)
    #expect(throws: (any Error).self) { try f.build(plan: changed) }
    #expect(f.core.owner.signatures == f.signatures && f.core.owner.unwraps == 0)
  }

  @Test func plannerRejectsUnknownAndAlreadyRevokedRecipientsAndUnknownOwner() throws {
    let f = try Fixture()
    let unknown = try V3RecoveryRecipientID.derive(
      publicKey: P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
    #expect(throws: V3RecoveryRecipientRemovalError.recipientNotFound) {
      try f.plan(target: unknown)
    }
    #expect(throws: V3RecoveryRecipientRemovalError.invalidOwner) {
      try f.plan(ownerID: UUID().uuidString.lowercased())
    }
    let candidate = try f.build()
    #expect(throws: V3RecoveryRecipientRemovalError.recipientAlreadyRevoked) {
      try V3RecoveryRecipientRemovalPlanner().plan(
        checkpoint: .init(vaultID: Core.vaultID, envelopeDigest: candidate.envelope.digest),
        parent: candidate.envelope, currentVaultKey: Self.nextKey,
        authorizingDeviceID: f.core.owner.publicIdentity.deviceID,
        removing: candidate.plan.removedRecipient.recipientID)
    }
    #expect(f.core.owner.signatures == f.signatures + 1 && f.core.owner.unwraps == 0)
  }

  @Test(arguments: 0..<9)
  func invalidKeysOwnerReasonAndFreshEpochIdentifiersRefuseBeforeSigning(variant: Int) throws {
    let f = try Fixture()
    #expect(throws: (any Error).self) {
      try f.build(
        currentKey: variant == 0 ? Self.nextKey : Core.nextKey,
        nextKey: variant == 1 ? Core.nextKey : (variant == 2 ? Data([1]) : Self.nextKey),
        owner: variant == 3 ? Core.Owner() : f.core.owner,
        reason: variant == 4 ? "" : "Software fixture",
        transition: variant == 5
          ? f.parent.body.fields.authorityTransitionID
          : (variant == 6 ? "invalid" : UUID().uuidString.lowercased()),
        generation: variant == 7
          ? f.parent.body.recovery.generationID
          : (variant == 8 ? "invalid" : UUID().uuidString.lowercased()))
    }
    #expect(f.core.owner.signatures == f.signatures && f.core.owner.unwraps == 0)
  }

  @Test(arguments: 0..<4)
  func independentPolicyRejectsAnotherDecisionGenerationOrDeviceRoster(variant: Int) throws {
    let f = try Fixture()
    let plan = try f.plan()
    let candidate: V3RecoveryRecipientRemovalCandidate
    if variant == 0 {
      let backup = try #require(
        f.parent.body.recovery.recipients.first {
          $0.recipientID != plan.removedRecipient.recipientID
        })
      let other = try f.build(plan: f.plan(target: backup.recipientID))
      candidate = .init(plan: plan, envelope: other.envelope, stagedEntries: other.stagedEntries)
    } else {
      let values = try V3EntrySnapshotValidator(limits: .standard).plaintexts(
        fields: f.parent.body.fields, entries: f.entries, vaultKey: Core.nextKey)
      let unrelated = try Core.Owner()
      let devices =
        variant == 3
        ? (f.parent.body.fields.devices + [
          .init(identity: unrelated.publicIdentity, status: .revoked)
        ])
        .sorted { $0.identity.deviceID < $1.identity.deviceID }
        : f.parent.body.fields.devices
      let material = try V3RecoveryEpochMaterialBuilder(limits: .standard).build(
        fields: f.parent.body.fields, plaintexts: values, nextVaultKey: Self.nextKey,
        authorityTransitionID: UUID().uuidString.lowercased(),
        devices: devices,
        generationID: variant == 1
          ? f.parent.body.recovery.generationID : UUID().uuidString.lowercased(),
        recipients: variant == 2 ? f.parent.body.recovery.recipients : plan.resultingRecipients)
      let envelope = try V3RecoveryEpochBoundary().authorize(
        candidate: material.body, parent: f.parent, currentVaultKey: Core.nextKey,
        nextVaultKey: Self.nextKey, signer: f.core.owner, reason: "Owned policy fixture")
      candidate = .init(plan: plan, envelope: envelope, stagedEntries: material.stagedEntries)
    }
    #expect(throws: V3RecoveryRecipientRemovalError.invalidCandidate) {
      try f.verifyLocalWrapper(candidate)
    }
    #expect(f.core.owner.unwraps == 0)
  }

  @Test(arguments: 0..<4)
  func constructionBudgetsRefuseBeforeSigning(variant: Int) throws {
    let f = try Fixture()
    let limits = [
      Core.Fixture.limits(entries: 1), Core.Fixture.limits(entryBytes: 1),
      Core.Fixture.limits(totalBytes: 1),
      Core.Fixture.limits(manifestBytes: f.parent.canonicalBytes.count),
    ][variant]
    #expect(throws: (any Error).self) { try f.build(limits: limits) }
    #expect(f.core.owner.signatures == f.signatures && f.core.owner.unwraps == 0)
  }

  @Test(arguments: 0..<3)
  func independentBudgetsRefuseBeforeLocalUnwrap(variant: Int) throws {
    let f = try Fixture()
    let candidate = try f.build()
    let limits = [
      Core.Fixture.limits(entries: 1), Core.Fixture.limits(entryBytes: 1),
      Core.Fixture.limits(totalBytes: 1),
    ][variant]
    #expect(throws: (any Error).self) { try f.verifyLocalWrapper(candidate, limits: limits) }
    #expect(f.core.owner.unwraps == 0)
  }

  @Test(arguments: 0..<5)
  func incompleteSubstitutedAndDuplicateSnapshotsRefuseBeforePrivateWork(variant: Int) throws {
    let f = try Fixture()
    let candidate = try f.build()
    let other = try f.build()
    let staged =
      variant == 0
      ? []
      : (variant == 1
        ? candidate.stagedEntries + candidate.stagedEntries
        : (variant == 2 ? other.stagedEntries : candidate.stagedEntries))
    #expect(throws: (any Error).self) {
      try V3RecoveryRecipientRemovalValidator().validateForPublication(
        .init(plan: candidate.plan, envelope: candidate.envelope, stagedEntries: staged),
        parent: f.parent, currentEntries: variant == 3 ? [:] : f.entries,
        currentVaultKey: Core.nextKey, nextVaultKey: variant == 4 ? Core.nextKey : Self.nextKey,
        identity: f.core.owner, reason: "Software fixture")
    }
    #expect(f.core.owner.unwraps == 0)
  }

  @Test(arguments: 0..<3)
  func localVerificationIsSingleAddressedAndFailureDoesNotRetry(variant: Int) throws {
    let f = try Fixture()
    let candidate = try f.build()
    f.core.owner.cancelUnwrap = variant == 1
    if variant == 2 {
      let identity = WrongUnwrap(publicIdentity: f.core.owner.publicIdentity)
      #expect(throws: V3RecoveryKeyRotationError.localWrapperMismatch) {
        try V3RecoveryRecipientRemovalValidator().validateForPublication(
          candidate, parent: f.parent, currentEntries: f.entries, currentVaultKey: Core.nextKey,
          nextVaultKey: Self.nextKey, identity: identity, reason: "Software provider fixture")
      }
      #expect(identity.calls.value == 1 && f.core.owner.unwraps == 0)
      return
    } else if variant == 1 {
      #expect(throws: Core.FixtureError.cancelled) { try f.verifyLocalWrapper(candidate) }
    } else {
      try f.verifyLocalWrapper(candidate)
    }
    #expect(f.core.owner.unwraps == 1)
  }

  private struct WrongUnwrap: V3DeviceWrappedVaultKeyUnwrapping {
    let vaultID = Core.vaultID
    let publicIdentity: V3EnrollmentDeviceIdentity
    let calls = Core.Counter()
    func unwrapDeviceWrappedVaultKey(
      _: V3HPKEWrappedVaultKey, context _: V3VaultKeyHPKEContext, reason _: String
    ) throws -> Data {
      calls.increment()
      return Core.oldKey
    }
  }

  @Test func cancelledSigningDoesNotProduceACandidateOrRetry() throws {
    let f = try Fixture()
    f.core.owner.cancelSigning = true
    #expect(throws: Core.FixtureError.cancelled) { try f.build() }
    #expect(f.core.owner.signatures == f.signatures + 1 && f.core.owner.unwraps == 0)
  }

  @Test func remainingMacWrapperOpensFreshKeyAndOldStateRemainsForwardOnly() throws {
    let f = try Fixture()
    let candidate = try f.build()
    let body = candidate.envelope.body
    let wrapper = try #require(body.fields.wrappedKeys.first)
    #expect(
      try V3VaultKeyHPKE().unwrap(
        wrapper.wrappedKey, recipientPrivateKey: f.core.owner.wrappingKey,
        context: body.deviceContext(recipientDeviceID: f.core.owner.publicIdentity.deviceID))
        == Self.nextKey)
    #expect(
      try V3EntrySnapshotValidator(limits: .standard).plaintexts(
        fields: f.parent.body.fields, entries: f.entries, vaultKey: Core.nextKey
      ).count == 2)
    let record = try #require(body.fields.entries.first)
    let entry = try #require(candidate.stagedEntries.first { $0.context.entryID == record.entryID })
    #expect(throws: (any Error).self) {
      try V3EntryCipher().openPlaintextDataTrusted(
        entry.canonicalBytes, vaultID: Core.vaultID, manifestEntry: record, vaultKey: Core.nextKey)
    }
  }

  @Test(arguments: 0..<3)
  func removalThenOrdinarySaveAllowsOnlyRemainingRecipients(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let (anchors, tokens, digest) = try removalChain(root, variant: variant)
    let store = V3FilesystemTransactionArtifactStore(
      rootHandle: try VaultRootDirectoryHandle(opening: root))
    for index in 0..<2 {
      let token = tokens[index]
      // Variant 0 removes primary, 1 removes backup, 2 removes both.
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
        ).withUnsafeBytes { Data($0) }
      }
      let snapshot = try V3RecoverySnapshotVerifier(source: store).open(
        selected, boundAnchor: anchors[index], receiver: receiver)
      #expect(selected.head.digest == digest && calls.value == 1)
      #expect(snapshot.entries.first { $0.name == "fixture/secret" }?.plaintext == "after removal")
      #expect(snapshot.entries.first { $0.name == "fixture/totp" }?.plaintext == "JBSWY3DPEHPK3PXP")
    }
  }

  private func removalChain(_ root: URL, variant: Int) throws -> (
    [V3RecoveryAnchor], [P256.KeyAgreement.PrivateKey], Data
  ) {
    let f = try V3RecoveryContentMutationPublisherTests.Fixture(root: root)
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
    for (index, target) in targets.enumerated() {
      let plan = try V3RecoveryRecipientRemovalPlanner().plan(
        checkpoint: .init(vaultID: Core.vaultID, envelopeDigest: parent.digest),
        parent: parent, currentVaultKey: key,
        authorizingDeviceID: f.core.owner.publicIdentity.deviceID, removing: target)
      let next = index == 0 ? Self.nextKey : Self.lastKey
      let candidate = try V3RecoveryRecipientRemovalBuilder().build(
        parent: parent, currentEntries: entries, plan: plan, currentVaultKey: key,
        nextVaultKey: next, owner: f.core.owner, reason: "Software fixture",
        protectionLossAcknowledgement: plan.removesLastActiveRecipient
          ? V3RecoveryProtectionLossAcknowledgement(plan: plan) : nil)
      try f.seed(candidate.envelope, entries: candidate.stagedEntries)
      if index < targets.count - 1 { obsolete += candidate.stagedEntries }
      parent = candidate.envelope
      entries = try V3EntrySnapshotValidator(limits: .standard).entryMap(candidate.stagedEntries)
      key = next
    }
    let checkpoint = try V3ManifestCheckpoint(vaultID: Core.vaultID, envelopeDigest: parent.digest)
    f.checkpoints.value = checkpoint.canonicalBytes
    try f.cache.store(parent.canonicalBytes, for: checkpoint)
    let session = V3DeviceWrappedVaultKeySessionStore()
    try session.install(key, vaultID: Core.vaultID, keyID: parent.body.fields.keyID)
    let owner = VaultTransactionMutationOwner()
    let service = V3RecoveryVaultMutationService(
      vaultID: Core.vaultID, session: session, objectStore: f.store, checkpointStore: f.checkpoints,
      recoveryAnchorStore: f.ownership, registrationAnchorStore: f.registration,
      adoptionAnchorStore: f.adoption, cache: f.cache)
    try owner.perform(.editEntry) { context in
      try service.edit(
        name: "fixture/secret", secret: "after removal", type: .secret,
        operationID: context.operationID)
    }
    session.invalidate()
    for entry in obsolete { try FileManager.default.removeItem(at: f.entryURL(entry)) }
    let last = try V3ManifestCheckpoint(canonicalBytes: #require(f.checkpoints.value))
    return ([f.anchor, backupAnchor], [f.core.token, f.core.backupToken], last.envelopeDigest)
  }

  private struct Fixture {
    let core: Core.Fixture
    let parent: V3RecoveryManifestEnvelope
    let checkpoint: V3ManifestCheckpoint
    let entries: [V3EntryObjectKey: V3EncryptedEntry]
    let primaryID: V3RecoveryRecipientID
    let signatures: Int

    init(empty: Bool = false, backup: Bool = true) throws {
      core = try Core.Fixture(empty: empty, backup: backup)
      let prepared = try core.prepare()
      parent = prepared.candidate
      checkpoint = try .init(vaultID: Core.vaultID, envelopeDigest: parent.digest)
      entries = try V3EntrySnapshotValidator(limits: .standard).entryMap(prepared.stagedEntries)
      primaryID = prepared.intent.anchor.recipientID
      signatures = core.owner.signatures
    }
    func plan(target: V3RecoveryRecipientID? = nil, ownerID: String? = nil) throws
      -> V3RecoveryRecipientRemovalPlan
    {
      try V3RecoveryRecipientRemovalPlanner().plan(
        checkpoint: checkpoint, parent: parent, currentVaultKey: Core.nextKey,
        authorizingDeviceID: ownerID ?? core.owner.publicIdentity.deviceID,
        removing: target ?? primaryID)
    }
    func build(
      plan: V3RecoveryRecipientRemovalPlan? = nil, currentKey: Data = Core.nextKey,
      nextKey: Data = V3RecoveryRecipientRemovalTests.nextKey, owner: Core.Owner? = nil,
      reason: String = "Software removal fixture",
      acknowledgement: V3RecoveryProtectionLossAcknowledgement? = nil,
      transition: String = UUID().uuidString.lowercased(),
      generation: String = UUID().uuidString.lowercased(),
      limits: V3ManifestRepositoryLimits = .standard
    ) throws -> V3RecoveryRecipientRemovalCandidate {
      try V3RecoveryRecipientRemovalBuilder(limits: limits).build(
        parent: parent, currentEntries: entries, plan: plan ?? self.plan(),
        currentVaultKey: currentKey, nextVaultKey: nextKey, owner: owner ?? core.owner,
        reason: reason, protectionLossAcknowledgement: acknowledgement,
        authorityTransitionID: transition, generationID: generation)
    }
    func verifyLocalWrapper(
      _ candidate: V3RecoveryRecipientRemovalCandidate,
      acknowledgement: V3RecoveryProtectionLossAcknowledgement? = nil,
      limits: V3ManifestRepositoryLimits = .standard
    ) throws {
      try V3RecoveryRecipientRemovalValidator(limits: limits).validateForPublication(
        candidate, parent: parent, currentEntries: entries, currentVaultKey: Core.nextKey,
        nextVaultKey: V3RecoveryRecipientRemovalTests.nextKey, identity: core.owner,
        reason: "Software wrapper fixture", protectionLossAcknowledgement: acknowledgement)
    }
  }
}
