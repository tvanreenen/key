import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Owned software credentials and disposable fixtures only. Epoch publication
/// and checkpoint setup are materialized here, not a revocation service.
struct V3RecoveryDeviceRevocationTests {
  private typealias Core = V3RecoveryRegistrationTests
  private static let now: UInt64 = 4_102_444_800
  private static let currentKey = Data(repeating: 0x33, count: 32)
  private static let nextKey = Data(repeating: 0x44, count: 32)

  @Test func reviewedPlanRevokesOnlyTheSelectedMacAndPreservesRecovery() throws {
    let f = try Fixture()
    let plan = try f.plan()
    let candidate = try f.build(plan: plan)
    let old = f.parent.body
    let new = candidate.envelope.body
    #expect(candidate.plan == plan && candidate.envelope.parents == [f.parent.digest])
    #expect(plan.expectedCheckpoint == f.checkpoint)
    #expect(plan.authorizingDevice.identity == f.core.owner.publicIdentity)
    #expect(
      plan.revokedDevice.identity == f.target.publicIdentity && plan.revokedDevice.status == .active
    )
    #expect(new.fields.devices == plan.resultingDevices)
    #expect(new.fields.devices.count == old.fields.devices.count)
    #expect(
      new.fields.devices.contains(.init(identity: f.retired.publicIdentity, status: .revoked)))
    #expect(new.recovery.recipients == old.recovery.recipients)
    #expect(new.recovery.generationID == old.recovery.generationID)
    #expect(
      new.fields.keyID != old.fields.keyID
        && new.epochSigningKey.publicKey != old.epochSigningKey.publicKey)
    #expect(old.fields.entries.count == new.fields.entries.count)
    #expect(
      zip(old.fields.entries, new.fields.entries).allSatisfy {
        $0.entryID == $1.entryID && $0.name == $1.name && $0.type == $1.type
          && $0.revision == $1.revision
          && $0.ciphertextDigest != $1.ciphertextDigest
      })
    let snapshots = V3EntrySnapshotValidator(limits: .standard)
    #expect(
      try snapshots.plaintexts(fields: old.fields, entries: f.entries, vaultKey: Self.currentKey)
        == snapshots.plaintexts(
          fields: new.fields, entries: snapshots.entryMap(candidate.stagedEntries),
          vaultKey: Self.nextKey))
    #expect(f.core.owner.signatures == f.ownerSignatures + 1 && f.core.owner.unwraps == 0)
  }

  @Test(arguments: 0..<3)
  func emptyAndUnregisteredVaultsPreserveTheirCoverageState(variant: Int) throws {
    let f = try Fixture(empty: variant == 1, backup: variant != 2)
    let candidate = try f.build()
    #expect(candidate.stagedEntries.isEmpty == (variant == 1))
    #expect(candidate.envelope.body.recovery.recipients == f.parent.body.recovery.recipients)
    #expect(candidate.envelope.body.recovery.wrappedKeys.isEmpty == (variant == 2))
    try f.validate(candidate)
  }

  @Test func remainingWrappersOpenTheFreshKeyButRevokedMacRetainsOnlyOldAccess() throws {
    let f = try Fixture()
    let candidate = try f.build()
    let body = candidate.envelope.body
    for device in [f.core.owner, f.peer] {
      let wrapper = try #require(
        body.fields.wrappedKeys.first { $0.recipientDeviceID == device.publicIdentity.deviceID })
      #expect(
        try V3VaultKeyHPKE().unwrap(
          wrapper.wrappedKey, recipientPrivateKey: device.wrappingKey,
          context: body.deviceContext(recipientDeviceID: device.publicIdentity.deviceID))
          == Self.nextKey)
    }
    #expect(
      !body.fields.wrappedKeys.contains { $0.recipientDeviceID == f.target.publicIdentity.deviceID }
    )
    #expect(
      !body.fields.wrappedKeys.contains {
        $0.recipientDeviceID == f.retired.publicIdentity.deviceID
      })
    let oldWrapper = try #require(
      f.parent.body.fields.wrappedKeys.first {
        $0.recipientDeviceID == f.target.publicIdentity.deviceID
      })
    let oldKey = try V3VaultKeyHPKE().unwrap(
      oldWrapper.wrappedKey, recipientPrivateKey: f.target.wrappingKey,
      context: f.parent.body.deviceContext(recipientDeviceID: f.target.publicIdentity.deviceID))
    #expect(oldKey == Self.currentKey)
    let record = try #require(body.fields.entries.first)
    let entry = try #require(candidate.stagedEntries.first { $0.context.entryID == record.entryID })
    #expect(throws: (any Error).self) {
      try V3EntryCipher().openPlaintextDataTrusted(
        entry.canonicalBytes, vaultID: Core.vaultID, manifestEntry: record, vaultKey: oldKey)
    }
    // Existing copied old state still opens; revocation is forward-only.
    #expect(
      try V3EntrySnapshotValidator(limits: .standard).plaintexts(
        fields: f.parent.body.fields, entries: f.entries, vaultKey: oldKey
      ).count == 2)
  }

  @Test(arguments: 0..<5)
  func plannerRejectsUnknownRevokedAndSelfSelections(variant: Int) throws {
    let f = try Fixture()
    let unknown = try Core.Owner()
    let owner = variant == 3 ? unknown : (variant == 4 ? f.retired : f.core.owner)
    let target =
      variant == 0 ? unknown : (variant == 1 ? f.retired : (variant == 2 ? f.core.owner : f.target))
    let expected: [V3DeviceWrappedRevocationPlanningError] = [
      .deviceNotFound, .deviceAlreadyRevoked, .cannotRevokeAuthorizingDevice,
      .invalidAuthorizingDevice, .invalidAuthorizingDevice,
    ]
    #expect(throws: expected[variant]) { try f.plan(owner: owner, target: target) }
    #expect(f.core.owner.signatures == f.ownerSignatures && owner.unwraps == 0)
  }

  @Test func plannerRejectsLastActiveMacBeforePrivateWork() throws {
    let f = try Core.Fixture(backup: true)
    #expect(throws: V3DeviceWrappedRevocationPlanningError.lastActiveDevice) {
      try V3RecoveryDeviceRevocationPlanner().plan(
        checkpoint: f.checkpoint, parent: f.parent, currentVaultKey: Core.oldKey,
        authorizingDeviceID: f.owner.publicIdentity.deviceID,
        revoking: f.owner.publicIdentity.deviceID)
    }
    #expect(f.owner.signatures == 0 && f.owner.unwraps == 0)
  }

  @Test(arguments: 0..<5)
  func changedReviewedPlanRefusesBeforeSigning(variant: Int) throws {
    let f = try Fixture()
    let plan = try f.plan()
    let changed = V3DeviceWrappedRevocationPlan(
      expectedCheckpoint: variant == 0
        ? try .init(vaultID: Core.vaultID, envelopeDigest: Data(repeating: 0x99, count: 32))
        : plan.expectedCheckpoint,
      authorizingDevice: variant == 1
        ? .init(identity: f.peer.publicIdentity, status: .active) : plan.authorizingDevice,
      revokedDevice: variant == 2
        ? .init(identity: f.target.publicIdentity, status: .revoked) : plan.revokedDevice,
      resultingDevices: variant == 3
        ? f.parent.body.fields.devices
        : (variant == 4
          ? plan.resultingDevices.filter { $0.identity != f.retired.publicIdentity }
          : plan.resultingDevices))
    #expect(throws: (any Error).self) { try f.build(plan: changed) }
    #expect(f.core.owner.signatures == f.ownerSignatures && f.core.owner.unwraps == 0)
  }

  @Test(arguments: 0..<7)
  func invalidKeysOwnerReasonAndTransitionRefuseBeforeSigning(variant: Int) throws {
    let f = try Fixture()
    #expect(throws: (any Error).self) {
      try f.build(
        currentKey: variant == 0 ? Self.nextKey : Self.currentKey,
        nextKey: variant == 1 ? Self.currentKey : (variant == 2 ? Data([1]) : Self.nextKey),
        owner: variant == 3 ? f.peer : f.core.owner,
        reason: variant == 4 ? "" : "Software fixture",
        transition: variant == 5
          ? f.parent.body.fields.authorityTransitionID
          : (variant == 6 ? "invalid" : UUID().uuidString.lowercased()))
    }
    #expect(f.core.owner.signatures == f.ownerSignatures && f.core.owner.unwraps == 0)
    #expect(f.peer.signatures == f.peerSignatures && f.peer.unwraps == 0)
  }

  @Test func anotherActiveMemberCanAuthorizeTheExactRevocation() throws {
    let f = try Fixture()
    let plan = try f.plan(owner: f.peer)
    let candidate = try f.build(plan: plan, owner: f.peer)
    try f.validate(candidate, owner: f.peer)
    #expect(
      candidate.envelope.authorizations.map(\.signerDeviceID) == [f.peer.publicIdentity.deviceID])
    #expect(f.peer.signatures == f.peerSignatures + 1)
  }

  @Test(arguments: 0..<3)
  func independentValidationRequiresExactReviewedRosterAndRecoveryGeneration(variant: Int) throws {
    let f = try Fixture()
    let plan = try f.plan()
    let candidate: V3RecoveryDeviceRevocationCandidate
    if variant == 0 {
      let other = try f.build(plan: f.plan(target: f.peer))
      candidate = .init(plan: plan, envelope: other.envelope, stagedEntries: other.stagedEntries)
    } else {
      let values = try V3EntrySnapshotValidator(limits: .standard).plaintexts(
        fields: f.parent.body.fields, entries: f.entries, vaultKey: Self.currentKey)
      let material = try V3RecoveryEpochMaterialBuilder(limits: .standard).build(
        fields: f.parent.body.fields, plaintexts: values, nextVaultKey: Self.nextKey,
        authorityTransitionID: UUID().uuidString.lowercased(),
        devices: variant == 1 ? f.parent.body.fields.devices : plan.resultingDevices,
        generationID: variant == 2
          ? UUID().uuidString.lowercased() : f.parent.body.recovery.generationID,
        recipients: f.parent.body.recovery.recipients)
      let envelope = try V3RecoveryEpochBoundary().authorize(
        candidate: material.body, parent: f.parent, currentVaultKey: Self.currentKey,
        nextVaultKey: Self.nextKey, signer: f.core.owner, reason: "Owned roster-policy fixture")
      candidate = .init(plan: plan, envelope: envelope, stagedEntries: material.stagedEntries)
    }
    #expect(throws: V3RecoveryDeviceRevocationError.invalidCandidate) { try f.validate(candidate) }
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
    #expect(f.core.owner.signatures == f.ownerSignatures && f.core.owner.unwraps == 0)
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

  @Test(arguments: 0..<4)
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
      try V3RecoveryDeviceRevocationValidator().validateForPublication(
        .init(plan: candidate.plan, envelope: candidate.envelope, stagedEntries: staged),
        parent: f.parent, currentEntries: variant == 3 ? [:] : f.entries,
        currentVaultKey: Self.currentKey, nextVaultKey: Self.nextKey, identity: f.core.owner,
        reason: "Software fixture")
    }
    #expect(f.core.owner.unwraps == 0)
  }

  @Test(arguments: [false, true])
  func localWrapperVerificationIsSingleAddressedAndDoesNotRetry(cancel: Bool) throws {
    let f = try Fixture()
    let candidate = try f.build()
    f.core.owner.cancelUnwrap = cancel
    if cancel {
      #expect(throws: Core.FixtureError.cancelled) { try f.verifyLocalWrapper(candidate) }
    } else {
      try f.verifyLocalWrapper(candidate)
    }
    #expect(f.core.owner.unwraps == 1 && f.peer.unwraps == 0 && f.target.unwraps == 0)
  }

  @Test func cancelledSigningDoesNotProduceACandidateOrRetry() throws {
    let f = try Fixture()
    f.core.owner.cancelSigning = true
    #expect(throws: Core.FixtureError.cancelled) { try f.build() }
    #expect(f.core.owner.signatures == f.ownerSignatures + 1 && f.core.owner.unwraps == 0)
  }

  @Test(arguments: [false, true])
  func primaryAndBackupRecoverAfterEnrollmentRevocationAndOrdinarySave(backup: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let (anchors, tokens, digest) = try revocationChain(root)
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
    #expect(selected.head.digest == digest && calls.value == 1)
    #expect(snapshot.entries.first { $0.name == "fixture/secret" }?.plaintext == "after revocation")
    #expect(snapshot.entries.first { $0.name == "fixture/totp" }?.plaintext == "JBSWY3DPEHPK3PXP")
  }

  private func revocationChain(_ root: URL) throws -> (
    [V3RecoveryAnchor], [P256.KeyAgreement.PrivateKey], Data
  ) {
    let f = try V3RecoveryContentMutationPublisherTests.Fixture(root: root)
    let recipient = try #require(f.core.parent.body.recovery.recipients.first)
    let backupAnchor = try V3RecoveryAnchor(
      floor: .init(vaultID: Core.vaultID, envelopeDigest: f.core.parent.digest),
      recipientID: recipient.recipientID, registrationID: recipient.registrationID,
      slot: .keyManagement)
    let target = try Core.Owner()
    let state = try V3RecoveryDeviceEnrollmentTests().ceremony(
      parentDigest: f.parent.digest, owner: f.core.owner, joiner: target)
    let enrolled = try V3RecoveryDeviceEnrollmentBuilder().build(
      checkpoint: f.checkpoint, parent: f.parent, currentEntries: f.entries, state: state,
      currentVaultKey: Core.nextKey, nextVaultKey: Self.currentKey, owner: f.core.owner,
      at: Self.now, reason: "Software fixture")
    try f.seed(enrolled.envelope, entries: enrolled.stagedEntries)
    let checkpoint = try V3ManifestCheckpoint(
      vaultID: Core.vaultID, envelopeDigest: enrolled.envelope.digest)
    let entries = try V3EntrySnapshotValidator(limits: .standard).entryMap(enrolled.stagedEntries)
    let plan = try V3RecoveryDeviceRevocationPlanner().plan(
      checkpoint: checkpoint, parent: enrolled.envelope, currentVaultKey: Self.currentKey,
      authorizingDeviceID: f.core.owner.publicIdentity.deviceID,
      revoking: target.publicIdentity.deviceID)
    let revoked = try V3RecoveryDeviceRevocationBuilder().build(
      parent: enrolled.envelope, currentEntries: entries, plan: plan,
      currentVaultKey: Self.currentKey,
      nextVaultKey: Self.nextKey, owner: f.core.owner, reason: "Software fixture")
    try f.seed(revoked.envelope, entries: revoked.stagedEntries)
    // Materialized setup only, not lifecycle publication, resume or catch-up.
    let finalCheckpoint = try V3ManifestCheckpoint(
      vaultID: Core.vaultID, envelopeDigest: revoked.envelope.digest)
    f.checkpoints.value = finalCheckpoint.canonicalBytes
    try f.cache.store(revoked.envelope.canonicalBytes, for: finalCheckpoint)
    let session = V3DeviceWrappedVaultKeySessionStore()
    try session.install(
      Self.nextKey, vaultID: Core.vaultID, keyID: revoked.envelope.body.fields.keyID)
    let owner = VaultTransactionMutationOwner()
    let service = V3RecoveryVaultMutationService(
      vaultID: Core.vaultID, session: session, objectStore: f.store, checkpointStore: f.checkpoints,
      recoveryAnchorStore: f.ownership, registrationAnchorStore: f.registration,
      adoptionAnchorStore: f.adoption, cache: f.cache)
    try owner.perform(.editEntry) { context in
      try service.edit(
        name: "fixture/secret", secret: "after revocation", type: .secret,
        operationID: context.operationID)
    }
    session.invalidate()
    for entry in Array(f.core.entries.values) + Array(f.entries.values) + enrolled.stagedEntries {
      try FileManager.default.removeItem(at: f.entryURL(entry))
    }
    let last = try V3ManifestCheckpoint(canonicalBytes: #require(f.checkpoints.value))
    return ([f.anchor, backupAnchor], [f.core.token, f.core.backupToken], last.envelopeDigest)
  }

  private struct Fixture {
    let core: Core.Fixture
    let target: Core.Owner
    let peer: Core.Owner
    let retired: Core.Owner
    let parent: V3RecoveryManifestEnvelope
    let checkpoint: V3ManifestCheckpoint
    let entries: [V3EntryObjectKey: V3EncryptedEntry]
    let ownerSignatures: Int
    let peerSignatures: Int
    init(empty: Bool = false, backup: Bool = true) throws {
      core = try Core.Fixture(empty: empty, backup: backup)
      target = try Core.Owner()
      peer = try Core.Owner()
      retired = try Core.Owner()
      let old = core.parent.body
      let fields = try V3DeviceWrappedManifestFields(
        vaultID: old.fields.vaultID, keyID: old.fields.keyID,
        authorityTransitionID: old.fields.authorityTransitionID,
        devices: (old.fields.devices + [.init(identity: retired.publicIdentity, status: .revoked)])
          .sorted { $0.identity.deviceID < $1.identity.deviceID },
        wrappedKeys: old.fields.wrappedKeys, entries: old.fields.entries)
      var current = try V3RecoveryEpochBoundary().encode(
        body: .init(
          fields: fields, epochSigningKey: old.epochSigningKey, transitionProof: nil,
          recovery: old.recovery),
        parents: [], vaultKey: Core.oldKey, authorizations: [])
      var currentEntries = core.entries
      var key = Core.oldKey
      for (joining, next) in [
        (target, Core.nextKey), (peer, V3RecoveryDeviceRevocationTests.currentKey),
      ] {
        let checkpoint = try V3ManifestCheckpoint(
          vaultID: Core.vaultID, envelopeDigest: current.digest)
        let state = try V3RecoveryDeviceEnrollmentTests().ceremony(
          parentDigest: current.digest, owner: core.owner, joiner: joining)
        let enrolled = try V3RecoveryDeviceEnrollmentBuilder().build(
          checkpoint: checkpoint, parent: current, currentEntries: currentEntries, state: state,
          currentVaultKey: key, nextVaultKey: next, owner: core.owner,
          at: V3RecoveryDeviceRevocationTests.now, reason: "Software fixture")
        current = enrolled.envelope
        currentEntries = try V3EntrySnapshotValidator(limits: .standard).entryMap(
          enrolled.stagedEntries)
        key = next
      }
      parent = current
      entries = currentEntries
      checkpoint = try V3ManifestCheckpoint(vaultID: Core.vaultID, envelopeDigest: current.digest)
      ownerSignatures = core.owner.signatures
      peerSignatures = peer.signatures
    }
    func plan(owner: Core.Owner? = nil, target: Core.Owner? = nil) throws
      -> V3DeviceWrappedRevocationPlan
    {
      try V3RecoveryDeviceRevocationPlanner().plan(
        checkpoint: checkpoint, parent: parent,
        currentVaultKey: V3RecoveryDeviceRevocationTests.currentKey,
        authorizingDeviceID: (owner ?? core.owner).publicIdentity.deviceID,
        revoking: (target ?? self.target).publicIdentity.deviceID)
    }
    func build(
      plan: V3DeviceWrappedRevocationPlan? = nil,
      currentKey: Data = V3RecoveryDeviceRevocationTests.currentKey,
      nextKey: Data = V3RecoveryDeviceRevocationTests.nextKey, owner: Core.Owner? = nil,
      reason: String = "Software revocation fixture",
      transition: String = UUID().uuidString.lowercased(),
      limits: V3ManifestRepositoryLimits = .standard
    ) throws -> V3RecoveryDeviceRevocationCandidate {
      try V3RecoveryDeviceRevocationBuilder(limits: limits).build(
        parent: parent, currentEntries: entries, plan: plan ?? self.plan(),
        currentVaultKey: currentKey,
        nextVaultKey: nextKey, owner: owner ?? core.owner, reason: reason,
        authorityTransitionID: transition)
    }
    func validate(_ candidate: V3RecoveryDeviceRevocationCandidate, owner: Core.Owner? = nil) throws
    {
      try V3RecoveryDeviceRevocationValidator().validate(
        candidate, parent: parent, currentEntries: entries,
        currentVaultKey: V3RecoveryDeviceRevocationTests.currentKey,
        nextVaultKey: V3RecoveryDeviceRevocationTests.nextKey,
        expectedOwner: (owner ?? core.owner).publicIdentity)
    }
    func verifyLocalWrapper(
      _ candidate: V3RecoveryDeviceRevocationCandidate,
      limits: V3ManifestRepositoryLimits = .standard
    ) throws {
      try V3RecoveryDeviceRevocationValidator(limits: limits).validateForPublication(
        candidate, parent: parent, currentEntries: entries,
        currentVaultKey: V3RecoveryDeviceRevocationTests.currentKey,
        nextVaultKey: V3RecoveryDeviceRevocationTests.nextKey, identity: core.owner,
        reason: "Software wrapper fixture")
    }
  }
}
