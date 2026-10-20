import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

/// Two independent local checkpoints/sessions, actual immutable publication and
/// software Mac identities. No vault, token, protected store or native UI is used.
struct V3RecoveryKeyTransitionCatchUpTests {
  typealias Core = V3RecoveryRegistrationTests
  typealias Publication = V3RecoveryContentMutationPublisherTests
  typealias Stop = Publication.Stop
  enum Action: CaseIterable, Sendable {
    case rotation, enrollment, revocation, removal, lastRemoval, addition
  }

  @Test(arguments: Action.allCases, [false, true])
  func independentMacAdvancesPublishedChangesAndCanSave(action: Action, empty: Bool) throws {
    let f = try Fixture(empty: empty, last: action == .lastRemoval)
    defer { f.disk.remove() }
    let transition = try f.publish(action)
    let signed = f.owner.signatures
    let unwraps = f.receiver.unwraps
    let next = try advance(f)
    #expect(next.envelope == transition && next.checkpoint != f.floor.checkpoint)
    #expect(f.local.value == next.checkpoint.canonicalBytes)
    #expect(f.disk.checkpoints.value == next.checkpoint.canonicalBytes)
    #expect(try f.session.load(vaultID: Core.vaultID, keyID: transition.body.fields.keyID) == f.key)
    #expect(f.receiver.unwraps == unwraps + 1 && f.owner.signatures == signed)
    try ordinary(f).add(
      name: "after/other-mac", secret: "saved by the continuing Mac", type: .secret,
      operationID: .init())
    let checkpoint = try V3ManifestCheckpoint(canonicalBytes: #require(f.local.value))
    #expect(
      checkpoint != next.checkpoint && f.disk.checkpoints.value == next.checkpoint.canonicalBytes)
    #expect(f.receiver.unwraps == unwraps + 1 && f.owner.signatures == signed)
    #expect(f.pending.allSatisfy { $0.value == nil })
  }

  @Test func mixedContentAndSeveralEpochsAdvanceOnlyVerifiedPrefixes() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    try f.edit("before first rotation")
    let first = try f.publish(.rotation)
    try f.edit("between rotations")
    let second = try f.publish(.rotation)
    try f.edit("after second rotation")
    let latest = f.parent
    let before = f.receiver.unwraps
    let a = try advance(f)
    #expect(a.envelope == first && f.local.value != f.disk.checkpoints.value)
    let b = try advance(f, from: a)
    #expect(b.envelope == second && f.local.value != f.disk.checkpoints.value)
    #expect(f.receiver.unwraps == before + 2)
    guard case .noKeyTransition = try service(f).advanceOneEpoch(from: b) else {
      throw Stop.interrupted
    }
    // Content coordination is explicit and uses the same installed epoch key.
    let key = try f.session.load(vaultID: Core.vaultID, keyID: b.envelope.body.fields.keyID)
    let outcome = try V3RecoverySameEpochCatchUpService(
      mutationOwner: VaultTransactionMutationOwner(), source: f.disk.store,
      checkpointStore: f.local, recoveryAnchorStore: f.pending[0],
      registrationAnchorStore: f.pending[1], adoptionAnchorStore: f.pending[2], cache: f.localCache
    ).catchUp(from: b, vaultKey: key)
    guard case .current(let current, _) = outcome else { throw Stop.interrupted }
    #expect(current.envelope == latest && f.local.value == f.disk.checkpoints.value)
    #expect(f.receiver.unwraps == before + 2)
  }

  @Test func noEpochDoesNotOpenAWrapperOrClaimContentCatchUp() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    try f.edit("same epoch only")
    guard case .noKeyTransition = try service(f).advanceOneEpoch(from: f.floor) else {
      throw Stop.interrupted
    }
    #expect(f.receiver.unwraps == 0 && f.local.value == f.floor.checkpoint.canonicalBytes)
    #expect(f.session.hasResidentKey && f.local.value != f.disk.checkpoints.value)
    f.session.invalidate()
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
      try service(f).advanceOneEpoch(from: f.floor)
    }
    #expect(f.receiver.unwraps == 0)
  }

  @Test(arguments: [false, true])
  func removedMacRefusesBeforePrivateWorkEvenWhenRemovalIsInALaterEpoch(later: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    if later { _ = try f.publish(.rotation) }
    _ = try f.revoke(f.receiver)
    #expect(throws: V3RecoveryKeyTransitionCatchUpError.deviceRevoked) {
      try service(f).advanceOneEpoch(from: f.floor)
    }
    #expect(f.receiver.unwraps == 0 && !f.session.hasResidentKey)
    #expect(f.local.value == f.floor.checkpoint.canonicalBytes)
  }

  @Test(arguments: 0..<3)
  func allPendingNamespacesBlockBeforePrivateWork(namespace: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    _ = try f.publish(.rotation)
    f.pending[namespace].value = Data([1])
    #expect(throws: V3RecoveryContentCatchUpError.localMutationPending) {
      try service(f).advanceOneEpoch(from: f.floor)
    }
    #expect(f.receiver.unwraps == 0 && !f.session.hasResidentKey)
    #expect(f.pending[namespace].value != nil && f.local.value == f.floor.checkpoint.canonicalBytes)
  }

  @Test func cancellationKeepsTrustAndHasNoAutomaticRetry() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let transition = try f.publish(.rotation)
    f.receiver.cancelUnwrap = true
    #expect(throws: Core.FixtureError.cancelled) {
      try service(f).advanceOneEpoch(from: f.floor)
    }
    #expect(f.receiver.unwraps == 1 && !f.session.hasResidentKey)
    #expect(f.local.value == f.floor.checkpoint.canonicalBytes)
    f.receiver.cancelUnwrap = false
    try f.unlock()
    #expect(try advance(f).envelope == transition && f.receiver.unwraps == 2)
  }

  @Test(arguments: [false, true])
  func lockAndSameOldKeyReauthenticationDuringWrapperCannotBeUndone(reinstall: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    _ = try f.publish(.rotation)
    f.receiver.onUnwrap = {
      f.session.invalidate()
      if reinstall { try f.unlock() }
    }
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
      try service(f).advanceOneEpoch(from: f.floor)
    }
    #expect(f.receiver.unwraps == 1 && !f.session.hasResidentKey)
    #expect(f.local.value == f.floor.checkpoint.canonicalBytes)
  }

  @Test func incorrectProviderResultCannotAdvanceOrRetainASession() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    _ = try f.publish(.rotation)
    #expect(throws: (any Error).self) {
      try service(f, identity: WrongResult(base: f.receiver)).advanceOneEpoch(from: f.floor)
    }
    #expect(f.receiver.unwraps == 1 && !f.session.hasResidentKey)
    #expect(f.local.value == f.floor.checkpoint.canonicalBytes)
  }

  @Test(arguments: 0..<4)
  func identityFloorAndResidentEpochMustBeExact(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    _ = try f.publish(.rotation)
    let other = try Core.Owner()
    if variant == 1 {
      let wrong = Data(repeating: 0xf0, count: 32)
      try f.session.install(
        wrong, vaultID: Core.vaultID, keyID: .derive(vaultKey: wrong, vaultID: Core.vaultID))
    }
    if variant == 2 { f.local.value = Data([1]) }
    let floor =
      variant == 3
      ? V3RecoveryContentCommit(checkpoint: f.disk.checkpoint, envelope: f.floor.envelope) : f.floor
    #expect(throws: (any Error).self) {
      try service(f, identity: variant == 0 ? other : nil).advanceOneEpoch(from: floor)
    }
    #expect(f.receiver.unwraps == 0 && other.unwraps == 0 && !f.session.hasResidentKey)
    #expect(f.local.value == (variant == 2 ? Data([1]) : f.floor.checkpoint.canonicalBytes))
  }

  @Test(arguments: [2, 3, 4], 0..<5)
  func changingStateAroundObservationAndCASCannotInstallStaleAuthority(read: Int, variant: Int)
    throws
  {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try f.publish(.rotation)
    let source = Source(f.disk.store) { count in
      if count == read {
        switch variant {
        case 0: f.pending[0].value = Data([1])
        case 1: f.pending[1].value = Data([1])
        case 2: f.pending[2].value = Data([1])
        case 3: f.local.value = Data([1])
        default: try f.branchFromFloor()
        }
      }
    }
    #expect(throws: (any Error).self) {
      try service(f, source: source).advanceOneEpoch(from: f.floor)
    }
    #expect(!f.session.hasResidentKey && f.receiver.unwraps == (read == 2 ? 0 : 1))
    if variant == 3 {
      #expect(f.local.value == Data([1]))
    } else {
      #expect(
        f.local.value
          == (read == 4 ? try cp(candidate).canonicalBytes : f.floor.checkpoint.canonicalBytes))
    }
  }

  @Test(arguments: 0..<3)
  func visibleContentAuthorityAndClosedEpochBranchesRefuseBeforePrivateWork(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    _ = try f.publish(.rotation)
    if variant == 0 {
      let parent = f.parent
      let checkpoint = try cp(parent)
      let entries = f.entries
      try f.edit("one new-epoch head")
      let branch = try V3RecoveryContentMutationBuilder().build(
        .edit(name: "fixture/secret", type: .secret, plaintext: "other new-epoch head"),
        checkpoint: checkpoint, parent: parent, currentEntries: entries, vaultKey: f.key)
      try f.disk.seed(branch.envelope, entries: branch.stagedEntries)
    } else if variant == 1 {
      let branch = try V3RecoveryKeyRotationBuilder().build(
        checkpoint: f.floor.checkpoint, parent: f.floor.envelope, currentEntries: f.initialEntries,
        currentVaultKey: f.initialKey, nextVaultKey: Data(repeating: 0xa1, count: 32),
        owner: f.owner, reason: "Owned competing rotation fixture")
      try f.disk.seed(branch.envelope, entries: branch.stagedEntries)
    } else {
      try f.branchFromFloor()
    }
    let error: V3RecoveryValidationError =
      variant == 0 ? .contentConflict : (variant == 1 ? .authorityConflict : .closedEpochBranch)
    #expect(throws: error) { try service(f).advanceOneEpoch(from: f.floor) }
    #expect(f.receiver.unwraps == 0 && f.local.value == f.floor.checkpoint.canonicalBytes)
  }

  @Test(arguments: 0..<3)
  func missingCurrentNextOrLaterCiphertextStopsBeforePrivateWork(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    _ = try f.publish(.rotation)
    var entry = try #require((variant == 0 ? f.initialEntries : f.entries).values.first)
    if variant == 2 {
      _ = try f.publish(.rotation)
      entry = try #require(f.entries.values.first)
    }
    try FileManager.default.removeItem(at: f.disk.entryURL(entry))
    #expect(throws: V3RecoveryValidationError.entryUnavailable) {
      try service(f).advanceOneEpoch(from: f.floor)
    }
    #expect(f.receiver.unwraps == 0 && !f.session.hasResidentKey)
    #expect(f.local.value == f.floor.checkpoint.canonicalBytes)
  }

  @Test(arguments: [false, true])
  func currentAndSelectedEpochMACsMustAuthenticateBeforeTrustChanges(descendant: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let transition = try f.publish(.rotation)
    if descendant { try f.edit("next-epoch descendant") }
    let original = descendant ? f.parent : transition
    let changed = try wrongMAC(original)
    try FileManager.default.removeItem(at: f.disk.manifestURL(original.digest))
    try f.disk.seed(changed, entries: [])
    #expect(throws: (any Error).self) { try service(f).advanceOneEpoch(from: f.floor) }
    #expect(f.receiver.unwraps == 1 && !f.session.hasResidentKey)
    #expect(f.local.value == f.floor.checkpoint.canonicalBytes)
  }

  @Test func fullPlaintextComparisonRejectsAnInconsistentOwnedSnapshotFixture() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    var plaintexts = try V3EntrySnapshotValidator(limits: .standard).plaintexts(
      fields: f.parent.body.fields, entries: f.entries, vaultKey: f.key)
    let record = try #require(f.parent.body.fields.entries.first { $0.type == .secret })
    plaintexts[record.entryID] = Data("inconsistent owned fixture".utf8)
    let nextKey = Data(repeating: 0xa2, count: 32)
    let material = try V3RecoveryEpochMaterialBuilder(limits: .standard).build(
      fields: f.parent.body.fields, plaintexts: plaintexts, nextVaultKey: nextKey,
      authorityTransitionID: UUID().uuidString.lowercased(), devices: f.parent.body.fields.devices,
      generationID: f.parent.body.recovery.generationID,
      recipients: f.parent.body.recovery.recipients)
    let candidate = try V3RecoveryEpochBoundary().authorize(
      candidate: material.body, parent: f.parent, currentVaultKey: f.key, nextVaultKey: nextKey,
      signer: f.owner, reason: "Owned inconsistent snapshot fixture")
    try f.disk.seed(candidate, entries: material.stagedEntries)
    #expect(throws: V3RecoveryKeyRotationError.invalidCandidate) {
      try service(f).advanceOneEpoch(from: f.floor)
    }
    #expect(f.receiver.unwraps == 1 && !f.session.hasResidentKey)
    #expect(f.local.value == f.floor.checkpoint.canonicalBytes)
  }

  @Test(arguments: 0..<5)
  func alteredPublicProofsAndUnsupportedRosterFixturesStopBeforePrivateWork(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    var floor = f.floor
    let candidate: V3RecoveryManifestEnvelope
    let staged: [V3EncryptedEntry]
    if variant < 2 {
      let original = try f.publish(.rotation)
      let proof = try #require(original.body.transitionProof)
      let authorization = try #require(original.authorizations.first)
      var altered =
        variant == 0
        ? try #require(Base64URL.decodeCanonical(authorization.signature))
        : proof.signature
      altered[0] ^= 1
      altered = try V3P256Signature.canonicalize(altered)
      let body = try V3RecoveryManifestBody(
        fields: original.body.fields, epochSigningKey: original.body.epochSigningKey,
        transitionProof: variant == 0
          ? proof : .init(parentEnvelopeDigest: proof.parentEnvelopeDigest, signature: altered),
        recovery: original.body.recovery)
      candidate = try V3RecoveryEpochBoundary().encode(
        body: body, parents: original.parents, vaultKey: f.key,
        authorizations: variant == 0
          ? [
            .init(
              signerDeviceID: f.owner.publicIdentity.deviceID, signature: Base64URL.encode(altered))
          ] : original.authorizations)
      staged = []
      try FileManager.default.removeItem(at: f.disk.manifestURL(original.digest))
    } else {
      if variant == 4 {
        _ = try f.publish(.revocation)
        floor = .init(checkpoint: try cp(f.parent), envelope: f.parent)
        f.local.value = floor.checkpoint.canonicalBytes
        try f.session.install(f.key, vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID)
      }
      let old = f.parent.body
      let devices = old.fields.devices.compactMap { device -> V3DeviceWrappedManifestDevice? in
        guard device.identity == f.target.publicIdentity else { return device }
        if variant == 3 { return nil }
        return .init(identity: device.identity, status: variant == 4 ? .active : .revoked)
      }
      let selected = try #require(old.recovery.recipients.first { $0.status == .active })
      let recipients = try old.recovery.recipients.map { recipient in
        variant == 2 && recipient.recipientID == selected.recipientID
          ? try V3RecoveryRecipient(
            registrationID: recipient.registrationID, publicKey: recipient.publicKey,
            slot: recipient.slot, status: .revoked) : recipient
      }
      let next = Data(repeating: 0xa3, count: 32)
      let plaintexts = try V3EntrySnapshotValidator(limits: .standard).plaintexts(
        fields: old.fields, entries: f.entries, vaultKey: f.key)
      let material = try V3RecoveryEpochMaterialBuilder(limits: .standard).build(
        fields: old.fields, plaintexts: plaintexts, nextVaultKey: next,
        authorityTransitionID: UUID().uuidString.lowercased(), devices: devices,
        generationID: variant == 2 ? UUID().uuidString.lowercased() : old.recovery.generationID,
        recipients: recipients)
      candidate = try V3RecoveryEpochBoundary().authorize(
        candidate: material.body, parent: f.parent, currentVaultKey: f.key, nextVaultKey: next,
        signer: f.owner, reason: "Owned unsupported roster fixture")
      staged = material.stagedEntries
    }
    try f.disk.seed(candidate, entries: staged)
    #expect(throws: (any Error).self) { try service(f).advanceOneEpoch(from: floor) }
    #expect(f.receiver.unwraps == 0 && !f.session.hasResidentKey)
    #expect(f.local.value == floor.checkpoint.canonicalBytes)
  }

  @Test func obsoleteCommittedSnapshotsAreNotReopenedWhileForwardSnapshotsRemainRequired() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    try f.edit("committed prefix")
    let laterFloor = V3RecoveryContentCommit(checkpoint: try cp(f.parent), envelope: f.parent)
    f.local.value = laterFloor.checkpoint.canonicalBytes
    let obsolete = try #require(f.initialEntries.values.first { $0.context.type == .secret })
    try FileManager.default.removeItem(at: f.disk.entryURL(obsolete))
    let transition = try f.publish(.rotation)
    #expect(try advance(f, from: laterFloor).envelope == transition)
    #expect(f.receiver.unwraps == 1)
  }

  @Test func checkpointLinkedLateBranchJoinCanPrecedeTheNextEpochWithoutOldCiphertext() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    try f.edit("committed prefix")
    let laterFloor = V3RecoveryContentCommit(checkpoint: try cp(f.parent), envelope: f.parent)
    f.local.value = laterFloor.checkpoint.canonicalBytes
    let branch = try V3RecoveryContentMutationBuilder().build(
      .edit(name: "fixture/secret", type: .secret, plaintext: "late same-epoch sibling"),
      checkpoint: f.floor.checkpoint, parent: f.floor.envelope, currentEntries: f.initialEntries,
      vaultKey: f.initialKey)
    try f.disk.seed(branch.envelope, entries: branch.stagedEntries)
    let obsolete = try #require(f.initialEntries.values.first { $0.context.type == .secret })
    try FileManager.default.removeItem(at: f.disk.entryURL(obsolete))
    let observed = try V3RecoverySameEpochRepositoryObserver(source: f.disk.store).observe(
      from: laterFloor, vaultKey: f.key)
    guard case .contentConflict(let report) = try V3RecoveryManifestReconciler().reconcile(observed)
    else { throw Stop.interrupted }
    let snapshot = V3ConflictObservationBuilder().build(
      report, entries: .lastTrusted(laterFloor.envelope.body.fields.entries.count),
      trustedVersionID: nil, trustedHeadDigest: laterFloor.checkpoint.envelopeDigest,
      trustedEntries: Set(laterFloor.envelope.body.fields.entries))
    let resolutions = try snapshot.conflicts.map { detail in
      VaultConflictResolution(
        conflictID: detail.summary.id,
        versionID: try #require(
          detail.versions.first {
            v3LowercaseHex(laterFloor.envelope.digest).hasPrefix($0.id)
          }
        ).id)
    }
    let merge = try V3RecoveryMergeMutationBuilder().buildResolution(
      resolutions, from: observed, vaultKey: f.key)
    f.parent = try V3RecoveryMergeMutationPublisher(
      mutationOwner: VaultTransactionMutationOwner(), objectStore: f.disk.store,
      checkpointStore: f.disk.checkpoints, recoveryAnchorStore: f.disk.ownership,
      registrationAnchorStore: f.disk.registration, adoptionAnchorStore: f.disk.adoption,
      cache: f.disk.cache
    ).publish(merge, vaultKey: f.key).envelope
    f.entries = try f.loadEntries(f.parent)
    let transition = try f.publish(.rotation)
    #expect(try advance(f, from: laterFloor).envelope == transition)
    #expect(f.receiver.unwraps == 1)
  }

  @Test(arguments: Action.allCases)
  func softwareRecoveryFollowsOtherMacSavingWithoutMacPrivateState(action: Action) throws {
    guard #available(macOS 26.0, *) else { return }
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let (anchor, token, head) = try savedRecoveryChain(root: root, action: action)
    let store = V3FilesystemTransactionArtifactStore(
      rootHandle: try VaultRootDirectoryHandle(opening: root))
    if action == .lastRemoval {
      #expect(throws: V3RecoveryValidationError.recipientRevoked) {
        try V3RecoveryHistorySelector(source: store).select(
          anchor: anchor, credentialPublicKey: token.publicKey.x963Representation)
      }
      return
    }
    let selected = try V3RecoveryHistorySelector(source: store).select(
      anchor: anchor, credentialPublicKey: token.publicKey.x963Representation)
    let calls = Core.Counter()
    let receiver = try PIVHPKEReceiver(publicBytes: token.publicKey.x963Representation) { peer in
      calls.increment()
      return try token.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: peer)
      ).withUnsafeBytes { Data($0) }
    }
    let opened = try V3RecoverySnapshotVerifier(source: store).open(
      selected, boundAnchor: anchor, receiver: receiver)
    #expect(calls.value == 1 && selected.head.digest == head)
    #expect(
      opened.entries.first { $0.name == "after/other-mac" }?.plaintext == "survives both Macs")
  }

  @available(macOS 26.0, *)
  private func savedRecoveryChain(root: URL, action: Action) throws
    -> (V3RecoveryAnchor, P256.KeyAgreement.PrivateKey, Data)
  {
    let f = try Fixture(root: root, last: action == .lastRemoval)
    _ = try f.publish(action)
    _ = try advance(f)
    try ordinary(f).add(
      name: "after/other-mac", secret: "survives both Macs", type: .secret,
      operationID: .init())
    f.session.invalidate()
    let head = try V3ManifestCheckpoint(canonicalBytes: #require(f.local.value)).envelopeDigest
    if action == .removal {
      let recipient = try #require(f.disk.core.parent.body.recovery.recipients.first)
      let anchor = try V3RecoveryAnchor(
        floor: .init(vaultID: Core.vaultID, envelopeDigest: f.disk.core.parent.digest),
        recipientID: recipient.recipientID, registrationID: recipient.registrationID,
        slot: .keyManagement)
      return (anchor, f.disk.core.backupToken, head)
    }
    return (f.disk.anchor, f.disk.core.token, head)
  }

  @Test(arguments: 0..<8)
  func wholeHistoryAndCiphertextLimitsRefuseBeforePrivateWork(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    _ = try f.publish(.rotation)
    let observed = try V3RecoveryKeyTransitionRepositoryObserver(
      source: f.disk.store, limits: .standard, maximumParentEdges: 16_384
    ).observe(from: f.floor, vaultKey: f.initialKey)
    let maximumManifestBytes = try #require(observed.manifestBytes.values.map(\.count).max())
    let limits = [
      V3ManifestRepositoryLimits(maximumManifestObjects: 1, maximumHistoryDepth: 100),
      V3ManifestRepositoryLimits(maximumManifestObjects: 100, maximumHistoryDepth: 0),
      Core.Fixture.limits(manifestBytes: 1), Core.Fixture.limits(entryBytes: 1),
      Core.Fixture.limits(entries: 3), Core.Fixture.limits(totalBytes: 1),
      V3ManifestRepositoryLimits(
        maximumManifestObjects: 100, maximumHistoryDepth: 100,
        maximumManifestBytes: maximumManifestBytes, maximumTotalManifestBytes: maximumManifestBytes),
      V3ManifestRepositoryLimits.standard,
    ][variant]
    #expect(throws: (any Error).self) {
      try service(f, limits: limits, maximumParentEdges: variant == 7 ? 1 : 16_384)
        .advanceOneEpoch(from: f.floor)
    }
    #expect(f.receiver.unwraps == 0 && f.local.value == f.floor.checkpoint.canonicalBytes)
  }

  @Test(arguments: 0..<4)
  func malformedInventoriesCannotHideCompetingWork(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    _ = try f.publish(.rotation)
    let source = Source(f.disk.store)
    source.listing =
      variant == 0
      ? .available(digests: [f.parent.digest, f.parent.digest], objectCount: 2)
      : (variant == 1
        ? .available(digests: [f.parent.digest], objectCount: 0)
        : (variant == 2
          ? .available(digests: [Data(repeating: 0, count: 31)], objectCount: 1) : .unavailable))
    #expect(throws: (any Error).self) {
      try service(f, source: source).advanceOneEpoch(from: f.floor)
    }
    #expect(f.receiver.unwraps == 0 && f.local.value == f.floor.checkpoint.canonicalBytes)
  }

  @Test(arguments: [false, true])
  func failedCASPreservesOldOrWinningTrustAndLocks(winner: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    _ = try f.publish(.rotation)
    let checkpoints = Checkpoints(
      base: f.local,
      before: {
        if winner { f.local.value = Data([1]) } else { f.local.rejectAdvance = true }
      })
    #expect(throws: (any Error).self) {
      try service(f, checkpoints: checkpoints).advanceOneEpoch(from: f.floor)
    }
    #expect(!f.session.hasResidentKey && f.receiver.unwraps == 1)
    #expect(f.local.value == (winner ? Data([1]) : f.floor.checkpoint.canonicalBytes))
  }

  @Test(arguments: 0..<6)
  func postCommitFailureNeverRollsBackOrInstallsAStaleSession(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try f.publish(.rotation)
    let checkpoints = Checkpoints(
      base: f.local,
      after: {
        switch variant {
        case 0: f.session.invalidate()
        case 1:
          f.session.invalidate()
          try f.unlock()
        case 2: f.pending[1].value = Data([1])
        case 3: f.pending[2].value = Data([1])
        case 4: f.local.value = Data([1])
        default:
          try FileManager.default.removeItem(
            at: f.disk.entryURL(try #require(f.entries.values.first)))
        }
      })
    #expect(throws: (any Error).self) {
      try service(f, checkpoints: checkpoints).advanceOneEpoch(from: f.floor)
    }
    #expect(!f.session.hasResidentKey && f.receiver.unwraps == 1)
    #expect(f.local.value == (variant == 4 ? Data([1]) : try cp(candidate).canonicalBytes))
  }

  @Test func cacheFailureDoesNotUndoAnAuthenticatedAdvance() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let candidate = try f.publish(.rotation)
    #expect(try advance(f, cache: FailingCache()).envelope == candidate)
    #expect(f.session.hasResidentKey && f.receiver.unwraps == 1)
  }

  @Test func concurrentStaleRequestsShareSerializationWithoutAnExtraWrapper() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    _ = try f.publish(.rotation)
    let owner = VaultTransactionMutationOwner()
    let successes = Core.Counter()
    let failures = Core.Counter()
    DispatchQueue.concurrentPerform(iterations: 2) { _ in
      do {
        guard case .advancedOneEpoch = try service(f, owner: owner).advanceOneEpoch(from: f.floor)
        else { throw Stop.interrupted }
        successes.increment()
      } catch {
        failures.increment()
      }
    }
    #expect(successes.value == 1 && failures.value == 1 && f.receiver.unwraps == 1)
    #expect(f.local.value == f.disk.checkpoints.value && !f.session.hasResidentKey)
    #expect(f.pending.allSatisfy { $0.value == nil })
  }

  final class Fixture: @unchecked Sendable {
    let disk: Publication.Fixture
    let receiver: Core.Owner
    let target: Core.Owner
    let local: Publication.Checkpoints
    let pending = [Publication.Ownership(), Publication.Ownership(), Publication.Ownership()]
    let session = V3DeviceWrappedVaultKeySessionStore()
    let localCache: V3CheckpointManifestFilesystemCache
    let floor: V3RecoveryContentCommit
    let initialEntries: [V3EntryObjectKey: V3EncryptedEntry]
    let initialKey: Data
    var parent: V3RecoveryManifestEnvelope
    var entries: [V3EntryObjectKey: V3EncryptedEntry]
    var key: Data
    var owner: Core.Owner { disk.core.owner }
    init(root: URL? = nil, empty: Bool = false, last: Bool = false) throws {
      disk = try Publication.Fixture(root: root, empty: empty, backup: !last)
      receiver = try Core.Owner()
      target = try Core.Owner()
      var current = disk.parent
      var currentEntries = disk.entries
      var currentKey = Core.nextKey
      for joining in [receiver, target] {
        let state = try V3RecoveryDeviceEnrollmentTests().ceremony(
          parentDigest: current.digest, owner: disk.core.owner, joiner: joining)
        let next = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        let candidate = try V3RecoveryDeviceEnrollmentBuilder().build(
          checkpoint: .init(vaultID: Core.vaultID, envelopeDigest: current.digest),
          parent: current, currentEntries: currentEntries, state: state,
          currentVaultKey: currentKey, nextVaultKey: next, owner: disk.core.owner,
          at: 4_102_444_800, reason: "Owned two-Mac fixture enrollment")
        let commit = try V3RecoveryDeviceEnrollmentPublisher(
          mutationOwner: VaultTransactionMutationOwner(), objectStore: disk.store,
          checkpointStore: disk.checkpoints, recoveryAnchorStore: disk.ownership,
          registrationAnchorStore: disk.registration, adoptionAnchorStore: disk.adoption,
          ceremonyStore: V3RecoveryDeviceEnrollmentPublisherTests.StateStore(state.canonicalBytes),
          cache: disk.cache
        ).publish(
          candidate, state: state, approvedTranscriptDigest: candidate.transcriptDigest,
          currentVaultKey: currentKey, nextVaultKey: next, identity: disk.core.owner,
          at: 4_102_444_800, reason: "Owned two-Mac fixture opening")
        current = commit.envelope
        currentEntries = try V3EntrySnapshotValidator(limits: .standard).entryMap(
          candidate.stagedEntries)
        currentKey = next
      }
      parent = current
      entries = currentEntries
      key = currentKey
      floor = .init(
        checkpoint: try .init(vaultID: Core.vaultID, envelopeDigest: current.digest),
        envelope: current)
      initialEntries = currentEntries
      initialKey = currentKey
      local = Publication.Checkpoints(floor.checkpoint.canonicalBytes)
      let cacheRoot = disk.root.appendingPathComponent("other-mac-cache")
      try FileManager.default.createDirectory(at: cacheRoot, withIntermediateDirectories: true)
      localCache = .init(rootHandle: try VaultRootDirectoryHandle(opening: cacheRoot))
      try localCache.store(current.canonicalBytes, for: floor.checkpoint)
      try unlock()
    }
    func unlock() throws {
      try session.install(
        initialKey, vaultID: Core.vaultID, keyID: floor.envelope.body.fields.keyID)
    }
    func ownerSession() throws -> V3DeviceWrappedVaultKeySessionStore {
      let result = V3DeviceWrappedVaultKeySessionStore()
      try result.install(key, vaultID: Core.vaultID, keyID: parent.body.fields.keyID)
      return result
    }
    func publish(_ action: Action) throws -> V3RecoveryManifestEnvelope {
      let before = parent
      let next = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
      switch action {
      case .rotation:
        let session = try ownerSession()
        parent = try V3RecoveryKeyRotationService(
          vaultID: Core.vaultID, identity: owner, session: session, objectStore: disk.store,
          checkpointStore: disk.checkpoints, recoveryAnchorStore: disk.ownership,
          registrationAnchorStore: disk.registration, adoptionAnchorStore: disk.adoption,
          cache: disk.cache
        ).rotate(expectedCheckpoint: cp(), operationID: .init()).envelope
        key = try session.load(vaultID: Core.vaultID, keyID: parent.body.fields.keyID)
      case .revocation: return try revoke(target)
      case .removal, .lastRemoval:
        let session = try ownerSession()
        let service = V3RecoveryAuthorityChangeService(
          vaultID: Core.vaultID, identity: owner, session: session, objectStore: disk.store,
          checkpointStore: disk.checkpoints, recoveryAnchorStore: disk.ownership,
          registrationAnchorStore: disk.registration, adoptionAnchorStore: disk.adoption,
          cache: disk.cache)
        let plan = try service.prepareRemoval(removing: disk.anchor.recipientID)
        parent = try service.remove(
          plan, operationID: .init(),
          protectionLossAcknowledgement: plan.removesLastActiveRecipient ? .init(plan: plan) : nil
        ).envelope
        key = try session.load(vaultID: Core.vaultID, keyID: parent.body.fields.keyID)
      case .enrollment:
        let state = try V3RecoveryDeviceEnrollmentTests().ceremony(
          parentDigest: parent.digest, owner: owner, joiner: Core.Owner())
        let candidate = try V3RecoveryDeviceEnrollmentBuilder().build(
          checkpoint: cp(), parent: parent, currentEntries: entries, state: state,
          currentVaultKey: key, nextVaultKey: next, owner: owner, at: 4_102_444_800,
          reason: "Owned additional Mac fixture")
        parent = try V3RecoveryDeviceEnrollmentPublisher(
          mutationOwner: VaultTransactionMutationOwner(), objectStore: disk.store,
          checkpointStore: disk.checkpoints, recoveryAnchorStore: disk.ownership,
          registrationAnchorStore: disk.registration, adoptionAnchorStore: disk.adoption,
          ceremonyStore: V3RecoveryDeviceEnrollmentPublisherTests.StateStore(state.canonicalBytes),
          cache: disk.cache
        ).publish(
          candidate, state: state, approvedTranscriptDigest: candidate.transcriptDigest,
          currentVaultKey: key, nextVaultKey: next, identity: owner, at: 4_102_444_800,
          reason: "Owned additional Mac opening"
        ).envelope
        key = next
      case .addition:
        // Recipient addition bytes are constructed by the real domain builder;
        // materialization here is not another possession/registration ceremony.
        let candidate = try V3RecoveryRegistrationBuilder().prepare(
          checkpoint: cp(), parent: parent, currentEntries: entries,
          currentVaultKey: key, nextVaultKey: next,
          credential: Core.Fixture().credential, occupancy: .absent, owner: owner,
          reason: "Owned recipient addition fixture", operationID: .init())
        try disk.seed(candidate.candidate, entries: candidate.stagedEntries)
        parent = candidate.candidate
        disk.checkpoints.value = try cp().canonicalBytes
        key = next
      }
      #expect(parent.parents == [before.digest])
      entries = try loadEntries(parent)
      return parent
    }
    func revoke(_ removed: Core.Owner) throws -> V3RecoveryManifestEnvelope {
      let session = try ownerSession()
      let service = V3RecoveryAuthorityChangeService(
        vaultID: Core.vaultID, identity: owner, session: session, objectStore: disk.store,
        checkpointStore: disk.checkpoints, recoveryAnchorStore: disk.ownership,
        registrationAnchorStore: disk.registration, adoptionAnchorStore: disk.adoption,
        cache: disk.cache)
      parent = try service.revoke(
        service.prepareRevocation(revoking: removed.publicIdentity.deviceID),
        operationID: .init()
      ).envelope
      key = try session.load(vaultID: Core.vaultID, keyID: parent.body.fields.keyID)
      entries = try loadEntries(parent)
      return parent
    }
    func edit(_ value: String) throws {
      let candidate = try V3RecoveryContentMutationBuilder().build(
        .edit(name: "fixture/secret", type: .secret, plaintext: value),
        checkpoint: cp(), parent: parent, currentEntries: entries, vaultKey: key)
      parent = try disk.publisher().publish(candidate, vaultKey: key).envelope
      entries = try loadEntries(parent)
    }
    func branchFromFloor() throws {
      let branch = try V3RecoveryContentMutationBuilder().build(
        .edit(name: "fixture/secret", type: .secret, plaintext: "late old-epoch branch"),
        checkpoint: floor.checkpoint, parent: floor.envelope, currentEntries: initialEntries,
        vaultKey: initialKey)
      try disk.seed(branch.envelope, entries: branch.stagedEntries)
    }
    func cp() throws -> V3ManifestCheckpoint {
      try .init(vaultID: Core.vaultID, envelopeDigest: parent.digest)
    }
    func loadEntries(_ envelope: V3RecoveryManifestEnvelope) throws -> [V3EntryObjectKey:
      V3EncryptedEntry]
    {
      var result: [V3EntryObjectKey: V3EncryptedEntry] = [:]
      for record in envelope.body.fields.entries {
        let address = try V3RecoveryMergeMutationValidator.address(record)
        guard
          case .available(let data) = try disk.store.readEntry(
            entryID: address.entryID, digest: address.digest, maximumBytes: 1_048_576)
        else { throw Stop.interrupted }
        result[address] = try V3EntryCipher().parse(data)
      }
      return result
    }
  }

  private func cp(_ envelope: V3RecoveryManifestEnvelope) throws -> V3ManifestCheckpoint {
    try .init(vaultID: Core.vaultID, envelopeDigest: envelope.digest)
  }
  private func service(
    _ f: Fixture, identity: (any V3DeviceWrappedVaultKeyUnwrapping)? = nil,
    source: (any V3ImmutableObjectReading)? = nil,
    checkpoints: (any V3ManifestCheckpointStoring)? = nil,
    cache: (any V3CheckpointManifestCaching)? = nil,
    owner: (any VaultTransactionMutationOwning)? = nil,
    limits: V3ManifestRepositoryLimits = .standard, maximumParentEdges: Int = 16_384
  ) -> V3RecoveryKeyTransitionCatchUpService {
    .init(
      mutationOwner: owner ?? VaultTransactionMutationOwner(), identity: identity ?? f.receiver,
      session: f.session, source: source ?? f.disk.store, checkpointStore: checkpoints ?? f.local,
      recoveryAnchorStore: f.pending[0], registrationAnchorStore: f.pending[1],
      adoptionAnchorStore: f.pending[2],
      cache: cache ?? f.localCache, limits: limits, maximumParentEdges: maximumParentEdges)
  }
  private func advance(
    _ f: Fixture, from floor: V3RecoveryContentCommit? = nil,
    cache: (any V3CheckpointManifestCaching)? = nil,
    owner: (any VaultTransactionMutationOwning)? = nil
  ) throws -> V3RecoveryContentCommit {
    guard
      case .advancedOneEpoch(let next) = try service(f, cache: cache, owner: owner)
        .advanceOneEpoch(from: floor ?? f.floor)
    else { throw Stop.interrupted }
    return next
  }
  private func ordinary(_ f: Fixture) -> V3RecoveryVaultMutationService {
    .init(
      vaultID: Core.vaultID, session: f.session, objectStore: f.disk.store,
      checkpointStore: f.local,
      recoveryAnchorStore: f.pending[0], registrationAnchorStore: f.pending[1],
      adoptionAnchorStore: f.pending[2],
      cache: f.localCache)
  }
  private func wrongMAC(_ envelope: V3RecoveryManifestEnvelope) throws -> V3RecoveryManifestEnvelope
  {
    let fields = try #require(CanonicalJSON.parse(envelope.canonicalBytes).objectValue)
    let bytes = CanonicalJSON.encode(
      .object(
        fields.map {
          $0.0 == "authentication"
            ? (
              "authentication",
              .object([
                ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
                ("tag", .string(Base64URL.encode(Data(repeating: 0xee, count: 32)))),
              ])
            ) : $0
        }))
    return try V3RecoveryManifestCodec().parseEnvelope(bytes)
  }
  private struct WrongResult: V3DeviceWrappedVaultKeyUnwrapping {
    let base: Core.Owner
    var vaultID: String { base.vaultID }
    var publicIdentity: V3EnrollmentDeviceIdentity { base.publicIdentity }
    func unwrapDeviceWrappedVaultKey(
      _ key: V3HPKEWrappedVaultKey, context: V3VaultKeyHPKEContext, reason: String
    ) throws -> Data {
      _ = try base.unwrapDeviceWrappedVaultKey(key, context: context, reason: reason)
      return Data(repeating: 0xee, count: 32)
    }
  }
  private final class Source: V3ImmutableObjectReading, @unchecked Sendable {
    let base: any V3ImmutableObjectReading
    let calls = Core.Counter()
    let action: @Sendable (Int) throws -> Void
    var listing: V3RepositoryDirectoryListing?
    init(
      _ base: any V3ImmutableObjectReading,
      action: @escaping @Sendable (Int) throws -> Void = { _ in }
    ) {
      self.base = base
      self.action = action
    }
    func manifestDigests(maximumCount: Int) throws -> V3RepositoryDirectoryListing {
      calls.increment()
      try action(calls.value)
      return try listing ?? base.manifestDigests(maximumCount: maximumCount)
    }
    func readManifest(digest: Data, maximumBytes: Int) throws -> V3RepositoryObjectRead {
      try base.readManifest(digest: digest, maximumBytes: maximumBytes)
    }
    func readEntry(entryID: String, digest: Data, maximumBytes: Int) throws
      -> V3RepositoryObjectRead
    {
      try base.readEntry(entryID: entryID, digest: digest, maximumBytes: maximumBytes)
    }
  }
  private struct Checkpoints: V3ManifestCheckpointStoring {
    let base: Publication.Checkpoints
    var before: @Sendable () throws -> Void = {}
    var after: @Sendable () throws -> Void = {}
    func loadCheckpoint(vaultID: String) throws -> Data? {
      try base.loadCheckpoint(vaultID: vaultID)
    }
    func replaceCheckpoint(_ checkpoint: Data, expectedCheckpoint: Data?, vaultID: String) throws {
      try before()
      try base.replaceCheckpoint(
        checkpoint, expectedCheckpoint: expectedCheckpoint, vaultID: vaultID)
      try after()
    }
  }
  private struct FailingCache: V3CheckpointManifestCaching {
    func load(for _: V3ManifestCheckpoint) throws -> V3CheckpointManifestCacheLookup { .missing }
    func store(_: Data, for _: V3ManifestCheckpoint) throws { throw Stop.interrupted }
  }
}
