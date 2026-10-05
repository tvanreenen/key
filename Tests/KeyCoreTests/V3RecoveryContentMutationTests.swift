import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

/// Real profile/entry crypto and recovery verification; token agreement uses
/// a software key. Filesystem materialization is test setup, not a production
/// content publisher, crash-reconciliation path or enabled product workflow.
struct V3RecoveryContentMutationTests {
  private typealias Core = V3RecoveryRegistrationTests
  private static let newID = "018f4d38-7d5a-7b20-b0f1-97d6e96c84c1"
  private static let copyID = "018f4d38-7d5a-7b20-b0f1-97d6e96c84c2"

  @Test(arguments: 0..<5)
  func everyEditPreservesAuthorityAndCoverageWithoutPrivateDeviceOrTokenCalls(operation: Int) throws
  {
    let f = try Fixture()
    let candidate = try f.build(try f.request(operation))
    let complete = try f.validate(candidate)
    let a = candidate.envelope.body
    let b = f.parent.body
    #expect(a.epochSigningKey == b.epochSigningKey && a.transitionProof == b.transitionProof)
    #expect(a.recovery == b.recovery && a.recovery.recipients.count == 2)
    #expect(a.fields.devices == b.fields.devices && a.fields.wrappedKeys == b.fields.wrappedKeys)
    #expect(
      a.fields.keyID == b.fields.keyID
        && a.fields.authorityTransitionID == b.fields.authorityTransitionID)
    #expect(candidate.envelope.parents == [f.checkpoint.envelopeDigest])
    #expect(candidate.envelope.authorizations.isEmpty)
    #expect(complete.count == candidate.envelope.body.fields.entries.count)
    #expect(candidate.stagedEntries.count == (operation == 4 ? 0 : 1))
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
    // The inherited root proof is unchanged, not a new proof over this edit.
    #expect(a.transitionProof?.parentEnvelopeDigest == f.core.checkpoint.envelopeDigest)
    #expect(a.transitionProof?.parentEnvelopeDigest != f.checkpoint.envelopeDigest)
  }

  @Test func registeredEditChainRecoversCurrentContentsWithoutOriginalMacAuthority() throws {
    guard #available(macOS 26.0, *) else { return }
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let store = V3FilesystemTransactionArtifactStore(
      rootHandle: try VaultRootDirectoryHandle(opening: root))
    // The scope returns no vault key, original owner, capsule signer or session.
    let (anchor, token, head) = try Self.makeUpdatedVault(store: store)
    let publicKey = token.publicKey.x963Representation
    let selector = V3RecoveryHistorySelector(source: store)
    let selection = try selector.select(anchor: anchor, credentialPublicKey: publicKey)
    #expect(selection.head.digest == head && selection.currentEpoch.count == 6)
    let count = Core.Counter()
    let receiver = try PIVHPKEReceiver(publicBytes: publicKey) { peer in
      count.increment()
      let secret = try token.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: peer))
      return secret.withUnsafeBytes { Data($0) }
    }
    let snapshot = try V3RecoverySnapshotVerifier(source: store).open(
      selection, boundAnchor: anchor, receiver: receiver)
    #expect(count.value == 1)
    #expect(snapshot.entries.map(\.name) == ["copy/account", "fixture/secret", "renamed/otp"])
    #expect(
      snapshot.entries.map(\.plaintext) == ["updated\n密碼", "updated\n密碼", "JBSWY3DPEHPK3PXP"])
    #expect(snapshot.entries.map(\.type) == [.secret, .secret, .totp])
  }

  @Test(arguments: [false, true])
  func copyAndMoveOverwriteOnlyTheExactDestination(move: Bool) throws {
    let f = try Fixture()
    let source = try f.entry("fixture/secret")
    let request: V3EntryMutationRequest =
      move
      ? .move(
        sourceName: "fixture/secret", sourceData: source.canonicalBytes,
        destinationName: "fixture/totp", overwrite: true)
      : .copy(
        sourceName: "fixture/secret", sourceData: source.canonicalBytes,
        destinationEntryID: Self.copyID, destinationName: "fixture/totp", overwrite: true)
    let candidate = try f.build(request)
    let entries = try f.validate(candidate)
    let records = candidate.envelope.body.fields.entries
    let destination = try #require(records.first { $0.name == "fixture/totp" })
    #expect(destination.type == .secret)
    #expect(destination.entryID == (move ? source.context.entryID : Self.copyID))
    #expect(destination.revision == (move ? source.context.revision + 1 : 1))
    let previousDestination = try f.entry("fixture/totp").context.entryID
    #expect(!records.contains { $0.entryID == previousDestination })
    #expect(records.count == (move ? 1 : 2))
    let plaintext = try V3EntrySnapshotValidator(limits: .standard).plaintexts(
      fields: candidate.envelope.body.fields, entries: entries, vaultKey: Core.nextKey)
    #expect(plaintext[destination.entryID] == Data("Software fixture secret e\u{301}\r\n".utf8))
  }

  @Test func emptyAndNoRecipientVaultsKeepTheirExistingProtectionState() throws {
    let empty = try Fixture(empty: true)
    let addition = try empty.build(
      .add(entryID: Self.newID, name: "new", type: .secret, plaintext: "value"))
    #expect(addition.envelope.body.recovery == empty.parent.body.recovery)
    #expect(try empty.validate(addition).count == 1)
    let core = try Core.Fixture()
    let unregistered = try V3RecoveryContentMutationBuilder().build(
      .remove(name: "fixture/totp"), checkpoint: core.checkpoint, parent: core.parent,
      currentEntries: core.entries, vaultKey: Core.oldKey)
    #expect(unregistered.envelope.body.recovery.recipients.isEmpty)
    #expect(unregistered.envelope.body.recovery == core.parent.body.recovery)
    #expect(core.owner.signatures == 0 && core.owner.unwraps == 0)
  }

  @Test(arguments: 0..<10)
  func invalidInputsCannotConstructAnEdit(variant: Int) throws {
    let f = try Fixture()
    let source = try f.entry("fixture/secret").canonicalBytes
    let requests: [V3EntryMutationRequest] = [
      .add(entryID: "invalid", name: "new", type: .secret, plaintext: "value"),
      .add(entryID: Self.newID, name: "../new", type: .secret, plaintext: "value"),
      .add(entryID: Self.newID, name: "fixture/secret", type: .secret, plaintext: "value"),
      .add(
        entryID: try f.entry("fixture/secret").context.entryID, name: "new", type: .secret,
        plaintext: "value"),
      .edit(name: "missing", type: .secret, plaintext: "value"),
      .copy(
        sourceName: "fixture/secret", sourceData: source, destinationEntryID: Self.copyID,
        destinationName: "fixture/secret", overwrite: true),
      .copy(
        sourceName: "fixture/secret", sourceData: source, destinationEntryID: Self.copyID,
        destinationName: "fixture/totp", overwrite: false),
      .move(
        sourceName: "fixture/secret", sourceData: source, destinationName: "fixture/totp",
        overwrite: false),
      .remove(name: "missing"),
      .edit(name: "fixture/totp", type: .totp, plaintext: "not a canonical TOTP seed"),
    ]
    #expect(throws: (any Error).self) { try f.build(requests[variant]) }
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test(arguments: 0..<5)
  func wrongParentKeyAndIncompleteCurrentSnapshotAreRefused(variant: Int) throws {
    let f = try Fixture()
    var entries = f.entries
    if variant == 2 { entries.removeValue(forKey: try #require(entries.keys.first)) }
    if variant == 3 {
      let first = try #require(entries.keys.first)
      entries[V3EntryObjectKey(entryID: first.entryID, digest: Data(repeating: 0x55, count: 32))] =
        entries.removeValue(forKey: first)
    }
    #expect(throws: (any Error).self) {
      try V3RecoveryContentMutationBuilder().build(
        .remove(name: "fixture/secret"),
        checkpoint: variant == 0
          ? V3ManifestCheckpoint(
            vaultID: Core.vaultID, envelopeDigest: Data(repeating: 0x55, count: 32)) : f.checkpoint,
        parent: f.parent, currentEntries: entries,
        vaultKey: variant == 1 ? Core.oldKey : (variant == 4 ? Data() : Core.nextKey))
    }
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test func copyAndMoveAuthenticateTheExactEncryptedSource() throws {
    let f = try Fixture()
    let incorrectSource = try f.entry("fixture/totp").canonicalBytes
    for request in [
      V3EntryMutationRequest.copy(
        sourceName: "fixture/secret", sourceData: incorrectSource,
        destinationEntryID: Self.copyID, destinationName: "copy", overwrite: false),
      .move(
        sourceName: "fixture/secret", sourceData: incorrectSource, destinationName: "move",
        overwrite: false),
    ] {
      #expect(throws: (any Error).self) { try f.build(request) }
    }
  }

  @Test(arguments: 0..<8)
  func changedEpochAndCoverageAreNotOrdinaryEdits(variant: Int) throws {
    let f = try Fixture()
    let candidate = try f.build(try f.request(1))
    let original = candidate.envelope.body
    let old = original.fields
    var recovery = original.recovery
    var capsule = original.epochSigningKey
    var proof = original.transitionProof
    var devices = old.devices
    var wrappers = old.wrappedKeys
    var authorizations: [V3ManifestAuthorization] = []
    if variant == 0 {
      recovery = try V3RecoveryRoster(
        generationID: recovery.generationID, recipients: [], wrappedKeys: [])
    }
    if variant == 1 {
      recovery = try V3RecoveryRoster(
        generationID: UUID().uuidString.lowercased(), recipients: recovery.recipients,
        wrappedKeys: recovery.wrappedKeys)
    }
    if variant == 2 {
      capsule = try V3EpochSigningKeyCipher().prepare(
        context: V3EpochSigningKeyContext(
          vaultID: old.vaultID, keyID: old.keyID,
          authorityTransitionID: old.authorityTransitionID), vaultKey: Core.nextKey)
    }
    if variant == 3 { proof = nil }
    if variant == 4 {
      let extra = try Core.Owner()
      devices.append(V3DeviceWrappedManifestDevice(identity: extra.publicIdentity, status: .active))
      devices.sort { $0.identity.deviceID < $1.identity.deviceID }
      wrappers.append(
        try V3DeviceWrappedManifestKey(
          recipientDeviceID: extra.publicIdentity.deviceID,
          wrappedKey: V3VaultKeyHPKE().wrap(
            vaultKey: Core.nextKey,
            recipientPublicKey: extra.publicIdentity.wrappingPublicKey,
            context: original.deviceContext(recipientDeviceID: extra.publicIdentity.deviceID))))
      wrappers.sort { $0.recipientDeviceID < $1.recipientDeviceID }
    }
    if variant == 5 { authorizations = f.parent.authorizations }
    if variant == 6 {
      let recipient = try #require(recovery.recipients.first)
      let replacement = try V3RecoveryVaultKeyHPKE().wrap(
        vaultKey: Core.nextKey,
        context: V3RecoveryHPKEContext(
          vaultID: old.vaultID, keyID: old.keyID,
          authorityTransitionID: old.authorityTransitionID,
          recoveryGenerationID: recovery.generationID, recipient: recipient))
      recovery = try V3RecoveryRoster(
        generationID: recovery.generationID,
        recipients: recovery.recipients,
        wrappedKeys: recovery.wrappedKeys.map {
          $0.recipientID == recipient.recipientID ? replacement : $0
        })
    }
    if variant == 7 {
      let recipient = try #require(recovery.recipients.first)
      let revoked = try V3RecoveryRecipient(
        registrationID: recipient.registrationID,
        publicKey: recipient.publicKey, slot: recipient.slot, status: .revoked)
      recovery = try V3RecoveryRoster(
        generationID: recovery.generationID,
        recipients: recovery.recipients.map {
          $0.recipientID == recipient.recipientID ? revoked : $0
        },
        wrappedKeys: recovery.wrappedKeys.filter { $0.recipientID != recipient.recipientID })
    }
    let body = try V3RecoveryManifestBody(
      fields: V3DeviceWrappedManifestFields(
        vaultID: old.vaultID, keyID: old.keyID,
        authorityTransitionID: old.authorityTransitionID, devices: devices, wrappedKeys: wrappers,
        entries: old.entries),
      epochSigningKey: capsule, transitionProof: proof, recovery: recovery)
    let envelope = try V3RecoveryEpochBoundary().encode(
      body: body, parents: candidate.envelope.parents,
      vaultKey: Core.nextKey, authorizations: authorizations)
    let changed = V3RecoveryContentMutationCandidate(
      kind: candidate.kind, expectedCheckpoint: candidate.expectedCheckpoint,
      envelope: envelope, stagedEntries: candidate.stagedEntries)
    #expect(throws: (any Error).self) { try f.validate(changed) }
  }

  @Test(arguments: 0..<4)
  func stagedCoverageMustBeExactAndOperationKindMustMatch(variant: Int) throws {
    let f = try Fixture()
    let original = try f.build(try f.request(1))
    var staged = original.stagedEntries
    if variant == 0 { staged = [] }
    if variant == 1 { staged += original.stagedEntries }
    if variant == 2 { staged.append(try f.entry("fixture/totp")) }
    let changed = V3RecoveryContentMutationCandidate(
      kind: variant == 3 ? .addEntry : original.kind,
      expectedCheckpoint: original.expectedCheckpoint, envelope: original.envelope,
      stagedEntries: staged)
    #expect(throws: (any Error).self) { try f.validate(changed) }
  }

  @Test func changedManifestMACOrParentIsRefusedIndependently() throws {
    let f = try Fixture()
    let candidate = try f.build(try f.request(1))
    let root = try #require(try CanonicalJSON.parse(candidate.envelope.canonicalBytes).objectValue)
    let bytes = CanonicalJSON.encode(
      .object(
        root.map {
          $0.0 == "authentication"
            ? (
              $0.0,
              .object([
                ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
                ("tag", .string(Base64URL.encode(Data(repeating: 0x11, count: 32)))),
              ])
            ) : $0
        }))
    let changedMAC = try V3RecoveryManifestCodec().parseEnvelope(bytes)
    let changedParent = try V3RecoveryEpochBoundary().encode(
      body: candidate.envelope.body,
      parents: [Data(repeating: 0x22, count: 32)], vaultKey: Core.nextKey, authorizations: [])
    for envelope in [changedMAC, changedParent] {
      #expect(throws: (any Error).self) {
        try f.validate(
          V3RecoveryContentMutationCandidate(
            kind: candidate.kind,
            expectedCheckpoint: candidate.expectedCheckpoint, envelope: envelope,
            stagedEntries: candidate.stagedEntries))
      }
    }
  }

  @Test(arguments: [
    VaultTransactionMutationKind.mergeHeads, .resolveConflict, .enrollDevice,
    .revokeDevice, .registerRecoveryRecipient, .adoptRecoveryProfile, .catchUpVault,
    .recoverInterruptedTransaction,
  ])
  func nonContentOperationsCannotUseTheEditValidator(kind: VaultTransactionMutationKind) throws {
    let f = try Fixture()
    let original = try f.build(try f.request(1))
    let changed = V3RecoveryContentMutationCandidate(
      kind: kind, expectedCheckpoint: original.expectedCheckpoint,
      envelope: original.envelope, stagedEntries: original.stagedEntries)
    #expect(throws: V3ImmutableTransactionError.invalidAncestryProof) { try f.validate(changed) }
  }

  @Test(arguments: [false, true])
  func independentValidationChecksCopyAndMovePayloads(move: Bool) throws {
    let f = try Fixture()
    let original = try f.build(try f.request(move ? 3 : 2))
    let entry = try #require(original.stagedEntries.first)
    let different = try V3EntryCipher().seal(
      "Different software fixture payload",
      context: entry.context, vaultKey: Core.nextKey)
    let old = original.envelope.body
    let fields = try V3DeviceWrappedManifestFields(
      vaultID: old.fields.vaultID, keyID: old.fields.keyID,
      authorityTransitionID: old.fields.authorityTransitionID, devices: old.fields.devices,
      wrappedKeys: old.fields.wrappedKeys,
      entries: old.fields.entries.map {
        $0.entryID == different.context.entryID
          ? V3ResealedEntry(encryptedEntry: different).manifestEntry : $0
      })
    let envelope = try V3RecoveryEpochBoundary().encode(
      body: V3RecoveryManifestBody(
        fields: fields, epochSigningKey: old.epochSigningKey,
        transitionProof: old.transitionProof, recovery: old.recovery),
      parents: original.envelope.parents,
      vaultKey: Core.nextKey, authorizations: [])
    let candidate = V3RecoveryContentMutationCandidate(
      kind: original.kind, expectedCheckpoint: original.expectedCheckpoint,
      envelope: envelope, stagedEntries: [different])
    #expect(throws: V3RecoveryContentMutationError.invalidCopyOrMove) { try f.validate(candidate) }
  }

  @Test func maximumRevisionCannotWrapAndWrongRevisionIsNotAnEdit() throws {
    let f = try Fixture()
    let original = try f.entry("fixture/secret")
    let maximum = try V3EntryCipher().seal(
      "maximum-revision fixture",
      context: V3EntryAuthenticationContext(
        vaultID: original.context.vaultID,
        entryID: original.context.entryID, name: original.context.name, type: original.context.type,
        keyID: original.context.keyID, revision: v3MaximumSafeInteger), vaultKey: Core.nextKey)
    let old = f.parent.body
    let fields = try V3DeviceWrappedManifestFields(
      vaultID: old.fields.vaultID, keyID: old.fields.keyID,
      authorityTransitionID: old.fields.authorityTransitionID, devices: old.fields.devices,
      wrappedKeys: old.fields.wrappedKeys,
      entries: old.fields.entries.map {
        $0.entryID == maximum.context.entryID
          ? V3ResealedEntry(encryptedEntry: maximum).manifestEntry : $0
      })
    let parent = try V3RecoveryEpochBoundary().encode(
      body: V3RecoveryManifestBody(
        fields: fields, epochSigningKey: old.epochSigningKey,
        transitionProof: old.transitionProof, recovery: old.recovery), parents: f.parent.parents,
      vaultKey: Core.nextKey, authorizations: [])
    var entries = f.entries.filter { $0.key.entryID != maximum.context.entryID }
    entries[Self.address(maximum)] = maximum
    let cp = try V3ManifestCheckpoint(vaultID: Core.vaultID, envelopeDigest: parent.digest)
    #expect(throws: V3DeviceWrappedContentMutationError.revisionOverflow) {
      try V3RecoveryContentMutationBuilder().build(
        .edit(name: "fixture/secret", type: .secret, plaintext: "new value"), checkpoint: cp,
        parent: parent, currentEntries: entries, vaultKey: Core.nextKey)
    }
    let candidate = try f.build(try f.request(1))
    let wrongRevision = candidate.envelope.body.fields.entries.map { record in
      record.entryID == original.context.entryID
        ? V3ManifestEntry(
          entryID: record.entryID, name: record.name, type: record.type,
          revision: record.revision + 1, keyID: record.keyID,
          ciphertextDigest: record.ciphertextDigest)
        : record
    }
    #expect(throws: V3ImmutableTransactionError.invalidAncestryProof) {
      try V3EntryMutationPolicy().validate(
        from: f.parent.body.fields.entries,
        to: wrongRevision, kind: .editEntry)
    }
  }

  @Test func manifestEntryAndAggregateBoundsApplyToBothSnapshots() throws {
    let f = try Fixture()
    let maxEntry = try #require(f.entries.values.map { $0.canonicalBytes.count }.max())
    let sum = f.entries.values.reduce(0) { $0 + $1.canonicalBytes.count }
    let limits = [
      V3ManifestRepositoryLimits(
        maximumManifestObjects: 10, maximumHistoryDepth: 10, maximumManifestBytes: 1),
      V3ManifestRepositoryLimits(
        maximumManifestObjects: 10, maximumHistoryDepth: 10, maximumEntryBytes: 1),
      V3ManifestRepositoryLimits(
        maximumManifestObjects: 10, maximumHistoryDepth: 10,
        maximumEntryBytes: maxEntry, maximumTotalEntryBytes: sum - 1),
      V3ManifestRepositoryLimits(
        maximumManifestObjects: 10, maximumHistoryDepth: 10, maximumReferencedEntryObjects: 1),
    ]
    for limit in limits {
      #expect(throws: (any Error).self) {
        try V3RecoveryContentMutationBuilder(limits: limit).build(
          .remove(name: "fixture/totp"),
          checkpoint: f.checkpoint, parent: f.parent, currentEntries: f.entries,
          vaultKey: Core.nextKey)
      }
    }
    let twoEntries = V3ManifestRepositoryLimits(
      maximumManifestObjects: 10,
      maximumHistoryDepth: 10, maximumReferencedEntryObjects: 2)
    #expect(throws: V3RecoveryContentMutationError.resourceLimit) {
      try V3RecoveryContentMutationBuilder(limits: twoEntries).build(
        .add(entryID: Self.newID, name: "new", type: .secret, plaintext: "value"),
        checkpoint: f.checkpoint, parent: f.parent, currentEntries: f.entries,
        vaultKey: Core.nextKey)
    }
  }

  @Test func shippingProfileTwoCodecStillRefusesTheNewContentCandidate() throws {
    let f = try Fixture()
    let candidate = try f.build(try f.request(1))
    #expect(throws: V3DeviceWrappedUnlockError.unsupportedProfileVersion(3)) {
      try V3DeviceWrappedManifestEnvelopeCodec().parse(candidate.envelope.canonicalBytes)
    }
    let text = String(decoding: candidate.envelope.canonicalBytes, as: UTF8.self)
    #expect(!text.contains("updated secret") && !text.contains(Base64URL.encode(Core.nextKey)))
    #expect(
      !String(decoding: candidate.stagedEntries[0].canonicalBytes, as: UTF8.self).contains(
        "updated secret"))
  }

  private struct Fixture {
    let core: Core.Fixture
    let parent: V3RecoveryManifestEnvelope
    let checkpoint: V3ManifestCheckpoint
    let entries: [V3EntryObjectKey: V3EncryptedEntry]
    let anchor: V3RecoveryAnchor
    init(empty: Bool = false) throws {
      core = try Core.Fixture(empty: empty, backup: true)
      let registration = try core.prepare()
      parent = registration.candidate
      checkpoint = try V3ManifestCheckpoint(vaultID: Core.vaultID, envelopeDigest: parent.digest)
      entries = try V3EntrySnapshotValidator(limits: .standard).entryMap(registration.stagedEntries)
      anchor = registration.intent.anchor
    }
    func entry(_ name: String) throws -> V3EncryptedEntry {
      try #require(entries.values.first { $0.context.name == name })
    }
    func request(_ operation: Int) throws -> V3EntryMutationRequest {
      switch operation {
      case 0:
        .add(
          entryID: V3RecoveryContentMutationTests.newID, name: "new/密碼", type: .secret,
          plaintext: "new value")
      case 1: .edit(name: "fixture/secret", type: .secret, plaintext: "updated secret")
      case 2:
        .copy(
          sourceName: "fixture/secret", sourceData: try entry("fixture/secret").canonicalBytes,
          destinationEntryID: V3RecoveryContentMutationTests.copyID, destinationName: "copy",
          overwrite: false)
      case 3:
        .move(
          sourceName: "fixture/secret", sourceData: try entry("fixture/secret").canonicalBytes,
          destinationName: "move", overwrite: false)
      default: .remove(name: "fixture/secret")
      }
    }
    func build(_ request: V3EntryMutationRequest) throws -> V3RecoveryContentMutationCandidate {
      try V3RecoveryContentMutationBuilder().build(
        request, checkpoint: checkpoint, parent: parent,
        currentEntries: entries, vaultKey: Core.nextKey)
    }
    func validate(_ candidate: V3RecoveryContentMutationCandidate) throws -> [V3EntryObjectKey:
      V3EncryptedEntry]
    {
      try V3RecoveryContentMutationValidator().validate(
        candidate, parent: parent,
        currentEntries: entries, vaultKey: Core.nextKey)
    }
  }
  private static func address(_ entry: V3EncryptedEntry) -> V3EntryObjectKey {
    V3EntryObjectKey(
      entryID: entry.context.entryID, digest: Data(SHA256.hash(data: entry.canonicalBytes)))
  }
  private static func materialize(
    _ envelope: V3RecoveryManifestEnvelope, entries: [V3EncryptedEntry],
    store: V3FilesystemTransactionArtifactStore
  ) throws {
    let operation = VaultTransactionOperationID()
    for entry in entries {
      let key = address(entry)
      try store.stageEntry(
        entry.canonicalBytes, entryID: key.entryID, digest: key.digest, operationID: operation)
      try store.publishStagedEntry(
        entry.canonicalBytes, entryID: key.entryID, digest: key.digest, operationID: operation)
    }
    try store.stageManifest(
      envelope.canonicalBytes, digest: envelope.digest, operationID: operation)
    try store.publishStagedManifest(
      envelope.canonicalBytes, digest: envelope.digest, operationID: operation)
  }
  private static func makeUpdatedVault(store: V3FilesystemTransactionArtifactStore) throws
    -> (V3RecoveryAnchor, P256.KeyAgreement.PrivateKey, Data)
  {
    let f = try Fixture()
    var parent = f.parent
    var checkpoint = f.checkpoint
    var entries = f.entries
    try materialize(parent, entries: Array(entries.values), store: store)
    func save(_ request: V3EntryMutationRequest) throws {
      let candidate = try V3RecoveryContentMutationBuilder().build(
        request, checkpoint: checkpoint,
        parent: parent, currentEntries: entries, vaultKey: Core.nextKey)
      entries = try V3RecoveryContentMutationValidator().validate(
        candidate, parent: parent,
        currentEntries: entries, vaultKey: Core.nextKey)
      try materialize(candidate.envelope, entries: candidate.stagedEntries, store: store)
      parent = candidate.envelope
      checkpoint = try V3ManifestCheckpoint(vaultID: Core.vaultID, envelopeDigest: parent.digest)
    }
    try save(.add(entryID: newID, name: "new/密碼", type: .secret, plaintext: "new value"))
    try save(.edit(name: "fixture/secret", type: .secret, plaintext: "updated\n密碼"))
    let secret = try #require(entries.values.first { $0.context.name == "fixture/secret" })
    try save(
      .copy(
        sourceName: "fixture/secret", sourceData: secret.canonicalBytes,
        destinationEntryID: copyID, destinationName: "copy/account", overwrite: false))
    let otp = try #require(entries.values.first { $0.context.name == "fixture/totp" })
    try save(
      .move(
        sourceName: "fixture/totp", sourceData: otp.canonicalBytes,
        destinationName: "renamed/otp", overwrite: false))
    try save(.remove(name: "new/密碼"))
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
    return (f.anchor, f.core.token, parent.digest)
  }
}
