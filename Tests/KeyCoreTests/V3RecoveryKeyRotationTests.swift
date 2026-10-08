import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Software crypto and disposable filesystem fixtures only. Rotation outputs
/// are unpublished; chain materialization is test setup, not a rotation service.
struct V3RecoveryKeyRotationTests {
  private typealias Core = V3RecoveryRegistrationTests
  private typealias Fixture = Core.Fixture

  @Test func rotationPreservesAuthorityAndAllEntryValuesWithFreshEpochMaterial() throws {
    let f = try Fixture(backup: true)
    let result = try build(f)
    let old = f.parent.body
    let new = result.envelope.body
    #expect(
      result.expectedCheckpoint == f.checkpoint && result.envelope.parents == [f.parent.digest])
    #expect(
      new.fields.devices == old.fields.devices && new.recovery.recipients == old.recovery.recipients
    )
    #expect(new.recovery.generationID == old.recovery.generationID)
    #expect(
      new.fields.keyID != old.fields.keyID
        && new.fields.authorityTransitionID != old.fields.authorityTransitionID)
    #expect(new.epochSigningKey.publicKey != old.epochSigningKey.publicKey)
    #expect(
      new.fields.wrappedKeys != old.fields.wrappedKeys
        && new.recovery.wrappedKeys != old.recovery.wrappedKeys)
    #expect(
      zip(old.fields.entries, new.fields.entries).allSatisfy {
        $0.entryID == $1.entryID && $0.name == $1.name && $0.type == $1.type
          && $0.revision == $1.revision
          && $0.ciphertextDigest != $1.ciphertextDigest
      })
    #expect(
      try plaintexts(new.fields, entries: result.stagedEntries, key: Core.nextKey)
        == plaintexts(old.fields, entries: Array(f.entries.values), key: Core.oldKey))
    #expect(f.owner.signatures == 1 && f.owner.unwraps == 0)
  }

  @Test(arguments: [false, true])
  func emptyAndUnregisteredVaultsRemainUnregisteredAfterRotation(empty: Bool) throws {
    let f = try Fixture(empty: empty)
    let result = try build(f)
    #expect(
      result.envelope.body.recovery.recipients.isEmpty
        && result.envelope.body.recovery.wrappedKeys.isEmpty)
    #expect(result.stagedEntries.isEmpty == empty)
    try validate(result, f: f)
  }

  @Test func onlyActiveDevicesAndRecipientsGetNewWrappers() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture(backup: true)
    let peer = try Core.Owner()
    let retired = try Core.Owner()
    let revokedToken = P256.KeyAgreement.PrivateKey()
    let revokedRecipient = try V3RecoveryRecipient(
      registrationID: UUID().uuidString.lowercased(),
      publicKey: revokedToken.publicKey.x963Representation,
      slot: .keyManagement, status: .revoked)
    let old = f.parent.body
    let devices =
      (old.fields.devices + [
        V3DeviceWrappedManifestDevice(identity: peer.publicIdentity, status: .active),
        V3DeviceWrappedManifestDevice(identity: retired.publicIdentity, status: .revoked),
      ]).sorted { $0.identity.deviceID < $1.identity.deviceID }
    let peerWrapper = try V3DeviceWrappedManifestKey(
      recipientDeviceID: peer.publicIdentity.deviceID,
      wrappedKey: V3VaultKeyHPKE().wrap(
        vaultKey: Core.oldKey,
        recipientPublicKey: peer.publicIdentity.wrappingPublicKey,
        context: old.deviceContext(recipientDeviceID: peer.publicIdentity.deviceID)))
    let fields = try V3DeviceWrappedManifestFields(
      vaultID: Core.vaultID, keyID: old.fields.keyID,
      authorityTransitionID: old.fields.authorityTransitionID,
      devices: devices,
      wrappedKeys: (old.fields.wrappedKeys + [peerWrapper]).sorted {
        $0.recipientDeviceID < $1.recipientDeviceID
      }, entries: old.fields.entries)
    let body = try V3RecoveryManifestBody(
      fields: fields, epochSigningKey: old.epochSigningKey,
      transitionProof: nil,
      recovery: V3RecoveryRoster(
        generationID: old.recovery.generationID,
        recipients: (old.recovery.recipients + [revokedRecipient]).sorted {
          $0.recipientID.rawValue < $1.recipientID.rawValue
        }, wrappedKeys: old.recovery.wrappedKeys))
    let parent = try V3RecoveryEpochBoundary().encode(
      body: body, parents: [], vaultKey: Core.oldKey, authorizations: [])
    let checkpoint = try V3ManifestCheckpoint(vaultID: Core.vaultID, envelopeDigest: parent.digest)
    let result = try V3RecoveryKeyRotationBuilder().build(
      checkpoint: checkpoint, parent: parent,
      currentEntries: f.entries, currentVaultKey: Core.oldKey, nextVaultKey: Core.nextKey,
      owner: f.owner, reason: "Software rotation fixture")
    #expect(result.envelope.body.fields.devices == devices)
    #expect(
      Set(result.envelope.body.fields.wrappedKeys.map(\.recipientDeviceID))
        == [f.owner.publicIdentity.deviceID, peer.publicIdentity.deviceID])
    #expect(result.envelope.body.recovery.recipients == body.recovery.recipients)
    #expect(
      !result.envelope.body.recovery.wrappedKeys.contains {
        $0.recipientID == revokedRecipient.recipientID
      })
    for owner in [f.owner, peer] {
      let wrapped = try #require(
        result.envelope.body.fields.wrappedKeys.first {
          $0.recipientDeviceID == owner.publicIdentity.deviceID
        })
      #expect(
        try V3VaultKeyHPKE().unwrap(
          wrapped.wrappedKey, recipientPrivateKey: owner.wrappingKey,
          context: result.envelope.body.deviceContext(
            recipientDeviceID: owner.publicIdentity.deviceID)) == Core.nextKey)
    }
    let recipient = try #require(
      result.envelope.body.recovery.recipients.first { $0.status == .active })
    #expect(
      try openWrapper(result.envelope, recipient: recipient, token: f.backupToken) == Core.nextKey)
  }

  @Test(arguments: 0..<6)
  func invalidKeysOwnerReasonAndTransitionRefuseBeforeSigning(variant: Int) throws {
    let f = try Fixture(backup: true)
    let other = try Core.Owner()
    #expect(throws: (any Error).self) {
      try V3RecoveryKeyRotationBuilder().build(
        checkpoint: f.checkpoint, parent: f.parent,
        currentEntries: f.entries, currentVaultKey: variant == 0 ? Core.nextKey : Core.oldKey,
        nextVaultKey: variant == 1 ? Core.oldKey : (variant == 2 ? Data([1]) : Core.nextKey),
        owner: variant == 3 ? other : f.owner, reason: variant == 4 ? "" : "Software fixture",
        authorityTransitionID: variant == 5
          ? f.parent.body.fields.authorityTransitionID : UUID().uuidString.lowercased())
    }
    #expect(f.owner.signatures == 0 && other.signatures == 0 && f.owner.unwraps == 0)
  }

  @Test(arguments: 0..<3)
  func incompleteExtraOrSubstitutedCurrentSnapshotRefusesBeforeSigning(variant: Int) throws {
    let f = try Fixture()
    var entries = f.entries
    let address = try #require(entries.keys.first)
    if variant == 0 {
      entries.removeValue(forKey: address)
    } else {
      let entry = try #require(f.entries.values.first)
      let replacement = try V3EntryCipher().seal(
        "different fixture", context: entry.context, vaultKey: Core.oldKey)
      let key =
        variant == 1
        ? try Core.Fixture.address(V3ResealedEntry(encryptedEntry: replacement).manifestEntry)
        : address
      entries[key] = replacement
    }
    #expect(throws: (any Error).self) {
      try V3RecoveryKeyRotationBuilder().build(
        checkpoint: f.checkpoint, parent: f.parent,
        currentEntries: entries, currentVaultKey: Core.oldKey, nextVaultKey: Core.nextKey,
        owner: f.owner, reason: "Software fixture")
    }
    #expect(f.owner.signatures == 0)
  }

  @Test(arguments: 0..<4)
  func boundedConstructionRefusesBeforeSigning(variant: Int) throws {
    let f = try Fixture(backup: true)
    let limits = [
      Core.Fixture.limits(entries: 1), Core.Fixture.limits(entryBytes: 1),
      Core.Fixture.limits(totalBytes: 1),
      Core.Fixture.limits(manifestBytes: f.parent.canonicalBytes.count),
    ][variant]
    #expect(throws: (any Error).self) { try build(f, limits: limits) }
    #expect(f.owner.signatures == 0 && f.owner.unwraps == 0)
  }

  @Test(arguments: 0..<3)
  func independentValidationRequiresExactCompleteStagedSnapshot(variant: Int) throws {
    let f = try Fixture(backup: true)
    let result = try build(f)
    let other = try build(f)
    let entries =
      variant == 0
      ? [] : (variant == 1 ? result.stagedEntries + result.stagedEntries : other.stagedEntries)
    let changed = V3RecoveryKeyRotationCandidate(
      expectedCheckpoint: result.expectedCheckpoint,
      envelope: result.envelope, stagedEntries: entries)
    #expect(throws: (any Error).self) { try validate(changed, f: f) }
    #expect(f.owner.unwraps == 0)
  }

  @Test func normalPublicationMustCompareResealedPlaintextsNotOnlyAuthentication() throws {
    let f = try Fixture(backup: true)
    var values = try V3EntrySnapshotValidator(limits: .standard).plaintexts(
      fields: f.parent.body.fields, entries: f.entries, vaultKey: Core.oldKey)
    let secret = try #require(f.parent.body.fields.entries.first { $0.name == "fixture/secret" })
    values[secret.entryID] = Data("incorrect reseal fixture".utf8)
    let material = try V3RecoveryEpochMaterialBuilder(limits: .standard).build(
      fields: f.parent.body.fields, plaintexts: values, nextVaultKey: Core.nextKey,
      authorityTransitionID: UUID().uuidString.lowercased(), devices: f.parent.body.fields.devices,
      generationID: f.parent.body.recovery.generationID,
      recipients: f.parent.body.recovery.recipients)
    let envelope = try V3RecoveryEpochBoundary().authorize(
      candidate: material.body, parent: f.parent,
      currentVaultKey: Core.oldKey, nextVaultKey: Core.nextKey, signer: f.owner,
      reason: "Software reseal contract fixture")
    let candidate = V3RecoveryKeyRotationCandidate(
      expectedCheckpoint: f.checkpoint,
      envelope: envelope, stagedEntries: material.stagedEntries)
    #expect(throws: V3RecoveryKeyRotationError.invalidCandidate) { try validate(candidate, f: f) }
  }

  @Test func recipientAdditionCannotBeMisclassifiedAsOrdinaryRotation() throws {
    let f = try Fixture(backup: true)
    let registration = try f.prepare()
    let candidate = V3RecoveryKeyRotationCandidate(
      expectedCheckpoint: f.checkpoint,
      envelope: registration.candidate, stagedEntries: registration.stagedEntries)
    #expect(throws: V3RecoveryKeyRotationError.invalidCandidate) { try validate(candidate, f: f) }
  }

  @Test func differentCheckpointOrNextKeyCannotValidateTheCandidate() throws {
    let f = try Fixture(backup: true)
    let result = try build(f)
    let checkpoint = try V3ManifestCheckpoint(
      vaultID: Core.vaultID, envelopeDigest: Data(repeating: 0x99, count: 32))
    #expect(throws: (any Error).self) {
      try validate(
        .init(
          expectedCheckpoint: checkpoint, envelope: result.envelope,
          stagedEntries: result.stagedEntries), f: f)
    }
    #expect(throws: (any Error).self) {
      try V3RecoveryKeyRotationValidator().validate(
        result, parent: f.parent,
        currentEntries: f.entries, currentVaultKey: Core.oldKey,
        nextVaultKey: Data(repeating: 0x77, count: 32),
        expectedOwner: f.owner.publicIdentity)
    }
  }

  @Test func publicationValidationOpensOneExactLocalWrapperAfterSoftwareChecks() throws {
    let f = try Fixture(backup: true)
    let result = try build(f)
    try V3RecoveryKeyRotationValidator().validateForPublication(
      result, parent: f.parent,
      currentEntries: f.entries, currentVaultKey: Core.oldKey, nextVaultKey: Core.nextKey,
      identity: f.owner, reason: "Software local wrapper fixture")
    #expect(f.owner.signatures == 1 && f.owner.unwraps == 1)
    #expect(throws: (any Error).self) {
      try V3RecoveryKeyRotationValidator().validateForPublication(
        .init(
          expectedCheckpoint: result.expectedCheckpoint, envelope: result.envelope,
          stagedEntries: []),
        parent: f.parent, currentEntries: f.entries, currentVaultKey: Core.oldKey,
        nextVaultKey: Core.nextKey, identity: f.owner, reason: "Software fixture")
    }
    #expect(f.owner.unwraps == 1)
  }

  @Test func cancelledLocalUnwrapDoesNotRetry() throws {
    let f = try Fixture(backup: true)
    let result = try build(f)
    f.owner.cancelUnwrap = true
    #expect(throws: Core.FixtureError.cancelled) {
      try V3RecoveryKeyRotationValidator().validateForPublication(
        result, parent: f.parent,
        currentEntries: f.entries, currentVaultKey: Core.oldKey, nextVaultKey: Core.nextKey,
        identity: f.owner, reason: "Software cancellation fixture")
    }
    #expect(f.owner.unwraps == 1 && f.owner.signatures == 1)
  }

  @Test func aMismatchedLocalUnwrapResultCannotApprovePublication() throws {
    let f = try Fixture(backup: true)
    let candidate = try build(f)
    let identity = WrongUnwrap(publicIdentity: f.owner.publicIdentity)
    #expect(throws: V3RecoveryKeyRotationError.localWrapperMismatch) {
      try V3RecoveryKeyRotationValidator().validateForPublication(
        candidate, parent: f.parent, currentEntries: f.entries,
        currentVaultKey: Core.oldKey, nextVaultKey: Core.nextKey,
        identity: identity, reason: "Software mismatched-provider fixture")
    }
    #expect(identity.calls.value == 1 && f.owner.unwraps == 0)
  }

  @Test(arguments: 0..<3)
  func independentPublicationValidationBoundsStagedBytesBeforePrivateWork(variant: Int) throws {
    let f = try Fixture(backup: true)
    let candidate = try build(f)
    let limits = [
      Core.Fixture.limits(entries: 1), Core.Fixture.limits(entryBytes: 1),
      Core.Fixture.limits(totalBytes: 1),
    ][variant]
    #expect(throws: (any Error).self) {
      try V3RecoveryKeyRotationValidator(limits: limits).validateForPublication(
        candidate, parent: f.parent, currentEntries: f.entries,
        currentVaultKey: Core.oldKey, nextVaultKey: Core.nextKey,
        identity: f.owner, reason: "Software bounds fixture")
    }
    #expect(f.owner.unwraps == 0)
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

  @Test func unsignedMaterialRequiresTheExactPlaintextIdentitySet() throws {
    let f = try Fixture()
    #expect(throws: V3RecoveryKeyRotationError.invalidCandidate) {
      try V3RecoveryEpochMaterialBuilder(limits: .standard).build(
        fields: f.parent.body.fields,
        plaintexts: [:], nextVaultKey: Core.nextKey,
        authorityTransitionID: UUID().uuidString.lowercased(),
        devices: f.parent.body.fields.devices, generationID: f.parent.body.recovery.generationID,
        recipients: f.parent.body.recovery.recipients)
    }
  }

  @Test(arguments: [false, true])
  func primaryAndBackupRecoverAfterRepeatedRotationsAndAnOrdinarySave(backup: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let (anchors, tokens, digest) = try rotationChain(root)
    let store = V3FilesystemTransactionArtifactStore(
      rootHandle: try VaultRootDirectoryHandle(opening: root))
    let anchor = anchors[backup ? 1 : 0]
    let token = tokens[backup ? 1 : 0]
    let selected = try V3RecoveryHistorySelector(source: store).select(
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
    let snapshot = try V3RecoverySnapshotVerifier(source: store).open(
      selected, boundAnchor: anchor, receiver: receiver)
    #expect(selected.head.digest == digest && calls.value == 1)
    #expect(snapshot.entries.first { $0.name == "fixture/secret" }?.plaintext == "after rotations")
    #expect(snapshot.entries.first { $0.name == "fixture/totp" }?.plaintext == "JBSWY3DPEHPK3PXP")
  }

  private func rotationChain(_ root: URL) throws -> (
    [V3RecoveryAnchor], [P256.KeyAgreement.PrivateKey], Data
  ) {
    let f = try V3RecoveryContentMutationPublisherTests.Fixture(root: root)
    let backupRecipient = try #require(f.core.parent.body.recovery.recipients.first)
    let backupAnchor = try V3RecoveryAnchor(
      floor: .init(vaultID: Core.vaultID, envelopeDigest: f.core.parent.digest),
      recipientID: backupRecipient.recipientID, registrationID: backupRecipient.registrationID,
      slot: .keyManagement)
    var parent = f.parent
    var entries = f.entries
    var key = Core.nextKey
    var obsolete = Array(f.core.entries.values) + Array(f.entries.values)
    for byte: UInt8 in [0x33, 0x44, 0x55] {
      let next = Data(repeating: byte, count: 32)
      let checkpoint = try V3ManifestCheckpoint(
        vaultID: Core.vaultID, envelopeDigest: parent.digest)
      let result = try V3RecoveryKeyRotationBuilder().build(
        checkpoint: checkpoint, parent: parent,
        currentEntries: entries, currentVaultKey: key, nextVaultKey: next,
        owner: f.core.owner, reason: "Software repeated rotation fixture")
      try f.seed(result.envelope, entries: result.stagedEntries)
      parent = result.envelope
      entries = try V3EntrySnapshotValidator(limits: .standard).entryMap(result.stagedEntries)
      key = next
      if byte != 0x55 { obsolete += result.stagedEntries }
    }
    // Materialization/checkpoint setup only. Rotation publication is not yet implemented.
    let checkpoint = try V3ManifestCheckpoint(vaultID: Core.vaultID, envelopeDigest: parent.digest)
    f.checkpoints.value = checkpoint.canonicalBytes
    try f.cache.store(parent.canonicalBytes, for: checkpoint)
    let session = V3DeviceWrappedVaultKeySessionStore()
    try session.install(key, vaultID: Core.vaultID, keyID: parent.body.fields.keyID)
    let owner = VaultTransactionMutationOwner()
    let ordinary = V3RecoveryVaultMutationService(
      vaultID: Core.vaultID, session: session, objectStore: f.store,
      checkpointStore: f.checkpoints, recoveryAnchorStore: f.ownership,
      registrationAnchorStore: f.registration,
      adoptionAnchorStore: f.adoption, cache: f.cache)
    try owner.perform(.editEntry) { context in
      try ordinary.edit(
        name: "fixture/secret", secret: "after rotations", type: .secret,
        operationID: context.operationID)
    }
    session.invalidate()
    for entry in obsolete { try FileManager.default.removeItem(at: f.entryURL(entry)) }
    let last = try V3ManifestCheckpoint(canonicalBytes: #require(f.checkpoints.value))
    return ([f.anchor, backupAnchor], [f.core.token, f.core.backupToken], last.envelopeDigest)
  }

  private func build(_ f: Fixture, limits: V3ManifestRepositoryLimits = .standard) throws
    -> V3RecoveryKeyRotationCandidate
  {
    try V3RecoveryKeyRotationBuilder(limits: limits).build(
      checkpoint: f.checkpoint, parent: f.parent,
      currentEntries: f.entries, currentVaultKey: Core.oldKey, nextVaultKey: Core.nextKey,
      owner: f.owner, reason: "Software key rotation fixture")
  }
  private func validate(_ candidate: V3RecoveryKeyRotationCandidate, f: Fixture) throws {
    try V3RecoveryKeyRotationValidator().validate(
      candidate, parent: f.parent, currentEntries: f.entries,
      currentVaultKey: Core.oldKey, nextVaultKey: Core.nextKey,
      expectedOwner: f.owner.publicIdentity)
  }
  private func plaintexts(
    _ fields: V3DeviceWrappedManifestFields, entries: [V3EncryptedEntry], key: Data
  ) throws -> [String: Data] {
    let snapshots = V3EntrySnapshotValidator(limits: .standard)
    return try snapshots.plaintexts(
      fields: fields, entries: snapshots.entryMap(entries), vaultKey: key)
  }
  @available(macOS 26.0, *)
  private func openWrapper(
    _ envelope: V3RecoveryManifestEnvelope, recipient: V3RecoveryRecipient,
    token: P256.KeyAgreement.PrivateKey
  ) throws -> Data {
    let receiver = try PIVHPKEReceiver(publicBytes: token.publicKey.x963Representation) { peer in
      try token.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: peer)
      )
      .withUnsafeBytes { Data($0) }
    }
    let wrapper = try #require(
      envelope.body.recovery.wrappedKeys.first { $0.recipientID == recipient.recipientID })
    return try V3RecoveryVaultKeyHPKE().unwrap(
      wrapper, recipientPrivateKey: receiver,
      context: V3RecoveryHPKEContext(
        vaultID: Core.vaultID, keyID: envelope.body.fields.keyID,
        authorityTransitionID: envelope.body.fields.authorityTransitionID,
        recoveryGenerationID: envelope.body.recovery.generationID, recipient: recipient))
  }
}
