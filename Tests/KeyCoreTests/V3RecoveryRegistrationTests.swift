import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

/// Software construction and completion checks, not product registration or
/// physical administration qualification. No YubiKey or user vault is accessed.
struct V3RecoveryRegistrationTests {
  private static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
  private static let transitionID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
  private static let generationID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b5"
  private static let entryID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b6"
  private static let totpID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b7"
  private static let oldKey = Data(0..<32)
  private static let nextKey = Data(32..<64)

  @Test func preparesAnExactEncryptedRecipientAdditionAndPublicExport() throws {
    let fixture = try Fixture()
    let preparation = try fixture.prepare()
    let body = preparation.candidate.body
    #expect(fixture.owner.signatures == 1)
    #expect(fixture.owner.unwraps == 0)
    #expect(body.fields.keyID != fixture.parent.body.fields.keyID)
    #expect(body.fields.authorityTransitionID != Self.transitionID)
    #expect(body.recovery.generationID != Self.generationID)
    #expect(body.epochSigningKey.publicKey != fixture.parent.body.epochSigningKey.publicKey)
    #expect(body.fields.devices == fixture.parent.body.fields.devices)
    #expect(body.recovery.recipients.count == 1)
    #expect(body.recovery.recipients[0].publicKey == fixture.credential.publicKey)
    #expect(preparation.candidate.parents == [fixture.parent.digest])
    #expect(
      try V3RecoveryAnchorCodec().parseCanonical(preparation.exportedAnchor)
        == preparation.intent.anchor)
    #expect(preparation.intent.anchor.floor.envelopeDigest == preparation.candidate.digest)
    #expect(preparation.intent.expectedCheckpoint == fixture.checkpoint)
    try fixture.validate(preparation)
    for (old, new) in zip(fixture.parent.body.fields.entries, body.fields.entries) {
      #expect(old.entryID == new.entryID && old.revision == new.revision)
      #expect(old.ciphertextDigest != new.ciphertextDigest)
      let resealed = try #require(
        preparation.stagedEntries.first { $0.context.entryID == new.entryID })
      let current = try #require(fixture.entries[Fixture.address(old)])
      #expect(
        try V3EntryCipher().openPlaintextDataTrusted(
          current.canonicalBytes, vaultID: Self.vaultID, manifestEntry: old, vaultKey: Self.oldKey)
          == V3EntryCipher().openPlaintextDataTrusted(
            resealed.canonicalBytes, vaultID: Self.vaultID, manifestEntry: new,
            vaultKey: Self.nextKey))
    }
    #expect(throws: V3DeviceWrappedUnlockError.unsupportedProfileVersion(3)) {
      try V3DeviceWrappedManifestEnvelopeCodec().parse(preparation.candidate.canonicalBytes)
    }
  }

  @Test func pendingIntentRoundTripsAndAuthenticatesWithoutPersistingSecrets() throws {
    let preparation = try Fixture().prepare()
    let bytes = preparation.intent.canonicalBytes
    let decoded = try V3RecoveryRegistrationIntent(canonicalBytes: bytes)
    #expect(decoded == preparation.intent)
    try decoded.authenticate(currentVaultKey: Self.oldKey)
    #expect(throws: V3RecoveryRegistrationError.authenticationFailed) {
      try decoded.authenticate(currentVaultKey: Self.nextKey)
    }
    #expect(throws: V3RecoveryRegistrationError.authenticationFailed) {
      try decoded.authenticate(currentVaultKey: Data())
    }
    let text = String(decoding: bytes, as: UTF8.self)
    #expect(!text.contains(Base64URL.encode(Self.oldKey)))
    #expect(!text.contains(Base64URL.encode(Self.nextKey)))
    #expect(!text.contains("Software fixture secret"))
    #expect(!text.contains("JBSWY3DPEHPK3PXP"))
    let fields = try #require(CanonicalJSON.parse(bytes).objectValue)
    #expect(
      Set(fields.map(\.0))
        == Set([
          "format", "version", "operationID", "expectedCheckpoint", "ownerDeviceID",
          "publicKey", "anchor", "requiresEmptyAnchor", "stagedEntries",
          "authenticationAlgorithm", "authenticationTag",
        ]))
  }

  @Test func pendingIntentRejectsNoncanonicalAndUnsupportedShapes() throws {
    let bytes = try Fixture().prepare().intent.canonicalBytes
    let text = String(decoding: bytes, as: UTF8.self)
    let invalid = [
      " " + text,
      "{\"unexpected\":true," + text.dropFirst(),
      "{\"format\":\"duplicate\"," + text.dropFirst(),
      text.replacingOccurrences(
        of: "\"requiresEmptyAnchor\":true", with: "\"requiresEmptyAnchor\":false"),
      text.replacingOccurrences(of: "\"version\":1", with: "\"version\":2"),
      text.replacingOccurrences(of: "HKDF-SHA256+HMAC-SHA256", with: "unsupported"),
    ]
    for input in invalid {
      #expect(throws: (any Error).self) {
        try V3RecoveryRegistrationIntent(canonicalBytes: Data(input.utf8))
      }
    }
    #expect(throws: V3RecoveryRegistrationError.resourceLimit) {
      try V3RecoveryRegistrationIntent(
        canonicalBytes: Data(repeating: 0, count: V3RecoveryRegistrationIntent.maximumBytes + 1))
    }
  }

  @Test func validlyEncodedIntentChangesStillFailAuthentication() throws {
    let preparation = try Fixture().prepare()
    let text = String(decoding: preparation.intent.canonicalBytes, as: UTF8.self)
    let changed = text.replacingOccurrences(
      of: preparation.intent.operationID.rawValue,
      with: "018f4d38-7d5a-7b20-b0f1-97d6e96c4400")
    let decoded = try V3RecoveryRegistrationIntent(canonicalBytes: Data(changed.utf8))
    #expect(throws: V3RecoveryRegistrationError.authenticationFailed) {
      try decoded.authenticate(currentVaultKey: Self.oldKey)
    }
    let tag = Base64URL.encode(preparation.intent.authenticationTag)
    let changedTag = text.replacingOccurrences(
      of: tag, with: Base64URL.encode(Data(repeating: 0, count: 32)))
    #expect(throws: V3RecoveryRegistrationError.authenticationFailed) {
      try V3RecoveryRegistrationIntent(canonicalBytes: Data(changedTag.utf8))
        .authenticate(currentVaultKey: Self.oldKey)
    }
  }

  @Test func allOccupiedApplicationObjectsAreRefusedBeforeSigning() throws {
    let fixture = try Fixture()
    let anchor = try fixture.prepare().intent.anchor
    let before = fixture.owner.signatures
    for occupancy in [PIVRecoveryAnchorOccupancy.unrecognized, .recognized(anchor)] {
      #expect(throws: V3RecoveryRegistrationError.occupiedAnchor) {
        try fixture.prepare(occupancy: occupancy)
      }
    }
    #expect(fixture.owner.signatures == before)
    #expect(fixture.owner.unwraps == 0)
  }

  @Test func unsupportedPoliciesAndImportedCredentialsAreRefusedBeforeSigning() throws {
    let fixture = try Fixture()
    let credentials = [
      fixture.metadata(pin: .default), fixture.metadata(pin: .never), fixture.metadata(pin: .once),
      fixture.metadata(touch: .default), fixture.metadata(touch: .never),
      fixture.metadata(touch: .cached),
      fixture.metadata(origin: .imported),
    ]
    for credential in credentials {
      #expect(throws: PIVRecoveryKeyPolicyError.unsupportedPolicy) {
        try fixture.prepare(credential: credential)
      }
    }
    #expect(fixture.owner.signatures == 0)
  }

  @Test func missingExtraOrMismatchedCurrentEntriesCannotBePrepared() throws {
    let fixture = try Fixture()
    var missing = fixture.entries
    missing.removeValue(forKey: try #require(missing.keys.first))
    #expect(throws: V3RecoveryRegistrationError.incompleteSnapshot) {
      try fixture.prepare(entries: missing)
    }
    var extra = fixture.entries
    let first = try #require(fixture.entries.values.first)
    extra[V3EntryObjectKey(entryID: Self.entryID, digest: Data(repeating: 0, count: 32))] =
      first
    #expect(throws: V3RecoveryRegistrationError.incompleteSnapshot) {
      try fixture.prepare(entries: extra)
    }
    let pair = try #require(fixture.entries.first)
    var mismatched = fixture.entries
    let other = try #require(fixture.entries.values.first { $0 != pair.value })
    mismatched[pair.key] = other
    #expect(throws: (any Error).self) { try fixture.prepare(entries: mismatched) }
    #expect(fixture.owner.signatures == 0)
  }

  @Test func wrongParentKeysCheckpointOwnerAndReusedEpochsCannotBePrepared() throws {
    let fixture = try Fixture()
    #expect(throws: (any Error).self) { try fixture.prepare(currentKey: Self.nextKey) }
    #expect(throws: (any Error).self) { try fixture.prepare(nextKey: Self.oldKey) }
    let other = try Owner()
    #expect(throws: V3RecoveryRegistrationError.invalidOwner) { try fixture.prepare(owner: other) }
    #expect(other.signatures == 0)
    #expect(throws: V3RecoveryRegistrationError.invalidCandidate) {
      try fixture.prepare(transition: Self.transitionID)
    }
    #expect(throws: V3RecoveryRegistrationError.invalidCandidate) {
      try fixture.prepare(generation: Self.generationID)
    }
    #expect(throws: V3RecoveryRegistrationError.invalidCredential) {
      try fixture.prepare(
        credential: fixture.metadata(publicKey: fixture.parent.body.epochSigningKey.publicKey))
    }
    #expect(fixture.owner.signatures == 0)
  }

  @Test func preparationBoundsAreCheckedBeforeOwnerSigning() throws {
    let fixture = try Fixture()
    for limits in [
      Fixture.limits(entries: 1), Fixture.limits(entryBytes: 1),
      Fixture.limits(totalBytes: 1), Fixture.limits(manifestBytes: 1),
    ] {
      #expect(throws: (any Error).self) { try fixture.prepare(limits: limits) }
    }
    #expect(fixture.owner.signatures == 0)
  }

  @Test func emptyVaultAndBackupRecipientAdditionHaveCompleteCoverage() throws {
    let empty = try Fixture(empty: true)
    let prepared = try empty.prepare()
    #expect(prepared.stagedEntries.isEmpty && prepared.intent.stagedEntries.isEmpty)
    try empty.validate(prepared)
    let fixture = try Fixture(backup: true)
    let addition = try fixture.prepare()
    let oldRecipient = try #require(fixture.parent.body.recovery.recipients.first)
    #expect(addition.candidate.body.recovery.recipients.contains(oldRecipient))
    #expect(addition.candidate.body.recovery.wrappedKeys.count == 2)
    let duplicate = fixture.metadata(publicKey: fixture.backupToken.publicKey.x963Representation)
    let before = fixture.owner.signatures
    #expect(throws: V3RecoveryRegistrationError.invalidCredential) {
      try fixture.prepare(credential: duplicate)
    }
    #expect(fixture.owner.signatures == before)
    if #available(macOS 26.0, *) {
      let wrapper = try #require(
        addition.candidate.body.recovery.wrappedKeys.first {
          $0.recipientID == oldRecipient.recipientID
        })
      let receiver = try PIVHPKEReceiver(publicBytes: oldRecipient.publicKey) {
        try fixture.backupToken.sharedSecretFromKeyAgreement(
          with: P256.KeyAgreement.PublicKey(x963Representation: $0)
        ).withUnsafeBytes { Data($0) }
      }
      #expect(
        try V3RecoveryVaultKeyHPKE().unwrap(
          wrapper, recipientPrivateKey: receiver,
          context: V3RecoveryHPKEContext(
            vaultID: Self.vaultID, keyID: addition.candidate.body.fields.keyID,
            authorityTransitionID: addition.candidate.body.fields.authorityTransitionID,
            recoveryGenerationID: addition.candidate.body.recovery.generationID,
            recipient: oldRecipient)) == Self.nextKey)
    }
  }

  @Test func completionUsesExactlyOneAgreementAndFreshLocalWrapperOpening() throws {
    guard #available(macOS 26.0, *) else { return }
    let fixture = try Fixture(backup: true)
    let preparation = try fixture.prepare()
    let count = Counter()
    try fixture.complete(preparation, receiver: fixture.receiver(count: count))
    #expect(count.value == 1)
    #expect(fixture.owner.unwraps == 1)
    #expect(fixture.owner.signatures == 1)
  }

  @Test func completionRechecksIntentCheckpointCredentialAndAnchorBeforePrivateOperations() throws {
    guard #available(macOS 26.0, *) else { return }
    let fixture = try Fixture()
    let preparation = try fixture.prepare()
    let count = Counter()
    let otherAnchor = try V3RecoveryAnchor(
      floor: preparation.intent.anchor.floor,
      recipientID: preparation.intent.anchor.recipientID,
      registrationID: UUID().uuidString.lowercased(), slot: .keyManagement)
    #expect(throws: V3RecoveryRegistrationError.anchorMismatch) {
      try fixture.complete(
        preparation, anchor: otherAnchor, receiver: fixture.receiver(count: count))
    }
    #expect(throws: PIVRecoveryKeyPolicyError.unsupportedPolicy) {
      try fixture.complete(
        preparation, credential: fixture.metadata(touch: .cached),
        receiver: fixture.receiver(count: count))
    }
    let checkpoint = try V3ManifestCheckpoint(
      vaultID: Self.vaultID, envelopeDigest: Data(repeating: 0, count: 32))
    #expect(throws: V3RecoveryRegistrationError.invalidParent) {
      try fixture.complete(
        preparation, checkpoint: checkpoint, receiver: fixture.receiver(count: count))
    }
    #expect(throws: V3RecoveryRegistrationError.authenticationFailed) {
      try fixture.complete(
        preparation, currentKey: Self.nextKey, receiver: fixture.receiver(count: count))
    }
    #expect(fixture.owner.unwraps == 0 && count.value == 0)
  }

  @Test func changedCandidateOrStagingIsRejectedBeforePrivateOperations() throws {
    guard #available(macOS 26.0, *) else { return }
    let fixture = try Fixture()
    let prepared = try fixture.prepare()
    let another = try fixture.prepare()
    let count = Counter()
    for input in [
      V3RecoveryRegistrationPreparation(
        intent: prepared.intent, candidate: another.candidate, stagedEntries: prepared.stagedEntries
      ),
      V3RecoveryRegistrationPreparation(
        intent: prepared.intent, candidate: prepared.candidate, stagedEntries: another.stagedEntries
      ),
      V3RecoveryRegistrationPreparation(
        intent: prepared.intent, candidate: prepared.candidate, stagedEntries: []),
    ] {
      #expect(throws: V3RecoveryRegistrationError.invalidCandidate) {
        try fixture.complete(input, receiver: fixture.receiver(count: count))
      }
    }
    #expect(fixture.owner.unwraps == 0 && count.value == 0)
  }

  @Test func currentSourceMismatchIsRejectedBeforeHardwareAgreement() throws {
    guard #available(macOS 26.0, *) else { return }
    let fixture = try Fixture()
    let preparation = try fixture.prepare()
    let count = Counter()
    #expect(throws: V3RecoveryRegistrationError.incompleteSnapshot) {
      try fixture.complete(preparation, entries: [:], receiver: fixture.receiver(count: count))
    }
    #expect(count.value == 0)
  }

  @Test func independentlyChecksResealedPlaintextBytesBeforeHardwareAgreement() throws {
    guard #available(macOS 26.0, *) else { return }
    let fixture = try Fixture()
    let preparation = try fixture.prepare()
    // The intent, MAC and both signatures are consistent software fixtures.
    // Only a full old/new plaintext comparison detects this content mismatch.
    // Swift String equality treats these Unicode spellings as equivalent;
    // registration must preserve their original UTF-8 bytes instead.
    let changed = try fixture.changingSecret(
      preparation, to: "Software fixture secret é\r\n")
    let count = Counter()
    #expect(throws: V3RecoveryRegistrationError.invalidEntry) {
      try fixture.complete(changed, receiver: fixture.receiver(count: count))
    }
    #expect(count.value == 0)
  }

  @Test func differentCredentialOrReceiverIsRejectedWithoutAuthentication() throws {
    guard #available(macOS 26.0, *) else { return }
    let fixture = try Fixture()
    let preparation = try fixture.prepare()
    let count = Counter()
    let otherPoint = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
    let otherReceiver = try PIVHPKEReceiver(publicBytes: otherPoint) { _ in
      count.increment()
      return Data(repeating: 0, count: 32)
    }
    #expect(throws: V3RecoveryRegistrationError.anchorMismatch) {
      try fixture.complete(preparation, receiver: otherReceiver)
    }
    #expect(throws: V3RecoveryRegistrationError.anchorMismatch) {
      try fixture.complete(
        preparation, credential: fixture.metadata(publicKey: otherPoint),
        receiver: fixture.receiver(count: count))
    }
    #expect(fixture.owner.unwraps == 0 && count.value == 0)
  }

  @Test func signingLocalAuthenticationAndHardwareCancellationAreNeverRetried() throws {
    let fixture = try Fixture()
    fixture.owner.cancelSigning = true
    #expect(throws: FixtureError.cancelled) { try fixture.prepare() }
    #expect(fixture.owner.signatures == 1)
    fixture.owner.cancelSigning = false
    let preparation = try fixture.prepare()
    guard #available(macOS 26.0, *) else { return }
    let count = Counter()
    fixture.owner.cancelUnwrap = true
    #expect(throws: FixtureError.cancelled) {
      try fixture.complete(preparation, receiver: fixture.receiver(count: count))
    }
    #expect(fixture.owner.unwraps == 1 && count.value == 0)
    fixture.owner.cancelUnwrap = false
    let receiver = try PIVHPKEReceiver(publicBytes: fixture.credential.publicKey) { _ in
      count.increment()
      throw FixtureError.cancelled
    }
    #expect(throws: FixtureError.cancelled) {
      try fixture.complete(preparation, receiver: receiver)
    }
    #expect(count.value == 1)
  }

  @Test func unexpectedAgreementResultsAreNotGivenAnotherEpochOrRecipient() throws {
    guard #available(macOS 26.0, *) else { return }
    let fixture = try Fixture(backup: true)
    let preparation = try fixture.prepare()
    let count = Counter()
    let receiver = try PIVHPKEReceiver(publicBytes: fixture.credential.publicKey) { _ in
      count.increment()
      return Data(repeating: 0, count: 32)
    }
    #expect(throws: (any Error).self) { try fixture.complete(preparation, receiver: receiver) }
    #expect(count.value == 1)
  }

  @Test func reloadedPendingIntentRequiresAFreshPossessionOperation() throws {
    guard #available(macOS 26.0, *) else { return }
    let fixture = try Fixture()
    let preparation = try fixture.prepare()
    let count = Counter()
    try fixture.complete(preparation, receiver: fixture.receiver(count: count))
    let reloaded = V3RecoveryRegistrationPreparation(
      intent: try V3RecoveryRegistrationIntent(canonicalBytes: preparation.intent.canonicalBytes),
      candidate: try V3RecoveryManifestCodec().parseEnvelope(preparation.candidate.canonicalBytes),
      stagedEntries: try preparation.stagedEntries.map {
        try V3EntryCipher().parse($0.canonicalBytes)
      })
    #expect(reloaded == preparation)
    try fixture.complete(reloaded, receiver: fixture.receiver(count: count))
    #expect(count.value == 2 && fixture.owner.unwraps == 2)
  }

  private enum FixtureError: Error { case cancelled }

  private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    var value: Int { lock.withLock { count } }
    func increment() { lock.withLock { count += 1 } }
  }

  private final class Owner: V3EnrollmentMessageSigning, V3DeviceWrappedVaultKeyUnwrapping,
    @unchecked Sendable
  {
    let vaultID = V3RecoveryRegistrationTests.vaultID
    let signingKey = P256.Signing.PrivateKey()
    let wrappingKey = P256.KeyAgreement.PrivateKey()
    let publicIdentity: V3EnrollmentDeviceIdentity
    private let lock = NSLock()
    private var signed = 0
    private var unwrapped = 0
    var cancelSigning = false
    var cancelUnwrap = false
    var signatures: Int { lock.withLock { signed } }
    var unwraps: Int { lock.withLock { unwrapped } }
    init() throws {
      publicIdentity = try V3EnrollmentDeviceIdentity(
        displayName: "Software Mac fixture",
        signingPublicKey: signingKey.publicKey.x963Representation,
        wrappingPublicKey: wrappingKey.publicKey.x963Representation)
    }
    func signature(for input: Data, reason _: String) throws -> Data {
      lock.withLock { signed += 1 }
      if cancelSigning { throw FixtureError.cancelled }
      return try signingKey.signature(for: input).rawRepresentation
    }
    func unwrapDeviceWrappedVaultKey(
      _ wrappedKey: V3HPKEWrappedVaultKey, context: V3VaultKeyHPKEContext, reason _: String
    ) throws -> Data {
      lock.withLock { unwrapped += 1 }
      if cancelUnwrap { throw FixtureError.cancelled }
      return try V3VaultKeyHPKE().unwrap(
        wrappedKey, recipientPrivateKey: wrappingKey, context: context)
    }
  }

  private struct Fixture {
    let owner: Owner
    let token = P256.KeyAgreement.PrivateKey()
    let backupToken = P256.KeyAgreement.PrivateKey()
    let parent: V3RecoveryManifestEnvelope
    let checkpoint: V3ManifestCheckpoint
    let entries: [V3EntryObjectKey: V3EncryptedEntry]
    var credential: PIVRecoveryKeyMetadata { metadata() }

    init(empty: Bool = false, backup: Bool = false) throws {
      owner = try Owner()
      let keyID = try V3VaultKeyID.derive(
        vaultKey: V3RecoveryRegistrationTests.oldKey, vaultID: V3RecoveryRegistrationTests.vaultID)
      let sealed =
        try empty
        ? []
        : [
          V3EntryCipher().seal(
            "Software fixture secret e\u{301}\r\n",
            context: V3EntryAuthenticationContext(
              vaultID: V3RecoveryRegistrationTests.vaultID,
              entryID: V3RecoveryRegistrationTests.entryID,
              name: "fixture/secret", type: .secret, keyID: keyID, revision: 4),
            vaultKey: V3RecoveryRegistrationTests.oldKey),
          V3EntryCipher().seal(
            "JBSWY3DPEHPK3PXP",
            context: V3EntryAuthenticationContext(
              vaultID: V3RecoveryRegistrationTests.vaultID,
              entryID: V3RecoveryRegistrationTests.totpID,
              name: "fixture/totp", type: .totp, keyID: keyID, revision: 2),
            vaultKey: V3RecoveryRegistrationTests.oldKey),
        ]
      entries = Dictionary(
        uniqueKeysWithValues: try sealed.map {
          (try Self.address(V3ResealedEntry(encryptedEntry: $0).manifestEntry), $0)
        })
      let fields = try V3DeviceWrappedManifestFields(
        vaultID: V3RecoveryRegistrationTests.vaultID, keyID: keyID,
        authorityTransitionID: V3RecoveryRegistrationTests.transitionID,
        devices: [.init(identity: owner.publicIdentity, status: .active)],
        wrappedKeys: [
          V3DeviceWrappedManifestKey(
            recipientDeviceID: owner.publicIdentity.deviceID,
            wrappedKey: V3VaultKeyHPKE().wrap(
              vaultKey: V3RecoveryRegistrationTests.oldKey,
              recipientPublicKey: owner.publicIdentity.wrappingPublicKey,
              context: V3VaultKeyHPKEContext(
                vaultID: V3RecoveryRegistrationTests.vaultID, keyID: keyID,
                authorityTransitionID: V3RecoveryRegistrationTests.transitionID,
                recipientDeviceID: owner.publicIdentity.deviceID, wrappingProfile: .recovery)))
        ], entries: sealed.map { V3ResealedEntry(encryptedEntry: $0).manifestEntry })
      let recipient = try V3RecoveryRecipient(
        registrationID: UUID().uuidString.lowercased(),
        publicKey: backupToken.publicKey.x963Representation,
        slot: .keyManagement, status: .active)
      let roster = try V3RecoveryRoster(
        generationID: V3RecoveryRegistrationTests.generationID,
        recipients: backup ? [recipient] : [],
        wrappedKeys: backup
          ? [
            V3RecoveryVaultKeyHPKE().wrap(
              vaultKey: V3RecoveryRegistrationTests.oldKey,
              context: V3RecoveryHPKEContext(
                vaultID: V3RecoveryRegistrationTests.vaultID, keyID: keyID,
                authorityTransitionID: V3RecoveryRegistrationTests.transitionID,
                recoveryGenerationID: V3RecoveryRegistrationTests.generationID, recipient: recipient
              ))
          ] : [])
      parent = try V3RecoveryEpochBoundary().encode(
        body: V3RecoveryManifestBody(
          fields: fields,
          epochSigningKey: V3EpochSigningKeyCipher().prepare(
            context: V3EpochSigningKeyContext(
              vaultID: V3RecoveryRegistrationTests.vaultID, keyID: keyID,
              authorityTransitionID: V3RecoveryRegistrationTests.transitionID),
            vaultKey: V3RecoveryRegistrationTests.oldKey), transitionProof: nil, recovery: roster),
        parents: [], vaultKey: V3RecoveryRegistrationTests.oldKey, authorizations: [])
      checkpoint = try V3ManifestCheckpoint(
        vaultID: V3RecoveryRegistrationTests.vaultID, envelopeDigest: parent.digest)
    }

    func metadata(
      pin: PIVRecoveryKeyMetadata.PINPolicy = .always,
      touch: PIVRecoveryKeyMetadata.TouchPolicy = .always,
      origin: PIVRecoveryKeyMetadata.Origin = .generated, publicKey: Data? = nil
    ) -> PIVRecoveryKeyMetadata {
      PIVRecoveryKeyMetadata(
        publicKey: publicKey ?? token.publicKey.x963Representation,
        pinPolicy: pin, touchPolicy: touch, origin: origin)
    }

    func prepare(
      occupancy: PIVRecoveryAnchorOccupancy = .absent, credential: PIVRecoveryKeyMetadata? = nil,
      entries: [V3EntryObjectKey: V3EncryptedEntry]? = nil,
      currentKey: Data = V3RecoveryRegistrationTests.oldKey,
      nextKey: Data = V3RecoveryRegistrationTests.nextKey, owner: Owner? = nil,
      transition: String = UUID().uuidString.lowercased(),
      generation: String = UUID().uuidString.lowercased(),
      limits: V3ManifestRepositoryLimits = .standard
    ) throws -> V3RecoveryRegistrationPreparation {
      try V3RecoveryRegistrationBuilder(limits: limits).prepare(
        checkpoint: checkpoint, parent: parent, currentEntries: entries ?? self.entries,
        currentVaultKey: currentKey, nextVaultKey: nextKey,
        credential: credential ?? self.credential,
        occupancy: occupancy, owner: owner ?? self.owner, reason: "Software registration fixture",
        authorityTransitionID: transition, generationID: generation)
    }

    func validate(_ preparation: V3RecoveryRegistrationPreparation) throws {
      try V3RecoveryRegistrationValidator().validate(
        preparation, checkpoint: checkpoint, parent: parent, currentEntries: entries,
        currentVaultKey: V3RecoveryRegistrationTests.oldKey,
        nextVaultKey: V3RecoveryRegistrationTests.nextKey,
        expectedOwner: owner.publicIdentity)
    }

    func changingSecret(
      _ preparation: V3RecoveryRegistrationPreparation, to plaintext: String
    ) throws -> V3RecoveryRegistrationPreparation {
      let old = preparation.candidate.body
      let context = try #require(
        preparation.stagedEntries.first {
          $0.context.entryID == V3RecoveryRegistrationTests.entryID
        }
      ).context
      let changed = try V3EntryCipher().seal(
        plaintext, context: context, vaultKey: V3RecoveryRegistrationTests.nextKey)
      let staged = preparation.stagedEntries.map {
        $0.context.entryID == context.entryID ? changed : $0
      }
      let fields = try V3DeviceWrappedManifestFields(
        vaultID: old.fields.vaultID, keyID: old.fields.keyID,
        authorityTransitionID: old.fields.authorityTransitionID, devices: old.fields.devices,
        wrappedKeys: old.fields.wrappedKeys,
        entries: staged.map { V3ResealedEntry(encryptedEntry: $0).manifestEntry })
      let candidate = try V3RecoveryEpochBoundary().authorize(
        candidate: V3RecoveryManifestBody(
          fields: fields, epochSigningKey: old.epochSigningKey, transitionProof: nil,
          recovery: old.recovery), parent: parent,
        currentVaultKey: V3RecoveryRegistrationTests.oldKey,
        nextVaultKey: V3RecoveryRegistrationTests.nextKey, signer: owner,
        reason: "Software content comparison fixture")
      let anchor = try V3RecoveryAnchor(
        floor: V3VaultHead(vaultID: old.fields.vaultID, envelopeDigest: candidate.digest),
        recipientID: preparation.intent.anchor.recipientID,
        registrationID: preparation.intent.anchor.registrationID, slot: .keyManagement)
      let addresses = try staged.map {
        V3ImmutableTransactionRecoveryEntry(
          entryID: $0.context.entryID,
          digest: try #require(Base64URL.decodeCanonical($0.ciphertextDigest)))
      }.sorted { $0.entryID < $1.entryID }
      let intent = try V3RecoveryRegistrationIntent(
        operationID: preparation.intent.operationID, expectedCheckpoint: checkpoint,
        ownerDeviceID: owner.publicIdentity.deviceID, publicKey: preparation.intent.publicKey,
        anchor: anchor, stagedEntries: addresses,
        currentVaultKey: V3RecoveryRegistrationTests.oldKey)
      return V3RecoveryRegistrationPreparation(
        intent: intent, candidate: candidate, stagedEntries: staged)
    }

    @available(macOS 26.0, *)
    func complete(
      _ preparation: V3RecoveryRegistrationPreparation, anchor: V3RecoveryAnchor? = nil,
      credential: PIVRecoveryKeyMetadata? = nil, checkpoint: V3ManifestCheckpoint? = nil,
      entries: [V3EntryObjectKey: V3EncryptedEntry]? = nil,
      currentKey: Data = V3RecoveryRegistrationTests.oldKey, receiver: PIVHPKEReceiver
    ) throws {
      try V3RecoveryRegistrationValidator().verifyForCompletion(
        preparation, checkpoint: checkpoint ?? self.checkpoint, parent: parent,
        currentEntries: entries ?? self.entries, currentVaultKey: currentKey, identity: owner,
        credential: credential ?? self.credential,
        installedAnchor: anchor ?? preparation.intent.anchor,
        receiver: receiver, reason: "Software completion fixture")
    }

    @available(macOS 26.0, *)
    func receiver(count: Counter) throws -> PIVHPKEReceiver {
      try PIVHPKEReceiver(publicBytes: credential.publicKey) { peer in
        count.increment()
        return try token.sharedSecretFromKeyAgreement(
          with: P256.KeyAgreement.PublicKey(x963Representation: peer)
        ).withUnsafeBytes { Data($0) }
      }
    }

    static func address(_ entry: V3ManifestEntry) throws -> V3EntryObjectKey {
      V3EntryObjectKey(
        entryID: entry.entryID,
        digest: try #require(Base64URL.decodeCanonical(entry.ciphertextDigest)))
    }

    static func limits(
      entries: Int = 16_384, entryBytes: Int = 16 * 1_024 * 1_024,
      totalBytes: Int = 256 * 1_024 * 1_024, manifestBytes: Int = 2 * 1_024 * 1_024
    ) -> V3ManifestRepositoryLimits {
      V3ManifestRepositoryLimits(
        maximumManifestObjects: 4_096, maximumHistoryDepth: 1_024,
        maximumReferencedEntryObjects: entries, maximumManifestBytes: manifestBytes,
        maximumEntryBytes: min(entryBytes, totalBytes),
        maximumTotalManifestBytes: 64 * 1_024 * 1_024,
        maximumTotalEntryBytes: totalBytes)
    }
  }
}
