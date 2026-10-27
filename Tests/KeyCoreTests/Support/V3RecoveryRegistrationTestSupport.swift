import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Software credentials and registration source data; no native authentication or token access.
enum V3RecoveryRegistrationTestSupport {
  static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
  static let transitionID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
  static let generationID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b5"
  static let entryID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b6"
  static let totpID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b7"
  static let oldKey = Data(0..<32)
  static let nextKey = Data(32..<64)

  enum FixtureError: Error { case cancelled }

  final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    var value: Int { lock.withLock { count } }
    func increment() { lock.withLock { count += 1 } }
  }

  final class Owner: V3EnrollmentMessageSigning, V3DeviceWrappedVaultKeyUnwrapping,
    @unchecked Sendable
  {
    let vaultID = V3RecoveryRegistrationTestSupport.vaultID
    let signingKey = P256.Signing.PrivateKey()
    let wrappingKey = P256.KeyAgreement.PrivateKey()
    let publicIdentity: V3EnrollmentDeviceIdentity
    private let lock = NSLock()
    private var signed = 0
    private var unwrapped = 0
    var cancelSigning = false
    var cancelUnwrap = false
    var onUnwrap: @Sendable () throws -> Void = {}
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
      try onUnwrap()
      if cancelUnwrap { throw FixtureError.cancelled }
      return try V3VaultKeyHPKE().unwrap(
        wrappedKey, recipientPrivateKey: wrappingKey, context: context)
    }
  }

  struct Fixture: Sendable {
    let owner: Owner
    let token = P256.KeyAgreement.PrivateKey()
    let backupToken = P256.KeyAgreement.PrivateKey()
    let parent: V3RecoveryManifestEnvelope
    let checkpoint: V3ManifestCheckpoint
    let entries: [V3EntryObjectKey: V3EncryptedEntry]
    var credential: PIVRecoveryKeyMetadata { metadata() }

    init(empty: Bool = false, backup: Bool = false, secretRevision: UInt64 = 4) throws {
      owner = try Owner()
      let keyID = try V3VaultKeyID.derive(
        vaultKey: V3RecoveryRegistrationTestSupport.oldKey, vaultID: V3RecoveryRegistrationTestSupport.vaultID)
      let sealed =
        try empty
        ? []
        : [
          V3EntryCipher().seal(
            "Software fixture secret e\u{301}\r\n",
            context: V3EntryAuthenticationContext(
              vaultID: V3RecoveryRegistrationTestSupport.vaultID,
              entryID: V3RecoveryRegistrationTestSupport.entryID,
              name: "fixture/secret", type: .secret, keyID: keyID, revision: secretRevision),
            vaultKey: V3RecoveryRegistrationTestSupport.oldKey),
          V3EntryCipher().seal(
            "JBSWY3DPEHPK3PXP",
            context: V3EntryAuthenticationContext(
              vaultID: V3RecoveryRegistrationTestSupport.vaultID,
              entryID: V3RecoveryRegistrationTestSupport.totpID,
              name: "fixture/totp", type: .totp, keyID: keyID, revision: 2),
            vaultKey: V3RecoveryRegistrationTestSupport.oldKey),
        ]
      entries = Dictionary(
        uniqueKeysWithValues: try sealed.map {
          (try Self.address(V3ResealedEntry(encryptedEntry: $0).manifestEntry), $0)
        })
      let fields = try V3DeviceWrappedManifestFields(
        vaultID: V3RecoveryRegistrationTestSupport.vaultID, keyID: keyID,
        authorityTransitionID: V3RecoveryRegistrationTestSupport.transitionID,
        devices: [.init(identity: owner.publicIdentity, status: .active)],
        wrappedKeys: [
          V3DeviceWrappedManifestKey(
            recipientDeviceID: owner.publicIdentity.deviceID,
            wrappedKey: V3VaultKeyHPKE().wrap(
              vaultKey: V3RecoveryRegistrationTestSupport.oldKey,
              recipientPublicKey: owner.publicIdentity.wrappingPublicKey,
              context: V3VaultKeyHPKEContext(
                vaultID: V3RecoveryRegistrationTestSupport.vaultID, keyID: keyID,
                authorityTransitionID: V3RecoveryRegistrationTestSupport.transitionID,
                recipientDeviceID: owner.publicIdentity.deviceID, wrappingProfile: .recovery)))
        ], entries: sealed.map { V3ResealedEntry(encryptedEntry: $0).manifestEntry })
      let recipient = try V3RecoveryRecipient(
        registrationID: UUID().uuidString.lowercased(),
        publicKey: backupToken.publicKey.x963Representation,
        slot: .keyManagement, status: .active)
      let roster = try V3RecoveryRoster(
        generationID: V3RecoveryRegistrationTestSupport.generationID,
        recipients: backup ? [recipient] : [],
        wrappedKeys: backup
          ? [
            V3RecoveryVaultKeyHPKE().wrap(
              vaultKey: V3RecoveryRegistrationTestSupport.oldKey,
              context: V3RecoveryHPKEContext(
                vaultID: V3RecoveryRegistrationTestSupport.vaultID, keyID: keyID,
                authorityTransitionID: V3RecoveryRegistrationTestSupport.transitionID,
                recoveryGenerationID: V3RecoveryRegistrationTestSupport.generationID, recipient: recipient
              ))
          ] : [])
      parent = try V3RecoveryEpochBoundary().encode(
        body: V3RecoveryManifestBody(
          fields: fields,
          epochSigningKey: V3EpochSigningKeyCipher().prepare(
            context: V3EpochSigningKeyContext(
              vaultID: V3RecoveryRegistrationTestSupport.vaultID, keyID: keyID,
              authorityTransitionID: V3RecoveryRegistrationTestSupport.transitionID),
            vaultKey: V3RecoveryRegistrationTestSupport.oldKey), transitionProof: nil, recovery: roster),
        parents: [], vaultKey: V3RecoveryRegistrationTestSupport.oldKey, authorizations: [])
      checkpoint = try V3ManifestCheckpoint(
        vaultID: V3RecoveryRegistrationTestSupport.vaultID, envelopeDigest: parent.digest)
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
      currentKey: Data = V3RecoveryRegistrationTestSupport.oldKey,
      nextKey: Data = V3RecoveryRegistrationTestSupport.nextKey, owner: Owner? = nil,
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
        currentVaultKey: V3RecoveryRegistrationTestSupport.oldKey,
        nextVaultKey: V3RecoveryRegistrationTestSupport.nextKey,
        expectedOwner: owner.publicIdentity)
    }

    func stage(
      _ preparation: V3RecoveryRegistrationPreparation, journal: V3RecoveryRegistrationJournal
    ) throws -> Data {
      try journal.stageAndExport(
        preparation, checkpoint: checkpoint, parent: parent, currentEntries: entries,
        currentVaultKey: V3RecoveryRegistrationTestSupport.oldKey,
        nextVaultKey: V3RecoveryRegistrationTestSupport.nextKey,
        expectedOwner: owner.publicIdentity)
    }

    func resume(
      journal: V3RecoveryRegistrationJournal, checkpoint: V3ManifestCheckpoint? = nil,
      entries: [V3EntryObjectKey: V3EncryptedEntry]? = nil,
      currentKey: Data = V3RecoveryRegistrationTestSupport.oldKey,
      nextKey: Data = V3RecoveryRegistrationTestSupport.nextKey, owner: V3EnrollmentDeviceIdentity? = nil
    ) throws -> Data {
      try journal.resumeAndExport(
        checkpoint: checkpoint ?? self.checkpoint, parent: parent,
        currentEntries: entries ?? self.entries,
        currentVaultKey: currentKey, nextVaultKey: nextKey,
        expectedOwner: owner ?? self.owner.publicIdentity)
    }

    func changingSecret(
      _ preparation: V3RecoveryRegistrationPreparation, to plaintext: String
    ) throws -> V3RecoveryRegistrationPreparation {
      let old = preparation.candidate.body
      let context = try #require(
        preparation.stagedEntries.first {
          $0.context.entryID == V3RecoveryRegistrationTestSupport.entryID
        }
      ).context
      let changed = try V3EntryCipher().seal(
        plaintext, context: context, vaultKey: V3RecoveryRegistrationTestSupport.nextKey)
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
        currentVaultKey: V3RecoveryRegistrationTestSupport.oldKey,
        nextVaultKey: V3RecoveryRegistrationTestSupport.nextKey, signer: owner,
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
        currentVaultKey: V3RecoveryRegistrationTestSupport.oldKey)
      return V3RecoveryRegistrationPreparation(
        intent: intent, candidate: candidate, stagedEntries: staged)
    }

    @available(macOS 26.0, *)
    func complete(
      _ preparation: V3RecoveryRegistrationPreparation, anchor: V3RecoveryAnchor? = nil,
      credential: PIVRecoveryKeyMetadata? = nil, checkpoint: V3ManifestCheckpoint? = nil,
      entries: [V3EntryObjectKey: V3EncryptedEntry]? = nil,
      currentKey: Data = V3RecoveryRegistrationTestSupport.oldKey, receiver: PIVHPKEReceiver
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
