import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

/// Production migration construction/validation on software authority and
/// disposable storage. No real vault, native authentication or token is used.
struct V3RecoveryProfileAdoptionTests {
  private typealias Core = V3RecoveryRegistrationTests

  @Test func adoptionPreservesTheCompleteSnapshotAndDeviceRoster() throws {
    let f = try Fixture()
    let candidate = try f.build()
    try f.validate(candidate)
    #expect(candidate.expectedCheckpoint == f.base.checkpoint)
    #expect(candidate.envelope.parents == [f.base.checkpoint.envelopeDigest])
    #expect(candidate.envelope.body.fields.devices == f.base.envelope.body.devices)
    #expect(candidate.envelope.body.fields.keyID != f.base.envelope.body.keyID)
    #expect(candidate.envelope.body.transitionProof == nil)
    #expect(candidate.envelope.body.recovery.recipients.isEmpty)
    #expect(candidate.envelope.body.recovery.wrappedKeys.isEmpty)
    #expect(f.owner.signatures == 1 && f.owner.unwraps == 0)
    for device in [f.owner, f.member] {
      let local = try #require(
        candidate.envelope.body.fields.wrappedKeys.first {
          $0.recipientDeviceID == device.publicIdentity.deviceID
        })
      let context = try candidate.envelope.body.deviceContext(
        recipientDeviceID: device.publicIdentity.deviceID)
      #expect(
        try V3VaultKeyHPKE().unwrap(
          local.wrappedKey, recipientPrivateKey: device.wrappingKey, context: context)
          == Core.nextKey)
      let oldContext = try V3VaultKeyHPKEContext(
        vaultID: Core.vaultID, keyID: candidate.envelope.body.fields.keyID,
        authorityTransitionID: candidate.envelope.body.fields.authorityTransitionID,
        recipientDeviceID: device.publicIdentity.deviceID)
      #expect(throws: (any Error).self) {
        try V3VaultKeyHPKE().unwrap(
          local.wrappedKey, recipientPrivateKey: device.wrappingKey, context: oldContext)
      }
    }
    #expect(
      !candidate.envelope.body.fields.wrappedKeys.contains {
        $0.recipientDeviceID == f.revoked.publicIdentity.deviceID
      })
    for (old, new) in zip(f.base.envelope.body.entries, candidate.envelope.body.fields.entries) {
      #expect(old.entryID == new.entryID && old.name == new.name && old.type == new.type)
      #expect(old.revision == new.revision && old.ciphertextDigest != new.ciphertextDigest)
    }
    try f.validateForPublication(candidate)
    #expect(f.owner.unwraps == 1)
    #expect(throws: (any Error).self) { try f.validate(candidate, nextKey: Core.oldKey) }
    let text = String(decoding: candidate.envelope.canonicalBytes, as: UTF8.self)
    #expect(!text.contains("Adoption fixture secret") && !text.contains("JBSWY3DPEHPK3PXP"))
    #expect(!text.contains(Base64URL.encode(Core.oldKey)))
    #expect(!text.contains(Base64URL.encode(Core.nextKey)))
  }

  @Test func emptyVaultAdoptsWithoutClaimingRecoveryProtection() throws {
    let f = try Fixture(empty: true)
    let candidate = try f.build()
    try f.validateForPublication(candidate)
    #expect(candidate.stagedEntries.isEmpty && candidate.envelope.body.recovery.recipients.isEmpty)
  }

  @Test func adoptedSnapshotIsAcceptedAsTheParentOfFirstRegistration() throws {
    let f = try Fixture()
    let adoption = try f.build()
    let credential = try Core.Fixture().credential
    let registration = try V3RecoveryRegistrationBuilder().prepare(
      checkpoint: V3ManifestCheckpoint(
        vaultID: Core.vaultID, envelopeDigest: adoption.envelope.digest),
      parent: adoption.envelope,
      currentEntries: V3EntrySnapshotValidator(limits: .standard).entryMap(adoption.stagedEntries),
      currentVaultKey: Core.nextKey, nextVaultKey: Data(repeating: 0x71, count: 32),
      credential: credential, occupancy: .absent, owner: f.owner,
      reason: "Register software fixture")
    #expect(registration.candidate.body.recovery.recipients.count == 1)
    #expect(registration.candidate.body.transitionProof != nil)
    #expect(registration.intent.anchor.floor.envelopeDigest == registration.candidate.digest)
  }

  @Test func exactPublishedAdoptionMakesTheShippingDiscoveryRequireUpgrade() throws {
    let f = try Fixture()
    let candidate = try f.build()
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let store = V3FilesystemTransactionArtifactStore(
      rootHandle: try VaultRootDirectoryHandle(opening: root))
    let operation = VaultTransactionOperationID()
    try store.stageManifest(
      candidate.envelope.canonicalBytes, digest: candidate.envelope.digest,
      operationID: operation)
    try store.publishStagedManifest(
      candidate.envelope.canonicalBytes,
      digest: candidate.envelope.digest, operationID: operation)
    let discovery = V3DeviceWrappedKeyTransitionDiscovery(source: store)
    #expect(throws: V3DeviceWrappedUnlockError.unsupportedProfileVersion(3)) {
      try V3DeviceWrappedManifestEnvelopeCodec().parse(candidate.envelope.canonicalBytes)
    }
    for allowStale in [true, false] {
      #expect(throws: V3DeviceWrappedCatchUpError.upgradeRequired) {
        try V3DeviceWrappedCatchUpAccessGate().requireCurrent(allowStale: allowStale) {
          _ = try discovery.discover(from: f.base, currentVaultKey: Core.oldKey)
          throw Core.FixtureError.cancelled
        }
      }
    }
    #expect(f.owner.unwraps == 0)
  }

  @Test(arguments: 0..<7)
  func invalidPreparationIsRefusedBeforeSigning(variant: Int) throws {
    let f = try Fixture()
    let outsider = try Core.Owner()
    let currentEntries = variant == 3 ? [:] : f.entries
    #expect(throws: (any Error).self) {
      try V3RecoveryProfileAdoptionBuilder().build(
        from: f.base, currentEntries: currentEntries,
        currentVaultKey: variant == 0 ? Core.nextKey : Core.oldKey,
        nextVaultKey: variant == 1 ? Core.oldKey : Core.nextKey,
        owner: variant == 4 ? outsider : f.owner, reason: variant == 2 ? "" : "Adopt fixture",
        authorityTransitionID: variant == 5
          ? f.base.envelope.body.authorityTransitionID
          : "018f4d38-7d5a-7b20-b0f1-97d6e96c84b5",
        generationID: variant == 6 ? "invalid" : "018f4d38-7d5a-7b20-b0f1-97d6e96c84b6")
    }
    #expect(f.owner.signatures == 0 && outsider.signatures == 0 && f.owner.unwraps == 0)
  }

  @Test func snapshotAndManifestLimitsPrecedeSigning() throws {
    for limits in [
      V3ManifestRepositoryLimits(
        maximumManifestObjects: 10, maximumHistoryDepth: 10,
        maximumReferencedEntryObjects: 1),
      V3ManifestRepositoryLimits(
        maximumManifestObjects: 10, maximumHistoryDepth: 10,
        maximumManifestBytes: 4_096),
    ] {
      let f = try Fixture()
      #expect(throws: (any Error).self) { try f.build(limits: limits) }
      #expect(f.owner.signatures == 0 && f.owner.unwraps == 0)
    }
  }

  @Test func wrongCheckpointAndIncompleteCandidateNeverReachLocalUnwrap() throws {
    let f = try Fixture()
    let candidate = try f.build()
    let changed = V3RecoveryProfileAdoptionCandidate(
      expectedCheckpoint: try V3ManifestCheckpoint(
        vaultID: Core.vaultID,
        envelopeDigest: Data(repeating: 0x92, count: 32)),
      envelope: candidate.envelope, stagedEntries: candidate.stagedEntries)
    #expect(throws: (any Error).self) { try f.validateForPublication(changed) }
    let missing = V3RecoveryProfileAdoptionCandidate(
      expectedCheckpoint: candidate.expectedCheckpoint,
      envelope: candidate.envelope, stagedEntries: Array(candidate.stagedEntries.dropFirst()))
    #expect(throws: (any Error).self) { try f.validateForPublication(missing) }
    #expect(f.owner.unwraps == 0)
  }

  @Test func duplicateStagedEntriesAndWrongAddressesAreRefused() throws {
    let f = try Fixture()
    let candidate = try f.build()
    let extra = V3RecoveryProfileAdoptionCandidate(
      expectedCheckpoint: candidate.expectedCheckpoint,
      envelope: candidate.envelope,
      stagedEntries: candidate.stagedEntries + [try #require(candidate.stagedEntries.first)])
    #expect(throws: V3EntrySnapshotValidationError.incompleteSnapshot) { try f.validate(extra) }
    var current = f.entries
    let first = try #require(current.keys.first)
    current[V3EntryObjectKey(entryID: first.entryID, digest: Data(repeating: 0x99, count: 32))] =
      current.removeValue(forKey: first)
    #expect(throws: V3EntrySnapshotValidationError.incompleteSnapshot) {
      try V3RecoveryProfileAdoptionValidator().validate(
        candidate, parent: f.base,
        currentEntries: current, currentVaultKey: Core.oldKey, nextVaultKey: Core.nextKey,
        expectedOwner: f.owner.publicIdentity)
    }
  }

  @Test(arguments: 0..<5)
  func changedSignedCandidateIsRefusedBeforeLocalUnwrap(variant: Int) throws {
    let f = try Fixture()
    let original = try f.build()
    let old = original.envelope.body
    var staged = original.stagedEntries
    var devices = old.fields.devices
    var wrappers = old.fields.wrappedKeys
    var proof = old.transitionProof
    var capsule = old.epochSigningKey
    if variant == 0 {
      devices.removeAll { $0.identity == f.member.publicIdentity }
      wrappers.removeAll { $0.recipientDeviceID == f.member.publicIdentity.deviceID }
    }
    if variant == 1 || variant == 2 {
      let entry = staged[0]
      let context = try V3EntryAuthenticationContext(
        vaultID: Core.vaultID,
        entryID: entry.context.entryID, name: variant == 1 ? "changed/name" : entry.context.name,
        type: entry.context.type, keyID: entry.context.keyID, revision: entry.context.revision)
      staged[0] = try V3EntryCipher().seal(
        "Different fixture value", context: context,
        vaultKey: Core.nextKey)
      staged.sort {
        v3ManifestEntryPrecedes(
          V3ResealedEntry(encryptedEntry: $0).manifestEntry,
          V3ResealedEntry(encryptedEntry: $1).manifestEntry)
      }
    }
    if variant == 3 {
      proof = try V3RecoveryEpochTransitionProof(
        parentEnvelopeDigest: original.expectedCheckpoint.envelopeDigest,
        signature: #require(
          Base64URL.decodeCanonical(original.envelope.authorizations[0].signature)))
    }
    if variant == 4 {
      var changed = old.epochSigningKey.protectedSigningKey
      changed[changed.count - 1] ^= 1
      capsule = try V3EpochSigningKeyCapsule(
        publicKey: old.epochSigningKey.publicKey, protectedSigningKey: changed)
    }
    let body = try V3RecoveryManifestBody(
      fields: V3DeviceWrappedManifestFields(
        vaultID: old.fields.vaultID, keyID: old.fields.keyID,
        authorityTransitionID: old.fields.authorityTransitionID, devices: devices,
        wrappedKeys: wrappers,
        entries: staged.map { V3ResealedEntry(encryptedEntry: $0).manifestEntry }),
      epochSigningKey: capsule, transitionProof: proof, recovery: old.recovery)
    let changed = try f.resign(original, body: body, staged: staged)
    #expect(throws: (any Error).self) { try f.validateForPublication(changed) }
    #expect(f.owner.unwraps == 0)
  }

  @Test func unsignedOrDifferentOwnerCandidateIsRefusedBeforeLocalUnwrap() throws {
    let f = try Fixture()
    let original = try f.build()
    let unsigned = try V3RecoveryEpochBoundary().encode(
      body: original.envelope.body,
      parents: original.envelope.parents, vaultKey: Core.nextKey, authorizations: [])
    let candidate = V3RecoveryProfileAdoptionCandidate(
      expectedCheckpoint: original.expectedCheckpoint,
      envelope: unsigned, stagedEntries: original.stagedEntries)
    #expect(throws: (any Error).self) { try f.validateForPublication(candidate) }
    let other = try f.resign(
      original, body: original.envelope.body,
      staged: original.stagedEntries, signer: f.member)
    #expect(throws: (any Error).self) { try f.validateForPublication(other) }
    #expect(f.owner.unwraps == 0)
  }

  @Test func localWrapperMismatchAndCancellationAreSingleOperationFailures() throws {
    let f = try Fixture()
    let original = try f.build()
    let old = original.envelope.body
    let wrappers = try old.fields.wrappedKeys.map { wrapper in
      guard wrapper.recipientDeviceID == f.owner.publicIdentity.deviceID else { return wrapper }
      return try V3DeviceWrappedManifestKey(
        recipientDeviceID: wrapper.recipientDeviceID,
        wrappedKey: V3VaultKeyHPKE().wrap(
          vaultKey: Core.oldKey,
          recipientPublicKey: f.owner.publicIdentity.wrappingPublicKey,
          context: old.deviceContext(recipientDeviceID: wrapper.recipientDeviceID)))
    }
    let body = try V3RecoveryManifestBody(
      fields: V3DeviceWrappedManifestFields(
        vaultID: old.fields.vaultID, keyID: old.fields.keyID,
        authorityTransitionID: old.fields.authorityTransitionID, devices: old.fields.devices,
        wrappedKeys: wrappers, entries: old.fields.entries), epochSigningKey: old.epochSigningKey,
      transitionProof: nil, recovery: old.recovery)
    let changed = try f.resign(original, body: body, staged: original.stagedEntries)
    #expect(throws: V3RecoveryProfileAdoptionError.localWrapperMismatch) {
      try f.validateForPublication(changed)
    }
    #expect(f.owner.unwraps == 1)
    f.owner.cancelUnwrap = true
    #expect(throws: Core.FixtureError.cancelled) { try f.validateForPublication(original) }
    #expect(f.owner.unwraps == 2)
  }

  private struct Fixture {
    let owner: Core.Owner
    let member: Core.Owner
    let revoked: Core.Owner
    let base: V3DeviceWrappedTrustedCheckpoint
    let entries: [V3EntryObjectKey: V3EncryptedEntry]
    init(empty: Bool = false) throws {
      owner = try Core.Owner()
      member = try Core.Owner()
      revoked = try Core.Owner()
      let publication = try V3DeviceWrappedGenesisBuilder().buildPublicationCandidate(
        vaultID: Core.vaultID, authorityTransitionID: "018f4d38-7d5a-7b20-b0f1-97d6e96c84b4",
        entryIDs: empty
          ? [] : ["018f4d38-7d5a-7b20-b0f1-97d6e96c84b7", "018f4d38-7d5a-7b20-b0f1-97d6e96c84b8"],
        snapshotEntries: empty
          ? []
          : [
            V3GenesisSourceEntry(
              name: "account/密碼", type: .secret, plaintext: "Adoption fixture secret"),
            V3GenesisSourceEntry(name: "otp", type: .totp, plaintext: "JBSWY3DPEHPK3PXP"),
          ],
        vaultKey: Core.oldKey, ownerIdentity: owner.publicIdentity)
      let devices = [
        V3DeviceWrappedManifestDevice(identity: owner.publicIdentity, status: .active),
        V3DeviceWrappedManifestDevice(identity: member.publicIdentity, status: .active),
        V3DeviceWrappedManifestDevice(identity: revoked.publicIdentity, status: .revoked),
      ]
      .sorted { $0.identity.deviceID < $1.identity.deviceID }
      let original = publication.genesis.body
      var current = publication.entries.map(\.encryptedEntry)
      if let index = current.firstIndex(where: { $0.context.type == .secret }) {
        let entry = current[index]
        current[index] = try V3EntryCipher().seal(
          "Adoption fixture secret",
          context: V3EntryAuthenticationContext(
            vaultID: Core.vaultID,
            entryID: entry.context.entryID, name: entry.context.name, type: .secret,
            keyID: original.keyID, revision: 7), vaultKey: Core.oldKey)
      }
      let wrappers = try devices.compactMap { device -> V3DeviceWrappedManifestKey? in
        guard device.status == .active else { return nil }
        return try V3DeviceWrappedManifestKey(
          recipientDeviceID: device.identity.deviceID,
          wrappedKey: V3VaultKeyHPKE().wrap(
            vaultKey: Core.oldKey,
            recipientPublicKey: device.identity.wrappingPublicKey,
            context: V3VaultKeyHPKEContext(
              vaultID: Core.vaultID, keyID: original.keyID,
              authorityTransitionID: original.authorityTransitionID,
              recipientDeviceID: device.identity.deviceID)))
      }
      let body = try V3DeviceWrappedManifestBody(
        vaultID: Core.vaultID, keyID: original.keyID,
        authorityTransitionID: original.authorityTransitionID, devices: devices,
        wrappedKeys: wrappers,
        entries: current.map { V3ResealedEntry(encryptedEntry: $0).manifestEntry })
      let content = CanonicalJSONValue.object([
        ("manifest", body.canonicalValue), ("parents", .array([])),
      ])
      let data = CanonicalJSON.encode(
        .object([
          ("format", .string("key-vault-manifest-envelope")), ("version", .integer(3)),
          ("content", content),
          (
            "authentication",
            .object([
              ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
              (
                "tag",
                .string(
                  Base64URL.encode(
                    try V3ManifestAuthenticator.authenticationTag(
                      canonicalContent: CanonicalJSON.encode(content), vaultID: Core.vaultID,
                      vaultKey: Core.oldKey)))
              ),
            ])
          ),
          ("authorizations", .array([])),
        ]))
      base = V3DeviceWrappedTrustedCheckpoint(
        checkpoint: try V3ManifestCheckpoint(
          vaultID: Core.vaultID, envelopeDigest: Data(SHA256.hash(data: data))),
        envelope: try V3DeviceWrappedManifestEnvelopeCodec().parse(data))
      entries = try V3EntrySnapshotValidator(limits: .standard).entryMap(
        current)
    }
    func build(limits: V3ManifestRepositoryLimits = .standard) throws
      -> V3RecoveryProfileAdoptionCandidate
    {
      try V3RecoveryProfileAdoptionBuilder(limits: limits).build(
        from: base, currentEntries: entries,
        currentVaultKey: Core.oldKey, nextVaultKey: Core.nextKey, owner: owner,
        reason: "Adopt fixture")
    }
    func validate(_ candidate: V3RecoveryProfileAdoptionCandidate, nextKey: Data = Core.nextKey)
      throws
    {
      try V3RecoveryProfileAdoptionValidator().validate(
        candidate, parent: base, currentEntries: entries,
        currentVaultKey: Core.oldKey, nextVaultKey: nextKey, expectedOwner: owner.publicIdentity)
    }
    func validateForPublication(_ candidate: V3RecoveryProfileAdoptionCandidate) throws {
      try V3RecoveryProfileAdoptionValidator().validateForPublication(
        candidate, parent: base,
        currentEntries: entries, currentVaultKey: Core.oldKey, nextVaultKey: Core.nextKey,
        identity: owner, reason: "Check fixture adoption")
    }
    func resign(
      _ original: V3RecoveryProfileAdoptionCandidate, body: V3RecoveryManifestBody,
      staged: [V3EncryptedEntry], signer: Core.Owner? = nil
    ) throws -> V3RecoveryProfileAdoptionCandidate {
      let signer = signer ?? owner
      let boundary = V3RecoveryEpochBoundary()
      let unsigned = try boundary.encode(
        body: body, parents: original.envelope.parents,
        vaultKey: Core.nextKey, authorizations: [])
      let signature = try V3P256Signature.canonicalize(
        signer.signature(
          for: V3ManifestAuthenticator.authenticationInput(for: unsigned.canonicalContentBytes),
          reason: "Sign changed software fixture"))
      return V3RecoveryProfileAdoptionCandidate(
        expectedCheckpoint: original.expectedCheckpoint,
        envelope: try boundary.encode(
          body: body, parents: original.envelope.parents,
          vaultKey: Core.nextKey,
          authorizations: [
            V3ManifestAuthorization(
              signerDeviceID: signer.publicIdentity.deviceID, signature: Base64URL.encode(signature)
            )
          ]),
        stagedEntries: staged)
    }
  }
}
