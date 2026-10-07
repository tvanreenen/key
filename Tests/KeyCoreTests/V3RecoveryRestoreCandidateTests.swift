import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Real filesystem recovery input and existing permanent-genesis crypto. No
/// destination publication, platform identity, token or configuration operation.
struct V3RecoveryRestoreCandidateTests {
  private typealias Core = V3RecoveryRegistrationTests
  private typealias Fixture = V3RecoveryContentMutationPublisherTests.Fixture
  private static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c4800"
  private static let transitionID = "018f4d38-7d5a-7b20-b0f1-97d6e96c4801"
  private static let entryIDs = [
    "018f4d38-7d5a-7b20-b0f1-97d6e96c4802", "018f4d38-7d5a-7b20-b0f1-97d6e96c4803",
  ]
  private static let key = Data(repeating: 0xA7, count: 32)

  @Test(arguments: [false, true])
  func verifiedContentsBecomeOnlyFreshMacBoundGenesisWithoutSourceWrites(empty: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture(empty: empty)
    defer { f.remove() }
    let before = try files(f.root)
    let signatures = f.core.owner.signatures
    let calls = Core.Counter()
    let snapshot = try open(f, calls: calls)
    let owner = try FreshOwner()
    let candidate = try build(f, snapshot: snapshot, owner: owner.identity)
    let genesis = candidate.publication.genesis
    #expect(candidate.snapshot.selection == snapshot.selection)
    #expect(genesis.body.vaultID == Self.vaultID)
    #expect(genesis.body.devices == [.init(identity: owner.identity, status: .active)])
    #expect(genesis.body.wrappedKeys.count == 1)
    #expect(genesis.body.entries.count == snapshot.entries.count)
    #expect(genesis.body.entries.allSatisfy { $0.revision == 1 })
    let envelope = try V3DeviceWrappedManifestEnvelopeCodec().parse(genesis.manifestData)
    #expect(envelope.parents.isEmpty && envelope.authorizations.isEmpty)
    #expect(throws: (any Error).self) {
      try V3RecoveryManifestCodec().parseEnvelope(genesis.manifestData)
    }
    let context = try V3VaultKeyHPKEContext(
      vaultID: Self.vaultID, keyID: genesis.body.keyID,
      authorityTransitionID: Self.transitionID, recipientDeviceID: owner.identity.deviceID)
    #expect(
      try V3VaultKeyHPKE().unwrap(
        genesis.body.wrappedKeys[0].wrappedKey, recipientPrivateKey: owner.wrapping,
        context: context) == Self.key)
    #expect(throws: (any Error).self) {
      try V3VaultKeyHPKE().unwrap(
        genesis.body.wrappedKeys[0].wrappedKey, recipientPrivateKey: f.core.token,
        context: context)
    }
    let plain = try V3EntrySnapshotValidator(limits: .standard).plaintexts(
      fields: genesis.body.fields,
      entries: V3EntrySnapshotValidator(limits: .standard).entryMap(
        candidate.publication.entries.map(\.encryptedEntry)), vaultKey: Self.key)
    for entry in candidate.publication.entries {
      #expect(plain[entry.manifestEntry.entryID] == Data(entry.source.plaintext.utf8))
      #expect(entry.encryptedEntry.context.vaultID == Self.vaultID)
    }
    #expect(try files(f.root) == before)
    #expect(calls.value == 1 && f.core.owner.signatures == signatures && f.core.owner.unwraps == 0)
  }

  @Test func actualRotationAndLaterEditPrepareTheLatestVerifiedContents() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let session = V3DeviceWrappedVaultKeySessionStore()
    try session.install(Core.nextKey, vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID)
    let rotation = V3RecoveryKeyRotationService(
      vaultID: Core.vaultID, identity: f.core.owner, session: session,
      objectStore: f.store, checkpointStore: f.checkpoints, recoveryAnchorStore: f.ownership,
      registrationAnchorStore: f.registration, adoptionAnchorStore: f.adoption, cache: f.cache)
    _ = try rotation.rotate(expectedCheckpoint: f.checkpoint, operationID: .init())
    let ordinary = V3RecoveryVaultMutationService(
      vaultID: Core.vaultID, session: session, objectStore: f.store,
      checkpointStore: f.checkpoints, recoveryAnchorStore: f.ownership,
      registrationAnchorStore: f.registration, adoptionAnchorStore: f.adoption, cache: f.cache)
    try ordinary.edit(
      name: "fixture/secret", secret: "after actual rotation\r\n", type: .secret,
      operationID: .init())
    session.invalidate()
    let before = try files(f.root)
    let signatures = f.core.owner.signatures
    let unwraps = f.core.owner.unwraps
    let calls = Core.Counter()
    let snapshot = try open(f, calls: calls)
    let prepared = try build(f, snapshot: snapshot, owner: FreshOwner().identity)
    #expect(
      prepared.publication.entries.first { $0.source.name == "fixture/secret" }?.source.plaintext
        == "after actual rotation\r\n")
    #expect(prepared.publication.entries.contains { $0.source.type == .totp })
    #expect(calls.value == 1 && !session.hasResidentKey)
    #expect(f.core.owner.signatures == signatures && f.core.owner.unwraps == unwraps)
    #expect(try files(f.root) == before)
  }

  @Test(arguments: 0..<10)
  func sourceAuthorityAndInvalidDestinationInputsCannotPrepareAReplacement(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let calls = Core.Counter()
    let snapshot = try open(f, calls: calls)
    let fresh = try FreshOwner()
    var owner = fresh.identity
    var ids = Self.entryIDs
    if variant == 2 { ids[0] = f.parent.body.fields.entries[0].entryID }
    if variant == 3 { owner = f.core.owner.publicIdentity }
    if variant == 4 || variant == 5 || variant == 6 {
      owner = try V3EnrollmentDeviceIdentity(
        displayName: "Fresh Mac",
        signingPublicKey: variant == 4
          ? f.core.owner.publicIdentity.signingPublicKey : fresh.identity.signingPublicKey,
        wrappingPublicKey: variant == 5
          ? f.core.owner.publicIdentity.wrappingPublicKey
          : (variant == 6 ? f.core.credential.publicKey : fresh.identity.wrappingPublicKey))
    }
    if variant == 7 { ids[0] = Self.vaultID }
    #expect(throws: (any Error).self) {
      try V3RecoveryRestoreCandidateBuilder(source: f.store).build(
        restoring: snapshot, vaultID: variant == 0 ? Core.vaultID : Self.vaultID,
        authorityTransitionID: variant == 1
          ? f.parent.body.fields.authorityTransitionID : Self.transitionID,
        entryIDs: variant == 8 ? ["invalid", ids[1]] : ids,
        vaultKey: variant == 9 ? Data(repeating: 1, count: 31) : Self.key,
        ownerIdentity: owner)
    }
    #expect(calls.value == 1 && f.core.owner.unwraps == 0)
  }

  @Test(arguments: 0..<9)
  func independentValidationRefusesMismatchedContentsAndArtifacts(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let snapshot = try open(f, calls: Core.Counter())
    let owner = try FreshOwner()
    var sources = snapshot.entries
    if variant == 0 {
      sources[0] = .init(name: sources[0].name, type: sources[0].type, plaintext: "different value")
    }
    if variant == 1 {
      sources[1] = .init(name: sources[1].name, type: .secret, plaintext: sources[1].plaintext)
    }
    if variant == 2 { sources.removeLast() }
    let initial = try V3DeviceWrappedGenesisBuilder().buildPublicationCandidate(
      vaultID: Self.vaultID, authorityTransitionID: Self.transitionID,
      entryIDs: Array(Self.entryIDs.prefix(sources.count)), snapshotEntries: sources,
      vaultKey: Self.key, ownerIdentity: owner.identity)
    var genesis = initial.genesis
    var entries = initial.entries
    if variant == 3 {
      genesis = .init(
        body: genesis.body, manifestData: genesis.manifestData,
        manifestDigest: Data(repeating: 0, count: 32))
    }
    if variant == 4 || variant == 5 || variant == 8 {
      let entry = entries[0]
      entries[0] = .init(
        source: variant == 5
          ? .init(
            name: entry.source.name, type: entry.source.type,
            plaintext: entry.source.plaintext.precomposedStringWithCanonicalMapping)
          : entry.source,
        manifestEntry: entry.manifestEntry,
        encryptedEntry: variant == 8 ? entries[1].encryptedEntry : entry.encryptedEntry,
        digest: variant == 4 ? Data(repeating: 0, count: 32) : entry.digest)
    }
    let candidate = V3DeviceWrappedGenesisPublicationCandidate(genesis: genesis, entries: entries)
    #expect(throws: (any Error).self) {
      try V3RecoveryRestoreCandidateBuilder(source: f.store).validate(
        candidate, restoring: snapshot,
        vaultKey: variant == 6 ? Data(repeating: 1, count: 32) : Self.key,
        expectedOwner: variant == 7 ? FreshOwner().identity : owner.identity)
    }
  }

  @Test(arguments: [false, true])
  func changedVerifiedSourceRefusesPreparationWithoutAnotherAgreement(manifest: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let calls = Core.Counter()
    let snapshot = try open(f, calls: calls)
    if manifest {
      let changed = try f.build(
        .edit(name: "fixture/secret", type: .secret, plaintext: "later save"))
      try f.seed(changed.envelope, entries: changed.stagedEntries)
    } else {
      try FileManager.default.removeItem(at: f.entryURL(try #require(f.entries.values.first)))
    }
    #expect(throws: (any Error).self) {
      try build(f, snapshot: snapshot, owner: FreshOwner().identity)
    }
    #expect(calls.value == 1)
  }

  @Test(arguments: 0..<4)
  func preparationAndValidationRespectBoundedSourceAndSnapshotLimits(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let snapshot = try open(f, calls: Core.Counter())
    let sizes = f.entries.values.map { $0.canonicalBytes.count }
    let limits = V3ManifestRepositoryLimits(
      maximumManifestObjects: 100, maximumHistoryDepth: 100,
      maximumReferencedEntryObjects: variant == 0 ? 1 : 100,
      maximumManifestBytes: variant == 1 ? 1 : 100_000,
      maximumEntryBytes: variant == 2 ? 1 : (variant == 3 ? try #require(sizes.max()) : 100_000),
      maximumTotalEntryBytes: variant == 3 ? sizes.reduce(0, +) - 1 : 1_000_000)
    #expect(throws: (any Error).self) {
      try build(f, snapshot: snapshot, owner: FreshOwner().identity, limits: limits)
    }
  }

  @available(macOS 26.0, *)
  private func open(_ f: Fixture, calls: Core.Counter) throws -> V3RecoveryVerifiedSnapshot {
    let receiver = try PIVHPKEReceiver(publicBytes: f.core.credential.publicKey) { peer in
      calls.increment()
      return try f.core.token.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: peer)
      ).withUnsafeBytes { Data($0) }
    }
    let selection = try V3RecoveryHistorySelector(source: f.store).select(
      anchor: f.anchor, credentialPublicKey: receiver.publicKey.bytes)
    return try V3RecoverySnapshotVerifier(source: f.store).open(
      selection, boundAnchor: f.anchor, receiver: receiver)
  }
  private func build(
    _ f: Fixture, snapshot: V3RecoveryVerifiedSnapshot, owner: V3EnrollmentDeviceIdentity,
    limits: V3ManifestRepositoryLimits = .standard
  ) throws -> V3RecoveryRestoreCandidate {
    try V3RecoveryRestoreCandidateBuilder(source: f.store, limits: limits).build(
      restoring: snapshot, vaultID: Self.vaultID, authorityTransitionID: Self.transitionID,
      entryIDs: Array(Self.entryIDs.prefix(snapshot.entries.count)), vaultKey: Self.key,
      ownerIdentity: owner)
  }
  private struct FreshOwner {
    let wrapping = P256.KeyAgreement.PrivateKey()
    let identity: V3EnrollmentDeviceIdentity
    init() throws {
      identity = try .init(
        displayName: "Fresh restored Mac",
        signingPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
        wrappingPublicKey: wrapping.publicKey.x963Representation)
    }
  }
  private func files(_ root: URL) throws -> [String: Data] {
    let urls = try #require(
      FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey]))
    var bytes: [String: Data] = [:]
    for case let url as URL in urls {
      if try url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true {
        bytes[url.path] = try Data(contentsOf: url)
      }
    }
    return bytes
  }
}
