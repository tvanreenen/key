import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Actual profile-3 publication, HPKE and capsule authentication. The identity
/// uses software P-256 keys; no native prompt, token or user vault is involved.
struct V3RecoveryVaultUnlockRuntimeTests {
  private typealias Core = V3RecoveryRegistrationTests
  private typealias Publication = V3RecoveryContentMutationPublisherTests

  @Test(arguments: [false, true])
  func exactCheckpointUsesCacheOrProviderAndInstallsOneMacKey(cached: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    if cached { f.cache.lookup = .available(f.disk.parent.canonicalBytes) }
    let runtime = f.runtime()
    let trusted = try runtime.unlock(reason: "Software fixture unlock")
    #expect(trusted.envelope == f.disk.parent && trusted.checkpoint == f.disk.checkpoint)
    #expect(f.loader.loads == 1 && f.disk.core.owner.unwraps == 1)
    #expect(f.source.reads == (cached ? 0 : 1) && f.cache.stores == (cached ? 0 : 1))
    #expect(f.source.entryReads == 0 && f.source.listings == 0)
    #expect(
      try f.session.load(vaultID: Core.vaultID, keyID: trusted.envelope.body.fields.keyID)
        == Core.nextKey)
    #expect(f.disk.checkpoints.value == f.disk.checkpoint.canonicalBytes)
    #expect(f.pending.allSatisfy { $0.value == nil })
  }

  @Test func warmCheckpointReuseDoesNotLoadIdentityOrUnwrapAgain() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let runtime = f.runtime()
    _ = try runtime.authenticatedCheckpoint(reason: "Software cold access")
    _ = try runtime.authenticatedCheckpoint(reason: "Software warm access")
    #expect(f.loader.loads == 1 && f.disk.core.owner.unwraps == 1)
    #expect(f.source.reads == 1 && f.cache.stores == 1)
    runtime.lock()
    #expect(!f.session.hasResidentKey)
    _ = try runtime.authenticatedCheckpoint(reason: "Software access after lock")
    #expect(f.loader.loads == 2 && f.disk.core.owner.unwraps == 2)
  }

  @Test func explicitReauthenticationClearsOldKeyBeforePrivateOperation() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let runtime = f.runtime()
    _ = try runtime.unlock(reason: "First software unlock")
    f.disk.core.owner.onUnwrap = { #expect(!f.session.hasResidentKey) }
    _ = try runtime.unlock(reason: "Explicit second software unlock")
    #expect(f.disk.core.owner.unwraps == 2 && f.session.hasResidentKey)
  }

  @Test(arguments: 0..<5)
  func unavailableInvalidOrSubstitutedManifestsRefuseBeforeIdentityAccess(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    switch variant {
    case 0: f.source.result = .unavailable
    case 1: f.source.result = .invalid
    case 2: f.source.result = .tooLarge
    case 3: f.source.result = .available(Data("substituted".utf8))
    default: f.cache.lookup = .available(Data("substituted cache".utf8))
    }
    #expect(
      throws: variant == 0
        ? V3RecoveryVaultUnlockError.temporaryUnavailable : .recoveryRequired
    ) {
      try f.runtime().unlock(reason: "Software refusal fixture")
    }
    #expect(f.loader.loads == 0 && f.disk.core.owner.unwraps == 0 && !f.session.hasResidentKey)
    #expect(f.cache.stores == 0)
  }

  @Test(arguments: 0..<3)
  func malformedMissingOrForeignCheckpointNeverSelectsProviderAuthority(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    switch variant {
    case 0: f.disk.checkpoints.value = nil
    case 1: f.disk.checkpoints.value = Data("invalid".utf8)
    default:
      f.disk.checkpoints.value = try V3ManifestCheckpoint(
        vaultID: "018f4d38-7d5a-7b20-b0f1-97d6e96c84d1",
        envelopeDigest: f.disk.parent.digest
      ).canonicalBytes
    }
    #expect(throws: V3RecoveryVaultUnlockError.recoveryRequired) {
      try f.runtime().unlock(reason: "Software checkpoint refusal")
    }
    #expect(f.source.reads == 0 && f.source.listings == 0 && f.loader.loads == 0)
  }

  @Test(arguments: 0..<3, [false, true])
  func everyPendingOrUnreadableOwnershipNamespaceBlocksColdAndWarmAccess(
    namespace: Int, unreadable: Bool
  ) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let runtime = f.runtime()
    _ = try runtime.unlock(reason: "Initial software unlock")
    if unreadable {
      f.pending[namespace].fails = true
    } else {
      f.pending[namespace].value = Data("any pending record".utf8)
    }
    #expect(
      throws: unreadable
        ? V3RecoveryVaultUnlockError.recoveryRequired : .mutationPending
    ) {
      try runtime.authenticatedCheckpoint(reason: "Blocked warm access")
    }
    #expect(!f.session.hasResidentKey && f.disk.core.owner.unwraps == 1)
    #expect(throws: (any Error).self) { try runtime.unlock(reason: "Blocked cold access") }
    #expect(f.disk.core.owner.unwraps == 1 && f.loader.loads == 1)
    #expect(f.pending[namespace].value == (unreadable ? nil : Data("any pending record".utf8)))
  }

  @Test(arguments: 0..<3)
  func missingForeignOrCancelledIdentityNeverInstallsAKey(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    switch variant {
    case 0: f.loader.identity = nil
    case 1: f.loader.identity = try Core.Owner()
    default: f.loader.error = V3EnrollmentDeviceIdentityStoreError.authenticationCancelled
    }
    #expect(throws: variant == 2 ? V3RecoveryVaultUnlockError.locked : .identityUnavailable) {
      try f.runtime().unlock(reason: "Software identity refusal")
    }
    #expect(f.loader.loads == 1 && f.disk.core.owner.unwraps == 0 && !f.session.hasResidentKey)
  }

  @Test(arguments: 0..<4)
  func lockCheckpointChangePendingWorkAndSessionReplacementDuringUnwrapRefuse(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let runtime = f.runtime()
    f.disk.core.owner.onUnwrap = {
      switch variant {
      case 0: runtime.lock()
      case 1: f.disk.checkpoints.value = f.disk.core.checkpoint.canonicalBytes
      case 2: f.pending[1].value = Data([1])
      default:
        try f.session.install(
          Core.nextKey, vaultID: Core.vaultID,
          keyID: f.disk.parent.body.fields.keyID)
      }
    }
    #expect(throws: (any Error).self) { try runtime.unlock(reason: "Software late-result refusal") }
    #expect(f.disk.core.owner.unwraps == 1 && !f.session.hasResidentKey && f.cache.stores == 0)
  }

  @Test func lockDuringIdentityLoadingStopsBeforePrivateOperation() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    f.loader.onLoad = { f.session.invalidate() }
    #expect(throws: V3RecoveryVaultUnlockError.locked) {
      try f.runtime().unlock(reason: "Software loader cancellation")
    }
    #expect(f.disk.core.owner.unwraps == 0 && !f.session.hasResidentKey)
  }

  @Test(arguments: [false, true])
  func cacheFailureCannotUndoValidUnlockButCacheCallbackCannotReviveLock(cancel: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    f.cache.onStore = {
      if cancel { f.session.invalidate() }
      throw Core.FixtureError.cancelled
    }
    if cancel {
      #expect(throws: V3RecoveryVaultUnlockError.locked) {
        try f.runtime().unlock(reason: "Software cache cancellation")
      }
      #expect(!f.session.hasResidentKey)
    } else {
      _ = try f.runtime().unlock(reason: "Software cache failure")
      #expect(f.session.hasResidentKey)
    }
    #expect(f.disk.core.owner.unwraps == 1 && f.cache.stores == 1)
  }

  @Test(arguments: [false, true])
  func currentMACAndEpochCapsuleMustBothAuthenticate(badCapsule: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    var bytes = f.disk.parent.canonicalBytes
    if badCapsule {
      let old = f.disk.parent.body
      let capsule = try V3EpochSigningKeyCapsule(
        publicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
        protectedSigningKey: old.epochSigningKey.protectedSigningKey)
      bytes = try V3RecoveryEpochBoundary().encode(
        body: V3RecoveryManifestBody(
          fields: old.fields, epochSigningKey: capsule,
          transitionProof: old.transitionProof, recovery: old.recovery),
        parents: f.disk.parent.parents, vaultKey: Core.nextKey,
        authorizations: f.disk.parent.authorizations
      ).canonicalBytes
    } else {
      bytes = Data(
        String(decoding: bytes, as: UTF8.self).replacingOccurrences(
          of: Base64URL.encode(f.disk.parent.authenticationTag),
          with: Base64URL.encode(Data(repeating: 0, count: 32))
        ).utf8)
    }
    f.disk.checkpoints.value = try V3ManifestCheckpoint(
      vaultID: Core.vaultID, envelopeDigest: Data(SHA256.hash(data: bytes))
    ).canonicalBytes
    f.source.result = .available(bytes)
    #expect(throws: V3RecoveryVaultUnlockError.recoveryRequired) {
      try f.runtime().unlock(reason: "Software authentication refusal")
    }
    #expect(f.disk.core.owner.unwraps == 1 && !f.session.hasResidentKey && f.cache.stores == 0)
  }

  @Test(arguments: [false, true])
  func permanentAndUnknownProfilesAreRefusedBeforePrivateOperation(unknown: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let bytes =
      try unknown
      ? Data(
        String(decoding: f.disk.parent.canonicalBytes, as: UTF8.self)
          .replacingOccurrences(of: "\"profileVersion\":3", with: "\"profileVersion\":4").utf8)
      : V3DeviceWrappedGenesisBuilder().build(
        vaultID: Core.vaultID, authorityTransitionID: UUID().uuidString.lowercased(),
        vaultKey: Core.nextKey, ownerIdentity: f.disk.core.owner.publicIdentity
      ).manifestData
    f.disk.checkpoints.value = try V3ManifestCheckpoint(
      vaultID: Core.vaultID, envelopeDigest: Data(SHA256.hash(data: bytes))
    ).canonicalBytes
    f.source.result = .available(bytes)
    #expect(throws: V3RecoveryVaultUnlockError.unsupportedProfile) {
      try f.runtime().unlock(reason: "Software profile refusal")
    }
    #expect(f.loader.loads == 0 && f.disk.core.owner.unwraps == 0 && !f.session.hasResidentKey)
  }

  @Test func authenticatedRevokedRosterRefusesBeforePrivateOperation() throws {
    let f = try V3RecoveryKeyTransitionCatchUpTests.Fixture()
    defer { f.disk.remove() }
    _ = try f.revoke(f.receiver)
    f.session.invalidate()
    let runtime = V3RecoveryVaultUnlockRuntime(
      vaultID: Core.vaultID, checkpointStore: f.disk.checkpoints, source: f.disk.store,
      cache: f.disk.cache, identityLoader: Loader(identity: f.receiver), session: f.session,
      transactionOwnershipStore: f.pending[0], registrationOwnershipStore: f.pending[1],
      adoptionOwnershipStore: f.pending[2])
    #expect(throws: V3RecoveryVaultUnlockError.deviceRevoked) {
      try runtime.unlock(reason: "Software revoked Mac refusal")
    }
    #expect(f.receiver.unwraps == 0 && !f.session.hasResidentKey)
  }

  @Test(arguments: [false, true])
  func privateOperationFailureDoesNotRetryOrRetainEarlierKey(cancelled: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    try f.session.install(
      Core.nextKey, vaultID: Core.vaultID,
      keyID: f.disk.parent.body.fields.keyID)
    f.disk.core.owner.onUnwrap = {
      #expect(!f.session.hasResidentKey)
      if cancelled { throw V3EnrollmentDeviceIdentityStoreError.authenticationCancelled }
      throw Core.FixtureError.cancelled
    }
    #expect(throws: cancelled ? V3RecoveryVaultUnlockError.locked : .recoveryRequired) {
      try f.runtime().unlock(reason: "Software private operation failure")
    }
    #expect(f.disk.core.owner.unwraps == 1 && !f.session.hasResidentKey && f.cache.stores == 0)
  }

  @Test(arguments: [false, true])
  func stateChangesAfterInstallationCannotReleaseAnAuthenticatedFloor(lock: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let checkpoints = Checkpoints(store: f.disk.checkpoints) {
      if f.session.hasResidentKey {
        if lock {
          f.session.invalidate()
        } else {
          f.disk.checkpoints.value = f.disk.core.checkpoint.canonicalBytes
        }
      }
    }
    #expect(throws: lock ? V3RecoveryVaultUnlockError.locked : .checkpointChanged) {
      try f.runtime(checkpoints: checkpoints).unlock(reason: "Software post-install race")
    }
    #expect(f.disk.core.owner.unwraps == 1 && !f.session.hasResidentKey && checkpoints.writes == 0)
  }

  @Test func warmResidentKeyMismatchRefusesWithoutRetryingIdentity() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let keyID = try V3VaultKeyID.derive(vaultKey: Core.oldKey, vaultID: Core.vaultID)
    try f.session.install(Core.oldKey, vaultID: Core.vaultID, keyID: keyID)
    #expect(throws: V3RecoveryVaultUnlockError.locked) {
      try f.runtime().authenticatedCheckpoint(reason: "Software mismatch")
    }
    #expect(f.loader.loads == 0 && f.disk.core.owner.unwraps == 0 && !f.session.hasResidentKey)
  }

  @Test func realColdUnlockFeedsExistingCatchUpOrdinarySaveAndFreshReopen() throws {
    let f = try V3RecoveryKeyTransitionCatchUpTests.Fixture()
    defer { f.disk.remove() }
    f.session.invalidate()
    let loader = Loader(identity: f.receiver)
    let runtime = V3RecoveryVaultUnlockRuntime(
      vaultID: Core.vaultID, checkpointStore: f.local, source: f.disk.store, cache: f.localCache,
      identityLoader: loader, session: f.session, transactionOwnershipStore: f.pending[0],
      registrationOwnershipStore: f.pending[1], adoptionOwnershipStore: f.pending[2])
    let floor = try runtime.unlock(reason: "Software cold enrolled-Mac unlock")
    #expect(floor.checkpoint == f.floor.checkpoint && floor.envelope == f.floor.envelope)
    #expect(f.receiver.unwraps == 1)
    _ = try f.publish(.rotation)
    guard
      case .current(let current, _) = try V3RecoveryCatchUpCoordinator(
        mutationOwner: VaultTransactionMutationOwner(), identity: f.receiver, session: f.session,
        source: f.disk.store, checkpointStore: f.local, recoveryAnchorStore: f.pending[0],
        registrationAnchorStore: f.pending[1], adoptionAnchorStore: f.pending[2],
        cache: f.localCache
      ).catchUp(from: floor)
    else { throw Core.FixtureError.cancelled }
    #expect(f.receiver.unwraps == 2 && current.envelope == f.parent)
    try V3RecoveryVaultMutationService(
      vaultID: Core.vaultID, session: f.session, objectStore: f.disk.store,
      checkpointStore: f.local, recoveryAnchorStore: f.pending[0],
      registrationAnchorStore: f.pending[1],
      adoptionAnchorStore: f.pending[2], cache: f.localCache
    ).add(
      name: "after/unlock", secret: "Software reopened contents", type: .secret,
      operationID: .init())
    runtime.lock()
    let reopened = try runtime.unlock(reason: "Software cold reopen after save")
    #expect(
      f.receiver.unwraps == 3
        && reopened.envelope.body.fields.entries.contains {
          $0.name == "after/unlock"
        })
    let key = try f.session.load(vaultID: Core.vaultID, keyID: reopened.envelope.body.fields.keyID)
    _ = try V3RecoveryRegistrationRepository(source: f.disk.store, limits: .standard).observe(
      checkpoint: reopened.checkpoint, currentVaultKey: key)
  }

  private struct Fixture: Sendable {
    let disk: Publication.Fixture
    let session = V3DeviceWrappedVaultKeySessionStore()
    let pending = [Ownership(), Ownership(), Ownership()]
    let source: Source
    let cache = Cache()
    let loader: Loader
    init() throws {
      disk = try Publication.Fixture()
      source = Source(store: disk.store)
      loader = Loader(identity: disk.core.owner)
    }
    func runtime(checkpoints: (any V3ManifestCheckpointStoring)? = nil)
      -> V3RecoveryVaultUnlockRuntime
    {
      .init(
        vaultID: Core.vaultID, checkpointStore: checkpoints ?? disk.checkpoints, source: source,
        cache: cache,
        identityLoader: loader, session: session, transactionOwnershipStore: pending[0],
        registrationOwnershipStore: pending[1], adoptionOwnershipStore: pending[2])
    }
  }

  private final class Checkpoints: V3ManifestCheckpointStoring, @unchecked Sendable {
    let store: Publication.Checkpoints
    let onRead: @Sendable () throws -> Void
    var writes = 0
    init(store: Publication.Checkpoints, onRead: @escaping @Sendable () throws -> Void) {
      self.store = store
      self.onRead = onRead
    }
    func loadCheckpoint(vaultID: String) throws -> Data? {
      try onRead()
      return try store.loadCheckpoint(vaultID: vaultID)
    }
    func replaceCheckpoint(_: Data, expectedCheckpoint _: Data?, vaultID _: String) throws {
      writes += 1
      throw Core.FixtureError.cancelled
    }
  }

  private final class Loader: V3DeviceWrappedIdentityLoading, @unchecked Sendable {
    var identity: (any V3DeviceWrappedVaultKeyUnwrapping)?
    var error: (any Error)?
    var onLoad: @Sendable () throws -> Void = {}
    var loads = 0
    init(identity: (any V3DeviceWrappedVaultKeyUnwrapping)?) { self.identity = identity }
    func loadDeviceIdentity(vaultID _: String, reason _: String) throws
      -> (any V3DeviceWrappedVaultKeyUnwrapping)?
    {
      loads += 1
      try onLoad()
      if let error { throw error }
      return identity
    }
  }

  private final class Ownership: V3ImmutableTransactionRecoveryAnchorStoring, @unchecked Sendable {
    var value: Data?
    var fails = false
    func loadRecoveryAnchor(vaultID _: String) throws -> Data? {
      if fails { throw Core.FixtureError.cancelled }
      return value
    }
    func replaceRecoveryAnchor(_: Data?, expectedAnchor _: Data?, vaultID _: String) throws {
      Issue.record("Unlock must not write ownership")
      throw Core.FixtureError.cancelled
    }
  }

  private final class Source: V3ImmutableObjectReading, @unchecked Sendable {
    let store: V3FilesystemTransactionArtifactStore
    var result: V3RepositoryObjectRead?
    var reads = 0
    var entryReads = 0
    var listings = 0
    init(store: V3FilesystemTransactionArtifactStore) { self.store = store }
    func readManifest(digest: Data, maximumBytes: Int) throws -> V3RepositoryObjectRead {
      reads += 1
      return try result ?? store.readManifest(digest: digest, maximumBytes: maximumBytes)
    }
    func readEntry(entryID _: String, digest _: Data, maximumBytes _: Int) throws
      -> V3RepositoryObjectRead
    {
      entryReads += 1
      throw Core.FixtureError.cancelled
    }
    func manifestDigests(maximumCount _: Int) throws -> V3RepositoryDirectoryListing {
      listings += 1
      throw Core.FixtureError.cancelled
    }
  }

  private final class Cache: V3CheckpointManifestCaching, @unchecked Sendable {
    var lookup = V3CheckpointManifestCacheLookup.missing
    var stores = 0
    var onStore: @Sendable () throws -> Void = {}
    func load(for _: V3ManifestCheckpoint) throws -> V3CheckpointManifestCacheLookup { lookup }
    func store(_ manifestData: Data, for _: V3ManifestCheckpoint) throws {
      stores += 1
      try onStore()
      lookup = .available(manifestData)
    }
  }
}
