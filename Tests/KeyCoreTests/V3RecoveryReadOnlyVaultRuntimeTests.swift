import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Real profile-3 publications and entry AEAD, with software Mac keys only.
/// Source callbacks make late changes deterministic without native prompts.
struct V3RecoveryReadOnlyVaultRuntimeTests {
  private typealias Core = V3RecoveryRegistrationTests
  private typealias Publication = V3RecoveryContentMutationPublisherTests

  @Test func readsListsAndStatusReuseOneMacUnwrapAndPreserveExactPlaintext() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let secret = try f.reader.read(name: "fixture/secret", allowStale: false)
    #expect(secret.type == .secret && secret.plaintext == "Software fixture secret e\u{301}\r\n")
    let otp = try f.reader.read(name: "fixture/totp", allowStale: false)
    #expect(otp.type == .totp && otp.plaintext == "JBSWY3DPEHPK3PXP")
    #expect(try f.reader.list(allowStale: false) == ["fixture/secret", "fixture/totp"])
    let status = try f.reader.status()
    #expect(status.health == .ready && status.entries == .effective(2) && status.issues.isEmpty)
    #expect(status.trustedVersionID == String(v3LowercaseHex(f.disk.parent.digest).prefix(16)))
    try f.reader.authorizeRead(name: "fixture/secret", allowStale: false)
    #expect(f.disk.core.owner.unwraps == 1 && f.loader.loads == 1)
    #expect(f.source.listings == 0 && f.disk.checkpoints.value == f.disk.checkpoint.canonicalBytes)
    f.unlock.lock()
    _ = try f.reader.read(name: "fixture/secret", allowStale: false)
    #expect(f.disk.core.owner.unwraps == 2)
  }

  @Test func emptyVaultHasEmptyListButMissingNameIsNotAnEmptySecret() throws {
    let f = try Fixture(empty: true)
    defer { f.disk.remove() }
    try f.reader.unlock()
    #expect(try f.reader.list(allowStale: false).isEmpty)
    #expect(try f.reader.status().entries == .effective(0))
    #expect(throws: AppError.entryNotFound("Entry 'fixture/missing' was not found.")) {
      try f.reader.read(name: "fixture/missing", allowStale: true)
    }
    #expect(f.source.entryReads == 0 && f.disk.core.owner.unwraps == 1)
  }

  @Test(arguments: ["", "../secret", "bad\nname", " /secret", "part//secret"], [false, true])
  func malformedSelectorsRefuseBeforeAuthentication(name: String, authorize: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    #expect(throws: AppError.self) {
      if authorize {
        try f.reader.authorizeRead(name: name, allowStale: false)
      } else {
        _ = try f.reader.read(name: name, allowStale: false)
      }
    }
    #expect(f.loader.loads == 0 && f.disk.core.owner.unwraps == 0 && f.source.entryReads == 0)
  }

  @Test func unavailableCiphertextAllowsOnlyExplicitStaleMetadata() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    f.source.result = .unavailable
    let status = try f.reader.status()
    #expect(status.health == .incomplete && status.entries == .lastTrusted(2))
    #expect(status.issues.map(\.code) == [.referencedObjectUnavailable])
    #expect(throws: VaultUXServiceError.vaultIncomplete) { try f.reader.list(allowStale: false) }
    #expect(try f.reader.list(allowStale: true) == ["fixture/secret", "fixture/totp"])
    for stale in [false, true] {
      #expect(throws: VaultUXServiceError.vaultIncomplete) {
        try f.reader.read(name: "fixture/secret", allowStale: stale)
      }
    }
    #expect(f.disk.core.owner.unwraps == 1)
  }

  @Test(arguments: 0..<4)
  func invalidOrOversizedCiphertextNeverBecomesStalePlaintext(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    switch variant {
    case 0: f.source.result = .invalid
    case 1: f.source.result = .tooLarge
    case 2: f.source.result = .available(Data("different encrypted file".utf8))
    default: f.source.fail = true
    }
    #expect(try f.reader.status().health == .recoveryRequired)
    #expect(throws: VaultUXServiceError.recoveryRequired) { try f.reader.list(allowStale: true) }
    #expect(throws: (any Error).self) {
      try f.reader.read(name: "fixture/secret", allowStale: true)
    }
    #expect(f.disk.core.owner.unwraps == 1)
  }

  @Test(arguments: 0..<3)
  func closureBudgetsAreEnforced(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let maximum = try #require(f.disk.entries.values.map(\.canonicalBytes.count).max())
    let limits = V3ManifestRepositoryLimits(
      maximumManifestObjects: 4096, maximumHistoryDepth: 1024,
      maximumReferencedEntryObjects: variant == 0 ? 1 : 16384,
      maximumEntryBytes: variant == 1 ? 1 : maximum,
      maximumTotalEntryBytes: variant == 2 ? maximum : 256 * 1024 * 1024)
    let reader = V3RecoveryReadOnlyVaultRuntime(
      source: f.source, unlockRuntime: f.unlock, limits: limits)
    #expect(try reader.status().health == .recoveryRequired)
    #expect(throws: VaultUXServiceError.recoveryRequired) { try reader.list(allowStale: true) }
    if variant == 1 {
      #expect(throws: VaultUXServiceError.recoveryRequired) {
        try reader.read(name: "fixture/secret", allowStale: false)
      }
    }
  }

  @Test(arguments: 0..<6, 0..<3)
  func changesDuringEntryIOBlockPlaintextNamesAndStatus(change: Int, operation: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    f.source.onEntry = {
      switch change {
      case 0: f.unlock.lock()
      case 1: f.disk.checkpoints.value = f.disk.core.checkpoint.canonicalBytes
      case 2:
        try f.session.install(
          Core.nextKey, vaultID: Core.vaultID, keyID: f.disk.parent.body.fields.keyID)
      default: f.pending[change - 3].value = Data("pending work".utf8)
      }
    }
    #expect(throws: (any Error).self) {
      switch operation {
      case 0: _ = try f.reader.read(name: "fixture/secret", allowStale: true)
      case 1: _ = try f.reader.list(allowStale: true)
      default: _ = try f.reader.status()
      }
    }
    #expect(f.disk.core.owner.unwraps == 1)
  }

  @Test(arguments: [false, true], 0..<3)
  func retainedContextDoesNotSurviveLockReplacementOrCheckpointAdvance(warm: Bool, change: Int)
    throws
  {
    let f = try Fixture()
    defer { f.disk.remove() }
    let first = try f.unlock.authenticatedReadContext(reason: "Software cold context")
    let context =
      try warm ? f.unlock.authenticatedReadContext(reason: "Software warm context") : first
    #expect(try context.loadVaultKey(keyID: f.disk.parent.body.fields.keyID) == Core.nextKey)
    switch change {
    case 0:
      f.unlock.lock()
      _ = try f.unlock.authenticatedReadContext(reason: "Software replacement authentication")
    case 1:
      try f.session.install(
        Core.nextKey, vaultID: Core.vaultID, keyID: f.disk.parent.body.fields.keyID)
    default: f.disk.checkpoints.value = f.disk.core.checkpoint.canonicalBytes
    }
    #expect(throws: (any Error).self) { try context.revalidate() }
    #expect(throws: (any Error).self) {
      try context.loadVaultKey(keyID: f.disk.parent.body.fields.keyID)
    }
  }

  @Test func contextRejectsWrongKeySelectorWithoutDiscardingItsValidSession() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let context = try f.unlock.authenticatedReadContext(reason: "Software key selector")
    #expect(throws: V3RecoveryVaultUnlockError.locked) {
      try context.loadVaultKey(
        keyID: V3VaultKeyID.derive(vaultKey: Core.oldKey, vaultID: Core.vaultID))
    }
    #expect(try context.loadVaultKey(keyID: f.disk.parent.body.fields.keyID) == Core.nextKey)
    #expect(f.disk.core.owner.unwraps == 1)
  }

  @Test(arguments: 0..<3)
  func pendingOwnershipBlocksAuthorizationBeforeUnwrap(namespace: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    f.pending[namespace].value = Data([1])
    #expect(throws: VaultUXServiceError.recoveryRequired) {
      try f.reader.authorizeRead(name: "fixture/secret", allowStale: false)
    }
    #expect(f.disk.core.owner.unwraps == 0 && f.loader.loads == 0)
  }

  @Test func historyAndWritesAreNotFalselyReportedAsSupported() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    #expect(throws: AppError.self) { try f.reader.authorizeMutation() }
    #expect(throws: AppError.self) { try f.reader.resolve([]) }
    #expect(throws: AppError.self) { try f.reader.conflicts() }
    #expect(throws: AppError.self) { try f.reader.conflict(id: "unknown") }
    #expect(throws: AppError.self) {
      try f.reader.conflictValue(id: "unknown", versionID: "unknown")
    }
    #expect(f.loader.loads == 0 && f.source.entryReads == 0 && f.source.listings == 0)
  }

  @Test func readsFollowActualSameEpochPublicationAndColdReopen() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    _ = try f.reader.read(name: "fixture/secret", allowStale: false)
    try V3RecoveryVaultMutationService(
      vaultID: Core.vaultID, session: f.session, objectStore: f.disk.store,
      checkpointStore: f.disk.checkpoints, recoveryAnchorStore: f.pending[0],
      registrationAnchorStore: f.pending[1], adoptionAnchorStore: f.pending[2], cache: f.disk.cache
    ).add(
      name: "fixture/caf\u{e9}", secret: "actual saved contents", type: .secret,
      operationID: .init())
    let saved = try f.reader.read(name: "fixture/cafe\u{301}", allowStale: false)
    #expect(saved.plaintext == "actual saved contents" && f.disk.core.owner.unwraps == 1)
    #expect(
      try f.reader.list(allowStale: false) == [
        "fixture/caf\u{e9}", "fixture/secret", "fixture/totp",
      ])
    f.unlock.lock()
    #expect(
      try f.reader.read(name: "fixture/caf\u{e9}", allowStale: false).plaintext == saved.plaintext)
    #expect(f.disk.core.owner.unwraps == 2 && f.source.listings == 0)
    #expect(f.pending.allSatisfy { $0.value == nil })
  }

  private struct Fixture: Sendable {
    let disk: Publication.Fixture
    let session = V3DeviceWrappedVaultKeySessionStore()
    let pending = [Publication.Ownership(), Publication.Ownership(), Publication.Ownership()]
    let source: Source
    let loader: Loader
    let unlock: V3RecoveryVaultUnlockRuntime
    var reader: V3RecoveryReadOnlyVaultRuntime { .init(source: source, unlockRuntime: unlock) }
    init(empty: Bool = false) throws {
      disk = try Publication.Fixture(empty: empty)
      source = Source(store: disk.store)
      loader = Loader(identity: disk.core.owner)
      unlock = .init(
        vaultID: Core.vaultID, checkpointStore: disk.checkpoints, source: source,
        cache: disk.cache, identityLoader: loader, session: session,
        transactionOwnershipStore: pending[0], registrationOwnershipStore: pending[1],
        adoptionOwnershipStore: pending[2])
    }
  }

  private final class Loader: V3DeviceWrappedIdentityLoading, @unchecked Sendable {
    let identity: any V3DeviceWrappedVaultKeyUnwrapping
    var loads = 0
    init(identity: any V3DeviceWrappedVaultKeyUnwrapping) { self.identity = identity }
    func loadDeviceIdentity(vaultID _: String, reason _: String) throws -> (
      any V3DeviceWrappedVaultKeyUnwrapping
    )? {
      loads += 1
      return identity
    }
  }

  private final class Source: V3ImmutableObjectReading, @unchecked Sendable {
    let store: V3FilesystemTransactionArtifactStore
    var result: V3RepositoryObjectRead?
    var fail = false
    var onEntry: @Sendable () throws -> Void = {}
    var entryReads = 0
    var listings = 0
    init(store: V3FilesystemTransactionArtifactStore) { self.store = store }
    func readManifest(digest: Data, maximumBytes: Int) throws -> V3RepositoryObjectRead {
      try store.readManifest(digest: digest, maximumBytes: maximumBytes)
    }
    func readEntry(entryID: String, digest: Data, maximumBytes: Int) throws
      -> V3RepositoryObjectRead
    {
      entryReads += 1
      if fail { throw Core.FixtureError.cancelled }
      let bytes =
        try result ?? store.readEntry(entryID: entryID, digest: digest, maximumBytes: maximumBytes)
      try onEntry()
      return bytes
    }
    func manifestDigests(maximumCount _: Int) throws -> V3RepositoryDirectoryListing {
      listings += 1
      throw Core.FixtureError.cancelled
    }
  }
}
