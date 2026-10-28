import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Concrete software Mac identities, real profile-3 history, publication and
/// the real helper mutation queue. No shipping hook, native UI or token.
struct V3RecoveryVaultRuntimeTests {
  private typealias Epochs = V3RecoveryCatchUpTestSupport
  private typealias Core = V3RecoveryRegistrationTestSupport

  @Test func coldUnlockCatchesUpMixedHistoryThenReadsSavesAndReopens() throws {
    let f = try Fixture(cold: true)
    defer { f.disk.disk.remove() }
    try f.disk.edit("before rotation")
    _ = try f.disk.publish(.rotation)
    try f.disk.edit("after rotation")
    let runtime = f.runtime()
    try runtime.unlock()
    #expect(f.disk.receiver.unwraps == 2) // Initial Mac wrapper plus one new epoch.
    #expect(
      try runtime.read(name: "fixture/secret", allowStale: false).plaintext == "after rotation")
    #expect(try runtime.list(allowStale: false) == ["fixture/secret", "fixture/totp"])
    #expect(try runtime.status().health == .ready)
    #expect(try runtime.conflicts().isEmpty)
    #expect(f.disk.receiver.unwraps == 2 && f.disk.local.value == f.disk.disk.checkpoints.value)
    try f.owner.perform(.addEntry) { scope in
      try runtime.authorizeMutation()
      try runtime.add(
        name: "local/new", secret: "saved locally", type: .secret, operationID: scope.operationID)
    }
    #expect(try runtime.read(name: "local/new", allowStale: false).plaintext == "saved locally")
    #expect(f.disk.receiver.unwraps == 2)
    runtime.lock()
    #expect(!f.disk.session.hasResidentKey)
    #expect(try runtime.read(name: "local/new", allowStale: false).plaintext == "saved locally")
    #expect(f.disk.receiver.unwraps == 3 && f.disk.pending.allSatisfy { $0.value == nil })
  }

  @Test func allOrdinaryMutationRoutesReuseTheOuterHelperOperation() throws {
    let f = try Fixture()
    defer { f.disk.disk.remove() }
    let runtime = f.runtime()
    try f.owner.perform(.editEntry) { scope in
      try runtime.edit(
        name: "fixture/secret", secret: "edited", type: .secret, operationID: scope.operationID)
    }
    try f.owner.perform(.copyEntry) { scope in
      try runtime.copy(
        source: "fixture/secret", destination: "local/copy", overwrite: false,
        operationID: scope.operationID)
    }
    try f.owner.perform(.moveEntry) { scope in
      try runtime.move(
        source: "local/copy", destination: "local/moved", overwrite: false,
        operationID: scope.operationID)
    }
    try f.owner.perform(.removeEntry) { scope in
      try runtime.remove(name: "fixture/secret", operationID: scope.operationID)
    }
    #expect(f.owner.calls.value == 4) // A nested queue would not complete.
    #expect(try runtime.read(name: "local/moved", allowStale: false).plaintext == "edited")
    #expect(f.disk.receiver.unwraps == 0 && f.disk.pending.allSatisfy { $0.value == nil })
  }

  @Test func contentConflictHasExplicitStaleReadsMetadataAndOwnedResolution() throws {
    let f = try Fixture()
    defer { f.disk.disk.remove() }
    try f.disk.edit("competing edit")
    try f.disk.branchFromFloor()
    let runtime = f.runtime()
    #expect(throws: VaultUXServiceError.catchUpContentConflict) {
      try runtime.read(name: "fixture/secret", allowStale: false)
    }
    #expect(try runtime.status().health == .contentConflicted)
    let stale = try runtime.read(name: "fixture/secret", allowStale: true)
    #expect(stale.plaintext == "Software fixture secret e\u{301}\r\n")
    let conflict = try #require(runtime.conflicts().first)
    let detail = try runtime.conflict(id: conflict.id)
    #expect(detail.versions.count == 2)
    let values = try detail.versions.map {
      try runtime.conflictValue(id: conflict.id, versionID: $0.id)
    }
    #expect(Set(values) == ["competing edit", "late old-epoch branch"])
    #expect(throws: VaultUXServiceError.contentConflict) {
      try f.owner.perform(.editEntry) { scope in
        try runtime.edit(
          name: "fixture/secret", secret: "must not publish", type: .secret,
          operationID: scope.operationID)
      }
    }
    #expect(f.disk.local.value == f.disk.floor.checkpoint.canonicalBytes)
    try f.owner.perform(.resolveConflict) { scope in
      try runtime.resolve(
        [.init(conflictID: conflict.id, versionID: detail.versions[0].id)],
        operationID: scope.operationID)
    }
    #expect(try runtime.status().health == .ready && runtime.conflicts().isEmpty)
    #expect(throws: VaultUXServiceError.conflictNotFound) { try runtime.conflict(id: conflict.id) }
    #expect(f.disk.receiver.unwraps == 0)
  }

  @Test func disjointPublishedEditsMergeBeforeAnOrdinarySave() throws {
    let f = try Fixture()
    defer { f.disk.disk.remove() }
    try f.disk.edit("secret branch")
    let branch = try V3RecoveryContentMutationBuilder().build(
      .edit(name: "fixture/totp", type: .totp, plaintext: "MZXW6YTBOI"),
      checkpoint: f.disk.floor.checkpoint, parent: f.disk.floor.envelope,
      currentEntries: f.disk.initialEntries, vaultKey: f.disk.initialKey)
    try f.disk.disk.seed(branch.envelope, entries: branch.stagedEntries)
    let runtime = f.runtime()
    try f.owner.perform(.addEntry) { scope in
      try runtime.add(
        name: "local/after-merge", secret: "saved", type: .secret, operationID: scope.operationID)
    }
    #expect(
      try runtime.read(name: "fixture/secret", allowStale: false).plaintext == "secret branch")
    #expect(try runtime.read(name: "fixture/totp", allowStale: false).plaintext == "MZXW6YTBOI")
    #expect(try runtime.read(name: "local/after-merge", allowStale: false).plaintext == "saved")
    #expect(f.disk.receiver.unwraps == 0 && f.disk.pending.allSatisfy { $0.value == nil })
  }

  @Test(arguments: 0 ..< 6)
  func conflictValueDoesNotReuseAnOldReviewAfterQueuedChanges(change: Int) throws {
    let f = try Fixture()
    defer { f.disk.disk.remove() }
    try f.disk.edit("first branch")
    try f.disk.branchFromFloor()
    let runtime = f.runtime()
    let detail = try #require(runtime.conflicts().first)
    let version = try #require(runtime.conflict(id: detail.id).versions.first)
    f.owner.onEnter = {
      switch change {
      case 0: runtime.lock()
      case 1:
        try f.disk.session.install(
          f.disk.initialKey, vaultID: Core.vaultID, keyID: f.disk.floor.envelope.body.fields.keyID)
      case 2: try f.disk.branchFromFloor()
      default: f.disk.pending[change - 3].value = Data([1])
      }
    }
    #expect(throws: (any Error).self) {
      try runtime.conflictValue(id: detail.id, versionID: version.id)
    }
    #expect(
      f.disk.receiver.unwraps == 0 && f.disk.local.value == f.disk.floor.checkpoint.canonicalBytes)
  }

  @Test(arguments: [false, true])
  func missingNewerFilesAllowOnlyExplicitUnadvancedStaleAccess(epoch: Bool) throws {
    let f = try Fixture()
    defer { f.disk.disk.remove() }
    if epoch { _ = try f.disk.publish(.rotation) }
    try f.disk.edit("unavailable newer value")
    let entry = try #require(f.disk.entries.values.first { $0.context.name == "fixture/secret" })
    try FileManager.default.removeItem(at: f.disk.disk.entryURL(entry))
    let runtime = f.runtime()
    #expect(try runtime.status().health == .incomplete)
    #expect(
      try runtime.read(name: "fixture/secret", allowStale: true).plaintext
        == "Software fixture secret e\u{301}\r\n")
    #expect(try runtime.list(allowStale: true).count == 2)
    #expect(
      f.disk.receiver.unwraps == 0 && f.disk.local.value == f.disk.floor.checkpoint.canonicalBytes)
    #expect(throws: VaultUXServiceError.vaultIncomplete) {
      try runtime.read(name: "fixture/secret", allowStale: false)
    }
    #expect(!f.disk.session.hasResidentKey && f.disk.receiver.unwraps == 0)
  }

  @Test(arguments: 0 ..< 3)
  func invalidOrCompetingAuthorityAndRevocationNeverGrantStaleAccess(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.disk.remove() }
    if variant == 0 {
      let bytes = Data("not a manifest".utf8)
      let digest = Data(SHA256.hash(data: bytes))
      let operationID = VaultTransactionOperationID()
      try f.disk.disk.store.stageManifest(bytes, digest: digest, operationID: operationID)
      try f.disk.disk.store.publishStagedManifest(bytes, digest: digest, operationID: operationID)
    } else {
      _ = try f.disk.publish(.rotation)
      if variant == 1 {
        try f.disk.branchFromFloor()
      } else {
        _ = try f.disk.revoke(f.disk.receiver)
      }
    }
    let runtime = f.runtime()
    #expect(throws: (any Error).self) { try runtime.read(name: "fixture/secret", allowStale: true) }
    #expect(f.disk.receiver.unwraps == 0 && !f.disk.session.hasResidentKey)
    #expect(f.disk.local.value == f.disk.floor.checkpoint.canonicalBytes)
  }

  @Test(arguments: 0 ..< 3)
  func everyPendingNamespaceStopsReadAndMutationBeforePrivateAccess(namespace: Int) throws {
    let f = try Fixture(cold: true)
    defer { f.disk.disk.remove() }
    f.disk.pending[namespace].value = Data("pending".utf8)
    let runtime = f.runtime()
    #expect(throws: VaultUXServiceError.recoveryRequired) {
      try runtime.read(name: "fixture/secret", allowStale: true)
    }
    #expect(throws: VaultUXServiceError.recoveryRequired) {
      try f.owner.perform(.removeEntry) { scope in
        try runtime.remove(name: "fixture/secret", operationID: scope.operationID)
      }
    }
    #expect(f.disk.receiver.unwraps == 0 && f.loader.loads == 0)
    #expect(f.disk.pending[namespace].value == Data("pending".utf8))
  }

  @Test(arguments: [false, true], 0 ..< 3)
  func lockReplacementOrCheckpointChangeWhileQueuedDoesNotBecomeFreshAuthentication(
    cold: Bool, change: Int
  ) throws {
    let f = try Fixture(cold: cold)
    defer { f.disk.disk.remove() }
    f.owner.onEnter = {
      switch change {
      case 0: f.disk.session.invalidate()
      case 1:
        try f.disk.session.install(
          f.disk.initialKey, vaultID: Core.vaultID, keyID: f.disk.floor.envelope.body.fields.keyID)
      default: f.disk.local.value = Data([1])
      }
    }
    #expect(throws: (any Error).self) {
      try f.runtime().read(name: "fixture/secret", allowStale: false)
    }
    #expect(f.disk.receiver.unwraps == 0 && f.loader.loads == 0)
    #expect(!f.disk.session.hasResidentKey)
  }

  @Test(arguments: 0 ..< 5)
  func identityHandOffCannotReviveLockReplacementOrPendingWork(change: Int) throws {
    let f = try Fixture()
    defer { f.disk.disk.remove() }
    f.loader.onLoad = {
      switch change {
      case 0: f.disk.session.invalidate()
      case 1:
        try f.disk.session.install(
          f.disk.initialKey, vaultID: Core.vaultID, keyID: f.disk.floor.envelope.body.fields.keyID)
      default: f.disk.pending[change - 2].value = Data([1])
      }
    }
    #expect(throws: (any Error).self) {
      try f.runtime().read(name: "fixture/secret", allowStale: true)
    }
    #expect(f.disk.receiver.unwraps == 0 && f.loader.loads == 1 && !f.disk.session.hasResidentKey)
  }

  @Test func lockDuringNewEpochOpeningKeepsFloorAndDoesNotRetry() throws {
    let f = try Fixture()
    defer { f.disk.disk.remove() }
    _ = try f.disk.publish(.rotation)
    let runtime = f.runtime()
    f.disk.receiver.onUnwrap = { runtime.lock() }
    #expect(throws: AppError.self) { try runtime.read(name: "fixture/secret", allowStale: true) }
    #expect(f.disk.receiver.unwraps == 1 && !f.disk.session.hasResidentKey)
    #expect(f.disk.local.value == f.disk.floor.checkpoint.canonicalBytes)
  }

  @Test func invalidNamesAndUnownedResolveDoNotAuthenticate() throws {
    let f = try Fixture(cold: true)
    defer { f.disk.disk.remove() }
    let runtime = f.runtime()
    #expect(throws: AppError.self) { try runtime.read(name: "bad//name", allowStale: false) }
    #expect(throws: AppError.self) {
      try runtime.authorizeRead(name: "bad\nname", allowStale: true)
    }
    #expect(throws: AppError.self) { try runtime.resolve([]) }
    #expect(f.loader.loads == 0 && f.owner.calls.value == 0 && f.disk.receiver.unwraps == 0)
  }

  @Test func memorySessionStatusAndLockAreNoninteractive() throws {
    let f = try Fixture(cold: true)
    defer { f.disk.disk.remove() }
    let runtime = f.runtime()
    #expect(!runtime.sessionStatus(at: nil).isUnlocked)
    runtime.lock()
    #expect(!runtime.sessionStatus(at: nil).isUnlocked)
    #expect(f.loader.loads == 0 && f.owner.calls.value == 0 && f.disk.receiver.unwraps == 0)
    _ = try runtime.read(name: "fixture/secret", allowStale: false)
    let loads = f.loader.loads
    #expect(runtime.sessionStatus(at: nil).isUnlocked)
    runtime.lock()
    #expect(!runtime.sessionStatus(at: nil).isUnlocked)
    #expect(f.loader.loads == loads && f.disk.receiver.unwraps == 1)
  }

  @Test(arguments: [false, true], 0 ..< 4)
  func interruptedOrdinarySaveReconcilesBeforeReadWithoutANewAuthenticationHandOff(
    cold: Bool, stage: Int
  ) throws {
    let f = try Fixture(cold: cold)
    defer { f.disk.disk.remove() }
    let phases: [V3ImmutableTransactionPhase] = [
      .recoveryAnchorPrepared, .manifestStaged, .manifestPublished, .checkpointAdvanced,
    ]
    let candidate = try V3RecoveryContentMutationBuilder().build(
      .edit(name: "fixture/secret", type: .secret, plaintext: "interrupted save"),
      checkpoint: f.disk.floor.checkpoint, parent: f.disk.floor.envelope,
      currentEntries: f.disk.initialEntries, vaultKey: f.disk.initialKey)
    #expect(throws: Core.FixtureError.cancelled) {
      try V3RecoveryContentMutationPublisher(
        mutationOwner: f.owner, objectStore: f.disk.disk.store,
        checkpointStore: f.disk.local, recoveryAnchorStore: f.disk.pending[0],
        registrationAnchorStore: f.disk.pending[1], adoptionAnchorStore: f.disk.pending[2],
        cache: f.disk.localCache, phaseObserver: Interrupt(phase: phases[stage])
      ).publish(candidate, vaultKey: f.disk.initialKey)
    }
    #expect(f.disk.pending[0].value != nil)
    let runtime = f.runtime()
    let value = try runtime.read(name: "fixture/secret", allowStale: false)
    #expect(
      value.plaintext
        == (stage == 0 ? "Software fixture secret e\u{301}\r\n" : "interrupted save"))
    #expect(f.disk.pending.allSatisfy { $0.value == nil })
    #expect(f.disk.receiver.unwraps == (cold ? 1 : 0))
    #expect(try runtime.status().health == .ready)
  }

  private struct Interrupt: V3ImmutableTransactionPhaseObserving {
    let phase: V3ImmutableTransactionPhase
    func didReach(_ phase: V3ImmutableTransactionPhase, operationID _: VaultTransactionOperationID)
      throws
    {
      if phase == self.phase { throw Core.FixtureError.cancelled }
    }
  }

  private struct Fixture: Sendable {
    let disk: Epochs.Fixture
    let loader: Loader
    let owner = Owner()
    init(cold: Bool = false) throws {
      disk = try Epochs.Fixture()
      loader = Loader(identity: disk.receiver)
      if cold { disk.session.invalidate() }
    }
    func runtime() -> V3RecoveryVaultRuntime {
      .init(
        vaultID: Core.vaultID, objectStore: disk.disk.store, checkpointStore: disk.local,
        transactionOwnershipStore: disk.pending[0], registrationOwnershipStore: disk.pending[1],
        adoptionOwnershipStore: disk.pending[2], cache: disk.localCache, identityLoader: loader,
        session: disk.session, mutationOwner: owner)
    }
  }

  private final class Loader: V3DeviceWrappedIdentityLoading, @unchecked Sendable {
    let identity: any V3DeviceWrappedVaultKeyUnwrapping
    var loads = 0
    var onLoad: @Sendable () throws -> Void = {}
    init(identity: any V3DeviceWrappedVaultKeyUnwrapping) { self.identity = identity }
    func loadDeviceIdentity(vaultID _: String, reason _: String) throws -> (
      any V3DeviceWrappedVaultKeyUnwrapping
    )? {
      loads += 1
      try onLoad()
      return identity
    }
  }
  private final class Owner: VaultTransactionMutationOwning, @unchecked Sendable {
    let calls = Core.Counter()
    let base = VaultTransactionMutationOwner()
    var onEnter: @Sendable () throws -> Void = {}
    func perform<Result>(
      _ kind: VaultTransactionMutationKind,
      _ operation: (VaultTransactionMutationContext) throws -> Result
    ) throws -> Result {
      try base.perform(kind) { context in
        calls.increment()
        try onEnter()
        return try operation(context)
      }
    }
  }
}

extension V3RecoveryVaultRuntimeTests {
  @Test(arguments: [true, false])
  func sessionInvalidationStopsSubsequentPublicationEffects(beforeInitialOwnership: Bool) throws {
    let f = try Fixture()
    defer { f.disk.disk.remove() }
    let staged = Core.Counter()
    let published = Core.Counter()
    let intents = Core.Counter()
    let trigger = PublicationBoundaryOnce {
      // These checks prove the lock happens before any entry staging or object
      // publication. The true variant additionally fires before the first local
      // ownership pin or shared intent is written.
      #expect(f.disk.session.hasResidentKey)
      #expect(f.disk.local.value == f.disk.floor.checkpoint.canonicalBytes)
      #expect(staged.value == 0 && published.value == 0)
      if beforeInitialOwnership {
        #expect(f.disk.pending[0].value == nil && intents.value == 0)
      } else {
        #expect(f.disk.pending[0].value != nil && intents.value == 1)
      }
      f.disk.session.invalidate() // The exact same session operation as runtime.lock().
      #expect(!f.disk.session.hasResidentKey)
    }
    let store = PublicationBoundaryStore(
      base: f.disk.disk.store,
      beforeStage: { if !beforeInitialOwnership { trigger.fire() } },
      staged: staged, published: published, intents: intents)
    let ownership = PublicationBoundaryOwnership(base: f.disk.pending[0]) {
      if beforeInitialOwnership { trigger.fire() }
    }
    let runtime = V3RecoveryVaultRuntime(
      vaultID: Core.vaultID, objectStore: store, checkpointStore: f.disk.local,
      transactionOwnershipStore: ownership, registrationOwnershipStore: f.disk.pending[1],
      adoptionOwnershipStore: f.disk.pending[2], cache: f.disk.localCache,
      identityLoader: f.loader, session: f.disk.session, mutationOwner: f.owner)
    var returnedSessionFailure = false
    do {
      try f.owner.perform(.addEntry) { scope in
        try runtime.add(
          name: "test/after-session-change", secret: "synthetic test value",
          type: .secret, operationID: scope.operationID)
      }
      Issue.record("Mutation unexpectedly returned success after session invalidation")
    } catch AppError.authFailed {
      returnedSessionFailure = true
    }
    #expect(trigger.count == 1 && returnedSessionFailure)
    #expect(!f.disk.session.hasResidentKey)
    #expect(staged.value == (beforeInitialOwnership ? 0 : 1))
    #expect(published.value == 0 && intents.value == (beforeInitialOwnership ? 0 : 1))
    #expect(f.disk.local.value == f.disk.floor.checkpoint.canonicalBytes)
    #expect(f.disk.pending[0].value != nil) // Retain the in-flight durable prefix.
    #expect(f.disk.receiver.unwraps == 0)
    // A later request authenticates the exact interrupted prefix and abandons
    // incomplete staging. It cannot silently finish the cancelled add.
    #expect(
      try runtime.read(name: "fixture/secret", allowStale: false).plaintext
        == "Software fixture secret e\u{301}\r\n")
    #expect(f.disk.pending.allSatisfy { $0.value == nil })
    #expect(f.disk.local.value == f.disk.floor.checkpoint.canonicalBytes)
    #expect(try !runtime.list(allowStale: false).contains("test/after-session-change"))
  }

  private final class PublicationBoundaryOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var fired = false
    private let action: @Sendable () -> Void
    var count: Int { lock.withLock { fired ? 1 : 0 } }
    init(_ action: @escaping @Sendable () -> Void) { self.action = action }
    func fire() {
      let first = lock.withLock {
        guard !fired else { return false }
        fired = true
        return true
      }
      if first { action() }
    }
  }

  private struct PublicationBoundaryOwnership: V3ImmutableTransactionRecoveryAnchorStoring {
    let base: any V3ImmutableTransactionRecoveryAnchorStoring
    let beforeInitialPin: @Sendable () -> Void
    init(
      base: any V3ImmutableTransactionRecoveryAnchorStoring,
      beforeInitialPin: @escaping @Sendable () -> Void
    ) {
      self.base = base
      self.beforeInitialPin = beforeInitialPin
    }
    func loadRecoveryAnchor(vaultID: String) throws -> Data? {
      try base.loadRecoveryAnchor(vaultID: vaultID)
    }
    func replaceRecoveryAnchor(_ anchor: Data?, expectedAnchor: Data?, vaultID: String) throws {
      if anchor != nil && expectedAnchor == nil { beforeInitialPin() }
      try base.replaceRecoveryAnchor(anchor, expectedAnchor: expectedAnchor, vaultID: vaultID)
    }
  }

  private struct PublicationBoundaryStore: V3TransactionArtifactStore {
    let base: any V3TransactionArtifactStore
    let beforeStage: @Sendable () -> Void
    let staged: Core.Counter
    let published: Core.Counter
    let intents: Core.Counter
    func manifestDigests(maximumCount: Int) throws -> V3RepositoryDirectoryListing {
      try base.manifestDigests(maximumCount: maximumCount)
    }
    func readManifest(digest: Data, maximumBytes: Int) throws -> V3RepositoryObjectRead {
      try base.readManifest(digest: digest, maximumBytes: maximumBytes)
    }
    func readEntry(entryID: String, digest: Data, maximumBytes: Int) throws
      -> V3RepositoryObjectRead
    {
      try base.readEntry(entryID: entryID, digest: digest, maximumBytes: maximumBytes)
    }
    func persistRecoveryIntent(_ data: Data, operationID: VaultTransactionOperationID) throws {
      try base.persistRecoveryIntent(data, operationID: operationID)
      intents.increment()
    }
    func readRecoveryIntent(operationID: VaultTransactionOperationID, maximumBytes: Int) throws
      -> V3RepositoryObjectRead
    {
      try base.readRecoveryIntent(operationID: operationID, maximumBytes: maximumBytes)
    }
    func removeRecoveryIntent(_ data: Data, operationID: VaultTransactionOperationID) throws {
      try base.removeRecoveryIntent(data, operationID: operationID)
    }
    func stageEntry(
      _ data: Data, entryID: String, digest: Data,
      operationID: VaultTransactionOperationID
    ) throws {
      beforeStage()
      try base.stageEntry(data, entryID: entryID, digest: digest, operationID: operationID)
      staged.increment()
    }
    func stageManifest(_ data: Data, digest: Data, operationID: VaultTransactionOperationID) throws
    {
      try base.stageManifest(data, digest: digest, operationID: operationID)
    }
    func readStagedEntry(
      entryID: String, digest: Data, operationID: VaultTransactionOperationID,
      maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
      try base.readStagedEntry(
        entryID: entryID, digest: digest, operationID: operationID,
        maximumBytes: maximumBytes)
    }
    func readStagedManifest(
      digest: Data, operationID: VaultTransactionOperationID,
      maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
      try base.readStagedManifest(
        digest: digest, operationID: operationID,
        maximumBytes: maximumBytes)
    }
    func publishStagedEntry(
      _ data: Data, entryID: String, digest: Data,
      operationID: VaultTransactionOperationID
    ) throws {
      try base.publishStagedEntry(data, entryID: entryID, digest: digest, operationID: operationID)
      published.increment()
    }
    func publishStagedManifest(
      _ data: Data, digest: Data,
      operationID: VaultTransactionOperationID
    ) throws {
      try base.publishStagedManifest(data, digest: digest, operationID: operationID)
      published.increment()
    }
    func removeStagedEntry(
      _ data: Data, entryID: String, digest: Data,
      operationID: VaultTransactionOperationID
    ) throws {
      try base.removeStagedEntry(data, entryID: entryID, digest: digest, operationID: operationID)
    }
    func removeStagedManifest(
      _ data: Data, digest: Data,
      operationID: VaultTransactionOperationID
    ) throws {
      try base.removeStagedManifest(data, digest: digest, operationID: operationID)
    }
    func removeEmptyTransactionDirectories(
      operationID: VaultTransactionOperationID,
      entryIDs: [String]
    ) throws {
      try base.removeEmptyTransactionDirectories(operationID: operationID, entryIDs: entryIDs)
    }
  }
}
