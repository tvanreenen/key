import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Concrete software Mac identities, real profile-3 history, publication and
/// the real helper mutation queue. No shipping hook, native UI or token.
struct V3RecoveryVaultRuntimeTests {
  private typealias Epochs = V3RecoveryKeyTransitionCatchUpTests
  private typealias Core = V3RecoveryRegistrationTests

  @Test func coldUnlockCatchesUpMixedHistoryThenReadsSavesAndReopens() throws {
    let f = try Fixture(cold: true)
    defer { f.disk.disk.remove() }
    try f.disk.edit("before rotation")
    _ = try f.disk.publish(.rotation)
    try f.disk.edit("after rotation")
    let runtime = f.runtime()
    try runtime.unlock()
    #expect(f.disk.receiver.unwraps == 2)  // Initial Mac wrapper plus one new epoch.
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
    #expect(f.owner.calls.value == 4)  // A nested queue would not complete.
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

  @Test(arguments: 0..<6)
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

  @Test(arguments: 0..<3)
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

  @Test(arguments: 0..<3)
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

  @Test(arguments: [false, true], 0..<3)
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

  @Test(arguments: 0..<5)
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

  @Test(arguments: [false, true], 0..<4)
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
