import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Concrete step services, independent Mac sessions and contained immutable
/// publication. No mocked steps, native prompts, real vault or token operations.
struct V3RecoveryCatchUpCoordinatorTests {
  typealias Epochs = V3RecoveryKeyTransitionCatchUpTests
  private typealias Fixture = Epochs.Fixture
  private typealias Core = V3RecoveryRegistrationTests
  private typealias Publication = V3RecoveryContentMutationPublisherTests

  @Test(arguments: Epochs.Action.allCases, [false, true])
  func publishedLifecycleAndFollowingSaveReachCurrent(action: Epochs.Action, empty: Bool) throws {
    let f = try Fixture(empty: empty, last: action == .lastRemoval)
    defer { f.disk.remove() }
    _ = try f.publish(action)
    let owner = CountingOwner()
    let signed = f.owner.signatures
    let result = try current(service(f, owner: owner).catchUp(from: f.floor))
    #expect(result.0.envelope == f.parent && result.1.keyEpochCount == 1)
    #expect(result.1.contentManifestCount == 0 && owner.calls.value == 1)
    #expect(f.local.value == f.disk.checkpoints.value && f.receiver.unwraps == 1)
    #expect(f.owner.signatures == signed && f.pending.allSatisfy { $0.value == nil })
    try V3RecoveryVaultMutationService(
      vaultID: Core.vaultID, session: f.session, objectStore: f.disk.store,
      checkpointStore: f.local, recoveryAnchorStore: f.pending[0],
      registrationAnchorStore: f.pending[1], adoptionAnchorStore: f.pending[2], cache: f.localCache
    ).add(
      name: "after/catch-up", secret: "continuing Mac save", type: .secret, operationID: .init())
    #expect(f.local.value != f.disk.checkpoints.value && f.receiver.unwraps == 1)
  }

  @Test func mixedEditsAndSeveralEpochsFinishUnderOneRealMutationBoundary() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    try f.edit("before first rotation")
    _ = try f.publish(.rotation)
    try f.edit("between rotations")
    _ = try f.publish(.rotation)
    try f.edit("after second rotation")
    try f.edit("last edit")
    let owner = CountingOwner()
    let result = try current(service(f, owner: owner).catchUp(from: f.floor))
    #expect(result.0.envelope == f.parent && f.local.value == f.disk.checkpoints.value)
    #expect(result.1 == .init(contentManifestCount: 2, keyEpochCount: 2))
    #expect(f.receiver.unwraps == 2 && owner.calls.value == 1)
    #expect(try f.session.load(vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID) == f.key)
  }

  @Test(arguments: [0, 2])
  func sameEpochOnlyAndUnchangedFloorNeedNoPrivateOpening(edits: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    for index in 0..<edits { try f.edit("edit \(index)") }
    let owner = CountingOwner()
    let result = try current(service(f, owner: owner).catchUp(from: f.floor))
    #expect(result.0.envelope == f.parent)
    #expect(result.1 == .init(contentManifestCount: edits, keyEpochCount: 0))
    #expect(f.receiver.unwraps == 0 && owner.calls.value == 1 && f.session.hasResidentKey)
  }

  @Test func initialContentConflictReturnsBothHeadsWithoutChoosingOrLocking() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    try f.edit("main branch")
    try f.branchFromFloor()
    guard
      case .contentConflict(let trusted, let heads, let progress) = try service(f).catchUp(
        from: f.floor)
    else { throw Publication.Stop.interrupted }
    #expect(trusted.envelope == f.floor.envelope && heads.count == 2)
    #expect(progress.totalStepCount == 0 && f.local.value == f.floor.checkpoint.canonicalBytes)
    #expect(f.receiver.unwraps == 0 && f.session.hasResidentKey)
  }

  @Test(arguments: [false, true])
  func closedEpochCompetitionAndLaterRevocationRefuseBeforeOpening(revoked: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    _ = try f.publish(.rotation)
    if revoked { _ = try f.revoke(f.receiver) } else { try f.branchFromFloor() }
    #expect(throws: (any Error).self) { try service(f).catchUp(from: f.floor) }
    #expect(f.receiver.unwraps == 0 && f.local.value == f.floor.checkpoint.canonicalBytes)
    #expect(!f.session.hasResidentKey)
  }

  @Test(arguments: [false, true])
  func lateSiblingAfterContentOrEpochCommitCannotReturnCurrent(epoch: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    if epoch { _ = try f.publish(.rotation) } else { try f.edit("main branch") }
    let cp = Checkpoints(f.local) { try f.branchFromFloor() }
    #expect(throws: (any Error).self) { try service(f, checkpoints: cp).catchUp(from: f.floor) }
    #expect(f.local.value != f.floor.checkpoint.canonicalBytes && !f.session.hasResidentKey)
    #expect(f.receiver.unwraps == (epoch ? 1 : 0))
  }

  @Test(arguments: [false, true])
  func budgetStopsAtACommittedPrefixAndExactTerminalBudgetSucceeds(epoch: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    if epoch { _ = try f.publish(.rotation) } else { try f.edit("first edit") }
    let first = f.parent
    let firstKey = f.key
    if epoch { _ = try f.publish(.rotation) } else { try f.edit("second edit") }
    #expect(throws: V3RecoveryContentCatchUpError.stepLimitExceeded) {
      try service(f, maximumStepCount: 1).catchUp(from: f.floor)
    }
    let floor = V3RecoveryContentCommit(
      checkpoint: try .init(vaultID: Core.vaultID, envelopeDigest: first.digest), envelope: first)
    #expect(f.local.value == floor.checkpoint.canonicalBytes && !f.session.hasResidentKey)
    #expect(f.receiver.unwraps == (epoch ? 1 : 0))
    // Explicit warm-session restart from the exact committed prefix, not an
    // automatic retry or native-unlock qualification.
    try f.session.install(firstKey, vaultID: Core.vaultID, keyID: first.body.fields.keyID)
    let result = try current(service(f, maximumStepCount: 1).catchUp(from: floor))
    #expect(result.0.envelope == f.parent && result.1.totalStepCount == 1)
  }

  @Test func cancellationInSecondEpochKeepsFirstCommitWithoutAutomaticRetry() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let first = try f.publish(.rotation)
    _ = try f.publish(.rotation)
    f.receiver.onUnwrap = {
      if f.receiver.unwraps == 2 { throw Publication.Stop.interrupted }
    }
    #expect(throws: Publication.Stop.interrupted) { try service(f).catchUp(from: f.floor) }
    #expect(f.receiver.unwraps == 2 && !f.session.hasResidentKey)
    #expect(
      f.local.value
        == (try V3ManifestCheckpoint(
          vaultID: Core.vaultID, envelopeDigest: first.digest)).canonicalBytes)
    #expect(f.pending.allSatisfy { $0.value == nil })
  }

  @Test(arguments: [false, true])
  func lockOrSameKeyReplacementBetweenEpochsCannotBeAdopted(reinstall: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let first = try f.publish(.rotation)
    let firstKey = f.key
    _ = try f.publish(.rotation)
    let firstCP = try V3ManifestCheckpoint(vaultID: Core.vaultID, envelopeDigest: first.digest)
    let seenAfterCommit = Core.Counter()
    let source = Source(f.disk.store) {
      if f.local.value == firstCP.canonicalBytes {
        seenAfterCommit.increment()
        // First read belongs to the epoch service's post-CAS check. The second
        // starts the coordinator's original-floor check after atomic install.
        if seenAfterCommit.value == 2 {
          f.session.invalidate()
          if reinstall {
            try f.session.install(firstKey, vaultID: Core.vaultID, keyID: first.body.fields.keyID)
          }
        }
      }
    }
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
      try service(f, source: source).catchUp(from: f.floor)
    }
    #expect(f.local.value == firstCP.canonicalBytes && f.receiver.unwraps == 1)
    #expect(!f.session.hasResidentKey)
  }

  @Test(arguments: 0..<5)
  func postContentCommitPendingCheckpointAndSessionRacesRefuse(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    try f.edit("first edit")
    let first = f.parent
    try f.edit("second edit")
    let cp = Checkpoints(f.local) {
      switch variant {
      case 0..<3: f.pending[variant].value = Data([1])
      case 3: f.local.value = Data([1])
      default:
        f.session.invalidate()
        try f.unlock()
      }
    }
    #expect(throws: (any Error).self) { try service(f, checkpoints: cp).catchUp(from: f.floor) }
    #expect(
      f.local.value
        == (variant == 3
          ? Data([1])
          : try V3ManifestCheckpoint(
            vaultID: Core.vaultID, envelopeDigest: first.digest
          ).canonicalBytes))
    #expect(f.receiver.unwraps == 0 && !f.session.hasResidentKey)
  }

  @Test(arguments: 0..<5)
  func wrongFloorIdentityColdSessionAndPendingWorkRefuseBeforeOpening(variant: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    _ = try f.publish(.rotation)
    if variant == 0 { f.session.invalidate() }
    if variant == 1 { f.local.value = Data([1]) }
    if variant == 2 { f.pending[1].value = Data([1]) }
    let identity = variant == 3 ? try Core.Owner() : f.receiver
    let floor =
      variant == 4
      ? V3RecoveryContentCommit(
        checkpoint: f.floor.checkpoint, envelope: f.parent) : f.floor
    #expect(throws: (any Error).self) {
      try service(f, identity: identity).catchUp(from: floor)
    }
    #expect(f.receiver.unwraps == 0 && !f.session.hasResidentKey)
  }

  @Test func missingLaterCiphertextAndRepositoryBudgetStopBeforeOpening() throws {
    for missing in [false, true] {
      let f = try Fixture()
      defer { f.disk.remove() }
      _ = try f.publish(.rotation)
      try f.edit("later edit")
      if missing {
        let entry = try #require(f.entries.values.first)
        try FileManager.default.removeItem(at: f.disk.entryURL(entry))
      }
      #expect(throws: (any Error).self) {
        try service(f, maximumParentEdges: missing ? 16_384 : 1).catchUp(from: f.floor)
      }
      #expect(f.receiver.unwraps == 0 && !f.session.hasResidentKey)
      #expect(f.local.value == f.floor.checkpoint.canonicalBytes)
    }
  }

  @Test func cacheFailureDoesNotPreventCompleteAuthenticatedCatchUp() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    _ = try f.publish(.rotation)
    try f.edit("final edit")
    let result = try current(service(f, cache: FailingCache()).catchUp(from: f.floor))
    #expect(result.0.envelope == f.parent && f.session.hasResidentKey)
  }

  @Test func concurrentStaleCallersCannotInterleaveTheComposedOperation() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    _ = try f.publish(.rotation)
    try f.edit("final edit")
    let owner = CountingOwner()
    let successes = Core.Counter()
    let failures = Core.Counter()
    DispatchQueue.concurrentPerform(iterations: 2) { _ in
      do {
        _ = try current(service(f, owner: owner).catchUp(from: f.floor))
        successes.increment()
      } catch { failures.increment() }
    }
    #expect(successes.value == 1 && failures.value == 1 && owner.calls.value == 2)
    #expect(f.local.value == f.disk.checkpoints.value && f.receiver.unwraps == 1)
    #expect(!f.session.hasResidentKey)
  }

  @Test func continuationReceiptTracksRealEpochInstallationsWithoutRevivingAdmission() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    _ = try f.publish(.rotation)
    _ = try f.publish(.rotation)
    let admission = f.session.beginAuthentication()
    let result = try service(f).catchUp(from: f.floor, continuing: admission, allowStale: false)
    guard case .verified(.current(let floor, _)) = result.selection else {
      throw Publication.Stop.interrupted
    }
    #expect(floor.envelope == f.parent && f.receiver.unwraps == 2)
    try f.session.requireCurrent(result.ticket)
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
      try f.session.requireCurrent(admission)
    }
  }

  @Test(arguments: 0..<3)
  func continuedReadSourceGuardDetectsLateFilesWithoutPrivateOpening(change: Int) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    try f.edit("saved contents")
    let result = try service(f).catchUp(
      from: f.floor,
      continuing: f.session.beginAuthentication(), allowStale: false)
    try result.revalidatePublishedSource()
    switch change {
    case 0: try f.branchFromFloor()
    case 1: try FileManager.default.removeItem(at: f.disk.manifestURL(f.parent.digest))
    default:
      let entry = try #require(f.entries.values.first { $0.context.name == "fixture/secret" })
      try FileManager.default.removeItem(at: f.disk.entryURL(entry))
    }
    #expect(throws: (any Error).self) { try result.revalidatePublishedSource() }
    #expect(f.receiver.unwraps == 0)
    try f.session.requireCurrent(result.ticket)
  }

  @Test func queueWaitCannotAdoptAnUnrelatedSameKeyReauthentication() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let owner = AdmissionOwner(before: {
      f.session.invalidate()
      try f.unlock()
    })
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
      try service(f, owner: owner).catchUp(from: f.floor)
    }
    #expect(f.receiver.unwraps == 0 && !f.session.hasResidentKey)
    #expect(f.local.value == f.floor.checkpoint.canonicalBytes)
  }

  @Test(arguments: [false, true])
  func transportFallbackStillRequiresExactAuthenticatedFloor(mismatched: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let source = UnavailableListing(base: f.disk.store)
    if mismatched { try f.edit("not the locally selected envelope") }
    let floor =
      mismatched
      ? V3RecoveryContentCommit(checkpoint: f.floor.checkpoint, envelope: f.parent) : f.floor
    let admission = f.session.beginAuthentication()
    if mismatched {
      #expect(throws: V3RecoveryValidationError.invalidObject) {
        try service(f, source: source).catchUp(from: floor, continuing: admission, allowStale: true)
      }
      #expect(!f.session.hasResidentKey)
    } else {
      let result = try service(f, source: source).catchUp(
        from: floor, continuing: admission, allowStale: true)
      guard case .incomplete(let selected) = result.selection else {
        throw Publication.Stop.interrupted
      }
      #expect(selected.envelope == floor.envelope && f.session.hasResidentKey)
      try f.session.requireCurrent(result.ticket)
    }
    #expect(f.receiver.unwraps == 0 && f.local.value == f.floor.checkpoint.canonicalBytes)
  }

  @Test func missingFilesAfterCommittedAdvanceCannotFallBackToOriginalFloor() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    try f.edit("first edit")
    let first = f.parent
    try f.edit("later edit")
    let removed = try #require(f.entries.values.first { $0.context.name == "fixture/secret" })
    let checkpoints = Checkpoints(f.local) {
      try FileManager.default.removeItem(at: f.disk.entryURL(removed))
    }
    #expect(throws: (any Error).self) {
      try service(f, checkpoints: checkpoints).catchUp(
        from: f.floor, continuing: f.session.beginAuthentication(), allowStale: true)
    }
    #expect(
      f.local.value
        == (try V3ManifestCheckpoint(vaultID: Core.vaultID, envelopeDigest: first.digest)
          .canonicalBytes))
    #expect(!f.session.hasResidentKey && f.receiver.unwraps == 0)
  }

  private func current(_ outcome: V3RecoveryCatchUpCoordinatorOutcome) throws
    -> (V3RecoveryContentCommit, V3RecoveryCatchUpProgress)
  {
    guard case .current(let value, let progress) = outcome else {
      throw Publication.Stop.interrupted
    }
    return (value, progress)
  }

  private func service(
    _ f: Fixture, identity: (any V3DeviceWrappedVaultKeyUnwrapping)? = nil,
    source: (any V3ImmutableObjectReading)? = nil,
    checkpoints: (any V3ManifestCheckpointStoring)? = nil,
    owner: (any VaultTransactionMutationOwning)? = nil,
    cache: (any V3CheckpointManifestCaching)? = nil,
    maximumParentEdges: Int = 16_384, maximumStepCount: Int = 4_096
  ) -> V3RecoveryCatchUpCoordinator {
    .init(
      mutationOwner: owner ?? VaultTransactionMutationOwner(), identity: identity ?? f.receiver,
      session: f.session, source: source ?? f.disk.store, checkpointStore: checkpoints ?? f.local,
      recoveryAnchorStore: f.pending[0], registrationAnchorStore: f.pending[1],
      adoptionAnchorStore: f.pending[2], cache: cache ?? f.localCache,
      maximumParentEdges: maximumParentEdges, maximumStepCount: maximumStepCount)
  }

  private final class CountingOwner: VaultTransactionMutationOwning, Sendable {
    let calls = Core.Counter()
    let base = VaultTransactionMutationOwner()
    func perform<Result>(
      _ kind: VaultTransactionMutationKind,
      _ mutation: (VaultTransactionMutationContext) throws -> Result
    ) throws -> Result {
      try base.perform(kind) { context in
        calls.increment()
        return try mutation(context)
      }
    }
  }

  private struct AdmissionOwner: VaultTransactionMutationOwning {
    let base = VaultTransactionMutationOwner()
    let before: @Sendable () throws -> Void
    func perform<Result>(
      _ kind: VaultTransactionMutationKind,
      _ operation: (VaultTransactionMutationContext) throws -> Result
    ) throws -> Result {
      try base.perform(kind) { context in
        try before()
        return try operation(context)
      }
    }
  }

  private struct UnavailableListing: V3ImmutableObjectReading {
    let base: any V3ImmutableObjectReading
    func manifestDigests(maximumCount _: Int) throws -> V3RepositoryDirectoryListing {
      .unavailable
    }
    func readManifest(digest: Data, maximumBytes: Int) throws -> V3RepositoryObjectRead {
      try base.readManifest(digest: digest, maximumBytes: maximumBytes)
    }
    func readEntry(entryID: String, digest: Data, maximumBytes: Int) throws
      -> V3RepositoryObjectRead
    {
      try base.readEntry(entryID: entryID, digest: digest, maximumBytes: maximumBytes)
    }
  }

  private struct Checkpoints: V3ManifestCheckpointStoring {
    let base: Publication.Checkpoints
    let after: @Sendable () throws -> Void
    init(_ base: Publication.Checkpoints, after: @escaping @Sendable () throws -> Void) {
      self.base = base
      self.after = after
    }
    func loadCheckpoint(vaultID: String) throws -> Data? {
      try base.loadCheckpoint(vaultID: vaultID)
    }
    func replaceCheckpoint(_ checkpoint: Data, expectedCheckpoint: Data?, vaultID: String) throws {
      try base.replaceCheckpoint(
        checkpoint, expectedCheckpoint: expectedCheckpoint, vaultID: vaultID)
      try after()
    }
  }

  private struct Source: V3ImmutableObjectReading {
    let base: any V3ImmutableObjectReading
    let action: @Sendable () throws -> Void
    init(_ base: any V3ImmutableObjectReading, action: @escaping @Sendable () throws -> Void) {
      self.base = base
      self.action = action
    }
    func manifestDigests(maximumCount: Int) throws -> V3RepositoryDirectoryListing {
      try action()
      return try base.manifestDigests(maximumCount: maximumCount)
    }
    func readManifest(digest: Data, maximumBytes: Int) throws -> V3RepositoryObjectRead {
      try base.readManifest(digest: digest, maximumBytes: maximumBytes)
    }
    func readEntry(entryID: String, digest: Data, maximumBytes: Int) throws
      -> V3RepositoryObjectRead
    {
      try base.readEntry(entryID: entryID, digest: digest, maximumBytes: maximumBytes)
    }
  }

  private struct FailingCache: V3CheckpointManifestCaching {
    func load(for _: V3ManifestCheckpoint) throws -> V3CheckpointManifestCacheLookup { .missing }
    func store(_: Data, for _: V3ManifestCheckpoint) throws { throw Publication.Stop.interrupted }
  }
}
