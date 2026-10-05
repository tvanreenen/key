import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Genuine offline publications, merge publication and immutable provider reads.
/// Reader checkpoints/caches are independent; only persistence races are scripted.
struct V3RecoveryMergedCatchUpTests {
  private typealias Publication = V3RecoveryContentMutationPublisherTests
  private typealias Fixture = Publication.Fixture
  private typealias Core = V3RecoveryRegistrationTests
  private let branches = V3RecoveryManifestReconciliationTests()
  private static let addedID = "018f4d38-7d5a-7b20-b0f1-97d6e96c84c1"

  @Test(arguments: [false, true])
  func independentReaderAcceptsDurablyPublishedMergeWithoutCheckpointingEitherSide(automatic: Bool)
    throws
  {
    let f = try Fixture()
    defer { f.remove() }
    let merged = try publishMerge(f, automatic: automatic)
    let reader = Publication.Checkpoints(f.checkpoint.canonicalBytes)
    let writes = Checkpoints(reader)
    let cache = try readerCache(f)
    let outcome = try service(f, checkpoints: writes, cache: cache).catchUp(
      from: floor(f), vaultKey: Core.nextKey)
    guard case .current(let current, let count) = outcome else {
      throw Publication.Stop.interrupted
    }
    #expect(current.envelope == merged.envelope && count == 1)
    #expect(
      writes.values == [merged.checkpoint.canonicalBytes]
        && reader.value == merged.checkpoint.canonicalBytes)
    #expect(try cache.load(for: current.checkpoint) == .available(merged.envelope.canonicalBytes))
    #expect(current.envelope.body.recovery == f.parent.body.recovery)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0 && f.ownership.value == nil)
  }

  @Test(arguments: [false, true])
  func commonLinearPrefixAdvancesThenJumpsToFirstJoinInBothCatchUpApis(coordinated: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let common = try branches.publishBranch(
      f, requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "common")])
    let merged = try publishMerge(f, automatic: true, branchFloor: common)
    let reader = Publication.Checkpoints(f.checkpoint.canonicalBytes)
    let writes = Checkpoints(reader)
    let s = service(f, checkpoints: writes)
    if coordinated {
      guard
        case .current(let current, let count) = try s.catchUp(
          from: floor(f), vaultKey: Core.nextKey)
      else {
        throw Publication.Stop.interrupted
      }
      #expect(current.envelope == merged.envelope && count == 2)
    } else {
      guard
        case .advancedOneStep(let first) = try s.advanceOneStep(
          from: floor(f), vaultKey: Core.nextKey),
        case .advancedOneStep(let second) = try s.advanceOneStep(
          from: first, vaultKey: Core.nextKey)
      else { throw Publication.Stop.interrupted }
      #expect(first.envelope == common.envelope && second.envelope == merged.envelope)
    }
    #expect(writes.values == [common.checkpoint.canonicalBytes, merged.checkpoint.canonicalBytes])
  }

  @Test func repeatedMergesAndFollowingSaveCatchUpUnderOneBoundaryAndRemainWritable() throws {
    let f = try Fixture()
    defer { f.remove() }
    let first = try publishMerge(f, automatic: true)
    let entries = try branches.entryMap(f, envelope: first.envelope)
    _ = try branches.publishBranch(
      f,
      requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "second merge")],
      from: first, entries: entries)
    _ = try branches.publishBranch(
      f,
      requests: [
        .add(entryID: Self.addedID, name: "added/account", type: .secret, plaintext: "added")
      ], from: first, entries: entries)
    let second = try publishCandidate(
      f,
      candidate: V3RecoveryMergeMutationBuilder().buildAutomatic(
        from: observation(f), vaultKey: Core.nextKey))
    let complete = try branches.entryMap(f, envelope: second.envelope)
    let save = try V3RecoveryContentMutationBuilder().build(
      .edit(name: "fixture/secret", type: .secret, plaintext: "following save"),
      checkpoint: second.checkpoint,
      parent: second.envelope, currentEntries: complete, vaultKey: Core.nextKey)
    let last = try ordinaryPublisher(
      f, checkpoints: Publication.Checkpoints(second.checkpoint.canonicalBytes)
    ).publish(save, vaultKey: Core.nextKey)
    let reader = Publication.Checkpoints(f.checkpoint.canonicalBytes)
    let writes = Checkpoints(reader)
    let owner = Owner()
    guard
      case .current(let current, let count) = try service(f, checkpoints: writes, owner: owner)
        .catchUp(from: floor(f), vaultKey: Core.nextKey)
    else { throw Publication.Stop.interrupted }
    #expect(count == 3 && owner.calls.value == 1 && current.envelope == last.envelope)
    #expect(
      writes.values == [
        first.checkpoint.canonicalBytes, second.checkpoint.canonicalBytes,
        last.checkpoint.canonicalBytes,
      ])
    let next = try V3RecoveryContentMutationBuilder().build(
      .remove(name: "added/account"),
      checkpoint: current.checkpoint, parent: current.envelope,
      currentEntries: branches.entryMap(f, envelope: current.envelope), vaultKey: Core.nextKey)
    let saved = try ordinaryPublisher(f, checkpoints: reader).publish(next, vaultKey: Core.nextKey)
    #expect(
      reader.value == saved.checkpoint.canonicalBytes
        && saved.envelope.body.recovery == f.parent.body.recovery)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test(arguments: 0..<5)
  func everyParentAndSnapshotMustAuthenticateBeforeAnyCheckpointAdvance(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let (a, b) = try deliverBranches(f, automatic: false, from: floor(f))
    let candidate = try resolution(f, head: a.envelope.digest)
    let merged = try publishCandidate(f, candidate: candidate)
    let unselected = try #require(
      try branches.entryMap(f, envelope: b.envelope).values.first {
        $0.context.name == "fixture/secret"
      })
    switch variant {
    case 0: try FileManager.default.removeItem(at: f.manifestURL(b.envelope.digest))
    case 1: try FileManager.default.removeItem(at: f.entryURL(unselected))
    case 2: try Data("changed encrypted fixture".utf8).write(to: f.entryURL(unselected))
    case 3:
      let selected = try #require(candidate.stagedEntries.first)
      try FileManager.default.removeItem(at: f.entryURL(selected))
    default:
      let invalid = try V3RecoveryEpochBoundary().encode(
        body: f.parent.body, parents: merged.envelope.parents,
        vaultKey: Core.nextKey, authorizations: [])
      try f.seed(invalid, entries: [])
    }
    let reader = Publication.Checkpoints(f.checkpoint.canonicalBytes)
    #expect(throws: (any Error).self) {
      try service(f, checkpoints: reader).catchUp(from: floor(f), vaultKey: Core.nextKey)
    }
    #expect(reader.value == f.checkpoint.canonicalBytes)
  }

  @Test func wrongSessionKeyCannotCatchUpOrChangeCheckpoint() throws {
    let f = try Fixture()
    defer { f.remove() }
    _ = try publishMerge(f, automatic: true)
    #expect(throws: (any Error).self) {
      try service(f).catchUp(from: floor(f), vaultKey: Core.oldKey)
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes)
  }

  @Test func sourceChangeBetweenCompleteObservationsPreventsMergeActivation() throws {
    let f = try Fixture()
    defer { f.remove() }
    _ = try publishMerge(f, automatic: true)
    let late = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "late"))
    let source = Source(f.store) { count in
      if count == 2 { try f.seed(late.envelope, entries: late.stagedEntries) }
    }
    #expect(throws: V3RecoveryValidationError.sourceChanged) {
      try service(f, source: source).catchUp(from: floor(f), vaultKey: Core.nextKey)
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes)
  }

  @Test(arguments: 0..<3)
  func everyPendingNamespaceIsRecheckedBeforeMergeCheckpointCas(namespace: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    _ = try publishMerge(f, automatic: true)
    let stores = [f.ownership, f.registration, f.adoption]
    let source = Source(f.store) { count in if count == 2 { stores[namespace].value = Data([1]) } }
    #expect(throws: V3RecoveryContentCatchUpError.localMutationPending) {
      try service(f, source: source).catchUp(from: floor(f), vaultKey: Core.nextKey)
    }
    #expect(
      f.checkpoints.value == f.checkpoint.canonicalBytes && stores[namespace].value == Data([1]))
  }

  @Test func mergeCheckpointCasCannotOverwriteConcurrentLocalWinner() throws {
    let f = try Fixture()
    defer { f.remove() }
    _ = try publishMerge(f, automatic: true)
    let reader = Publication.Checkpoints(f.checkpoint.canonicalBytes)
    let winner = Data("competing local checkpoint".utf8)
    let writes = Checkpoints(reader) { _ in reader.value = winner }
    #expect(throws: V3RecoveryContentCatchUpError.checkpointChanged) {
      try service(f, checkpoints: writes).catchUp(from: floor(f), vaultKey: Core.nextKey)
    }
    #expect(reader.value == winner)
  }

  @Test(arguments: [false, true])
  func newlyDeliveredSiblingAfterPrefixCasIsNotHiddenByTheAdvancedFloor(resolve: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let common = try branches.publishBranch(
      f, requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "common")])
    let first = try publishMerge(f, automatic: true, branchFloor: common)
    let late = try f.build(
      .add(entryID: Self.addedID, name: "late/account", type: .secret, plaintext: "late"))
    let reader = Publication.Checkpoints(f.checkpoint.canonicalBytes)
    let writes = Checkpoints(reader) { count in
      if count == 1 {
        try f.seed(late.envelope, entries: late.stagedEntries)
        if resolve {
          let candidate = try V3RecoveryMergeMutationBuilder().buildAutomatic(
            from: observation(f), vaultKey: Core.nextKey)
          _ = try publishCandidate(f, candidate: candidate)
        }
      }
    }
    let outcome = try service(f, checkpoints: writes).catchUp(
      from: floor(f), vaultKey: Core.nextKey)
    if resolve {
      guard case .current(let current, let count) = outcome else {
        throw Publication.Stop.interrupted
      }
      #expect(count == 2 && current.envelope.parents.contains(first.envelope.digest))
      #expect(
        writes.values == [common.checkpoint.canonicalBytes, current.checkpoint.canonicalBytes])
    } else {
      guard case .contentConflict(let current, let heads, let count) = outcome else {
        throw Publication.Stop.interrupted
      }
      #expect(current.envelope == common.envelope && count == 1 && heads.count == 2)
      #expect(writes.values == [common.checkpoint.canonicalBytes])
    }
  }

  @Test func exactStepBudgetLeavesJoinProgressThenResumesFollowingSaveWithoutCacheDependency()
    throws
  {
    let f = try Fixture()
    defer { f.remove() }
    let merged = try publishMerge(f, automatic: true)
    let candidate = try V3RecoveryContentMutationBuilder().build(
      .edit(name: "fixture/secret", type: .secret, plaintext: "after"),
      checkpoint: merged.checkpoint, parent: merged.envelope,
      currentEntries: branches.entryMap(f, envelope: merged.envelope), vaultKey: Core.nextKey)
    let last = try ordinaryPublisher(
      f, checkpoints: Publication.Checkpoints(merged.checkpoint.canonicalBytes)
    )
    .publish(candidate, vaultKey: Core.nextKey)
    let reader = Publication.Checkpoints(f.checkpoint.canonicalBytes)
    let s = service(f, checkpoints: reader, cache: FailingCache())
    #expect(throws: V3RecoveryContentCatchUpError.stepLimitExceeded) {
      try s.catchUp(from: floor(f), vaultKey: Core.nextKey, maximumStepCount: 1)
    }
    #expect(reader.value == merged.checkpoint.canonicalBytes)
    guard
      case .current(let current, let count) = try s.catchUp(
        from: merged, vaultKey: Core.nextKey, maximumStepCount: 1)
    else { throw Publication.Stop.interrupted }
    #expect(current.envelope == last.envelope && count == 1)
  }

  @Test func missingCommittedJoinOnTerminalRecheckCannotRewindOrClaimCurrent() throws {
    let f = try Fixture()
    defer { f.remove() }
    let merged = try publishMerge(f, automatic: true)
    let reader = Publication.Checkpoints(f.checkpoint.canonicalBytes)
    let source = Source(f.store) { count in
      if count == 3 {
        try FileManager.default.removeItem(at: f.manifestURL(merged.envelope.digest))
      }
    }
    #expect(throws: V3RecoveryValidationError.sourceChanged) {
      try service(f, checkpoints: reader, source: source).catchUp(
        from: floor(f), vaultKey: Core.nextKey)
    }
    #expect(reader.value == merged.checkpoint.canonicalBytes)
  }

  @Test(arguments: [false, true])
  func coParentBelowSuppliedCheckpointAuthenticatesWithoutRewinding(coordinated: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let (a, _) = try deliverBranches(f, automatic: true, from: floor(f))
    let merged = try publishCandidate(
      f,
      candidate: V3RecoveryMergeMutationBuilder().buildAutomatic(
        from: observation(f), vaultKey: Core.nextKey))
    let reader = Publication.Checkpoints(a.checkpoint.canonicalBytes)
    let writes = Checkpoints(reader)
    if coordinated {
      guard
        case .current(let current, let count) = try service(f, checkpoints: writes).catchUp(
          from: a, vaultKey: Core.nextKey)
      else { throw Publication.Stop.interrupted }
      #expect(current.envelope == merged.envelope && count == 1)
    } else {
      guard
        case .advancedOneStep(let current) = try service(f, checkpoints: writes).advanceOneStep(
          from: a, vaultKey: Core.nextKey)
      else { throw Publication.Stop.interrupted }
      #expect(current.envelope == merged.envelope)
    }
    #expect(writes.values == [merged.checkpoint.canonicalBytes])
    #expect(reader.value == merged.checkpoint.canonicalBytes)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test(arguments: [false, true])
  func lateSiblingCanBeReconciledAndDurablyMergedFromAdvancedCheckpoint(automatic: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let (a, b) = try deliverBranches(f, automatic: automatic, from: floor(f))
    let reader = Publication.Checkpoints(a.checkpoint.canonicalBytes)
    let writes = Checkpoints(reader)
    guard
      case .contentConflict(let current, let heads, let count) = try service(
        f, checkpoints: writes
      ).catchUp(from: a, vaultKey: Core.nextKey)
    else { throw Publication.Stop.interrupted }
    #expect(
      current.envelope == a.envelope && count == 0
        && Set(heads) == [a.envelope.digest, b.envelope.digest])
    #expect(writes.values.isEmpty && reader.value == a.checkpoint.canonicalBytes)
    let observed = try V3RecoverySameEpochRepositoryObserver(source: f.store).observe(
      from: a, vaultKey: Core.nextKey)
    #expect(observed.checkpoint == a.checkpoint && observed.graphFloor == f.parent.digest)
    #expect(observed.committedAncestorDigests == [f.parent.digest, a.envelope.digest])
    #expect(!observed.envelopes.keys.contains(f.core.parent.digest))
    let candidate =
      try automatic
      ? V3RecoveryMergeMutationBuilder().buildAutomatic(from: observed, vaultKey: Core.nextKey)
      : resolution(f, head: a.envelope.digest, from: a)
    #expect(candidate.expectedCheckpoint == a.checkpoint)
    let merged = try publishCandidate(f, candidate: candidate)
    guard
      case .current(let accepted, let advanced) = try service(f, checkpoints: writes).catchUp(
        from: a, vaultKey: Core.nextKey)
    else { throw Publication.Stop.interrupted }
    #expect(
      accepted.envelope == merged.envelope && advanced == 1
        && writes.values == [merged.checkpoint.canonicalBytes])
    #expect(merged.envelope.body.recovery == a.envelope.body.recovery)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test func committedAncestorCiphertextIsNotReopenedToExplainALateBranch() throws {
    let f = try Fixture()
    defer { f.remove() }
    let common = try branches.publishBranch(
      f, requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "common")])
    let (a, _) = try deliverBranches(f, automatic: false, from: common)
    let merged = try publishCandidate(
      f, candidate: resolution(f, head: a.envelope.digest))
    let old = try branches.entryMap(f, envelope: f.parent).values.first {
      $0.context.name == "fixture/secret"
    }
    let intermediate = try branches.entryMap(f, envelope: common.envelope).values.first {
      $0.context.name == "fixture/secret"
    }
    try FileManager.default.removeItem(at: f.entryURL(try #require(old)))
    try FileManager.default.removeItem(at: f.entryURL(try #require(intermediate)))
    let reader = Publication.Checkpoints(a.checkpoint.canonicalBytes)
    let observed = try V3RecoverySameEpochRepositoryObserver(source: f.store).observe(
      from: a, vaultKey: Core.nextKey)
    #expect(
      observed.committedAncestorDigests == [
        f.parent.digest, common.envelope.digest, a.envelope.digest,
      ])
    guard
      case .current(let accepted, let count) = try service(f, checkpoints: reader).catchUp(
        from: a, vaultKey: Core.nextKey)
    else { throw Publication.Stop.interrupted }
    #expect(
      accepted.envelope == merged.envelope && count == 1
        && reader.value == merged.checkpoint.canonicalBytes)
  }

  @Test(arguments: 0..<4)
  func requiredBelowCheckpointManifestsAndNewBranchSnapshotsFailClosed(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let (a, b) = try deliverBranches(f, automatic: false, from: floor(f))
    _ = try publishCandidate(f, candidate: resolution(f, head: a.envelope.digest))
    switch variant {
    case 0: try FileManager.default.removeItem(at: f.manifestURL(f.parent.digest))
    case 1: try Data("changed ancestor fixture".utf8).write(to: f.manifestURL(f.parent.digest))
    default:
      let entry = try #require(
        try branches.entryMap(f, envelope: b.envelope).values.first {
          $0.context.name == "fixture/secret"
        })
      if variant == 2 {
        try FileManager.default.removeItem(at: f.entryURL(entry))
      } else {
        try Data("changed uncommitted branch fixture".utf8).write(to: f.entryURL(entry))
      }
    }
    let reader = Publication.Checkpoints(a.checkpoint.canonicalBytes)
    #expect(throws: (any Error).self) {
      try service(f, checkpoints: reader).catchUp(from: a, vaultKey: Core.nextKey)
    }
    #expect(reader.value == a.checkpoint.canonicalBytes)
  }

  @Test func disconnectedSameEpochFixtureDoesNotAcquireCheckpointAncestry() throws {
    let f = try Fixture()
    defer { f.remove() }
    let (a, _) = try deliverBranches(f, automatic: true, from: floor(f))
    let disconnected = try V3RecoveryEpochBoundary().encode(
      body: f.parent.body, parents: [], vaultKey: Core.nextKey, authorizations: [])
    try f.seed(disconnected, entries: [])
    let reader = Publication.Checkpoints(a.checkpoint.canonicalBytes)
    #expect(throws: V3RecoveryValidationError.unanchoredParent) {
      try service(f, checkpoints: reader).catchUp(from: a, vaultKey: Core.nextKey)
    }
    #expect(reader.value == a.checkpoint.canonicalBytes)
  }

  @Test func expandedAncestryAndForwardBranchShareTheExistingDepthBudget() throws {
    let f = try Fixture()
    defer { f.remove() }
    let (a, _) = try deliverBranches(f, automatic: true, from: floor(f))
    let merged = try publishCandidate(
      f,
      candidate: V3RecoveryMergeMutationBuilder().buildAutomatic(
        from: observation(f), vaultKey: Core.nextKey))
    let reader = Publication.Checkpoints(a.checkpoint.canonicalBytes)
    #expect(throws: V3RecoveryValidationError.resourceLimit) {
      try service(
        f, checkpoints: reader, limits: .init(maximumManifestObjects: 100, maximumHistoryDepth: 1)
      ).catchUp(
        from: a, vaultKey: Core.nextKey)
    }
    #expect(reader.value == a.checkpoint.canonicalBytes)
    guard
      case .current(let current, _) = try service(
        f, checkpoints: reader, limits: .init(maximumManifestObjects: 100, maximumHistoryDepth: 2)
      ).catchUp(from: a, vaultKey: Core.nextKey)
    else { throw Publication.Stop.interrupted }
    #expect(current.envelope == merged.envelope)
  }

  @Test func checkpointAncestryStopsAtItsCommittedEpochBoundary() throws {
    let f = try Fixture()
    defer { f.remove() }
    let (a, b) = try deliverBranches(f, automatic: true, from: floor(f))
    // The old epoch is outside this local-checkpoint authentication contract.
    try FileManager.default.removeItem(at: f.manifestURL(f.core.parent.digest))
    let reader = Publication.Checkpoints(a.checkpoint.canonicalBytes)
    guard
      case .contentConflict(let current, let heads, let count) = try service(
        f, checkpoints: reader
      ).catchUp(from: a, vaultKey: Core.nextKey)
    else { throw Publication.Stop.interrupted }
    #expect(current.envelope == a.envelope && count == 0)
    #expect(Set(heads) == [a.envelope.digest, b.envelope.digest])
    #expect(reader.value == a.checkpoint.canonicalBytes)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test func lateBranchBeforeAnAlreadyCommittedJoinCanBeMergedWithoutChoosingAnOldSide() throws {
    let f = try Fixture()
    defer { f.remove() }
    let first = try publishMerge(f, automatic: true)
    _ = try branches.publishBranch(
      f,
      requests: [
        .add(entryID: Self.addedID, name: "late/account", type: .secret, plaintext: "late")
      ])
    let observed = try V3RecoverySameEpochRepositoryObserver(source: f.store).observe(
      from: first, vaultKey: Core.nextKey)
    #expect(observed.graphFloor == f.parent.digest && observed.committedAncestorDigests.count == 4)
    let candidate = try V3RecoveryMergeMutationBuilder().buildAutomatic(
      from: observed, vaultKey: Core.nextKey)
    let merged = try publishCandidate(f, candidate: candidate)
    let reader = Publication.Checkpoints(first.checkpoint.canonicalBytes)
    let writes = Checkpoints(reader)
    guard
      case .current(let accepted, let count) = try service(f, checkpoints: writes).catchUp(
        from: first, vaultKey: Core.nextKey)
    else { throw Publication.Stop.interrupted }
    #expect(accepted.envelope == merged.envelope && count == 1)
    #expect(writes.values == [merged.checkpoint.canonicalBytes])
  }

  @Test(arguments: 0..<5)
  func expandedObservationRetainsSourcePendingAndCheckpointGuards(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let (a, b) = try deliverBranches(f, automatic: true, from: floor(f))
    _ = try publishCandidate(
      f,
      candidate: V3RecoveryMergeMutationBuilder().buildAutomatic(
        from: observation(f), vaultKey: Core.nextKey))
    let reader = Publication.Checkpoints(a.checkpoint.canonicalBytes)
    let winner = try V3ManifestCheckpoint(
      vaultID: Core.vaultID, envelopeDigest: Data(repeating: 0x66, count: 32))
    let stores = [f.ownership, f.registration, f.adoption]
    let source = Source(f.store) { count in
      if count == 2 {
        switch variant {
        case 0: try FileManager.default.removeItem(at: f.manifestURL(b.envelope.digest))
        case 1...3: stores[variant - 1].value = Data([1])
        default: reader.value = winner.canonicalBytes
        }
      }
    }
    #expect(throws: (any Error).self) {
      try service(f, checkpoints: reader, source: source).catchUp(from: a, vaultKey: Core.nextKey)
    }
    #expect(reader.value == (variant == 4 ? winner.canonicalBytes : a.checkpoint.canonicalBytes))
  }

  @Test(arguments: [false, true], 0..<3)
  func lateBranchMergeResumesWithTheExactAdvancedCheckpointAndCandidate(automatic: Bool, phase: Int)
    throws
  {
    let f = try Fixture()
    defer { f.remove() }
    let (a, _) = try deliverBranches(f, automatic: automatic, from: floor(f))
    let observed = try V3RecoverySameEpochRepositoryObserver(source: f.store).observe(
      from: a, vaultKey: Core.nextKey)
    let candidate =
      try automatic
      ? V3RecoveryMergeMutationBuilder().buildAutomatic(from: observed, vaultKey: Core.nextKey)
      : resolution(f, head: a.envelope.digest, from: a)
    let reader = Publication.Checkpoints(a.checkpoint.canonicalBytes)
    let ownership = Publication.Ownership()
    let phases: [V3ImmutableTransactionPhase] = [
      .manifestStaged, .manifestPublished, .checkpointAdvanced,
    ]
    func publisher(_ interrupt: Bool) -> V3RecoveryMergeMutationPublisher {
      .init(
        mutationOwner: VaultTransactionMutationOwner(), objectStore: f.store,
        checkpointStore: reader,
        recoveryAnchorStore: ownership, registrationAnchorStore: f.registration,
        adoptionAnchorStore: f.adoption, cache: f.cache,
        phaseObserver: Interrupt(phase: interrupt ? phases[phase] : nil))
    }
    #expect(throws: Publication.Stop.interrupted) {
      try publisher(true).publish(candidate, vaultKey: Core.nextKey)
    }
    #expect(ownership.value != nil)
    let outcome = try publisher(false).recoverInterruptedTransaction(
      vaultID: Core.vaultID, vaultKey: Core.nextKey)
    switch outcome {
    case .completed where phase < 2, .alreadyCompleted where phase == 2: break
    default: throw Publication.Stop.interrupted
    }
    let checkpoint = try V3ManifestCheckpoint(
      vaultID: Core.vaultID, envelopeDigest: candidate.envelope.digest)
    #expect(reader.value == checkpoint.canonicalBytes && ownership.value == nil)
    #expect(
      try Data(contentsOf: f.manifestURL(candidate.envelope.digest))
        == candidate.envelope.canonicalBytes)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test func crissCrossMergeBasesAreReportedWithoutSelectingOrPublishingOne() throws {
    let f = try Fixture()
    defer { f.remove() }
    let (a, b) = try deliverBranches(f, automatic: false, from: floor(f))
    let first = try resolution(f, head: a.envelope.digest)
    let second = try resolution(f, head: b.envelope.digest)
    _ = try publishCandidate(f, candidate: first)
    // Exact fixture delivery models a second preconstructed offline resolution.
    // This is not a claim that a live publisher ignores newly visible heads.
    try f.seed(second.envelope, entries: second.stagedEntries)
    let observed = try observation(f)
    guard
      case .historyConflict(let conflict) = try V3RecoveryManifestReconciler().reconcile(observed)
    else { throw Publication.Stop.interrupted }
    #expect(
      Set(conflict.commonAncestors.map(\.envelopeDigest))
        == Set([a.envelope.digest, b.envelope.digest]))
    #expect(throws: V3RecoveryMergeMutationError.invalidCandidate) {
      try V3RecoveryMergeMutationBuilder().buildAutomatic(from: observed, vaultKey: Core.nextKey)
    }
    guard
      case .contentConflict(_, let heads, let count) = try service(f).catchUp(
        from: floor(f), vaultKey: Core.nextKey)
    else { throw Publication.Stop.interrupted }
    #expect(heads.count == 2 && count == 0 && f.checkpoints.value == f.checkpoint.canonicalBytes)
  }

  @Test func aggregateHistoryAndSnapshotBudgetsIncludeAllMergedParents() throws {
    let f = try Fixture()
    defer { f.remove() }
    let merged = try publishMerge(f, automatic: false)
    let observed = try observation(f)
    let maximumManifest = try #require(observed.observedManifestBytes.values.map(\.count).max())
    let maximumEntry = try #require(
      observed.entryObjects.values.map { $0.canonicalBytes.count }.max())
    let exact = V3ManifestRepositoryLimits(
      maximumManifestObjects: observed.listedObjectCount, maximumHistoryDepth: 2,
      maximumReferencedEntryObjects: observed.entryObjects.count,
      maximumManifestBytes: maximumManifest,
      maximumEntryBytes: maximumEntry,
      maximumTotalManifestBytes: observed.observedManifestBytes.values.reduce(0) { $0 + $1.count },
      maximumTotalEntryBytes: observed.entryObjects.values.reduce(0) {
        $0 + $1.canonicalBytes.count
      })
    let reader = Publication.Checkpoints(f.checkpoint.canonicalBytes)
    guard
      case .current(let current, _) = try service(f, checkpoints: reader, limits: exact).catchUp(
        from: floor(f), vaultKey: Core.nextKey)
    else { throw Publication.Stop.interrupted }
    #expect(current.envelope == merged.envelope)
    for limits in [
      V3ManifestRepositoryLimits(
        maximumManifestObjects: observed.listedObjectCount - 1, maximumHistoryDepth: 2),
      V3ManifestRepositoryLimits(
        maximumManifestObjects: observed.listedObjectCount, maximumHistoryDepth: 1),
      V3ManifestRepositoryLimits(
        maximumManifestObjects: observed.listedObjectCount, maximumHistoryDepth: 2,
        maximumReferencedEntryObjects: observed.entryObjects.count - 1),
    ] {
      let cp = Publication.Checkpoints(f.checkpoint.canonicalBytes)
      #expect(throws: V3RecoveryValidationError.resourceLimit) {
        try service(f, checkpoints: cp, limits: limits).catchUp(
          from: floor(f), vaultKey: Core.nextKey)
      }
      #expect(cp.value == f.checkpoint.canonicalBytes)
    }
    let cp = Publication.Checkpoints(f.checkpoint.canonicalBytes)
    #expect(throws: V3RecoveryValidationError.resourceLimit) {
      try service(f, checkpoints: cp, maximumParentEdges: 4).catchUp(
        from: floor(f), vaultKey: Core.nextKey)
    }
    #expect(cp.value == f.checkpoint.canonicalBytes)
  }

  private func deliverBranches(_ f: Fixture, automatic: Bool, from base: V3RecoveryContentCommit)
    throws
    -> (V3RecoveryContentCommit, V3RecoveryContentCommit)
  {
    let entries = try branches.entryMap(f, envelope: base.envelope)
    let a = try branches.publishBranch(
      f, requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "selected")],
      from: base, entries: entries)
    let b = try branches.publishBranch(
      f,
      requests: automatic
        ? [.remove(name: "fixture/totp")]
        : [.edit(name: "fixture/secret", type: .secret, plaintext: "other")], from: base,
      entries: entries)
    return (a, b)
  }
  private func publishMerge(
    _ f: Fixture, automatic: Bool, branchFloor: V3RecoveryContentCommit? = nil
  ) throws -> V3RecoveryContentCommit {
    let (a, _) = try deliverBranches(f, automatic: automatic, from: branchFloor ?? floor(f))
    let candidate =
      try automatic
      ? V3RecoveryMergeMutationBuilder().buildAutomatic(
        from: observation(f), vaultKey: Core.nextKey)
      : resolution(f, head: a.envelope.digest)
    return try publishCandidate(f, candidate: candidate)
  }
  private func resolution(_ f: Fixture, head: Data, from current: V3RecoveryContentCommit? = nil)
    throws -> V3RecoveryMergeMutationCandidate
  {
    let current = current ?? floor(f)
    let observed = try V3RecoverySameEpochRepositoryObserver(source: f.store).observe(
      from: current, vaultKey: Core.nextKey)
    guard case .contentConflict(let report) = try V3RecoveryManifestReconciler().reconcile(observed)
    else { throw Publication.Stop.interrupted }
    let snapshot = V3ConflictObservationBuilder().build(
      report, entries: .lastTrusted(current.envelope.body.fields.entries.count),
      trustedVersionID: nil, trustedHeadDigest: current.checkpoint.envelopeDigest,
      trustedEntries: Set(current.envelope.body.fields.entries))
    let choices = try snapshot.conflicts.map { detail in
      VaultConflictResolution(
        conflictID: detail.summary.id,
        versionID: try #require(detail.versions.first { v3LowercaseHex(head).hasPrefix($0.id) }).id)
    }
    return try V3RecoveryMergeMutationBuilder().buildResolution(
      choices, from: observed, vaultKey: Core.nextKey)
  }
  private func publishCandidate(_ f: Fixture, candidate: V3RecoveryMergeMutationCandidate) throws
    -> V3RecoveryContentCommit
  {
    try V3RecoveryMergeMutationPublisher(
      mutationOwner: VaultTransactionMutationOwner(), objectStore: f.store,
      checkpointStore: Publication.Checkpoints(candidate.expectedCheckpoint.canonicalBytes),
      recoveryAnchorStore: Publication.Ownership(),
      registrationAnchorStore: Publication.Ownership(),
      adoptionAnchorStore: Publication.Ownership(), cache: f.cache
    ).publish(candidate, vaultKey: Core.nextKey)
  }
  private func ordinaryPublisher(_ f: Fixture, checkpoints: any V3ManifestCheckpointStoring)
    -> V3RecoveryContentMutationPublisher
  {
    V3RecoveryContentMutationPublisher(
      mutationOwner: VaultTransactionMutationOwner(), objectStore: f.store,
      checkpointStore: checkpoints, recoveryAnchorStore: Publication.Ownership(),
      registrationAnchorStore: Publication.Ownership(),
      adoptionAnchorStore: Publication.Ownership(), cache: f.cache)
  }
  private func floor(_ f: Fixture) -> V3RecoveryContentCommit {
    .init(checkpoint: f.checkpoint, envelope: f.parent)
  }
  private func observation(_ f: Fixture) throws -> V3RecoverySameEpochObservation {
    try V3RecoverySameEpochRepositoryObserver(source: f.store).observe(
      from: floor(f), vaultKey: Core.nextKey)
  }
  private func service(
    _ f: Fixture, checkpoints: (any V3ManifestCheckpointStoring)? = nil,
    source: (any V3ImmutableObjectReading)? = nil, cache: (any V3CheckpointManifestCaching)? = nil,
    limits: V3ManifestRepositoryLimits = .standard, maximumParentEdges: Int = 16_384,
    owner: (any VaultTransactionMutationOwning)? = nil
  ) -> V3RecoverySameEpochCatchUpService {
    V3RecoverySameEpochCatchUpService(
      mutationOwner: owner ?? VaultTransactionMutationOwner(), source: source ?? f.store,
      checkpointStore: checkpoints ?? f.checkpoints, recoveryAnchorStore: f.ownership,
      registrationAnchorStore: f.registration,
      adoptionAnchorStore: f.adoption, cache: cache ?? f.cache, limits: limits,
      maximumParentEdges: maximumParentEdges)
  }
  private func readerCache(_ f: Fixture) throws -> V3CheckpointManifestFilesystemCache {
    let root = f.root.appendingPathComponent("reader-cache")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    return V3CheckpointManifestFilesystemCache(
      rootHandle: try VaultRootDirectoryHandle(opening: root))
  }
  private final class Checkpoints: V3ManifestCheckpointStoring, @unchecked Sendable {
    let base: Publication.Checkpoints
    let action: @Sendable (Int) throws -> Void
    private let lock = NSLock()
    private var data: [Data] = []
    var values: [Data] { lock.withLock { data } }
    init(
      _ base: Publication.Checkpoints, action: @escaping @Sendable (Int) throws -> Void = { _ in }
    ) {
      self.base = base
      self.action = action
    }
    func loadCheckpoint(vaultID: String) throws -> Data? {
      try base.loadCheckpoint(vaultID: vaultID)
    }
    func replaceCheckpoint(_ checkpoint: Data, expectedCheckpoint: Data?, vaultID: String) throws {
      try action(values.count + 1)
      try base.replaceCheckpoint(
        checkpoint, expectedCheckpoint: expectedCheckpoint, vaultID: vaultID)
      lock.withLock { data.append(checkpoint) }
    }
  }
  private final class Source: V3ImmutableObjectReading, Sendable {
    let base: any V3ImmutableObjectReading
    let calls = Core.Counter()
    let action: @Sendable (Int) throws -> Void
    init(_ base: any V3ImmutableObjectReading, action: @escaping @Sendable (Int) throws -> Void) {
      self.base = base
      self.action = action
    }
    func manifestDigests(maximumCount: Int) throws -> V3RepositoryDirectoryListing {
      calls.increment()
      try action(calls.value)
      return try base.manifestDigests(maximumCount: maximumCount)
    }
    func readManifest(digest: Data, maximumBytes: Int) throws -> V3RepositoryObjectRead {
      try base.readManifest(digest: digest, maximumBytes: maximumBytes)
    }
    func readEntry(entryID: String, digest: Data, maximumBytes: Int) throws
      -> V3RepositoryObjectRead
    { try base.readEntry(entryID: entryID, digest: digest, maximumBytes: maximumBytes) }
  }
  private final class Owner: VaultTransactionMutationOwning, Sendable {
    let base = VaultTransactionMutationOwner()
    let calls = Core.Counter()
    func perform<Result>(
      _ kind: VaultTransactionMutationKind,
      _ mutation: (VaultTransactionMutationContext) throws -> Result
    ) throws -> Result {
      calls.increment()
      return try base.perform(kind, mutation)
    }
  }
  private struct FailingCache: V3CheckpointManifestCaching {
    func load(for _: V3ManifestCheckpoint) throws -> V3CheckpointManifestCacheLookup { .missing }
    func store(_: Data, for _: V3ManifestCheckpoint) throws { throw Publication.Stop.interrupted }
  }
  private struct Interrupt: V3ImmutableTransactionPhaseObserving {
    let phase: V3ImmutableTransactionPhase?
    func didReach(_ phase: V3ImmutableTransactionPhase, operationID _: VaultTransactionOperationID)
      throws
    {
      if self.phase == phase { throw Publication.Stop.interrupted }
    }
  }
}
