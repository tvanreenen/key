import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Real crypto, immutable filesystem publication and bounded source inventory.
/// Local checkpoint/pin CAS and deliberate process interruptions are scripted.
struct V3RecoveryMergeMutationPublisherTests {
  private typealias Publication = V3RecoveryContentMutationPublisherTests
  private typealias Fixture = Publication.Fixture
  private typealias Core = V3RecoveryRegistrationTests
  private let branches = V3RecoveryManifestReconciliationTests()
  private static let phases: [V3ImmutableTransactionPhase] = [
    .recoveryAnchorPrepared, .recoveryIntentPersisted, .recoveryArmed,
    .entryStaged(index: 0), .manifestStaged, .repositoryStateRechecked,
    .entryPublished(index: 0), .publishedEntriesValidated, .manifestPublished,
    .publishedManifestValidated, .checkpointAdvanced, .cleanupCompleted,
  ]

  @Test(arguments: [false, true])
  func publishesEveryParentManifestLastAndPreservesRecoveryWithoutPrivateOperations(automatic: Bool)
    throws
  {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try candidate(f, automatic: automatic)
    let phases = Phases()
    let result = try publisher(f, observer: Observer { phases.append($0) }).publish(
      candidate, vaultKey: Core.nextKey)
    let expected = Self.phases.filter {
      !automatic || ($0 != .entryStaged(index: 0) && $0 != .entryPublished(index: 0))
    }
    #expect(phases.value == expected)
    #expect(result.envelope == candidate.envelope)
    #expect(f.checkpoints.value == result.checkpoint.canonicalBytes && f.ownership.value == nil)
    #expect(
      try f.cache.load(for: result.checkpoint) == .available(candidate.envelope.canonicalBytes))
    #expect(
      try Data(contentsOf: f.manifestURL(candidate.envelope.digest))
        == candidate.envelope.canonicalBytes)
    #expect(
      candidate.envelope.parents == candidate.expectedHeads && candidate.expectedHeads.count == 2)
    #expect(candidate.envelope.body.epochSigningKey == f.parent.body.epochSigningKey)
    #expect(candidate.envelope.body.transitionProof == f.parent.body.transitionProof)
    #expect(candidate.envelope.body.recovery == f.parent.body.recovery)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test(arguments: [false, true], 0..<12)
  func everyDurableBoundaryResumesExactCandidateOrAbandonsUnpublishedStaging(
    automatic: Bool, phase: Int
  ) throws {
    if automatic && (phase == 3 || phase == 6) { return }
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try candidate(f, automatic: automatic)
    #expect(throws: Publication.Stop.interrupted) {
      try publisher(
        f, observer: Observer { if $0 == Self.phases[phase] { throw Publication.Stop.interrupted } }
      )
      .publish(candidate, vaultKey: Core.nextKey)
    }
    let outcome = try publisher(f).recoverInterruptedTransaction(
      vaultID: Core.vaultID, vaultKey: Core.nextKey)
    if phase < 4 {
      #expect(outcome == .abandoned(operationID: f.operationID))
      #expect(f.checkpoints.value == f.checkpoint.canonicalBytes)
      #expect(
        !FileManager.default.fileExists(atPath: f.manifestURL(candidate.envelope.digest).path))
    } else {
      #expect(
        outcome
          == (phase == 11
            ? .nothingToRecover
            : (phase == 10
              ? .alreadyCompleted(operationID: f.operationID)
              : .completed(operationID: f.operationID))))
      #expect(
        f.checkpoints.value
          == (try V3ManifestCheckpoint(
            vaultID: Core.vaultID, envelopeDigest: candidate.envelope.digest)).canonicalBytes)
      #expect(
        try Data(contentsOf: f.manifestURL(candidate.envelope.digest))
          == candidate.envelope.canonicalBytes)
      for entry in candidate.stagedEntries {
        #expect(try Data(contentsOf: f.entryURL(entry)) == entry.canonicalBytes)
      }
    }
    #expect(f.ownership.value == nil && f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test(arguments: [false, true])
  func failedCheckpointCASResumesThePublishedExactMerge(automatic: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try candidate(f, automatic: automatic)
    f.checkpoints.rejectAdvance = true
    #expect(throws: Publication.Stop.interrupted) {
      try publisher(f).publish(candidate, vaultKey: Core.nextKey)
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes && f.ownership.value != nil)
    f.checkpoints.rejectAdvance = false
    #expect(
      try publisher(f).recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
        == .completed(operationID: f.operationID))
    #expect(
      try Data(contentsOf: f.manifestURL(candidate.envelope.digest))
        == candidate.envelope.canonicalBytes)
  }

  @Test func committedCleanupDoesNotReopenSupersededCiphertextOrRequireHistoricalManifests() throws
  {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try candidate(f, automatic: false)
    let observed = try observation(f)
    f.ownership.rejectClear = true
    let result = try publisher(f).publish(candidate, vaultKey: Core.nextKey)
    let retained = Set(candidate.envelope.body.fields.entries.map(\.ciphertextDigest))
    for entry in observed.entryObjects.values {
      if !retained.contains(Base64URL.encode(Data(SHA256.hash(data: entry.canonicalBytes)))) {
        try FileManager.default.removeItem(at: f.entryURL(entry))
      }
    }
    for digest in observed.observedManifestBytes.keys {
      try FileManager.default.removeItem(at: f.manifestURL(digest))
    }
    try FileManager.default.removeItem(
      at: f.cacheRoot.appendingPathComponent("\(Core.vaultID).json"))
    f.ownership.rejectClear = false
    #expect(
      try publisher(f).recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
        == .alreadyCompleted(operationID: f.operationID))
    #expect(f.ownership.value == nil && f.checkpoints.value == result.checkpoint.canonicalBytes)
    #expect(
      try f.cache.load(for: result.checkpoint) == .available(candidate.envelope.canonicalBytes))
  }

  @Test(arguments: [false, true])
  func pendingRegistrationOrAdoptionBlocksMergeAndResume(registration: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try candidate(f, automatic: false)
    let other = registration ? f.registration : f.adoption
    other.value = Data([1])
    #expect(throws: V3RecoveryContentPublicationError.otherMutationPending) {
      try publisher(f).publish(candidate, vaultKey: Core.nextKey)
    }
    #expect(f.ownership.value == nil)
    other.value = nil
    try interrupt(f, candidate: candidate)
    other.value = Data([1])
    #expect(throws: V3RecoveryContentPublicationError.otherMutationPending) {
      try publisher(f).recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
    }
    #expect(f.ownership.value != nil && f.checkpoints.value == f.checkpoint.canonicalBytes)
  }

  @Test(arguments: [false, true])
  func anotherPinnedMutationBlocksMergeAndOrdinarySave(mergePending: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let merge = try candidate(f, automatic: false)
    if mergePending {
      try interrupt(f, candidate: merge)
    } else {
      f.ownership.value = Data("another local intent".utf8)
    }
    let pinned = f.ownership.value
    #expect(throws: (any Error).self) { try publisher(f).publish(merge, vaultKey: Core.nextKey) }
    #expect(throws: (any Error).self) {
      try f.publisher().publish(f.build(.remove(name: "fixture/totp")), vaultKey: Core.nextKey)
    }
    #expect(f.ownership.value == pinned)
  }

  @Test(arguments: [
    V3ImmutableTransactionPhase.repositoryStateRechecked, .publishedEntriesValidated,
    .publishedManifestValidated,
  ])
  func newlyDeliveredBranchInvalidatesExactHeadSetBeforeCheckpointAdvance(
    phase: V3ImmutableTransactionPhase
  )
    throws
  {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try candidate(f, automatic: true)
    let late = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "late branch"))
    #expect(throws: (any Error).self) {
      try publisher(
        f,
        observer: Observer {
          if $0 == phase { try f.seed(late.envelope, entries: late.stagedEntries) }
        }
      )
      .publish(candidate, vaultKey: Core.nextKey)
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes && f.ownership.value != nil)
    if phase != .publishedManifestValidated {
      #expect(
        !FileManager.default.fileExists(atPath: f.manifestURL(candidate.envelope.digest).path))
    }
    #expect(throws: (any Error).self) {
      try publisher(f).recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
    }
    #expect(f.ownership.value != nil)
  }

  @Test(arguments: [false, true])
  func ownershipAndCheckpointRacesDoNotOverwriteTheWinner(checkpoint: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try candidate(f, automatic: false)
    let winner = Data("different local owner".utf8)
    #expect(throws: (any Error).self) {
      try publisher(
        f,
        observer: Observer {
          if $0 == .repositoryStateRechecked {
            if checkpoint { f.checkpoints.value = winner } else { f.ownership.value = winner }
          }
        }
      ).publish(candidate, vaultKey: Core.nextKey)
    }
    #expect(checkpoint ? f.checkpoints.value == winner : f.ownership.value == winner)
    #expect(!FileManager.default.fileExists(atPath: f.manifestURL(candidate.envelope.digest).path))
  }

  @Test func wrongKeyRefusesResumeWithoutConsumingOrChangingThePin() throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try candidate(f, automatic: false)
    try interrupt(f, candidate: candidate)
    let pin = f.ownership.value
    #expect(throws: (any Error).self) {
      try publisher(f).recoverInterruptedTransaction(
        vaultID: Core.vaultID, vaultKey: Data(repeating: 7, count: 32))
    }
    #expect(f.ownership.value == pin && f.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(
      try publisher(f).recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
        == .completed(operationID: f.operationID))
  }

  @Test func providerIntentAloneCannotResumeAndOrdinaryPublishersCannotInterpretMergeIntent() throws
  {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try candidate(f, automatic: false)
    try interrupt(f, candidate: candidate)
    let pin = f.ownership.value
    #expect(
      throws: V3ImmutableTransactionRecoveryError.invalidIntent(operationID: f.operationID.rawValue)
    ) {
      try f.publisher().recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
    }
    #expect(f.ownership.value == pin)
    let old = V3DeviceWrappedContentMutationPublisher(
      mutationOwner: VaultTransactionMutationOwner(), objectStore: f.store,
      checkpointStore: f.checkpoints, recoveryAnchorStore: f.ownership, cache: f.cache)
    #expect(
      throws: V3ImmutableTransactionRecoveryError.invalidIntent(operationID: f.operationID.rawValue)
    ) {
      try old.recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
    }
    #expect(f.ownership.value == pin)
    f.ownership.value = nil
    #expect(
      try publisher(f).recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
        == .nothingToRecover)
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes)
    f.ownership.value = pin
    #expect(
      try publisher(f).recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
        == .completed(operationID: f.operationID))
  }

  @Test(arguments: [false, true])
  func ordinaryIntentsCannotBeResumedAsMergesOrMistakenForFreshApproval(staged: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "ordinary"))
    #expect(throws: Publication.Stop.interrupted) {
      try f.publisher(
        observer: Observer {
          if $0 == (staged ? .manifestStaged : .recoveryIntentPersisted) {
            throw Publication.Stop.interrupted
          }
        }
      ).publish(candidate, vaultKey: Core.nextKey)
    }
    let pin = f.ownership.value
    #expect(
      throws: V3ImmutableTransactionRecoveryError.invalidIntent(operationID: f.operationID.rawValue)
    ) {
      try publisher(f).recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
    }
    #expect(f.ownership.value == pin && f.checkpoints.value == f.checkpoint.canonicalBytes)
    _ = try f.publisher().recoverInterruptedTransaction(
      vaultID: Core.vaultID, vaultKey: Core.nextKey)
  }

  @Test(arguments: [false, true])
  func missingResolutionCiphertextAbandonsOnlyAnUnpublishedManifest(published: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try candidate(f, automatic: false)
    #expect(throws: Publication.Stop.interrupted) {
      try publisher(
        f,
        observer: Observer {
          if $0 == (published ? .manifestPublished : .manifestStaged) {
            throw Publication.Stop.interrupted
          }
        }
      ).publish(candidate, vaultKey: Core.nextKey)
    }
    let entry = try #require(candidate.stagedEntries.first)
    try f.store.removeStagedEntry(
      entry.canonicalBytes, entryID: entry.context.entryID,
      digest: Data(SHA256.hash(data: entry.canonicalBytes)), operationID: f.operationID)
    if published {
      try FileManager.default.removeItem(at: f.entryURL(entry))
      #expect(throws: V3ImmutableTransactionRecoveryError.transactionDirectoryUnavailable) {
        try publisher(f).recoverInterruptedTransaction(
          vaultID: Core.vaultID, vaultKey: Core.nextKey)
      }
      #expect(f.ownership.value != nil)
    } else {
      #expect(
        try publisher(f).recoverInterruptedTransaction(
          vaultID: Core.vaultID, vaultKey: Core.nextKey)
          == .abandoned(operationID: f.operationID))
      #expect(f.ownership.value == nil)
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes)
  }

  @Test func exactPinnedIntentDetectsChangedSelectorsAndFreshPolicyRejectsUnknownChoices() throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try candidate(f, automatic: false)
    try interrupt(f, candidate: candidate)
    guard
      case .available(let bytes) = try f.store.readRecoveryIntent(
        operationID: f.operationID, maximumBytes: V3ImmutableTransactionRecoveryIntent.maximumBytes)
    else { throw Publication.Stop.interrupted }
    let original = try V3ImmutableTransactionRecoveryIntent(canonicalBytes: bytes)
    let choices = try #require(original.recoveryMergeResolutions)
    let changed = try V3ImmutableTransactionRecoveryIntent(
      operationID: original.operationID, kind: original.kind, vaultID: original.vaultID,
      expectedCheckpoint: original.expectedCheckpoint, expectedHeads: original.expectedHeads,
      candidateManifestDigest: original.candidateManifestDigest,
      stagedEntries: original.stagedEntries,
      recoveryMergeResolutions: choices.map {
        .init(conflictID: $0.conflictID, versionID: "aaaaaaaaaaaaaaaa")
      })
    try f.store.removeRecoveryIntent(bytes, operationID: f.operationID)
    try f.store.persistRecoveryIntent(changed.canonicalBytes, operationID: f.operationID)
    let pinned = f.ownership.value
    #expect(
      throws: V3ImmutableTransactionRecoveryError.invalidIntent(operationID: f.operationID.rawValue)
    ) {
      try publisher(f).recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
    }
    #expect(f.ownership.value == pinned)
    // Deliberately scripted local pin, not a model of provider authority. Even
    // with matching pin bytes, stale selectors do not replace fresh validation.
    f.ownership.value = try V3ImmutableTransactionRecoveryAnchor(
      operationID: f.operationID, vaultID: Core.vaultID,
      intentDigest: Data(SHA256.hash(data: changed.canonicalBytes)), phase: .recoverable
    ).canonicalBytes
    #expect(
      throws: V3ImmutableTransactionRecoveryError.invalidRecoveryState(
        operationID: f.operationID.rawValue)
    ) {
      try publisher(f).recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes && f.ownership.value != nil)
  }

  @Test(arguments: [false, true])
  func durableMergeCanBeRestoredThroughPublicHistoryAndOneSoftwareAgreement(automatic: Bool) throws
  {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try candidate(f, automatic: automatic)
    _ = try publisher(f).publish(candidate, vaultKey: Core.nextKey)
    let selection = try V3RecoveryHistorySelector(source: f.store).select(
      anchor: f.anchor, credentialPublicKey: f.core.token.publicKey.x963Representation)
    let count = Core.Counter()
    let receiver = try PIVHPKEReceiver(publicBytes: f.core.token.publicKey.x963Representation) {
      peer in
      count.increment()
      let secret = try f.core.token.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: peer))
      return secret.withUnsafeBytes { Data($0) }
    }
    let snapshot = try V3RecoverySnapshotVerifier(source: f.store).open(
      selection, boundAnchor: f.anchor, receiver: receiver)
    #expect(count.value == 1 && selection.head.digest == candidate.envelope.digest)
    #expect(snapshot.entries.first { $0.name == "fixture/secret" }?.plaintext == "selected")
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test(arguments: [false, true])
  func exactProjectedBudgetsAllowPublishedMergeResumeWithoutDoubleCounting(automatic: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try candidate(f, automatic: automatic)
    let observed = try observation(f)
    let allManifestBytes =
      observed.observedManifestBytes.values.reduce(0) { $0 + $1.count }
      + candidate.envelope.canonicalBytes.count
    let allEntryBytes =
      observed.entryObjects.values.reduce(0) { $0 + $1.canonicalBytes.count }
      + candidate.stagedEntries.reduce(0) { $0 + $1.canonicalBytes.count }
    let limits = V3ManifestRepositoryLimits(
      maximumManifestObjects: observed.listedObjectCount + 1, maximumHistoryDepth: 2,
      maximumReferencedEntryObjects: observed.entryObjects.count + candidate.stagedEntries.count,
      maximumManifestBytes: (Array(observed.observedManifestBytes.values) + [
        candidate.envelope.canonicalBytes
      ])
      .map(\.count).max()!,
      maximumEntryBytes: (Array(observed.entryObjects.values) + candidate.stagedEntries)
        .map { $0.canonicalBytes.count }.max()!,
      maximumTotalManifestBytes: allManifestBytes, maximumTotalEntryBytes: allEntryBytes)
    #expect(throws: Publication.Stop.interrupted) {
      try publisher(
        f,
        observer: Observer { if $0 == .manifestPublished { throw Publication.Stop.interrupted } },
        limits: limits
      )
      .publish(candidate, vaultKey: Core.nextKey)
    }
    #expect(
      try publisher(f, limits: limits).recoverInterruptedTransaction(
        vaultID: Core.vaultID, vaultKey: Core.nextKey)
        == .completed(operationID: f.operationID))
  }

  @Test(arguments: 0..<4)
  func tighterProjectedLimitsRefuseBeforeCreatingLocalIntent(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try candidate(f, automatic: false)
    let observed = try observation(f)
    let limits = V3ManifestRepositoryLimits(
      maximumManifestObjects: observed.listedObjectCount + (variant == 0 ? 0 : 1),
      maximumHistoryDepth: variant == 1 ? 1 : 2,
      maximumReferencedEntryObjects: observed.entryObjects.count + (variant == 2 ? 0 : 1),
      maximumManifestBytes: candidate.envelope.canonicalBytes.count,
      maximumTotalManifestBytes: observed.observedManifestBytes.values.reduce(0) { $0 + $1.count }
        + candidate.envelope.canonicalBytes.count - (variant == 3 ? 1 : 0))
    #expect(throws: (any Error).self) {
      try publisher(f, limits: limits).publish(candidate, vaultKey: Core.nextKey)
    }
    #expect(f.ownership.value == nil && f.checkpoints.value == f.checkpoint.canonicalBytes)
  }

  @Test(arguments: [false, true])
  func ordinarySaveAfterCompletedMergeKeepsTheSameRecoveryCoverage(automatic: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try candidate(f, automatic: automatic)
    let merge = try publisher(f).publish(candidate, vaultKey: Core.nextKey)
    let entries = try branches.entryMap(f, envelope: merge.envelope)
    let next = try V3RecoveryContentMutationBuilder().build(
      .edit(name: "fixture/secret", type: .secret, plaintext: "saved after merge"),
      checkpoint: merge.checkpoint, parent: merge.envelope, currentEntries: entries,
      vaultKey: Core.nextKey)
    let saved = try f.publisher(owner: VaultTransactionMutationOwner()).publish(
      next, vaultKey: Core.nextKey)
    #expect(saved.envelope.parents == [merge.envelope.digest])
    #expect(saved.envelope.body.recovery == f.parent.body.recovery)
    #expect(f.checkpoints.value == saved.checkpoint.canonicalBytes && f.ownership.value == nil)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test(arguments: [
    V3ImmutableTransactionPhase.publishedEntriesValidated, .publishedManifestValidated,
  ])
  func changedRetainedCiphertextCannotActivateOrResumeMerge(phase: V3ImmutableTransactionPhase)
    throws
  {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try candidate(f, automatic: true)
    let retained = try #require(candidate.envelope.body.fields.entries.first)
    let key = try V3RecoveryMergeMutationValidator.address(retained)
    let entry = try #require(try branches.entryMap(f, envelope: candidate.envelope)[key])
    #expect(throws: (any Error).self) {
      try publisher(
        f,
        observer: Observer {
          if $0 == phase { try Data("changed encrypted fixture".utf8).write(to: f.entryURL(entry)) }
        }
      ).publish(candidate, vaultKey: Core.nextKey)
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes && f.ownership.value != nil)
    if phase == .publishedEntriesValidated {
      #expect(
        !FileManager.default.fileExists(atPath: f.manifestURL(candidate.envelope.digest).path))
    }
    #expect(throws: (any Error).self) {
      try publisher(f).recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
    }
    #expect(f.ownership.value != nil)
  }

  @Test(arguments: [
    V3ImmutableTransactionPhase.repositoryStateRechecked, .publishedEntriesValidated,
    .publishedManifestValidated,
  ])
  func authorityWorkAppearingDuringMergeStopsActivation(phase: V3ImmutableTransactionPhase) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try candidate(f, automatic: false)
    #expect(throws: V3RecoveryContentPublicationError.otherMutationPending) {
      try publisher(f, observer: Observer { if $0 == phase { f.adoption.value = Data([1]) } })
        .publish(candidate, vaultKey: Core.nextKey)
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes && f.ownership.value != nil)
  }

  private func candidate(_ f: Fixture, automatic: Bool) throws -> V3RecoveryMergeMutationCandidate {
    let selected = try branches.publishBranch(
      f,
      requests: [
        .edit(name: "fixture/secret", type: .secret, plaintext: "selected")
      ])
    _ = try branches.publishBranch(
      f,
      requests: automatic
        ? [.remove(name: "fixture/totp")]
        : [.edit(name: "fixture/secret", type: .secret, plaintext: "other")])
    let observed = try observation(f)
    if automatic {
      return try V3RecoveryMergeMutationBuilder().buildAutomatic(
        from: observed, vaultKey: Core.nextKey)
    }
    guard case .contentConflict(let report) = try V3RecoveryManifestReconciler().reconcile(observed)
    else {
      throw Publication.Stop.interrupted
    }
    let snapshot = V3ConflictObservationBuilder().build(
      report,
      entries: .lastTrusted(f.parent.body.fields.entries.count), trustedVersionID: nil,
      trustedHeadDigest: f.checkpoint.envelopeDigest,
      trustedEntries: Set(f.parent.body.fields.entries))
    let choices = try snapshot.conflicts.map { detail in
      let version = try #require(
        detail.versions.first { v3LowercaseHex(selected.envelope.digest).hasPrefix($0.id) })
      return VaultConflictResolution(conflictID: detail.summary.id, versionID: version.id)
    }
    return try V3RecoveryMergeMutationBuilder().buildResolution(
      choices, from: observed, vaultKey: Core.nextKey)
  }

  private func observation(_ f: Fixture) throws -> V3RecoverySameEpochObservation {
    try V3RecoverySameEpochRepositoryObserver(source: f.store).observe(
      from: .init(checkpoint: f.checkpoint, envelope: f.parent), vaultKey: Core.nextKey)
  }

  private func publisher(
    _ f: Fixture,
    observer: any V3ImmutableTransactionPhaseObserving = V3NoopContentTransactionPhaseObserver(),
    limits: V3ManifestRepositoryLimits = .standard
  ) -> V3RecoveryMergeMutationPublisher {
    V3RecoveryMergeMutationPublisher(
      mutationOwner: VaultTransactionMutationOwner(makeOperationID: { f.operationID }),
      objectStore: f.store, checkpointStore: f.checkpoints, recoveryAnchorStore: f.ownership,
      registrationAnchorStore: f.registration, adoptionAnchorStore: f.adoption, cache: f.cache,
      limits: limits, phaseObserver: observer)
  }

  private func interrupt(_ f: Fixture, candidate: V3RecoveryMergeMutationCandidate) throws {
    #expect(throws: Publication.Stop.interrupted) {
      try publisher(
        f, observer: Observer { if $0 == .manifestStaged { throw Publication.Stop.interrupted } }
      )
      .publish(candidate, vaultKey: Core.nextKey)
    }
  }

  private struct Observer: V3ImmutableTransactionPhaseObserving {
    let action: @Sendable (V3ImmutableTransactionPhase) throws -> Void
    init(_ action: @escaping @Sendable (V3ImmutableTransactionPhase) throws -> Void) {
      self.action = action
    }
    func didReach(_ phase: V3ImmutableTransactionPhase, operationID _: VaultTransactionOperationID)
      throws
    {
      try action(phase)
    }
  }
  private final class Phases: @unchecked Sendable {
    private let lock = NSLock()
    private var data: [V3ImmutableTransactionPhase] = []
    var value: [V3ImmutableTransactionPhase] { lock.withLock { data } }
    func append(_ phase: V3ImmutableTransactionPhase) { lock.withLock { data.append(phase) } }
  }
}
