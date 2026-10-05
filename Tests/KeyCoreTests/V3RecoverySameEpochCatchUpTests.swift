import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

/// Real published objects/crypto with independent local checkpoint and cache
/// stores. Session keys are supplied by software fixtures, not native unlock.
struct V3RecoverySameEpochCatchUpTests {
  private typealias Publication = V3RecoveryContentMutationPublisherTests
  private typealias Fixture = Publication.Fixture
  private typealias Core = V3RecoveryRegistrationTests

  @Test func coordinatedCatchUpWalksTheCompleteChainUnderOneMutationBoundary() throws {
    let f = try Fixture()
    defer { f.remove() }
    let (first, last) = try publishChain(f)
    let local = Publication.Checkpoints(f.checkpoint.canonicalBytes)
    let owner = CountingOwner()
    guard
      case .current(let current, let count) = try service(
        f, checkpoints: local, cache: FailingCache(), owner: owner
      ).catchUp(from: floor(f), vaultKey: Core.nextKey)
    else {
      Issue.record("Expected the complete visible chain to be current")
      return
    }
    #expect(current.checkpoint == last.checkpoint && current.checkpoint != first.checkpoint)
    #expect(count == 2 && owner.calls.value == 1)
    #expect(local.value == last.checkpoint.canonicalBytes && f.ownership.value == nil)
    #expect(current.envelope.body.recovery == f.parent.body.recovery)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test func coordinatedUnchangedFloorReturnsWithoutCheckpointReplacement() throws {
    let f = try Fixture()
    defer { f.remove() }
    let cp = CheckpointRace(f.checkpoints) { throw Publication.Stop.interrupted }
    guard
      case .current(let current, let count) = try service(f, checkpoints: cp).catchUp(
        from: floor(f), vaultKey: Core.nextKey)
    else {
      Issue.record("Expected the initial floor to be current")
      return
    }
    #expect(current.checkpoint == f.checkpoint && count == 0 && cp.calls.value == 0)
  }

  @Test func coordinatedLateSiblingAfterCASReportsBothHeadsAndPreservesProgress() throws {
    let f = try Fixture()
    defer { f.remove() }
    let (first, last) = try publishChain(f)
    let branch = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "late"))
    let local = Publication.Checkpoints(f.checkpoint.canonicalBytes)
    let cp = CheckpointRace(local) { try f.seed(branch.envelope, entries: branch.stagedEntries) }
    guard
      case .contentConflict(let current, let heads, let count) = try service(
        f, checkpoints: cp
      ).catchUp(from: floor(f), vaultKey: Core.nextKey)
    else {
      Issue.record("Expected both authenticated branches, not a current result")
      return
    }
    #expect(
      current.checkpoint == first.checkpoint && local.value == first.checkpoint.canonicalBytes)
    #expect(count == 1 && cp.calls.value == 1)
    #expect(
      heads
        == [last.envelope.digest, branch.envelope.digest].sorted {
          $0.lexicographicallyPrecedes($1)
        })
  }

  @Test func coordinatedInitialBranchesDoNotChooseOrAdvanceEitherHead() throws {
    let f = try Fixture()
    defer { f.remove() }
    let a = try f.build(.remove(name: "fixture/totp"))
    let b = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "offline"))
    try f.seed(a.envelope, entries: a.stagedEntries)
    try f.seed(b.envelope, entries: b.stagedEntries)
    guard
      case .contentConflict(let current, let heads, let count) = try service(f).catchUp(
        from: floor(f), vaultKey: Core.nextKey)
    else {
      Issue.record("Expected competing initial branches")
      return
    }
    #expect(current.checkpoint == f.checkpoint && count == 0 && heads.count == 2)
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes && f.ownership.value == nil)
  }

  @Test func coordinatedStepBudgetPreservesCommittedProgressWithoutClaimingCurrent() throws {
    let f = try Fixture()
    defer { f.remove() }
    let (first, last) = try publishChain(f)
    let local = Publication.Checkpoints(f.checkpoint.canonicalBytes)
    #expect(throws: V3RecoveryContentCatchUpError.stepLimitExceeded) {
      try service(f, checkpoints: local).catchUp(
        from: floor(f), vaultKey: Core.nextKey, maximumStepCount: 1)
    }
    #expect(local.value == first.checkpoint.canonicalBytes)
    // An exact bound is permitted when the next fresh observation is terminal.
    guard
      case .current(let current, let count) = try service(f, checkpoints: local).catchUp(
        from: first, vaultKey: Core.nextKey, maximumStepCount: 1)
    else {
      Issue.record("Expected a terminal result at the exact budget")
      return
    }
    #expect(current.checkpoint == last.checkpoint && count == 1)
  }

  @Test(arguments: 0..<3)
  func coordinatedPendingWorkAfterFirstCASBlocksEveryNamespace(namespace: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let (first, _) = try publishChain(f)
    let local = Publication.Checkpoints(f.checkpoint.canonicalBytes)
    let stores = [f.ownership, f.registration, f.adoption]
    let cp = CheckpointRace(local) { stores[namespace].value = Data([1]) }
    #expect(throws: V3RecoveryContentCatchUpError.localMutationPending) {
      try service(f, checkpoints: cp).catchUp(from: floor(f), vaultKey: Core.nextKey)
    }
    #expect(local.value == first.checkpoint.canonicalBytes && cp.calls.value == 1)
    #expect(stores[namespace].value == Data([1]))
  }

  @Test(arguments: [false, true])
  func coordinatedLostCheckpointOrSourceAfterCASCannotReportCurrent(checkpoint: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let (first, _) = try publishChain(f)
    let local = Publication.Checkpoints(f.checkpoint.canonicalBytes)
    let winner = try V3ManifestCheckpoint(
      vaultID: Core.vaultID, envelopeDigest: Data(repeating: 0x55, count: 32))
    let source = Source(f.store) { count in
      if count == 3 {
        if checkpoint {
          local.value = winner.canonicalBytes
        } else {
          try FileManager.default.removeItem(at: f.manifestURL(first.envelope.digest))
        }
      }
    }
    #expect(throws: (any Error).self) {
      try service(f, checkpoints: local, source: source).catchUp(
        from: floor(f), vaultKey: Core.nextKey)
    }
    #expect(local.value == (checkpoint ? winner.canonicalBytes : first.checkpoint.canonicalBytes))
  }

  @Test func coordinatedTerminalSourceRecheckMustAgreeBeforeReturningCurrent() throws {
    let f = try Fixture()
    defer { f.remove() }
    let child = try f.build(.remove(name: "fixture/totp"))
    try f.seed(child.envelope, entries: child.stagedEntries)
    let branch = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "late"))
    let source = Source(f.store) { count in
      if count == 4 { try f.seed(branch.envelope, entries: branch.stagedEntries) }
    }
    #expect(throws: V3RecoveryValidationError.sourceChanged) {
      try service(f, source: source).catchUp(from: floor(f), vaultKey: Core.nextKey)
    }
    #expect(f.checkpoints.value != f.checkpoint.canonicalBytes)
  }

  @Test func coordinatedListingCannotHideAnAlreadyCommittedChildAndReturnTheOldFloor() throws {
    let f = try Fixture()
    defer { f.remove() }
    let (first, _) = try publishChain(f)
    let local = Publication.Checkpoints(f.checkpoint.canonicalBytes)
    let source = Source(f.store)
    let cp = CheckpointRace(local) {
      source.overrideListing = .available(
        digests: [f.parent.digest, f.core.parent.digest], objectCount: 2)
    }
    #expect(throws: V3RecoveryValidationError.sourceChanged) {
      try service(f, checkpoints: cp, source: source).catchUp(
        from: floor(f), vaultKey: Core.nextKey)
    }
    #expect(local.value == first.checkpoint.canonicalBytes && cp.calls.value == 1)
  }

  @Test func coordinatedIncompleteFinalSnapshotBlocksTheEntireWalk() throws {
    let f = try Fixture()
    defer { f.remove() }
    let (_, last) = try publishChain(f)
    let local = Publication.Checkpoints(f.checkpoint.canonicalBytes)
    let record = try #require(last.envelope.body.fields.entries.first)
    let entry = try #require(Base64URL.decodeCanonical(record.ciphertextDigest))
    guard
      case .available(let bytes) = try f.store.readEntry(
        entryID: record.entryID, digest: entry, maximumBytes: 1_000_000)
    else {
      Issue.record("Expected the published entry fixture")
      return
    }
    try FileManager.default.removeItem(at: f.entryURL(try V3EntryCipher().parse(bytes)))
    #expect(throws: V3RecoveryValidationError.entryUnavailable) {
      try service(f, checkpoints: local).catchUp(from: floor(f), vaultKey: Core.nextKey)
    }
    #expect(local.value == f.checkpoint.canonicalBytes)
  }

  @Test func twoLocalCheckpointsCatchUpAndThenPublishWithoutTokenOrSignerCalls() throws {
    let f = try Fixture()
    defer { f.remove() }
    let other = Publication.Checkpoints(f.checkpoint.canonicalBytes)
    let cache = try secondCache(f)
    let child = try f.build(
      .edit(name: "fixture/secret", type: .secret, plaintext: "first Mac edit"))
    let complete = try V3RecoveryContentMutationValidator().validate(
      child, parent: f.parent, currentEntries: f.entries, vaultKey: Core.nextKey)
    let first = try f.publisher().publish(child, vaultKey: Core.nextKey)
    #expect(other.value == f.checkpoint.canonicalBytes)
    let caughtUp = try advanced(
      service(f, checkpoints: other, cache: cache).advanceOneStep(
        from: floor(f), vaultKey: Core.nextKey))
    #expect(caughtUp.envelope == first.envelope && caughtUp.checkpoint == first.checkpoint)
    #expect(try cache.load(for: caughtUp.checkpoint) == .available(child.envelope.canonicalBytes))
    let next = try V3RecoveryContentMutationBuilder().build(
      .remove(name: "fixture/totp"), checkpoint: caughtUp.checkpoint, parent: caughtUp.envelope,
      currentEntries: complete, vaultKey: Core.nextKey)
    let second = try V3RecoveryContentMutationPublisher(
      mutationOwner: VaultTransactionMutationOwner(), objectStore: f.store,
      checkpointStore: other, recoveryAnchorStore: Publication.Ownership(),
      registrationAnchorStore: Publication.Ownership(),
      adoptionAnchorStore: Publication.Ownership(),
      cache: cache
    ).publish(next, vaultKey: Core.nextKey)
    let returned = try advanced(service(f).advanceOneStep(from: first, vaultKey: Core.nextKey))
    #expect(returned.envelope == second.envelope && f.checkpoints.value == other.value)
    #expect(second.envelope.body.recovery == f.parent.body.recovery)
    #expect(second.envelope.body.epochSigningKey == f.parent.body.epochSigningKey)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test func aLongerPathAdvancesOnlyItsFirstDirectChild() throws {
    let f = try Fixture()
    defer { f.remove() }
    let other = Publication.Checkpoints(f.checkpoint.canonicalBytes)
    let child = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "first"))
    let complete = try V3RecoveryContentMutationValidator().validate(
      child, parent: f.parent, currentEntries: f.entries, vaultKey: Core.nextKey)
    let first = try f.publisher().publish(child, vaultKey: Core.nextKey)
    let candidate = try V3RecoveryContentMutationBuilder().build(
      .remove(name: "fixture/totp"), checkpoint: first.checkpoint, parent: first.envelope,
      currentEntries: complete, vaultKey: Core.nextKey)
    // A fresh owner gives each durable publication its own operation ID.
    let last = try f.publisher(owner: VaultTransactionMutationOwner()).publish(
      candidate, vaultKey: Core.nextKey)
    let step = try advanced(
      service(f, checkpoints: other).advanceOneStep(from: floor(f), vaultKey: Core.nextKey))
    #expect(step.checkpoint == first.checkpoint && step.checkpoint != last.checkpoint)
    let final = try advanced(
      service(f, checkpoints: other).advanceOneStep(from: step, vaultKey: Core.nextKey))
    #expect(final.checkpoint == last.checkpoint)
    guard
      case .upToDate(let current) = try service(f, checkpoints: other).advanceOneStep(
        from: final, vaultKey: Core.nextKey)
    else {
      Issue.record("Expected the exact visible local floor to be current")
      return
    }
    #expect(current.checkpoint == last.checkpoint)
  }

  @Test func anUpToDateFloorDoesNotChangeLocalTrustOrCreateIntent() throws {
    let f = try Fixture()
    defer { f.remove() }
    guard
      case .upToDate(let current) = try service(f).advanceOneStep(
        from: floor(f), vaultKey: Core.nextKey)
    else {
      Issue.record("Expected an unchanged floor")
      return
    }
    #expect(current.envelope == f.parent && current.checkpoint == f.checkpoint)
    #expect(f.ownership.value == nil && f.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test func independentProductionWritesReportAllContentHeadsWithoutPickingAWinner() throws {
    let f = try Fixture()
    defer { f.remove() }
    let a = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "first writer"))
    let b = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "offline writer"))
    // A second real provider directory represents files not yet delivered to
    // the first writer. Both branches use the production publication path.
    let offlineRoot = FileManager.default.temporaryDirectory.appendingPathComponent(
      UUID().uuidString)
    try FileManager.default.createDirectory(at: offlineRoot, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: offlineRoot) }
    let offline = V3FilesystemTransactionArtifactStore(
      rootHandle: try VaultRootDirectoryHandle(opening: offlineRoot))
    try seed(f.parent, entries: Array(f.entries.values), into: offline)
    let cp = Publication.Checkpoints(f.checkpoint.canonicalBytes)
    _ = try V3RecoveryContentMutationPublisher(
      mutationOwner: VaultTransactionMutationOwner(), objectStore: offline,
      checkpointStore: cp, recoveryAnchorStore: Publication.Ownership(),
      registrationAnchorStore: Publication.Ownership(),
      adoptionAnchorStore: Publication.Ownership(), cache: f.cache
    ).publish(b, vaultKey: Core.nextKey)
    _ = try f.publisher().publish(a, vaultKey: Core.nextKey)
    // Deliver the exact immutable files after both offline writes completed.
    try f.seed(b.envelope, entries: b.stagedEntries)
    let local = Publication.Checkpoints(f.checkpoint.canonicalBytes)
    guard
      case .contentConflict(let heads) = try service(f, checkpoints: local).advanceOneStep(
        from: floor(f), vaultKey: Core.nextKey)
    else {
      Issue.record("Expected competing authenticated content heads")
      return
    }
    #expect(
      heads == [a.envelope.digest, b.envelope.digest].sorted { $0.lexicographicallyPrecedes($1) })
    #expect(local.value == f.checkpoint.canonicalBytes && f.ownership.value == nil)
  }

  @Test func stalePublicationMustCatchUpBeforeWriting() throws {
    let f = try Fixture()
    defer { f.remove() }
    let other = Publication.Checkpoints(f.checkpoint.canonicalBytes)
    let candidate = try f.build(.remove(name: "fixture/totp"))
    _ = try f.publisher().publish(
      try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "online writer")),
      vaultKey: Core.nextKey)
    let pin = Publication.Ownership()
    #expect(throws: V3RecoveryValidationError.sourceChanged) {
      try V3RecoveryContentMutationPublisher(
        mutationOwner: VaultTransactionMutationOwner(), objectStore: f.store,
        checkpointStore: other, recoveryAnchorStore: pin,
        registrationAnchorStore: Publication.Ownership(),
        adoptionAnchorStore: Publication.Ownership(), cache: f.cache
      ).publish(candidate, vaultKey: Core.nextKey)
    }
    #expect(pin.value == nil && other.value == f.checkpoint.canonicalBytes)
    _ = try advanced(
      service(f, checkpoints: other).advanceOneStep(from: floor(f), vaultKey: Core.nextKey))
  }

  @Test(arguments: 0..<3)
  func everyLocalPendingNamespaceBlocksCatchUp(namespace: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let stores = [f.ownership, f.registration, f.adoption]
    stores[namespace].value = Data("pending local work".utf8)
    #expect(throws: V3RecoveryContentCatchUpError.localMutationPending) {
      try service(f).advanceOneStep(from: floor(f), vaultKey: Core.nextKey)
    }
    #expect(stores[namespace].value != nil && f.checkpoints.value == f.checkpoint.canonicalBytes)
  }

  @Test(arguments: [false, true])
  func checkpointOrPendingWorkChangingDuringObservationStopsCatchUp(checkpoint: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let child = try f.build(.remove(name: "fixture/totp"))
    try f.seed(child.envelope, entries: child.stagedEntries)
    let replacement = try V3ManifestCheckpoint(
      vaultID: Core.vaultID, envelopeDigest: Data(repeating: 0x55, count: 32))
    let source = Source(f.store) { count in
      if count == 2 {
        if checkpoint {
          f.checkpoints.value = replacement.canonicalBytes
        } else {
          f.registration.value = Data([1])
        }
      }
    }
    #expect(
      throws: checkpoint ? V3RecoveryContentCatchUpError.checkpointChanged : .localMutationPending
    ) {
      try service(f, source: source).advanceOneStep(from: floor(f), vaultKey: Core.nextKey)
    }
    #expect(
      f.checkpoints.value == (checkpoint ? replacement.canonicalBytes : f.checkpoint.canonicalBytes)
    )
  }

  @Test func branchArrivalDuringTheFinalReadPreventsCheckpointAdvancement() throws {
    let f = try Fixture()
    defer { f.remove() }
    let child = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "first"))
    let branch = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "late branch"))
    try f.seed(child.envelope, entries: child.stagedEntries)
    let source = Source(f.store) {
      if $0 == 2 { try f.seed(branch.envelope, entries: branch.stagedEntries) }
    }
    #expect(throws: V3RecoveryValidationError.sourceChanged) {
      try service(f, source: source).advanceOneStep(from: floor(f), vaultKey: Core.nextKey)
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes)
  }

  @Test func lostCheckpointCASPreservesTheWinningCheckpoint() throws {
    let f = try Fixture()
    defer { f.remove() }
    let child = try f.build(.remove(name: "fixture/totp"))
    try f.seed(child.envelope, entries: child.stagedEntries)
    let winner = try V3ManifestCheckpoint(
      vaultID: Core.vaultID, envelopeDigest: Data(repeating: 0x55, count: 32))
    let store = CheckpointRace(f.checkpoints) { f.checkpoints.value = winner.canonicalBytes }
    #expect(throws: V3RecoveryContentCatchUpError.checkpointChanged) {
      try service(f, checkpoints: store).advanceOneStep(from: floor(f), vaultKey: Core.nextKey)
    }
    #expect(f.checkpoints.value == winner.canonicalBytes && store.calls.value == 1)
  }

  @Test func lateSiblingAfterCASIsNotReportedAsUpToDateOnTheNextStep() throws {
    let f = try Fixture()
    defer { f.remove() }
    let child = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "first"))
    let branch = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "late"))
    try f.seed(child.envelope, entries: child.stagedEntries)
    let store = CheckpointRace(f.checkpoints) {
      try f.seed(branch.envelope, entries: branch.stagedEntries)
    }
    let step = try advanced(
      service(f, checkpoints: store).advanceOneStep(from: floor(f), vaultKey: Core.nextKey))
    #expect(step.envelope == child.envelope)
    guard
      case .contentConflict(let heads) = try service(f).advanceOneStep(
        from: step, vaultKey: Core.nextKey)
    else { throw Publication.Stop.interrupted }
    #expect(Set(heads) == [child.envelope.digest, branch.envelope.digest])
    #expect(f.checkpoints.value == step.checkpoint.canonicalBytes)
  }

  @Test func cacheFailureDoesNotUndoAnAuthenticatedStep() throws {
    let f = try Fixture()
    defer { f.remove() }
    let child = try f.build(.remove(name: "fixture/totp"))
    try f.seed(child.envelope, entries: child.stagedEntries)
    let result = try advanced(
      service(f, cache: FailingCache()).advanceOneStep(from: floor(f), vaultKey: Core.nextKey))
    #expect(
      result.envelope == child.envelope && f.checkpoints.value == result.checkpoint.canonicalBytes)
  }

  @Test(arguments: 0..<5)
  func missingOrChangedForwardObjectsDoNotAdvanceTrust(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let child = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "first"))
    try f.seed(child.envelope, entries: child.stagedEntries)
    if variant == 0 {
      try FileManager.default.removeItem(at: f.entryURL(try #require(child.stagedEntries.first)))
    }
    if variant == 1 {
      try Data("changed entry fixture".utf8).write(
        to: f.entryURL(try #require(child.stagedEntries.first)))
    }
    if variant == 2 {
      try Data("changed manifest fixture".utf8).write(to: f.manifestURL(child.envelope.digest))
    }
    if variant == 3 { try FileManager.default.removeItem(at: f.manifestURL(f.parent.digest)) }
    if variant == 4 {
      let grandchild = try V3RecoveryEpochBoundary().encode(
        body: child.envelope.body, parents: [Data(repeating: 0x55, count: 32)],
        vaultKey: Core.nextKey, authorizations: [])
      try f.seed(grandchild, entries: [])
    }
    #expect(throws: (any Error).self) {
      try service(f).advanceOneStep(from: floor(f), vaultKey: Core.nextKey)
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes && f.ownership.value == nil)
  }

  @Test(arguments: 0..<4)
  func authenticationCoverageProofAndRevisionErrorsAreRefused(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let child = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "first"))
    let old = child.envelope.body
    var entries = child.stagedEntries
    var fields = old.fields
    if variant == 3 {
      let entry = try #require(entries.first)
      let changed = try V3EntryCipher().seal(
        "fixture",
        context: V3EntryAuthenticationContext(
          vaultID: Core.vaultID, entryID: entry.context.entryID, name: entry.context.name,
          type: entry.context.type, keyID: entry.context.keyID, revision: entry.context.revision + 1
        ), vaultKey: Core.nextKey)
      entries = [changed]
      fields = try V3DeviceWrappedManifestFields(
        vaultID: old.fields.vaultID, keyID: old.fields.keyID,
        authorityTransitionID: old.fields.authorityTransitionID,
        devices: old.fields.devices, wrappedKeys: old.fields.wrappedKeys,
        entries: old.fields.entries.map {
          $0.entryID == changed.context.entryID
            ? V3ResealedEntry(encryptedEntry: changed).manifestEntry : $0
        })
    }
    let body = try V3RecoveryManifestBody(
      fields: fields, epochSigningKey: old.epochSigningKey,
      transitionProof: variant == 1 ? nil : old.transitionProof,
      recovery: variant == 2
        ? V3RecoveryRoster(generationID: old.recovery.generationID, recipients: [], wrappedKeys: [])
        : old.recovery)
    var envelope = try V3RecoveryEpochBoundary().encode(
      body: body, parents: child.envelope.parents, vaultKey: Core.nextKey, authorizations: [])
    if variant == 0 {
      let fields = try #require(CanonicalJSON.parse(envelope.canonicalBytes).objectValue)
      let bytes = CanonicalJSON.encode(
        .object(
          fields.map {
            $0.0 == "authentication"
              ? (
                "authentication",
                .object([
                  ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
                  ("tag", .string(Base64URL.encode(Data(repeating: 0x55, count: 32)))),
                ])
              ) : $0
          }))
      envelope = try V3RecoveryManifestCodec().parseEnvelope(bytes)
    }
    try f.seed(envelope, entries: entries)
    #expect(throws: (any Error).self) {
      try service(f).advanceOneStep(from: floor(f), vaultKey: Core.nextKey)
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes)
  }

  @Test func invalidTOTPAndWrongSessionKeyCannotCatchUp() throws {
    let f = try Fixture()
    defer { f.remove() }
    #expect(throws: (any Error).self) {
      try service(f).advanceOneStep(from: floor(f), vaultKey: Core.oldKey)
    }
    let old = try #require(f.entries.values.first { $0.context.type == .totp })
    let changed = try V3EntryCipher().seal(
      "not a seed",
      context: V3EntryAuthenticationContext(
        vaultID: Core.vaultID, entryID: old.context.entryID, name: old.context.name, type: .totp,
        keyID: old.context.keyID, revision: old.context.revision + 1), vaultKey: Core.nextKey)
    let b = f.parent.body
    let fields = try V3DeviceWrappedManifestFields(
      vaultID: b.fields.vaultID, keyID: b.fields.keyID,
      authorityTransitionID: b.fields.authorityTransitionID, devices: b.fields.devices,
      wrappedKeys: b.fields.wrappedKeys,
      entries: b.fields.entries.map {
        $0.entryID == changed.context.entryID
          ? V3ResealedEntry(encryptedEntry: changed).manifestEntry : $0
      })
    let envelope = try V3RecoveryEpochBoundary().encode(
      body: V3RecoveryManifestBody(
        fields: fields, epochSigningKey: b.epochSigningKey, transitionProof: b.transitionProof,
        recovery: b.recovery),
      parents: [f.parent.digest], vaultKey: Core.nextKey, authorizations: [])
    try f.seed(envelope, entries: [changed])
    #expect(throws: V3EntrySnapshotValidationError.invalidEntry) {
      try service(f).advanceOneStep(from: floor(f), vaultKey: Core.nextKey)
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes)
  }

  @Test func aKeyEpochChangeRequiresTheSeparateLifecyclePathWithoutUnwrapOrTokenUse() throws {
    let f = try Fixture()
    defer { f.remove() }
    let old = V3RecoveryContentCommit(checkpoint: f.core.checkpoint, envelope: f.core.parent)
    let local = Publication.Checkpoints(old.checkpoint.canonicalBytes)
    #expect(throws: V3RecoveryContentCatchUpError.epochTransitionRequired) {
      try service(f, checkpoints: local).advanceOneStep(from: old, vaultKey: Core.oldKey)
    }
    #expect(local.value == old.checkpoint.canonicalBytes && f.core.owner.unwraps == 0)
  }

  @Test func incompleteLaterSnapshotPreventsEvenTheFirstStepOfALongerPath() throws {
    let f = try Fixture()
    defer { f.remove() }
    let child = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "first"))
    let complete = try V3RecoveryContentMutationValidator().validate(
      child, parent: f.parent, currentEntries: f.entries, vaultKey: Core.nextKey)
    let checkpoint = try V3ManifestCheckpoint(
      vaultID: Core.vaultID, envelopeDigest: child.envelope.digest)
    let later = try V3RecoveryContentMutationBuilder().build(
      .edit(name: "fixture/secret", type: .secret, plaintext: "later"),
      checkpoint: checkpoint, parent: child.envelope, currentEntries: complete,
      vaultKey: Core.nextKey)
    try f.seed(child.envelope, entries: child.stagedEntries)
    try f.seed(later.envelope, entries: later.stagedEntries)
    try FileManager.default.removeItem(at: f.entryURL(try #require(later.stagedEntries.first)))
    #expect(throws: V3RecoveryValidationError.entryUnavailable) {
      try service(f).advanceOneStep(from: floor(f), vaultKey: Core.nextKey)
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes)
  }

  @Test func limitsApplyToTheWholeForwardGraphAndDeduplicatedSnapshots() throws {
    let f = try Fixture()
    defer { f.remove() }
    let child = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "first"))
    try f.seed(child.envelope, entries: child.stagedEntries)
    let manifestCounts = [f.core.parent, f.parent, child.envelope].map { $0.canonicalBytes.count }
    let entryCounts = (Array(f.entries.values) + child.stagedEntries).map {
      $0.canonicalBytes.count
    }
    let maximumManifest = try #require(manifestCounts.max())
    let maximumEntry = try #require(entryCounts.max())
    let limits = [
      V3ManifestRepositoryLimits(maximumManifestObjects: 2, maximumHistoryDepth: 10),
      V3ManifestRepositoryLimits(maximumManifestObjects: 10, maximumHistoryDepth: 0),
      V3ManifestRepositoryLimits(
        maximumManifestObjects: 10, maximumHistoryDepth: 10, maximumManifestBytes: 1),
      V3ManifestRepositoryLimits(
        maximumManifestObjects: 10, maximumHistoryDepth: 10, maximumEntryBytes: 1),
      V3ManifestRepositoryLimits(
        maximumManifestObjects: 10, maximumHistoryDepth: 10, maximumReferencedEntryObjects: 2),
      V3ManifestRepositoryLimits(
        maximumManifestObjects: 10, maximumHistoryDepth: 10, maximumManifestBytes: maximumManifest,
        maximumTotalManifestBytes: manifestCounts.reduce(0, +) - 1),
      V3ManifestRepositoryLimits(
        maximumManifestObjects: 10, maximumHistoryDepth: 10, maximumEntryBytes: maximumEntry,
        maximumTotalEntryBytes: entryCounts.reduce(0, +) - 1),
    ]
    for limit in limits {
      #expect(throws: (any Error).self) {
        try service(f, limits: limit).advanceOneStep(from: floor(f), vaultKey: Core.nextKey)
      }
      #expect(f.checkpoints.value == f.checkpoint.canonicalBytes)
    }
    #expect(throws: V3RecoveryValidationError.resourceLimit) {
      try service(f, maximumParentEdges: 1).advanceOneStep(from: floor(f), vaultKey: Core.nextKey)
    }
  }

  @Test(arguments: 0..<4)
  func malformedInventoryCannotHideVisibleForwardState(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let source = Source(f.store)
    let digests = [f.parent.digest, f.core.parent.digest]
    source.overrideListing =
      variant == 0
      ? .available(digests: digests + [f.parent.digest], objectCount: 3)
      : (variant == 1
        ? .available(digests: digests, objectCount: 1)
        : (variant == 2
          ? .available(digests: [Data(repeating: 0, count: 31)], objectCount: 1) : .limitExceeded))
    #expect(throws: V3RecoveryValidationError.resourceLimit) {
      try service(f, source: source).advanceOneStep(from: floor(f), vaultKey: Core.nextKey)
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes)
  }

  private func floor(_ f: Fixture) -> V3RecoveryContentCommit {
    .init(checkpoint: f.checkpoint, envelope: f.parent)
  }
  private func advanced(_ outcome: V3RecoverySameEpochCatchUpOutcome) throws
    -> V3RecoveryContentCommit
  {
    guard case .advancedOneStep(let next) = outcome else { throw Publication.Stop.interrupted }
    return next
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
      registrationAnchorStore: f.registration, adoptionAnchorStore: f.adoption,
      cache: cache ?? f.cache,
      limits: limits, maximumParentEdges: maximumParentEdges)
  }
  private func publishChain(_ f: Fixture) throws
    -> (V3RecoveryContentCommit, V3RecoveryContentCommit)
  {
    let child = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "first"))
    let complete = try V3RecoveryContentMutationValidator().validate(
      child, parent: f.parent, currentEntries: f.entries, vaultKey: Core.nextKey)
    let first = try f.publisher().publish(child, vaultKey: Core.nextKey)
    let candidate = try V3RecoveryContentMutationBuilder().build(
      .remove(name: "fixture/totp"), checkpoint: first.checkpoint, parent: first.envelope,
      currentEntries: complete, vaultKey: Core.nextKey)
    let last = try f.publisher(owner: VaultTransactionMutationOwner()).publish(
      candidate, vaultKey: Core.nextKey)
    return (first, last)
  }
  private final class CountingOwner: VaultTransactionMutationOwning, Sendable {
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
  private func secondCache(_ f: Fixture) throws -> V3CheckpointManifestFilesystemCache {
    let root = f.root.appendingPathComponent("second-local-cache")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    return V3CheckpointManifestFilesystemCache(
      rootHandle: try VaultRootDirectoryHandle(opening: root))
  }
  private func seed(
    _ envelope: V3RecoveryManifestEnvelope, entries: [V3EncryptedEntry],
    into store: V3FilesystemTransactionArtifactStore
  ) throws {
    let operation = VaultTransactionOperationID()
    for entry in entries {
      let digest = Data(SHA256.hash(data: entry.canonicalBytes))
      try store.stageEntry(
        entry.canonicalBytes, entryID: entry.context.entryID, digest: digest, operationID: operation
      )
      try store.publishStagedEntry(
        entry.canonicalBytes, entryID: entry.context.entryID, digest: digest, operationID: operation
      )
    }
    try store.stageManifest(
      envelope.canonicalBytes, digest: envelope.digest, operationID: operation)
    try store.publishStagedManifest(
      envelope.canonicalBytes, digest: envelope.digest, operationID: operation)
  }
  private final class Source: V3ImmutableObjectReading, @unchecked Sendable {
    let base: any V3ImmutableObjectReading
    let counts = Core.Counter()
    let action: @Sendable (Int) throws -> Void
    var overrideListing: V3RepositoryDirectoryListing?
    init(
      _ base: any V3ImmutableObjectReading,
      action: @escaping @Sendable (Int) throws -> Void = { _ in }
    ) {
      self.base = base
      self.action = action
    }
    func manifestDigests(maximumCount: Int) throws -> V3RepositoryDirectoryListing {
      counts.increment()
      try action(counts.value)
      return try overrideListing ?? base.manifestDigests(maximumCount: maximumCount)
    }
    func readManifest(digest: Data, maximumBytes: Int) throws -> V3RepositoryObjectRead {
      try base.readManifest(digest: digest, maximumBytes: maximumBytes)
    }
    func readEntry(entryID: String, digest: Data, maximumBytes: Int) throws
      -> V3RepositoryObjectRead
    { try base.readEntry(entryID: entryID, digest: digest, maximumBytes: maximumBytes) }
  }
  private final class CheckpointRace: V3ManifestCheckpointStoring, @unchecked Sendable {
    let base: Publication.Checkpoints
    let action: @Sendable () throws -> Void
    let calls = Core.Counter()
    init(_ base: Publication.Checkpoints, action: @escaping @Sendable () throws -> Void) {
      self.base = base
      self.action = action
    }
    func loadCheckpoint(vaultID: String) throws -> Data? {
      try base.loadCheckpoint(vaultID: vaultID)
    }
    func replaceCheckpoint(_ checkpoint: Data, expectedCheckpoint: Data?, vaultID: String) throws {
      calls.increment()
      try action()
      try base.replaceCheckpoint(
        checkpoint, expectedCheckpoint: expectedCheckpoint, vaultID: vaultID)
    }
  }
  private struct FailingCache: V3CheckpointManifestCaching {
    func load(for _: V3ManifestCheckpoint) throws -> V3CheckpointManifestCacheLookup { .missing }
    func store(_: Data, for _: V3ManifestCheckpoint) throws { throw Publication.Stop.interrupted }
  }
}
