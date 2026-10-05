import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Independent offline publications use actual immutable stores and crypto.
/// Reconciliation receives only complete production-observer authentication.
struct V3RecoveryManifestReconciliationTests {
  typealias Publication = V3RecoveryContentMutationPublisherTests
  typealias Fixture = Publication.Fixture
  typealias Core = V3RecoveryRegistrationTests
  private static let addedID = "018f4d38-7d5a-7b20-b0f1-97d6e96c84c1"
  private static let otherID = "018f4d38-7d5a-7b20-b0f1-97d6e96c84c2"

  @Test func aSingleForwardHeadNeedsNoMergeAndDoesNotAdvanceTheLocalCheckpoint() throws {
    let f = try Fixture()
    defer { f.remove() }
    let child = try publishBranch(f, requests: [.remove(name: "fixture/totp")])
    let result = try reconcile(f)
    #expect(result == .noMergeRequired(head: try head(child)))
    try requireUnchangedLocalState(f)
  }

  @Test func independentOfflineEditsProduceExactDeterministicMergeEntries() throws {
    let f = try Fixture()
    defer { f.remove() }
    let a = try publishBranch(
      f,
      requests: [
        .edit(name: "fixture/secret", type: .secret, plaintext: "updated")
      ])
    let b = try publishBranch(
      f,
      requests: [
        .edit(name: "fixture/totp", type: .totp, plaintext: "JBSWY3DPEHPK3PXP")
      ])
    let plan = try mergePlan(reconcile(f))
    #expect(plan.commonAncestor == (try head(floor(f))))
    #expect(plan.parentHeads == (try sortedHeads([a, b])))
    #expect(plan.entries == expectedEntries(a.envelope, b.envelope))
    #expect(try reconcile(f, source: ReverseInventory(f.store)) == .automaticMerge(plan))
    try requireUnchangedLocalState(f)
  }

  @Test func threeIndependentHeadsReconcileEditDeletionAndCreation() throws {
    let f = try Fixture()
    defer { f.remove() }
    let a = try publishBranch(
      f,
      requests: [
        .edit(name: "fixture/secret", type: .secret, plaintext: "updated")
      ])
    let b = try publishBranch(f, requests: [.remove(name: "fixture/totp")])
    let c = try publishBranch(
      f,
      requests: [
        .add(entryID: Self.addedID, name: "new/account", type: .secret, plaintext: "new")
      ])
    let plan = try mergePlan(reconcile(f))
    #expect(plan.parentHeads == (try sortedHeads([a, b, c])))
    #expect(plan.entries.map(\.name) == ["fixture/secret", "new/account"])
    #expect(
      plan.entries.contains(
        try #require(
          a.envelope.body.fields.entries.first {
            $0.name == "fixture/secret"
          })))
    try requireUnchangedLocalState(f)
  }

  @Test func nearestSharedForwardCheckpointIsTheComparisonBaseNotTheOldFloor() throws {
    let f = try Fixture()
    defer { f.remove() }
    let base = try publishBranch(
      f,
      requests: [
        .edit(name: "fixture/secret", type: .secret, plaintext: "shared change")
      ])
    let entries = try entryMap(f, envelope: base.envelope)
    let a = try publishBranch(
      f, requests: [.remove(name: "fixture/totp")], from: base, entries: entries)
    let b = try publishBranch(
      f,
      requests: [
        .add(entryID: Self.addedID, name: "new/account", type: .secret, plaintext: "new")
      ], from: base, entries: entries)
    let plan = try mergePlan(reconcile(f))
    #expect(plan.commonAncestor == (try head(base)))
    #expect(plan.commonAncestor != (try head(floor(f))))
    #expect(plan.parentHeads == (try sortedHeads([a, b])))
    #expect(plan.entries.map(\.name) == ["fixture/secret", "new/account"])
    try requireUnchangedLocalState(f)
  }

  @Test(arguments: [false, true])
  func competingSameEntryEditsRemainExplicitEvenWhenPlaintextMatches(samePlaintext: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let a = try publishBranch(
      f,
      requests: [
        .edit(name: "fixture/secret", type: .secret, plaintext: "first")
      ])
    let b = try publishBranch(
      f,
      requests: [
        .edit(name: "fixture/secret", type: .secret, plaintext: samePlaintext ? "first" : "second")
      ])
    let report = try conflict(reconcile(f))
    #expect(report.heads == (try sortedHeads([a, b])))
    let entryConflict = try only(report.entryConflicts)
    #expect(entryConflict.kind == .editEdit)
    #expect(entryConflict.versions.map(\.head) == report.heads)
    #expect(
      Set(entryConflict.versions.compactMap(\.entry))
        == Set(
          [a, b].compactMap {
            $0.envelope.body.fields.entries.first { $0.name == "fixture/secret" }
          }))
    #expect(report.entriesReconciledByID.map(\.name) == ["fixture/totp"])
    try requireUnchangedLocalState(f)
  }

  @Test(arguments: [false, true])
  func deletionAgainstEditOrRenameIncludesTheExactDeletedVersion(rename: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let a = try publishBranch(f, requests: [.remove(name: "fixture/secret")])
    let original = try #require(f.entries.values.first { $0.context.name == "fixture/secret" })
    let request: V3EntryMutationRequest =
      rename
      ? .move(
        sourceName: "fixture/secret", sourceData: original.canonicalBytes,
        destinationName: "renamed/account", overwrite: false)
      : .edit(name: "fixture/secret", type: .secret, plaintext: "edited")
    let b = try publishBranch(f, requests: [request])
    let report = try conflict(reconcile(f))
    let entryConflict = try only(report.entryConflicts)
    #expect(entryConflict.kind == .deleteEdit)
    #expect(entryConflict.versions.first { $0.head == (try? head(a)) }?.entry == nil)
    #expect(entryConflict.versions.first { $0.head == (try? head(b)) }?.entry != nil)
    #expect(entryConflict.versions.count == 2)
    try requireUnchangedLocalState(f)
  }

  @Test(arguments: [false, true])
  func renameEditAndDifferentRenamesDoNotSelectASilentWinner(bothRename: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let original = try #require(f.entries.values.first { $0.context.name == "fixture/secret" })
    _ = try publishBranch(
      f,
      requests: [
        .move(
          sourceName: "fixture/secret", sourceData: original.canonicalBytes,
          destinationName: "renamed/first", overwrite: false)
      ])
    let request: V3EntryMutationRequest =
      bothRename
      ? .move(
        sourceName: "fixture/secret", sourceData: original.canonicalBytes,
        destinationName: "renamed/second", overwrite: false)
      : .edit(name: "fixture/secret", type: .secret, plaintext: "edited")
    _ = try publishBranch(f, requests: [request])
    let report = try conflict(reconcile(f))
    #expect(try only(report.entryConflicts).kind == (bothRename ? .conflictingRename : .renameEdit))
    try requireUnchangedLocalState(f)
  }

  @Test func separateEntryIdentitiesWithTheSameDestinationRemainAmbiguous() throws {
    let f = try Fixture()
    defer { f.remove() }
    _ = try publishBranch(
      f,
      requests: [
        .add(entryID: Self.addedID, name: "same/account", type: .secret, plaintext: "first")
      ])
    _ = try publishBranch(
      f,
      requests: [
        .add(entryID: Self.otherID, name: "same/account", type: .secret, plaintext: "second")
      ])
    let report = try conflict(reconcile(f))
    #expect(report.entryConflicts.isEmpty)
    let destination = try only(report.destinationConflicts)
    #expect(destination.name == "same/account")
    #expect(Set(destination.entries.map(\.entryID)) == [Self.addedID, Self.otherID])
    try requireUnchangedLocalState(f)
  }

  @Test func concurrentCreationOfOneStableIdentityPreservesBothVersions() throws {
    let f = try Fixture()
    defer { f.remove() }
    _ = try publishBranch(
      f,
      requests: [
        .add(entryID: Self.addedID, name: "first/account", type: .secret, plaintext: "first")
      ])
    _ = try publishBranch(
      f,
      requests: [
        .add(entryID: Self.addedID, name: "second/account", type: .secret, plaintext: "second")
      ])
    let report = try conflict(reconcile(f))
    let entryConflict = try only(report.entryConflicts)
    #expect(entryConflict.kind == .concurrentCreation && entryConflict.versions.count == 2)
    #expect(entryConflict.commonAncestorEntry == nil)
    try requireUnchangedLocalState(f)
  }

  @Test func identicalDeletionOnTwoDifferentHeadsDoesNotBecomeAConflict() throws {
    let f = try Fixture()
    defer { f.remove() }
    _ = try publishBranch(f, requests: [.remove(name: "fixture/totp")])
    _ = try publishBranch(
      f,
      requests: [
        .edit(name: "fixture/secret", type: .secret, plaintext: "later"),
        .remove(name: "fixture/totp"),
      ])
    let plan = try mergePlan(reconcile(f))
    #expect(plan.entries.map(\.name) == ["fixture/secret"])
    try requireUnchangedLocalState(f)
  }

  @Test(arguments: [false, true])
  func incompleteOrSubstitutedBranchObjectsCannotProduceAPlan(substitute: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let a = try publishBranch(
      f,
      requests: [
        .edit(name: "fixture/secret", type: .secret, plaintext: "first")
      ])
    _ = try publishBranch(f, requests: [.remove(name: "fixture/totp")])
    let objects = try entryMap(f, envelope: a.envelope)
    let entry = try #require(objects.values.first { $0.context.name == "fixture/secret" })
    if substitute {
      try Data("changed encrypted fixture".utf8).write(to: f.entryURL(entry))
    } else {
      try FileManager.default.removeItem(at: f.entryURL(entry))
    }
    #expect(throws: (any Error).self) { try reconcile(f) }
    try requireUnchangedLocalState(f)
  }

  private func reconcile(_ f: Fixture, source: (any V3ImmutableObjectReading)? = nil) throws
    -> V3RecoveryManifestReconciliationResult
  {
    let observed = try V3RecoverySameEpochRepositoryObserver(source: source ?? f.store).observe(
      from: floor(f), vaultKey: Core.nextKey)
    return try V3RecoveryManifestReconciler().reconcile(observed)
  }
  private func floor(_ f: Fixture) -> V3RecoveryContentCommit {
    .init(checkpoint: f.checkpoint, envelope: f.parent)
  }
  private func head(_ commit: V3RecoveryContentCommit) throws -> V3VaultHead {
    try V3VaultHead(vaultID: commit.checkpoint.vaultID, envelopeDigest: commit.envelope.digest)
  }
  private func sortedHeads(_ commits: [V3RecoveryContentCommit]) throws -> [V3VaultHead] {
    try commits.map(head).sorted { $0.envelopeDigest.lexicographicallyPrecedes($1.envelopeDigest) }
  }
  private func mergePlan(_ result: V3RecoveryManifestReconciliationResult) throws
    -> V3RecoveryAutomaticMergePlan
  {
    guard case .automaticMerge(let plan) = result else { throw Publication.Stop.interrupted }
    return plan
  }
  private func conflict(_ result: V3RecoveryManifestReconciliationResult) throws
    -> V3ContentConflictReport
  {
    guard case .contentConflict(let report) = result else { throw Publication.Stop.interrupted }
    return report
  }
  private func requireUnchangedLocalState(_ f: Fixture) throws {
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(f.ownership.value == nil && f.registration.value == nil && f.adoption.value == nil)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }
  private func only<Element>(_ values: [Element]) throws -> Element {
    try #require(values.count == 1)
    return try #require(values.first)
  }
  private func expectedEntries(_ a: V3RecoveryManifestEnvelope, _ b: V3RecoveryManifestEnvelope)
    -> [V3ManifestEntry]
  {
    [
      a.body.fields.entries.first { $0.name == "fixture/secret" },
      b.body.fields.entries.first { $0.name == "fixture/totp" },
    ].compactMap { $0 }.sorted(by: v3ManifestEntryPrecedes)
  }
  func entryMap(_ f: Fixture, envelope: V3RecoveryManifestEnvelope) throws
    -> [V3EntryObjectKey: V3EncryptedEntry]
  {
    var result: [V3EntryObjectKey: V3EncryptedEntry] = [:]
    for record in envelope.body.fields.entries {
      let digest = try #require(Base64URL.decodeCanonical(record.ciphertextDigest))
      let key = V3EntryObjectKey(entryID: record.entryID, digest: digest)
      guard
        case .available(let bytes) = try f.store.readEntry(
          entryID: record.entryID, digest: digest, maximumBytes: 1_000_000)
      else {
        throw Publication.Stop.interrupted
      }
      result[key] = try V3EntryCipher().parse(bytes)
    }
    return result
  }

  /// Complete each branch in its own provider directory before delivery, so
  /// later branches cannot silently observe the earlier branch's files.
  func publishBranch(
    _ f: Fixture, requests: [V3EntryMutationRequest], from start: V3RecoveryContentCommit? = nil,
    entries startEntries: [V3EntryObjectKey: V3EncryptedEntry]? = nil
  ) throws -> V3RecoveryContentCommit {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let store = V3FilesystemTransactionArtifactStore(
      rootHandle: try VaultRootDirectoryHandle(opening: root))
    var current = start ?? floor(f)
    var entries = startEntries ?? f.entries
    try seed(f.core.parent, entries: Array(f.core.entries.values), into: store)
    try seed(f.parent, entries: Array(f.entries.values), into: store)
    if current.checkpoint != f.checkpoint {
      try seed(current.envelope, entries: Array(entries.values), into: store)
    }
    let checkpoint = Publication.Checkpoints(current.checkpoint.canonicalBytes)
    let publisher = V3RecoveryContentMutationPublisher(
      mutationOwner: VaultTransactionMutationOwner(), objectStore: store,
      checkpointStore: checkpoint,
      recoveryAnchorStore: Publication.Ownership(),
      registrationAnchorStore: Publication.Ownership(),
      adoptionAnchorStore: Publication.Ownership(), cache: f.cache)
    var delivered: [V3RecoveryContentMutationCandidate] = []
    for request in requests {
      let candidate = try V3RecoveryContentMutationBuilder().build(
        request, checkpoint: current.checkpoint, parent: current.envelope, currentEntries: entries,
        vaultKey: Core.nextKey)
      entries = try V3RecoveryContentMutationValidator().validate(
        candidate, parent: current.envelope, currentEntries: entries, vaultKey: Core.nextKey)
      current = try publisher.publish(candidate, vaultKey: Core.nextKey)
      delivered.append(candidate)
    }
    for candidate in delivered { try f.seed(candidate.envelope, entries: candidate.stagedEntries) }
    return current
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
  private struct ReverseInventory: V3ImmutableObjectReading {
    let base: any V3ImmutableObjectReading
    init(_ base: any V3ImmutableObjectReading) { self.base = base }
    func manifestDigests(maximumCount: Int) throws -> V3RepositoryDirectoryListing {
      switch try base.manifestDigests(maximumCount: maximumCount) {
      case .available(let digests, let count):
        return .available(digests: digests.reversed(), objectCount: count)
      case let result: return result
      }
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
}
