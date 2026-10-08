import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Genuine manifest/entry crypto and contained filesystem storage. Only local
/// checkpoint/ownership persistence and deliberate interruption are scripted.
struct V3RecoveryContentMutationPublisherTests {
  typealias Core = V3RecoveryRegistrationTests
  private static let addedID = "018f4d38-7d5a-7b20-b0f1-97d6e96c84c1"
  private static let copyID = "018f4d38-7d5a-7b20-b0f1-97d6e96c84c2"
  private static let phases: [V3ImmutableTransactionPhase] = [
    .recoveryAnchorPrepared, .recoveryIntentPersisted, .recoveryArmed,
    .entryStaged(index: 0), .manifestStaged, .repositoryStateRechecked,
    .entryPublished(index: 0), .publishedEntriesValidated, .manifestPublished,
    .publishedManifestValidated, .checkpointAdvanced, .cleanupCompleted,
  ]

  @Test func manifestLastPublicationUsesTheSharedOrderingAndExactCache() throws {
    let f = try Fixture()
    defer { f.remove() }
    let recorded = Phases()
    let candidate = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "saved"))
    let result = try f.publisher(observer: Observer { recorded.append($0) }).publish(
      candidate, vaultKey: Core.nextKey)
    #expect(recorded.value == Self.phases)
    #expect(result.envelope == candidate.envelope)
    #expect(f.checkpoints.value == result.checkpoint.canonicalBytes && f.ownership.value == nil)
    #expect(
      try f.cache.load(for: result.checkpoint) == .available(candidate.envelope.canonicalBytes))
    #expect(
      try Data(contentsOf: f.manifestURL(candidate.envelope.digest))
        == candidate.envelope.canonicalBytes)
    #expect(candidate.envelope.body.epochSigningKey == f.parent.body.epochSigningKey)
    #expect(candidate.envelope.body.transitionProof == f.parent.body.transitionProof)
    #expect(candidate.envelope.body.recovery == f.parent.body.recovery)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test(arguments: 0..<12)
  func everyPublicationBoundaryResumesExactBytesOrLeavesOldCheckpoint(phase: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "saved"))
    #expect(throws: Stop.interrupted) {
      try f.publisher(observer: Observer { if $0 == Self.phases[phase] { throw Stop.interrupted } })
        .publish(candidate, vaultKey: Core.nextKey)
    }
    let outcome = try f.publisher().recoverInterruptedTransaction(
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
    }
    #expect(f.ownership.value == nil)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test func failedCheckpointCASResumesTheAlreadyPublishedCandidate() throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try f.build(.remove(name: "fixture/totp"))
    f.checkpoints.rejectAdvance = true
    #expect(throws: Stop.interrupted) {
      try f.publisher().publish(candidate, vaultKey: Core.nextKey)
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes && f.ownership.value != nil)
    f.checkpoints.rejectAdvance = false
    #expect(
      try f.publisher().recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
        == .completed(operationID: f.operationID))
    #expect(
      f.checkpoints.value
        == (try V3ManifestCheckpoint(
          vaultID: Core.vaultID, envelopeDigest: candidate.envelope.digest)).canonicalBytes)
  }

  @Test func committedCleanupDoesNotRequireRemovedEntriesOrOldManifestCache() throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try f.build(.remove(name: "fixture/totp"))
    let removed = try #require(f.entries.values.first { $0.context.name == "fixture/totp" })
    f.ownership.rejectClear = true
    let result = try f.publisher().publish(candidate, vaultKey: Core.nextKey)
    #expect(f.ownership.value != nil)
    #expect(try f.cache.load(for: f.checkpoint) == .available(f.parent.canonicalBytes))
    try FileManager.default.removeItem(at: f.entryURL(removed))
    try FileManager.default.removeItem(at: f.manifestURL(f.parent.digest))
    try FileManager.default.removeItem(at: f.manifestURL(f.core.parent.digest))
    try FileManager.default.removeItem(
      at: f.cacheRoot.appendingPathComponent("\(Core.vaultID).json"))
    f.ownership.rejectClear = false
    #expect(
      try f.publisher().recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
        == .alreadyCompleted(operationID: f.operationID))
    #expect(f.ownership.value == nil && f.checkpoints.value == result.checkpoint.canonicalBytes)
    #expect(
      try f.cache.load(for: result.checkpoint) == .available(candidate.envelope.canonicalBytes))
  }

  @Test(arguments: [false, true])
  func pendingAuthorityWorkBlocksNewSaveAndResume(registration: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let other = registration ? f.registration : f.adoption
    let candidate = try f.build(.remove(name: "fixture/totp"))
    other.value = Data("pending authority work".utf8)
    #expect(throws: V3RecoveryContentPublicationError.otherMutationPending) {
      try f.publisher().publish(candidate, vaultKey: Core.nextKey)
    }
    #expect(f.ownership.value == nil)
    other.value = nil
    #expect(throws: Stop.interrupted) {
      try f.publisher(observer: Observer { if $0 == .manifestStaged { throw Stop.interrupted } })
        .publish(candidate, vaultKey: Core.nextKey)
    }
    other.value = Data("pending authority work".utf8)
    #expect(throws: V3RecoveryContentPublicationError.otherMutationPending) {
      try f.publisher().recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
    }
    #expect(f.ownership.value != nil && f.checkpoints.value == f.checkpoint.canonicalBytes)
  }

  @Test(arguments: [
    V3ImmutableTransactionPhase.repositoryStateRechecked, .publishedEntriesValidated,
    .publishedManifestValidated,
  ])
  func authorityWorkAppearingDuringSaveStopsBeforeActivation(phase: V3ImmutableTransactionPhase)
    throws
  {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "saved"))
    #expect(throws: V3RecoveryContentPublicationError.otherMutationPending) {
      try f.publisher(observer: Observer { if $0 == phase { f.registration.value = Data([1]) } })
        .publish(candidate, vaultKey: Core.nextKey)
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes && f.ownership.value != nil)
    if phase != .publishedManifestValidated {
      #expect(
        !FileManager.default.fileExists(atPath: f.manifestURL(candidate.envelope.digest).path))
    }
  }

  @Test(arguments: [
    V3ImmutableTransactionPhase.repositoryStateRechecked, .publishedEntriesValidated,
    .publishedManifestValidated,
  ])
  func concurrentBranchNeverAdvancesTheLocalCheckpoint(phase: V3ImmutableTransactionPhase) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "saved"))
    let branch = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "other edit"))
    #expect(throws: V3RecoveryValidationError.sourceChanged) {
      try f.publisher(
        observer: Observer {
          if $0 == phase { try f.seed(branch.envelope, entries: branch.stagedEntries) }
        }
      ).publish(candidate, vaultKey: Core.nextKey)
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes && f.ownership.value != nil)
    #expect(throws: (any Error).self) {
      try f.publisher().recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
    }
    #expect(f.ownership.value != nil)
  }

  @Test(arguments: [false, true])
  func localOwnershipAndCheckpointChangesAreRecheckedBeforeWrites(checkpoint: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "saved"))
    let replacement = Data("different local owner".utf8)
    #expect(throws: (any Error).self) {
      try f.publisher(
        observer: Observer {
          if $0 == .repositoryStateRechecked {
            if checkpoint {
              f.checkpoints.value = replacement
            } else {
              f.ownership.value = replacement
            }
          }
        }
      ).publish(candidate, vaultKey: Core.nextKey)
    }
    #expect(!FileManager.default.fileExists(atPath: f.manifestURL(candidate.envelope.digest).path))
    #expect(checkpoint ? f.checkpoints.value == replacement : f.ownership.value == replacement)
  }

  @Test(arguments: [false, true])
  func missingChangedObjectAbandonsOnlyAnUnpublishedManifest(published: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "saved"))
    #expect(throws: Stop.interrupted) {
      try f.publisher(
        observer: Observer {
          if $0 == (published ? .manifestPublished : .manifestStaged) { throw Stop.interrupted }
        }
      ).publish(candidate, vaultKey: Core.nextKey)
    }
    let entry = try #require(candidate.stagedEntries.first)
    let key = Self.address(entry)
    try f.store.removeStagedEntry(
      entry.canonicalBytes, entryID: key.entryID, digest: key.digest, operationID: f.operationID)
    if published { try FileManager.default.removeItem(at: f.entryURL(entry)) }
    if published {
      #expect(throws: V3ImmutableTransactionRecoveryError.transactionDirectoryUnavailable) {
        try f.publisher().recoverInterruptedTransaction(
          vaultID: Core.vaultID, vaultKey: Core.nextKey)
      }
      #expect(f.ownership.value != nil)
    } else {
      #expect(
        try f.publisher().recoverInterruptedTransaction(
          vaultID: Core.vaultID, vaultKey: Core.nextKey) == .abandoned(operationID: f.operationID))
      #expect(f.ownership.value == nil)
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes)
  }

  @Test func providerIntentWithoutLocalPinCannotResumeAndProfileTwoCannotInterpretProfileThree()
    throws
  {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try f.build(.remove(name: "fixture/totp"))
    #expect(throws: Stop.interrupted) {
      try f.publisher(observer: Observer { if $0 == .manifestStaged { throw Stop.interrupted } })
        .publish(candidate, vaultKey: Core.nextKey)
    }
    let pin = f.ownership.value
    f.ownership.value = nil
    #expect(
      try f.publisher().recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
        == .nothingToRecover)
    f.ownership.value = pin
    let old = V3DeviceWrappedContentMutationPublisher(
      mutationOwner: VaultTransactionMutationOwner(), objectStore: f.store,
      checkpointStore: f.checkpoints, recoveryAnchorStore: f.ownership, cache: f.cache)
    #expect(throws: (any Error).self) {
      try old.recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
    }
    #expect(f.ownership.value == pin && f.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(
      try f.publisher().recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
        == .completed(operationID: f.operationID))
  }

  @Test func wrongKeyIncompleteStagingAndProjectedLimitsCannotCreateLocalIntent() throws {
    for variant in 0..<4 {
      let f = try Fixture()
      defer { f.remove() }
      let candidate = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "saved"))
      let input =
        variant == 1
        ? V3RecoveryContentMutationCandidate(
          kind: candidate.kind, expectedCheckpoint: candidate.expectedCheckpoint,
          envelope: candidate.envelope, stagedEntries: []) : candidate
      let limits =
        variant == 2
        ? V3ManifestRepositoryLimits(
          maximumManifestObjects: 2, maximumHistoryDepth: 10)
        : (variant == 3
          ? V3ManifestRepositoryLimits(
            maximumManifestObjects: 10, maximumHistoryDepth: 10, maximumReferencedEntryObjects: 2)
          : .standard)
      #expect(throws: (any Error).self) {
        try f.publisher(limits: limits).publish(
          input, vaultKey: variant == 0 ? Core.oldKey : Core.nextKey)
      }
      #expect(f.ownership.value == nil && f.checkpoints.value == f.checkpoint.canonicalBytes)
    }
  }

  @Test func corruptCurrentEntryAndMutatedIntentAreRefusedOnResume() throws {
    for variant in 0..<2 {
      let f = try Fixture()
      defer { f.remove() }
      let candidate = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "saved"))
      #expect(throws: Stop.interrupted) {
        try f.publisher(observer: Observer { if $0 == .manifestStaged { throw Stop.interrupted } })
          .publish(candidate, vaultKey: Core.nextKey)
      }
      if variant == 0 {
        let old = try #require(f.entries.values.first)
        try Data("changed encrypted object".utf8).write(to: f.entryURL(old))
      } else {
        try Data("changed durable intent".utf8).write(
          to: f.root.appendingPathComponent(".transactions/\(f.operationID)/intent.json"))
      }
      #expect(throws: (any Error).self) {
        try f.publisher().recoverInterruptedTransaction(
          vaultID: Core.vaultID, vaultKey: Core.nextKey)
      }
      #expect(f.ownership.value != nil && f.checkpoints.value == f.checkpoint.canonicalBytes)
    }
  }

  @Test func wrongSessionKeyCannotResumeOrClearThePinnedWork() throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try f.build(.remove(name: "fixture/totp"))
    #expect(throws: Stop.interrupted) {
      try f.publisher(observer: Observer { if $0 == .manifestStaged { throw Stop.interrupted } })
        .publish(candidate, vaultKey: Core.nextKey)
    }
    let pin = f.ownership.value
    #expect(
      throws: V3ImmutableTransactionRecoveryError.vaultKeyUnavailable(
        keyID: candidate.envelope.body.fields.keyID.rawValue)
    ) {
      try f.publisher().recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.oldKey)
    }
    #expect(f.ownership.value == pin && f.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(
      try f.publisher().recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
        == .completed(operationID: f.operationID))
  }

  @Test func missingProviderFloorAndInconsistentTypedCandidateCannotStartPublication() throws {
    for variant in 0..<2 {
      let f = try Fixture()
      defer { f.remove() }
      let candidate = try f.build(.remove(name: "fixture/totp"))
      let envelope = candidate.envelope
      let input: V3RecoveryContentMutationCandidate
      if variant == 0 {
        try FileManager.default.removeItem(at: f.manifestURL(f.parent.digest))
        #expect(try f.cache.load(for: f.checkpoint) == .available(f.parent.canonicalBytes))
        input = candidate
      } else {
        input = V3RecoveryContentMutationCandidate(
          kind: candidate.kind, expectedCheckpoint: candidate.expectedCheckpoint,
          envelope: V3RecoveryManifestEnvelope(
            parents: envelope.parents, body: envelope.body,
            authenticationTag: Data(repeating: 0x55, count: 32),
            authorizations: envelope.authorizations,
            canonicalBytes: envelope.canonicalBytes,
            canonicalContentBytes: envelope.canonicalContentBytes),
          stagedEntries: candidate.stagedEntries)
      }
      #expect(throws: (any Error).self) { try f.publisher().publish(input, vaultKey: Core.nextKey) }
      #expect(f.ownership.value == nil && f.checkpoints.value == f.checkpoint.canonicalBytes)
    }
  }

  @Test(arguments: [
    V3ImmutableTransactionPhase.publishedEntriesValidated, .publishedManifestValidated,
  ])
  func changedPublishedEntryCannotActivateTheManifest(phase: V3ImmutableTransactionPhase) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "saved"))
    let entry = try #require(candidate.stagedEntries.first)
    #expect(throws: (any Error).self) {
      try f.publisher(
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
      try f.publisher().recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.nextKey)
    }
    #expect(f.ownership.value != nil)
  }

  @Test func durablySavedEditChainRecoversWithoutTheOriginalMac() throws {
    guard #available(macOS 26.0, *) else { return }
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    // No original owner, session key or signer escapes this scope.
    let (anchor, token, head) = try Self.saveChain(root: root)
    let store = V3FilesystemTransactionArtifactStore(
      rootHandle: try VaultRootDirectoryHandle(opening: root))
    let selection = try V3RecoveryHistorySelector(source: store).select(
      anchor: anchor, credentialPublicKey: token.publicKey.x963Representation)
    let count = Core.Counter()
    let receiver = try PIVHPKEReceiver(publicBytes: token.publicKey.x963Representation) { peer in
      count.increment()
      let secret = try token.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: peer))
      return secret.withUnsafeBytes { Data($0) }
    }
    let snapshot = try V3RecoverySnapshotVerifier(source: store).open(
      selection, boundAnchor: anchor, receiver: receiver)
    #expect(count.value == 1 && selection.head.digest == head)
    #expect(snapshot.entries.map(\.name) == ["copy/account", "fixture/secret", "renamed/otp"])
    #expect(
      snapshot.entries.map(\.plaintext) == ["updated\n密碼", "updated\n密碼", "JBSWY3DPEHPK3PXP"])
  }

  private static func saveChain(root: URL) throws -> (
    V3RecoveryAnchor, P256.KeyAgreement.PrivateKey, Data
  ) {
    let f = try Fixture(root: root)
    var parent = f.parent
    var entries = f.entries
    func save(_ request: V3EntryMutationRequest) throws {
      let cp = try V3ManifestCheckpoint(vaultID: Core.vaultID, envelopeDigest: parent.digest)
      let candidate = try V3RecoveryContentMutationBuilder().build(
        request, checkpoint: cp, parent: parent, currentEntries: entries, vaultKey: Core.nextKey)
      entries = try V3RecoveryContentMutationValidator().validate(
        candidate, parent: parent, currentEntries: entries, vaultKey: Core.nextKey)
      parent = try f.publisher(owner: VaultTransactionMutationOwner()).publish(
        candidate, vaultKey: Core.nextKey
      ).envelope
    }
    try save(.add(entryID: addedID, name: "temporary", type: .secret, plaintext: "new"))
    try save(.edit(name: "fixture/secret", type: .secret, plaintext: "updated\n密碼"))
    let secret = try #require(entries.values.first { $0.context.name == "fixture/secret" })
    try save(
      .copy(
        sourceName: "fixture/secret", sourceData: secret.canonicalBytes, destinationEntryID: copyID,
        destinationName: "copy/account", overwrite: false))
    let otp = try #require(entries.values.first { $0.context.name == "fixture/totp" })
    try save(
      .move(
        sourceName: "fixture/totp", sourceData: otp.canonicalBytes, destinationName: "renamed/otp",
        overwrite: false))
    try save(.remove(name: "temporary"))
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
    return (f.anchor, f.core.token, parent.digest)
  }

  enum Stop: Error { case interrupted }
  private struct Observer: V3ImmutableTransactionPhaseObserving {
    let action: @Sendable (V3ImmutableTransactionPhase) throws -> Void
    init(_ action: @escaping @Sendable (V3ImmutableTransactionPhase) throws -> Void) {
      self.action = action
    }
    func didReach(_ phase: V3ImmutableTransactionPhase, operationID _: VaultTransactionOperationID)
      throws
    { try action(phase) }
  }
  private final class Phases: @unchecked Sendable {
    private let lock = NSLock()
    private var data: [V3ImmutableTransactionPhase] = []
    var value: [V3ImmutableTransactionPhase] { lock.withLock { data } }
    func append(_ phase: V3ImmutableTransactionPhase) { lock.withLock { data.append(phase) } }
  }
  final class Checkpoints: V3ManifestCheckpointStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var data: Data?
    var rejectAdvance = false
    var value: Data? {
      get { lock.withLock { data } }
      set { lock.withLock { data = newValue } }
    }
    init(_ data: Data) { self.data = data }
    func loadCheckpoint(vaultID _: String) throws -> Data? { value }
    func replaceCheckpoint(_ checkpoint: Data, expectedCheckpoint: Data?, vaultID _: String) throws
    {
      try lock.withLock {
        if rejectAdvance { throw Stop.interrupted }
        guard data == expectedCheckpoint else { throw V3ManifestCheckpointStoreError.conflict }
        data = checkpoint
      }
    }
  }
  final class Ownership: V3ImmutableTransactionRecoveryAnchorStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var data: Data?
    var rejectClear = false
    var value: Data? {
      get { lock.withLock { data } }
      set { lock.withLock { data = newValue } }
    }
    func loadRecoveryAnchor(vaultID _: String) throws -> Data? { value }
    func replaceRecoveryAnchor(_ anchor: Data?, expectedAnchor: Data?, vaultID _: String) throws {
      try lock.withLock {
        if rejectClear && anchor == nil { throw Stop.interrupted }
        guard data == expectedAnchor else {
          throw V3ImmutableTransactionRecoveryAnchorError.conflict
        }
        data = anchor
      }
    }
  }
  struct Fixture: Sendable {
    let core: Core.Fixture
    let parent: V3RecoveryManifestEnvelope
    let checkpoint: V3ManifestCheckpoint
    let entries: [V3EntryObjectKey: V3EncryptedEntry]
    let anchor: V3RecoveryAnchor
    let root: URL
    let cacheRoot: URL
    let store: V3FilesystemTransactionArtifactStore
    let cache: V3CheckpointManifestFilesystemCache
    let checkpoints: Checkpoints
    let ownership = Ownership()
    let registration = Ownership()
    let adoption = Ownership()
    let operationID = VaultTransactionOperationID()
    init(root: URL? = nil, empty: Bool = false, backup: Bool = true) throws {
      core = try Core.Fixture(empty: empty, backup: backup)
      let prepared = try core.prepare()
      parent = prepared.candidate
      checkpoint = try V3ManifestCheckpoint(vaultID: Core.vaultID, envelopeDigest: parent.digest)
      entries = try V3EntrySnapshotValidator(limits: .standard).entryMap(prepared.stagedEntries)
      anchor = prepared.intent.anchor
      self.root =
        root ?? FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
      cacheRoot = self.root.appendingPathComponent("local-cache")
      try FileManager.default.createDirectory(at: cacheRoot, withIntermediateDirectories: true)
      store = V3FilesystemTransactionArtifactStore(
        rootHandle: try VaultRootDirectoryHandle(opening: self.root))
      cache = V3CheckpointManifestFilesystemCache(
        rootHandle: try VaultRootDirectoryHandle(opening: cacheRoot))
      checkpoints = Checkpoints(checkpoint.canonicalBytes)
      try seed(core.parent, entries: Array(core.entries.values))
      try seed(parent, entries: prepared.stagedEntries)
      try cache.store(parent.canonicalBytes, for: checkpoint)
    }
    func build(_ request: V3EntryMutationRequest) throws -> V3RecoveryContentMutationCandidate {
      try V3RecoveryContentMutationBuilder().build(
        request, checkpoint: checkpoint, parent: parent, currentEntries: entries,
        vaultKey: Core.nextKey)
    }
    func publisher(
      observer: any V3ImmutableTransactionPhaseObserving = V3NoopContentTransactionPhaseObserver(),
      limits: V3ManifestRepositoryLimits = .standard,
      owner: (any VaultTransactionMutationOwning)? = nil
    ) -> V3RecoveryContentMutationPublisher {
      V3RecoveryContentMutationPublisher(
        mutationOwner: owner ?? VaultTransactionMutationOwner(makeOperationID: { operationID }),
        objectStore: store, checkpointStore: checkpoints, recoveryAnchorStore: ownership,
        registrationAnchorStore: registration, adoptionAnchorStore: adoption, cache: cache,
        limits: limits, phaseObserver: observer)
    }
    func seed(_ envelope: V3RecoveryManifestEnvelope, entries: [V3EncryptedEntry]) throws {
      let operation = VaultTransactionOperationID()
      for entry in entries {
        let key = V3RecoveryContentMutationPublisherTests.address(entry)
        try store.stageEntry(
          entry.canonicalBytes, entryID: key.entryID, digest: key.digest, operationID: operation)
        try store.publishStagedEntry(
          entry.canonicalBytes, entryID: key.entryID, digest: key.digest, operationID: operation)
      }
      try store.stageManifest(
        envelope.canonicalBytes, digest: envelope.digest, operationID: operation)
      try store.publishStagedManifest(
        envelope.canonicalBytes, digest: envelope.digest, operationID: operation)
    }
    func manifestURL(_ digest: Data) -> URL {
      root.appendingPathComponent("manifests/\(v3LowercaseHex(digest)).json")
    }
    func entryURL(_ entry: V3EncryptedEntry) -> URL {
      root.appendingPathComponent(
        "entries/\(entry.context.entryID)/\(v3LowercaseHex(Data(SHA256.hash(data: entry.canonicalBytes)))).json"
      )
    }
    func remove() { try? FileManager.default.removeItem(at: root) }
  }
  private static func address(_ entry: V3EncryptedEntry) -> V3EntryObjectKey {
    V3EntryObjectKey(
      entryID: entry.context.entryID, digest: Data(SHA256.hash(data: entry.canonicalBytes)))
  }
}
