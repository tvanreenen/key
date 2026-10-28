import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Registered recovery history, contained storage, and local checkpoint/ownership failure controls.
enum V3RecoveryPublicationTestSupport {
  typealias Core = V3RecoveryRegistrationTestSupport
  enum Stop: Error { case interrupted }
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
    init(root: URL? = nil, empty: Bool = false, backup: Bool = true, secretRevision: UInt64 = 4)
      throws
    {
      core = try Core.Fixture(empty: empty, backup: backup, secretRevision: secretRevision)
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
        let key = V3RecoveryPublicationTestSupport.address(entry)
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
  static func address(_ entry: V3EncryptedEntry) -> V3EntryObjectKey {
    V3EntryObjectKey(
      entryID: entry.context.entryID, digest: Data(SHA256.hash(data: entry.canonicalBytes)))
  }
}
