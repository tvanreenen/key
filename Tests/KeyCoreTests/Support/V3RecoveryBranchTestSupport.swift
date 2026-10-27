import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Offline branches are published in separate contained directories before delivery.
enum V3RecoveryBranchTestSupport {
  typealias Publication = V3RecoveryPublicationTestSupport
  typealias Fixture = Publication.Fixture
  typealias Core = V3RecoveryRegistrationTestSupport
  static func entryMap(_ f: Fixture, envelope: V3RecoveryManifestEnvelope) throws
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
  static func publishBranch(
    _ f: Fixture, requests: [V3EntryMutationRequest], from start: V3RecoveryContentCommit? = nil,
    entries startEntries: [V3EntryObjectKey: V3EncryptedEntry]? = nil
  ) throws -> V3RecoveryContentCommit {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let store = V3FilesystemTransactionArtifactStore(
      rootHandle: try VaultRootDirectoryHandle(opening: root))
    var current = start ?? V3RecoveryContentCommit(checkpoint: f.checkpoint, envelope: f.parent)
    var entries = startEntries ?? f.entries
    try seed(f.core.parent, entries: Array(f.core.entries.values), into: store)
    try seed(f.parent, entries: Array(f.entries.values), into: store)
    if current.checkpoint != f.checkpoint {
      try seed(current.envelope, entries: Array(entries.values), into: store)
      // A merged floor has several ancestry paths. Copy only its exact known
      // ancestors, not another writer's later branch. Old ciphertext snapshots
      // are not needed by ordinary publication from this trusted floor.
      var pending = current.envelope.parents
      var seen: Set<Data> = [f.parent.digest, f.core.parent.digest]
      while let digest = pending.popLast() {
        guard seen.insert(digest).inserted else { continue }
        guard
          case .available(let bytes) = try f.store.readManifest(
            digest: digest, maximumBytes: V3ManifestRepositoryLimits.standard.maximumManifestBytes)
        else { throw Publication.Stop.interrupted }
        let ancestor = try V3RecoveryManifestCodec().parseEnvelope(bytes)
        try seed(ancestor, entries: [], into: store)
        pending.append(contentsOf: ancestor.parents)
      }
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
  private static func seed(
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
}
