import CryptoKit
import Foundation

enum V3RecoveryContentMutationError: Error, Equatable {
  case invalidParent
  case invalidCandidate
  case resourceLimit
  case invalidCopyOrMove
}

/// One internal, unpublished same-epoch edit. No saved authorization, token
/// capability, plaintext or raw key is retained. Publication must independently
/// check its fresh local floor, source/heads, pending work and durable intent.
struct V3RecoveryContentMutationCandidate: Equatable, Sendable {
  let kind: VaultTransactionMutationKind
  let expectedCheckpoint: V3ManifestCheckpoint
  let envelope: V3RecoveryManifestEnvelope
  let stagedEntries: [V3EncryptedEntry]
}

/// Uses existing entry planning without projecting profile 3 into profile 2.
/// Ordinary edits preserve every authority/capsule/proof/recipient/wrapper
/// value exactly. There is no signer, token reader/agreement or admin writer.
struct V3RecoveryContentMutationBuilder: Sendable {
  private let limits: V3ManifestRepositoryLimits
  private var validator: V3RecoveryContentMutationValidator { .init(limits: limits) }
  init(limits: V3ManifestRepositoryLimits = .standard) { self.limits = limits }

  func build(
    _ request: V3EntryMutationRequest, checkpoint: V3ManifestCheckpoint,
    parent: V3RecoveryManifestEnvelope, currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
    vaultKey: Data
  ) throws -> V3RecoveryContentMutationCandidate {
    try validator.validateParent(parent, checkpoint: checkpoint, vaultKey: vaultKey)
    _ = try V3EntrySnapshotValidator(limits: limits).plaintexts(
      fields: parent.body.fields, entries: currentEntries, vaultKey: vaultKey)
    // Bound separately supplied copy/move input before its parser/decryption.
    switch request {
    case .copy(_, let bytes, _, _, _), .move(_, let bytes, _, _):
      guard bytes.count <= limits.maximumEntryBytes else {
        throw V3RecoveryContentMutationError.resourceLimit
      }
    case .add(_, _, _, let plaintext), .edit(_, _, let plaintext):
      guard plaintext.utf8.count <= limits.maximumEntryBytes else {
        throw V3RecoveryContentMutationError.resourceLimit
      }
    case .remove: break
    }
    let plan = try V3EntryMutationPlanner().plan(
      request, fields: parent.body.fields,
      vaultKey: vaultKey)
    guard plan.entries.count <= limits.maximumReferencedEntryObjects else {
      throw V3RecoveryContentMutationError.resourceLimit
    }
    _ = try V3EntrySnapshotValidator(limits: limits).entryMap(plan.stagedEntries)
    let old = parent.body.fields
    let fields = try V3DeviceWrappedManifestFields(
      vaultID: old.vaultID, keyID: old.keyID,
      authorityTransitionID: old.authorityTransitionID, devices: old.devices,
      wrappedKeys: old.wrappedKeys, entries: plan.entries)
    let body = try V3RecoveryManifestBody(
      fields: fields, epochSigningKey: parent.body.epochSigningKey,
      transitionProof: parent.body.transitionProof, recovery: parent.body.recovery)
    let envelope = try V3RecoveryEpochBoundary().encode(
      body: body, parents: [checkpoint.envelopeDigest],
      vaultKey: vaultKey, authorizations: [])
    let candidate = V3RecoveryContentMutationCandidate(
      kind: plan.kind, expectedCheckpoint: checkpoint,
      envelope: envelope, stagedEntries: plan.stagedEntries)
    _ = try validator.validate(
      candidate, parent: parent, currentEntries: currentEntries,
      vaultKey: vaultKey)
    return candidate
  }
}

/// Complete independent crypto/content validation, not publication authority.
/// Same-epoch metadata equality includes the inherited root proof. It does not
/// invent a boundary proof for the edit or weaken normal transition validation.
struct V3RecoveryContentMutationValidator: Sendable {
  private let limits: V3ManifestRepositoryLimits
  private var snapshots: V3EntrySnapshotValidator { .init(limits: limits) }
  init(limits: V3ManifestRepositoryLimits = .standard) { self.limits = limits }

  func validateParent(
    _ parent: V3RecoveryManifestEnvelope, checkpoint: V3ManifestCheckpoint,
    vaultKey: Data
  ) throws {
    guard parent.canonicalBytes.count <= limits.maximumManifestBytes,
      parent.body.fields.entries.count <= limits.maximumReferencedEntryObjects
    else {
      throw V3RecoveryContentMutationError.resourceLimit
    }
    guard checkpoint.vaultID == parent.body.fields.vaultID,
      checkpoint.envelopeDigest == Data(SHA256.hash(data: parent.canonicalBytes)),
      try V3RecoveryManifestCodec().parseEnvelope(parent.canonicalBytes) == parent
    else {
      throw V3RecoveryContentMutationError.invalidParent
    }
    try V3RecoveryEpochBoundary().verifyCurrentAuthentication(parent, vaultKey: vaultKey)
  }

  /// Returns the complete checked encrypted snapshot for subsequent guarded
  /// publication. The input maps must be complete/exact, not best-effort reads.
  @discardableResult
  func validate(
    _ candidate: V3RecoveryContentMutationCandidate, parent: V3RecoveryManifestEnvelope,
    currentEntries: [V3EntryObjectKey: V3EncryptedEntry], vaultKey: Data
  ) throws
    -> [V3EntryObjectKey: V3EncryptedEntry]
  {
    try validateParent(parent, checkpoint: candidate.expectedCheckpoint, vaultKey: vaultKey)
    let envelope = candidate.envelope
    guard envelope.canonicalBytes.count <= limits.maximumManifestBytes,
      candidate.stagedEntries.count <= limits.maximumReferencedEntryObjects,
      envelope.body.fields.entries.count <= limits.maximumReferencedEntryObjects
    else {
      throw V3RecoveryContentMutationError.resourceLimit
    }
    let boundary = V3RecoveryEpochBoundary()
    try boundary.verifyCurrentAuthentication(envelope, vaultKey: vaultKey)
    try boundary.verifySameEpochMetadata(envelope, parents: [parent])
    try V3EntryMutationPolicy().validate(
      from: parent.body.fields.entries,
      to: envelope.body.fields.entries, kind: candidate.kind)
    let before = try snapshots.plaintexts(
      fields: parent.body.fields, entries: currentEntries,
      vaultKey: vaultKey)
    let old = Dictionary(uniqueKeysWithValues: parent.body.fields.entries.map { ($0.entryID, $0) })
    let changed = envelope.body.fields.entries.filter { old[$0.entryID] != $0 }
    let expectedStaged = try Set(changed.map { try address($0) })
    let staged = try snapshots.entryMap(candidate.stagedEntries)
    guard Set(staged.keys) == expectedStaged else {
      throw V3RecoveryContentMutationError.invalidCandidate
    }
    // Check typed staged objects independently, not just their canonical bytes.
    for entry in candidate.stagedEntries {
      guard try V3EntryCipher().parse(entry.canonicalBytes) == entry else {
        throw V3RecoveryContentMutationError.invalidCandidate
      }
    }
    var complete: [V3EntryObjectKey: V3EncryptedEntry] = [:]
    for record in envelope.body.fields.entries {
      let key = try address(record)
      guard let entry = staged[key] ?? currentEntries[key] else {
        throw V3RecoveryContentMutationError.invalidCandidate
      }
      complete[key] = entry
    }
    let after = try snapshots.plaintexts(
      fields: envelope.body.fields, entries: complete,
      vaultKey: vaultKey)
    // Cipher/authentication checks alone cannot establish copy/move semantics.
    // Move keeps its identity; copy must match a retained, unchanged source.
    if candidate.kind == .moveEntry {
      guard let moved = changed.first, before[moved.entryID] == after[moved.entryID] else {
        throw V3RecoveryContentMutationError.invalidCopyOrMove
      }
    }
    if candidate.kind == .copyEntry {
      guard let copied = changed.first,
        envelope.body.fields.entries.contains(where: { source in
          old[source.entryID] == source && source.name != copied.name && source.type == copied.type
            && before[source.entryID] == after[copied.entryID]
        })
      else { throw V3RecoveryContentMutationError.invalidCopyOrMove }
    }
    return complete
  }

  private func address(_ entry: V3ManifestEntry) throws -> V3EntryObjectKey {
    guard let digest = Base64URL.decodeCanonical(entry.ciphertextDigest), digest.count == 32 else {
      throw V3RecoveryContentMutationError.invalidCandidate
    }
    return V3EntryObjectKey(entryID: entry.entryID, digest: digest)
  }
}
