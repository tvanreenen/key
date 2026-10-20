import Foundation

/// Scoped in-memory inputs only, never a persisted intent or CLI/XPC payload.
/// Copy/move carry an encrypted source pinned by the authenticated manifest.
enum V3EntryMutationRequest: Sendable {
  case add(entryID: String, name: String, type: SecretEntryType, plaintext: String)
  case edit(name: String, type: SecretEntryType, plaintext: String)
  case copy(
    sourceName: String, sourceData: Data, destinationEntryID: String,
    destinationName: String, overwrite: Bool)
  case move(sourceName: String, sourceData: Data, destinationName: String, overwrite: Bool)
  case remove(name: String)
}

struct V3EntryMutationPlan: Sendable {
  let kind: VaultTransactionMutationKind
  let entries: [V3ManifestEntry]
  let stagedEntries: [V3EncryptedEntry]
}

/// Shared entry semantics for permanent and recovery profiles. The caller
/// authenticates its exact envelope/checkpoint and owns profile-specific
/// preservation, resource bounds, publication, conflict policy and durability.
struct V3EntryMutationPlanner: Sendable {
  private typealias Failure = V3DeviceWrappedContentMutationError

  func plan(
    _ request: V3EntryMutationRequest, fields: V3DeviceWrappedManifestFields,
    vaultKey: Data
  ) throws -> V3EntryMutationPlan {
    guard vaultKey.count == 32,
      (try? V3VaultKeyID.derive(vaultKey: vaultKey, vaultID: fields.vaultID)) == fields.keyID
    else { throw Failure.invalidVaultKey }
    var entries = fields.entries
    let staged: [V3EncryptedEntry]
    let kind: VaultTransactionMutationKind
    func entry(_ name: String) throws -> V3ManifestEntry {
      guard let value = fields.entries.first(where: { $0.name == name }) else {
        throw Failure.entryNotFound
      }
      return value
    }
    func seal(
      _ plaintext: String, id: String, name: String, type: SecretEntryType,
      revision: UInt64
    ) throws -> V3EncryptedEntry {
      try V3EntryCipher().seal(
        plaintext,
        context: V3EntryAuthenticationContext(
          vaultID: fields.vaultID, entryID: id,
          name: name, type: type, keyID: fields.keyID, revision: revision), vaultKey: vaultKey)
    }
    switch request {
    case .add(let id, let name, let type, let plaintext):
      try requireID(id)
      try requireName(name)
      guard !entries.contains(where: { $0.name == name }) else { throw Failure.entryExists }
      guard !entries.contains(where: { $0.entryID == id }) else { throw Failure.invalidEntryID }
      let encrypted = try seal(plaintext, id: id, name: name, type: type, revision: 1)
      entries.append(V3ResealedEntry(encryptedEntry: encrypted).manifestEntry)
      staged = [encrypted]
      kind = .addEntry
    case .edit(let name, let type, let plaintext):
      try requireName(name)
      let old = try entry(name)
      try requireNextRevision(old)
      let encrypted = try seal(
        plaintext, id: old.entryID, name: name, type: type,
        revision: old.revision + 1)
      entries = entries.map {
        $0.entryID == old.entryID ? V3ResealedEntry(encryptedEntry: encrypted).manifestEntry : $0
      }
      staged = [encrypted]
      kind = .editEntry
    case .copy(let sourceName, let sourceData, let id, let destinationName, let overwrite):
      try requireName(sourceName)
      try requireName(destinationName)
      try requireID(id)
      guard sourceName != destinationName else { throw Failure.unchangedName }
      let source = try entry(sourceName)
      let destination = entries.first { $0.name == destinationName }
      guard destination == nil || overwrite else { throw Failure.entryExists }
      guard !entries.contains(where: { $0.entryID == id }) else { throw Failure.invalidEntryID }
      let plaintext = try V3EntryCipher().openTrusted(
        sourceData, vaultID: fields.vaultID,
        manifestEntry: source, vaultKey: vaultKey)
      let encrypted = try seal(
        plaintext, id: id, name: destinationName, type: source.type, revision: 1)
      entries.removeAll { $0.entryID == destination?.entryID }
      entries.append(V3ResealedEntry(encryptedEntry: encrypted).manifestEntry)
      staged = [encrypted]
      kind = .copyEntry
    case .move(let sourceName, let sourceData, let destinationName, let overwrite):
      try requireName(sourceName)
      try requireName(destinationName)
      guard sourceName != destinationName else { throw Failure.unchangedName }
      let source = try entry(sourceName)
      let destination = entries.first { $0.name == destinationName }
      guard destination == nil || overwrite else { throw Failure.entryExists }
      try requireNextRevision(source)
      let plaintext = try V3EntryCipher().openTrusted(
        sourceData, vaultID: fields.vaultID,
        manifestEntry: source, vaultKey: vaultKey)
      let encrypted = try seal(
        plaintext, id: source.entryID, name: destinationName,
        type: source.type, revision: source.revision + 1)
      entries.removeAll { $0.entryID == source.entryID || $0.entryID == destination?.entryID }
      entries.append(V3ResealedEntry(encryptedEntry: encrypted).manifestEntry)
      staged = [encrypted]
      kind = .moveEntry
    case .remove(let name):
      try requireName(name)
      let old = try entry(name)
      entries.removeAll { $0.entryID == old.entryID }
      staged = []
      kind = .removeEntry
    }
    return V3EntryMutationPlan(
      kind: kind, entries: entries.sorted(by: v3ManifestEntryPrecedes),
      stagedEntries: staged)
  }

  private func requireID(_ id: String) throws {
    guard isValidV3UUID(id) else { throw Failure.invalidEntryID }
  }
  private func requireName(_ name: String) throws {
    guard isValidV3EntryName(name) else { throw Failure.invalidEntryName }
  }
  private func requireNextRevision(_ entry: V3ManifestEntry) throws {
    guard entry.revision < v3MaximumSafeInteger else { throw Failure.revisionOverflow }
  }
}

/// Independent content delta policy shared by both profiles' validators.
/// Authority equality, exact codecs, staged coverage and plaintext checks are
/// separate prerequisites. This type does not authenticate or approve a save.
struct V3EntryMutationPolicy: Sendable {
  func validate(
    from parent: [V3ManifestEntry], to candidate: [V3ManifestEntry],
    kind: VaultTransactionMutationKind
  ) throws {
    guard Set(parent.map(\.entryID)).count == parent.count,
      Set(candidate.map(\.entryID)).count == candidate.count
    else {
      throw V3ImmutableTransactionError.invalidAncestryProof
    }
    let old = Dictionary(uniqueKeysWithValues: parent.map { ($0.entryID, $0) })
    let new = Dictionary(uniqueKeysWithValues: candidate.map { ($0.entryID, $0) })
    let added = candidate.filter { old[$0.entryID] == nil }
    let removed = parent.filter { new[$0.entryID] == nil }
    let updated = candidate.compactMap { entry -> (old: V3ManifestEntry, new: V3ManifestEntry)? in
      guard let previous = old[entry.entryID], previous != entry else { return nil }
      return (previous, entry)
    }
    guard added.allSatisfy({ $0.revision == 1 }),
      updated.allSatisfy({
        $0.old.revision < v3MaximumSafeInteger && $0.new.revision == $0.old.revision + 1
      })
    else { throw V3ImmutableTransactionError.invalidAncestryProof }
    let permitted: Bool
    switch kind {
    case .addEntry: permitted = added.count == 1 && removed.isEmpty && updated.isEmpty
    case .editEntry:
      permitted =
        added.isEmpty && removed.isEmpty && updated.count == 1
        && updated[0].old.name == updated[0].new.name
    case .copyEntry:
      permitted =
        added.count == 1 && updated.isEmpty && removed.count <= 1
        && (removed.first?.name == added[0].name || removed.isEmpty)
    case .moveEntry:
      permitted =
        added.isEmpty && updated.count == 1 && removed.count <= 1
        && updated[0].old.name != updated[0].new.name && updated[0].old.type == updated[0].new.type
        && (removed.first?.name == updated[0].new.name || removed.isEmpty)
    case .removeEntry: permitted = added.isEmpty && updated.isEmpty && removed.count == 1
    case .resolveConflict, .mergeHeads, .migrateToV3, .enrollDevice, .revokeDevice, .rotateVaultKey,
      .registerRecoveryRecipient, .removeRecoveryRecipient, .adoptRecoveryProfile, .catchUpVault,
      .recoverInterruptedTransaction:
      permitted = false
    }
    guard permitted else { throw V3ImmutableTransactionError.invalidAncestryProof }
  }
}
