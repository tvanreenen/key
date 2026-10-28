import CryptoKit
import Foundation

enum V3EntrySnapshotValidationError: Error, Equatable {
  case resourceLimit
  case incompleteSnapshot
  case invalidEntry
}

/// Complete current-snapshot checks shared by explicit profile adoption and
/// recovery registration. Fields must already be authenticated by the caller;
/// this component establishes no checkpoint or publication authority.
struct V3EntrySnapshotValidator: Sendable {
  let limits: V3ManifestRepositoryLimits

  func entryMap(_ entries: [V3EncryptedEntry]) throws -> [V3EntryObjectKey: V3EncryptedEntry] {
    guard entries.count <= limits.maximumReferencedEntryObjects else {
      throw V3EntrySnapshotValidationError.resourceLimit
    }
    var result: [V3EntryObjectKey: V3EncryptedEntry] = [:]
    var total = 0
    for entry in entries {
      guard entry.canonicalBytes.count <= limits.maximumEntryBytes,
        entry.canonicalBytes.count <= limits.maximumTotalEntryBytes - total
      else { throw V3EntrySnapshotValidationError.resourceLimit }
      total += entry.canonicalBytes.count
      let key = V3EntryObjectKey(
        entryID: entry.context.entryID, digest: Data(SHA256.hash(data: entry.canonicalBytes)))
      guard result.updateValue(entry, forKey: key) == nil else {
        throw V3EntrySnapshotValidationError.incompleteSnapshot
      }
    }
    return result
  }

  func plaintexts(
    fields: V3DeviceWrappedManifestFields, entries: [V3EntryObjectKey: V3EncryptedEntry],
    vaultKey: Data
  ) throws -> [String: Data] {
    let records = fields.entries
    guard records.count <= limits.maximumReferencedEntryObjects,
      entries.count <= limits.maximumReferencedEntryObjects
    else { throw V3EntrySnapshotValidationError.resourceLimit }
    let expected = try records.map { record in
      guard let digest = Base64URL.decodeCanonical(record.ciphertextDigest), digest.count == 32
      else {
        throw V3EntrySnapshotValidationError.invalidEntry
      }
      return V3EntryObjectKey(entryID: record.entryID, digest: digest)
    }
    guard Set(entries.keys) == Set(expected) else {
      throw V3EntrySnapshotValidationError.incompleteSnapshot
    }
    var total = 0
    var result: [String: Data] = [:]
    for (record, address) in zip(records, expected) {
      guard let entry = entries[address] else {
        throw V3EntrySnapshotValidationError.incompleteSnapshot
      }
      let bytes = entry.canonicalBytes
      guard bytes.count <= limits.maximumEntryBytes,
        bytes.count <= limits.maximumTotalEntryBytes - total
      else { throw V3EntrySnapshotValidationError.resourceLimit }
      total += bytes.count
      let plaintext = try V3EntryCipher().openPlaintextDataTrusted(
        bytes, vaultID: fields.vaultID, manifestEntry: record, vaultKey: vaultKey)
      guard let text = String(data: plaintext, encoding: .utf8),
        record.type != .totp || (try? TOTPGenerator.normalizeBase32Seed(text)) == text
      else { throw V3EntrySnapshotValidationError.invalidEntry }
      result[record.entryID] = plaintext
    }
    return result
  }
}
