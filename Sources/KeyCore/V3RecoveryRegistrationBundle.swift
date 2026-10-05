import CryptoKit
import Foundation
internal import JSONCanonicalization

/// One complete encrypted preparation, installed atomically before export.
/// Parsing checks exact byte bindings, not parent authority or possession.
struct V3RecoveryRegistrationBundle: Equatable, Sendable {
  let preparation: V3RecoveryRegistrationPreparation
  let canonicalBytes: Data

  init(
    preparation: V3RecoveryRegistrationPreparation,
    limits: V3ManifestRepositoryLimits = .standard
  ) throws {
    try Self.requireBindings(preparation, limits: limits)
    let bytes = try CanonicalJSON.encode(
      .object([
        ("format", .string("key-vault-recovery-registration-preparation")),
        ("version", .integer(1)),
        ("intent", CanonicalJSON.parse(preparation.intent.canonicalBytes)),
        ("candidate", CanonicalJSON.parse(preparation.candidate.canonicalBytes)),
        (
          "entries",
          .array(
            preparation.stagedEntries.map {
              try CanonicalJSON.parse($0.canonicalBytes)
            })
        ),
      ]))
    guard bytes.count <= Self.maximumBytes(limits: limits) else {
      throw V3RecoveryRegistrationError.resourceLimit
    }
    self.preparation = preparation
    canonicalBytes = bytes
  }

  init(canonicalBytes: Data, limits: V3ManifestRepositoryLimits = .standard) throws {
    guard canonicalBytes.count <= Self.maximumBytes(limits: limits) else {
      throw V3RecoveryRegistrationError.resourceLimit
    }
    let json = try CanonicalJSON.parse(canonicalBytes)
    guard CanonicalJSON.encode(json) == canonicalBytes,
      let fields = json.objectValue, fields.count == 5,
      Set(fields.map(\.0)) == ["format", "version", "intent", "candidate", "entries"]
    else { throw V3RecoveryRegistrationError.invalidIntent }
    let root = Dictionary(uniqueKeysWithValues: fields)
    guard root["format"]?.stringValue == "key-vault-recovery-registration-preparation",
      root["version"]?.integerValue == 1,
      let intentValue = root["intent"], let candidateValue = root["candidate"],
      let entries = root["entries"]?.arrayValue,
      entries.count <= limits.maximumReferencedEntryObjects
    else { throw V3RecoveryRegistrationError.invalidIntent }
    let intentBytes = CanonicalJSON.encode(intentValue)
    let candidateBytes = CanonicalJSON.encode(candidateValue)
    guard candidateBytes.count <= limits.maximumManifestBytes else {
      throw V3RecoveryRegistrationError.resourceLimit
    }
    var total = 0
    let parsedEntries = try entries.map { value in
      let bytes = CanonicalJSON.encode(value)
      guard bytes.count <= limits.maximumEntryBytes,
        bytes.count <= limits.maximumTotalEntryBytes - total
      else { throw V3RecoveryRegistrationError.resourceLimit }
      total += bytes.count
      return try V3EntryCipher().parse(bytes)
    }
    let preparation = try V3RecoveryRegistrationPreparation(
      intent: V3RecoveryRegistrationIntent(canonicalBytes: intentBytes),
      candidate: V3RecoveryManifestCodec().parseEnvelope(candidateBytes),
      stagedEntries: parsedEntries)
    try Self.requireBindings(preparation, limits: limits)
    self.preparation = preparation
    self.canonicalBytes = canonicalBytes
  }

  static func maximumBytes(limits: V3ManifestRepositoryLimits) -> Int {
    // Embedded canonical objects avoid base64 duplication of the snapshot.
    // Saturate only for custom limits whose sum is not representable.
    var result = 512
    for value in [
      V3RecoveryRegistrationIntent.maximumBytes, limits.maximumManifestBytes,
      limits.maximumTotalEntryBytes,
    ] {
      let sum = result.addingReportingOverflow(value)
      if sum.overflow { return Int.max }
      result = sum.partialValue
    }
    // Entries add one comma each outside their existing canonical bytes.
    let sum = result.addingReportingOverflow(limits.maximumReferencedEntryObjects)
    return sum.overflow ? Int.max : sum.partialValue
  }

  private static func requireBindings(
    _ preparation: V3RecoveryRegistrationPreparation, limits: V3ManifestRepositoryLimits
  ) throws {
    let intent = preparation.intent
    let candidate = preparation.candidate
    guard intent.canonicalBytes.count <= V3RecoveryRegistrationIntent.maximumBytes,
      candidate.canonicalBytes.count <= limits.maximumManifestBytes,
      preparation.stagedEntries.count <= limits.maximumReferencedEntryObjects
    else { throw V3RecoveryRegistrationError.resourceLimit }
    guard candidate.digest == intent.anchor.floor.envelopeDigest,
      candidate.body.fields.vaultID == intent.expectedCheckpoint.vaultID,
      candidate.parents == [intent.expectedCheckpoint.envelopeDigest],
      candidate.authorizations.map(\.signerDeviceID) == [intent.ownerDeviceID],
      preparation.stagedEntries.count == candidate.body.fields.entries.count
    else { throw V3RecoveryRegistrationError.invalidCandidate }
    var total = 0
    let addresses = try zip(preparation.stagedEntries, candidate.body.fields.entries).map {
      entry, record in
      guard entry.canonicalBytes.count <= limits.maximumEntryBytes,
        entry.canonicalBytes.count <= limits.maximumTotalEntryBytes - total
      else { throw V3RecoveryRegistrationError.resourceLimit }
      total += entry.canonicalBytes.count
      guard try V3EntryCipher().parse(entry.canonicalBytes) == entry,
        V3ResealedEntry(encryptedEntry: entry).manifestEntry == record,
        entry.context.vaultID == candidate.body.fields.vaultID,
        entry.context.keyID == candidate.body.fields.keyID
      else { throw V3RecoveryRegistrationError.invalidEntry }
      return V3ImmutableTransactionRecoveryEntry(
        entryID: entry.context.entryID,
        digest: Data(SHA256.hash(data: entry.canonicalBytes)))
    }.sorted { $0.entryID < $1.entryID }
    guard addresses == intent.stagedEntries,
      try V3RecoveryManifestCodec().parseEnvelope(candidate.canonicalBytes) == candidate
    else { throw V3RecoveryRegistrationError.invalidCandidate }
  }
}
