import CryptoKit
import Foundation
internal import JSONCanonicalization

/// Complete encrypted artifacts only. Parsing validates public bindings, not
/// the MAC, plaintext equality, local ownership or permission to publish.
struct V3RecoveryRestoreBundle: Equatable, Sendable {
  let intent: V3RecoveryRestoreIntent
  let manifest: V3DeviceWrappedManifestEnvelope
  let entries: [V3EncryptedEntry]
  let canonicalBytes: Data

  init(
    intent: V3RecoveryRestoreIntent, candidate: V3RecoveryRestoreCandidate,
    limits: V3ManifestRepositoryLimits = .standard
  ) throws {
    try intent.requireCandidate(candidate)
    let json = try CanonicalJSON.encode(
      .object([
        ("format", .string("key-vault-recovery-restore-preparation")), ("version", .integer(1)),
        ("intent", CanonicalJSON.parse(intent.canonicalBytes)),
        ("manifest", CanonicalJSON.parse(candidate.publication.genesis.manifestData)),
        (
          "entries",
          .array(
            candidate.publication.entries.map {
              try CanonicalJSON.parse($0.encryptedEntry.canonicalBytes)
            })
        ),
      ]))
    try self.init(canonicalBytes: json, limits: limits)
  }

  init(canonicalBytes: Data, limits: V3ManifestRepositoryLimits = .standard) throws {
    guard canonicalBytes.count <= Self.maximumBytes(limits: limits) else {
      throw V3RecoveryRestoreError.resourceLimit
    }
    let json = try CanonicalJSON.parse(canonicalBytes)
    guard CanonicalJSON.encode(json) == canonicalBytes, let fields = json.objectValue,
      fields.count == 5,
      Set(fields.map(\.0)) == ["format", "version", "intent", "manifest", "entries"]
    else { throw V3RecoveryRestoreError.invalidIntent }
    let root = Dictionary(uniqueKeysWithValues: fields)
    guard root["format"]?.stringValue == "key-vault-recovery-restore-preparation",
      root["version"]?.integerValue == 1, let intentValue = root["intent"],
      let manifestValue = root["manifest"],
      let entryValues = root["entries"]?.arrayValue,
      entryValues.count <= limits.maximumReferencedEntryObjects
    else { throw V3RecoveryRestoreError.invalidIntent }
    intent = try .init(canonicalBytes: CanonicalJSON.encode(intentValue))
    let manifestBytes = CanonicalJSON.encode(manifestValue)
    guard manifestBytes.count <= limits.maximumManifestBytes else {
      throw V3RecoveryRestoreError.resourceLimit
    }
    manifest = try V3DeviceWrappedManifestEnvelopeCodec().parse(manifestBytes)
    var total = 0
    entries = try entryValues.map { value in
      let bytes = CanonicalJSON.encode(value)
      guard bytes.count <= limits.maximumEntryBytes,
        bytes.count <= limits.maximumTotalEntryBytes - total
      else { throw V3RecoveryRestoreError.resourceLimit }
      total += bytes.count
      return try V3EntryCipher().parse(bytes)
    }
    self.canonicalBytes = canonicalBytes
    let body = manifest.body
    guard manifest.parents.isEmpty, manifest.authorizations.isEmpty,
      body.vaultID == intent.destinationCheckpoint.vaultID,
      Data(SHA256.hash(data: manifestBytes)) == intent.destinationCheckpoint.envelopeDigest,
      body.keyID == intent.destinationKeyID, body.devices.count == 1,
      body.devices[0].status == .active, body.devices[0].identity.deviceID == intent.ownerDeviceID,
      body.wrappedKeys.count == 1, body.wrappedKeys[0].recipientDeviceID == intent.ownerDeviceID,
      entries.count == body.entries.count
    else { throw V3RecoveryRestoreError.invalidIntent }
    for (entry, record) in zip(entries, body.entries) {
      guard entry.context.vaultID == body.vaultID, record.revision == 1,
        V3ResealedEntry(encryptedEntry: entry).manifestEntry == record
      else { throw V3RecoveryRestoreError.invalidIntent }
    }
  }

  /// Uses freshly recovered scoped plaintext only to reconstruct the in-memory
  /// validation input. No encryption/randomness or saved plaintext is involved.
  func publication(restoring snapshot: V3RecoveryVerifiedSnapshot) throws
    -> V3DeviceWrappedGenesisPublicationCandidate
  {
    let sources = Dictionary(
      uniqueKeysWithValues: snapshot.entries.map { (Data($0.name.utf8), $0) })
    let restored = try zip(entries, manifest.body.entries).map { entry, record in
      guard let source = sources[Data(record.name.utf8)], source.type == record.type else {
        throw V3RecoveryRestoreError.invalidIntent
      }
      return V3DeviceWrappedGenesisPublicationCandidate.Entry(
        source: source, manifestEntry: record, encryptedEntry: entry,
        digest: Data(SHA256.hash(data: entry.canonicalBytes)))
    }
    return .init(
      genesis: .init(
        body: manifest.body, manifestData: manifest.canonicalBytes,
        manifestDigest: intent.destinationCheckpoint.envelopeDigest), entries: restored)
  }

  static func maximumBytes(limits: V3ManifestRepositoryLimits) -> Int {
    var result = 512
    for size in [
      V3RecoveryRestoreIntent.maximumBytes, limits.maximumManifestBytes,
      limits.maximumTotalEntryBytes, limits.maximumReferencedEntryObjects,
    ] {
      let sum = result.addingReportingOverflow(size)
      if sum.overflow { return Int.max }
      result = sum.partialValue
    }
    return result
  }
}
