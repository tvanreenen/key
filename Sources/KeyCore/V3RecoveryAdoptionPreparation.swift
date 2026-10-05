import CryptoKit
import Foundation
internal import JSONCanonicalization

enum V3RecoveryAdoptionServiceError: Error, Equatable {
  case adoptionPending
  case otherMutationPending
  case noPendingAdoption
  case preparationUnavailable
  case invalidPreparation
  case ownershipChanged
  case checkpointChanged
  case invalidPublishedObject
}

/// Complete encrypted migration intent, pinned by its full digest in a
/// dedicated device-local ownership record. Parsing proves byte bindings only,
/// not consent, source authority, completed durability or publication approval.
struct V3RecoveryAdoptionPreparation: Equatable, Sendable {
  let operationID: VaultTransactionOperationID
  let ownerDeviceID: String
  let candidate: V3RecoveryProfileAdoptionCandidate
  let canonicalBytes: Data
  var digest: Data { Data(SHA256.hash(data: canonicalBytes)) }

  init(
    operationID: VaultTransactionOperationID, ownerDeviceID: String,
    candidate: V3RecoveryProfileAdoptionCandidate, limits: V3ManifestRepositoryLimits = .standard
  ) throws {
    try Self.requireBindings(candidate, owner: ownerDeviceID, limits: limits)
    let bytes = try CanonicalJSON.encode(
      .object([
        ("format", .string("key-vault-recovery-profile-adoption-preparation")),
        ("version", .integer(1)), ("operationID", .string(operationID.rawValue)),
        ("expectedCheckpoint", CanonicalJSON.parse(candidate.expectedCheckpoint.canonicalBytes)),
        ("ownerDeviceID", .string(ownerDeviceID)),
        ("candidate", CanonicalJSON.parse(candidate.envelope.canonicalBytes)),
        (
          "entries",
          .array(candidate.stagedEntries.map { try CanonicalJSON.parse($0.canonicalBytes) })
        ),
      ]))
    guard bytes.count <= Self.maximumBytes(limits) else {
      throw V3RecoveryProfileAdoptionError.resourceLimit
    }
    self.operationID = operationID
    self.ownerDeviceID = ownerDeviceID
    self.candidate = candidate
    canonicalBytes = bytes
  }

  init(canonicalBytes: Data, limits: V3ManifestRepositoryLimits = .standard) throws {
    guard canonicalBytes.count <= Self.maximumBytes(limits) else {
      throw V3RecoveryProfileAdoptionError.resourceLimit
    }
    let value = try CanonicalJSON.parse(canonicalBytes)
    guard CanonicalJSON.encode(value) == canonicalBytes, let fields = value.objectValue,
      fields.count == 7,
      Set(fields.map(\.0)) == [
        "format", "version", "operationID", "expectedCheckpoint", "ownerDeviceID", "candidate",
        "entries",
      ]
    else { throw V3RecoveryAdoptionServiceError.invalidPreparation }
    let root = Dictionary(uniqueKeysWithValues: fields)
    guard root["format"]?.stringValue == "key-vault-recovery-profile-adoption-preparation",
      root["version"]?.integerValue == 1,
      let operation = root["operationID"]?.stringValue,
      let owner = root["ownerDeviceID"]?.stringValue,
      let checkpoint = root["expectedCheckpoint"], let envelope = root["candidate"],
      let entries = root["entries"]?.arrayValue,
      entries.count <= limits.maximumReferencedEntryObjects
    else { throw V3RecoveryAdoptionServiceError.invalidPreparation }
    let manifest = CanonicalJSON.encode(envelope)
    guard manifest.count <= limits.maximumManifestBytes else {
      throw V3RecoveryProfileAdoptionError.resourceLimit
    }
    var total = 0
    let staged = try entries.map { entry in
      let bytes = CanonicalJSON.encode(entry)
      guard bytes.count <= limits.maximumEntryBytes,
        bytes.count <= limits.maximumTotalEntryBytes - total
      else { throw V3RecoveryProfileAdoptionError.resourceLimit }
      total += bytes.count
      return try V3EntryCipher().parse(bytes)
    }
    let candidate = try V3RecoveryProfileAdoptionCandidate(
      expectedCheckpoint: V3ManifestCheckpoint(canonicalBytes: CanonicalJSON.encode(checkpoint)),
      envelope: V3RecoveryManifestCodec().parseEnvelope(manifest), stagedEntries: staged)
    try Self.requireBindings(candidate, owner: owner, limits: limits)
    operationID = try VaultTransactionOperationID(validating: operation)
    ownerDeviceID = owner
    self.candidate = candidate
    self.canonicalBytes = canonicalBytes
  }

  static func maximumBytes(_ limits: V3ManifestRepositoryLimits) -> Int {
    var total = 2_048
    for count in [
      limits.maximumManifestBytes, limits.maximumTotalEntryBytes,
      limits.maximumReferencedEntryObjects,
    ] {
      let sum = total.addingReportingOverflow(count)
      if sum.overflow { return Int.max }
      total = sum.partialValue
    }
    return total
  }

  private static func requireBindings(
    _ candidate: V3RecoveryProfileAdoptionCandidate, owner: String,
    limits: V3ManifestRepositoryLimits
  ) throws {
    let envelope = candidate.envelope
    guard envelope.canonicalBytes.count <= limits.maximumManifestBytes else {
      throw V3RecoveryProfileAdoptionError.resourceLimit
    }
    guard try V3RecoveryManifestCodec().parseEnvelope(envelope.canonicalBytes) == envelope,
      candidate.expectedCheckpoint.vaultID == envelope.body.fields.vaultID,
      envelope.parents == [candidate.expectedCheckpoint.envelopeDigest],
      envelope.digest != candidate.expectedCheckpoint.envelopeDigest,
      envelope.authorizations.map(\.signerDeviceID) == [owner],
      envelope.body.fields.devices.contains(where: {
        $0.identity.deviceID == owner && $0.status == .active
      }),
      envelope.body.transitionProof == nil, envelope.body.recovery.recipients.isEmpty,
      envelope.body.recovery.wrappedKeys.isEmpty,
      candidate.stagedEntries.count == envelope.body.fields.entries.count
    else { throw V3RecoveryAdoptionServiceError.invalidPreparation }
    _ = try V3EntrySnapshotValidator(limits: limits).entryMap(candidate.stagedEntries)
    for (entry, record) in zip(candidate.stagedEntries, envelope.body.fields.entries) {
      guard try V3EntryCipher().parse(entry.canonicalBytes) == entry,
        V3ResealedEntry(encryptedEntry: entry).manifestEntry == record,
        entry.context.vaultID == envelope.body.fields.vaultID
      else { throw V3RecoveryAdoptionServiceError.invalidPreparation }
    }
  }
}

protocol V3RecoveryAdoptionPreparationStoring: Sendable {
  func persistAdoptionPreparation(_ data: Data, operationID: VaultTransactionOperationID) throws
  func readAdoptionPreparation(operationID: VaultTransactionOperationID, maximumBytes: Int) throws
    -> V3RepositoryObjectRead
  func confirmAdoptionPreparation(_ data: Data, operationID: VaultTransactionOperationID) throws
}
