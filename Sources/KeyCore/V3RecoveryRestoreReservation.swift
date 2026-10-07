import Foundation
internal import JSONCanonicalization

/// Public plan pinned locally before platform credential creation. Loading it
/// after interruption does not authorize creating a replacement credential.
struct V3RecoveryRestoreReservation: Equatable, Sendable {
  static let maximumBytes = 4 * 1_024 * 1_024
  let operationID: VaultTransactionOperationID
  let locations: V3RecoveryRestoreLocations
  let sourceAnchor: V3RecoveryAnchor
  let sourcePublicKey: Data
  let sourceHeadDigest: Data
  let sourceObservationDigest: Data
  let vaultID: String
  let transitionID: String
  let entryIDs: [String]

  init(
    operationID: VaultTransactionOperationID, environment: V3RecoveryRestoreEnvironment,
    snapshot: V3RecoveryVerifiedSnapshot, vaultID: String, transitionID: String, entryIDs: [String]
  ) throws {
    try environment.requireSnapshot(snapshot)
    let selection = snapshot.selection
    try self.init(
      operationID: operationID, locations: environment.locations, sourceAnchor: selection.anchor,
      sourcePublicKey: selection.credentialPublicKey, sourceHeadDigest: selection.head.digest,
      sourceObservationDigest: V3RecoveryRestoreIntent.observationDigest(selection),
      vaultID: vaultID, transitionID: transitionID, entryIDs: entryIDs)
    let source = selection.head.body.fields
    guard entryIDs.count == snapshot.entries.count, transitionID != source.authorityTransitionID,
      Set(entryIDs).isDisjoint(with: source.entries.map(\.entryID))
    else { throw V3RecoveryRestoreError.invalidIntent }
  }

  private init(
    operationID: VaultTransactionOperationID, locations: V3RecoveryRestoreLocations,
    sourceAnchor: V3RecoveryAnchor, sourcePublicKey: Data, sourceHeadDigest: Data,
    sourceObservationDigest: Data, vaultID: String, transitionID: String, entryIDs: [String]
  ) throws {
    let ids = [vaultID, transitionID] + entryIDs
    guard ids.allSatisfy(isValidV3UUID), Set(ids).count == ids.count,
      vaultID != sourceAnchor.floor.vaultID,
      entryIDs.count <= V3ManifestRepositoryLimits.standard.maximumReferencedEntryObjects,
      sourceHeadDigest.count == 32, sourceObservationDigest.count == 32,
      try V3RecoveryRecipientID.derive(publicKey: sourcePublicKey) == sourceAnchor.recipientID
    else { throw V3RecoveryRestoreError.invalidIntent }
    _ = try V3RecoveryRestoreLocations(value: locations.value)
    self.operationID = operationID
    self.locations = locations
    self.sourceAnchor = sourceAnchor
    self.sourcePublicKey = sourcePublicKey
    self.sourceHeadDigest = sourceHeadDigest
    self.sourceObservationDigest = sourceObservationDigest
    self.vaultID = vaultID
    self.transitionID = transitionID
    self.entryIDs = entryIDs
    guard canonicalBytes.count <= Self.maximumBytes else {
      throw V3RecoveryRestoreError.resourceLimit
    }
  }

  init(canonicalBytes: Data) throws {
    guard canonicalBytes.count <= Self.maximumBytes else {
      throw V3RecoveryRestoreError.resourceLimit
    }
    do {
      let json = try CanonicalJSON.parse(canonicalBytes)
      guard CanonicalJSON.encode(json) == canonicalBytes, let fields = json.objectValue,
        fields.count == 11,
        Set(fields.map(\.0)) == [
          "format", "version", "operationID", "locations", "sourceAnchor", "sourcePublicKey",
          "sourceHeadDigest", "sourceObservationDigest", "vaultID", "transitionID", "entryIDs",
        ]
      else { throw V3RecoveryRestoreError.invalidIntent }
      let root = Dictionary(uniqueKeysWithValues: fields)
      guard root["format"]?.stringValue == "key-vault-recovery-restore-reservation",
        root["version"]?.integerValue == 1, let operation = root["operationID"]?.stringValue,
        let locations = root["locations"], let anchor = root["sourceAnchor"],
        let point = Self.bytes(root["sourcePublicKey"], count: 65),
        let head = Self.bytes(root["sourceHeadDigest"], count: 32),
        let observation = Self.bytes(root["sourceObservationDigest"], count: 32),
        let vault = root["vaultID"]?.stringValue,
        let transition = root["transitionID"]?.stringValue,
        let entries = root["entryIDs"]?.arrayValue,
        entries.count <= V3ManifestRepositoryLimits.standard.maximumReferencedEntryObjects
      else { throw V3RecoveryRestoreError.invalidIntent }
      let ids = try entries.map { value in
        guard let id = value.stringValue else { throw V3RecoveryRestoreError.invalidIntent }
        return id
      }
      try self.init(
        operationID: .init(validating: operation), locations: .init(value: locations),
        sourceAnchor: V3RecoveryAnchorCodec().parseCanonical(CanonicalJSON.encode(anchor)),
        sourcePublicKey: point, sourceHeadDigest: head, sourceObservationDigest: observation,
        vaultID: vault, transitionID: transition, entryIDs: ids)
    } catch let error as V3RecoveryRestoreError { throw error } catch {
      throw V3RecoveryRestoreError.invalidIntent
    }
  }

  func requireSnapshot(_ snapshot: V3RecoveryVerifiedSnapshot) throws {
    let selection = snapshot.selection
    guard sourceAnchor.canonicalBytes == selection.anchor.canonicalBytes,
      sourcePublicKey == selection.credentialPublicKey, sourceHeadDigest == selection.head.digest,
      sourceObservationDigest == V3RecoveryRestoreIntent.observationDigest(selection)
    else { throw V3RecoveryRestoreError.invalidIntent }
  }

  func requireBundle(_ bundle: V3RecoveryRestoreBundle) throws {
    let intent = bundle.intent
    guard operationID == intent.operationID, locations == intent.locations,
      sourceAnchor.canonicalBytes == intent.sourceAnchor.canonicalBytes,
      sourcePublicKey == intent.sourcePublicKey, sourceHeadDigest == intent.sourceHeadDigest,
      sourceObservationDigest == intent.sourceObservationDigest,
      vaultID == intent.destinationCheckpoint.vaultID,
      transitionID == bundle.manifest.body.authorityTransitionID,
      entryIDs == bundle.manifest.body.entries.map(\.entryID)
    else { throw V3RecoveryRestoreError.invalidIntent }
  }

  var canonicalBytes: Data {
    CanonicalJSON.encode(
      .object([
        ("format", .string("key-vault-recovery-restore-reservation")), ("version", .integer(1)),
        ("operationID", .string(operationID.rawValue)), ("locations", locations.value),
        ("sourceAnchor", sourceAnchor.canonicalValue),
        ("sourcePublicKey", .string(Base64URL.encode(sourcePublicKey))),
        ("sourceHeadDigest", .string(Base64URL.encode(sourceHeadDigest))),
        ("sourceObservationDigest", .string(Base64URL.encode(sourceObservationDigest))),
        ("vaultID", .string(vaultID)), ("transitionID", .string(transitionID)),
        ("entryIDs", .array(entryIDs.map { .string($0) })),
      ]))
  }

  private static func bytes(_ value: CanonicalJSONValue?, count: Int) -> Data? {
    guard let text = value?.stringValue, text.utf8.count == (count * 8 + 5) / 6,
      let bytes = Base64URL.decodeCanonical(text), bytes.count == count
    else { return nil }
    return bytes
  }
}
