import CryptoKit
import Foundation
internal import JSONCanonicalization

/// Public bindings for exactly one restore attempt. This is the authenticated
/// record format, not a durable journal or saved consent. Parsing grants no
/// filesystem, credential-opening, publication or configuration authority.
struct V3RecoveryRestoreIntent: Equatable, Sendable {
  static let maximumBytes = 32 * 1_024
  private static let keyInfo = Data("work.tvr.key/v3/recovery-restore-intent-mac/v1".utf8)

  let operationID: VaultTransactionOperationID
  let locations: V3RecoveryRestoreLocations
  let sourceAnchor: V3RecoveryAnchor
  let sourcePublicKey: Data
  let sourceHeadDigest: Data
  let sourceObservationDigest: Data
  let destinationCheckpoint: V3ManifestCheckpoint
  let destinationKeyID: V3VaultKeyID
  let ownerDeviceID: String
  let authenticationTag: Data

  init(
    operationID: VaultTransactionOperationID, candidate: V3RecoveryRestoreCandidate,
    environment: V3RecoveryRestoreEnvironment, destinationVaultKey: Data
  ) throws {
    try environment.requireSnapshot(candidate.snapshot)
    let locations = environment.locations
    let selection = candidate.snapshot.selection
    let genesis = candidate.publication.genesis
    guard let owner = genesis.body.devices.first, genesis.body.devices.count == 1 else {
      throw V3RecoveryRestoreError.invalidIntent
    }
    let unsigned = try Self(
      operationID: operationID, locations: locations, sourceAnchor: selection.anchor,
      sourcePublicKey: selection.credentialPublicKey, sourceHeadDigest: selection.head.digest,
      sourceObservationDigest: Self.observationDigest(selection),
      destinationCheckpoint: .init(
        vaultID: genesis.body.vaultID, envelopeDigest: genesis.manifestDigest),
      destinationKeyID: genesis.body.keyID, ownerDeviceID: owner.identity.deviceID,
      authenticationTag: Data(repeating: 0, count: 32))
    guard
      try V3VaultKeyID.derive(
        vaultKey: destinationVaultKey, vaultID: genesis.body.vaultID) == genesis.body.keyID
    else { throw V3RecoveryRestoreError.authenticationFailed }
    let tag = Data(
      HMAC<SHA256>.authenticationCode(
        for: unsigned.unsignedBytes,
        using: try Self.authenticationKey(destinationVaultKey, vaultID: genesis.body.vaultID)))
    try self.init(
      operationID: operationID, locations: locations, sourceAnchor: unsigned.sourceAnchor,
      sourcePublicKey: unsigned.sourcePublicKey, sourceHeadDigest: unsigned.sourceHeadDigest,
      sourceObservationDigest: unsigned.sourceObservationDigest,
      destinationCheckpoint: unsigned.destinationCheckpoint,
      destinationKeyID: unsigned.destinationKeyID,
      ownerDeviceID: unsigned.ownerDeviceID, authenticationTag: tag)
    try requireCandidate(candidate)
    try environment.requireSnapshot(candidate.snapshot)
  }

  private init(
    operationID: VaultTransactionOperationID, locations: V3RecoveryRestoreLocations,
    sourceAnchor: V3RecoveryAnchor, sourcePublicKey: Data, sourceHeadDigest: Data,
    sourceObservationDigest: Data, destinationCheckpoint: V3ManifestCheckpoint,
    destinationKeyID: V3VaultKeyID, ownerDeviceID: String, authenticationTag: Data
  ) throws {
    guard sourceHeadDigest.count == 32, sourceObservationDigest.count == 32,
      sourcePublicKey.count == 65,
      try V3RecoveryRecipientID.derive(publicKey: sourcePublicKey) == sourceAnchor.recipientID,
      destinationCheckpoint.vaultID != sourceAnchor.floor.vaultID,
      sourceAnchor.floor.envelopeDigest != destinationCheckpoint.envelopeDigest,
      Base64URL.decodeCanonical(ownerDeviceID)?.count == 32,
      ownerDeviceID.utf8.count == 43, authenticationTag.count == 32,
      locations.source.identity != locations.destination.identity,
      locations.configuration.identity != locations.source.identity,
      locations.configuration.identity != locations.destination.identity
    else { throw V3RecoveryRestoreError.invalidIntent }
    // Apply the same path/identifier rules to construction and parsing.
    _ = try V3RecoveryRestoreLocations(value: locations.value)
    self.operationID = operationID
    self.locations = locations
    self.sourceAnchor = sourceAnchor
    self.sourcePublicKey = sourcePublicKey
    self.sourceHeadDigest = sourceHeadDigest
    self.sourceObservationDigest = sourceObservationDigest
    self.destinationCheckpoint = destinationCheckpoint
    self.destinationKeyID = destinationKeyID
    self.ownerDeviceID = ownerDeviceID
    self.authenticationTag = authenticationTag
  }

  init(canonicalBytes: Data) throws {
    guard canonicalBytes.count <= Self.maximumBytes else {
      throw V3RecoveryRestoreError.resourceLimit
    }
    do {
      let json = try CanonicalJSON.parse(canonicalBytes)
      guard CanonicalJSON.encode(json) == canonicalBytes,
        let fields = json.objectValue, fields.count == 13,
        Set(fields.map(\.0)) == [
          "format", "version", "operationID", "locations", "sourceAnchor", "sourcePublicKey",
          "sourceHeadDigest", "sourceObservationDigest", "destinationCheckpoint",
          "destinationKeyID",
          "ownerDeviceID", "authenticationAlgorithm", "authenticationTag",
        ]
      else { throw V3RecoveryRestoreError.invalidIntent }
      let root = Dictionary(uniqueKeysWithValues: fields)
      guard root["format"]?.stringValue == "key-vault-recovery-restore-intent",
        root["version"]?.integerValue == 1,
        root["authenticationAlgorithm"]?.stringValue == "HKDF-SHA256+HMAC-SHA256",
        let operation = root["operationID"]?.stringValue,
        let locationsValue = root["locations"], let anchor = root["sourceAnchor"],
        let publicKey = Self.bytes(root["sourcePublicKey"], count: 65),
        let head = Self.bytes(root["sourceHeadDigest"], count: 32),
        let observation = Self.bytes(root["sourceObservationDigest"], count: 32),
        let checkpoint = root["destinationCheckpoint"],
        let keyID = root["destinationKeyID"]?.stringValue,
        let owner = root["ownerDeviceID"]?.stringValue,
        let tag = Self.bytes(root["authenticationTag"], count: 32)
      else { throw V3RecoveryRestoreError.invalidIntent }
      try self.init(
        operationID: .init(validating: operation), locations: .init(value: locationsValue),
        sourceAnchor: V3RecoveryAnchorCodec().parseCanonical(CanonicalJSON.encode(anchor)),
        sourcePublicKey: publicKey, sourceHeadDigest: head, sourceObservationDigest: observation,
        destinationCheckpoint: .init(canonicalBytes: CanonicalJSON.encode(checkpoint)),
        destinationKeyID: .init(rawValue: keyID), ownerDeviceID: owner, authenticationTag: tag)
    } catch let error as V3RecoveryRestoreError { throw error } catch {
      throw V3RecoveryRestoreError.invalidIntent
    }
  }

  func authenticate(destinationVaultKey: Data) throws {
    guard destinationVaultKey.count == 32,
      try V3VaultKeyID.derive(vaultKey: destinationVaultKey, vaultID: destinationCheckpoint.vaultID)
        == destinationKeyID,
      HMAC<SHA256>.isValidAuthenticationCode(
        authenticationTag, authenticating: unsignedBytes,
        using: try Self.authenticationKey(
          destinationVaultKey, vaultID: destinationCheckpoint.vaultID))
    else { throw V3RecoveryRestoreError.authenticationFailed }
  }

  /// Bind a freshly reverified source/candidate to the saved record. This is
  /// additional to MAC authentication, live locations and full candidate checks.
  func requireCandidate(_ candidate: V3RecoveryRestoreCandidate) throws {
    let selection = candidate.snapshot.selection
    let genesis = candidate.publication.genesis
    guard sourceAnchor.canonicalBytes == selection.anchor.canonicalBytes,
      sourcePublicKey == selection.credentialPublicKey, sourceHeadDigest == selection.head.digest,
      sourceObservationDigest == Self.observationDigest(selection),
      destinationCheckpoint.vaultID == genesis.body.vaultID,
      destinationCheckpoint.envelopeDigest == genesis.manifestDigest,
      genesis.manifestDigest == Data(SHA256.hash(data: genesis.manifestData)),
      destinationKeyID == genesis.body.keyID, genesis.body.devices.count == 1,
      genesis.body.devices.first?.identity.deviceID == ownerDeviceID
    else { throw V3RecoveryRestoreError.invalidIntent }
  }

  var canonicalBytes: Data {
    CanonicalJSON.encode(
      .object(
        unsignedFields + [
          ("authenticationTag", .string(Base64URL.encode(authenticationTag)))
        ]))
  }

  private var unsignedBytes: Data { CanonicalJSON.encode(.object(unsignedFields)) }
  private var unsignedFields: [(String, CanonicalJSONValue)] {
    [
      ("format", .string("key-vault-recovery-restore-intent")), ("version", .integer(1)),
      ("operationID", .string(operationID.rawValue)), ("locations", locations.value),
      ("sourceAnchor", sourceAnchor.canonicalValue),
      ("sourcePublicKey", .string(Base64URL.encode(sourcePublicKey))),
      ("sourceHeadDigest", .string(Base64URL.encode(sourceHeadDigest))),
      ("sourceObservationDigest", .string(Base64URL.encode(sourceObservationDigest))),
      (
        "destinationCheckpoint",
        .object([
          ("format", .string("key-vault-manifest-checkpoint")), ("version", .integer(1)),
          ("vaultID", .string(destinationCheckpoint.vaultID)),
          ("envelopeDigest", .string(Base64URL.encode(destinationCheckpoint.envelopeDigest))),
        ])
      ),
      ("destinationKeyID", .string(destinationKeyID.rawValue)),
      ("ownerDeviceID", .string(ownerDeviceID)),
      ("authenticationAlgorithm", .string("HKDF-SHA256+HMAC-SHA256")),
    ]
  }

  static func observationDigest(_ selection: V3RecoveryPublicSelection) -> Data {
    // Current entry bytes are already committed by the exact head. Also bind
    // the public observation so resume cannot silently absorb a different
    // listing/history while retaining the same selected head.
    let observed = selection.observedManifestBytes.map { digest, bytes in
      (v3LowercaseHex(digest), Data(SHA256.hash(data: bytes)))
    }.sorted { $0.0 < $1.0 }
    let bytes = CanonicalJSON.encode(
      .object([
        ("format", .string("key-vault-recovery-restore-source-observation")),
        ("version", .integer(1)),
        ("epochRoot", .string(Base64URL.encode(selection.epochRoot.digest))),
        ("listedObjectCount", .integer(UInt64(selection.listedObjectCount))),
        (
          "listedDigests",
          .array(selection.listedDigests.map(v3LowercaseHex).sorted().map { .string($0) })
        ),
        (
          "observedManifests",
          .array(observed.map { .array([.string($0.0), .string(Base64URL.encode($0.1))]) })
        ),
      ]))
    return Data(SHA256.hash(data: bytes))
  }

  private static func authenticationKey(_ key: Data, vaultID: String) throws -> SymmetricKey {
    guard key.count == 32 else { throw V3RecoveryRestoreError.authenticationFailed }
    return HKDF<SHA256>.deriveKey(
      inputKeyMaterial: SymmetricKey(data: key), salt: Data(vaultID.utf8), info: keyInfo,
      outputByteCount: 32)
  }

  private static func bytes(_ value: CanonicalJSONValue?, count: Int) -> Data? {
    guard let text = value?.stringValue, text.utf8.count == (count * 8 + 5) / 6,
      let bytes = Base64URL.decodeCanonical(text), bytes.count == count
    else { return nil }
    return bytes
  }
}
