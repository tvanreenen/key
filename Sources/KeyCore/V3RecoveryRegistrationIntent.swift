import CryptoKit
import Foundation
internal import JSONCanonicalization

enum V3RecoveryRegistrationError: Error, Equatable {
  case invalidParent
  case invalidCandidate
  case invalidCredential
  case occupiedAnchor
  case invalidOwner
  case invalidIntent
  case authenticationFailed
  case incompleteSnapshot
  case invalidEntry
  case resourceLimit
  case anchorMismatch
  case possessionMismatch
}

/// Exact, public evidence for one external registration attempt. The MAC is
/// checked with the reauthenticated parent key; parsing alone proves no consent.
/// No private key, plaintext, administrator secret or possession result is saved.
struct V3RecoveryRegistrationIntent: Equatable, Sendable {
  static let maximumBytes = 4 * 1_024 * 1_024
  private static let keyInfo = Data("work.tvr.key/v3/recovery-registration-intent-mac/v1".utf8)

  let operationID: VaultTransactionOperationID
  let expectedCheckpoint: V3ManifestCheckpoint
  let ownerDeviceID: String
  let publicKey: Data
  let anchor: V3RecoveryAnchor
  let stagedEntries: [V3ImmutableTransactionRecoveryEntry]
  let authenticationTag: Data

  init(
    operationID: VaultTransactionOperationID, expectedCheckpoint: V3ManifestCheckpoint,
    ownerDeviceID: String, publicKey: Data, anchor: V3RecoveryAnchor,
    stagedEntries: [V3ImmutableTransactionRecoveryEntry], currentVaultKey: Data
  ) throws {
    let unsigned = try Self(
      operationID: operationID, expectedCheckpoint: expectedCheckpoint,
      ownerDeviceID: ownerDeviceID, publicKey: publicKey, anchor: anchor,
      stagedEntries: stagedEntries, authenticationTag: Data(repeating: 0, count: 32))
    let tag = Data(
      HMAC<SHA256>.authenticationCode(
        for: unsigned.unsignedBytes,
        using: try Self.authenticationKey(currentVaultKey, vaultID: expectedCheckpoint.vaultID)))
    try self.init(
      operationID: operationID, expectedCheckpoint: expectedCheckpoint,
      ownerDeviceID: ownerDeviceID, publicKey: publicKey, anchor: anchor,
      stagedEntries: stagedEntries, authenticationTag: tag)
  }

  private init(
    operationID: VaultTransactionOperationID, expectedCheckpoint: V3ManifestCheckpoint,
    ownerDeviceID: String, publicKey: Data, anchor: V3RecoveryAnchor,
    stagedEntries: [V3ImmutableTransactionRecoveryEntry], authenticationTag: Data
  ) throws {
    guard ownerDeviceID.utf8.count == 43,
      Base64URL.decodeCanonical(ownerDeviceID)?.count == 32,
      expectedCheckpoint.vaultID == anchor.floor.vaultID,
      expectedCheckpoint.envelopeDigest != anchor.floor.envelopeDigest,
      try V3RecoveryRecipientID.derive(publicKey: publicKey) == anchor.recipientID,
      stagedEntries.count <= V3ImmutableTransactionRecoveryIntent.maximumStagedEntries,
      stagedEntries.allSatisfy({ isValidV3UUID($0.entryID) && $0.digest.count == 32 }),
      Set(stagedEntries.map(\.entryID)).count == stagedEntries.count,
      stagedEntries.map(\.entryID) == stagedEntries.map(\.entryID).sorted(),
      authenticationTag.count == 32
    else { throw V3RecoveryRegistrationError.invalidIntent }
    self.operationID = operationID
    self.expectedCheckpoint = expectedCheckpoint
    self.ownerDeviceID = ownerDeviceID
    self.publicKey = publicKey
    self.anchor = anchor
    self.stagedEntries = stagedEntries
    self.authenticationTag = authenticationTag
  }

  init(canonicalBytes: Data) throws {
    guard canonicalBytes.count <= Self.maximumBytes else {
      throw V3RecoveryRegistrationError.resourceLimit
    }
    do {
      let json = try CanonicalJSON.parse(canonicalBytes)
      guard CanonicalJSON.encode(json) == canonicalBytes,
        let fields = json.objectValue, fields.count == 11,
        Set(fields.map(\.0))
          == Set([
            "format", "version", "operationID", "expectedCheckpoint", "ownerDeviceID",
            "publicKey", "anchor", "requiresEmptyAnchor", "stagedEntries",
            "authenticationAlgorithm", "authenticationTag",
          ])
      else { throw V3RecoveryRegistrationError.invalidIntent }
      let root = Dictionary(uniqueKeysWithValues: fields)
      guard root["format"]?.stringValue == "key-vault-external-recovery-registration",
        root["version"]?.integerValue == 1, case .bool(true)? = root["requiresEmptyAnchor"],
        root["authenticationAlgorithm"]?.stringValue == "HKDF-SHA256+HMAC-SHA256",
        let operation = root["operationID"]?.stringValue,
        let checkpoint = root["expectedCheckpoint"],
        let owner = root["ownerDeviceID"]?.stringValue,
        let point = Self.bytes(root["publicKey"], count: 65),
        let anchorValue = root["anchor"],
        let entries = root["stagedEntries"]?.arrayValue,
        entries.count <= V3ImmutableTransactionRecoveryIntent.maximumStagedEntries,
        let tag = Self.bytes(root["authenticationTag"], count: 32)
      else { throw V3RecoveryRegistrationError.invalidIntent }
      let staged = try entries.map { value in
        guard let fields = value.objectValue, fields.count == 2,
          Set(fields.map(\.0)) == ["entryID", "digest"]
        else { throw V3RecoveryRegistrationError.invalidIntent }
        let entry = Dictionary(uniqueKeysWithValues: fields)
        guard let id = entry["entryID"]?.stringValue,
          let digest = Self.bytes(entry["digest"], count: 32)
        else { throw V3RecoveryRegistrationError.invalidIntent }
        return V3ImmutableTransactionRecoveryEntry(entryID: id, digest: digest)
      }
      try self.init(
        operationID: VaultTransactionOperationID(validating: operation),
        expectedCheckpoint: V3ManifestCheckpoint(canonicalBytes: CanonicalJSON.encode(checkpoint)),
        ownerDeviceID: owner, publicKey: point,
        anchor: V3RecoveryAnchorCodec().parseCanonical(CanonicalJSON.encode(anchorValue)),
        stagedEntries: staged, authenticationTag: tag)
    } catch let error as V3RecoveryRegistrationError {
      throw error
    } catch { throw V3RecoveryRegistrationError.invalidIntent }
  }

  func authenticate(currentVaultKey: Data) throws {
    guard
      HMAC<SHA256>.isValidAuthenticationCode(
        authenticationTag, authenticating: unsignedBytes,
        using: try Self.authenticationKey(currentVaultKey, vaultID: expectedCheckpoint.vaultID))
    else { throw V3RecoveryRegistrationError.authenticationFailed }
  }

  var canonicalBytes: Data {
    CanonicalJSON.encode(
      .object(
        unsignedFields + [("authenticationTag", .string(Base64URL.encode(authenticationTag)))]))
  }

  private var unsignedBytes: Data { CanonicalJSON.encode(.object(unsignedFields)) }

  private var unsignedFields: [(String, CanonicalJSONValue)] {
    [
      ("format", .string("key-vault-external-recovery-registration")), ("version", .integer(1)),
      ("operationID", .string(operationID.rawValue)),
      (
        "expectedCheckpoint",
        .object([
          ("format", .string("key-vault-manifest-checkpoint")), ("version", .integer(1)),
          ("vaultID", .string(expectedCheckpoint.vaultID)),
          ("envelopeDigest", .string(Base64URL.encode(expectedCheckpoint.envelopeDigest))),
        ])
      ),
      ("ownerDeviceID", .string(ownerDeviceID)),
      ("publicKey", .string(Base64URL.encode(publicKey))),
      ("anchor", anchor.canonicalValue), ("requiresEmptyAnchor", .bool(true)),
      (
        "stagedEntries",
        .array(
          stagedEntries.map {
            .object([
              ("entryID", .string($0.entryID)), ("digest", .string(Base64URL.encode($0.digest))),
            ])
          })
      ),
      ("authenticationAlgorithm", .string("HKDF-SHA256+HMAC-SHA256")),
    ]
  }

  private static func authenticationKey(_ vaultKey: Data, vaultID: String) throws -> SymmetricKey {
    guard vaultKey.count == 32 else { throw V3RecoveryRegistrationError.authenticationFailed }
    return HKDF<SHA256>.deriveKey(
      inputKeyMaterial: SymmetricKey(data: vaultKey), salt: Data(vaultID.utf8),
      info: Self.keyInfo, outputByteCount: 32)
  }

  private static func bytes(_ value: CanonicalJSONValue?, count: Int) -> Data? {
    guard let text = value?.stringValue, text.utf8.count == (count * 8 + 5) / 6,
      let bytes = Base64URL.decodeCanonical(text), bytes.count == count
    else { return nil }
    return bytes
  }
}
