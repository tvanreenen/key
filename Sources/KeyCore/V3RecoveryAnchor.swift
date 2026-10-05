import Foundation
internal import JSONCanonicalization

enum V3RecoveryAnchorError: Error, Equatable {
  case invalidAnchor
  case invalidEncoding
  case nonCanonicalEncoding
  case unsupportedVersion(UInt64)
}

/// Exact public trust-floor record. Parsing establishes shape, not provenance:
/// the platform must read this from the bound token under qualified protected
/// administration. A provider copy or local JSON file is not a recovery anchor.
struct V3RecoveryAnchor: Equatable, Sendable {
  static let version: UInt64 = 1
  static let maximumBytes = 1_024
  let floor: V3VaultHead
  let recipientID: V3RecoveryRecipientID
  let registrationID: String
  let slot: V3RecoveryPIVSlot

  init(
    floor: V3VaultHead, recipientID: V3RecoveryRecipientID,
    registrationID: String, slot: V3RecoveryPIVSlot
  ) throws {
    guard isValidV3UUID(registrationID) else { throw V3RecoveryAnchorError.invalidAnchor }
    self.floor = floor
    self.recipientID = recipientID
    self.registrationID = registrationID
    self.slot = slot
  }

  var canonicalValue: CanonicalJSONValue {
    .object([
      ("format", .string("key-vault-piv-recovery-anchor")), ("version", .integer(Self.version)),
      ("profile", .string(V3EpochSigningKeyContext.profile)),
      ("profileVersion", .integer(V3RecoveryManifestBody.profileVersion)),
      ("vaultID", .string(floor.vaultID)),
      ("registrationManifestDigest", .string(Base64URL.encode(floor.envelopeDigest))),
      ("recipientID", .string(recipientID.rawValue)),
      ("registrationID", .string(registrationID)), ("slot", .string(slot.rawValue)),
      (
        "hpkeSuite",
        .object([
          ("mode", .integer(V3VaultKeyHPKEContext.hpkeMode)),
          ("kem", .integer(V3VaultKeyHPKEContext.hpkeKEM)),
          ("kdf", .integer(V3VaultKeyHPKEContext.hpkeKDF)),
          ("aead", .integer(V3VaultKeyHPKEContext.hpkeAEAD)),
        ])
      ),
    ])
  }

  var canonicalBytes: Data { CanonicalJSON.encode(canonicalValue) }
}

struct V3RecoveryAnchorCodec: Sendable {
  func parseCanonical(_ data: Data) throws -> V3RecoveryAnchor {
    guard data.count <= V3RecoveryAnchor.maximumBytes else {
      throw V3RecoveryAnchorError.invalidEncoding
    }
    let value: CanonicalJSONValue
    do { value = try CanonicalJSON.parse(data) } catch {
      throw V3RecoveryAnchorError.invalidEncoding
    }
    guard CanonicalJSON.encode(value) == data else {
      throw V3RecoveryAnchorError.nonCanonicalEncoding
    }
    return try decode(value)
  }

  func decode(_ value: CanonicalJSONValue) throws -> V3RecoveryAnchor {
    guard let fields = value.objectValue,
      let version = fields.first(where: { $0.0 == "version" })?.1.integerValue
    else { throw V3RecoveryAnchorError.invalidAnchor }
    guard version == V3RecoveryAnchor.version else {
      throw V3RecoveryAnchorError.unsupportedVersion(version)
    }
    let root = try object(
      value,
      names: [
        "format", "version", "profile", "profileVersion", "vaultID",
        "registrationManifestDigest", "recipientID", "registrationID", "slot", "hpkeSuite",
      ])
    let suite = try object(member("hpkeSuite", in: root), names: ["mode", "kem", "kdf", "aead"])
    guard root["format"]?.stringValue == "key-vault-piv-recovery-anchor",
      root["profile"]?.stringValue == V3EpochSigningKeyContext.profile,
      root["profileVersion"]?.integerValue == V3RecoveryManifestBody.profileVersion,
      root["slot"]?.stringValue == V3RecoveryPIVSlot.keyManagement.rawValue,
      suite["mode"]?.integerValue == V3VaultKeyHPKEContext.hpkeMode,
      suite["kem"]?.integerValue == V3VaultKeyHPKEContext.hpkeKEM,
      suite["kdf"]?.integerValue == V3VaultKeyHPKEContext.hpkeKDF,
      suite["aead"]?.integerValue == V3VaultKeyHPKEContext.hpkeAEAD,
      let digestText = root["registrationManifestDigest"]?.stringValue, digestText.utf8.count == 43,
      let digest = Base64URL.decodeCanonical(digestText), digest.count == 32
    else { throw V3RecoveryAnchorError.invalidAnchor }
    do {
      return try V3RecoveryAnchor(
        floor: V3VaultHead(vaultID: string("vaultID", in: root), envelopeDigest: digest),
        recipientID: V3RecoveryRecipientID(rawValue: string("recipientID", in: root)),
        registrationID: string("registrationID", in: root), slot: .keyManagement)
    } catch { throw V3RecoveryAnchorError.invalidAnchor }
  }

  private func object(_ value: CanonicalJSONValue, names: Set<String>) throws -> [String:
    CanonicalJSONValue]
  {
    guard let fields = value.objectValue, fields.count == names.count, Set(fields.map(\.0)) == names
    else {
      throw V3RecoveryAnchorError.invalidAnchor
    }
    return Dictionary(uniqueKeysWithValues: fields)
  }

  private func member(_ name: String, in fields: [String: CanonicalJSONValue]) throws
    -> CanonicalJSONValue
  {
    guard let value = fields[name] else { throw V3RecoveryAnchorError.invalidAnchor }
    return value
  }

  private func string(_ name: String, in fields: [String: CanonicalJSONValue]) throws -> String {
    guard let value = fields[name]?.stringValue else { throw V3RecoveryAnchorError.invalidAnchor }
    return value
  }
}
