import CryptoKit
import Foundation
internal import JSONCanonicalization

enum V3RecoveryRecipientError: Error, Equatable {
  case invalidRecipient
  case invalidContext
  case invalidWrappedKey
  case invalidCoverage
  case invalidEncoding
  case nonCanonicalEncoding
  case unsupportedVersion(UInt64)
  case invalidStructure
  case recipientMismatch
  case invalidVaultKey
  case keyIdentityMismatch
}

/// Recovery credentials are not Mac identities. This digest identifies only
/// a validated public key; it proves neither token possession nor registration.
struct V3RecoveryRecipientID: Equatable, Hashable, Sendable {
  let rawValue: String

  init(rawValue: String) throws {
    guard rawValue.utf8.count == 43, Base64URL.decodeCanonical(rawValue)?.count == 32 else {
      throw V3RecoveryRecipientError.invalidRecipient
    }
    self.rawValue = rawValue
  }

  static func derive(publicKey: Data) throws -> Self {
    guard publicKey.count == 65, publicKey.first == 0x04,
      (try? P256.KeyAgreement.PublicKey(x963Representation: publicKey)) != nil
    else { throw V3RecoveryRecipientError.invalidRecipient }
    var input = Data("work.tvr.key/v3/recovery-recipient-id/v1".utf8)
    input.append(0)
    input.append(publicKey)
    return try Self(rawValue: Base64URL.encode(Data(SHA256.hash(data: input))))
  }
}

enum V3RecoveryPIVSlot: String, Sendable { case keyManagement = "9d" }
enum V3RecoveryRecipientStatus: String, Sendable { case active, revoked }

struct V3RecoveryRecipient: Equatable, Sendable {
  let recipientID: V3RecoveryRecipientID
  let registrationID: String
  let publicKey: Data
  let slot: V3RecoveryPIVSlot
  let status: V3RecoveryRecipientStatus

  init(
    registrationID: String, publicKey: Data, slot: V3RecoveryPIVSlot,
    status: V3RecoveryRecipientStatus
  ) throws {
    guard isValidV3UUID(registrationID) else { throw V3RecoveryRecipientError.invalidRecipient }
    recipientID = try .derive(publicKey: publicKey)
    self.registrationID = registrationID
    self.publicKey = publicKey
    self.slot = slot
    self.status = status
  }

  var canonicalValue: CanonicalJSONValue {
    .object([
      ("recipientID", .string(recipientID.rawValue)),
      ("registrationID", .string(registrationID)),
      (
        "publicKey",
        .object([
          ("algorithm", .string("P-256-ECDH")), ("encoding", .string("x963")),
          ("value", .string(Base64URL.encode(publicKey))),
        ])
      ),
      ("slot", .string(slot.rawValue)), ("status", .string(status.rawValue)),
    ])
  }
}

struct V3RecoveryWrappedKey: Equatable, Sendable {
  let recipientID: V3RecoveryRecipientID
  let registrationID: String
  let wrappedKey: V3HPKEWrappedVaultKey

  init(
    recipientID: V3RecoveryRecipientID, registrationID: String,
    wrappedKey: V3HPKEWrappedVaultKey
  ) throws {
    guard isValidV3UUID(registrationID) else { throw V3RecoveryRecipientError.invalidWrappedKey }
    self.recipientID = recipientID
    self.registrationID = registrationID
    self.wrappedKey = wrappedKey
  }

  var canonicalValue: CanonicalJSONValue {
    .object([
      ("recipientID", .string(recipientID.rawValue)),
      ("registrationID", .string(registrationID)),
      ("encapsulatedKey", .string(Base64URL.encode(wrappedKey.encapsulatedKey))),
      ("ciphertext", .string(Base64URL.encode(wrappedKey.ciphertext))),
    ])
  }
}

/// Experimental profile-3 recovery member. Shape and coverage are validated,
/// not origin, possession, anchor administration, or transition authorization.
struct V3RecoveryRoster: Equatable, Sendable {
  static let version: UInt64 = 1
  static let maximumRecipients = 64

  let generationID: String
  let recipients: [V3RecoveryRecipient]
  let wrappedKeys: [V3RecoveryWrappedKey]

  init(
    generationID: String, recipients: [V3RecoveryRecipient], wrappedKeys: [V3RecoveryWrappedKey]
  ) throws {
    guard isValidV3UUID(generationID), recipients.count <= Self.maximumRecipients,
      wrappedKeys.count <= Self.maximumRecipients,
      Set(recipients.map(\.recipientID)).count == recipients.count,
      Set(recipients.map(\.registrationID)).count == recipients.count,
      recipients.map(\.recipientID.rawValue) == recipients.map(\.recipientID.rawValue).sorted(),
      wrappedKeys.map(\.recipientID.rawValue) == wrappedKeys.map(\.recipientID.rawValue).sorted()
    else { throw V3RecoveryRecipientError.invalidCoverage }
    let active = recipients.filter { $0.status == .active }
    guard active.count == wrappedKeys.count,
      zip(active, wrappedKeys).allSatisfy({
        $0.recipientID == $1.recipientID && $0.registrationID == $1.registrationID
      })
    else { throw V3RecoveryRecipientError.invalidCoverage }
    self.generationID = generationID
    self.recipients = recipients
    self.wrappedKeys = wrappedKeys
  }

  var canonicalValue: CanonicalJSONValue {
    .object([
      ("version", .integer(Self.version)), ("generationID", .string(generationID)),
      ("recipients", .array(recipients.map(\.canonicalValue))),
      ("wrappedKeys", .array(wrappedKeys.map(\.canonicalValue))),
    ])
  }

  var canonicalBytes: Data { CanonicalJSON.encode(canonicalValue) }
}

struct V3RecoveryRosterCodec: Sendable {
  static let maximumBytes = 65_536

  func parseCanonical(_ data: Data) throws -> V3RecoveryRoster {
    guard data.count <= Self.maximumBytes else { throw V3RecoveryRecipientError.invalidEncoding }
    let value: CanonicalJSONValue
    do { value = try CanonicalJSON.parse(data) } catch {
      throw V3RecoveryRecipientError.invalidEncoding
    }
    guard CanonicalJSON.encode(value) == data else {
      throw V3RecoveryRecipientError.nonCanonicalEncoding
    }
    return try decode(value)
  }

  /// The containing profile must enforce its own byte bound before decoding.
  /// Explicit field counts also reject duplicates in manually constructed values.
  func decode(_ value: CanonicalJSONValue) throws -> V3RecoveryRoster {
    guard let fields = value.objectValue,
      let version = fields.first(where: { $0.0 == "version" })?.1.integerValue
    else { throw V3RecoveryRecipientError.invalidStructure }
    guard version == V3RecoveryRoster.version else {
      throw V3RecoveryRecipientError.unsupportedVersion(version)
    }
    let root = try object(value, names: ["version", "generationID", "recipients", "wrappedKeys"])
    guard let recipients = root["recipients"]?.arrayValue,
      let wrappers = root["wrappedKeys"]?.arrayValue,
      recipients.count <= V3RecoveryRoster.maximumRecipients,
      wrappers.count <= V3RecoveryRoster.maximumRecipients
    else { throw V3RecoveryRecipientError.invalidStructure }
    return try V3RecoveryRoster(
      generationID: string("generationID", in: root),
      recipients: recipients.map(decodeRecipient), wrappedKeys: wrappers.map(decodeWrappedKey))
  }

  private func decodeRecipient(_ value: CanonicalJSONValue) throws -> V3RecoveryRecipient {
    let fields = try object(
      value, names: ["recipientID", "registrationID", "publicKey", "slot", "status"])
    let key = try object(
      try member("publicKey", in: fields), names: ["algorithm", "encoding", "value"])
    guard try string("algorithm", in: key) == "P-256-ECDH",
      try string("encoding", in: key) == "x963",
      let slot = V3RecoveryPIVSlot(rawValue: try string("slot", in: fields)),
      let status = V3RecoveryRecipientStatus(rawValue: try string("status", in: fields))
    else { throw V3RecoveryRecipientError.invalidStructure }
    let result = try V3RecoveryRecipient(
      registrationID: string("registrationID", in: fields),
      publicKey: data("value", in: key, count: 65), slot: slot, status: status)
    guard try string("recipientID", in: fields) == result.recipientID.rawValue else {
      throw V3RecoveryRecipientError.invalidRecipient
    }
    return result
  }

  private func decodeWrappedKey(_ value: CanonicalJSONValue) throws -> V3RecoveryWrappedKey {
    let fields = try object(
      value, names: ["recipientID", "registrationID", "encapsulatedKey", "ciphertext"])
    let wrapped: V3HPKEWrappedVaultKey
    do {
      wrapped = try V3HPKEWrappedVaultKey(
        encapsulatedKey: data("encapsulatedKey", in: fields, count: 65),
        ciphertext: data("ciphertext", in: fields, count: 48))
    } catch { throw V3RecoveryRecipientError.invalidWrappedKey }
    return try V3RecoveryWrappedKey(
      recipientID: V3RecoveryRecipientID(rawValue: string("recipientID", in: fields)),
      registrationID: string("registrationID", in: fields), wrappedKey: wrapped)
  }

  private func object(_ value: CanonicalJSONValue, names: Set<String>) throws -> [String:
    CanonicalJSONValue]
  {
    guard let fields = value.objectValue, fields.count == names.count,
      Set(fields.map(\.0)) == names
    else { throw V3RecoveryRecipientError.invalidStructure }
    return Dictionary(uniqueKeysWithValues: fields)
  }

  private func member(_ name: String, in fields: [String: CanonicalJSONValue]) throws
    -> CanonicalJSONValue
  {
    guard let value = fields[name] else { throw V3RecoveryRecipientError.invalidStructure }
    return value
  }

  private func string(_ name: String, in fields: [String: CanonicalJSONValue]) throws -> String {
    guard let value = try member(name, in: fields).stringValue else {
      throw V3RecoveryRecipientError.invalidStructure
    }
    return value
  }

  private func data(_ name: String, in fields: [String: CanonicalJSONValue], count: Int) throws
    -> Data
  {
    let encoded = try string(name, in: fields)
    guard encoded.utf8.count == (count * 8 + 5) / 6,
      let value = Base64URL.decodeCanonical(encoded), value.count == count
    else {
      throw V3RecoveryRecipientError.invalidStructure
    }
    return value
  }
}
