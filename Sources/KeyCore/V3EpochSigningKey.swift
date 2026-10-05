import CryptoKit
import Foundation
internal import JSONCanonicalization

enum V3EpochSigningKeyError: Error, Equatable {
  case invalidContext
  case invalidVaultKey
  case keyIdentityMismatch
  case invalidPublicKey
  case invalidCapsule
  case invalidEncoding
  case nonCanonicalEncoding
  case unsupportedVersion(UInt64)
  case invalidStructure
  case sealingFailed
  case authenticationFailed
}

/// Syntactically valid epoch identity, not an authenticated checkpoint.
/// Profile 3 remains experimental; this component does not enable its callers.
struct V3EpochSigningKeyContext: Equatable, Sendable {
  static let profile = "device-wrapped"
  static let profileVersion: UInt64 = 3

  let vaultID: String
  let keyID: V3VaultKeyID
  let authorityTransitionID: String

  init(vaultID: String, keyID: V3VaultKeyID, authorityTransitionID: String) throws {
    guard isValidV3UUID(vaultID), isValidV3UUID(authorityTransitionID) else {
      throw V3EpochSigningKeyError.invalidContext
    }
    self.vaultID = vaultID
    self.keyID = keyID
    self.authorityTransitionID = authorityTransitionID
  }

  func authenticatedData(publicKey: Data) throws -> Data {
    try V3EpochSigningKeyCapsule.validatePublicKey(publicKey)
    let value: CanonicalJSONValue = .object([
      ("format", .string("key-vault-epoch-signing-key-context")),
      ("version", .integer(V3EpochSigningKeyCapsule.version)),
      ("profile", .string(Self.profile)),
      ("profileVersion", .integer(Self.profileVersion)),
      ("vaultID", .string(vaultID)),
      ("keyID", .string(keyID.rawValue)),
      ("authorityTransitionID", .string(authorityTransitionID)),
      ("signingAlgorithm", .string(V3EpochSigningKeyCapsule.signingAlgorithm)),
      ("protectionAlgorithm", .string(V3EpochSigningKeyCapsule.protectionAlgorithm)),
      ("publicKey", .string(Base64URL.encode(publicKey))),
    ])
    var result = Data("work.tvr.key/v3/epoch-signing-key-aad/v1".utf8)
    result.append(0)
    result.append(CanonicalJSON.encode(value))
    return result
  }
}

/// Public key and encrypted private representation only. Parsing proves shape,
/// not origin, authorization, or correspondence with the encrypted private key.
struct V3EpochSigningKeyCapsule: Equatable, Sendable {
  static let version: UInt64 = 1
  static let signingAlgorithm = "P-256-ECDSA-SHA256"
  static let protectionAlgorithm = "HKDF-SHA256+AES-256-GCM"
  static let combinedByteCount = 12 + 32 + 16

  let publicKey: Data
  let protectedSigningKey: Data

  init(publicKey: Data, protectedSigningKey: Data) throws {
    try Self.validatePublicKey(publicKey)
    guard protectedSigningKey.count == Self.combinedByteCount else {
      throw V3EpochSigningKeyError.invalidCapsule
    }
    self.publicKey = publicKey
    self.protectedSigningKey = protectedSigningKey
  }

  var canonicalValue: CanonicalJSONValue {
    .object([
      ("version", .integer(Self.version)),
      ("signingAlgorithm", .string(Self.signingAlgorithm)),
      ("protectionAlgorithm", .string(Self.protectionAlgorithm)),
      ("publicKey", .string(Base64URL.encode(publicKey))),
      ("protectedSigningKey", .string(Base64URL.encode(protectedSigningKey))),
    ])
  }

  var canonicalBytes: Data { CanonicalJSON.encode(canonicalValue) }

  fileprivate static func validatePublicKey(_ data: Data) throws {
    guard data.count == 65, data.first == 0x04,
      (try? P256.Signing.PublicKey(x963Representation: data)) != nil
    else {
      throw V3EpochSigningKeyError.invalidPublicKey
    }
  }
}

struct V3EpochSigningKeyCapsuleCodec: Sendable {
  static let maximumBytes = 1_024

  func parseCanonical(_ data: Data) throws -> V3EpochSigningKeyCapsule {
    guard data.count <= Self.maximumBytes else {
      throw V3EpochSigningKeyError.invalidEncoding
    }
    let value: CanonicalJSONValue
    do {
      value = try CanonicalJSON.parse(data)
    } catch {
      throw V3EpochSigningKeyError.invalidEncoding
    }
    guard CanonicalJSON.encode(value) == data else {
      throw V3EpochSigningKeyError.nonCanonicalEncoding
    }
    return try decode(value)
  }

  /// Used by the containing profile's bounded canonical parser. Rejects
  /// duplicate fields even for a manually constructed JSON value.
  func decode(_ value: CanonicalJSONValue) throws -> V3EpochSigningKeyCapsule {
    guard let fields = value.objectValue,
      let version = fields.first(where: { $0.0 == "version" })?.1.integerValue
    else {
      throw V3EpochSigningKeyError.invalidStructure
    }
    guard version == V3EpochSigningKeyCapsule.version else {
      throw V3EpochSigningKeyError.unsupportedVersion(version)
    }
    guard fields.count == 5,
      Set(fields.map(\.0))
        == Set([
          "version", "signingAlgorithm", "protectionAlgorithm", "publicKey",
          "protectedSigningKey",
        ]),
      string("signingAlgorithm", in: fields) == V3EpochSigningKeyCapsule.signingAlgorithm,
      string("protectionAlgorithm", in: fields) == V3EpochSigningKeyCapsule.protectionAlgorithm,
      let publicKey = data("publicKey", in: fields, byteCount: 65),
      let protectedKey = data(
        "protectedSigningKey", in: fields,
        byteCount: V3EpochSigningKeyCapsule.combinedByteCount
      )
    else {
      throw V3EpochSigningKeyError.invalidStructure
    }
    return try V3EpochSigningKeyCapsule(publicKey: publicKey, protectedSigningKey: protectedKey)
  }

  private func string(_ name: String, in fields: [(String, CanonicalJSONValue)]) -> String? {
    fields.first(where: { $0.0 == name })?.1.stringValue
  }

  private func data(
    _ name: String, in fields: [(String, CanonicalJSONValue)], byteCount: Int
  ) -> Data? {
    guard let encoded = string(name, in: fields),
      let decoded = Base64URL.decodeCanonical(encoded), decoded.count == byteCount
    else { return nil }
    return decoded
  }
}

/// Capsule cryptography, not a history verifier or publication authority.
///
/// The epoch builder must supply a fresh vault key and prepare one capsule per
/// epoch. Preserve its exact bytes through edits/retries; abandon the complete
/// candidate and generate fresh epoch keys when re-preparing. This stateless
/// component cannot enforce durable nonce budgets or detect vault-key reuse.
struct V3EpochSigningKeyCipher: Sendable {
  private static let keyInfo = Data("work.tvr.key/v3/epoch-signing-key-kek/v1".utf8)

  func prepare(
    context: V3EpochSigningKeyContext, vaultKey: Data
  ) throws -> V3EpochSigningKeyCapsule {
    let wrappingKey = try wrappingKey(context: context, vaultKey: vaultKey)
    let signingKey = P256.Signing.PrivateKey()
    let publicKey = signingKey.publicKey.x963Representation
    do {
      let box = try AES.GCM.seal(
        signingKey.rawRepresentation, using: wrappingKey,
        authenticating: context.authenticatedData(publicKey: publicKey)
      )
      guard let combined = box.combined else {
        throw V3EpochSigningKeyError.sealingFailed
      }
      return try V3EpochSigningKeyCapsule(publicKey: publicKey, protectedSigningKey: combined)
    } catch {
      throw V3EpochSigningKeyError.sealingFailed
    }
  }

  /// Internal scoped access for the authority builder/validator. The closure
  /// must not retain or persist the key. Swift/CryptoKit do not give this API
  /// a guarantee of immediate memory zeroization or prevent a caller escaping it.
  func withSigningKey<Result>(
    _ capsule: V3EpochSigningKeyCapsule, context: V3EpochSigningKeyContext,
    vaultKey: Data, operation: (P256.Signing.PrivateKey) throws -> Result
  ) throws -> Result {
    let wrappingKey = try wrappingKey(context: context, vaultKey: vaultKey)
    let signingKey: P256.Signing.PrivateKey
    do {
      let raw = try AES.GCM.open(
        AES.GCM.SealedBox(combined: capsule.protectedSigningKey), using: wrappingKey,
        authenticating: context.authenticatedData(publicKey: capsule.publicKey)
      )
      guard raw.count == 32 else {
        throw V3EpochSigningKeyError.authenticationFailed
      }
      let candidate = try P256.Signing.PrivateKey(rawRepresentation: raw)
      guard candidate.publicKey.x963Representation == capsule.publicKey else {
        throw V3EpochSigningKeyError.authenticationFailed
      }
      signingKey = candidate
    } catch {
      throw V3EpochSigningKeyError.authenticationFailed
    }
    // Preserve the caller's error rather than misclassifying it as an
    // authentication failure, and never retry either crypto or the closure.
    return try operation(signingKey)
  }

  private func wrappingKey(
    context: V3EpochSigningKeyContext, vaultKey: Data
  ) throws -> SymmetricKey {
    guard vaultKey.count == 32 else { throw V3EpochSigningKeyError.invalidVaultKey }
    guard try V3VaultKeyID.derive(vaultKey: vaultKey, vaultID: context.vaultID) == context.keyID
    else {
      throw V3EpochSigningKeyError.keyIdentityMismatch
    }
    guard let salt = v3UUIDBytes(context.vaultID) else {
      throw V3EpochSigningKeyError.invalidContext
    }
    return HKDF<SHA256>.deriveKey(
      inputKeyMaterial: SymmetricKey(data: vaultKey), salt: salt,
      info: Self.keyInfo, outputByteCount: 32
    )
  }
}
