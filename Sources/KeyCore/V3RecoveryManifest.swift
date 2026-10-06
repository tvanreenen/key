import CryptoKit
import Foundation
internal import JSONCanonicalization

enum V3RecoveryManifestError: Error, Equatable {
  case invalidEncoding
  case nonCanonicalEncoding
  case invalidStructure
  case unsupportedProfileVersion(UInt64)
  case resourceLimit
  case invalidBoundary
  case invalidDeviceAuthorization
  case invalidEpochAuthorization
  case invalidVaultKey
  case authenticationFailed
}

/// An immutable epoch-root proof. Later same-epoch edits preserve these bytes;
/// their parent list is not the parent to which this inherited proof refers.
struct V3RecoveryEpochTransitionProof: Equatable, Sendable {
  static let version: UInt64 = 1
  let parentEnvelopeDigest: Data
  let signature: Data

  init(parentEnvelopeDigest: Data, signature: Data) throws {
    guard parentEnvelopeDigest.count == 32, V3P256Signature.isCanonical(signature) else {
      throw V3RecoveryManifestError.invalidStructure
    }
    self.parentEnvelopeDigest = parentEnvelopeDigest
    self.signature = signature
  }

  var unsignedValue: CanonicalJSONValue {
    .object([
      ("version", .integer(Self.version)),
      ("algorithm", .string(V3EpochSigningKeyCapsule.signingAlgorithm)),
      ("parentEnvelopeDigest", .string(Base64URL.encode(parentEnvelopeDigest))),
    ])
  }

  var canonicalValue: CanonicalJSONValue {
    // The projection below removes only this named signature member.
    guard let fields = unsignedValue.objectValue else { preconditionFailure() }
    return .object(fields + [("signature", .string(Base64URL.encode(signature)))])
  }
}

/// Experimental profile 3, separate from shipping profile 2 and all trusted
/// checkpoint types. A nil proof denotes an origin requiring independent local
/// validation/anchoring, not an unauthenticated transition accepted by recovery.
struct V3RecoveryManifestBody: Equatable, Sendable {
  static let profileVersion: UInt64 = 3
  let fields: V3DeviceWrappedManifestFields
  let epochSigningKey: V3EpochSigningKeyCapsule
  let transitionProof: V3RecoveryEpochTransitionProof?
  let recovery: V3RecoveryRoster

  init(
    fields: V3DeviceWrappedManifestFields, epochSigningKey: V3EpochSigningKeyCapsule,
    transitionProof: V3RecoveryEpochTransitionProof?, recovery: V3RecoveryRoster
  ) throws {
    let devicePoints = Set(
      fields.devices.flatMap {
        [$0.identity.signingPublicKey, $0.identity.wrappingPublicKey]
      })
    guard !devicePoints.contains(epochSigningKey.publicKey),
      recovery.recipients.allSatisfy({
        !devicePoints.contains($0.publicKey) && $0.publicKey != epochSigningKey.publicKey
      })
    else { throw V3RecoveryManifestError.invalidStructure }
    self.fields = fields
    self.epochSigningKey = epochSigningKey
    self.transitionProof = transitionProof
    self.recovery = recovery
  }

  func deviceContext(recipientDeviceID: String) throws -> V3VaultKeyHPKEContext {
    try V3VaultKeyHPKEContext(
      vaultID: fields.vaultID, keyID: fields.keyID,
      authorityTransitionID: fields.authorityTransitionID, recipientDeviceID: recipientDeviceID,
      wrappingProfile: .recovery)
  }

  var canonicalValue: CanonicalJSONValue {
    canonicalValue(proof: transitionProof?.canonicalValue ?? .null)
  }

  var canonicalBytes: Data { CanonicalJSON.encode(canonicalValue) }

  // One construction path for finalized bodies and exact unsigned projections.
  func canonicalValue(proof: CanonicalJSONValue) -> CanonicalJSONValue {
    .object(
      [
        ("format", .string(V3DeviceWrappedManifestBody.format)),
        ("version", .integer(V3DeviceWrappedManifestBody.version)),
        ("profile", .string(V3DeviceWrappedManifestBody.profile)),
        ("profileVersion", .integer(Self.profileVersion)),
        (
          "epochAuthority",
          .object([
            ("version", .integer(1)), ("capsule", epochSigningKey.canonicalValue),
            ("transitionProof", proof),
          ])
        ),
        ("recovery", recovery.canonicalValue),
      ] + fields.canonicalMembers)
  }
}

/// Explicit domain dispatch only. Shipping services still call their profile-2
/// codec, which rejects 3. No live observer, adoption, or restore is enabled.
enum V3DeviceWrappedManifestProfile: Equatable, Sendable {
  case permanent(V3DeviceWrappedManifestBody)
  case recovery(V3RecoveryManifestBody)
}

struct V3RecoveryManifestCodec: Sendable {
  static let maximumBytes = V3ManifestRepositoryLimits.standard.maximumManifestBytes

  func parseCanonicalBody(_ data: Data) throws -> V3DeviceWrappedManifestProfile {
    try decodeBody(parseCanonical(data))
  }

  func decodeBody(_ value: CanonicalJSONValue) throws -> V3DeviceWrappedManifestProfile {
    guard let fields = value.objectValue,
      fields.first(where: { $0.0 == "format" })?.1.stringValue
        == V3DeviceWrappedManifestBody.format,
      fields.first(where: { $0.0 == "version" })?.1.integerValue == 3,
      fields.first(where: { $0.0 == "profile" })?.1.stringValue == "device-wrapped",
      let version = fields.first(where: { $0.0 == "profileVersion" })?.1.integerValue
    else { throw V3RecoveryManifestError.invalidStructure }
    switch version {
    case 2:
      return .permanent(try V3DeviceWrappedManifestCodec().decodeBody(value))
    case 3:
      let root = try object(
        value,
        names: [
          "format", "version", "profile", "profileVersion", "vaultID", "keyID",
          "authorityTransitionID", "hpkeSuite", "devices", "wrappedKeys", "entries",
          "epochAuthority", "recovery",
        ])
      let authority = try object(
        member("epochAuthority", in: root),
        names: [
          "version", "capsule", "transitionProof",
        ])
      guard authority["version"]?.integerValue == 1 else {
        throw V3RecoveryManifestError.invalidStructure
      }
      let proofValue = try member("transitionProof", in: authority)
      let proof: V3RecoveryEpochTransitionProof?
      if case .null = proofValue {
        proof = nil
      } else {
        let record = try object(
          proofValue,
          names: [
            "version", "algorithm", "parentEnvelopeDigest", "signature",
          ])
        guard record["version"]?.integerValue == V3RecoveryEpochTransitionProof.version,
          record["algorithm"]?.stringValue == V3EpochSigningKeyCapsule.signingAlgorithm
        else { throw V3RecoveryManifestError.invalidStructure }
        proof = try V3RecoveryEpochTransitionProof(
          parentEnvelopeDigest: data("parentEnvelopeDigest", in: record, count: 32),
          signature: data("signature", in: record, count: 64))
      }
      return .recovery(
        try V3RecoveryManifestBody(
          fields: V3DeviceWrappedManifestCodec().decodeFields(in: fields, path: "$"),
          epochSigningKey: V3EpochSigningKeyCapsuleCodec().decode(member("capsule", in: authority)),
          transitionProof: proof,
          recovery: V3RecoveryRosterCodec().decode(member("recovery", in: root))))
    default:
      throw V3RecoveryManifestError.unsupportedProfileVersion(version)
    }
  }

  func parseEnvelope(_ data: Data) throws -> V3RecoveryManifestEnvelope {
    guard data.count <= Self.maximumBytes else { throw V3RecoveryManifestError.resourceLimit }
    let container = try V3DeviceWrappedManifestEnvelopeCodec().parseContainer(data)
    guard case .recovery(let body) = try decodeBody(container.manifestValue) else {
      throw V3RecoveryManifestError.unsupportedProfileVersion(2)
    }
    return V3RecoveryManifestEnvelope(
      parents: container.metadata.parents, body: body,
      authenticationTag: container.authenticationTag,
      authorizations: container.metadata.authorizations,
      canonicalBytes: data, canonicalContentBytes: container.metadata.canonicalContentBytes)
  }

  private func parseCanonical(_ data: Data) throws -> CanonicalJSONValue {
    guard data.count <= Self.maximumBytes else { throw V3RecoveryManifestError.resourceLimit }
    let value: CanonicalJSONValue
    do { value = try CanonicalJSON.parse(data) } catch {
      throw V3RecoveryManifestError.invalidEncoding
    }
    guard CanonicalJSON.encode(value) == data else {
      throw V3RecoveryManifestError.nonCanonicalEncoding
    }
    return value
  }

  private func object(_ value: CanonicalJSONValue, names: Set<String>) throws -> [String:
    CanonicalJSONValue]
  {
    guard let fields = value.objectValue, fields.count == names.count,
      Set(fields.map(\.0)) == names
    else { throw V3RecoveryManifestError.invalidStructure }
    return Dictionary(uniqueKeysWithValues: fields)
  }

  private func member(_ name: String, in fields: [String: CanonicalJSONValue]) throws
    -> CanonicalJSONValue
  {
    guard let value = fields[name] else { throw V3RecoveryManifestError.invalidStructure }
    return value
  }

  private func data(_ name: String, in fields: [String: CanonicalJSONValue], count: Int) throws
    -> Data
  {
    guard let encoded = fields[name]?.stringValue, encoded.utf8.count == (count * 8 + 5) / 6,
      let decoded = Base64URL.decodeCanonical(encoded), decoded.count == count
    else { throw V3RecoveryManifestError.invalidStructure }
    return decoded
  }
}

/// Parsed bytes only. In particular, public boundary validation must never be
/// promoted to an ordinary MAC-verified checkpoint or restorable snapshot.
struct V3RecoveryManifestEnvelope: Equatable, Sendable {
  let parents: [Data]
  let body: V3RecoveryManifestBody
  let authenticationTag: Data
  let authorizations: [V3ManifestAuthorization]
  let canonicalBytes: Data
  let canonicalContentBytes: Data

  var digest: Data { Data(SHA256.hash(data: canonicalBytes)) }
}
