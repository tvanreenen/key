import CryptoKit
import Foundation

enum PIVRecoveryKeyPolicyError: Error, Equatable {
  case invalidMetadata
  case unsupportedPolicy
  case publicKeyMismatch
}

/// Reported public slot metadata, not attestation, possession or proof that a
/// provider actually requested the required PIN/touch in a particular run.
struct PIVRecoveryKeyMetadata: Equatable, Sendable {
  enum PINPolicy: UInt8, Sendable {
    case `default` = 0
    case never = 1
    case once = 2
    case always = 3
    case matchOnce = 4
    case matchAlways = 5
  }
  enum TouchPolicy: UInt8, Sendable {
    case `default` = 0
    case never = 1
    case always = 2
    case cached = 3
  }
  enum Origin: UInt8, Sendable {
    case generated = 1
    case imported = 2
  }
  let publicKey: Data
  let pinPolicy: PINPolicy
  let touchPolicy: TouchPolicy
  let origin: Origin

  func requireRecoveryPolicy() throws {
    guard pinPolicy == .always, touchPolicy == .always, origin == .generated else {
      throw PIVRecoveryKeyPolicyError.unsupportedPolicy
    }
  }
}

/// Yubico GET METADATA slot 9d response (firmware 5.3+). This deliberately
/// accepts only the four documented P-256 key fields and exact value lengths.
/// It does not infer missing policies or substitute certificate-only identity.
enum PIVRecoveryKeyMetadataCodec {
  static let maximumBytes = 256

  static func parse(_ response: Data) throws -> PIVRecoveryKeyMetadata {
    do {
      let fields = try PIVPublicObjectCodec.fields(response, maximumBytes: maximumBytes)
      guard Set(fields.keys) == [1, 2, 3, 4], fields[1] == Data([0x11]),
        let policies = fields[2], policies.count == 2,
        let pin = PIVRecoveryKeyMetadata.PINPolicy(rawValue: policies[policies.startIndex]),
        let touch = PIVRecoveryKeyMetadata.TouchPolicy(rawValue: policies[policies.startIndex + 1]),
        let originBytes = fields[3], originBytes.count == 1,
        let origin = PIVRecoveryKeyMetadata.Origin(rawValue: originBytes[originBytes.startIndex]),
        let encodedKey = fields[4]
      else { throw PIVRecoveryKeyPolicyError.invalidMetadata }
      let key = try PIVPublicObjectCodec.fields(encodedKey, maximumBytes: maximumBytes)
      guard Set(key.keys) == [0x86], let point = key[0x86], point.count == 65 else {
        throw PIVRecoveryKeyPolicyError.invalidMetadata
      }
      _ = try P256.KeyAgreement.PublicKey(x963Representation: point)
      return PIVRecoveryKeyMetadata(
        publicKey: point, pinPolicy: pin, touchPolicy: touch, origin: origin)
    } catch {
      throw PIVRecoveryKeyPolicyError.invalidMetadata
    }
  }
}
