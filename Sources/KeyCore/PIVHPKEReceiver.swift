import CryptoKit
import Foundation

// Receiver adapter for an externally supplied P-256 key-agreement operation.
// The platform supplies agreement; CryptoKit handles the HPKE key schedule and AEAD.
// RFC 9180 section 4.1 DHKEM(P-256, HKDF-SHA256), base-mode receiver only.
enum PIVHPKEError: Error { case invalidInput, unsupportedOperation }

func pivKEMSecret(dh: Data, enc: Data, recipient: Data) throws -> SymmetricKey {
  guard dh.count == 32 else { throw PIVHPKEError.invalidInput }
  _ = try P256.KeyAgreement.PublicKey(x963Representation: enc)
  _ = try P256.KeyAgreement.PublicKey(x963Representation: recipient)
  let suiteID = Data([0x4b, 0x45, 0x4d, 0x00, 0x10])
  let prefix = Data("HPKE-v1".utf8) + suiteID
  let labeledIKM = prefix + Data("eae_prk".utf8) + dh
  let prk = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: labeledIKM), salt: Data())
  let info = Data([0x00, 0x20]) + prefix + Data("shared_secret".utf8) + enc + recipient
  return HKDF<SHA256>.expand(pseudoRandomKey: prk, info: info, outputByteCount: 32)
}

@available(macOS 26.0, *)
struct PIVHPKEPublicKey: HPKEKEMPublicKey {
  typealias EphemeralPrivateKey = PIVHPKEReceiver
  let bytes: Data

  init<D>(_ serialization: D, kem: HPKE.KEM) throws where D: ContiguousBytes {
    guard kem == .P256_HKDF_SHA256 else { throw PIVHPKEError.invalidInput }
    bytes = serialization.withUnsafeBytes { Data($0) }
    _ = try P256.KeyAgreement.PublicKey(x963Representation: bytes)
  }

  func hpkeRepresentation(kem: HPKE.KEM) throws -> Data {
    guard kem == .P256_HKDF_SHA256 else { throw PIVHPKEError.invalidInput }
    return bytes
  }

  func encapsulate() throws -> KEM.EncapsulationResult {
    // This type is deliberately receiver-only. Sending uses CryptoKit P256.
    throw PIVHPKEError.unsupportedOperation
  }
}

@available(macOS 26.0, *)
struct PIVHPKEReceiver: HPKEKEMPrivateKeyGeneration {
  let publicKey: PIVHPKEPublicKey
  let agree: @Sendable (Data) throws -> Data

  init(publicBytes: Data, agree: @escaping @Sendable (Data) throws -> Data) throws {
    publicKey = try PIVHPKEPublicKey(publicBytes, kem: .P256_HKDF_SHA256)
    self.agree = agree
  }

  init() throws { throw PIVHPKEError.unsupportedOperation }
  static func generate() throws -> PIVHPKEReceiver { throw PIVHPKEError.unsupportedOperation }

  func decapsulate(_ encapsulated: Data) throws -> SymmetricKey {
    // Validate before calling the eventual hardware boundary.
    _ = try P256.KeyAgreement.PublicKey(x963Representation: encapsulated)
    return try pivKEMSecret(dh: agree(encapsulated), enc: encapsulated, recipient: publicKey.bytes)
  }
}
