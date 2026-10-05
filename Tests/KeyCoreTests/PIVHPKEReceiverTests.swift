import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Software-only interoperability and input-boundary checks. No token is accessed.
struct PIVHPKEReceiverTests {
  @Test
  func publishedP256VectorMatchesKEMSecretAndCiphertext() throws {
    guard #available(macOS 26.0, *) else { return }
    // Public test vector: RFC 9180 Appendix A.3.1, not a user credential.
    let key = try P256.KeyAgreement.PrivateKey(
      rawRepresentation: Self.hex(
        "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2"))
    let enc = try Self.hex(
      "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"
    )
    let receiver = try Self.receiver(key)
    let secret = try receiver.decapsulate(enc).withUnsafeBytes { Data($0) }
    #expect(
      secret
        == (try Self.hex(
          "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8")))
    var opener = try HPKE.Recipient(
      privateKey: receiver,
      ciphersuite: .init(kem: .P256_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_128),
      info: Self.hex("4f6465206f6e2061204772656369616e2055726e"),
      encapsulatedKey: enc)
    let opened = try opener.open(
      Self.hex(
        "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434"
      ),
      authenticating: Self.hex("436f756e742d30"))
    #expect(
      opened
        == (try Self.hex(
          "4265617574792069732074727574682c20747275746820626561757479")))
  }

  @Test
  func softwareSenderRoundTripsAndRejectsChangedInputs() throws {
    guard #available(macOS 26.0, *) else { return }
    for _ in 0..<16 {
      let key = P256.KeyAgreement.PrivateKey()
      let receiver = try Self.receiver(key)
      let info = Data("key/piv-receiver/software-test/v1".utf8)
      let aad = Data(UUID().uuidString.utf8)
      let message = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
      var sender = try HPKE.Sender(
        recipientKey: key.publicKey, ciphersuite: .P256_SHA256_AES_GCM_256, info: info)
      let ciphertext = try sender.seal(message, authenticating: aad)
      func open(_ receiver: PIVHPKEReceiver, info: Data, aad: Data, ciphertext: Data) throws -> Data
      {
        var opener = try HPKE.Recipient(
          privateKey: receiver, ciphersuite: .P256_SHA256_AES_GCM_256,
          info: info, encapsulatedKey: sender.encapsulatedKey)
        return try opener.open(ciphertext, authenticating: aad)
      }
      #expect(try open(receiver, info: info, aad: aad, ciphertext: ciphertext) == message)
      #expect(throws: (any Error).self) {
        try open(receiver, info: info + Data([0]), aad: aad, ciphertext: ciphertext)
      }
      #expect(throws: (any Error).self) {
        try open(receiver, info: info, aad: aad + Data([0]), ciphertext: ciphertext)
      }
      var altered = ciphertext
      altered[altered.startIndex] ^= 1
      #expect(throws: (any Error).self) {
        try open(receiver, info: info, aad: aad, ciphertext: altered)
      }
      let wrongReceiver = try Self.receiver(P256.KeyAgreement.PrivateKey())
      #expect(throws: (any Error).self) {
        try open(wrongReceiver, info: info, aad: aad, ciphertext: ciphertext)
      }
    }
  }

  @Test
  func malformedPointsNeverReachAgreementAndShortSecretsAreRejected() throws {
    guard #available(macOS 26.0, *) else { return }
    let key = P256.KeyAgreement.PrivateKey()
    let receiver = try PIVHPKEReceiver(publicBytes: key.publicKey.x963Representation) { _ in
      Issue.record("Malformed encapsulated point reached agreement")
      throw PIVHPKEError.invalidInput
    }
    for invalid in [Data(), Data([0x04]), Data([0x04]) + Data(repeating: 0, count: 64)] {
      #expect(throws: (any Error).self) { try receiver.decapsulate(invalid) }
    }
    #expect(throws: PIVHPKEError.invalidInput) {
      try pivKEMSecret(
        dh: Data(), enc: key.publicKey.x963Representation,
        recipient: key.publicKey.x963Representation)
    }
    let shortSecret = try PIVHPKEReceiver(publicBytes: key.publicKey.x963Representation) { _ in
      Data()
    }
    #expect(throws: PIVHPKEError.invalidInput) {
      try shortSecret.decapsulate(key.publicKey.x963Representation)
    }
  }

  @Test
  func receiverDoesNotGenerateKeysOrEncapsulate() throws {
    guard #available(macOS 26.0, *) else { return }
    let receiver = try Self.receiver(P256.KeyAgreement.PrivateKey())
    #expect(throws: PIVHPKEError.unsupportedOperation) { try PIVHPKEReceiver() }
    #expect(throws: PIVHPKEError.unsupportedOperation) { try PIVHPKEReceiver.generate() }
    #expect(throws: PIVHPKEError.unsupportedOperation) { try receiver.publicKey.encapsulate() }
    #expect(
      try receiver.publicKey.hpkeRepresentation(kem: .P256_HKDF_SHA256) == receiver.publicKey.bytes)
  }

  @available(macOS 26.0, *)
  private static func receiver(_ key: P256.KeyAgreement.PrivateKey) throws -> PIVHPKEReceiver {
    try PIVHPKEReceiver(publicBytes: key.publicKey.x963Representation) { bytes in
      try key.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: bytes)
      )
      .withUnsafeBytes { Data($0) }
    }
  }

  private static func hex(_ value: String) throws -> Data {
    let bytes = Array(value.utf8)
    #expect(bytes.count.isMultiple(of: 2))
    var result = Data()
    for index in stride(from: 0, to: bytes.count, by: 2) {
      let pair = String(decoding: bytes[index..<(index + 2)], as: UTF8.self)
      result.append(try #require(UInt8(pair, radix: 16)))
    }
    return result
  }
}
