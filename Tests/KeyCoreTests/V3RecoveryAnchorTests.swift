import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

struct V3RecoveryAnchorTests {
  @Test
  func anchorHasExactCanonicalFixtureAndNoSecretFields() throws {
    let anchor = try fixture()
    let expected =
      "{\"format\":\"key-vault-piv-recovery-anchor\",\"hpkeSuite\":{\"aead\":2,\"kdf\":1,\"kem\":16,\"mode\":0},\"profile\":\"device-wrapped\",\"profileVersion\":3,\"recipientID\":\"\(anchor.recipientID.rawValue)\",\"registrationID\":\"018f4d38-7d5a-7b20-b0f1-97d6e96c44b6\",\"registrationManifestDigest\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"slot\":\"9d\",\"vaultID\":\"018f4d38-7d5a-7b20-b0f1-97d6e96c44b3\",\"version\":1}"
    #expect(anchor.canonicalBytes == Data(expected.utf8))
    #expect(anchor.canonicalBytes.count < V3RecoveryAnchor.maximumBytes)
    #expect(try V3RecoveryAnchorCodec().parseCanonical(anchor.canonicalBytes) == anchor)
  }

  @Test
  func exactFieldsVersionsSuiteIdentifiersAndEncodingAreRequired() throws {
    let value = try fixture().canonicalValue
    let fields = try #require(value.objectValue)
    var invalid: [CanonicalJSONValue] = [
      .object(fields + [("extra", .null)]), .object(Array(fields.dropFirst())),
      .object(fields + [fields[0]]),
    ]
    for (name, replacement) in [
      ("format", CanonicalJSONValue.string("other")), ("profileVersion", .integer(2)),
      ("slot", .string("9a")), ("registrationID", .string("not-a-uuid")),
      ("vaultID", .string("018F4D38-7D5A-7B20-B0F1-97D6E96C44B3")),
      ("registrationManifestDigest", .string(Base64URL.encode(Data(repeating: 0, count: 31)))),
      ("recipientID", .string("bad")),
      (
        "hpkeSuite",
        .object([
          ("mode", .integer(1)), ("kem", .integer(16)),
          ("kdf", .integer(1)), ("aead", .integer(2)),
        ])
      ),
    ] {
      invalid.append(.object(fields.map { ($0.0, $0.0 == name ? replacement : $0.1) }))
    }
    for candidate in invalid {
      #expect(throws: (any Error).self) { try V3RecoveryAnchorCodec().decode(candidate) }
    }
    let future = CanonicalJSONValue.object(
      fields.map {
        ($0.0, $0.0 == "version" ? .integer(2) : $0.1)
      })
    #expect(throws: V3RecoveryAnchorError.unsupportedVersion(2)) {
      try V3RecoveryAnchorCodec().decode(future)
    }
    let bytes = CanonicalJSON.encode(value)
    #expect(throws: V3RecoveryAnchorError.nonCanonicalEncoding) {
      try V3RecoveryAnchorCodec().parseCanonical(bytes + Data([10]))
    }
    #expect(throws: V3RecoveryAnchorError.invalidEncoding) {
      try V3RecoveryAnchorCodec().parseCanonical(Data(repeating: 0x20, count: 1_025))
    }
    for length in 0..<bytes.count {
      #expect(throws: (any Error).self) {
        try V3RecoveryAnchorCodec().parseCanonical(Data(bytes.prefix(length)))
      }
    }
  }

  private func fixture() throws -> V3RecoveryAnchor {
    let key = try P256.KeyAgreement.PrivateKey(
      rawRepresentation: Data(repeating: 0, count: 31) + Data([3]))
    return try V3RecoveryAnchor(
      floor: V3VaultHead(
        vaultID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3",
        envelopeDigest: Data(repeating: 0, count: 32)),
      recipientID: V3RecoveryRecipientID.derive(publicKey: key.publicKey.x963Representation),
      registrationID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b6", slot: .keyManagement)
  }
}
