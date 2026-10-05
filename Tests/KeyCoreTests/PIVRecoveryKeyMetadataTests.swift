import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct PIVRecoveryKeyMetadataTests {
  @Test func exactP256MetadataParsesWithoutAuthentication() throws {
    let point = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
    let encoded = Self.encode(point: point)
    let metadata = try PIVRecoveryKeyMetadataCodec.parse(encoded)
    #expect(metadata.publicKey == point && metadata.pinPolicy == .always)
    #expect(metadata.touchPolicy == .always && metadata.origin == .generated)
    try metadata.requireRecoveryPolicy()
    // These flat TLVs have no GET DATA's 0x53 outer container.
    #expect(encoded.prefix(3) == Data([1, 1, 0x11]))
  }

  @Test func allRecognizedPoliciesParseButOnlyExplicitAlwaysAndGeneratedAreSupported() throws {
    let point = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
    for pin: UInt8 in 0...5 {
      for touch: UInt8 in 0...3 {
        for origin: UInt8 in 1...2 {
          let metadata = try PIVRecoveryKeyMetadataCodec.parse(
            Self.encode(point: point, pin: pin, touch: touch, origin: origin))
          if pin == 3 && touch == 2 && origin == 1 {
            try metadata.requireRecoveryPolicy()
          } else {
            #expect(throws: PIVRecoveryKeyPolicyError.unsupportedPolicy) {
              try metadata.requireRecoveryPolicy()
            }
          }
        }
      }
    }
  }

  @Test func missingExtraDuplicateAndIncorrectLengthFieldsAreRefused() {
    let point = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
    let values = [Data([0x11]), Data([3, 2]), Data([1]), Self.tlv(0x86, point)]
    for index in values.indices {
      for replacement: Data? in [nil, Data(), values[index] + Data([0])] {
        var encoded = Data()
        for field in values.indices {
          if field == index {
            if let replacement { encoded += Self.tlv(UInt8(field + 1), replacement) }
          } else {
            encoded += Self.tlv(UInt8(field + 1), values[field])
          }
        }
        Self.refused(encoded)
      }
    }
    let valid = Self.encode(point: point)
    Self.refused(valid + Self.tlv(5, Data([0])))
    Self.refused(valid + Self.tlv(1, Data([0x11])))
    Self.refused(Self.tlv(0x53, valid))
  }

  @Test func unsupportedAlgorithmsValuesAndPublicPointsAreRefused() {
    let point = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
    for algorithm: UInt8 in [0, 3, 0x07, 0x14, 0x22] {
      Self.refused(Self.encode(point: point, algorithm: algorithm))
    }
    Self.refused(Self.encode(point: point, pin: 6))
    Self.refused(Self.encode(point: point, touch: 4))
    Self.refused(Self.encode(point: point, origin: 0))
    Self.refused(Self.encode(point: point, origin: 3))
    for invalid in [
      Data(), Data([4]), Data(repeating: 0, count: 65), Data(repeating: 4, count: 66),
    ] {
      Self.refused(Self.encode(point: invalid))
    }
  }

  @Test func framingTruncationNonminimalLengthsAndOversizeAreRefused() {
    let valid = Self.encode(point: P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
    for size in 0..<valid.count { Self.refused(Data(valid.prefix(size))) }
    Self.refused(Data([1, 0x81, 1, 0x11]) + valid.dropFirst(3))
    Self.refused(valid + Data([0]))
    Self.refused(Data(repeating: 0, count: PIVRecoveryKeyMetadataCodec.maximumBytes + 1))
  }

  private static func refused(_ bytes: Data) {
    #expect(throws: PIVRecoveryKeyPolicyError.invalidMetadata) {
      try PIVRecoveryKeyMetadataCodec.parse(bytes)
    }
  }
  private static func encode(
    point: Data, algorithm: UInt8 = 0x11, pin: UInt8 = 3, touch: UInt8 = 2, origin: UInt8 = 1
  ) -> Data {
    tlv(1, Data([algorithm])) + tlv(2, Data([pin, touch])) + tlv(3, Data([origin]))
      + tlv(4, tlv(0x86, point))
  }
  private static func tlv(_ tag: UInt8, _ value: Data) -> Data {
    Data([tag, UInt8(value.count)]) + value
  }
}
