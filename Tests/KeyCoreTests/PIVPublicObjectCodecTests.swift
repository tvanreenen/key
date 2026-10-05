import Foundation
import Testing

@testable import KeyCore

struct PIVPublicObjectCodecTests {
  @Test
  func framingBoundsAndEveryTruncatedPrefixFailClosed() throws {
    let wrapped = Self.tlv(0x53, Data(repeating: 0x42, count: 1_024))
    for count in 0..<wrapped.count {
      #expect(throws: PIVPublicObjectError.invalidResponse) {
        try PIVPublicObjectCodec.object(Data(wrapped.prefix(count)), maximumBytes: 1_024)
      }
    }
    #expect(try PIVPublicObjectCodec.object(wrapped, maximumBytes: 1_024).count == 1_024)
    for maximumBytes in [-1, Int.max] {
      #expect(throws: PIVPublicObjectError.invalidResponse) {
        try PIVPublicObjectCodec.object(wrapped, maximumBytes: maximumBytes)
      }
    }
    #expect(throws: PIVPublicObjectError.invalidResponse) {
      try PIVPublicObjectCodec.object(
        Self.tlv(0x53, Data(repeating: 0, count: 1_025)), maximumBytes: 1_024)
    }
  }

  @Test
  func duplicateTagsAndNonminimalOrUnsupportedLengthsAreRejected() {
    let invalid: [Data] = [
      Data(), Data([0x53]), Data([0x53, 0x80]), Data([0x53, 0x81, 0]),
      Data([0x53, 0x81, 1, 0]), Data([0x53, 0x82, 0, 0x80]),
      Data([0x53, 0x82, 1]), Data([0x53, 0x83, 1, 0, 0]),
      Data([0x1f, 0]), Data([0x53, 0, 0x53, 0]), Data([0x53, 0, 0]),
    ]
    for input in invalid {
      #expect(throws: PIVPublicObjectError.invalidResponse) {
        try PIVPublicObjectCodec.fields(input, maximumBytes: 65_536)
      }
    }
    for input in [Self.tlv(0x70, Data()), Self.tlv(0x53, Data()) + Self.tlv(0x70, Data())] {
      #expect(throws: PIVPublicObjectError.invalidResponse) {
        try PIVPublicObjectCodec.object(input, maximumBytes: 1_024)
      }
    }
  }

  @Test
  func supportedLengthBoundariesRoundTrip() throws {
    for count in [0, 1, 127, 128, 255, 256, 65_535] {
      let value = Data(repeating: 0x42, count: count)
      #expect(try PIVPublicObjectCodec.object(Self.tlv(0x53, value), maximumBytes: 65_536) == value)
    }
    #expect(throws: PIVPublicObjectError.invalidResponse) {
      try PIVPublicObjectCodec.object(Data([0x53, 0x83, 1, 0, 0]), maximumBytes: 65_536)
    }
  }

  @Test
  func certificateContainerRequiresUncompressedNonemptyBytesAndExactFields() throws {
    // Tests framing only, not DER parsing or certificate trust.
    let bytes = Data([1, 2, 3])
    let fields = Self.tlv(0x70, bytes) + Self.tlv(0x71, Data([0]))
    for input in [fields, fields + Self.tlv(0xfe, Data())] {
      #expect(try PIVPublicObjectCodec.certificate(Self.tlv(0x53, input)) == bytes)
    }
    for input in [
      Self.tlv(0x70, bytes),
      Self.tlv(0x70, Data()) + Self.tlv(0x71, Data([0])),
      Self.tlv(0x70, bytes) + Self.tlv(0x71, Data([1])),
      fields + Self.tlv(0xfe, Data([0])),
      fields + Self.tlv(0x72, Data()), fields + Self.tlv(0x70, bytes),
    ] {
      #expect(throws: PIVPublicObjectError.invalidResponse) {
        try PIVPublicObjectCodec.certificate(Self.tlv(0x53, input))
      }
    }
  }

  private static func tlv(_ tag: UInt8, _ value: Data) -> Data {
    let length: Data
    if value.count < 128 {
      length = Data([UInt8(value.count)])
    } else if value.count <= 255 {
      length = Data([0x81, UInt8(value.count)])
    } else {
      length = Data([0x82, UInt8(value.count >> 8), UInt8(value.count & 0xff)])
    }
    return Data([tag]) + length + value
  }
}
