import Foundation

enum PIVPublicObjectError: Error, Equatable {
  case invalidResponse
  case unexpectedStatus
  case unavailable
  case deadlineExceeded
}

/// Strict framing for bounded PIV public-object reads, independent of transport.
/// Only the one-byte tags used by these readers are supported. Lengths must be
/// definite and minimal; duplicates, truncation and trailing bytes fail closed.
enum PIVPublicObjectCodec {
  static func fields(_ data: Data, maximumBytes: Int) throws -> [UInt8: Data] {
    guard !data.isEmpty, data.count <= maximumBytes else {
      throw PIVPublicObjectError.invalidResponse
    }
    let bytes = Array(data)
    var offset = 0
    var values: [UInt8: Data] = [:]
    while offset < bytes.count {
      let tag = bytes[offset]
      offset += 1
      guard tag & 0x1f != 0x1f, offset < bytes.count else {
        throw PIVPublicObjectError.invalidResponse
      }
      let first = bytes[offset]
      offset += 1
      var length = Int(first)
      if first & 0x80 != 0 {
        let count = Int(first & 0x7f)
        guard (1...2).contains(count), count <= bytes.count - offset,
          bytes[offset] != 0
        else { throw PIVPublicObjectError.invalidResponse }
        length = 0
        for _ in 0..<count {
          length = (length << 8) | Int(bytes[offset])
          offset += 1
        }
        guard length >= 128, count == 1 || length > 255 else {
          throw PIVPublicObjectError.invalidResponse
        }
      }
      guard length <= bytes.count - offset, values[tag] == nil else {
        throw PIVPublicObjectError.invalidResponse
      }
      values[tag] = Data(bytes[offset..<(offset + length)])
      offset += length
    }
    return values
  }

  static func object(_ response: Data, maximumBytes: Int) throws -> Data {
    guard (0...65_536).contains(maximumBytes) else {
      throw PIVPublicObjectError.invalidResponse
    }
    // A three-byte BER length is needed when the certificate container is
    // exactly 65,536 bytes. The reader deliberately supports at most two
    // length bytes, so that boundary fails closed rather than overflowing.
    let parsed = try fields(response, maximumBytes: maximumBytes + 4)
    guard parsed.count == 1, let value = parsed[0x53], value.count <= maximumBytes else {
      throw PIVPublicObjectError.invalidResponse
    }
    return value
  }

  static func certificate(_ response: Data) throws -> Data {
    let parsed = try fields(try object(response, maximumBytes: 65_536), maximumBytes: 65_536)
    guard Set(parsed.keys).isSubset(of: [0x70, 0x71, 0xfe]),
      let der = parsed[0x70], !der.isEmpty, parsed[0x71] == Data([0]),
      parsed[0xfe] == nil || parsed[0xfe] == Data()
    else {
      // No compressed-certificate fallback or decompression.
      throw PIVPublicObjectError.invalidResponse
    }
    return der
  }
}
