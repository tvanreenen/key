import Foundation

let v3MaximumSafeInteger: UInt64 = 9_007_199_254_740_991

func isValidV3UUID(_ value: String) -> Bool {
    let bytes = Array(value.utf8)
    guard bytes.count == 36,
          bytes.enumerated().allSatisfy({ index, byte in
              if [8, 13, 18, 23].contains(index) {
                  return byte == UInt8(ascii: "-")
              }
              return (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
                  || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "f"))
          })
    else {
        return false
    }
    return UUID(uuidString: value) != nil
}

func isValidV3EntryName(_ name: String) -> Bool {
    let utf8 = Data(name.utf8)
    let segments = name.split(separator: "/", omittingEmptySubsequences: false)
    return !name.isEmpty
        && name.unicodeScalars.count <= 1_024
        && utf8.count <= 1_024
        && utf8 == Data(name.precomposedStringWithCanonicalMapping.utf8)
        && name.first != "/"
        && name.last != "/"
        && !name.contains("\\")
        && !name.unicodeScalars.contains(where: isV3ControlCharacter)
        && !hasLeadingOrTrailingWhitespace(name)
        && segments.allSatisfy({
            !$0.isEmpty && $0 != "." && $0 != ".." && $0.utf8.count <= 255
        })
}

func isV3ControlCharacter(_ scalar: UnicodeScalar) -> Bool {
    scalar.value <= 0x1F || (0x7F...0x9F).contains(scalar.value)
}

private func hasLeadingOrTrailingWhitespace(_ value: String) -> Bool {
    guard let first = value.unicodeScalars.first,
          let last = value.unicodeScalars.last
    else {
        return false
    }
    return CharacterSet.whitespacesAndNewlines.contains(first)
        || CharacterSet.whitespacesAndNewlines.contains(last)
}
