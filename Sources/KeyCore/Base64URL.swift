import Foundation

enum Base64URL {
    static func encode(_ data: Data) -> String {
        // macOS 26.4 adds .base64URLAlphabet and .omitPaddingCharacter.
        // Keep this portable path while the package supports macOS 13.
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func decodeCanonical(_ value: String) -> Data? {
        guard value.utf8.allSatisfy(isAlphabetByte) else {
            return nil
        }

        var standard = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        standard += String(repeating: "=", count: (4 - standard.count % 4) % 4)

        guard let decoded = Data(base64Encoded: standard),
              encode(decoded) == value
        else {
            return nil
        }
        return decoded
    }

    private static func isAlphabetByte(_ byte: UInt8) -> Bool {
        (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z"))
            || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z"))
            || (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
            || byte == UInt8(ascii: "-")
            || byte == UInt8(ascii: "_")
    }
}
