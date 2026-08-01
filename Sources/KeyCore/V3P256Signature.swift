import Foundation

enum V3P256SignatureError: Error, Equatable {
    case invalidRawRepresentation
}

/// Shared canonical encoding rules for P-256 ECDSA signatures stored by v3.
///
/// ECDSA admits both `s` and `n - s` for the same signature. Requiring the
/// lower representative gives manifests and enrollment messages one stable
/// 64-byte `r || s` representation.
enum V3P256Signature {
    private static let order: [UInt8] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
        0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
    ]

    private static let halfOrder: [UInt8] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00,
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42,
        0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
    ]

    static func canonicalize(_ rawRepresentation: Data) throws -> Data {
        guard rawRepresentation.count == 64 else {
            throw V3P256SignatureError.invalidRawRepresentation
        }

        var result = Array(rawRepresentation)
        let s = Array(result[32..<64])
        if !isLowScalar(s) {
            var normalized = [UInt8](repeating: 0, count: 32)
            var borrow = 0
            for index in stride(from: 31, through: 0, by: -1) {
                let difference = Int(order[index]) - Int(s[index]) - borrow
                if difference < 0 {
                    normalized[index] = UInt8(difference + 256)
                    borrow = 1
                } else {
                    normalized[index] = UInt8(difference)
                    borrow = 0
                }
            }
            result.replaceSubrange(32..<64, with: normalized)
        }
        return Data(result)
    }

    static func isCanonical(_ rawRepresentation: Data) -> Bool {
        rawRepresentation.count == 64
            && isLowScalar(Array(rawRepresentation.suffix(32)))
    }

    private static func isLowScalar(_ scalar: [UInt8]) -> Bool {
        guard scalar.count == 32 else {
            return false
        }
        return scalar == halfOrder || scalar.lexicographicallyPrecedes(halfOrder)
    }
}
