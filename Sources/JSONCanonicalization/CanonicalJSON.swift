import Foundation

package enum CanonicalJSONError: Error, Equatable {
    case invalidEncoding
    case invalidJSON
    case duplicateProperty
}

package enum CanonicalJSONValue {
    case null
    case bool(Bool)
    case integer(UInt64)
    case string(String)
    case array([CanonicalJSONValue])
    case object([(String, CanonicalJSONValue)])

    package var objectValue: [(String, CanonicalJSONValue)]? {
        guard case let .object(value) = self else {
            return nil
        }
        return value
    }

    package var arrayValue: [CanonicalJSONValue]? {
        guard case let .array(value) = self else {
            return nil
        }
        return value
    }

    package var stringValue: String? {
        guard case let .string(value) = self else {
            return nil
        }
        return value
    }

    package var integerValue: UInt64? {
        guard case let .integer(value) = self else {
            return nil
        }
        return value
    }
}

package enum CanonicalJSON {
    private static let maximumNestingDepth = 32

    package static func parse(_ data: Data) throws -> CanonicalJSONValue {
        guard !data.starts(with: [0xEF, 0xBB, 0xBF]) else {
            throw CanonicalJSONError.invalidEncoding
        }
        var parser = Parser(bytes: Array(data), maximumNestingDepth: maximumNestingDepth)
        return try parser.parseDocument()
    }

    package static func encode(_ value: CanonicalJSONValue) -> Data {
        var bytes: [UInt8] = []
        append(value, to: &bytes)
        return Data(bytes)
    }

    package static func canonicalize(_ data: Data) throws -> Data {
        encode(try parse(data))
    }

    private static func append(_ value: CanonicalJSONValue, to bytes: inout [UInt8]) {
        switch value {
        case .null:
            bytes.append(contentsOf: "null".utf8)
        case let .bool(value):
            bytes.append(contentsOf: value ? "true".utf8 : "false".utf8)
        case let .integer(value):
            bytes.append(contentsOf: String(value).utf8)
        case let .string(value):
            appendString(value, to: &bytes)
        case let .array(values):
            bytes.append(ascii: "[")
            for (index, element) in values.enumerated() {
                if index > 0 {
                    bytes.append(ascii: ",")
                }
                append(element, to: &bytes)
            }
            bytes.append(ascii: "]")
        case let .object(members):
            bytes.append(ascii: "{")
            let sorted = members.sorted { lhs, rhs in
                Array(lhs.0.utf16).lexicographicallyPrecedes(Array(rhs.0.utf16))
            }
            for (index, member) in sorted.enumerated() {
                if index > 0 {
                    bytes.append(ascii: ",")
                }
                appendString(member.0, to: &bytes)
                bytes.append(ascii: ":")
                append(member.1, to: &bytes)
            }
            bytes.append(ascii: "}")
        }
    }

    private static func appendString(_ value: String, to bytes: inout [UInt8]) {
        bytes.append(ascii: "\"")
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x08:
                bytes.append(contentsOf: "\\b".utf8)
            case 0x09:
                bytes.append(contentsOf: "\\t".utf8)
            case 0x0A:
                bytes.append(contentsOf: "\\n".utf8)
            case 0x0C:
                bytes.append(contentsOf: "\\f".utf8)
            case 0x0D:
                bytes.append(contentsOf: "\\r".utf8)
            case 0x22:
                bytes.append(contentsOf: "\\\"".utf8)
            case 0x5C:
                bytes.append(contentsOf: "\\\\".utf8)
            case 0x00...0x1F:
                bytes.append(contentsOf: String(format: "\\u%04x", scalar.value).utf8)
            default:
                bytes.append(contentsOf: String(scalar).utf8)
            }
        }
        bytes.append(ascii: "\"")
    }
}

private struct Parser {
    let bytes: [UInt8]
    let maximumNestingDepth: Int
    var index = 0

    mutating func parseDocument() throws -> CanonicalJSONValue {
        skipWhitespace()
        let value = try parseValue(containerDepth: 0)
        skipWhitespace()
        guard index == bytes.count else {
            throw CanonicalJSONError.invalidJSON
        }
        return value
    }

    private mutating func parseValue(containerDepth: Int) throws -> CanonicalJSONValue {
        guard let byte = current else {
            throw CanonicalJSONError.invalidJSON
        }

        switch byte {
        case CharacterByte.leftBrace:
            guard containerDepth < maximumNestingDepth else {
                throw CanonicalJSONError.invalidJSON
            }
            return try parseObject(containerDepth: containerDepth + 1)
        case CharacterByte.leftBracket:
            guard containerDepth < maximumNestingDepth else {
                throw CanonicalJSONError.invalidJSON
            }
            return try parseArray(containerDepth: containerDepth + 1)
        case CharacterByte.quote:
            return .string(try parseString())
        case CharacterByte.zero...CharacterByte.nine:
            return .integer(try parseInteger())
        case CharacterByte.t:
            try consume("true")
            return .bool(true)
        case CharacterByte.f:
            try consume("false")
            return .bool(false)
        case CharacterByte.n:
            try consume("null")
            return .null
        default:
            throw CanonicalJSONError.invalidJSON
        }
    }

    private mutating func parseObject(containerDepth: Int) throws -> CanonicalJSONValue {
        index += 1
        skipWhitespace()

        var members: [(String, CanonicalJSONValue)] = []
        var encodedNames = Set<Data>()
        if consumeIf(CharacterByte.rightBrace) {
            return .object(members)
        }

        while true {
            guard current == CharacterByte.quote else {
                throw CanonicalJSONError.invalidJSON
            }
            let name = try parseString()
            guard encodedNames.insert(Data(name.utf8)).inserted else {
                throw CanonicalJSONError.duplicateProperty
            }

            skipWhitespace()
            guard consumeIf(CharacterByte.colon) else {
                throw CanonicalJSONError.invalidJSON
            }
            skipWhitespace()
            members.append((name, try parseValue(containerDepth: containerDepth)))
            skipWhitespace()

            if consumeIf(CharacterByte.rightBrace) {
                return .object(members)
            }
            guard consumeIf(CharacterByte.comma) else {
                throw CanonicalJSONError.invalidJSON
            }
            skipWhitespace()
        }
    }

    private mutating func parseArray(containerDepth: Int) throws -> CanonicalJSONValue {
        index += 1
        skipWhitespace()

        var values: [CanonicalJSONValue] = []
        if consumeIf(CharacterByte.rightBracket) {
            return .array(values)
        }

        while true {
            values.append(try parseValue(containerDepth: containerDepth))
            skipWhitespace()
            if consumeIf(CharacterByte.rightBracket) {
                return .array(values)
            }
            guard consumeIf(CharacterByte.comma) else {
                throw CanonicalJSONError.invalidJSON
            }
            skipWhitespace()
        }
    }

    private mutating func parseString() throws -> String {
        guard consumeIf(CharacterByte.quote) else {
            throw CanonicalJSONError.invalidJSON
        }

        var decoded: [UInt8] = []
        while let byte = current {
            switch byte {
            case CharacterByte.quote:
                index += 1
                guard let value = String(data: Data(decoded), encoding: .utf8) else {
                    throw CanonicalJSONError.invalidEncoding
                }
                return value
            case CharacterByte.backslash:
                index += 1
                try appendEscape(to: &decoded)
            case 0x00...0x1F:
                throw CanonicalJSONError.invalidJSON
            default:
                decoded.append(byte)
                index += 1
            }
        }
        throw CanonicalJSONError.invalidJSON
    }

    private mutating func appendEscape(to decoded: inout [UInt8]) throws {
        guard let escape = current else {
            throw CanonicalJSONError.invalidJSON
        }
        index += 1

        switch escape {
        case CharacterByte.quote:
            decoded.append(CharacterByte.quote)
        case CharacterByte.backslash:
            decoded.append(CharacterByte.backslash)
        case CharacterByte.slash:
            decoded.append(CharacterByte.slash)
        case CharacterByte.b:
            decoded.append(0x08)
        case CharacterByte.f:
            decoded.append(0x0C)
        case CharacterByte.n:
            decoded.append(0x0A)
        case CharacterByte.r:
            decoded.append(0x0D)
        case CharacterByte.t:
            decoded.append(0x09)
        case CharacterByte.u:
            let first = try parseHexQuad()
            let scalarValue: UInt32
            if (0xD800...0xDBFF).contains(first) {
                guard consumeIf(CharacterByte.backslash), consumeIf(CharacterByte.u) else {
                    throw CanonicalJSONError.invalidJSON
                }
                let second = try parseHexQuad()
                guard (0xDC00...0xDFFF).contains(second) else {
                    throw CanonicalJSONError.invalidJSON
                }
                scalarValue = 0x10000
                    + (UInt32(first - 0xD800) << 10)
                    + UInt32(second - 0xDC00)
            } else {
                guard !(0xDC00...0xDFFF).contains(first) else {
                    throw CanonicalJSONError.invalidJSON
                }
                scalarValue = UInt32(first)
            }
            guard let scalar = UnicodeScalar(scalarValue) else {
                throw CanonicalJSONError.invalidJSON
            }
            decoded.append(contentsOf: String(scalar).utf8)
        default:
            throw CanonicalJSONError.invalidJSON
        }
    }

    private mutating func parseHexQuad() throws -> UInt16 {
        guard index + 4 <= bytes.count else {
            throw CanonicalJSONError.invalidJSON
        }
        var value: UInt16 = 0
        for _ in 0..<4 {
            guard let digit = hexValue(bytes[index]) else {
                throw CanonicalJSONError.invalidJSON
            }
            value = value * 16 + UInt16(digit)
            index += 1
        }
        return value
    }

    private mutating func parseInteger() throws -> UInt64 {
        let start = index
        if current == CharacterByte.zero {
            index += 1
            if let next = current, (CharacterByte.zero...CharacterByte.nine).contains(next) {
                throw CanonicalJSONError.invalidJSON
            }
        } else {
            while let byte = current, (CharacterByte.zero...CharacterByte.nine).contains(byte) {
                index += 1
            }
        }

        if let next = current, next == CharacterByte.period || next == CharacterByte.e || next == CharacterByte.upperE {
            throw CanonicalJSONError.invalidJSON
        }
        guard let text = String(bytes: bytes[start..<index], encoding: .utf8),
              let value = UInt64(text),
              value <= 9_007_199_254_740_991
        else {
            throw CanonicalJSONError.invalidJSON
        }
        return value
    }

    private mutating func consume(_ literal: StaticString) throws {
        let expected = Array("\(literal)".utf8)
        guard bytes[index...].starts(with: expected) else {
            throw CanonicalJSONError.invalidJSON
        }
        index += expected.count
    }

    private mutating func skipWhitespace() {
        while let byte = current, byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D {
            index += 1
        }
    }

    private mutating func consumeIf(_ byte: UInt8) -> Bool {
        guard current == byte else {
            return false
        }
        index += 1
        return true
    }

    private var current: UInt8? {
        index < bytes.count ? bytes[index] : nil
    }

    private func hexValue(_ byte: UInt8) -> UInt8? {
        switch byte {
        case CharacterByte.zero...CharacterByte.nine:
            byte - CharacterByte.zero
        case CharacterByte.upperA...CharacterByte.upperF:
            byte - CharacterByte.upperA + 10
        case CharacterByte.lowerA...CharacterByte.lowerF:
            byte - CharacterByte.lowerA + 10
        default:
            nil
        }
    }
}

private enum CharacterByte {
    static let quote = UInt8(ascii: "\"")
    static let backslash = UInt8(ascii: "\\")
    static let slash = UInt8(ascii: "/")
    static let leftBrace = UInt8(ascii: "{")
    static let rightBrace = UInt8(ascii: "}")
    static let leftBracket = UInt8(ascii: "[")
    static let rightBracket = UInt8(ascii: "]")
    static let colon = UInt8(ascii: ":")
    static let comma = UInt8(ascii: ",")
    static let period = UInt8(ascii: ".")
    static let zero = UInt8(ascii: "0")
    static let nine = UInt8(ascii: "9")
    static let upperA = UInt8(ascii: "A")
    static let upperE = UInt8(ascii: "E")
    static let upperF = UInt8(ascii: "F")
    static let lowerA = UInt8(ascii: "a")
    static let b = UInt8(ascii: "b")
    static let e = UInt8(ascii: "e")
    static let f = UInt8(ascii: "f")
    static let lowerF = UInt8(ascii: "f")
    static let n = UInt8(ascii: "n")
    static let r = UInt8(ascii: "r")
    static let t = UInt8(ascii: "t")
    static let u = UInt8(ascii: "u")
}

private extension Array where Element == UInt8 {
    mutating func append(ascii character: Unicode.Scalar) {
        append(UInt8(ascii: character))
    }
}
