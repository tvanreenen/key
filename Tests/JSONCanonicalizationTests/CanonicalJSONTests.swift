import Foundation
import JSONCanonicalization
import Testing

struct CanonicalJSONTests {
    @Test
    func objectPropertyOrderingMatchesRFC8785() {
        // RFC 8785 section 3.2.3 orders names by their UTF-16 code units.
        let value = CanonicalJSONValue.object([
            ("\u{20ac}", .string("Euro Sign")),
            ("\r", .string("Carriage Return")),
            ("\u{fb33}", .string("Hebrew Letter Dalet With Dagesh")),
            ("1", .string("One")),
            ("\u{1f600}", .string("Emoji: Grinning Face")),
            ("\u{0080}", .string("Control")),
            ("\u{00f6}", .string("Latin Small Letter O With Diaeresis"))
        ])

        let encoded = String(decoding: CanonicalJSON.encode(value), as: UTF8.self)

        #expect(encoded == """
        {"\\r":"Carriage Return","1":"One","":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}
        """)
    }

    @Test
    func canonicalizeRemovesWhitespaceAndSortsNestedObjects() throws {
        let input = Data(#" { "z": [true, null], "a": { "b": 2, "a": 1 } } "#.utf8)

        let canonical = try CanonicalJSON.canonicalize(input)

        #expect(String(decoding: canonical, as: UTF8.self) == #"{"a":{"a":1,"b":2},"z":[true,null]}"#)
    }

    @Test
    func parserRejectsDuplicateNamesAfterEscapeDecoding() {
        #expect(throws: CanonicalJSONError.duplicateProperty) {
            _ = try CanonicalJSON.parse(Data(#"{"a":1,"\u0061":2}"#.utf8))
        }
    }

    @Test
    func parserRejectsByteOrderMarkAndInvalidUTF8() {
        #expect(throws: CanonicalJSONError.invalidEncoding) {
            _ = try CanonicalJSON.parse(Data([0xEF, 0xBB, 0xBF, 0x7B, 0x7D]))
        }
        #expect(throws: CanonicalJSONError.invalidEncoding) {
            _ = try CanonicalJSON.parse(Data([0x22, 0xFF, 0x22]))
        }
    }

    @Test
    func parserEnforcesNestingLimit() {
        let count = 33
        let input = String(repeating: "[", count: count)
            + "0"
            + String(repeating: "]", count: count)

        #expect(throws: CanonicalJSONError.invalidJSON) {
            _ = try CanonicalJSON.parse(Data(input.utf8))
        }
    }

    @Test
    func parserRejectsNumbersOutsideTheManifestProfile() {
        for input in ["-1", "1.0", "1e2", "9007199254740992"] {
            #expect(throws: CanonicalJSONError.invalidJSON) {
                _ = try CanonicalJSON.parse(Data(input.utf8))
            }
        }
    }
}
