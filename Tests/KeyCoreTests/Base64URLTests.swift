import Foundation
import Testing
@testable import KeyCore

struct Base64URLTests {
    @Test
    func matchesRFC4648VectorsWithoutPadding() {
        let vectors = [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy")
        ]

        for (plaintext, encoded) in vectors {
            let data = Data(plaintext.utf8)

            #expect(Base64URL.encode(data) == encoded)
            #expect(Base64URL.decodeCanonical(encoded) == data)
        }
    }

    @Test
    func usesURLSafeAlphabet() {
        let data = Data([0xFB, 0xFF])

        #expect(Base64URL.encode(data) == "-_8")
        #expect(Base64URL.decodeCanonical("-_8") == data)
    }

    @Test
    func rejectsPaddingStandardAlphabetWhitespaceAndNoncanonicalBits() {
        for value in ["Zg==", "+_8", "-/8", "Z g", "A", "Zh"] {
            #expect(Base64URL.decodeCanonical(value) == nil)
        }
    }
}
