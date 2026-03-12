import Foundation
import Testing
@testable import KeyCore

struct CryptoAndStorageTests {
    @Test
    func secretFileRoundTripsThroughJSON() throws {
        let file = SecretFile(nonce: Data([1, 2, 3]).base64EncodedString(), ciphertext: Data([4, 5]).base64EncodedString())
        let data = try JSONEncoder().encode(file)
        let decoded = try JSONDecoder().decode(SecretFile.self, from: data)
        #expect(decoded == file)
    }

    @Test
    func cipherEncryptsAndDecrypts() throws {
        let cipher = VaultCipher()
        let keyData = Data((0..<32).map(UInt8.init))
        let encrypted = try cipher.encrypt("super-secret", keyData: keyData)
        let decrypted = try cipher.decrypt(encrypted, keyData: keyData)
        #expect(decrypted == "super-secret")
    }

    @Test
    func entryStoreBuildsExpectedPath() throws {
        let root = URL(fileURLWithPath: "/tmp/key-tests", isDirectory: true)
        let store = EntryStore(rootURL: root)
        let result = try store.url(for: "github/personal")
        #expect(result.path(percentEncoded: false) == "/tmp/key-tests/github/personal.secret")
    }

    @Test
    func entryStoreRejectsTraversal() throws {
        let root = URL(fileURLWithPath: "/tmp/key-tests", isDirectory: true)
        let store = EntryStore(rootURL: root)
        #expect(throws: AppError.invalidEntryName("Entry name must not contain '.' or '..' segments.")) {
            try store.url(for: "../nope")
        }
    }

    func entryStoreListsSortedEntries() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let store = EntryStore(rootURL: root)
        try store.save(
            SecretFile(nonce: Data([1]).base64EncodedString(), ciphertext: Data([2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]).base64EncodedString()),
            as: "zeta/one",
            overwrite: false
        )
        try store.save(
            SecretFile(nonce: Data([1]).base64EncodedString(), ciphertext: Data([2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]).base64EncodedString()),
            as: "alpha/two",
            overwrite: false
        )

        #expect(try store.listEntries() == ["alpha/two", "zeta/one"])
    }
}
