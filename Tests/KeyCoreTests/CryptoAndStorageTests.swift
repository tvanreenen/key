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

    @Test
    func defaultLocationCreatesConfigAndVaultDirectory() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: homeDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let location = try EntryStore.defaultLocation(homeDirectoryURL: homeDirectory)
        let rereadLocation = try EntryStore.defaultLocation(homeDirectoryURL: homeDirectory)
        let configFileURL = homeDirectory
            .appendingPathComponent(".key", isDirectory: true)
            .appendingPathComponent("config.toml", isDirectory: false)
        let expectedVaultURL = homeDirectory
            .appendingPathComponent(".key", isDirectory: true)
            .appendingPathComponent("vault", isDirectory: true)
            .standardizedFileURL

        #expect(location.rootURL.standardizedFileURL == expectedVaultURL)
        #expect(location.configFileURL == configFileURL)
        #expect(location.sourceDescription == "Config file (default)")
        #expect(rereadLocation == location)
        #expect(FileManager.default.fileExists(atPath: location.rootURL.path(percentEncoded: false)))
        #expect(FileManager.default.fileExists(atPath: configFileURL.path(percentEncoded: false)))
        #expect(try String(contentsOf: configFileURL, encoding: .utf8).contains("vault_dir = "))
    }

    @Test
    func defaultLocationReadsCustomVaultDirectoryFromConfig() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let configDirectory = homeDirectory.appendingPathComponent(".key", isDirectory: true)
        let customVaultDirectory = homeDirectory.appendingPathComponent("Secrets Vault", isDirectory: true)
        try FileManager.default.createDirectory(at: configDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let configContents = """
        # key configuration
        vault_dir = "~/Secrets Vault"
        """
        try configContents.write(
            to: configDirectory.appendingPathComponent("config.toml", isDirectory: false),
            atomically: true,
            encoding: .utf8
        )

        let location = try EntryStore.defaultLocation(homeDirectoryURL: homeDirectory)

        #expect(location.rootURL.standardizedFileURL == customVaultDirectory.standardizedFileURL)
        #expect(location.sourceDescription == "Config file (custom)")
        #expect(FileManager.default.fileExists(atPath: customVaultDirectory.path(percentEncoded: false)))
    }

    @Test
    func configStoreSetWritesResolvedAbsoluteVaultDirectoryAndCreatesIt() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: homeDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let store = KeyConfigStore(homeDirectoryURL: homeDirectory)
        let updated = try store.setValue("~/Secrets Vault", for: .vaultDir)
        let expectedVaultURL = homeDirectory
            .appendingPathComponent("Secrets Vault", isDirectory: true)
            .standardizedFileURL

        #expect(updated.vaultDirectoryURL.standardizedFileURL == expectedVaultURL)
        #expect(try store.getValue(for: .vaultDir) == expectedVaultURL.path(percentEncoded: false))
        #expect(FileManager.default.fileExists(atPath: expectedVaultURL.path(percentEncoded: false)))
        #expect(try String(contentsOf: updated.configFileURL, encoding: .utf8).contains("vault_dir = \"\(expectedVaultURL.path(percentEncoded: false))\""))
    }

    @Test
    func configStoreRejectsVaultDirectoryThatIsAFile() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: homeDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let fileURL = homeDirectory.appendingPathComponent("not-a-directory", isDirectory: false)
        FileManager.default.createFile(atPath: fileURL.path(percentEncoded: false), contents: Data(), attributes: nil)

        let store = KeyConfigStore(homeDirectoryURL: homeDirectory)
        #expect(throws: AppError.invalidConfiguration("Configured vault directory '\(fileURL.path(percentEncoded: false))' exists but is not a directory.")) {
            try store.setValue(fileURL.path(percentEncoded: false), for: .vaultDir)
        }
    }

    @Test
    func configStoreRejectsFileAtKeyConfigRoot() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: homeDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let keyRootURL = homeDirectory.appendingPathComponent(".key", isDirectory: false)
        FileManager.default.createFile(atPath: keyRootURL.path(percentEncoded: false), contents: Data(), attributes: nil)

        #expect(throws: AppError.invalidConfiguration("Key config root '\(keyRootURL.path(percentEncoded: false))' exists but is not a directory.")) {
            _ = try EntryStore.defaultLocation(homeDirectoryURL: homeDirectory)
        }
    }
}
