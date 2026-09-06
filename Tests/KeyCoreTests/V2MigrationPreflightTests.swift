import Foundation
import Testing
@testable import KeyCore

struct V2MigrationPreflightTests {
    @Test
    func emptyVaultPassesWithoutLoadingOrCreatingAKey() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: EntryStore(rootURL: root)
        )

        let response = handler.handle(.migrationPreflight)

        #expect(response == .success("""
        Your vault is ready to migrate.
        Entries checked: 0 (0 secrets, 0 TOTP entries).
        The original vault has no entries.
        No files or Keychain items were changed. Migration has not started.

        """))
        #expect(keyStore.loadCount == 0)
        #expect(keyStore.storeCount == 0)
        #expect(keyStore.localKeyData == nil)
        #expect(keyStore.iCloudKeyData == nil)
    }

    @Test
    func validEntriesPassWithoutRepairingKeychainOrChangingFiles() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let store = EntryStore(rootURL: root)
        let cipher = VaultCipher()
        let vaultKey = Data((0..<32).map(UInt8.init))
        let staleLocalKey = Data((32..<64).map(UInt8.init))
        try store.save(
            cipher.encrypt("portable-secret", keyData: vaultKey),
            as: "mail/personal",
            overwrite: false
        )
        try store.save(
            cipher.encrypt("JBSWY3DPEHPK3PXP", type: .totp, keyData: vaultKey),
            as: "mail/mfa",
            overwrite: false
        )
        let before = try fileSnapshot(at: root)

        let keyStore = MemoryVaultKeyStore()
        keyStore.localKeyData = staleLocalKey
        keyStore.iCloudKeyData = vaultKey
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: store,
            keychainMode: .icloud
        )

        let response = handler.handle(.migrationPreflight)

        #expect(response == .success("""
        Your vault is ready to migrate.
        Entries checked: 2 (1 secret, 1 TOTP entry).
        Key could read and verify every entry, and each name is supported by the new format.
        No files or Keychain items were changed. Migration has not started.

        """))
        #expect(keyStore.requests.count == 1)
        #expect(keyStore.requests.first?.mode == .icloud)
        #expect(keyStore.requests.first?.createIfMissing == false)
        #expect(keyStore.storeCount == 0)
        #expect(keyStore.localKeyData == staleLocalKey)
        #expect(keyStore.iCloudKeyData == vaultKey)
        #expect(try fileSnapshot(at: root) == before)
    }

    @Test
    func prototypeMarkerBlocksMigrationWithoutBlockingVersion2Reads() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let store = EntryStore(rootURL: root)
        let vaultKey = Data((0..<32).map(UInt8.init))
        try store.save(
            VaultCipher().encrypt("portable-secret", keyData: vaultKey),
            as: "mail/personal",
            overwrite: false
        )
        try Data(#"{"version":1,"securityMode":"enclave"}"#.utf8).write(
            to: root.appendingPathComponent(".key-vault.json", isDirectory: false)
        )
        let before = try fileSnapshot(at: root)

        let keyStore = MemoryVaultKeyStore()
        keyStore.localKeyData = vaultKey
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: store)

        #expect(handler.handle(.get(name: "mail/personal")) == .success("portable-secret"))

        let response = handler.handle(.migrationPreflight)
        let message = try #require(response.errorMessage)

        #expect(response.exitCode == EXIT_FAILURE)
        #expect(message.contains("unreleased Secure Enclave sharing prototype"))
        #expect(message.contains("not a supported migration source"))
        #expect(message.hasSuffix("No files or Keychain items were changed. Migration has not started."))
        #expect(keyStore.loadCount == 1)
        #expect(keyStore.storeCount == 0)
        #expect(try fileSnapshot(at: root) == before)
    }

    @Test
    func incompatibleCorruptAndUndecryptableEntriesAreAllReported() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let store = EntryStore(rootURL: root)
        let cipher = VaultCipher()
        let vaultKey = Data((0..<32).map(UInt8.init))
        let otherKey = Data((32..<64).map(UInt8.init))

        try store.save(
            cipher.encrypt("safe", keyData: vaultKey),
            as: " leading-space",
            overwrite: false
        )
        try store.save(
            SecretFile(version: 1, nonce: "AQID", ciphertext: "BAUG"),
            as: "legacy",
            overwrite: false
        )
        try store.save(
            cipher.encrypt("other", keyData: otherKey),
            as: "wrong-key",
            overwrite: false
        )
        try store.save(
            cipher.encrypt("NOT!", type: .totp, keyData: vaultKey),
            as: "invalid-totp",
            overwrite: false
        )
        try store.save(
            SecretFile(nonce: "!!!", ciphertext: "!!!"),
            as: "bad-payload",
            overwrite: false
        )
        let brokenURL = try store.url(for: "broken")
        try Data("not-json".utf8).write(to: brokenURL)
        let before = try fileSnapshot(at: root)

        let keyStore = MemoryVaultKeyStore()
        keyStore.localKeyData = vaultKey
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: store)

        let response = handler.handle(.migrationPreflight)
        let message = try #require(response.errorMessage)

        #expect(response.exitCode == EXIT_FAILURE)
        #expect(message.contains(#"" leading-space": the entry name is not supported by the new vault format."#))
        #expect(message.contains(#""bad-payload": the file contains an invalid encrypted payload."#))
        #expect(message.contains(#""broken": the file is not a readable entry in the older vault format."#))
        #expect(message.contains(#""invalid-totp": the authenticator setup secret is not valid Base32."#))
        #expect(message.contains(#""legacy": the file does not use the supported encryption format (v2 AES-GCM)."#))
        #expect(message.contains(#""wrong-key": the entry could not be verified with this vault's encryption key."#))
        #expect(message.hasSuffix("No files or Keychain items were changed. Migration has not started."))
        #expect(!message.contains("safe"))
        #expect(!message.contains("other"))
        #expect(keyStore.requests.first?.createIfMissing == false)
        #expect(keyStore.storeCount == 0)
        #expect(try fileSnapshot(at: root) == before)
    }

    @Test
    func missingVaultKeyBlocksWithoutCreatingAReplacement() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let store = EntryStore(rootURL: root)
        let originalKey = Data((0..<32).map(UInt8.init))
        try store.save(
            VaultCipher().encrypt("portable-secret", keyData: originalKey),
            as: "mail/personal",
            overwrite: false
        )
        let before = try fileSnapshot(at: root)

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: store)
        let response = handler.handle(.migrationPreflight)
        let message = try #require(response.errorMessage)

        #expect(response.exitCode == EXIT_FAILURE)
        #expect(message.contains("Vault key does not exist yet."))
        #expect(message.hasSuffix("No files or Keychain items were changed. Migration has not started."))
        #expect(keyStore.requests.first?.createIfMissing == false)
        #expect(keyStore.localKeyData == nil)
        #expect(keyStore.storeCount == 0)
        #expect(try fileSnapshot(at: root) == before)
    }
}

private func temporaryDirectory() throws -> URL {
    let url = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

private func fileSnapshot(at root: URL) throws -> [String: Data] {
    guard let enumerator = FileManager.default.enumerator(
        at: root,
        includingPropertiesForKeys: [.isDirectoryKey, .isRegularFileKey],
        options: []
    ) else {
        return [:]
    }

    var snapshot: [String: Data] = [:]
    for case let fileURL as URL in enumerator {
        let values = try fileURL.resourceValues(forKeys: [.isDirectoryKey, .isRegularFileKey])
        let relative = fileURL.path(percentEncoded: false)
            .dropFirst(root.path(percentEncoded: false).count + 1)
        if values.isDirectory == true {
            snapshot["directory:\(relative)"] = Data()
        } else if values.isRegularFile == true {
            snapshot["file:\(relative)"] = try Data(contentsOf: fileURL)
        }
    }
    return snapshot
}
