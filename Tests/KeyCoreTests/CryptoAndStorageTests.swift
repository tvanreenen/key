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
        #expect(decoded.type == .secret)
    }

    @Test
    func legacySecretFileWithoutTypeIsRejected() {
        let data = Data("""
        {
          "version": 1,
          "alg": "AES.GCM",
          "nonce": "AQID",
          "ciphertext": "BAU="
        }
        """.utf8)

        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(SecretFile.self, from: data)
        }
    }

    @Test
    func cipherEncryptsAndDecrypts() throws {
        let cipher = VaultCipher()
        let keyData = Data((0..<32).map(UInt8.init))
        let encrypted = try cipher.encrypt("super-secret", keyData: keyData)
        let decrypted = try cipher.decrypt(encrypted, keyData: keyData)
        #expect(decrypted == "super-secret")
        #expect(encrypted.version == 2)
        #expect(encrypted.type == .secret)
    }

    @Test
    func cipherEncryptsTOTPSecretsWithTypedEnvelope() throws {
        let cipher = VaultCipher()
        let keyData = Data((0..<32).map(UInt8.init))
        let encrypted = try cipher.encrypt("JBSWY3DPEHPK3PXP", type: .totp, keyData: keyData)
        let decrypted = try cipher.decrypt(encrypted, keyData: keyData)

        #expect(decrypted == "JBSWY3DPEHPK3PXP")
        #expect(encrypted.version == 2)
        #expect(encrypted.type == .totp)
    }

    @Test
    func totpSeedNormalizationStripsWhitespaceAndUppercases() throws {
        let normalized = try TOTPGenerator.normalizeBase32Seed("  jbsw y3dp ehpk 3pxp  ")
        #expect(normalized == "JBSWY3DPEHPK3PXP")
    }

    @Test
    func totpSeedValidationRejectsInvalidBase32() {
        #expect(throws: AppError.invalidSecret("TOTP seed must be valid Base32.")) {
            _ = try TOTPGenerator.normalizeBase32Seed("nope!")
        }
    }

    @Test
    func totpGeneratorMatchesKnownVectors() throws {
        let seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

        #expect(try TOTPGenerator.generateCode(fromBase32Seed: seed, at: Date(timeIntervalSince1970: 59)) == "287082")
        #expect(try TOTPGenerator.generateCode(fromBase32Seed: seed, at: Date(timeIntervalSince1970: 1_234_567_890)) == "005924")
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

    @Test
    func entryStoreListsSortedVisibleAndHiddenEntries() throws {
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
        try store.save(
            SecretFile(nonce: Data([1]).base64EncodedString(), ciphertext: Data([2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]).base64EncodedString()),
            as: ".private",
            overwrite: false
        )
        try store.save(
            SecretFile(nonce: Data([1]).base64EncodedString(), ciphertext: Data([2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]).base64EncodedString()),
            as: ".group/token",
            overwrite: false
        )

        #expect(try store.listEntries() == [".group/token", ".private", "alpha/two", "zeta/one"])
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
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
            .appendingPathComponent("Key", isDirectory: true)
            .appendingPathComponent("config.toml", isDirectory: false)
        let expectedVaultURL = homeDirectory
            .appendingPathComponent(".key", isDirectory: true)
            .standardizedFileURL

        #expect(location.rootURL.standardizedFileURL == expectedVaultURL)
        #expect(location.configFileURL == configFileURL)
        #expect(location.pathSource == .appSupportConfigDefault)
        #expect(try KeyConfigStore(homeDirectoryURL: homeDirectory).getValue(for: .keychainMode) == "local")
        #expect(rereadLocation == location)
        #expect(FileManager.default.fileExists(atPath: location.rootURL.path(percentEncoded: false)))
        #expect(FileManager.default.fileExists(atPath: configFileURL.path(percentEncoded: false)))
        #expect(try String(contentsOf: configFileURL, encoding: .utf8).contains("vault_dir = "))
        #expect(try String(contentsOf: configFileURL, encoding: .utf8).contains("keychain_mode = \"local\""))
    }

    @Test
    func defaultLocationReadsCustomVaultDirectoryFromConfig() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let customVaultDirectory = homeDirectory.appendingPathComponent("Secrets Vault", isDirectory: true)
        let configDirectory = homeDirectory
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
            .appendingPathComponent("Key", isDirectory: true)
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
        #expect(location.pathSource == .appSupportConfigCustom)
        #expect(FileManager.default.fileExists(atPath: customVaultDirectory.path(percentEncoded: false)))
        #expect(try KeyConfigStore(homeDirectoryURL: homeDirectory).getValue(for: .keychainMode) == "local")
    }

    @Test
    func configVaultIDSelectsV3AndSurvivesOrdinaryConfigUpdates() throws {
        let homeDirectory = URL(
            fileURLWithPath: NSTemporaryDirectory(),
            isDirectory: true
        ).appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vaultDirectory = homeDirectory.appendingPathComponent(
            "Vault",
            isDirectory: true
        )
        let configDirectory = homeDirectory
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
            .appendingPathComponent("Key", isDirectory: true)
        try FileManager.default.createDirectory(
            at: configDirectory,
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: vaultDirectory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
        let config = """
        # key configuration
        vault_dir = "\(vaultDirectory.path(percentEncoded: false))"
        keychain_mode = "local"
        vault_id = "\(vaultID)"
        """
        let configURL = configDirectory.appendingPathComponent(
            "config.toml",
            isDirectory: false
        )
        try config.write(to: configURL, atomically: true, encoding: .utf8)

        let store = KeyConfigStore(homeDirectoryURL: homeDirectory)
        #expect(try store.load().vaultID == vaultID)
        #expect(
            try store.configuredVaultRuntimeSelection().vaultID == vaultID
        )

        _ = try store.setValue("icloud", for: .keychainMode)
        #expect(try store.load().vaultID == vaultID)
        #expect(
            try String(contentsOf: configURL, encoding: .utf8)
                .contains("vault_id = \"\(vaultID)\"")
        )
    }

    @Test
    func configRejectsNoncanonicalV3VaultID() throws {
        let homeDirectory = URL(
            fileURLWithPath: NSTemporaryDirectory(),
            isDirectory: true
        ).appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vaultDirectory = homeDirectory.appendingPathComponent(
            "Vault",
            isDirectory: true
        )
        let configDirectory = homeDirectory
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
            .appendingPathComponent("Key", isDirectory: true)
        try FileManager.default.createDirectory(
            at: configDirectory,
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: vaultDirectory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let config = """
        vault_dir = "\(vaultDirectory.path(percentEncoded: false))"
        vault_id = "018F4D38-7D5A-7B20-B0F1-97D6E96C44B3"
        """
        try config.write(
            to: configDirectory.appendingPathComponent("config.toml"),
            atomically: true,
            encoding: .utf8
        )

        #expect(throws: AppError.self) {
            try KeyConfigStore(homeDirectoryURL: homeDirectory).load()
        }
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
        #expect(try store.getValue(for: .keychainMode) == "local")
        #expect(FileManager.default.fileExists(atPath: expectedVaultURL.path(percentEncoded: false)))
        #expect(try String(contentsOf: updated.configFileURL, encoding: .utf8).contains("vault_dir = \"\(expectedVaultURL.path(percentEncoded: false))\""))
        #expect(try String(contentsOf: updated.configFileURL, encoding: .utf8).contains("keychain_mode = \"local\""))
    }

    @Test
    func configStoreSetWorksWhenDefaultVaultDirectoryIsAmbiguous() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let ambiguousVaultDirectory = homeDirectory.appendingPathComponent(".key", isDirectory: true)
        try FileManager.default.createDirectory(at: ambiguousVaultDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }
        FileManager.default.createFile(
            atPath: ambiguousVaultDirectory.appendingPathComponent("notes.txt", isDirectory: false).path(percentEncoded: false),
            contents: Data("not a vault".utf8),
            attributes: nil
        )

        let store = KeyConfigStore(homeDirectoryURL: homeDirectory)
        let updated = try store.setValue("~/Secrets Vault", for: .vaultDir)
        let expectedVaultURL = homeDirectory
            .appendingPathComponent("Secrets Vault", isDirectory: true)
            .standardizedFileURL

        #expect(updated.vaultDirectoryURL.standardizedFileURL == expectedVaultURL)
        #expect(updated.configFileURL.path(percentEncoded: false) == homeDirectory
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
            .appendingPathComponent("Key", isDirectory: true)
            .appendingPathComponent("config.toml", isDirectory: false)
            .path(percentEncoded: false))
        #expect(try store.getValue(for: .keychainMode) == "local")
    }

    @Test
    func configStoreCanSetKeychainModeWithoutChangingVaultDirectory() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: homeDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let store = KeyConfigStore(homeDirectoryURL: homeDirectory)
        let initialVaultDirectory = try store.getValue(for: .vaultDir)
        let updated = try store.setValue("icloud", for: .keychainMode)

        #expect(updated.keychainMode == .icloud)
        #expect(try store.getValue(for: .vaultDir) == initialVaultDirectory)
        #expect(try store.getValue(for: .keychainMode) == "icloud")
        #expect(try String(contentsOf: updated.configFileURL, encoding: .utf8).contains("keychain_mode = \"icloud\""))
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
    func defaultLocationAcceptsExistingVaultDirectoryWithSecretFiles() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: homeDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let vaultRootURL = homeDirectory.appendingPathComponent(".key", isDirectory: true)
        let nestedDirectory = vaultRootURL.appendingPathComponent("github", isDirectory: true)
        try FileManager.default.createDirectory(at: nestedDirectory, withIntermediateDirectories: true)
        FileManager.default.createFile(
            atPath: nestedDirectory.appendingPathComponent("personal.secret", isDirectory: false).path(percentEncoded: false),
            contents: Data("{}".utf8),
            attributes: nil
        )

        let location = try EntryStore.defaultLocation(homeDirectoryURL: homeDirectory)

        #expect(location.rootURL.standardizedFileURL == vaultRootURL.standardizedFileURL)
        #expect(location.pathSource == .appSupportConfigDefault)
    }

    @Test
    func defaultLocationRejectsAmbiguousExistingDefaultVaultDirectory() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vaultRootURL = homeDirectory.appendingPathComponent(".key", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultRootURL, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }
        FileManager.default.createFile(
            atPath: vaultRootURL.appendingPathComponent("notes.txt", isDirectory: false).path(percentEncoded: false),
            contents: Data("not a vault".utf8),
            attributes: nil
        )
        let normalizedVaultPath = vaultRootURL.standardizedFileURL.path(percentEncoded: false)
        let expectedVaultPath = normalizedVaultPath.hasSuffix("/") ? String(normalizedVaultPath.dropLast()) : normalizedVaultPath

        #expect(throws: AppError.invalidConfiguration("Default vault directory '\(expectedVaultPath)' already contains unrelated files. Run `key config set vault-dir <path>` to choose another vault directory.")) {
            _ = try EntryStore.defaultLocation(homeDirectoryURL: homeDirectory)
        }
    }

    @Test
    func defaultLocationRejectsFileAtDefaultVaultPath() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: homeDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let vaultRootURL = homeDirectory.appendingPathComponent(".key", isDirectory: false)
        FileManager.default.createFile(atPath: vaultRootURL.path(percentEncoded: false), contents: Data(), attributes: nil)

        #expect(throws: AppError.invalidConfiguration("Default vault directory '\(vaultRootURL.path(percentEncoded: false))' exists but is not a directory. Run `key config set vault-dir <path>` to choose another vault directory.")) {
            _ = try EntryStore.defaultLocation(homeDirectoryURL: homeDirectory)
        }
    }

    @Test
    func configStoreRejectsFileAtAppSupportConfigDirectory() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let appSupportDirectory = homeDirectory
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
        try FileManager.default.createDirectory(at: appSupportDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let configDirectoryURL = appSupportDirectory.appendingPathComponent("Key", isDirectory: false)
        FileManager.default.createFile(atPath: configDirectoryURL.path(percentEncoded: false), contents: Data(), attributes: nil)

        #expect(throws: AppError.invalidConfiguration("Key config directory '\(configDirectoryURL.path(percentEncoded: false))' exists but is not a directory.")) {
            _ = try EntryStore.defaultLocation(homeDirectoryURL: homeDirectory)
        }
    }
}
