import Foundation
import Testing
@testable import KeyCore

struct VaultRootChangeCoordinationTests {
    @Test
    func helperPersistsRootChangeInvalidatesSessionAndRefusesMoreWork() throws {
        let home = try temporaryHomeDirectory()
        defer { try? FileManager.default.removeItem(at: home) }
        let originalRoot = home.appendingPathComponent(
            "Original Vault",
            isDirectory: true
        )
        let configStore = KeyConfigStore(homeDirectoryURL: home)
        try writeLegacyTestConfiguration(home: home, root: originalRoot)
        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: EntryStore(rootURL: originalRoot),
            configStore: configStore
        )

        try FileManager.default.createDirectory(at: home.appendingPathComponent("Replacement Vault"), withIntermediateDirectories: false)
        #expect(
            handler.handle(
                .setVaultDirectory(path: "~/Replacement Vault")
            ) == .success()
        )

        let replacementRoot = home.appendingPathComponent(
            "Replacement Vault",
            isDirectory: true
        )
        #expect(
            try configStore.getValue(for: .vaultDir)
                == replacementRoot.standardizedFileURL.path(
                    percentEncoded: false
                )
        )
        #expect(
            FileManager.default.fileExists(
                atPath: replacementRoot.path(percentEncoded: false)
            )
        )
        #expect(keyStore.invalidateCount == 1)

        let staleResponse = handler.handle(.list)
        #expect(staleResponse.exitCode == EXIT_FAILURE)
        #expect(staleResponse.errorMessage?.contains("restarting") == true)
        #expect(staleResponse.errorMessage?.contains("key lock") == true)

        let secondChange = handler.handle(
            .setVaultDirectory(path: "~/Third Vault")
        )
        #expect(secondChange.exitCode == EXIT_FAILURE)
        #expect(
            try configStore.getValue(for: .vaultDir)
                == replacementRoot.standardizedFileURL.path(
                    percentEncoded: false
                )
        )

        #expect(handler.handle(.lock) == .success())
        #expect(keyStore.invalidateCount == 2)
    }

    @Test
    func failedRootChangeLeavesCurrentSessionUsable() throws {
        let home = try temporaryHomeDirectory()
        defer { try? FileManager.default.removeItem(at: home) }
        let originalRoot = home.appendingPathComponent(
            "Original Vault",
            isDirectory: true
        )
        let invalidRoot = home.appendingPathComponent(
            "Not A Directory",
            isDirectory: false
        )
        let configStore = KeyConfigStore(homeDirectoryURL: home)
        try writeLegacyTestConfiguration(home: home, root: originalRoot)
        try Data("file".utf8).write(to: invalidRoot)
        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: EntryStore(rootURL: originalRoot),
            configStore: configStore
        )

        let response = handler.handle(
            .setVaultDirectory(
                path: invalidRoot.path(percentEncoded: false)
            )
        )

        #expect(response.exitCode == KeyExitCode.configurationFailure.rawValue)
        #expect(keyStore.invalidateCount == 0)
        #expect(handler.handle(.list) == .success())
        #expect(
            try configStore.getValue(for: .vaultDir)
                == originalRoot.standardizedFileURL.path(
                    percentEncoded: false
                )
        )
    }

    @Test
    func externallyChangedConfigurationFailsClosed() throws {
        let home = try temporaryHomeDirectory()
        defer { try? FileManager.default.removeItem(at: home) }
        let originalRoot = home.appendingPathComponent(
            "Original Vault",
            isDirectory: true
        )
        let replacementRoot = home.appendingPathComponent(
            "Replacement Vault",
            isDirectory: true
        )
        let configStore = KeyConfigStore(homeDirectoryURL: home)
        try writeLegacyTestConfiguration(home: home, root: originalRoot)
        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: EntryStore(rootURL: originalRoot),
            configStore: configStore
        )

        try FileManager.default.createDirectory(at: replacementRoot, withIntermediateDirectories: false)
        _ = try configStore.setValue(
            replacementRoot.path(percentEncoded: false),
            for: .vaultDir
        )
        let response = handler.handle(.list)

        #expect(response.exitCode == EXIT_FAILURE)
        #expect(
            response.errorMessage?.contains(
                "configuration changed while Key Agent was running"
            ) == true
        )
        #expect(keyStore.invalidateCount == 1)
    }

    @Test
    func externallyChangedVaultIdentityFailsClosed() throws {
        let home = try temporaryHomeDirectory()
        defer { try? FileManager.default.removeItem(at: home) }
        let originalRoot = home.appendingPathComponent(
            "Original Vault",
            isDirectory: true
        )
        let configStore = KeyConfigStore(homeDirectoryURL: home)
        let configuration = try writeLegacyTestConfiguration(home: home, root: originalRoot)
        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: EntryStore(rootURL: originalRoot),
            configStore: configStore
        )

        try """
        # key configuration
        vault_dir = "\(originalRoot.path(percentEncoded: false))"
        keychain_mode = "local"
        vault_id = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
        """.write(
            to: configuration.configFileURL,
            atomically: true,
            encoding: .utf8
        )
        let response = handler.handle(.list)

        #expect(response.exitCode == EXIT_FAILURE)
        #expect(
            response.errorMessage?.contains(
                "configuration changed while Key Agent was running"
            ) == true
        )
        #expect(keyStore.invalidateCount == 1)
    }

    @Test
    func missingConfigurationFailsClosedWithoutRecreatingIt() throws {
        let home = try temporaryHomeDirectory()
        defer { try? FileManager.default.removeItem(at: home) }
        let originalRoot = home.appendingPathComponent(
            "Original Vault",
            isDirectory: true
        )
        let configStore = KeyConfigStore(homeDirectoryURL: home)
        let configuration = try writeLegacyTestConfiguration(home: home, root: originalRoot)
        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: EntryStore(rootURL: originalRoot),
            configStore: configStore
        )
        try FileManager.default.removeItem(at: configuration.configFileURL)

        let response = handler.handle(.status)

        #expect(response.exitCode == KeyExitCode.configurationFailure.rawValue)
        #expect(response.errorMessage?.contains("does not exist") == true)
        #expect(keyStore.invalidateCount == 1)
        #expect(
            !FileManager.default.fileExists(
                atPath: configuration.configFileURL.path(
                    percentEncoded: false
                )
            )
        )
    }

    @Test
    func rootChangeRequiresHelperConfigurationStore() throws {
        let root = try temporaryHomeDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let handler = KeyServiceHandler(
            keyStore: MemoryVaultKeyStore(),
            entryStore: EntryStore(rootURL: root)
        )

        let response = handler.handle(
            .setVaultDirectory(path: "/private/tmp/replacement")
        )

        #expect(response.exitCode == EXIT_FAILURE)
        #expect(
            response.errorMessage?.contains(
                "without its configuration store"
            ) == true
        )
        #expect(handler.handle(.list) == .success())
    }
}

private func temporaryHomeDirectory() throws -> URL {
    let home = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
        at: home,
        withIntermediateDirectories: false
    )
    return home
}
