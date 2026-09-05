import Foundation
import Testing
@testable import KeyCore

struct ConfigCompatibilityTests {
    @Test(arguments: ["local", "icloud", "omitted"], [false, true])
    func terminalConfigListWarnsOnlyForV2(storedMode: String, isV3: Bool) throws {
        let fixture = try ConfigFixture(storedMode: storedMode, isV3: isV3)
        defer { fixture.remove() }
        let original = try Data(contentsOf: fixture.configURL)
        let io = MemoryIO(stdinIsTTY: false, stdoutIsTTY: true)
        let transport = MemoryTransport { _ in
            Issue.record("Config warnings must not contact the helper")
            return .success()
        }
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: MemoryClipboard(),
            configStore: fixture.store
        )
        #expect(app.run(arguments: ["config", "list"]) == EXIT_SUCCESS)
        let mode = storedMode == "icloud" ? "icloud" : "local"
        let legacyLine = isV3 ? "" : "keychain-mode=\(mode)\n"
        #expect(io.stdout == "vault-dir=\(fixture.root.path(percentEncoded: false))\n" + legacyLine)
        if isV3 {
            #expect(io.stderr.isEmpty)
        } else {
            #expect(io.stderr.components(separatedBy: "Warning:").count == 2)
            #expect(io.stderr.contains("deprecated; v2 reads and writes remain supported"))
            #expect(io.stderr.contains("key migrate --check"))
            #expect(io.stderr.contains("Migration is explicit"))
        }
        #expect(transport.requests.isEmpty)
        #expect(try Data(contentsOf: fixture.configURL) == original)
    }

    @Test(arguments: ["local", "icloud", "omitted"], [false, true])
    func configReadsPreserveStableFilesAndExposeOnlyActiveSettings(
        storedMode: String,
        isV3: Bool
    ) throws {
        let fixture = try ConfigFixture(storedMode: storedMode, isV3: isV3)
        defer { fixture.remove() }
        let original = try Data(contentsOf: fixture.configURL)
        let mode: KeychainMode = storedMode == "icloud" ? .icloud : .local
        let configuration = try fixture.store.load()
        let expectedPath = fixture.root.path(percentEncoded: false)
        let expectedAuthority: ConfiguredVaultAuthority = isV3
            ? .v3(vaultID: ConfigFixture.vaultID)
            : .v2(keychainMode: mode)
        #expect(configuration.authority == expectedAuthority)
        #expect(configuration.keychainMode == mode)
        #expect(
            try fixture.store.configuredVaultRuntimeSelection().authority
                == expectedAuthority
        )

        let transport = MemoryTransport { _ in
            Issue.record("Config reads must not contact the helper")
            return .success()
        }
        for arguments in [
            ["config", "list"],
            ["config", "get", "vault-dir"],
            ["config", "get", "keychain-mode"]
        ] {
            let io = MemoryIO(stdinIsTTY: false)
            let app = KeyCLIApplication(
                transport: transport,
                io: io,
                clipboard: MemoryClipboard(),
                configStore: fixture.store
            )
            #expect(app.run(arguments: arguments) == EXIT_SUCCESS)
            if arguments == ["config", "list"] {
                let legacyLine = isV3 ? "" : "keychain-mode=\(mode.rawValue)\n"
                #expect(io.stdout == "vault-dir=\(expectedPath)\n" + legacyLine)
                #expect(io.stderr.isEmpty)
            } else if arguments.last == "vault-dir" {
                #expect(io.stdout == "\(expectedPath)\n")
                #expect(io.stderr.isEmpty)
            } else {
                #expect(io.stdout == "\(mode.rawValue)\n")
                if isV3 {
                    #expect(io.stderr.contains("retained legacy metadata"))
                    #expect(io.stderr.contains("Device enrollment"))
                    #expect(io.stderr.contains("iCloud Drive"))
                } else {
                    #expect(io.stderr.isEmpty)
                }
            }
        }
        #expect(transport.requests.isEmpty)
        #expect(try Data(contentsOf: fixture.configURL) == original)
    }

    @Test(arguments: KeychainMode.allCases)
    func migrationAndRootUpdateRetainSourceMode(mode: KeychainMode) throws {
        let fixture = try ConfigFixture(storedMode: mode.rawValue, isV3: false)
        defer { fixture.remove() }
        let rootHandle = try VaultRootDirectoryHandle(opening: fixture.root)
        let selected = try fixture.store.selectV3Vault(
            vaultID: ConfigFixture.vaultID,
            expectedRootHandle: rootHandle,
            expectedKeychainMode: mode
        )
        #expect(selected.authority == .v3(vaultID: ConfigFixture.vaultID))
        #expect(selected.keychainMode == mode)
        let newRoot = fixture.home.appendingPathComponent("Moved Vault")
        let updated = try fixture.store.setValue(newRoot.path, for: .vaultDir)
        #expect(updated.authority == selected.authority)
        #expect(updated.keychainMode == mode)
        #expect(
            try String(contentsOf: fixture.configURL, encoding: .utf8)
                .contains("keychain_mode = \"\(mode.rawValue)\"")
        )
    }

    @Test(arguments: [false, true])
    func externalLegacyModeChangeStillInvalidatesHelper(isV3: Bool) throws {
        let fixture = try ConfigFixture(storedMode: "icloud", isV3: isV3)
        defer { fixture.remove() }
        let keys = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(
            keyStore: keys,
            entryStore: EntryStore(rootURL: fixture.root),
            keychainMode: .icloud,
            configStore: fixture.store,
            mutationOwner: VaultTransactionMutationOwner(),
            configuredVaultID: isV3 ? ConfigFixture.vaultID : nil
        )
        // An old writer or manual edit can still alter retained metadata.
        _ = try fixture.store.setValue("local", for: .keychainMode)
        let response = handler.handle(.status)
        #expect(response.errorCode == .operationRefused)
        #expect(response.errorMessage?.contains("key lock") == true)
        #expect(keys.invalidateCount == 1)
    }

    @Test(arguments: [
        "keychain_mode = \"unsupported\"",
        "keychain_mode = \"local\"\nkeychain_mode = \"icloud\"",
        "vault_id = \"not-a-uuid\"",
        "vault_id = \"\(ConfigFixture.vaultID)\"\nvault_id = \"\(ConfigFixture.vaultID)\""
    ])
    func malformedConfigProducesNoPartialCLIOutput(extra: String) throws {
        let fixture = try ConfigFixture(storedMode: "omitted", isV3: false)
        defer { fixture.remove() }
        let contents = "vault_dir = \"\(fixture.root.path)\"\n\(extra)\n"
        try contents.write(to: fixture.configURL, atomically: true, encoding: .utf8)
        let io = MemoryIO(stdinIsTTY: false, stdoutIsTTY: true)
        let app = KeyCLIApplication(
            transport: MemoryTransport { _ in
                Issue.record("Malformed config must not contact the helper")
                return .success()
            },
            io: io,
            clipboard: MemoryClipboard(),
            configStore: fixture.store
        )
        #expect(
            app.run(arguments: ["config", "list"])
                == KeyExitCode.configurationFailure.rawValue
        )
        #expect(io.stdout.isEmpty)
        #expect(!io.stderr.isEmpty)
        #expect(!io.stderr.contains("deprecated"))
        #expect(try String(contentsOf: fixture.configURL, encoding: .utf8) == contents)
    }
}

private struct ConfigFixture {
    static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    let home: URL
    let root: URL
    let store: KeyConfigStore
    let configURL: URL

    init(storedMode: String, isV3: Bool) throws {
        home = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
            .standardizedFileURL
        root = home.appendingPathComponent("Vault", isDirectory: true)
        store = KeyConfigStore(homeDirectoryURL: home)
        configURL = try store.setValue(root.path, for: .vaultDir).configFileURL
        var contents = "# Stable-compatible fixture\nvault_dir = \"\(root.path)\"\n"
        if storedMode != "omitted" {
            contents += "keychain_mode = \"\(storedMode)\"\n"
        }
        if isV3 {
            contents += "vault_id = \"\(Self.vaultID)\"\n"
        }
        contents += "unknown_setting = \"preserve on reads\"\n"
        try contents.write(to: configURL, atomically: true, encoding: .utf8)
    }

    func remove() {
        try? FileManager.default.removeItem(at: home)
    }
}
