import Foundation
import Testing
@testable import KeyCore

struct KeyInitializationTests {
    private let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c4504"

    @Test
    func completedSetupRestartGuidanceDoesNotRepeatCompletedOperations() {
        let acceptance = KeyShareRequest.accept(
            vaultID: vaultID, invitationID: String(repeating: "a", count: 64),
            comparisonCode: "123456"
        )
        let requests: [KeyServiceRequest] = [
            .initializeVault(path: "/tmp/Vault"), .migrationApply,
            .share(acceptance), .shareInDirectory(request: acceptance, path: "/tmp/Vault")
        ]
        for request in requests {
            let message = KeyXPCClientTransport.helperRestartTimeoutError(
                for: request, helperName: "Test Agent", timeoutSeconds: 5
            ).localizedDescription
            #expect(message.contains("key status"))
            #expect(message.contains("Test Agent"))
            #expect(!message.contains("Run the same command again"))
        }
    }

    @Test(arguments: [
        V3DeviceWrappedGenesisInstallError.persistedIdentityUnavailable,
        .checkpointChanged, .verifiedReopenMismatch
    ])
    func interruptedInitDoesNotDescribeAnOlderConfiguredVault(error: V3DeviceWrappedGenesisInstallError) throws {
        let home = try makeHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let config = KeyConfigStore(homeDirectoryURL: home)
        let service = V3VaultInitializationService(configStore: config) { _, _, _ in
            throw error
        }
        do {
            _ = try service.initialize(path: home.appendingPathComponent("Vault").path)
            Issue.record("Expected initialization to fail")
        } catch let failure as AppError {
            #expect(!failure.localizedDescription.lowercased().contains("version 2"))
            #expect(failure.localizedDescription.contains("key status"))
            #expect(failure.localizedDescription.contains("intact"))
        }
        #expect(try !config.hasConfiguration())
        #expect(try attemptRecords(config).count == 1)
    }

    @Test
    func ordinaryUnconfiguredRequestsNeverComposeOrCreateState() throws {
        let home = temporaryURL()
        defer { try? FileManager.default.removeItem(at: home) }
        let config = KeyConfigStore(homeDirectoryURL: home)
        let host = KeyServiceHost(hasConfiguration: { try config.hasConfiguration() }, makeHandler: {
            Issue.record("Ordinary requests must not bootstrap a runtime")
            return { _ in .success() }
        }, initialize: { _ in Issue.record("Only init can initialize"); return "" })
        let requests: [KeyServiceRequest] = [
            .vaultStatus, .unlock, .list, .get(name: "one"),
            .migrationPreflight, .migrationApply, .listConflicts,
            .showConflict(id: "conflict"), .getConflictValue(id: "conflict", versionID: "version"),
            .resolveConflicts([]), .share(.devices),
            .addManual(name: "one", secret: "test", type: .secret),
            .editManual(name: "one", secret: "test", type: .secret),
            .copyEntry(source: "one", destination: "two", force: false),
            .moveEntry(source: "one", destination: "two", force: false),
            .removeEntry(name: "one"), .setKeychainMode(.local),
            .setVaultDirectory(path: home.appendingPathComponent("Vault").path)
        ]
        for request in requests {
            #expect(host.handle(request) == .failure(KeyConfigStore.notInitializedError))
        }
        #expect(!FileManager.default.fileExists(atPath: home.path))
    }

    @Test(arguments: [["help"], ["version"]])
    func helpAndVersionDoNotRequireInitialization(arguments: [String]) {
        let home = temporaryURL()
        let io = MemoryIO(stdinIsTTY: false, stdoutIsTTY: false)
        let transport = MemoryTransport { _ in Issue.record("Help and version must stay local"); return .success() }
        let app = KeyCLIApplication(
            transport: transport, io: io, clipboard: MemoryClipboard(),
            configStore: KeyConfigStore(homeDirectoryURL: home)
        )
        #expect(app.run(arguments: arguments) == EXIT_SUCCESS)
        #expect(!io.stdout.isEmpty)
        #expect(io.stderr.isEmpty)
        #expect(!FileManager.default.fileExists(atPath: home.path))
    }

    @Test
    func configWritesRequireExistingConfigurationAndDestination() throws {
        let home = temporaryURL()
        defer { try? FileManager.default.removeItem(at: home) }
        let config = KeyConfigStore(homeDirectoryURL: home)
        let destination = home.appendingPathComponent("Missing Vault")
        #expect(throws: KeyConfigStore.notInitializedError) {
            try config.setValue(destination.path, for: .vaultDir)
        }
        #expect(throws: KeyConfigStore.notInitializedError) {
            try config.setValue("local", for: .keychainMode)
        }
        #expect(!FileManager.default.fileExists(atPath: home.path))
        let existing = try writeLegacyTestConfiguration(home: home)
        let bytes = try Data(contentsOf: existing.configFileURL)
        #expect(throws: AppError.self) { try config.setValue(destination.path, for: .vaultDir) }
        #expect(!FileManager.default.fileExists(atPath: destination.path))
        #expect(try Data(contentsOf: existing.configFileURL) == bytes)
    }

    @Test(arguments: [KeychainMode.local, .icloud])
    func emptyLegacyVaultNeverCreatesAMissingKey(mode: KeychainMode) throws {
        let home = try makeHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let existing = try writeLegacyTestConfiguration(home: home)
        let config = KeyConfigStore(homeDirectoryURL: home)
        _ = try config.setValue(mode.rawValue, for: .keychainMode)
        let keys = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(
            keyStore: keys, entryStore: EntryStore(rootURL: existing.vaultDirectoryURL),
            keychainMode: mode, configStore: config
        )
        for request: KeyServiceRequest in [.unlock, .addManual(name: "one", secret: "test", type: .secret)] {
            #expect(handler.handle(request).errorCode == .vaultKeyMismatch)
        }
        #expect(keys.requests.allSatisfy { !$0.createIfMissing })
        #expect(keys.localKeyData == nil)
        #expect(keys.iCloudKeyData == nil)
        #expect(keys.storeCount == 0)
        #expect(try FileManager.default.contentsOfDirectory(atPath: existing.vaultDirectoryURL.path).isEmpty)
    }

    @Test(arguments: [false, true])
    func unavailableRunningVaultRefusesBeforeKeyAccess(replace: Bool) throws {
        let home = try makeHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let existing = try writeLegacyTestConfiguration(home: home)
        let keys = MemoryVaultKeyStore(keyData: Data((0..<32).map(UInt8.init)))
        let handler = KeyServiceHandler(
            keyStore: keys, entryStore: EntryStore(rootURL: existing.vaultDirectoryURL),
            configStore: KeyConfigStore(homeDirectoryURL: home)
        )
        try FileManager.default.moveItem(at: existing.vaultDirectoryURL, to: home.appendingPathComponent("Moved Vault"))
        if replace {
            try FileManager.default.createDirectory(at: existing.vaultDirectoryURL, withIntermediateDirectories: false)
        }
        #expect(handler.handle(.unlock).errorCode == .invalidConfiguration)
        #expect(handler.handle(.addManual(name: "one", secret: "test", type: .secret)).errorCode == .invalidConfiguration)
        #expect(keys.loadCount == 0)
        #expect(keys.storeCount == 0)
        #expect(keys.invalidateCount == 2)
        #expect(FileManager.default.fileExists(atPath: existing.vaultDirectoryURL.path) == replace)
        if replace {
            #expect(try FileManager.default.contentsOfDirectory(atPath: existing.vaultDirectoryURL.path).isEmpty)
        }
        #expect(handler.handle(.lock) == .success())
    }

    @Test
    func lockDoesNotReadMalformedConfigurationBeforeRuntimeComposition() {
        let host = KeyServiceHost(hasConfiguration: {
            Issue.record("Lock must not need configuration")
            throw AppError.invalidConfiguration("Malformed config")
        }, makeHandler: {
            Issue.record("Lock must not need a runtime")
            return { _ in .success() }
        }, initialize: { _ in "" })
        #expect(host.handle(.lock) == .success())
    }

    @Test(arguments: [false, true])
    func liveHostCanCorrectAMovedVaultWithoutComposingItsOldRuntime(version3: Bool) throws {
        let home = try makeHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let existing = try writeLegacyTestConfiguration(home: home)
        if version3 {
            var bytes = try Data(contentsOf: existing.configFileURL)
            bytes.append(Data("vault_id = \"\(vaultID)\"\n".utf8))
            try bytes.write(to: existing.configFileURL)
        }
        let destination = home.appendingPathComponent("Moved Vault")
        try FileManager.default.moveItem(at: existing.vaultDirectoryURL, to: destination)
        let config = KeyConfigStore(homeDirectoryURL: home)
        let keys = MemoryVaultKeyStore()
        let host = KeyServiceHost.live(
            keyStore: keys, configStore: config,
            runtimeConfiguration: RuntimeConfiguration(productIdentity: .stable)
        )
        #expect(host.handle(.list).errorCode == .invalidConfiguration)
        #expect(host.handle(.setVaultDirectory(path: home.appendingPathComponent("Missing").path)).errorCode == .invalidConfiguration)
        #expect(host.handle(.setVaultDirectory(path: destination.path)) == .success())
        let selected = try config.load()
        #expect(selected.vaultDirectoryURL.standardizedFileURL == destination.standardizedFileURL)
        #expect(selected.vaultID == (version3 ? vaultID : nil))
        #expect(selected.keychainMode == .local)
        #expect(keys.loadCount == 0)
        #expect(keys.storeCount == 0)
        #expect(keys.invalidateCount == 1)
        #expect(host.handle(.list).errorMessage?.contains("restarting") == true)
        #expect(host.handle(.lock) == .success())
        #expect(!FileManager.default.fileExists(atPath: existing.vaultDirectoryURL.path))
    }

    @Test(arguments: [["config", "list"], ["config", "get", "vault-dir"], ["config", "get", "keychain-mode"]])
    func unconfiguredConfigInspectionDoesNotCreateAnything(arguments: [String]) throws {
        let home = temporaryURL()
        defer { try? FileManager.default.removeItem(at: home) }
        let config = KeyConfigStore(homeDirectoryURL: home)
        let io = MemoryIO(stdinIsTTY: false, stdoutIsTTY: false)
        let transport = MemoryTransport { _ in Issue.record("Read must stay local"); return .success() }
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: MemoryClipboard(), configStore: config)
        #expect(app.run(arguments: arguments) == KeyConfigStore.notInitializedError.exitCode.rawValue)
        #expect(io.stdout.isEmpty)
        #expect(io.stderr.contains("key init"))
        #expect(!FileManager.default.fileExists(atPath: home.path))
        #expect(throws: KeyConfigStore.notInitializedError) { try config.load() }
        #expect(!FileManager.default.fileExists(atPath: home.path))
    }

    @Test
    func missingConfiguredRootIsNotRecreated() throws {
        let home = try makeHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let existing = try writeLegacyTestConfiguration(home: home)
        let bytes = try Data(contentsOf: existing.configFileURL)
        try FileManager.default.removeItem(at: existing.vaultDirectoryURL)
        #expect(throws: AppError.self) { try KeyConfigStore(homeDirectoryURL: home).load() }
        #expect(!FileManager.default.fileExists(atPath: existing.vaultDirectoryURL.path))
        #expect(try Data(contentsOf: existing.configFileURL) == bytes)
    }

    @Test
    func parserSupportsCurrentDirectoryExplicitPathAndOptionTerminator() throws {
        #expect(try CLIParser.parse(arguments: ["init"]) == .initializeVault(path: nil))
        #expect(try CLIParser.parse(arguments: ["init", "Key Vault"]) == .initializeVault(path: "Key Vault"))
        #expect(try CLIParser.parse(arguments: ["init", "--", "-vault"]) == .initializeVault(path: "-vault"))
        for arguments in [["init", "--force"], ["init", "a", "b"], ["init", ""], ["init", "bad\0path"]] {
            #expect(throws: AppError.self) { try CLIParser.parse(arguments: arguments) }
        }
    }

    @Test(arguments: [nil, "Key Vault", "/tmp/Elsewhere"] as [String?])
    func cliSendsAnAbsolutePathWithoutLoadingConfiguration(path: String?) throws {
        let home = temporaryURL()
        defer { try? FileManager.default.removeItem(at: home) }
        let current = home.appendingPathComponent("Working Directory")
        let expected = path.map { URL(fileURLWithPath: $0, relativeTo: current).standardizedFileURL.path }
            ?? current.path
        let transport = MemoryTransport { request in
            #expect(request == .initializeVault(path: expected))
            return .success("Initialized.\n")
        }
        let io = MemoryIO(stdinIsTTY: false, stdoutIsTTY: false)
        let app = KeyCLIApplication(
            transport: transport, io: io, clipboard: MemoryClipboard(),
            configStore: KeyConfigStore(homeDirectoryURL: home),
            currentDirectory: { current }
        )
        #expect(app.run(arguments: ["init"] + (path.map { [$0] } ?? [])) == EXIT_SUCCESS)
        #expect(io.stdout == "Initialized.\n")
        #expect(io.stderr.contains("cannot currently be recovered"))
        #expect(!FileManager.default.fileExists(atPath: home.path))
    }

    @Test
    func initRequestRoundTripsAndRequiresFullAuthorityAndRestart() throws {
        let request = KeyServiceRequest.initializeVault(path: "/tmp/Key Vault")
        #expect(try JSONDecoder().decode(KeyServiceRequest.self, from: JSONEncoder().encode(request)) == request)
        #expect(KeyXPCClientRole.fullCLI.authorizes(request))
        #expect(!KeyXPCClientRole.utilityStatus.authorizes(request))
        #expect(request.requiresHelperShutdownAfterSuccess)
        #expect(request.responseTimeoutSeconds == nil)
        let message = KeyXPCClientTransport.helperRestartTimeoutError(
            for: request, helperName: "Agent", timeoutSeconds: 5
        ).localizedDescription
        #expect(message.contains("key status"))
        #expect(!message.contains("Run the same command again"))
    }

    @Test(arguments: [false, true])
    func serviceSelectsOnlyAfterInstallationAndRetainsAnAttemptReceipt(existingDirectory: Bool) throws {
        let home = try makeHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let root = home.appendingPathComponent("Key Vault\nquoted\"path")
        if existingDirectory { try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false) }
        let config = KeyConfigStore(homeDirectoryURL: home)
        let service = V3VaultInitializationService(configStore: config) { directory, _, select in
            #expect(directory.rootHandle.rootURL.standardizedFileURL == root.standardizedFileURL)
            #expect(try !config.hasConfiguration())
            #expect(try attemptRecords(config).count == 1)
            try select(vaultID)
            return report()
        }
        #expect(try service.initialize(path: root.path).contains("Created and selected"))
        let selection = try config.configuredVaultRuntimeSelection()
        #expect(selection.vaultID == vaultID)
        #expect(selection.rootURL.standardizedFileURL == root.standardizedFileURL)
        #expect(try attemptRecords(config).count == 1)
        #expect(!FileManager.default.fileExists(atPath: home.appendingPathComponent(".key").path))
    }

    @Test(arguments: ["file", "directory", "danglingLink", "v2", "v3"])
    func anyExistingConfigurationRefusesBeforeCreatingDestination(kind: String) throws {
        let home = try makeHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let config = KeyConfigStore(homeDirectoryURL: home)
        let configURL = config.initializationConfigFileURL
        try FileManager.default.createDirectory(at: configURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        switch kind {
        case "directory":
            try FileManager.default.createDirectory(at: configURL, withIntermediateDirectories: false)
        case "danglingLink":
            try FileManager.default.createSymbolicLink(at: configURL, withDestinationURL: home.appendingPathComponent("missing"))
        default:
            let text = kind == "file" ? "malformed" : "vault_dir = \"/unavailable\"\nkeychain_mode = \"icloud\"" + (kind == "v3" ? "\nvault_id = \"\(vaultID)\"" : "")
            try Data(text.utf8).write(to: configURL)
        }
        let root = home.appendingPathComponent("New Vault")
        let service = V3VaultInitializationService(configStore: config) { _, _, _ in
            Issue.record("Must not create identity for an existing selection")
            return report()
        }
        #expect(throws: AppError.self) { try service.initialize(path: root.path) }
        #expect(!FileManager.default.fileExists(atPath: root.path))
    }

    @Test
    func interruptedAttemptSurvivesServiceRestartAndCannotRepeatKeyCreation() throws {
        let home = try makeHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let config = KeyConfigStore(homeDirectoryURL: home)
        let root = home.appendingPathComponent("Vault")
        var calls = 0
        for _ in 0..<2 {
            let service = V3VaultInitializationService(configStore: config) { _, _, _ in
                calls += 1
                throw AppError.operationRefused("Simulated interruption")
            }
            #expect(throws: AppError.self) { try service.initialize(path: root.path) }
        }
        #expect(calls == 1)
        #expect(try !config.hasConfiguration())
        #expect(try attemptRecords(config).count == 1)
        let renamed = home.appendingPathComponent("Renamed Vault")
        try FileManager.default.moveItem(at: root, to: renamed)
        let retried = V3VaultInitializationService(configStore: config) { _, _, _ in
            calls += 1
            return report()
        }
        #expect(throws: AppError.self) { try retried.initialize(path: renamed.path) }
        #expect(calls == 1)
    }

    @Test
    func lateConfigurationWriterIsNotOverwritten() throws {
        let home = try makeHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let config = KeyConfigStore(homeDirectoryURL: home)
        let root = home.appendingPathComponent("Vault")
        let otherBytes = Data("another writer".utf8)
        let service = V3VaultInitializationService(configStore: config) { _, _, select in
            try otherBytes.write(to: config.initializationConfigFileURL)
            try select(vaultID)
            return report()
        }
        #expect(throws: AppError.self) { try service.initialize(path: root.path) }
        #expect(try Data(contentsOf: config.initializationConfigFileURL) == otherBytes)
    }

    @Test
    func changedAttemptRecordPreventsSelection() throws {
        let home = try makeHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let config = KeyConfigStore(homeDirectoryURL: home)
        let service = V3VaultInitializationService(configStore: config) { _, _, select in
            let record = try #require(attemptRecords(config).first)
            try Data("changed".utf8).write(to: record)
            try select(vaultID)
            return report()
        }
        #expect(throws: AppError.self) { try service.initialize(path: home.appendingPathComponent("Vault").path) }
        #expect(try !config.hasConfiguration())
    }

    @Test
    func changedConfigDirectoryPreventsSelection() throws {
        let home = try makeHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let config = KeyConfigStore(homeDirectoryURL: home)
        let service = V3VaultInitializationService(configStore: config) { _, _, select in
            let configDirectory = config.initializationConfigFileURL.deletingLastPathComponent()
            try FileManager.default.moveItem(at: configDirectory, to: configDirectory.appendingPathExtension("moved"))
            try FileManager.default.createDirectory(at: configDirectory, withIntermediateDirectories: false)
            try select(vaultID)
            return report()
        }
        #expect(throws: AppError.self) { try service.initialize(path: home.appendingPathComponent("Vault").path) }
        #expect(try !config.hasConfiguration())
    }

    @Test
    func concurrentInitRequestsStartOnlyOneAttempt() {
        let state = ConcurrentInitState()
        let host = KeyServiceHost(hasConfiguration: { false }, makeHandler: {
            Issue.record("Init must not compose a runtime")
            return { _ in .failure("Unexpected runtime") }
        }, initialize: { _ in
            state.lock.withLock { state.attempts += 1 }
            return "Created"
        })
        let captured = InitHostBox(host: host)
        DispatchQueue.concurrentPerform(iterations: 8) { index in
            let response = captured.host.handle(.initializeVault(path: "/new-\(index)"))
            state.lock.withLock { state.responses.append(response) }
        }
        #expect(state.attempts == 1)
        #expect(state.responses.filter { $0.exitCode == EXIT_SUCCESS }.count == 1)
    }

    @Test
    func unconfiguredStatusAndLockNeverComposeLegacyRuntime() {
        let host = KeyServiceHost(hasConfiguration: { false }, makeHandler: {
            Issue.record("Status must not bootstrap a legacy config")
            return { _ in .success() }
        }, initialize: { _ in "Created" })
        #expect(host.handle(.status).helperStatus?.isUnlocked == false)
        #expect(host.handle(.lock).exitCode == EXIT_SUCCESS)
        #expect(host.handle(.vaultStatus).errorMessage?.contains("key init") == true)
        #expect(host.handle(.initializeVault(path: "/new")).exitCode == EXIT_SUCCESS)
        #expect(host.handle(.list).exitCode != EXIT_SUCCESS)
        #expect(host.handle(.initializeVault(path: "/another")).exitCode != EXIT_SUCCESS)
        #expect(host.handle(.lock).exitCode == EXIT_SUCCESS)
    }

    @Test
    func configuredHostRefusesInitAndComposesNormalRuntimeOnce() {
        var compositions = 0
        let host = KeyServiceHost(hasConfiguration: { true }, makeHandler: {
            compositions += 1
            return { _ in .success("Existing vault") }
        }, initialize: { _ in Issue.record("Existing config must not initialize"); return "" })
        #expect(host.handle(.initializeVault(path: "/new")).exitCode != EXIT_SUCCESS)
        #expect(compositions == 0)
        #expect(host.handle(.list).value == "Existing vault")
        #expect(host.handle(.status).value == "Existing vault")
        #expect(compositions == 1)
    }

    private func report() -> V3DeviceWrappedGenesisInstallReport {
        .init(vaultID: vaultID, deviceID: vaultID, entryCount: 0, secretCount: 0, totpCount: 0)
    }

    private func temporaryURL() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    }

    private func makeHome() throws -> URL {
        let home = temporaryURL()
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: false)
        return home
    }

    private func attemptRecords(_ config: KeyConfigStore) throws -> [URL] {
        try FileManager.default.contentsOfDirectory(
            at: config.initializationConfigFileURL.deletingLastPathComponent().appendingPathComponent("v3-init-attempts"),
            includingPropertiesForKeys: nil
        ).filter { $0.pathExtension == "json" }
    }
}

private final class ConcurrentInitState: @unchecked Sendable {
    let lock = NSLock()
    var attempts = 0
    var responses: [KeyServiceResponse] = []
}

private struct InitHostBox: @unchecked Sendable {
    let host: KeyServiceHost
}
