import Foundation
import Testing
@testable import KeyCore

struct KeyCLIApplicationTests {
    @Test
    func currentProcessVersionResolvesThroughSymlinkIntoAppBundle() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let appURL = root.appendingPathComponent("Key.app", isDirectory: true)
        let contentsURL = appURL.appendingPathComponent("Contents", isDirectory: true)
        let macOSURL = contentsURL.appendingPathComponent("MacOS", isDirectory: true)
        try FileManager.default.createDirectory(at: macOSURL, withIntermediateDirectories: true)

        let executableURL = macOSURL.appendingPathComponent("key", isDirectory: false)
        FileManager.default.createFile(atPath: executableURL.path, contents: Data(), attributes: nil)

        let infoPlistURL = contentsURL.appendingPathComponent("Info.plist", isDirectory: false)
        let infoPlist: NSDictionary = [
            "CFBundleIdentifier": "work.tvr.key.test",
            "CFBundleName": "Key",
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": "1.2.3",
            "CFBundleVersion": "45"
        ]
        #expect(infoPlist.write(to: infoPlistURL, atomically: true))

        let fallbackAppURL = root.appendingPathComponent("Fallback.app", isDirectory: true)
        let fallbackContentsURL = fallbackAppURL.appendingPathComponent("Contents", isDirectory: true)
        try FileManager.default.createDirectory(at: fallbackContentsURL, withIntermediateDirectories: true)
        let fallbackInfoPlistURL = fallbackContentsURL.appendingPathComponent("Info.plist", isDirectory: false)
        let fallbackInfoPlist: NSDictionary = [
            "CFBundleIdentifier": "work.tvr.key.fallback",
            "CFBundleName": "Fallback",
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": "9.9.9",
            "CFBundleVersion": "99"
        ]
        #expect(fallbackInfoPlist.write(to: fallbackInfoPlistURL, atomically: true))

        let symlinkURL = root.appendingPathComponent("bin/key", isDirectory: false)
        try FileManager.default.createDirectory(at: symlinkURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: symlinkURL, withDestinationURL: executableURL)

        let fallbackBundle = try #require(Bundle(url: fallbackAppURL))
        let version = KeyVersionInfo.currentProcess(mainBundle: fallbackBundle, executableURL: symlinkURL)

        #expect(version == KeyVersionInfo(marketingVersion: "1.2.3", buildVersion: "45"))
    }

    @Test
    func helpPrintsUsage() throws {
        let transport = MemoryTransport { _ in
            Issue.record("transport should not be called for help")
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["help"]) == EXIT_SUCCESS)
        #expect(io.stdout == CLIParser.usageText + "\n")
        #expect(io.stderr == "")
    }

    @Test
    func versionPrintsHumanReadableVersion() throws {
        let transport = MemoryTransport { _ in
            Issue.record("transport should not be called for version")
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: clipboard,
            version: KeyVersionInfo(marketingVersion: "1.2.3", buildVersion: "45")
        )

        #expect(app.run(arguments: ["version"]) == EXIT_SUCCESS)
        #expect(io.stdout == "1.2.3 (45)\n")
        #expect(io.stderr == "")
    }

    @Test
    func versionPrintsJSONVersion() throws {
        let transport = MemoryTransport { _ in
            Issue.record("transport should not be called for version")
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: clipboard,
            version: KeyVersionInfo(marketingVersion: "1.2.3", buildVersion: "45")
        )

        #expect(app.run(arguments: ["version", "--json"]) == EXIT_SUCCESS)

        let data = try #require(io.stdout.data(using: .utf8))
        let decoded = try JSONDecoder().decode(KeyVersionInfo.self, from: data)
        #expect(decoded == KeyVersionInfo(marketingVersion: "1.2.3", buildVersion: "45"))
    }

    @Test
    func configGetPrintsEffectiveVaultDirectoryWithoutTransport() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: homeDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let transport = MemoryTransport { _ in
            Issue.record("transport should not be called for config get")
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: clipboard,
            configStore: KeyConfigStore(homeDirectoryURL: homeDirectory)
        )

        #expect(app.run(arguments: ["config", "get", "vault-dir"]) == EXIT_SUCCESS)
        #expect(io.stdout == "\(homeDirectory.appendingPathComponent(".key", isDirectory: true).standardizedFileURL.path(percentEncoded: false))\n")
        #expect(io.stderr == "")
    }

    @Test
    func configSetVaultDirectoryUsesTransport() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: homeDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let transport = MemoryTransport { request in
            #expect(
                request == .setVaultDirectory(path: "~/Secrets Vault")
            )
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let configStore = KeyConfigStore(homeDirectoryURL: homeDirectory)
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: clipboard,
            configStore: configStore
        )

        #expect(app.run(arguments: ["config", "set", "vault-dir", "~/Secrets Vault"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(io.stderr == "")
        #expect(
            transport.requests == [
                .setVaultDirectory(path: "~/Secrets Vault")
            ]
        )
        #expect(
            try configStore.getValue(for: .vaultDir)
                == homeDirectory
                    .appendingPathComponent(".key", isDirectory: true)
                    .standardizedFileURL
                    .path(percentEncoded: false)
        )
    }

    @Test
    func configListPrintsShellFriendlyOutputWithoutTransport() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: homeDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let transport = MemoryTransport { _ in
            Issue.record("transport should not be called for config list")
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: clipboard,
            configStore: KeyConfigStore(homeDirectoryURL: homeDirectory)
        )

        #expect(app.run(arguments: ["config", "list"]) == EXIT_SUCCESS)
        #expect(io.stdout == "vault-dir=\(homeDirectory.appendingPathComponent(".key", isDirectory: true).standardizedFileURL.path(percentEncoded: false))\nkeychain-mode=local\n")
        #expect(io.stderr == "")
    }

    @Test
    func configGetPrintsKeychainModeWithoutTransport() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: homeDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let transport = MemoryTransport { _ in
            Issue.record("transport should not be called for config get")
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: clipboard,
            configStore: KeyConfigStore(homeDirectoryURL: homeDirectory)
        )

        #expect(app.run(arguments: ["config", "get", "keychain-mode"]) == EXIT_SUCCESS)
        #expect(io.stdout == "local\n")
        #expect(io.stderr == "")
    }

    @Test
    func configSetKeychainModeUsesTransport() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: homeDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let transport = MemoryTransport { request in
            #expect(request == .setKeychainMode(.icloud))
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let configStore = KeyConfigStore(homeDirectoryURL: homeDirectory)
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: clipboard,
            configStore: configStore
        )

        #expect(app.run(arguments: ["config", "set", "keychain-mode", "icloud"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(io.stderr == "")
        #expect(transport.requests == [.setKeychainMode(.icloud)])
        #expect(try configStore.getValue(for: .keychainMode) == "local")
    }

    @Test
    func migrationPreflightPrintsTheHelperReport() throws {
        let report = """
        Migration preflight passed.
        Entries checked: 2 (1 secret, 1 TOTP entry).
        No files or Keychain items were changed. Migration has not started.

        """
        let transport = MemoryTransport { request in
            #expect(request == .migrationPreflight)
            return .success(report)
        }
        let io = MemoryIO(stdinIsTTY: false)
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: MemoryClipboard()
        )

        #expect(app.run(arguments: ["migrate", "--check"]) == EXIT_SUCCESS)
        #expect(io.stdout == report)
        #expect(io.stderr == "")
        #expect(transport.requests == [.migrationPreflight])
    }

    @Test
    func blockedMigrationPreflightPrintsOnlyToStderr() throws {
        let transport = MemoryTransport { request in
            #expect(request == .migrationPreflight)
            return .failure("Migration preflight blocked.\nMigration has not started.")
        }
        let io = MemoryIO(stdinIsTTY: false)
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: MemoryClipboard()
        )

        #expect(app.run(arguments: ["migrate", "--check"]) == EXIT_FAILURE)
        #expect(io.stdout == "")
        #expect(io.stderr == "Migration preflight blocked.\nMigration has not started.\n")
    }

    @Test
    func unlockSendsUnlockRequest() throws {
        let transport = MemoryTransport { request in
            #expect(request == .unlock)
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["unlock"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(io.stderr == "")
    }

    @Test
    func lockSendsLockRequest() throws {
        let transport = MemoryTransport { request in
            #expect(request == .lock)
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["lock"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(io.stderr == "")
    }

    @Test
    func getAddsTrailingNewlineForTerminalOutput() throws {
        let transport = MemoryTransport { request in
            #expect(request == .get(name: "demo/test"))
            return .success("k9W2mQ7pL4xR")
        }
        let io = MemoryIO(stdinIsTTY: false, stdoutIsTTY: true)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["get", "demo/test"]) == EXIT_SUCCESS)
        #expect(io.stdout == "k9W2mQ7pL4xR\n")
    }

    @Test
    func getPreservesExactOutputWhenStdoutIsNotATerminal() throws {
        let transport = MemoryTransport { request in
            #expect(request == .get(name: "demo/test"))
            return .success("k9W2mQ7pL4xR")
        }
        let io = MemoryIO(stdinIsTTY: false, stdoutIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["get", "demo/test"]) == EXIT_SUCCESS)
        #expect(io.stdout == "k9W2mQ7pL4xR")
    }

    @Test
    func copyWritesToClipboardWithoutStdout() throws {
        let transport = MemoryTransport { request in
            #expect(request == .get(name: "mail/personal"))
            return .success("hunter2")
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["copy", "mail/personal"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(clipboard.copiedText == "hunter2")
    }

    @Test
    func manualAddReadsPipedInputAndSendsItToService() throws {
        let transport = MemoryTransport { request in
            #expect(request == .addManual(name: "aws/prod/token", secret: "hunter2", type: .secret))
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false, pipedInput: "hunter2")
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["add", "aws/prod/token"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(io.stderr == "")
    }

    @Test
    func manualAddTOTPReadsPipedInputNormalizesSeedAndSendsItToService() throws {
        let transport = MemoryTransport { request in
            #expect(request == .addManual(name: "aws/prod/token", secret: "JBSWY3DPEHPK3PXP", type: .totp))
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false, pipedInput: " jbsw y3dp ehpk 3pxp ")
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["add", "--totp", "aws/prod/token"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(io.stderr == "")
    }

    @Test
    func manualAddTOTPRejectsInvalidBase32BeforeSendingRequest() throws {
        let transport = MemoryTransport { _ in
            Issue.record("transport should not be called for invalid TOTP seeds")
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false, pipedInput: "not base32!")
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["add", "--totp", "aws/prod/token"]) == EXIT_FAILURE)
        #expect(io.stderr == "TOTP seed must be valid Base32.\n")
    }

    @Test
    func manualEditReadsPipedInputAndSendsItToService() throws {
        let transport = MemoryTransport { request in
            #expect(request == .editManual(name: "aws/prod/token", secret: "hunter2", type: .secret))
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false, pipedInput: "hunter2")
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["edit", "aws/prod/token"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(io.stderr == "")
    }

    @Test
    func duplicateSendsEncryptedCopyRequest() throws {
        let transport = MemoryTransport { request in
            #expect(request == .copyEntry(source: "src/token", destination: "dst/token", force: true))
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["duplicate", "src/token", "dst/token", "--force"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(io.stderr == "")
    }

    @Test
    func renameSendsEncryptedMoveRequest() throws {
        let transport = MemoryTransport { request in
            #expect(request == .moveEntry(source: "src/token", destination: "dst/token", force: true))
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["rename", "src/token", "dst/token", "--force"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(io.stderr == "")
    }

    @Test
    func removePromptsOnTTYAndSendsDeleteRequest() throws {
        let transport = MemoryTransport { request in
            #expect(request == .removeEntry(name: "src/token"))
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: true, lineInput: "y")
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["remove", "src/token"]) == EXIT_SUCCESS)
        #expect(io.stderr == "Remove 'src/token'? [y/N]: ")
    }

    @Test
    func removeRequiresForceWhenNonInteractive() throws {
        let transport = MemoryTransport { _ in
            Issue.record("transport should not be called")
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["remove", "src/token"]) == EXIT_FAILURE)
        #expect(io.stderr.contains("without --force in non-interactive mode") == true)
    }

    @Test
    func removeForceSkipsPrompt() throws {
        let transport = MemoryTransport { request in
            #expect(request == .removeEntry(name: "src/token"))
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["remove", "src/token", "--force"]) == EXIT_SUCCESS)
        #expect(io.stderr == "")
    }
}

struct KeyServiceHandlerTests {
    @Test
    func vaultStatusReportsCurrentVersion2StateWithoutLoadingTheKey() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let keyStore = MemoryVaultKeyStore()
        let entryStore = EntryStore(rootURL: root)
        try entryStore.save(
            SecretFile(
                version: 2,
                type: .secret,
                alg: "AES.GCM",
                nonce: "AA==",
                ciphertext: "AA=="
            ),
            as: "one",
            overwrite: false
        )
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: entryStore
        )

        let response = handler.handle(.vaultStatus)

        #expect(
            response.vaultStatus == VaultStatus(
                format: .version2,
                health: .ready,
                entries: .effective(1)
            )
        )
        #expect(response.exitCode == EXIT_SUCCESS)
        #expect(keyStore.loadCount == 0)
    }

    @Test
    func unlockAuthenticatesWithoutReturningOutput() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: EntryStore(rootURL: tempDirectory))

        #expect(handler.handle(.unlock) == .success())
        #expect(keyStore.loadCount == 1)
        #expect(keyStore.requests.last?.createIfMissing == true)
        #expect(keyStore.requests.last?.mode == .local)
    }

    @Test
    func lockInvalidatesSessionWithoutReturningOutput() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: EntryStore(rootURL: tempDirectory))

        #expect(handler.handle(.lock) == .success())
        #expect(keyStore.invalidateCount == 1)
    }

    @Test
    func statusReturnsLockedHelperStateWhenNoSessionIsActive() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let store = SessionVaultKeyStore(underlying: MemoryVaultKeyStore(), inactivityTimeout: 120)
        let handler = KeyServiceHandler(keyStore: store, entryStore: EntryStore(rootURL: tempDirectory))

        #expect(handler.handle(.status) == .success(helperStatus: .locked(inactivityTimeoutSeconds: 120)))
    }

    @Test
    func statusReturnsUnlockedHelperStateWhenSessionIsWarm() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let store = SessionVaultKeyStore(underlying: MemoryVaultKeyStore(), inactivityTimeout: 120)
        let handler = KeyServiceHandler(keyStore: store, entryStore: EntryStore(rootURL: tempDirectory))

        #expect(handler.handle(.unlock) == .success())

        let response = handler.handle(.status)
        #expect(response.exitCode == EXIT_SUCCESS)
        #expect(response.helperStatus?.isUnlocked == true)
        #expect(response.helperStatus?.inactivityTimeoutSeconds == 120)
    }

    @Test
    func addThenGetRoundTripsSecret() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: EntryStore(rootURL: tempDirectory))

        let putResponse = handler.handle(.addManual(name: "mail/personal", secret: "hunter2", type: .secret))
        #expect(putResponse == .success())

        let getResponse = handler.handle(.get(name: "mail/personal"))
        #expect(getResponse == .success("hunter2"))
        #expect(keyStore.loadCount == 2)
    }

    @Test
    func unlockRefusesToCreateNewVaultKeyWhenEntriesAlreadyExist() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let store = EntryStore(rootURL: tempDirectory)
        let existingKey = Data((100..<132).map(UInt8.init))
        let encrypted = try VaultCipher().encrypt("hunter2", keyData: existingKey)
        try store.save(encrypted, as: "mail/personal", overwrite: false)

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: store)

        let response = handler.handle(.unlock)
        #expect(response.exitCode == KeyExitCode.securityFailure.rawValue)
        #expect(response.errorMessage?.contains("Refusing to create a new vault key") == true)
        #expect(keyStore.loadCount == 0)
    }

    @Test
    func getReturnsFriendlyErrorWhenCurrentVaultKeyCannotDecryptEntry() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let store = EntryStore(rootURL: tempDirectory)
        let existingKey = Data((0..<32).map(UInt8.init))
        let wrongKey = Data((32..<64).map(UInt8.init))
        let encrypted = try VaultCipher().encrypt("hunter2", keyData: existingKey)
        try store.save(encrypted, as: "mail/personal", overwrite: false)

        let keyStore = MemoryVaultKeyStore()
        keyStore.keyData = wrongKey
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: store)

        let response = handler.handle(.get(name: "mail/personal"))
        #expect(response.exitCode == KeyExitCode.securityFailure.rawValue)
        #expect(response.errorMessage?.contains("cannot decrypt 'mail/personal'") == true)
    }

    @Test
    func switchingToICloudPublishesWorkingLocalKeyAndUpdatesConfig() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vaultDirectory = homeDirectory.appendingPathComponent("Vault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let configStore = KeyConfigStore(homeDirectoryURL: homeDirectory)
        _ = try configStore.setValue(vaultDirectory.path(percentEncoded: false), for: .vaultDir)

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: EntryStore(rootURL: vaultDirectory),
            configStore: configStore
        )

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "hunter2", type: .secret)) == .success())
        let localKey = try #require(keyStore.localKeyData)

        #expect(handler.handle(.setKeychainMode(.icloud)) == .success())
        #expect(keyStore.iCloudKeyData == localKey)
        #expect(try configStore.getValue(for: .keychainMode) == "icloud")
        #expect(handler.handle(.get(name: "mail/personal")) == .success("hunter2"))
    }

    @Test
    func switchingToICloudWaitsWhenOnlyStaleLocalKeyExists() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vaultDirectory = homeDirectory.appendingPathComponent("Vault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let configStore = KeyConfigStore(homeDirectoryURL: homeDirectory)
        _ = try configStore.setValue(vaultDirectory.path(percentEncoded: false), for: .vaultDir)

        let store = EntryStore(rootURL: vaultDirectory)
        let originalKey = Data((0..<32).map(UInt8.init))
        let staleLocalKey = Data((32..<64).map(UInt8.init))
        let encrypted = try VaultCipher().encrypt("hunter2", keyData: originalKey)
        try store.save(encrypted, as: "mail/personal", overwrite: false)

        let keyStore = MemoryVaultKeyStore()
        keyStore.localKeyData = staleLocalKey
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: store,
            configStore: configStore
        )

        let response = handler.handle(.setKeychainMode(.icloud))
        #expect(response.exitCode == KeyExitCode.securityFailure.rawValue)
        #expect(response.errorMessage?.contains("wait for iCloud Keychain sync") == true)
        #expect(keyStore.iCloudKeyData == nil)
        #expect(try configStore.getValue(for: .keychainMode) == "local")
    }

    @Test
    func switchingToICloudAdoptsExistingSyncedKeyAndRepairsLocalMirror() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vaultDirectory = homeDirectory.appendingPathComponent("Vault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let configStore = KeyConfigStore(homeDirectoryURL: homeDirectory)
        _ = try configStore.setValue(vaultDirectory.path(percentEncoded: false), for: .vaultDir)

        let store = EntryStore(rootURL: vaultDirectory)
        let sharedKey = Data((0..<32).map(UInt8.init))
        let staleLocalKey = Data((32..<64).map(UInt8.init))
        let encrypted = try VaultCipher().encrypt("hunter2", keyData: sharedKey)
        try store.save(encrypted, as: "mail/personal", overwrite: false)

        let keyStore = MemoryVaultKeyStore()
        keyStore.localKeyData = staleLocalKey
        keyStore.iCloudKeyData = sharedKey
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: store,
            configStore: configStore
        )

        #expect(handler.handle(.setKeychainMode(.icloud)) == .success())
        #expect(keyStore.localKeyData == sharedKey)
        #expect(try configStore.getValue(for: .keychainMode) == "icloud")
        #expect(handler.handle(.get(name: "mail/personal")) == .success("hunter2"))
    }

    @Test
    func switchingBackToLocalRepairsMissingLocalMirrorFromICloud() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vaultDirectory = homeDirectory.appendingPathComponent("Vault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let configStore = KeyConfigStore(homeDirectoryURL: homeDirectory)
        _ = try configStore.setValue(vaultDirectory.path(percentEncoded: false), for: .vaultDir)
        _ = try configStore.setValue("icloud", for: .keychainMode)

        let store = EntryStore(rootURL: vaultDirectory)
        let sharedKey = Data((0..<32).map(UInt8.init))
        let encrypted = try VaultCipher().encrypt("hunter2", keyData: sharedKey)
        try store.save(encrypted, as: "mail/personal", overwrite: false)

        let keyStore = MemoryVaultKeyStore()
        keyStore.iCloudKeyData = sharedKey
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: store,
            keychainMode: .icloud,
            configStore: configStore
        )

        #expect(handler.handle(.setKeychainMode(.local)) == .success())
        #expect(keyStore.localKeyData == sharedKey)
        #expect(try configStore.getValue(for: .keychainMode) == "local")
        #expect(handler.handle(.get(name: "mail/personal")) == .success("hunter2"))
    }

    @Test
    func iCloudModeReadsRepairAStaleLocalMirror() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vaultDirectory = homeDirectory.appendingPathComponent("Vault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let configStore = KeyConfigStore(homeDirectoryURL: homeDirectory)
        _ = try configStore.setValue(vaultDirectory.path(percentEncoded: false), for: .vaultDir)
        _ = try configStore.setValue("icloud", for: .keychainMode)

        let store = EntryStore(rootURL: vaultDirectory)
        let sharedKey = Data((0..<32).map(UInt8.init))
        let staleLocalKey = Data((32..<64).map(UInt8.init))
        let encrypted = try VaultCipher().encrypt("hunter2", keyData: sharedKey)
        try store.save(encrypted, as: "mail/personal", overwrite: false)

        let keyStore = MemoryVaultKeyStore()
        keyStore.localKeyData = staleLocalKey
        keyStore.iCloudKeyData = sharedKey
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: store,
            keychainMode: .icloud,
            configStore: configStore
        )

        #expect(handler.handle(.get(name: "mail/personal")) == .success("hunter2"))
        #expect(keyStore.localKeyData == sharedKey)
    }

    @Test
    func switchingToICloudRejectsMixedKeyVaultBeforeRepairingLocalMirror() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vaultDirectory = homeDirectory.appendingPathComponent("Vault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let configStore = KeyConfigStore(homeDirectoryURL: homeDirectory)
        _ = try configStore.setValue(vaultDirectory.path(percentEncoded: false), for: .vaultDir)

        let sharedKey = Data((0..<32).map(UInt8.init))
        let otherEntryKey = Data((32..<64).map(UInt8.init))
        let staleLocalKey = Data((64..<96).map(UInt8.init))
        let store = EntryStore(rootURL: vaultDirectory)
        try saveMixedKeyEntries(in: store, acceptedKey: sharedKey, otherKey: otherEntryKey)

        let keyStore = MemoryVaultKeyStore()
        keyStore.localKeyData = staleLocalKey
        keyStore.iCloudKeyData = sharedKey
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: store,
            configStore: configStore
        )

        let response = handler.handle(.setKeychainMode(.icloud))

        #expect(response.errorCode == .vaultKeyMismatch)
        #expect(keyStore.storeCount == 0)
        #expect(keyStore.localKeyData == staleLocalKey)
        #expect(try configStore.getValue(for: .keychainMode) == "local")
    }

    @Test
    func switchingBackToLocalRejectsMixedKeyVaultBeforeRepairingLocalMirror() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vaultDirectory = homeDirectory.appendingPathComponent("Vault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let configStore = KeyConfigStore(homeDirectoryURL: homeDirectory)
        _ = try configStore.setValue(vaultDirectory.path(percentEncoded: false), for: .vaultDir)
        _ = try configStore.setValue("icloud", for: .keychainMode)

        let sharedKey = Data((0..<32).map(UInt8.init))
        let otherEntryKey = Data((32..<64).map(UInt8.init))
        let store = EntryStore(rootURL: vaultDirectory)
        try saveMixedKeyEntries(in: store, acceptedKey: sharedKey, otherKey: otherEntryKey)

        let keyStore = MemoryVaultKeyStore()
        keyStore.localKeyData = otherEntryKey
        keyStore.iCloudKeyData = sharedKey
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: store,
            keychainMode: .icloud,
            configStore: configStore
        )

        let response = handler.handle(.setKeychainMode(.local))

        #expect(response.errorCode == .vaultKeyMismatch)
        #expect(keyStore.storeCount == 0)
        #expect(keyStore.localKeyData == otherEntryKey)
        #expect(try configStore.getValue(for: .keychainMode) == "icloud")
    }

    @Test
    func iCloudModeReadRejectsMixedKeyVaultBeforeRepairingLocalMirror() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vaultDirectory = homeDirectory.appendingPathComponent("Vault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let configStore = KeyConfigStore(homeDirectoryURL: homeDirectory)
        _ = try configStore.setValue(vaultDirectory.path(percentEncoded: false), for: .vaultDir)
        _ = try configStore.setValue("icloud", for: .keychainMode)

        let sharedKey = Data((0..<32).map(UInt8.init))
        let otherEntryKey = Data((32..<64).map(UInt8.init))
        let store = EntryStore(rootURL: vaultDirectory)
        try saveMixedKeyEntries(in: store, acceptedKey: sharedKey, otherKey: otherEntryKey)

        let keyStore = MemoryVaultKeyStore()
        keyStore.localKeyData = otherEntryKey
        keyStore.iCloudKeyData = sharedKey
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: store,
            keychainMode: .icloud,
            configStore: configStore
        )

        let response = handler.handle(.get(name: "alpha/matching"))

        #expect(response.errorCode == .vaultKeyMismatch)
        #expect(keyStore.storeCount == 0)
        #expect(keyStore.localKeyData == otherEntryKey)
    }

    @Test
    func rejectsOverwriteWithoutForce() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let handler = KeyServiceHandler(
            keyStore: MemoryVaultKeyStore(),
            entryStore: EntryStore(rootURL: tempDirectory)
        )

        #expect(handler.handle(.addManual(name: "dup", secret: "one", type: .secret)) == .success())

        let secondResponse = handler.handle(.addManual(name: "dup", secret: "two", type: .secret))
        #expect(secondResponse.exitCode == KeyExitCode.conflict.rawValue)
        #expect(secondResponse.errorMessage?.contains("already exists") == true)
    }

    @Test
    func editUpdatesExistingSecretAndFailsForMissingEntry() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: EntryStore(rootURL: tempDirectory))

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "one", type: .secret)) == .success())
        #expect(handler.handle(.editManual(name: "mail/personal", secret: "two", type: .secret)) == .success())
        #expect(handler.handle(.get(name: "mail/personal")) == .success("two"))

        let missingResponse = handler.handle(.editManual(name: "missing", secret: "value", type: .secret))
        #expect(missingResponse.exitCode == KeyExitCode.notFound.rawValue)
        #expect(missingResponse.errorMessage?.contains("was not found") == true)
    }

    @Test
    func editRefusesToOverwriteWhenCurrentVaultKeyCannotDecryptExistingEntry() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let store = EntryStore(rootURL: tempDirectory)
        let originalKey = Data((0..<32).map(UInt8.init))
        let wrongKey = Data((32..<64).map(UInt8.init))
        let encrypted = try VaultCipher().encrypt("one", keyData: originalKey)
        try store.save(encrypted, as: "mail/personal", overwrite: false)

        let keyStore = MemoryVaultKeyStore()
        keyStore.keyData = wrongKey
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: store)

        let response = handler.handle(.editManual(name: "mail/personal", secret: "two", type: .secret))
        #expect(response.exitCode == KeyExitCode.securityFailure.rawValue)
        #expect(response.errorMessage?.contains("cannot decrypt 'mail/personal'") == true)

        let persisted = try store.load("mail/personal")
        let decrypted = try VaultCipher().decrypt(persisted, keyData: originalKey)
        #expect(decrypted == "one")
    }

    @Test
    func addThenGetReturnsCurrentTOTPCode() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: EntryStore(rootURL: tempDirectory),
            now: { Date(timeIntervalSince1970: 59) }
        )

        let addResponse = handler.handle(.addManual(
            name: "mail/mfa",
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            type: .totp
        ))
        #expect(addResponse == .success())
        #expect(handler.handle(.get(name: "mail/mfa")) == .success("287082"))
    }

    @Test
    func editCanConvertExistingSecretIntoTOTPEntry() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: EntryStore(rootURL: tempDirectory),
            now: { Date(timeIntervalSince1970: 59) }
        )

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "one", type: .secret)) == .success())
        #expect(handler.handle(.editManual(
            name: "mail/personal",
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            type: .totp
        )) == .success())
        #expect(handler.handle(.get(name: "mail/personal")) == .success("287082"))
    }

    @Test
    func copyDuplicatesEncryptedEntryWithoutKeyAccess() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: EntryStore(rootURL: tempDirectory))

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "one", type: .secret)) == .success())
        let loadCountBeforeCopy = keyStore.loadCount

        #expect(handler.handle(.copyEntry(source: "mail/personal", destination: "mail/work", force: false)) == .success())
        #expect(keyStore.loadCount == loadCountBeforeCopy)
        #expect(handler.handle(.get(name: "mail/work")) == .success("one"))

        let conflictResponse = handler.handle(.copyEntry(source: "mail/personal", destination: "mail/work", force: false))
        #expect(conflictResponse.exitCode == KeyExitCode.conflict.rawValue)
        #expect(conflictResponse.errorMessage?.contains("already exists") == true)
    }

    @Test
    func moveRenamesEncryptedEntryWithoutKeyAccess() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: EntryStore(rootURL: tempDirectory))

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "one", type: .secret)) == .success())
        let loadCountBeforeMove = keyStore.loadCount

        #expect(handler.handle(.moveEntry(source: "mail/personal", destination: "mail/work", force: false)) == .success())
        #expect(keyStore.loadCount == loadCountBeforeMove)
        #expect(handler.handle(.get(name: "mail/work")) == .success("one"))

        let oldResponse = handler.handle(.get(name: "mail/personal"))
        #expect(oldResponse.exitCode == KeyExitCode.notFound.rawValue)
        #expect(oldResponse.errorMessage?.contains("was not found") == true)

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "two", type: .secret)) == .success())
        let conflictResponse = handler.handle(.moveEntry(source: "mail/personal", destination: "mail/work", force: false))
        #expect(conflictResponse.exitCode == KeyExitCode.conflict.rawValue)
        #expect(conflictResponse.errorMessage?.contains("already exists") == true)
    }

    @Test
    func copiedAndMovedTOTPEntriesPreserveTheirType() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: EntryStore(rootURL: tempDirectory),
            now: { Date(timeIntervalSince1970: 59) }
        )

        #expect(handler.handle(.addManual(
            name: "mail/mfa",
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            type: .totp
        )) == .success())
        #expect(handler.handle(.copyEntry(source: "mail/mfa", destination: "mail/mfa-copy", force: false)) == .success())
        #expect(handler.handle(.moveEntry(source: "mail/mfa-copy", destination: "mail/mfa-moved", force: false)) == .success())
        #expect(handler.handle(.get(name: "mail/mfa-moved")) == .success("287082"))
    }

    @Test
    func removeDeletesEntryWithoutKeyAccessAndCleansEmptyDirectories() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let keyStore = MemoryVaultKeyStore()
        let store = EntryStore(rootURL: tempDirectory)
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: store)

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "one", type: .secret)) == .success())
        let loadCountBeforeRemove = keyStore.loadCount

        #expect(handler.handle(.removeEntry(name: "mail/personal")) == .success())
        #expect(keyStore.loadCount == loadCountBeforeRemove)

        let missingResponse = handler.handle(.get(name: "mail/personal"))
        #expect(missingResponse.exitCode == KeyExitCode.notFound.rawValue)
        #expect(missingResponse.errorMessage?.contains("was not found") == true)

        let parentDirectory = tempDirectory.appendingPathComponent("mail", isDirectory: true)
        #expect(FileManager.default.fileExists(atPath: parentDirectory.path(percentEncoded: false)) == false)
    }

    @Test
    func missingAndCorruptedFilesFail() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let store = EntryStore(rootURL: tempDirectory)
        let handler = KeyServiceHandler(keyStore: MemoryVaultKeyStore(), entryStore: store)

        let missingResponse = handler.handle(.get(name: "missing"))
        #expect(missingResponse.exitCode == KeyExitCode.notFound.rawValue)
        #expect(missingResponse.errorCode == .entryNotFound)
        #expect(missingResponse.errorMessage?.contains("was not found") == true)

        let brokenURL = try store.url(for: "broken")
        try FileManager.default.createDirectory(at: brokenURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("not-json".utf8).write(to: brokenURL)

        let corruptResponse = handler.handle(.get(name: "broken"))
        #expect(corruptResponse.exitCode == KeyExitCode.securityFailure.rawValue)
        #expect(corruptResponse.errorCode == .invalidSecretFile)
        #expect(corruptResponse.errorMessage?.contains("unreadable") == true)
    }

    @Test
    func listPrintsSortedEntryNames() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let handler = KeyServiceHandler(
            keyStore: MemoryVaultKeyStore(),
            entryStore: EntryStore(rootURL: tempDirectory)
        )

        #expect(handler.handle(.addManual(name: "zeta/one", secret: "one", type: .secret)) == .success())
        #expect(handler.handle(.addManual(name: "alpha/two", secret: "two", type: .secret)) == .success())

        let listResponse = handler.handle(.list)
        #expect(listResponse == .success("alpha/two\nzeta/one\n"))
    }

    private func saveMixedKeyEntries(
        in store: EntryStore,
        acceptedKey: Data,
        otherKey: Data
    ) throws {
        let cipher = VaultCipher()
        try store.save(
            cipher.encrypt("matching", keyData: acceptedKey),
            as: "alpha/matching",
            overwrite: false
        )
        try store.save(
            cipher.encrypt("other", keyData: otherKey),
            as: "zeta/other",
            overwrite: false
        )
    }
}

struct SessionVaultKeyStoreTests {
    @Test
    func reusesUnlockedSessionWithinTimeout() throws {
        let underlying = MemoryVaultKeyStore()
        let start = Date(timeIntervalSince1970: 1_000)
        var currentTime = start
        let store = SessionVaultKeyStore(
            underlying: underlying,
            inactivityTimeout: 60,
            now: { currentTime }
        )

        _ = try store.loadKey(mode: .local, reason: "first", createIfMissing: true)
        currentTime = start.addingTimeInterval(30)
        _ = try store.loadKey(mode: .local, reason: "second", createIfMissing: false)

        #expect(underlying.loadCount == 1)
        #expect(store.isUnlocked(at: currentTime) == true)
    }

    @Test
    func reauthenticatesAfterExpiry() throws {
        let underlying = MemoryVaultKeyStore()
        let start = Date(timeIntervalSince1970: 2_000)
        var currentTime = start
        let store = SessionVaultKeyStore(
            underlying: underlying,
            inactivityTimeout: 60,
            now: { currentTime }
        )

        _ = try store.loadKey(mode: .local, reason: "first", createIfMissing: true)
        currentTime = start.addingTimeInterval(61)
        _ = try store.loadKey(mode: .local, reason: "second", createIfMissing: false)

        #expect(underlying.loadCount == 2)
    }

    @Test
    func sessionStatusReflectsExpiryWithoutRefreshingTheSession() throws {
        let underlying = MemoryVaultKeyStore()
        let start = Date(timeIntervalSince1970: 2_000)
        var currentTime = start
        let store = SessionVaultKeyStore(
            underlying: underlying,
            inactivityTimeout: 60,
            now: { currentTime }
        )

        _ = try store.loadKey(mode: .local, reason: "first", createIfMissing: true)
        currentTime = start.addingTimeInterval(61)

        let status = store.sessionStatus(at: currentTime)
        #expect(status == .locked(inactivityTimeoutSeconds: 60))
        #expect(store.isUnlocked(at: currentTime) == false)
    }

    @Test
    func addThenGetReusesSessionAcrossHandlerRequests() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let underlying = MemoryVaultKeyStore()
        let store = SessionVaultKeyStore(underlying: underlying)
        let handler = KeyServiceHandler(keyStore: store, entryStore: EntryStore(rootURL: tempDirectory))

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "hunter2", type: .secret)) == .success())
        #expect(handler.handle(.get(name: "mail/personal")) == .success("hunter2"))
        #expect(underlying.loadCount == 1)
    }

    @Test
    func lockForcesNextKeyBackedRequestToReauthenticate() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let underlying = MemoryVaultKeyStore()
        let store = SessionVaultKeyStore(underlying: underlying)
        let handler = KeyServiceHandler(keyStore: store, entryStore: EntryStore(rootURL: tempDirectory))

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "hunter2", type: .secret)) == .success())
        #expect(handler.handle(.lock) == .success())
        #expect(store.isUnlocked() == false)
        #expect(handler.handle(.get(name: "mail/personal")) == .success("hunter2"))
        #expect(underlying.loadCount == 2)
    }

    @Test
    func authFailureDoesNotLeaveSessionUnlocked() throws {
        let underlying = MemoryVaultKeyStore()
        underlying.error = AppError.authFailed("Authentication was cancelled or failed.")
        let store = SessionVaultKeyStore(underlying: underlying)

        #expect(throws: AppError.authFailed("Authentication was cancelled or failed.")) {
            _ = try store.loadKey(mode: .local, reason: "unlock", createIfMissing: false)
        }
        #expect(store.isUnlocked() == false)
    }

    @Test
    func invalidateClearsSession() throws {
        let underlying = MemoryVaultKeyStore()
        let store = SessionVaultKeyStore(underlying: underlying)

        _ = try store.loadKey(mode: .local, reason: "unlock", createIfMissing: true)
        #expect(store.isUnlocked() == true)

        store.invalidate()

        #expect(store.isUnlocked() == false)
    }
}

struct KeyAppDiagnosticsCollectorTests {
    @Test
    func doesNotQueryHelperStatusWhenHelperIsNotRunning() {
        var helperStatusProbeCount = 0
        let collector = KeyAppDiagnosticsCollector(
            context: .testFixture(),
            registrationProbe: {
                .registered(detail: "ready")
            },
            runningProbe: {
                false
            },
            helperStatusProbe: {
                helperStatusProbeCount += 1
                return .locked(inactivityTimeoutSeconds: 900)
            },
            shellCLIProbe: {
                ShellCLIStatus(
                    resolvedPath: "/opt/homebrew/bin/key",
                    version: KeyVersionInfo(marketingVersion: "0.1.0", buildVersion: "1")
                )
            },
            now: {
                Date(timeIntervalSince1970: 10_000)
            }
        )

        let snapshot = collector.load()
        #expect(snapshot.isHelperRunning == false)
        #expect(snapshot.helperStatus == nil)
        #expect(helperStatusProbeCount == 0)
    }

    @Test
    func recordsHelperStatusErrorsWhenHelperStatusProbeFails() {
        let collector = KeyAppDiagnosticsCollector(
            context: .testFixture(),
            registrationProbe: {
                .registered(detail: "ready")
            },
            runningProbe: {
                true
            },
            helperStatusProbe: {
                throw AppError.service("Key Agent returned no helper status.")
            },
            shellCLIProbe: {
                ShellCLIStatus(
                    resolvedPath: "/opt/homebrew/bin/key",
                    version: KeyVersionInfo(marketingVersion: "0.1.0", buildVersion: "1")
                )
            }
        )

        let snapshot = collector.load()
        #expect(snapshot.helperStatus == nil)
        #expect(snapshot.helperStatusErrorDescription == "Key Agent returned no helper status.")
    }

    @Test
    func reportsVersionMismatchAgainstShellCLI() {
        let snapshot = KeyAppDiagnosticsCollector(
            context: .testFixture(),
            registrationProbe: {
                .registered(detail: "ready")
            },
            runningProbe: {
                false
            },
            helperStatusProbe: {
                .locked(inactivityTimeoutSeconds: 900)
            },
            shellCLIProbe: {
                ShellCLIStatus(
                    resolvedPath: "/usr/local/bin/key",
                    version: KeyVersionInfo(marketingVersion: "0.1.0", buildVersion: "2")
                )
            }
        ).load()

        #expect(snapshot.shellCLIStatus.matchState(appVersion: snapshot.context.appVersion) == .mismatch)
        #expect(snapshot.hero.title == "Welcome to Key")
        #expect(snapshot.callout?.title == "CLI version mismatch")
    }

    @Test
    func reportsMatchingShellCLIVersion() {
        let snapshot = KeyAppDiagnosticsCollector(
            context: .testFixture(),
            registrationProbe: {
                .registered(detail: "ready")
            },
            runningProbe: {
                false
            },
            helperStatusProbe: {
                .locked(inactivityTimeoutSeconds: 900)
            },
            shellCLIProbe: {
                ShellCLIStatus(
                    resolvedPath: "/opt/homebrew/bin/key",
                    version: KeyVersionInfo(marketingVersion: "0.1.0", buildVersion: "1"),
                    resolutionSource: .homebrewInstall
                )
            }
        ).load()

        #expect(snapshot.shellCLIStatus.matchState(appVersion: snapshot.context.appVersion) == .matches)
        #expect(snapshot.shellCLIStatus.resolutionSummary == "Homebrew install path")
        #expect(snapshot.callout == nil)
    }

    @Test
    func reportsBundledCLIGuidanceWhenShellCLIMissing() {
        let snapshot = KeyAppDiagnosticsCollector(
            context: .testFixture(),
            registrationProbe: {
                .registered(detail: "ready")
            },
            runningProbe: {
                false
            },
            helperStatusProbe: {
                .locked(inactivityTimeoutSeconds: 900)
            },
            shellCLIProbe: {
                ShellCLIStatus(resolvedPath: nil, version: nil)
            }
        ).load()

        #expect(snapshot.shellCLIStatus.matchState(appVersion: snapshot.context.appVersion) == .missing)
        #expect(snapshot.callout?.title == "External CLI not found")
        #expect(snapshot.callout?.guidance.first?.command == "\"/Applications/Key.app/Contents/MacOS/key\" unlock")
    }

    @Test
    func compressesLegacyShellCLIVersionHelpIntoConciseCallout() {
        let snapshot = KeyAppDiagnosticsCollector(
            context: .testFixture(),
            registrationProbe: {
                .registered(detail: "ready")
            },
            runningProbe: {
                false
            },
            helperStatusProbe: {
                .locked(inactivityTimeoutSeconds: 900)
            },
            shellCLIProbe: {
                ShellCLIStatus(
                    resolvedPath: "/usr/local/bin/key",
                    version: nil,
                    versionErrorDescription: "Unknown command 'version'.\n\n\(CLIParser.usageText)"
                )
            }
        ).load()

        #expect(snapshot.callout?.title == "CLI version unavailable")
        #expect(snapshot.callout?.detail.contains("Usage:") == false)
        #expect(snapshot.callout?.detail.contains("does not support `key version` yet.") == true)
        #expect(snapshot.callout?.guidance.first?.command == "\"/Applications/Key.app/Contents/MacOS/key\" version")
    }

    @Test
    func includesDefaultVaultLocationSource() {
        let snapshot = KeyAppDiagnosticsCollector(
            context: .testFixture(),
            registrationProbe: {
                .registered(detail: "ready")
            },
            runningProbe: {
                true
            },
            helperStatusProbe: {
                KeyHelperStatus(
                    isUnlocked: true,
                    sessionExpiresAt: Date(timeIntervalSince1970: 10_600),
                    inactivityTimeoutSeconds: 900
                )
            },
            shellCLIProbe: {
                ShellCLIStatus(
                    resolvedPath: "/opt/homebrew/bin/key",
                    version: KeyVersionInfo(marketingVersion: "0.1.0", buildVersion: "1")
                )
            },
            now: {
                Date(timeIntervalSince1970: 10_000)
            }
        ).load()

        #expect(snapshot.context.configFilePath == "/Users/test/Library/Application Support/Key/config.toml")
        #expect(snapshot.context.vaultDirectoryPath == "/Users/test/.key")
        #expect(snapshot.context.vaultLocationSource == "App Support config (default)")
        #expect(snapshot.hero.title == "Welcome to Key")
        #expect(snapshot.callout == nil)
    }

    @Test
    func heroRemainsInformationalWhenHelperIsLockedButHealthy() {
        let snapshot = KeyAppDiagnosticsCollector(
            context: .testFixture(),
            registrationProbe: {
                .registered(detail: "ready")
            },
            runningProbe: {
                true
            },
            helperStatusProbe: {
                .locked(inactivityTimeoutSeconds: 900)
            },
            shellCLIProbe: {
                ShellCLIStatus(
                    resolvedPath: "/opt/homebrew/bin/key",
                    version: KeyVersionInfo(marketingVersion: "0.1.0", buildVersion: "1")
                )
            }
        ).load()

        #expect(snapshot.hero.title == "Welcome to Key")
        #expect(snapshot.callout == nil)
    }
}

private extension KeyAppDiagnosticsContext {
    static func testFixture() -> KeyAppDiagnosticsContext {
        KeyAppDiagnosticsContext(
            appVersion: KeyVersionInfo(marketingVersion: "0.1.0", buildVersion: "1"),
            bundledCLIPath: "/Applications/Key.app/Contents/MacOS/key",
            helperAppPath: "/Applications/Key.app/Contents/Helpers/Key Agent.app",
            helperExecutablePath: "/Applications/Key.app/Contents/Helpers/Key Agent.app/Contents/MacOS/Key Agent",
            launchAgentPlistPath: "/Applications/Key.app/Contents/Library/LaunchAgents/work.tvr.key.agent.plist",
            machServiceName: "work.tvr.key.agent",
            configFilePath: "/Users/test/Library/Application Support/Key/config.toml",
            vaultDirectoryPath: "/Users/test/.key",
            vaultLocationSource: "App Support config (default)"
        )
    }
}
