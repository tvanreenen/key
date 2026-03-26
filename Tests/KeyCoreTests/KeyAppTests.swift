import Foundation
import Testing
@testable import KeyCore

struct KeyCLIApplicationTests {
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
            #expect(request == .addManual(name: "aws/prod/token", secret: "hunter2"))
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
    func manualEditReadsPipedInputAndSendsItToService() throws {
        let transport = MemoryTransport { request in
            #expect(request == .editManual(name: "aws/prod/token", secret: "hunter2"))
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

        let putResponse = handler.handle(.addManual(name: "mail/personal", secret: "hunter2"))
        #expect(putResponse == .success())

        let getResponse = handler.handle(.get(name: "mail/personal"))
        #expect(getResponse == .success("hunter2"))
        #expect(keyStore.loadCount == 2)
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

        #expect(handler.handle(.addManual(name: "dup", secret: "one")) == .success())

        let secondResponse = handler.handle(.addManual(name: "dup", secret: "two"))
        #expect(secondResponse.exitCode == EXIT_FAILURE)
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

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "one")) == .success())
        #expect(handler.handle(.editManual(name: "mail/personal", secret: "two")) == .success())
        #expect(handler.handle(.get(name: "mail/personal")) == .success("two"))

        let missingResponse = handler.handle(.editManual(name: "missing", secret: "value"))
        #expect(missingResponse.exitCode == EXIT_FAILURE)
        #expect(missingResponse.errorMessage?.contains("was not found") == true)
    }

    @Test
    func copyDuplicatesEncryptedEntryWithoutKeyAccess() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: EntryStore(rootURL: tempDirectory))

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "one")) == .success())
        let loadCountBeforeCopy = keyStore.loadCount

        #expect(handler.handle(.copyEntry(source: "mail/personal", destination: "mail/work", force: false)) == .success())
        #expect(keyStore.loadCount == loadCountBeforeCopy)
        #expect(handler.handle(.get(name: "mail/work")) == .success("one"))

        let conflictResponse = handler.handle(.copyEntry(source: "mail/personal", destination: "mail/work", force: false))
        #expect(conflictResponse.exitCode == EXIT_FAILURE)
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

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "one")) == .success())
        let loadCountBeforeMove = keyStore.loadCount

        #expect(handler.handle(.moveEntry(source: "mail/personal", destination: "mail/work", force: false)) == .success())
        #expect(keyStore.loadCount == loadCountBeforeMove)
        #expect(handler.handle(.get(name: "mail/work")) == .success("one"))

        let oldResponse = handler.handle(.get(name: "mail/personal"))
        #expect(oldResponse.exitCode == EXIT_FAILURE)
        #expect(oldResponse.errorMessage?.contains("was not found") == true)

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "two")) == .success())
        let conflictResponse = handler.handle(.moveEntry(source: "mail/personal", destination: "mail/work", force: false))
        #expect(conflictResponse.exitCode == EXIT_FAILURE)
        #expect(conflictResponse.errorMessage?.contains("already exists") == true)
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

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "one")) == .success())
        let loadCountBeforeRemove = keyStore.loadCount

        #expect(handler.handle(.removeEntry(name: "mail/personal")) == .success())
        #expect(keyStore.loadCount == loadCountBeforeRemove)

        let missingResponse = handler.handle(.get(name: "mail/personal"))
        #expect(missingResponse.exitCode == EXIT_FAILURE)
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
        #expect(missingResponse.exitCode == EXIT_FAILURE)
        #expect(missingResponse.errorMessage?.contains("was not found") == true)

        let brokenURL = try store.url(for: "broken")
        try FileManager.default.createDirectory(at: brokenURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("not-json".utf8).write(to: brokenURL)

        let corruptResponse = handler.handle(.get(name: "broken"))
        #expect(corruptResponse.exitCode == EXIT_FAILURE)
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

        #expect(handler.handle(.addManual(name: "zeta/one", secret: "one")) == .success())
        #expect(handler.handle(.addManual(name: "alpha/two", secret: "two")) == .success())

        let listResponse = handler.handle(.list)
        #expect(listResponse == .success("alpha/two\nzeta/one\n"))
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

        _ = try store.loadKey(reason: "first", createIfMissing: true)
        currentTime = start.addingTimeInterval(30)
        _ = try store.loadKey(reason: "second", createIfMissing: false)

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

        _ = try store.loadKey(reason: "first", createIfMissing: true)
        currentTime = start.addingTimeInterval(61)
        _ = try store.loadKey(reason: "second", createIfMissing: false)

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

        _ = try store.loadKey(reason: "first", createIfMissing: true)
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

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "hunter2")) == .success())
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

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "hunter2")) == .success())
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
            _ = try store.loadKey(reason: "unlock", createIfMissing: false)
        }
        #expect(store.isUnlocked() == false)
    }

    @Test
    func invalidateClearsSession() throws {
        let underlying = MemoryVaultKeyStore()
        let store = SessionVaultKeyStore(underlying: underlying)

        _ = try store.loadKey(reason: "unlock", createIfMissing: true)
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
        #expect(snapshot.callout?.title == "Shell CLI version mismatch")
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
                    version: KeyVersionInfo(marketingVersion: "0.1.0", buildVersion: "1")
                )
            }
        ).load()

        #expect(snapshot.shellCLIStatus.matchState(appVersion: snapshot.context.appVersion) == .matches)
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

        #expect(snapshot.callout?.title == "Shell CLI version unavailable")
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

        #expect(snapshot.context.vaultDirectoryPath == "/Users/test/Library/Application Support/key/vault")
        #expect(snapshot.context.vaultLocationSource == "Default")
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
            vaultDirectoryPath: "/Users/test/Library/Application Support/key/vault",
            vaultLocationSource: "Default"
        )
    }
}
