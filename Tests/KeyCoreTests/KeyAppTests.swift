import Foundation
import Testing
@testable import KeyCore

struct KeyCLIApplicationTests {
    @Test
    func showCopyWritesToClipboardWithoutStdout() throws {
        let transport = MemoryTransport { request in
            #expect(request == .get(name: "mail/personal"))
            return .success("hunter2")
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["show", "mail/personal", "--copy"]) == EXIT_SUCCESS)
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
    func generatedAddSucceedsWithoutOutput() throws {
        let transport = MemoryTransport { request in
            #expect(request == .addGenerated(name: "demo/token", length: 32, revealMode: .none))
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["add", "demo/token", "--generate", "--length", "32"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(clipboard.copiedText == nil)
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
    func generatedEditSucceedsWithoutOutput() throws {
        let transport = MemoryTransport { request in
            #expect(request == .editGenerated(name: "demo/token", length: 32, revealMode: .none))
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["edit", "demo/token", "--generate", "--length", "32"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(clipboard.copiedText == nil)
    }

    @Test
    func copySendsEncryptedCopyRequest() throws {
        let transport = MemoryTransport { request in
            #expect(request == .copyEntry(source: "src/token", destination: "dst/token", force: true))
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["cp", "src/token", "dst/token", "--force"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(io.stderr == "")
    }

    @Test
    func moveSendsEncryptedMoveRequest() throws {
        let transport = MemoryTransport { request in
            #expect(request == .moveEntry(source: "src/token", destination: "dst/token", force: true))
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["mv", "src/token", "dst/token", "--force"]) == EXIT_SUCCESS)
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

        #expect(app.run(arguments: ["rm", "src/token"]) == EXIT_SUCCESS)
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

        #expect(app.run(arguments: ["rm", "src/token"]) == EXIT_FAILURE)
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

        #expect(app.run(arguments: ["rm", "src/token", "--force"]) == EXIT_SUCCESS)
        #expect(io.stderr == "")
    }
}

struct KeyServiceHandlerTests {
    @Test
    func putThenGetRoundTripsSecret() throws {
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
    func generatedPutStoresSecretAndSuppressesRevealByDefault() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let keyStore = MemoryVaultKeyStore()
        let generator = SecretGenerator(alphabet: "A")
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: EntryStore(rootURL: tempDirectory),
            generator: generator
        )

        let putResponse = handler.handle(.addGenerated(name: "aws/prod/token", length: 8, revealMode: .none))
        #expect(putResponse == .success())

        let getResponse = handler.handle(.get(name: "aws/prod/token"))
        #expect(getResponse == .success("AAAAAAAA"))
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
