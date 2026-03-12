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
            #expect(request == .putManual(name: "aws/prod/token", secret: "hunter2", force: false))
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
            #expect(request == .putGenerated(name: "demo/token", length: 32, force: false, revealMode: .none))
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["add", "demo/token", "--generate", "--length", "32"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(clipboard.copiedText == nil)
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

        let putResponse = handler.handle(.putManual(name: "mail/personal", secret: "hunter2", force: false))
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

        let putResponse = handler.handle(.putGenerated(name: "aws/prod/token", length: 8, force: false, revealMode: .none))
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

        #expect(handler.handle(.putManual(name: "dup", secret: "one", force: false)) == .success())

        let secondResponse = handler.handle(.putManual(name: "dup", secret: "two", force: false))
        #expect(secondResponse.exitCode == EXIT_FAILURE)
        #expect(secondResponse.errorMessage?.contains("already exists") == true)
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

        #expect(handler.handle(.putManual(name: "zeta/one", secret: "one", force: false)) == .success())
        #expect(handler.handle(.putManual(name: "alpha/two", secret: "two", force: false)) == .success())

        let listResponse = handler.handle(.list)
        #expect(listResponse == .success("alpha/two\nzeta/one\n"))
    }
}
