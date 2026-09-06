import Foundation
import Testing
@testable import KeyCore

struct UserFacingHelpTests {
    @Test(arguments: [
        "init", "share", "config", "migrate", "status", "conflict", "get", "copy",
        "add", "edit", "duplicate", "rename", "remove", "unlock", "lock", "list", "version",
        "config get", "config set", "config list",
        "conflict list", "conflict show", "conflict get", "conflict copy", "conflict resolve",
        "share devices", "share invite", "share invitations", "share join", "share requests",
        "share compare", "share approve", "share accept", "share revoke"
    ])
    func helpDoesNotContactTheServiceOrCreateConfiguration(topic: String) throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let config = KeyConfigStore(homeDirectoryURL: home)
        let transport = MemoryTransport { _ in
            Issue.record("Help must not contact the background service")
            return .failure("Unexpected request")
        }
        let words = topic.split(separator: " ").map(String.init)
        for arguments in [["help"] + words, words + ["--help"], words + ["-h"]] {
            let io = MemoryIO(stdinIsTTY: false, stdoutIsTTY: false)
            let app = KeyCLIApplication(
                transport: transport, io: io, clipboard: MemoryClipboard(),
                configStore: config
            )
            #expect(app.run(arguments: arguments) == EXIT_SUCCESS)
            #expect(io.stdout == CLIParser.helpText(for: topic)! + "\n")
            #expect(io.stderr.isEmpty)
        }
        #expect(transport.requests.isEmpty)
        #expect(!FileManager.default.fileExists(atPath: home.path))
    }

    @Test(arguments: [
        [String](), ["config"], ["share"], ["conflict"], ["unknown"],
        ["migrate"], ["migrate", "--check", "--apply"],
        ["status", "--json", "--verbose"], ["add", "entry", "extra-value"],
        ["edit", "entry", "--secret", "extra-value"], ["get"], ["remove"],
        ["conflict", "resolve"], ["conflict", "resolve", "a="],
        ["share", "invite", "--name", "First", "--name", "Second"],
        ["share", "join", "id", "--name=First", "--name=Second"],
        ["share", "invitations", "--vault-dir=a", "--vault-dir=b"],
        ["share", "approve", "vault", "invitation", "code", "--vault-dir=a"]
    ])
    func invalidArgumentsKeepUsageExitCodeAndNeverReachTheService(arguments: [String]) {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let io = MemoryIO(stdinIsTTY: false, stdoutIsTTY: false)
        let transport = MemoryTransport { _ in
            Issue.record("Invalid arguments must not contact the service")
            return .failure("Unexpected request")
        }
        let app = KeyCLIApplication(
            transport: transport, io: io, clipboard: MemoryClipboard(),
            configStore: KeyConfigStore(homeDirectoryURL: home)
        )
        #expect(app.run(arguments: arguments) == KeyServiceErrorCode.invalidUsage.exitCode.rawValue)
        #expect(io.stdout.isEmpty)
        #expect(io.stderr.contains("USAGE:") || io.stderr.contains("Usage:"))
        #expect(transport.requests.isEmpty)
        #expect(!FileManager.default.fileExists(atPath: home.path))
    }

    @Test
    func helpStatesConsequencesInsteadOfPromisingRecovery() throws {
        let share = try #require(CLIParser.helpText(for: "share")).split(whereSeparator: \.isWhitespace).joined(separator: " ")
        #expect(share.contains("any secrets and older vault data it already obtained"))
        #expect(share.contains("Stop if they differ"))
        let initHelp = try #require(CLIParser.helpText(for: "init")).split(whereSeparator: \.isWhitespace).joined(separator: " ")
        #expect(initHelp.contains("do not delete them to force a retry"))
        #expect(initHelp.contains("never replaces existing configuration"))
        #expect(initHelp.contains("may still have files waiting to download"))
        let read = try #require(CLIParser.helpText(for: "get")).split(whereSeparator: \.isWhitespace).joined(separator: " ")
        #expect(read.contains("may be out of date"))
        #expect(read.contains("does not bypass failed security checks"))
    }

    @Test
    func readyHumanStatusOmitsFormatButVerboseAndJSONRetainIt() throws {
        let status = VaultStatus(format: .version3, health: .ready, entries: .effective(2))
        for flags in [[], ["--verbose"], ["--json"]] {
            let io = MemoryIO(stdinIsTTY: false, stdoutIsTTY: false)
            let app = KeyCLIApplication(
                transport: MemoryTransport { _ in .vaultStatus(status) },
                io: io, clipboard: MemoryClipboard()
            )
            #expect(app.run(arguments: ["status"] + flags) == EXIT_SUCCESS)
            if flags == ["--json"] {
                #expect(try JSONDecoder().decode(VaultStatus.self, from: Data(io.stdout.utf8)) == status)
            } else {
                #expect(io.stdout.contains("Vault is ready."))
                #expect(io.stdout.contains("version 3") == flags.contains("--verbose"))
            }
        }
    }
}
