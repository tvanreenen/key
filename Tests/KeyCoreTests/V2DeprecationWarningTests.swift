import Foundation
import Testing
@testable import KeyCore

struct V2DeprecationWarningTests {
    @Test(arguments: [false, true], [false, true])
    func statusWarningPreservesPayloadAndExitCode(isV3: Bool, terminal: Bool) throws {
        let home = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: home) }
        for health: VaultHealth in [.ready, .incomplete, .recoveryRequired] {
            for flags in [[], ["--verbose"], ["--json"]] {
                let status = VaultStatus(
                    format: isV3 ? .version3 : .version2,
                    health: health,
                    entries: .effective(2)
                )
                let transport = MemoryTransport { request in
                    #expect(request == .vaultStatus)
                    return .vaultStatus(status)
                }
                let io = MemoryIO(stdinIsTTY: false, stdoutIsTTY: terminal)
                let app = KeyCLIApplication(
                    transport: transport,
                    io: io,
                    clipboard: MemoryClipboard(),
                    configStore: KeyConfigStore(homeDirectoryURL: home)
                )
                #expect(app.run(arguments: ["status"] + flags) == health.exitCode.rawValue)
                #expect(transport.requests == [.vaultStatus])
                let json = flags == ["--json"]
                if json {
                    let decoded = try JSONDecoder().decode(
                        VaultStatus.self,
                        from: Data(io.stdout.utf8)
                    )
                    #expect(decoded == status)
                    #expect(!io.stdout.contains("deprecated"))
                } else {
                    if flags.contains("--verbose") {
                        #expect(io.stdout.contains("Storage format: version \(isV3 ? 3 : 2)\n"))
                    } else {
                        #expect(!io.stdout.contains("Storage format:"))
                    }
                    #expect(io.stdout.contains("Entries: 2\n"))
                    #expect(!io.stdout.contains("Warning:"))
                }
                if !isV3 && terminal && !json {
                    #expect(io.stderr.components(separatedBy: "Warning:").count == 2)
                    #expect(io.stderr.contains("key migrate --check"))
                    #expect(io.stderr.contains("without changing the vault"))
                    #expect(io.stderr.contains("other-Mac setup and recovery limits"))
                } else {
                    #expect(io.stderr.isEmpty)
                }
                // Format comes from the helper, not a new local config read.
                #expect(!FileManager.default.fileExists(atPath: home.path))
            }
        }
    }

    @Test(arguments: [false, true])
    func failedStatusDoesNotAddAMisleadingWarning(terminal: Bool) {
        let io = MemoryIO(stdinIsTTY: false, stdoutIsTTY: terminal)
        let failure = KeyServiceResponse.failure(
            AppError.operationRefused("Configuration changed; run key lock.")
        )
        let app = KeyCLIApplication(
            transport: MemoryTransport { _ in failure },
            io: io,
            clipboard: MemoryClipboard()
        )
        #expect(app.run(arguments: ["status"]) == failure.exitCode)
        #expect(io.stdout.isEmpty)
        #expect(io.stderr == "Configuration changed; run key lock.\n")
    }

    @Test(arguments: [false, true])
    func ordinaryCommandsDoNotProbeConfigOrAddWarnings(terminal: Bool) throws {
        let home = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: home) }
        for arguments in [
            ["get", "test"], ["copy", "test"], ["list"], ["unlock"], ["lock"],
            ["add", "test"], ["edit", "test"], ["duplicate", "test", "other"],
            ["rename", "test", "other"], ["remove", "test", "--force"],
            ["migrate", "--check"], ["migrate", "--apply"]
        ] {
            let io = MemoryIO(
                stdinIsTTY: false,
                stdoutIsTTY: terminal,
                pipedInput: "input secret"
            )
            let transport = MemoryTransport { _ in .success("test value") }
            let clipboard = MemoryClipboard()
            let app = KeyCLIApplication(
                transport: transport,
                io: io,
                clipboard: clipboard,
                configStore: KeyConfigStore(homeDirectoryURL: home)
            )
            #expect(app.run(arguments: arguments) == EXIT_SUCCESS)
            #expect(transport.requests.count == 1)
            #expect(io.stderr.isEmpty)
            if arguments.first == "get" {
                #expect(io.stdout == "test value" + (terminal ? "\n" : ""))
            } else if ["list", "unlock", "lock", "migrate"].contains(arguments[0]) {
                #expect(io.stdout == "test value")
            } else {
                #expect(io.stdout.isEmpty)
            }
            #expect(!FileManager.default.fileExists(atPath: home.path))
        }
    }
}
