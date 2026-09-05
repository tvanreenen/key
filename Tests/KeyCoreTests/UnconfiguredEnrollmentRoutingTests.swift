import Foundation
import Testing
@testable import KeyCore

struct UnconfiguredEnrollmentRoutingTests {
    private let invite = String(repeating: "a", count: 64)
    private let vault = "018f4d38-7d5a-7b20-b0f1-97d6e96c4504"

    @Test
    func parserAcceptsDirectoryOnlyOnSupportedCommands() throws {
        let commands = [
            ["invitations"], ["join", invite, "--name", "Laptop"],
            ["compare", vault, invite], ["accept", vault, invite, "code"]
        ]
        for arguments in commands {
            guard case let .share(command, _) = try CLIParser.parse(arguments: ["share"] + arguments) else {
                Issue.record("Expected share command"); continue
            }
            for expanded in [arguments + ["--vault-dir", "Key Vault"], [arguments[0], "--vault-dir", "Key Vault"] + arguments.dropFirst()] {
                #expect(try CLIParser.parse(arguments: ["share"] + expanded) == .share(command, vaultDirectory: "Key Vault"))
            }
        }
        for arguments in [
            ["invitations", "--vault-dir"], ["invitations", "--vault-dir", ""],
            ["invitations", "--vault-dir", "bad\0path"],
            ["invitations", "--vault-dir", "a", "--vault-dir", "b"],
            ["devices", "--vault-dir", "a"], ["invite", "--name", "Mac", "--vault-dir", "a"],
            ["approve", vault, invite, "code", "--vault-dir", "a"]
        ] {
            #expect(throws: AppError.self) { try CLIParser.parse(arguments: ["share"] + arguments) }
        }
    }

    @Test(arguments: [false, true], [false, true])
    func cliResolvesFolderBeforeSendingAndConfiguredMacIgnoresCWD(configured: Bool, explicit: Bool) throws {
        let home = try temporaryHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let current = home.appendingPathComponent("Current")
        let config = KeyConfigStore(homeDirectoryURL: home)
        let selected = home.appendingPathComponent("Selected")
        if configured { try writeLegacyTestConfiguration(home: home, root: selected) }
        let expected = explicit ? current.appendingPathComponent("Other Vault") : (configured ? selected : current)
        let transport = MemoryTransport { request in
            #expect(request == .shareInDirectory(request: .invitations, path: expected.path))
            return .success("Invitations\n")
        }
        let io = MemoryIO(stdinIsTTY: false)
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: MemoryClipboard(), configStore: config, currentDirectory: { current })
        #expect(app.run(arguments: ["share", "invitations"] + (explicit ? ["--vault-dir", "Other Vault"] : [])) == EXIT_SUCCESS)
        #expect(io.stderr.contains(expected.path))
        #expect(try config.hasConfiguration() == configured)
        #expect(!FileManager.default.fileExists(atPath: current.path))
    }

    @Test
    func protocolRoundTripsAndOnlyAcceptanceRequiresRestart() throws {
        let requests: [KeyShareRequest] = [.invitations, .join(invitationID: invite, deviceName: "Laptop"), .compare(vaultID: vault, invitationID: invite, joinRequestID: nil), .accept(vaultID: vault, invitationID: invite, comparisonCode: "code")]
        for action in requests {
            let request = KeyServiceRequest.shareInDirectory(request: action, path: "/tmp/Key Vault")
            #expect(try JSONDecoder().decode(KeyServiceRequest.self, from: JSONEncoder().encode(request)) == request)
            #expect(KeyXPCClientRole.fullCLI.authorizes(request))
            #expect(!KeyXPCClientRole.utilityStatus.authorizes(request))
            #expect(request.requiresHelperShutdownAfterSuccess == (action == requests.last))
            #expect(request.responseTimeoutSeconds == nil)
        }
    }

    @Test
    func malformedConfigurationNeverFallsBackToCurrentDirectory() throws {
        let home = try temporaryHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let config = KeyConfigStore(homeDirectoryURL: home)
        let file = config.initializationConfigFileURL
        try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        let bytes = Data("malformed".utf8)
        try bytes.write(to: file)
        let io = MemoryIO(stdinIsTTY: false)
        let app = KeyCLIApplication(transport: MemoryTransport { _ in
            Issue.record("Broken config must not select another folder"); return .success()
        }, io: io, clipboard: MemoryClipboard(), configStore: config, currentDirectory: { home })
        #expect(app.run(arguments: ["share", "invitations"]) != EXIT_SUCCESS)
        #expect(try Data(contentsOf: file) == bytes)
    }

    @Test
    func configuredHostRefusesDifferentFolderAndPreservesNormalEnrollment() {
        var calls = 0
        let host = KeyServiceHost(hasConfiguration: { true }, makeHandler: {
            { request in
                #expect(request == .share(.invitations))
                calls += 1
                return .success("Configured")
            }
        }, initialize: { _ in Issue.record("No init"); return "" }, configuredDirectory: { URL(fileURLWithPath: "/selected") }, enroll: { _, _ in
            Issue.record("Must not enter unconfigured enrollment"); return .success()
        })
        #expect(host.handle(.shareInDirectory(request: .invitations, path: "/elsewhere")).exitCode != EXIT_SUCCESS)
        #expect(calls == 0)
        #expect(host.handle(.shareInDirectory(request: .invitations, path: "/selected")) == .success("Configured"))
        #expect(calls == 1)
    }

    @Test
    func unconfiguredHostNeverComposesLegacyRuntimeAndBlocksWorkAfterAcceptance() {
        var calls = 0
        let host = KeyServiceHost(hasConfiguration: { false }, makeHandler: {
            Issue.record("Must not compose v2"); return { _ in .success() }
        }, initialize: { _ in "" }, enroll: { _, path in
            #expect(path == "/selected")
            calls += 1
            return .success("Enrollment")
        })
        #expect(host.handle(.shareInDirectory(request: .invite(deviceName: "Mac"), path: "/selected")).exitCode != EXIT_SUCCESS)
        #expect(calls == 0)
        #expect(host.handle(.shareInDirectory(request: .invitations, path: "/selected")).exitCode == EXIT_SUCCESS)
        #expect(host.handle(.list).exitCode != EXIT_SUCCESS)
        #expect(host.handle(.shareInDirectory(request: .accept(vaultID: vault, invitationID: invite, comparisonCode: "code"), path: "/selected")).exitCode == EXIT_SUCCESS)
        #expect(host.handle(.shareInDirectory(request: .invitations, path: "/selected")).errorMessage?.contains("restarting") == true)
        #expect(host.handle(.lock) == .success())
        #expect(calls == 2)
    }

    @Test
    func discoveryAndUnavailableInvitationDoNotCreateLocalState() throws {
        let home = try temporaryHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let root = home.appendingPathComponent("Vault")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        let config = KeyConfigStore(homeDirectoryURL: home)
        let service = V3UnconfiguredEnrollmentService(configStore: config, exchange: {
            V3EnrollmentExchangeCoordinator(mailbox: V3FilesystemEnrollmentMailbox(rootHandle: $0), stateStore: NoEnrollmentState())
        }, perform: { _, _, _ in Issue.record("No identity or adoption before admission"); return .success() })
        #expect(try service.handle(.invitations, path: root.path).value?.contains("No enrollment invitations") == true)
        #expect(throws: (any Error).self) { try service.handle(.join(invitationID: invite, deviceName: "Laptop"), path: root.path) }
        #expect(throws: (any Error).self) { try service.handle(.accept(vaultID: vault, invitationID: invite, comparisonCode: "code"), path: root.path) }
        let missing = home.appendingPathComponent("Missing")
        #expect(throws: (any Error).self) { try service.handle(.invitations, path: missing.path) }
        let link = home.appendingPathComponent("Link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: root)
        #expect(throws: (any Error).self) { try service.handle(.invitations, path: link.path) }
        #expect(!FileManager.default.fileExists(atPath: missing.path))
        #expect(!FileManager.default.fileExists(atPath: config.initializationConfigFileURL.deletingLastPathComponent().path))
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty)
    }

    private func temporaryHome() throws -> URL {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: false)
        return home
    }
}

private struct NoEnrollmentState: V3EnrollmentCeremonyStateStoring {
    func loadState(vaultID: String, invitationDigest: Data) throws -> Data? {
        Issue.record("Discovery must not access ceremony state"); return nil
    }
    func replaceState(_ state: Data, expectedState: Data?, vaultID: String, invitationDigest: Data) throws {
        Issue.record("Discovery must not mutate ceremony state")
    }
}
