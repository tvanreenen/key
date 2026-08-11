import Foundation
import Testing
@testable import KeyCore

struct VaultUXCLITests {
    @Test
    func statusExplainsHealthAndReturnsStableHealthExitCode() throws {
        let status = VaultStatus(
            format: .version3,
            health: .contentConflicted,
            entries: .lastTrusted(7),
            conflictCount: 2,
            trustedVersionID: "0123456789abcdef"
        )
        let transport = MemoryTransport { request in
            #expect(request == .vaultStatus)
            return .vaultStatus(status)
        }
        let io = MemoryIO(stdinIsTTY: false)
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: MemoryClipboard()
        )

        #expect(
            app.run(arguments: ["status"])
                == KeyExitCode.conflict.rawValue
        )
        #expect(io.stdout.contains("Vault has content conflicts"))
        #expect(io.stdout.contains("Last trusted entries: 7"))
        #expect(io.stdout.contains("Conflicts: 2"))
        #expect(io.stdout.contains("key conflict list"))
        #expect(!io.stdout.contains("0123456789abcdef"))
        #expect(io.stderr == "")
    }

    @Test
    func statusJSONHasTheStableDocumentedShape() throws {
        let status = VaultStatus(
            format: .version3,
            health: .incomplete,
            entries: .lastTrusted(4),
            trustedVersionID: "0123456789abcdef",
            issues: [
                VaultIssue(
                    code: .transportUnavailable,
                    message: "A referenced object is not available yet."
                )
            ]
        )
        let transport = MemoryTransport { _ in
            .vaultStatus(status)
        }
        let io = MemoryIO(stdinIsTTY: false)
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: MemoryClipboard()
        )

        #expect(
            app.run(arguments: ["status", "--json"])
                == KeyExitCode.temporarilyUnavailable.rawValue
        )
        #expect(
            io.stdout
                == #"{"conflictCount":0,"entries":{"basis":"last_trusted","count":4},"format":"v3","health":"incomplete","issues":[{"code":"transport_unavailable","message":"A referenced object is not available yet."}],"trustedVersionID":"0123456789abcdef"}"# + "\n"
        )
    }

    @Test
    func rollbackStatusAndConflictShowRecommendRecoveryNotResolution()
        throws
    {
        let summary = VaultConflictSummary(
            id: "c-rollback",
            entryName: "mail/personal",
            kind: .revisionRollback,
            versionCount: 1
        )
        let detail = VaultConflictDetail(
            summary: summary,
            versions: [
                VaultConflictVersion(
                    id: "0123456789abcdef",
                    entryName: "mail/personal",
                    entryType: .secret,
                    revision: 1,
                    previouslyTrustedOnThisMac: false
                )
            ]
        )
        let status = VaultStatus(
            format: .version3,
            health: .rollbackDetected,
            entries: .lastTrusted(1),
            conflictCount: 1
        )
        let transport = MemoryTransport { request in
            switch request {
            case .vaultStatus:
                .vaultStatus(status)
            case .showConflict(id: "c-rollback"):
                .conflict(detail)
            default:
                .failure("Unexpected request.")
            }
        }

        let statusIO = MemoryIO(stdinIsTTY: false)
        let statusApp = KeyCLIApplication(
            transport: transport,
            io: statusIO,
            clipboard: MemoryClipboard()
        )
        #expect(
            statusApp.run(arguments: ["status"])
                == KeyExitCode.securityFailure.rawValue
        )
        #expect(statusIO.stdout.contains("recover from a known-good state"))
        #expect(!statusIO.stdout.contains("Next: run `key conflict list`."))

        let conflictIO = MemoryIO(stdinIsTTY: false)
        let conflictApp = KeyCLIApplication(
            transport: transport,
            io: conflictIO,
            clipboard: MemoryClipboard()
        )
        #expect(
            conflictApp.run(arguments: [
                "conflict", "show", "c-rollback"
            ]) == EXIT_SUCCESS
        )
        #expect(
            conflictIO.stdout.contains(
                "cannot be resolved with `key conflict resolve`"
            )
        )
        #expect(
            !conflictIO.stdout.contains(
                "Resolve only after reviewing every conflict"
            )
        )
    }

    @Test
    func conflictInspectionKeepsMetadataAndSecretsSeparate() throws {
        let summary = VaultConflictSummary(
            id: "c-123",
            entryName: "mail/personal",
            kind: .editEdit,
            versionCount: 2
        )
        let detail = VaultConflictDetail(
            summary: summary,
            versions: [
                VaultConflictVersion(
                    id: "aaaaaaaaaaaaaaaa",
                    entryName: "mail/personal",
                    entryType: .secret,
                    revision: 2,
                    previouslyTrustedOnThisMac: false
                ),
                VaultConflictVersion(
                    id: "bbbbbbbbbbbbbbbb",
                    entryName: "mail/personal",
                    entryType: .secret,
                    revision: 2,
                    previouslyTrustedOnThisMac: false
                )
            ]
        )
        let transport = MemoryTransport { request in
            switch request {
            case .listConflicts:
                return .conflicts([summary])
            case .showConflict(id: "c-123"):
                return .conflict(detail)
            case .getConflictValue(
                id: "c-123",
                versionID: "aaaaaaaaaaaaaaaa"
            ):
                return .success("secret-value")
            default:
                Issue.record("Unexpected conflict request: \(request)")
                return .failure("Unexpected request.")
            }
        }

        let listIO = MemoryIO(stdinIsTTY: false)
        #expect(
            KeyCLIApplication(
                transport: transport,
                io: listIO,
                clipboard: MemoryClipboard()
            ).run(arguments: ["conflict", "list"]) == EXIT_SUCCESS
        )
        #expect(listIO.stdout.contains("mail/personal"))
        #expect(!listIO.stdout.contains("secret-value"))

        let showIO = MemoryIO(stdinIsTTY: false)
        #expect(
            KeyCLIApplication(
                transport: transport,
                io: showIO,
                clipboard: MemoryClipboard()
            ).run(arguments: ["conflict", "show", "c-123"])
                == EXIT_SUCCESS
        )
        #expect(showIO.stdout.contains("aaaaaaaaaaaaaaaa"))
        #expect(!showIO.stdout.contains("secret-value"))

        let getIO = MemoryIO(stdinIsTTY: false, stdoutIsTTY: false)
        #expect(
            KeyCLIApplication(
                transport: transport,
                io: getIO,
                clipboard: MemoryClipboard()
            ).run(arguments: [
                "conflict", "get", "c-123", "aaaaaaaaaaaaaaaa"
            ]) == EXIT_SUCCESS
        )
        #expect(getIO.stdout == "secret-value")
        #expect(getIO.stderr == "")
    }

    @Test
    func conflictCopyAndResolutionDoNotWriteStdout() throws {
        let resolution = VaultConflictResolution(
            conflictID: "c-123",
            versionID: "aaaaaaaaaaaaaaaa"
        )
        let transport = MemoryTransport { request in
            switch request {
            case .getConflictValue(
                id: "c-123",
                versionID: "aaaaaaaaaaaaaaaa"
            ):
                return .success("secret-value")
            case let .resolveConflicts(resolutions):
                #expect(resolutions == [resolution])
                return .success()
            default:
                Issue.record("Unexpected conflict request: \(request)")
                return .failure("Unexpected request.")
            }
        }
        let clipboard = MemoryClipboard()
        let io = MemoryIO(stdinIsTTY: false)
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: clipboard
        )

        #expect(
            app.run(arguments: [
                "conflict", "copy", "c-123", "aaaaaaaaaaaaaaaa"
            ]) == EXIT_SUCCESS
        )
        #expect(clipboard.copiedText == "secret-value")
        #expect(io.stdout == "")

        #expect(
            app.run(arguments: [
                "conflict", "resolve", "c-123=aaaaaaaaaaaaaaaa"
            ]) == EXIT_SUCCESS
        )
        #expect(io.stdout == "")
    }

    @Test
    func conflictJSONHasTheStableDocumentedShape() {
        let detail = VaultConflictDetail(
            summary: VaultConflictSummary(
                id: "c-123",
                entryName: "mail/personal",
                kind: .editEdit,
                versionCount: 2
            ),
            versions: [
                VaultConflictVersion(
                    id: "aaaaaaaaaaaaaaaa",
                    entryName: "mail/personal",
                    entryType: .secret,
                    revision: 2,
                    previouslyTrustedOnThisMac: true
                ),
                VaultConflictVersion(
                    id: "bbbbbbbbbbbbbbbb",
                    entryName: nil,
                    entryType: nil,
                    revision: nil,
                    previouslyTrustedOnThisMac: false
                )
            ]
        )
        let io = MemoryIO(stdinIsTTY: false)
        let app = KeyCLIApplication(
            transport: MemoryTransport { request in
                #expect(request == .showConflict(id: "c-123"))
                return .conflict(detail)
            },
            io: io,
            clipboard: MemoryClipboard()
        )

        #expect(
            app.run(arguments: [
                "conflict", "show", "c-123", "--json"
            ]) == EXIT_SUCCESS
        )
        #expect(
            io.stdout
                == #"{"summary":{"entryName":"mail\/personal","id":"c-123","kind":"edit_edit","versionCount":2},"versions":[{"entryName":"mail\/personal","entryType":"secret","id":"aaaaaaaaaaaaaaaa","previouslyTrustedOnThisMac":true,"revision":2},{"id":"bbbbbbbbbbbbbbbb","previouslyTrustedOnThisMac":false}]}"# + "\n"
        )
    }

    @Test
    func vaultServiceErrorCodesRetainTheirAutomationValues() throws {
        let codes: [KeyServiceErrorCode] = [
            .vaultIncomplete,
            .contentConflict,
            .securityConflict,
            .rollbackDetected,
            .recoveryRequired,
            .conflictNotFound,
            .conflictVersionNotFound,
            .expectedHeadsChanged
        ]
        let data = try JSONEncoder().encode(codes)
        let encoded = try #require(String(data: data, encoding: .utf8))

        #expect(
            encoded
                == #"["vault_incomplete","content_conflict","security_conflict","rollback_detected","recovery_required","conflict_not_found","conflict_version_not_found","expected_heads_changed"]"#
        )
        #expect(
            codes.map(\.exitCode)
                == [
                    .temporarilyUnavailable,
                    .conflict,
                    .securityFailure,
                    .securityFailure,
                    .securityFailure,
                    .notFound,
                    .notFound,
                    .conflict
                ]
        )
    }

    @Test
    func catchUpContentConflictRetainsThePublicConflictContract() {
        let response = KeyServiceResponse.failure(
            VaultUXServiceError.catchUpContentConflict
        )

        #expect(response.errorCode == .contentConflict)
        #expect(response.exitCode == KeyExitCode.conflict.rawValue)
        #expect(response.errorMessage?.contains("--allow-stale") == true)
        #expect(response.errorMessage?.contains("conflict show") == false)
    }

    @Test(arguments: [
        ["status"],
        ["conflict", "list"],
        ["conflict", "show", "c-123"],
        ["conflict", "get", "c-123", "version-1"],
        ["conflict", "copy", "c-123", "version-1"]
    ])
    func missingSuccessfulPayloadIsRejected(arguments: [String]) {
        let io = MemoryIO(stdinIsTTY: false)
        let app = KeyCLIApplication(
            transport: MemoryTransport { _ in .success() },
            io: io,
            clipboard: MemoryClipboard()
        )

        #expect(
            app.run(arguments: arguments) == KeyExitCode.failure.rawValue
        )
        #expect(io.stdout == "")
        #expect(io.stderr.contains("returned an invalid"))
    }
}
