import Testing
@testable import KeyCore

struct CLIParserTests {
    @Test
    func parsesHelp() throws {
        let command = try CLIParser.parse(arguments: ["help"])
        #expect(command == .help(text: CLIParser.usageText))
    }

    @Test
    func parsesVersion() throws {
        let command = try CLIParser.parse(arguments: ["version"])
        #expect(command == .version(json: false))
    }

    @Test
    func parsesVersionJSON() throws {
        let command = try CLIParser.parse(arguments: ["version", "--json"])
        #expect(command == .version(json: true))
    }

    @Test
    func parsesConfigGet() throws {
        let command = try CLIParser.parse(arguments: ["config", "get", "vault-dir"])
        #expect(command == .config(.get(key: .vaultDir)))
    }

    @Test
    func parsesConfigGetKeychainMode() throws {
        let command = try CLIParser.parse(arguments: ["config", "get", "keychain-mode"])
        #expect(command == .config(.get(key: .keychainMode)))
    }

    @Test
    func parsesConfigSet() throws {
        let command = try CLIParser.parse(arguments: ["config", "set", "vault-dir", "~/Secrets"])
        #expect(command == .config(.set(key: .vaultDir, value: "~/Secrets")))
    }

    @Test
    func parsesConfigSetKeychainMode() throws {
        let command = try CLIParser.parse(arguments: ["config", "set", "keychain-mode", "icloud"])
        #expect(command == .config(.set(key: .keychainMode, value: "icloud")))
    }

    @Test
    func parsesConfigList() throws {
        let command = try CLIParser.parse(arguments: ["config", "list"])
        #expect(command == .config(.list))
    }

    @Test
    func parsesReadOnlyMigrationPreflight() throws {
        let command = try CLIParser.parse(arguments: ["migrate", "--check"])
        #expect(command == .migrationPreflight)
    }

    @Test
    func parsesExplicitMigrationApply() throws {
        let command = try CLIParser.parse(arguments: ["migrate", "--apply"])
        #expect(command == .migrationApply)
    }

    @Test
    func parsesGet() throws {
        let command = try CLIParser.parse(arguments: ["get", "github/personal"])
        #expect(command == .get(name: "github/personal"))
    }

    @Test
    func parsesCopy() throws {
        let command = try CLIParser.parse(arguments: ["copy", "github/personal"])
        #expect(command == .copy(name: "github/personal"))
    }

    @Test
    func parsesStatusOutputModes() throws {
        #expect(
            try CLIParser.parse(arguments: ["status"])
                == .status(json: false, verbose: false)
        )
        #expect(
            try CLIParser.parse(arguments: ["status", "--json"])
                == .status(json: true, verbose: false)
        )
        #expect(
            try CLIParser.parse(arguments: ["status", "--verbose"])
                == .status(json: false, verbose: true)
        )
    }

    @Test
    func parsesConflictCommands() throws {
        #expect(
            try CLIParser.parse(arguments: ["conflict", "list", "--json"])
                == .conflict(.list(json: true))
        )
        #expect(
            try CLIParser.parse(
                arguments: ["conflict", "show", "c-123", "--json"]
            ) == .conflict(.show(id: "c-123", json: true))
        )
        #expect(
            try CLIParser.parse(
                arguments: ["conflict", "get", "c-123", "abc123"]
            ) == .conflict(.get(id: "c-123", versionID: "abc123"))
        )
        #expect(
            try CLIParser.parse(
                arguments: ["conflict", "copy", "c-123", "abc123"]
            ) == .conflict(.copy(id: "c-123", versionID: "abc123"))
        )
        #expect(
            try CLIParser.parse(
                arguments: [
                    "conflict", "resolve",
                    "c-123=abc123", "c-456=def456"
                ]
            ) == .conflict(.resolve([
                VaultConflictResolution(
                    conflictID: "c-123",
                    versionID: "abc123"
                ),
                VaultConflictResolution(
                    conflictID: "c-456",
                    versionID: "def456"
                )
            ]))
        )
    }

    @Test
    func parsesExplicitDeviceSharingCeremony() throws {
        #expect(
            try CLIParser.parse(arguments: ["share", "devices"])
                == .share(.devices(json: false))
        )
        #expect(
            try CLIParser.parse(arguments: [
                "share", "devices", "--json"
            ]) == .share(.devices(json: true))
        )
        #expect(
            try CLIParser.parse(arguments: ["share", "invitations"])
                == .share(.invitations)
        )
        #expect(
            try CLIParser.parse(arguments: [
                "share", "revoke", "member-device-id"
            ]) == .share(.revoke(deviceID: "member-device-id"))
        )
        #expect(
            try CLIParser.parse(arguments: [
                "share", "invite", "--name", "Office Mac"
            ]) == .share(.invite(deviceName: "Office Mac"))
        )
        #expect(throws: AppError.self) {
            _ = try CLIParser.parse(arguments: [
                "share", "invite", "--name", "Office Mac", "--owner"
            ])
        }
        #expect(
            try CLIParser.parse(arguments: [
                "share", "join", "invite-id", "--name", "Laptop"
            ]) == .share(.join(
                invitationID: "invite-id",
                deviceName: "Laptop"
            ))
        )
        #expect(
            try CLIParser.parse(arguments: [
                "share", "compare", "vault-id", "invite-id",
                "request-id"
            ]) == .share(.compare(
                vaultID: "vault-id",
                invitationID: "invite-id",
                joinRequestID: "request-id"
            ))
        )
        #expect(
            try CLIParser.parse(arguments: [
                "share", "accept", "vault-id", "invite-id",
                "1234-5678-9abc-def0-1234"
            ]) == .share(.accept(
                vaultID: "vault-id",
                invitationID: "invite-id",
                comparisonCode: "1234-5678-9abc-def0-1234"
            ))
        )
    }

    @Test
    func rejectsImplicitOrUnnamedDeviceSharing() {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: [
                "share", "devices", "--verbose"
            ])
        }
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["share", "invite"])
        }
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["share", "revoke"])
        }
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: [
                "share", "join", "invite-id", "--owner",
                "--name", "Laptop"
            ])
        }
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: [
                "share", "approve", "vault-id", "invite-id"
            ])
        }
    }

    @Test
    func parsesExplicitStaleReads() throws {
        #expect(
            try CLIParser.parse(
                arguments: ["get", "github/personal", "--allow-stale"]
            ) == .get(name: "github/personal", allowStale: true)
        )
        #expect(
            try CLIParser.parse(
                arguments: ["copy", "--allow-stale", "github/personal"]
            ) == .copy(name: "github/personal", allowStale: true)
        )
    }

    @Test
    func rejectsAmbiguousStatusAndMalformedConflictResolution() {
        #expect(throws: AppError.self) {
            try CLIParser.parse(
                arguments: ["status", "--json", "--verbose"]
            )
        }
        #expect(throws: AppError.self) {
            try CLIParser.parse(
                arguments: ["conflict", "resolve", "missing-version"]
            )
        }
    }

    @Test
    func parsesUnlock() throws {
        let command = try CLIParser.parse(arguments: ["unlock"])
        #expect(command == .unlock)
    }

    @Test
    func parsesLock() throws {
        let command = try CLIParser.parse(arguments: ["lock"])
        #expect(command == .lock)
    }

    @Test
    func parsesAdd() throws {
        let command = try CLIParser.parse(arguments: ["add", "api/token"])
        #expect(command == .add(name: "api/token", type: .secret))
    }

    @Test
    func parsesAddTOTP() throws {
        let command = try CLIParser.parse(arguments: ["add", "--totp", "api/token"])
        #expect(command == .add(name: "api/token", type: .totp))
    }

    @Test
    func parsesDuplicateWithForce() throws {
        let command = try CLIParser.parse(arguments: ["duplicate", "src/token", "dst/token", "--force"])
        #expect(command == .duplicate(source: "src/token", destination: "dst/token", force: true))
    }

    @Test
    func parsesEdit() throws {
        let command = try CLIParser.parse(arguments: ["edit", "api/token"])
        #expect(command == .edit(name: "api/token", type: .secret))
    }

    @Test
    func parsesEditTOTPWithOptionAfterName() throws {
        let command = try CLIParser.parse(arguments: ["edit", "api/token", "--totp"])
        #expect(command == .edit(name: "api/token", type: .totp))
    }

    @Test
    func parsesRemoveWithForce() throws {
        let command = try CLIParser.parse(arguments: ["remove", "src/token", "--force"])
        #expect(command == .remove(name: "src/token", force: true))
    }

    @Test
    func parsesList() throws {
        let command = try CLIParser.parse(arguments: ["list"])
        #expect(command == .list)
    }

    @Test
    func parsesRenameWithForce() throws {
        let command = try CLIParser.parse(arguments: ["rename", "src/token", "dst/token", "--force"])
        #expect(command == .rename(source: "src/token", destination: "dst/token", force: true))
    }

    @Test
    func rejectsLegacyShowCommand() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["show", "github/personal"])
        }
    }

    @Test
    func rejectsLegacyGetCommandShape() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["get", "github/personal", "--copy"])
        }
    }

    @Test
    func rejectsRemovedTwoArgumentCopyCommand() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["copy", "src/token", "dst/token"])
        }
    }

    @Test
    func rejectsRemovedMoveCommand() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["move", "src/token", "dst/token"])
        }
    }

    @Test
    func rejectsRemovedCopyAlias() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["cp", "src/token", "dst/token"])
        }
    }

    @Test
    func rejectsRemovedMoveAlias() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["mv", "src/token", "dst/token"])
        }
    }

    @Test
    func rejectsRemovedRemoveAlias() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["rm", "src/token"])
        }
    }

    @Test
    func rejectsRemovedListAlias() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["ls"])
        }
    }

    @Test
    func acceptsShortHelpFlag() throws {
        #expect(try CLIParser.parse(arguments: ["-h"]) == .help(text: CLIParser.usageText))
    }

    @Test
    func acceptsLongHelpFlag() throws {
        #expect(try CLIParser.parse(arguments: ["--help"]) == .help(text: CLIParser.usageText))
    }

    @Test
    func standardOptionOrderingAndTerminatorsPreserveCommandMeaning() throws {
        #expect(try CLIParser.parse(arguments: ["remove", "--force", "entry"])
            == .remove(name: "entry", force: true))
        #expect(try CLIParser.parse(arguments: ["rename", "--force", "old", "new"])
            == .rename(source: "old", destination: "new", force: true))
        #expect(try CLIParser.parse(arguments: ["get", "--", "--help"])
            == .get(name: "--help"))
        #expect(try CLIParser.parse(arguments: ["add", "--totp", "--", "-entry"])
            == .add(name: "-entry", type: .totp))
        #expect(try CLIParser.parse(arguments: ["share", "join", "--name=New Mac", "--vault-dir=Key Vault", "invitation"])
            == .share(.join(invitationID: "invitation", deviceName: "New Mac"), vaultDirectory: "Key Vault"))
        #expect(try CLIParser.parse(arguments: ["conflict", "show", "--json", "id"])
            == .conflict(.show(id: "id", json: true)))
    }

    @Test
    func rejectsLegacyPutCommand() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["put", "api/token"])
        }
    }

    @Test
    func rejectsUnsupportedAddOptions() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["add", "api/token", "--generate"])
        }
    }

    @Test
    func rejectsUnsupportedEditOptions() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["edit", "api/token", "--generate"])
        }
    }

    @Test
    func rejectsDuplicateWithoutDestination() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["duplicate", "src/token"])
        }
    }

    @Test
    func rejectsRenameWithoutDestination() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["rename", "src/token"])
        }
    }

    @Test
    func rejectsRemoveWithoutName() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["remove"])
        }
    }

    @Test
    func rejectsUnlockOptions() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["unlock", "--force"])
        }
    }

    @Test
    func rejectsLockOptions() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["lock", "--force"])
        }
    }

    @Test
    func rejectsUnknownVersionOptions() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["version", "--yaml"])
        }
    }

    @Test
    func rejectsMigrationWithoutAnExplicitAction() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["migrate"])
        }
    }

    @Test
    func rejectsUnsupportedMigrationOptions() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["migrate", "--automatic"])
        }
    }

    @Test
    func rejectsConfigWithoutSubcommand() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["config"])
        }
    }

    @Test
    func rejectsUnknownConfigSubcommand() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["config", "show"])
        }
    }

    @Test
    func rejectsUnknownConfigKey() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["config", "get", "theme"])
        }
    }

    @Test
    func rejectsConfigSetWithoutValue() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["config", "set", "vault-dir"])
        }
    }

    @Test
    func rejectsConfigListOptions() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["config", "list", "--json"])
        }
    }

    @Test
    func rejectsHelpOptions() throws {
        #expect(throws: AppError.self) {
            try CLIParser.parse(arguments: ["help", "--verbose"])
        }
    }

    @Test
    func helpExplainsAccessLossAndKeepsDetailsInRelevantTopics() throws {
        let help = CLIParser.usageText.split(whereSeparator: \.isWhitespace).joined(separator: " ")
        let status = try #require(CLIParser.helpText(for: "status")).split(whereSeparator: \.isWhitespace).joined(separator: " ")
        let share = try #require(CLIParser.helpText(for: "share")).split(whereSeparator: \.isWhitespace).joined(separator: " ")
        #expect(status.contains("Local APFS and iCloud Drive"))
        #expect(status.contains("directly validated for Stable 0.2.0"))
        #expect(status.contains("may work, but are not directly validated"))
        #expect(help.contains("at least two active enrolled Macs"))
        #expect(share.contains("Invitations expire after 10 minutes"))
        #expect(share.contains("lost or revoked Mac rejoins"))
        #expect(help.contains("cannot recover access from the vault folder alone"))
        #expect(help.contains("no password, cloud, or support fallback"))
        #expect(!help.contains("v3"))
        #expect(share.contains("--name identifies this Mac, not the Mac you are inviting"))
        #expect(share.contains("Stop if they differ"))
    }

    @Test(arguments: ["init", "share", "config", "migrate", "status", "conflict", "get", "copy", "add", "edit", "duplicate", "rename", "remove", "unlock", "lock", "list", "version"])
    func commandHelpHasBothSpellings(topic: String) throws {
        #expect(try CLIParser.parse(arguments: ["help", topic]) == .help(text: CLIParser.helpText(for: topic)!))
        #expect(try CLIParser.parse(arguments: [topic, "--help"]) == .help(text: CLIParser.helpText(for: topic)!))
        #expect(CLIParser.helpText(for: topic) != nil)
    }

    @Test
    func helpTakesPrecedenceButRespectsTheOptionTerminator() throws {
        #expect(try CLIParser.parse(arguments: ["init", "--", "--help"]) == .initializeVault(path: "--help"))
        // Argument Parser displays help even with incomplete or invalid input.
        // A help request must never become an operation.
        for arguments in [["init", "--help", "folder"], ["help", "init", "extra"], ["help", "unknown"], ["unknown", "--help"], ["--help", "extra"]] {
            guard case .help = try CLIParser.parse(arguments: arguments) else {
                Issue.record("Expected help for \(arguments)")
                continue
            }
        }
    }
}
