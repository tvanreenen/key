import Testing
@testable import KeyCore

struct CLIParserTests {
    @Test
    func parsesHelp() throws {
        let command = try CLIParser.parse(arguments: ["help"])
        #expect(command == .help)
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
    func parsesConfigSet() throws {
        let command = try CLIParser.parse(arguments: ["config", "set", "vault-dir", "~/Secrets"])
        #expect(command == .config(.set(key: .vaultDir, value: "~/Secrets")))
    }

    @Test
    func parsesConfigList() throws {
        let command = try CLIParser.parse(arguments: ["config", "list"])
        #expect(command == .config(.list))
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
        #expect(throws: AppError.usage("Unknown command 'show'.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["show", "github/personal"])
        }
    }

    @Test
    func rejectsLegacyGetCommandShape() throws {
        #expect(throws: AppError.usage("Unknown option '--copy' for get.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["get", "github/personal", "--copy"])
        }
    }

    @Test
    func rejectsRemovedTwoArgumentCopyCommand() throws {
        #expect(throws: AppError.usage("Unknown option 'dst/token' for copy.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["copy", "src/token", "dst/token"])
        }
    }

    @Test
    func rejectsRemovedMoveCommand() throws {
        #expect(throws: AppError.usage("Unknown command 'move'.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["move", "src/token", "dst/token"])
        }
    }

    @Test
    func rejectsRemovedCopyAlias() throws {
        #expect(throws: AppError.usage("Unknown command 'cp'.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["cp", "src/token", "dst/token"])
        }
    }

    @Test
    func rejectsRemovedMoveAlias() throws {
        #expect(throws: AppError.usage("Unknown command 'mv'.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["mv", "src/token", "dst/token"])
        }
    }

    @Test
    func rejectsRemovedRemoveAlias() throws {
        #expect(throws: AppError.usage("Unknown command 'rm'.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["rm", "src/token"])
        }
    }

    @Test
    func rejectsRemovedListAlias() throws {
        #expect(throws: AppError.usage("Unknown command 'ls'.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["ls"])
        }
    }

    @Test
    func rejectsRemovedShortHelpFlag() throws {
        #expect(throws: AppError.usage("Unknown command '-h'.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["-h"])
        }
    }

    @Test
    func rejectsRemovedLongHelpFlag() throws {
        #expect(throws: AppError.usage("Unknown command '--help'.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["--help"])
        }
    }

    @Test
    func rejectsLegacyPutCommand() throws {
        #expect(throws: AppError.usage("Unknown command 'put'.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["put", "api/token"])
        }
    }

    @Test
    func rejectsUnsupportedAddOptions() throws {
        #expect(throws: AppError.usage("Unknown option '--generate' for add.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["add", "api/token", "--generate"])
        }
    }

    @Test
    func rejectsUnsupportedEditOptions() throws {
        #expect(throws: AppError.usage("Unknown option '--generate' for edit.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["edit", "api/token", "--generate"])
        }
    }

    @Test
    func rejectsDuplicateWithoutDestination() throws {
        #expect(throws: AppError.usage("Missing destination entry name for duplicate.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["duplicate", "src/token"])
        }
    }

    @Test
    func rejectsRenameWithoutDestination() throws {
        #expect(throws: AppError.usage("Missing destination entry name for rename.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["rename", "src/token"])
        }
    }

    @Test
    func rejectsRemoveWithoutName() throws {
        #expect(throws: AppError.usage("Missing entry name for remove.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["remove"])
        }
    }

    @Test
    func rejectsUnlockOptions() throws {
        #expect(throws: AppError.usage("Unknown option '--force' for unlock.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["unlock", "--force"])
        }
    }

    @Test
    func rejectsLockOptions() throws {
        #expect(throws: AppError.usage("Unknown option '--force' for lock.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["lock", "--force"])
        }
    }

    @Test
    func rejectsUnknownVersionOptions() throws {
        #expect(throws: AppError.usage("Unknown option '--yaml' for version.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["version", "--yaml"])
        }
    }

    @Test
    func rejectsConfigWithoutSubcommand() throws {
        #expect(throws: AppError.usage("Missing config subcommand.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["config"])
        }
    }

    @Test
    func rejectsUnknownConfigSubcommand() throws {
        #expect(throws: AppError.usage("Unknown config subcommand 'show'.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["config", "show"])
        }
    }

    @Test
    func rejectsUnknownConfigKey() throws {
        #expect(throws: AppError.usage("Unknown config key 'theme'.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["config", "get", "theme"])
        }
    }

    @Test
    func rejectsConfigSetWithoutValue() throws {
        #expect(throws: AppError.usage("Missing value for config set.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["config", "set", "vault-dir"])
        }
    }

    @Test
    func rejectsConfigListOptions() throws {
        #expect(throws: AppError.usage("Unknown option '--json' for config list.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["config", "list", "--json"])
        }
    }

    @Test
    func rejectsHelpOptions() throws {
        #expect(throws: AppError.usage("Unknown option '--verbose' for help.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["help", "--verbose"])
        }
    }
}
