import Foundation

public enum CLIParser {
    public static func parse(arguments: [String]) throws -> Command {
        guard let subcommand = arguments.first else {
            throw AppError.usage(usageText)
        }

        switch subcommand {
        case "help":
            return try parseHelp(arguments: Array(arguments.dropFirst()))
        case "version":
            return try parseVersion(arguments: Array(arguments.dropFirst()))
        case "config":
            return try parseConfig(arguments: Array(arguments.dropFirst()))
        case "migrate":
            return try parseMigrate(arguments: Array(arguments.dropFirst()))
        case "unlock":
            return try parseUnlock(arguments: Array(arguments.dropFirst()))
        case "lock":
            return try parseLock(arguments: Array(arguments.dropFirst()))
        case "get":
            return try parseGet(arguments: Array(arguments.dropFirst()))
        case "copy":
            return try parseCopy(arguments: Array(arguments.dropFirst()))
        case "add":
            return try parseAdd(arguments: Array(arguments.dropFirst()))
        case "edit":
            return try parseEdit(arguments: Array(arguments.dropFirst()))
        case "duplicate":
            return try parseDuplicate(arguments: Array(arguments.dropFirst()))
        case "rename":
            return try parseRename(arguments: Array(arguments.dropFirst()))
        case "remove":
            return try parseRemove(arguments: Array(arguments.dropFirst()), commandName: subcommand)
        case "list":
            return try parseList(arguments: Array(arguments.dropFirst()), commandName: subcommand)
        default:
            throw AppError.usage("Unknown command '\(subcommand)'.\n\n\(usageText)")
        }
    }

    public static let usageText = """
    Usage:
      key <command> [arguments]

    Commands:
      config get <config-name>           Print a config value.
      config set <config-name> <value>   Update a config value.
      config list                        List known config values.
      migrate --check                    Check v2 migration readiness without changing the vault.
      get <name>                         Print a secret or current TOTP code.
      copy <name>                        Copy a secret or current TOTP code.
      add [--totp] <name>                Add a new secret from stdin or prompt.
      edit [--totp] <name>               Update a secret from stdin or prompt.
      duplicate <src> <dst> [--force]    Duplicate an entry.
      rename <src> <dst> [--force]       Rename an entry.
      remove <name> [--force]            Remove a secret.
      list                               List stored secrets.
      unlock                             Warm the helper session.
      lock                               Clear the helper session and stop the helper.
      version [--json]                   Print the CLI version.
      help                               Show this help.

    Options:
      --force  Skip overwrite or removal confirmation.
      --check  Run the read-only v2 migration preflight.
      --json   Print version info as JSON.
      --totp   Treat add/edit input as a Base32 TOTP seed.

    Config names:
      vault-dir      Effective vault directory.
      keychain-mode  Vault key storage mode (`local` or `icloud`).
    """

    private static func parseHelp(arguments: [String]) throws -> Command {
        guard arguments.isEmpty else {
            throw AppError.usage("Unknown option '\(arguments[0])' for help.\n\n\(usageText)")
        }

        return .help
    }

    private static func parseVersion(arguments: [String]) throws -> Command {
        guard arguments.count <= 1 else {
            throw AppError.usage("Unknown option '\(arguments[1])' for version.\n\n\(usageText)")
        }

        if let argument = arguments.first {
            guard argument == "--json" else {
                throw AppError.usage("Unknown option '\(argument)' for version.\n\n\(usageText)")
            }
            return .version(json: true)
        }

        return .version(json: false)
    }

    private static func parseConfig(arguments: [String]) throws -> Command {
        guard let action = arguments.first else {
            throw AppError.usage("Missing config subcommand.\n\n\(usageText)")
        }

        switch action {
        case "get":
            return try parseConfigGet(arguments: Array(arguments.dropFirst()))
        case "set":
            return try parseConfigSet(arguments: Array(arguments.dropFirst()))
        case "list":
            return try parseConfigList(arguments: Array(arguments.dropFirst()))
        default:
            throw AppError.usage("Unknown config subcommand '\(action)'.\n\n\(usageText)")
        }
    }

    private static func parseConfigGet(arguments: [String]) throws -> Command {
        guard let key = arguments.first else {
            throw AppError.usage("Missing config key for config get.\n\n\(usageText)")
        }
        guard arguments.count == 1 else {
            throw AppError.usage("Unknown option '\(arguments[1])' for config get.\n\n\(usageText)")
        }

        return .config(.get(key: try parseConfigKey(key)))
    }

    private static func parseConfigSet(arguments: [String]) throws -> Command {
        guard let key = arguments.first else {
            throw AppError.usage("Missing config key for config set.\n\n\(usageText)")
        }
        guard arguments.count >= 2 else {
            throw AppError.usage("Missing value for config set.\n\n\(usageText)")
        }
        guard arguments.count == 2 else {
            throw AppError.usage("Unknown option '\(arguments[2])' for config set.\n\n\(usageText)")
        }

        return .config(.set(key: try parseConfigKey(key), value: arguments[1]))
    }

    private static func parseConfigList(arguments: [String]) throws -> Command {
        guard arguments.isEmpty else {
            throw AppError.usage("Unknown option '\(arguments[0])' for config list.\n\n\(usageText)")
        }

        return .config(.list)
    }

    private static func parseConfigKey(_ key: String) throws -> ConfigKey {
        guard let configKey = ConfigKey(rawValue: key) else {
            throw AppError.usage("Unknown config key '\(key)'.\n\n\(usageText)")
        }

        return configKey
    }

    private static func parseMigrate(arguments: [String]) throws -> Command {
        guard let argument = arguments.first else {
            throw AppError.usage(
                "Migration does not start automatically. Use `key migrate --check` to inspect readiness without changing the vault.\n\n\(usageText)"
            )
        }
        guard argument == "--check" else {
            throw AppError.usage("Unknown option '\(argument)' for migrate.\n\n\(usageText)")
        }
        guard arguments.count == 1 else {
            throw AppError.usage("Unknown option '\(arguments[1])' for migrate.\n\n\(usageText)")
        }
        return .migrationPreflight
    }

    private static func parseUnlock(arguments: [String]) throws -> Command {
        guard arguments.isEmpty else {
            throw AppError.usage("Unknown option '\(arguments[0])' for unlock.\n\n\(usageText)")
        }

        return .unlock
    }

    private static func parseLock(arguments: [String]) throws -> Command {
        guard arguments.isEmpty else {
            throw AppError.usage("Unknown option '\(arguments[0])' for lock.\n\n\(usageText)")
        }

        return .lock
    }

    private static func parseGet(arguments: [String]) throws -> Command {
        guard let name = arguments.first else {
            throw AppError.usage("Missing entry name for get.\n\n\(usageText)")
        }
        guard arguments.count == 1 else {
            throw AppError.usage("Unknown option '\(arguments[1])' for get.\n\n\(usageText)")
        }

        return .get(name: name)
    }

    private static func parseCopy(arguments: [String]) throws -> Command {
        guard let name = arguments.first else {
            throw AppError.usage("Missing entry name for copy.\n\n\(usageText)")
        }
        guard arguments.count == 1 else {
            throw AppError.usage("Unknown option '\(arguments[1])' for copy.\n\n\(usageText)")
        }

        return .copy(name: name)
    }

    private static func parseAdd(arguments: [String]) throws -> Command {
        let (name, type) = try parseSecretWrite(arguments: arguments, commandName: "add")
        return .add(name: name, type: type)
    }

    private static func parseEdit(arguments: [String]) throws -> Command {
        let (name, type) = try parseSecretWrite(arguments: arguments, commandName: "edit")
        return .edit(name: name, type: type)
    }

    private static func parseSecretWrite(
        arguments: [String],
        commandName: String
    ) throws -> (name: String, type: SecretEntryType) {
        guard !arguments.isEmpty else {
            throw AppError.usage("Missing entry name for \(commandName).\n\n\(usageText)")
        }

        var type: SecretEntryType = .secret
        var name: String?

        for argument in arguments {
            switch argument {
            case "--totp":
                type = .totp
            default:
                guard !argument.hasPrefix("-") else {
                    throw AppError.usage("Unknown option '\(argument)' for \(commandName).\n\n\(usageText)")
                }
                guard name == nil else {
                    throw AppError.usage("Unknown option '\(argument)' for \(commandName).\n\n\(usageText)")
                }
                name = argument
            }
        }

        guard let name else {
            throw AppError.usage("Missing entry name for \(commandName).\n\n\(usageText)")
        }

        return (name, type)
    }

    private static func parseDuplicate(arguments: [String]) throws -> Command {
        try parseEntryTransfer(arguments: arguments, commandName: "duplicate") { source, destination, force in
            .duplicate(source: source, destination: destination, force: force)
        }
    }

    private static func parseRename(arguments: [String]) throws -> Command {
        try parseEntryTransfer(arguments: arguments, commandName: "rename") { source, destination, force in
            .rename(source: source, destination: destination, force: force)
        }
    }

    private static func parseEntryTransfer(
        arguments: [String],
        commandName: String,
        build: (String, String, Bool) -> Command
    ) throws -> Command {
        guard let source = arguments.first else {
            throw AppError.usage("Missing source entry name for \(commandName).\n\n\(usageText)")
        }
        guard arguments.count >= 2 else {
            throw AppError.usage("Missing destination entry name for \(commandName).\n\n\(usageText)")
        }

        let destination = arguments[1]
        var force = false
        var index = 2

        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "--force":
                force = true
                index += 1
            default:
                throw AppError.usage("Unknown option '\(argument)' for \(commandName).\n\n\(usageText)")
            }
        }

        return build(source, destination, force)
    }

    private static func parseRemove(arguments: [String], commandName: String) throws -> Command {
        guard let name = arguments.first else {
            throw AppError.usage("Missing entry name for \(commandName).\n\n\(usageText)")
        }

        var force = false
        var index = 1

        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "--force":
                force = true
                index += 1
            default:
                throw AppError.usage("Unknown option '\(argument)' for \(commandName).\n\n\(usageText)")
            }
        }

        return .remove(name: name, force: force)
    }

    private static func parseList(arguments: [String], commandName: String) throws -> Command {
        guard arguments.isEmpty else {
            throw AppError.usage("Unknown option '\(arguments[0])' for \(commandName).\n\n\(usageText)")
        }

        return .list
    }
}
