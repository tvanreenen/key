import Foundation

public enum CLIParser {
    public static func parse(arguments: [String]) throws -> Command {
        guard let subcommand = arguments.first else {
            throw AppError.usage(usageText)
        }

        if arguments.count == 1, subcommand == "--help" {
            return .help
        }
        if arguments.count == 2, arguments[1] == "--help",
           helpText(for: subcommand) != nil {
            return .commandHelp(topic: subcommand)
        }

        switch subcommand {
        case "help":
            return try parseHelp(arguments: Array(arguments.dropFirst()))
        case "version":
            return try parseVersion(arguments: Array(arguments.dropFirst()))
        case "config":
            return try parseConfig(arguments: Array(arguments.dropFirst()))
        case "init":
            return try parseInit(arguments: Array(arguments.dropFirst()))
        case "migrate":
            return try parseMigrate(arguments: Array(arguments.dropFirst()))
        case "status":
            return try parseStatus(arguments: Array(arguments.dropFirst()))
        case "conflict":
            return try parseConflict(arguments: Array(arguments.dropFirst()))
        case "share":
            return try parseShare(arguments: Array(arguments.dropFirst()))
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


    private static func parseInit(arguments: [String]) throws -> Command {
        var paths = arguments
        if paths.first == "--" {
            paths.removeFirst()
        } else if paths.first?.hasPrefix("-") == true {
            throw AppError.usage("Unknown option for init. Use `key init [directory]`; use `--` before a directory beginning with '-'.")
        }
        guard paths.count <= 1, paths.first?.isEmpty != true,
              paths.first?.utf8.contains(0) != true else {
            throw AppError.usage("Use `key init [directory]` with one nonempty directory path.")
        }
        return .initializeVault(path: paths.first)
    }

    private static func parseHelp(arguments: [String]) throws -> Command {
        if arguments.count == 1, helpText(for: arguments[0]) != nil {
            return .commandHelp(topic: arguments[0])
        }
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
                "Migration does not start automatically. Use `key migrate --check` to inspect readiness or `key migrate --apply` to convert this device explicitly.\n\n\(usageText)"
            )
        }
        guard arguments.count == 1 else {
            throw AppError.usage("Unknown option '\(arguments[1])' for migrate.\n\n\(usageText)")
        }
        return switch argument {
        case "--check":
            .migrationPreflight
        case "--apply":
            .migrationApply
        default:
            throw AppError.usage(
                "Unknown option '\(argument)' for migrate.\n\n\(usageText)"
            )
        }
    }

    private static func parseStatus(arguments: [String]) throws -> Command {
        var json = false
        var verbose = false
        for argument in arguments {
            switch argument {
            case "--json":
                json = true
            case "--verbose":
                verbose = true
            default:
                throw AppError.usage(
                    "Unknown option '\(argument)' for status.\n\n\(usageText)"
                )
            }
        }
        guard !(json && verbose) else {
            throw AppError.usage(
                "Use either --json or --verbose with status, not both.\n\n\(usageText)"
            )
        }
        return .status(json: json, verbose: verbose)
    }

    private static func parseConflict(arguments: [String]) throws -> Command {
        guard let action = arguments.first else {
            throw AppError.usage(
                "Missing conflict subcommand.\n\n\(usageText)"
            )
        }
        let remaining = Array(arguments.dropFirst())
        switch action {
        case "list":
            let json = try parseOptionalJSON(
                remaining,
                commandName: "conflict list"
            )
            return .conflict(.list(json: json))
        case "show":
            guard let id = remaining.first else {
                throw AppError.usage(
                    "Missing conflict ID for conflict show.\n\n\(usageText)"
                )
            }
            let json = try parseOptionalJSON(
                Array(remaining.dropFirst()),
                commandName: "conflict show"
            )
            return .conflict(.show(id: id, json: json))
        case "get":
            return .conflict(
                try parseConflictValue(remaining, copy: false)
            )
        case "copy":
            return .conflict(
                try parseConflictValue(remaining, copy: true)
            )
        case "resolve":
            guard !remaining.isEmpty else {
                throw AppError.usage(
                    "Provide every resolution as <conflict-id>=<version-id>.\n\n\(usageText)"
                )
            }
            return .conflict(.resolve(
                try remaining.map(parseConflictResolution)
            ))
        default:
            throw AppError.usage(
                "Unknown conflict subcommand '\(action)'.\n\n\(usageText)"
            )
        }
    }

    private static func parseShare(arguments: [String]) throws -> Command {
        guard let action = arguments.first else {
            throw AppError.usage(
                "Missing share subcommand.\n\n\(usageText)"
            )
        }
        let remaining = Array(arguments.dropFirst())
        if let index = remaining.firstIndex(of: "--vault-dir") {
            guard ["invitations", "join", "compare", "accept"].contains(action),
                  index + 1 < remaining.count,
                  !remaining[index + 1].isEmpty,
                  !remaining[index + 1].hasPrefix("--"),
                  !remaining[index + 1].utf8.contains(0)
            else {
                throw AppError.usage("Use --vault-dir <existing-directory> with share invitations, join, compare, or accept.")
            }
            let path = remaining[index + 1]
            var rest = remaining
            rest.removeSubrange(index...index + 1)
            guard !rest.contains("--vault-dir"),
                  case let .share(command, _) = try parseShare(arguments: [action] + rest)
            else {
                throw AppError.usage("Specify --vault-dir only once.")
            }
            return .share(command, vaultDirectory: path)
        }
        switch action {
        case "devices":
            return .share(.devices(json: try parseOptionalJSON(
                remaining,
                commandName: "share devices"
            )))
        case "revoke":
            guard remaining.count == 1 else {
                throw AppError.usage(
                    "Use `key share revoke <device-id>`.\n\n\(usageText)"
                )
            }
            return .share(.revoke(deviceID: remaining[0]))
        case "invitations":
            guard remaining.isEmpty else {
                throw AppError.usage(
                    "Unknown option '\(remaining[0])' for share invitations.\n\n\(usageText)"
                )
            }
            return .share(.invitations)
        case "invite":
            let name = try parseShareIdentityOptions(remaining)
            return .share(.invite(deviceName: name))
        case "join":
            guard let invitationID = remaining.first else {
                throw AppError.usage(
                    "Missing invitation ID for share join.\n\n\(usageText)"
                )
            }
            let name = try parseShareIdentityOptions(
                Array(remaining.dropFirst())
            )
            return .share(.join(
                invitationID: invitationID,
                deviceName: name
            ))
        case "requests":
            guard remaining.count == 1 else {
                throw AppError.usage(
                    "Use `key share requests <invitation-id>`.\n\n\(usageText)"
                )
            }
            return .share(.requests(invitationID: remaining[0]))
        case "compare":
            guard remaining.count == 2 || remaining.count == 3 else {
                throw AppError.usage(
                    "Use `key share compare <vault-id> <invitation-id> [join-request-id]`.\n\n\(usageText)"
                )
            }
            return .share(.compare(
                vaultID: remaining[0],
                invitationID: remaining[1],
                joinRequestID: remaining.count == 3 ? remaining[2] : nil
            ))
        case "approve", "accept":
            guard remaining.count == 3 else {
                throw AppError.usage(
                    "Use `key share \(action) <vault-id> <invitation-id> <comparison-code>`.\n\n\(usageText)"
                )
            }
            return .share(
                action == "approve"
                    ? .approve(
                        vaultID: remaining[0],
                        invitationID: remaining[1],
                        comparisonCode: remaining[2]
                    )
                    : .accept(
                        vaultID: remaining[0],
                        invitationID: remaining[1],
                        comparisonCode: remaining[2]
                    )
            )
        default:
            throw AppError.usage(
                "Unknown share subcommand '\(action)'.\n\n\(usageText)"
            )
        }
    }

    private static func parseShareIdentityOptions(
        _ arguments: [String]
    ) throws -> String {
        var name: String?
        var index = 0
        while index < arguments.count {
            switch arguments[index] {
            case "--name":
                guard index + 1 < arguments.count, name == nil else {
                    throw AppError.usage(
                        "Provide one device name after --name.\n\n\(usageText)"
                    )
                }
                name = arguments[index + 1]
                index += 2
            default:
                throw AppError.usage(
                    "Unknown option '\(arguments[index])' for share.\n\n\(usageText)"
                )
            }
        }
        guard let name else {
            throw AppError.usage(
                "Provide this Mac's readable name with --name.\n\n\(usageText)"
            )
        }
        return name
    }

    private static func parseOptionalJSON(
        _ arguments: [String],
        commandName: String
    ) throws -> Bool {
        guard arguments.count <= 1 else {
            throw AppError.usage(
                "Unknown option '\(arguments[1])' for \(commandName).\n\n\(usageText)"
            )
        }
        guard let argument = arguments.first else {
            return false
        }
        guard argument == "--json" else {
            throw AppError.usage(
                "Unknown option '\(argument)' for \(commandName).\n\n\(usageText)"
            )
        }
        return true
    }

    private static func parseConflictValue(
        _ arguments: [String],
        copy: Bool
    ) throws -> ConflictCommand {
        let commandName = copy ? "conflict copy" : "conflict get"
        guard let id = arguments.first else {
            throw AppError.usage(
                "Missing conflict ID for \(commandName).\n\n\(usageText)"
            )
        }
        guard arguments.count >= 2 else {
            throw AppError.usage(
                "Missing version ID for \(commandName).\n\n\(usageText)"
            )
        }
        guard arguments.count == 2 else {
            throw AppError.usage(
                "Unknown option '\(arguments[2])' for \(commandName).\n\n\(usageText)"
            )
        }
        return copy
            ? .copy(id: id, versionID: arguments[1])
            : .get(id: id, versionID: arguments[1])
    }

    private static func parseConflictResolution(
        _ argument: String
    ) throws -> VaultConflictResolution {
        let components = argument.split(
            separator: "=",
            maxSplits: 1,
            omittingEmptySubsequences: false
        )
        guard components.count == 2,
              !components[0].isEmpty,
              !components[1].isEmpty
        else {
            throw AppError.usage(
                "Invalid conflict resolution '\(argument)'. Expected <conflict-id>=<version-id>.\n\n\(usageText)"
            )
        }
        return VaultConflictResolution(
            conflictID: String(components[0]),
            versionID: String(components[1])
        )
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
        let (name, allowStale) = try parseRead(
            arguments: arguments,
            commandName: "get"
        )
        return .get(name: name, allowStale: allowStale)
    }

    private static func parseCopy(arguments: [String]) throws -> Command {
        let (name, allowStale) = try parseRead(
            arguments: arguments,
            commandName: "copy"
        )
        return .copy(name: name, allowStale: allowStale)
    }

    private static func parseRead(
        arguments: [String],
        commandName: String
    ) throws -> (name: String, allowStale: Bool) {
        var name: String?
        var allowStale = false
        for argument in arguments {
            if argument == "--allow-stale" {
                allowStale = true
            } else if argument.hasPrefix("-") {
                throw AppError.usage(
                    "Unknown option '\(argument)' for \(commandName).\n\n\(usageText)"
                )
            } else if name == nil {
                name = argument
            } else {
                throw AppError.usage(
                    "Unknown option '\(argument)' for \(commandName).\n\n\(usageText)"
                )
            }
        }
        guard let name else {
            throw AppError.usage(
                "Missing entry name for \(commandName).\n\n\(usageText)"
            )
        }
        return (name, allowStale)
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
