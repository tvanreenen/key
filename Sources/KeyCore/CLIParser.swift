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
      get <name>                       Print a secret.
      copy <name>                      Copy a secret to the clipboard.
      add <name>                       Add a new secret from stdin or prompt.
      edit <name>                      Update a secret from stdin or prompt.
      duplicate <src> <dst> [--force]  Duplicate an entry.
      rename <src> <dst> [--force]     Rename an entry.
      remove <name> [--force]          Remove a secret.
      list                             List stored secrets.
      unlock                           Warm the helper session.
      lock                             Clear the helper session and stop the helper.
      version [--json]                 Print the CLI version.
      help                             Show this help.

    Options:
      --force  Skip overwrite or removal confirmation.
      --json   Print version info as JSON.
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
        guard let name = arguments.first else {
            throw AppError.usage("Missing entry name for add.\n\n\(usageText)")
        }
        guard arguments.count == 1 else {
            throw AppError.usage("Unknown option '\(arguments[1])' for add.\n\n\(usageText)")
        }
        return .add(name: name)
    }

    private static func parseEdit(arguments: [String]) throws -> Command {
        guard let name = arguments.first else {
            throw AppError.usage("Missing entry name for edit.\n\n\(usageText)")
        }
        guard arguments.count == 1 else {
            throw AppError.usage("Unknown option '\(arguments[1])' for edit.\n\n\(usageText)")
        }
        return .edit(name: name)
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
