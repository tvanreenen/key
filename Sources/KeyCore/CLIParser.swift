import Foundation

public enum CLIParser {
    public static func parse(arguments: [String]) throws -> Command {
        guard let subcommand = arguments.first else {
            throw AppError.usage(usageText)
        }

        switch subcommand {
        case "show":
            return try parseShow(arguments: Array(arguments.dropFirst()))
        case "add":
            return try parseAdd(arguments: Array(arguments.dropFirst()))
        case "edit":
            return try parseEdit(arguments: Array(arguments.dropFirst()))
        case "copy", "cp":
            return try parseCopy(arguments: Array(arguments.dropFirst()), commandName: subcommand)
        case "move", "mv":
            return try parseMove(arguments: Array(arguments.dropFirst()), commandName: subcommand)
        case "remove", "rm":
            return try parseRemove(arguments: Array(arguments.dropFirst()), commandName: subcommand)
        case "list", "ls":
            return try parseList(arguments: Array(arguments.dropFirst()), commandName: subcommand)
        case "help", "--help", "-h":
            throw AppError.usage(usageText)
        default:
            throw AppError.usage("Unknown command '\(subcommand)'.\n\n\(usageText)")
        }
    }

    public static let usageText = """
    macOS file-based secret manager with native auth

    Usage:
      key show <name> [--copy]
      key add <name>
      key edit <name>
      key copy <src> <dst> [--force]
      key move <src> <dst> [--force]
      key remove <name> [--force]
      key list

    Commands:
      show    Write a secret to stdout.
      add     Add a new secret.
      edit    Update an existing secret.
      copy    Copy a secret to a new name.
      move    Move a secret to a new name.
      remove  Remove a secret.
      list    List stored secrets.
    """

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

    private static func parseCopy(arguments: [String], commandName: String) throws -> Command {
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

        return .copy(source: source, destination: destination, force: force)
    }

    private static func parseMove(arguments: [String], commandName: String) throws -> Command {
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

        return .move(source: source, destination: destination, force: force)
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

    private static func parseShow(arguments: [String]) throws -> Command {
        guard let name = arguments.first else {
            throw AppError.usage("Missing entry name for show.\n\n\(usageText)")
        }

        var copy = false
        for argument in arguments.dropFirst() {
            switch argument {
            case "--copy":
                copy = true
            default:
                throw AppError.usage("Unknown option '\(argument)' for show.\n\n\(usageText)")
            }
        }

        return .show(name: name, copy: copy)
    }

    private static func parseList(arguments: [String], commandName: String) throws -> Command {
        guard arguments.isEmpty else {
            throw AppError.usage("Unknown option '\(arguments[0])' for \(commandName).\n\n\(usageText)")
        }

        return .list
    }
}
