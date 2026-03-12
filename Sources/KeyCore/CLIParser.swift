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
        case "cp":
            return try parseCopy(arguments: Array(arguments.dropFirst()))
        case "mv":
            return try parseMove(arguments: Array(arguments.dropFirst()))
        case "rm":
            return try parseRemove(arguments: Array(arguments.dropFirst()))
        case "ls":
            return try parseList(arguments: Array(arguments.dropFirst()))
        case "help", "--help", "-h":
            throw AppError.usage(usageText)
        default:
            throw AppError.usage("Unknown command '\(subcommand)'.\n\n\(usageText)")
        }
    }

    public static let usageText = """
    Usage:
      key show <name> [--copy]
      key add <name>
      key add <name> --generate [--length <n>]
      key edit <name>
      key edit <name> --generate [--length <n>]
      key cp <src> <dst> [--force]
      key mv <src> <dst> [--force]
      key rm <name> [--force]
      key ls
    """

    private static func parseAdd(arguments: [String]) throws -> Command {
        guard let name = arguments.first else {
            throw AppError.usage("Missing entry name for add.\n\n\(usageText)")
        }

        var generate = false
        var length = 24
        var index = 1

        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "--generate":
                generate = true
                index += 1
            case "--length":
                let valueIndex = index + 1
                guard valueIndex < arguments.count else {
                    throw AppError.usage("Missing value for --length.\n\n\(usageText)")
                }
                guard let parsedLength = Int(arguments[valueIndex]), parsedLength > 0 else {
                    throw AppError.invalidLength("Length must be a positive integer.")
                }
                length = parsedLength
                index += 2
            default:
                throw AppError.usage("Unknown option '\(argument)' for add.\n\n\(usageText)")
            }
        }

        guard generate || length == 24 else {
            throw AppError.usage("--length requires --generate.\n\n\(usageText)")
        }

        if generate {
            return .add(name: name, mode: .generated(length: length, revealMode: .none))
        }
        return .add(name: name, mode: .manual)
    }

    private static func parseEdit(arguments: [String]) throws -> Command {
        guard let name = arguments.first else {
            throw AppError.usage("Missing entry name for edit.\n\n\(usageText)")
        }

        var generate = false
        var length = 24
        var index = 1

        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "--generate":
                generate = true
                index += 1
            case "--length":
                let valueIndex = index + 1
                guard valueIndex < arguments.count else {
                    throw AppError.usage("Missing value for --length.\n\n\(usageText)")
                }
                guard let parsedLength = Int(arguments[valueIndex]), parsedLength > 0 else {
                    throw AppError.invalidLength("Length must be a positive integer.")
                }
                length = parsedLength
                index += 2
            default:
                throw AppError.usage("Unknown option '\(argument)' for edit.\n\n\(usageText)")
            }
        }

        guard generate || length == 24 else {
            throw AppError.usage("--length requires --generate.\n\n\(usageText)")
        }

        if generate {
            return .edit(name: name, mode: .generated(length: length, revealMode: .none))
        }
        return .edit(name: name, mode: .manual)
    }

    private static func parseCopy(arguments: [String]) throws -> Command {
        guard let source = arguments.first else {
            throw AppError.usage("Missing source entry name for cp.\n\n\(usageText)")
        }
        guard arguments.count >= 2 else {
            throw AppError.usage("Missing destination entry name for cp.\n\n\(usageText)")
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
                throw AppError.usage("Unknown option '\(argument)' for cp.\n\n\(usageText)")
            }
        }

        return .copy(source: source, destination: destination, force: force)
    }

    private static func parseMove(arguments: [String]) throws -> Command {
        guard let source = arguments.first else {
            throw AppError.usage("Missing source entry name for mv.\n\n\(usageText)")
        }
        guard arguments.count >= 2 else {
            throw AppError.usage("Missing destination entry name for mv.\n\n\(usageText)")
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
                throw AppError.usage("Unknown option '\(argument)' for mv.\n\n\(usageText)")
            }
        }

        return .move(source: source, destination: destination, force: force)
    }

    private static func parseRemove(arguments: [String]) throws -> Command {
        guard let name = arguments.first else {
            throw AppError.usage("Missing entry name for rm.\n\n\(usageText)")
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
                throw AppError.usage("Unknown option '\(argument)' for rm.\n\n\(usageText)")
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

    private static func parseList(arguments: [String]) throws -> Command {
        guard arguments.isEmpty else {
            throw AppError.usage("Unknown option '\(arguments[0])' for ls.\n\n\(usageText)")
        }

        return .list
    }
}
