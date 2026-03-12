import Foundation

public enum CLIParser {
    public static func parse(arguments: [String]) throws -> Command {
        guard let subcommand = arguments.first else {
            throw AppError.usage(usageText)
        }

        switch subcommand {
        case "get":
            return try parseGet(arguments: Array(arguments.dropFirst()))
        case "put":
            return try parsePut(arguments: Array(arguments.dropFirst()))
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
      key get <name> [--copy]
      key put <name> [--force]
      key put <name> --generate [--length <n>] [--force] [--show | --copy]
      key ls
    """

    private static func parsePut(arguments: [String]) throws -> Command {
        guard let name = arguments.first else {
            throw AppError.usage("Missing entry name for put.\n\n\(usageText)")
        }

        var force = false
        var generate = false
        var length = 24
        var revealMode: RevealMode = .none
        var index = 1

        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "--force":
                force = true
                index += 1
            case "--generate":
                generate = true
                index += 1
            case "--show":
                guard revealMode == .none else {
                    throw AppError.usage("Only one of --show or --copy may be used.\n\n\(usageText)")
                }
                revealMode = .show
                index += 1
            case "--copy":
                guard revealMode == .none else {
                    throw AppError.usage("Only one of --show or --copy may be used.\n\n\(usageText)")
                }
                revealMode = .copy
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
                throw AppError.usage("Unknown option '\(argument)' for put.\n\n\(usageText)")
            }
        }

        guard generate || revealMode == .none else {
            throw AppError.usage("--show and --copy require --generate.\n\n\(usageText)")
        }
        guard generate || length == 24 else {
            throw AppError.usage("--length requires --generate.\n\n\(usageText)")
        }

        if generate {
            return .put(name: name, mode: .generated(length: length, revealMode: revealMode), force: force)
        }
        return .put(name: name, mode: .manual, force: force)
    }

    private static func parseGet(arguments: [String]) throws -> Command {
        guard let name = arguments.first else {
            throw AppError.usage("Missing entry name for get.\n\n\(usageText)")
        }

        var copy = false
        for argument in arguments.dropFirst() {
            switch argument {
            case "--copy":
                copy = true
            default:
                throw AppError.usage("Unknown option '\(argument)' for get.\n\n\(usageText)")
            }
        }

        return .get(name: name, copy: copy)
    }

    private static func parseList(arguments: [String]) throws -> Command {
        guard arguments.isEmpty else {
            throw AppError.usage("Unknown option '\(arguments[0])' for ls.\n\n\(usageText)")
        }

        return .list
    }
}
