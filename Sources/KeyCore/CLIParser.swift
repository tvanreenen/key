import ArgumentParser
import Foundation

/// Translates command-line syntax into requests without performing vault operations.
public enum CLIParser {
    public static func parse(arguments: [String]) throws -> Command {
        guard !arguments.isEmpty else { throw AppError.usage(usageText) }
        do {
            var parsed = try KeyArguments.parseAsRoot(arguments)
            if let request = parsed as? any CLIRequest {
                return request.command
            }
            if parsed is KeyArguments || !type(of: parsed).configuration.subcommands.isEmpty {
                throw AppError.usage(KeyArguments.helpMessage(for: type(of: parsed), columns: helpColumns)
                    .trimmingCharacters(in: .newlines))
            }
            // The remaining parsed command is Argument Parser's built-in help.
            // Its run() throws the selected help request. Render it directly:
            // exitCode(for:) would also render at the unchecked terminal width,
            // which can assert for very narrow terminals in Argument Parser 1.8.2.
            do {
                try parsed.run()
            } catch {
                return .help(text: KeyArguments.fullMessage(for: error, columns: helpColumns)
                    .trimmingCharacters(in: .newlines))
            }
            throw AppError.usage(usageText)
        } catch let error as AppError {
            throw error
        } catch {
            let text = KeyArguments.fullMessage(for: error, columns: helpColumns)
                .trimmingCharacters(in: .newlines)
            if KeyArguments.exitCode(for: error) == .success {
                return .help(text: text)
            }
            throw AppError.usage(text)
        }
    }

    public static var usageText: String {
        KeyArguments.helpMessage(columns: helpColumns).trimmingCharacters(in: .newlines)
    }

    public static func helpText(for topic: String) -> String? {
        var command: any ParsableCommand.Type = KeyArguments.self
        for name in topic.split(separator: " ") {
            guard let child = command.configuration.subcommands.first(where: {
                $0.configuration.commandName == String(name)
            }) else { return nil }
            command = child
        }
        return KeyArguments.helpMessage(for: command, columns: helpColumns).trimmingCharacters(in: .newlines)
    }

    private static var helpColumns: Int {
        var size = winsize()
        let terminalWidth = ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0
            ? Int(size.ws_col) : 0
        let width = ProcessInfo.processInfo.environment["COLUMNS"].flatMap(Int.init)
            ?? (terminalWidth > 0 ? terminalWidth : 80)
        // Keep wide terminals readable and avoid Argument Parser's fixed label
        // column exceeding a very narrow window. Usage and long tokens stay intact.
        return min(80, max(40, width))
    }
}

/// These declarations describe syntax only; KeyCLIApplication owns execution.
private protocol CLIRequest: ParsableCommand {
    var command: Command { get }
}

private struct KeyArguments: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "key",
        abstract: "Manage secrets with macOS authentication and an encrypted vault folder.",
        discussion: CLIHelp.overview,
        groupedSubcommands: [
            CommandGroup(name: "Get started", subcommands: [Init.self, Share.self]),
            CommandGroup(name: "Work with secrets", subcommands: [
                Add.self, Edit.self, Get.self, Copy.self, List.self,
                Duplicate.self, Rename.self, Remove.self
            ]),
            CommandGroup(name: "Check and manage your vault", subcommands: [
                Status.self, Conflict.self, Config.self, Migrate.self,
                Unlock.self, Lock.self, Version.self
            ])
        ]
    )

    struct Init: CLIRequest {
        static let configuration = CommandConfiguration(
            commandName: "init", abstract: "Create a new vault and use it on this Mac.",
            discussion: CLIHelp.initialize
        )
        @Argument(help: "An empty directory. Defaults to the current directory.", completion: .directory)
        var directory: String?
        mutating func validate() throws {
            if let directory { try validateDirectory(directory) }
        }
        var command: Command { .initializeVault(path: directory) }
    }

    struct Version: CLIRequest {
        static let configuration = CommandConfiguration(
            commandName: "version", abstract: "Show the installed CLI's version and build number."
        )
        @Flag(help: "Print machine-readable version information.") var json = false
        var command: Command { .version(json: json) }
    }

    struct Migrate: CLIRequest {
        static let configuration = CommandConfiguration(
            commandName: "migrate", abstract: "Check or migrate a vault in the older format.",
            usage: "key migrate (--check | --apply)",
            discussion: CLIHelp.migrate
        )
        enum Action: String, EnumerableFlag { case check, apply }
        @Flag(exclusivity: .exclusive, help: "Use --check to inspect readiness or --apply to create and verify a migrated copy.")
        var action: Action
        var command: Command {
            action == .check ? .migrationPreflight : .migrationApply
        }
    }

    struct Status: CLIRequest {
        static let configuration = CommandConfiguration(
            commandName: "status", abstract: "Check vault health without editing its contents.",
            usage: "key status [--json | --verbose]",
            discussion: CLIHelp.status
        )
        @Flag(help: "Print machine-readable status with stable field names and codes.") var json = false
        @Flag(help: "Include storage-format and verified-history identifiers.") var verbose = false
        mutating func validate() throws {
            guard !(json && verbose) else {
                throw ValidationError("Use either --json or --verbose with status, not both.")
            }
        }
        var command: Command { .status(json: json, verbose: verbose) }
    }

    struct ReadOptions: ParsableArguments {
        @Argument(help: "The saved entry name.") var name: String
        @Flag(help: "Read the last complete version verified on this Mac, even if out of date.")
        var allowStale = false
    }

    struct Get: CLIRequest {
        static let configuration = CommandConfiguration(
            commandName: "get", abstract: "Print a secret or current one-time code.",
            discussion: CLIHelp.read
        )
        @OptionGroup var entry: ReadOptions
        var command: Command { .get(name: entry.name, allowStale: entry.allowStale) }
    }

    struct Copy: CLIRequest {
        static let configuration = CommandConfiguration(
            commandName: "copy", abstract: "Copy a secret or current one-time code to the clipboard.",
            discussion: CLIHelp.read
        )
        @OptionGroup var entry: ReadOptions
        var command: Command { .copy(name: entry.name, allowStale: entry.allowStale) }
    }

    struct WriteOptions: ParsableArguments {
        @Argument(help: "The entry name to save.") var name: String
        @Flag(help: "Store a Base32 authenticator setup secret to generate one-time codes.")
        var totp = false
        var type: SecretEntryType { totp ? .totp : .secret }
    }

    struct Add: CLIRequest {
        static let configuration = CommandConfiguration(
            commandName: "add", abstract: "Save a secret or authenticator setup secret.",
            discussion: CLIHelp.write + "\n\nExisting entries are not overwritten; use key edit to replace one."
        )
        @OptionGroup var entry: WriteOptions
        var command: Command { .add(name: entry.name, type: entry.type) }
    }

    struct Edit: CLIRequest {
        static let configuration = CommandConfiguration(
            commandName: "edit", abstract: "Replace a saved secret or authenticator setup secret.",
            discussion: CLIHelp.write + "\n\nUse --totp again when replacing an authenticator setup secret."
        )
        @OptionGroup var entry: WriteOptions
        var command: Command { .edit(name: entry.name, type: entry.type) }
    }

    struct TransferOptions: ParsableArguments {
        @Argument(help: "The existing entry name.") var source: String
        @Argument(help: "The new entry name.") var destination: String
        @Flag(help: "Replace an existing destination without asking for confirmation.")
        var force = false
    }

    struct Duplicate: CLIRequest {
        static let configuration = CommandConfiguration(
            commandName: "duplicate", abstract: "Copy an entry under another name.",
            discussion: "An existing destination is refused unless you supply --force.\n\nExample: key duplicate github/old github/new"
        )
        @OptionGroup var entries: TransferOptions
        var command: Command { .duplicate(source: entries.source, destination: entries.destination, force: entries.force) }
    }

    struct Rename: CLIRequest {
        static let configuration = CommandConfiguration(
            commandName: "rename", abstract: "Change an entry's name.",
            discussion: "An existing destination is refused unless you supply --force.\n\nExample: key rename github/old github/new"
        )
        @OptionGroup var entries: TransferOptions
        var command: Command { .rename(source: entries.source, destination: entries.destination, force: entries.force) }
    }

    struct Remove: CLIRequest {
        static let configuration = CommandConfiguration(
            commandName: "remove", abstract: "Delete an entry after confirmation.",
            discussion: "Key asks for confirmation in an interactive terminal. --force skips confirmation and is required when running non-interactively."
        )
        @Argument(help: "The entry name to delete.") var name: String
        @Flag(help: "Delete without asking for confirmation.") var force = false
        var command: Command { .remove(name: name, force: force) }
    }

    struct List: CLIRequest {
        static let configuration = CommandConfiguration(
            commandName: "list", abstract: "List saved entry names.",
            discussion: "Print saved entry names, one per line. Secret values are not printed."
        )
        var command: Command { .list }
    }

    struct Unlock: CLIRequest {
        static let configuration = CommandConfiguration(
            commandName: "unlock", abstract: "Unlock the vault before running other commands.",
            discussion: CLIHelp.unlock
        )
        var command: Command { .unlock }
    }

    struct Lock: CLIRequest {
        static let configuration = CommandConfiguration(
            commandName: "lock", abstract: "Lock the vault on this Mac.",
            discussion: CLIHelp.lock
        )
        var command: Command { .lock }
    }

    struct Config: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "config", abstract: "Show or change this Mac's vault settings.",
            discussion: CLIHelp.config, subcommands: [Get.self, Set.self, List.self]
        )
        enum Setting: String, ExpressibleByArgument, CaseIterable {
            case vaultDir = "vault-dir"
            case keychainMode = "keychain-mode"
            var key: ConfigKey {
                switch self {
                case .vaultDir: .vaultDir
                case .keychainMode: .keychainMode
                }
            }
        }
        struct Get: CLIRequest {
            static let configuration = CommandConfiguration(commandName: "get", abstract: "Print one setting.")
            @Argument(help: "The setting name.") var name: Setting
            var command: Command { .config(.get(key: name.key)) }
        }
        struct Set: CLIRequest {
            static let configuration = CommandConfiguration(
                commandName: "set", abstract: "Change a setting in existing configuration.",
                discussion: "Changing vault-dir does not move files or join another vault. The complete vault must already exist at the new path. See key config --help for details."
            )
            @Argument(help: "The setting name.") var name: Setting
            @Argument(help: "The new directory path, or local/icloud for the legacy keychain-mode setting.") var value: String
            var command: Command { .config(.set(key: name.key, value: value)) }
        }
        struct List: CLIRequest {
            static let configuration = CommandConfiguration(commandName: "list", abstract: "Print this Mac's vault settings.")
            var command: Command { .config(.list) }
        }
    }

    struct Conflict: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "conflict", abstract: "Review conflicting entries and choose what to keep.",
            discussion: CLIHelp.conflict,
            subcommands: [List.self, Show.self, Get.self, Copy.self, Resolve.self]
        )
        struct List: CLIRequest {
            static let configuration = CommandConfiguration(commandName: "list", abstract: "List the current conflicts.")
            @Flag(help: "Print machine-readable conflicts.") var json = false
            var command: Command { .conflict(.list(json: json)) }
        }
        struct Show: CLIRequest {
            static let configuration = CommandConfiguration(commandName: "show", abstract: "Show the choices for one conflict.")
            @Argument(help: "The conflict ID from key conflict list.") var conflictID: String
            @Flag(help: "Print machine-readable conflict details.") var json = false
            var command: Command { .conflict(.show(id: conflictID, json: json)) }
        }
        struct ValueOptions: ParsableArguments {
            @Argument(help: "The conflict ID.") var conflictID: String
            @Argument(help: "The version ID from key conflict show.") var versionID: String
        }
        struct Get: CLIRequest {
            static let configuration = CommandConfiguration(commandName: "get", abstract: "Print one conflicting secret version.")
            @OptionGroup var choice: ValueOptions
            var command: Command { .conflict(.get(id: choice.conflictID, versionID: choice.versionID)) }
        }
        struct Copy: CLIRequest {
            static let configuration = CommandConfiguration(commandName: "copy", abstract: "Copy one conflicting secret version to the clipboard.")
            @OptionGroup var choice: ValueOptions
            var command: Command { .conflict(.copy(id: choice.conflictID, versionID: choice.versionID)) }
        }
        struct Resolve: CLIRequest {
            static let configuration = CommandConfiguration(
                commandName: "resolve", abstract: "Choose a version for every current conflict.",
                discussion: "Review all versions first. Choosing a version can discard another edit or keep a deletion. If the vault changes during review, review the new conflicts before retrying.\n\nExample: key conflict resolve conflict-a=version-a conflict-b=version-b"
            )
            @Argument(help: ArgumentHelp("One conflict-id=version-id choice per conflict.", valueName: "conflict-id=version-id"), transform: parseResolution)
            var choices: [VaultConflictResolution]
            mutating func validate() throws {
                guard !choices.isEmpty else {
                    throw ValidationError("Provide every resolution as <conflict-id>=<version-id>.")
                }
            }
            var command: Command { .conflict(.resolve(choices)) }
        }
    }

    struct Share: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "share", abstract: "Add another Mac to an existing vault or manage access.",
            discussion: CLIHelp.share,
            subcommands: [Devices.self, Invite.self, Invitations.self, Join.self,
                          Requests.self, Compare.self, Approve.self, Accept.self, Revoke.self]
        )

        // Arrays preserve occurrences so validate() can reject duplicates instead
        // of silently accepting Argument Parser's last value for a scalar option.
        struct IdentityOptions: ParsableArguments {
            @Option(name: .customLong("name"), help: ArgumentHelp("This Mac's readable name. Required; specify exactly once.", valueName: "this-mac-name"))
            var names: [String]
            mutating func validate() throws {
                guard names.count == 1 else {
                    throw ValidationError("Provide this Mac's readable name once with --name.")
                }
            }
            var name: String { names[0] }
        }

        struct DirectoryOptions: ParsableArguments {
            @Option(name: .customLong("vault-dir"), help: ArgumentHelp("An existing vault directory. Specify at most once; never switches a configured Mac to another vault.", valueName: "directory"), completion: .directory)
            var directories: [String] = []
            mutating func validate() throws {
                guard directories.count <= 1 else {
                    throw ValidationError("Specify --vault-dir only once.")
                }
                if let directory { try validateDirectory(directory) }
            }
            var directory: String? { directories.first }
        }

        struct Devices: CLIRequest {
            static let configuration = CommandConfiguration(commandName: "devices", abstract: "List enrolled Macs and their recorded names.")
            @Flag(help: "Print machine-readable device information.") var json = false
            var command: Command { .share(.devices(json: json)) }
        }

        struct Invite: CLIRequest {
            static let configuration = CommandConfiguration(
                commandName: "invite", abstract: "Create an invitation on a Mac that already has access.",
                usage: "key share invite --name <this-mac-name>",
                discussion: "Use this Mac's exact recorded name from key share devices, not the joining Mac's name. Invitations expire after 10 minutes. See key share --help for the full sequence."
            )
            @OptionGroup var identity: IdentityOptions
            var command: Command { .share(.invite(deviceName: identity.name)) }
        }

        struct Invitations: CLIRequest {
            static let configuration = CommandConfiguration(
                commandName: "invitations", abstract: "Find invitations in the existing vault folder.",
                usage: "key share invitations [--vault-dir <directory>]",
                discussion: CLIHelp.joiningDirectory
            )
            @OptionGroup var location: DirectoryOptions
            var command: Command { .share(.invitations, vaultDirectory: location.directory) }
        }

        struct Join: CLIRequest {
            static let configuration = CommandConfiguration(
                commandName: "join", abstract: "Request access from the joining Mac.",
                usage: "key share join <invitation-id> --name <this-mac-name> [--vault-dir <directory>]",
                discussion: "Use --name for the name you want to give this joining Mac. Follow the commands printed on both Macs; joining is not complete until verified acceptance.\n\n" + CLIHelp.joiningDirectory
            )
            @Argument(help: "The invitation ID from key share invitations.") var invitationID: String
            @OptionGroup var identity: IdentityOptions
            @OptionGroup var location: DirectoryOptions
            var command: Command {
                .share(.join(invitationID: invitationID, deviceName: identity.name), vaultDirectory: location.directory)
            }
        }

        struct Requests: CLIRequest {
            static let configuration = CommandConfiguration(commandName: "requests", abstract: "Review requests on the Mac that created the invitation.")
            @Argument(help: "The invitation ID from key share invite.") var invitationID: String
            var command: Command { .share(.requests(invitationID: invitationID)) }
        }

        struct Compare: CLIRequest {
            static let configuration = CommandConfiguration(
                commandName: "compare", abstract: "Show the comparison code and Mac names for this attempt.",
                usage: "key share compare <vault-id> <invitation-id> [<request-id>] [--vault-dir <directory>]",
                discussion: "Compare the exact code and both Mac names on the two screens. Stop if they differ. On the existing Mac, include the request ID printed by key share requests.\n\n" + CLIHelp.joiningDirectory
            )
            @Argument(help: "The vault ID printed during this attempt.") var vaultID: String
            @Argument(help: "The invitation ID.") var invitationID: String
            @Argument(help: "The joining request ID, required on the existing Mac.") var requestID: String?
            @OptionGroup var location: DirectoryOptions
            var command: Command {
                .share(.compare(vaultID: vaultID, invitationID: invitationID, joinRequestID: requestID), vaultDirectory: location.directory)
            }
        }

        struct ConfirmationOptions: ParsableArguments {
            @Argument(help: "The vault ID printed during this attempt.") var vaultID: String
            @Argument(help: "The invitation ID.") var invitationID: String
            @Argument(help: "The exact comparison code verified on both screens.") var comparisonCode: String
        }

        struct Approve: CLIRequest {
            static let configuration = CommandConfiguration(
                commandName: "approve", abstract: "Approve access on the Mac that created the invitation.",
                discussion: "Compare the exact code and both Mac names on the two screens first. Stop if they differ. After approval, run the printed accept command on the joining Mac."
            )
            @OptionGroup var confirmation: ConfirmationOptions
            var command: Command {
                .share(.approve(vaultID: confirmation.vaultID, invitationID: confirmation.invitationID, comparisonCode: confirmation.comparisonCode))
            }
        }

        struct Accept: CLIRequest {
            static let configuration = CommandConfiguration(
                commandName: "accept", abstract: "Verify approved access and configure the joining Mac.",
                usage: "key share accept <vault-id> <invitation-id> <comparison-code> [--vault-dir <directory>]",
                discussion: "Compare the exact code and both Mac names on the two screens before approval and acceptance. Stop if they differ. Only verified acceptance saves this Mac's vault configuration.\n\n" + CLIHelp.joiningDirectory
            )
            @OptionGroup var confirmation: ConfirmationOptions
            @OptionGroup var location: DirectoryOptions
            var command: Command {
                .share(.accept(vaultID: confirmation.vaultID, invitationID: confirmation.invitationID, comparisonCode: confirmation.comparisonCode), vaultDirectory: location.directory)
            }
        }

        struct Revoke: CLIRequest {
            static let configuration = CommandConfiguration(
                commandName: "revoke", abstract: "Review and remove a Mac's access.",
                discussion: "Key shows a review and requires you to type REVOKE. The removed Mac cannot read the new vault or future changes, but keeps any secrets and older vault data it already obtained.\n\nA lost or revoked Mac rejoins through an invitation from a surviving Mac. If every enrolled Mac is lost, the vault folder alone cannot restore access."
            )
            @Argument(help: "The device ID from key share devices.") var deviceID: String
            var command: Command { .share(.revoke(deviceID: deviceID)) }
        }
    }
}

private func validateDirectory(_ path: String) throws {
    guard !path.isEmpty, !path.utf8.contains(0) else {
        throw ValidationError("Provide one nonempty directory path without NUL characters.")
    }
}

private func parseResolution(_ argument: String) throws -> VaultConflictResolution {
    let parts = argument.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
    guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty else {
        throw ValidationError("Expected <conflict-id>=<version-id> for each resolution.")
    }
    return VaultConflictResolution(conflictID: String(parts[0]), versionID: String(parts[1]))
}
