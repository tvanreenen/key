import Foundation

extension CLIParser {
    public static let usageText = """
    Usage: key <command> [arguments]

    Get started:
      init [directory]       Create a new vault and use it on this Mac.
      share                  Add another Mac to an existing vault or manage access.
      help <command>         Show instructions and examples for a command.

    Work with secrets:
      add [--totp] <name>     Save a secret or authenticator setup secret.
      edit [--totp] <name>    Replace a saved secret or authenticator setup secret.
      get <name>             Print a secret or current one-time code.
      copy <name>            Copy a secret or current one-time code to the clipboard.
      list                   List saved entry names.
      duplicate <src> <dst>   Copy an entry to another name.
      rename <src> <dst>      Change an entry's name.
      remove <name>          Delete an entry after confirmation.

    Check and manage your vault:
      status                 Check vault health without editing its contents.
      conflict               Review conflicting entries and choose what to keep.
      config                 Show or change this Mac's vault settings.
      migrate                Check or migrate a vault in the older format.
      unlock                 Unlock the vault before running other commands.
      lock                   Lock the vault on this Mac.
      version [--json]       Show the installed CLI version.

    Use `key <command> --help` for options and examples.
    Help, version, and lock work before setup. Other commands need a configured vault,
    except the joining steps described in `key help share`.

    Keep access to your vault:
      Keep at least two active enrolled Macs. If every enrolled Mac is lost,
      you cannot recover access from the vault folder alone. There is currently
      no password, cloud, or support fallback.
    """

    public static func helpText(for topic: String) -> String? {
        switch topic {
        case "init":
            """
            Usage: key init [directory]

            Create a new vault and use it for future commands on this Mac.
            With no directory, Key uses your current directory. It must be empty,
            including hidden files. If the destination does not exist, Key creates
            it; the parent directory must already exist. Destination symlinks are refused.

            Examples:
              key init
              key init /path/to/NewVault
              key init -- -vault

            Key checks that this Mac can reopen the new vault before saving its
            configuration. Init never replaces existing configuration or reinitializes
            a vault. If setup is interrupted, keep the files and local records intact
            and follow the error's instructions; do not delete them to force a retry.

            To join a vault from another Mac, use `key help share`, not init.
            An empty synced folder may still have files waiting to download.

            After setup: run `key status`, then `key add <name>`.
            Add another Mac before relying on this vault. If every enrolled Mac is
            lost, a backup of the vault folder alone cannot restore access.
            """
        case "share":
            """
            Add another Mac to the same vault, or review and remove access.

            Commands:
              key share devices [--json]
              key share invite --name <this-mac-name>
              key share invitations [--vault-dir <directory>]
              key share join <invitation-id> --name <this-mac-name> [--vault-dir <directory>]
              key share requests <invitation-id>
              key share compare <vault-id> <invitation-id> [request-id] [--vault-dir <directory>]
              key share approve <vault-id> <invitation-id> <comparison-code>
              key share accept <vault-id> <invitation-id> <comparison-code> [--vault-dir <directory>]
              key share revoke <device-id>

            On a Mac that already has access:
              Run `key share devices` to find this Mac's recorded name.
              Run `key share invite --name "Existing Mac"` using that exact name.
              --name identifies this Mac, not the Mac you are inviting.

            On the joining Mac:
              Open the existing synced vault folder in your terminal. Do not run init.
              Run `key share invitations`, then:
              key share join <invitation-id> --name "New Mac"
              Here, --name is the name you want to give the joining Mac.

            Follow the commands printed on each Mac. Compare the exact code and both
            Mac names on the two screens. Stop if they differ. Approve on the existing
            Mac, then accept on the joining Mac. Only verified acceptance saves the
            joining Mac's vault configuration. Invitations expire after 10 minutes.

            Folder selection:
              With no configuration, joining commands use the current directory.
              Use --vault-dir on invitations/join/compare/accept to run elsewhere.
              Keep using the same folder and invitation for that attempt.
              A configured Mac uses its configured folder; --vault-dir cannot switch vaults.
              Joining never creates a folder. Wait for existing vault files to download.

            Removing access:
              `key share revoke` shows a review and requires you to type REVOKE.
              The removed Mac cannot read the new vault or future changes, but keeps
              any secrets and older vault data it already obtained.
              A lost or revoked Mac rejoins through an invitation from a surviving Mac.

            Keep at least two active enrolled Macs. If all are lost, the vault folder
            alone cannot restore access. There is no password, cloud, or support fallback.
            """
        case "config":
            """
            Usage:
              key config list
              key config get <name>
              key config set <name> <value>

            vault-dir is the folder Key uses for this vault. To correct its path after
            deliberately moving the complete vault:
              key config set vault-dir /path/to/ExistingVault

            The folder must already exist. This changes the path, not the vault's ID,
            and does not move files or join a different vault. Missing vault files or
            keys are errors; Key will not create replacements.

            For device-enrolled vaults, put the vault folder in iCloud Drive or another
            file-sync location to synchronize files. keychain-mode does not control
            their synchronization or device access. Key retains that setting for
            compatibility and omits it from `config list` for these vaults.

            Older vaults support keychain-mode values local and icloud for key storage.
            Use `key help migrate` to learn about moving to the newer vault format.
            Config commands require existing configuration. Use init for a new vault
            or share to join an existing one; config set is not a setup command.
            """
        case "migrate":
            """
            Usage:
              key migrate --check
              key migrate --apply

            Move an older Keychain-backed vault to the device-enrolled format.
            --check verifies readiness without changing files or Keychain items.
            --apply creates a new copy, verifies it, and configures this Mac to use it.
            Migration never starts automatically.

            Key retains the original files. Keep them while checking the migration.
            They do not receive later changes from the new vault and cannot restore
            access to it. Other Macs are not migrated automatically; add them to the
            new vault using `key help share` after installing a compatible release.

            Keep at least two active enrolled Macs. If all are lost, the new vault's
            files alone cannot restore access. No password, cloud, or support fallback
            is currently available.

            The older vault format (v2) is deprecated, but reads and writes still work.
            No removal release has been scheduled. Format numbers describe storage
            compatibility, not the version of the Key app.
            """
        case "status":
            """
            Usage: key status [--json] [--verbose]

            Check whether your vault is ready to use, has missing files, or needs
            attention. This does not edit entries or resolve conflicts.
            --verbose includes storage-format and verified-history identifiers.
            --json prints machine-readable status with stable field names and codes.

            If files are unavailable, check your sync provider before retrying.
            Local APFS and iCloud Drive were directly validated for Stable 0.2.0.
            Other ordinary folder-backed providers may work, but are not directly validated.
            These results do not qualify new setup behavior in later builds.
            """
        case "conflict":
            """
            Usage:
              key conflict list [--json]
              key conflict show <conflict-id> [--json]
              key conflict get <conflict-id> <version-id>
              key conflict copy <conflict-id> <version-id>
              key conflict resolve <conflict-id>=<version-id> ...

            Start with list, then show each conflict. Use get or copy to inspect a
            particular secret version. Get prints the secret; copy uses the clipboard.
            Resolve every current conflict together, with one choice for each conflict.
            If the vault changes during review, review the new conflicts before retrying.

            Choosing a version can discard another edit or keep a deletion. Review all
            versions first. Conflicts involving older revisions or device access cannot
            be bypassed with resolve. Keep vault files and local records intact if Key
            reports that it cannot safely continue.
            """
        case "get", "copy":
            """
            Usage: key \(topic) <name> [--allow-stale]

            \(topic == "get" ? "Print a secret or its current one-time code." : "Copy a secret or its current one-time code to the clipboard.")
            Example: key \(topic) github/personal

            --allow-stale explicitly allows reading the last complete version already
            verified on this Mac when newer files are unavailable or have competing edits.
            That value may be out of date. It does not bypass failed security checks.
            """
        case "add", "edit":
            """
            Usage: key \(topic) [--totp] <name>

            \(topic == "add" ? "Save a new secret." : "Replace an existing secret.") Type it at the hidden prompt, or pipe it through
            standard input. Do not put the secret in the command's arguments.

            Examples:
              key \(topic) github/personal
              key \(topic) --totp github/mfa

            --totp stores an authenticator setup secret to generate one-time codes.
            Supply the Base32 secret, not a current code or a full otpauth:// URL.
            \(topic == "edit" ? "Use --totp again when replacing an authenticator setup secret." : "Existing entries are not overwritten; use key edit to replace one.")
            """
        case "duplicate", "rename":
            """
            Usage: key \(topic) <source> <destination> [--force]

            \(topic == "duplicate" ? "Copy an entry under another name." : "Change an entry's name.")
            Example: key \(topic) github/old github/new
            An existing destination is refused unless you supply --force.
            --force replaces that destination without asking for confirmation.
            """
        case "remove":
            """
            Usage: key remove <name> [--force]

            Delete an entry. Key asks for confirmation in an interactive terminal.
            --force skips confirmation and is required when running non-interactively.
            """
        case "unlock":
            """
            Usage: key unlock

            Authenticate with macOS before running commands that need the vault key.
            Key normally asks when access is needed, so unlocking in advance is optional.
            Access expires after inactivity. Use `key lock` to end it immediately.
            """
        case "lock":
            """
            Usage: key lock

            End this Mac's unlocked session and stop Key's background service.
            The next command that needs the vault key will require authentication.
            This does not lock other Macs or clear secrets already printed or copied.
            """
        case "list":
            """
            Usage: key list

            Print saved entry names, one per line. Secret values are not printed.
            """
        case "version":
            """
            Usage: key version [--json]

            Show the installed CLI's version and build number.
            --json prints machine-readable version information.
            """
        default:
            nil
        }
    }
}
