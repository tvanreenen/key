/// Workflow explanations supplied to Argument Parser's generated help.
/// Keep paragraphs unwrapped; the renderer owns wrapping and column alignment.
enum CLIHelp {
    static let overview = """
    Use key init for a new vault, or key share to join one from another Mac. Run key <command> --help for options and examples.

    Help, version, and lock work before setup. Other commands need a configured vault, except the joining steps described in key share --help.

    Keep at least two active enrolled Macs. If every enrolled Mac is lost, you cannot recover access from the vault folder alone. There is currently no password, cloud, or support fallback.
    """

    static let initialize = """
    With no directory, Key uses your current directory. It must be empty, including hidden files. If the destination does not exist, Key creates it; the parent directory must already exist. Destination symlinks are refused.

    Examples:
      key init
      key init /path/to/NewVault
      key init -- -vault

    Key checks that this Mac can reopen the new vault before saving its configuration. Init never replaces existing configuration or reinitializes a vault. If setup is interrupted, keep the files and local records intact and follow the error's instructions; do not delete them to force a retry.

    To join a vault from another Mac, use key share --help, not init. An empty synced folder may still have files waiting to download.

    After setup: run key status, then key add <name>. Add another Mac before relying on this vault. If every enrolled Mac is lost, a backup of the vault folder alone cannot restore access.
    """

    static let share = """
    On a Mac that already has access:
      Run key share devices to find this Mac's recorded name.
      Run key share invite --name "Existing Mac" using that exact name.
      --name identifies this Mac, not the Mac you are inviting.

    On the joining Mac:
      Open the existing synced vault folder in your terminal. Do not run init.
      Run key share invitations, then:
      key share join <invitation-id> --name "New Mac"
      Here, --name is the name you want to give the joining Mac.

    Follow the commands printed on each Mac. Compare the exact code and both Mac names on the two screens. Stop if they differ. Approve on the existing Mac, then accept on the joining Mac. Only verified acceptance saves the joining Mac's vault configuration. Invitations expire after 10 minutes.

    Folder selection:
    With no configuration, joining commands use the current directory. Use --vault-dir on invitations/join/compare/accept to run elsewhere. Keep using the same folder and invitation for that attempt. A configured Mac uses its configured folder; --vault-dir cannot switch vaults. Joining never creates a folder. Wait for existing vault files to download.

    Removing access:
    key share revoke shows a review and requires you to type REVOKE. The removed Mac cannot read the new vault or future changes, but keeps any secrets and older vault data it already obtained. A lost or revoked Mac rejoins through an invitation from a surviving Mac.

    Keep at least two active enrolled Macs. If all are lost, the vault folder alone cannot restore access. There is no password, cloud, or support fallback.
    """

    static let joiningDirectory = """
    With no configuration, this command uses the current directory. Use --vault-dir to select the existing vault folder elsewhere. A configured Mac uses its configured folder; --vault-dir cannot switch vaults. Joining never creates a folder. Wait for existing vault files to download, and do not run init.

    Keep using the same folder and invitation for this attempt. See key share --help for the full sequence.
    """

    static let config = """
    vault-dir is the folder Key uses for this vault. To correct its path after deliberately moving the complete vault:
      key config set vault-dir /path/to/ExistingVault

    The folder must already exist. This changes the path, not the vault's ID, and does not move files or join a different vault. Missing vault files or keys are errors; Key will not create replacements.

    For device-enrolled vaults, put the vault folder in iCloud Drive or another file-sync location to synchronize files. keychain-mode does not control their synchronization or device access. Key retains that setting for compatibility and omits it from config list for these vaults.

    Older vaults support keychain-mode values local and icloud for key storage. Use key migrate --help to learn about moving to the newer vault format.

    Config commands require existing configuration. Use init for a new vault or share to join an existing one; config set is not a setup command.
    """

    static let migrate = """
    Move an older Keychain-backed vault to the device-enrolled format. Migration never starts automatically; choose exactly one action.

    Examples:
      key migrate --check
      key migrate --apply

    --check verifies readiness without changing files or Keychain items. --apply creates a new copy, verifies it, and configures this Mac to use it.

    Key retains the original files. Keep them while checking the migration. They do not receive later changes from the new vault and cannot restore access to it. Other Macs are not migrated automatically; add them to the new vault using key share --help after installing a compatible release.

    Keep at least two active enrolled Macs. If all are lost, the new vault's files alone cannot restore access. No password, cloud, or support fallback is currently available.

    The older vault format (v2) is deprecated, but reads and writes still work. No removal release has been scheduled. Format numbers describe storage compatibility, not the version of the Key app.
    """

    static let status = """
    Check whether your vault is ready to use, has missing files, or needs attention. This does not edit entries or resolve conflicts. Use either --json or --verbose, not both.

    If files are unavailable, check your sync provider before retrying. Local APFS and iCloud Drive were directly validated for Stable 0.2.0. Other ordinary folder-backed providers may work, but are not directly validated. These results do not qualify new setup behavior in later builds.
    """

    static let conflict = """
    Start with key conflict list, then key conflict show for each conflict. Use get or copy to inspect a particular secret version. Get prints the secret; copy uses the clipboard.

    Resolve every current conflict together, with one choice for each conflict. If the vault changes during review, review the new conflicts before retrying.

    Choosing a version can discard another edit or keep a deletion. Review all versions first. Conflicts involving older revisions or device access cannot be bypassed with resolve. Keep vault files and local records intact if Key reports that it cannot safely continue.

    Example:
      key conflict resolve conflict-a=version-a conflict-b=version-b
    """

    static let read = """
    --allow-stale explicitly allows reading the last complete version already verified on this Mac when newer files are unavailable or have competing edits. That value may be out of date. It does not bypass failed security checks.

    Examples:
      key get github/personal
      key copy github/personal
    """

    static let write = """
    Type the secret at the hidden prompt, or pipe it through standard input. Do not put the secret in the command's arguments.

    --totp stores an authenticator setup secret to generate one-time codes. Supply the Base32 secret, not a current code or a full otpauth:// URL.

    Examples:
      key add github/personal
      key edit --totp github/mfa
    """

    static let unlock = """
    Authenticate with macOS before running commands that need the vault key. Key normally asks when access is needed, so unlocking in advance is optional. Access expires after inactivity. Use key lock to end it immediately.
    """

    static let lock = """
    End this Mac's unlocked session and stop Key's background service. The next command that needs the vault key will require authentication. This does not lock other Macs or clear secrets already printed or copied.
    """
}
