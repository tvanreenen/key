/// Workflow explanations supplied to Argument Parser's generated help.
/// Keep paragraphs unwrapped; the renderer owns wrapping and column alignment.
enum CLIHelp {
    static let recovery = """
    Recovery is not enabled in Stable or ordinary Preview builds. These commands define the guarded recovery interface under development; they do not opt a real vault into recovery.

    When enabled, restore will require the complete source vault files and a previously registered hardware recovery key. It creates a separate vault on an unconfigured Mac; it never replaces the source or this Mac's selected vault. The new vault has fresh Mac access and no recovery key registered until separately registered.

    When enabled, key recovery tokens lists connected candidates without choosing one. Use key recovery review --source <directory> --token <token-id> for a public source/credential review and its complete recipient ID. Neither command requests PIN/touch, reads entry objects or saves a restore attempt. Review does not prove possession or restorable contents and is not approval to restore.

    For restore/resume, specify --source, --destination, --token and --recipient exactly once. Paths may be absolute or relative to the current directory; Key never takes them from existing configuration. The token ID selects a connected device. The complete recipient ID identifies its recovery public key, not its certificate fingerprint. Neither selector is a secret or an approval.

    Key does not set up, reset or write to the hardware key. Enter its PIN only in the macOS dialog and physically touch the key when it flashes. Cancel unexpected prompts. Key does not automatically retry authentication or a failed restore.

    After interruption or a lost reply, leave the source, destination, local records and configuration intact. Do not initialize, enroll, change vault-dir, delete state to force a retry or start another restore. See key recovery resume --help. The storage provider is responsible for delivering files; Key cannot prove it has supplied every newer file.
    """

    static let recoveryTokens = """
    Not enabled in Stable or ordinary Preview builds. List at most 64 public token candidates with exact token IDs and reader names. No candidate is automatically selected; no slot certificate, key metadata, anchor or private operation is read. An empty list is not proof of missing recovery protection.

    Listing does not prove possession, compatibility, registration or restorable contents. Use the exact token ID with key recovery review --source <directory> --token <token-id>. Public observations may change if a key is removed or replaced; restore rechecks them independently. --json prints the same observations for scripts, not a readiness or approval signal.
    """

    static let recoveryCredential = """
    Gated public inspection of one explicitly selected token. Use the exact --token from recovery tokens. Reads the slot 9d credential, required reported P-256/generated/PIN-always/touch-always policy and anchor occupancy; returns the complete recipient ID even before registration. No PIN/touch, entry read, setup intent or token write is requested. Public metadata is not attestation or proof of possession, protected administration or recoverability.
    """

    static let recoveryRegistration = """
    Not enabled in Stable or ordinary Preview builds. Use only disposable vaults in an explicitly enabled qualification build until review and signed hardware testing are complete. The configured vault must use the recovery-capable format; explicit adoption is separate.

    Set up slot 9d externally with vendor tools: P-256 generated on the token, PIN always and touch always. Secure PIV administration separately and retain the required recovery/admin credentials safely. Key does not provision, reset or write the token and cannot infer protected administration from public key metadata.

    Inspect recovery credential --token <token-id> for its complete recipient ID. Run register prepare with that --token, --recipient and --export-anchor <new-file>. Preparation creates one locally owned encrypted candidate and exports public commitments only. Install those exact bytes using the documented external vendor-tool procedure. Then register finish with the same token/recipient verifies the installed anchor and requests one possession operation before activation. Enter PIN only in the macOS dialog; touch the key when it flashes.

    After a failed export or interruption, preserve all state. register resume-export exports the same locally owned candidate to a new file; it does not replace setup or rewrite the token. Explicit finish rechecks the original candidate or exact committed state. register status authenticates local registration state without contacting a token; it is not a hardware qualification or provider-freshness claim. Never delete records to force another attempt.
    """

    static let recoveryAdoption = """
    Gated explicit format adoption, not registration or recovery. Preserve a backup and coordinate upgrades on every Mac before changing the format. Old clients must refuse the new profile. Adoption performs complete authenticated resealing and changes the selected checkpoint, but adds no token recipient. It never writes hardware or changes vault-dir.

    Use --resume <complete-original-operation-id> only for the exact locally owned interrupted adoption. It never starts a replacement or adopts provider records. Preserve files and local records after interruption; do not delete ownership to retry. Check registration status after the helper restarts, then separately register a recovery key. This workflow requires an interactive terminal.
    """

    static let recoveryReview = """
    Not enabled in Stable or ordinary Preview builds. Provide --source and the exact --token from key recovery tokens once each. The source must already exist; Key never defaults to configured vault-dir. Review reads only the selected token's public P-256 credential, reported slot 9d policies and recognized recovery anchor, then checks bounded public history for a matching vault and one visible head.

    The reported policy must be generated-on-token with PIN always and touch always. Public metadata is not attestation, possession proof or proof that PIN/touch will be enforced in a later operation. An absent or unrecognized anchor, incompatible policy, missing history, competing heads or changed observations is refused without fallback.

    Review never requests PIN/touch, opens entry objects, creates a destination, reads local ownership records, saves a pending attempt or changes configuration. It can inspect public source state on a configured Mac or while local restore ownership remains. A listed entry count is not secret-content verification, a complete backup or proof of provider freshness. Only a later explicit restore can authenticate contents with the hardware key; it rechecks everything independently.

    --json prints the same public observations, with public-observation-only assurance, not readiness or restore approval. No private credential or confirmation token is returned. Keep unexpected state intact; no automatic retry or cleanup occurs.
    """

    static let recoveryRestore = """
    Not enabled in Stable or ordinary Preview builds. See key recovery --help for prerequisites and limits.

    Provide --name for this Mac's readable name, plus explicit --source, --destination, --token and --recipient. The source and destination parent must already exist. The destination itself must be missing, even if an existing folder is empty. Source and destination must be separate; Key refuses overlapping folders and never adopts, replaces or erases an existing destination.

    Successful restore authenticates the selected source contents and required history, then creates and selects a new vault. The source is unchanged. The helper restarts before ordinary use. Keep the source and hardware key until you have checked the new vault. Recovery protection is not inherited by the new vault.

    If the command fails, times out or loses its reply, do not repeat restore automatically. Preserve all state and explicitly resume the exact attempt when possible. A failure before a complete saved preparation may require inspection instead of resume.
    """

    static let recoveryResume = """
    Not enabled in Stable or ordinary Preview builds. Resume is not a new restore or a general repair command.

    Provide the original --source, --destination, --token and complete --recipient. Do not supply a new Mac name. Key requires the exact locally owned attempt and existing folders, credentials, preparation and completion state. It never recreates missing state, adopts another attempt or falls back to restore. A completed attempt whose ownership records are cleared cannot be resumed again as proof of success.

    If the helper reports that it is restarting, run key lock, then key status. Status alone does not prove completion or clear saved ownership. Resume explicitly when a saved attempt remains. If no complete preparation is available or resume refuses changed or missing state, stop and preserve it for inspection; do not delete records or folders to force a retry. No PIN or hardware operation is automatically retried.
    """

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
