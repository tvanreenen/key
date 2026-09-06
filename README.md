# Key

![Key](.github/assets/hero.png)

Key is a secret manager for macOS, used from your terminal. It combines familiar macOS authentication with an encrypted vault folder you control, for passwords, tokens, and authenticator setup secrets. In a device-enrolled vault, Key verifies access and saved history itself; your sync provider delivers the files.

## Quick start

The commands below work in released Stable `0.2.0`. The development build also supports [first-time vault setup](#unreleased-first-time-vault-setup), without first creating and migrating a Keychain-backed vault.

After installing Key, add a secret from a secure prompt:

```sh
key add github/personal
```

Or pipe a value without placing it in the command-line arguments:

```sh
openssl rand -base64 32 | key add github/personal
```

Read or copy it, list the vault, and lock access on this Mac:

```sh
key get github/personal
key copy github/personal
key list
key lock
```

`key unlock` authenticates in advance. Otherwise, the first operation that needs key material prompts through macOS. Key Agent keeps an unlocked session copy in memory for a short idle window so separate CLI invocations can reuse it.

To generate one-time codes (TOTP), save the authenticator setup secret in Base32 format with `--totp`. You can also combine entry names with shell tools such as [`fzf`](https://github.com/junegunn/fzf):

```sh
key add --totp github/mfa
key copy github/mfa
key copy "$(key list | fzf)"
```

Full `otpauth://` URLs are not accepted yet; provide only their `secret` value. Key intentionally has no built-in password generator, so any generator that writes to stdout can feed `key add` or `key edit`.

## How access works

When a command first needs protected key material, macOS asks you to confirm your presence using Touch ID, Apple Watch approval, or your Mac password, depending on your hardware and settings. macOS enforces this requirement on access to the protected keys themselves. Apple explains the available [macOS authentication methods](https://developer.apple.com/documentation/LocalAuthentication/LAPolicy/deviceOwnerAuthentication) and how to [enable Apple Watch approval](https://support.apple.com/en-us/102442).

For a device-enrolled vault, each approved Mac has its own private access keys protected by the Secure Enclave. Those private keys cannot be exported to another Mac. After authentication, they let Key Agent, the signed background service, unlock the vault's encryption key in memory. The CLI asks that service to perform vault operations rather than loading protected keys itself. Another Mac needs an invitation and approval; copying the vault folder or signing into the same cloud account does not grant access.

Once unlocked, ordinary commands reuse the in-memory session instead of prompting every time. The session expires after 15 minutes of inactivity; using the vault key extends that window. Run `key lock` to end it immediately on this Mac. This convenience means user presence is checked when protected key access is needed, not separately for every secret read. Locking does not erase secrets already printed or copied, and an unlocked session is not a defense against malicious software operating through an authorized CLI on your Mac.

> [!NOTE]
> There is no separate vault password to remember. Your Mac password authorizes local key access; it is not used to derive the vault's encryption key and cannot restore access after every enrolled Mac is lost. See [vault protection](#how-key-protects-a-vault) for the differences between older and newer vault formats.

## Choose your sync provider

Put the vault folder in the location you want to use for file synchronization. For a device-enrolled vault, iCloud Drive works through the folder location, not a Keychain-mode setting. The sync provider carries encrypted files; it cannot approve another Mac or decide which vault history Key should trust.

The device-enrolled format also protects how changes are saved. Key writes new encrypted entries and history records without overwriting existing versions, verifies the saved files, and only then advances this Mac's record of the verified vault state. Local transaction records let it recognize interrupted ordinary writes and finish a verified change or retain the previous state. If the evidence needed to continue is missing or contradictory, Key stops instead of guessing. This crash-recovery behavior does not mean every interrupted setup or enrollment step can resume automatically.

Those checks matter when files arrive late, out of order, or incompletely. Key combines independent edits when it can do so safely and preserves conflicting edits for your choice, rather than letting a sync provider's timestamps decide which one wins. Files that do not match their authenticated history are rejected. An enrolled Mac checks history against its locally saved record, so presenting an older copy does not silently reset what that Mac already trusts. Missing files pause operations that need them; they do not cause Key to create an empty replacement vault.

> [!NOTE]
> Your sync provider delivers files; Key decides what it can safely use. Encryption, verified history, crash-aware writes, and conflict handling belong to the device-enrolled vault, so they do not require an iCloud-specific service.

These protections cannot make a provider deliver files, prevent it from deleting its copies, or recover a vault after all usable copies or all enrolled Macs are lost. Keep backups as well as another enrolled Mac. Local APFS and iCloud Drive have been directly qualified; other providers still need compatible filesystem behavior and testing. See [provider setup and conflicts](#provider-setup-and-conflicts) for the supported scope and inspection commands.

## Install and choose a release channel

Install Stable for ordinary use. Key Stable and Key Preview are separate installed products, not names for the two vault models. They can live side by side with different apps, CLIs, helpers, configuration, default vaults, and Keychain namespaces.

| Channel | Current release | App and CLI | Homebrew cask | Purpose |
|---|---|---|---|---|
| Stable | `0.2.0` | `Key.app`, `key` | `key` | Ordinary use |
| Preview | `0.2.0-beta.1` | `Key Preview.app`, `key-preview` | `key@beta` | Isolated prerelease testing |

The published Preview beta predates Stable `0.2.0`; install it only when you specifically need to reproduce that prerelease. Preview does not read or modify Stable configuration, vault selection, or Keychain state.

> [!IMPORTANT]
> Keep at least two Macs enrolled in a device-enrolled vault. If every enrolled Mac and its access credentials are lost, the vault is permanently unrecoverable in `0.2.0`. A backup of the vault folder alone cannot restore access. There is no password, cloud escrow, support override, or hidden recovery path.

### Install Stable

```sh
brew tap tvanreenen/tap
brew install --cask key
open -a Key
```

Existing Homebrew users can update in place:

```sh
brew update
brew upgrade --cask key
open -a Key
```

Open `Key.app` once after installation or upgrade so macOS can register Key Agent. If macOS asks, allow the background item. Then confirm that the CLI and helper are available:

```sh
key version
key status
```

### Install Preview (optional)

```sh
brew install --cask tvanreenen/tap/key@beta
open -a "Key Preview"
key-preview version
key-preview status
```

The current Preview is older than Stable `0.2.0`. Do not point it at the live Stable vault; use its isolated default vault or a disposable copy. In the examples below, replace `key` with `key-preview` when reproducing Preview behavior.

## Unreleased: first-time vault setup

The development build adds `key init [directory]`. This command is not available in Stable `0.2.0`. After installing a build that includes it and opening Key once, initialize a brand-new vault in your current empty directory:

```sh
key init
key status
key add github/personal
```

Alternatively, give a relative or absolute destination. Key creates the final directory if missing; its parent must already exist. There is no separate configuration step or migration from an older vault:

```sh
key init "$HOME/Library/Mobile Documents/com~apple~CloudDocs/Key Vault"
```

Key checks that this Mac can reopen the new vault, then saves the settings that future commands will use. It refuses nonempty directories, destination symlinks, and any existing configuration, including malformed configuration. Hidden files count as contents. It never overwrites an existing vault or switches away from a configured one. Unlike Git, rerunning init does not reinitialize anything. Use `key init -- -vault` for a directory name beginning with a dash.

In this development build, creating a new vault requires `key init`. Ordinary vault commands and config reads or writes fail with setup guidance when no config exists; they do not create a default folder, config, or legacy vault key. `key help`, `key version`, and `key lock` remain available before setup. Existing configured vaults do not need to run init again.

If a configured folder or an older vault's Keychain key is missing, Key reports the problem instead of creating a replacement. Restore the existing vault or key. After deliberately moving the complete vault, use `key config set vault-dir <existing-directory>` to correct its path; the destination must already exist, and this preserves the selected vault ID. A directory replaced while the helper is running is refused until the helper restarts.

Init means **create a new vault**, not open a vault synchronized from another Mac. Use [device enrollment](#enrolling-another-mac) for that. An empty local directory listing cannot prove that a provider has no files waiting to arrive. Key checks for unexpected arrivals during initialization but does not control provider delivery.

In the development build, a new Mac can join directly from the existing synced vault folder. Do not run init first. The folder contains the files, but the existing Mac must still invite and approve the new Mac before it can use them.

On the joining Mac, after the existing Mac creates an invitation:

```sh
cd "$HOME/Library/Mobile Documents/com~apple~CloudDocs/Key Vault"
key share invitations
key share join <invitation-id> --name "Laptop"
```

Complete the [comparison and approval](#enrolling-another-mac) on the existing Mac, then accept from the same folder on the joining Mac:

```sh
key share accept <vault-id> <invitation-id> <comparison-code>
key status
key list
```

To run from elsewhere, add `--vault-dir <existing-directory>` to `share invitations`, `share join`, `share compare`, or `share accept`. Relative paths resolve against the CLI's current directory. Key prints the vault folder before sending the request. With an existing config, these commands use the configured folder regardless of the terminal's directory; an explicit different folder is refused, not selected. Enrollment never creates the vault folder or searches parent directories.

Sending a join request does not finish setup. After approval, `share accept` verifies the vault and saves this Mac's settings automatically. Key keeps local records of the joining attempt, including its invitation and folder, so an interrupted attempt cannot silently continue against a different vault. Keep these records intact when retrying. A copied, renamed, or replaced folder cannot silently reuse the attempt. Missing invitations or approvals may need time to sync; retry the same command against the same folder. If acceptance already saved config, run `key status` after the helper restarts instead of starting another enrollment.

If initialization is interrupted, leave the destination and the local `v3-init-attempts` records beside `config.toml` intact. Run `key status` to check whether Key finished configuring the vault. If it did, continue using that vault after the helper restarts. If it did not, the attempt requires inspection; init refuses to start another identity in that same directory, even after it is renamed. This release of the implementation has no automatic resume or cleanup command. The records contain an operation ID, path, and filesystem identity, not secret keys, and remain as local receipts after success.

Keep at least two Macs enrolled so one can add a replacement if the other is lost. Init does not add catastrophe recovery or require a YubiKey. Existing older vaults and their migration path remain supported. The retained `keychain_mode` setting does not need to be removed from existing configuration files.

## How Key protects a vault

Release channel and vault protection are separate choices. Stable `0.2.0` supports both protection models. New Stable vaults begin Keychain-backed, and upgrades preserve the existing Keychain-backed selection; installing the release never migrates a vault automatically. Moving to the device-enrolled model is a separate, explicit operation.

The on-disk names are format v2 and format v3, respectively. The rest of this README uses the descriptive model names because they express the security property that matters to a user:

- A **Keychain-backed vault** keeps its raw vault key in a local or synchronizable Keychain item.
- A **device-enrolled vault** wraps the vault key separately to every approved Mac's Secure Enclave identity and keeps plaintext key material only in Key Agent's short-lived session.

| | Keychain-backed (format v2) | Device-enrolled (format v3) |
|---|---|---|
| Access model | Any Mac that receives the selected Keychain item | Explicitly enrolled Macs with equal authority |
| Vault key | Persistent local or synchronizable Keychain item | Wrapped separately to each active Mac's Secure Enclave identity |
| Unlocked key | Reused briefly by Key Agent | Exists in plaintext only in Key Agent's short-lived memory session |
| Provider history | Individually encrypted named files | Authenticated, immutable, content-addressed history |
| Concurrency | Provider filesystem behavior | Automatic independent merges; explicit genuine-conflict resolution |
| Device loss | Depends on the configured Keychain mode | Recoverable only while at least one enrolled Mac survives |

A device-enrolled vault stores encrypted entries, authenticated manifests, public device metadata, and per-device vault-key wrappers in the selected folder. The provider can delay or omit files and deny service, but it cannot silently grant access or choose which history Key trusts.

## Moving to a device-enrolled vault

Migration is explicit and local. It never begins merely because a newer binary was installed.

First check whether your vault is ready to migrate. This does not change it:

```sh
key migrate --check
```

Review the report, then create a migrated copy and use it on this Mac:

```sh
key migrate --apply
```

Migration moves from the older Keychain-backed format (v2) to the device-enrolled format (v3). Key keeps the original files unchanged and checks that this Mac can open the new vault before configuring it for future commands. Keep the original files while checking the migration. They do not receive later changes from the new vault and cannot restore access to it. Stable `0.2.0` does not have a command to switch back automatically.

Other Macs remain on their existing Keychain-backed state. Their later edits are not imported into the migrated snapshot. Enroll each additional Mac into the device-enrolled vault instead of migrating independent copies of the same vault.

Preview can migrate only a Keychain-backed vault and key that already belong to Preview's isolated namespace. It cannot use Stable's protected Keychain state.

## Enrolling another Mac

Enrollment uses a 10-minute invitation and a comparison code. Both Macs must show the exact same device pair and code before approval.

On an active Mac, inspect the roster and create an invitation using this Mac's exact recorded name:

```sh
key share devices
key share invite --name "<this Mac's recorded name>"
```

On the joining Mac, discover or enter that invitation and create an answer:

```sh
key share invitations
key share join <invitation-id> --name "Laptop"
```

Use the IDs printed by those commands to compare on both Macs:

```sh
key share requests <invitation-id>
key share compare <vault-id> <invitation-id> [join-request-id]
```

Only after the device pair and comparison code match, approve on the existing Mac and accept on the joining Mac:

```sh
key share approve <vault-id> <invitation-id> <comparison-code>
key share accept <vault-id> <invitation-id> <comparison-code>
```

Each command prints the exact safe next command for its side of the ceremony. If an invitation expires, begin a fresh ceremony. A prepared exact approval may finish after provider delay, but expiry never authorizes a different request.

Inspect the authenticated roster at any time:

```sh
key share devices
```

## Revocation and replacement

```sh
key share revoke <device-id>
```

Removing a Mac's access requires authentication and confirmation. Key changes the encryption key and encrypts the current vault again for the Macs that keep access. The removed Mac cannot read that new vault or future changes, but removal cannot erase secrets, screenshots, exports, or older vault data it already obtained.

A lost or revoked Mac can rejoin only through a fresh invitation from a surviving active Mac. Running the ordinary `share join` command on the revoked Mac presents a replacement review and requires the literal `REJOIN` before removing only that Mac's unusable local enrollment state.

## Provider setup and conflicts

The device-enrolled vault is directly validated on local APFS and iCloud Drive. Other ordinary folder-backed providers may work if they preserve the required containment, atomicity, hydration, type, and naming semantics, but they have not been directly validated and are not covered by the `0.2.0` compatibility guarantee.

> [!TIP]
> If the vault is stored in iCloud Drive, Control-click its folder in Finder and choose [Keep Downloaded](https://support.apple.com/guide/mac-help/mchl1a02d711/mac) on every enrolled Mac. This helps keep required vault files available locally. It does not guarantee that every file has arrived, bypass Key's checks, or provide a way to restore access after losing every enrolled Mac.

Run `key status` when the vault needs attention. If required files are missing, check synchronization before trying again. Key combines independent edits automatically; use `key conflict list` and `key conflict show <id>` to review edits that need your choice. Failed verification, older revisions reappearing, or conflicting changes to device access stop operations instead of being accepted as ordinary edits. Keep the files and local records intact if Key cannot safely continue.

`key get` and `key copy` accept `--allow-stale` to read the last complete version already verified on this Mac when newer files are unavailable or have competing edits. The value may be out of date. This option does not bypass failed security checks or allow you to save changes.

To move a vault, move its complete directory and update the configured path:

```sh
mv ~/.key ~/Secrets/key-vault
key config set vault-dir ~/Secrets/key-vault
key config get vault-dir
```

Do not repoint one product at another product's live vault. If the default directory already contains unrelated files, Key refuses to adopt it.

## Command reference

In the development build, `key help` shows an overview. Use `key help init`, `key help share`, or `key <command> --help` for options, safety notes, and examples. Nested commands have their own help, such as `key share join --help` or `key help share join`; `-h` also works. These help topics are not available in Stable `0.2.0`. Storage-format numbers remain available in `key status --verbose` and JSON diagnostics; they describe vault compatibility, not the app version.

Options can appear before or after positional arguments. Use `--` before a name or path that begins with a dash. Help takes precedence over other arguments and never starts a vault operation, even when the rest of the command is incomplete or invalid. Invalid operational commands still fail with the existing usage exit code; their error wording and usage layout now come from Swift Argument Parser. Supply `--name` exactly once and `--vault-dir` at most once where supported. Secrets still belong at the hidden prompt or on standard input, never in command arguments.

Help paragraphs and descriptions wrap to the terminal width, or the `COLUMNS` override, between 40 and 80 columns. Output defaults to 80 columns when no width is available. Usage lines and long tokens stay intact and may be wider; narrower terminals may wrap them further.

```text
key status [--json | --verbose]           Explain vault health and the next safe action
key init [directory]                      Create a new vault and use it on this Mac (unreleased)
key unlock                                Unlock the vault before running other commands
key lock                                  Lock the vault on this Mac

key get <name> [--allow-stale]            Print a secret or current TOTP code
key copy <name> [--allow-stale]           Copy a secret or current TOTP code
key add [--totp] <name>                   Add a secret from stdin or a secure prompt
key edit [--totp] <name>                  Update a secret
key duplicate <src> <dst> [--force]       Duplicate an entry
key rename <src> <dst> [--force]          Rename an entry
key remove <name> [--force]               Remove an entry
key list                                  List entry names

key config get <config-name>              Print one configuration value
key config set <config-name> <value>      Update one configuration value
key config list                           List known configuration values

key migrate --check                       Check migration readiness without changing the vault
key migrate --apply                       Create and verify a migrated copy, then use it on this Mac

key conflict list [--json]                List unresolved device-enrolled conflicts
key conflict show <id> [--json]           Review the verified versions of a conflict
key conflict get <id> <version>           Print one conflicted value
key conflict copy <id> <version>          Copy one conflicted value
key conflict resolve <id>=<version>…      Resolve the complete listed conflict set

key share devices [--json]                List Macs recorded for this vault
key share revoke <device-id>              Review and remove a Mac's access
key share invitations                     List available invitations
key share invite --name <name>            Create an invitation from this Mac
key share join <invite> --name <name>     Answer an invitation on the joining Mac
key share requests <invite>               List answers to an invitation
key share compare <vault> <invite> [request]
                                          Show the device pair and comparison code
key share approve <vault> <invite> <code>
                                          Approve the compared joining Mac
key share accept <vault> <invite> <code>
                                          Finish joining the approved vault on this Mac

key version [--json]                      Print the CLI version
key help                                  Show the command overview
```

## macOS integration

Key is intentionally macOS-specific and requires macOS 14 or later for the device-enrolled Secure Enclave and CryptoKit HPKE profile. The installed product has three signed components:

1. `Key.app` registers the helper and shows installation diagnostics.
2. The `key` CLI handles command parsing, terminal I/O, and clipboard writes.
3. Key Agent owns Keychain and Secure Enclave access, encryption, authenticated storage operations, and the short-lived in-memory session.

The CLI talks to the on-demand helper over an authenticated XPC Mach service. `launchd` starts it when needed, and the helper exits after its idle window. The CLI does not directly access protected vault-key material.

## Security scope

Key uses AES-256-GCM for entries, HKDF-SHA256 and HMAC-SHA256 for derived manifest authentication, P-256 signatures for device-authorized transitions, and RFC 9180 HPKE with P-256, HKDF-SHA256, and AES-256-GCM for per-device vault key wrapping.

The `0.2.0` assurance boundary includes extensive focused internal review, automated fault and security coverage, notarized installed-product checks, and two-device physical qualification on local APFS and iCloud Drive. It has not received an independent third-party security audit. A third physical device and additional storage providers were not direct release gates.

For the complete promises and limitations, read:

- [Security, continuity, and recovery](docs/security-continuity-recovery.md)
- [Version 3 device-wrapped key architecture](docs/v3-device-wrapped-key-architecture.md)
- [Version 3 implementation and qualification tracker](docs/v3-vault-implementation.md)
- [Release process](docs/release.md)

## Development

The Swift package and release-script checks run with:

```sh
just test
```

Run `just test-cli-help` to build the CLI and check help alignment, narrow and wide terminal widths, output streams, and usage exits without accessing a vault. The product build workflow runs these checks against both bundled CLIs.

The Xcode project builds the signed host apps and helpers. Signing, notarization, Preview isolation, and release publication are documented in the [release process](docs/release.md) and [Apple setup guide](docs/apple-setup.md).

The CLI uses Apple's [Swift Argument Parser](https://github.com/apple/swift-argument-parser) for syntax, validation, and help. SwiftPM and Xcode both pin version `1.8.2`, with checked-in resolution files; initial builds need access to fetch the package. Command declarations only translate arguments into existing application requests. Authentication, secret input, service execution, and exit handling remain in Key's application layer. Workflow explanations live in `CLIHelp.swift` as unwrapped paragraphs. A few usage lines are explicitly supplied where duplicate-option limits or mutually exclusive choices need a more accurate synopsis than the generated one. Argument Parser is licensed under [Apache 2.0 with the Swift Runtime Library Exception](https://github.com/apple/swift-argument-parser/blob/1.8.2/LICENSE.txt).

Key is available under the [MIT License](LICENSE).
