# Key

![Key](.github/assets/hero.png)

Key is a macOS-native, CLI-first secret manager. It keeps encrypted vault files
in a folder you control, uses Touch ID, Apple Watch, or your Mac password for
local authentication, and exposes a small command set that composes naturally
with the shell. Behind that small interface is a signed, on-demand agent and a
device-enrolled security model designed to keep protected key material and
trust decisions away from the sync provider.

## Quick start

After installing Key, add a secret from a secure prompt:

```sh
key add github/personal
```

Or pipe a value without placing it in the command-line arguments:

```sh
openssl rand -base64 32 | key add github/personal
```

Read or copy it, list the vault, and explicitly clear the helper session:

```sh
key get github/personal
key copy github/personal
key list
key lock
```

`key unlock` authenticates in advance. Otherwise, the first operation that
needs key material prompts through macOS. Key Agent keeps an unlocked session
copy in memory for a short idle window so separate CLI invocations can reuse
it.

TOTP and shell composition are part of the ordinary workflow. Store a bare
Base32 TOTP seed with `--totp`, or combine hierarchical entry names with tools
such as [`fzf`](https://github.com/junegunn/fzf):

```sh
key add --totp github/mfa
key copy github/mfa
key copy "$(key list | fzf)"
```

Full `otpauth://` URLs are not accepted yet; provide only their `secret`
value. Key intentionally has no built-in password generator, so any generator
that writes to stdout can feed `key add` or `key edit`.

## Security beneath the CLI

The command-line client never accesses protected vault-key material directly.
It talks over authenticated XPC to the signed, on-demand Key Agent, while macOS
gates key use with Touch ID, Apple Watch, or your Mac password. Secrets use
AES-256-GCM authenticated encryption, and unlocked key material is reused only
inside the agent's short-lived memory session.

The device-enrolled vault strengthens that model for multiple Macs. Each Mac
holds non-exportable Secure Enclave identity keys, the vault key is wrapped
separately to every approved device using HPKE, and membership changes and
vault history are cryptographically authenticated. Your sync provider carries
ciphertext, but it cannot enroll a Mac, silently make old state trusted, or
choose a conflict winner.

## Install and choose a release channel

Key Stable and Key Preview are separate installed products, not names for the
two vault models. They can live side by side with different apps, CLIs,
helpers, configuration, default vaults, and Keychain namespaces.

| Channel | Current release | App and CLI | Homebrew cask | Vault model today |
|---|---|---|---|---|
| Stable | `0.1.2` | `Key.app`, `key` | `key` | Keychain-backed |
| Preview | `0.2.0-beta.1` | `Key Preview.app`, `key-preview` | `key@beta` | Device-enrolled |

The repository is preparing version `0.2.0` for Stable. Until that release is
published, the device-enrolled vault remains Preview-only. Preview does not
read or modify Stable configuration, vault selection, or Keychain state.

> [!IMPORTANT]
> Keep at least two Macs enrolled in a device-enrolled vault. If every enrolled
> Mac and its Secure Enclave identity is lost, the vault is permanently
> unrecoverable in `0.2.0`. Provider files alone are not a backup, and there is
> no password, cloud escrow, support override, or hidden recovery path.

### Install Stable

```sh
brew tap tvanreenen/tap
brew install --cask key
open -a Key
```

Open `Key.app` once after installation so macOS can register Key Agent. If
macOS asks, allow the background item. Then confirm that the CLI and helper are
available:

```sh
key version
key status
```

### Install Preview

```sh
brew install --cask tvanreenen/tap/key@beta
open -a "Key Preview"
key-preview version
key-preview status
```

Do not point Preview at the live Stable vault. Use Preview's isolated default
vault or a disposable copy. In the examples below, replace `key` with
`key-preview` when working in Preview.

## How Key protects a vault

Release channel and vault protection are separate choices. Stable currently
uses the Keychain-backed vault model. The `0.2.0` Preview is qualifying the
device-enrolled model that will move into Stable with the `0.2.0` release.

The on-disk names are format v2 and format v3, respectively. The rest of this
README uses the descriptive model names because they express the security
property that matters to a user:

- A **Keychain-backed vault** keeps its raw vault key in a local or
  synchronizable Keychain item.
- A **device-enrolled vault** wraps the vault key separately to every approved
  Mac's Secure Enclave identity and keeps plaintext key material only in Key
  Agent's short-lived session.

| | Keychain-backed (format v2) | Device-enrolled (format v3) |
|---|---|---|
| Access model | Any Mac that receives the selected Keychain item | Explicitly enrolled Macs with equal authority |
| Vault key | Persistent local or synchronizable Keychain item | Wrapped separately to each active Mac's Secure Enclave identity |
| Unlocked key | Reused briefly by Key Agent | Exists in plaintext only in Key Agent's short-lived memory session |
| Provider history | Individually encrypted named files | Authenticated, immutable, content-addressed history |
| Concurrency | Provider filesystem behavior | Automatic independent merges; explicit genuine-conflict resolution |
| Device loss | Depends on the configured Keychain mode | Recoverable only while at least one enrolled Mac survives |

A device-enrolled vault stores encrypted entries, authenticated manifests,
public device metadata, and per-device vault-key wrappers in the selected
folder. The provider can delay or omit files and deny service, but it cannot
silently grant access or choose which history Key trusts.

## Moving to a device-enrolled vault

Migration is explicit and local. It never begins merely because a newer binary
was installed.

First run the read-only preflight:

```sh
key migrate --check
```

Review the report, then create and select a verified device-enrolled snapshot:

```sh
key migrate --apply
```

Migration converts format v2 to format v3. It retains the Keychain-backed
source files unchanged and selects the device-enrolled vault only after the new
snapshot, local device identity, wrapper, and checkpoint are usable. The
retained source supports controlled rollback or remigration while the
migration is being validated; it does not receive later device-enrolled
changes and is not a recovery key for the new vault.

Other Macs remain on their existing Keychain-backed state. Their later edits
are not imported into the migrated snapshot. Enroll each additional Mac into
the device-enrolled vault instead of migrating independent copies of the same
vault.

Preview can migrate only a Keychain-backed vault and key that already belong
to Preview's isolated namespace. It cannot use Stable's protected Keychain
state.

## Enrolling another Mac

Enrollment uses a 10-minute invitation and a comparison code. Both Macs must
show the exact same device pair and code before approval.

On an active Mac, inspect the roster and create an invitation using this Mac's
exact recorded name:

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

Only after the device pair and comparison code match, approve on the existing
Mac and accept on the joining Mac:

```sh
key share approve <vault-id> <invitation-id> <comparison-code>
key share accept <vault-id> <invitation-id> <comparison-code>
```

Each command prints the exact safe next command for its side of the ceremony.
If an invitation expires, begin a fresh ceremony. A prepared exact approval may
finish after provider delay, but expiry never authorizes a different request.

Inspect the authenticated roster at any time:

```sh
key share devices
```

## Revocation and replacement

```sh
key share revoke <device-id>
```

Revocation requires local authentication and explicit review. It rotates the
vault key, re-encrypts the current snapshot, and omits the revoked Mac from new
wrappers. It cannot erase old plaintext, screenshots, exports, or key material
that device already possessed.

A lost or revoked Mac can rejoin only through a fresh invitation from a
surviving active Mac. Running the ordinary `share join` command on the revoked
Mac presents a replacement review and requires the literal `REJOIN` before
removing only that Mac's unusable local enrollment state.

## Storage providers and conflicts

The device-enrolled vault is directly validated on local APFS and iCloud Drive.
Other ordinary folder-backed providers may work if they preserve the required
containment, atomicity, hydration, type, and naming semantics, but they have
not been directly validated and are not covered by the `0.2.0` compatibility
guarantee.

Key does not trust provider timestamps, ordering, mutable metadata, or a
claimed “latest” file. Missing synchronized objects produce an incomplete
state and block writes. Malformed, substituted, rolled-back, or competing
authority objects fail closed. Independent content edits merge automatically;
genuinely incompatible edits remain available through the `conflict` commands
until you choose the complete resolution.

To move a vault, move its complete directory and update the configured path:

```sh
mv ~/.key ~/Secrets/key-vault
key config set vault-dir ~/Secrets/key-vault
key config get vault-dir
```

Do not repoint one product at another product's live vault. If the default
directory already contains unrelated files, Key refuses to adopt it.

## Command reference

```text
key status [--json] [--verbose]        Explain vault health and the next safe action
key unlock                             Warm the helper session
key lock                               Clear the session and stop the helper

key get <name> [--allow-stale]         Print a secret or current TOTP code
key copy <name> [--allow-stale]        Copy a secret or current TOTP code
key add [--totp] <name>                Add a secret from stdin or a secure prompt
key edit [--totp] <name>               Update a secret
key duplicate <src> <dst> [--force]    Duplicate an entry
key rename <src> <dst> [--force]       Rename an entry
key remove <name> [--force]            Remove an entry
key list                               List entry names

key config get <config-name>           Print one configuration value
key config set <config-name> <value>   Update one configuration value
key config list                        List known configuration values

key conflict list [--json]             List unresolved device-enrolled conflicts
key conflict show <id> [--json]        Inspect authenticated conflict metadata
key conflict get <id> <version>        Print one conflicted value
key conflict copy <id> <version>       Copy one conflicted value
key conflict resolve <id>=<version>…   Resolve the complete listed conflict set

key share devices [--json]             List authenticated enrolled devices
key share revoke <device-id>           Review and revoke a device
key help                               Show the complete command reference
```

`--allow-stale` is intentionally narrow. It permits a read only from the last
complete version already trusted on that Mac when newer provider delivery is
incomplete. It does not bypass corruption, rollback, or an authority conflict.

## macOS integration

Key is intentionally macOS-specific and requires macOS 14 or later for the
device-enrolled Secure Enclave and CryptoKit HPKE profile. The installed
product has three signed components:

1. `Key.app` registers the helper and shows installation diagnostics.
2. The `key` CLI handles command parsing, terminal I/O, and clipboard writes.
3. Key Agent owns Keychain and Secure Enclave access, encryption, authenticated
   storage operations, and the short-lived in-memory session.

The CLI talks to the on-demand helper over an authenticated XPC Mach service.
`launchd` starts it when needed, and the helper exits after its idle window.
The CLI does not directly access protected vault-key material.

## Security scope

Key uses AES-256-GCM for entries, HKDF-SHA256 and HMAC-SHA256 for derived
manifest authentication, P-256 signatures for device-authorized transitions,
and RFC 9180 HPKE with P-256, HKDF-SHA256, and AES-256-GCM for per-device vault
key wrapping.

The `0.2.0` assurance boundary includes extensive focused internal review,
automated fault and security coverage, notarized installed-product checks, and
two-device physical qualification on local APFS and iCloud Drive. It has not
received an independent third-party security audit. A third physical device
and additional storage providers were not direct release gates.

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

The Xcode project builds the signed host apps and helpers. Signing,
notarization, Preview isolation, and release publication are documented in the
[release process](docs/release.md) and [Apple setup guide](docs/apple-setup.md).

Key is available under the [MIT License](LICENSE).
