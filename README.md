# key

> [!WARNING]
> `key` is still in early development. There is not a public release yet. The project is being worked toward an alpha release.

`key` is a macOS secret manager for people who like what [`pass`](https://www.passwordstore.org/) gets right: secrets live as encrypted files in a normal directory tree, not inside an opaque app-specific database. That makes the store easy to inspect, back up, move around, and reason about from the shell.

`key` keeps that file-oriented, CLI-first model, but replaces the GPG-centered unlock story with native macOS key handling. A single random vault key is stored in Keychain, protected with Apple's [`userPresence`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence) access control, and used to encrypt and decrypt the per-secret files on disk.

The result is meant to sit in the gap between `pass` and a full GUI password manager: low surface area, easy to understand, and tightly integrated with macOS authentication instead of a separate agent-driven crypto workflow.

## Why this exists

`pass` is a great fit if you want a Unix-native store built around GPG and Git. `key` is for the narrower macOS case where you want the same basic file-oriented model, but you would rather lean on the OS for protected key access than carry a separate GPG and agent workflow.

## How it works

`key` separates storage, key management, and authentication:

- the secret values themselves are stored as encrypted files on disk
- a single random vault key is stored in Keychain
- macOS local authentication controls access to that Keychain item through [`userPresence`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence)

That means Keychain is not the database of secrets. The filesystem holds the encrypted secret files, and Keychain holds only the one key that can decrypt them.

When the vault key does not exist yet, `key` generates a fresh random 256-bit symmetric key, stores it in Keychain, and marks that item as [`userPresence`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence)-protected. That same vault key is then used to encrypt and decrypt the per-secret files.

## CLI

The current CLI is intentionally small:

```bash
key ls
key get <name> [--copy]
key put <name> [--force]
key put <name> --generate [--length N] [--force] [--show | --copy]
```

Examples:

```bash
key ls
key get github/personal
key get github/personal --copy
printf 'hunter2' | key put github/personal --force
key put aws/prod/token --generate --show
```

Secrets are stored as encrypted files under:

```text
~/Library/Application Support/key/vault
```

An entry like `github/personal` becomes:

```text
~/Library/Application Support/key/vault/github/personal.secret
```

Each file is an encrypted JSON envelope. The plaintext secret is never stored in the repo.

## Native macOS integration

`key` is not just a standalone CLI binary. To use the stronger macOS Keychain and user-presence path correctly, it is structured as three pieces:

1. `Key.app`
2. `key` CLI client
3. `KeyXPCService.xpc`

### `Key.app`

The host app exists primarily to give the project a proper macOS app identity, signing context, entitlements, and release shape. It is not intended to be a full GUI password manager.

### `key` CLI client

The CLI is the user-facing interface. It handles:

- command parsing
- stdin and secure prompt input
- stdout and stderr output
- clipboard writes for `--copy`

The CLI does **not** directly access the protected vault key.

### `KeyXPCService.xpc`

The XPC service is the privileged side of the system. It is launched on demand by macOS and owns:

- Keychain access
- [`userPresence`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence)-gated vault key retrieval
- encryption and decryption
- on-disk secret file access

This split is what gives `key` native macOS integration without turning the CLI itself into the privileged actor.

Conceptually, a `get` looks like this:

1. `key get github/personal`
2. the CLI sends a request to the bundled XPC service
3. the XPC service asks macOS for access to the vault key
4. macOS enforces the Keychain item's [`userPresence`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence) requirement through its normal local-authentication path, using whatever user-presence mechanism the OS makes available for that machine and state
5. the service decrypts the secret file
6. the CLI prints the result or copies it to the pasteboard

That is the tradeoff that makes the native macOS auth path possible while keeping the day-to-day interface CLI-first. This is intentionally macOS-specific and optimizes for native platform integration over cross-platform portability.

## Development notes

The checked-in Xcode project is the source of truth:

- [Key.xcodeproj](/Users/tim.vanreenen/Code/key/Key.xcodeproj)

Useful commands:

```bash
swift test
scripts/build-debug-app.sh
scripts/build-release-archive.sh
```

The release and signing workflow is described in:

- [release.md](/Users/tim.vanreenen/Code/key/docs/release.md)
