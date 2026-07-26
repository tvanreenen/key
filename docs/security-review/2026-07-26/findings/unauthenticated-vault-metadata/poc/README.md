# Unauthenticated vault metadata defensive regression

This harmless local harness decodes an inconsistent `.key-vault.json`-shaped
fixture. The fixture omits device B from the active device list but retains a
current-epoch wrapped-key record for B.

The first check reproduces the current wrapped-key selection predicate. The
second models defensive preconditions: an authenticated manifest, active
membership, and exactly one current wrapped-key record.

Requirements:

- macOS 13 or later
- Xcode Command Line Tools with `swiftc`

Run:

```sh
make run
```

Expected output:

```text
[+] decoded metadata: vault=example-vault epoch=7
[+] active device IDs: ["device-a"]
[+] metadata has authenticator: false
[!] current selector accepts device-b's wrapped key without active membership
[+] defensive selector rejected metadata: missingAuthenticatedManifest
```

This harness does not access Keychain, Secure Enclave, XPC, iCloud, or a real
vault. It reads only the bundled fixture. Clean local build output with:

```sh
make clean
```
