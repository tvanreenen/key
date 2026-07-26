# Device removal without key rotation PoC

This local, non-destructive state-machine reproduction uses CryptoKit AES-GCM.
It models two authorized devices sharing one unwrapped vault key. Device B
retains that key, is removed from metadata using the vulnerable transition,
and then decrypts an entry created afterward by device A.

Requirements:

- macOS 13 or later
- Xcode Command Line Tools with `swiftc`

Run:

```sh
make run
```

Expected output:

```text
[+] before leave: epoch=7 devices=["device-a", "device-b"]
[+] after leave:  epoch=7 devices=["device-a"]
[+] wrapped key removed for device-b: true
[+] removed device decrypted future entry: future-secret-after-removal
```

The PoC does not access Keychain, Secure Enclave, XPC, iCloud, or a real vault.
It writes only the local build artifact. Remove it with:

```sh
make clean
```
