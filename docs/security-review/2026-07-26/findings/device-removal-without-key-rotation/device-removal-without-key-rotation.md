# Device removal does not rotate the shared vault key

## Executive Summary

The enclave-sharing implementation removes a departing device from
`.key-vault.json` and deletes that Mac's Secure Enclave identity, but it does
not replace the shared AES vault key. It also leaves the metadata epoch
unchanged and does not re-encrypt entries or rewrap a new key for the remaining
devices.

This distinction matters because every authorized device must receive the
unwrapped symmetric vault key to decrypt entries. Secure Enclave
non-exportability protects the device's private wrapping key; it does not make
the unwrapped AES key non-exportable. A compromised endpoint can therefore
retain that AES key before it leaves. Removing its metadata records then blocks
the honest client path, but the retained key still decrypts entries written
after removal because the remaining devices continue using the same key.

The affected source reviewed here is revision
`84e7ddb79141d8f1665f3c1bf2e4254677a988a2`. This revision introduced the
enclave-sharing workflow in the available repository history. No fixed
revision was available for comparison. I reviewed that revision directly and
compiled and ran the included local CryptoKit proof of concept. I did not test
against a real Keychain, Secure Enclave, iCloud account, XPC service, or
compromised endpoint.

The issue has **Medium severity / P2 priority**. Its confidentiality impact is
high, but exploitation requires a formerly authorized device to have captured
the unwrapped key while it was authorized and to retain access to subsequently
synced ciphertext.

## Background

Key encrypts every vault entry with one shared 256-bit AES-GCM key. In enclave
mode, each authorized device has its own Secure Enclave private key, while
shared metadata contains one wrapped copy of the common AES key for each
device. The metadata type makes the intended generation boundary explicit:

```swift
// Sources/KeyCore/VaultKeyStore.swift:37-59
public struct EnclaveVaultMetadata: Codable, Equatable, Sendable {
    public let version: Int
    public let securityMode: SecurityMode
    public let vaultID: String
    public let epoch: Int
    public var devices: [EnclaveDeviceRecord]
    public var wrappedKeys: [EnclaveWrappedKeyRecord]

    public init(
        version: Int = 1,
        securityMode: SecurityMode = .enclave,
        vaultID: String,
        epoch: Int,
        devices: [EnclaveDeviceRecord],
        wrappedKeys: [EnclaveWrappedKeyRecord]
    ) {
        self.version = version
        self.securityMode = securityMode
        self.vaultID = vaultID
        self.epoch = epoch
        self.devices = devices
        self.wrappedKeys = wrappedKeys
    }
}
```

When a device unlocks the vault, Key selects the wrapped record for that
device and the current epoch, then returns the decrypted AES key as ordinary
`Data`:

```swift
// Sources/KeyCore/VaultKeyStore.swift:683-694
private func loadEnclaveVaultKey(vaultRootURL: URL, reason: String) throws -> Data {
    let metadata = try loadMetadata(vaultRootURL: vaultRootURL)
    let identity = try loadOrCreateDeviceIdentity(reason: reason)
    guard let wrappedKey = metadata.wrappedKeys.first(where: {
        $0.deviceID == identity.deviceID && $0.epoch == metadata.epoch
    }) else {
        throw AppError.operationRefused(
            "This Mac is not authorized to unlock enclave vault '\(vaultRootURL.path(percentEncoded: false))'."
        )
    }
    guard let ciphertext = Data(base64Encoded: wrappedKey.ciphertext) else {
        throw AppError.invalidConfiguration(
            "Vault metadata contains an invalid wrapped key payload."
        )
    }

    return try decryptWrappedVaultKey(ciphertext, privateKey: identity.privateKey)
}
```

We should read the Secure Enclave boundary precisely. The private key used by
`decryptWrappedVaultKey` is device-bound, but the returned symmetric key is
not. Key must provide those bytes to CryptoKit and caches them for a bounded
helper session. A fully compromised authorized endpoint can copy the bytes
while they are present. No later metadata edit can make an already learned
secret unknown.

The XPC protocol exposes two superficially similar lifecycle operations:

```swift
// Sources/KeyCore/KeyServiceProtocol.swift:14-16
case syncVault
case leaveVault
case unshareVault
```

`leaveVault` is a self-removal operation. `unshareVault` instead converts the
entire vault to local mode and performs a global key change. The command
handler preserves that split:

```swift
// Sources/KeyCore/KeyServiceHandler.swift:103-114
case .syncVault:
    try ensureEnclaveMode()
    return .success(try keyStore.syncDevice(vaultRootURL: entryStore.rootURL))
case .leaveVault:
    try ensureEnclaveMode()
    return .success(try keyStore.leaveEnclaveVault(
        vaultRootURL: entryStore.rootURL,
        reason: "Unlock key vault to leave this shared vault."
    ))
case .unshareVault:
    try ensureEnclaveMode()
    return .success(try unshareVault())
```

The security invariant for device removal is therefore stronger than
"metadata no longer lists the device." To revoke future access, Key must
advance to a new symmetric key that the removed endpoint has never known,
rewrite entries under that key, and distribute it only to the remaining
authorized devices.

## Vulnerability Details

We reach the vulnerable transition when an authorized Mac invokes
`leaveVault`. The implementation first proves that this Mac currently has
access, loads its identity, and refuses to remove the final authorized device.
Those are useful consistency checks. The decisive transition follows:

```swift
// Sources/KeyCore/VaultKeyStore.swift:505-525
public func leaveEnclaveVault(vaultRootURL: URL, reason: String) throws -> String {
    _ = try loadEnclaveVaultKey(vaultRootURL: vaultRootURL, reason: reason)
    var metadata = try loadMetadata(vaultRootURL: vaultRootURL)
    guard let identity = try loadDeviceIdentityIfPresent(
        reason: reason,
        allowInteraction: true
    ) else {
        throw AppError.operationRefused(
            "This Mac does not have a local Secure Enclave identity for vault '\(vaultRootURL.path(percentEncoded: false))'."
        )
    }

    guard metadata.devices.contains(where: { $0.deviceID == identity.deviceID }) else {
        throw AppError.operationRefused(
            "This Mac is not currently authorized for shared access to '\(vaultRootURL.path(percentEncoded: false))'."
        )
    }

    let remainingAuthorizedDevices =
        metadata.devices.filter { $0.deviceID != identity.deviceID }
    guard !remainingAuthorizedDevices.isEmpty else {
        throw AppError.operationRefused(
            "Refusing to leave the shared vault because this is the last authorized device. Use `key vault unshare` if you want to convert the vault back to local-only mode."
        )
    }

    metadata.devices = remainingAuthorizedDevices
    metadata.wrappedKeys.removeAll { $0.deviceID == identity.deviceID }
    try saveMetadata(metadata, vaultRootURL: vaultRootURL)
    try deleteDeviceIdentityIfPresent()
    return "This Mac has left shared vault '\(metadata.vaultID)'.\n"
}
```

The first line is especially important to the exploit story: immediately
before removal, the function successfully unwraps the current vault key. The
normal implementation discards that return value, but a compromised endpoint
can retain the same bytes from this or any earlier authorized operation.

From there, the function mutates only two authorization records:

1. it removes the local device from `metadata.devices`;
2. it removes that device's wrapped-key record.

It then saves metadata and deletes the local Secure Enclave identity. We never
construct a new `EnclaveVaultMetadata`, so the immutable `epoch` is carried
forward unchanged. We also never generate a fresh `SymmetricKey`, enumerate or
rewrite entry files, or replace the remaining devices' wrapped records.

The state transition is consequently:

| State | Before leave | After leave |
|---|---|---|
| Metadata epoch | `E` | `E` |
| Shared AES key | `K_E` | `K_E` |
| Leaving device wrapped record | Present | Removed |
| Leaving device Secure Enclave identity | Present | Deleted locally |
| Remaining-device wrapped records | Wrap `K_E` | Still wrap `K_E` |
| Future entries | Encrypt with `K_E` | Still encrypt with `K_E` |

When a remaining device later adds or edits an entry, the handler loads its
wrapped record for the unchanged epoch and receives `K_E`. `VaultCipher`
directly uses that key for AES-GCM:

```swift
// Sources/KeyCore/VaultCipher.swift:7-20
public func encrypt(
    _ plaintext: String,
    type: SecretEntryType = .secret,
    keyData: Data
) throws -> SecretFile {
    let key = SymmetricKey(data: keyData)
    let nonce = AES.GCM.Nonce()
    let sealedBox = try AES.GCM.seal(
        Data(plaintext.utf8),
        using: key,
        nonce: nonce
    )
    let payload = sealedBox.ciphertext + sealedBox.tag
    return SecretFile(
        type: type,
        nonce: Data(nonce).base64EncodedString(),
        ciphertext: payload.base64EncodedString()
    )
}
```

If we carry the retained `K_E` to the ciphertext synchronized after the leave
operation, AES-GCM has no notion of the metadata device list. Decryption
succeeds because the cryptographic key did not change. The removed device does
not need its deleted wrapped-key record or Secure Enclave private key anymore.

The helper's session wrapper clears its honest in-memory cache after a
successful leave. That is good local hygiene, but it cannot revoke a copy made
before the cache was cleared. Likewise, deleting the Secure Enclave identity
prevents the normal client from unwrapping again; it does not erase a symmetric
key already exported into ordinary process memory.

## Exploitability Analysis

The strongest realistic actor is a formerly authorized but compromised Mac.
While authorized, malware or an attacker with sufficient endpoint control
captures the 32-byte AES key from the helper process, instrumentation, a
debugging path, or another plaintext-bearing component. This precondition is
substantial, but it is also the precise endpoint-compromise case that
per-device removal is expected to contain.

We can then follow a reliable exploitation sequence:

1. Device A and compromised device B are both authorized for epoch `E`.
2. B unwraps `K_E` during an ordinary vault operation and retains it.
3. B executes `vault leave`, or the user causes B to leave.
4. Key removes B's metadata records and local identity, but leaves epoch `E`
   and `K_E` in place.
5. Device A writes future entries with `K_E`.
6. The synchronized `.secret` files remain visible to B or are collected by
   an attacker from the shared storage provider.
7. B decrypts those future entries offline with retained `K_E`.

No race is required after key capture. Removing B can complete successfully,
the honest Key client can report that the Mac left, and B's Secure Enclave
identity can be deleted. Those events do not affect the retained bytes.

The endpoint must still obtain future ciphertext. In the common synchronized
directory deployment, the old local directory may continue receiving files
even though Key's metadata no longer authorizes the device. An attacker could
also obtain ciphertext through access to the storage account, backups, or
copies from another source. Ciphertext access alone is not enough; possession
of the retained shared key is the essential capability.

There are meaningful constraints:

- An honest, uncompromised device that does not retain the AES key loses its
  normal unwrap path after its identity is deleted.
- Removal cannot revoke plaintext or ciphertext already copied before the
  operation. A correct fix can protect only data re-encrypted under the new key
  and future writes.
- The current `leaveVault` flow is self-removal. It does not provide a
  remaining device with a selective command to revoke an unreachable lost
  device.
- Global `unshareVault` does generate a fresh local key and rewrites entries,
  but it terminates shared-enclave operation. It is not a selective revocation
  mechanism for a vault that should remain shared.
- A last authorized device cannot invoke `leaveVault`; the code requires
  global unshare instead.

One tempting but ineffective hardening is to clear the helper cache more
aggressively. That narrows the capture window, which is useful defense in
depth, but cannot prove that a compromised endpoint did not copy `K_E`.
Another dead end is deleting only the leaving device's ECIES ciphertext more
quickly or more durably. Once B knows `K_E`, access to that wrapped copy is no
longer relevant.

The primitive is therefore stable rather than timing-sensitive: with retained
`K_E` and later ciphertext, future decryption continues until the vault
eventually changes keys through some other workflow.

## Proof of Concept

The `poc/` directory contains a local, non-destructive CryptoKit
state-machine reproduction. It creates metadata for two devices at epoch 7,
lets device B retain the shared AES key, applies the same vulnerable metadata
transition as `leaveEnclaveVault`, and encrypts a new entry afterward with the
unchanged key. Device B then decrypts that future entry using only its retained
key.

The PoC deliberately does not invoke Keychain, Secure Enclave, XPC, iCloud, or
a real vault. It isolates the cryptographic consequence of the validated
source transition and writes only a local compiler output file.

From the report directory:

```sh
cd poc
make run
```

Representative output from the vulnerable model:

```text
[+] before leave: epoch=7 devices=["device-a", "device-b"]
[+] after leave:  epoch=7 devices=["device-a"]
[+] wrapped key removed for device-b: true
[+] removed device decrypted future entry: future-secret-after-removal
```

The third line confirms that the metadata removal occurred. The fourth line
then demonstrates why metadata-only removal is not revocation: a future
AES-GCM entry is still readable with the previously captured key.

A fixed implementation should advance the epoch and encrypt the future entry
with a fresh key. Under that state transition, the PoC's final `AES.GCM.open`
using B's retained old key should throw an authentication failure.

Cleanup removes the local binary and compiler cache:

```sh
make clean
```

I compiled and ran this PoC successfully on macOS using the Swift compiler and
CryptoKit. I did not perform a live compromised-process capture or modify a
real vault, because the authorized scope was limited to local,
non-destructive probes.

## Remediation

The invariant to restore is straightforward to state:

> After a device is removed at epoch `E`, every protected entry that remains
> current or is created later must require a fresh key `K_(E+1)` that was
> never wrapped to, or otherwise disclosed to, the removed device.

Meeting that invariant requires an actual rotation transaction, not another
metadata filter. At minimum, Key should:

1. load `K_E` through a remaining authorized device;
2. generate random `K_(E+1)`;
3. decrypt and re-encrypt every current entry under `K_(E+1)`;
4. wrap `K_(E+1)` separately to each remaining authorized public key;
5. create metadata with epoch `E+1` and only those new wrapped records;
6. atomically publish the new entry generation and metadata;
7. retain enough journal/recovery state to finish or roll back after a crash;
8. reject replay of older epochs.

`VaultKeyStore` cannot perform the entry rewrite by itself because it does not
own `EntryStore` or `VaultCipher`. The clean structural fix is to coordinate
rotation in `KeyServiceHandler` or a dedicated vault-generation transaction,
then give `VaultKeyStore` responsibility for wrapping and committing the new
metadata.

An illustrative core of that flow is:

```swift
// Illustrative structure; commitVaultGeneration must be transactional.
private func revokeDevice(_ removedDeviceID: String) throws {
    let oldKey = try loadVaultKeyFromEnclave(
        reason: "Unlock key vault to revoke a device."
    )
    let oldMetadata = try keyStore.loadMetadataForRotation(
        vaultRootURL: entryStore.rootURL
    )
    let remaining = oldMetadata.devices.filter {
        $0.deviceID != removedDeviceID
    }
    guard !remaining.isEmpty else {
        throw AppError.operationRefused("Cannot revoke the final device.")
    }

    let newKey = Data(
        SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
    )
    let newEpoch = oldMetadata.epoch + 1
    let rewrittenEntries = try reencryptAllEntries(
        from: oldKey,
        to: newKey
    )
    let newWrappedKeys = try remaining.map {
        try keyStore.wrap(
            newKey,
            for: $0,
            epoch: newEpoch
        )
    }
    let newMetadata = EnclaveVaultMetadata(
        version: oldMetadata.version,
        vaultID: oldMetadata.vaultID,
        epoch: newEpoch,
        devices: remaining,
        wrappedKeys: newWrappedKeys
    )

    try commitVaultGeneration(
        entries: rewrittenEntries,
        metadata: newMetadata
    )
}
```

This sketch is intentionally not a recommendation to replace files one by one
and then write metadata. A multi-file key rotation can strand the vault if the
process crashes or sync interleaves generations. A durable design should stage
a complete generation, verify that all remaining devices' wrapped records
target the new epoch, and switch one authenticated manifest pointer only after
all rewritten entries are durable.

The XPC protocol and CLI should expose selective revocation from a remaining
authorized device, for example `revokeDevice(deviceID:)`, rather than relying
only on self-directed `leaveVault`. The self-leave flow should use the same
rotation primitive if its user-facing promise is that the departed device no
longer has future access.

Regression coverage should include:

- two devices at epoch `E`; remove B; assert epoch becomes `E+1`;
- assert all surviving wrapped records reference `E+1` and B has none;
- assert B's captured `K_E` cannot decrypt any rewritten or newly created
  entry;
- assert A can unwrap `K_(E+1)` and decrypt every entry;
- inject failure before and after each staging/commit step and verify restart
  yields one complete readable generation;
- replay epoch `E` metadata or entry files after rotation and require explicit
  rejection;
- race an edit with revocation and require conflict detection rather than a
  mixed-key vault;
- verify last-device removal still routes to an explicit local conversion or
  recovery policy.

Cache clearing and local identity deletion should remain after a successful
commit as defense in depth, but they must not be treated as substitutes for
rotation.

## Summary

The enclave design correctly avoids placing an unwrapped vault key in shared
storage, but each authorized endpoint necessarily receives that key in process
memory. We traced `leaveVault` from its XPC operation to
`leaveEnclaveVault`, where Key removes device and wrapped-key records while
preserving both the metadata epoch and shared AES key. We then demonstrated
with the included CryptoKit PoC that the retained old key decrypts an entry
created after removal.

The practical fix is a crash-safe, monotonic shared-vault rotation that
re-encrypts entries and rewraps a fresh key only for remaining devices.
Further review should concentrate on the atomic generation switch and rollback
protection, because a correct cryptographic rotation can still fail its
security goal if synced storage can replay the pre-revocation generation.
