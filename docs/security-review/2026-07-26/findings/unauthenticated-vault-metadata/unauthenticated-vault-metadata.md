# Synced vault authorization metadata is accepted without authentication

## Executive Summary

Key stores the complete authorization state for a shared enclave vault in the
synchronized `.key-vault.json` file. The file names the vault and current
epoch, lists authorized devices, and contains each device's wrapped copy of the
shared AES key. At revision
`84e7ddb79141d8f1665f3c1bf2e4254677a988a2`, Key decodes this JSON directly
without a signature, MAC, authenticated digest chain, or locally pinned
monotonic revision.

A storage or synchronization adversary can therefore delete fields, combine
inconsistent device and wrapped-key records, or restore an older valid file.
The strongest directly validated consequence is authorization-state
inconsistency and availability loss. In particular, status and sync paths
require active membership in the `devices` array, while the key-unwrapping path
accepts a current-epoch wrapped-key record without checking that membership.
The same local device can consequently be reported as unapproved yet still
unwrap the vault key.

Secure Enclave ECIES wrapping remains an important confidentiality control. A
storage-only attacker cannot construct an arbitrary wrapped vault key that a
victim device can decrypt and does not learn the shared key merely by editing
JSON. This narrows the impact to replay, deletion, inconsistent authorization,
and denial of access rather than direct key disclosure.

The issue has **Low severity / P3 priority**, with high static confidence. The
affected enclave-sharing implementation first appears in the available history
at the reviewed revision; no fixed revision was available. I reviewed that
revision directly and compiled and ran the included defensive metadata-format
regression harness. I did not exercise a real sync-provider rollback or access
Keychain, Secure Enclave, XPC, iCloud, or a live vault.

## Background

The enclave-sharing design uses one symmetric key for entry encryption and one
Secure Enclave keypair per device for key distribution. Shared storage contains
one ECIES-wrapped copy of the symmetric key for each authorized device. The
metadata object defines all of the policy information needed to decide which
wrapped record is current:

```swift
// Sources/KeyCore/VaultKeyStore.swift:7-59
public struct EnclaveDeviceRecord: Codable, Equatable, Sendable {
    public let deviceID: String
    public let deviceName: String
    public let publicKey: String
    public let addedAt: Date
    public let status: String
}

public struct EnclaveWrappedKeyRecord: Codable, Equatable, Sendable {
    public let deviceID: String
    public let epoch: Int
    public let algorithm: String
    public let ciphertext: String
}

public struct EnclaveVaultMetadata: Codable, Equatable, Sendable {
    public let version: Int
    public let securityMode: SecurityMode
    public let vaultID: String
    public let epoch: Int
    public var devices: [EnclaveDeviceRecord]
    public var wrappedKeys: [EnclaveWrappedKeyRecord]
}
```

The file is named `.key-vault.json`:

```swift
// Sources/KeyCore/VaultKeyStore.swift:156-159
public final class VaultKeyStore: VaultKeyStoring {
    private static let metadataFilename = ".key-vault.json"
    private static let wrappingAlgorithm =
        SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
    private static let signingAlgorithm =
        SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
```

There is a signing algorithm in this class, but it is used for device
enrollment requests. The metadata structure itself has no authenticator,
signer identity, previous digest, or trusted revision field beyond the
unauthenticated integer `epoch`.

An atomic filesystem replacement keeps a single local write from being torn,
which is valuable for durability:

```swift
// Sources/KeyCore/VaultKeyStore.swift:735-749
private func saveMetadata(
    _ metadata: EnclaveVaultMetadata,
    vaultRootURL: URL
) throws {
    let url = metadataURL(for: vaultRootURL)
    let directory = url.deletingLastPathComponent()
    try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
    let tempURL = directory.appendingPathComponent(
        ".\(url.lastPathComponent).\(UUID().uuidString).tmp"
    )
    defer { try? fileManager.removeItem(at: tempURL) }

    let data = try encoder.encode(metadata)
    try data.write(to: tempURL, options: .atomic)
    if fileManager.fileExists(atPath: url.path(percentEncoded: false)) {
        _ = try fileManager.replaceItemAt(url, withItemAt: tempURL)
    } else {
        try fileManager.moveItem(at: tempURL, to: url)
    }
}
```

Atomic replacement does not establish who wrote the bytes or whether the file
is the newest accepted generation. Once the directory is synchronized, an
older complete file or a complete attacker-edited file is just as readable as
the locally generated one.

The required trust boundary is therefore between untrusted synchronized bytes
and the device's key-unwrapping decision. We need authenticity, internal
consistency, and freshness before metadata can become authorization state.

## Vulnerability Details

We first reach the metadata boundary in `loadMetadataIfPresent`. The helper
reads the synchronized file and asks `JSONDecoder` to construct the policy
object:

```swift
// Sources/KeyCore/VaultKeyStore.swift:696-718
private func loadMetadata(vaultRootURL: URL) throws -> EnclaveVaultMetadata {
    guard let metadata = try loadMetadataIfPresent(vaultRootURL: vaultRootURL) else {
        throw AppError.invalidConfiguration(
            "Vault is not initialized for enclave mode."
        )
    }
    guard metadata.securityMode == .enclave else {
        throw AppError.invalidConfiguration(
            "Vault metadata does not describe an enclave vault."
        )
    }
    return metadata
}

private func loadMetadataIfPresent(
    vaultRootURL: URL
) throws -> EnclaveVaultMetadata? {
    let url = metadataURL(for: vaultRootURL)
    guard fileManager.fileExists(atPath: url.path(percentEncoded: false)) else {
        return nil
    }

    do {
        let data = try Data(contentsOf: url)
        return try decoder.decode(EnclaveVaultMetadata.self, from: data)
    } catch {
        throw AppError.invalidConfiguration(
            "Vault metadata is unreadable."
        )
    }
}
```

The only semantic guard in `loadMetadata` is `securityMode == .enclave`.
There is no check of:

- a MAC or signature over the complete object;
- an authenticated binding between the file and the expected vault;
- a device-local last accepted epoch or digest;
- epoch regression or same-epoch divergent content;
- duplicate device IDs or wrapped-key records;
- exact supported metadata version and wrapping algorithm;
- consistency between active membership and wrapped-key possession.

From this decoded object, the key-loading path selects the first record whose
device ID and record epoch match local state:

```swift
// Sources/KeyCore/VaultKeyStore.swift:683-694
private func loadEnclaveVaultKey(
    vaultRootURL: URL,
    reason: String
) throws -> Data {
    let metadata = try loadMetadata(vaultRootURL: vaultRootURL)
    let identity = try loadOrCreateDeviceIdentity(reason: reason)
    guard let wrappedKey = metadata.wrappedKeys.first(where: {
        $0.deviceID == identity.deviceID &&
        $0.epoch == metadata.epoch
    }) else {
        throw AppError.operationRefused(
            "This Mac is not authorized to unlock enclave vault."
        )
    }
    guard let ciphertext = Data(base64Encoded: wrappedKey.ciphertext) else {
        throw AppError.invalidConfiguration(
            "Vault metadata contains an invalid wrapped key payload."
        )
    }

    return try decryptWrappedVaultKey(
        ciphertext,
        privateKey: identity.privateKey
    )
}
```

We carry forward two untrusted values here: the metadata-level `epoch` and the
array of wrapped records. The predicate does not require a matching device in
`metadata.devices`, does not require `status == "authorized"`, and does not
check the record's declared `algorithm`.

The inconsistency is visible when we compare this with status inspection. The
status path treats membership and wrapped-key possession as separate required
conditions:

```swift
// Sources/KeyCore/VaultKeyStore.swift:316-341
let approved = metadata.devices.contains {
    $0.deviceID == identity.deviceID
}
let hasWrappedKey = metadata.wrappedKeys.contains {
    $0.deviceID == identity.deviceID &&
    $0.epoch == metadata.epoch
}

if !approved {
    return VaultStatusReport(
        // ...
        accessState: .enclaveNotApproved,
        detail: "This Mac can see the shared vault, but it has not been approved for enclave access."
    )
}

if !hasWrappedKey {
    return VaultStatusReport(
        // ...
        accessState: .enclaveWaitingForWrappedKey,
        detail: "This Mac is approved for the shared vault, but its wrapped vault key has not arrived in synced metadata yet."
    )
}
```

Consider a complete, well-formed file at epoch 7 with `device-a` as the only
member of `devices`, but with wrapped records for both `device-a` and
`device-b`. This shape can arise from direct modification, a stale restore, or
an application-unaware sync conflict.

For device B:

| Consumer | Predicate | Result |
|---|---|---|
| Status inspection | active device record and current wrapped record | `enclave-not-approved` |
| `syncDevice` | active device record and current wrapped record | refuses |
| `loadEnclaveVaultKey` | current wrapped record only | attempts unwrap |

If B's wrapped ciphertext is legitimate, its Secure Enclave private key can
unwrap it even though the policy list says B is not active. If the record is
invalid or belongs to another generation, ECIES decryption fails, producing
denial of access rather than key disclosure.

Freshness fails one layer earlier. Because no trusted local state records the
last accepted `(vaultID, epoch, digest)`, a previously valid complete metadata
file remains indistinguishable from current metadata. Replaying it can restore
old device names, membership, wrapped-key availability, and epoch selection,
or can simply strand devices whose current wrapped records disappear. A
same-epoch conflict is equally ambiguous because the helper has no authenticated
digest with which to identify divergent histories.

## Exploitability Analysis

The relevant actor controls synchronized storage ordering or file contents but
does not possess an authorized device key. This includes a malicious storage
provider, an attacker able to alter the shared directory, and stale restore or
conflict behavior that is not itself malicious.

The most reliable primitive is denial of access:

1. replace `.key-vault.json` with well-formed JSON;
2. omit the victim's current wrapped record or change the selected epoch;
3. allow Key to decode the file successfully;
4. cause `loadEnclaveVaultKey` to report unauthorized status or fail ECIES
   decryption.

This route needs no cryptographic forgery. Deleting a record is sufficient,
and an old complete file may have the same effect after legitimate enrollment
changes.

The more interesting integrity primitive is inconsistent authorization. We can
retain a legitimate wrapped record for a device while omitting its active
membership record. The status and sync paths then reject the device, but the
ordinary key-loading path still selects its ciphertext. This does not let a
storage-only attacker become that device; successful unwrap still requires the
corresponding Secure Enclave private key. It does show that the file format and
consumers do not enforce one coherent authorization decision.

Rollback is constrained by cryptographic generations. Replaying old metadata
does not magically make an old key decrypt ciphertext produced under a
different key. Its effect depends on what entry generation is present and what
wrapped key the local device can unwrap. At minimum, replay can make current
data unavailable or present stale authorization state. Stronger semantic
rollback requires a mutually compatible old metadata and ciphertext
generation.

Several tempting attack ideas stop at the ECIES boundary:

- Replacing `ciphertext` with arbitrary bytes does not disclose the vault key;
  private-key decryption should fail.
- Copying one device's wrapped record to another device ID does not make it
  decryptable by the second device.
- Inventing an attacker device record and public key does not create a wrapped
  copy of the existing symmetric key.

Those dead ends are why this report does not claim direct confidentiality
compromise from storage access alone. The vulnerability is that attacker- or
staleness-controlled policy is accepted without proof, not that ECIES itself
is broken.

Reliability is high for deletion and inconsistent-state effects because the
metadata is ordinary JSON and the decoder accepts structurally valid content.
Provider-specific rollback timing was not reproduced, so the exact delivery
mechanism remains environment-dependent.

## Proof of Concept

The `poc/` directory contains a defensive regression harness rather than
offensive tooling. Its fixture is shaped like `.key-vault.json` and deliberately
contains one harmless inconsistency:

- `devices` contains only `device-a`;
- `wrappedKeys` contains current-epoch records for `device-a` and `device-b`;
- no metadata authenticator is present.

The Swift harness decodes that fixture using corresponding `Codable` structs
and applies the exact current selection predicate from
`loadEnclaveVaultKey`. It then compares that result with a defensive model
that requires an authenticated manifest, active membership, and exactly one
current wrapped record.

From the report directory:

```sh
cd poc
make run
```

Representative output:

```text
[+] decoded metadata: vault=example-vault epoch=7
[+] active device IDs: ["device-a"]
[+] metadata has authenticator: false
[!] current selector accepts device-b's wrapped key without active membership
[+] defensive selector rejected metadata: missingAuthenticatedManifest
```

The warning line is the regression condition: a current-epoch wrapped record
is selected despite the absence of an active device record. The final line
shows the intended fail-closed structural behavior.

This harness only reads its bundled fixture and produces a local compiler
artifact. It does not contain key material, perform ECIES operations, mutate a
vault, contact a sync service, or interact with any Apple security service.

Clean local build output with:

```sh
make clean
```

I compiled and ran the harness locally on macOS and observed the output above.
I did not attempt to alter synchronized user data or reproduce a provider-level
rollback.

## Remediation

The invariant to restore is:

> A device may use a wrapped vault key only when the complete metadata object
> is cryptographically authentic, internally consistent, and no older or
> divergent from the last state that device accepted.

A practical design can use a vault-key-derived MAC for storage authenticity,
combined with device-local monotonic state for rollback detection:

1. Define one canonical encoding of all security-relevant metadata fields,
   excluding the authenticator itself.
2. Derive a metadata authentication key from the vault key with domain
   separation, for example HKDF label `key-vault-metadata-v1`.
3. Store an HMAC-SHA256 over the canonical metadata bytes.
4. Treat the selected wrapped key as untrusted bootstrap material; unwrap it,
   then verify the metadata MAC before using the vault key for entries.
5. Persist the last accepted vault ID, epoch, and metadata digest in a
   device-only Keychain item.
6. Reject lower epochs, same-epoch different digests, and broken
   predecessor-digest chains.
7. During first-device enrollment, bind the initial accepted metadata digest
   and epoch to the independently approved enrollment transcript.

An illustrative verified load shape is:

```swift
private func loadVerifiedMetadataAndKey(
    vaultRootURL: URL,
    identity: DeviceIdentity
) throws -> (EnclaveVaultMetadata, Data) {
    let envelope = try decodeMetadataEnvelope(vaultRootURL)
    try validateStructure(envelope.metadata)

    let device = try requireExactlyOneActiveDevice(
        envelope.metadata,
        deviceID: identity.deviceID,
        publicKey: identity.publicKeyData
    )
    let wrapped = try requireExactlyOneWrappedKey(
        envelope.metadata,
        deviceID: device.deviceID,
        epoch: envelope.metadata.epoch,
        algorithm: Self.wrappingAlgorithm
    )

    let vaultKey = try decryptWrappedVaultKey(
        wrapped.ciphertextData,
        privateKey: identity.privateKey
    )
    let canonical = try canonicalMetadataBytes(envelope.metadata)
    let authenticationKey = deriveMetadataKey(vaultKey)
    guard HMAC<SHA256>.isValidAuthenticationCode(
        envelope.authenticationTag,
        authenticating: canonical,
        using: authenticationKey
    ) else {
        throw AppError.invalidConfiguration(
            "Vault metadata authentication failed."
        )
    }

    try verifyAndAdvanceLocalMetadataPin(
        vaultID: envelope.metadata.vaultID,
        epoch: envelope.metadata.epoch,
        digest: SHA256.hash(data: canonical),
        previousDigest: envelope.metadata.previousDigest
    )
    return (envelope.metadata, vaultKey)
}
```

The device/membership checks should be shared by status, sync, and key-loading
paths so they cannot drift into different definitions of "authorized."
Structural validation should also enforce:

- exactly one supported metadata version and security mode;
- a nonempty, expected vault ID;
- positive epochs with checked increment semantics;
- unique device IDs;
- `status == "authorized"` for active records;
- a device-record public key whose fingerprint equals `deviceID`;
- exactly one wrapped record per active device for the current epoch;
- no current wrapped records for devices absent from the active set;
- exact supported algorithm identifiers and valid field sizes.

The local monotonic pin is essential. A valid MAC proves that some holder of
the vault key created the metadata; by itself, it does not distinguish a valid
old file from the newest file. On a genuinely new device, enrollment must
provide the trusted bootstrap because no prior local pin exists.

Regression tests should cover:

- one current wrapped record but no active device record: reject before entry
  decryption;
- active device record with no current wrapped record: reject consistently in
  status, sync, and load;
- duplicate device IDs or wrapped records: reject rather than select `.first`;
- modified epoch, vault ID, device status, public key, algorithm, or wrapped
  ciphertext: MAC verification fails;
- lower authenticated epoch after a higher accepted epoch: rollback rejection;
- same epoch with a different authenticated digest: explicit conflict;
- valid next epoch with wrong `previousDigest`: reject;
- first-device enrollment pins the approved digest and epoch;
- corrupt or attacker-generated wrapped ciphertext fails without advancing
  the local pin;
- atomic-write interruption retains the last authenticated generation.

## Summary

The synchronized `.key-vault.json` file is both a transport format and the
authorization policy for enclave key access, yet revision
`84e7ddb79141d8f1665f3c1bf2e4254677a988a2` accepts it without cryptographic
authentication or trusted freshness state. We traced the file from raw
`Data(contentsOf:)` through `JSONDecoder` to a wrapped-key selector that does
not require active membership. The included defensive harness demonstrates
that exact inconsistent shape without touching a real vault.

ECIES still prevents a storage-only adversary from forging a decryptable
wrapped key or learning the shared key directly. The appropriate repair is
therefore not a change to the wrapping primitive, but an authenticated,
canonical metadata envelope; one shared authorization validator; and a
device-local monotonic pin that detects replay and divergent sync histories.
