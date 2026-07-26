# Authentic historical entry files can be replayed without freshness detection

## Executive Summary

Key authenticates each encrypted vault entry with AES-GCM, but it does not
record or verify which authentic version of an entry is current. A
synchronized-storage writer, stale restore, or conflict resolver that presents
an older valid `SecretFile` causes the normal decoder and GCM open path to
accept that file and return its historical plaintext. The bytes have not been
forged, so cryptographic authentication succeeds exactly as designed.

The missing property is freshness, not ciphertext integrity. Neither
`SecretFile` nor a separate trusted manifest contains an authenticated
per-entry revision that is anchored outside the replaceable synchronized
directory. The application consequently cannot distinguish the latest
envelope from a byte-for-byte valid historical envelope.

The issue is assessed as **Low severity (P3)**. It affects the integrity and
freshness of one entry at a time and can cause use of an old password or TOTP
seed. It does not directly reveal plaintext to the storage actor, and it
requires access to both historical ciphertext and the ability to make that
version appear current.

I reviewed revision
`84e7ddb79141d8f1665f3c1bf2e4254677a988a2` directly. The same freshness-free
envelope design is present in the initial repository commit from March 11,
2026, and remains in the reviewed revision. I ran only the included
deterministic in-memory freshness model. I did not modify a vault, exercise a
cloud rollback, contact a synchronization provider, or test against live
data. No fixed revision was supplied or reviewed.

## Background

Each vault entry is serialized as `SecretFile`. At the reviewed revision,
`Sources/KeyCore/SecretFile.swift` contains a format version, semantic type,
algorithm identifier, nonce, and ciphertext:

```swift
public struct SecretFile: Codable, Equatable {
    public let version: Int
    public let type: SecretEntryType
    public let alg: String
    public let nonce: String
    public let ciphertext: String
}
```

The `version` field describes the file format; it is not an entry revision.
There is no sequence number, update generation, creation identifier, previous
version digest, or reference to a trusted current-state record.

`Sources/KeyCore/VaultCipher.swift::encrypt` creates a fresh AES-GCM nonce for
each write and returns the ciphertext and tag:

```swift
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
```

Fresh nonces are an important and correct control. AES-GCM authentication
detects modification of the sealed payload. It intentionally does not answer
whether a valid sealed payload is the newest one.

Entry writes also use a temporary file and replacement in
`Sources/KeyCore/EntryStore.swift::save`:

```swift
let data = try encoder.encode(file)
try data.write(to: tempURL, options: .completeFileProtection)
if fileManager.fileExists(atPath: destination.path(percentEncoded: false)) {
    _ = try fileManager.replaceItemAt(destination, withItemAt: tempURL)
} else {
    try fileManager.moveItem(at: tempURL, to: destination)
}
```

This reduces torn local writes and applies file protection. Once historical
bytes exist in backups or synchronization history, however, atomic replacement
does not identify which successful replacement represents current state.

## Vulnerability Details

We can prove the freshness gap by following the ordinary `get` path.
`Sources/KeyCore/EntryStore.swift::load` reads whichever bytes currently
occupy the entry path and decodes them as `SecretFile`:

```swift
public func load(_ name: String) throws -> SecretFile {
    let fileURL = try url(for: name)
    guard fileManager.fileExists(
        atPath: fileURL.path(percentEncoded: false)
    ) else {
        throw AppError.entryNotFound("Secret '\(name)' was not found.")
    }

    do {
        let data = try Data(contentsOf: fileURL)
        return try decoder.decode(SecretFile.self, from: data)
    } catch {
        throw AppError.invalidSecretFile(
            "Secret file for '\(name)' is unreadable."
        )
    }
}
```

The decoder validates the JSON representation and required field types. It
does not have trusted state against which a revision could be compared, and
the file does not supply an entry revision anyway.

The resulting envelope proceeds to `VaultCipher.decrypt`:

```swift
guard file.version == 2, file.alg == "AES.GCM" else {
    throw AppError.invalidSecretFile("Unsupported secret file format.")
}
guard let nonceData = file.nonceData,
      let ciphertextData = file.ciphertextData else {
    throw AppError.invalidSecretFile("Secret file is not valid base64.")
}
guard ciphertextData.count >= 16 else {
    throw AppError.invalidSecretFile(
        "Secret file ciphertext is invalid."
    )
}

let ciphertext = ciphertextData.dropLast(16)
let tag = ciphertextData.suffix(16)
let sealedBox = try AES.GCM.SealedBox(
    nonce: AES.GCM.Nonce(data: nonceData),
    ciphertext: ciphertext,
    tag: tag
)
let plaintext = try AES.GCM.open(sealedBox, using: key)
```

Every guard is satisfied by an older envelope that the application itself
previously produced. Its format remains version 2, its fields remain valid
base64, and its GCM tag remains valid under the unchanged vault key.

The service then returns the decrypted historical value through the same
successful path used for current data:

```swift
case let .get(name):
    let encrypted = try entryStore.load(name)
    let keyData = try loadVaultKey(
        reason: "Unlock key vault to read '\(name)'.",
        createIfMissing: false
    )
    let decrypted = try decryptSecret(
        encrypted,
        named: name,
        keyData: keyData
    )
    return .success(
        try renderValue(
            for: encrypted.type,
            decryptedValue: decrypted
        )
    )
```

If we label two valid states `E1` and `E2`, where `E2` is written after
`E1`, the application observes only:

```text
authenticate(E1, vaultKey) = valid
authenticate(E2, vaultKey) = valid
```

The missing decision is:

```text
revision(E1) < trustedCurrentRevision
```

Because neither side of that comparison exists in the reviewed design,
presenting `E1` after `E2` deterministically restores the old plaintext
without an error or warning.

## Exploitability Analysis

The bounded scenario is a storage-level rollback. The relevant actor must
already be able to influence which valid synchronized or restored version
appears at an entry's path. This includes a synchronization conflict, stale
backup restore, or storage principal operating within the explicit vault
filesystem threat boundary.

The actor also needs historical bytes. Arbitrary JSON or ciphertext is not
enough: malformed fields are rejected, and any change to the sealed payload
causes AES-GCM authentication failure. This is useful counterevidence because
it sharply limits the issue to replay of authentic historical state rather
than general ciphertext forgery.

The strongest effect is semantic staleness. A user may receive an older
password that was intentionally replaced, or generate TOTP values from an old
seed. Depending on the external service, that may produce authentication
failures, reuse a credential that remains valid unexpectedly, or obscure the
fact that a local update was lost. The storage actor does not learn the
plaintext from this operation, and successful use of an old credential depends
on the external service still accepting it.

We should also distinguish rollback from ordinary sync delay. Eventual
consistency may temporarily expose an older file while updates propagate. A
freshness control needs an explicit product policy for that condition: fail
closed, show a conflict, or allow a clearly marked degraded read. Silently
returning the old value makes an adversarial rollback and a benign conflict
indistinguishable to the operator.

An encrypted revision field inside `SecretFile` would not be sufficient on
its own. A historical envelope carries its historical revision and valid tag
with it, so replaying the complete envelope replays both. Similarly, an
authenticated manifest stored only beside the entries can itself be replayed
unless some trusted state pins the newest accepted manifest or checkpoint.

This is the central durability constraint for an offline-capable,
multi-device vault. A device can reliably detect rollback only relative to a
checkpoint it already trusts. A newly enrolled or fully reset device needs
that checkpoint from an authenticated existing device or another trusted
monotonic service; otherwise first-seen stale state remains indistinguishable
from current state.

## Proof of Concept

No live rollback or file-replacement procedure was developed. The
`poc/replay_freshness_model.swift` artifact is a harmless, deterministic
assurance model that uses no vault code, ciphertext, files, network, or cloud
provider.

The model defines two envelopes:

- revision 1 is historical and authentic;
- revision 2 is current and authentic.

It then compares the current policy—accept any authentic envelope—with a
freshness-aware policy that also consults trusted current revision 2.

From the report directory:

```sh
cd poc
swift replay_freshness_model.swift
```

Representative output:

```text
[legacy] current authentic envelope accepted: true
[legacy] historical authentic envelope accepted: true
[fixed] historical revision 1 vs pinned revision 2 accepted: false
[+] regression invariant holds
```

I ran this model locally and observed the output above. It creates no
persistent files and requires no cleanup. The model does not claim to
reproduce iCloud or filesystem behavior; it isolates the exact policy
difference that production regression tests should enforce.

## Remediation

The invariant to restore is:

> After a device has accepted revision N of an entry, it must not silently
> accept an authentic revision lower than N, and newly enrolled devices must
> receive an authenticated current checkpoint.

A practical design needs two related layers.

First, extend the authenticated entry representation with a vault identifier,
canonical entry identifier, and revision. These values should be included in
AES-GCM authenticated data or inside the sealed plaintext. For example:

```swift
struct EntryContext: Codable {
    let vaultID: UUID
    let entryID: UUID
    let revision: UInt64
}

func decrypt(
    _ file: SecretFile,
    context: EntryContext,
    trustedRevision: UInt64,
    keyData: Data
) throws -> String {
    guard context.revision == trustedRevision else {
        throw AppError.invalidSecretFile(
            "Secret entry is not the trusted current revision."
        )
    }

    let authenticatedContext = try canonicalEncoder.encode(context)
    let plaintext = try AES.GCM.open(
        sealedBox,
        using: SymmetricKey(data: keyData),
        authenticating: authenticatedContext
    )
    // Decode and return plaintext.
}
```

This binds the revision to the ciphertext, but the `trustedRevision` argument
must not come exclusively from the same replaceable file.

Second, maintain an authenticated vault checkpoint mapping stable entry IDs to
current revisions and ciphertext digests. Each device should pin the newest
accepted checkpoint—or a monotonic epoch/head derived from it—in
device-protected state outside the synchronized vault directory. Enrollment
must transfer the current checkpoint through the already authenticated device
authorization channel.

The exact coordination mechanism depends on the desired offline behavior:

- a single-writer model can use a monotonic manifest generation and
  compare-and-swap publication;
- a multi-writer model needs explicit conflict representation, such as
  per-device counters or an authenticated operation log;
- a trusted synchronization service can provide conditional writes or a
  monotonic record version; and
- a fully offline design can pin per-device heads, but must surface divergence
  when devices reconnect.

Entry and checkpoint updates also need transactional recovery. Writing the
entry first and crashing before its checkpoint, or vice versa, must not create
an unrecoverable false rollback. A small authenticated journal can make the
transition resumable:

```text
prepare(entryID, oldRevision, newRevision, ciphertextDigest)
write(new envelope)
commit(new checkpoint)
clear journal record
```

On restart, the helper should either finish a valid prepared update or retain
the last committed checkpoint and explain the conflict. It should never lower
trusted state automatically to match synchronized files.

Recommended regression tests are:

- a current authentic envelope is accepted;
- a historical authentic envelope is rejected after a newer revision was
  accepted;
- an unauthenticated envelope is rejected regardless of revision;
- trusted revision state survives helper restart;
- the revision, vault ID, entry ID, and ciphertext digest are all
  cryptographically bound;
- a newly enrolled device receives an authenticated current checkpoint;
- a replayed checkpoint cannot lower locally pinned state;
- concurrent updates produce a visible conflict rather than silently selecting
  a lower revision; and
- interruption between entry and checkpoint writes recovers without accepting
  stale state.

## Summary

AES-GCM correctly proves that an entry envelope was created under the vault
key and has not been modified. It cannot prove that the envelope is the newest
valid state. At the reviewed revision, `SecretFile` carries no entry revision,
`EntryStore.load` decodes whichever bytes appear at the path, and
`VaultCipher.decrypt` authenticates those bytes without consulting a trusted
checkpoint.

We demonstrated the missing decision with a deterministic defensive model:
both current and historical envelopes can be authentic, while only trusted
revision state distinguishes them. In the real vault, that gap allows a
historical password or TOTP seed to be returned silently after a synchronized
or restored rollback.

The durable fix is not merely another field in the entry JSON. Key needs
cryptographically bound entry revisions plus a current checkpoint that the
storage actor cannot lower without detection. Multi-device enrollment,
concurrent updates, and interrupted writes must all preserve that checkpoint
or surface an explicit conflict.
