# Vault entries are not authenticated to their logical context

## Executive Summary

Key encrypts each vault entry with AES-256-GCM, but the authenticated data
covers only the plaintext bytes. The logical entry name, vault identity,
semantic type, and format context are outside the GCM authentication boundary.
The read path then trusts the outer `type` field after decrypting the unrelated
ciphertext bytes.

A writer to the synchronized vault directory does not need the AES key to
exchange two valid entry envelopes, move a valid envelope under another logical
name, or change a TOTP envelope's outer type to `secret`. Authentication still
succeeds because none of those values participated in the original GCM tag.
The user can consequently receive a valid secret under the wrong trusted name,
or receive a raw TOTP seed where the CLI was expected to return only a generated
code.

The issue is CWE-345, Insufficient Verification of Data Authenticity. I
reviewed revision `84e7ddb79141d8f1665f3c1bf2e4254677a988a2` directly and
confirmed the cryptographic data flow statically. I did not modify a vault,
execute a trigger, or run a live synchronization test. No fixed revision was
available. The reviewed revision is confirmed affected; the exact introduction
version is unknown.

The attacker needs write access to synchronized vault storage and a subsequent
victim read. AES-GCM still prevents arbitrary ciphertext forgery. Given those
constraints, the recommended calibration is **Low (P3)** with medium integrity
impact.

## Background

Each Key entry is a JSON-encoded `SecretFile`. Its format separates semantic
metadata from the GCM payload:

```swift
// Sources/KeyCore/SecretFile.swift
public struct SecretFile: Codable, Equatable {
    public let version: Int
    public let type: SecretEntryType
    public let alg: String
    public let nonce: String
    public let ciphertext: String
}
```

The entry's logical name is not stored in this structure. It comes from the
relative filesystem path selected by `EntryStore`. The vault identity is
likewise managed outside the entry envelope.

AES-GCM provides confidentiality and integrity for encrypted bytes and can also
authenticate unencrypted associated data. Associated data is the normal
mechanism for binding ciphertext to contextual values that must remain visible,
such as a record identifier or protocol version. A secure read must reconstruct
the exact same associated data from trusted context; otherwise the tag check
must fail.

For this vault, the intended context includes at least:

- a domain separator identifying Key vault entries;
- the entry-format version and algorithm suite;
- the vault identifier;
- the canonical logical entry name; and
- the semantic entry type.

The current format does not provide that binding.

## Vulnerability Details

We first reach encryption in `Sources/KeyCore/VaultCipher.swift`. The function
generates a fresh nonce, which is correct, but invokes `AES.GCM.seal` without
the `authenticating:` parameter:

```swift
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

The `type` is copied into the outer JSON object after sealing. The function
does not receive a logical name or vault ID, so those values cannot influence
the tag either.

Decryption mirrors that omission:

```swift
public func decrypt(
    _ file: SecretFile,
    keyData: Data
) throws -> String {
    guard file.version == 2, file.alg == "AES.GCM" else {
        throw AppError.invalidSecretFile(
            "Unsupported secret file format."
        )
    }

    // Decode nonce, ciphertext, and tag...

    let key = SymmetricKey(data: keyData)
    let sealedBox = try AES.GCM.SealedBox(
        nonce: AES.GCM.Nonce(data: nonceData),
        ciphertext: ciphertext,
        tag: tag
    )
    let plaintext = try AES.GCM.open(sealedBox, using: key)
    // Decode UTF-8...
}
```

The guards at lines 24-25 enforce the currently supported outer format values,
but those values are not authenticated. More importantly, `AES.GCM.open`
receives no expected entry name, vault ID, or type. A tag produced for one
logical position is therefore equally valid at every other position using the
same vault key.

We can follow that state into the read path at
`Sources/KeyCore/KeyServiceHandler.swift:115-122`:

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

Although `decryptSecret` receives `name`, it uses that value only to improve an
error message:

```swift
private func decryptSecret(
    _ file: SecretFile,
    named name: String,
    keyData: Data
) throws -> String {
    do {
        return try cipher.decrypt(file, keyData: keyData)
    } catch CryptoKitError.authenticationFailure {
        throw mismatchedVaultKeyError(for: name)
    }
}
```

The logical name never crosses into the cryptographic operation. After GCM
opens, line 122 uses `encrypted.type` from the outer, storage-controlled
envelope to decide whether to return the decrypted value directly or interpret
it as a TOTP seed.

This produces two concrete context failures:

1. If two intact envelopes are exchanged, both tags remain valid. A request for
   logical name A returns the value originally encrypted for B, and vice versa.
2. If an intact TOTP envelope's outer `type` changes from `totp` to `secret`,
   GCM still opens the original seed and the handler returns the seed rather
   than deriving a short-lived code.

The bad state is not a forged plaintext. It is authentic ciphertext used under
an unauthenticated identity and interpretation.

## Exploitability Analysis

The relevant attacker is a synchronized-storage writer: a compromised sync
provider account, another authorized endpoint that can write the shared
directory, a malicious restore source, or a local process with access to that
directory. The actor controls envelope placement and outer JSON fields but does
not possess the vault key in the storage-only case.

Valid-envelope substitution is the most reliable integrity effect. The actor
does not need to predict a nonce or calculate a tag; each original envelope is
left byte-for-byte intact and only its filesystem association changes. The
result is deterministic whenever both records use the same shared vault key.
The actor may not know each plaintext, but observable file names, sizes, and
update timing can help select records. Without that observation, the effect is
still confusion rather than chosen-plaintext control.

Outer-type substitution is narrower but can cross a meaningful disclosure
boundary. A TOTP seed is long-lived credential material, while the expected CLI
result is a short-lived numeric code. Because the seed is the GCM plaintext and
the outer type selects post-decryption rendering, relabeling the envelope can
cause the output path to expose the seed. This still requires the user or
another authorized client to read the entry; storage write access alone does
not directly return plaintext to the storage actor.

The existing controls significantly bound the primitive:

- fresh GCM nonces avoid same-key nonce reuse in normal encryption;
- the tag prevents arbitrary edits to ciphertext or substitution from a vault
  using a different key;
- unsupported outer `version` and `alg` values are rejected;
- a storage-only actor cannot directly decrypt an entry;
- a victim read is required for semantic confusion or output disclosure.

Changing ciphertext bytes, inventing a new secret, or copying an entry from an
unrelated vault normally fails authentication because the tag or key differs.
Those dead ends are important: this is a context-binding failure, not a break
of AES-GCM itself.

Rollback freshness is related but requires a separate state design. Adding name
and type as associated data prevents cross-context substitution, but it does
not by itself reject an older valid envelope for the same name and context.
If replay resistance is required, the authenticated payload must also carry a
generation that is checked against trusted, conflict-aware vault state.

## Proof of Concept

No offensive or live proof was executed. The sibling `poc/` directory contains
a harmless regression model using only synthetic keys, names, types, vault IDs,
and marker plaintexts. It is designed to run entirely in a unit-test temporary
directory, without Keychain, Secure Enclave, XPC, synchronization, or user data.

The model describes two current-format assertions:

- exchanging two synthetic v2 envelopes does not cause GCM authentication
  failure; and
- changing only a synthetic TOTP envelope's outer type does not cause GCM
  authentication failure.

Those assertions document the reviewed behavior. The fixed-format assertions
invert the expected outcome: changing name, vault ID, type, algorithm suite, or
format version must produce `CryptoKitError.authenticationFailure`.

Representative fixed-format test output should be:

```text
[PASS] exact entry context decrypts
[PASS] changed logical name is rejected
[PASS] changed vault ID is rejected
[PASS] changed semantic type is rejected
[PASS] swapped envelopes are rejected
```

I did not add or execute these tests in the target repository because the
review was non-mutating. The artifact is a defensive test specification, not a
claim of runtime reproduction.

## Remediation

The invariant to restore is: **an entry may decrypt only under the exact vault,
logical name, semantic type, and format suite for which it was encrypted**.

A durable format should use a new version rather than silently changing v2
semantics. One suitable v3 design is:

1. Encrypt a structured payload containing both the secret value and its
   semantic type.
2. Construct canonical, collision-resistant associated data from a domain
   separator, v3 algorithm suite, vault ID, and normalized logical name.
3. Pass that associated data to both `AES.GCM.seal` and `AES.GCM.open`.
4. After opening, use the authenticated inner type; do not trust an outer type
   to select rendering.

The cipher API should make omission difficult:

```swift
struct VaultEntryContext {
    let vaultID: UUID
    let normalizedName: String
    let formatVersion: UInt32

    func authenticatedData() throws -> Data {
        try CanonicalEntryContextEncoder.encode(
            domain: "work.tvr.key.vault-entry",
            vaultID: vaultID,
            normalizedName: normalizedName,
            formatVersion: formatVersion,
            algorithm: "AES-256-GCM"
        )
    }
}

struct EncryptedEntryPayload: Codable {
    let type: SecretEntryType
    let value: String
}

func encrypt(
    _ payload: EncryptedEntryPayload,
    context: VaultEntryContext,
    keyData: Data
) throws -> SecretFile {
    let plaintext = try encoder.encode(payload)
    let aad = try context.authenticatedData()
    let box = try AES.GCM.seal(
        plaintext,
        using: SymmetricKey(data: keyData),
        authenticating: aad
    )
    // Encode nonce, ciphertext, and tag as a v3 SecretFile.
}

func decrypt(
    _ file: SecretFile,
    context: VaultEntryContext,
    keyData: Data
) throws -> EncryptedEntryPayload {
    let box = try makeSealedBox(file)
    let aad = try context.authenticatedData()
    let plaintext = try AES.GCM.open(
        box,
        using: SymmetricKey(data: keyData),
        authenticating: aad
    )
    return try decoder.decode(
        EncryptedEntryPayload.self,
        from: plaintext
    )
}
```

`CanonicalEntryContextEncoder` must not use an ambiguous concatenation. Use a
specified binary encoding with fixed-width integers and length-prefixed UTF-8
fields, or another deterministic canonical representation. Normalize entry
names once before both path resolution and AAD construction so equivalent path
spellings cannot create divergent contexts.

The handler must construct context from trusted runtime state:

- vault ID from authenticated vault metadata or a device-local immutable vault
  identity;
- normalized name from the requested logical name; and
- v3 format/algorithm constants selected by code.

Binding the name changes copy and move semantics. Those operations must
decrypt, verify the source context, and re-encrypt under the destination
context. Raw ciphertext relocation should fail by design.

Migration should be explicit and interruption-safe: read and authenticate each
v2 entry with the existing key, re-encrypt to v3 in staged files, verify the
staged set, and atomically commit or retain enough journal state to resume.
After migration, normal reads should reject v2 rather than quietly accepting
the weaker context rules indefinitely.

Regression tests should cover:

1. Exact-context v3 round trips for secrets and TOTP entries.
2. Authentication failure when only the normalized logical name changes.
3. Authentication failure when only the vault ID changes.
4. Authentication failure when semantic type changes.
5. Authentication failure for format-version or algorithm-suite confusion.
6. Exchanging two valid v3 envelopes under different names fails for both.
7. Copy and move decrypt then re-encrypt under the destination name.
8. Canonicalization produces identical AAD for the one permitted normalized
   representation and rejects ambiguous names.
9. A v2-to-v3 migration interruption can resume without mixed-format loss.
10. If replay resistance is implemented, an older authenticated generation is
    rejected against trusted current state.

## Summary

Key uses AES-GCM correctly for the bytes it chooses to authenticate, but the
chosen boundary is too narrow for a file-backed synchronized vault. We traced
the logical name from `KeyServiceHandler` and the semantic type from
`SecretFile` to `VaultCipher`; neither reaches GCM associated data or the
encrypted payload. As a result, authentic envelopes remain valid after
cross-name substitution, and an unauthenticated outer type controls whether a
decrypted TOTP seed is rendered as a code or returned directly.

The attacker cannot forge ciphertext or decrypt entries from storage alone,
which keeps the severity at Low/P3. The durable correction is a versioned
format that authenticates canonical vault and entry context, carries semantic
type inside the encrypted payload, and rebinds ciphertext during copy or move.
The accompanying synthetic regression model defines the expected security
invariant without touching a live vault.
