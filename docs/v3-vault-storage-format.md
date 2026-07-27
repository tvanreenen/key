# Key Vault Version 3 Storage Format

Status: normative schema and authority specification for `FMT-201` and
`FMT-202`.

This document freezes the data model and canonical encoding for the version 3
vault manifest body, authenticated manifest envelope, and encrypted entry
files. The envelope uses layered symmetric authentication and device
authorization as defined below.

No version 3 reader or writer is enabled by this specification.

## Normative Language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** are normative.

The machine-readable schemas live beside this document:

- [`v3-common.schema.json`](schemas/v3-common.schema.json)
- [`v3-manifest-body.schema.json`](schemas/v3-manifest-body.schema.json)
- [`v3-manifest-envelope.schema.json`](schemas/v3-manifest-envelope.schema.json)
- [`v3-entry.schema.json`](schemas/v3-entry.schema.json)

The schemas enforce structure. The semantic checks in this document are also
required; JSON Schema alone cannot express all cross-record invariants.

## Design Properties

Version 3 has one manifest body that names a complete logical vault state.
That body commits:

- the vault identity and security mode;
- the manifest generation and active key epoch;
- device membership and roles;
- wrapped keys eligible for the active epoch; and
- every committed entry identity, logical name, semantic type, revision,
  key epoch, and ciphertext digest.

An entry file repeats its authenticated identity context beside its AES-GCM
payload. Those fields are untrusted until authenticated as associated data by
`FMT-204` and `FMT-205`.

Unchanged entries can be referenced by successive manifest generations without
being re-encrypted. Therefore an entry contains its own revision and key epoch,
not the generation number of a particular manifest that references it.

## Canonical JSON

All cryptographic hashes, MACs, signatures, and AES-GCM associated data derived
from JSON objects MUST use the JSON Canonicalization Scheme (JCS) in RFC 8785.

The following rules apply to every version 3 JSON artifact:

1. Input MUST be valid UTF-8 without a byte-order mark.
2. The parsed value MUST satisfy the I-JSON constraints used by JCS.
3. Object property names MUST be unique. A duplicate property is an error,
   even if both values are identical.
4. Producers MUST emit the exact JCS serialization: no insignificant
   whitespace, trailing newline, or alternate string/number encoding.
5. Readers MUST canonicalize the parsed value and require the original bytes
   to equal the canonical bytes before authenticating or hashing it.
6. `null`, floating-point values, negative integers, and JSON values not
   admitted by the relevant schema are forbidden.
7. Integers MUST be in `0...9007199254740991`, the exactly interoperable
   nonnegative integer range for JCS implementations based on IEEE-754 binary64.
8. Binary fields MUST use canonical unpadded `base64url` from RFC 4648
   section 5. `+`, `/`, `=`, whitespace, and non-zero unused pad bits are
   forbidden.
9. UUIDs MUST use lowercase hexadecimal in the
   `8-4-4-4-12` representation.

Pretty-printed JSON MAY be shown in documentation and diagnostics, but it is
never an authenticatable on-disk representation.

## Logical Name Normalization

`name` is the CLI-visible logical identity of an entry. Its normalization is
security-critical because it is committed by the manifest and later included
in AES-GCM associated data.

A producer MUST:

1. interpret the name as Unicode scalar values;
2. normalize the complete string to Unicode Normalization Form C (NFC);
3. split it only on literal `/`;
4. reject an empty name, a leading or trailing `/`, empty segments, `.` or
   `..` segments, NUL, C0/C1 control characters, and literal `\`;
5. reject leading or trailing Unicode whitespace rather than silently trim it;
6. limit each segment to 255 UTF-8 bytes and the complete name to 1024 UTF-8
   bytes; and
7. persist only the normalized result.

A reader MUST reject a stored name that is not already in this canonical form.
Names are equal only when their normalized UTF-8 bytes are equal. Case folding
and compatibility normalization are not performed. A later filesystem layer
MUST reject names that collide on the selected provider even when their
protocol identities differ.

## Identifiers And Counters

| Value | Representation | Meaning |
|---|---|---|
| `vaultID` | lowercase UUID | Random, permanent identity of one vault |
| `entryID` | lowercase UUID | Random, permanent identity of one logical entry |
| `deviceID` | 43-character base64url | SHA-256 fingerprint of the canonical signing/wrapping public-key pair |
| `generation` | nonnegative safe integer | Monotonic committed manifest generation |
| `keyEpoch` | nonnegative safe integer | Monotonic vault encryption-key epoch |
| `revision` | positive safe integer | Monotonic revision of one `entryID` |

IDs MUST NOT be reused after deletion or revocation. Counters MUST NOT wrap.
The transaction and enrollment specifications will define exactly when each
counter advances.

## Manifest Body

The canonical manifest body has these fields and no others:

| Field | Type | Requirement |
|---|---|---|
| `format` | string | Exactly `key-vault-manifest` |
| `version` | integer | Exactly `3` |
| `vaultID` | UUID | Permanent vault identity |
| `mode` | enum | `local` or `shared` |
| `generation` | integer | Current committed manifest generation |
| `keyEpoch` | integer | Current vault-key epoch |
| `devices` | array | Device membership records |
| `wrappedKeys` | array | Per-device wrappers for vault keys |
| `entries` | array | Complete set of committed entry records |

The authenticated envelope MUST authenticate the exact JCS bytes of this entire
object together with its parent-manifest reference. It MUST NOT authenticate a
projection that omits an admitted field.

### Device Record

| Field | Type | Requirement |
|---|---|---|
| `deviceID` | device ID | Stable public-key fingerprint |
| `displayName` | NFC string | User-facing name, 1–128 Unicode scalars, no control characters |
| `role` | enum | `owner` or `member` |
| `status` | enum | `active` or `revoked` |
| `signingPublicKey` | object | P-256 ECDSA public key in X9.63 encoding |
| `wrappingPublicKey` | object | P-256 ECDH public key in X9.63 encoding |
| `enrolledAtGeneration` | integer | First generation containing the device |
| `revokedAtGeneration` | integer | Required only when `status` is `revoked` |

Each public-key value MUST decode to the 65-byte uncompressed P-256 X9.63 form,
including the leading `0x04`, and MUST represent a valid point on the curve.
The signing and wrapping keys MUST be distinct.

`deviceID` is the unpadded base64url encoding of SHA-256 over the JCS bytes of:

```json
{
  "format": "key-vault-device-identity",
  "version": 3,
  "signingPublicKey": {
    "algorithm": "P-256-ECDSA",
    "encoding": "x963",
    "value": "<base64url>"
  },
  "wrappingPublicKey": {
    "algorithm": "P-256-ECDH",
    "encoding": "x963",
    "value": "<base64url>"
  }
}
```

Separate keys preserve purpose separation between authorization signatures and
vault-key delivery. Both keys are bound by the enrollment transcript. The
signing private key MUST be Secure Enclave-backed and require user presence;
therefore ordinary entry-only manifests deliberately do not require a
signature.

Revoked records remain in the manifest so a removed identity cannot be silently
reintroduced as if it were new. Role semantics and enrollment authorization
are finalized by `ENR-501` through `ENR-505`.

### Wrapped-Key Record

| Field | Type | Requirement |
|---|---|---|
| `deviceID` | device ID | Recipient device |
| `keyEpoch` | integer | Epoch of the wrapped vault key |
| `algorithm` | enum | `p256-ecies-x963-sha256-aes-gcm` |
| `ciphertext` | base64url | Complete algorithm output |

For a shared manifest, later semantic validation in `FMT-208` will require
exactly one current-epoch wrapper for every active device and none for revoked
devices. Older wrapped keys do not belong in the current manifest.

### Manifest Entry Record

| Field | Type | Requirement |
|---|---|---|
| `entryID` | UUID | Stable logical entry identity |
| `name` | normalized name | CLI-visible logical name |
| `type` | enum | `secret` or `totp` |
| `revision` | integer | Positive per-entry revision |
| `keyEpoch` | integer | Epoch used to encrypt this revision |
| `ciphertextDigest` | 43-character base64url | SHA-256 of the exact canonical entry-file bytes |

The physical entry filename is derived from `entryID`; it is not supplied by
the manifest. The transaction/filesystem specifications will finalize the
generation directory layout.

### Manifest Ordering And Invariants

JCS does not reorder arrays. Producers MUST sort:

- `devices` by the UTF-8 bytes of `deviceID`;
- `wrappedKeys` by `keyEpoch`, then `deviceID`; and
- `entries` by normalized `name`, then `entryID`, comparing UTF-8 bytes.

Readers MUST reject unsorted arrays. Readers MUST also reject:

- duplicate device IDs, entry IDs, or normalized entry names;
- a device ID that does not equal the fingerprint of its canonical signing and
  wrapping public-key pair;
- `enrolledAtGeneration` later than the manifest generation;
- an active device with `revokedAtGeneration`;
- a revoked device without `revokedAtGeneration`, or with a revocation
  generation earlier than enrollment or later than the manifest;
- an entry or wrapped key whose `keyEpoch` exceeds the manifest `keyEpoch`; and
- a manifest whose mode-specific membership/wrapper invariants fail.

The last item is specified fully in `FMT-208`; until then, no v3 manifest may
be accepted as usable vault authority.

## Manifest Authority And Envelope

Version 3 uses a layered authority model:

- Every manifest has an HMAC-SHA-256 tag under a key derived from the current
  vault encryption key. This proves current vault-key possession and keeps
  ordinary CLI mutations fast and noninteractive.
- A transition that changes mode, key epoch, devices, device roles, device
  status, public keys, or wrapped keys additionally requires at least one
  P-256 ECDSA signature from a device that was an active `owner` in the parent
  manifest. This supplies device attribution and prevents an ordinary member
  that knows the vault key from changing authority.

A signature is not required when only the committed entry set changes.
Verifiers determine this by comparing the authenticated parent and candidate
manifest bodies; a candidate cannot declare its own transition class.

This is preferred over either single mechanism:

- HMAC alone proves vault-key possession but cannot distinguish an `owner` from
  any other device that can decrypt the vault.
- A Secure Enclave signature on every manifest provides attribution but would
  require user presence for routine scripted entry edits.
- The layered rule keeps ordinary CLI use efficient while reserving explicit,
  attributable approval for changes to future authority.

### Envelope Shape

The persisted envelope has exactly:

| Field | Requirement |
|---|---|
| `format` | Exactly `key-vault-manifest-envelope` |
| `version` | Exactly `3` |
| `content` | Parent reference plus the complete manifest body |
| `authentication` | Current-epoch derived-key HMAC |
| `authorizations` | Sorted owner signatures; empty for ordinary entry-only transitions |

`content.parent` is either `{"kind":"genesis"}` or an object containing
`kind: "manifest"`, the parent generation, and SHA-256 of the exact canonical
parent-envelope bytes. A non-genesis candidate MUST advance the parent
generation by exactly one.

The common authentication input is:

```text
UTF8("work.tvr.key/v3/manifest-content") || 0x00 || JCS(content)
```

The 32-byte manifest authentication key is:

```text
HKDF-SHA256(
  IKM = vaultEncryptionKey[keyEpoch],
  salt = 16 UUID bytes in displayed network order,
  info = UTF8("work.tvr.key/v3/manifest-auth-key"),
  L = 32
)
```

`authentication.tag` is the complete 32-byte HMAC-SHA-256 output over the
common authentication input. `authentication.keyEpoch` MUST equal
`content.manifest.keyEpoch`.

Each authorization signs SHA-256 of the same common authentication input using
the signer's dedicated Secure Enclave P-256 signing key. The stored signature
is the canonical 64-byte `r || s` raw representation, with `s` normalized to
the lower half of the P-256 group order before encoding.

Authorizations MUST be sorted by `signerDeviceID` and MUST NOT repeat a signer.
Signers are resolved only from the authenticated parent manifest. A public key
introduced by the candidate cannot authorize its own introduction.

### Verification Order

A reader MUST:

1. validate canonical encoding and structural schemas without side effects;
2. require the parent reference to match the locally trusted current envelope;
3. load the addressed local key or select and unwrap only the candidate's
   current-epoch vault-key wrapper, treating all candidate fields as untrusted;
4. derive the manifest authentication key and verify the HMAC in constant time;
5. compare parent and candidate authority fields;
6. require and verify an active-parent-owner signature for an authority change;
7. apply all manifest semantic checks; and only then
8. expose the candidate as authenticated state.

Failure at any step leaves the trusted current generation unchanged.

An HMAC alone does not establish freshness. `FMT-207` must persist a trusted
current envelope digest/generation locally and treat divergent children as
explicit conflicts.

Local genesis is anchored by local key creation and Keychain state.
Shared genesis and local-to-shared conversion require an owner authorization
and the enrollment/migration ceremony defined later. A self-signed synced
manifest is never sufficient to establish first trust.

This design does not protect against a compromised active owner while its
signing key and current vault key are both usable. It limits ordinary
vault-key-only compromise from silently changing authority and makes authorized
authority changes attributable.

## Encrypted Entry File

The canonical encrypted entry file has these fields and no others:

| Field | Type | Requirement |
|---|---|---|
| `format` | string | Exactly `key-vault-entry` |
| `version` | integer | Exactly `3` |
| `vaultID` | UUID | Must match the manifest |
| `entryID` | UUID | Must match its manifest record |
| `name` | normalized name | Must match its manifest record |
| `type` | enum | Must match its manifest record |
| `keyEpoch` | integer | Must match its manifest record |
| `revision` | integer | Must match its manifest record |
| `encryption` | object | AES-256-GCM payload |

`encryption` contains:

| Field | Type | Requirement |
|---|---|---|
| `algorithm` | enum | Exactly `AES-256-GCM` |
| `nonce` | base64url | Exactly 12 bytes before encoding |
| `ciphertext` | base64url | Zero or more encrypted payload bytes |
| `tag` | base64url | Exactly 16 bytes before encoding |

The plaintext is UTF-8. Type-specific plaintext validation is outside this
storage envelope.

### Entry Authentication Context

The typed entry authentication context contains exactly:

```json
{
  "format": "key-vault-entry",
  "version": 3,
  "vaultID": "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3",
  "entryID": "018f4d39-930c-735d-8d6f-588e9b0a3a48",
  "name": "email/personal",
  "type": "secret",
  "keyEpoch": 3,
  "revision": 4
}
```

The exact AES-GCM associated-data bytes are:

```text
UTF8("work.tvr.key/v3/entry-aad") || 0x00 || JCS(entryAuthenticationContext)
```

The fixed `format` and `version` values are the corresponding entry-file
identity fields, not identifiers for a separate file format. A writer MUST
construct the context from the identity it intends to commit. A reader MUST
construct it from the authenticated manifest's `vaultID` and entry record, then
require every duplicated entry-file field to equal that context.

The context deliberately excludes:

- manifest generation, because one immutable entry revision may be referenced
  by multiple manifest generations;
- `ciphertextDigest`, because it commits the completed canonical entry file
  from the manifest and including it in the entry's own tag would be circular;
  and
- `encryption.nonce`, `ciphertext`, and `tag`, which are direct AES-GCM inputs
  and output.

`encryption.algorithm` is fixed to `AES-256-GCM` by version 3 and MUST be
validated before opening. A reader MUST also compare the exact canonical-file
SHA-256 with the authenticated manifest before returning plaintext.

`FMT-205` MUST pass these exact associated-data bytes to AES-GCM sealing and
opening. The bound revision prevents a ciphertext from validating under a
different revision, but freshness still depends on trusted manifest state from
`FMT-207`.

### Entry Sealing And Opening Contract

The `FMT-205` implementation treats a parsed entry as untrusted structured
data. Sealing generates a fresh 12-byte AES-GCM nonce, encrypts the UTF-8
plaintext with the typed entry context as associated data, emits the exact
canonical entry object, and returns the SHA-256 digest of those canonical bytes
for the manifest record.

The public opening API requires the verifier-produced manifest type and selects
the entry by ID, rather than accepting a free-standing record that a caller
could accidentally treat as authenticated. Before returning plaintext, the
reader MUST:

1. require an exact 32-byte vault key;
2. decode the manifest's canonical base64url `ciphertextDigest` and compare it
   with SHA-256 over the exact entry-file bytes;
3. derive the expected typed context from authenticated manifest values;
4. parse the exact version 3 schema, reject noncanonical JSON, unknown fields,
   unsupported algorithms, and malformed encryption components;
5. require every duplicated entry identity field to equal the manifest-derived
   context;
6. open AES-256-GCM using that context's associated-data bytes; and
7. require valid UTF-8 before releasing plaintext.

Cryptographic opening failures are reported as authentication failures without
returning candidate plaintext. Standalone parsing does not authenticate an
entry and MUST NOT be used as a trust decision.

### Copy And Rename Resealing

Version 3 copy and rename operations MUST authenticate and decrypt the source
through a verifier-produced manifest before constructing a destination. They
MUST preserve the exact valid UTF-8 plaintext bytes and MUST seal with a fresh
12-byte nonce under the destination authentication context. Copying or moving
the existing ciphertext bytes is invalid because the entry identity fields are
authenticated.

Copy creates a new logical entry with:

- the same vault ID, type, and key epoch as the source;
- a fresh, noncolliding entry ID;
- the requested normalized destination name; and
- revision `1`.

Rename creates a replacement revision with:

- the same vault ID, entry ID, type, and key epoch as the source;
- the requested normalized destination name; and
- the source revision incremented by one.

Both operations return canonical encrypted-entry bytes and the matching
manifest record. They reject invalid destination values, current-manifest name
or ID collisions, unchanged rename destinations, revision overflow, and any
source digest or authentication failure before producing a destination.

Overwrite policy and atomic manifest/file commit belong to the transaction
layer. A transaction implementing `--force` MUST still construct and seal the
correct destination context; it MUST NOT fall back to a filesystem copy or
move. Historical ID reuse and stale-source detection remain part of `FMT-207`.
Version 2 CLI copy and rename behavior remains unchanged until the version 3
reader, writer, and transaction layer are enabled together.

## Illustrative Objects

These examples are pretty-printed for readability and are not canonical byte
vectors.

Manifest body:

```json
{
  "format": "key-vault-manifest",
  "version": 3,
  "vaultID": "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3",
  "mode": "shared",
  "generation": 12,
  "keyEpoch": 3,
  "devices": [
    {
      "deviceID": "DzO1MpK36yEEcRSR1JUYExdqhU-2FMv_jYlp5gZ99xs",
      "displayName": "Laptop",
      "role": "owner",
      "status": "active",
      "signingPublicKey": {
        "algorithm": "P-256-ECDSA",
        "encoding": "x963",
        "value": "BGsX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
      },
      "wrappingPublicKey": {
        "algorithm": "P-256-ECDH",
        "encoding": "x963",
        "value": "BHzyexiNA09-ilI4AwS1GsPAiWnid_IbNaYLSPxHZpl4B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E"
      },
      "enrolledAtGeneration": 1
    }
  ],
  "wrappedKeys": [
    {
      "deviceID": "DzO1MpK36yEEcRSR1JUYExdqhU-2FMv_jYlp5gZ99xs",
      "keyEpoch": 3,
      "algorithm": "p256-ecies-x963-sha256-aes-gcm",
      "ciphertext": "AQIDBA"
    }
  ],
  "entries": [
    {
      "entryID": "018f4d39-930c-735d-8d6f-588e9b0a3a48",
      "name": "email/personal",
      "type": "secret",
      "revision": 4,
      "keyEpoch": 3,
      "ciphertextDigest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    }
  ]
}
```

Authenticated envelope:

```json
{
  "format": "key-vault-manifest-envelope",
  "version": 3,
  "content": {
    "parent": {
      "kind": "manifest",
      "generation": 11,
      "digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    },
    "manifest": {
      "format": "key-vault-manifest",
      "version": 3,
      "vaultID": "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3",
      "mode": "shared",
      "generation": 12,
      "keyEpoch": 3,
      "devices": [
        {
          "deviceID": "DzO1MpK36yEEcRSR1JUYExdqhU-2FMv_jYlp5gZ99xs",
          "displayName": "Laptop",
          "role": "owner",
          "status": "active",
          "signingPublicKey": {
            "algorithm": "P-256-ECDSA",
            "encoding": "x963",
            "value": "BGsX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
          },
          "wrappingPublicKey": {
            "algorithm": "P-256-ECDH",
            "encoding": "x963",
            "value": "BHzyexiNA09-ilI4AwS1GsPAiWnid_IbNaYLSPxHZpl4B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E"
          },
          "enrolledAtGeneration": 1
        }
      ],
      "wrappedKeys": [
        {
          "deviceID": "DzO1MpK36yEEcRSR1JUYExdqhU-2FMv_jYlp5gZ99xs",
          "keyEpoch": 3,
          "algorithm": "p256-ecies-x963-sha256-aes-gcm",
          "ciphertext": "AQIDBA"
        }
      ],
      "entries": []
    }
  },
  "authentication": {
    "algorithm": "HKDF-SHA256+HMAC-SHA256",
    "keyEpoch": 3,
    "tag": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  },
  "authorizations": [
    {
      "algorithm": "P-256-ECDSA-SHA256",
      "signerDeviceID": "DzO1MpK36yEEcRSR1JUYExdqhU-2FMv_jYlp5gZ99xs",
      "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    }
  ]
}
```

Encrypted entry:

```json
{
  "format": "key-vault-entry",
  "version": 3,
  "vaultID": "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3",
  "entryID": "018f4d39-930c-735d-8d6f-588e9b0a3a48",
  "name": "email/personal",
  "type": "secret",
  "keyEpoch": 3,
  "revision": 4,
  "encryption": {
    "algorithm": "AES-256-GCM",
    "nonce": "AAAAAAAAAAAAAAAA",
    "ciphertext": "AQIDBA",
    "tag": "AAAAAAAAAAAAAAAAAAAAAA"
  }
}
```

## Version And Unknown-Field Behavior

Parsing is fail-closed:

1. Read enough JSON to identify `format` and `version` without performing
   cryptographic or filesystem side effects.
2. A missing, duplicate, wrong-type, negative, fractional, or unsupported
   `version` is an explicit format error.
3. `version > 3` is an unsupported-future-version error. It MUST NOT be retried
   as v2, prototype metadata, or plaintext.
4. `version < 3` is not a v3 artifact and MUST be routed only to an explicit
   compatible reader or migration preflight.
5. An unknown property at any depth is an error. Version 3 has no extension
   namespace.
6. An unknown enum value, algorithm, role, status, or entry type is an error.
7. Invalid canonical encoding, ordering, normalization, lengths, digest, or
   cross-record semantics is an error.
8. Errors MUST identify the artifact and failure class without including
   ciphertext, wrapped keys, public-key bytes, or decrypted content.

Readers MUST NOT ignore unknown authenticated data. Any future optional field
therefore requires a new format version or a versioned extension mechanism
defined by a later specification.

## Deliberately Deferred

The following decisions are not part of `FMT-201` or `FMT-202`:

- manifest authenticator implementation and key persistence (`FMT-203`);
- exact AES-GCM associated-data bytes (`FMT-204`);
- freshness storage and replay state (`FMT-207`);
- full membership/wrapper consistency rules (`FMT-208`);
- migration and prototype refusal (`FMT-209`, `FMT-210`);
- physical root-pointer, generation, and transaction layout (`TXN-403`,
  `TXN-404`); and
- root-contained filesystem operations (`FS-301` through `FS-305`).

Until those work packages land, version 3 artifacts are specification fixtures,
not trusted production state.

Implementation boundaries and future extraction work are tracked in the
[canonical JSON module plan](json-canonicalization.md).

## Normative References

- [RFC 8785 — JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html)
- [RFC 4648 — Base-N Encodings](https://www.rfc-editor.org/rfc/rfc4648.html)
- [RFC 3629 — UTF-8](https://www.rfc-editor.org/rfc/rfc3629.html)
- [RFC 5869 — HKDF](https://www.rfc-editor.org/rfc/rfc5869.html)
- [RFC 4231 — HMAC-SHA-256 identifiers and test vectors](https://www.rfc-editor.org/rfc/rfc4231.html)
- [NIST FIPS 186-5 — Digital Signature Standard](https://csrc.nist.gov/pubs/fips/186-5/final)
- [NIST SP 800-57 Part 1 Rev. 5 — Key-management guidance](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
- [Apple Secure Enclave P-256 signing](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing)
- [Apple Secure Enclave P-256 key agreement](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/keyagreement)
- [Unicode Standard Annex #15 — Unicode Normalization Forms](https://unicode.org/reports/tr15/)
