# Key Vault Version 3 Storage Format

Status: normative schema specification for `FMT-201`.

This document freezes the data model and canonical encoding for the version 3
vault manifest body and encrypted entry files. It intentionally does not choose
the manifest authentication authority. `FMT-202` and `DEC-001` will select that
authority and define the persisted authenticated manifest envelope around the
body specified here.

No version 3 reader or writer is enabled by this specification.

## Normative Language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** are normative.

The machine-readable schemas live beside this document:

- [`v3-common.schema.json`](schemas/v3-common.schema.json)
- [`v3-manifest-body.schema.json`](schemas/v3-manifest-body.schema.json)
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
| `deviceID` | 43-character base64url | SHA-256 fingerprint of the canonical device public key |
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

The authenticated envelope selected by `FMT-202` MUST authenticate the exact
JCS bytes of this entire object. It MUST NOT authenticate a projection that
omits an admitted field.

### Device Record

| Field | Type | Requirement |
|---|---|---|
| `deviceID` | device ID | Stable public-key fingerprint |
| `displayName` | NFC string | User-facing name, 1–128 Unicode scalars, no control characters |
| `role` | enum | `owner` or `member` |
| `status` | enum | `active` or `revoked` |
| `publicKey` | object | P-256 public-key algorithm, X9.63 encoding, and canonical bytes |
| `enrolledAtGeneration` | integer | First generation containing the device |
| `revokedAtGeneration` | integer | Required only when `status` is `revoked` |

`publicKey.value` MUST decode to the 65-byte uncompressed P-256 X9.63 form,
including the leading `0x04`, and MUST represent a valid point on the curve.
`deviceID` is the unpadded base64url encoding of SHA-256 over those exact 65
bytes.

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
- a device ID that does not equal the fingerprint of `publicKey.value`;
- `enrolledAtGeneration` later than the manifest generation;
- an active device with `revokedAtGeneration`;
- a revoked device without `revokedAtGeneration`, or with a revocation
  generation earlier than enrollment or later than the manifest;
- an entry or wrapped key whose `keyEpoch` exceeds the manifest `keyEpoch`; and
- a manifest whose mode-specific membership/wrapper invariants fail.

The last item is specified fully in `FMT-208`; until then, no v3 manifest may
be accepted as usable vault authority.

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

The entry authenticator context defined by `FMT-204` MUST include every
identity field above. `FMT-205` MUST authenticate that context with AES-GCM.
A reader MUST compare all duplicated fields and the canonical-file SHA-256
against the manifest before returning plaintext.

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
      "deviceID": "aYvqY9xEo0RmP_FCmuoQhC3ye2uZHvJYZrLGwCzcxb4",
      "displayName": "Laptop",
      "role": "owner",
      "status": "active",
      "publicKey": {
        "algorithm": "P-256",
        "encoding": "x963",
        "value": "BGsX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
      },
      "enrolledAtGeneration": 1
    }
  ],
  "wrappedKeys": [
    {
      "deviceID": "aYvqY9xEo0RmP_FCmuoQhC3ye2uZHvJYZrLGwCzcxb4",
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

The following decisions are not part of `FMT-201`:

- MAC, device signature, or layered manifest authority (`FMT-202`, `DEC-001`);
- the persisted authenticated manifest envelope and key identifiers
  (`FMT-202`, `FMT-203`);
- exact AES-GCM associated-data bytes (`FMT-204`);
- encryption/decryption implementation (`FMT-205`);
- rename/copy resealing (`FMT-206`);
- freshness storage and replay state (`FMT-207`);
- full membership/wrapper consistency rules (`FMT-208`);
- migration and prototype refusal (`FMT-209`, `FMT-210`);
- physical root-pointer, generation, and transaction layout (`TXN-403`,
  `TXN-404`); and
- root-contained filesystem operations (`FS-301` through `FS-305`).

Until those work packages land, version 3 artifacts are specification fixtures,
not trusted production state.

## Normative References

- [RFC 8785 — JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html)
- [RFC 4648 — Base-N Encodings](https://www.rfc-editor.org/rfc/rfc4648.html)
- [RFC 3629 — UTF-8](https://www.rfc-editor.org/rfc/rfc3629.html)
- [Unicode Standard Annex #15 — Unicode Normalization Forms](https://unicode.org/reports/tr15/)
