# Key Vault Version 3 Storage Format

Status: normative schema, authority, replay, membership, migration,
prototype-refusal, exact-head, and exact-key-identity specification through
`KEY-403`.

This document defines the current unreleased data model and canonical encoding
for the version 3 vault manifest body, authenticated manifest envelope, and
encrypted entry files. The envelope uses layered symmetric authentication and
device authorization as defined below. Planned format changes are explicitly
listed under Deliberately Deferred and must update this specification before
implementation.

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
- the exact active vault-key identity;
- device membership and roles;
- wrappers for the exact active vault key; and
- every committed entry identity, logical name, semantic type, revision,
  vault-key identity, and ciphertext digest.

An entry file repeats its authenticated identity context beside its AES-GCM
payload. Those fields are untrusted until authenticated as associated data by
`FMT-204` and `FMT-205`.

Unchanged entries can be referenced by successive manifests without being
re-encrypted. Therefore an entry contains its own revision and exact vault-key
identity, while the exact authenticated envelope digest identifies each
complete vault state.

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
| `keyID` | 43-character base64url | Vault-scoped identity of one exact 32-byte vault key |
| `revision` | positive safe integer | Monotonic revision of one `entryID` |

IDs MUST NOT be reused after deletion or revocation. Revisions MUST NOT wrap.
Manifest freshness, ancestry, key identity, and concurrency MUST NOT be inferred
from a counter.

### Vault-Key Identity

`keyID` is the unpadded canonical base64url encoding of this 32-byte output:

```text
HKDF-SHA256(
  IKM = exact 32-byte vault encryption key,
  salt = 16 vaultID UUID bytes in displayed network order,
  info = UTF8("work.tvr.key/v3/vault-key-id"),
  L = 32
)
```

The identifier is public authenticated metadata, not key material. The
vault-ID salt prevents correlation if the same vault-key bytes are accidentally
reused across vaults, and the distinct `info` label separates this output from
encryption and manifest-authentication keys.

A producer or reader that possesses vault-key bytes MUST derive `keyID` and
require an exact match before using those bytes for manifest authentication,
entry sealing or opening, or a wrapped-key result. A different key MUST NOT be
accepted merely because it was produced on a branch that would previously have
used the same next numeric epoch.

## Manifest Body

The canonical manifest body has these fields and no others:

| Field | Type | Requirement |
|---|---|---|
| `format` | string | Exactly `key-vault-manifest` |
| `version` | integer | Exactly `3` |
| `vaultID` | UUID | Permanent vault identity |
| `mode` | enum | `local` or `shared` |
| `keyID` | 43-character base64url | Exact current vault-key identity |
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
reintroduced as if it were new. Enrollment and revocation are authenticated
history transitions derived by comparing a manifest with its parent; the
current snapshot does not carry a counter pretending to identify those
transitions. Role semantics and enrollment authorization are finalized by
`ENR-501` through `ENR-505`.

### Wrapped-Key Record

| Field | Type | Requirement |
|---|---|---|
| `deviceID` | device ID | Recipient device |
| `keyID` | 43-character base64url | Identity of the wrapped vault key |
| `algorithm` | enum | `p256-ecies-x963-sha256-aes-gcm` |
| `ciphertext` | base64url | Complete algorithm output |

Local manifests MUST have empty `devices` and `wrappedKeys` arrays. Shared
manifests MUST contain at least one active owner and exactly one wrapper at the
manifest's current `keyID` for every active device. After unwrapping, a reader
MUST derive the resulting key's ID and require that exact value. A wrapper MUST
NOT name a revoked or unknown device. Older wrapped keys do not belong in the
current manifest.

### Manifest Entry Record

| Field | Type | Requirement |
|---|---|---|
| `entryID` | UUID | Stable logical entry identity |
| `name` | normalized name | CLI-visible logical name |
| `type` | enum | `secret` or `totp` |
| `revision` | integer | Positive per-entry revision |
| `keyID` | 43-character base64url | Identity of the key used to encrypt this revision |
| `ciphertextDigest` | 43-character base64url | SHA-256 of the exact canonical entry-file bytes |

The manifest supplies logical entry identity, not a trusted physical path. The
immutable digest-addressed object layout is finalized by `STORE-405`.

### Manifest Ordering And Invariants

JCS does not reorder arrays. Producers MUST sort:

- `devices` by the UTF-8 bytes of `deviceID`;
- `wrappedKeys` by the UTF-8 bytes of `keyID`, then `deviceID`; and
- `entries` by normalized `name`, then `entryID`, comparing UTF-8 bytes.

Readers MUST reject unsorted arrays. Readers MUST also reject:

- duplicate device IDs, entry IDs, or normalized entry names;
- a device ID that does not equal the fingerprint of its canonical signing and
  wrapping public-key pair;
- a local manifest with any device or wrapped-key record;
- a shared manifest without an active owner;
- a shared manifest without exactly one current-key wrapper for every active
  device; and
- a shared manifest with a wrapper for a revoked or unknown device.

## Manifest Authority And Envelope

Version 3 uses a layered authority model:

- Every manifest has an HMAC-SHA-256 tag under a key derived from the current
  vault encryption key. This proves current vault-key possession and keeps
  ordinary CLI mutations fast and noninteractive.
- A transition that changes mode, active key ID, devices, device roles, device
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
| `authentication` | Exact-current-key derived HMAC |
| `authorizations` | Sorted owner signatures; empty for ordinary entry-only transitions |

`content.parent` is either `{"kind":"genesis"}` or an object containing
`kind: "manifest"` and canonical base64url SHA-256 of the exact canonical
parent-envelope bytes. A non-genesis candidate MUST name the exact trusted
parent digest. `HIST-404` later replaces this singular reference with a
canonical parent-digest array for authenticated merge history.

The common authentication input is:

```text
UTF8("work.tvr.key/v3/manifest-content") || 0x00 || JCS(content)
```

The 32-byte manifest authentication key is:

```text
HKDF-SHA256(
  IKM = exact vaultEncryptionKey identified by content.manifest.keyID,
  salt = 16 UUID bytes in displayed network order,
  info = UTF8("work.tvr.key/v3/manifest-auth-key"),
  L = 32
)
```

`authentication.tag` is the complete 32-byte HMAC-SHA-256 output over the
common authentication input. `authentication.keyID` MUST equal
`content.manifest.keyID`, and both MUST equal the ID derived from the supplied
vault key before the manifest can authenticate.

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
   exact-current-key wrapper, treating all candidate fields as untrusted;
4. derive the supplied key's ID, require it to match both authenticated key-ID
   fields, then derive the manifest authentication key and verify the HMAC in
   constant time;
5. compare parent and candidate authority fields;
6. require and verify an active-parent-owner signature for an authority change;
7. apply all manifest semantic checks; and only then
8. expose the candidate as authenticated state.

Failure at any step leaves the trusted current head unchanged.

An HMAC alone does not establish freshness. A reader MUST also pass the
device-local manifest freshness gate below before treating authenticated
manifest data as current.

### Device-Local Manifest Freshness

Each device persists one local checkpoint for every trusted version 3 vault.
The checkpoint is canonical JSON with exactly:

| Field | Requirement |
|---|---|
| `format` | Exactly `key-vault-manifest-checkpoint` |
| `version` | Exactly `1` |
| `vaultID` | The independently expected vault UUID |
| `envelopeDigest` | Canonical base64url SHA-256 of the exact current manifest-envelope bytes |

The checkpoint is rollback state, not synchronized vault content. The shipping
store MUST use a non-synchronizing, this-device-only Keychain item scoped to
the signed application's access group. It does not require user presence
because it contains no secret and ordinary reads must remain scriptable.
Checkpoint writes belong only to the serialized helper mutation owner; other
processes MUST NOT write the item directly.

First trust may be established only while creating an independently anchored
local genesis and only when the checkpoint is expected to be absent. A missing
checkpoint beside an existing or synchronized vault MUST NOT be repaired by
silently adopting the observed manifest. Shared genesis and conversion use the
later enrollment and migration ceremonies.

For an existing checkpoint, a reader classifies an observed manifest before
exposing it as current:

- only the exact vault ID and envelope digest already in the checkpoint may be
  reopened as current;
- any other manifest from the same vault is an unexpected head and MUST NOT be
  adopted from its fields or counters; and
- rollback, descendant, and fork classification requires authenticating the
  observed manifest's parent history back to the checkpointed head or a common
  authenticated ancestor. That graph-aware classification belongs to
  `STORE-405`.

During this linear increment, advancement accepts exactly one authenticated
child of the checkpointed parent. The reader first reopens the exact parent
bytes through the checkpoint, verifies that the child names that exact parent
digest, performs the complete child verification order above, and only then
replaces the checkpoint while requiring the expected prior checkpoint. The
parent and child vault keys are separate inputs because a valid authority
transition may replace the vault key. Authentication, semantic, authorization,
or persistence failure leaves the prior checkpoint unchanged.

Only this freshness gate produces a `V3TrustedManifest`. Public entry open,
copy, and rename operations require that type rather than a merely
`V3VerifiedManifest`, preventing an old but cryptographically valid manifest
from being used as entry authority.

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
| `keyID` | 43-character base64url | Must match its manifest record |
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
  "keyID": "YWHJjbH1Mqt6bAtnVdqoT84nrfbogDs7lWSFQT8V8iA",
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

- manifest-envelope digest and parent history, because one immutable entry
  revision may be referenced by multiple authenticated manifests;
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
for the manifest record. Before sealing, it derives the supplied vault key's ID
for the context vault ID and requires an exact match.

The public opening API requires the verifier-produced manifest type and selects
the entry by ID, rather than accepting a free-standing record that a caller
could accidentally treat as authenticated. Before returning plaintext, the
reader MUST:

1. require an exact 32-byte vault key;
2. derive its vault-scoped key ID and require it to equal the authenticated
   manifest entry's `keyID`;
3. decode the manifest's canonical base64url `ciphertextDigest` and compare it
   with SHA-256 over the exact entry-file bytes;
4. derive the expected typed context from authenticated manifest values;
5. parse the exact version 3 schema, reject noncanonical JSON, unknown fields,
   unsupported algorithms, and malformed encryption components;
6. require every duplicated entry identity field to equal the manifest-derived
   context;
7. open AES-256-GCM using that context's associated-data bytes; and
8. require valid UTF-8 before releasing plaintext.

Cryptographic opening failures are reported as authentication failures without
returning candidate plaintext. Standalone parsing does not authenticate an
entry and MUST NOT be used as a trust decision.

If the exact entry-file digest differs, a reader may authenticate the observed
canonical entry under its own associated-data context solely to classify the
failure; it MUST NOT release that plaintext. An authenticated lower revision
is an explicit entry rollback. An authenticated same or higher revision with a
different digest is an explicit entry conflict. Malformed or unauthenticated
alternatives remain ordinary digest mismatches.

### Copy And Rename Resealing

Version 3 copy and rename operations MUST authenticate and decrypt the source
through a freshness-approved manifest before constructing a destination. They
MUST preserve the exact valid UTF-8 plaintext bytes and MUST seal with a fresh
12-byte nonce under the destination authentication context. Copying or moving
the existing ciphertext bytes is invalid because the entry identity fields are
authenticated.

Copy creates a new logical entry with:

- the same vault ID, type, and exact key ID as the source;
- a fresh, noncolliding entry ID;
- the requested normalized destination name; and
- revision `1`.

Rename creates a replacement revision with:

- the same vault ID, entry ID, type, and exact key ID as the source;
- the requested normalized destination name; and
- the source revision incremented by one.

Both operations return canonical encrypted-entry bytes and the matching
manifest record. They reject invalid destination values, current-manifest name
or ID collisions, unchanged rename destinations, revision overflow, and any
source digest or authentication failure before producing a destination.

Overwrite policy and atomic manifest/file commit belong to the transaction
layer. A transaction implementing `--force` MUST still construct and seal the
correct destination context; it MUST NOT fall back to a filesystem copy or
move. The freshness gate rejects stale source manifests, and authenticated old
entry revisions receive explicit rollback errors. The public copy primitive
does not accept caller-selected IDs; transaction and migration code that does
construct identities MUST also reject IDs found in retained trusted history.
Version 2 CLI copy and rename behavior remains unchanged until the version 3
reader, writer, and transaction layer are enabled together.

## Version 2 Migration Preflight And Rollback

Migration is an explicit user action. Installing a release that understands
version 3 MUST NOT rewrite an existing version 2 vault automatically.

`key migrate --check` is the read-only compatibility check. It MUST:

- enumerate every version 2 `.secret` entry through the shipping entry store;
- require each logical name to satisfy the version 3 name rules;
- require the supported version 2 typed AES-GCM file format;
- authenticate and decrypt every entry with the currently selected vault key;
- validate decrypted TOTP values as Base32 without returning plaintext;
- report every discovered per-entry blocker in deterministic order; and
- return failure when any entry is unreadable, unsupported, malformed,
  undecryptable, semantically invalid, or incompatible with version 3 naming.

The preflight MUST NOT create, replace, synchronize, or repair a Keychain item.
It MUST NOT write, rename, delete, or change permissions on any vault file.
An empty vault passes without loading or creating a vault key. Every result
states that no migration has started.

The report is a point-in-time diagnostic, not permission to skip later checks.
A migration writer MUST rerun the complete preflight under the serialized
mutation owner immediately before staging output.

The later migration writer and transaction layer MUST implement this rollback
contract:

1. Treat the version 2 vault as the active and only authoritative state
   until a complete version 3 replacement has been staged and verified.
2. Create version 3 artifacts in a distinct staging or immutable-object
   location. Never overwrite a version 2 entry in place.
3. Authenticate and reopen every staged version 3 entry through its candidate
   manifest before publishing an authenticated version 3 head.
4. Make the authenticated-head commit and device-local checkpoint transition
   the only operation that selects version 3 as active state.
5. On failure before that transition, discard only incomplete version 3 staging
   state; the untouched version 2 vault remains active.
6. Retain the complete version 2 source after transition until the committed
   version 3 vault has been reopened successfully and the user explicitly
   chooses a later cleanup policy.
7. On interruption during or after the transition, use transaction recovery
   to select one complete state. Never combine version 2 and version 3
   files into a partially migrated active vault.

`key migrate --check` implements only the diagnostic portion of this contract.
It does not enable a version 3 writer or an apply command.

## Unsupported Prototype Enclave State

The unreleased Secure Enclave sharing prototype at revision
`84e7ddb79141d8f1665f3c1bf2e4254677a988a2` is not a compatibility format. Its
root-level `.key-vault.json` file contains unauthenticated version 1
authorization, membership, epoch, and wrapped-key records. Those records MUST
NOT become a version 3 trust anchor.

`key migrate --check` MUST inspect the direct children of the selected vault
root for the exact `.key-vault.json` marker before loading a vault key. Presence
blocks migration regardless of the marker's contents, readability, or file
type. The preflight MUST NOT decode, repair, delete, rename, or rewrite the
prototype marker and MUST preserve its ordinary guarantees against file and
Keychain item writes.

This refusal is limited to migration. Shipping version 2 reads remain
unchanged because they neither interpret nor trust the prototype metadata.
Version 3 parsers independently require their exact format discriminator,
version, canonical encoding, and schema, and MUST reject prototype JSON as a
version 3 manifest.

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
  "keyID": "YWHJjbH1Mqt6bAtnVdqoT84nrfbogDs7lWSFQT8V8iA",
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
      }
    }
  ],
  "wrappedKeys": [
    {
      "deviceID": "DzO1MpK36yEEcRSR1JUYExdqhU-2FMv_jYlp5gZ99xs",
      "keyID": "YWHJjbH1Mqt6bAtnVdqoT84nrfbogDs7lWSFQT8V8iA",
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
      "keyID": "YWHJjbH1Mqt6bAtnVdqoT84nrfbogDs7lWSFQT8V8iA",
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
      "digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    },
    "manifest": {
      "format": "key-vault-manifest",
      "version": 3,
      "vaultID": "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3",
      "mode": "shared",
      "keyID": "YWHJjbH1Mqt6bAtnVdqoT84nrfbogDs7lWSFQT8V8iA",
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
          }
        }
      ],
      "wrappedKeys": [
        {
          "deviceID": "DzO1MpK36yEEcRSR1JUYExdqhU-2FMv_jYlp5gZ99xs",
          "keyID": "YWHJjbH1Mqt6bAtnVdqoT84nrfbogDs7lWSFQT8V8iA",
          "algorithm": "p256-ecies-x963-sha256-aes-gcm",
          "ciphertext": "AQIDBA"
        }
      ],
      "entries": []
    }
  },
  "authentication": {
    "algorithm": "HKDF-SHA256+HMAC-SHA256",
    "keyID": "YWHJjbH1Mqt6bAtnVdqoT84nrfbogDs7lWSFQT8V8iA",
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
  "keyID": "YWHJjbH1Mqt6bAtnVdqoT84nrfbogDs7lWSFQT8V8iA",
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

`HIST-402` and `KEY-403` establish exact digest-based identities for linear
authenticated history and vault keys. They deliberately do not define:

- canonical multi-parent merge history (`HIST-404`);
- immutable physical object layout and head discovery (`STORE-405`);
- automatic reconciliation (`MERGE-406`);
- transaction publication and recovery (`TXN-407` and `TXN-408`); or
- physical migration execution beyond preflight.

Until those work packages land, version 3 artifacts remain disabled as trusted
production state.

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
