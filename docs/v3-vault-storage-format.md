# Key Vault Version 3 Storage Format

Status: normative schema, authority, replay, membership, migration,
prototype-refusal, exact-head, exact-key-identity, and canonical multi-parent
history specification through `HIST-404`.

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

The authenticated envelope MUST authenticate the exact JCS bytes of this
entire object together with its complete parent-manifest set. It MUST NOT
authenticate a projection that omits an admitted field.

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
| `algorithm` | enum | `p256-ecies-x963-sha256-aes-gcm` |
| `ciphertext` | base64url | Complete algorithm output |

Local manifests MUST have empty `devices` and `wrappedKeys` arrays. Shared
manifests MUST contain at least one active owner and exactly one wrapper at the
manifest's current `keyID` for every active device. The wrapper inherits that
identity from the manifest rather than repeating it. After unwrapping, a reader
MUST derive the resulting key's ID and require it to equal `manifest.keyID`. A
wrapper MUST NOT name a revoked or unknown device. Older wrapped keys do not
belong in the current manifest.

### Manifest Entry Record

| Field | Type | Requirement |
|---|---|---|
| `entryID` | UUID | Stable logical entry identity |
| `name` | normalized name | CLI-visible logical name |
| `type` | enum | `secret` or `totp` |
| `revision` | integer | Positive per-entry revision |
| `keyID` | 43-character base64url | Identity of the key used to encrypt this revision |
| `ciphertextDigest` | 43-character base64url | SHA-256 of the exact canonical entry-file bytes |

The manifest supplies logical entry identity, not a trusted physical path.
Immutable entry objects use the digest-derived repository path defined below.

For every non-genesis parent-to-child transition, revisions are checked per
stable `entryID`:

- a record that is byte-for-byte unchanged from its parent may retain its
  revision;
- a changed record MUST have a revision greater than every direct parent
  record for that entry;
- a newly introduced entry ID MUST start at revision `1`; and
- a multi-parent manifest may reuse an exact parent record only when it is the
  unambiguous highest-revision record across the direct parents.

Consequently, a lower revision is a rollback and a different record at the
same highest revision is a conflict. When two parents contain different
records at the same highest revision, a merge cannot silently select either
one. It must preserve the conflict or publish an explicitly resolved,
newly sealed record at a higher revision. Deletion removes the record and does
not create a synthetic tombstone revision.

### Manifest Ordering And Invariants

JCS does not reorder arrays. Producers MUST sort:

- `devices` by the UTF-8 bytes of `deviceID`;
- `wrappedKeys` by the UTF-8 bytes of `deviceID`; and
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
- A single-parent transition that changes mode, active key ID, devices, device
  roles, device status, public keys, or wrapped keys additionally requires at
  least one P-256 ECDSA signature from a device that was an active `owner` in
  the parent manifest. This supplies device attribution and prevents an
  ordinary member that knows the vault key from changing authority.
- A multi-parent transition is admitted only when every parent and the
  candidate have identical vault identity, mode, active key ID, membership,
  roles, public keys, statuses, and wrapped-key state. A merge cannot change
  authority and carries no owner authorization.

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
| `content` | Complete parent-digest set plus the complete manifest body |
| `authentication` | Exact-current-key derived HMAC |
| `authorizations` | Sorted owner signatures; empty for ordinary entry-only transitions |

`content.parents` is an array of canonical base64url SHA-256 digests over the
exact canonical parent-envelope bytes. Genesis has no parents, an ordinary
commit has exactly one, and a merge commit has two or more. Digests MUST be
strictly increasing by their decoded 32-byte values, which also rejects
duplicates. A non-genesis candidate MUST name the complete exact set of
verified parents.

The verification API accepts parent history only as `V3VerifiedManifest`
values. Raw synchronized files cannot become parent authority merely because
their digest appears in a candidate. Repository traversal in `STORE-405` is
responsible for authenticating each branch from established ancestry before
passing those typed results to merge verification.

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
common authentication input. `content.manifest.keyID` MUST equal the ID derived
from the supplied vault key before the manifest can authenticate. The
authentication object does not repeat the active key ID.

Each authorization signs SHA-256 of the same common authentication input using
the signer's dedicated Secure Enclave P-256 signing key. The stored signature
is the canonical 64-byte `r || s` raw representation, with `s` normalized to
the lower half of the P-256 group order before encoding.

Authorizations MUST be sorted by `signerDeviceID` and MUST NOT repeat a signer.
For a single-parent authority change, signers are resolved only from the
authenticated parent manifest. A public key
introduced by the candidate cannot authorize its own introduction.

### Verification Order

A reader MUST:

1. validate canonical encoding and structural schemas without side effects;
2. require the complete canonical parent set to match supplied verified
   manifests, including the locally trusted current envelope when advancing
   device-local state;
3. load the addressed local key or select and unwrap only the candidate's
   exact-current-key wrapper, treating all candidate fields as untrusted;
4. derive the supplied key's ID, require it to match the manifest's
   authenticated key ID, then derive the manifest authentication key and verify
   the HMAC in constant time;
5. compare every parent and candidate authority field;
6. for one parent, require and verify an active-parent-owner signature for an
   authority change; for multiple parents, reject every authority difference;
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

Advancement currently accepts exactly one authenticated child of the
checkpointed parent. The reader first reopens the exact parent through the
checkpoint, verifies the child's parent set, performs the verification order
above, and only then replaces the checkpoint while requiring the expected
prior checkpoint. The parent and candidate vault keys are separate inputs
because a valid single-parent authority transition may replace the vault key.
Authentication, semantic, authorization, or persistence failure leaves the
prior checkpoint unchanged.

This increment can authenticate the direct parent set of a merge but MUST NOT
promote that merge to the device-local checkpoint from
`V3VerifiedManifest` values alone. Read-only repository discovery produces a
`V3ManifestAncestryProof` only after every branch reaches established trusted
history. A later freshness API will accept that proof rather than treating
cryptographic validity as freshness. Calculating the merged entry set remains
`MERGE-406`.

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

## Immutable Object Repository

Version 3 synchronized state contains immutable objects at these exact relative
paths:

```text
manifests/<64-lowercase-hex-manifest-digest>.json
entries/<entry-id>/<64-lowercase-hex-ciphertext-digest>.json
```

The manifest filename digest is SHA-256 of the exact canonical manifest
envelope bytes. The entry filename digest is the same SHA-256 value encoded as
`ciphertextDigest` in its authenticated manifest entry record. Authenticated
records retain canonical unpadded base64url; physical filenames use lowercase
hexadecimal so two object names cannot differ only by case on a
case-insensitive filesystem or sync provider.

Writers MUST publish a new object only at its derived path and MUST NOT replace
an existing object. Identical bytes converge on the same filename. Different
bytes use different filenames. A file such as `current`, `HEAD`, or
`latest.json` has no authority even if a sync provider or older client creates
one.

Readers MUST resolve the repository and each referenced object relative to the
retained vault-root descriptor using the containment rules in this
specification. A manifest object is eligible for graph authentication only
when its canonical bytes hash to the digest in its exact lowercase filename.
An entry object is usable only when its exact bytes hash to the filename and
authenticated manifest digest and its canonical entry context matches the
manifest-derived context.

### Authenticated History Discovery

Discovery begins from the exact manifest named by the device-local checkpoint,
not from a synchronized mutable pointer or the lexically greatest filename.
The reader:

1. requires the checkpoint manifest at its derived immutable path;
2. follows its exact parent digests backward, reopening those exact historical
   bytes as checkpoint-anchored ancestry;
3. enumerates candidate manifest objects under the canonical object layout;
4. fully authenticates forward descendants against their complete verified
   parent sets and an exact locally available vault key;
5. derives leaf heads as authenticated manifests that are not the parent of
   another authenticated reachable manifest;
6. recursively follows unresolved, authenticated candidate ancestry before
   treating a missing referenced manifest as incomplete transport; and
7. validates every immutable entry object against every manifest context that
   references it without decrypting entry plaintext.

Walking backward through digest links does not require retaining every
historical vault key. The trusted checkpoint envelope cryptographically commits
to its exact parents, which commit to their parents transitively. A new forward
candidate still requires normal HMAC, authorization, semantic, and complete
parent-set verification before it can join authenticated reachable history.

Discovery returns one of these states:

| State | Meaning |
|---|---|
| `ready` | Exactly one complete authenticated reachable head |
| `incomplete` | A checkpoint-linked manifest, authenticated candidate parent, or referenced entry is missing or is an unmaterialized provider placeholder |
| `contentConflicted` | Multiple complete authenticated heads have identical authority state |
| `securityConflicted` | Multiple complete authenticated heads disagree on mode, active key identity, membership, roles, public keys, statuses, or wrapped-key state |
| `recoveryRequired` | A referenced immutable object has the wrong bytes or structure, violates safe path resolution, or exceeds a traversal/resource bound |

Recovery-required state takes precedence over incomplete state, which takes
precedence over a conflict classification. Invalid unreferenced objects and
noncanonical filenames do not become trusted history and cannot replace the
checkpoint head. An authenticated candidate that names an unavailable parent
is incomplete transport only while the candidate remains structurally capable
of joining the trusted graph. The reader MUST recursively inspect available
unresolved parents, MUST reject merge candidates that already violate the
authority or authorization rules, and MUST NOT let such impossible candidates
block readiness. It MUST NOT guess a genuinely unavailable parent or discard
the other branch.

A physical entry object MAY be read once when several reachable manifests
reference the same entry ID and ciphertext digest, but the reader MUST compare
the parsed entry context with every referencing manifest context. Matching one
of those contexts is not sufficient.

A complete classification may return a typed ancestry proof containing the
checkpoint, authenticated reachable manifests, and derived heads. The proof is
read-only. Discovery MUST NOT modify synchronized files or advance the
device-local checkpoint.

Readers MUST bound repository work. This implementation accepts at most 4,096
manifest-directory objects, history depth 1,024, 16,384 distinct referenced
entry objects, 2 MiB per manifest object, and 16 MiB per encrypted entry
object. One scan also accepts at most 64 MiB of manifest bytes and 256 MiB of
encrypted-entry bytes in total. Writers MUST remain within these limits.

### Deterministic Reconciliation

Reconciliation accepts only a complete `V3ManifestAncestryProof`. It is a pure
logical operation: it performs no filesystem access, entry decryption, random
generation, publication, or device-local checkpoint mutation.

For one authenticated head, no merge is required. For two or more heads, the
reader:

1. orders heads by their decoded envelope digests;
2. rejects authority divergence before comparing content;
3. finds the nearest common authenticated ancestor of every head;
4. indexes ancestor and head entries by stable entry ID;
5. preserves a lower-revision rollback or same-revision substitution as a
   typed conflict;
6. selects the ancestor value when no head changed that entry;
7. selects one distinct changed value when every other head retained the
   ancestor value or made the identical change;
8. returns a typed entry conflict when two or more distinct changes remain;
9. rejects duplicate logical destination names in the proposed result; and
10. emits canonical manifest content whose parents are the exact ordered heads.

Entry conflicts preserve the common-ancestor record and every changed head's
exact record. A nil head record represents deletion. Conflict kinds distinguish
concurrent creation, edit/edit, delete/edit, rename-plus-edit, and conflicting
renames, revision rollback, and same-revision substitution. Destination
collisions retain every selected entry record. Authority divergence is a
security conflict and MUST NOT enter content reconciliation.

Rename-plus-edit is not automatically combined in version 3. Renaming changes
the entry AAD and therefore requires new ciphertext even when plaintext is
unchanged. Authenticated manifest records alone cannot prove whether a branch
only renamed the ancestor value or renamed and edited it. A reader MUST retain
both versions rather than risk silently discarding a value.

If a criss-cross graph has more than one nearest common ancestor, the reader
MUST return those exact ancestor heads as a history conflict. It MUST NOT choose
one based on array order, filename order, timestamps, device labels, or
transport metadata.

An automatic merge plan contains the unique common ancestor, every exact
parent head, and deterministic manifest content. It is not an authenticated or
published manifest. The transaction publisher defined later MUST authenticate
and durably commit it under the expected-head rules.

### Immutable Transaction Publication

One helper-owned mutation publishes a candidate only from a complete
authenticated ancestry proof. The candidate's direct parents MUST equal the
proof's exact heads. A multi-parent automatic merge candidate MUST equal the
deterministic reconciliation plan; unresolved content, security, revision, or
history conflicts cannot enter publication.

New objects are staged at:

```text
.transactions/<operation-id>/intent.json
.transactions/<operation-id>/entries/<entry-id>/<64-lowercase-hex-digest>.json
.transactions/<operation-id>/manifests/<64-lowercase-hex-digest>.json
```

The operation ID is a canonical lowercase UUID assigned inside the serialized
helper mutation owner. These paths are staging state only. Repository
discovery MUST ignore them, and neither their names nor their contents have
manifest authority.

Each canonical staging path is installed by synchronizing complete bytes to a
fresh, exclusively created, same-directory hidden temporary file and then
using an exclusive atomic rename. A crash can leave a hidden `*.partial` file,
but it cannot expose partial bytes at a canonical intent, entry, or manifest
staging path. Hidden temporary files have no recovery or manifest authority,
MUST be ignored, and MUST NOT be reopened or truncated by a later attempt.

Before creating shared transaction state, the publishing device MUST create a
small expected-value-guarded recovery anchor outside the synchronized vault.
The current implementation stores it beside the device-local checkpoint in
the non-synchronizing Keychain. A device MUST interpret, resume, abandon, or
clean a shared intent only when it has the exact matching local anchor.

The publisher performs these steps in order:

1. observe a complete authenticated proof and capture its exact device-local
   checkpoint and ordered head set;
2. authenticate the candidate against those exact parents and reject any
   unresolved reconciliation result;
3. validate each new encrypted entry against the candidate context, digest,
   and current vault key;
4. verify every reused entry object at its existing immutable digest path and
   reject a candidate whose projected repository-wide object, history-depth,
   or aggregate-byte usage exceeds the reader's bounds;
5. prepare the device-local recovery anchor, exclusively create and
   synchronize the immutable shared intent, arm the local anchor, then create
   the staged entry and manifest files;
6. observe authenticated repository state and resource usage again and stop
   if either the
   checkpoint or head set changed;
7. move staged entries to their final digest paths with an atomic,
   no-overwrite rename and synchronize the affected directories;
8. reopen every candidate entry from its final path and revalidate its digest,
   canonical context, and repository limits;
9. move the candidate manifest to its final digest path with the same
   no-overwrite and synchronization rules, then reopen its exact bytes; and
10. replace the device-local checkpoint only when its prior canonical bytes
    still equal the captured checkpoint.

An existing destination is accepted only when it contains the exact requested
bytes. Content-addressed identical writes therefore converge, while any
different existing bytes fail closed. No `--force` policy may replace an
immutable object, skip authentication, bypass a conflict, or weaken the
expected-head check.

Staging may create private directories before the final head recheck. If that
recheck fails, no object is moved into the authoritative `entries` or
`manifests` layouts. A synchronized head that arrives after the recheck cannot
be atomically excluded by a provider-neutral filesystem protocol; because
publication is immutable, it creates another authenticated branch instead of
overwriting history.

### Transaction Recovery Intent

The canonical recovery intent has exactly these fields:

| Field | Type | Requirement |
|---|---|---|
| `format` | string | Exactly `key-vault-transaction-recovery` |
| `version` | integer | Exactly `1` |
| `operationID` | string | Canonical lowercase UUID matching its directory |
| `kind` | enum | Original add, edit, copy, move, or remove mutation |
| `vaultID` | UUID | Must match the checkpoint and candidate |
| `expectedCheckpoint` | checkpoint object | Exact canonical old checkpoint |
| `expectedHeads` | digest array | Nonempty, unique, ascending byte order |
| `candidateManifestDigest` | base64url | SHA-256 of exact candidate bytes |
| `stagedEntries` | entry reference array | Unique ascending entry ID and digest pairs |

Each staged entry reference contains exactly `entryID` and `digest`. The intent
MUST NOT contain a vault key, plaintext, timestamp, provider identifier,
device-local path, or mutable phase counter. It is durable evidence of what
the helper attempted, not authority to complete the attempt.

The canonical device-local recovery anchor has exactly these fields:

| Field | Type | Requirement |
|---|---|---|
| `format` | string | Exactly `key-vault-transaction-recovery-anchor` |
| `version` | integer | Exactly `1` |
| `operationID` | string | Canonical lowercase UUID |
| `vaultID` | UUID | Keychain account and shared intent must match |
| `intentDigest` | base64url | SHA-256 of exact canonical shared intent |
| `phase` | enum | Exactly `prepared` or `recoverable` |

`prepared` means the device reserved the operation but shared intent may not
have become durable; no staging or publication can have begun. `recoverable`
means the exact shared intent was durable before any staging began. Anchor
replacement and removal MUST use exact expected-value guards and MUST NOT use
Keychain synchronization.

Before another local mutation for the same vault can publish, recovery MUST
resolve the existing device-local anchor under the serialized mutation owner.
Recovery MUST:

1. load the canonical local anchor for the vault;
2. load a bounded canonical shared intent whose operation ID and digest match
   that anchor;
3. load and validate the exact device-local checkpoint;
4. reconstruct the recorded authenticated parent proof;
5. authenticate the candidate with its identified vault key and exact parents;
6. validate every staged or published entry against candidate context and
   digest;
7. derive the completed publication phase from staged objects, final immutable
   objects,
   and the checkpoint rather than trusting mutable journal state;
8. finish publication only if the old checkpoint and required repository state
   still satisfy the recorded expected values; and
9. validate and remove only exact known staged bytes, clear the local anchor
   once the transaction has a complete old or new outcome, and then remove the
   exact shared intent and empty transaction directories on a best-effort
   basis.

If a `prepared` local anchor's shared intent is unavailable, recovery MAY clear
the anchor and retain the complete old checkpoint because no staging could
have begun. If a `recoverable` anchor's shared intent is unavailable, recovery
MUST retain the anchor and report transport-unavailable.

If the candidate manifest is absent and authenticated intent proves required
staging is unavailable, recovery MAY abandon the attempt at the complete old
checkpoint. Already published entries remain harmless immutable orphans. If
the final candidate manifest or candidate checkpoint exists, unavailable
required content MUST be treated as transport-unavailable and retained for
later recovery.

If the checkpoint names another head, recovery MUST NOT replace it. The
candidate, if already published, remains an immutable branch for ordinary
reconciliation. Shared intents without this device's exact local anchor MUST
be ignored. They MUST NOT be selected or cleaned using UUID, directory order,
modification time, or provider metadata.

Cleanup MUST NOT delete an immutable entry or manifest. Once exact staged
content has been validated and the transaction has a complete old or new
outcome, the local anchor MAY clear before best-effort shared cleanup. An
operation directory without this device's exact local anchor has no recovery
authority and MUST be ignored; this permits safe synchronization and restart
with inert shared staging still present.

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
    "parents": [
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    ],
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
          "algorithm": "p256-ecies-x963-sha256-aes-gcm",
          "ciphertext": "AQIDBA"
        }
      ],
      "entries": []
    }
  },
  "authentication": {
    "algorithm": "HKDF-SHA256+HMAC-SHA256",
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

`HIST-402`, `KEY-403`, `HIST-404`, `STORE-405`, `MERGE-406`, `TXN-407`, the
core `TXN-408` recovery protocol, and the `UX-409` status/conflict contract
establish exact digest-based identities, safe multi-parent authentication,
bounded read-only discovery, deterministic logical reconciliation, and
restartable entry-first immutable publication with stable user-visible health
states. They deliberately do not define:

- release-environment protected-write and synchronized-provider validation;
- shipping-target activation of the v3 reader and conflict-resolution
  publisher; or
- physical migration execution beyond preflight.

Until those runtime and migration work packages land, version 3 artifacts
remain disabled as trusted production state.

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
