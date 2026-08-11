# Version 3 Device-Wrapped Key Architecture

Status: selected permanent design during the `0.2.0` alpha series. The
`KEY-509` manifest, HPKE, one-device genesis, local cache, session unlock, and
durable content-publication runtime are implemented and connected to the
shipping helper. `ENR-510` first and later enrollment now use that permanent
profile and one key-rotating roster-addition transition. The signed alpha.7
Preview release physically qualified migration, wrapper-backed restart,
owner-to-second-device enrollment, and a joining-device write on two Macs.
Authenticated remaining-device catch-up is implemented for the next Preview
build. Revocation, recovery, physical catch-up qualification, and final review
remain pending.

This document defines the intended final key-management model for version 3
vaults. It replaces the prerelease design in which the raw vault key is stored
persistently in a local or synchronizable Keychain item. Implementation work
must preserve these invariants across context compaction, pull requests, and
release qualification.

## User Promise

Encrypted vault files may live in any ordinary file provider. Access belongs
only to explicitly enrolled devices and, when configured, one offline recovery
kit.

Each enrolled Mac owns non-exportable Secure Enclave keys. The current vault
key is encrypted separately to every active device and exists in plaintext only
inside Key Agent's authenticated, short-lived memory session. Adding or
removing a device creates a new key epoch and a newly encrypted current vault
snapshot.

The file provider may delay, omit, replay, or fork bytes. It can deny service,
but it cannot silently grant access, choose trusted history, or authorize a
membership change.

## Product Model

There is one device-managed vault mode.

- A new vault begins with one active owner device.
- A one-device vault and a multi-device vault use the same manifest semantics.
- The second, third, and later enrollments use the same roster-addition
  transition.
- There is no permanent local-to-shared exception or separate signature
  convention.
- Exact parent digests establish history order. The format does not use a
  global generation counter.

The ordinary CLI remains small:

- `key unlock` or the first key-backed command opens a local device wrapper.
- `key share devices` shows the authenticated roster and this Mac.
- `key share invite`, `join`, `compare`, `approve`, and `accept` enroll a
  device.
- `key share revoke` removes a selected device after explicit confirmation.
- `key lock` destroys the in-memory vault-key session.
- Recovery uses one explicit offline recovery-kit flow.

## Trust And Storage Boundaries

### Device-local trusted state

Key Agent owns the following non-synchronizing state on each Mac:

- a Secure Enclave P-256 signing key;
- a Secure Enclave P-256 key-agreement key;
- the canonical public device-identity record;
- the exact trusted vault ID and manifest-envelope digest;
- a cached copy of the exact checkpoint manifest; and
- bounded ceremony, transaction, and recovery state.

The Secure Enclave key representations and checkpoint remain protected by the
data-protection Keychain with a `ThisDeviceOnly` accessibility class. The
checkpoint-manifest cache may live in Key-owned Application Support storage
because it contains no plaintext secret; its bytes gain authority only when
their SHA-256 digest matches the device-local checkpoint.

The raw vault key is never stored in Keychain, configuration, Application
Support, the provider-backed vault, logs, crash-recovery state, or enrollment
state.

### Provider-backed untrusted state

The vault root contains only immutable, content-addressed objects:

- canonical authenticated manifests;
- encrypted entry objects;
- one current-key wrapper for every active device;
- one recovery wrapper when recovery is enabled;
- bounded enrollment mailbox objects;
- the encrypted recovery-identity object; and
- transaction artifacts that carry no authority until authenticated
  publication completes.

Device names, roles, public keys, revocation status, object sizes, and history
shape are metadata, not secret plaintext.

### Session state

After user presence and successful wrapper opening, Key Agent retains the
current 32-byte vault key only in its in-process session. The session is
destroyed on explicit lock, idle expiry, helper restart, runtime selection
change, or process termination.

Code executing inside the authenticated helper while the session is unlocked
can use the vault key. This design does not claim protection from a fully
compromised helper during an unlocked session.

## Cryptographic Profile

### Device identity

Every device has separate Secure Enclave P-256 keys for:

- ECDSA owner authorization; and
- ECDH/HPKE vault-key unwrapping.

Private keys are generated on the device and are never exportable. Public keys
and the stable device ID derived from them are authenticated manifest fields.

Apple documents Secure Enclave P-256 signing and key agreement through the
Security framework and CryptoKit:

- [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [`SecureEnclave.P256.KeyAgreement.PrivateKey`](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/keyagreement/privatekey)

### Per-device vault-key wrappers

Wrappers use HPKE as specified by
[RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) through
[CryptoKit HPKE](https://developer.apple.com/documentation/cryptokit/hpke).
The intended suite is P-256, HKDF-SHA256, and AES-GCM.

CryptoKit exposes HPKE and makes
`SecureEnclave.P256.KeyAgreement.PrivateKey` conform to its HPKE private-key
protocol beginning in macOS 14. The permanent profile therefore raises Key's
minimum deployment target from macOS 13 to macOS 14. Do not retain or add a
parallel custom ECIES implementation or availability fallback.

HPKE base mode is sufficient because the complete authority-changing manifest
is separately signed by an active owner. Each wrapper is additionally bound
through HPKE `info` and authenticated data to a canonical context containing:

- wrapper format and version;
- vault ID;
- exact vault-key ID;
- authenticated authority-transition ID;
- recipient device ID; and
- selected HPKE suite.

The authority-transition ID is identity, not a freshness counter. Genesis uses
a random value. Enrollment derives it deterministically from the complete
comparison transcript so that every wrapper and the signed transition are
bound to that exact ceremony. The wrapper context remains self-contained in
permanent manifest state and does not depend on temporary mailbox state.

### Vault and entry encryption

Each key epoch has one random 256-bit vault key. Domain-separated derivatives
authenticate manifests and seal entries with AES-256-GCM using the existing
typed entry associated data.

Every membership change creates a new random key and re-encrypts the complete
current entry snapshot:

- a newly enrolled device receives current values but not prior key epochs;
- a revoked device retains any past material it already possessed but cannot
  decrypt the new current snapshot or future changes; and
- unchanged historical objects remain immutable and are never presented as
  erased history.

A pure key rotation preserves each entry's logical ID, name, type, and content
revision while changing its key ID, nonce, ciphertext, and ciphertext digest.
The manifest verifier permits this same-revision reseal only inside an exact
owner-authorized key transition that covers the complete current snapshot.
Ordinary same-revision substitution remains a security error.

## Lifecycle

### Vault creation

1. Create this Mac's Secure Enclave signing and key-agreement keys.
2. Create a random vault ID, authority-transition ID, and vault key.
3. Build a one-device roster with this Mac as active owner.
4. HPKE-wrap the vault key to this Mac.
5. Optionally create the offline recovery identity and recovery wrapper.
6. Publish and authenticate the one-device genesis manifest.
7. Persist its exact checkpoint and local manifest cache.
8. Retain the raw vault key only in the current helper session.

### Routine unlock

1. Load the device-local checkpoint and recorded device identity.
2. Open the cached checkpoint manifest, or the exact provider object if the
   cache is absent.
3. Require its SHA-256 digest and vault ID to match the checkpoint.
4. Parse only enough canonical structure to find this device's wrapper.
5. Ask the Secure Enclave to open the wrapper after user presence.
6. Derive and require the exact authenticated vault-key ID.
7. Authenticate the complete manifest HMAC, semantics, and wrapper coverage.
8. Enter the bounded in-memory session.

Missing provider bytes are temporary-unavailable. A digest mismatch, invalid
wrapper, wrong key ID, missing active-device wrapper, or inaccessible recorded
identity is recovery-required. A manifest that authentically records this
device as revoked returns an explicit revoked-device outcome and never asks the
Secure Enclave to open unrelated wrappers.

### Ordinary reads and writes

Reads retain the current exact-manifest planning and revalidation gates.
Ordinary content mutations preserve the key epoch and authenticated authority.
They may branch and use the existing content reconciliation rules.

### Enrollment

1. Require one complete authenticated current head and an active local owner.
2. Perform the existing invitation, signed request, device-name, and comparison
   ceremony.
3. Generate a new vault key and derive the authority-transition ID from the
   complete compared transcript.
4. Re-encrypt the complete current snapshot under the new key.
5. Preserve existing active devices and add exactly the compared identity.
6. HPKE-wrap the new key to every resulting active device and the recovery
   identity, if present.
7. Sign the complete transition with the inviting owner's Secure Enclave key.
8. Publish entries first, the manifest last, and checkpoint under an expected
   old value.
9. Each existing device advances by authenticating the owner transition and
   opening its new wrapper. The joining device establishes first trust through
   the compared ceremony and selects the vault last.

No device must be online during approval except the approving owner and joining
device. Existing offline devices already have authenticated public wrapping
keys in the parent roster.

### Revocation

1. Show the exact device name, stable ID, role, and status.
2. Require explicit confirmation and one complete authenticated current head.
3. Refuse to revoke the last active owner unless recovery is immediately
   establishing a replacement owner.
4. Generate a new key and re-encrypt the complete current snapshot.
5. Mark the selected device revoked and omit its wrapper.
6. Create wrappers only for remaining active devices and recovery.
7. Sign and publish the exact authority transition atomically.

Revocation is forward-looking. It cannot erase plaintext, old keys, historical
ciphertext, screenshots, clipboard contents, backups, or exports already held
by the revoked device.

### Offline catch-up and key transitions

The local checkpoint remains the bootstrap trust anchor. A returning device
opens its checkpoint wrapper, authenticates forward history under that key,
and processes each owner-authorized key transition in order. At a transition it
verifies the parent-owner signature before opening its addressed new wrapper,
then authenticates the candidate with the recovered key.

Missing transition objects or provider placeholders stop catch-up as
temporary-unavailable while preserving the last trusted checkpoint for
explicit stale reads. Invalid or substituted transition objects require
recovery. Key must never select an unauthenticated newest wrapper merely
because it appears latest in provider storage.

Competing key or membership transitions are security conflicts and are never
automatically merged. The current permanent-profile catch-up implementation
detects content-only forks, pauses writes, and preserves the local checkpoint
for explicit stale reads. It does not yet expose entry-level conflict
inspection or resolution; parity with the existing reconciliation UX remains
a full-release requirement.

## Recovery

There is one optional, strongly recommended recovery mechanism: an offline
recovery kit.

At creation, Key generates a software recovery signing/key-agreement identity.
Its public identity is authenticated as a special recovery authority. Its
private material is encrypted under a random 256-bit recovery secret, and only
the encrypted object is stored with the vault. The recovery secret is rendered
as a checksummed printable/saveable code and is never stored by Key.

Every key epoch includes one HPKE wrapper for the recovery public key. Recovery
requires both the provider-backed vault and the offline recovery code.

A successful recovery:

1. decrypts the recovery identity locally;
2. opens the current recovery wrapper;
3. enrolls a new Secure Enclave owner;
4. rotates the vault key and revokes lost devices;
5. replaces the recovery identity; and
6. issues a new recovery code.

Recovery authorization is limited to this replacement transition. It is not an
ordinary device session. Possession of the recovery code and vault files is
equivalent to ownership of the vault and must be documented plainly.

The user may explicitly decline or remove recovery only after confirming that
loss of every active owner permanently destroys access. Key offers no cloud
escrow, support override, security question, or hidden Apple-account fallback.

The recovery identity proves authenticity and decryptability, not freshness
after every device-local checkpoint has been lost. A provider that withholds
newer valid objects can present an older authentic recovery state, and no
provider-neutral offline secret can distinguish that omission without a newer
external receipt. Recovery must therefore enumerate all available
authenticated heads, refuse ambiguity, identify the recovered head digest to
the user, and state that it is the newest complete state currently available,
not a cryptographic proof that no later state ever existed. Retained backups
or a separately saved recent checkpoint receipt provide additional rollback
evidence without becoming required online infrastructure.

## Required Failure Behavior

| Condition | Required outcome |
|---|---|
| Checkpoint manifest or required transition is missing | Temporary-unavailable; retain local trust |
| Cached manifest does not match the local checkpoint | Ignore the cache; require exact provider bytes or recovery |
| Provider bytes are malformed, substituted, or exceed limits | Recovery-required; release no plaintext |
| Recorded Secure Enclave identity is inaccessible | Recovery-required; re-enroll through an owner or recovery kit |
| Current authenticated roster marks this device revoked | Explicit revoked-device error; no unwrap attempt |
| Two key or membership transitions compete | Security conflict; no automatic merge or key choice |
| Rotation cannot decrypt every current entry | Abort before publishing new authority |
| Rotation is interrupted | Recover to the complete old or complete new checkpoint |
| Every owner is lost and no recovery kit exists | Permanent loss, stated without offering destructive repair |
| Recovery code is wrong or recovery object is substituted | Fail before installing a key, identity, or checkpoint |
| Recovery has no surviving recent checkpoint | Recover only one complete authenticated available head and disclose that provider omission cannot be ruled out |

## Alpha Compatibility Policy

The currently released `0.2.0` alpha profile is not the permanent wire format.
It stores the raw vault key after enrollment, distinguishes local and shared
manifests, uses a custom wrapper construction, and retains a special first-peer
authorization convention.

The permanent profile intentionally breaks that prerelease behavior:

- new binaries recognize and clearly refuse the old alpha profile;
- old binaries reject the permanent profile through strict required fields;
- no indefinite dual reader/writer or cryptographic fallback is retained;
- retained v2 files may be remigrated where available; and
- existing alpha-only shared vaults require an explicit reset/remigration and
  device re-enrollment.

The permanent profile must have an explicit required profile/version marker so
no implementation can interpret old and new bytes as the same format. The
product may continue to call the completed system version 3 because the prior
profile was never stable, but the on-disk discriminator must be unambiguous.

## Implementation Sequence

### `ARCH-508` — Permanent key architecture

- Commit this decision and update the implementation tracker.
- Raise the minimum deployment target to macOS 14 when implementation begins.
- Fix the required trust, wrapper, cache, recovery, and compatibility
  boundaries before changing the prerelease format.

### `KEY-509` — Device-wrapped genesis and session unlock

- [x] Specify and validate the exact permanent manifest, wrapper, and
  local-cache schemas before enabling a permanent-profile writer.
- [x] Create every vault with one owner and one durable HPKE wrapper.
- [x] Add the exact local checkpoint-manifest cache.
- [x] Open wrappers into helper memory and remove persistent raw v3 vault-key
  storage.
- [x] Connect explicit migration, reads, and ordinary content writes to the
  shipping helper without falling through to version 2 storage.
- [x] Detect and refuse the older alpha profile with actionable recovery
  guidance.
- [x] Qualify lock, helper restart, and the installed permanent runtime on two
  physical Macs with the signed alpha.7 Preview release.

### `ENR-510` — Unified enrollment and key epochs

- [x] Make first and later enrollment use one roster-addition transition.
- [x] Rotate the key and re-encrypt the current snapshot when adding a device.
- [x] Bind the signed transition and every wrapper to the complete compared
  transcript.
- [x] Remove the local-to-shared exception and legacy wrapper implementation.
- [x] Qualify the owner-to-second-device ceremony and joining-device restart
  and write paths with the signed alpha.7 Preview release.
- [ ] Qualify a third-device ceremony before beta; it uses the same transition
  but requires another physical identity or a completed revocation/re-enrollment
  path.

### `ENR-511` — Revocation and rotation

- [ ] Add explicit device revocation.
- [ ] Rotate and re-encrypt the complete current snapshot.
- [x] Add authenticated remaining-device catch-up across ordered content and
  key epochs.
- [x] Distinguish provider delay, content divergence, and competing authority
  transitions without allowing stale writes.
- [ ] Bring permanent-profile entry-level conflict inspection and resolution
  to parity with the existing version 3 UX.
- [ ] Prove old-or-new crash recovery across every revocation publication
  phase.

### `REC-512` — Offline recovery and final qualification

- Specify and validate the exact encrypted recovery-object and printable-kit
  schemas before enabling recovery-kit creation.
- Implement the single recovery-kit flow and recovery-authorized replacement.
- Exercise loss, reinstall, provider delay, stale history, concurrent rotation,
  and recovery-code compromise scenarios.
- Release alpha.8 only after enrollment, revocation, recovery, and restart tests
  pass on multiple physical Macs.

Beta begins only after the permanent profile has completed realistic provider,
migration, rollback, destructive-device-loss, signing, notarization, and
independent security review gates.

## Permanent Acceptance Gates

- No raw v3 vault key persists outside an unlocked Key Agent session.
- Every vault has one authenticated device roster from genesis.
- Every active device and optional recovery identity has exactly one wrapper
  for the current key; revoked and unknown devices have none.
- Every membership change rotates the key and re-encrypts the complete current
  snapshot.
- The local checkpoint and digest-verified cache are the only routine unlock
  bootstrap; provider ordering and mutable pointers grant no trust.
- Ordinary content conflicts cannot become authority conflicts, and authority
  conflicts never auto-merge.
- Missing bytes remain availability failures; invalid bytes remain security
  failures; neither releases plaintext or changes local trust.
- Recovery is either the one explicit offline kit or permanent loss. There is
  no implicit iCloud Keychain or Apple-account recovery path.
- Catastrophic recovery without a surviving checkpoint proves authenticity,
  not global freshness; the CLI states that limitation and exact recovered
  head plainly.
- The older alpha profile is never silently upgraded, interpreted, or written
  by the permanent implementation.
