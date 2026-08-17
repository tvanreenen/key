# Version 3 Device-Wrapped Key Architecture

Status: selected permanent design during the `0.2.0` alpha series. The
`KEY-509` manifest, HPKE, one-device genesis, local cache, session unlock, and
durable content-publication runtime are implemented and connected to the
shipping helper. `ENR-510` first and later enrollment now use that permanent
profile and one key-rotating roster-addition transition. The signed alpha.7
Preview release physically qualified migration, wrapper-backed restart,
first-to-second-device enrollment, and a joining-device write on two Macs.
Alpha.8 added authenticated catch-up, revocation, equal enrolled-device
authority, and continuity guidance; alpha.9 clarified revoked-device handling.
Alpha.10 shipped and physically qualified restart-safe replacement
re-enrollment through the ordinary join journey on two Macs, including
cross-device catch-up, writes, cleanup, and helper restart.
Alpha.11 added destructive-step invitation revalidation and bounded,
same-command helper-restart recovery, then completed the practical local-APFS
and two-device iCloud beta provider qualifications.
Catastrophe recovery after every enrolled device is lost is explicitly
deferred beyond `0.2.0`.

This document defines the normative key-management model and on-disk profile
for version 3 vaults. It replaces the prerelease design in which the raw vault
key is stored
persistently in a local or synchronizable Keychain item. Implementation work
must preserve these invariants across context compaction, pull requests, and
release qualification.

## User Promise

Encrypted vault files may live in an ordinary folder-backed file provider. In
`0.2.0`, access belongs only to explicitly enrolled devices.

Local APFS and iCloud Drive are the directly qualified `0.2.0` storage targets.
The format and recovery protocol remain provider-neutral. Other ordinary
folder-backed providers may work when they preserve the required filesystem
semantics, but they have not been directly validated and are not covered by the
`0.2.0` compatibility guarantee. Every configured root must still pass Key's
containment, type, atomicity, hydration, and naming-safety checks.

Each enrolled Mac has equal authority backed by non-exportable Secure Enclave
keys. The current vault key is encrypted separately to every active device and
exists in plaintext only inside Key Agent's authenticated, short-lived memory
session. Adding or removing a device creates a new key epoch and a newly
encrypted current vault snapshot.

The file provider may delay, omit, replay, or fork bytes. It can deny service,
but it cannot silently grant access, choose trusted history, or authorize a
membership change.

## Product Model

There is one device-managed vault mode.

- A new vault begins with one active device.
- A one-device vault and a multi-device vault use the same manifest semantics.
- Every active device may authorize enrollment or revocation after the
  operation's explicit local-presence and confirmation checks.
- The permanent manifest has no owner/member role field. A device is active or
  revoked; status, not a hierarchy, determines its continuing authority.
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
  new Mac or re-enroll a revoked Mac with a new identity.
- `key share revoke` removes a selected device after explicit confirmation.
- `key lock` destroys the in-memory vault-key session.
- Key recommends at least two enrolled devices and identifies a one-device
  vault as at risk of permanent loss.

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
- bounded enrollment mailbox objects;
- transaction artifacts that carry no authority until authenticated
  publication completes.

Device names, public keys, revocation status, object sizes, and history
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

- ECDSA device authorization; and
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
is separately signed by an active device. Each wrapper is additionally bound
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

### Normative on-disk profile

The permanent manifest body is canonical JSON with `format`
`key-vault-manifest`, outer `version` `3`, `profile` `device-wrapped`, and
required `profileVersion` `2`. Its exact top-level fields are `format`,
`version`, `profile`, `profileVersion`, `vaultID`, `keyID`,
`authorityTransitionID`, `hpkeSuite`, `devices`, `wrappedKeys`, and `entries`.
The HPKE suite is base mode (`0`), P-256 (`16`), HKDF-SHA256 (`1`), and
AES-256-GCM (`2`).

Each device record contains exactly `deviceID`, `displayName`, `status`,
`signingPublicKey`, and `wrappingPublicKey`. Status is `active` or `revoked`;
there is no owner/member role. Each wrapper contains exactly
`recipientDeviceID`, the 65-byte P-256 `encapsulatedKey`, and the 48-byte HPKE
`ciphertext` containing a 32-byte vault key plus the AES-GCM tag. The wrapper
array covers every active device exactly once, in roster order, and contains
no revoked device or recovery recipient. The roster is nonempty, has at least
one active device, is ordered by device ID, and uses unique device IDs and
globally distinct valid P-256 public keys. Entries are ordered by name and
entry ID, have unique IDs and names, and all reference the manifest key ID.

The outer canonical JSON envelope has `format`
`key-vault-manifest-envelope`, `version` `3`, and exactly `content`,
`authentication`, and `authorizations` beside those discriminators. Content
contains the ordered unique SHA-256 parent digests and the manifest body.
Authentication is `HKDF-SHA256+HMAC-SHA256` with a 32-byte tag.
Authorizations are ordered by unique signer device ID and use canonical-low-S,
64-byte raw `P-256-ECDSA-SHA256` signatures.

The structural JSON Schemas in [`schemas`](schemas/) are part of this profile.
The shipping canonical codecs remain normative for constraints JSON Schema
cannot express, including canonical JSON encoding, UTF-8 ordering, key
validity and derivation, wrapper coverage, cross-field equality, and
canonical-low-S signatures. A schema-valid object that fails those checks is
not a valid Key manifest.

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
device-authorized key transition that covers the complete current snapshot.
Ordinary same-revision substitution remains a security error.

## Lifecycle

### Vault creation

1. Create this Mac's Secure Enclave signing and key-agreement keys.
2. Create a random vault ID, authority-transition ID, and vault key.
3. Build a one-device roster with this Mac active.
4. HPKE-wrap the vault key to this Mac.
5. Publish and authenticate the one-device genesis manifest.
6. Persist its exact checkpoint and local manifest cache.
7. Retain the raw vault key only in the current helper session.

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

1. Require one complete authenticated current head and an active local device.
2. Perform the existing invitation, signed request, device-name, and comparison
   ceremony.
3. Generate a new vault key and derive the authority-transition ID from the
   complete compared transcript.
4. Re-encrypt the complete current snapshot under the new key.
5. Preserve existing active devices and add exactly the compared identity.
6. HPKE-wrap the new key to every resulting active device.
7. Sign the complete transition with the inviting device's Secure Enclave key.
8. Publish entries first, the manifest last, and checkpoint under an expected
   old value.
9. Each existing device advances by authenticating the device-authorized
   transition and opening its new wrapper. The joining device establishes
   first trust through the compared ceremony and selects the vault last.

No device must be online during approval except the approving and joining
devices. Existing offline devices already have authenticated public wrapping
keys in the parent roster.

### Revocation

1. Show the exact device name, stable ID, and status.
2. Require explicit confirmation and one complete authenticated current head.
3. Refuse to revoke the last active device.
4. Generate a new key and re-encrypt the complete current snapshot.
5. Mark the selected device revoked and omit its wrapper.
6. Create wrappers only for remaining active devices.
7. Sign and publish the exact authority transition atomically.

Revocation is forward-looking. It cannot erase plaintext, old keys, historical
ciphertext, screenshots, clipboard contents, backups, or exports already held
by the revoked device.

### Offline catch-up and key transitions

The local checkpoint remains the bootstrap trust anchor. A returning device
opens its checkpoint wrapper, authenticates forward history under that key,
and processes each device-authorized key transition in order. At a transition
it verifies the parent-device signature before opening its addressed new
wrapper, then authenticates the candidate with the recovered key.

Missing transition objects or provider placeholders stop catch-up as
temporary-unavailable while preserving the last trusted checkpoint for
explicit stale reads. Invalid or substituted transition objects require
recovery. Key must never select an unauthenticated newest wrapper merely
because it appears latest in provider storage.

Competing key or membership transitions are security conflicts and are never
automatically merged. The permanent-profile catch-up implementation detects
content-only forks, pauses writes, preserves the local checkpoint for explicit
stale reads, and exposes entry-level inspection and explicit resolution for
resolvable content conflicts. Authority conflicts remain recovery-required and
cannot be resolved by selecting an entry value.

## Recovery

Continuity and catastrophe recovery are different capabilities.

When at least one enrolled device survives, it can revoke a lost identity,
rotate the vault key, and authorize a returning or replacement Mac as a new
identity. Key recommends at least two enrolled devices so ordinary device loss
does not strand the vault. A one-device vault remains valid but must be
presented as at risk.

`0.2.0` has no catastrophe-recovery authority. If every enrolled Secure Enclave
identity becomes unavailable, provider-backed vault files cannot be opened and
access is permanently lost. Provider storage contains ciphertext, not a usable
backup of device authority. Key offers no password, recovery code, cloud
escrow, support override, security question, or hidden Apple-account fallback.

This is an intentional release boundary rather than an incomplete hidden
feature. It is safer than adding a portable authority before its theft, loss,
and operational behavior has been physically qualified. The CLI and migration
cleanup UX must state the boundary plainly, especially when only one device
remains.

[Offline Recovery Models](offline-recovery-models.md) preserves the later
catastrophe-recovery candidates. Primary and backup PIV P-256 hardware keys are
the leading feasibility direction, with threshold shares retained as the
hardware-free alternative. Any later recovery profile requires its own
normative schema, compatibility decision, physical qualification, and security
review; it is not part of the stable `0.2.0` format promise.

## Required Failure Behavior

| Condition | Required outcome |
|---|---|
| Checkpoint manifest or required transition is missing | Temporary-unavailable; retain local trust |
| Cached manifest does not match the local checkpoint | Ignore the cache; require exact provider bytes |
| Provider bytes are malformed, substituted, or exceed limits | Recovery-required; release no plaintext |
| Recorded Secure Enclave identity is inaccessible | Re-enroll through a surviving device; if none survives, report permanent loss |
| Current authenticated roster marks this device revoked | Explicit revoked-device error; no unwrap attempt |
| Two key or membership transitions compete | Security conflict; no automatic merge or key choice |
| Rotation cannot decrypt every current entry | Abort before publishing new authority |
| Rotation is interrupted | Recover to the complete old or complete new checkpoint |
| Every enrolled device is lost | Permanent loss, stated without offering destructive repair or password recovery |

## Alpha Compatibility Policy

The currently released `0.2.0` alpha profile is not the permanent wire format.
It stores the raw vault key after enrollment, distinguishes local and shared
manifests, uses a custom wrapper construction, and retains a special first-peer
authorization convention.

The permanent profile intentionally breaks that prerelease behavior. The
role-free profile revision introduced during the alpha series is another
intentional break: manifests and enrollment transcripts that grant an
owner/member role are not valid role-free state.

- the role-free permanent profile and enrollment protocol use required version
  `2` discriminators;
- new binaries clearly refuse earlier role-bearing alpha state;
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
- [x] Create every vault with one active device and one durable HPKE wrapper.
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
- [x] Qualify the first-to-second-device ceremony and joining-device restart
  and write paths with the signed alpha.7 Preview release.
- [x] Cover third-and-later enrollment with dedicated multi-device transition
  and adoption tests. A third physical identity is useful opportunistic
  evidence, not a beta release gate.

### `ENR-511` — Revocation and rotation

- [x] Add explicit device revocation.
- [x] Rotate and re-encrypt the complete current snapshot.
- [x] Add authenticated remaining-device catch-up across ordered content and
  key epochs.
- [x] Distinguish provider delay, content divergence, and competing authority
  transitions without allowing stale writes.
- [x] Bring permanent-profile entry-level conflict inspection and resolution
  to parity with the existing version 3 UX.
- [x] Prove old-or-new crash recovery across every revocation publication
  phase.

### `AUTH-513` — Equal enrolled-device authority

- [x] Remove owner/member roles from the permanent manifest and enrollment
  transcript schemas.
- [x] Treat every active enrolled device as eligible to authorize enrollment
  and revocation; retain explicit local presence, comparison, and confirmation.
- [x] Require at least one active device and one exact current-key wrapper per
  active device.
- [x] Give the role-free schema required profile/protocol version `2` and
  clearly reject role-bearing alpha state rather than silently translating it.
- [x] Update catch-up, revocation, status, and CLI output to describe devices and
  statuses without implying a hierarchy.

### `REC-512` — Continuity UX and explicit permanent loss

- [x] Report whether a vault has one or multiple enrolled devices.
- [x] Recommend at least two devices without preventing one-device use.
- [x] Warn prominently before revocation leaves only one device.
- [x] Explain during migration cleanup that provider bytes alone cannot recover
  a device-wrapped vault.
- [x] Report permanent loss honestly when no enrolled Secure Enclave identity
  survives; offer no destructive repair or password fallback.
- [x] Ship continuity guidance and explicit permanent-loss behavior in
  alpha.8.

### `REP-514` — Revoked-device replacement re-enrollment

- [x] Require a surviving active device to revoke the old identity before the
  revoked Mac can replace its local enrollment state.
- [x] Bind explicit cleanup confirmation to the exact authenticated vault,
  revoked identity, checkpoint, and revocation authority.
- [x] Make local identity and checkpoint cleanup restart-safe without changing
  synchronized vault history.
- [x] Restrict the helper to cleanup while cleanup is pending, then to the
  ordinary enrollment ceremony until the new identity and checkpoint are
  usable.
- [x] Consume replacement authorization only after successful enrollment
  adoption.
- [x] Integrate replacement review and confirmation into `key share join`
  without exposing a separate replacement command or its bound confirmation
  token.
- [x] Revalidate the invitation and unchanged review immediately before local
  cleanup, then wait for helper termination before retrying enrollment.
- [x] Physically qualify revoke, cleanup, restart, re-enrollment, catch-up, and
  writes on multiple Macs before the next Preview release.

### Later recovery track — Catastrophe recovery

- Prototype two independent PIV P-256 hardware recovery keys on physical Macs.
- Prove safe provisioning, non-exportable key agreement, PIN and touch policy,
  restart, removal, replacement, and blocked-token behavior.
- Retain two-of-three shares as the hardware-free comparison.
- Select no permanent recovery schema or release number until feasibility and
  security review justify one.

Beta begins only after the permanent profile has completed realistic migration
and supported rollback, targeted replacement fault injection, scoped local
APFS and iCloud Drive qualification, device-continuity and permanent-loss
documentation, signing and notarization verification, and focused security
review gates.

## Permanent Acceptance Gates

- No raw v3 vault key persists outside an unlocked Key Agent session.
- Every vault has one authenticated device roster from genesis.
- Every active device has exactly one wrapper for the current key; revoked and
  unknown devices have none.
- Every membership change rotates the key and re-encrypts the complete current
  snapshot.
- The local checkpoint and digest-verified cache are the only routine unlock
  bootstrap; provider ordering and mutable pointers grant no trust.
- Ordinary content conflicts cannot become authority conflicts, and authority
  conflicts never auto-merge.
- Missing bytes remain availability failures; invalid bytes remain security
  failures; neither releases plaintext or changes local trust.
- A surviving device can authorize a replacement; provider bytes alone cannot.
- Loss of every enrolled device is permanent in `0.2.0` and is stated plainly.
- There is no implicit password, iCloud Keychain, Apple-account, support, or
  provider recovery path.
- The older alpha profile is never silently upgraded, interpreted, or written
  by the permanent implementation.
