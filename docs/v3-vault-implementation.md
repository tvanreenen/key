# Version 3 Vault Implementation Tracker

This is the durable execution record for the file-backed, multi-device vault.
It records only current decisions, work packages, acceptance gates, and PR
state.

## Current State

| Field | Value |
|---|---|
| Status | In progress |
| Production base | `main` at `542382f5516e292518486f85db9512c8c1bb662b` |
| Selected architecture | Authenticated, versioned transaction layer |
| Format specification | [Version 3 vault storage format](v3-vault-storage-format.md) |
| Canonical JSON module | [Intent, constraints, and extraction plan](json-canonicalization.md) |
| Current branch | `agent/open-vault-root-handle` |
| Current PR | Not opened |
| Next work | `FS-302`: resolve every child component relative to the trusted root with no-follow semantics |

Local-only mode remains the default. Multi-device sharing MUST remain
unavailable or explicitly experimental until every release gate below passes.

## Security And Durability Invariants

- [x] `INV-01` Only the correctly signed CLI or utility role can invoke its
  authorized helper operations.
- [ ] `INV-02` Enrollment authenticates both device keys, roles, vault ID,
  fresh nonces, and an independently compared transcript.
- [x] `INV-03` Membership, key epoch, wrapped keys, and committed entries form
  one authenticated state.
- [ ] `INV-04` Revocation rotates the vault key and removes future decrypt
  authority from the revoked device.
- [ ] `INV-05` Every entry authenticates vault ID, normalized name, type,
  format version, key epoch, and revision.
- [x] `INV-06` Replayed manifests and entries are detected explicitly.
- [ ] `INV-07` Concurrent mutations serialize or return a revision conflict.
- [ ] `INV-08` Recovery observes one complete old or new generation, never a
  mixed-key vault.
- [ ] `INV-09` Every filesystem effect remains beneath the opened vault root.
- [ ] `INV-10` Loss of all enrolled devices has an explicit recovery outcome.

## PR Sequence

### PR 1 — XPC Boundary

Status: complete; squash-merged as `6ef98bd` in PR #13.

- [x] Authenticate CLI, utility, and helper signing identities.
- [x] Separate full CLI authority from status/lock authority.
- [x] Prevent idle shutdown during active requests.
- [x] Use operation-aware request completion.
- [x] Validate intended and unintended installed clients.

### Version 3 Authenticated Storage

Status: `FMT-201` squash-merged as `f377093` in PR #14, `FMT-202`
squash-merged as `ff402b8` in PR #15, `FMT-203` squash-merged as `18cfb3e`
in PR #16, `FMT-204` squash-merged as `cceb783` in PR #17, `FMT-205`
squash-merged as `942e444` in PR #18, and `FMT-206` squash-merged as
`a390042` in PR #19, `FMT-207` squash-merged as `73775eb` in PR #20,
`FMT-208` squash-merged as `4ef1ffa` in PR #21, `FMT-209` squash-merged as
`9eaac88` in PR #22, and `FMT-210` squash-merged as `542382f` in PR #23.

- [x] `FMT-201` Specify canonical manifest-body and encrypted-entry schemas,
  encoding, ordering, normalization, and unknown-version behavior.
- [x] `FMT-202` Select the manifest authority and authenticated envelope.
- [x] `FMT-203` Authenticate the complete manifest body.
- [x] Isolate canonical JSON behind an internal module boundary with a
  documented path to independent publication.
- [x] `FMT-204` Define the typed entry associated-data context.
- [x] `FMT-205` Seal and open entries with that context as AES-GCM AAD.
- [x] `FMT-206` Make copy and rename decrypt-and-reseal operations.
- [x] `FMT-207` Detect manifest and entry replay.
- [x] `FMT-208` Reject inconsistent membership and wrapped-key state.
- [x] `FMT-209` Add read-only local-v2 migration preflight and rollback steps.
- [x] `FMT-210` Refuse unsupported prototype enclave metadata.

Acceptance gate:

- Cross-vault, name, type, generation, and revision substitution fails.
- Historical manifests or entries return explicit rollback/conflict errors.
- Unknown or inconsistent metadata fails closed.
- Migration never deletes the only readable generation.

### PR 3 — Root-Contained Filesystem

- [x] `FS-301` Open and retain a trusted vault-root directory handle.
- [ ] Resolve every component with no-follow semantics.
- [ ] Reject symlinks, aliases, root substitution, and provider collisions.
- [ ] Implement contained replace, move, and cleanup.
- [ ] Coordinate vault-root changes with the running helper.

### PR 4 — Transaction Engine

- [ ] Introduce one mutation owner with operation IDs.
- [ ] Require expected manifest generations and explicit conflicts.
- [ ] Stage immutable entries and the next manifest.
- [ ] Commit with one verified root-pointer transition.
- [ ] Persist recovery state before irreversible effects.
- [ ] Stream re-encryption and recover at every interruption phase.
- [ ] Resolve the shipping protected-write `EPERM` failures.

### PR 5 — Enrollment And Revocation

- [ ] Bind enrollment to both keys, roles, vault ID, nonces, and expiry.
- [ ] Derive and independently display a transcript authentication value.
- [ ] Reject replay, substitution, wrong-vault, and role confusion.
- [ ] Add device inspection and revoke/rotate commands.
- [ ] Re-encrypt for remaining devices after revocation.

### PR 6 — Recovery, CLI UX, And Release

- [ ] Decide and test the all-devices-lost policy.
- [ ] Add doctor, transaction, conflict, recovery, and device diagnostics.
- [ ] Add stable JSON output and machine-readable exit codes.
- [ ] Validate supported providers and realistic migration copies.
- [ ] Document the implemented security model and recovery limits.

## Decision Log

| ID | Status | Decision |
|---|---|---|
| `DEC-000` | Accepted | Use authenticated immutable generations and one serialized transaction owner. |
| `DEC-001` | Accepted | Require a derived-key HMAC on every manifest and a parent-owner Secure Enclave signature on authority-changing transitions. Use separate signing and wrapping keys. |
| `DEC-002` | Proposed | Reject silent multi-writer merge; use expected generations and explicit conflicts. |
| `DEC-003` | Open | Define recovery when every enrolled device is lost. |
| `DEC-004` | Open | Define supported providers and required atomic commit semantics. |
| `DEC-005` | Open | Make vault-root changes helper-owned or require a locked/restarted helper. |
| `DEC-006` | Accepted | Give the CLI full authority and the utility status/lock authority on separate authenticated endpoints. |
| `DEC-007` | Accepted | Keep the signed nested helper, constrain launchd spawning, and re-register it on app upgrades. |
| `DEC-008` | Accepted | Keep canonical JSON independent of vault schemas in an internal SwiftPM target; do not claim or publish full RFC 8785 conformance until complete number handling, upstream vectors, fuzzing, and independent review are complete. |
| `DEC-009` | Accepted | Authenticate v3 entry identity as the entry-AAD domain label, a NUL delimiter, and canonical JSON over format, version, vault ID, entry ID, name, type, key epoch, and revision. Derive those values from authenticated manifest state when opening. |
| `DEC-010` | Accepted | Keep v3 entry parsing explicitly untrusted. Before releasing plaintext, require the authenticated manifest digest and manifest-derived context to match the canonical file, then open AES-256-GCM with the exact typed associated data and require UTF-8 plaintext. |
| `DEC-011` | Accepted | Implement v3 copy and rename as authenticated decrypt-and-reseal operations. Copy creates a fresh logical entry at revision 1; rename preserves the logical entry ID and advances its revision. Both preserve exact valid UTF-8 plaintext bytes, type, and key epoch and require a fresh nonce. |
| `DEC-012` | Accepted | Treat authentication and freshness as separate gates. Persist one exact vault ID, generation, and manifest-envelope digest in the non-synchronizing device-local Keychain; advance it under the serialized helper mutation owner with an expected-checkpoint guard only after verifying the exact child transition. Require the freshness-approved manifest type for entry open, copy, and rename. |
| `DEC-013` | Accepted | Keep local manifests free of device-membership and wrapped-key records. Require shared manifests to retain at least one active owner and exactly one current-epoch wrapped key for every active device, with no wrapper for a revoked or unknown device. Defer membership-transition ceremonies to enrollment and revocation work. |
| `DEC-014` | Accepted | Make migration opt-in. Ship `key migrate --check` as a helper-owned, read-only v2 compatibility and decryptability check. A later writer must stage and verify v3 beside the untouched v2 source, commit only through the transaction root pointer, and retain v2 until verified reopen and explicit cleanup. |
| `DEC-015` | Accepted | Treat the unreleased prototype as a migration exclusion, not a permanent runtime compatibility mode. `key migrate --check` refuses the exact root-level `.key-vault.json` marker before loading a key, while ordinary v2 reads remain unchanged and the strict v3 parser rejects prototype JSON. |
| `DEC-016` | Accepted | Establish vault-root authority by opening the configured file URL once through Swift System's `FileDescriptor` with directory-only, no-follow, and close-on-exec semantics. Retain that descriptor and its device/inode identity for the lifetime of the filesystem session; later contained operations must resolve relative to the descriptor instead of trusting the configured path again. |

## Validation Matrix

- [x] Canonical manifest and entry-context encoding tests.
- [x] Negative authentication tests for every bound field.
- [x] Copy/rename identity, revision, collision, and exact-byte resealing tests.
- [x] Manifest generation/digest and entry revision replay tests.
- [x] Local/shared membership and current-epoch wrapped-key consistency tests.
- [x] V2 migration-preflight compatibility, decryptability, and no-write tests.
- [x] Prototype migration-marker and v3 parser rejection tests.
- [x] Trusted vault-root type, no-follow open, retained-identity, and close-on-exec tests.
- [ ] Enrollment and key-epoch replay tests.
- [x] Installed XPC tests for intended and unintended signing identities.
- [ ] Mutation/key-transition concurrency tests.
- [ ] Transaction fault injection at every phase.
- [ ] Filesystem containment and provider-placeholder tests.
- [ ] Local-v2 migration and rollback tests.
- [ ] Revocation tests with retained old keys.
- [ ] Recovery tests for missing devices and corrupt or conflicting state.

## Release Gates

- [ ] All ten invariants pass.
- [ ] The v3 reader ships before any v3 writer is enabled.
- [ ] Local APFS and every supported sync provider pass commit/conflict tests.
- [ ] Protected writes pass in the release environment.
- [ ] Migration and rollback pass with realistic vault copies.
- [ ] Recovery limitations are visible in CLI help and documentation.
- [ ] An independent security review signs off on identity, enrollment,
  authentication, revocation, and recovery.
- [ ] Signing, notarization, and installed-helper verification pass.

## Immediate Next Action

Implement `FS-302`: resolve each relative child component from the trusted
vault-root descriptor with no-follow semantics.
