# Version 3 Vault Implementation Tracker

This is the durable execution record for the file-backed, multi-device vault.
It records only current decisions, work packages, acceptance gates, and PR
state.

## Current State

| Field | Value |
|---|---|
| Status | In progress |
| Production base | `main` at `f377093a3ca7808def7a42aea753c901398eb1ce` |
| Selected architecture | Authenticated, versioned transaction layer |
| Format specification | [Version 3 vault storage format](v3-vault-storage-format.md) |
| Current branch | `agent/define-v3-manifest-authority` |
| Current PR | Not opened |
| Next work | `FMT-203`: implement complete manifest authentication |

Local-only mode remains the default. Multi-device sharing MUST remain
unavailable or explicitly experimental until every release gate below passes.

## Security And Durability Invariants

- [x] `INV-01` Only the correctly signed CLI or utility role can invoke its
  authorized helper operations.
- [ ] `INV-02` Enrollment authenticates both device keys, roles, vault ID,
  fresh nonces, and an independently compared transcript.
- [ ] `INV-03` Membership, key epoch, wrapped keys, and committed entries form
  one authenticated state.
- [ ] `INV-04` Revocation rotates the vault key and removes future decrypt
  authority from the revoked device.
- [ ] `INV-05` Every entry authenticates vault ID, normalized name, type,
  format version, key epoch, and revision.
- [ ] `INV-06` Replayed manifests and entries are detected explicitly.
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

Status: `FMT-201` squash-merged as `f377093` in PR #14; authority
specification continues on `agent/define-v3-manifest-authority`.

- [x] `FMT-201` Specify canonical manifest-body and encrypted-entry schemas,
  encoding, ordering, normalization, and unknown-version behavior.
- [x] `FMT-202` Select the manifest authority and authenticated envelope.
- [ ] `FMT-203` Authenticate the complete manifest body.
- [ ] `FMT-204` Define the typed entry associated-data context.
- [ ] `FMT-205` Seal and open entries with that context as AES-GCM AAD.
- [ ] `FMT-206` Make copy and rename decrypt-and-reseal operations.
- [ ] `FMT-207` Detect manifest and entry replay.
- [ ] `FMT-208` Reject inconsistent membership and wrapped-key state.
- [ ] `FMT-209` Add read-only local-v2 migration preflight and rollback steps.
- [ ] `FMT-210` Refuse unsupported prototype enclave metadata.

Acceptance gate:

- Cross-vault, name, type, generation, and revision substitution fails.
- Historical manifests or entries return explicit rollback/conflict errors.
- Unknown or inconsistent metadata fails closed.
- Migration never deletes the only readable generation.

### PR 3 — Root-Contained Filesystem

- [ ] Open and retain a trusted vault-root directory handle.
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

## Validation Matrix

- [ ] Canonical manifest and entry-context encoding tests.
- [ ] Negative authentication tests for every bound field.
- [ ] Manifest, entry, enrollment, and key-epoch replay tests.
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

Implement `FMT-203`: canonical envelope parsing, HKDF-SHA256 key derivation,
HMAC-SHA-256 verification, owner-signature verification, and negative tests for
every authenticated manifest field. Do not enable a production v3 writer.
