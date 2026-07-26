# Enclave Vault Security Implementation Tracker

This file is the durable execution record for turning the enclave-sharing
prototype into a production-quality, file-backed multi-device vault. Update it
in every related pull request so the work remains understandable across
branches, commits, reviewers, and context-window compaction.

## Plan Identity

| Field | Value |
|---|---|
| Plan ID | `KEY-ENCLAVE-V3` |
| Status | In progress |
| Selected design | Versioned transaction layer |
| Prototype branch | `bugfix/icloud-keychain-publish` |
| Reviewed prototype revision | `84e7ddb79141d8f1665f3c1bf2e4254677a988a2` |
| Base revision | `22b226d41ac9d2c92e46b7debf4c4824e0154a49` |
| Security review | [Report](../report.md) |
| Architecture proposal | [Authenticated vault state machine](../hardening/proposals/authenticated-vault-state-machine.md) |
| Last updated | 2026-07-26 |

## How To Use This Tracker

- Reference stable work-package IDs such as `XPC-102` and `TXN-304` in PR
  descriptions and, when useful, commit bodies.
- Check an item only after its acceptance criteria pass on the branch that will
  merge. A prototype or partial implementation does not count as complete.
- At the end of every PR, update the PR ledger, decision log, test evidence, and
  first remaining blocker.
- If the design changes, add a decision-log entry rather than silently
  rewriting history.
- To resume after context compaction: read this file, inspect `git status` and
  the PR ledger, then continue from the first unchecked blocking work package.

## Product Decision

The existing branch is retained as a reviewed prototype and source of reusable
code. It should not merge as the production enclave-sharing implementation.
The production work will be ported into a reviewable PR stack based on `main`.

Local-only mode remains the default throughout the stack. Enclave sharing must
remain unavailable or explicitly experimental until all release gates in this
file pass.

## Security And Durability Invariants

- [ ] `INV-01` Only an authorized, correctly signed Key client can invoke the
  helper's vault authority.
- [ ] `INV-02` Enrollment authenticates both device keys, their roles, the
  target vault, fresh nonces, and one independently compared transcript.
- [ ] `INV-03` Active membership, key epoch, wrapped keys, entry generation,
  and configuration belong to one authenticated committed state.
- [ ] `INV-04` Revoking a device rotates the vault key and prevents the old key
  from decrypting every future entry.
- [ ] `INV-05` Every entry authenticates its vault ID, normalized logical name,
  semantic type, format version, key generation, and entry revision.
- [ ] `INV-06` A historical manifest or entry cannot silently replace the
  current state.
- [ ] `INV-07` Concurrent mutations are serialized or rejected as explicit
  revision conflicts; they cannot silently overwrite or strand data.
- [ ] `INV-08` A crash, logout, timeout, or power loss observes the complete old
  generation or a complete new generation, never a mixed-key vault.
- [ ] `INV-09` Every filesystem side effect is proven to remain under the
  selected vault root at the actual operation.
- [ ] `INV-10` Losing all enrolled devices has an explicit, tested product
  outcome: supported recovery or a prominent declaration that recovery is
  impossible.

## Current Prototype Disposition

### Preserve And Port

- Secure Enclave device-key creation and public-key wrapping primitives.
- Keychain access-group and user-presence configuration.
- `SessionVaultKeyStore` session semantics, after reviewing its new transaction
  boundary.
- CLI command vocabulary and the useful parser/application tests.
- Vault-location resolution and conservative local-only initialization.
- Release signing and notarization verification.

### Refactor Before Porting

- Split `VaultKeyStore` into device identity, manifest verification, enrollment,
  key wrapping, and transaction responsibilities.
- Make helper configuration and vault-root changes helper-owned or explicitly
  restart-coordinated.
- Move mutation serialization out of scattered queues into one vault mutation
  owner.
- Turn status and sync output into truthful state observations rather than
  metadata-presence checks.

### Replace

- Enrollment codes supplied by the joining peer.
- Unauthenticated version-1 enclave metadata.
- Device leave without key rotation.
- In-place `unshare` re-encryption and catch-only rollback.
- Lexical-only path containment.
- Unauthenticated entry identity and revision.

The prototype enclave metadata format is not a compatibility target. The branch
has not shipped from `main`, so production code should detect and refuse that
format with a clear development-migration message rather than silently adopt
its security semantics.

Existing local-only entry data is a compatibility target. Its migration must be
explicit, verified, and recoverable.

## PR Stack

The sequence below is intentionally dependency ordered. A PR may be split
further, but later work must not bypass the acceptance gates of an earlier
boundary.

### PR 0 — Preserve The Review And Prototype

**Purpose:** Make the security decision and reviewed source identity durable.

- [x] `DOC-001` Commit the review bundle and this implementation tracker with no
  unrelated source changes.
- [x] `DOC-002` Mark the existing enclave-sharing PR as draft/prototype and link
  this tracker from its description.
- [x] `DOC-003` Preserve the prototype branch until every reusable component has
  either been ported or explicitly rejected.
- [x] `DOC-004` Record the replacement PR links in the ledger below.

**Acceptance gate:** A future contributor can identify the reviewed revision,
why it is not merge-ready, the selected design, and the next PR without relying
on chat history.

### PR 1 — Authenticate And Test The Helper Boundary

**Purpose:** Remove ambient access to cached vault authority before expanding
the protocol.

- [x] `XPC-101` Make the LaunchAgent helper buildable and testable in CI,
  including its listener and lifecycle behavior.
- [x] `XPC-102` Enforce the expected client code-signing requirement before
  accepting or resuming an XPC connection.
- [x] `XPC-103` Derive authorization from the connection audit identity and fail
  closed for ad-hoc, wrong-team, wrong-bundle, and malformed clients.
- [x] `XPC-104` Separate or explicitly authorize read, ordinary mutation,
  enrollment, and destructive migration capabilities.
- [x] `XPC-105` Track active requests so the idle timer cannot terminate a
  mutation in progress.
- [x] `XPC-106` Replace the universal client timeout with operation-aware
  completion, cancellation, or idempotent status lookup.
- [ ] `XPC-107` Add installed helper integration tests for cold and warm key
  sessions.

**Acceptance gate:**

- The intended signed CLI succeeds.
- Unauthorized clients are rejected before request decoding or handler access.
- An active request cannot be terminated as idle.
- The helper target is built and exercised by release CI.

**Findings addressed:** `CAND-001`; prerequisite containment for `CAND-011`.

### PR 2 — Introduce Version-3 Authenticated Storage

**Purpose:** Give files a verifiable identity and define one authenticated
current vault state before changing lifecycle operations.

- [ ] `FMT-201` Specify the canonical version-3 manifest and entry schemas,
  including encoding rules and unknown-field/version behavior.
- [ ] `FMT-202` Decide and document the manifest authority model in `DEC-001`.
- [ ] `FMT-203` Authenticate manifest vault ID, mode, generation, key epoch,
  membership, wrapped keys, and committed entry revisions.
- [ ] `FMT-204` Define a typed entry encryption context containing vault ID,
  normalized name, type, format version, key generation, and entry revision.
- [ ] `FMT-205` Use the canonical context as AES-GCM associated data on seal and
  open.
- [ ] `FMT-206` Make copy and rename explicit decrypt-and-reseal operations
  rather than ciphertext relocation.
- [ ] `FMT-207` Detect replayed manifests and entries against an authenticated
  current generation.
- [ ] `FMT-208` Reject inconsistent membership and wrapped-key records.
- [ ] `FMT-209` Implement a read-only local-v2 to v3 migration preflight with
  complete backup and rollback instructions.
- [ ] `FMT-210` Refuse prototype enclave metadata instead of treating it as a
  supported production format.

**Acceptance gate:**

- Swapping entries across names, types, vaults, or generations fails
  authentication.
- Replaying an older entry or manifest produces an explicit rollback/conflict
  state.
- Unsupported or inconsistent metadata fails closed.
- Local-v2 migration never deletes the only readable generation.

**Findings addressed:** `CAND-004`, `CAND-005`, and `CAND-006`.

### PR 3 — Add Root-Contained Filesystem Capabilities

**Purpose:** Ensure synchronized or local filesystem content cannot redirect
vault operations outside the selected root.

- [ ] `FS-301` Represent the opened vault root with a trusted directory handle,
  not only a path string.
- [ ] `FS-302` Resolve and create every intermediate component relative to that
  root with no-follow semantics.
- [ ] `FS-303` Reject symlink, alias, non-directory, and root-substitution
  conditions at the actual sink.
- [ ] `FS-304` Implement safe replace, move, and cleanup using root-contained
  handles.
- [ ] `FS-305` Define behavior for file-provider placeholders and temporarily
  unavailable synchronized items.
- [ ] `FS-306` Coordinate `vault path set` with the helper: make it a
  helper-owned transaction or refuse it until the helper is locked/restarted.

**Acceptance gate:**

- Intermediate and final symlinks cannot escape any read or mutation sink.
- Symlink replacement races do not create an out-of-root effect.
- CLI and helper always report and use the same vault root.

**Findings addressed:** `CAND-008`; hardening item `CAND-009`.

### PR 4 — Implement The Vault Transaction Engine

**Purpose:** Make key, mode, manifest, and file transitions serializable and
crash recoverable.

- [ ] `TXN-401` Introduce one vault mutation actor/queue with typed operations
  and explicit operation IDs.
- [ ] `TXN-402` Require an expected manifest generation for every mutation and
  reject conflicts rather than overwrite.
- [ ] `TXN-403` Stage immutable entry files and the next authenticated manifest
  in a new generation.
- [ ] `TXN-404` Commit a complete generation through one verified root-pointer
  transition whose semantics are tested on every supported provider.
- [ ] `TXN-405` Persist transaction phase and recovery information before the
  first irreversible side effect.
- [ ] `TXN-406` Stream re-encryption one entry at a time without retaining the
  full vault plaintext in memory.
- [ ] `TXN-407` Resume or roll back after termination at every transaction
  phase.
- [ ] `TXN-408` Queue or reject ordinary mutations while a key-generation
  transition is active.
- [ ] `TXN-409` Expose transaction status, progress, conflict, resume, and
  rollback through the service protocol.
- [ ] `TXN-410` Diagnose and resolve the current
  `.completeFileProtection`/`EPERM` write failure in the shipping environment.

**Acceptance gate:**

- Forced termination at every write/commit phase recovers a completely readable
  old or new generation.
- Concurrent add, edit, remove, share, revoke, rotate, and unshare executions
  are serializable or return an explicit conflict.
- No operation can report success while leaving a mixed-key vault.
- The full test suite passes with the shipping file-protection behavior.

**Findings addressed:** `CAND-011`; hardening items `CAND-007`, `CAND-009`, and
`CAND-010`.

### PR 5 — Replace Enrollment And Add Cryptographic Revocation

**Purpose:** Make device membership an authenticated protocol whose removal
changes actual decrypt authority.

- [ ] `ENR-501` Specify a versioned enrollment transcript containing vault ID,
  both device public keys, fresh nonces, roles, request expiry, and protocol
  version.
- [ ] `ENR-502` Derive the short authentication string from the complete
  transcript.
- [ ] `ENR-503` Display the value independently on both devices and require an
  explicit comparison; never echo a joiner-supplied code as proof.
- [ ] `ENR-504` Bind nearby peer selection to the approved transcript and stop
  accepting arbitrary peer certificates without an application identity check.
- [ ] `ENR-505` Reject replayed, expired, role-confused, or wrong-vault
  enrollment requests.
- [ ] `DEV-506` Add `vault devices` with stable device identifiers, state, and
  current key epoch.
- [ ] `DEV-507` Add `vault revoke <device>` as a versioned transaction.
- [ ] `DEV-508` Rotate the AES vault key, re-encrypt entries, and rewrap only to
  remaining active devices.
- [ ] `DEV-509` Prove the prior key and revoked device wrappers cannot decrypt
  entries written after rotation.
- [ ] `DEV-510` Make voluntary leave an acknowledged revoke/rotate workflow, not
  local metadata deletion.

**Acceptance gate:**

- Substituting either peer key, nonce, role, vault ID, or transcript changes the
  comparison value and prevents enrollment.
- A racing peer cannot become the selected identity without explicit approval.
- A revoked device cannot decrypt any future entry with retained pre-revocation
  material.
- Rotation interruption satisfies the PR 4 recovery invariants.

**Findings addressed:** `CAND-002` and `CAND-003`.

### PR 6 — Recovery, CLI UX, And Release Enablement

**Purpose:** Make the security model understandable and operable from the CLI
before enabling sharing.

- [ ] `UX-601` Decide and implement the all-devices-lost recovery policy in
  `DEC-003`.
- [ ] `UX-602` Add `vault doctor` with manifest, generation, entry revision,
  device, provider, transaction, and recovery checks.
- [ ] `UX-603` Add `vault rotate`, recovery status, and explicit
  resume/rollback commands where automatic recovery is unsafe.
- [ ] `UX-604` Require confirmation for destructive leave, revoke, rotate,
  unshare, and recovery actions; require explicit flags in noninteractive use.
- [ ] `UX-605` Add stable JSON output and machine-readable exit codes for
  status, devices, conflicts, and transactions.
- [ ] `UX-606` Make `vault sync` report observed provider/current-generation
  state; do not imply that checking for metadata triggered or completed sync.
- [ ] `UX-607` Escape or provide NUL/JSON forms for attacker-controlled entry
  and device names.
- [ ] `UX-608` Update README and security-model documentation to describe the
  implemented protocol, recovery limits, and supported providers.
- [ ] `REL-609` Run the complete release test matrix and record evidence below.
- [ ] `REL-610` Enable enclave sharing only after every release gate passes.

**Acceptance gate:** A CLI-first user can enroll, inspect, revoke, rotate,
diagnose, recover, and automate the vault without guessing at hidden state.

## Finding-To-Work Mapping

| Candidate | Short title | Primary work packages |
|---|---|---|
| `CAND-001` | Unauthenticated XPC authority | `XPC-101`–`XPC-107` |
| `CAND-002` | Self-authenticating enrollment code | `ENR-501`–`ENR-505` |
| `CAND-003` | Removal without key rotation | `DEV-506`–`DEV-510`, `TXN-401`–`TXN-409` |
| `CAND-004` | Unauthenticated vault metadata | `FMT-201`–`FMT-203`, `FMT-207`–`FMT-208` |
| `CAND-005` | Entry context not authenticated | `FMT-204`–`FMT-206` |
| `CAND-006` | Entry replay without freshness | `FMT-203`, `FMT-207` |
| `CAND-007` | Last-writer-wins updates | `TXN-401`–`TXN-402` |
| `CAND-008` | Symlink escape | `FS-301`–`FS-305` |
| `CAND-009` | Warm helper uses stale path | `FS-306`, `TXN-401` |
| `CAND-010` | Interrupted unshare leaves mixed keys | `TXN-403`–`TXN-410` |
| `CAND-011` | Concurrent key-transition race | `XPC-105`–`XPC-106`, `TXN-401`–`TXN-409` |

## Compatibility And Migration

- Local-only mode remains readable and is never automatically converted merely
  because a new binary launches.
- Ship a version-3 reader and `vault doctor` before enabling any version-3
  writer.
- Migration begins with a complete readability and disk-space preflight.
- Preserve the prior local generation and key until the new manifest and every
  entry have been authenticated and reopened successfully.
- Never mix version-2 and version-3 entries under an ambiguous current
  manifest.
- Prototype enclave metadata is refused with explicit instructions; it is not
  silently promoted into a production authorization root.
- Once a device writes a version-3 generation, rollback requires a binary that
  understands version 3. Ship reader compatibility before writer enablement.

## Tactical Protections During The Stack

- Keep local-only mode as the default.
- Keep enclave sharing unavailable or explicitly experimental.
- Land XPC caller authentication before relying on helper caching for any new
  privileged workflow.
- Refuse unsupported enclave metadata rather than attempt best-effort recovery.
- Do not expose selective device removal until rotation is implemented.
- Do not describe `sync` as complete, current, or conflict-free without provider
  evidence.

## Test And Validation Matrix

### Required Automated Coverage

- [ ] Unit tests for canonical manifest and entry-context encoding.
- [ ] Negative tests for every changed authenticated field.
- [ ] Replay tests for manifest, entry, enrollment request, and device epoch.
- [ ] Installed XPC tests for intended and unintended signing identities.
- [ ] Concurrency stress tests for every mutation against every key transition.
- [ ] Fault injection before and after every transaction phase.
- [ ] Filesystem containment tests for symlinks, aliases, mount changes, and
  provider placeholders.
- [ ] Migration tests from every supported local-only format.
- [ ] Revocation tests using retained pre-revocation key material.
- [ ] Recovery tests with missing devices, corrupt stages, stale manifests, and
  provider conflicts.

### Required Provider Matrix

| Provider/filesystem | Atomic commit verified | Conflict behavior verified | Placeholder behavior verified | Notes |
|---|---:|---:|---:|---|
| Local APFS | [ ] | [ ] | N/A | |
| iCloud Drive | [ ] | [ ] | [ ] | |
| Additional supported provider | [ ] | [ ] | [ ] | Name before release. |

### Performance And Resource Evidence

Measure rather than assume:

| Workload | Metrics | Baseline | Candidate | Decision threshold |
|---|---|---|---|---|
| Add/get one entry | CLI latency, helper latency | TBD | TBD | Define before PR 4 merge. |
| List 100/10,000 entries | Latency, peak RSS | TBD | TBD | Define before PR 4 merge. |
| Rekey 1/100/10,000 entries | Duration, peak RSS, temporary disk | TBD | TBD | Must remain observable and cancellable only at safe phases. |
| Crash recovery at each phase | Recovery duration, data loss | N/A | TBD | Zero unreadable committed entries. |
| Two-device conflict | Detection latency, state retained | N/A | TBD | No silent overwrite. |

## Release Gates

Enclave sharing remains disabled until all are checked:

- [ ] `GATE-01` All ten invariants pass.
- [ ] `GATE-02` All eight reportable findings are revalidated against the
  production branch.
- [ ] `GATE-03` Durability items `CAND-007`, `CAND-009`, and `CAND-010` have
  explicit closure.
- [ ] `GATE-04` Full unit, helper integration, concurrency, fault-injection, and
  provider suites pass.
- [ ] `GATE-05` Protected writes succeed in the actual release environment.
- [ ] `GATE-06` Migration and rollback are tested with copies of realistic
  local-only vaults.
- [ ] `GATE-07` Recovery policy and all-devices-lost behavior are documented and
  tested.
- [ ] `GATE-08` README, CLI help, and security-model documentation agree with
  actual behavior.
- [ ] `GATE-09` An independent reviewer signs off on XPC identity, enrollment,
  manifest authentication, revocation, and transaction recovery.
- [ ] `GATE-10` The release build passes signing, notarization, and installed
  helper verification.

## PR And Commit Ledger

Update this table when work begins, not only after merge.

| Stack item | Branch | PR | Head commit | Status | First remaining blocker |
|---|---|---|---|---|---|
| Prototype/review | `bugfix/icloud-keychain-publish` | [#12](https://github.com/tvanreenen/key/pull/12) | `92fe552` | Draft prototype; review and tracker preserved | None; preserve until reusable work is dispositioned |
| PR 1: XPC boundary | `agent/authenticate-xpc-boundary` | [#13](https://github.com/tvanreenen/key/pull/13) | `8dadc56` | Draft; `XPC-101`–`XPC-106` implemented | `XPC-107` |
| PR 2: v3 storage | TBD | TBD | TBD | Not started | `FMT-201` |
| PR 3: filesystem | TBD | TBD | TBD | Not started | `FS-301` |
| PR 4: transactions | TBD | TBD | TBD | Not started | `TXN-401` |
| PR 5: enrollment/revocation | TBD | TBD | TBD | Not started | `ENR-501` |
| PR 6: UX/release | TBD | TBD | TBD | Not started | `UX-601` |

## Decision Log

Do not erase superseded decisions. Add a new row and reference the decision it
changes.

| ID | Date | Status | Decision | Reason / evidence |
|---|---|---|---|---|
| `DEC-000` | 2026-07-26 | Accepted | Use a versioned transaction layer rather than local guards or a signed operation log. | Best balance of file portability, security ownership, crash recovery, and implementation complexity. |
| `DEC-001` | 2026-07-26 | Open | Choose manifest authentication and authority: shared-key MAC, device signatures, or a layered design. | Must balance simple verification, device attribution, revocation, and multi-writer conflicts. |
| `DEC-002` | 2026-07-26 | Proposed | Reject silent multi-writer merge initially; use expected generations and explicit conflicts. | File-sync providers do not provide a trustworthy distributed lock or ordering primitive. |
| `DEC-003` | 2026-07-26 | Open | Choose all-devices-lost behavior and recovery credential design. | Recovery can weaken device-bound security and must be an explicit product decision. |
| `DEC-004` | 2026-07-26 | Open | Define supported sync providers and required commit semantics. | Transaction durability depends on real provider behavior. |
| `DEC-005` | 2026-07-26 | Open | Decide whether `vault path set` is helper-owned or requires a locked helper. | CLI-only configuration currently creates stale process state. |
| `DEC-006` | 2026-07-26 | Accepted | Give the bundled CLI full current vault authority and the utility app only status/lock authority, using separate code-signing-bound Mach services. | Listener-selected roles cannot be escalated through client-supplied data; production also requires Developer ID Application certificates, and clients authenticate the helper. |

## Implementation Evidence

### PR 1 — XPC Boundary

- Commit: `8dadc568e29c847d94b70220afb09d3f367d8a3b`
- Focused policy and lifecycle suite: 10 tests pass.
- SwiftPM Release helper build: passes.
- Full Xcode Debug and universal Release builds with signing disabled: pass.
- Signed Debug packaging reports identifiers `work.tvr.key.app`,
  `work.tvr.key.cli`, and `work.tvr.key.xpc`, all with team
  `9Q355KSV85`.
- The current machine has zero valid code-signing identities. Requirement
  evaluation therefore fails closed with `CSSMERR_TP_NOT_TRUSTED`; installed
  intended-client cold/warm validation remains `XPC-107`.
- The full Swift suite still reproduces the same 46 protected-write permission
  failures present on `main`; this remains tracked as `TXN-410`.

## Session Resume Checklist

When beginning a new implementation session:

1. Read this file and the linked architecture proposal.
2. Run `git status --short`, identify the current branch and head, and compare
   them with the PR ledger.
3. Confirm that no earlier stack dependency is still open.
4. Select exactly one unchecked work package or one tightly coupled group.
5. State its invariant and acceptance evidence before editing code.
6. Implement and test it without enabling later protocol behavior.
7. Update the checkbox, PR ledger, test evidence, decision log, and last-updated
   date before handing off.

## Immediate Next Action

Complete `XPC-107` on a machine with a valid development signing identity:
install the built helper, prove cold and warm CLI sessions, prove the utility
endpoint is limited to status/lock, and prove wrong-team, wrong-bundle, and
ad-hoc clients are rejected before handler access. Then move PR
[#13](https://github.com/tvanreenen/key/pull/13) out of draft.
