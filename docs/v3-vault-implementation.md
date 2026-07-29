# Version 3 Vault Implementation Tracker

This is the durable execution record for the file-backed, multi-device vault.
It records only current decisions, work packages, acceptance gates, and PR
state.

## Current State

| Field | Value |
|---|---|
| Status | In progress |
| Production base | `main` at `78b4921` |
| Selected architecture | Authenticated, content-addressed manifest history |
| Format specification | [Version 3 vault storage format](v3-vault-storage-format.md) |
| Canonical JSON module | [Intent, constraints, and extraction plan](json-canonicalization.md) |
| Current branch | `agent/require-expected-vault-head` |
| Current PR | Not opened |
| Active increment | `HIST-402` implemented on branch; awaiting review |
| Next work | Commit and review the exact-head implementation, then begin `KEY-403` |

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
- [ ] `INV-08` Recovery observes one complete old or new authenticated head,
  never a mixed-key vault.
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

- Cross-vault, name, type, key-epoch, and revision substitution fails.
- A manifest other than the exact checkpointed head is never silently trusted.
- Unknown or inconsistent metadata fails closed.
- Migration never deletes the only readable vault state.

### PR 3 — Root-Contained Filesystem

Status: `FS-301` squash-merged as `da33a66` in PR #24, `FS-302`
squash-merged as `4e6a0f0` in PR #25, `FS-303` squash-merged as
`632adfd` in PR #26, and `FS-304` squash-merged as `45713e5` in PR #27.
Vault-root change coordination continues on
`agent/coordinate-vault-root-changes`.

- [x] `FS-301` Open and retain a trusted vault-root directory handle.
- [x] `FS-302` Resolve every component with no-follow semantics.
- [x] `FS-303` Reject symlinks, aliases, root substitution, and provider collisions.
- [x] `FS-304` Implement contained replace, move, and cleanup.
- [x] `FS-305` Coordinate vault-root changes with the running helper.

### Authenticated History And Transaction Engine

This work is intentionally divided into serial PRs. Each increment changes one
security or durability boundary and updates this tracker before it merges.

| Increment | Status | Purpose |
|---|---|---|
| `TXN-401` | Complete; PR #29 | Serialize helper-owned mutations and assign local operation IDs |
| `HIST-402` | Implemented; awaiting review | Identify trusted vault state by an exact authenticated head digest |
| `KEY-403` | Planned | Replace counter-only key epochs with exact vault-key identities |
| `HIST-404` | Planned | Admit canonical multi-parent manifests and authenticated merge history |
| `STORE-405` | Planned | Read immutable digest-addressed objects and classify repository state |
| `MERGE-406` | Planned | Reconcile independent path changes and return typed conflicts |
| `TXN-407` | Planned | Publish entries first and the expected-head manifest last |
| `TXN-408` | Planned | Recover every interrupted transaction phase and resolve protected writes |
| `UX-409` | Planned | Add typed service failures, status, and conflict-resolution CLI commands |

`TXN-401` routes the current add, edit, copy, move, and remove operations
through one synchronous serial owner inside Key Agent while leaving reads
concurrent. Every accepted mutation attempt receives a canonical lowercase
UUID operation ID. The ID is stable input for later staging, journal, and
recovery records; this increment does not yet persist those records and does
not claim crash recovery.

#### `HIST-402` — Exact Authenticated Heads

Current branch: `agent/require-expected-vault-head`.

Scope:

- Remove manifest generation from manifest bodies, parent references,
  device-local checkpoints, membership records, schemas, and trust decisions.
- Represent the current trusted state as a vault ID plus SHA-256 of the exact
  canonical authenticated manifest-envelope bytes.
- Retain the current linear model: genesis has no parent and every later
  manifest names exactly one parent digest.
- Reopen only the exact checkpointed manifest and accept only a child naming
  that exact parent.
- Replace the checkpoint only with an expected-value guard.
- Update the storage specification, examples, and tests without introducing a
  writer or changing the shipping version 2 vault.

Out of scope:

- multi-parent manifests and head discovery;
- key-identity changes;
- immutable physical object layout;
- automatic merge or conflict CLI;
- transaction staging, publication, or recovery; and
- provider-specific behavior.

Acceptance gate:

- No manifest freshness or concurrency decision depends on a global counter.
- A different authenticated digest is never silently trusted.
- Exact single-child advancement remains authenticated and compare-and-swap
  guarded.
- Manifest, checkpoint, schema, and replay tests pass.

#### `KEY-403` — Exact Vault-Key Identity

Replace `keyEpoch` as a key identity with a cryptographically bound `keyID`.
Entries, wrappers, manifest authentication, and associated data will name that
exact identity. This prevents two offline branches from independently creating
different keys that both happen to be called the same next epoch. The precise
identifier construction is a format decision and must be documented and
reviewed before implementation.

Acceptance gate:

- Different vault keys cannot be mistaken for the same security state.
- Entry, wrapper, and authentication-key substitution continues to fail.
- No merge behavior is introduced by this increment.

#### `HIST-404` — Merge-Capable Manifest History

Replace the singular parent with a canonical, sorted, duplicate-free parent
digest array. Genesis has zero parents, ordinary commits have one, and merge
commits have two or more. Verify every parent and admit an automatic merge only
when the parents agree on vault identity, active key identity, membership,
roles, and wrapped-key state.

Acceptance gate:

- Parent ordering produces deterministic canonical bytes.
- Both sides of a merge remain reachable and authenticated.
- Foreign-vault, missing, duplicate, unsorted, and unauthenticated parents
  fail closed.
- Authority-changing histories are never combined automatically.

#### `STORE-405` — Immutable Object Repository

Introduce a read-only repository over immutable digest-derived paths such as:

```text
manifests/<manifest-digest>.json
entries/<entry-id>/<ciphertext-digest>.json
```

Enumerate authenticated manifests, build their parent relationships, find leaf
heads, and classify the observed repository as ready, incomplete, content
conflicted, security conflicted, or recovery required. Provider placeholders
and missing referenced files are incomplete transport, not corruption.

Acceptance gate:

- No synchronized mutable `current` pointer is authoritative.
- Concurrent writers use unique names and cannot overwrite one another.
- Invalid unreferenced objects cannot replace trusted history.
- Graph traversal has explicit object-count and depth bounds.
- This increment remains read-only.

#### `MERGE-406` — Deterministic Reconciliation

Implement a pure common-ancestor and three-way comparison engine over logical
paths, stable entry IDs, and exact ciphertext digests. Independently changed
paths merge automatically. Rename-plus-edit of the same stable entry merges
when the destination is unambiguous. Edit/edit, delete/edit, conflicting
renames, destination collisions, and security-state divergence return typed
conflicts without selecting a winner.

Automatic merge output depends only on authenticated history. It contains no
clock time, device display name, random merge ID, filesystem metadata, or
transport metadata, allowing independent devices to produce the same canonical
merge manifest and digest.

Acceptance gate:

- Identical authenticated inputs always produce identical merge output.
- Both values in a genuine conflict remain addressable.
- Graph and merge tests run without a filesystem or sync provider.
- Security-state divergence cannot enter the content auto-merge path.

#### `TXN-407` — Immutable Transaction Publisher

Connect version 3 to the serialized mutation owner. Capture the exact ready
head inside the helper, stage immutable encrypted entries, recheck the expected
head, durably publish referenced entry objects, and publish the authenticated
manifest last. Local transaction operation IDs remain in staging and recovery
records; they do not make deterministic logical merge state device-specific.

Acceptance gate:

- A changed expected head publishes nothing.
- A failed entry write cannot expose a manifest that references it.
- Every published manifest references only durable immutable objects.
- `--force` cannot bypass expected-head, trust, or conflict checks.
- Reads remain concurrent.

#### `TXN-408` — Recovery And Fault Injection

Persist recovery intent before irreversible effects, resume or safely abandon
interrupted staging, test interruption after every phase, and resolve the
shipping protected-write `EPERM` failures. Cleanup remains conservative and
never removes the only readable object or provider-delayed content.

Acceptance gate:

- Every interruption recovers to the complete old or complete new head.
- Recovery never invents, silently selects, or rolls back a head.
- Provider delay remains distinguishable from local transaction failure.
- Protected writes pass in the release environment.

#### `UX-409` — Typed Status And Conflict UX

Replace string-only service failures with stable semantic codes and introduce
one central vault-observation model. Add `key status`, machine-readable JSON,
and the `key conflict list`, `show`, `get`, `copy`, and `resolve` family.
Conflict resolution is bound to the exact set of heads that the user reviewed;
newly arrived history invalidates an outdated resolution attempt without
changing state.

Acceptance gate:

- Secrets remain the only stdout from value-returning commands.
- Scripts branch on stable error codes, never English messages.
- Incomplete, content-conflicted, security-conflicted, rollback, and recovery
  states are distinguishable.
- Unaffected reads continue during content conflicts.
- Mutations remain paused until genuine conflicts are resolved.
- Stale reads require explicit `--allow-stale`; stale writes are impossible.

### Committed CLI And Conflict Contract

- Existing everyday commands retain their current names and default behavior.
- Normal linear advancement and non-overlapping reconciliation require no user
  action and never contaminate secret stdout.
- `key status` explains health; Enclave does not claim to control transport
  through a misleading `key sync` command.
- Digests, heads, and graph terminology are hidden by default and available
  through verbose or JSON diagnostics.
- `--force` may skip an overwrite or removal confirmation. It never suppresses
  an expected-head mismatch, conflict, rollback, incomplete state, or trust
  failure.
- An incomplete newer state fails temporarily by default. A read may explicitly
  request the last complete trusted state with `--allow-stale`; mutations may
  not.
- Concurrent changes to different paths merge automatically.
- Reads of unaffected paths continue during a content conflict. Reading a
  conflicted path requires an explicit version, and all mutations pause until
  the genuine conflict is resolved.
- Routine shared-key HMAC manifests do not prove which device authored them.
  The CLI uses honest labels such as "previously trusted on this Mac" and short
  authenticated version IDs rather than `ours`, `theirs`, or unverified device
  attribution.
- Immutable history is retained initially. Provider-safe garbage collection is
  deferred until recovery and realistic provider tests establish safe rules.

### Design Lineage

The history and conflict model applies established ideas to Enclave's narrow
file-vault domain; it is not a new general-purpose synchronization protocol.
These references are non-normative, and Enclave does not adopt their on-disk
formats or transport stacks:

- [Git's data model](https://git-scm.com/docs/gitdatamodel.html) supplies
  immutable content-addressed objects, parent-linked history, and merge
  ancestry. Enclave does not adopt Git's mutable refs or text merge machinery.
- [restic's repository design](https://github.com/restic/restic/blob/master/doc/design.rst)
  supplies the publication invariant that referenced immutable data is durable
  before the snapshot naming it is published.
- [CouchDB's conflict model](https://docs.couchdb.org/en/stable/replication/conflicts.html)
  demonstrates retaining concurrent revision leaves for later reconciliation.
  Enclave does not silently expose a deterministic winner.
- [Automerge's merge rules](https://automerge.org/docs/reference/under-the-hood/merge-rules/)
  inform common-ancestor comparison and automatic combination of independent
  fields. Enclave does not require a general CRDT engine for coarse vault
  entries.
- [The Update Framework specification](https://theupdateframework.github.io/specification/)
  informs rollback, freeze, fast-forward, and mix-and-match threat analysis.
  Enclave uses authenticated ancestry rather than TUF's centralized version
  stream.
- [Tahoe-LAFS architecture](https://tahoe-lafs.readthedocs.io/en/latest/architecture.html)
  informs the separation between immutable encrypted objects, human-readable
  names, and future least-authority sharing capabilities.

### Enrollment And Revocation Track

- [ ] Bind enrollment to both keys, roles, vault ID, nonces, and expiry.
- [ ] Derive and independently display a transcript authentication value.
- [ ] Reject replay, substitution, wrong-vault, and role confusion.
- [ ] Add device inspection and revoke/rotate commands.
- [ ] Re-encrypt for remaining devices after revocation.

### Release Track

- [ ] Decide and test the all-devices-lost policy.
- [ ] Add doctor, transaction, conflict, recovery, and device diagnostics.
- [ ] Add stable JSON output and machine-readable exit codes.
- [ ] Validate supported providers and realistic migration copies.
- [ ] Document the implemented security model and recovery limits.

## Decision Log

| ID | Status | Decision |
|---|---|---|
| `DEC-000` | Accepted | Use authenticated immutable manifest history and one serialized transaction owner. |
| `DEC-001` | Accepted | Require a derived-key HMAC on every manifest and a parent-owner Secure Enclave signature on authority-changing transitions. Use separate signing and wrapping keys. |
| `DEC-002` | Accepted | Use exact authenticated heads for mutation safety. Automatically reconcile independent path changes, preserve every concurrent value, and require explicit resolution only for genuinely incompatible changes. |
| `DEC-003` | Open | Define recovery when every enrolled device is lost. |
| `DEC-004` | Open | Define supported providers and required atomic commit semantics. |
| `DEC-005` | Accepted | Make vault-root configuration changes helper-owned through the authenticated full-CLI XPC channel. Serialize the change after in-flight handler work, persist it, invalidate the warm key session, refuse later work from the stale handler, and shut the helper down after its successful reply. Re-read the configured root before other requests and fail closed if the file was changed or removed out of band. |
| `DEC-006` | Accepted | Give the CLI full authority and the utility status/lock authority on separate authenticated endpoints. |
| `DEC-007` | Accepted | Keep the signed nested helper, constrain launchd spawning, and re-register it on app upgrades. |
| `DEC-008` | Accepted | Keep canonical JSON independent of vault schemas in an internal SwiftPM target; do not claim or publish full RFC 8785 conformance until complete number handling, upstream vectors, fuzzing, and independent review are complete. |
| `DEC-009` | Accepted | Authenticate v3 entry identity as the entry-AAD domain label, a NUL delimiter, and canonical JSON over format, version, vault ID, entry ID, name, type, key epoch, and revision. Derive those values from authenticated manifest state when opening. |
| `DEC-010` | Accepted | Keep v3 entry parsing explicitly untrusted. Before releasing plaintext, require the authenticated manifest digest and manifest-derived context to match the canonical file, then open AES-256-GCM with the exact typed associated data and require UTF-8 plaintext. |
| `DEC-011` | Accepted | Implement v3 copy and rename as authenticated decrypt-and-reseal operations. Copy creates a fresh logical entry at revision 1; rename preserves the logical entry ID and advances its revision. Both preserve exact valid UTF-8 plaintext bytes, type, and key epoch and require a fresh nonce. |
| `DEC-012` | Accepted | Treat authentication and freshness as separate gates. Persist one exact vault ID and manifest-envelope digest in the non-synchronizing device-local Keychain; advance it under the serialized helper mutation owner with an expected-checkpoint guard only after verifying authenticated ancestry. Require the freshness-approved manifest type for entry open, copy, and rename. |
| `DEC-013` | Accepted | Keep local manifests free of device-membership and wrapped-key records. Require shared manifests to retain at least one active owner and exactly one current-epoch wrapped key for every active device, with no wrapper for a revoked or unknown device. Defer membership-transition ceremonies to enrollment and revocation work. |
| `DEC-014` | Accepted | Make migration opt-in. Ship `key migrate --check` as a helper-owned, read-only v2 compatibility and decryptability check. A later writer must stage and verify v3 beside the untouched v2 source, select it only through an authenticated-head commit and device-local checkpoint transition, and retain v2 until verified reopen and explicit cleanup. |
| `DEC-015` | Accepted | Treat the unreleased prototype as a migration exclusion, not a permanent runtime compatibility mode. `key migrate --check` refuses the exact root-level `.key-vault.json` marker before loading a key, while ordinary v2 reads remain unchanged and the strict v3 parser rejects prototype JSON. |
| `DEC-016` | Accepted | Establish vault-root authority by opening the configured file URL once through Swift System's `FileDescriptor` with directory-only, no-follow, and close-on-exec semantics. Retain that descriptor and its device/inode identity for the lifetime of the filesystem session; later contained operations must resolve relative to the descriptor instead of trusting the configured path again. |
| `DEC-017` | Accepted | Accept only canonical, nonempty relative child paths. Open one component at a time from the trusted root with `openat`, no-follow, close-on-exec, and directory-only semantics for every intermediate component. Verify that the terminal descriptor has the requested directory or regular-file type before use, and open special files nonblocking so an unexpected FIFO cannot stall the helper. |
| `DEC-018` | Accepted | Before granting retained-root descriptor access, reopen the configured root with the original no-follow rules and require the same device/inode identity. Keep resolved components on the root device; reject Finder aliases, firmlinks, multiply linked regular files, and dataless provider placeholders. Model provider name collisions explicitly: canonical Unicode equivalents always collide, and case variants collide when the selected provider is case-insensitive. |
| `DEC-019` | Accepted | Resolve mutation parents from the retained vault-root descriptor and pass terminal names directly to `renameat`, exclusive `renameatx_np`, or `unlinkat`. Limit replacement to validated regular files, make moves no-overwrite, and restrict cleanup to validated regular files or already-empty directories. These primitives guarantee local namespace containment and atomic rename behavior; the transaction engine and provider qualification remain responsible for synchronization and crash durability. |
| `DEC-020` | Accepted | Model synchronized vault history as immutable authenticated manifests named by exact digest. Genesis has no parents, ordinary commits have one, and later merge commits have a canonical sorted parent set. Derive current heads from authenticated reachability instead of trusting a synchronized mutable pointer. |
| `DEC-021` | Accepted | Keep graph mechanics out of the ordinary CLI. Automatically merge non-overlapping changes, continue unaffected reads during content conflicts, pause mutations for genuine ambiguity, and provide explicit status and conflict commands with stable machine-readable outcomes. |
| `DEC-022` | Accepted | Reserve `--force` for confirmation and overwrite policy; it never bypasses trust, expected-head, completeness, rollback, or conflict checks. Permit stale reads only through an explicit `--allow-stale` request and never permit stale writes. |
| `DEC-023` | Proposed | Replace counter-only `keyEpoch` identity with an exact cryptographically bound `keyID` before multi-parent history ships. |

## Validation Matrix

- [x] Canonical manifest and entry-context encoding tests.
- [x] Negative authentication tests for every bound field.
- [x] Copy/rename identity, revision, collision, and exact-byte resealing tests.
- [x] Exact-head and single-parent replay tests without manifest generations.
- [x] Local/shared membership and current-epoch wrapped-key consistency tests.
- [x] V2 migration-preflight compatibility, decryptability, and no-write tests.
- [x] Prototype migration-marker and v3 parser rejection tests.
- [x] Trusted vault-root type, no-follow open, retained-identity, and close-on-exec tests.
- [x] Component-by-component relative resolution, traversal rejection, symlink rejection, and terminal-type tests.
- [ ] Enrollment and key-epoch replay tests.
- [x] Installed XPC tests for intended and unintended signing identities.
- [ ] Mutation/key-transition concurrency tests.
- [ ] Transaction fault injection at every phase.
- [x] Root substitution, filesystem alias, provider-placeholder, and provider-name collision tests.
- [x] Descriptor-relative replace, exclusive move, and non-recursive cleanup tests.
- [x] Helper-owned vault-root change, stale-session refusal, and out-of-band configuration tests.
- [x] Serialized mutation ownership, canonical operation-ID, and mutation-routing tests.
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

Review and merge `HIST-402`. After it merges, begin `KEY-403`; do not introduce
multi-parent manifests until exact vault-key identity is specified and
implemented.
