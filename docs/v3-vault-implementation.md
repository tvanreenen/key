# Version 3 Vault Implementation Tracker

This is the durable execution record for the file-backed, multi-device vault.
It records only current decisions, work packages, acceptance gates, and PR
state.

## Current State

| Field | Value |
|---|---|
| Status | `v0.2.0-beta.1` is the latest Preview release and has completed local, distribution, two-device channel-transition, and post-install reboot qualification; catastrophe recovery is deferred beyond `0.2.0` |
| Latest release | `v0.2.0-beta.1 (17)` at `6ab38f8` |
| Selected architecture | Device-wrapped, session-only keys over authenticated content-addressed history |
| Current prerelease profile | [Version 3 device-wrapped key architecture](v3-device-wrapped-key-architecture.md) |
| Historical alpha.6 format | [Role-bearing version 3 vault storage format](v3-vault-storage-format.md) |
| Canonical JSON module | [Intent, constraints, and extraction plan](json-canonicalization.md) |
| Active work | `STABLE-703`: overhaul the GitHub README and user-facing release contract before final promotion |
| Next work | `STABLE-704`: observe beta.1, close findings, and qualify the deliberate Stable artifact |

The current device-wrapped profile remains prerelease-only. It MUST not ship as
stable until the scoped Stable work packages below pass.

## Security And Durability Invariants

- [x] `INV-01` Only the correctly signed CLI or utility role can invoke its
  authorized helper operations.
- [x] `INV-02` Enrollment authenticates both device keys, vault ID,
  fresh nonces, and an independently compared transcript.
- [x] `INV-03` Membership, exact vault-key identity, wrapped keys, and committed entries form
  one authenticated state.
- [x] `INV-04` Revocation rotates the vault key and removes future decrypt
  authority from the revoked device.
- [x] `INV-05` Every entry authenticates vault ID, normalized name, type,
  format version, exact vault-key ID, and revision.
- [x] `INV-06` Replayed manifests and entries are detected explicitly.
- [x] `INV-07` Concurrent mutations serialize or return a revision conflict.
- [x] `INV-08` Recovery observes one complete old or new authenticated head,
  never a mixed-key vault.
- [x] `INV-09` Every filesystem effect remains beneath the opened vault root.
- [x] `INV-10` Loss of all enrolled devices has an explicit outcome: permanent
  loss in `0.2.0`, with no weaker fallback.
- [x] `INV-11` A raw v3 vault key exists only in an unlocked Key Agent session
  and is never persisted or synchronized.
- [x] `INV-12` Every membership change creates a fresh key and re-encrypts the
  complete current snapshot.
- [x] `INV-13` Every vault has one authenticated device roster and durable
  device wrapper from genesis; there is no local-to-shared trust exception.

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

- Cross-vault, name, type, key-ID, and revision substitution fails.
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
| `HIST-402` | Complete; PR #30 | Identify trusted vault state by an exact authenticated head digest |
| `KEY-403` | Complete; PR #31 | Replace counter-only key epochs with exact vault-key identities |
| `HIST-404` | Complete; PR #32 | Support canonical multi-parent manifests and authenticated merge history |
| `STORE-405` | Complete; PR #33 | Read immutable digest-addressed objects and classify repository state |
| `MERGE-406` | Complete; PR #34 | Reconcile independent path changes and return typed conflicts |
| `TXN-407` | Complete; PR #35 | Publish entries first and the expected-head manifest last |
| `TXN-408` | Complete; PR #36 | Recover every interrupted transaction phase without trusting synchronized staging |
| `UX-409` | Complete; PR #37 | Add typed service failures, status, and conflict-resolution CLI commands |
| `READ-410` | Complete; PR #38 | Bind every v3 read to one exact authenticated entry and repository state |
| `RUNTIME-411` | Complete; PR #39 | Connect exact v3 reads to the shipping helper while every v3 mutation remains disabled |
| `MIG-412` | Complete; PR #43 | Add explicit local version 2 migration and verified version 3 bootstrap |
| `ENR-501` | Complete; PR #44 | Define canonical enrollment invitations, join requests, and comparison transcripts |
| `ENR-502` | Complete; PR #45 | Create device-bound signing and wrapping identities and signed ceremony messages |
| `ENR-503` | Complete; PR #46 | Exchange bounded enrollment messages without trusting the file provider |
| `ENR-504` | Complete; PR #47 | Approve and publish the owner-authorized local-to-shared transition |
| `ENR-505` | Complete; PR #48 | Verify first trust, unwrap the exact vault key, select the vault, and expose the read-only CLI flow |
| `ENR-505A` | Complete; PR #49 | Resume only the exact authenticated owner approval after provider delivery outlives its invitation |
| `MUT-507` | Complete; PR #50 | Route selected-vault entry mutations and explicit conflict choices through authenticated expected-head publication |
| `ENR-506` | Complete; PR #52 | Inspect authenticated device membership without invoking private-key operations |
| `ENR-507` | Complete; PR #53 | Enroll additional devices through the same owner-approved comparison ceremony |
| `ARCH-508` | Complete | Select the permanent device-wrapped, session-only key profile, macOS 14 floor, and breaking-alpha path |
| `KEY-509` | Complete; PRs #54–#56; physically qualified in alpha.7 | Ship one-device genesis, durable HPKE wrappers, explicit migration, wrapper-backed sessions, exact reads, and recoverable ordinary writes without persisting the raw vault key |
| `ENR-510` | Complete; PR #57; two-device ceremony physically qualified in alpha.7 | Use one explicitly approved, key-rotating roster-addition path for first and later enrollment |
| `ENR-511` | Complete; shipped in alpha.8 | Revoke devices, rotate the key, re-encrypt the current snapshot, and catch remaining devices up safely |
| `AUTH-513` | Complete; shipped in alpha.8 | Remove owner/member roles from the permanent profile and give every active enrolled device equal authority |
| `REC-512` | Complete; shipped in alpha.8 | Add multi-device continuity guidance, one-device risk warnings, and explicit permanent-loss behavior |
| `REP-514` | Complete; PR #65; shipped and physically qualified in alpha.10 | Safely retire a revoked local identity and rejoin the same vault through the ordinary enrollment ceremony |
| Later recovery track | Deferred beyond `0.2.0` | Prototype primary and backup PIV P-256 recovery keys before selecting a permanent catastrophe-recovery schema or release |

#### `ARCH-508` / `KEY-509` — Permanent Profile Runtime

Status: complete in PRs #54–#56 and physically qualified on two Macs with the
signed alpha.7 Preview release.

This work delivers the macOS 14 CryptoKit HPKE foundation, permanent
device-wrapped manifests, one-owner genesis, an exact checkpoint-manifest
cache, and wrapper-backed in-memory sessions. Explicit migration keeps version
2 selected until it has reloaded the persisted Secure Enclave identity,
reopened every published object, and verified the permanent runtime. It then
selects the new vault last while retaining the version 2 source for recovery.

Once selected, the shipping helper uses the permanent runtime for unlock,
status, list, get, add, edit, duplicate, rename, and remove. Each ordinary
write recovers any locally anchored interruption, reauthenticates the exact
device-local checkpoint and complete encrypted snapshot, builds a
content-only child manifest, publishes immutable entries before the manifest,
and compare-and-swap advances the checkpoint last. It cannot fall through to
legacy `.secret` files or persistent raw version 3 key storage.

This is the permanent runtime foundation used by the enrollment and revocation
work below. `REC-512` now completes the continuity and explicit permanent-loss
UX without adding catastrophe-recovery authority to `0.2.0`.

#### `ENR-510` — Permanent Key-Rotating Enrollment

Status: complete in PR #57. The owner-to-second-device ceremony and the
joining-device read, restart, and write paths were physically qualified with
the signed alpha.7 Preview release. Third-and-later enrollment uses this exact
transition and has dedicated multi-device transition and adoption tests. A
third physical Mac is useful opportunistic evidence, not a beta release gate.

First and later device enrollment now use the same user ceremony: an active
device invites a Mac, both Macs compare the short code, and the authorizing
device approves the exact request. Approval creates a fresh vault key, reseals
the complete current snapshot, adds the compared device to the authenticated
roster, and gives each active device its own HPKE wrapper. Entries are
published before the signed manifest, and the authorizing device's checkpoint
advances last.

The joining Mac accepts only the exact compared and authorizer-signed
transition. It verifies the complete encrypted snapshot before asking its
Secure Enclave key to open its wrapper, keeps the raw vault key only in the
helper session, and selects the vault last. The authority-transition ID is
derived from the complete comparison transcript, so an otherwise valid
transition from another ceremony cannot be substituted. Exact retries remain
safe across provider delay, invitation expiry, and interruption.

This increment deliberately did not revoke devices, create a recovery kit, or
automatically advance another enrolled Mac that was offline during the key
rotation. The new manifest already carried a wrapper for every active device;
`ENR-511` now supplies the remaining-device catch-up UX and revocation
transition.

#### `ENR-511` — Authenticated Catch-Up And Device Revocation

Status: complete and shipped in alpha.8.

A returning device now starts from its exact device-local checkpoint and
authenticates forward content and device-authorized key transitions in order.
At each key epoch it verifies the parent authorizer signature, opens only the
HPKE wrapper addressed to its Secure Enclave identity, authenticates the
complete resealed snapshot, and advances the checkpoint with an expected-value
guard.
The complete operation shares the helper mutation boundary with ordinary
writes, so catch-up and publication cannot interleave.

Unlock, reads, status, and writes invoke catch-up automatically. Missing
provider objects remain temporary-unavailable, invalid or substituted objects
require recovery, and competing key or membership transitions are security
conflicts. An explicit `--allow-stale` read may use only the exact version
already trusted on this Mac; writes never bypass catch-up.

This increment detects content-only forks and pauses normal writes without
discarding either authenticated branch. It does not yet claim permanent-profile
entry-level conflict inspection or resolution; that UX must be brought to
parity before full release. The catch-up-specific error therefore explains the
safe stale-read option without directing users to unavailable conflict-detail
commands.

An active enrolled Mac can inspect authenticated device IDs with
`key share devices`, then run `key share revoke <device-id>`. Key catches that
Mac up before showing the exact selected device and remaining active roster.
Execution requires the literal interactive confirmation `REVOKE`, catches up
again, and accepts only the confirmation token bound to that exact checkpoint
and device.

The accepted transition generates a fresh vault key, re-encrypts the complete
current snapshot, marks the selected device revoked, and creates wrappers only
for remaining active devices. It publishes immutable entries before the
authorizer-signed manifest and advances the device-local checkpoint last. Every
publication phase recovers to the complete old or new epoch; an exact retry
also finishes post-checkpoint cleanup without publishing a second rotation.
Remaining devices accept the new epoch only through authenticated catch-up.
The revoked device keeps any past material it already possessed but receives
no wrapper for the new current snapshot or future epochs.

#### `AUTH-513` — Equal Enrolled-Device Authority

Status: complete and shipped in alpha.8.

The permanent profile no longer divides enrolled Macs into owner and member
roles. Every active enrolled Mac has the same ability to authorize another
device or revoke a different device. The user-presence, comparison-code, and
explicit revocation-confirmation requirements remain unchanged, so equal
authority does not make roster changes implicit or provider-controlled.

The breaking prerelease format and enrollment protocol are both version 2.
Role-bearing alpha manifests and ceremony messages are rejected explicitly
instead of being silently translated. Each accepted manifest must contain at
least one active device and exactly one wrapper for every active device. Device
inventory, catch-up, enrollment, revocation, and CLI output now describe active
devices without implying a hierarchy.

#### `REC-512` — Continuity UX And Explicit Permanent Loss

Status: complete and shipped in alpha.8.

`key share devices` now tells the user whether the vault relies on one or
multiple enrolled Macs and recommends keeping at least two. Revocation review
warns prominently when the requested change would leave only one active Mac;
the existing last-device rule still refuses a transition that would leave
none.

After migration, Key explains that the retained version 2 source is useful
while validating or returning from the prerelease migration, but it is not a
recovery mechanism for the device-wrapped version 3 vault. The report
recommends enrolling another Mac and states that synchronized version 3 files
cannot recover the vault after every enrolled Mac is lost.

When this Mac has no usable enrolled Secure Enclave identity, Key preserves
the stable `recovery_required` error and security exit code 6 while giving a
specific next step: use a surviving enrolled Mac to enroll this Mac again. It
states permanent loss only conditionally—when no enrolled Mac survives—and
offers no password fallback, cloud escrow, support override, or destructive
repair.

#### `REP-514` — Revoked-Device Replacement Re-enrollment

Status: complete in PR #65 and physically qualified on two Macs with the
signed alpha.10 Preview release.

This is continuity through a surviving enrolled Mac, not recovery from the
loss of every device. The surviving Mac first revokes the old device identity,
rotating the vault key and removing that identity from future access. The
revoked Mac can then review the exact authenticated revocation, explicitly
confirm local cleanup, restart the helper, and use the ordinary invitation,
comparison, approval, and acceptance ceremony to join with a new Secure
Enclave identity.

Cleanup never edits synchronized vault history. It removes only the revoked
Mac's local enrollment identity and checkpoint after binding confirmation to
the reviewed vault, identity, and authority. Durable device-only intent makes
each destructive step retry-safe across interruption and helper restart. Key
admits only cleanup commands while cleanup is incomplete and only enrollment
commands afterward; normal reads and writes cannot accidentally revive stale
authority. The intent is consumed last, after the new identity, checkpoint,
and runtime are usable.

`key share join` is the only joining entry point. On a new Mac it answers the
invitation directly. On a revoked Mac it recognizes that the local identity
must be replaced, verifies the selected invitation exists, is authentic,
unexpired, and belongs to the same vault, then performs the authenticated
replacement review. It refuses noninteractive cleanup, explains exactly which
local state will be removed, and requires the literal confirmation `REJOIN`.
Immediately before cleanup it revalidates the invitation and requires the
replacement review to remain byte-for-byte unchanged. It then cleans up, waits
for the old helper process to terminate, reconnects through launchd, and
retries the same invitation with a new identity. Interrupted cleanup or
enrollment resumes through the same command. The bound confirmation token
never becomes a user-managed argument. Helper termination has a bounded client
wait, but safety does not depend on meeting that deadline: on timeout the CLI
reports that cleanup completed and directs the user to rerun the same join,
which resumes from the durable enrollment-pending state.

Alpha.10 physically qualified the complete revoke-to-rejoin sequence on a
disposable iCloud Drive Preview vault. The revoked Mac revalidated the fresh
invitation and unchanged authenticated review before cleanup, removed only its
local unusable enrollment state, waited for helper termination, and published
a new join request without a retry. The surviving Mac independently derived
the same device pair and comparison code, approved the new identity, and both
Macs converged on the old identity remaining revoked and the distinct new
identity active. Cross-device write, read, removal, catch-up, lock, complete
helper termination, on-demand restart, and post-restart decrypt all passed.

`TXN-401` routes the current add, edit, copy, move, and remove operations
through one synchronous serial owner inside Key Agent while leaving reads
concurrent. Every accepted mutation attempt receives a canonical lowercase
UUID operation ID. The ID is stable input for later staging, journal, and
recovery records; this increment does not yet persist those records and does
not claim crash recovery.

#### `HIST-402` — Exact Authenticated Heads

Status: complete; squash-merged as `205ac4f` in PR #30.

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

Status: complete; squash-merged as `89ee693` in PR #31.

Scope:

- Replace `keyEpoch` with a typed `keyID` in manifest bodies, entry records,
  encrypted entry files, entry AAD, schemas, examples, and tests.
- Derive the 32-byte ID with HKDF-SHA256 from the exact 32-byte vault key,
  the canonical vault UUID bytes as salt, and the domain-separated
  `work.tvr.key/v3/vault-key-id` info label.
- Encode the result as canonical unpadded 43-character base64url.
- Require manifest authentication and entry sealing/opening to derive the
  supplied key's ID and match authenticated metadata before cryptographic use.
- Let every shared-mode active-device wrapper inherit the manifest's exact
  current key ID, then verify the unwrapped key against that single authority.
- Treat a changed active key ID as an authority change requiring an active
  parent-owner signature.
- Retain per-entry `revision`; it identifies revisions of one stable entry, not
  vault keys or global state.

This prevents two offline branches from independently creating different keys
that both happen to be called the same next epoch.

Out of scope:

- multi-parent manifests or reconciliation;
- key rotation and wrapped-key creation ceremonies;
- immutable object storage and head discovery;
- transaction publication or recovery; and
- any shipping version 2 behavior.

Acceptance gate:

- Different vault keys cannot be mistaken for the same security state.
- Entry, wrapped-key-result, and authentication-key substitution continues to
  fail.
- The key ID is vault-specific and has an exact independent vector.
- No merge behavior is introduced by this increment.

#### `HIST-404` — Merge-Capable Manifest History

Status: complete; squash-merged as `80262fe` in PR #32.

Replace the singular parent with a canonical, sorted, duplicate-free parent
digest array. Genesis has zero parents, ordinary commits have one, and merge
commits have two or more. Verify every parent and admit an automatic merge only
when the parents agree on vault identity, active key identity, membership,
roles, and wrapped-key state.

Implementation:

- Persist the complete direct-parent set as `content.parents`, ordered by the
  decoded 32-byte SHA-256 digests.
- Accept parent authority only through `V3VerifiedManifest` values so raw
  synchronized files cannot self-assert authenticated ancestry.
- Preserve owner-authorized authority changes for single-parent transitions.
- Require every parent and the merge candidate to carry exactly the same
  authority state; merge commits cannot carry an authority authorization.
- Leave branch discovery and entry reconciliation to `STORE-405` and
  `MERGE-406`.

Acceptance gate:

- Parent ordering produces deterministic canonical bytes.
- Both sides of a merge remain reachable and authenticated.
- Foreign-vault, missing, duplicate, unsorted, and unauthenticated parents
  fail closed.
- Authority-changing histories are never combined automatically.

#### `STORE-405` — Immutable Object Repository

Status: complete; squash-merged in PR #33.

Introduce a read-only repository over immutable lowercase-hex digest paths:

```text
manifests/<64-lowercase-hex-manifest-digest>.json
entries/<entry-id>/<64-lowercase-hex-ciphertext-digest>.json
```

Enumerate authenticated manifests, build their parent relationships, find leaf
heads, and classify the observed repository as ready, incomplete, content
conflicted, security conflicted, or recovery required. Provider placeholders
and missing referenced files are incomplete transport, not corruption.

Implementation:

- Resolve the `manifests` directory and every referenced object from the
  retained vault-root descriptor with the existing no-follow containment
  checks.
- Use lowercase hexadecimal names even though authenticated manifest records
  use canonical base64url digests. Hex avoids case-only filename collisions on
  case-insensitive providers.
- Require the exact checkpoint manifest to exist at its digest path, then walk
  its digest-linked ancestors backward to recover the authenticated common
  history without requiring every historical vault key to remain available.
- Fully authenticate forward descendants against their complete verified
  parent sets and every locally available exact vault key.
- Recursively inspect the unresolved ancestry of a cryptographically
  authenticated candidate before calling the graph complete. Treat a missing
  object on a still-plausible branch as incomplete transport, but do not let a
  candidate that already violates merge authority or authorization rules block
  repository readiness.
- Read each distinct encrypted entry object once, then validate its digest,
  canonical structure, and every manifest-derived context that references
  those bytes. Reusing ciphertext after changing authenticated entry metadata
  is recovery-required state.
- Return a typed ancestry proof only for complete ready or conflicted graphs.
  The proof is read-only and does not advance the device-local checkpoint.
- Bound one scan to 4,096 manifest-directory objects, history depth 1,024,
  16,384 distinct referenced entry objects, 2 MiB per manifest, and 16 MiB per
  encrypted entry, with 64 MiB cumulative manifest input and 256 MiB cumulative
  entry input.

Classification:

- `ready`: exactly one complete authenticated reachable head;
- `incomplete`: a checkpoint-linked manifest, authenticated branch parent, or
  referenced entry is missing or still a provider placeholder;
- `contentConflicted`: multiple complete authenticated heads have identical
  vault authority state;
- `securityConflicted`: multiple complete authenticated heads disagree on
  mode, active key identity, membership, roles, public keys, statuses, or
  wrapped-key state; and
- `recoveryRequired`: a referenced immutable path contains the wrong bytes,
  fails structural validation, violates containment, or exceeds a resource
  bound.

Acceptance gate:

- [x] No synchronized mutable `current` pointer is authoritative.
- [x] Concurrent writers use unique names and cannot overwrite one another.
- [x] Invalid unreferenced objects cannot replace trusted history.
- [x] Graph traversal has explicit object-count and depth bounds.
- [x] This increment remains read-only.

#### `MERGE-406` — Deterministic Reconciliation

Status: complete; squash-merged in PR #34.

Implement a pure common-ancestor and three-way comparison engine over logical
paths, stable entry IDs, and exact ciphertext digests. Independently changed
entries merge automatically across two or more heads. Edit/edit, delete/edit,
rename-plus-edit, conflicting renames, destination collisions, and
security-state divergence return typed conflicts without selecting a winner.
Lower revisions and different records that reuse an ancestor revision are also
preserved as typed conflicts rather than being selected as automatic changes.

Manifest authentication enforces the same rule at the transition boundary. A
changed existing record must advance beyond its direct parents, and a new
stable entry ID starts at revision 1. A multi-parent manifest may reuse an
exact parent record only when it is the unique highest-revision value; equal
highest revisions with different records remain ambiguous.

Rename-plus-edit is deliberately conservative. A v3 rename must reseal the
entry because its name is authenticated AES-GCM associated data. Manifest
metadata alone therefore cannot prove that a renamed ciphertext preserved the
ancestor plaintext. Automatically selecting the other branch's edit could
silently discard a value, so both exact versions remain addressable for manual
resolution.

The reconciler returns a deterministic logical merge plan containing the
unique nearest common ancestor, canonically ordered parent heads, and canonical
manifest content. It performs no file access, decryption, random generation,
publication, or checkpoint mutation. A criss-cross graph with several nearest
common ancestors returns a typed history conflict instead of choosing a base
arbitrarily.

Acceptance gate:

- [x] Identical authenticated inputs always produce identical merge output.
- [x] Both values in a genuine conflict remain addressable.
- [x] Graph and merge tests run without a filesystem or sync provider.
- [x] Security-state divergence cannot enter the content auto-merge path.
- [x] Rollbacks and same-revision substitutions cannot enter an automatic
  merge.

#### `TXN-407` — Immutable Transaction Publisher

Status: complete; squash-merged as `bbc0213` in PR #35.

Connect version 3 to the serialized mutation owner. Capture the exact ready
head inside the helper, stage immutable encrypted entries, recheck the expected
head, durably publish referenced entry objects, and publish the authenticated
manifest last. Local transaction operation IDs remain in staging and recovery
records; they do not make deterministic logical merge state device-specific.

The publisher authenticates a candidate against the exact observed parents and
refuses unresolved content, security, or history conflicts. For an automatic
merge, the candidate must equal the reconciler's deterministic content
exactly. Newly staged entries must match candidate manifest context, digest,
and current key, while reused entries are reopened from their immutable paths
before and after staging. A device-local checkpoint must anchor at least one
current head; other authenticated heads may be sibling branches from an older
common ancestor.

Repository discovery carries its bounded manifest, history-depth, referenced
entry, and aggregate-byte usage into publication. The publisher projects the
candidate against those repository-wide totals both before staging and during
the final head recheck, so it cannot advance the checkpoint into a state that
the bounded reader would immediately classify as recovery-required.

Staged files live under `.transactions/<operation-id>/` and have no authority.
After the head recheck, entry objects move to their final digest paths with
exclusive no-overwrite renames. The publisher reopens every referenced entry,
then moves the manifest to its final digest path, reopens the exact manifest,
and finally advances the device-local checkpoint with an expected-value guard.
Identical existing objects converge; different existing bytes fail closed.

The implementation uses Swift System's typed `FileDescriptor.writeAll` for
complete staged writes and a shared pure-Swift lowercase hexadecimal encoder.
The Darwin-only directory-relative create and exclusive-rename calls remain in
one small adapter, with their validated descriptor and path-component
preconditions documented at each explicitly unsafe call.

This increment establishes safe publication ordering, not complete crash
recovery. A failure after immutable entry publication can leave harmless
unreferenced entry objects. A failure after manifest publication but before
checkpoint advancement can leave a valid uncheckpointed descendant. Staging
directories are intentionally retained for `TXN-408` recovery rather than
being guessed at or aggressively deleted.

Acceptance gate:

- [x] A changed expected head publishes no final repository object.
- [x] A failed entry write cannot expose a manifest that references it.
- [x] Every published manifest references only durable immutable objects.
- [x] `--force` cannot bypass expected-head, trust, or conflict checks.
- [x] Reads remain concurrent.

#### `TXN-408` — Recovery And Fault Injection

Status: complete; squash-merged as `0f41ed0` in PR #36.

Before staging begins, the publisher now prepares a small recovery anchor in
the same non-synchronizing, device-local Keychain domain as the checkpoint.
The anchor identifies the vault, operation, exact shared-intent digest, and
whether shared intent became durable. The publisher then persists one
canonical immutable intent at `.transactions/<operation-id>/intent.json` and
arms the local anchor before staging.

The shared intent records the exact old checkpoint, exact ordered head
digests, candidate manifest digest, mutation kind, and the newly staged entry
object identities. It contains no plaintext, keys, timestamps, transport
metadata, or mutable publication-phase counter. Neither the shared intent nor
the local anchor has vault authority: recovery must authenticate the real
candidate against the recorded parents, revalidate every entry context and
digest, and satisfy the device-local expected-checkpoint guard.

Separating the two records is important for multi-device folders. iCloud or
another provider can deliver one device's shared intent before its staged
files. A second device has no matching local anchor, so it ignores that intent
and cannot abandon, resume, or delete the first device's in-flight state.

Recovery derives progress from authenticated filesystem facts instead of
trusting a phase flag. If no final manifest exists and required staging is
absent, it safely retains the old checkpoint and abandons the attempt. If
complete staging remains and the exact old checkpoint and heads still match,
it resumes entry-first publication. If the final manifest is already durable,
it validates the candidate and entries before advancing the checkpoint. If
the checkpoint already names the candidate, only validated staging cleanup
remains.

A checkpoint that changed to some other head causes the locally anchored
staged attempt to be abandoned without replacing that head. Shared intents
without this device's exact local anchor are ignored rather than ordered by
operation ID, filename, timestamp, or provider metadata. New local publication
is blocked while a recovery anchor for that vault remains, so callers cannot
skip recovery after restart.

Cleanup removes only exact known staged bytes, removes the exact canonical
shared staging, and then clears the device-local anchor once the transaction
has a complete old or new outcome. Shared-intent and empty-directory cleanup
is best effort after the anchor clears. Immutable repository objects are never
deleted. An interruption can therefore leave inert shared staging, but without
a matching local anchor it has no recovery or vault authority and is safely
ignored.

Fault injection now covers every publication boundary in both the in-memory
model and the directory-relative filesystem adapter: local-anchor preparation,
shared-intent persistence, recovery arming, each stage and publish phase,
final-object validation, checkpoint advancement, and cleanup. Every tested
interruption converges to the complete old or complete new checkpoint with no
retained actionable local anchor.

A Swift Testing child-process exit test terminates the writer after a complete
temporary object is synchronized but before its exclusive rename. The
canonical shared-intent and staging paths remain absent at that point, so
recovery cannot parse partial bytes as durable state. A later attempt can
safely create a fresh exclusively named temporary file while leaving the
terminated process's non-authoritative temporary file inert.

Provider caveat: if interruption occurs before the local anchor records that
shared intent was durable, an unavailable intent can be safely abandoned to
the old checkpoint because staging could not yet have begun. Once recovery is
armed, unavailable shared intent or authoritative content is retained and
reported as transport-unavailable rather than cleaned or guessed at. If no
authoritative candidate manifest exists and the authenticated intent proves
required staging was never published, recovery may retain the old checkpoint;
the caller may need to retry the mutation after transport settles.

The earlier `EPERM` observation came from a restricted scanner environment,
not from the shipping app. Key uses hardened runtime but does not enable App
Sandbox; its app entitlements are empty and the helper entitlement is limited
to the shared Keychain access group. The existing signed application already
uses complete file protection for v2 writes, while the transaction engine's
descriptor-relative write, synchronization, interruption, and recovery paths
are covered by automated filesystem tests and a successful signed Xcode
build.

Real provider smoke tests remain valuable release qualification. They are not
a correctness input to the provider-neutral recovery protocol and are not
practical as a deterministic automated test gate. At the `TXN-408` checkpoint,
version 3 writing remained disabled. It was enabled later by `MUT-507` only
after the deterministic recovery gates passed. Local APFS and iCloud Drive are
the directly qualified `0.2.0` scope. Other ordinary folder-backed providers
may work when they preserve the required semantics, but are not directly
validated or covered by the `0.2.0` compatibility guarantee.

Acceptance gate:

- [x] Every injected interruption recovers to the complete old or complete new
  head in the model and real filesystem adapter.
- [x] Recovery never invents, silently selects, or rolls back a head.
- [x] Provider-unavailable recovery is distinct from invalid recovery state.
- [x] Protected writes use the existing shipping protection model, and the
  signed hardened-runtime build succeeds.
- [x] Provider unavailability and interruption behavior pass the deterministic
  recovery matrix.
- [x] iCloud Drive receives release-qualification smoke testing before the
  alpha.6 guarded writer is treated as qualified.
- [x] Additional providers are not directly validated release targets; every
  configured root still has to pass the provider-neutral filesystem safety
  checks.

#### `UX-409` — Typed Status And Conflict UX

Status: complete; squash-merged as `a0404d0` in PR #37.

This increment gives the CLI one plain-language answer to “is my vault safe to
use right now?” The answer comes from a typed observation shared by status,
reads, writes, and conflict commands, so a warning cannot be shown in one path
and silently ignored in another.

`key status` reports a healthy v2 vault today without opening the vault key.
It also establishes the v3 health vocabulary: ready, waiting for synchronized
files, content conflict, security conflict, rollback detected, or recovery
required. Human output explains the next safe action; `--json` and stable
process exit codes give scripts a durable contract that does not depend on
English wording. Entry totals explicitly identify whether they describe the
effective ready state or the last state trusted by this Mac; incomplete or
conflicted transport never turns a known checkpoint into a misleading zero.

For genuine v3 content ambiguity, `key conflict list` and `show` expose only
authenticated metadata. `get` is the sole conflict command that prints a
secret, and `copy` sends it only to the clipboard. Resolution requires one
explicit version for every current conflict. Each conflict ID includes the
exact authenticated head set, so newly arrived history invalidates a stale
choice before anything is published.
Revision rollback remains inspectable but is recovery-only: neither status nor
conflict detail presents ordinary version selection as a valid next step.

The machine-readable CLI contract uses sorted-key JSON with the following
stable fields:

- Status: `format`, `health`, `entries`, `conflictCount`,
  `trustedVersionID`, and `issues`.
- Entry summary: `count` and `basis`; `basis` is `effective` or
  `last_trusted`.
- Issue: `code` and `message`. Scripts branch on `code`; `message` is for
  people and may improve over time.
- Conflict summary: `id`, `entryName`, `kind`, and `versionCount`.
- Conflict detail: `summary` and `versions`. Each version contains `id`,
  `entryName`, `entryType`, `revision`, and
  `previouslyTrustedOnThisMac`.

Optional values are omitted when absent. Enum values and service error codes
use their documented lowercase snake-case representations. Exact JSON fixture
tests protect these field names and values from accidental source-level
renaming.

The v3 observation and resolution service remains a domain seam in the Swift
package. The shipping Xcode target now composes it with the exact read runtime
and the guarded mutation service whenever device-local configuration selects
a v3 vault. `KeyServiceHandler` routes those operations explicitly; it never
falls through to legacy `.secret` storage.

The `authorizeRead` and `authorizeMutation` calls remain UX policy gates, not
storage authority. Each actual read carries a typed plan bound to its exact
authenticated state, and each mutation independently reopens the checkpoint,
ancestry proof, expected heads, immutable objects, and resource bounds inside
the helper's serialized publication boundary. A successful policy check alone
never authorizes a later unbound filesystem operation.

Acceptance gate:

- [x] Secrets remain the only stdout from value-returning commands.
- [x] Scripts branch on stable error and status codes, never English messages.
- [x] Incomplete, content-conflicted, security-conflicted, rollback, and recovery
  states are distinguishable.
- [x] Unaffected reads continue during content conflicts.
- [x] Mutations remain paused until genuine conflicts are resolved.
- [x] Stale reads require explicit `--allow-stale`; stale writes are impossible.

#### `READ-410` — Exact Authenticated Read Plans

Status: complete; squash-merged as `92fc9fd` in PR #38.

The v3 runtime must not authorize a name and later reopen whichever file then
appears current at that name. Repository state can change while a file
provider delivers new objects, so the result of trust evaluation must remain
attached to the eventual immutable-object read.

This increment introduces a typed read plan containing the authenticated
checkpoint, expected head set when current repository state is required,
vault ID, exact manifest entry, ciphertext digest, and whether the user
explicitly selected the last locally trusted checkpoint. Planning resolves
the requested name against a complete authenticated ancestry proof,
deterministic automatic merge, or exact local checkpoint. Content conflicts
block only ambiguous names; authority conflict, rollback, and recovery states
block every ordinary read.

Execution opens the digest-addressed entry beneath the retained vault-root
handle, applies the existing size bound, verifies the SHA-256 digest and
canonical entry context, obtains only the vault key named by the authenticated
entry, and uses the existing AES-256-GCM entry cipher. For a current or
conflict-selected read, the executor revalidates the expected checkpoint and
head set immediately before releasing plaintext. An explicit stale read is
instead bound to the exact device-local checkpoint that made it permissible.

This increment remains a Swift-package security seam. It does not select v3
at runtime, add v3 sources to the shipping Xcode target, migrate a v2 vault,
publish a conflict resolution, or enable any v3 mutation.

Acceptance gate:

- [x] A normal read identifies one exact entry from authenticated effective
  state and retains its expected checkpoint and heads.
- [x] An incomplete repository fails unless the caller explicitly requests a
  stale read, which uses only the exact locally trusted checkpoint.
- [x] Unambiguous entries remain readable during an ordinary content conflict;
  ambiguous names, destination collisions, rollback, authority conflict, and
  recovery states fail closed.
- [x] Missing, oversized, substituted, malformed, digest-mismatched,
  context-mismatched, or wrong-key entry objects never release plaintext.
- [x] A changed checkpoint or head set invalidates a current or selected
  conflict read before plaintext is returned.
- [x] Tests exercise planning and execution without enabling the shipping v3
  reader, migration, resolution publication, or writes.

#### `RUNTIME-411` — Shipping Read-Only Runtime

Status: complete; squash-merged as `752a22d` in PR #39.

The helper must select the storage format from device-local configuration, not
from untrusted files arriving through a synchronized vault directory. Existing
configuration without a vault identity continues to mean version 2. A
device-local canonical `vault_id` selects version 3 and binds the configured
root to that exact identity; the Keychain checkpoint and authenticated
manifest must still agree before any v3 metadata or plaintext is returned.
Migration and future enrollment will write this selection deliberately. This
increment does not infer it from synchronized files or change an existing
configuration automatically.

For a selected v3 vault, the shipping helper opens and retains the configured
root, reopens the exact checkpointed manifest, authenticates and classifies the
available immutable history, and composes the status/conflict UX with the
READ-410 planner and executor. Ordinary `get` and `copy` requests require no
version argument. `--allow-stale` remains explicit, conflict-value reads remain
bound to the exact reviewed heads, and logical listing returns only
authenticated unambiguous names.

The runtime is deliberately read-only. Unlocking never creates a replacement
key or invokes the legacy iCloud-to-local key repair path for a selected v3
vault. It authenticates the loaded key against the exact device-local
checkpoint and checkpointed manifest before succeeding. Add, edit, duplicate,
rename, remove, conflict resolution, migration, and key-storage-mode changes
fail before touching vault files or Keychain state. Changing the configured
vault directory remains available and restarts the helper through the existing
coordination path.

Acceptance gate:

- [x] Configuration without `vault_id` retains the exact existing v2 runtime;
  a valid canonical UUID selects only that exact v3 identity.
- [x] The installed helper target contains the canonical JSON and required v3
  reader modules without collapsing their SwiftPM separation.
- [x] V3 status, conflict inspection, list, get, copy, explicit stale reads,
  and selected conflict-version reads use one freshly authenticated runtime.
- [x] V3 unlock cannot create a key, and every v3 mutation or migration command
  fails before a v2 filesystem operation can run.
- [x] A wrong configured vault ID, absent or changed checkpoint, unavailable
  checkpoint manifest, changed head set, wrong key, or invalid immutable object
  fails without releasing plaintext.
- [x] Focused service integration tests and the complete v3 suite pass; no v3
  migration, bootstrap, resolution publication, or write path is enabled.

#### `MIG-412` — Opt-In Local Migration And Verified Bootstrap

Status: complete; squash-merged as `eb9779d` in PR #43 and released as
`v0.2.0-alpha.3`.

This increment adds the first deliberately enabled version 3 write path, but
only for converting the current device's readable local version 2 vault. The
user must request migration explicitly. Installing or unlocking a new release
never starts it automatically.

Scope:

- Add one explicit migration command whose normal output first makes clear
  that version 2 remains available and cleanup is deferred.
- Run the complete version 2 compatibility and decryptability preflight again
  inside the serialized mutation owner; an earlier `--check` result is never a
  reusable authorization.
- Generate a canonical vault ID and use the currently authenticated local
  vault key to create a local-mode version 3 genesis state. Migration never
  creates or repairs a vault key; a keyless empty vault is refused.
- Decrypt each version 2 entry, normalize its supported value, assign a stable
  version 3 entry identity and initial revision, then seal it with the complete
  version 3 associated-data context.
- Stage and publish immutable entries before the authenticated genesis
  manifest, establish the device-local checkpoint, and independently reopen
  the complete candidate through the shipping version 3 reader.
- Write the device-local `vault_id` selection only after that verified reopen
  succeeds and the configured path still names the exact root directory opened
  for publication. Until then, version 2 remains the selected and authoritative
  runtime.
- Retain every version 2 source file after success. Cleanup requires a later,
  explicit policy and is not part of this increment.
- Fail or interrupt without selecting incomplete version 3 state or mixing it
  into the active version 2 vault.
- Treat encrypted staging, immutable objects, or a checkpoint left by a hard
  interruption as non-authoritative while their exact `vault_id` is not
  selected. Defer provider-safe orphan cleanup rather than deleting broadly.

Out of scope:

- shared-vault device enrollment or synchronized key distribution;
- general version 3 add, edit, duplicate, rename, remove, or conflict-resolution
  writes;
- deleting, moving, or rewriting the retained version 2 source; and
- automatic migration, provider-specific cleanup, or a version 2 downgrade
  command.

User-visible caveat:

- The selected version 3 vault is read-only at the alpha.3 migration
  checkpoint. Add, edit, duplicate, rename, remove, and conflict-resolution
  writes remain disabled at that checkpoint.
- Other devices continue using version 2. Any later version 2 changes are not
  imported into this version 3 snapshot; enrollment and multi-device version 3
  transport arrive in later increments.

Acceptance gate:

- Migration never begins implicitly and refuses a selected version 3 vault.
- A blocker, authentication failure, write failure, interruption, or failed
  verified reopen leaves version 2 selected and readable.
- A keyless empty vault creates no key or version 3 state, and a root-directory
  replacement before selection is refused.
- A successful migration produces the same logical names, types, and values
  through ordinary version 3 list, get, and copy commands.
- The device-local checkpoint and `vault_id` are installed only for the exact
  authenticated genesis that was independently reopened.
- Every version 2 source file remains byte-for-byte intact after both success
  and failure.
- Every other version 3 mutation and all shared-vault behavior remain disabled.

#### `ENR-501` — Canonical Enrollment Invitation And Transcript

Status: complete; squash-merged as `45eb609` in PR #44.

The first alpha.4 increment defines the exact public facts that two devices
must agree on before any key is shared or membership changes. An existing
device creates a short-lived invitation for one exact trusted vault head and
role. The joining device answers that exact invitation with a second fresh
nonce and its proposed identity. Both sides then derive the same compact
comparison code from the canonical message digests.

Scope:

- Represent each proposed device identity by its display name and distinct
  P-256 signing and wrapping public keys; derive and validate its device ID
  with the manifest's existing identity rule.
- Bind the invitation to the canonical vault ID, exact trusted parent-manifest
  digest, exact vault format version, inviting owner identity, role to grant,
  32-byte nonce, and explicit expiry.
- Bind the join request to the exact invitation digest, joining identity, and
  an independent 32-byte nonce.
- Reject malformed, oversized, noncanonical, unknown-field, wrong-digest,
  self-enrollment, and public-key-reuse inputs.
- Distinguish a canonical future enrollment-message or unsupported vault-format
  version as upgrade-required while retaining invalid-format classification for
  malformed current-version bytes.
- Derive a domain-separated transcript digest and display its first 80 bits as
  five groups of four lowercase hexadecimal characters.
- Publish a fixed deterministic vector so later implementations can reproduce
  the exact bytes and comparison value.

Out of scope:

- creating, storing, or using Secure Enclave private keys;
- signing either ceremony message or granting manifest authority;
- wrapping, transporting, or persisting the vault key;
- provider mailbox paths, local ceremony state, expiry consumption, or durable
  replay tracking;
- publishing a local-to-shared manifest transition or establishing first
  trust on the joining device; and
- any shipping CLI or XPC behavior.

Acceptance gate:

- Changing the vault, parent head, granted role, expiry, either nonce, or any
  public identity key changes the transcript digest.
- The invitation explicitly binds vault format 3; unsupported enrollment or
  vault versions fail with a typed upgrade-required result rather than being
  mistaken for current-format corruption.
- Canonical invitation and join-request bytes parse back to the exact typed
  values; noncanonical or structurally extended bytes fail closed.
- A join request cannot answer a different invitation, enroll the inviter as a
  second device, or reuse any public key across purposes or devices.
- Expiry has a deterministic inclusive boundary for later clock-aware callers.
- This increment cannot modify files, Keychain state, device membership, the
  selected vault, or plaintext behavior.

#### `ENR-502` — Device-Bound Identities And Signed Messages

Status: complete; squash-merged as `bf0f049` in PR #45.

The second alpha.4 increment proves that each participant controls the private
signing key represented in the `ENR-501` transcript. It also creates the
separate device-bound wrapping key that a later increment will use to deliver
the vault key. Both private keys remain in the Secure Enclave; synchronized
files receive only public identities and signed messages.

Scope:

- Create one distinct Secure Enclave P-256 signing key and one distinct Secure
  Enclave P-256 key-agreement key for an exact vault enrollment identity.
- Require device-only accessibility, private-key usage, and user presence for
  both private-key operations.
- Persist only CryptoKit's opaque key representations and the derived public
  identity in one non-synchronizing, this-device-only Keychain record scoped to
  the signed application's access group and exact vault ID.
- Refuse to overwrite an existing identity or silently replace a malformed,
  mismatched, inaccessible, or invalidated Secure Enclave identity.
- Wrap invitations and join requests in strict canonical signed envelopes with
  separate domain-separated P-256 ECDSA-SHA256 inputs.
- Normalize generated signatures to canonical low-`s` form and reject high-`s`,
  substituted, wrong-key, wrong-signer, cross-message, noncanonical, oversized,
  or structurally extended envelopes.
- Keep pure message authentication, private-key operations, and Keychain
  persistence behind separate testable seams.

Out of scope:

- provider mailbox paths or any shared-file exchange;
- durable invitation consumption, replay tracking, or ceremony resumption;
- deriving a wrapping shared secret or transporting the vault key;
- verifying that the inviter is an active owner of the exact parent manifest;
- publishing device membership or a local-to-shared manifest transition;
- establishing the joining device's checkpoint or selected vault; and
- any shipping CLI or XPC behavior.

Acceptance gate:

- Each signed carrier verifies only under the signing key embedded in its exact
  invitation or join request and cannot be replayed as the other message kind.
- A device-local identity cannot sign for another vault, and join-request
  signing requires the exact verified invitation being answered.
- Signature randomness does not change the `ENR-501` comparison transcript.
- The signing and wrapping private keys are device-bound, separately generated,
  non-synchronizing, and recover the exact stored public identity.
- Existing, corrupt, mismatched, or inaccessible local identity state fails
  closed without replacement.
- No vault file, manifest, checkpoint, vault key, selected-vault setting, or
  plaintext behavior can change through this increment.

#### `ENR-503` — Bounded Message Exchange And Resumable Ceremony State

Status: complete; squash-merged as `d4d4f06` in PR #46.

This increment lets the two devices pass the signed `ENR-502` invitation and
join request through the synchronized vault without treating the sync provider
as a trusted participant. It also gives each device enough private local state
to retry safely after an interrupted upload or process restart. It still does
not enroll a device or share a vault key.

Scope:

- Store immutable signed invitations beneath
  `.enrollment/invitations/<invitation-payload-digest>.json` and signed join
  requests beneath
  `.enrollment/join-requests/<invitation-payload-digest>/<join-payload-digest>.json`.
- Derive every path from the authenticated canonical payload digest and require
  the parsed message to reproduce that digest before accepting it.
- Install complete message bytes atomically without overwriting a different
  object already present at the same digest path.
- Bound each message read and directory scan. Count every provider-created
  directory entry toward the scan limit before ignoring names that are not
  canonical digest filenames.
- Treat missing or placeholder files as temporarily unavailable, while
  malformed, oversized, substituted, symbolic-link, and root-replacement
  states fail closed.
- Retain the exact signed invitation and join-request carrier bytes in one
  non-synchronizing, this-device-only Keychain record per invitation. Saving
  before publishing means a retry republishes the identical randomized ECDSA
  carrier rather than creating a competing message for the same payload.
- Track whether the local device is the inviter or joiner, whether it is waiting
  for a response or comparison, and whether the exact transcript has been
  consumed. Local state changes use expected-state guards so a stale operation
  cannot silently advance a ceremony.
- Enforce expiry from the signed invitation and explicitly supplied current
  time. Provider timestamps, versions, conflict labels, enumeration order, and
  delivery order never influence authenticity, freshness, or authority.
- Pin the first exact authenticated join response selected by the inviter.
  Reopening that response is idempotent; selecting a different response is a
  conflict rather than an implicit winner.

Out of scope:

- proving that the inviter is an active owner of the named parent manifest;
- asking the user to compare and approve the transcript;
- deriving a P-256 shared secret or wrapping the vault key;
- publishing membership or an owner-authorized manifest transition;
- establishing the joining device's checkpoint or selected vault;
- removing synchronized mailbox artifacts; and
- any shipping CLI or XPC surface.

Acceptance gate:

- A failed publish leaves resumable device-local state containing the exact
  carrier bytes, and an exact retry is idempotent.
- A mailbox object is accepted only at its payload-derived path and only after
  canonical parsing, signature verification, vault/transcript binding, and
  signed expiry checks.
- Untrusted directory contents cannot bypass the object-count cap or cause an
  implicit response selection.
- Corrupt local state, the wrong local role, a stale expected state, a second
  join response, or a consumed transcript fails closed without deleting or
  replacing the existing record.
- Provider files and local ceremony state grant no membership, manifest
  authority, vault key, checkpoint, selected-vault setting, or plaintext access.

#### `ENR-504` — Owner Approval And Local-To-Shared Publication

Status: complete; squash-merged as `2e59478` in PR #47.

This increment lets the inviting Mac turn one exact, independently compared
enrollment transcript into the first authenticated shared manifest. It wraps
the unchanged vault key separately for both compared devices, records the two
active memberships, and publishes the immutable authority transition before
advancing only the inviter's checkpoint. The joining device still receives no
trust or plaintext through this increment.

Scope:

- Require inviter-side ceremony state for the exact signed invitation and
  selected signed join request, with the caller supplying the complete 32-byte
  transcript digest it independently approved.
- Require the invitation to name the one complete local checkpoint and head.
  Preserve the exact vault ID, key ID, entry records, and parent digest; the
  conversion cannot also edit entries, rotate the key, or reconcile a branch.
- Create exactly two active device records from the compared identities. The
  inviter becomes an owner and the joining device receives exactly the role in
  the signed invitation.
- Wrap the same exact 32-byte vault key independently to each device's P-256
  wrapping public key. Bind X9.63-SHA256 key derivation and AES-256-GCM
  authenticated data to the vault ID, exact key ID, recipient device ID, and
  complete enrollment transcript digest.
- Sign the complete candidate manifest content with the inviter's Secure
  Enclave signing key. The candidate HMAC continues to prove exact vault-key
  possession; the owner signature proves the compared inviter approved this
  exact membership and wrapper state.
- Keep the local-to-shared verification exception narrow. The parent must be
  local and membership-free, the candidate must preserve its exact key and
  entries, and the candidate identities must reproduce the exact authenticated
  transcript. Ordinary repository discovery does not receive the local
  approval evidence and cannot treat an arbitrary self-signed conversion as
  an authoritative descendant.
- Persist a bounded device-local retry record before publication. It contains
  only the two randomized wrapper outputs, the owner signature, transcript
  digest, and candidate digest—not the vault key or full manifest—so a retry
  reconstructs the identical candidate without another signature prompt.
- Serialize publication with other helper mutations, stage and reopen the
  exact candidate, recheck the exact checkpoint and head, publish the immutable
  manifest, reopen it, and replace the inviter checkpoint last. Mark the local
  ceremony consumed only after checkpoint advancement.
- Permit an exact prepared approval to finish after invitation expiry. Expiry
  still prevents creating a new approval; this exception only completes bytes
  that were durably approved while the signed invitation was valid.

Out of scope:

- unwrapping the vault key with the joining device's Secure Enclave key;
- letting the joining device adopt the shared manifest or establish a
  checkpoint;
- CLI, XPC, or user-interface enrollment commands;
- adding a third device to an already shared vault;
- changing an existing role, revoking a device, or rotating/re-encrypting the
  vault key; and
- synchronized mailbox or immutable-history cleanup.

Acceptance gate:

- A wrong vault, parent, key ID, transcript digest, inviter identity, joining
  identity, role, wrapper recipient, owner signature, or wrapped-key context
  fails before checkpoint advancement.
- Generic parent verification continues to reject the local-to-shared
  candidate without the exact authenticated enrollment transcript.
- The owner-authorized candidate preserves every parent entry record exactly
  and contains one current-key wrapper for each of the two active devices.
- A failed preparation publishes nothing. A failure after preparation retries
  the same wrappers, signature, and manifest digest; a failure after checkpoint
  advancement only completes the idempotent local consumption marker.
- No joining-device checkpoint, selected-vault setting, Keychain vault key, or
  plaintext access changes through this increment.

#### `ENR-505` — Joining-Device First Trust And Read-Only Sharing

Status: implementation complete; PR #48 open from
`agent/adopt-v3-enrollment`.

This increment completes the first two-device enrollment ceremony. Both Macs
show the same device pair, granted role, and 80-bit comparison code. The
existing Mac approves that exact transcript and publishes the shared manifest;
the joining Mac then independently verifies the approval, opens only the vault
key wrapper addressed to its Secure Enclave identity, and selects the vault
only after its local key, checkpoint, and shipping read-only runtime are ready.

Scope:

- Add explicit `key share` commands for invitation discovery, invitation
  creation, joining, request discovery, comparison, approval, and acceptance.
  Every provider object is selected by its complete lowercase hexadecimal
  digest; there is no implicit "latest" invitation or join request.
- Create short-lived ten-minute invitations. Require both users to compare the
  same five-group code and readable device pair, then supply that exact code to
  `approve` and `accept` before either command can advance its local ceremony.
- Keep invitation and join-request files transport-only. Authenticate their
  canonical bytes, payload-derived path, signatures, nonces, identities,
  vault, role, parent, and expiry before displaying a comparison.
- Before asking the joining Secure Enclave to unwrap, require one candidate
  with the exact compared parent, device set, role, wrapper recipients, and a
  valid signature from the compared inviter. Unrelated or unauthenticated
  repository files cannot become trust and cannot create extra unwrap prompts.
  Candidate discovery enforces both the repository object-count cap and its
  aggregate manifest-byte cap before local trust can change.
- Derive the key-encryption key through the joining device's non-exportable
  P-256 key-agreement key. Authenticate the vault ID, exact manifest key ID,
  recipient device ID, and complete transcript digest as wrap context, then
  require the recovered 32-byte key to derive the manifest's exact key ID.
- Reopen the exact parent digest named by the compared invitation and run the
  narrow local-to-shared verifier again with the recovered key and complete
  transcript. The generic repository verifier still cannot self-authorize the
  transition.
- Treat local adoption as monotonic, exact-idempotent steps: consume the exact
  transcript as a retry marker, insert or match the vault key, insert or match
  the checkpoint, authenticate the shipping read-only runtime, and write
  `vault_id` last. Runtime authentication must classify the complete referenced
  repository as ready; missing or invalid entry objects cannot commit
  selection. A different existing key or checkpoint is never replaced.
- If join-request publication fails after local persistence, repeat `share
  join` republishes the exact stored request bytes before any fresh nonce,
  signature, or identity state is created.
- Restart the helper only after successful joining-device selection so the next
  ordinary command is served by the selected v3 runtime.
- Map a merely unavailable approved manifest or parent to temporary-unavailable
  exit code 5. Map ambiguous, substituted, unauthenticated, wrong-key,
  wrong-identity, or conflicting local trust state to recovery-required exit
  code 6. Enrollment never prints secret plaintext.

Historical caveats at the end of `ENR-505`:

- That increment could add only the first peer to a local vault. `ENR-507`
  generalizes the same ceremony to third and later devices; role changes,
  revocation, and key rotation remain separate work.
- Both Macs must point at copies of the same file-provider-backed vault root.
  Enclave authenticates what arrives but does not control provider delivery;
  a missing invitation, request, parent, or approval should be retried after
  synchronization settles.
- The provider mailbox and retained version 2 files are not cleaned up by this
  ceremony. They grant no authority, but cleanup needs a separate explicit
  policy.
- The selected shared v3 vault was read-only in alpha.4. Guarded entry writes
  were enabled and qualified in alpha.6; authority changes remain explicit
  enrollment or revocation operations.
- Loss of every enrolled Secure Enclave identity still has no recovery path.
  `DEC-033` now makes that permanent loss the explicit `0.2.0` policy; its UX
  and documentation remain release gates.

Acceptance gate:

- Missing approval bytes change no joining-device key, checkpoint, ceremony
  phase, configuration, file, or plaintext behavior.
- An invalid comparison code, invitation, request, owner signature, parent,
  wrapper recipient or context, recovered key ID, candidate HMAC, membership,
  role, or preserved entry fails before vault selection.
- A different existing local key or checkpoint is retained unchanged and
  reported as recovery-required; the adoption path never uses overwrite.
- An interruption after comparison, key insertion, checkpoint insertion, or
  runtime verification retries only the exact consumed ceremony. Expiry cannot
  strand an already consumed exact retry, and `vault_id` remains the final
  commit point.
- A persisted-but-unpublished join request is republished byte-for-byte, and
  candidate scanning stops at the aggregate repository manifest-byte limit.
- After success, both devices trust the same authenticated shared manifest and
  ordinary v3 list/get/copy reads produce the same logical vault without
  enabling any general v3 writer.

#### `ENR-507` — Additional-Device Enrollment

Status: complete; squash-merged as `38c4db2` in PR #53.

This increment allows an existing shared vault to add a third or later Mac
through the same explicit invitation, device comparison, owner approval, and
joining-device acceptance ceremony used for the first peer. It does not add a
second enrollment protocol or weaken the exact-parent rule.

Scope:

- Permit invitation creation from a complete single authenticated shared head
  only when this Mac's recorded Secure Enclave identity exactly matches an
  active owner in that head.
- Bind the invitation to that exact head. A content change before a new
  approval makes the invitation stale instead of silently rebasing authority.
- Preserve every existing device, wrapped key, entry record, vault ID, and key
  ID exactly. Add one compared active device with the requested role and one
  new vault-key wrapper addressed to its distinct P-256 wrapping key.
- Reject an already enrolled identity and any joining identity that reuses an
  existing signing or wrapping key.
- Use the ordinary shared-manifest owner-authorization convention for the new
  authority change while retaining the released first-enrollment signature
  convention for existing local-to-shared ceremonies.
- Persist only the newly randomized wrapper, owner signature, transcript
  digest, and candidate digest for retry. Reconstruct existing wrappers from
  the exact parent rather than duplicating them in device-local ceremony state.
- Allow a prepared retry to recognize the exact candidate or its authenticated
  descendants after provider publication. A new approval may start from the
  sole authenticated head even when the local checkpoint is an older ancestor;
  checkpoint replacement remains bound to that exact observed state and
  refuses unrelated heads.
- On the joining Mac, filter candidates by the compared owner's signature
  before requesting Secure Enclave unwrap, authenticate an existing shared
  parent with the recovered vault key, verify the exact one-device authority
  delta, authenticate the shipping runtime, and select the vault last.
- Keep all existing CLI ceremony commands and comparison-code behavior. After
  acceptance, `key share devices` shows the expanded authenticated roster.

Out of scope:

- changing an existing device's role or display name;
- revoking a device or removing its historical wrapper;
- rotating the vault key or re-encrypting entries;
- automatically rebasing a ceremony across concurrent vault changes; and
- provider mailbox or immutable-history garbage collection.

Acceptance gate:

- An active owner can enroll a third or later distinct device as the exact role
  recorded in the compared transcript; a member cannot create an authoritative
  enrollment transition.
- The candidate contains every parent device, wrapper, and entry unchanged,
  plus exactly one active device and one wrapper for the joining identity.
- The joining device unwraps only its transcript-bound wrapper, authenticates
  both the shared parent and approved child, and changes no local trust before
  those checks pass.
- Missing, stale, ambiguous, malformed, substituted, duplicate-identity,
  key-reuse, wrong-owner, wrong-parent, and interrupted states fail closed or
  resume only the exact prepared candidate.
- First two-device enrollment remains byte-compatible and continues to pass
  its existing regression suite.

#### `MUT-507` — Guarded Shared Entry Writes

Status: complete; squash-merged as `7364aa9` in PR #50 and released as
`v0.2.0-alpha.6 (11)`.

This increment enables the existing everyday entry commands for a selected
version 3 vault without giving the file provider, a pathname, or a stale local
view authority to overwrite authenticated state. Version 2 keeps its existing
implementation. Version 3 receives a dedicated mutation service that begins
from a freshly authenticated ancestry proof and publishes only immutable entry
objects plus an authenticated child manifest.

Scope:

- Route add, edit, duplicate, rename, remove, and explicit conflict resolution
  to the v3 mutation service whenever device-local configuration selects a v3
  vault. Never fall through to legacy `.secret` file operations.
- Carry the operation ID created by Key Agent's serial mutation owner into the
  transaction publisher. The publisher remains responsible for staged
  recovery intent, entry-first durable publication, final manifest
  publication, and expected-value checkpoint advancement.
- Normalize and validate logical names before planning. Additions receive a
  fresh stable entry UUID at revision 1; edits and renames retain identity and
  advance revision; duplicate creates a new identity; deletion removes only
  the manifest record and retains immutable history.
- Treat `--force` only as explicit destination-overwrite policy for duplicate
  and rename. It may remove the prior destination from the candidate manifest,
  but cannot bypass trust, completeness, conflicts, expected heads, resource
  limits, or recovery checks.
- When authenticated heads contain independent changes, publish the exact
  deterministic merge before applying the requested mutation. A head arriving
  during planning invalidates publication instead of becoming last-writer
  wins.
  The merge and requested change are separate durable transactions: if the
  merge succeeds but the requested change later loses a race or fails, vault
  content is unchanged and retry starts from the already-merged history.
- Bind conflict choices to the complete freshly observed head set. Reseal a
  selected same-entry version at a revision above every parent so a resolution
  cannot publish a rollback or same-revision substitution. Destination-name
  collisions retain only the explicitly selected stable entry identity.
- Attempt exact interrupted-transaction recovery before planning a new
  mutation. Contradictory, incomplete, oversized, or unauthenticated recovery
  state remains fail closed.

Out of scope:

- adding a third device, changing roles, revocation, vault-key rotation, or
  recovery after loss of every enrolled Secure Enclave identity;
- provider-specific synchronization APIs, automatic background writes,
  mutable remote references, or silent conflict winners; and
- immutable-history, enrollment-mailbox, staging-orphan, or retained-v2
  garbage collection.

Acceptance gate:

- A selected v3 mutation never invokes the v2 entry store and an unselected
  vault retains the exact v2 behavior.
- Every successful command reopens a complete authenticated state, seals the
  intended logical change, publishes referenced entry objects first, publishes
  the manifest last, and advances only the expected checkpoint.
- Missing provider objects remain temporary-unavailable; malformed,
  substituted, wrong-key, rollback, authority, or recovery state never
  releases plaintext or publishes a candidate.
- A changed checkpoint or authenticated head set publishes no requested
  mutation. `--force` cannot weaken this boundary.
- Independent changes converge through an exact authenticated merge; genuine
  same-entry or destination conflicts remain paused until every current
  conflict receives one explicit choice.
- Regression tests cover every ordinary command, overwrite policy,
  automatic-merge-before-write, stale-head refusal, interrupted recovery, and
  conflict-resolution publication.

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

- [x] `ENR-501` Bind the canonical enrollment transcript to both device key
  pairs, exact roles, vault ID, trusted parent, fresh nonces, and expiry.
- [x] `ENR-501` Derive an independently reproducible 80-bit comparison value
  from the domain-separated complete transcript digest.
- [x] `ENR-502` Create device-bound signing and wrapping keys and authenticate
  both sides of the ceremony.
- [x] `ENR-503` Exchange bounded messages and reject expired, replayed, or
  mismatched ceremony state without trusting provider metadata.
- [x] `ENR-504` Publish an owner-authorized shared manifest with one exact-key
  wrapper for every active device.
- [x] `ENR-505` Independently verify first trust and select the same exact
  authenticated head on the joining device.
- [x] `ENR-506` Expose authenticated device names, roles, statuses, stable
  identifiers, and this Mac's recorded identity through human and JSON CLI
  output without invoking a private-key operation.
- [x] `ENR-507` Generalize owner-approved enrollment beyond the first two
  Macs.
- [x] `ARCH-508` Select the permanent device-wrapped, session-only key model
  and the deliberate breaking-alpha transition.
- [x] `KEY-509` Implement the permanent manifest, CryptoKit HPKE wrappers,
  one-device genesis, exact local manifest cache, wrapper-backed session
  unlock, checkpoint reads, and durable ordinary-content publication seams.
- [x] `KEY-509` Connect permanent genesis, migration, session-only unlock,
  reads, and recoverable ordinary writes to the shipping helper without
  persistent raw v3 key use.
- [x] `KEY-509` Qualify lock, helper restart, and the installed permanent
  runtime on a physical Mac.
- [x] `ENR-510` Use one owner-approved transition for first and later
  enrollment, rotate the key, re-encrypt the current snapshot, and remove the
  local-to-shared exception.
- [x] `ENR-510` Qualify first-to-second-device enrollment, lock, helper
  restart, and writes on physical Macs; cover third-and-later enrollment with
  the same automated transition and adoption tests. A third physical identity
  is opportunistic evidence rather than a beta blocker.
- [x] `ENR-511` Revoke a selected device, rotate the vault key, re-encrypt the
  current snapshot, and wrap the new key only for remaining active devices.
- [x] `ENR-511` Authenticate and apply ordered content and key-epoch catch-up
  before normal access, preserving explicit stale reads and fail-closed
  authority conflicts.
- [x] `REC-512` Add continuity status, one-device warnings, migration-cleanup
  guidance, and explicit permanent-loss behavior.
- [x] `AUTH-513` Remove owner/member roles, bump the prerelease profile and
  enrollment protocol to version 2, and authorize roster changes from any
  active device.
- [x] Reject replay, substitution, wrong-vault, and authority confusion.
- [x] Add the reviewed revoke-and-rotate command.
- [x] Re-encrypt on every membership change.

### Release Track

- [x] Set the `0.2.0` all-devices-lost policy: no catastrophe-recovery
  authority; provider bytes alone cannot recover the vault.
- [x] Implement and test continuity guidance and permanent-loss UX.
- [x] Provide actionable status, conflict, device, transaction-interruption,
  and recovery-required diagnostics. A catch-all `doctor` command and raw
  transaction/recovery inspection are not `0.2.0` gates; add narrower
  diagnostics later only when observed failures identify a user need.
- [x] Add conflict diagnostics, stable JSON status output, and machine-readable
  exit codes.
- [x] Validate local APFS and iCloud Drive plus realistic migration copies.
- [x] Document the implemented security model and recovery limits.
- [x] Consolidate the permanent role-free device-wrapped profile into an exact
  normative storage specification and update the machine-readable schemas.
  `STABLE-702` reconciled the schemas with production-generated canonical
  body and envelope fixtures.

## Decision Log

| ID | Status | Decision |
|---|---|---|
| `DEC-000` | Accepted | Use authenticated immutable manifest history and one serialized transaction owner. |
| `DEC-001` | Accepted | Require a derived-key HMAC on every manifest and a parent-owner Secure Enclave signature on authority-changing transitions. Use separate signing and wrapping keys. |
| `DEC-002` | Accepted | Use exact authenticated heads for mutation safety. Automatically reconcile independent path changes, preserve every concurrent value, and require explicit resolution only for genuinely incompatible changes. |
| `DEC-003` | Superseded by `DEC-033` | Define recovery when every enrolled device is lost. |
| `DEC-004` | Accepted | Directly qualify local APFS and iCloud Drive for `0.2.0`. Keep correctness provider-neutral and trust only authenticated immutable history, never provider ordering or mutable metadata. Other ordinary folder-backed providers may work when they preserve the required filesystem semantics, but they are not directly validated or covered by the `0.2.0` compatibility guarantee. Every configured root must still pass Key's containment, type, atomicity, hydration, and naming-safety checks. |
| `DEC-005` | Accepted | Make vault-root configuration changes helper-owned through the authenticated full-CLI XPC channel. Serialize the change after in-flight handler work, persist it, invalidate the warm key session, refuse later work from the stale handler, and shut the helper down after its successful reply. Re-read the configured root before other requests and fail closed if the file was changed or removed out of band. |
| `DEC-006` | Accepted | Give the CLI full authority and the utility status/lock authority on separate authenticated endpoints. |
| `DEC-007` | Accepted | Keep the signed nested helper, constrain launchd spawning, and re-register it on app upgrades. |
| `DEC-008` | Accepted | Keep canonical JSON independent of vault schemas in an internal SwiftPM target; do not claim or publish full RFC 8785 conformance until complete number handling, upstream vectors, fuzzing, and independent review are complete. |
| `DEC-009` | Accepted | Authenticate v3 entry identity as the entry-AAD domain label, a NUL delimiter, and canonical JSON over format, version, vault ID, entry ID, name, type, exact vault-key ID, and revision. Derive those values from authenticated manifest state when opening. |
| `DEC-010` | Accepted | Keep v3 entry parsing explicitly untrusted. Before releasing plaintext, require the authenticated manifest digest and manifest-derived context to match the canonical file, then open AES-256-GCM with the exact typed associated data and require UTF-8 plaintext. |
| `DEC-011` | Accepted | Implement v3 copy and rename as authenticated decrypt-and-reseal operations. Copy creates a fresh logical entry at revision 1; rename preserves the logical entry ID and advances its revision. Both preserve exact valid UTF-8 plaintext bytes, type, and exact key ID and require a fresh nonce. |
| `DEC-012` | Accepted | Treat authentication and freshness as separate gates. Persist one exact vault ID and manifest-envelope digest in the non-synchronizing device-local Keychain; advance it under the serialized helper mutation owner with an expected-checkpoint guard only after verifying authenticated ancestry. Require the freshness-approved manifest type for entry open, copy, and rename. |
| `DEC-013` | Superseded by `DEC-028` | Keep local manifests free of device-membership and wrapped-key records. Require shared manifests to retain at least one active owner and exactly one exact-current-key wrapper for every active device, with no wrapper for a revoked or unknown device. Defer membership-transition ceremonies to enrollment and revocation work. |
| `DEC-014` | Accepted | Make migration opt-in. Ship `key migrate --check` as a helper-owned, read-only v2 compatibility and decryptability check. A later writer must stage and verify v3 beside the untouched v2 source, select it only through an authenticated-head commit and device-local checkpoint transition, and retain v2 until verified reopen and explicit cleanup. |
| `DEC-015` | Accepted | Treat the unreleased prototype as a migration exclusion, not a permanent runtime compatibility mode. `key migrate --check` refuses the exact root-level `.key-vault.json` marker before loading a key, while ordinary v2 reads remain unchanged and the strict v3 parser rejects prototype JSON. |
| `DEC-016` | Accepted | Establish vault-root authority by opening the configured file URL once through Swift System's `FileDescriptor` with directory-only, no-follow, and close-on-exec semantics. Retain that descriptor and its device/inode identity for the lifetime of the filesystem session; later contained operations must resolve relative to the descriptor instead of trusting the configured path again. |
| `DEC-017` | Accepted | Accept only canonical, nonempty relative child paths. Open one component at a time from the trusted root with `openat`, no-follow, close-on-exec, and directory-only semantics for every intermediate component. Verify that the terminal descriptor has the requested directory or regular-file type before use, and open special files nonblocking so an unexpected FIFO cannot stall the helper. |
| `DEC-018` | Accepted | Before granting retained-root descriptor access, reopen the configured root with the original no-follow rules and require the same device/inode identity. Keep resolved components on the root device; reject Finder aliases, firmlinks, multiply linked regular files, and dataless provider placeholders. Model provider name collisions explicitly: canonical Unicode equivalents always collide, and case variants collide when the selected provider is case-insensitive. |
| `DEC-019` | Accepted | Resolve mutation parents from the retained vault-root descriptor and pass terminal names directly to `renameat`, exclusive `renameatx_np`, or `unlinkat`. Limit replacement to validated regular files, make moves no-overwrite, and restrict cleanup to validated regular files or already-empty directories. These primitives guarantee local namespace containment and atomic rename behavior; the transaction engine and provider qualification remain responsible for synchronization and crash durability. |
| `DEC-020` | Accepted | Model synchronized vault history as immutable authenticated manifests named by exact digest. Genesis has no parents, ordinary commits have one, and later merge commits have a canonical sorted parent set. Derive current heads from authenticated reachability instead of trusting a synchronized mutable pointer. |
| `DEC-021` | Accepted | Keep graph mechanics out of the ordinary CLI. Automatically merge non-overlapping changes, continue unaffected reads during content conflicts, pause mutations for genuine ambiguity, and provide explicit status and conflict commands with stable machine-readable outcomes. |
| `DEC-022` | Accepted | Reserve `--force` for confirmation and overwrite policy; it never bypasses trust, expected-head, completeness, rollback, or conflict checks. Permit stale reads only through an explicit `--allow-stale` request and never permit stale writes. |
| `DEC-023` | Accepted | Define `keyID` as canonical base64url of HKDF-SHA256 over the exact 32-byte vault key, salted by canonical vault UUID bytes with `work.tvr.key/v3/vault-key-id` as the domain-separated info label. Require supplied keys to match this authenticated ID before manifest authentication or entry encryption/decryption. |
| `DEC-024` | Accepted | Store immutable manifest and entry objects under lowercase hexadecimal SHA-256 filenames so content addressing remains collision-safe on case-insensitive providers. Discover history read-only from the exact device-local checkpoint, reopen its digest-linked ancestors, fully authenticate forward descendants, and expose a typed ancestry proof only when every referenced object is complete and valid. Treat missing or dataless provider objects as incomplete transport, referenced invalid objects or exhausted bounds as recovery-required state, and unrelated invalid objects as non-authoritative noise. |
| `DEC-025` | Accepted | Reconcile complete authenticated history by stable entry ID against one unique nearest common ancestor. Automatically combine zero or one valid advancing change per entry across any number of heads, but preserve revision rollback, same-revision substitution, edit/edit, delete/edit, rename-plus-edit, conflicting rename, destination, security-state, and criss-cross-base ambiguity as typed conflicts. Enforce revision monotonicity again when authenticating a parent-to-child transition; a merge may reuse only an exact, unambiguous highest parent revision. Treat rename-plus-edit conservatively because opaque ciphertext resealed under name-bound AAD cannot prove that the rename branch preserved the ancestor value. |
| `DEC-026` | Accepted | Publish a v3 transaction only inside the serialized mutation owner. Stage canonical immutable entry and manifest bytes under a local operation ID, recheck the exact authenticated checkpoint and head set, publish entries through exclusive digest-path renames, reopen every referenced entry, publish and reopen the manifest last, then advance the device-local checkpoint with an expected-value guard. Staging has no authority and remains available for later recovery. A remote head arriving after the final recheck creates an ordinary immutable branch rather than overwriting either history. |
| `DEC-027` | Superseded in part by `DEC-028`–`DEC-034` | Complete first trust through an explicit digest-selected, independently compared two-device ceremony. Filter synchronized candidates by the exact transcript and inviter signature before Secure Enclave unwrap, bind the exact recipient and key identity into authenticated wrap context, rerun the narrow local-to-shared verifier with the recovered key, install only absent-or-identical local key and checkpoint state, authenticate through the shipping reader, and write the device-local `vault_id` last. Treat consumed joiner state as an exact retry marker rather than provider authority. The comparison and select-last guarantees remain; persistent raw-key installation and the local-to-shared exception do not. |
| `DEC-028` | Accepted | Use one device-managed vault profile from genesis. A new vault begins with one active owner and one durable current-key wrapper; first and later enrollment use the same roster-addition transition. |
| `DEC-029` | Accepted | Never persist or synchronize a raw v3 vault key. Store only device-bound Secure Enclave key representations, exact checkpoint trust, a digest-verified manifest cache, and bounded local workflow state. Keep the opened vault key only in Key Agent's short-lived memory session. |
| `DEC-030` | Accepted | Replace the prerelease custom wrapper with RFC 9180 HPKE through CryptoKit using P-256, HKDF-SHA256, and AES-GCM. Bind a self-contained canonical wrapper context to the vault ID, exact key ID, authenticated authority-transition ID, recipient device ID, format, version, and suite. Use a random transition ID for genesis and derive enrollment transition IDs from the complete compared transcript. Raise the minimum deployment target from macOS 13 to macOS 14, where CryptoKit HPKE and its Secure Enclave P-256 conformance become available, instead of retaining a custom cryptographic fallback. |
| `DEC-031` | Accepted | Rotate the vault key and re-encrypt the complete current snapshot on every device-roster addition or removal. Preserve logical entry revisions during a pure owner-authorized reseal, while ordinary same-revision substitution remains invalid. |
| `DEC-032` | Accepted | Cache the exact checkpoint manifest in device-local Key-owned storage so routine unlock does not depend on provider hydration. The cache carries no authority unless its SHA-256 digest and vault ID match the non-synchronizing device-local checkpoint. |
| `DEC-033` | Accepted | Ship `0.2.0` with device continuity but no catastrophe-recovery authority. Recommend at least two enrolled devices; let a surviving device enroll a replacement and revoke a lost device; and state that provider bytes alone are not a recoverable backup. Losing every enrolled device means permanent loss without a password, cloud escrow, support override, or hidden fallback. Evaluate two independent PIV P-256 recovery keys for a later minor release without making their schema part of the stable `0.2.0` promise. |
| `DEC-034` | Accepted | Treat the current local/shared raw-key alpha profile as intentionally replaceable prerelease state. Give the permanent profile an unambiguous required discriminator, clearly refuse old alpha state, support explicit reset/remigration where possible, and retain no indefinite dual cryptographic reader or writer. |
| `DEC-035` | Accepted | Before the permanent profile stabilizes, supersede the role-dependent parts of `DEC-001`, `DEC-028`, `DEC-031`, and `DEC-033`: remove owner/member roles from manifests, enrollment transcripts, and user-facing device state. Every active enrolled device has equal authority to enroll or revoke a device after explicit local-presence, comparison, and confirmation checks. Keep only active/revoked status, require at least one active device, and use required prerelease profile/protocol version `2` so role-bearing alpha state is rejected rather than silently reinterpreted. |

## Validation Matrix

- [x] Canonical manifest and entry-context encoding tests.
- [x] Negative authentication tests for every bound field.
- [x] Copy/rename identity, revision, collision, and exact-byte resealing tests.
- [x] Exact-head and single-parent replay tests without manifest generations.
- [x] Canonical multi-parent ordering, complete-parent-set, foreign-parent,
  and authority-conflict tests.
- [x] Local/shared membership and exact-current-key wrapped-key consistency tests.
- [x] Parent-to-child revision advancement and reconciliation rollback tests.
- [x] V2 migration-preflight compatibility, decryptability, and no-write tests.
- [x] Prototype migration-marker and v3 parser rejection tests.
- [x] Trusted vault-root type, no-follow open, retained-identity, and close-on-exec tests.
- [x] Component-by-component relative resolution, traversal rejection, symlink rejection, and terminal-type tests.
- [x] Vault-key ID derivation, substitution, and cross-vault separation tests.
- [x] Enrollment and key-identity replay tests.
- [x] Exact HPKE context, `info`, authenticated-data, framing, mutation,
  wrong-recipient, and round-trip evidence. CryptoKit controls randomized
  sender ephemeral material, so this does not claim an independently verified
  ciphertext vector.
- [x] One-device genesis and wrapper-only unlock tests proving no raw v3 key
  survives lock or helper restart.
- [x] Membership-addition and revocation tests proving new devices cannot open
  prior epochs and revoked devices cannot open the new current snapshot.
- [x] Offline multi-epoch catch-up, missing-transition, and competing-rotation
  unit tests.
- [x] Physical multi-device catch-up through provider delay and key rotation
  in the alpha.7 through alpha.10 release exercises.
- [x] Recovery-kit and all-devices-lost recovery tests are explicitly not
  applicable to `0.2.0`, which has no catastrophe-recovery authority. PIV and
  other recovery candidates remain a later-minor-release track.
- [x] Installed XPC tests for intended and unintended signing identities.
- [x] Mutation/key-transition concurrency tests.
- [x] Transaction fault injection at every phase.
- [x] Root substitution, filesystem alias, provider-placeholder, and provider-name collision tests.
- [x] Descriptor-relative replace, exclusive move, and non-recursive cleanup tests.
- [x] Helper-owned vault-root change, stale-session refusal, and out-of-band configuration tests.
- [x] Serialized mutation ownership, canonical operation-ID, and mutation-routing tests.
- [x] Deterministic multi-head reconciliation, exact conflict-version,
  destination-collision, authority-divergence, and criss-cross-history tests.
- [x] Expected-head, entry-first, no-overwrite, durable-object, and
  manifest-last publication tests.
- [x] Shipping v3 runtime selection, exact read, stale read, conflict read,
  no-key-creation, and read-only enforcement tests.
- [x] Local-v2 migration and rollback tests.
- [x] Revocation tests with retained old keys.
- [x] Recovery tests for unavailable provider content and corrupt or
  conflicting state.

## Release Gates

### Alpha Release Checkpoints

These prereleases deliberately expose one new security boundary at a time. An
alpha is cut before implementation begins on the next checkpoint so regressions
can be attributed to a narrow change. Expected build numbers assume no
intervening release; `CURRENT_PROJECT_VERSION` remains an automatically
incremented internal counter rather than part of the public version identity.

`v0.2.0-alpha.1` was [withdrawn on July 28,
2026](https://github.com/tvanreenen/key/releases/tag/v0.2.0-alpha.1), and its
installation assets were removed. Its legacy mode-change path could accept a
vault key after authenticating only one entry; a vault whose entries had been
sealed under different keys could therefore retain inaccessible entries. The
release record remains available as the recovery warning and historical source
of truth. This failure drove the replacement design toward exact vault and key
identities, whole authenticated state, fail-before-mutation transitions, and
explicit migration rather than another implicit synchronized-key repair.

| Version | Expected build | Status | Checkpoint |
|---|---:|---|---|
| `v0.2.0-alpha.1` | 6 | Withdrawn | Retained release record and version 2 incident baseline; installation assets removed |
| `v0.2.0-alpha.2` | 7 | Released | Contain unsafe legacy version 2 key adoption and ship the authenticated version 3 reader while version 2 remains the default and every version 3 writer stays disabled |
| `v0.2.0-alpha.3` | 8 | Released | Add explicit, opt-in local version 2 to version 3 migration and verified bootstrap |
| `v0.2.0-alpha.4` | 9 | Released | Add device enrollment and multi-device read-only sharing |
| `v0.2.0-alpha.5` | 10 | Released | Resume the exact authenticated owner-approved enrollment after invitation expiry or delayed provider delivery |
| `v0.2.0-alpha.6` | 11 | Released | Enable guarded multi-device writes and conflict resolution |
| `v0.2.0-alpha.7` | 12 | Released | Introduce the side-by-side Preview track and ship the permanent device-wrapped profile for physical multi-device qualification without replacing Stable Key |
| `v0.2.0-alpha.8` | 13 | Released | Add revocation, remaining-device catch-up, equal enrolled-device authority, and continuity and permanent-loss UX |
| `v0.2.0-alpha.9` | 14 | Released | Distinguish a revoked local device from damaged vault state and direct it toward replacement through a surviving active Mac |
| `v0.2.0-alpha.10` | 15 | Released and physically qualified | Ship and physically qualify restart-safe revoked-device cleanup and ordinary re-enrollment on two Macs |
| `v0.2.0-alpha.11` | 16 | Released and physically qualified | Revalidate replacement invitations before cleanup, bound helper-restart waits with safe same-command recovery, and complete the practical local-APFS and two-device iCloud beta provider gates |
| `v0.2.0-beta.1` | 17 | Released and physically qualified | Complete provider qualification, migration and rollback validation, continuity and permanent-loss documentation, signing checks, and the required security-review gates |

Urgent fixes may add an intervening prerelease and advance the build counter,
but they do not redefine the security checkpoint assigned to a version above.
Update this table whenever a checkpoint ships or its scope changes.

#### Alpha.6 Release Qualification

The signed and notarized alpha.6 build was installed through the opt-in
Homebrew alpha channel on both enrolled Macs. The complete Swift suite passed
432 tests across 40 suites before release. Installed app, CLI, and helper
signatures, Gatekeeper assessment, notarization, helper registration, and
build-version alignment passed on the release artifacts.

The two-device iCloud Drive exercise then verified:

- one disposable write on each Mac was delivered, authenticated, and decrypted
  by the other Mac;
- simultaneous edits to one disposable entry produced one authenticated
  `edit_edit` conflict rather than a silent winner;
- the conflicted entry released no default plaintext while an unrelated entry
  remained readable;
- both exact versions could be inspected and authenticated before one was
  explicitly selected;
- the resolution converged on both Macs, and cleanup restored the original
  entry count with zero conflicts and both disposable entries absent; and
- recovery source, configuration, Git state, and retained backups remained
  unchanged throughout the exercise.

Provider caveat: one final iCloud convergence remained temporarily unavailable
until the user manually retriggered provider upload on the originating Mac.
Key remained fail closed, released no ambiguous plaintext, and performed no
speculative mutation while delivery was incomplete. The retry completed normal
authenticated convergence. This qualifies iCloud Drive for the current alpha
smoke-test scope; it does not turn provider timing into a Key correctness input
or establish support for other providers.

#### Alpha.7 Release Qualification

The signed and notarized alpha.7 build was published as the first isolated
Preview release. Homebrew installed `Key Preview.app` and `key-preview` on both
physical Macs without replacing Stable Key's app, CLI, helper identity,
configuration, Keychain namespace, or vault selection. Strict signatures,
provisioning and entitlement allowlists, hardened runtime, stapling,
Gatekeeper, artifact identity, helper registration, and version/build
alignment passed. The release branch's full Swift suite passed 581 tests.

The physical exercise used a new disposable iCloud Drive vault and verified:

- explicit migration of one version 2 entry to the permanent device-wrapped
  profile while retaining the version 2 source unchanged;
- one-device status, read, ordinary write, lock, complete helper termination,
  restart, Secure Enclave authentication, and wrapper-backed unlock;
- an independently matched enrollment code and exact owner/joiner device pair;
- owner-approved key rotation, complete snapshot resealing, one wrapper for
  each active device, and joining-device acceptance;
- authenticated reads of both owner-written values on the joining Mac;
- joining-device lock, helper restart, Secure Enclave unwrap, and one ordinary
  member write; and
- unchanged Stable configuration and protected vault aggregates throughout,
  with zero offline, dataless, symlink, or special provider objects.

The member write and its parent manifest uploaded successfully and arrived on
the owner Mac as materialized, digest-matching immutable objects. Alpha.7
correctly kept the owner on its exact device-local checkpoint instead of
trusting newly arrived bytes, so the owner did not expose the new value or
publish a competing write. The catch-up implementation now provides the
authenticated advancement that alpha.7 lacked; it remains unshipped and must
pass this same two-device exercise before the next Preview release.

#### Alpha.10 Release Qualification

The signed and notarized alpha.10 build was installed through the opt-in
Homebrew alpha channel on both physical Macs. Gatekeeper accepted the installed
Preview app, the app, CLI, and helper all reported version `0.2.0-alpha.10`
build `15`, and Stable Key and protected vault baselines remained outside the
exercise.

The disposable iCloud Drive replacement exercise then verified:

- the surviving Mac authenticated the old Air identity as revoked while the
  revoked Air retained the older trusted checkpoint needed to review the exact
  direct-child revocation;
- a fresh invitation, exact vault and identity review, and literal `REJOIN`
  confirmation were revalidated immediately before destructive local cleanup;
- cleanup changed no synchronized vault files, helper termination completed,
  and the ordinary join retry published a new identity on the first attempt;
- both Macs displayed the same existing/joining device pair and comparison
  code before approval and acceptance;
- the old Air identity remained revoked, the new distinct Air identity became
  active, and continuity returned to two active devices on both Macs;
- an Air-originated disposable write was authenticated and decrypted on the
  mini, its mini-originated removal converged back to the Air, and the original
  four-entry baseline was restored; and
- locking the newly enrolled Air stopped its helper cleanly, after which
  launchd restarted it on demand and status, roster inspection, and a baseline
  decrypt all succeeded.

The CLI correctly refused an owner-side `share compare` attempt on the joining
Mac as the wrong ceremony role. The joining Mac's signed join output and the
surviving Mac's independently derived comparison output supplied the bilateral
code check.

### Beta.1 Work Packages

Beta qualification closes specific user-risk gaps; it does not repeat every
successful alpha exercise or require hardware that is impractical to obtain.
Local APFS and iCloud Drive are the complete supported-provider matrix for
`0.2.0`. Third-and-later enrollment must continue to pass its automated
multi-device transition and adoption coverage, while another physical Mac is
opportunistic evidence rather than a release gate.

| ID | Status | Exit criteria |
|---|---|---|
| `BETA-601` | Complete | Migrate disposable copies of a small clean v2 vault, a realistic large mixed-entry vault, and deliberately invalid inputs. Compare names, types, and value hashes without logging plaintext; prove the v2 source is byte-identical, v3 selection happens last, no raw v3 key persists, and the same Stable-variant runtime can reopen its untouched v2 source as the supported rollback. |
| `BETA-602` | Complete | Deterministically expire the invitation while the replacement confirmation is open and delay helper termination beyond the client wait. Prove no cleanup follows expiry and the bounded-timeout path resumes safely through the same join command. |
| `BETA-603` | Complete; split evidence | Verify the exact notarized candidate's signing, installation, helper registration, cold start, and enrolled-vault inventory; run the same checkout through the isolated installed local-APFS identity for migration, ordinary mutation, lock/restart, rollback, and final inventory; and bind deterministic interruption/conflict tests to the same source. This split is required because both physical Preview profiles are enrolled and repointing either would destroy its non-exportable local identity. |
| `BETA-604` | Complete | Run one concise installed-build iCloud regression covering two-device catch-up, one cross-device write and removal, lock/restart, exact roster continuity, and fail-closed behavior during incomplete delivery. Prior alpha.6, alpha.7, and alpha.10 exercises remain the broader evidence base. |
| `BETA-605` | Complete | Make supported providers, two-device continuity, revocation, replacement, invitation lifetime, provider-only non-recovery, and all-devices-lost permanent loss explicit in CLI help and user documentation. |
| `BETA-606` | Complete | Complete a focused security review of identity binding, ceremony substitution, comparison transcripts, revocation and key rotation, replacement cleanup authorization, durable retry state, checkpoint rollback, filesystem containment, and persistent raw-key absence. |
| `BETA-607` | Complete | Pass the full suite and release scripts; verify signatures, entitlements, hardened runtime, notarization, stapling, Gatekeeper, the Homebrew alpha-to-beta channel transition, Stable isolation, helper registration after reboot, and app/CLI/helper version alignment. |

`BETA-606` focused-review ledger:

- [x] `BETA-606A` — Replacement cleanup invitation binding. The replacement
  review digest correctly commits to the exact residual identity, identity
  record digest, vault, checkpoint or revocation authority, and authorizing
  device. The helper also re-observes that complete review inside its serialized
  mutation boundary before the first destructive transition. However, the CLI
  revalidates the selected invitation in one helper request and then sends a
  cleanup request containing only the replacement-review digest. The cleanup
  boundary therefore cannot prove which invitation was just validated or that
  it remains valid. Bind the exact invitation digest into the initial cleanup
  request and validate it in the helper immediately before starting cleanup.
  The confirmation transcript now binds the exact replacement-review and
  invitation digests; substitution and cleanup-boundary expiry fail before the
  replacement service is invoked. Prepared cleanup still requires a live exact
  invitation, while durable destructive progress uses a distinct admission
  state and the existing invitation-free, idempotent resume path. The focused
  replacement, CLI, and XPC suites pass, as does the 750-test serial suite.
- [x] `BETA-606B` — Comparison-transcript identity binding. No production flaw
  was found. The domain-separated transcript digest commits to canonical
  invitation and join-request digests, which in turn bind the vault and format,
  exact parent manifest, invitation expiry, both nonces, and both devices'
  display names, signing keys, and wrapping keys. The separately signed
  carriers are verified again when local ceremony state is loaded. Compare,
  approve, and accept reconstruct the transcript from that exact pinned state;
  the human-entered 80-bit code is checked locally, while the complete 256-bit
  digest binds owner approval, the authenticated authority-transition ID,
  joining-device adoption, and ceremony consumption. Regression coverage now
  changes each display name without changing its keys and proves a wrong human
  code leaves the owner ceremony byte-for-byte untouched.
- [x] `BETA-606C` — Revocation authorization and key rotation. The planner and
  independent publication validator require an exact authenticated checkpoint,
  an active local authorizer, one different active target, and at least one
  surviving active device. Rotation uses a distinct 32-byte key and authority
  transition ID, reseals the complete plaintext-preserving entry snapshot,
  emits wrappers for exactly the remaining active roster, and advances the
  checkpoint only after staged and published bytes are revalidated. The review
  token previously bound the checkpoint and target but not which active device
  the UI named as authorizer; version 2 now binds that exact authorizer ID, and
  regression coverage rejects authorizer substitution with the checkpoint and
  target held fixed.
- [x] `BETA-606D` — Durable retry state and checkpoint rollback protection. No
  production flaw was found. A device-local, non-synchronizing recovery anchor
  commits to the SHA-256 digest of one canonical shared intent; that intent
  binds the operation and mutation kind, vault, exact parent checkpoint and
  heads, candidate manifest, and every staged entry. Recovery accepts only the
  anchored parent or candidate checkpoint, reauthenticates the immutable
  candidate and complete entry snapshot, checks current repository ancestry
  and usage, and advances by expected-value replacement only after published
  bytes are verified. Changed checkpoints abandon only owned staging and are
  never overwritten. Interruption matrices already cover content, enrollment,
  and revocation publication; new filesystem regression coverage substitutes a
  different canonical intent and proves the digest-bound anchor preserves the
  parent checkpoint, retains recovery state, and publishes nothing.
- [x] `BETA-606E` — Filesystem containment and path substitution. No production
  flaw was found. Vault authority is retained as an open directory descriptor
  plus device/inode identity; the configured root is revalidated before each
  operation. Descendants are canonical relative paths opened component by
  component with no-follow, close-on-exec, type, device, dataless, firmlink,
  Finder-alias, and regular-file link-count checks. Writes use exclusive
  descriptor-relative temporary creation and atomic rename, immutable
  destinations never overwrite different bytes, and cleanup uses exact-byte
  checks plus nonrecursive `unlinkat`. Existing tests cover invalid paths,
  symlinks, hard links, special files, cross-filesystem metadata, root and
  transaction-directory replacement, preexisting hostile temporary names, and
  process interruption. New recovery-store coverage proves an exact-path
  symlink cannot redirect cleanup or alter its external target.
- [x] `BETA-606F` — Persistent raw-key absence. No production flaw was found.
  Permanent-profile raw vault keys exist only while being generated, unwrapped,
  validated, or held by the expiring in-memory session. Repository entries are
  AES-GCM ciphertext; manifests contain derived key IDs and RFC 9180 HPKE
  wrappers; checkpoints, caches, recovery anchors and intents, replacement
  state, and diagnostics contain only authenticated public metadata, encrypted
  material, or non-secret digests. Secure Enclave identity records persist
  opaque key representations, not vault keys, and the legacy v2 keychain-backed
  profile remains outside this permanent-profile claim. Existing enrollment
  coverage proves both rotation keys are absent from its recovery intent and
  local anchor. New revocation coverage interrupts after every candidate object
  is staged, then scans all durable repository and transaction files plus the
  local anchor, checkpoint, and cache for raw, Base64URL, or hexadecimal forms
  of both the old and rotated vault keys.

`BETA-607` release-verification ledger:

- [x] The clean `main` candidate was fetched against `origin/main`, which had
  not advanced, and versioned as `v0.2.0-beta.1` build 17 in commit `2449cca`.
  The full serial Swift suite passed with 754 tests in 70 suites. The Homebrew
  cask-channel and Preview install-safety script suites also passed.
- [x] The universal Preview archive used the Developer ID Application identity
  for team `9Q355KSV85` with hardened runtime enabled. The app, CLI, and helper
  signatures and strict entitlement allowlists passed. The app and helper use
  the Preview-specific identifiers, helper service, and Keychain access group.
- [x] Apple notarization submission
  `57711752-af7f-49c4-ada1-ea5fa59ad32b` was accepted on 2026-08-17. Stapling,
  Gatekeeper assessment, and independent verification of the extracted final
  ZIP passed. The app, CLI, and helper all report `0.2.0-beta.1` build 17. The
  final `Key-Preview-v0.2.0-beta.1.zip` SHA-256 is
  `8216afea14a4de764b0b844f2c6ff30c035b0ce7eb510bece7f02aa8e81b5b64`.
- [x] The exact verified ZIP was published as the GitHub prerelease
  `v0.2.0-beta.1`, and only the new `key@beta` cask was published from tap
  commit `13cc21f`. On the first physical alpha installation, Homebrew removed
  only `key@alpha` and installed `key@beta`; the transition was correctly
  treated as a mutually exclusive channel change, not an in-place upgrade.
- [x] On the first physical Mac, Gatekeeper accepted the installed beta as
  Notarized Developer ID software. The app and CLI report beta.1 build 17, the
  Preview helper registered and ran, and the enrolled v3 vault reopened with
  the same four entries and trusted version `d294566947db67dc`. Stable remained
  installed at 0.1.2 build 6 with its distinct app identity. SHA-256 inventories
  of every Stable and Preview config and checkpoint file were byte-identical
  before and after the channel change.
- [x] After a 2026-08-17 16:32:03 reboot, launchd retained the Preview helper
  registration while leaving it stopped and uninitialized before first use.
  The first beta CLI status started the helper on demand and returned ready,
  zero conflicts, the same four names, and trusted version
  `d294566947db67dc`. Gatekeeper and strict app/CLI/helper signature validation
  still passed; the app, CLI, and helper remained beta.1 build 17; Stable
  remained 0.1.2 build 6; and every recorded Stable and Preview config and
  checkpoint hash remained byte-identical.
- [x] The existing enrolled MacBook Air completed the same non-destructive
  `key@alpha` to `key@beta` transition. Its app, CLI, and helper report beta.1
  build 17; strict signing and Gatekeeper pass; Stable remains 0.1.2; and its
  config and checkpoint hashes are unchanged. Both Macs report ready, zero
  conflicts, the exact same four names, and trusted version
  `d294566947db67dc`. The Air's three immutable provider objects beyond an older
  baseline all predate this transition and are the already-qualified alpha.11
  add/remove history; no provider file was created during the beta transition.
  No three-device gate was introduced.

`BETA-601` coverage inventory:

- [x] Read-only preflight covers empty and valid vaults plus incompatible
  names, unreadable files, unsupported formats, invalid payloads, wrong keys,
  invalid TOTP seeds, prototype metadata, and missing keys without repair or
  mutation.
- [x] Permanent genesis tests cover immutable entry-first publication,
  manifest-last publication, device-wrapper verification, checkpoint/cache/
  session installation, permanent-runtime reopen, exact source recheck,
  local-state recheck, and selection last.
- [x] Every observable preselection interruption leaves v2 selected and clears
  the in-memory v3 session key; source and checkpoint changes before selection
  fail closed.
- [x] A realistic 300-entry nested snapshot with 240 secrets and 60 TOTP
  entries migrates through the filesystem publisher, preserves every exact v2
  source byte, verifies the permanent manifest inventory, and leaves no
  staging directory. Run this scale gate explicitly with
  `scripts/test-migration-qualification.sh`; it stays out of the ordinary
  parallel suite so its filesystem and cryptographic load cannot distort
  timing-sensitive lifecycle tests.
- [x] The Debug-only installed qualification identity uses a distinct parent
  app ID, helper ID, Keychain service, vault account, Application Support
  directory, default vault, LaunchAgent label, and Mach services. Its CLI
  retains Stable's CLI identity and its helper retains Stable's Keychain access
  group so authenticated XPC, Keychain, and Secure Enclave execute through the
  real boundaries without macOS resolving a qualification service to Stable,
  Preview, or another qualification install. See
  [migration qualification](migration-qualification.md).
- [x] On 2026-08-17 the installed harness rejected both preflight and apply for
  a deliberately corrupted encrypted source without selecting v3 or changing
  source/config bytes. It migrated and independently reopened an 8-entry mixed
  corpus and a 300-entry nested corpus with 240 secrets and 60 TOTP entries.
  Both successful runs preserved exact v2 bytes, inventories, types, and all
  externally comparable value hashes, passed TOTP reads, lock, and cold helper
  restart, and found no generated plaintext in persistent qualification files.
- [x] Both successful installed runs restored the exact pre-migration
  qualification config after v3 verification. The same Stable-variant
  qualification runtime reopened the retained v2 sources with identical
  inventories and secret-value hashes.
  Before/after SHA-256 inventories of Stable and Preview Application Support,
  checkpoint caches, and default roots were identical in every scenario.

- [x] All security and durability invariants pass.
- [x] The v3 reader ships before any v3 writer is enabled.
- [x] Local APFS passes its scoped installed-build beta qualification.
- [x] iCloud Drive passes its scoped installed-build beta qualification.
- [x] Protected writes pass in the release environment.
- [x] Migration and rollback pass with realistic disposable vault copies.

`BETA-602` coverage inventory:

- [x] The CLI test clock advances from the invitation's inclusive expiry
  boundary to one second after expiry while `readLine` is servicing the open
  `REJOIN` prompt. The CLI reissues the exact join request, reports expiry, and
  never sends replacement cleanup.
- [x] The helper test independently advances its injected clock between two
  exact join requests. Its second invitation validation fails before another
  replacement review or any cleanup confirmation reaches the replacement
  workflow.
- [x] The XPC connection-end signal is deterministically withheld beyond a
  zero-duration test bound, exercising the same bounded wait used by the
  30-second production policy without a wall-clock sleep.
- [x] The CLI fault test receives the production post-completion timeout error
  after cleanup has durably completed. Repeating the same join command enters
  the enrollment-pending path, publishes the join request, and does not repeat
  destructive cleanup.

`BETA-603` coverage inventory:

- [x] The notarized `v0.2.0-alpha.11 (16)` Preview candidate from `81502fb`
  passed signing, entitlements, hardened-runtime, stapling, Gatekeeper, product
  identity, and final-artifact verification. Apple accepted notarization
  submission `278efaad-ab65-44d9-b8b6-c774d221f188`; the ZIP SHA-256 is
  `8ff1bab3824ccc98988aaa7f05219d36073b2f629e377fb24d7e2a8250d9ef6c`.
- [x] The exact candidate upgraded the mini's installed Preview while
  preserving its enrolled iCloud configuration. After narrowly removing a
  stale same-ID DerivedData app and refreshing only Preview's SMAppService
  record, the helper received a fresh BTM UUID, cold-started on demand, and
  reported version 3 ready with the exact four-entry trusted inventory.
- [x] Stable and Preview configuration SHA-256 values remained
  `4053db468914ad2922a251bb23625d54afdbe5c3719ff1d63da5b38d56d88aff`
  and `120df0d01843a33709b161e0f281b4fcf70e90b0adebf5980b617b2d5f0d6d3c`.
  The 31 enrolled Preview vault files retained modification times no later
  than the prior 2026-08-16 qualification.
- [x] A fresh `beta603c-small` installed qualification identity built from the
  alpha.11 checkout migrated an eight-entry mixed local-APFS vault, matched
  every inventory and externally comparable value hash, completed a real v3
  add/read/remove round trip, restored the exact pre-mutation inventory,
  locked, cold-restarted its helper, reopened the retained v2 rollback, found
  no generated plaintext in persistent files, and proved Stable/Preview files
  byte-identical before and after.
- [x] Fourteen focused content-mutation and publisher tests pass on the same
  source, including authenticated ordinary commands, explicit conflict
  choice, independent-head merge, every injected interruption phase resolving
  to a complete old or new checkpoint, competing-checkpoint abandonment,
  substituted-staging rejection, and exact candidate-key binding.
- [x] The seam is explicit: the exact notarized product identity covers the
  shipping signature/install/SMAppService path, while the current-checkout
  qualification identity covers disposable local APFS and Secure Enclave
  state. No claim is made that the notarized Preview identity itself was
  repointed away from its enrolled iCloud vault.

`BETA-604` coverage inventory:

- [x] `v0.2.0-alpha.11 (16)` was published as a GitHub prerelease at tag
  `c64fe13` with the accepted notarized artifact, then the `key@alpha` cask was
  updated and published from tap commit `fef2ee2`. Both Macs upgraded through
  Homebrew from alpha.10 to the same SHA-256 artifact.
- [x] On both Macs, Gatekeeper accepted the Notarized Developer ID app; strict
  host-context validation passed for the app, bundled CLI, and helper; all
  three components reported alpha.11 build 16; and the helper registered under
  Preview's expected parent ID and build. A restricted-command `codesign`
  false negative on the mini was rejected only after the same sandbox also
  reported an Apple system app untrusted; the required host-context checks
  independently passed on both Macs.
- [x] Both Macs began ready at trusted version `25010d3cdb97120f` with the
  same exact four-entry inventory. The Air published one disposable entry,
  read it locally, and the mini caught up to trusted version
  `c59459b710e82fac`, decrypted the exact non-sensitive test value, and removed
  only that entry.
- [x] Both Macs converged on trusted version `d294566947db67dc`, the disposable
  entry returned entry-not-found, and the original four-entry inventory was
  exact. Stable and Preview configuration stayed unchanged; the enrolled vault
  gained only the expected immutable disposable entry revision and its
  authenticated add/removal history.
- [x] The Air locked alpha.11, its helper stopped with exit zero, and an
  on-demand cold start returned ready with the same four entries. Its roster
  still showed the mini active, old Air revoked, new/current Air active, and
  continuity two; a baseline decrypt succeeded with the previously recorded
  SHA-256 `ac78585ab6859aecee5cef5eecdfca1cd9d650ea06f98ec7abbe7125359e42ba`.
- [x] Twenty-eight focused repository, read-only-runtime, and read-plan tests
  pass on the released source, including missing parents and ancestry,
  delayed referenced entries, authenticated stale-read boundaries, corruption
  versus transport-unavailable classification, and fail-closed incomplete or
  recovery-required states. Physical provider corruption was not induced in
  the enrolled iCloud vault.

`BETA-605` coverage inventory:

- [x] Top-level CLI help names local APFS and iCloud Drive as the only
  supported version 3 storage, rejects other providers, and explains the
  fail-safe two-device continuity baseline.
- [x] CLI help states the 10-minute invitation lifetime, exact device/code
  comparison requirement, surviving-device replacement path, provider's lack
  of key or enrollment authority, and permanent loss after every enrolled Mac
  is gone, with no password, cloud, or support fallback.
- [x] The README's stale prerelease language is replaced with the current
  isolated Preview channel and links to a dedicated user-facing
  [security, continuity, and recovery](security-continuity-recovery.md) guide.
- [x] The guide explains supported-provider and incomplete-delivery behavior,
  equal enrolled-device authority, the two-device recommendation, invitation
  expiry, revocation key rotation, revoked-device `REJOIN` cleanup and safe
  retry, migration rollback limits, and provider-only non-recovery.
- [x] A focused CLI help regression test asserts all of those permanent-loss
  and continuity promises; all 56 parser tests pass.

- [x] Recovery limitations are visible in CLI help and documentation.
- [x] A third-party security audit is not a `0.2.0` release gate. The release
  must accurately disclose that it has extensive internal focused review,
  automated coverage, and two-device physical qualification but no independent
  third-party audit.
- [x] Signing, notarization, and installed-helper verification pass.

### Stable 0.2.0 Work Packages

Stable readiness is intentionally bounded by the hardware and provider matrix
that is practical for this project:

- two physical Macs are the complete physical device gate; third-and-later
  enrollment remains covered by the same automated transition/adoption tests;
- local APFS and iCloud Drive are directly qualified; another ordinary
  folder-backed provider may work but is not directly validated or covered by
  the `0.2.0` compatibility guarantee; and
- no third-party security audit is required. Do not imply one occurred; retain
  the completed `BETA-606` focused review and disclose the assurance boundary.

| ID | Status | Exit criteria |
|---|---|---|
| `STABLE-701` | Complete | Reconcile every stale unchecked release item against current evidence or an explicit scope decision; record the practical device, provider, recovery, diagnostics, and review boundaries without changing product behavior. |
| `STABLE-702` | Complete | Updated the normative permanent-profile specification and schemas to the shipping role-free profile and bound them to production-generated canonical fixtures; locked the exact deterministic HPKE context, `info`, and authenticated-data bytes while explicitly scoping out a randomized ciphertext fixture and independent implementation claim; and proved an ordinary content mutation and membership transition cannot interleave through the shared mutation owner. |
| `STABLE-703` | Pending | Completely overhaul the GitHub README as the Stable landing page. Clearly separate Stable and Preview, provide a tested quick start and migration path, describe directly validated versus not-directly-validated providers, make continuity and permanent loss visible, scope v2 and v3 claims correctly, link deeper documents, and align CLI help and user-facing provider language. |
| `STABLE-704` | Pending | Observe beta.1 in ordinary two-device use; resolve any findings; run the full suite and release scripts; choose an RC only if post-beta code or release behavior warrants one; then build, notarize, verify, and deliberately qualify the Stable artifact and explicit v2 migration/rollback boundary before publishing `v0.2.0`. |

`STABLE-701` reconciliation ledger:

- Existing BETA-601, BETA-603, and BETA-604 evidence closes realistic
  migration/rollback and the complete local APFS plus iCloud Drive provider
  matrix. No third physical device or additional provider is required.
- One-device genesis, exact wrapper-backed unlock, explicit lock, helper
  restart, session invalidation, and durable raw-key-absence tests close the
  older combined genesis/unlock item.
- Status JSON, typed exit codes, conflict inspection/resolution, authenticated
  device status, and explicit incomplete/recovery-required outcomes provide
  the actionable `0.2.0` diagnostics. A broad `doctor` surface is deferred
  until concrete beta usage shows a missing diagnosis.
- Catastrophe-recovery tests are inapplicable because recovery authority is
  deliberately absent from `0.2.0`; the PIV prototype remains separate.
- HPKE round trips, exact context encoding, field-substitution failures, and
  wrong-recipient tests exist. `STABLE-702` additionally locks the exact HPKE
  `info` and authenticated-data domain bytes, separator, and canonical context
  through the same production input path. CryptoKit generates the HPKE
  sender's ephemeral key internally, so an exact ciphertext fixture is not a
  stable output and cannot be supplied without adding a production test seam.
  Deterministic input fixtures, exact output framing, context-mutation and
  wrong-recipient failures, software-key round trips, and the completed
  Secure Enclave two-device qualification close the older vector item without
  claiming independent implementation verification.
- The shared mutation owner includes content, enrollment, revocation,
  catch-up, and recovery kinds. `STABLE-702` directly holds an ordinary content
  mutation open while a revocation mutation attempts to enter, proving the
  key/membership transition remains excluded until content mutation exits.
- The architecture document and checked-in JSON Schemas now define the
  shipping role-free profile, and a conformance regression test compares their
  exact object fields and discriminators with production-generated canonical
  body and envelope fixtures.

## Immediate Next Action

Perform the `STABLE-703` README overhaul while beta.1 remains in normal
two-device use, then complete the bounded `STABLE-704` Stable qualification.
Do not add a portable recovery authority, require a third physical Mac, or
expand the directly validated provider matrix as part of `0.2.0`
stabilization.
