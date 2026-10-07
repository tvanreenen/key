# PIV catastrophe recovery implementation plan

Current implementation tracker: 2026-10-06. The retained evidence summaries
are linked below. This is the authoritative completion plan for the
PIV recovery track; the v3 roadmap summarizes it rather than maintaining a
second set of work-package statuses.

Creating this plan does not approve its unresolved format decisions, hardware
writes, credential changes, real-vault conversion, or release publication.
The next work is integrated implementation, qualified with disposable vaults.

## Completion contract

After explicit registration, either independently enrolled primary or backup
YubiKey, its PIN, and the available encrypted vault files can restore all
supported entries onto a replacement Mac with no original Mac identity or
trusted checkpoint. No separate receipt, certificate file, registration-Mac
intent, cloud escrow, or management key is required during recovery. Local Mac
authentication creates fresh destination credentials. Recovery creates a new
vault, preserves its source, and does not claim to revoke old devices or copies.

Ordinary writes do not require a connected token. Every supported device
enrollment, revocation, key rotation, and conflict-resolution path preserves
current recovery access for active recipients or refuses publication. A newly
restored vault is explicitly unprotected until separately registered; it must
be possible to register it through the same supported workflow.

The owner-selected recovery design target is one deliberate PIN/touch approval
for source recovery, regardless of the number of intervening key changes.
Prefer one hardware decapsulation with remaining verification in software;
do not weaken PIN/touch policy or source authentication to achieve it. Fresh
destination Mac authentication remains separate. The selected experimental design uses a protected epoch signing key and the
existing Mac signature. The rejected signature-only design and comparison
findings are summarized in the AI review record. The owner authorized experimental implementation
following a fresh AI review, with accurate limits and explicit future migrations.
Human audit is recommended, not mandatory. Repeated per-epoch approvals remain
a comparison baseline, not the selected product experience.

Provider delivery, backup retention, and whether newer files were withheld are
the user's and provider's responsibility. Proving global latest state is not
an implementation or release gate. Key remains responsible for verifying the
selected anchored public commitments and authority transitions, authenticating
all restored current entries, detecting required missing objects and
visible conflicts, and never silently choosing an older complete state when
visible newer required state is incomplete. Any future salvage workflow is
separate from normal recovery. Removal excludes recipients from fresh keys on
the legitimate continuing lineage, not from constructing alternative history
using retained pre-removal dual capabilities. Visible authority conflicts require
refusal; hidden competitors cannot be identified with a stable older anchor.
Recovery does not recheck closed-epoch MACs, old entry AEAD/capsule correspondence,
or every historical plaintext-preserving reseal. Ordinary full checks remain.

Full completion means the integrated capability is implemented, reviewed,
qualified with two independent tokens on the supported Macs/OS versions, and
released through the normal Stable workflow with accurate user documentation.
A local passing test, functional Preview, or software-only result is not full
completion. Real-vault activation is opt-in and remains disabled until its
qualification gates pass.

## Baseline and remaining scope

The feasibility baseline passed with one token on two Macs. Native agreement,
encrypted-key opening, public-anchor readback, source-only frozen-checkpoint
restore, and token-free ordinary read/edit/reopen passed in a disposable flow.
See [the evidence summary](piv-feasibility-results.md) for provenance and limits.
The experiment sources and operational transcripts are archived locally, not
part of the product build or a supported command interface.

Retained internal domain code includes bounded public-object framing, the HPKE
receiver adapter, epoch capsule, recovery profile, anchored graph selection,
and complete current-snapshot verification. Integrated review, the product token
adapter, protected registration, lifecycle coverage, authenticated resume,
and adoption remain. One-token experiments do not qualify independent backup
recovery or PIN/touch enforcement.

## Tracking rules

Statuses are `planned`, `in progress`, `implemented`, `qualified`, and `released`.
`Implemented` requires integrated code and passing applicable software checks.
`Qualified` requires the package's stated physical, compatibility, or review
evidence as well. `Released` requires the exact artifact and publication record.
Use `blocked` only with a concrete dependency or external requirement, not as a
synonym for unfinished. Do not report an estimated completion percentage.

Each completed package gets a short evidence entry with commit or local diff,
test commands/results, artifact identity where applicable, remaining limits,
and the next package. Update this table and the evidence entry in the same work
increment. Pending reviews and owner decisions remain explicit. Existing
`REC-801` through `REC-803` describe the feasibility parent track; the IDs below
are the implementation packages, not new names for already completed probes.

| Package | Deliverable | Depends on | Status |
|---|---|---|---|
| `REC-804` | Format, authority, lifecycle, and compatibility contract | Baseline | In progress; experimental direction and AI review disposition recorded; internal exact adoption publication/resume implemented; integrated graph/platform and rollout acceptance remain |
| `REC-805` | Versioned recovery profile, contexts, codecs, fixtures, and validators | 804 | In progress; profile-3 domain codecs, contexts, proof construction/checks, and fixtures implemented; final acceptance and integrated review remain |
| `REC-806` | Token-anchored history selection and complete snapshot verification | 805 | In progress; bounded software selector and complete current-snapshot verifier implemented; native anchor provenance, integrated review, and restore-only input integration remain |
| `REC-807` | Product token binding, external administration, and credential lifecycle | 804 | In progress; reader, scoped agreement and configured key-policy checks implemented; all administration stays in owner-run vendor tools; external workflow, capabilities and physical qualification remain |
| `REC-808` | Authenticated registration and status, including interruption reconciliation | 805, 806, 807 | In progress; internal prepare/resume/finish, authenticated four-state status and reciprocal pending guards implemented; product composition, shipping-runtime barriers and physical qualification remain |
| `REC-809` | Recovery coverage through ordinary edits, branches, and resolution | 805, 808 | In progress; internal mutation service and reciprocal authority-service guards implemented; shipping-runtime barriers, product/CLI acceptance and integrated/native qualification remain |
| `REC-810` | Recovery coverage through key/device/recipient changes | 805, 808, 809 | In progress; internal publication/resume, owner/adoption sessions, exact review, full reseal catch-up and reciprocal lifecycle/software recovery checks are implemented; independent lifecycle AI review and its two rotation fixes are recorded; user confirmation and shipping product/native acceptance remain |
| `REC-811` | Integrated new-vault restore and authenticated resume | 806 | In progress; internal authenticated initial restore and exact resume now compose preparation, manifest-last publication, insert-only trust, ordinary-runtime reopening, configuration selection and ordered finalization; product dispatch/barriers, separate-process and physical acceptance remain |
| `REC-812` | CLI/helper integration and meaningful signed Preview vertical slice | 807, 808, 809, 810, 811 | In progress; public token/source review and restore/resume CLI/protocol, gated host/connection lifecycle, restart ownership admission, native factories and internal profile-3 Mac unlock/read adapter implemented; catch-up composition, remaining commands, live feature gating, shipping runtime and signed qualification remain |
| `REC-813` | Independent backup-token and full lifecycle qualification | 812 | Planned |
| `REC-814` | Security, OS/provider compatibility, and release qualification | 812, 813 | Planned |
| `REC-815` | Opt-in adoption, Stable publication, and support handoff | 814 | Planned |

Dependencies identify the implemented contracts needed to finish a package;
they do not require every later physical qualification before coding starts.
Scoped pure-code implementation may progress following the recorded AI review;
unresolved integrated contracts remain acceptance requirements for their owners.
Hardware runs and release/adoption gates require the stated qualification and
separate owner authorization.

## Delivery and audit history

A work package tracks an acceptance outcome, a PR bounds a cohesive review,
and a commit records a logical change. They are not one-to-one. Decide the
next PR boundary when its code path and verification are understood, not by
assigning one PR to each row or imposing a line-count quota. Keep related code,
tests, and necessary documentation together; separate independent design
decisions when that improves review.

Context-rich PR descriptions remain the audit narrative: package linkage,
rationale, consequential alternatives, verification, and unresolved limits.
The tracker records completion, not a duplicate PR description. Product
integration proceeds incrementally; 812 is the complete-workflow gate, not a
single deferred integration PR.

### Review stack, 2026-10-06

The accumulated implementation is partitioned at consecutive existing commit
boundaries and published through `gh stack` as GitHub stack 73. No implementation
commit was rewritten. The existing CLI/help PR remains ready for review; the four
recovery PRs are drafts assigned to the maintainer. Each targets the preceding
branch so its diff contains only that layer.

| PR | Review scope | Implementation boundary |
|---|---|---|
| [68](https://github.com/tvanreenen/key/pull/68) | Existing CLI/help changes, unchanged | `2adba7d` |
| [69](https://github.com/tvanreenen/key/pull/69) | Genesis preparation, recovery format, anchored history and current-snapshot verification | `22a431c` |
| [70](https://github.com/tvanreenen/key/pull/70) | Read-only token binding, external registration and profile adoption | `dfc34f0` |
| [71](https://github.com/tvanreenen/key/pull/71) | Ordinary mutations, catch-up, branches, merge/resolution and reciprocal guards | `f7d671f` |
| [72](https://github.com/tvanreenen/key/pull/72) | Key/device/recipient lifecycle; active unfinished layer | `19e1e3e` before this documentation-only record |

Independent serial Debug boundary reruns passed 141 tests in 12 suites for
foundations (including genesis/initialization), 223 tests in 16 suites for
registration/adoption, and 401 tests in 27 suites for content/reconciliation and
shared publication. These are affected regressions, not full-suite claims. The
unchanged lifecycle code retains its recorded full Debug/Release and universal
Preview evidence below. Raw boundary logs and PR drafts remain ignored under
`tmp/piv-recovery/2026-10-06-stack-` and `tmp/piv-recovery/stack-`.

Continue lifecycle implementation on `codex/recovery-lifecycle` in PR 72. Changes
to an earlier layer belong on that layer and propagate through stack-aware rebase
and submission, rather than being patched around at the top. Restore and product
integration should get subsequent review layers when their boundaries are known.
Stack publication does not complete any implementation package or authorize a
hardware operation, real-vault activation, merge or release.

## Architecture ownership

- Format and cryptographic validation stay in `KeyCore`, following
  [the manifest model](../Sources/KeyCore/V3DeviceWrappedManifest.swift) and
  [envelope codec](../Sources/KeyCore/V3DeviceWrappedManifestEnvelope.swift).
  New profile dispatch must preserve exact existing-profile validation.
- Content changes extend the [mutation service](../Sources/KeyCore/V3DeviceWrappedVaultMutationService.swift)
  and [content publisher](../Sources/KeyCore/V3DeviceWrappedContentMutationPublisher.swift).
  Device/epoch changes extend the [shared rotation builder](../Sources/KeyCore/V3DeviceWrappedKeyRotationTransition.swift)
  and [rotation publisher](../Sources/KeyCore/V3DeviceWrappedKeyRotationTransitionPublisher.swift).
  Coverage belongs in candidate construction and validation, not a CLI after-check.
- New-vault publication reuses the [genesis installer](../Sources/KeyCore/V3DeviceWrappedGenesisInstaller.swift).
  Recovery authenticates source snapshots; the installer owns destination
  identity/publication/trust ordering. Accept only a verified snapshot at that seam.
- Product requests follow the [service protocol](../Sources/KeyCore/KeyServiceProtocol.swift)
  and [host](../Sources/KeyCore/KeyServiceHost.swift), not the separate diagnostic
  interception path. The helper retains authority and serialization; the CLI
  supplies reviewed inputs and renders bounded results.
- Token access will use a product platform adapter with the retained
  [public-object codec](../Sources/KeyCore/PIVPublicObjectCodec.swift) and
  [HPKE receiver](../Sources/KeyCore/PIVHPKEReceiver.swift). Archive prototypes
  are evidence, not a production transaction owner. Hardware exclusion must
  integrate with the helper's existing request and mutation ownership.
- Schemas, security promises, and signing/distribution gates stay in their
  existing repository locations.

## Work-package acceptance criteria

### REC-804: contract before persistent format changes

- Specify the typed recipient roster, token-held registration anchor, trust
  bootstrap, authorized descendants across key epochs, and registration/removal
  ordering. Distinguish provider ciphertext, token trust, and device-local intent.
- Resolve how a new Mac validates history without any lost device's private
  key. Opening an HPKE wrapper alone must not establish vault origin. Specify
  which checks precede hardware activation and which require the recovered key.
- Compare concrete single-operation recovery designs with the per-epoch reuse
  baseline. Preserve token-pinned source authentication, future exclusion of
  removed recipients on the continuing lineage, independent backup recovery,
  and token-free normal use. Record the retained-capability alternative-history
  and reduced historical-verification limits.
  Review the protected epoch-signing-key candidate's two authorizations, exact
  projection, capsule custody, initial registration trust, old-client refusal,
  and distinction from historical plaintext equality. Preserve full ordinary
  publication and catch-up checks; do not present primitive tests as a graph proof.
  Review historical-key access, retention, bounded verification, cancellation,
  and interrupted publication. Do not freeze recovery payload/context bytes
  until exact fixtures and their security boundaries have been reviewed. Use
  the [AI review record](piv-recovery-ai-review.md) for scope, findings, and limits.
  Human audit is recommended, not a mandatory implementation/release gate.
- Compare an integrated versioned profile with a separate recovery sidecar for
  the same callers and failure cases. Recommend the integrated profile: the
  manifest already owns authenticated rosters, wrappers, and publication. A
  sidecar would need its own atomic coverage/authority linkage. Do not add fields
  silently to shipping profile 2 or use a recovery token as an enrolled Mac.
- Compare a stable token-held history anchor with repinning every snapshot.
  Recommend the stable anchor plus verified descendants; repinning conflicts
  with normal use while the token is stored away. Specify registration-generation
  changes and removal semantics rather than treating the recommendation as a
  completed protocol.
- Resolve profile/version dispatch, explicit conversion from profile 2,
  multi-Mac upgrade order, old-client refusal, interrupted conversion, and what
  rollback can recover. Never promise an old client can read the new profile.
- Decide initial token/vault capacity, recovery OS floor, command/review shape,
  and supported setup tooling. The existing receiver requires macOS 26 APIs;
  the package minimum is macOS 14. Record the supported combination explicitly.
- Exit: AI review and owner direction recorded, known correctness findings
  resolved, and complete contract/representative cases sufficient for integrated
  implementation. Review exact production contexts/projection and canonical
  fixtures before format freeze. Scoped 805 domain work can proceed while
  remaining graph/platform/adoption decisions are completed. No hardware change.

### REC-805: real profile and cryptographic domain types

- Add explicit version dispatch, bounded canonical codecs, typed recipients,
  recovery wrappers/contexts, and schema fixtures without weakening profile 2.
  Bind vault, key epoch, recipient, suite, profile, and recovery authority.
- Reuse existing CryptoKit HPKE sending and the reviewed hardware-compatible
  receiver. Keep raw keys in scoped memory; do not introduce custom encryption
  or a second device-wrapping implementation.
- Test malformed/unknown fields, noncanonical input, duplicate recipients,
  absent/extra wrappers, cross-vault/epoch/recipient substitution, old-client
  refusal, and independent interoperability vectors at the relevant boundary.
- Exit: production domain components and fixtures pass focused and regression
  checks. Their format remains experimental until review and qualification.

### REC-806: recovery trust and complete source validation

- Start from the bound token anchor, not provider descriptors or local records
  copied from another Mac. Select an authorized state using bounded history,
  never timestamps, filenames, or an unauthenticated highest revision.
- Validate authorized epoch/recipient changes, manifest authentication,
  key identity, every referenced entry's context/digest/AEAD, and payload
  semantics. Handle visible branches explicitly; do not guess a winning branch.
- Verify the final epoch capsule's private/public correspondence after the one
  opening. Define immutable proof inheritance and closed-epoch public-commitment
  verification without claiming historical MAC/AEAD/capsule or reseal replay.
- Test forged-origin capsules, spliced history, missing required ancestry,
  incomplete visible descendants, conflicting heads, changed anchors, and
  resource bounds. Recovery must succeed without original device credentials.
- Include visible versus hidden alternative lineages signed with retained
  pre-removal dual capabilities. Visible authority competition requires refusal;
  hidden competition is a documented limit, not a test of global freshness.
- Exit: a verified snapshot type is the only input accepted by restore;
  provider withholding is documented as external, not tested as a solvable gate.

### REC-807: product token support and safe setup

- Replace the probe's fixed certificate/fingerprint interface with explicit
  credential selection and bound native reads/agreement. Recover using the
  token itself without requiring a separately retained certificate file.
- Define PIN/touch policy requirements, removal/cancellation/deadline behavior,
  per-process operation exclusion, and public-reader/private-operation session
  ordering. Never retry authentication automatically or expose PIN/PUK values.
- All administration, including credential preparation and anchor installation,
  stays in owner-run vendor tools. Key does not collect administrative secrets or
  execute a vendor importer. Export only the reviewed public anchor and explain
  the exact write, target selection and finish verification.
- Document protected administration as an owner prerequisite before real
  registration. Refuse occupied application objects during initial preparation
  and incompatible credentials; never reset PIV or replace a key automatically.
  Explicitly exclude atomic prior-state preservation across an external import:
  preflight and exact readback cannot prevent the vendor tool from overwriting
  changed state. Keep management credentials out of Key, command arguments,
  XPC, logs and provider files.
- Qualify certificate renewal/expiry with an unchanged key, key replacement,
  reset invalidation, and safe PIN/PUK recovery guidance. Simulate wrong-PIN and
  blocked-token cases; do not deliberately consume hardware retry counters.
- Exit: integrated token adapter plus documented supported setup path. Physical
  changes and credential entry require separate exact-scope owner approval.

### REC-808: registration, readiness, and reconciliation

- Register an explicitly reviewed credential from a complete authenticated
  enrolled-Mac vault. Publish exact encrypted artifacts, verify anchor readback,
  and prove possession before reporting verified registration.
- Separate prepare/export from finish/activation. Authenticate one immutable
  pending candidate and source checkpoint; reselect and review the token after
  the external write. Vendor success is never an activation signal.
- Preserve one authenticated candidate across interruption. Reconcile that
  candidate after reauthentication; do not regenerate randomness, overwrite
  unfamiliar objects, repeat hardware writes, or promote provider intent to trust.
- Expose distinct unregistered, pending, registered, and attention-required
  states. Define what readiness proves; token absence is not proof that stored
  hardware or admin policy remains unchanged. Local intent is not recovery input.
- Exit: arbitrary supported disposable entries register through product services;
  every durable phase is fault-tested and incomplete setup cannot claim protection.

### REC-809: ordinary content changes without a connected token

- Extend the existing mutation candidate/validator/publisher and catch-up paths
  to preserve the authenticated recovery roster and same-epoch coverage.
- Exercise add, edit, copy, move, remove, independent-Mac writes, branches, and
  conflict resolution through ordinary service/CLI paths, not fixture-only APIs.
- Test refusal of removed, altered, or missing recovery coverage before
  publication. Normal writes must make no token call or admin write.
- Exit: register, disconnect token, make ordinary changes, discard original
  device authority, and recover the selected updated contents in software.

### REC-810: epochs, device changes, and recipient lifecycle

- Extend the shared rotation builder and enrollment/revocation validators and
  publisher so every active recipient has exactly one current-key recovery
  wrapper. Ordinary key rotation uses stored public keys, not connected tokens.
- Implement authenticated recipient addition/removal with possession-verified
  additions and a fresh vault-key epoch on removal. Removing the last recipient
  needs explicit loss-of-protection review; no silent downgrade via config edits.
- Cover enrollment, revocation, catch-up, relevant merges, interrupted publication,
  and exact candidate recovery. Do not confuse ordinary crash-recovery anchors
  with hardware catastrophe credentials.
- Exit: recovery succeeds after each supported transition; missing coverage
  refuses publication. Removed recipients lack the new key's wrapper on the
  continuing lineage. Earlier captured secrets and hidden alternative lineages
  remain outside the exclusion promise.

### REC-811: restore and safe resume

- Promote the existing genesis installer reuse into the real verified-snapshot
  path, removing dependence on prototype types and fixed toy payloads.
- Preserve source bytes, reject existing/aliased destinations and unrelated
  configs, reseal all supported entries under fresh vault/key/device IDs, and
  install local trust only in the intended destination namespace.
- Clear key sessions and prove fresh ordinary Mac-bound reopen before config
  selection. Report the new vault as lacking recovery registration until setup
  completes; do not silently inherit old source authority.
- Add scoped authenticated restore intent and explicit reauthenticated resume
  that reconciles exact prior artifacts. No plaintext/raw-key persistence,
  duplicate identity/destination creation, hidden cleanup, or retry after ambiguity.
- Exit: real filesystem/crypto tests cover every durable phase and a separate
  later process reads and mutates the restored vault without the recovery token.

### REC-812: supported product workflow and first vertical slice

- Add narrow registration/status/restore/resume requests to the normal service
  protocol, client roles, handler/host, and CLI. Serialize source mutations with
  the vault mutation owner and destination/config changes with the host barrier.
  Keep hardware exclusion and bounded responses across multiple XPC clients.
- Reconcile disconnects, late replies, helper death/restart, and uncertain
  completion through durable state. Status requests cannot activate a token.
- Deliver feature-gated, signed Preview release-configuration support for an
  arbitrary disposable vault, not more debug-only `piv-rehearsal` commands.
  Stable/unqualified profiles remain gated. Exact command names are decided in 804.
- Exit: two-Mac signed-product test registers, makes ordinary edits and a device
  key rotation without the token, loses original authority, restores, removes
  the token, then reads/edits/reopens through ordinary commands. No separate
  receipt or original local state is transferred. This is the first proper
  implementation milestone; publication still needs explicit approval.

### REC-813: backup token and physical lifecycle

- Enroll two independently generated tokens, never cloned private keys. Prove
  that either alone recovers selected current data without the other token,
  original Mac identity, or original setup intent, including after key rotation.
- Qualify recipient addition/removal, restored-vault registration and second
  recovery, certificate renewal, cancellation, unplugging, helper termination,
  interrupted setup/restore and explicit resume, and observed PIN/touch behavior.
- Record token model/firmware, OS/build, exact app identity/hashes, operation
  scope, owner observations, and unchanged unrelated state. No credential values.
- Exit: independent backup recovery and lifecycle matrix pass. Acquiring and
  provisioning a second token is an external owner prerequisite, not permission
  inferred from this plan. Known failure paths remain visible until resolved.

### REC-814: security and release readiness

- Review bootstrap origin, domain separation, descendant/epoch authority,
  recipient removal, protected administration, state reconciliation, key
  lifetime, sensitive output, and hostile-input/resource bounds. Obtain a
  fresh AI implementation review before real-vault enablement. Compare the
  actual codecs, graph validation, services, setup, and failure handling against
  804's reviewed protocol; record findings and their disposition. This is separate
  from the scoped design review. External human review remains recommended,
  not mandatory. Neither an AI pass nor risk disclosure replaces functional,
  compatibility, protected-setup, and physical qualification.
- Decide and qualify the recovery OS/token matrix and unsupported-platform
  refusals. Test ordinary profile-2/v2 regressions and supported local APFS/iCloud
  delivery behavior, including partial delivery. Do not expand provider support
  or promise provider completeness as part of recovery.
- Run full regression/static/build checks and release-script gates. Reconcile
  required smartcard entitlements with production signing allowlists, without
  debug permissions or bypasses. Verify installed signed release configuration,
  notarization, quarantine, helper registration, and channel/config isolation.
- Exit: exact candidate qualifies, no unresolved safety-critical findings, and
  user docs explain setup, backup-token retention, maintenance, recovery/resume,
  loss limits, provider responsibility, and restored-vault re-registration.

### REC-815: opt-in adoption and full completion

- Provide reviewed, explicit profile-2 adoption with backup/rollback guidance,
  old-client refusal and coordinated Mac upgrades. No automatic conversion,
  ordinary config deletion, token reset, or source cleanup during installation.
- Qualify migration/interruption and supported recovery from an adopted
  disposable vault before allowing opt-in real-vault registration.
- Select semver/build and rollout after compatibility review; do not invent a
  version here or replace a published artifact. Publish meaningful Preview and
  Stable artifacts through the existing release workflow only when authorized.
- Exit: gated real-vault adoption is enabled only after 813/814, the exact Stable
  artifact and distribution are verified, user/security docs match the shipped
  promise, and the evidence ledger records all packages' qualified/released state.

## Milestone checkpoints

- **Baseline complete:** one-token feasibility and frozen-checkpoint rehearsal.
- **Domain implementation underway:** AI review and owner direction recorded;
  scoped 805 work has begun without another hardware probe. Complete remaining
  804 integrated decisions before their dependent acceptance cases.
- **First integrated capability:** 805 through 812 produce the real vertical
  slice on disposable data. This is implementation, not another standalone test.
- **Real-vault ready:** 813/814 pass and explicit adoption in 815 is qualified.
- **Full completion:** 815's Stable artifact is released and verified.

The latest increment is bounded read-only public token/source review under
`REC-812`, after restore/resume CLI dispatch, native restore composition and
complete internal authenticated restore and exact resume under `REC-811`. Remaining
command dispatch, live feature gating and shipping
profile-3 integration remain, alongside final platform, lifecycle and release
acceptance. The ledger below records each component's scope and evidence. The
[contract](piv-recovery-contract.md) describes the
experimental dual-authorization direction and its reduced historical replay
promise. The capsule, recipient roster, recovery contexts/wrappers, containing
profile, canonical proof projection, anchor codec, graph selector, snapshot
verifier, registration candidate/intent, completion checks, durable preparation
journal and service-owned manifest-last activation are implemented as internal
components. Explicit profile-adoption construction/validation, durable exact
publication/resume and a source-level old-client refusal check are implemented.
Profile-3 content publication now shares the immutable transaction state machine
with an explicitly selected validator, preserving shipping profile-2 parsing.
The ordinary catch-up step reuses recovery's bounded graph traversal but has
separate local-checkpoint/session-key authentication. The coordinator retains its
starting floor through a serialized walk, reports initial or newly delivered
branches without choosing a winner, accepts authenticated published joins without
checkpointing either side, and refuses key transitions or unanchored co-parents.
The new reconciler shares entry comparison policy with the existing profile,
without converting profile-3 authority into older manifests or granting publication
authority to a plan. All-parent construction now encodes and independently validates
complete candidates, preserving exact coverage and the selected values. The merge
publisher now reuses manifest-last durability with strict head/selector-bound
intents and fresh parent validation, leaving ordinary single-parent contracts intact.
Late branches below a later checkpoint now use its exact committed same-epoch
ancestry, without a separate trusted journal or checkpoint rollback. The internal
ordinary mutation service now composes these components behind the existing save
interface with an exact in-memory session. Finish reciprocal runtime barriers,
shipping composition, lifecycle and domain acceptance next. Reciprocal internal
registration/adoption guards now preserve exact pending work across save,
approval, activation and local repair boundaries.
The first lifecycle component now constructs and independently validates complete
unchanged-roster rotations. Registration shares unsigned epoch material without
sharing its recipient-addition policy. Compared-device enrollment now uses that
material and shared snapshot cryptography, with its own exact ceremony/roster
validator. Reviewed device revocation now uses the same epoch components and a
roster policy shared with profile 2. Recipient removal has its own exact reviewed
policy, fresh generation and plan-bound last-recipient acknowledgment. Rotation
now reuses the immutable durability kernel with its own exact source/policy
validator and interrupted-publication reconciliation. An internal unlocked-session
service now composes initial rotation and an atomic live-session replacement;
post-commit errors lock rather than leave a stale session. Exact interrupted-rotation
session reconciliation now uses shared bounded pending-state selection and public
preflight before addressed Mac unwraps. Enrollment now reuses that durability
kernel under its own transcript/source policy and consumes the exact local ceremony
after authenticated commitment while pending ownership protects retries. Its owner
service now composes exact reviewed comparison approval, random-key publication
and guarded initial/restart sessions without new signing on resume. Joining-Mac
adoption now authenticates the exact compared enrollment and current snapshot,
then pins insert-only checkpoint trust before ceremony completion and guarded
session installation. Reviewed device revocation now uses the immutable kernel
with exact approved-plan comparison and one-device policy reconstruction on
restart. Current-only committed cleanup retains its checkpoint without obsolete
keys or ciphertext. Recipient removal now has its own durable kind and exact
initial protection-loss acknowledgment, with transition-only owned restart.
An initial authority-change service now composes separately reviewed revocation/
removal with random-key publication and guarded session installation. Its explicit
restart methods now reconcile exact locally owned work through bounded public
preflight and cold/warm Mac-wrapper authentication without renewed consent or
signing. A guarded remaining-Mac key-transition step now validates exact public
history and fully authenticates the selected epoch and resealed snapshots before
local trust advances. Mixed content/key-epoch coordination now composes those
steps under one mutation owner, retaining the original observed history and exact
session generation through a terminal result. Shipping cold-unlock/runtime/config
activation and user confirmation remain. Native public-read binding and scoped
agreement are implemented but have not been physically qualified. The isolated
capsule and internal lifecycle layer have fresh independent AI reviews. Lifecycle
review found two initial-rotation activation gaps; their verified fixes and
regressions are recorded below. This is not product/hardware qualification or an
independent cryptographic assessment.

Restore now has source-bound preparation from the verifier-only snapshot type,
reusing permanent genesis and complete entry validation. It produces no durable
state or selection authority. The destination/configuration reservation, scoped
authenticated intent, publication and reauthenticated resume remain to implement
before a restore route can be enabled.

## Implementation evidence ledger

No implementation package `REC-804` through `REC-815` is complete yet.

| Increment | Retained evidence | Limit / next work |
|---|---|---|
| One-token, two-Mac feasibility | [Evidence summary](piv-feasibility-results.md) | Disposable frozen checkpoint only; no protected administration or backup-token qualification. |
| Authority comparison and AI review, 2026-10-04 | [Twelve design tests](../Tests/KeyCoreTests/PIVRecoveryAuthorityDesignTests.swift), [review dispositions](piv-recovery-ai-review.md) | Linear software evidence, not an integrated graph verifier. Finish 804's graph/platform/adoption decisions. |
| First 805 domain component, 2026-10-04 | [Epoch capsule](../Sources/KeyCore/V3EpochSigningKey.swift), [13 tests](../Tests/KeyCoreTests/V3EpochSigningKeyTests.swift); focused suite, 89-test seven-suite regression, and unsigned two-architecture KeyCore build passed before cleanup | Exact local capsule only; no product caller or new-profile activation. |
| Repository cleanup, 2026-10-04 | Removed experiment-only CLI/XPC and prototype dependencies; retained reusable crypto, framing, regression tests, and generic genesis groundwork | Raw files preserved under ignored root `tmp/`. No install, token operation, vault change, commit, or release. See the cleanup verification below. |
| Second 805 domain component, 2026-10-04 | [Recipient roster/codec](../Sources/KeyCore/V3RecoveryRecipients.swift), [recovery HPKE](../Sources/KeyCore/V3RecoveryVaultKeyHPKE.swift), and software tests | No profile dispatch, epoch proof, token anchor, registration, source graph, service command, or real-vault activation. Verification details follow below. |
| Third 805 domain component, 2026-10-04 | [Profile/codec](../Sources/KeyCore/V3RecoveryManifest.swift), [boundary transcripts](../Sources/KeyCore/V3RecoveryEpochBoundary.swift), [14 software tests](../Tests/KeyCoreTests/V3RecoveryManifestTests.swift), and [experimental schema](schemas/v3-recovery-manifest-body.schema.json) | Parsed/publicly checked state is not an anchored graph, a publication-approved candidate, or a restorable snapshot. No shipping profile-3 caller is enabled. |
| First 806 domain increment, 2026-10-04 | [Anchor](../Sources/KeyCore/V3RecoveryAnchor.swift), [bounded history selector](../Sources/KeyCore/V3RecoveryHistory.swift), [snapshot verifier](../Sources/KeyCore/V3RecoverySnapshot.swift), and [graph/source tests](../Tests/KeyCoreTests/V3RecoveryHistoryTests.swift) | One software agreement across multiple epochs; complete selected current entries; no native token provenance, protected administration, restore service, or product activation. |
| First 807 native foundation, 2026-10-04 | [Public token reader](../Sources/KeyCore/PIVRecoveryTokenReader.swift), [17 software tests](../Tests/KeyCoreTests/PIVRecoveryTokenReaderTests.swift), native SDK and two-architecture compilation | No external certificate file or fixed reader name. Scripted read/session tests are not physical-token qualification, private-key binding, possession, protected administration or registration readiness. |
| Second 807 native foundation, 2026-10-05 | [Scoped agreement adapter](../Sources/KeyCore/PIVRecoveryAgreement.swift), [software boundary tests](../Tests/KeyCoreTests/PIVRecoveryAgreementTests.swift), shared reader lease and native compilation | Unique token/public-key handle binding, one-use scope and pending-worker exclusion. Native query/prompt delivery, required PIN/touch policy, protected setup and hardware behavior remain unqualified. No product caller or hardware operation was enabled. |
| Third 807 native foundation, 2026-10-05 | [Key metadata codec](../Sources/KeyCore/PIVRecoveryKeyMetadata.swift), [codec tests](../Tests/KeyCoreTests/PIVRecoveryKeyMetadataTests.swift), reader/agreement refusal tests and [setup boundary](piv-recovery-contract.md#owner-operated-setup-boundary) | Requires explicit PIN/touch ALWAYS and reported generated origin, not attestation or demonstrated enforcement. Vendor credential setup selected; unconditional object import does not satisfy guarded anchor writing. |
| First 808 domain increment, 2026-10-05 | [Registration construction/completion checks](../Sources/KeyCore/V3RecoveryRegistration.swift), [authenticated pending-intent codec](../Sources/KeyCore/V3RecoveryRegistrationIntent.swift), [19 software tests](../Tests/KeyCoreTests/V3RecoveryRegistrationTests.swift), and [external workflow](piv-recovery-contract.md#planned-external-registration-experience) | All administration stays external; atomic prior-state preservation across vendor import is explicitly excluded. No durable staging/publisher, native registration service, product command, hardware call or activation. Verification details below. |
| Second 808 storage increment, 2026-10-05 | [Complete preparation codec](../Sources/KeyCore/V3RecoveryRegistrationBundle.swift), [journal](../Sources/KeyCore/V3RecoveryRegistrationJournal.swift), [contained filesystem storage](../Sources/KeyCore/V3RecoveryRegistrationFilesystem.swift), and 22 additional tests in the [registration suite](../Tests/KeyCoreTests/V3RecoveryRegistrationTests.swift) | Durable atomic preparation and revalidated resume/export only. Device-local store behavior is scripted, not native Keychain qualification. No service-owned source/head/native-token review, reconciliation cleanup, activation, status route or hardware call. |
| Third 808 service increment, 2026-10-05 | [Registration service](../Sources/KeyCore/V3RecoveryRegistrationService.swift), [bounded exact-transition observer](../Sources/KeyCore/V3RecoveryRegistrationRepository.swift), and [service phase tests](../Tests/KeyCoreTests/V3RecoveryRegistrationServiceTests.swift) | Internal profile-3 prepare/resume/finish and committed-state reconciliation. Real filesystem/crypto, scripted native calls and local stores. No shipping composition/CLI/XPC, profile-2 adoption, general profile-3 catch-up/content writes, physical qualification or hardware administration. |
| First 804 adoption implementation, 2026-10-05 | [Adoption builder/validator](../Sources/KeyCore/V3RecoveryProfileAdoption.swift), [shared snapshot validator](../Sources/KeyCore/V3EntrySnapshotValidator.swift), [11 adoption tests](../Tests/KeyCoreTests/V3RecoveryProfileAdoptionTests.swift), and `v0.2.0` source comparison | Exact signed profile-2 to profile-3 candidate only. Tested existing discovery/access-gate refusal, not the released binary. No durable adoption service, checkpoint advancement, ordinary profile-3 writes or product route. |
| Second 804 adoption implementation, 2026-10-05 | [Adoption service](../Sources/KeyCore/V3RecoveryAdoptionService.swift), [encrypted preparation](../Sources/KeyCore/V3RecoveryAdoptionPreparation.swift), [contained preparation store](../Sources/KeyCore/V3RecoveryAdoptionFilesystem.swift), [shared exact-source reader](../Sources/KeyCore/V3ExactTransitionRepository.swift), and [20 service/storage tests](../Tests/KeyCoreTests/V3RecoveryAdoptionServiceTests.swift) | Internal exact publication/resume, manifest-last checkpoint/session advancement and committed reconciliation. Real filesystem/crypto with scripted local stores and confirmation failures. No product routing, reciprocal runtime barriers, ordinary profile-3 writes/lifecycle or native qualification. |
| First 809 content increment, 2026-10-05 | [Shared entry planner/policy](../Sources/KeyCore/V3EntryMutationPlanner.swift), [profile-3 content builder/validator](../Sources/KeyCore/V3RecoveryContentMutation.swift), and [content/recovery tests](../Tests/KeyCoreTests/V3RecoveryContentMutationTests.swift) | Pure add/edit/copy/move/remove with complete snapshot checks and exact authority/coverage preservation. Cold software recovery of a filesystem edit chain; materialization is test setup, not a production save route. Publication/resume, catch-up, branches, resolution and physical qualification remain. |
| Second 809 content increment, 2026-10-05 | [Profile-3 publisher/validator](../Sources/KeyCore/V3RecoveryContentMutationPublisher.swift), [shared immutable publisher](../Sources/KeyCore/V3ContentTransactionPublisher.swift), [shared interrupted-save recovery](../Sources/KeyCore/V3ContentTransactionRecoverer.swift), and [16 filesystem/crypto tests](../Tests/KeyCoreTests/V3RecoveryContentMutationPublisherTests.swift) | Actual internal durable same-epoch saves/resume, pinned ownership and manifest-last checkpoint activation. Cold recovery now follows production publication of five edits. Local stores/software token are scripted; no shipping service/CLI dispatch, catch-up, branches/resolution, native qualification or hardware administration. |
| Third 809 content increment, 2026-10-05 | [Ordinary same-epoch observer/step service](../Sources/KeyCore/V3RecoverySameEpochCatchUpService.swift), [shared bounded graph/progression checks](../Sources/KeyCore/V3RecoveryManifestGraph.swift), and [19 filesystem/crypto tests](../Tests/KeyCoreTests/V3RecoverySameEpochCatchUpTests.swift) | Two independent software checkpoint/cache states catch up and publish in turn. Whole-forward-graph authentication, pending-work refusal and fresh source/CAS guards; competing content heads remain unresolved. Not a full catch-up coordinator, merge/resolution path, epoch lifecycle, native unlock/local-store qualification or enabled product route. |
| Fourth 809 content increment, 2026-10-05 | [Coordinated same-epoch walk](../Sources/KeyCore/V3RecoverySameEpochCatchUpService.swift) and [29 combined step/coordination tests](../Tests/KeyCoreTests/V3RecoverySameEpochCatchUpTests.swift) | One mutation boundary retains the original floor, advances direct children, and authenticates late siblings without selecting a winner. Complete repeated source checks, pending barriers, bounded partial progress and committed-child visibility guards. Operation-local classification only; durable branch reconciliation, merge/resolution, epoch lifecycle and native/product composition remain. |
| Fifth 809 content increment, 2026-10-05 | [Profile-3 branch comparison](../Sources/KeyCore/V3RecoveryManifestReconciliation.swift), [shared entry comparison](../Sources/KeyCore/V3ManifestReconciliation.swift), and [11 filesystem/crypto tests](../Tests/KeyCoreTests/V3RecoveryManifestReconciliationTests.swift) | Authenticated forward-tree comparison returns exact independent-change merge entries or explicit conflicts, using the nearest shared forward ancestor. No encoded merge, provider write, checkpoint advancement or private operation. All-parent publication, merged-history observation and product/native integration remain. |
| Sixth 809 content increment, 2026-10-05 | [All-parent construction and independent validation](../Sources/KeyCore/V3RecoveryMergeMutation.swift) and [16 software domain tests](../Tests/KeyCoreTests/V3RecoveryMergeMutationTests.swift) | Automatic merges reuse exact ciphertext; complete head-bound choices preserve selected values through bounded-revision resealing or explicit deletion. Full candidate snapshots and projected limits check; recovery coverage remains exact. Unpublished candidates only; one-parent intent/publisher are unchanged, and all-parent durability/native/product acceptance remain. |
| Seventh 809 content increment, 2026-10-05 | [All-parent publication and source validation](../Sources/KeyCore/V3RecoveryMergeMutationPublisher.swift), [durable interruption tests](../Tests/KeyCoreTests/V3RecoveryMergeMutationPublisherTests.swift) and [strict intent tests](../Tests/KeyCoreTests/V3RecoveryMergeIntentTests.swift) | Explicit merge validator reuses manifest-last ordering; exact pinned heads/selectors and staged ciphertext resume without new choices or private operations. Current-only committed cleanup and ordinary saves after merge pass. Earlier-floor merged-history catch-up, durable below-floor siblings, product composition and hardware acceptance remain. |
| Eighth 809 content increment, 2026-10-05 | [Authenticated merge observation and catch-up](../Sources/KeyCore/V3RecoverySameEpochCatchUpService.swift), [bounded DAG policy](../Sources/KeyCore/V3RecoveryContentAncestry.swift), [14 publication-to-reader tests](../Tests/KeyCoreTests/V3RecoveryMergedCatchUpTests.swift) and [three graph/reference tests](../Tests/KeyCoreTests/V3RecoveryContentAncestryTests.swift) | Complete all-parent snapshots authenticate before the first unambiguous forward join can become the local checkpoint. Repeated joins and saves work; criss-cross bases report history conflict. Existing pending/CAS/source guards remain. Co-parents below a supplied later floor still refuse; durable ancestry and product/native acceptance remain. |
| Ninth 809 content increment, 2026-10-05 | [Checkpoint-linked ancestry](../Sources/KeyCore/V3RecoveryCheckpointAncestry.swift), [observation/catch-up](../Sources/KeyCore/V3RecoverySameEpochCatchUpService.swift) and [late-branch integration cases](../Tests/KeyCoreTests/V3RecoveryMergedCatchUpTests.swift) | Exact committed same-epoch links explain older siblings/co-parents without rollback or another trusted journal. Current/new branch snapshots fully check; committed older ciphertext and pre-boundary state are not reopened. Reconciliation and manifest-last publication retain the advanced checkpoint. Service composition, lifecycle and integrated/native acceptance remain. |
| Tenth 809 content increment, 2026-10-05 | [Internal mutation service](../Sources/KeyCore/V3RecoveryVaultMutationService.swift) and [19 service integration tests](../Tests/KeyCoreTests/V3RecoveryVaultMutationServiceTests.swift) | Existing ordinary interface, real exact-bound session, pinned interruption dispatch, catch-up, automatic merge and fresh explicit choices compose without a signer or unwrap. Cold software recovery follows actual service saves. No shipping dispatch, native unlock, concurrent-safe read/status service, reciprocal authority-service barriers or integrated/native qualification. |
| Reciprocal 808/809 service guards, 2026-10-05 | [Registration service](../Sources/KeyCore/V3RecoveryRegistrationService.swift), [adoption service](../Sources/KeyCore/V3RecoveryAdoptionService.swift), [registration integration tests](../Tests/KeyCoreTests/V3RecoveryRegistrationServiceTests.swift) and [adoption integration tests](../Tests/KeyCoreTests/V3RecoveryAdoptionServiceTests.swift) | Thirteen new declarations cover competing work before/during approvals, late publication/CAS/session/cleanup, committed repair, unreadable ownership, and real registration/save composition. Internal exact namespaces and the shared mutation owner only; no shipping runtime/CLI dispatch, native qualification or lifecycle extension. |
| First 810 epoch component, 2026-10-05 | [Rotation builder/validator and shared material](../Sources/KeyCore/V3RecoveryKeyRotation.swift), [registration reuse](../Sources/KeyCore/V3RecoveryRegistration.swift) and [16 software tests](../Tests/KeyCoreTests/V3RecoveryKeyRotationTests.swift) | Exact complete resealing, unchanged authority/recipient generation, fresh capsule/proofs and all-active public-key wrappers. Primary/backup software recovery crosses three materialized rotations and an actual service save after private Mac state leaves scope. Rotation materialization is test setup, not durable publication; device/recipient lifecycle, catch-up, native/product routing and integrated review remain. |
| Second 810 enrollment component, 2026-10-05 | [Compared-device builder/validator](../Sources/KeyCore/V3RecoveryDeviceEnrollment.swift), [shared epoch checks](../Sources/KeyCore/V3RecoveryKeyRotation.swift) and [15 software tests](../Tests/KeyCoreTests/V3RecoveryDeviceEnrollmentTests.swift) | One exact signed, unexpired comparison ceremony adds only its joining Mac; transcript-derived epoch, complete resealing, exact recipient/generation preservation and all-active coverage. Primary/backup recovery follows two materialized enrollments and an actual service save without original Mac private state or superseded ciphertext. No enrollment publication/resume, ceremony consumption, joining adoption, catch-up or product/native qualification. |
| Third 810 revocation component, 2026-10-05 | [Reviewed revocation planner/builder/validator](../Sources/KeyCore/V3RecoveryDeviceRevocation.swift), [shared roster policy](../Sources/KeyCore/V3DeviceRevocationRosterPolicy.swift), [profile-2 reuse](../Sources/KeyCore/V3DeviceWrappedRevocationPlanner.swift) and [15 software tests](../Tests/KeyCoreTests/V3RecoveryDeviceRevocationTests.swift) | Exact one-device revocation retains tombstones, approving-Mac access and complete recovery coverage while replacing the key epoch. Old-key/new-snapshot separation and primary/backup recovery after materialized enrollment/revocation plus an actual save. No durable revocation publication/resume, remaining-Mac catch-up, product/native routing or integrated qualification. |
| Fourth 810 removal component, 2026-10-06 | [Reviewed recipient removal and exact-plan acknowledgment](../Sources/KeyCore/V3RecoveryRecipientRemoval.swift) and [15 software declarations](../Tests/KeyCoreTests/V3RecoveryRecipientRemovalTests.swift) | One recipient becomes a tombstone in a fresh vault-key/recovery generation; all other authority and plaintext stay exact. Primary/backup/last removal followed by an actual save; only remaining recipients recover the latest snapshot. Last removal requires explicit plan-bound acknowledgment, not a general override or durable approval. No lifecycle publisher/resume, user-confirmation UI, product/native routing or integrated qualification. |
| Fifth 810 durable rotation component, 2026-10-06 | [Rotation publisher/source validator](../Sources/KeyCore/V3RecoveryKeyRotationPublisher.swift), [shared exact source comparison](../Sources/KeyCore/V3ExactTransitionRepository.swift) and [17 software declarations](../Tests/KeyCoreTests/V3RecoveryKeyRotationPublisherTests.swift) | Actual manifest-last/checkpoint-last rotation with exact locally pinned resume, unchanged authority and one initial addressed Mac-wrapper verification. Every interruption boundary, pending/source guards, committed current-only cleanup and primary/backup recovery after an actual rotation/save. Keys remain helper-scoped inputs; native restart/session routing, other lifecycle publication, product composition and integrated qualification remain. |
| Sixth 810 initial rotation service, 2026-10-06 | [Unlocked-session orchestration](../Sources/KeyCore/V3RecoveryKeyRotationService.swift), [atomic session replacement](../Sources/KeyCore/V3DeviceWrappedVaultKeySession.swift), [13 service declarations](../Tests/KeyCoreTests/V3RecoveryKeyRotationServiceTests.swift) and [five session declarations](../Tests/KeyCoreTests/V3DeviceWrappedVaultKeySessionTests.swift) | Actual random-key generation, reviewed checkpoint execution, full source checks, publication and authenticated live-session switch. Errors after checkpoint changes lock rather than retain a stale key; intervening lock/expiry cannot be undone. Cold-start wrapper opening/resume-to-session routing, other lifecycle publication, product composition and integrated qualification remain. |
| Seventh 810 rotation restart component, 2026-10-06 | [Exact restart orchestration](../Sources/KeyCore/V3RecoveryKeyRotationService.swift), [shared pending-state preparation](../Sources/KeyCore/V3ContentTransactionRecoverer.swift), [15 restart declarations](../Tests/KeyCoreTests/V3RecoveryKeyRotationRecoveryTests.swift) and [guarded session authentication](../Tests/KeyCoreTests/V3DeviceWrappedVaultKeySessionTests.swift) | Exact interrupted random-key rotation resumes without new signing or token use, then installs only authenticated committed authority. Public preflight precedes addressed Mac unwraps; committed cleanup needs only the new epoch, and exact warm sessions reduce operations. Lock/expiry/status races and post-commit failures are exercised. Shipping cold unlock/routing, other lifecycle publication, product composition and integrated qualification remain. |
| Eighth 810 durable enrollment component, 2026-10-06 | [Enrollment publisher/source validator](../Sources/KeyCore/V3RecoveryDeviceEnrollmentPublisher.swift), [domain completion hook](../Sources/KeyCore/V3ContentTransactionValidation.swift) and [publication tests](../Tests/KeyCoreTests/V3RecoveryDeviceEnrollmentPublisherTests.swift) | Exact locally stored compared transcript and approved digest select one manifest-last enrollment epoch. All interruption points, marker/cleanup failure ordering, expiry, source guards, current-only committed cleanup and primary/backup recovery after actual enrollment/save are exercised. Owner-service/session composition, joining adoption, other lifecycle publication and product/native acceptance remain. |
| Ninth 810 enrollment owner component, 2026-10-06 | [Owner service and exact restart](../Sources/KeyCore/V3RecoveryEnrollmentOwnerService.swift), [public enrollment preflight](../Sources/KeyCore/V3RecoveryDeviceEnrollment.swift) and [23 software declarations](../Tests/KeyCoreTests/V3RecoveryEnrollmentOwnerServiceTests.swift) | Exact compared approval generates and publishes a random-key epoch, then installs only authenticated committed authority with a session race guard. All 14 interruption points, cold/warm restart, exact ceremony completion, substituted anchor refusal and primary/backup recovery after owner-service enrollment/save are covered. Joining adoption, other lifecycle publication, shipping composition and native acceptance remain. |
| Tenth 810 joining component, 2026-10-06 | [Joining-Mac adoption](../Sources/KeyCore/V3RecoveryEnrollmentAdoption.swift) and [17 software declarations](../Tests/KeyCoreTests/V3RecoveryEnrollmentAdoptionTests.swift) | Exact comparison and public enrollment proofs precede the joining Mac wrapper; full current authentication precedes insert-only checkpoint trust, exact ceremony completion and guarded session installation. Cold/warm retry, interruption/lock at three verification/persistence boundaries, malformed/competing state and primary/backup recovery after a joining-Mac save pass. Config/runtime activation, catch-up, other lifecycle publication and native acceptance remain. |
| Eleventh 810 revocation publisher component, 2026-10-06 | [Reviewed-device publisher/validator](../Sources/KeyCore/V3RecoveryDeviceRevocationPublisher.swift) and [20 software declarations](../Tests/KeyCoreTests/V3RecoveryDeviceRevocationPublisherTests.swift) | Exact approved plan precedes manifest-last/checkpoint-last publication. Before commitment, restart reconstructs one active-to-revoked change and compares complete snapshots; committed cleanup needs only pinned current state. All 14 interruptions, reciprocal kind refusal, current-state retention and primary/backup recovery after actual enrollment/revocation/save are exercised. Confirmation/session orchestration, recipient-removal durability, remaining-Mac catch-up and native/product acceptance remain. |
| Twelfth 810 removal publisher component, 2026-10-06 | [Recipient-removal publisher/validator](../Sources/KeyCore/V3RecoveryRecipientRemovalPublisher.swift) and [20 software declarations](../Tests/KeyCoreTests/V3RecoveryRecipientRemovalPublisherTests.swift) | Exact plan and initial last-recipient acknowledgment precede reservation. Version-1 intent pins one new removal kind without saved consent. Every publication boundary covers continuing/last-recipient removal; exact restart, current-only cleanup and ordinary-save/software-recovery composition pass. Full Debug/Release and unsigned universal Preview checks pass. Owner/session orchestration, catch-up and native/product qualification remain. |
| Thirteenth 810 initial authority service, 2026-10-06 | [Explicit revocation/removal methods](../Sources/KeyCore/V3RecoveryAuthorityChangeService.swift) and [15 software declarations](../Tests/KeyCoreTests/V3RecoveryAuthorityChangeServiceTests.swift) | One shared source/session flow retains independent decision policies and exact initial review/acknowledgment. Random-key publication installs only authenticated committed state, with generation guards against lock or same-key reauthentication during UI. All durable boundaries and ordinary-save/software-recovery composition pass. Full Debug/Release and unsigned universal Preview checks pass; session-aware restart, catch-up and native/product qualification remain. |
| Fourteenth 810 authority restart component, 2026-10-06 | [Explicit restart/session methods](../Sources/KeyCore/V3RecoveryAuthorityChangeService.swift) and [18 software declarations](../Tests/KeyCoreTests/V3RecoveryAuthorityChangeRecoveryTests.swift) | Exact owned revocation/removal intent and optional routed anchor precede public preflight and addressed Mac-wrapper opening. Cold/warm reconciliation generates no new epoch or consent; current-only committed cleanup preserves trust without obsolete files. All initial durable boundaries, session/source/pending races and ordinary-save/software-recovery composition pass. Full Debug/Release and unsigned universal Preview checks pass; key-transition catch-up and native/product acceptance remain. |
| Fifteenth 810 remaining-Mac key-transition step, 2026-10-06 | [Bounded observation and guarded step](../Sources/KeyCore/V3RecoveryKeyTransitionCatchUpService.swift) and [24 software declarations](../Tests/KeyCoreTests/V3RecoveryKeyTransitionCatchUpTests.swift) | One continuing-Mac wrapper authenticates the selected new epoch and full old/new reseal before checkpoint CAS. Independent checkpoints, edits around several epochs, late joins, visible conflicts and source/session/pending races are exercised. Software recovery follows another Mac's save without Mac private state. Verification below; mixed coordination and integrated/native/product review remain. |
| Sixteenth 810 mixed catch-up coordination, 2026-10-06 | [Concrete coordinator](../Sources/KeyCore/V3RecoveryCatchUpCoordinator.swift), [14 software declarations](../Tests/KeyCoreTests/V3RecoveryCatchUpCoordinatorTests.swift) and [atomic session receipts](../Sources/KeyCore/V3DeviceWrappedVaultKeySession.swift) | One mutation owner composes content/epoch steps from an exact unlocked floor. Original-source checks prevent a late old-floor sibling from disappearing; atomic installation receipts reject unrelated reauthentication between epochs. Committed prefixes survive failures without a current claim or automatic retry. Verification below; lifecycle integration review and shipping/native composition remain. |
| Seventeenth 810 lifecycle integration checks, 2026-10-06 | [Two longer software sequences](../Tests/KeyCoreTests/V3RecoveryLifecycleIntegrationTests.swift) and the source self-review below | Independent Macs walk mixed five-/seven-epoch histories, reject the revoked Mac, take turns saving and retain recovery without Mac state or caches. Last-recipient removal explicitly ends recovery without ending ordinary access. Full unlocked regression and integration verification are recorded below; independent review and native/product acceptance remain. |
| Eighteenth 810 independent lifecycle review and rotation fixes, 2026-10-06 | [Rotation activation guards](../Sources/KeyCore/V3RecoveryKeyRotationService.swift), [expanded regression cases](../Tests/KeyCoreTests/V3RecoveryKeyRotationServiceTests.swift) and the review disposition below | Two confirmed findings share the final rotation-activation boundary. Existing session-generation tickets reject same-key reauthentication; exact committed ownership rejects conflicting or unreadable pending work. Both reproduce before the fix and pass afterward; the reviewer rechecked both remedies. Native/product acceptance remains. |
| First 811 restore candidate, 2026-10-07 | [Source-bound preparation and validation](../Sources/KeyCore/V3RecoveryRestoreCandidate.swift) and [six software declarations](../Tests/KeyCoreTests/V3RecoveryRestoreCandidateTests.swift) | Only a verified snapshot prepares a complete fresh permanent-profile genesis. Exact bytes/types, fresh namespace/device separation and bounded encrypted artifacts validate without source writes or another recovery agreement. Actual rotation/edit composition is covered. No durable restore ownership, publication, config selection or resume is enabled. |
| Second 811 restore bindings and intent, 2026-10-07 | [Filesystem environment](../Sources/KeyCore/V3RecoveryRestoreEnvironment.swift), [authenticated record format](../Sources/KeyCore/V3RecoveryRestoreIntent.swift) and [contained software tests](../Tests/KeyCoreTests/V3RecoveryRestoreIntentTests.swift) | Checks physical source/destination/config separation before folder creation, retains exact paths and folder identities, and refuses any configuration. A bounded, purpose-separated MAC binds the source observation and destination genesis. No durable reservation, encrypted journal, credential creation, publication or resume is enabled. |
| Third 811 owned encrypted preparation, 2026-10-07 | [Local journal](../Sources/KeyCore/V3RecoveryRestoreJournal.swift), [pre-credential reservation](../Sources/KeyCore/V3RecoveryRestoreReservation.swift), [encrypted bundle](../Sources/KeyCore/V3RecoveryRestoreBundle.swift) and [filesystem/software checks](../Tests/KeyCoreTests/V3RecoveryRestoreJournalTests.swift) | Two source-vault ownership pins reserve before credential creation and commit exact complete encrypted bytes. Explicit confirmation validates the saved preparation without resealing. Interrupted, changed or unavailable records remain owned and cannot be regenerated. No publication, private-key caller, product resume, checkpoint or config selection is enabled. |
| Fourth 811 exact restore publication, 2026-10-07 | [Restore publisher](../Sources/KeyCore/V3RecoveryRestorePublisher.swift) and [contained publication/reconciliation checks](../Tests/KeyCoreTests/V3RecoveryRestorePublisherTests.swift) | Opens the saved addressed Mac wrapper once per explicit call, installs exact entries before the manifest and reconciles known prefixes without resealing. A present manifest requires a complete exact snapshot, never repair. Unexpected files/partials stop publication. No checkpoint, cache, config, ownership cleanup, product route or native qualification. |
| Fifth 811 local trust and ordinary reopen, 2026-10-07 | [Trust installer](../Sources/KeyCore/V3RecoveryRestoreTrustInstaller.swift) and [software trust/reopen tests](../Tests/KeyCoreTests/V3RecoveryRestoreTrustInstallerTests.swift) | Rechecks complete published objects, verifies the persisted addressed wrapper, caches exact encrypted bytes and inserts only an absent checkpoint. A fresh empty session uses the ordinary identity loader/runtime to read every restored item. Matching interrupted trust is retained; different trust is refused. No config selection, ownership cleanup, product caller or native qualification. |
| Sixth 811 configuration selection and reconciliation, 2026-10-07 | [Selection installer](../Sources/KeyCore/V3RecoveryRestoreSelectionInstaller.swift), [bound environment](../Sources/KeyCore/V3RecoveryRestoreEnvironment.swift) and [selection tests](../Tests/KeyCoreTests/V3RecoveryRestoreSelectionInstallerTests.swift) | Fresh trust/ordinary-access checks precede exact no-overwrite config publication. Explicit selected continuation requires matching config, existing exact trust and complete owned files. Both ownership records remain intact. No product caller, native qualification or ownership finalization. |
| Seventh 811 ordered ownership finalization, 2026-10-07 | [Finalizer](../Sources/KeyCore/V3RecoveryRestoreFinalizer.swift), [journal completion reader](../Sources/KeyCore/V3RecoveryRestoreJournal.swift) and [finalization tests](../Tests/KeyCoreTests/V3RecoveryRestoreFinalizerTests.swift) | Fresh ordinary access and exact selected/source/trust/files precede reservation-first, preparation-last CAS removal. The remaining complete-bundle pin supports halfway continuation without another record or new format. No pins means no pending claim, not retrospective success. Encrypted files remain inert; no product caller or native qualification. |
| Eighth 811 authenticated preparation service, 2026-10-07 | [Restore service](../Sources/KeyCore/V3RecoveryRestoreService.swift), [scoped journal](../Sources/KeyCore/V3RecoveryRestoreJournal.swift) and [service tests](../Tests/KeyCoreTests/V3RecoveryRestoreServiceTests.swift) | Reader-issued native observation and one recovery agreement authenticate the source before new-directory creation. Durable reservation precedes fresh Mac credentials; independent reload and wrapper opening precede encrypted preparation. Source/token, cancellation, deadline and authentication-generation checks span the call and record rename boundaries. Scoped completion, product dispatch/resume and native acceptance remain. |
| Ninth 811 scoped completion and resume, 2026-10-07 | [Restore service](../Sources/KeyCore/V3RecoveryRestoreService.swift), [completion tests](../Tests/KeyCoreTests/V3RecoveryRestoreCompletionServiceTests.swift) and existing publication/trust/selection/finalization components | One source agreement spans initial restore through ordered cleanup. Explicit resume requires exact local ownership and fresh source authentication, never new credentials or replacement ciphertext. Selected resume verifies existing trust and only finalizes. Product dispatch/barriers, separate-process and physical acceptance remain. |
| First 812 gated host and connection boundary, 2026-10-07 | [Recovery request/scope](../Sources/KeyCore/KeyRecoveryRequest.swift), [host](../Sources/KeyCore/KeyServiceHost.swift), [helper connections](../Sources/KeyLaunchAgentHelper/main.swift) and [routing tests](../Tests/KeyCoreTests/KeyRecoveryRoutingTests.swift) | Public restore/resume selectors cross the protocol; one request is admitted through the existing exclusive host barrier. Lock cancels out of band and disconnect cancels its connection's scopes. Uncertain selection forces restart; process-local pending state refuses competing setup. Live Stable/Preview capability remains disabled; durable restart admission and native/CLI/runtime composition remain. |
| Second 812 restart ownership admission, 2026-10-07 | [Local ownership queries](../Sources/KeyCore/V3ImmutableTransactionRecoveryAnchor.swift), [paired capability](../Sources/KeyCore/KeyRecoveryRequest.swift), [host](../Sources/KeyCore/KeyServiceHost.swift) and [ownership tests](../Tests/KeyCoreTests/KeyRecoveryOwnershipTests.swift) | Recovery capability requires an ownership inspector. Either existing restore pin or an uncertain query refuses competing setup and cold selected-runtime composition. Explicit resume still validates exact source-bound state; presence grants no authority. No new marker or file scan. Live products remain disabled; native composition and signed Keychain acceptance remain. |
| Third 812 native restore composition, 2026-10-07 | [Workflow/factory](../Sources/KeyCore/V3RecoveryRestoreWorkflow.swift), [local metadata roots](../Sources/KeyCore/VaultLocationResolver.swift), [physical containment](../Sources/KeyCore/V3RecoveryRestoreEnvironment.swift) and [workflow tests](../Tests/KeyCoreTests/V3RecoveryRestoreWorkflowTests.swift) | Exact public selectors resolve through the native reader before local scaffolding. The factory pairs ownership, journal pins, Mac identity, checkpoint/cache and one scoped agreement with the actual restore service. Fresh-Mac metadata creation is bounded; resume never recreates missing directories. Live Stable/Preview remain disabled and no CLI is added. Native product acceptance and actual XPC/hardware behavior remain unqualified. |
| Fourth 812 restore/resume CLI, 2026-10-07 | [Parser](../Sources/KeyCore/CLIParser.swift), [application](../Sources/KeyCore/KeyCLIApplication.swift), [help](../Sources/KeyCore/CLIHelp.swift) and [CLI software tests](../Tests/KeyCoreTests/RecoveryCLITests.swift) | Explicit selectors and paths dispatch through the existing guarded request, never configuration defaults or CLI credentials. Actual software CLI/host/workflow/service composition covers completion, saved-preparation interruption, fresh-host exact resume and completed-attempt refusal. Live Stable/Preview still refuse before state creation; public review, other commands, shipping profile-3 composition and signed/native qualification remain. |
| Fifth 812 public review, 2026-10-07 | [Closed request/result/workflow](../Sources/KeyCore/KeyRecoveryReview.swift), [host admission](../Sources/KeyCore/KeyServiceHost.swift), [CLI](../Sources/KeyCore/KeyCLIApplication.swift) and [review tests](../Tests/KeyCoreTests/KeyRecoveryReviewTests.swift) | Bounded token listing never selects or reads a credential; explicit source review reuses public history selection and revalidates token, source and scope. No entry read, PIN/touch, private agreement, Keychain, saved-attempt change or configuration selection. Shared exclusion/cancellation keeps restore exclusive and review read-only; configured lock still runs. Live products stay disabled; other commands, runtime composition and signed/native qualification remain. |

Append concise package evidence here as implementation progresses. Record full
operational logs outside committed documentation; keep enough provenance,
commands/results, and qualifications here to audit each accepted increment.

### Cleanup verification, 2026-10-04

- `swift test --no-parallel`: 850 KeyCore tests across 80 suites and 6
  canonical-JSON tests passed after cleanup and formatting.
- Focused `swift test -c release --no-parallel --filter` covering HPKE/framing,
  epoch capsule, authority design, genesis, initialization, and new-directory
  suites: 65 tests across seven suites passed.
- Unsigned `Key Preview` / `PreviewDebug` Xcode app, CLI, and helper build:
  arm64 and x86_64 passed. Product-bundle isolation, bundled CLI help, release
  scripts, Preview install safety scripts, focused strict Swift-format lint,
  project plist syntax, document-link targets, and `git diff --check` passed.
- Full Release suite: 850 KeyCore tests ran with seven expectation failures
  in one unchanged test, `debugQualificationBundleUsesIsolatedMutableNamespaces`.
  It expects qualification namespaces that `RuntimeConfiguration.live` enables
  only under `#if DEBUG`. The test, runtime configuration, and product identity
  match base HEAD; they were not changed by cleanup. Six JSON tests passed.
  This is a Release-test compatibility issue, not a passing full Release gate.

Raw verification output stays in the ignored local archive. No signed-artifact,
hardware, installed-product, or real-vault qualification was performed here.

### Recipient and wrapper verification, 2026-10-04

The cleaned baseline was preserved locally as `49d8749` (generic genesis
groundwork) and `3f11e0c` (crypto primitives, tests, reviewed direction, and
tracking). Commit `cca0b62` adds internal recipient/context/wrapper types without
changing shipping profile-2 context bytes or enabling a recovery command.

- Focused Debug checks: 22 tests across three suites passed, including exact
  records and context bytes, the maximum roster boundary, malformed inputs,
  coverage, device/recovery separation, key-identity checks, and cancellation.
- Focused Release regression: 87 tests across ten suites passed, covering the
  new components, existing HPKE/PIV framing, epoch capsule, authority design,
  genesis, initialization, and new-directory checks.
- Unsigned `Key Preview` / `PreviewDebug` app, CLI, and helper build passed for
  arm64 and x86_64. Product-bundle isolation, bundled CLI help, strict formatting
  of the four new Swift files, project plist syntax, local document-link targets,
  and `git diff --check` passed.
- Full Debug rerun with the console unlocked: 866 KeyCore tests across 82 suites
  and six JSON tests passed. The isolated 27-test legacy storage/preflight probe
  also passed. The initial locked-console run had 65 issues, including protected
  temporary-file writes and downstream expectations; its isolated probe had five
  issues. Unlocking cleared those failures without code changes, supporting the
  lock-state explanation for `EntryStore`'s `.completeFileProtection` writes.
  Both initial and unlocked run logs are retained. No storage protections were
  changed. The prior full Release limitation remains recorded above.

Software fixtures use CryptoKit on both sides, not an independent HPKE library.
The one-callback assertion is software evidence, not hardware PIN/touch or
integrated recovery qualification. No fresh independent review, product caller,
token operation, installation, push, or release was performed. Raw verification
logs remain under ignored `tmp/piv-recovery/`.

### Profile and boundary verification, 2026-10-04

This increment shares validated device/entry fields and outer-envelope syntax,
not shipping profile acceptance. Existing services retain their profile-2 types
and reject profile 3. Device HPKE now has an explicit profile-3 context using
the same CryptoKit operation; all existing callers retain profile-2 defaults.
The shared foundation is preserved locally as `9331268`.

- Focused Debug: 28 tests across three suites passed, including 14 new software
  tests and existing manifest/HPKE regressions. Exact canonical body/projection
  fixtures, malformed/duplicate/unknown fields, old-reader refusal, cross-profile
  device wrapping, separate signature checks, complete candidate commitments,
  inherited proofs, MAC/capsule checks, and cancellation are covered.
- Focused Release regression: 109 tests across 12 suites passed on the final
  source state. No full Release pass is claimed; its prior limitation remains above.
- The final unsigned arm64/x86_64 Preview app, CLI, and helper build passed.
  Product-bundle isolation, bundled CLI help, new-file strict formatting, project
  plist syntax, 53 local documentation targets, schema JSON syntax/shape, 60 local
  schema references, and `git diff --check` passed. Schema shape checks are not
  an independent JSON Schema validation engine.
- At this increment, full Debug verification awaited an unlocked console. The Mac
  locked again after the previous increment's passing full run. No protected
  storage behavior, system lock setting, or token configuration was changed.

Boundary validation checks one exact parent and both signatures. Same-epoch
metadata validation preserves authority across edits/merges. Neither establishes
anchor provenance, bounded graph selection, recipient-transition policy, full
resealing, entry authentication, or a verified snapshot. Those remain the graph
and publication services' responsibilities. Origin anchoring/adoption, hardware
operation counts, fresh integrated review, and real-vault activation remain
unqualified. No install, token operation, push, or release was performed. Raw
logs stay under ignored `tmp/piv-recovery/`.

### Anchored history and snapshot verification, 2026-10-04

The first 806 increment reuses `V3ImmutableObjectReading` and ordinary repository
budgets. Public selection and verified snapshots have separate construction
boundaries; neither is an ordinary MAC-trusted checkpoint. The selector validates
the floor's exact digest and recipient, all required parent paths, proof
inheritance, dual-authorized epoch changes, monotonic rosters, revision rules,
and visible branch conflicts. It refuses a same-vault tip with a missing link
to the floor instead of treating it as unrelated. It does not privately replay
known pre-floor history or fetch historical entry ciphertexts.

The snapshot verifier reselects before one software agreement, validates the
final capsule and current-epoch MACs, authenticates every selected current
entry and its payload semantics, then rechecks source bytes before returning.
Source changes and cancellation fail without another approval or fallback.
Publication must revalidate again, including native token/directory bindings.
The [contract](piv-recovery-contract.md#implemented-history-and-snapshot-verification)
records the conservative opaque-object policy and its availability cost.

The 27 new software tests cover exact anchor bytes and rejection, multi-epoch
opening, floor cuts, all-parent merges, missing links, unsupported descendants,
content/authority/closed-epoch branches, roster/revision policy, resource bounds,
current MAC/capsule/entry/payload failures, cancellation and source changes.
A disposable directory fixture uses the real filesystem source and checks
symlink refusal. No private hardware callback is exercised by these tests.

- Focused Debug regression: 129 tests across 13 suites passed, covering the new
  anchor/history/snapshot checks and existing profile, HPKE, PIV framing,
  capsule, entry-cipher and repository behavior.
- Focused Release regression: 129 tests across the same 13 suites passed.
  This is not a full Release pass.
- Unsigned arm64/x86_64 Preview app, CLI and helper build, product-bundle
  isolation and bundled CLI help passed. No recovery command was enabled.
- Strict formatting, project plist syntax, 61 local documentation link targets
  and `git diff --check` passed.
- A negative compiler check confirmed that a separate source file cannot invoke
  the verified snapshot's fileprivate initializer. Raw probe code/output remains
  under ignored `tmp/piv-recovery/`, not in the product or committed tests.

At this increment, full Debug verification awaited an unlocked console; the unchanged full
Release compatibility limitation is recorded above. No system lock setting or
protected-file behavior was changed. Raw logs remain under ignored
`tmp/piv-recovery/`; no install, token operation, push, or release was performed.

### Native public-reader verification, 2026-10-04

The first 807 increment uses token-to-slot metadata and a retained native card
instance rather than the archived probe's one fixed reader name and separately
supplied certificate. It requires explicit selection, reads slot 9d's public
certificate and the application anchor in one exclusive session, validates the
P-256 point and anchor credential ID, and rechecks the retained binding. Candidate
handles belong to one reader instance; removal cannot revive a reviewed handle
through a same-named replacement. Certificate issuer/expiry is not authority.

The command surface contains only PIV application selection and the two public
GET DATA reads. It cannot express PIN verification, administration, private-key
operations, writes or reset. Occupied unrecognized bytes are not returned; a
private digest detects changes during revalidation. An absent object is distinct
from an occupied empty object or an invalid response. A recognized anchor is
not proof of protected administration or registration readiness.

Live access shares a process-wide operation gate. Late begin/send callbacks
retain its lease after the 25-second public-read deadline until native completion
and session closure. Timeout does not claim cancellation or allow overlapping
operations. The software tests exercise these lifetime rules without sleeping,
calling native token methods or consuming hardware retry counters.

Native implementation was compiled against the installed macOS 27 SDK with
deployment target 14; the SDK's token-info and card-lifetime contracts informed
the binding. [Apple's token information](https://developer.apple.com/documentation/cryptotokenkit/tktokenwatcher/tokeninfo?language=objc)
exposes token ID and optional reader-slot metadata. This is not hardware
attestation. The SDK documents `com.apple.security.smartcard` for access to
`TKSmartCardSlotManager.default`. Neither helper currently grants it; no
entitlement, installed-product capability or CLI/XPC route changed here.

Verification:

- Focused Debug and Release regressions each passed 146 tests across 14 suites,
  including 17 new public-reader and session-lifetime tests. Neither result is a
  full-suite pass.
- Unsigned arm64/x86_64 Preview app, CLI and helper build, product-bundle
  isolation and bundled CLI help passed. No recovery command was enabled.
- Strict formatting, project plist syntax, 64 local documentation link targets
  and `git diff --check` passed.

Remaining 807 work is unique native agreement-key binding to this observation,
one approved operation, cancellation/deadline/exclusion integration, protected
owner-operated setup and product/hardware qualification. The occupied disposable
object and factory-default management credentials were not altered. No native
token discovery, read or private operation was run in this increment. Full Debug
verification then awaited an unlocked console; the known full Release limitation
remains. Raw logs stay under ignored `tmp/piv-recovery/`.

### Scoped agreement verification, 2026-10-05

The second 807 increment connects a reviewed reader observation to one-use HPKE
agreement through the Security provider. One process-wide lease spans public
revalidation, noninteractive lookup, another public revalidation, one ECDH
request and final public revalidation. No public card session stays open during
agreement. Token ID, public point, private P-256 attributes, uniqueness and
algorithm support are checked before enabling interaction. There is no external
certificate input, label-only identity, software fallback or authentication retry.

Cancellation, scope exit and the absolute deadline discard stopped/late results
and invalidate the operation's authentication context. The waiting caller can
return while native work remains pending; that worker retains exclusion until
native return and cleanup. Context invalidation is a cancellation request, not
a native termination guarantee. Tests deliberately hold a scripted provider
pending, prove the gate stays claimed, and release it without a token operation.

The software tests exercise scope escape/concurrent reuse, malformed peers,
missing/ambiguous/mismatched/unsupported handles, provider failure, invalid result
size, removal, anchor changes, busy exclusion, cancellation and timeout. The KEM
comparison uses a software peer and public certificate fixture; it is not native
provider interoperability. Native code was compiled, not invoked. Apple's
[authentication context](https://developer.apple.com/documentation/security/ksecuseauthenticationcontext)
and the installed macOS 27 SDK informed the query and cancellation boundary.

Verification:

- Focused Debug and Release regressions each passed 161 tests across 15 suites,
  including 15 new agreement-boundary tests. Neither is a full-suite pass.
- The 15 agreement-boundary tests also passed with default runner concurrency.
- Unsigned arm64/x86_64 Preview app, CLI and helper build, product-bundle
  isolation and bundled CLI help passed. No recovery command was enabled.
- Strict formatting, project plist syntax, 67 local documentation link targets
  and `git diff --check` passed.
- An ephemeral software public-key import exposed the nonempty application
  label required by lookup; a software private-key import confirmed attribute
  decoding. Neither probe queried the keychain or native token.

Protected owner-operated setup, required PIN/touch policy and signed-product
capabilities remain next, followed by explicit-scope native qualification on
disposable data. Public observation and successful ECDH alone are not registration
readiness or a real-vault restore. No entitlement, CLI/XPC route, installed build,
YubiKey credential/object or vault was changed. Raw logs remain under ignored
`tmp/piv-recovery/`; full Debug then awaited an unlocked console and the known
full Release limitation remains.

### Configured policy and setup verification, 2026-10-05

The third 807 increment adds only GET METADATA for slot 9d to the closed public
command surface. It checks the metadata P-256 point against the certificate,
retains reported origin/PIN/touch policy in the observation, and compares them
on every revalidation. Agreement refuses all but generated origin and explicit
PIN/touch ALWAYS before provider lookup. Missing metadata cannot fall back to
certificate-only identity. There is no PIN verification or administrative APDU.

The codec reuses strict bounded TLV framing: exact fields, supported values and
curve encoding, with a 256-byte response limit. Ten additional software tests
cover recognized versus accepted policies, malformed and substituted metadata,
removal during the new read, weaker/imported credentials, and policy changes
before or after agreement. Fixtures are software-only; no current token metadata
was fetched and no hardware retry counter was consumed.

Primary evidence: Yubico's
[GET METADATA extension](https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html),
[policy guide](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html),
and [PIV CLI guide](https://docs.yubico.com/software/yubikey/tools/ykman/PIV_Commands.html),
plus the installed `ykman` 5.9.2 `yubikit/piv.py` and `ykman/_cli/piv.py`.
The source establishes flat metadata TLVs, policy/origin constants, nested
public-point encoding, management authentication for PUT DATA, hidden credential
prompts and unconditional object import. It was read, not executed on hardware.

At this increment, owner-operated vendor credential setup was the initial choice.
Key would not collect management credentials for it. Guarded anchor writing was
unresolved:
the vendor importer has no reviewed-prior-state comparison, and Key's gate is
not cross-process exclusion. The contract records the random nondefault AES
management-key direction, PIN-protected versus separate custody tradeoff, and
the approval/readback requirements. These are not hardware instructions or proof
of current protected administration. The existing disposable object and default
management key were not changed.

The subsequent external-registration decision below supersedes that unresolved
writer choice; the observations and qualification limits above remain applicable.

Verification:

- Complete Debug suite with the console unlocked: 949 KeyCore tests across
  88 suites and 6 canonical-JSON tests passed. This covers the previously deferred
  profile, history, reader and agreement increments together with the policy
  changes. Their earlier unlocked-console verification gap is closed.
- Focused Release regression: 171 tests across 16 suites passed. This does not
  supersede the unchanged full Release qualification-bundle limitation.
- Unsigned arm64/x86_64 Preview app, CLI and helper build, product-bundle
  isolation and bundled CLI help passed. No recovery command was enabled.
- Strict formatting, project plist syntax, 71 local documentation targets and
  `git diff --check` passed. Logs remain under ignored `tmp/piv-recovery/`.

Configured-policy checks do not qualify actual prompts, native metadata delivery
or protected anchor administration. No install, hardware call, write, credential
change, push or release was performed.

### First 808 domain verification and external-administration decision

The owner selected vendor tools for both preparation and anchor installation.
Key must not collect administrative credentials, execute the vendor importer, or
write to the token. Public preflight and exact finish verification do not provide
atomic prior-state preservation across an unconditional external import. This
limit is recorded in the contract, together with the planned user workflow.

The [registration component](../Sources/KeyCore/V3RecoveryRegistration.swift)
adds one new recipient to an already authenticated experimental profile-3 parent.
It refuses occupied application objects, incompatible credentials and duplicate
recipients, retains existing devices/recipients, rotates the vault and epoch
authority, reseals the complete current snapshot, and creates new device and
recovery wrappers. It reuses the existing entry cipher, HPKE contexts and dual
boundary authorization; no shipping profile-2 dispatch or adoption is changed.

The [pending intent](../Sources/KeyCore/V3RecoveryRegistrationIntent.swift) has
bounded exact canonical fields and a domain-separated HKDF/HMAC under the parent
vault key. It binds the operation, parent, authorizing Mac, candidate/anchor,
recipient and staged-entry addresses. Serialized bytes contain public identifiers
and an authentication tag, not raw keys, plaintext or saved possession approval.
Parsing does not authenticate it or make it publication authority.

Completion authenticates the same pending candidate, checks its exact parent and
anchor, verifies dual signatures and current MAC/capsule, opens the local Mac
wrapper, and independently compares every old/new entry's plaintext bytes. It
then opens one exact candidate recovery wrapper and compares that key with the
local result. Cancellation and other failures are not retried; a reloaded intent
requires a fresh operation. Scripted/software inputs do not establish native
provenance, actual PIN/touch enforcement or administration readiness.

This is an internal domain increment, not a finished prepare/finish service.
Remaining 808 work includes durable immutable staging/export, authenticated local
intent ownership and phase reconciliation, fresh native review around the
external handoff, source/head/token rechecks under product mutation ownership,
manifest-last activation, checkpoint advancement and readiness/status. The
completion function returns no durable approval and must not substitute for
those publication barriers. Product commands and physical tests are not enabled.

Verification, 2026-10-05:

- The 19 new registration tests passed. They cover candidate construction,
  exact intent parsing/authentication, policy and occupancy refusal, complete
  same-byte resealing, substitution checks, cancellation and fresh possession
  after reloading the serialized intent. All key operations use software fixtures.
- `swift test --no-parallel` passed the complete Debug suite: 968 KeyCore tests
  across 89 suites and 6 canonical-JSON tests. Two full runs without explicit
  serial scheduling failed one-second coordination waits in unchanged runtime,
  catch-up and mutation-owner tests. The later run had no competing compilation;
  competing builds do not explain that result. A focused run of those three
  suites passed all 27 tests under ordinary scheduling. Scheduling sensitivity
  under the full concurrent load is suspected, not established as the cause;
  no unrelated timeout or concurrency code was changed.
- The final-source affected Release regression passed 217 tests across 17
  suites, covering recovery/profile, epoch capsules, token boundaries and device
  transitions. A complete Release run was not performed; the previously recorded
  qualification-bundle limitation is unchanged.
- The unsigned Preview app, CLI and helper built for arm64 and x86_64 using the
  existing package checkout. Product-bundle isolation and bundled CLI help checks
  passed. This compiles the internal components, not an enabled recovery command.
- Strict Swift formatting, project plist syntax, 37 unique local documentation
  file targets and `git diff --check` passed. Raw logs and the unsigned build
  remain under ignored `tmp/piv-recovery/`.

No native token operation, hardware write, credential change, installation,
notarization, push or release was performed. These tests do not replace integrated
review, durable-phase verification or physical qualification.

### Second 808 storage increment, 2026-10-05

The preparation journal chooses one atomically installed bundle over independent
intent/manifest/entry writes. It preserves the exact randomized candidate before
the external handoff, without publishing any current-state object. The existing
contained no-overwrite writer and root-identity checks are reused; no replacement
filesystem writer or new provider backend was introduced. The bundle embeds existing
canonical objects rather than base64-encoding the encrypted snapshot a second
time. Aggregate/per-object limits precede parsing or object construction where
possible; the outer read is bounded before allocation.

Local ownership uses the existing prepared/recoverable record and compare-before-
replacement interface in a dedicated non-synchronizing registration namespace.
The ordinary transaction default is unchanged. A provider-only bundle is never
selected or adopted. Registration staging lives under
`.recovery-registrations/<operationID>/preparation.json`, outside ordinary
transaction discovery. This record is experimental version 1 with exactly
`format`, `version`, `intent`, `candidate` and `entries` fields; the codec enforces
exact candidate/parent/authorizer and ordered entry bindings. Parsing proves no
parent authority, consent or possession.

Preparation validates the complete old/new snapshot before reserving ownership,
installs the complete bundle, reads it back, revalidates it, confirms exact-file
and directory synchronization, promotes ownership, and only then returns the
exact public anchor. Resume repeats full cryptographic
and plaintext checks with caller-supplied authenticated keys. It does not sign,
reseal, rewrite the bundle or save a possession result. Missing or invalid files,
changed authority, ownership conflicts and failures retain pending evidence.
A prepared reservation without a complete bundle cannot resume automatically;
explicit pre-handoff abandonment/reconciliation remains a later service case.

Twenty-two additional tests include all four journal phase interruptions, failure
before atomic installation, exact reload, duplicate/unsupported/substituted
records, aggregate/per-object limits, missing/invalid/oversized files, competing
ownership attempts, ownership changes before export, no-overwrite installation,
linked-path refusal, changed configured-root identity, failed durability
confirmation and disappearance after readback. Readable data cannot be promoted
after a synchronization failure; retry validates and synchronizes the same bytes
without regenerating them. A completion exercise on reloaded disk bytes still
requires a fresh software possession operation each
time. The filesystem writer is real; local ownership is a scripted store using
the production compare-before-replacement contract, not a test of native
Keychain persistence or cross-process exclusion.

The journal must be called inside the helper's mutation owner. It does not
observe live heads/checkpoints, block other product mutations, review a native
credential, write a standalone export file, activate recovery or clear pending
records. Native binding, integrated phase reconciliation, manifest-last
publication, checkpoint advancement and user-facing status remain next. No
product route, installation or hardware administration was enabled.

Verification:

- All 41 registration tests passed, including the 22 new storage tests and the
  four cases of the journal interruption test. No token was contacted.
- Final-source `swift test --no-parallel` passed the complete Debug suite:
  990 KeyCore tests across 89 suites and 6 canonical-JSON tests. The previously
  recorded concurrent full-suite scheduling limitation was not reassessed.
- Affected Release regression passed 283 tests across 20 suites. This includes
  recovery/profile, token boundaries, device transitions, ordinary immutable
  transaction recovery and the immutable repository. Full Release was not run;
  the existing qualification-bundle limitation is unchanged.
- Final-source unsigned arm64/x86_64 Preview app, CLI and helper builds passed,
  as did product-bundle isolation and bundled CLI help/completion checks.
- Strict formatting of the new/expanded Swift files, project plist syntax,
  40 unique local documentation file targets and `git diff --check` passed.
  Raw verification logs and the unsigned build remain in ignored
  `tmp/piv-recovery/`.

No user vault/configuration, installed product, hardware credential or token
object was changed. No notarization, push or release was performed. Native
Keychain qualification, integrated review and product/hardware acceptance remain.

### Third 808 service increment, 2026-10-05

The internal registration service now owns prepare, exact resume/export and
finish under the existing shared mutation owner. It composes the registration
builder/validator, durable journal, contained immutable publisher, local
checkpoint store and native reader/agreement adapters. Shipping profile-2
dispatch is unchanged; no CLI/XPC route instantiates this service.

Preparation reviews the authenticated current snapshot and fresh bound token,
requires absent anchor occupancy and the reported generated/PIN ALWAYS/touch
ALWAYS policy, persists one exact randomized candidate and returns only its
public anchor. All credential generation, administration and import remain
owner-run outside Key. Resume opens the candidate's local wrapper once and
revalidates the retained exact bytes without signing or generating a replacement.

Finish rechecks intent, owner, current source/checkpoint, exact installed anchor,
dual boundary, MAC/capsule and complete same-plaintext comparison. It opens the
local wrapper once and requests one agreement through the scoped native adapter.
Successful possession is consumed within that request, never persisted. The
existing publisher installs entries first and the manifest last, with exact
readback, source/checkpoint/token rechecks and resource budgets before local
checkpoint advancement. Session installation follows checkpoint advancement;
only then is local pending ownership cleared. The encrypted preparation bundle
is retained inert for audit, not deleted or adopted by scanning.

The bounded observer uses the local authenticated checkpoint as its floor,
matching the shipping observer's trust model. It accepts only that current
snapshot and this exact pending transition above the floor. Competing same-vault
state refuses instead of silently selecting, merging or rebasing it. Pre-floor
manifests consume listing/byte budgets but are not reopened under historical
keys. This observer does not apply recovery's reduced replay rules to authorize
normal publication. General profile-3 catch-up remains separate work.

An interruption before checkpoint advancement requires a fresh possession
operation, including after manifest publication. After exact checkpoint
advancement, reconciliation reauthenticates current local contents and repairs
session/ownership state without another agreement or republication. Cleanup
failure reports a committed result with cleanup pending. A lost reply after
ownership cleanup is recognized only when the existing local checkpoint equals
the token floor and its authenticated active recipient matches. Token/provider
data cannot establish a new local checkpoint through that path.

Nineteen service tests exercise real filesystem staging/publication, actual
cryptography, the mutation owner and reader/agreement adapters. Native calls and
device-local stores are scripted. Cases include prepare interruption, eight
finish phase interruptions, checkpoint/session/cleanup failures, lost replies,
single-operation cancellation, pre-expired requests, changed source/token,
competing state before and after publication, corruption and projected limits.
No hardware operation, credential change or administrative write was performed.

Remaining work includes explicit profile-2 adoption, helper composition and
status/CLI/XPC boundaries, pending-state barriers for other mutations, ordinary
profile-3 content and authority lifecycle, and native checkpoint/token physical
qualification. `REC-808` is not complete. The components have not received a
fresh integrated independent review.

Verification of final source:

- Complete serial Debug regression passed 1,009 KeyCore tests in 90 suites and
  6 canonical-JSON tests. This includes all 60 registration tests. The previously
  recorded concurrent full-suite scheduling limitation was not reassessed.
- Affected serial Release regression passed 319 tests in 23 suites. The initial
  concurrent selection hit the existing one-second first-operation waits in two
  mutation-owner tests; both failures and the serial retry are retained. Full
  Release was not run; the prior qualification-bundle limitation is unchanged.
- The unsigned Preview app, CLI and helper built for arm64 and x86_64. Bundle
  isolation and bundled CLI help/completion checks passed. Nothing was installed.
- Strict formatting of the new/expanded Swift files, project plist syntax,
  43 unique local documentation targets and `git diff --check` passed.
  Raw logs and build output remain under ignored `tmp/piv-recovery/`.

No real vault/configuration, installed product or token was changed. No
notarization, push or release was performed.

### First 804 adoption implementation, 2026-10-05

The adoption builder creates an explicit profile-2 to profile-3 child of the
exact locally authenticated checkpoint. It is not a new vault, a registration
or a profile discriminator change applied to old ciphertext. It retains the
whole device roster, creates profile-3 wrappers for active Macs only, rotates
the vault key and authority-transition ID, reseals every current entry and
creates a fresh epoch capsule. Entry identity, name, type and revision stay
unchanged. The initial recovery roster is empty, with no recovery wrapper or
protection claim.

The old active Mac signs the entire canonical child and exact parent digest.
The epoch proof is null because profile 2 supplies no prior epoch signer. The
independent validator checks strict parsing, old/new MACs and key identities,
the active parent's signature, exact roster and metadata, the new capsule and
all old/new plaintexts. Publication validation additionally opens the addressed
local new wrapper once and compares its key. Errors/cancellation return without
an automatic private-operation retry. No saved approval is returned.

Registration and adoption now share the bounded complete-entry snapshot checker.
Registration retains its existing error contract; its 60 tests are included in
regression. No new cryptographic primitive or dependency was introduced.

Eleven adoption tests cover secret/TOTP and Unicode metadata, a retained
revision-7 entry, multiple active Macs and a revoked Mac, empty vaults, opening
both active wrappers, wrong profile domains, independent validation, malformed
preparation before signing, snapshot/manifest limits, missing/duplicate objects,
changed roster/content/capsule/proof, wrong authorizer and local wrapper failure
or cancellation. A separate integration case uses the real contained filesystem
to present the exact signed adoption candidate to existing profile-2 discovery
and the access gate. Both ordinary and stale-read requests receive
upgrade-required before a wrapper operation. A follow-on software registration
uses the adopted snapshot as its parent and establishes its separate token floor.

The `v0.2.0` discovery and owner-signature guard files are unchanged from the
tested code. Related outer-parser differences are shared visibility/comments;
the coordinator difference is prompt copy. This supports the intended refusal
without claiming execution of the published binary or complete multi-Mac upgrade
qualification. A provider withholding the adoption file remains outside global
freshness guarantees.

This increment implements migration construction/validation only. Durable
adoption intent, exact resume, source/head and pending-state barriers,
manifest-last publication, checkpoint/session advancement and product routing
remain. Ordinary profile-3 mutation/lifecycle and integrated review/qualification
must pass before real-vault opt-in. No implementation package is marked complete.

Verification:

- Complete serial Debug regression passed 1,020 KeyCore tests in 91 suites and
  6 canonical-JSON tests. Focused adoption/registration regression passed all
  71 tests in three suites.
- Affected serial Release regression passed 330 tests in 24 suites. Full Release
  and concurrent full-suite scheduling were not reassessed; prior limitations
  remain recorded above.
- The unsigned arm64/x86_64 Preview app, CLI and helper built. Product-bundle
  isolation and bundled CLI help/completion checks passed.
- Strict formatting of the new/expanded Swift files, project plist syntax and
  `git diff --check` passed. Raw output remains under ignored `tmp/piv-recovery/`.

No installed product, real vault/configuration or token was changed. No native
authentication, hardware write, notarization, push or release was performed.

### Second 804 adoption implementation, 2026-10-05

The internal service now publishes and resumes the exact adoption candidate.
It reuses the contained immutable writer, shared mutation owner, local ownership
and checkpoint compare-and-swap. Registration and adoption share bounded exact
source inventory and preparation durability checks; each retains its domain
authentication and full snapshot validation. No new dependency or crypto
primitive was introduced, and shipping profile-2 dispatch stays unchanged.

One complete canonical encrypted preparation is stored under
`.recovery-adoptions/<operationID>/preparation.json`. A dedicated non-sync local
record pins the whole preparation digest. Unarmed ownership is reserved before
atomic installation, then promoted to recoverable only after exact readback,
one addressed local wrapper opening, complete old/new crypto validation and
file/directory synchronization. Resume repeats those checks on the same bytes;
it cannot regenerate keys or a signature. An ambiguous confirmation failure
must be reconfirmed, not inferred successful from readability.

Bounded inventory refuses competing same-vault manifests and projected budget
overflow. Other pending transaction/registration records, the source, local
ownership and checkpoint are checked before signing/publication and around
approval. Entries publish first and are read back before the manifest publishes.
The checkpoint advances after exact manifest/entry readback and source checks;
the verified new key then installs in the local session before ownership clears.

Committed reconciliation opens the current local wrapper once, authenticates
the capsule/MAC and complete current snapshot, and repairs session/ownership.
It does not decrypt old entries, publish again or re-sign. After ownership
cleanup, an explicitly selected provider preparation can reconcile only the
already committed exact local checkpoint; it cannot establish ownership,
advance trust or prove operation attribution. Encrypted files remain inert for
inspection. An incomplete unarmed reservation requires attention or explicit
exact-operation abandonment; recoverable ownership cannot use that escape.

Twenty service/storage tests exercise real crypto and filesystem publication,
13 interruption phases, lost replies, missing preparation, failed durability
confirmation, checkpoint and cleanup failures, session repair without old
entries, provider-only preparations, changed bindings/source/checkpoint,
competing manifests, pending barriers, cancellation without retry, projected
limits, canonical/aggregate bounds, no-overwrite and symlink containment.
Dedicated registration/adoption kinds are refused by ordinary recovery intents.
Local persistence and confirmation failures are scripted, not physical Keychain
or power-loss qualification.

Verification:

- Complete serial Debug regression passed 1,040 KeyCore tests in 92 suites and
  six canonical-JSON tests, including all final service and race cases.
- Affected serial Release regression passed 350 tests in 25 suites. This is not
  a full Release result or a reassessment of the previously recorded concurrent
  full-suite scheduling and qualification-bundle limitations.
- The unsigned arm64/x86_64 Preview app, CLI and helper built. Product-bundle
  isolation and bundled CLI help/completion checks passed.
- Strict formatting of the new/expanded Swift files, project plist syntax,
  51 local documentation targets and `git diff --check` passed. Raw logs/builds
  remain under ignored `tmp/piv-recovery/`.

No package is complete. Next is profile-3 ordinary mutation/catch-up and
lifecycle support, preserving recovery coverage without a connected token.
Product composition/status, reciprocal pending-state barriers, restore,
integrated review and physical/distribution qualification remain before
real-vault opt-in. No installed app, real vault/configuration or YubiKey was
changed, and no native authentication, push, notarization or release occurred.

### First 809 content increment, 2026-10-05

Add/edit/copy/move/remove candidates now preserve profile-3 recovery coverage.
Entry planning and content-delta policy were extracted from the existing
permanent-profile builder/validator. Existing callers keep their profile-2
codec, checkpoint authentication, envelope serialization and publication path.
The new builder uses the same entry operations but constructs a real profile-3
envelope. It does not fabricate a profile-2 parent or duplicate save/recovery
machinery. No new dependency or cryptographic primitive was introduced.

The exact parent checkpoint, current-key MAC/capsule and full current snapshot
are checked before planning. The new envelope changes only entries and its
single parent/MAC. It retains the vault-key epoch, complete Mac roster/wrappers,
capsule, inherited root proof, recovery generation, recipients and recovery
wrappers exactly. No token API, signer or private Mac wrapper operation is
available to the builder. Empty/unregistered vaults retain their existing
protection state, without implying registration or readiness.

The independent validator checks both manifest MACs/capsules, identical
same-epoch metadata, permitted entry counts/revisions and exact changed-entry
staging. It authenticates the complete before/after encrypted snapshots and
checks UTF-8 and canonical TOTP payloads. Move must preserve its source payload;
copy must
match a retained unchanged source of the same type. Changed authority, proof,
recipient status/generation/wrapper or device authorization is not a content
edit. This remains stricter than merely accepting a valid current-key MAC.

Fifteen tests cover the five operations, overwrite behavior, Unicode and retained
revisions, empty/no-recipient states, wrong checkpoint/key, incomplete snapshots,
source substitution, invalid names/IDs, noncanonical TOTP, changed authority and
coverage, manifest authentication/parent bindings, staging coverage, forbidden
operation kinds, mismatched copy/move payloads, revision overflow, per-object
and aggregate limits, and continued shipping-codec refusal of profile 3.

The cold-recovery case uses the real immutable filesystem writer to materialize
a software registration and five validated edit candidates. Original Mac
authority and vault-key variables leave scope before the public selector and
snapshot verifier receive only encrypted files, the pinned anchor and a software
token private key. One agreement recovers the selected final secret/TOTP values.
That proves construction/crypto interoperability, not an integrated save route,
real hardware budget or physical backup-token qualification. The test's writer
calls are fixture materialization, not production transaction publication.

Verification:

- Complete serial Debug regression passed 1,055 KeyCore tests in 93 suites and
  six canonical-JSON tests, including the final content and authentication cases.
- Affected serial Release regression passed 378 tests in 28 suites, including
  existing permanent-profile builders, mutation services and publication
  recovery. This is not a full Release result; previously recorded full Release
  qualification-bundle and concurrent full-suite scheduling limits remain.
- The unsigned arm64/x86_64 Preview app, CLI and helper built. Product-bundle
  isolation and bundled CLI help/completion checks passed.
- Strict formatting of the new Swift files, project plist syntax, 54 local
  documentation targets and `git diff --check` passed. Unchanged legacy source
  formatting was retained. Raw logs/builds remain under ignored
  `tmp/piv-recovery/`.

At the end of this increment, `REC-809` remained in progress. Next was profile-3 content publication and
interrupted-save reconciliation with explicit profile dispatch, reciprocal
pending ownership barriers and exact source/checkpoint guards. Same-epoch
multi-Mac catch-up, independent writes, branches/merges/resolution, lifecycle,
product services/CLI and qualification remain. No installed app, real
vault/configuration or YubiKey was changed. No native authentication, hardware
administration, push, notarization or release was performed.

### Second 809 content increment, 2026-10-05

Profile-3 same-epoch content candidates now have a durable library publication
and interrupted-save path. The existing permanent-profile publisher/recoverer
was extracted into a shared immutable transaction state machine. Separate
typed entry points select concrete validators; the kernel does not detect
profiles or reinterpret profile 3 through a profile-2 body. Existing intent
version, encrypted object layout, local pin phases and publication phase order
are retained. This shares the interruption logic rather than duplicating it.

The profile-3 validator independently authenticates the locally trusted parent,
complete before/after snapshots, exact changed-entry staging and unchanged
authority/coverage. It inventories bounded source manifests and projects the
floor/candidate storage budget before creating local intent. Ownership and
checkpoint checks surround source rechecks before immutable publication and
checkpoint CAS. Exact published entries are checked again immediately before
manifest publication. Same-vault competitors, substituted objects or changed
inventory cannot advance this single-parent transaction. The exact candidate's
own publication is the only permitted inventory addition during an operation.

Registration and adoption ownership dependencies are mandatory and separate
from the ordinary transaction pin. Pending authority work blocks new content
publication and resume; it is rechecked during the save. This complements the
existing registration/adoption refusal of an ordinary pin. Native namespace
composition and reciprocal shipping runtime barriers still require integration.
There is no token, private-device signer/unwrap or administration dependency in
the content publisher. The current session key is scoped to validation calls;
intent, staging and cache contain only encrypted/public bytes.

Recovery requires the exact locally pinned intent and current checkpoint. It
finishes the saved candidate without new randomness or repeating the original
request. An incomplete unpublished preparation can be abandoned at the old
checkpoint. Once a manifest is published, missing/corrupt references refuse
recovery and retain the pin. A committed checkpoint uses complete current
snapshot validation before cleanup, not old removed entry versions or old
manifest cache. Exact source inventory policy still applies; unexplained
same-vault objects are not ignored simply because intermediate history is
missing. Cache replacement occurs only after local cleanup succeeds.

Sixteen tests use real contained filesystem publication and real crypto, with
scripted local stores and failure injection. Cases cover every one of the 12
save phases, checkpoint/ownership changes, competing branches, pending authority
work, failed checkpoint CAS, cleanup with obsolete files removed, partial
preparation, missing published entries, corrupted objects/intent, wrong session
key, inconsistent typed envelopes, absent provider floor, projected bounds and
strict old-profile refusal. Provider intent without a local pin does nothing.

The cold-recovery case now publishes five content changes through the actual
library publisher, rather than fixture writer calls. Original Mac authority and
session key leave scope before recovery receives encrypted files, the pinned
anchor and software token key. One agreement recovers the final secret/TOTP
contents; ordinary saves cause no additional private-device or token operation.
This is not a measured real-hardware budget or native local-store qualification.

Verification:

- Final complete serial Debug regression passed 1,071 KeyCore tests in 94 suites
  and six canonical-JSON tests.
- Affected serial Release regression passed 394 tests in 29 suites, including
  recovery, capsule/native-boundary software tests, permanent-profile builders,
  publication, mutation services, enrollment/revocation and mutation ownership.
  This is not a full Release result; the previously recorded full Release
  qualification-bundle and concurrent scheduling limits remain.
- Final unsigned arm64/x86_64 Preview app, CLI and helper built. Bundle isolation
  and bundled CLI help/completion checks passed; each executable is universal.
- Strict Swift formatting, project plist syntax, 85 local documentation targets
  and `git diff --check` passed. Raw logs and builds remain under ignored
  `tmp/piv-recovery/2026-10-05-content-publication-*` and the existing product
  build directory.

`REC-809` remains incomplete. Next is same-epoch multi-Mac catch-up and branch
reconciliation, then resolution/lifecycle and service/CLI integration. No
installed app, real vault/configuration or YubiKey was changed. No native
authentication, token write, push, notarization or release was performed.

### Third 809 content increment, 2026-10-05

The ordinary profile-3 path now authenticates visible same-epoch forward history
and advances one local checkpoint at a time. The input is an exact locally
trusted manifest/checkpoint and already unlocked session key, not a synthetic
token anchor or a recovery wrapper. No native unlock, token reader/agreement,
signer, private Mac unwrap or provider writer is available to the service.

Bounded inventory, ancestry closure, topological ordering and revision progression
were extracted from the recovery selector for reuse. The selector's token-floor
checks, public epoch/roster policy, selected wrapper and reduced historical
replay promise remain separate and unchanged. The ordinary observer adds current
MAC/capsule authentication and complete snapshot checks for every visible
forward same-epoch manifest, including branches. Entries are deduplicated for
aggregate object/byte accounting; metadata, AEAD, UTF-8 and canonical TOTP checks
still apply to each snapshot. Old pre-floor snapshots are not decrypted.

The service owns `.catchUpVault` mutation serialization and requires exact
checkpoint state and no ordinary, registration or adoption pin. It repeats the
bounded source observation and compares exact manifests/entries, listing/count,
heads and traversal before the next direct-child checkpoint CAS. Multiple
authenticated content heads are reported without choosing one or changing local
trust. Cache failure cannot undo a committed checkpoint. A changed-key
descendant or multi-parent merge refuses this path, without retrying another key
or making a private call; this refusal does not authenticate a new epoch.

Nineteen tests use genuine filesystem storage and crypto, reusing the publication
suite's software vault/local-store fixtures. Independent local checkpoints and
caches catch up, publish a later edit through the real publisher, and let the
other checkpoint catch up in turn. Separate provider directories also permit
two real offline publications before exact immutable file delivery; catch-up
reports both resulting heads without selecting a winner. Other tests cover long
paths, unchanged floors, stale-write refusal, all pending namespaces, source and
checkpoint races, CAS loss, cache failure, missing/substituted objects, wrong
session keys, MAC/proof/coverage/revision and TOTP failures, merged/changed-key
refusal, malformed listings and per-object/aggregate/depth/edge/reference bounds.
An incomplete later snapshot prevents even the first step of a longer path.

This is a guarded step, not a full catch-up coordinator or access gate. A branch
delivered after successful CAS cannot undo the accepted child. The next step
refuses the now-unexplained same-vault lineage instead of returning up to date;
coordinator/branch reconciliation must classify and resolve it. No provider-global
freshness promise was added. The two-checkpoint simulation does not qualify two
physical Macs, native session/keychain behavior, provider delivery or backup
hardware. No shipping profile-2 codec or runtime dispatch was widened.

Verification:

- Complete serial Debug regression passed 1,090 KeyCore tests in 95 suites and
  six canonical-JSON tests.
- Affected serial Release regression passed 449 tests in 34 suites. It includes
  recovery/publication, the shared graph, the new ordinary step and existing
  profile-2 catch-up planner/coordinator/observer/service regressions. This is
  not a full Release result; the previously recorded qualification-bundle and
  concurrent scheduling limits remain.
- The unsigned arm64/x86_64 Preview app, CLI and helper built. Bundle isolation
  and bundled CLI help/completion checks passed; all three executables are universal.
- Strict Swift formatting, project plist syntax, 88 local documentation targets
  and `git diff --check` passed. Raw logs remain under ignored
  `tmp/piv-recovery/2026-10-05-content-catch-up-*`; product build artifacts stay
  in the existing ignored verification directory.

`REC-809` remains incomplete. Next is branch-aware catch-up coordination and
reconciliation, followed by merge/resolution publication and lifecycle/product
integration. No installed app, real vault/configuration or YubiKey was changed.
No native authentication, token write, push, notarization or release was performed.

### Fourth 809 content increment, 2026-10-05

The internal ordinary catch-up service now offers a coordinated same-epoch walk
as well as its guarded one-step API. One `.catchUpVault` mutation boundary covers
the entire walk, without nested queue ownership. Every step and terminal result
reuses the production observer's complete graph/snapshot authentication, repeated
exact-source equality checks, all three pending-work barriers and exact local
checkpoint checks. Direct-child CAS and best-effort cache storage are shared
with the one-step API. There is no additional signer, private Mac unwrap, token
operation, provider write or native session installation.

Two coordination choices were considered: move the observation floor forward
and recheck passed parents separately, or retain the original floor throughout
the operation. The latter preserves one closed authenticated forward graph and
lets the existing observer authenticate a late sibling after a successful CAS.
The coordinated result reports all visible heads and the accepted checkpoint
and step count without choosing a winner. Initially competing heads leave trust
unchanged; a later conflict retains already committed progress.

The currently committed manifest must remain present with exact bytes in each
new observation. Hiding a committed child cannot return an older floor as current.
A bounded step count refuses further advancement without undoing accepted CAS
operations; a terminal result at the exact bound is allowed. Source changes,
missing snapshots, checkpoint races or newly pending work refuse a terminal
current result. Complete observation is repeated for each step; no large-history
performance or native authentication budget has been measured.

Ten new test declarations extend the existing suite to 29, using genuine
filesystem objects, production publication and crypto. They cover a complete
two-step chain under one real mutation owner, unchanged state, initial branches,
late sibling delivery after CAS, exact and exceeded step budgets, every pending
namespace, lost checkpoint/provider state, changed terminal observations, hidden
committed manifests, incomplete snapshots and cache failure. Local checkpoint
and pending stores remain software fixtures; this is not native Keychain or
physical two-Mac qualification.

The retained floor is operation-local, not a new durable ancestry capability.
Starting a later invocation at an already-advanced checkpoint still refuses
unexplained siblings below that floor. Explicit branch reconciliation and
merge/resolution publication are the next increment. Changed-key and multi-parent
histories remain refused; native session composition and the shipping read/write
access gate are not enabled. `REC-809` remains incomplete.

Verification:

- The final combined step/coordination suite passed all 29 tests. A preceding
  focused recovery and existing catch-up run passed 229 tests in 14 suites before
  the final hidden-child test was added.
- Affected serial Release regression passed 463 tests in 34 suites, including
  the final coordinator source and all 29 step/coordination tests. This is not
  a full Release result. The locked-host run excluded the legacy mutation-owner
  suite whose handler test writes file-protected version-2 fixtures.
- The complete serial Debug attempt ran 1,099 KeyCore tests in 95 suites and
  reported 65 issues in existing file-protected storage/handler tests. The Mac
  reported `CGSSessionScreenIsLocked=Yes`; an unchanged focused storage test
  reproduced the permission failure at `.completeFileProtection` writes while
  the final 29-test catch-up suite passed. Six canonical-JSON tests also passed.
  The complete Debug suite still needs an unlocked-host rerun; no protection
  policy was changed to bypass this boundary.
- The unsigned arm64/x86_64 Preview app, CLI and helper built. Bundle isolation
  and bundled CLI help/completion checks passed; all three executables are universal.
- Strict Swift formatting, project plist syntax, local documentation targets
  and `git diff --check` passed. Raw logs remain under ignored
  `tmp/piv-recovery/2026-10-05-content-coordination-*`; product artifacts stay in
  the existing ignored build directory.

No installed app, real vault/configuration or YubiKey was changed. No native
authentication, token write, push, notarization or release was performed.

### Fifth 809 content increment, 2026-10-05

Profile-3 ordinary branches now have a read-only reconciliation path. It consumes
the production observer's complete authenticated forward tree. It does not accept
raw envelope arrays, invent a token anchor or convert profile-3 authority into an
older-profile body. Current MAC/capsule authentication, exact coverage/authority
equality, revision progression and complete entry snapshots remain the observer's
responsibility. The reconciler follows each exact head back to the local floor and
compares entries against their nearest common forward ancestor, not an arbitrary
head or necessarily the oldest floor.

Duplicating the existing conflict algorithm and extracting its content comparison
were compared. A shared `V3EntryReconciler` avoids separate rules drifting while
leaving profile-specific authentication and ancestry selection with their current
owners. The older public reconciler retains its authority checks, complete graph
validation, security/history conflict results and original merge-body construction.
The shared helper accepts exact head identities and entry records only. It neither
parses a profile nor authorizes a merge or checkpoint change.

Independent changes to different stable entry IDs produce logical merge entries,
including additions and deletions. Competing edits, edit-versus-delete, rename/edit,
different renames, concurrent creation and colliding destination names retain exact
conflict versions. Different ciphertext versions remain conflicted even when their
plaintexts match. The shared revision-rollback and same-revision-substitution rules
remain in place. The result is a merge plan or conflict report, not encoded bytes,
fresh source state, a publication permit or an advanced checkpoint.

Eleven new test declarations use real crypto, the production ordinary builder and
publisher, and independent offline filesystem providers. Each branch completes its
publication before exact immutable file delivery into a shared observation. Cases
cover one visible head, independent two/three-head changes, a shared comparison base
newer than the local floor, deterministic inventory ordering, competing ciphertext
versions with equal or different plaintext, deletion/edit/rename conflicts, same-name
destinations, concurrent creation, matching deletions and missing/substituted entries.
Local checkpoint/pending state stays unchanged, with no additional software signer
or private Mac unwrap calls after fixture registration.

All-parent merge/resolution construction, independent validation, durable publication
and resume remain next. The persisted ordinary one-parent intent is unchanged, and
the observer still refuses multi-parent or changed-key histories. Durable handling
of siblings below a later local floor and merged-history catch-up remain unfinished.
No shipping profile dispatch, native session/access gate, Keychain qualification or
physical multi-Mac/token acceptance was added. `REC-809` remains incomplete.

Verification:

- Focused old/new reconciliation regression passed 22 tests in two suites.
- Complete serial Debug regression passed 1,111 KeyCore tests in 96 suites and
  six canonical-JSON tests. The Mac no longer reported a locked screen; the
  existing protected-file tests passed without any policy change. This also
  closes the fourth increment's pending unlocked-host Debug verification.
- Affected serial Release regression passed 481 tests in 36 suites, including
  old/new reconciliation, recovery, publication, both catch-up paths and mutation
  ownership. This is not a full Release result; the previously recorded
  qualification-bundle limits remain.
- The unsigned arm64/x86_64 Preview app, CLI and helper built. Bundle isolation
  and bundled CLI help/completion checks passed; all three executables are universal.
- Strict Swift formatting, project plist syntax, 93 local documentation targets
  and `git diff --check` passed. Raw logs remain under ignored
  `tmp/piv-recovery/2026-10-05-branch-reconciliation-*`; product artifacts stay in
  the existing ignored build directory.

No installed app, real vault/configuration or YubiKey was changed. No native
authentication, token write, push, notarization or release was performed.

### Sixth 809 content increment, 2026-10-05

All-parent automatic merge and explicit conflict-resolution candidates now have
internal construction and independent validation. They consume an ordinary
authenticated forward-tree observation, not raw manifests or an older-profile
projection. Automatic merges reuse exact independent-change ciphertext records
and stage nothing. Complete explicit choices use the existing head-bound conflict
IDs, version IDs and resolution planner. Selected conflicted values are resealed
above every parent revision of their stable identity, retaining the selected
name/type/plaintext. Explicit deletions remain absent. Destination choices remove
only the other identities in that reported collision, retaining selected
ciphertext. Choices that introduce another name collision refuse construction.

Direct new selectors and reuse of the established CLI-safe selector/planner were
compared. Reuse keeps conflict IDs and complete-choice rules consistent without
enabling a new CLI route. The domain candidate remains separate from ordinary
single-parent content publication: merging all heads requires its own source,
pending-state and durable-intent/resume integration. Widening the existing
single-parent recovery guard as part of construction would mix those contracts.

Every candidate preserves the complete authority transition, Mac roster/wrappers,
key identity, capsule, inherited proof and recovery roster/generation/wrappers
exactly, with empty fresh boundary authorizations. The independent validator checks
the supplied floor/key and every exact parent snapshot, recomputes policy from
head-bound choices, verifies candidate MAC/capsule and all-parent metadata/revision
progression, and checks exact retained records, exact staged objects and the full
candidate AEAD/UTF-8/TOTP snapshot. Resealed plaintext must equal the selected source
value. Projected object/reference counts, aggregate bytes and depth include the new
manifest and new ciphertext objects. Counter overflow refuses resealing while
still permitting an explicit deletion.

Sixteen test declarations extend genuine offline-publication fixtures with these
domain checks. They cover deterministic automatic construction, coverage/ciphertext
preservation, selecting an older version above all parent revisions, deletion,
rename, destination choice, incomplete/duplicate/unknown/stale choices, new name
collisions, exact head/checkpoint/kind/metadata guards, changed selected values,
missing/extra staging, wrong session keys, projected limits and revision overflow.
A fixture-delivered automatic-merge candidate also opens through the real recovery
selector/snapshot verifier with one software agreement. That fixture delivery is
not production merge publication or physical-token qualification. The existing
single-parent publisher refuses an all-parent candidate before creating intent.

At this increment, choices were in-memory inputs only, not persisted approval or
authority. Builder and validator have no provider writer, checkpoint store, native
session or token capability. No durable intent or shipping profile dispatch was
changed in this increment. All-parent
publication/resume, merged-history observation/catch-up, durable handling of siblings
below a later local floor and product/native qualification remain unfinished.
`REC-809` remains incomplete. The next increment is all-parent durable publication
and exact interruption reconciliation.

Verification:

- Complete serial Debug regression passed 1,127 KeyCore tests in 97 suites and
  six canonical-JSON tests, including all 16 new construction/validation tests
  and the final single-parent-publication refusal test.
- Affected serial Release regression passed 510 tests in 39 suites. This includes
  recovery, capsule, ordinary publication, catch-up, old/new reconciliation and
  construction, existing conflict-choice/mutation services and mutation ownership.
  This is not a full Release result; the previously recorded qualification-bundle
  limits remain.
- The unsigned arm64/x86_64 Preview app, CLI and helper built. Bundle isolation
  and bundled CLI help/completion checks passed; all three executables are universal.
- Strict Swift formatting, project plist syntax, 95 local documentation targets
  and `git diff --check` passed. Raw logs remain under ignored
  `tmp/piv-recovery/2026-10-05-merge-construction-*`; product artifacts stay in the
  existing ignored build directory.

No installed app, real vault/configuration or YubiKey was changed. No native
authentication, token write, push, notarization or release was performed.

### Seventh 809 content increment, 2026-10-05

All-parent automatic merges and complete explicit conflict choices now have an
internal durable publisher and exact interruption reconciliation. A separate
durability state machine and reuse of the existing manifest-last kernel were
compared. Reuse avoids duplicating ordering, intent/pin CAS and exact cleanup.
The selected merge validator owns parent authentication, choice policy and source
rechecks. Narrow intent construction/validation/reconstruction hooks keep the
default ordinary content path single-parent; the kernel does not detect profiles
or acquire private-key/token capabilities.

Before intent, publication freshly authenticates the floor and complete forward
parent history/snapshots, recomputes the exact head-bound merge or explicit choices,
and verifies candidate coverage, selected plaintext, staging and projected limits.
The local pin binds a strict canonical version 3 intent with exact sorted heads
and bounded sorted conflict/version selectors. Selectors contain no plaintext and
grant no independent authority. Empty selectors mark automatic merge. Existing
version 1 content and version 2 enrollment bytes retain their schemas, including
the older generic publisher's multi-head version 1 intents. Ordinary profile-2/
profile-3 publishers and the older generic recoverer refuse the new merge shape;
the merge publisher refuses ordinary intents, even before staging exists.

The shared kernel stages and publishes ciphertext before the merge manifest,
reads back exact bytes and rechecks source/checkpoint/pending state before CAS.
Uncommitted resume revalidates all parents and choices against fresh source, then
reuses the exact encrypted candidate bytes without another choice or resealing.
An already-published exact candidate is excluded only from parent-head discovery,
not from inventory budgets. Other branches and children remain visible. Projected
manifest/entry/object/depth/edge budgets include the candidate once, including on
resume. Late branches or authority work, changed ciphertext, wrong keys and local
checkpoint/pin races cannot activate the stale candidate. Published-but-incomplete
state retains the local pin and refuses. After checkpoint commitment, exact cleanup
checks current authentication and the complete current snapshot without requiring
superseded ciphertext or old manifest/cache files. Ordinary saves after a completed
merge preserve the same recovery coverage.

Nineteen publication test declarations and five intent test declarations use real
crypto and contained immutable filesystem storage. They cover all 12 applicable
durable phases for resealed resolution and all 10 for automatic merge, exact resume,
checkpoint CAS failure, current-only committed cleanup, pending work and competing
mutations, newly delivered branches, checkpoint/pin races, wrong keys, missing or
changed ciphertext, pin/selector substitution, cross-publisher refusal, strict
versioned canonical parsing, malformed/oversized intents, exact/tighter resource
budgets and ordinary saves after merge. Both durably published merge kinds open
through the public history/snapshot verifier with one software agreement. This is
not physical approval-budget measurement or native session/Keychain qualification.

At this increment, `REC-809` remained incomplete. Next was observing and accepting
merged history from an earlier local floor, with durable handling for siblings
below a later floor.
Service/CLI composition, lifecycle, integrated review and native/product/hardware
acceptance remain separate work. No shipping profile dispatch was enabled.

Verification:

- Complete serial Debug regression passed 1,151 KeyCore tests in 99 suites and
  six canonical-JSON tests, including all 24 new test declarations.
- Affected serial Release regression passed 534 tests in 41 suites, including
  recovery, capsule, ordinary publication, catch-up, reconciliation, merge durability,
  conflict/mutation services, intent-sharing lifecycle paths and mutation ownership.
  This is not a full Release result; the previously recorded qualification-bundle
  limits remain.
- The unsigned arm64/x86_64 Preview app, CLI and helper built. Bundle isolation
  and bundled CLI help/completion checks passed; all three executables are universal.
- Strict Swift formatting for the new/updated profile-3 and kernel files, project
  plist syntax, 98 local documentation targets and `git diff --check` passed.
  The older generic recoverer retains its existing layout with one shape guard.
  Raw logs remain under ignored
  `tmp/piv-recovery/2026-10-05-merge-publication-*`; product artifacts stay in the
  existing ignored build directory.

No installed app, real vault/configuration or YubiKey was changed. No native
authentication, token write, push, notarization or release was performed.

### Eighth 809 content increment, 2026-10-05

Ordinary same-epoch observation now authenticates closed forward merged history
from the exact supplied checkpoint/session key. Each non-floor manifest checks
current MAC/capsule, exact authority and recovery metadata against every parent,
all-parent revision progression and its complete bounded AEAD/UTF-8/TOTP snapshot.
Unselected parent ciphertext is not skipped. Changed-key history still requires
the separate lifecycle path; no private unwrap, native prompt or token operation
is available here. Earlier snapshots outside the supplied floor remain outside
this replay obligation.

Walking one branch before a join, jumping directly to the terminal head and
choosing unambiguous intermediate advance points were compared. The last option
preserves linear direct-child steps and bounded partial progress without selecting
a side of a resolved fork or skipping an earlier join. The pure DAG policy computes
the immediate-dominator chain of the sole authenticated visible head and chooses
its earliest member strictly forward of the current checkpoint. A multi-parent
join is accepted only after the entire visible source and all parent snapshots
have passed authentication twice. Unresolved heads still stop advancement.

The predecessor-chain intersection representation follows
[Cooper, Harvey and Kennedy's dominance algorithm](https://ustc-compiler-principles.github.io/2023/lab4/Dom.pdf),
adapted here to an already-validated acyclic topological graph. All predecessors
are processed before a child, so no cyclic fixed-point iteration is needed. The
advance calculation retains linear graph state instead of per-node ancestor sets;
its work is bounded by parent edges times history depth. A separate iterative
ancestor intersection supports reconciliation without recursion or arbitrary
merge-base selection. Multiple nearest bases reuse the existing history-conflict
report and refuse ordinary merge construction. Candidate depth accounting now
handles all-parent histories, allowing another real merge after a prior join.

The coordinator retains its initial floor, repeats complete source/pending/local
checkpoint checks at every replacement and terminal result, and cannot roll back
or claim current if an accepted manifest disappears. It can accept a newly
published join of a late sibling during the same call, even when that sibling
bypasses a checkpoint accepted earlier in the call. A new call whose co-parent
lies below its supplied later floor still refuses as unanchored. No durable trust
floor, ancestry journal or fallback root was invented in this increment. This
remaining refusal is covered and must be addressed before product composition.

Fourteen integration declarations cover automatic and explicit-choice production
publication followed by an independent reader, common prefixes, repeated joins,
post-merge saves, missing manifests and unselected/selected ciphertext, invalid
progress, wrong keys, source delivery changes, every pending namespace, checkpoint
CAS loss, late siblings with/without a subsequent join, exact step budgets and
failing cache, disappeared committed joins, below-floor co-parents, criss-cross
bases and aggregate object/depth/reference/edge/byte limits. Three pure-graph test
declarations compare advance points and nearest bases against an independent
set-based reference for all 9,765 rooted labelled topologically ordered six-node
DAGs, and check malformed inputs and exact floor cuts.

The obsolete fixture-only multi-parent-refusal test was removed in favor of these
real publication-to-reader cases. The offline writer fixture now copies only a
merged checkpoint's exact known ancestor manifests, without copying later sibling
branches or requiring historical ciphertext. The existing source guard correctly
refused the previously incomplete ancestry fixture; production policy was not
weakened to accommodate it.

`REC-809` remains incomplete. Next is durable ancestry handling for siblings and
co-parents below a later local floor. Service/CLI composition, epoch lifecycle,
integrated review and native/product/hardware acceptance remain separate work.
No shipping profile dispatch or persisted schema was changed.

Verification:

- Full serial Debug regression: 1,167 KeyCore tests in 101 suites and six
  canonical-JSON tests passed. Seventeen new test declarations replace one
  obsolete refusal declaration.
- Affected optimized Release regression: 550 tests in 43 suites passed, covering
  recovery, PIV software policy, epoch signing, older-profile reconciliation and
  device transitions, immutable durability, content mutation/catch-up and mutation
  ownership/UX. This was not a full Release run; the previously recorded
  qualification-bundle limitations remain.
- Unsigned universal Preview build passed. App, CLI and helper contain arm64 and
  x86_64 slices. Product bundle and CLI help/completion checks passed; no app was
  installed.
- Strict Swift formatting, Xcode project plist validation, 102 local documentation
  link targets and `git diff --check` passed.
- Raw logs use the ignored prefix
  `tmp/piv-recovery/2026-10-05-merged-catch-up-`; product artifacts remain in the
  existing ignored build directory.

No installed app, real vault/configuration or YubiKey was changed. No native
authentication, token write, push, notarization or release was performed.

### Ninth 809 content increment, 2026-10-05

Late same-epoch siblings and merge co-parents below an advanced checkpoint now
use exact ancestry committed transitively by that checkpoint. A separate stored
older floor/journal and reconstruction from immutable parent hashes were compared.
Reconstruction reuses the existing rollback anchor and avoids another trusted
store, two-record commit ordering, migration and recovery protocol. Provider bytes
remain untrusted input; each required address must match its hash before parsing.
This is not selection of an older checkpoint or trust in a provider-supplied root.

The ordinary observer first attempts its existing forward cut. Only an
unanchored-parent result permits bounded checkpoint ancestry reconstruction. Every
required same-epoch ancestor checks current MAC/capsule and exact inherited
authority, roster, wrapper, proof and recovery metadata. Ordinary/all-parent entry
progress checks, unique-root closure, acyclicity and the existing graph budgets
remain. Reconstruction stops at the exact committed origin or authorized epoch
boundary whose single parent matches the inherited transition proof. It does not
reopen that boundary's parent, authenticate an old epoch with the current key or
unwrap a historical key. Missing required same-epoch manifests still refuse.

The reconstructed graph cut and committed-ancestor set are observer-owned fields,
not caller-issued trust capabilities. The current checkpoint remains the sole
expected CAS value. Current and every newly encountered branch snapshot fully
authenticate, including unselected merge parents. Older committed snapshots are
not reopened merely to explain links or compare records. An older shared base's
entry records are usable because their exact bytes are linked to the checkpoint;
that does not establish current availability of its old ciphertext. Fresh
observation equality and publication rechecks include the reconstructed scope.

Both catch-up APIs can report a late conflict and accept its published join
without rewinding or checkpointing an old side. Branch comparison and automatic
or explicit-choice merge construction keep the advanced checkpoint while using
the older shared base. The existing manifest-last publisher and interruption
recovery reuse that same scope; ordinary single-parent intent and shipping profile
parsing are unchanged.

Nine additional integration declarations cover late-branch reporting,
reconciliation and real publication from an advanced checkpoint; missing older
committed ciphertext; missing/substituted required ancestors and new branch
ciphertext; disconnected same-epoch fixtures; exact depth bounds; unavailable
pre-boundary state; late branches predating an already committed join; source,
all three pending namespaces and concurrent checkpoint changes; and interrupted
automatic/explicit publication before/after manifest publication and after CAS.
The two earlier below-floor refusal cases now assert authenticated conflict/join
behavior instead. No signing-attack reproduction or token operation is involved.

`REC-809` remains incomplete. Next is internal service composition, with integrated
domain acceptance and reciprocal mutation barriers before CLI/native enablement.
Epoch/device/recipient lifecycle remains `REC-810`; restore orchestration, product
integration, integrated review and physical acceptance are still separate work.
No persisted schema or shipping profile dispatch was changed.

Verification:

- Final serial Debug run excluding five locked-host-dependent legacy suites:
  1,108 KeyCore tests in 96 suites and six canonical-JSON tests passed, including
  all 23 merged-history test declarations and automatic/explicit interruption
  cases. The five excluded suites contain 68 declarations and still need an
  unlocked-host rerun.
- An earlier full Debug attempt reported 65 issues in unchanged file-protected
  storage/handler tests. Read-only host inspection confirmed `IOConsoleLocked`
  and `CGSSessionScreenIsLocked` were true. No protection policy was changed;
  the user was asked to unlock the host.
- Affected optimized Release regression: 552 tests in 42 suites passed, covering
  recovery/PIV software policy, epoch signing, graph reconciliation, device
  transitions, immutable durability and content mutation/catch-up. The
  locked-host legacy mutation-owner suite was excluded. This was not a full
  Release result; earlier qualification-bundle limitations remain.
- Unsigned universal Preview build passed after correcting the new source's
  Xcode build-phase reference. App, CLI and helper contain arm64 and x86_64
  slices. Product bundle and CLI help/completion checks passed.
- Strict Swift formatting, Xcode plist validation, 105 local documentation link
  targets and `git diff --check` passed.
- Raw logs use the ignored prefix
  `tmp/piv-recovery/2026-10-05-checkpoint-ancestry-`; product artifacts remain in
  the existing ignored build directory.

No installed app, real vault/configuration or YubiKey was changed. No native
authentication, token write, push, notarization or release was performed.

### Tenth 809 content increment, 2026-10-05

An internal ordinary mutation service now composes the production profile-3
builders, publishers, pinned interruption recovery, coordinated same-epoch
catch-up and branch reconciliation behind `VaultMutationServicing`. Extending
the shipping profile-2 service with implicit profile selection was compared with
an explicit profile-3 service. The explicit service avoids older-profile trust
projections and keeps shipping dispatch unchanged. It reuses the existing
in-memory Mac-bound vault-key session and the helper-owned serialized boundary.
There is no new key store, signer, unwrap, token administration or native prompt.

Every operation loads the exact checkpoint/provider manifest and matching session
key. Provider bytes must match the checkpoint digest before they can affect
session binding. Publication authority comes from fresh complete source validation,
not the preliminary authorization check. Catch-up and observation repeat local
pending/checkpoint/source guards before planning. An automatic merge uses a fresh
separate operation identity, then the requested save is replanned at the committed
merge. If that save fails, the merge remains committed and the request still fails.
Explicit conflict choices are rebuilt against fresh metadata and current heads.
Conflict inspection stays inside the serialized boundary; this is not yet the
concurrent-safe read/status service used by the product.

Interrupted ordinary or merge work is selected only from the exact operation
pinned by device-local ownership. Canonical bounded intent bytes must match that
pin before choosing the concrete validator. The shared kernel now accepts an
optional expected ownership record and checks it before any resume or unstaged
abandonment. A changed or missing pin cannot redirect recovery to another operation.
Existing direct callers keep their defaults, schemas and validator selection.
Unowned synchronized intents remain inert; missing recoverable evidence refuses.

Nineteen integration declarations exercise actual sessions and filesystem/crypto
publication: all ordinary entry methods, normalization/overwrite, catch-up before
copy, separate automatic-merge/save identities, fresh explicit selectors, late
branches, interruption before/after manifest publication and checkpoint CAS,
missing/malformed/unowned intent handling, changed/missing ownership, session
binding/invalidation, unavailable/substituted current provider objects, entry-ID
collisions, failed post-merge saves, and authority work arriving during intent
persistence. A cold software recovery case opens service-saved contents after the
original session/service leave scope, with one software agreement and no original
Mac record. These are not physical approval measurements or native qualification.

`REC-809` remains incomplete. Next are reciprocal pending-state barriers in
authority/runtime composition and final domain acceptance. Native unlock,
concurrent-safe reads/status, profile-3 lifecycle (`REC-810`), restore orchestration,
shipping product/CLI dispatch, integrated review and physical acceptance remain.
No implementation package `REC-804` through `REC-815` is marked complete.

Verification:

- Complete serial Debug regression passed: 1,195 KeyCore tests in 102 suites and
  six canonical-JSON tests, including all 19 new service declarations. The earlier
  locked-host gap is closed: all 68 legacy declarations passed separately on the
  unlocked host and are included in this full run. No storage protection policy
  was changed.
- Affected optimized Release regression passed: 578 tests in 44 suites, including
  recovery/PIV software policy, epoch signing, reconciliation, device transitions,
  immutable publication/resume, ordinary mutations/catch-up and mutation
  ownership/UX. This was not a full Release run; the previously recorded
  qualification-bundle limitations remain.
- Unsigned universal Preview build passed. App, CLI and helper contain arm64 and
  x86_64 slices. Product bundle and CLI help/completion checks passed; no app was
  installed.
- Strict Swift formatting, Xcode project plist validation, 109 local documentation
  targets and `git diff --check` passed. Shared four-space source files retain
  their existing formatting; formatter configuration and raw logs are ignored.
- Raw logs use `tmp/piv-recovery/2026-10-05-service-composition-`; product artifacts
  remain in the existing ignored build directory.

No installed app, real vault/configuration or YubiKey was changed. No native
authentication, token write, push, notarization or release was performed.

### Reciprocal 808/809 service guards, 2026-10-05

Registration now requires ordinary-transaction and adoption ownership stores,
matching the existing adoption dependency pattern. Mandatory exact stores were
chosen over a generic optional callback or a new cross-service coordinator.
Callers must supply both competing namespaces, no new lock or format
is introduced, and the existing mutation owner remains serialization authority.
All services must be composed with that same owner and device-local namespaces.
This does not implement an atomic cross-process protocol.

Existing competing work blocks prepare, export resume, finish and committed/lost
reply repair before private operations. Any present record blocks, including
malformed bytes; storage read failures propagate. Registration and adoption
recheck competing namespaces around exact checkpoint reads at effect boundaries.
Registration also rechecks after public token validation, before publication/CAS,
and before session repair or ownership cleanup. Work arriving during approval
stops the remaining effects without clearing its marker or the exact preparation.
Already advanced checkpoints stay committed. Explicit retry before commitment
requires new possession; committed reconciliation needs no hardware agreement,
new signature or repeated publication. Platform operations already in flight are
not guaranteed cancellable. No automatic retry was added.

Adoption's existing exact unarmed-reservation abandonment stays local-only. It
can release its own prepared pin without publishing, advancing trust or clearing
another service's work. Ordinary mutation already has the reverse guards; no
shipping profile dispatch or product-runtime routing is enabled by this increment.

Thirteen new declarations test the services with real crypto/filesystem
publication and scripted local/native boundaries. Registration checks competing
ordinary/adoption work before signing, resume and finish, during preparation,
local unwrap, agreement, staging, manifest verification, checkpoint activation,
session update and committed repair. Its unreadable-store case fails closed.
Adoption checks prepared resume, late durable boundaries and committed repair
before/after ownership cleanup. Assertions distinguish committed state from
unpublished work, preserve exact pins and reject repeated private operations.

Two real composition cases share the same stores and mutation owner. A real
pinned ordinary save blocks registration until its publisher resumes; registration
then binds its preparation to that resulting checkpoint. A pending registration
blocks ordinary edits; activation installs its exact new session key, a following
ordinary edit succeeds, and the public recovery verifier opens that edited state
through a software receiver. These are not native or physical-token tests.

Internal reciprocal guards are implemented. `REC-808` and `REC-809` still need
shipping runtime/product acceptance, final integrated domain review and native
qualification. Next domain work is recovery coverage across key/device/recipient
changes (`REC-810`), followed by restore orchestration and product integration.
No implementation package is marked complete and no real-vault opt-in is enabled.

Verification:

- Focused service regression passed: 71 tests in three suites, including 13 new
  declarations and their parameterized interruption/resume cases.
- Complete serial Debug regression passed: 1,208 KeyCore tests in 102 suites and
  six canonical-JSON tests on the unlocked macOS 27.0 (`26A428`) host. No suites
  were excluded; macOS 26+ software receiver cases ran on this supported host.
- Affected optimized Release regression passed: 591 tests in 44 suites, covering
  recovery/PIV software policy, epoch signing, reconciliation, device transitions,
  immutable publication/resume, ordinary mutations/catch-up and ownership/UX.
  This was not a full Release run; earlier qualification-bundle limitations remain.
- Unsigned universal Preview build passed. App, CLI and helper contain arm64 and
  x86_64 slices. Product-bundle isolation and CLI help/completion checks passed;
  no app was installed.
- Strict formatting, 113 local documentation targets and `git diff --check`
  passed. Raw logs use `tmp/piv-recovery/2026-10-05-pending-barriers-`; build
  artifacts remain in the existing ignored directory.

No installed app, real vault/configuration or YubiKey was changed. No native
authentication, token write, push, notarization or release was performed.

### First 810 epoch component, 2026-10-05

An internal key-rotation builder and independent validator now construct complete
profile-3 epochs without changing device/recipient authority. Devices, recipient
records/statuses and recovery generation remain exact. All entries reseal under
a fresh key while keeping their identities, names, types, revisions and values.
A fresh transition ID and epoch capsule replace the old epoch; the old epoch
key and active Mac authorize the complete child through the existing boundary
protocol. Stored public keys create one wrapper per active Mac/recipient without
requiring a connected token. Revoked records receive no wrapper.

Extending the profile-2 builder through a profile projection was compared with
sharing unsigned profile-3 material already duplicated in registration. Shared
material avoids older-profile trust/body projections and separate encryption and
wrapping implementations. Registration retains its own addition, generation-change,
anchor/intent and possession policy. Rotation independently requires unchanged
device/recipient rosters and generation. No unchecked generic roster callback
authorizes lifecycle changes. Profile-2 builders, signing transcripts, profile
dispatch and persisted schemas are unchanged.

Material construction bounds plaintext/entry work and verifies strict body parsing
with envelope/proof room before the Mac signer is invoked. Its output contains
only the unsigned body and encrypted entries, never plaintext/raw keys. Parent
authority and complete current snapshot authentication remain caller prerequisites.
Normal rotation validation checks exact checkpoint/parent MAC and capsule, direct
boundary signatures, independent fresh epoch, exact rosters, complete staged
objects and old/new plaintext equality. Staged byte budgets apply before parsing
their ciphertext. Optional local-wrapper verification follows full software
validation, opens one addressed wrapper, compares its key and propagates
cancellation without retry. No physical authentication count is qualified here.

Sixteen new software declarations cover authority/value preservation, empty and
unregistered vaults, active/revoked device/recipient coverage, real wrapper opening,
invalid keys/owner/reason/transition, missing/extra/substituted current objects,
construction and independent-validation budgets, exact staged snapshots,
incorrect resealing, misclassified recipient addition, checkpoint/key mismatch,
local unwrap/cancellation/mismatch and unsigned plaintext-identity completeness.

A disposable filesystem case follows three successive rotation candidates and
an actual ordinary-service save. Both primary and backup credentials select/open
the final state with one software agreement each after the original Mac identity
and session leave scope. Superseded snapshot ciphertext is removed. This exercises
the existing public-history/current-snapshot recovery contract without reopening
every old epoch. Rotation candidates and their checkpoints are materialized by
test setup; this is not a production rotation publisher or service.

REC-810 remains incomplete. Next are device/recipient transition policies over
this foundation, durable lifecycle publication/resume and authenticated key-epoch
catch-up. Removal needs the separately reviewed loss-of-protection policy.
Restore orchestration, native/runtime/CLI integration, integrated review and
physical acceptance remain. No implementation package is marked complete.

Verification:

- Focused rotation/registration regression passed: 86 tests in three suites.
- Complete serial Debug regression passed: 1,224 KeyCore tests in 103 suites and
  six canonical-JSON tests. No suites were excluded.
- Affected optimized Release regression passed: 607 tests in 45 suites, including
  recovery/PIV software policy, epoch signing, reconciliation, device transitions,
  immutable publication/resume, ordinary mutations/catch-up and ownership/UX.
  This was not a full Release run; earlier qualification-bundle limitations remain.
- Unsigned universal Preview build passed. App, CLI and helper contain arm64 and
  x86_64 slices. Product-bundle isolation and CLI help/completion checks passed;
  no app was installed.
- Strict formatting, 118 local documentation targets, Xcode project syntax and
  `git diff --check` passed.

Raw logs use `tmp/piv-recovery/2026-10-05-key-rotation-`; build artifacts remain
in the existing ignored directory.

No installed app, real vault/configuration or YubiKey was changed. No native
authentication, token write, push, notarization or release was performed.

### Second 810 enrollment component, 2026-10-05

The internal profile-3 enrollment builder and independent validator add one Mac
from the exact signed comparison ceremony. Both invitation and join-request
signatures, inviter role, awaiting-comparison phase, expiration, vault, checkpoint
and active inviting identity must match. The existing transcript-derived transition
ID binds the new signed epoch and every wrapper to that comparison. Consumed,
unrelated or expired ceremonies and enrolled/reused keys refuse before signing.

The complete old device roster, including revoked tombstones, is preserved with
one active addition. Recovery recipients, registration identities/statuses and
generation remain exact. A distinct key and capsule replace the epoch, all entries
reseal with identical identities/metadata/values, and stored public keys create
wrappers for every active Mac and recipient. No connected token is required.

Broadening the older profile-2 enrollment builder/validator was compared with
reusing its signed ceremony and the new profile-3 material/boundary components.
Separate profile-specific policy avoids projecting profile-3 into older trusted
checkpoint/body types or changing shipping profile dispatch. Rotation and enrollment
now share bounded epoch-signature, metadata, snapshot equality and addressed local
wrapper checks. Each keeps its own independent roster validator; no generic
unchecked callback authorizes membership. Profile-2 behavior and persisted
ceremony, manifest and recovery formats are unchanged.

Fifteen new declarations cover complete enrollment, empty/unregistered vaults,
real software device-wrapper opening, expiration/role/phase/checkpoint mismatch,
invalid message authentication, invalid keys/owner/reason, enrolled/reused keys,
exact transcript/transition binding, misclassified operations, independent roster
decisions, construction/publication budgets, incomplete snapshots, cancellation
and revoked tombstones. Full software validation precedes one optional addressed
local unwrap; provider cancellation does not retry. Physical prompt counts remain
unqualified.

Two successive enrollment candidates are materialized through disposable
filesystem setup. The newly added member can authorize the next enrollment.
An actual ordinary mutation-service save follows. Primary and backup software
credentials each recover the final secret and TOTP with one agreement after all
Mac private identities/sessions leave scope and superseded ciphertext is removed.
This is not enrollment publication, joining-Mac adoption or key-transition catch-up.

Revocation and recipient lifecycle policy remain next, followed by durable epoch
publication/resume, ceremony consumption, joining adoption and authenticated
catch-up. Restore orchestration, product/runtime/CLI integration, integrated review
and physical acceptance remain. No implementation package is marked complete and
no public command or real-vault opt-in is enabled.

Verification:

- Focused enrollment/rotation/registration regression passed: 130 tests in five
  suites, including the older profile-2 enrollment regression.
- The same 130 focused tests in five suites passed in optimized Release.
- Complete serial Debug regression was attempted on the locked host: 1,239
  KeyCore tests in 104 suites reported 65 issues across five existing suites,
  beginning with denied writes through `EntryStore`'s unchanged complete-file-
  protection path and cascading missing-entry assertions. The six canonical-JSON
  tests passed. This is not a clean full-regression result; an unlocked rerun is
  required. The separately gated large-migration qualification case was skipped.
- Affected optimized Release regression was attempted: 622 tests in 46 suites
  reported seven issues in the existing mutation-owner handler fixture, beginning
  with the same protected legacy write and cascading missing-entry assertions.
  This is not a clean broad Release result; an unlocked rerun is required.
- Unsigned universal Preview build passed. App, CLI and helper contain arm64 and
  x86_64 slices. Product-bundle isolation and CLI help/completion checks passed;
  no app was installed.
- Strict formatting, 123 local documentation targets, Xcode project syntax and
  `git diff --check` passed.

Raw logs use `tmp/piv-recovery/2026-10-05-recovery-enrollment-`; build artifacts
remain in the existing ignored directory. No installed app, real vault/configuration
or YubiKey was changed. No token operation, administration, push, notarization or
release was performed.

### Third 810 revocation component, 2026-10-05

The profile-3 planner authenticates the exact parent checkpoint, current MAC and
epoch capsule before reconstructing the established one-device revocation rule.
The builder and independent validator recompute and compare the entire reviewed
plan: checkpoint, active authorizer, selected active device and resulting roster.
Exactly one other active device becomes a revoked tombstone. The approving Mac
must remain active; unknown/revoked selections, self-revocation and loss of the
last active Mac refuse. The existing profile-2 planning error order is preserved.

Copying that roster rule into a new profile-3 planner was compared with extracting
the profile-independent policy. Both planners now share the pure rule while each
keeps its own exact profile/checkpoint authentication boundary. The shared policy
establishes no trust or saved approval. Existing plan types, persisted formats,
signing transcripts and shipping dispatch are unchanged. Only the policy was
extracted from the older planner; its cryptographic validation was not projected
onto profile 3.

The revocation builder reuses bounded unsigned epoch material; the validator
reuses boundary authorization, complete metadata/plaintext comparison and
addressed local-wrapper checks. Recipient identities/statuses/registrations and
generation remain exact. A fresh vault key, transition ID and signing capsule
replace the epoch. Every entry reseals without changing its identity, metadata
or value. Stored public keys create wrappers for all active Macs and recovery
recipients, never for revoked records. Full software validation precedes optional
one approving-Mac unwrap, with provider cancellation propagated without retry.

Fifteen software declarations cover exact reviewed planning and resealing, empty
and unregistered vaults, remaining-device wrappers, old-key/new-snapshot separation,
unknown/revoked/self/last-active refusals, stale/changed plans, wrong keys/owner/reason/
transition, another active authorizer, independent roster/generation policy,
construction/publication budgets, incomplete/substituted/duplicate snapshots and
signing/unwrap cancellation. Existing copied old state still opens with its old
key; no retroactive revocation claim is made.

A disposable filesystem case materializes enrollment and revocation, then performs
an actual ordinary mutation-service save. Primary and backup credentials each
recover the latest secret and TOTP with one software agreement after all Mac
private identities/sessions leave scope and superseded ciphertext is removed.
Materializing epochs/checkpoints is test setup, not a revocation publisher,
confirmation flow, interruption recovery or remaining-Mac catch-up.

Recipient removal policy, including explicit last-recipient loss-of-protection
review, remains next. Durable lifecycle publication/resume, ceremony consumption,
joining adoption, key-transition catch-up, restore orchestration, product/runtime/
CLI integration, integrated review and physical acceptance remain. No package is
marked complete and no public command or real-vault opt-in is enabled.

Verification:

- Focused revocation/enrollment/rotation/registration Debug regression passed:
  177 tests in 11 suites, including the existing profile-2 revocation planner,
  transition/publication and enrollment cases. Fifteen new declarations were added.
- The same 177 tests in 11 suites passed in optimized Release.
- Unsigned universal Preview build passed. App, CLI and helper contain arm64 and
  x86_64 slices. Product-bundle isolation and CLI help/completion checks passed;
  no app was installed.
- Strict formatting of the new components/tests, 130 local documentation targets,
  Xcode project syntax and `git diff --check` passed. The older planner's existing
  formatting was retained outside the extracted block.
- The host remained locked, so the previously failed full Debug and broader
  Release regressions were not repeated. Their protected legacy-fixture write
  failures still require an unlocked rerun; no protection or test guard was weakened.

Raw logs use `tmp/piv-recovery/2026-10-05-recovery-revocation-`; build artifacts
remain in the existing ignored directory. No installed app, real vault/configuration
or YubiKey was changed. No token operation, administration, push, notarization or
release was performed.

### Fourth 810 recipient-removal component, 2026-10-06

The internal planner authenticates the exact parent checkpoint, current MAC and
epoch capsule before selecting one active recovery recipient. The builder and
independent validator reconstruct the entire reviewed decision: checkpoint,
active authorizer, selected credential and resulting roster. Exactly that record
becomes revoked; its public key, registration and slot remain as a tombstone.
Every other recipient record and the complete Mac roster remain unchanged.
Unknown and already revoked selections refuse before signing.

A general last-recipient override was compared with an acknowledgment bound to
the complete reviewed plan. The latter is implemented. Last removal requires
that exact acknowledgment at construction and independent validation; another
checkpoint, authorizer or credential cannot reuse it. Ordinary removal rejects
the acknowledgment rather than treating it as a force flag. The product must
collect informed user confirmation before creating this in-memory value. Its
existence does not prove human consent, durable approval or permission to resume;
it is not saved in the encrypted candidate or manifest.

Removal reuses the bounded unsigned epoch material and shared full snapshot
validation, with its own recipient policy. A fresh vault key, transition ID,
signing capsule and recovery generation replace the epoch. Every entry reseals
without changing identity, metadata or plaintext. Stored public keys create
wrappers for all active Macs and remaining recovery credentials, not revoked
records. Full independent software validation precedes optional one addressed
local-Mac unwrap; cancellation and a mismatched provider result do not retry.
No hardware operation is needed for construction. The removed token and its
external anchor are not cleared, overwritten or reset.

Fifteen software declarations cover complete preservation and empty snapshots,
last-recipient default refusal and exact acknowledgment, nontransferability and
ordinary-removal override refusal, changed plans, unknown/revoked selections and
unknown authorizers, wrong keys/owner/reason/epoch identifiers, independent
recipient/generation/device policy, resource budgets, incomplete/substituted/
duplicate snapshots and signing/unwrap cancellation or mismatch. Old copied
states still open with their old keys, but those keys cannot open the new snapshot.
Later rotation preserves an all-revoked recovery roster without silently
reactivating coverage.

Disposable filesystem cases materialize primary, backup and last-recipient
removal, then perform an actual ordinary mutation-service save. Remaining
credentials recover the latest secret and TOTP with one software agreement after
original Mac private identities/sessions leave scope and superseded-epoch ciphertext
is removed. Removed credentials refuse at the visible new head during public
selection, before any agreement and without fallback to older wrappers. Ordinary
Mac-authorized saves remain usable after all recovery recipients are revoked.
These epoch/checkpoint setups are not a lifecycle publisher or confirmation UI.

The next increment is durable lifecycle publication/resume over these validated
outputs. User-confirmation flows, ceremony consumption, joining adoption,
key-transition catch-up, restore orchestration, product/runtime/CLI integration,
integrated review and physical acceptance remain. No package is marked complete
and no public command or real-vault opt-in is enabled. Profile-2 behavior and
persisted formats are unchanged.

Verification:

- Focused removal/revocation/enrollment/rotation/registration Debug regression
  passed: 192 tests in 12 suites, including existing profile-2 revocation planner,
  transition/publication and enrollment cases.
- The same 192 tests in 12 suites passed in optimized Release.
- Unsigned universal Preview build passed. App, CLI and helper contain arm64 and
  x86_64 slices. Product-bundle isolation and CLI help/completion checks passed;
  no app was installed.
- Strict formatting, 134 local documentation targets, Xcode project syntax and
  `git diff --check` passed.
- The host remained locked, so the previously failed full Debug and broader
  Release regressions were not repeated. Their protected legacy-fixture writes
  still require an unlocked rerun; no protection or test guard was weakened.

Raw logs use `tmp/piv-recovery/2026-10-06-recipient-removal-`; build artifacts
remain in the existing ignored directory. No installed app, real vault/configuration
or YubiKey was changed. No token operation, administration, push, notarization or
release was performed.

### Fifth 810 durable rotation component, 2026-10-06

Unchanged-roster rotation now has an internal durable publisher and source
validator. A separate rotation transaction engine was compared with reusing the
existing profile-neutral immutable kernel. The latter retains one implementation
of local intent/checkpoint CAS, manifest-last ordering, readback and interruption
cleanup. Rotation owns authentication, full resealing and source policy; enrollment,
revocation and recipient-removal approvals are not inferred from that policy.
Ordinary publication and rotation also share the exact source-byte comparison,
allowing only the reviewed candidate to appear during publication.

One mutation-owner operation ID spans the workflow. Before durable reservation,
the publisher verifies the exact parent, both key epochs, unchanged authority and
recipient generation, both boundary authorizations, complete staged objects,
old/new plaintext equality and bounded projected usage. It then verifies one
addressed local-Mac wrapper and rechecks source/pending work after authentication.
Cancellation or a changed source creates no intent. Physical prompt counts remain
unqualified; no recovery-token operation is involved.

The new internal `rotateVaultKey` kind uses the existing version-1 intent shape.
Existing kind encodings and manifest formats are unchanged; an older reader
refuses the unrecognized kind. Both ordinary-profile resume validators now reject
lifecycle kinds before intent cleanup or publication. Rotation accepts only its
exact locally pinned intent, with no enrollment transcript, merge resolutions or
profile/lifecycle fallback. Pending registration/adoption and changed ownership,
checkpoint, source or projected limits retain the established refusal boundaries.

Uncommitted resume requires helper-scoped old/new keys and complete old/new
snapshots. It resumes the same encrypted epoch without signing, rewrapping or
generating another candidate. If the local checkpoint already equals the pinned
candidate, reconciliation validates its current MAC/capsule, exact complete
snapshot and immutable bytes before cleanup. Old keys, old ciphertext and old
manifest cache are not needed after commitment. This does not relax initial
publication checks or treat synchronized intents as approval. Keys are never
persisted in intents or supplied through CLI/XPC.

Seventeen software declarations cover manifest-last/checkpoint-last ordering,
empty snapshots, all 14 publication interruption boundaries, checkpoint failure,
committed current-only cleanup, wrong/missing keys and owners, cancellation,
source changes during private approval, pending authority work at critical
boundaries, changed ownership/checkpoint, routed-anchor equality, cross-kind
refusal in both ordinary profiles, refusal of recipient removal as rotation and
source/projected budgets. An unavailable entry after manifest publication leaves
the old checkpoint and exact pending intent until its bytes return. The initial
repair fixture was corrected to restage the exact bytes, because publication
consumes staging; no production behavior was changed to accommodate the test.

Primary and backup credentials recover the latest secret and TOTP after an actual
durable rotation and ordinary mutation-service save. Original Mac private state
and superseded ciphertext leave scope before one software agreement per credential.
Rotation is no longer just seeded test setup. Initial profile-3 registration still
uses the existing disposable fixture setup, not a product opt-in.

Next is service/session orchestration, including native wrapper opening on restart,
then publication/resume for compared enrollment, reviewed revocation and recipient
removal under their own approval rules. Joining adoption, key-transition catch-up,
restore orchestration, product/runtime/CLI integration, integrated review and
physical acceptance remain. No implementation package is complete and no public
command or real-vault opt-in is enabled.

Verification:

- Complete serial Debug regression passed on the unlocked host: 1,286 KeyCore
  tests in 107 suites and six canonical-JSON tests in one suite. The final run
  includes the ordinary-profile routing guard and profile-2 refusal case.
  The separately gated large-migration qualification was skipped.
- An initial full Release run reported seven assertions in one pre-existing
  [qualification-namespace fixture](../Tests/KeyCoreTests/KeyAppTests.swift).
  The [production configuration](../Sources/KeyCore/RuntimeConfiguration.swift)
  intentionally enables qualification namespaces only in Debug. The test now
  verifies isolated namespaces in Debug and the unchanged stable identity in
  Release, rather than assuming Debug behavior or skipping Release. Its 41-test
  Debug suite passed after that test-only correction.
- Complete serial optimized Release regression then passed: the same 1,286
  KeyCore tests in 107 suites and six canonical-JSON tests in one suite, with the
  separately gated large-migration qualification skipped. The previous full
  Debug and broad Release protected-fixture failures are resolved by these
  unlocked runs; no file protection or production qualification guard changed.
- Unsigned universal Preview build passed. App, CLI and helper contain arm64 and
  x86_64 slices. Product-bundle isolation and CLI help/completion checks passed;
  no app was installed.
- Strict formatting of changed/new components and tests, 141 local documentation
  targets, Xcode project syntax and `git diff --check` passed. Existing formatting
  outside the added mutation-kind lines was retained.

Raw logs use `tmp/piv-recovery/2026-10-06-rotation-publication-`; build artifacts
remain in the existing ignored directory. No installed app, real vault/configuration
or YubiKey was changed. No token operation, administration, push, notarization or
release was performed.

### Sixth 810 initial rotation service, 2026-10-06

The internal unchanged-roster service now composes initial rotation from an
already unlocked session. Extending the ordinary save service was compared with
a dedicated signer/unwrapper-dependent service. The dedicated service keeps
ordinary edits free of private-operation dependencies and leaves epoch policy,
durability and session expiry with their existing owners. It uses the helper's
operation ID through direct nested publishers, not another serialized queue or
a new generic lifecycle abstraction.

Preparation returns the exact authenticated current checkpoint/envelope after
checking this Mac's active identity, complete plaintext snapshot, source bounds
and pending barriers. It is review data, not persisted approval or proof of user
consent. Execution requires that reviewed checkpoint, generates a random 256-bit
key with a distinct derived key ID, and uses the existing builder/publisher.
Signing is followed by exact source/checkpoint/pending/session rechecks before
the addressed local wrapper is opened. Projected old/new storage limits remain
the publisher's responsibility and can refuse after signing but before wrapper
verification and durable reservation. No recovery credential is opened.

Session installation after publisher return was compared with adding a shared
transaction-kernel callback. A kernel callback would widen ordinary publication
to own a private session side effect and would still need to handle exceptions
after checkpoint advancement. This service instead authenticates the committed
current snapshot before its own exact session switch. The session store now owns
an atomic prior-epoch replacement check under its existing expiry lock. A lock or
timeout during publication cannot be undone by installation; existing install,
load and profile-2 behavior are unchanged.

An error may occur after checkpoint commitment. Only an unchanged exact reviewed
checkpoint permits the old session to remain. A changed, missing or unreadable
checkpoint locks the session without rolling back authority, deleting pending
intent or installing a key from an error path. Cleanup can fail after a successful
commit and still permit verified session replacement, leaving the exact rotation
pending for dedicated reconciliation. The service refuses all existing pending
work instead of generating or signing a substitute. Raw keys are in-memory
implementation values, not return fields, intent contents or CLI/XPC inputs.

Thirteen service declarations use real key generation, epoch crypto, session and
contained filesystem publication. They cover review without private operations,
empty/populated rotation and continued ordinary saving, all 14 publication
interruption points, failed checkpoint CAS, cleanup failure, both cancellation
boundaries, source/identity/session/pending refusals, changes during signing,
lock during wrapper verification and post-commit source/authority/checkpoint
failure. Five session declarations cover exact prior-epoch replacement, wrong
keys/epochs, foreign vaults, absent or explicitly locked sessions and expiry.
An initial focused compile exposed a missing `try` on the established software
identity's throwing initializer; the fixture call was corrected before execution.

Cold-start service recovery was separated from initial session orchestration to
keep the next review boundary explicit. It must select the exact locally pinned
rotation, distinguish pre-commit and committed states, validate bounded public
inputs before native authentication, open only the addressed old/new Mac wrappers
needed for that state, recheck after authentication, and install only authenticated
committed authority. The existing publisher already resumes scoped keys without
re-signing. No cold-start service path or physical prompt count is claimed by this
increment. Other lifecycle publication/resume, key-transition catch-up, joining
adoption, restore/product composition, user confirmation and integrated review
remain. `REC-810` and the other implementation packages are not complete.

Verification:

- Complete serial Debug regression passed on the unlocked host: 1,304 KeyCore
  tests in 109 suites and six canonical-JSON tests in one suite. This includes
  all final service/session declarations and existing profile-2 paths. The
  separately gated large-migration qualification was skipped as designed.
- Targeted serial optimized Release regression passed: 83 tests in seven suites
  covering recovery rotation construction/publication/service, exact session
  replacement, recovery ordinary-service composition and permanent-profile
  checkpoint unlock/revocation service. This increment did not rerun the full
  Release suite; the preceding durable-rotation increment's full Release result
  is recorded above.
- Unsigned universal Preview build passed. App, CLI and helper contain arm64 and
  x86_64 slices. Product-bundle isolation and CLI help/completion checks passed;
  no app was installed.
- Strict formatting of new service/test files, 149 local documentation targets,
  Xcode project syntax and `git diff --check` passed. Existing session-store
  formatting outside the added replacement method was retained.

Raw logs use `tmp/piv-recovery/2026-10-06-rotation-service-`; build artifacts stay
in the existing ignored directory. No installed app, real vault/configuration or
YubiKey was changed. No token operation, administration, push, notarization or
release was performed.

### Seventh 810 rotation restart component, 2026-10-06

The internal rotation service now selects and resumes one exact locally pinned
interrupted rotation, then installs its authenticated committed current key.
Duplicating staged/published selection in a rotation-only reader was compared
with exposing bounded preparation from the existing immutable recovery engine.
Shared preparation retains one implementation of exact anchor/intent selection,
published-object preference, unavailable-object handling and locally owned early
abandonment. It cannot authenticate an epoch or advance a checkpoint. Actual
profile validation and publication remain in the existing kernel. Existing
intent, anchor and manifest formats are unchanged.

The shared reader now explicitly bounds local anchor/checkpoint/intent bytes,
staged entry count, per-object bytes and accumulated selected/cleanup entry bytes.
These checks apply before parsing or private operations and retain pending state
on invalid or over-budget input. The prepared/no-intent abandonment path also
rechecks competing authority work before clearing its exact local reservation.
Early abandonment uses existing kernel semantics; provider files are never
scanned to infer ownership or approval.

Before authentication, the service parses exact profile-3 candidate bytes and
checks active exact Mac identity, entry address/context completeness, source
inventory and projected budgets. Uncommitted rotation also checks unchanged
rosters/generation/entry metadata and both public boundary authorizations against
the exact locally trusted parent. Rotation and the other epoch validators share
public snapshot preflight without changing full normal-validation ordering or
dropping parent MAC/capsule/plaintext checks.

Cold uncommitted recovery opens the addressed old Mac wrapper, authenticates its
MAC/capsule and complete plaintext snapshot, and rechecks all source/pending bytes
before the addressed new wrapper is opened. Both keys and full old/new plaintext
comparison are required before exact kernel resume. Committed reconciliation
needs only the addressed new key and exact current snapshot, not superseded keys,
ciphertext, manifests or cache. No signature, new epoch, rewrap, recovery-token
operation or authentication retry occurs. Exact live sessions reuse only their
matching old or committed current key. Software tests establish a two/one/one/zero
Mac-private-operation budget for cold uncommitted, cold committed, warm old-key
and warm committed-key cases respectively, not a physical prompt guarantee.

Unconditional post-authentication session installation was compared with a
store-bound process-local race guard. The guard is captured before key reuse or
authentication and is rejected by explicit lock, actual expiry or session
replacement. Status polling of an already empty locked session must not reject
it. The existing session store owns this under its mutex alongside expiry;
ordinary install/load semantics are unchanged. The ticket contains no secret,
cannot cross stores, is consumed by installation, and proves neither human
consent nor successful authentication. Full current MAC/capsule, snapshot,
checkpoint and pending checks remain prerequisites to installation.

Every failed recovery locks the session. A committed checkpoint is never rolled
back. Otherwise valid pinned work remains available after cancellation, private
result mismatch, unavailable published objects or source/authority changes.
Incomplete staged work may use the established safe abandonment path, including
when it becomes incomplete during a post-authentication recheck. A no-pending
outcome does not implement general cold unlock; normal product routing remains
separate. Cleanup failure after commitment keeps exact pending work and locks;
the next restart opens only the committed current wrapper.

Fifteen restart declarations exercise actual random-key service publication at
all 14 interruption boundaries, exact ciphertext resume and continued ordinary
saving. They cover current-only committed cleanup without obsolete objects,
warm-key reuse, cancellation at both wrappers, explicit lock during either
operation, changes before the next private operation, incorrect provider results,
malformed/foreign/other-kind inputs, selected aggregate and projected budgets,
unavailable published objects until exact bytes return, checkpoint/cleanup
failures and source/lock/authority changes after commitment. Four added session
declarations cover status polling, empty-session explicit lock, cross-store and
replacement rejection, and actual expiry. All private operations use software
Mac keys; neither a real vault nor a PIV key participates.

Next is durable compared-device enrollment over its own ceremony/roster rules,
followed by reviewed revocation and recipient removal. Initial rotation and
restart do not confer those approvals. Joining adoption, key-transition catch-up,
shipping cold unlock/runtime/CLI integration, restore orchestration, user
confirmation, integrated review and physical acceptance remain. No implementation
package is complete and no public command or real-vault opt-in is enabled.

Verification:

- Final complete serial Debug regression passed on the unlocked host: 1,323
  KeyCore tests in 110 suites and six canonical-JSON tests in one suite. This
  includes the final provider-result and post-commit cases. An earlier complete
  run also passed before those last cases and the early-abandonment session lock
  were added; its raw log remains separate from the final result.
- Complete serial optimized Release regression passed: the same 1,323 KeyCore
  tests in 110 suites and six canonical-JSON tests in one suite. The separately
  gated large-migration qualification was skipped in both configurations.
- Final unsigned universal Preview build passed. App, CLI and helper contain
  arm64 and x86_64 slices. Product-bundle isolation and CLI help/completion checks
  passed; no app was installed.
- Strict formatting of the modern rotation components and new/expanded tests,
  156 local documentation targets, Xcode project syntax and `git diff --check`
  passed. Existing shared-kernel/session formatting outside the added logic was
  retained.

Raw logs use `tmp/piv-recovery/2026-10-06-rotation-restart-`; build artifacts stay
in the existing ignored directory. No installed app, real vault/configuration or
YubiKey was changed. No token operation, administration, push, notarization or
release was performed.

### Eighth 810 durable enrollment component, 2026-10-06

Compared-device enrollment now has internal durable publication and exact resume.
A separate enrollment durability engine was compared with an enrollment-specific
validator over the shared immutable transaction kernel. Both need exact local
ownership, bounded staging/readback, manifest-last publication, checkpoint CAS,
source guards and idempotent cleanup. Reusing the kernel keeps those rules in
one place without allowing unchanged-roster rotation to authorize device addition.
The enrollment validator owns the signed ceremony, exact joining identity,
transcript-derived transition ID and unchanged recipient/existing-device policy.

The helper caller supplies the transcript digest the user explicitly approved;
awaiting-comparison state is not human consent. The publisher requires matching
exact signed device-local ceremony bytes and fresh invitation validity before
one addressed inviting-Mac wrapper verification. Full source/snapshot checks,
competing registration/adoption guards and local ceremony checks precede and
follow that operation. Cancellation cannot reserve an intent. Every later source
recheck reloads the matching ceremony before continuing publication.

Re-running a fresh comparison on restart was compared with binding resume to the
existing exact local anchor and transcript-bearing intent. A new comparison could
select another joiner or lead to a second randomized epoch; it cannot explain
already published ciphertext. Resume instead uses the existing version-2 intent,
its locally pinned hash and unchanged signed transcript. Expiry prevents new
approvals, not completion of exact pending work. No new signature, key generation,
private wrapper verification or token agreement occurs in this component's resume.
Both scoped keys and full old/new snapshot comparison remain required before
commitment. After commitment, current-only authentication and exact intent binding
allow cleanup without obsolete keys or ciphertext. Preparation selects bounded
ciphertext without authenticating it or consuming the ceremony.

Completing local ceremony bookkeeping after the kernel returned was compared with
completing it while the anchor still protects retries. A post-return marker failure
would lose the pending transaction that identifies the committed approval. A small
domain completion hook therefore runs after checkpoint advancement and before
owned cleanup in both publication and resume. It defaults to a no-op for existing
validators. Enrollment reopens the authenticated current snapshot, then marks the
exact inviter ceremony consumed by CAS. Marker failure retains the exact pending
intent. Consumed state is idempotent if later cleanup fails and cannot authorize
a fresh publication. Checkpoint/ownership are checked around completion; neither
marker nor synchronized intent replaces authenticated vault authority.

Nineteen software declarations cover every one of the 14 publication interruption
points, empty snapshots, exact version-2 intent binding, expiry, addressed wrapper
verification/cancellation, wrong scoped keys, changed local ceremony and authority,
branch/source guards including post-commit refusal, bounded/projected usage,
checkpoint/marker/cleanup failures, unavailable published entries until exact bytes
return, current-only committed cleanup and cross-kind rejection before cleanup.
They open the joining-Mac wrapper and recover with primary or backup after actual
enrollment publication, an ordinary service save and obsolete ciphertext removal.
All credentials and agreement operations are software fixtures, not native or
physical qualification. One-operation software counts are not prompt guarantees.

Next is owner-service initial approval and restart with guarded session handling.
Joining adoption, reviewed revocation and recipient-removal publication/resume,
remaining-Mac key-transition catch-up, restore orchestration, shipping runtime/CLI
composition, user confirmation, integrated review and native/physical acceptance
remain. No implementation package is complete and no public command or real-vault
opt-in is enabled. Existing profile-2 enrollment and persisted formats are unchanged.

Verification:

- Complete serial Debug and optimized Release regressions each passed: 1,342
  KeyCore tests in 111 suites and six canonical-JSON tests in one suite. The
  separately gated large-migration qualification was skipped in both builds.
  These full runs include the corrected obsolete-history cleanup fixture and
  final unavailable-entry/post-commit ceremony cases. Earlier focused attempts
  caught Swift type/assertion compilation issues and that fixture mistake;
  the conservative source-inventory policy was not relaxed.
- Unsigned universal Preview build passed. App, CLI and helper contain arm64 and
  x86_64 slices. Bundle isolation and CLI help/completion checks passed. No app
  was installed, signed, submitted or released.
- Strict formatting of the enrollment components, shared validation interface
  and new tests, 162 local documentation targets, Xcode project syntax and
  `git diff --check` passed. Existing shared publisher/recoverer formatting
  outside the added logic was retained.

Raw logs use `tmp/piv-recovery/2026-10-06-enrollment-publication-`; build artifacts
stay in the existing ignored directory. No installed app, real vault/configuration
or YubiKey was changed. No token operation, administration, push, notarization or
release was performed.

### Ninth 810 enrollment owner component, 2026-10-06

The internal owner service now prepares authenticated comparison data, executes
explicit reviewed approval from an unlocked session and resumes exact interrupted
enrollment into a guarded session. A generic rotation/enrollment service with
policy callbacks was compared with separate domain-owned orchestration over the
existing transaction and session mechanisms. Both must preserve bounded source
selection, full pre-commit snapshots, exact local ownership and lock/expiry guards.
Enrollment additionally owns invitation freshness, the compared transcript and
post-commit ceremony completion. Keeping its workflow separate preserves those
approval requirements without changing rotation's interface or treating its
unchanged-roster policy as enrollment approval. The immutable reader/publisher,
epoch snapshot checks, local stores and process-local session ticket remain shared.

Preparation loads exact signed local messages, validates the inviting/joining
identities and unexpired ceremony, and authenticates the complete pinned snapshot
with the existing session. It neither saves consent nor makes a private identity
call. Approval requires the exact reviewed checkpoint and digest the user approved.
CryptoKit creates a fresh random key; existing enrollment construction and
publication own full old/new comparison and manifest-last/checkpoint-last ordering.
Source, ceremony, pending and session state are rechecked after signing, before
addressed Mac-wrapper verification. A session-bound unwrap checks the existing
ticket before and after the private operation, preventing reservation after lock
or replacement during that operation.

The service authenticates the committed key/capsule and complete current snapshot,
requires exact consumed ceremony bytes and checks ownership/checkpoint before
guarded key installation. Unlike unconditional installation, the ticket cannot
revive a session locked, expired or replaced during publication. Initial best-effort
cleanup may leave exact committed work while installing its valid current key;
the service first reconstructs the exact intent digest for this operation and
compares its anchor before selecting pending bytes. Neither a different operation
nor different intent can be abandoned or installed through this completion path.
This exact-anchor check was added during inspection and has explicit same-operation
and different-operation replacement cases.

Restart performs public enrollment-specific preflight before private operations:
exact transcript/roster/recipient rules and both public boundary authorizations,
complete entry addresses/context, source inventory and projected budgets. An
uncommitted old wrapper result must authenticate its MAC/capsule and whole snapshot
before the new wrapper is opened. Exact local/source/session rechecks separate the
two operations. Full old/new comparison remains before actual kernel commitment.
Committed reconciliation needs only the new epoch, current key and snapshot;
expired invitations do not prevent finishing already pinned approval. Restart
never signs, creates a replacement epoch, repeats comparison or invokes a token.
Software unwrap budgets are two/one/one/zero for cold uncommitted, cold committed,
warm old-key and warm committed-key sessions; physical prompt counts remain unqualified.

Failures do not install keys or undo committed checkpoints. Initial failure retains
the old session only while its reviewed checkpoint remains exact. Recovery errors
invalidate the session; marker and cleanup failure keep exact pending work for the
next current-only restart. Existing incomplete-staging abandonment remains distinct
from approval and does not consume the ceremony. No pending work is not permission
to cold-unlock or approve a consumed ceremony again.

Twenty-three declarations exercise actual random-key service publication at all
14 interruption points, empty snapshots and continued ordinary saving, exact
cold/warm restart, provider cancellation and invalid results, lock and same-key
session replacement, source/ceremony/authority/checkpoint/ownership changes before
further private operations, selected/projected limits, malformed/cross-kind work,
marker/cleanup/checkpoint failures and post-commit refusal. Primary/backup recovery
after actual owner-service enrollment/save and obsolete ciphertext removal uses
one software agreement per credential. Reused publisher fixtures retain real
cryptography and contained storage; only local failure and identity callbacks are
scripted. No native key or real vault participates.

Next is joining-Mac adoption for the exact recovery-profile enrollment, followed
by durable reviewed revocation and recipient removal. Remaining-Mac key-transition
catch-up, restore orchestration, product comparison/confirmation and shipping
runtime/CLI routing, integrated review and native/physical qualification remain.
No implementation package is complete, no public command or real-vault opt-in is
enabled, and profile-2 enrollment/runtime dispatch and persisted formats are unchanged.

Verification:

- Complete serial Debug and optimized Release regressions each passed: 1,365
  KeyCore tests in 112 suites and six canonical-JSON tests in one suite. These
  runs include the final malformed-input and owner-service primary/backup
  recovery cases. The separately gated large-migration qualification was
  skipped in both builds.
- Focused enrollment/rotation regression passed before those final two
  declarations were added: 116 tests in seven suites. Earlier compilation
  probes caught fixture access-control and assertion syntax issues; both were
  corrected before the passing runs. The exact post-publication anchor check
  and its replacement cases are included in the focused and full results.
- Unsigned universal Preview build passed. App, CLI and helper contain arm64
  and x86_64 slices. Product-bundle isolation and CLI help/completion checks
  passed; no app was installed, signed, submitted or released.
- Strict formatting of the changed enrollment components and tests, 167 local
  documentation targets, Xcode project syntax and `git diff --check` passed.

Raw logs use `tmp/piv-recovery/2026-10-06-enrollment-owner-`; build artifacts stay
in the existing ignored directory. No installed app, real vault/configuration or
YubiKey was changed. No token operation, administration, push, notarization or
release was performed.

### Tenth 810 joining component, 2026-10-06

The [internal joining service](../Sources/KeyCore/V3RecoveryEnrollmentAdoption.swift)
now establishes exact first trust from an explicitly compared digest and this
Mac's exact local signed joining ceremony. The inviter role is never fabricated:
shared public transition policy is separate from the owner approval/freshness checks. The
existing owner paths still require their original inviter ceremony and approval.

Two composition options were considered against exact retry, lock safety and
shipping isolation. Extending the profile-2 adoption workflow would put config
selection and runtime callbacks into this increment and require profile dispatch
plus changes to its existing persistence/session behavior. Both options must
preserve exact retries, full authentication and lock safety. A separate profile-3
domain service reuses graph, snapshot, stores and session guards while leaving
shipping profile-2 behavior unchanged. The latter was chosen. Configuration and
runtime activation stay with later product composition; this result only names
the exact verified enrollment and local checkpoint/session.

Public preparation requires one exact transcript-derived, directly parented
enrollment. Owner/epoch authorizations, exact device addition, unchanged recovery
recipients/generation and reseal metadata are checked before the Mac wrapper.
The bounded graph/inventory refuses unreadable named files, ambiguous approvals,
visible later heads or competitors rather than choosing an older approval. This
is exact adoption, not catch-up; withheld files remain outside its freshness
claim. Existing pending work, a different checkpoint/session, missing or replaced
local messages, invalid identities and limits stop before private authentication.

After one cold Mac unwrap, the current key/MAC/capsule and every current entry
must authenticate. A warm exact session avoids that operation. Source, local
ceremony, checkpoint, pending work and the authentication ticket are rechecked
across authentication and persistence. The non-authoritative encrypted cache is
written before insert-only checkpoint trust. The checkpoint is then pinned before
the exact ceremony CAS is marked consumed. Retries accept only nil or that same
checkpoint; failure never rolls it back or overwrites a different one. Guarded
session installation is last, and all errors lock. No shared object is published
by adoption. Public parent/history bytes remain necessary, but obsolete entry
ciphertext is not opened or required.

[Seventeen software test declarations](../Tests/KeyCoreTests/V3RecoveryEnrollmentAdoptionTests.swift)
exercise actual owner-service output and separate joining local state,
empty/full snapshots, ordinary joining-Mac saves, primary/backup recovery,
interruption and lock at three verification/persistence boundaries, local CAS/cache failure,
cancellation, mismatched provider output, source/ceremony/checkpoint/pending/session
changes, obsolete ciphertext removal, ambiguous approvals and bounded malformed
inventory. Protected-filesystem execution was initially deferred because the
host console was locked, then passed after the owner unlocked the Mac. No storage
protection policy was changed. Primary/backup recovery after a joining-Mac save
uses one software agreement per credential, not a qualified physical prompt count.

Verification:

- Debug compilation of the new production and test files passed.
- Software-only enrollment policy/session regression passed: 25 tests in two
  suites, including compared public preflight without inviter-role substitution
  and rejection of well-formed but different roster/recovery decisions.
- Focused joining/owner/publisher/legacy-adoption/session regression passed:
  96 tests in six suites, including all 17 new adoption declarations.
- Complete serial Debug and optimized Release regressions each passed: 1,383
  KeyCore tests in 113 suites and six canonical-JSON tests in one suite. The
  independently gated large-migration qualification was skipped in both runs.
- Unsigned universal Preview build passed. App, CLI and helper each contain arm64
  and x86_64 slices; product-bundle isolation and CLI help/completion checks passed.
- Strict formatting of changed Swift files, Xcode project syntax and
  `git diff --check` passed; 173 local documentation targets verified.

Next: durable reviewed revocation and recipient removal. Key-transition catch-up,
restore orchestration, shipping UI/runtime/CLI composition, integrated review and
native/physical qualification remain. Raw logs use
`tmp/piv-recovery/2026-10-06-enrollment-joiner-`. No real
vault, config, installed app or token was changed; no release or push occurred.

### Eleventh 810 revocation publisher component, 2026-10-06

The [internal publisher and transaction validator](../Sources/KeyCore/V3RecoveryDeviceRevocationPublisher.swift)
now durably publish the exact reviewed one-device revocation and resume its pinned
bytes through the existing immutable kernel. This does not implement confirmation,
session replacement, remaining-Mac catch-up or a shipping command. The caller
supplies its approved plan and scoped keys; a typed plan alone is not human consent.

The existing version-1 intent was compared with adding a persisted reviewed-roster
record under the same requirements: exact target/checkpoint binding, no new approval
on restart, full pre-commit verification and current-only committed cleanup. The
local intent already pins the old checkpoint and full candidate digest, so the
complete roster decision can be reconstructed and compared before commitment.
Another stored roster would duplicate those selectors and require a new format
without adding authority. The existing intent was retained. A generic lifecycle
dispatcher was also considered, but separate revocation policy keeps its one-device
approval distinct from unchanged-roster rotation and enrollment. Only the durability
kernel and established source/crypto mechanisms are shared.

Initial publication requires a separately supplied plan exactly equal to the
candidate's plan. The authenticated old floor, active authorizer and one-device
change are reconstructed independently. Both boundary authorizations, unchanged
recovery recipients/generation and complete old/new metadata/plaintext checks
remain mandatory. Source inventory, projected limits, exact checkpoint/ownership
and reciprocal registration/adoption guards pass before the one addressed Mac
wrapper. Cancellation or wrong provider output does not reserve an intent; source,
plan and local state are rechecked when the private operation returns.

The shared kernel reserves a local exact intent, stages and readbacks entries,
publishes the manifest last, then advances only the expected checkpoint. Resume
accepts only `revokeDevice` without enrollment/merge fields. Existing intent kind
checks precede checkpoint-based abandonment, and an explicit routed anchor must
match even before missing prepared-intent cleanup. An incomplete unpublished
attempt may be abandoned without selecting a different target or creating consent.

Uncommitted restart still requires both keys, full snapshots and exactly one
active-to-revoked change, retaining all identities and other statuses. Other valid
epoch policies cannot stand in for revocation. Committed cleanup authenticates
only the current key/MAC/capsule and full snapshot after the kernel checks its
exact candidate checkpoint and locally pinned intent. It does not reopen old keys,
ciphertext, manifests or cache. Missing current objects retain intent and checkpoint.
Restart never signs, generates an epoch, requests a Mac unwrap, selects a target
or invokes a token. Future session orchestration will own scoped native operations.

[Twenty software declarations](../Tests/KeyCoreTests/V3RecoveryDeviceRevocationPublisherTests.swift)
use actual durable enrollment and contained immutable files, then exercise all 14
revocation interruptions, exact reviewed plans, empty/full snapshots, wrong keys
and owner, cancellation/provider output, source/pending/ownership guards, checkpoint
and cleanup failure, missing required state, projected bounds and reciprocal kind
refusal. Primary/backup software recovery follows actual publication and an ordinary
service save with one agreement each after obsolete ciphertext removal. Revoked
Macs do not gain new wrappers; their retained old copies are not erased or revoked.

An early test expected the inner roster error on resume, while the established
recovery kernel correctly returned `invalidRecoveryState`. The assertion was fixed
and a direct domain-validator check added. No production check was weakened.

Verification:

- Focused revocation/rotation/joining regression passed: 69 tests in four suites,
  including the final wrong-policy, missing-snapshot and provider-result cases.
- Full Debug and Release suites passed: 1,403 KeyCore tests in 114 suites and
  six canonical-JSON tests in one suite in each configuration. The separately
  gated large-migration qualification was skipped in both runs.
- Unsigned universal Preview build passed. The app, CLI and helper each contain
  arm64 and x86_64 slices; bundle isolation and CLI help/usage checks passed.
- Strict formatting of the new Swift files, Xcode project syntax, Git whitespace
  checks and all 179 local documentation targets passed.

Next: durable recovery-recipient removal, then revocation/removal session services.
Remaining-Mac key-transition catch-up, restore orchestration, shipping confirmation/
runtime/CLI composition, integrated review and native/physical qualification remain.
No implementation package is complete. Raw logs use
`tmp/piv-recovery/2026-10-06-device-revocation-`. No real vault, config, installed
app or YubiKey was changed. No token operation, administration, push or release occurred.

### Twelfth 810 removal publisher component, 2026-10-06

The [internal recipient-removal publisher](../Sources/KeyCore/V3RecoveryRecipientRemovalPublisher.swift)
uses the established immutable kernel and independent removal policy. Initial
publication requires the exact separately reviewed plan and, when losing the
last recipient, its explicit plan-bound acknowledgment. Both snapshots and all
authority/source/limit guards pass before one addressed Mac-wrapper operation;
private cancellation or wrong output leaves no intent.

Persisting another review/consent record was compared with reconstructing the
decision from exact owned intent. The version-1 selectors already bind the old
checkpoint and entire candidate, so duplication would add schema and false consent
semantics without authority. The existing fields are retained with one new explicit
`removeRecoveryRecipient` kind. Ordinary mutation policy refuses it, and restart
refuses other kinds before unrelated-checkpoint abandonment. Existing-profile
bytes and other kind encodings do not change; old decoders refuse the new kind.

The domain validator separates initial acknowledgment from transition-only
validation used after the kernel establishes exact local restart ownership. This
does not synthesize an acknowledgment or authorize a new removal. Uncommitted
restart rechecks exactly one recipient tombstone, unchanged Macs, fresh generation
and full old/new plaintext identity. Committed cleanup needs only exact current
authentication/snapshot. It never re-signs, generates a key or requests a token.

Twenty software declarations cover both continuing-protection and last-removal
publication across all 14 boundaries, incorrect acknowledgment/review, wrong keys
or owner, cancellation, provider result, pending/source/CAS changes, missing state,
kind/policy refusal and bounds. Actual primary/backup/last removal plus an ordinary
save remains recoverable only by continuing recipients after original Mac state
leaves scope. Last removal still permits ordinary Mac-authorized saves. One early
acknowledgment fixture accidentally reused the exact original plan; that fixture
was corrected without weakening production checks.

Verification:

- Focused removal/revocation/rotation/joining regression passed: 72 tests in
  four suites.
- Full Debug and Release passed: 1,423 KeyCore tests in 115 suites and six
  canonical-JSON tests in one suite in each configuration. The separately gated
  large-migration qualification was skipped in both runs.
- The first Debug run failed one existing handler test with seven issues after
  protected temporary-file writes were refused while the Mac was locked. The
  unchanged test passed in both unlocked runs. Protected-storage settings were
  not changed; the initial failure log is retained alongside the successful runs.
- Debug and optimized production compilation passed.
- Unsigned universal Preview build passed. The app, CLI and helper each contain
  arm64 and x86_64 slices; bundle isolation and CLI help/usage checks passed.
- Strict formatting of the touched modern Swift files, Xcode project syntax,
  Git whitespace checks and all 184 local documentation targets passed.

Raw output uses `tmp/piv-recovery/2026-10-06-recipient-removal-`.

Next: revocation/removal owner/session services, then remaining-Mac key-transition
catch-up. Restore orchestration, shipping confirmation/runtime/CLI, integrated
review and native/physical qualification remain. No package is complete. No real
vault/configuration, installed app or YubiKey is changed, and no token operation,
administration or release is performed. Work remains local unless separately
published through the tracked stack.

### Thirteenth 810 initial authority service, 2026-10-06

The [authority-change service](../Sources/KeyCore/V3RecoveryAuthorityChangeService.swift)
adds separate authenticated prepare/execute methods for device revocation and
recovery-recipient removal. Two standalone services duplicating the session/source
flow were compared with one service retaining explicit typed methods and independent
planners/builders/publishers. The shared service keeps common session ownership and
failure handling together without a generic policy registry or kind autodetection.
Rotation and enrollment services are unchanged; restart dispatch is not added here.

Exact review and, for the last recipient, exact protection-loss acknowledgment
precede random-key generation and signing. Full current state and source limits
authenticate from the unlocked session. Source/checkpoint/pending work and session
generation recheck after signing, before one addressed Mac-wrapper verification.
After durable publication, current authentication and the complete snapshot precede
atomic session installation using the existing authentication ticket. It refuses
lock/expiry or lock followed by reinstallation of the same old key during native UI.
Errors after checkpoint movement lock without rollback or deleting owned intent.
Cleanup failure may retain the exact committed intent and new session, but ordinary
saves remain blocked until reconciliation. Unrelated/malformed replacement ownership
cannot justify installing the new session.

Fifteen software declarations reuse actual enrollment/publication fixtures, real
CryptoKit cryptography, random production keys, contained filesystem storage and
the actual session store. They cover all 14 durable boundaries for revocation and
continuing/last-recipient removal, invalid independent review/acknowledgment,
cancellation, wrong provider output, source/pending/CAS changes, lock and same-key
reauthentication races, post-commit missing/changed state and bounds. Successful
service changes permit actual ordinary saves and continuing-recipient software
recovery. An early assertion incorrectly expected unchanged encrypted recovery
wrappers across revocation; it now requires fresh wrappers while preserving the
recipient roster and generation. Production checks were not weakened.

Verification:

- Focused authority-service/rotation-service/revocation/removal regression passed:
  68 tests in four suites, including corrected wrapper-refresh and wrong-provider
  result assertions.
- Full Debug and Release passed: 1,438 KeyCore tests in 116 suites and six
  canonical-JSON tests in one suite in each configuration. The separately gated
  large-migration qualification was skipped in both runs.
- Debug and optimized production compilation passed. Unsigned universal Preview
  passed; app, CLI and helper each contain arm64 and x86_64 slices. Bundle
  isolation and real bundled CLI help/usage/version/completion checks passed.
- Strict formatting of touched Swift files, Xcode project syntax, Git whitespace
  checks and all 189 local documentation targets passed.

Raw output uses `tmp/piv-recovery/2026-10-06-authority-session-`.

Next: exact session-aware interrupted revocation/removal reconciliation, then
remaining-Mac key-transition catch-up. Restore orchestration, shipping confirmation/
runtime/CLI, integrated review and native/physical qualification remain. No package
is complete. No real vault/configuration, installed app or YubiKey is changed, and
no token operation, administration, push or release is performed.

### Fourteenth 810 authority restart component, 2026-10-06

The [authority-change service](../Sources/KeyCore/V3RecoveryAuthorityChangeService.swift)
adds explicit interrupted-revocation and interrupted-removal routes sharing session
reconciliation. Automatically resuming any pending authority operation during a
new preparation/save was compared with explicit typed routes. Explicit routes keep
the existing decision boundaries and prevent interpreting unrelated work as the
requested change. The established kernel still selects exact local intent, checks
kind before unrelated-checkpoint abandonment and checks a routed anchor before
even prepared/no-intent cleanup. There is no provider-wide intent scanning.

The domain validators now expose public transition preflight, and the transaction
validators share exact metadata reconstruction with the service. These helpers
establish no authenticated review, MAC, snapshot or permission to publish. Initial
execution retains authenticated planning and exact acknowledgment; full transaction
validation retains old/new key and complete snapshot checks. No persisted format
or new consent record is introduced.

Before native opening, restart verifies the exact one-record policy, parent-bound
public proofs, addresses/contexts, complete ciphertext availability, source and
projected bounds. Cold uncommitted work opens old/new addressed Mac wrappers; an
exact warm session avoids the old opening. Each result authenticates before the
next operation. Already committed cleanup uses only the current wrapper, or none
with its exact resident key, without obsolete manifests/ciphertext/cache. No new
key, signature, token operation or protection-loss acknowledgment is requested.
Source/checkpoint/ownership and authentication-ticket checks bracket UI. Only exact
authenticated committed state with no pending work installs a session. Errors lock
without rollback or deleting owned intent; nothing pending leaves a live session
alone rather than acting as cold unlock.

Eighteen software declarations reuse the actual random-key initial service and
contained immutable filesystem fixtures. All 14 boundaries cover revocation and
continuing/last-recipient removal. Additional cases cover cold/warm counts,
cancellation and wrong output at either wrapper, lock/same-key reauthentication,
changed source/pending/checkpoint, wrong owner/policy/kind, routed anchors, bounds,
missing published ciphertext, failed CAS/cleanup and post-commit session refusal.
Current-only cleanup succeeds after obsolete files are removed. Actual ordinary
saves after restart remain recoverable only by continuing software recipients.

Verification:

- Focused restart/service/domain/publisher/rotation regression passed: 118 tests
  in seven suites. An initial test compile error used three argument collections;
  combining the two scenario values into one tuple collection preserves every
  case within Swift Testing's two-collection limit.
- Full Debug and Release passed: 1,456 KeyCore tests in 117 suites and six
  canonical-JSON tests in one suite in each configuration. The separately gated
  large-migration qualification was skipped in both runs.
- Debug and optimized production compilation passed. Unsigned universal Preview
  passed; app, CLI and helper each contain arm64 and x86_64 slices. Bundle
  isolation and real bundled CLI help/usage/version/completion checks passed.
- Strict formatting of touched Swift files, Git whitespace checks and all 194
  local documentation targets passed.

Raw output uses
`tmp/piv-recovery/2026-10-06-authority-restart-`.

Next: remaining-Mac key-transition catch-up, then lifecycle integration checks and
review before closing PR 72's scope. Restore orchestration and shipping product
composition belong in later stacked review layers. No package is complete, and no
real vault/configuration, installed app, token operation/administration, push or
release is involved in this increment.

### Fifteenth 810 remaining-Mac key-transition step, 2026-10-06

The [new step service](../Sources/KeyCore/V3RecoveryKeyTransitionCatchUpService.swift)
compares a single automatic history-to-latest operation with explicit guarded
epoch steps. Explicit steps fit the existing same-epoch and profile-2 step
contracts: publication and each ordinary epoch retain full old/new plaintext
checks, cancellation does not trigger another private attempt, and a verified
prefix is not reported as current. A complete mixed content/epoch coordinator
will compose these steps separately; catastrophe recovery's one-token opening
does not authorize reduced ordinary catch-up validation.

Discovery reuses bounded graph loading, checkpoint-linked ancestry, public
cryptography and existing independent device/recipient planners. Public policy
recognizes only the supported single lifecycle decisions. Comparison, possession
and acknowledgment belong to original publication, not a remote reader accepting
its authenticated immutable result. Neither provider metadata nor the public
observation grants a trusted checkpoint. No format, saved-consent or intent
change is introduced.

All visible forward public boundaries, same-epoch progression, epoch uniqueness,
inventory and deduplicated ciphertext bounds/contexts check before UI. Visible
content/authority/closed-epoch competition refuses. Current-epoch snapshots fully
authenticate, including uncommitted siblings; exact committed same-epoch ancestors
explain late joins without obsolete ciphertext. Future ciphertext must be present,
but later epoch keys/MACs/AEAD are not claimed authenticated by the first step.
After the one addressed continuing-Mac opening, current MAC/capsule correspondence,
full boundary plaintext equality and all selected-epoch content snapshots check.
One exact source and checkpoint, all pending namespaces and the session-generation
ticket bracket UI/CAS. Errors lock without rollback or an invented resume pin.
Best-effort cache failure cannot undo committed trust.

Twenty-four declarations use independent local trust/cache/session states over
contained actual filesystem publication. Rotation, enrollment, revocation and
recipient removal use production services/publishers. Recipient addition uses the
real domain builder and explicit materialization; it is not another possession
ceremony. Cases cover mixed edits and several explicit epoch steps, resolved late
branches, obsolete committed ciphertext, revocation in a later visible epoch,
concurrent stale callers, cancellation, wrong output, MACs, complete reseal equality,
bounds and pre-/post-CAS source/pending/lock/re-authentication changes. Recovery of
another Mac's subsequent save uses only a continuing software recipient and files
after both Macs leave scope.

Initial test compilation corrected two calls to existing API signatures and
separated nested Swift Testing macros. A
resource-limit fixture initially violated its constructor precondition; it now
uses a valid aggregate-byte boundary. A serialization test incorrectly nested the
same synchronous queue and stopped the process; it was replaced with genuine
concurrent callers using the established owner contract. Production checks were
not weakened.

Verification before the local commit:

- Catch-up regression passed: 79 tests in four suites, followed by two focused
  preflight/concurrency tests, including five altered-proof/roster cases. The
  two additional late-branch/software-recovery declarations also passed in their
  separate composition run and the broader catch-up regression.
- Full Debug ran 1,480 KeyCore tests in 118 suites. The new 24-declaration
  catch-up suite passed, but one existing handler test reported seven issues.
  Its first complete-file-protection write failed with a permission error,
  followed by missing-entry errors; the console was observed locked at the end.
  An unlocked Debug rerun passed all 29 tests in the mutation-owner and storage
  suites, including that exact handler test. This supports the locked-storage
  explanation; the original full run remains recorded as failed, with its
  affected suites successfully rerun. Six canonical-JSON tests passed.
  Large-migration qualification remained skipped.
- Debug and optimized production compilation passed. Unsigned universal Preview
  passed, with arm64/x86_64 app, CLI and helper slices; bundle isolation and real
  bundled CLI help/usage/version/completion checks passed.
- The initial Release attempt was cancelled during test compilation while the
  console remained locked. After unlock, a complete Release run passed all
  1,480 KeyCore tests in 118 suites and six canonical-JSON tests in one suite.
  Large-migration qualification remained skipped. No protection or screen-lock
  setting was changed.
- Strict formatting, Xcode project syntax, Git whitespace checks and all 199
  local documentation targets passed again after the unlocked rerun. Raw output
  remains ignored; only source, tests, project wiring and the implementation
  record belong in the local commit.

Raw output uses
`tmp/piv-recovery/2026-10-06-key-catch-up-`.

Next: mixed content/key-epoch coordination and lifecycle integration checks/review
within PR 72. Restore orchestration and shipping runtime/CLI composition remain
later stack layers. No package is complete. This increment changes no real vault,
configuration, installed app or token, and performs no hardware administration,
push, notarization or release.

### Sixteenth 810 mixed catch-up coordination, 2026-10-06

The [coordinator](../Sources/KeyCore/V3RecoveryCatchUpCoordinator.swift) compares
moving discovery forward after each successful step with retaining an exact
original-source observation for the entire operation. Moving-only discovery can
hide a sibling delivered below an already committed epoch. The fixed-source
approach fits existing same-epoch coordination and reuses bounded observers,
without retaining every historical key or introducing another graph algorithm.
The original-floor key stays in memory only for this bounded call's checks.
New source arrivals stop the call and require explicit rediscovery; no provider
transaction, global freshness guarantee or automatic private retry is invented.

One actual mutation owner surrounds concrete content and key-epoch services.
Their direct owners reuse the operation ID rather than nesting the same queue.
Epoch steps still fully compare old/new plaintexts and authenticate the selected
epoch. Content steps use its installed session key. The progress counters measure
actual checkpoint replacements, not every inspected snapshot in an epoch jump.
Initial same-epoch content ambiguity returns both authenticated heads. Mixed
authority/closed-epoch competition refuses. Only the exact unchanged observed
head can produce a current result, including at the exact step budget.

Guarded session installation now returns its next-generation receipt atomically.
The coordinator passes its exact ticket into the epoch step and continues only
with the returned receipt. It does not take a new generation snapshot after
installation, which could accidentally adopt an unrelated lock/unlock. Existing
callers can discard the return value and retain their prior behavior. Errors lock
without rolling back committed checkpoints or modifying pending ownership.

Fourteen coordinator declarations reuse the existing two-Mac filesystem fixture
and actual steps. They cover every lifecycle kind, complete mixed histories,
content-only and unchanged sources, conflicts, late siblings after CAS, budgets,
second-epoch cancellation, lock/same-key replacement between epochs, all pending
namespaces, checkpoint/session races, cold/wrong state, future ciphertext/bounds,
cache failure and genuine concurrent stale callers. A session declaration checks
that the install receipt accepts only its own generation and rejects later lock
or same-key reinstall. No step is mocked and no native or token operation is used.

Initial test compilation corrected the existing encrypted-entry URL helper call
and the visibility of reused test aliases/fixtures. These were fixture-only
changes; no production validation was relaxed. Strict formatting also normalizes
existing guard continuation indentation in the touched session store.

Verification before the local commit:

- Focused Debug passed 24 tests in two suites: all 14 coordinator declarations
  and ten session declarations, including the new installation-receipt test.
- Optimized regression passed 167 tests in nine suites. It includes the
  coordinator, epoch/content/merged catch-up, session store, authority-change
  service, key-rotation service, enrollment-owner service and joining adoption.
  These exercise the concrete catch-up steps and guarded-install consumers.
- Debug production compilation and unsigned universal Preview passed. App, CLI
  and helper each contain arm64/x86_64 slices. Product-bundle isolation and real
  bundled CLI help/usage/version/completion checks passed.
- Strict formatting of all touched Swift files, project syntax, Git whitespace
  checks and all 205 local documentation targets passed. The session store uses
  its existing four-space indentation; other touched files use two spaces.
- The console was observed locked during this increment. No fresh whole-suite
  Debug/Release or protected-storage qualification is claimed. The preceding
  increment's full Release result remains evidence for that revision only.
  A fresh unlocked whole-suite run remains part of lifecycle integration checks;
  no protection or screen-lock setting was changed.

Raw output uses `tmp/piv-recovery/2026-10-06-coordinator-` and remains ignored.

Next: lifecycle integration checks and review within PR 72. Restore orchestration
and shipping runtime/CLI composition remain later stack layers. No package is
complete. This increment changes no real vault, configuration, installed app or
token, and performs no hardware administration, push, notarization or release.

### Seventeenth 810 lifecycle integration checks, 2026-10-06

The [integration suite](../Tests/KeyCoreTests/V3RecoveryLifecycleIntegrationTests.swift)
extends the existing component evidence with two longer sequences. Actual
enrollment, rotation, revocation and recipient-removal publication surround
ordinary edits. Recipient addition retains the existing domain-builder and
fixture-materialization boundary; this is not another possession/registration
ceremony. Independent local Mac checkpoints catch up through five or seven epochs,
and a visibly revoked Mac refuses before a private opening.

The continuing Mac saves, the original writer catches up to that save and writes,
then the continuing Mac catches up again. Those reciprocal same-epoch advances
need no additional Mac opening or owner signature. Sessions are invalidated,
both public manifest caches are removed, and the Mac fixtures leave helper scope.
Only the immutable source, public recovery anchor and software backup credential
remain. Recovery must open the complete final snapshot with exactly one software
agreement callback and preserve both later saves, the final edit and TOTP entry.
The second sequence explicitly acknowledges the last-recipient removal, still
permits ordinary catch-up and saves, and rejects the former backup recipient
before recovery opening. Neither test uses native UI, a token or a real vault.

Source self-review traced concrete coordinator ownership, direct component
owners, generation receipts, public-before-private epoch checks, full boundary
snapshot equality, three pending-work namespaces, checkpoint CAS, committed
cleanup and reciprocal ordinary publication. No confirmed production defect
requiring a change was found in that review. This is not a fresh independent
review, proof of protocol security or physical/native qualification. Public
history, current-snapshot authentication and source-stability checks retain their
documented scope; provider withholding remains outside the project's guarantee.

Verification before the local commit:

- The unlocked full Debug run at `f04164b` passed 1,495 KeyCore tests in 119
  suites and six canonical-JSON tests in one suite. It started before the new
  integration declarations were added. The exact protected-storage handler test
  that failed while locked in the earlier increment passed in this full run.
- Both added integration declarations then passed in their focused Debug run,
  using the expanded test module. No production code changed between these runs.
- Full Release with the expanded module passed 1,497 KeyCore tests in 120 suites
  and six canonical-JSON tests in one suite, including both new declarations and
  protected storage. The separately gated large-migration qualification remained
  skipped in both full runs.
- Strict formatting of the new test file, Git whitespace checks and all 208 local
  documentation targets passed. Production sources and Xcode wiring are unchanged;
  the preceding universal Preview/bundle/CLI evidence still applies to them.
- The console was observed unlocked through these checks. No protection or
  screen-lock setting changed. Only contained fixture caches were removed; no
  user data or installed app was affected.

Raw output uses `tmp/piv-recovery/2026-10-06-lifecycle-integration-` and remains
ignored. Only the tests and reconciled implementation evidence belong in the commit.

Next: evaluate the integration results, then review/finalize PR 72's internal
lifecycle scope before moving to the restore review layer. Product dispatch,
confirmation UX, native prompt behavior and physical backup-token acceptance
remain later work. No implementation package is marked complete, and no real
vault/configuration, installed app, token operation/administration, push or release
is involved in this test-and-evidence increment.

### Eighteenth 810 independent lifecycle review and rotation fixes, 2026-10-06

A fresh, read-only AI reviewer inspected `1d81575` against
`codex/recovery-content`, including lifecycle policy/builders, publication and
restart services, joining adoption, shared transaction changes, remaining-Mac
catch-up and mixed coordination. The reviewer reported two P2 findings in initial
rotation. Source inspection and contained software regressions confirmed both:

- Lock followed by same-key reauthentication during signing or wrapper approval
  was indistinguishable from the original session. Rotation now captures the
  existing generation ticket before loading its key, checks it after base
  validation and signing, and uses guarded atomic installation. Refusal before
  publication preserves the separately reauthenticated session; refusal after
  commitment locks rather than leaving a stale key.
- Final activation checked registration/adoption ownership but not ordinary
  pending work. It now requires either no ordinary pin or the exact recoverable
  pin and matching intent for this committed rotation, before and after complete
  snapshot authentication. Malformed, foreign, unreadable or mismatched ownership
  refuses installation. Valid cleanup-failure pins remain allowed.

These fixes reuse the authority-change service's existing mechanisms. They add no
new protocol, token operation, persisted secret, retry or rollback path. The two
findings are grouped in one local commit because both protect activation of the
same committed rotation. Error handling preserves committed checkpoint trust
and pending work. The independent reviewer rechecked the remedies and found no
unresolved issue in that diff; it ran no tests and made no edits.

Verification:

- Six added parameter cases reproduced the gaps before production changes. The
  focused 13-declaration Debug suite failed with 13 assertion issues across those
  cases. The same suite passed after the fix, including all durable interruption
  boundaries, cancellation, ordinary saving and valid cleanup-failure ownership.
- A separate focused Release run passed all 15 rotation-service and lifecycle
  integration declarations in two suites. It exercises the full mixed histories,
  reciprocal saving and software recovery without Mac state, using the same
  optimized binaries as the broad run.
- Full Release attempted 1,497 KeyCore tests in 120 suites and failed with 65
  assertion issues in five protected-storage suites: `CryptoAndStorageTests`,
  `KeyServiceHandlerTests`, `SessionVaultKeyStoreTests`,
  `V2MigrationPreflightTests` and `VaultTransactionMutationOwnerTests`.
  All recovery and device-wrapped session suites passed within that run; the six
  canonical-JSON tests also passed. Large-migration qualification remained skipped.
  The console was observed locked before and during the run. Failures report
  permission errors or downstream unsuccessful responses on unchanged
  `EntryStore.save` code, which uses `.completeFileProtection`. This is consistent
  with the locked-console condition, not a fresh full-suite pass. An unlocked
  rerun remains necessary to settle that qualification; no protection/lock setting
  was changed.
- Unsigned universal Preview compilation passed, with arm64/x86_64 app, CLI and
  helper slices. Product-bundle isolation and the real bundled CLI's help/version
  checks passed. Nothing was installed or launched beyond those read-only CLI
  commands.
- Strict formatting of both Swift files, Git whitespace checks and all 210 local
  documentation targets passed.

Raw review output and test logs use `tmp/piv-recovery/2026-10-06-lifecycle-`
and remain ignored. This review covers internal lifecycle code, not shipping
dispatch, cold product unlock, restore, native storage/hardware qualification or
provider withholding. No broader security certification is claimed.

Next: new-vault restore orchestration (`REC-811`) in the next stack layer.
User-confirmation/product integration and physical qualification remain later
work. No implementation package is marked complete. This increment changes no
real vault, configuration, installed app or token, and performs no push or release.

### First 811 source-bound restore candidate, 2026-10-07

The new local `codex/recovery-restore` layer starts at lifecycle commit `ce63290`,
using `gh stack add`. It is above `codex/recovery-lifecycle` in the existing stack;
no hosted PR was created or changed, and nothing was pushed.

The [candidate component](../Sources/KeyCore/V3RecoveryRestoreCandidate.swift)
accepts only a `V3RecoveryVerifiedSnapshot`, which the complete snapshot verifier
alone can construct. It rechecks the exact observed source, then reuses the
permanent genesis builder with new vault/transition/entry identifiers and an
explicit new Mac identity. It rejects reuse of the selected source's namespace,
entry/transition identifiers and device/recipient public keys. Randomness and
identity creation remain the future restore owner's responsibility; this domain
component does not prove entropy or create platform credentials.

Independent candidate validation parses the permanent envelope, verifies its
digest and MAC, requires one new active Mac and its addressed wrapper, checks
every encrypted entry against the manifest, and compares exact plaintext/name
bytes and types with the verified source. New entry revisions start at one.
Byte comparison does not treat canonically equivalent Unicode secrets as the
same bytes. Complete source state is checked again after crypto validation.
No source roster, signing capsule, recovery recipients or ancestry becomes the
new vault's authority. Its ordinary wrapper still needs an actual addressed Mac
opening before checkpoint trust or configuration selection.

Architecture inspection compared adding a restore mode to the existing genesis
installer with restore-owned orchestration over shared domain crypto. The existing
installer removes staging on errors and cannot resume exact artifacts. Restore
will therefore own its journal and destination/configuration barriers while
reusing the existing builder, entry validator and ordinary runtime. This increment
implements preparation/validation only, not another crypto or publication kernel.

Verification:

- Focused Debug passed 35 declarations in three suites: restore candidates,
  recovery history/snapshot verification and permanent genesis construction.
  Six restore declarations exercise 28 cases, including an empty
  verified snapshot, reused source identifiers/keys, altered contents/artifacts,
  Unicode byte differences, changed source and resource bounds.
- Focused Release passed 50 declarations in five suites: the same three suites
  plus initial rotation and reciprocal lifecycle integration. All checks use
  contained filesystem/software crypto, without native or token prompts.
- The console initially reported locked. A final query returned no usable flag;
  no unlocked state was inferred from its absence. The five storage suites that
  failed in the preceding increment then passed all 68 declarations in a direct
  optimized rerun, including the exact mutation-owner handler regression.
- The subsequent full optimized rerun passed 1,503 KeyCore declarations in 121
  suites and six canonical-JSON declarations in one suite, including protected
  storage, the rotation fixes and the new restore component. The separately gated
  large-migration qualification remained skipped. This supersedes the preceding
  locked-console full-Release failure for ordinary regression qualification at
  this revision; it does not qualify native restore or hardware behavior.
- The added sequence performs actual key-rotation and ordinary-edit publication,
  clears its Mac session, then prepares the latest recovered secret and TOTP
  contents. One software recovery agreement suffices; preparation makes no
  additional source-Mac private call or source write. No token is involved.
- Unsigned universal Preview compilation passed. App, CLI and helper each have
  arm64/x86_64 slices; product-bundle isolation and the real CLI's help/version
  checks passed. Nothing was installed.
- Initial test compilation corrected an existing edit-request argument label;
  test limit construction was also corrected to satisfy repository preconditions.
  No production validation was relaxed.
- Strict formatting of both Swift files, project syntax, Git whitespace checks
  and all 215 local documentation targets passed. No lock or protection setting
  was changed.

Raw logs use `tmp/piv-recovery/2026-10-07-restore-candidate-` and remain ignored.
This is source self-review and software composition evidence, not fresh independent
review, native provenance or physical recovery qualification. No implementation
package is complete and no product restore command is enabled.

Next in this layer: exact destination/configuration ownership and scoped
authenticated restore intent, then manifest-last publication, explicit resume
without regenerated artifacts, and fresh ordinary Mac-bound reopening before
selection. This increment changes no real vault, configuration, installed app or
token and performs no hardware administration, push or release.

### Second 811 live restore bindings and authenticated record, 2026-10-07

This increment stays on local `codex/recovery-restore`, above the existing
lifecycle layer. It implements the record format and initial live filesystem
guards, not a durable journal or product restore route.

The [restore environment](../Sources/KeyCore/V3RecoveryRestoreEnvironment.swift)
owns the opened source, newly created destination, destination parent and local
configuration root. It checks physical ancestry before creating the final folder,
including a source reached through a symlinked ancestor. The new destination
cannot be inside the source or configuration tree. Existing folders are refused,
even when empty. Exact path bytes and physical identities are retained and
rechecked around source observations and future durable transitions. Any config
file, directory or dangling link blocks preparation. This initial path requires
an unconfigured Mac and an existing local config directory; its read-only config
accessor does not bootstrap paths or write a selection.

The [intent](../Sources/KeyCore/V3RecoveryRestoreIntent.swift) binds one operation,
those locations, the exact source anchor/credential/head, a stable commitment to
the observed manifest inventory/history, and the new genesis digest/key ID/owner.
The genesis digest already commits the complete entry references, transition and
addressed wrapper. Its bounded canonical format uses a restore-only HKDF/HMAC
domain and the destination vault key, with a key-ID check. No plaintext, raw key,
PIN, administrator secret or saved approval is recorded. Construction rechecks
the snapshot through the environment's retained source descriptor before and
after record authentication. Parsing alone grants no authority.

Architecture inspection compared reusing the registration intent/ownership
semantics with a separate restore format over the existing persistence and crypto
mechanisms. Registration authenticates an existing parent checkpoint and token
registration; restore binds a different namespace, physical destination and
currently absent configuration. Reusing its semantic record would obscure those
requirements. Restore therefore keeps its own format while retaining canonical
JSON, purpose-separated HKDF/HMAC, descriptor-relative source reads and the
existing exclusive directory creator. No generic transaction-policy framework
or new encryption format was introduced.

Verification:

- The initial focused Debug run passed 39 declarations in three suites. Two
  further restore declarations and source-descriptor binding were then added.
- Final focused Release passed 89 declarations in six suites: both restore
  components, recovery history, initialization, config compatibility and the
  existing permanent-genesis installer. Twelve new declarations exercise 40
  cases over contained filesystem/software crypto. They cover incorrect keys,
  changed/malformed/oversized records, a later source, folder replacement, config
  arrival and refusal before directory creation. Inspection leaves a missing
  config root missing. No token or native credential is used.
- Full Release passed 1,515 KeyCore declarations in 122 suites and six canonical
  JSON declarations in one suite. The separately gated large-migration
  qualification remained skipped. This qualifies ordinary software regression
  at this increment, not native or hardware restore behavior.
- The final unsigned universal Preview build passed. App, CLI and helper each
  contain arm64/x86_64 slices; product isolation and actual CLI help/version
  checks passed. Nothing was installed.
- Strict formatting passed for the three new Swift files. Whole-file formatting
  of the touched legacy config source still reports its 61 existing diagnostics;
  comparison against the parent found no changed diagnostic messages/counts.
  Those unrelated lines were left intact. Project syntax, Git whitespace and
  all 222 relative documentation targets passed.
- Initial compilation corrected a missing throwing-call marker, the tests'
  existing module-import convention and a software closure's Sendable captures.
  Production validation was not relaxed. Self-review moved overlap refusal
  before folder creation and bound record construction to actual source reads.

Raw logs use `tmp/piv-recovery/2026-10-07-restore-intent-` and remain ignored.
This is source self-review and software qualification, not fresh independent
review, native provenance or physical recovery qualification. No implementation
package is complete. No real vault, config, installed app or token was changed,
and nothing was pushed or released.

Next: reserve local ownership before platform credential creation and durably
store the exact complete encrypted preparation. Only that owned preparation may
support explicitly reauthenticated resume. Manifest-last publication, exact
interruption reconciliation, checkpoint installation, fresh ordinary Mac-bound
reopening and final no-overwrite config selection still remain. The current
record alone cannot resume or publish, and a new attempt cannot adopt an existing
empty destination. Source/native binding and session-generation checks must be
carried through the future service; filesystem observations are not locks.

### Third 811 durable local reservation and encrypted preparation, 2026-10-07

This increment stays on local `codex/recovery-restore`. It adds internal
persistence and explicit software confirmation of a complete owned preparation.
It does not enable a product restore command or publish destination objects.

The [journal](../Sources/KeyCore/V3RecoveryRestoreJournal.swift) uses two dedicated
ownership namespaces, both keyed by the source vault ID. The first pins the
exact [reservation](../Sources/KeyCore/V3RecoveryRestoreReservation.swift) before
any platform credential is created. That public record binds the source
anchor/point/head/observed history, source/destination/config locations and fresh
vault/transition/entry IDs. Returning it requires contained atomic installation,
exact readback, file/directory synchronization and source/pin revalidation. The
existing single-use new-directory gate now spans environment copies; a reopened
environment cannot reserve again. Its immutable handles and lock-protected
single mutable field support the retained Sendable environment.

The second pin commits the exact complete
[encrypted bundle](../Sources/KeyCore/V3RecoveryRestoreBundle.swift) before its
file is written. It contains the authenticated intent, genesis envelope and all
encrypted entries, not plaintext, raw keys or approval. Both records live under
the local configuration root at `v3-restore-attempts/<operationID>/`, outside the
source and destination vaults. The existing ownership store is non-synchronizing
and device-only. Its format and ordinary transaction, registration and adoption
namespaces remain unchanged.

Inspection compared adding restore-specific phases to the shared ownership
anchor with two namespaces using its existing format. A reservation exists before
there is a credential; a complete encrypted preparation has a different digest
and failure boundary. Separate pins represent both without changing every
existing ownership decoder or hiding record-type policy inside a generic phase
machine. The journal reuses the existing contained atomic writer, exact durable
readback, source verifier and full genesis validation. It introduces no new
encryption algorithm or general transaction framework.

Only locally pinned operation IDs select files. The journal checks each complete
record against its ownership digest before returning candidate wrapper bytes.
Files without a pin are inert, and JSON paths are never opened as authority.
Missing, changed, oversized, symlinked or uncontained records stop the operation.
An incomplete reservation cannot recreate credentials or silently regenerate
preparation. There is no cleanup or abandonment implementation yet.

Explicit confirmation receives a freshly verified source snapshot, destination
key and expected owner. It authenticates the intent and reconstructs validation
input from the saved ciphertext plus scoped source plaintext, with no encryption,
randomness or wrapper generation. Existing full checks authenticate the genesis
and every entry and compare every restored plaintext/type/name. Live locations,
source observation, both pins and both saved files are checked across the durable
transition, including a final exact reload. A source that changes during
validation cannot advance an unready preparation pin.

Verification:

- Focused Debug passed 93 declarations in five suites. After adding the final
  reserved-ID and budget checks, the complete new journal suite passed its 13
  declarations and 45 cases in Debug.
- Final focused Release passed 113 declarations in six suites, including all
  restore components, initialization, registration and the existing permanent
  genesis installer.
- Full Release passed 1,528 KeyCore declarations in 123 suites and six canonical
  JSON declarations in one suite. The separately gated large-migration
  qualification remained skipped. Protected-storage regression checks passed;
  this is not native restore or hardware qualification.
- New cases cover empty/populated preparation; all seven durable journal
  boundaries; interruptions during both real atomic file writes; fresh-reader
  confirmation after a destination software-wrapper opening; wrong keys/owners;
  source changes; folder replacement; config arrival; ownership/file changes
  during final validation; missing, oversized and symlinked files; inert unowned
  records; exact reserved IDs; resource refusal before consumption; and bounded
  public bundle parsing without an authentication claim. No ciphertext or
  platform credential is regenerated during confirmation.
- Unsigned universal Preview compilation passed. App, CLI and helper each
  contain arm64/x86_64 slices; product isolation and actual CLI help/version
  checks passed. Nothing was installed.
- Strict formatting passed for the seven restore Swift files. The two touched
  legacy sources retain their 66 existing whole-file diagnostics; comparison
  against the parent found no changed diagnostic messages/counts. Project syntax,
  Git whitespace and all 232 relative documentation targets passed.
- Initial compilation corrected the fixture's ownership type, a limit argument
  name and nested throwing-call markers. Preservation assertions were corrected
  to compare each exact record's bytes directly. Production validation was not
  relaxed. Self-review added final reloads of both records and retained the
  existing single-use directory gate rather than adding another mutable gate.

Raw logs use `tmp/piv-recovery/2026-10-07-restore-journal-` and remain ignored.
This is source self-review and software composition evidence, not fresh
independent review, native credential provenance, separate-process recovery or
physical-token qualification. The tests replace only the Keychain ownership
boundary with the existing compare-and-replace fixture and use real disposable
filesystem/crypto operations. The new live Keychain namespaces are not accessed.
No implementation package is complete. No real vault, config, installed app or
token was changed, and nothing was pushed or released.

Next: manifest-last publication of this exact owned preparation and explicit
interruption reconciliation, followed by checkpoint installation, fresh ordinary
Mac-bound reopening and final no-overwrite configuration selection. Native
credential creation/opening and source/token/session-generation binding still
need the serialized service owner. The current confirmation operation does not
provide those approvals or make its returned bundle permission to publish.

### Fourth 811 manifest-last publication and exact reconciliation, 2026-10-07

This increment stays on local `codex/recovery-restore`. The internal
[publisher](../Sources/KeyCore/V3RecoveryRestorePublisher.swift) publishes a
complete, locally owned encrypted preparation. It does not install checkpoints,
cache manifests, select configuration or expose a product restore command.

Publication first confirms the saved preparation, revalidates the actual source
and checks the candidate under publication limits. It then uses the existing
permanent-profile checkpoint unlocker to open the saved addressed Mac wrapper
once and compare the resulting key with the supplied destination key. The
validation session is scoped to the call and invalidated on every exit. A later
explicit publication call must open the same saved wrapper again; it never
creates credentials or repeats encryption.

Inspection compared calling the existing genesis installer with a separate
restore publisher. The installer generates vault/key/device state, assumes a
single-use first attempt, and proceeds through trust installation and selection.
Those responsibilities do not fit a saved, source-bound restore preparation or
an explicitly resumed attempt. Restore therefore retains its own narrow
publisher, using the existing full candidate checks and wrapper opener.

The complete encrypted preparation is already durable staging. Duplicating it
under `.transactions` would add another set of crash artifacts and cleanup
ownership. Instead, the publisher uses the existing contained atomic
no-overwrite writer directly at each final content address. Entry bytes and
directories are synchronized and read back before the genesis manifest is
installed. The saved manifest and every ciphertext must match the owned bundle
exactly. Full genesis validation rechecks names, types, plaintext bytes, roster,
key ID and authenticated content against the fresh source snapshot.

Before a manifest exists, destination inspection permits only exact known object
addresses and known empty parent folders left by interrupted creation. It rejects
unrelated root files, extra entry IDs, extra object versions, foreign manifests,
symlinks, malformed bytes and orphan partial files. No unknown object is removed.
Directory listings use fresh open descriptions and bounded counts. Published
entries can be reconciled from the same bundle, with no new nonce, wrapper, ID or
credential. If the manifest already exists, all exact entries must already be
present; damaged committed snapshots are refused, not repaired.

Source observations, live source/destination/config identities, local ownership
and saved record bytes are rechecked across wrapper opening and publication.
Detected changes stop the attempt and leave its preparation and published objects
in place. These are observations, not filesystem locks. The future helper owner
must still serialize callers and bind the operation to current authentication
and session generation.

The publication report identifies a checkpoint to be considered by later trust
installation. It is not saved approval or a reason to clear ownership. There is
no checkpoint/cache/config write or persistent session installation in this
publisher. The token and original Mac credentials are not publication dependencies;
the caller supplies its already verified source snapshot and the new Mac identity.

Verification:

- Initial focused Debug passed 42 declarations in four restore suites. After
  adding empty-vault boundaries, interrupted-parent-folder cases and separate
  explicit continuation after authentication failure, the final Debug publisher
  suite passed all 13 declarations and 60 cases.
- Final focused Release passed 126 declarations in seven suites, including the
  restore components, initialization, registration and the existing permanent
  genesis installer.
- Full Release passed 1,541 KeyCore declarations in 124 suites and six canonical
  JSON declarations in one suite. The separately gated large-migration
  qualification remained skipped. Protected-storage regression checks passed.
- Publication cases cover exact empty/populated objects, every reachable
  observer boundary, interruption inside both real atomic installation paths,
  explicit fresh-reader reconciliation, no automatic private retry, incorrect
  identities/keys and cancellation. Record, ownership, source, config and folder
  changes across wrapper opening and final validation stop the operation.
  Unknown objects and symlinks refuse before wrapper opening. A published
  manifest with damaged/missing entries refuses without repair or replacement.
- Unsigned universal Preview compilation passed. App, CLI and helper each
  contain arm64/x86_64 slices; product isolation and actual CLI help/version
  checks passed. Nothing was installed.
- Strict formatting of all three touched Swift files, project syntax, Git
  whitespace and all 237 relative documentation targets passed.
- Initial compilation corrected the repository's already encoded entry-digest
  type and test availability/throwing-expression annotations. Self-review added
  publication-limit validation before the private operation and complete-entry
  checks immediately before manifest installation. Production protections were
  not relaxed.

Raw logs use `tmp/piv-recovery/2026-10-07-restore-publication-` and remain ignored.
This is source self-review and filesystem/software-wrapper evidence, not fresh
independent review or native authentication qualification. Tests replace the
Keychain boundary with existing memory ownership and use the real atomic writer
and real software HPKE. They reuse the previous journal fixture rather than
duplicating setup or introducing a test-only production adapter. Actual process
termination, a later OS process, large-vault performance and physical recovery
remain unqualified. A crash that leaves an orphan partial file is not promised
automatic continuation; it stops for inspection without deletion. No
implementation package is complete. No real vault, config, installed app or token
was changed, and nothing was pushed or released.

Next: exact checkpoint installation and a fresh ordinary Mac-bound reopen,
followed by no-overwrite configuration selection and completed-state ownership
reconciliation. Native source/key/session binding, credential creation and product
restore/resume still need the serialized service owner. No selection should rely
only on the report returned by this publisher.

### Fifth 811 insert-only trust and fresh ordinary-runtime read, 2026-10-07

The internal [trust installer](../Sources/KeyCore/V3RecoveryRestoreTrustInstaller.swift)
stays on local `codex/recovery-restore`. It rechecks the complete owned published
snapshot without repairing files. Missing, changed or unknown objects cannot
justify local trust. Only an absent checkpoint is inserted; an existing exact
checkpoint supports explicit continuation, and different/malformed trust is refused.

The addressed saved identity is loaded through the existing identity boundary.
Its wrapper is verified before checkpoint insertion. Exact encrypted manifest
bytes are stored using the existing filesystem cache. Source/location/ownership,
record, checkpoint and cache checks span the durable boundaries; failures retain
exact committed trust rather than deleting or replacing it.

Inspection compared reopening with a preseeded preparation session against an
empty ordinary-runtime session. Preseeding would prove file/crypto consistency
but not independent access through the saved Mac identity. The installer instead
clears validation state, creates an empty session and uses the ordinary identity
loader, unlock runtime and read runtime. It opens the published wrapper and
checks every item name/type/plaintext byte against the recovered snapshot.
Both temporary sessions are invalidated on exit. This requires two software Mac
wrapper calls within trust completion, independent of entry count, and no token
operation. Native authentication prompt counts are not qualified.

Verification:

- Final focused Release passed 134 declarations in eight suites. The new trust
  suite's eight declarations cover 26 cases, including every trust boundary,
  conflicting/malformed checkpoints, cache/CAS failure, failed initial identity
  access, failed fresh reopening and changed source/config/ownership/files.
- Final focused Debug passed all eight trust declarations and 26 cases. Empty
  and populated snapshots open through a new ordinary runtime/session, with two
  addressed software-wrapper calls and no original Mac private operation.
- The full Release run failed with 65 issues across 1,549 KeyCore declarations
  in 125 suites. Existing protected-storage writes were denied while the console
  was locked, confirmed by `CGSSessionScreenIsLocked=Yes`. The new trust suite
  passed within that run; six canonical-JSON declarations also passed. The
  separately gated large migration remained skipped. This failed run is retained
  as verification history, not ordinary regression qualification.
- The subsequent full Release rerun passed all 1,549 KeyCore declarations in
  125 suites in 250.320 seconds, plus six canonical-JSON declarations in one
  suite. It used the same optimized binaries with `--skip-build --no-parallel`.
  The separately gated large migration remained skipped. This pass qualifies
  the ordinary software regression scope, not native or hardware recovery.
- Unsigned universal Preview compilation, arm64/x86_64 slices for app/CLI/helper,
  product isolation, actual CLI help/version, strict formatting of four touched
  Swift files, project syntax, Git whitespace and 241 local documentation targets
  passed. Nothing was installed.
- Initial compilation corrected throwing-call and shared-fixture visibility
  annotations. One failure fixture cancelled the first wrapper when it intended
  a missing identity on the second load; that test was corrected and rerun.
  Production protection checks were not relaxed. The passing full rerun resolved
  the regression gate before the local commit.

Raw logs use `tmp/piv-recovery/2026-10-07-restore-trust-` and remain ignored. Tests
use real contained files and the real filesystem cache, with memory checkpoint
ownership and software identities. No native Keychain checkpoint, Secure Enclave
credential or token is accessed by the new cases. This is source self-review and
same-process ordinary-runtime composition, not fresh independent review,
separate-process recovery or native authentication qualification. Large-vault
performance and physical recovery remain unqualified. No implementation package
is complete. No real vault, config, installed app or token was changed, and
nothing was pushed or released.

Next: no-overwrite configuration selection and completed-state reconciliation.
Those steps must recheck actual trust/files rather than treating this report as
saved approval. Native source/identity/session-generation binding and serialized
product restore/resume still need service integration. Configuration is not
selected and ownership is not cleared by this increment.

### Sixth 811 configuration selection and reconciliation, 2026-10-07

The internal [selection installer](../Sources/KeyCore/V3RecoveryRestoreSelectionInstaller.swift)
stays on local `codex/recovery-restore`. It loads the exact owned preparation,
matches independently opened physical handles, and invokes the trust installer
for fresh saved-identity access and ordinary-runtime verification. A prior report
is not accepted as approval or completion evidence.

Inspection compared the mutable config setter with the existing contained atomic
writer. A setter could replace a competing selection; the atomic writer preserves
it. Selection therefore publishes the normal local config without overwrite and
checks the source, owned records, complete files, checkpoint and encrypted cache
again at the synchronized temporary-file boundary and after publication.

Keeping every environment strictly unconfigured would prevent reconciliation
after a committed config write. A dedicated completion environment instead
requires exact selected bytes and the intended vault ID. It never accepts a
semantically similar or user-edited config. Existing exact checkpoint trust is
required before credential access; config cannot recreate missing trust. The
ordinary preparation/publication gates remain unconfigured-only. Selected retry
repeats fresh trust/read verification and synchronizes config without rewriting.
Failures retain committed config/trust and both ownership pins, with no rollback,
repair, resealing, credential creation or private-operation retry.

Verification:

- Final Debug passed 11 declarations and 42 cases. Real filesystem cases cover
  empty/populated selection, all three selection boundaries before/after config,
  malformed/different/linked config, missing/different checkpoint, temporary-write
  interruption, source/ownership/file changes, physical-root replacement and
  selected-state damage. A separately constructed ordinary runtime uses only
  the actual saved config, identity, checkpoint and cache to read every item.
- Focused Release passed 116 declarations in ten suites covering restore,
  config compatibility, initialization, genesis and unconfigured enrollment.
- Full Release passed all 1,560 KeyCore declarations in 126 suites in 298.861
  seconds, plus six canonical-JSON declarations in one suite. The separately
  gated large migration remained skipped. No behavioral source change followed
  the focused optimized build; the full run used `--skip-build --no-parallel`.
- Unsigned universal Preview compilation, arm64/x86_64 app/CLI/helper slices,
  bundle isolation, actual CLI help/version, strict formatting of six restore
  Swift files, project syntax, Git whitespace and 246 relative documentation
  targets passed. The existing config file's formatting convention is retained.
- The first test compile rejected an incorrect fixture `Sendable` declaration;
  callbacks now capture only their actual Sendable dependencies. The first Xcode
  build caught a file-reference/build-reference typo, corrected before the
  successful build. Self-review added the selected-config vault-ID guard and its
  regression case. No production protection check was relaxed.

Raw logs use `tmp/piv-recovery/2026-10-07-restore-selection-` and remain ignored.
Tests use disposable config/files/cache, software identities and memory
checkpoint/ownership stores. No real config/vault, native credential or token
was changed. Native prompt counts, physical recovery, separate-process recovery,
large-vault performance and fresh independent review remain unqualified. No
implementation package is complete, and nothing was installed, pushed or released.

Next: interruption-safe ownership finalization. Both pins and encrypted records
remain deliberately intact; a selected report does not authorize deleting them.
Later ordinary edits that advance the restored checkpoint are not adopted by
this exact-genesis path. Native approval/session-generation binding, serialized
service orchestration and product restore/resume remain.

### Seventh 811 ordered ownership finalization, 2026-10-07

The internal [finalizer](../Sources/KeyCore/V3RecoveryRestoreFinalizer.swift)
stays on local `codex/recovery-restore`. It verifies the actual selected config,
existing exact checkpoint/cache, complete owned published files and freshly
scoped source snapshot. The shared ordinary reopener loads the saved Mac identity
into a new empty session, opens its wrapper once, compares every restored item
and invalidates the temporary session. No prepared key is injected and no token
operation is requested by this component.

Inspection compared the two possible removal orders. Preparation-first loses
the local digest of the complete encrypted bundle. Reservation-first retains it,
so the journal can verify that same bundle and reconstruct every original public
reservation field solely to compare it with the retained record. This supports
halfway continuation without a third marker, another namespace, a new format or
restoring a removed pin. Normal pending/preparation/publication/selection readers
still refuse preparation-only ownership. The finalization reader does not grant
approval; selected config, existing trust and fresh ordinary access remain required.

Exact reservation CAS removal precedes another complete state check, then exact
preparation CAS removal. Changes or ambiguous errors stop further work without
retry or rollback. Final checks also require both pins absent before success is
returned. If the final reply is lost, a later call returns only "no locally owned
pending attempt", not a retrospective success claim from unowned files. Ordinary
configured-vault status remains a separate check. Encrypted journal files remain
inert audit evidence; no filesystem object, config, credential, source or
destination checkpoint is deleted.

Verification:

- Debug passed ten finalization declarations and 40 cases. Empty/populated
  snapshots, every boundary, before/after-application CAS errors, cancelled or
  unavailable fresh identity, conflicting config/trust, damaged/missing records,
  changed source and halfway ownership substitution are covered. Calls after
  final clearance load no file or identity and make no success claim.
- Earlier Debug restore regression passed 32 declarations in three suites after
  sharing the ordinary reopener. The first new test compile required availability
  and throwing-call annotations; those were corrected before the passing run.
- Final focused Release passed 101 declarations in nine suites covering restore,
  initialization and config compatibility. Full Release passed all 1,570 KeyCore
  declarations in 127 suites in 336.911 seconds, plus six canonical-JSON
  declarations in one suite. The separately gated large migration remained
  skipped. No source changed after the focused optimized build; the full run
  used `--skip-build --no-parallel`.
- Unsigned universal Preview compilation, app/CLI/helper arm64/x86_64 slices,
  bundle isolation and actual CLI help/version passed. Strict formatting of eight
  touched Swift files, project syntax, Git whitespace and 251 relative
  documentation targets passed. Nothing was installed.

Raw logs use `tmp/piv-recovery/2026-10-07-restore-finalization-` and remain ignored.
The tests use real disposable files/cache/runtime, software identities and memory
checkpoint/ownership stores, including an applied-then-failed CAS boundary. They
do not qualify native Keychain removal, authentication prompt counts, hardware,
separate-process recovery, large-vault performance or a fresh independent review.
No real vault, configuration, credential or token was changed. No implementation
package is complete, and nothing was pushed or released.

Next: authenticated restore service orchestration. It must compose existing
reservation, saved-credential preparation, publication, trust/reopen, selection
and finalization under the native source/identity/session-generation scope and
host serialization. Product restore/resume, separate-process ordinary access and
physical acceptance remain. Later ordinary edits are not silently adopted by the
exact-genesis cleanup path.

### Eighth 811 authenticated preparation service, 2026-10-07

The internal [restore service](../Sources/KeyCore/V3RecoveryRestoreService.swift)
now connects the native public reader and one-operation agreement adapter to
the permanent-genesis builder, existing Mac identity manager and owned journal.
It accepts independently opened source/parent handles and a reader-issued
observation, not caller-supplied recovered plaintext or a saved approval flag.
Public preflight checks the exact journal/config root, unconfigured selection,
credential policy, recognized token anchor and absence of prior ownership.
The source selector and complete current-snapshot verifier run through the real
adapter with exactly one software-provider agreement in the tests.

One shared source mutation owner spans the request. The service captures the
existing authentication-generation ticket before queue admission; lock,
replacement, cancellation or deadline expiry prevents later admission. After
the hardware operation drains, an exclusive token lease spans preparation.
Rechecks reread the same card/key/anchor and verify the exact source observation,
with public sessions closed before Mac private operations. This does not freeze
external filesystem or token changes; checks surround the admitted operations.
Product host serialization and lock/disconnect invalidation still need wiring.

Only a freshly authenticated source can create the requested new final folder.
Fresh vault, transition and entry IDs are pinned in a durable reservation before
creating any Mac credential. The service independently reloads the saved
identity, checks its namespace/public identity, creates a random destination
key, and opens the new Mac wrapper through the existing checkpoint unlocker.
The recovered source key is not needed for any destination wrapper. The
temporary destination session is invalidated before encrypted preparation is
staged; no key is installed in the supplied authentication-generation store.
The returned report contains identifiers, destination path and entry count only.

The journal accepts a synchronous, nonescaping scope check for reservation,
staging and preparation confirmation. The existing atomic writer now admits
such a check before writing and immediately before each rename attempt, after
the synchronized-temporary-file observer. Unrelated callers retain their
existing behavior. Incomplete or ambiguously saved state stays owned and intact;
another prepare request refuses before another agreement, directory or identity.
No automatic retries, replacement artifacts, token writes or cleanup are added.

Two service designs were considered against native provenance, secret lifetime,
interruption ownership and existing module boundaries. A separate retained
recovery-key session would introduce another secret-owning lifecycle and make
later components depend on a saved-session capability. Composing the existing
native reader/agreement in one synchronous scope keeps source plaintext and
the destination key local to the call, with the established generation ticket
as a race guard rather than evidence of consent. This increment uses that
composition without changing a persisted format or the shipping host.

The [service suite](../Tests/KeyCoreTests/V3RecoveryRestoreServiceTests.swift)
has 14 declarations / 45 cases. It uses actual adapters, codecs, cryptography,
contained files and the real mutation owner; only native card/provider/Mac keys
and device-local ownership storage are replaced. Cases cover empty/populated
sources, native observation provenance, cancellation and locks, late record
rename rejection, ownership-advance guards, uncertain credential save/reload,
source/token change during Mac approval, interrupted replies, journal-root
mismatch and competing requests. Existing native fixture code is reused.

Verification:

- Initial focused Debug: 12 service declarations / 38 cases passed in
  7.467 seconds, before adding observation-provenance and interrupted-reply
  cases. The final optimized run passed 190 declarations across 15 suites in
  123.050 seconds, including all 14 service declarations / 45 cases, restore
  primitives, reader/agreement adapters, transaction ownership and config/init
  regressions. Initial compile errors for a non-Sendable config value and the
  exhaustive content-policy switch were corrected without changing config
  ownership or permitting restore as a content edit.
- Full optimized suite: 1,584 KeyCore declarations across 128 suites passed in
  337.015 seconds; six canonical-JSON tests also passed. The separately gated
  large migration was skipped, unchanged. This run reused the final optimized
  binaries; no source changed afterward.
- Unsigned universal Preview build succeeded. Product-bundle isolation,
  bundled CLI help/version `0.2.0 (19)` and arm64/x86_64 slices for the app,
  CLI and helper passed. Nothing was signed, installed or published.
- Strict default Swift-format lint passed for five changed/new Swift files.
  The same lint reports existing four-space/style findings in the three older
  writer/store/mutation-owner files; comparison against HEAD confirmed the
  non-indentation findings predate this change. Their established formatting
  was preserved instead of bulk rewriting them. Project plist syntax,
  258 relative documentation targets and `git diff --check` passed.

Raw logs remain under ignored
`tmp/piv-recovery/2026-10-07-restore-service-*`.

Next: extend this same service scope through existing publication, trust/reopen,
selection and finalization, plus exact freshly authenticated resume. The
internal prepare method is not a user-facing two-command approval design;
full initial restore must preserve one source agreement across its completion
steps. Product host/CLI dispatch, separate-process ordinary reads and mutations,
and physical acceptance still remain. No real token, vault or installed product
was operated on by this increment.

### Ninth 811 scoped completion and resume, 2026-10-07

The [restore service](../Sources/KeyCore/V3RecoveryRestoreService.swift) now
completes initial restore through the existing publisher, trust installer,
configuration selector and finalizer inside its original authenticated source
scope. Exactly one source recovery agreement spans preparation through cleanup.
The shared mutation owner and reader's exclusive token lease remain held;
source/token, authentication-generation, cancellation and deadline checks are
passed synchronously into private-operation admission, atomic publication and
ownership removal. No report or persisted field becomes saved approval.

Two continuation designs were considered. Retaining an approval/session object
would introduce another secret-owning lifecycle and require later callers to
interpret its authority. Extending the existing synchronous source scope reuses
the implemented components and keeps keys local to the call. This increment
uses the latter without new durable formats. Configuration publication now uses
the shared atomic writer's nonescaping callback instead of an escaping observer
gate. Internal `prepare` remains available for isolated preparation checks, not
as a proposed two-command initial restore flow.

Explicit resume first checks exact local ownership, physical locations and
public source selection. A reservation without complete preparation refuses
before agreement or Mac credential creation. Complete preparation with a
still-prepared pin can be verified and promoted, using its original bytes.
Resume gets one fresh source agreement and independently reloads/opens the
saved Mac wrapper, invalidating the temporary session before continuation. It
never creates replacement credentials, chooses new identifiers or reencrypts
the preparation. An unselected destination continues through publication and
selection. An already selected destination requires exact existing trust/cache,
skips those steps and only verifies/finalizes. Later ordinary edits are not
silently adopted by this exact-genesis cleanup path.

Ordered cleanup removes the reservation pin first and preparation pin last.
The remaining preparation-only pin can finish exact selected cleanup. If both
pins have already been cleared, resume reports no pending attempt before another
private operation. A lost final reply is not retrospectively converted into a
success claim; ordinary selected-vault status/access is a separate observation.
Encrypted audit records remain intact after successful cleanup.

The [completion suite](../Tests/KeyCoreTests/V3RecoveryRestoreCompletionServiceTests.swift)
adds nine declarations / 83 cases. Actual adapters, crypto, contained files,
ordinary runtimes and mutation owner are used; native I/O and local ownership/
trust storage are substituted. It exercises empty/populated initial restore,
21 interruption boundaries, 42 lock/cancellation cases, late entry/manifest/config
rename guards, prepared-pin promotion, invalid public resume state, existing
selected trust, later ordinary edits and rejected approvals. It also removes
token availability, composes a fresh ordinary runtime from config/saved identity/
trust, reads and mutates the result, then cold-reopens and reads the new entry.
That proof is in one process; separate-process acceptance remains.

Software initial restore performs five saved Mac-wrapper operations;
unselected resume performs five and selected resume two. Each explicit call
uses one source agreement regardless of entry/history count. Wrapper-operation
counts do not qualify physical Touch ID prompts. Product host serialization,
generation invalidation on lock/disconnect and native acceptance remain required.

Verification:

- Focused Debug passed 26 declarations across three suites in 95.557 seconds,
  including initial full restore and existing preparation/selection regressions.
  The optimized restore run passed 96 declarations across nine suites in
  180.667 seconds, including all nine new declarations / 83 cases.
- An initial integration failure exposed strict inventory being checked while
  the atomic writer's own temporary file existed. The corrected rename guard
  checks source scope and exact referenced entries before manifest publication;
  strict inventory runs after atomic installation. No partial-file allowlist or
  inventory relaxation was added. Initial compiler errors were corrected by
  adjusting the private consume callback's lifetime and shared test fixture
  visibility; authorization callbacks remain nonescaping and are not retained.
- Full optimized suite passed 1,593 KeyCore declarations across 129 suites in
  408.783 seconds, plus six canonical-JSON tests. The separately gated large
  migration remained skipped. The final callback-formatting adjustment does
  not change behavior. Final optimized recompilation and three declarations /
  five smoke cases passed in 5.037 seconds, covering empty/populated restore,
  exact prepared-pin resume and selected-resume trust refusal.
- Unsigned universal Preview build and product-bundle isolation passed. Bundled
  CLI help/version `0.2.0 (19)` and arm64/x86_64 slices for app, CLI and helper
  passed. Nothing was signed, installed or published.
- Strict default Swift-format lint passed for all nine changed/new Swift files.
  Two mixed callback/trailing-closure style findings were corrected before the
  final lint. Project plist syntax, 263 relative documentation targets and
  `git diff --check` passed.

Raw logs remain under ignored
`tmp/piv-recovery/2026-10-07-restore-completion-*`.

Next: product host/CLI restore and explicit resume dispatch, exclusive barriers
against init/enrollment/configuration work, lock/disconnect invalidation, bounded
request/status behavior, then separate-process and physical qualification. No
real token, vault or installed product was operated on by this increment.

### First 812 gated host and connection boundary, 2026-10-07

The normal service protocol now represents restore and explicit resume using
public source/destination paths, token ID and the existing credential-derived
recipient ID. Initial restore also supplies a display name. No PIN, PUK,
management key, recovered key, native observation or saved consent crosses XPC.
Selectors are structurally bounded but are not native binding or approval;
the future native composition must independently select and validate them.
The utility role cannot send these requests. Their client reply bound is 120
seconds and their host scope expires after 90 seconds, starting before queue
admission. Successful recovery uses the existing helper shutdown handshake,
with restart-timeout guidance that never suggests starting another restore.

The [host](../Sources/KeyCore/KeyServiceHost.swift) admits at most one recovery
request, including one waiting behind another exclusive host operation. Other
recovery clients receive an immediate refusal. Its existing exclusive queue
serializes source/destination/configuration work against init, directory-scoped
enrollment and runtime selection. A configured handler is never replaced by
recovery. Cold selected resume is admitted without composing an ordinary runtime;
the restore service must still prove its exact saved selection and trust.

Lock cannot wait behind the recovery barrier before invalidating authentication.
The host first invalidates its generation and cancels its admitted scope. If
recovery is active, lock returns without waiting for native UI, which may not
drain immediately. This fast path is possible only because active recovery has
no configured handler. The composed service must use the exact scope's
generation store, cancellation and deadline; its later checks reject approval
or publication after cancellation. Finished scopes are cancelled too. Token
exclusion remains a separate existing native lease, including callbacks that
outlive cancellation or timeout.

Each authenticated helper XPC connection now has a permanent cancellation
lifetime. Interruption/invalidation cancels only that connection's registered
scopes. A later registration on a closed connection is cancelled immediately;
disconnect never automatically starts another operation or cancels another
client's independent scope.

After entering recovery, process-local pending state refuses another initial
restore, init, enrollment and vault-directory changes; explicit resume remains
available. If configuration exists on exit, even after failure, cancellation or
a lost reply, the host requires restart instead of composing a runtime from an
uncertain selection. Apparent success without actual configuration is refused.
This guard is not durable ownership. The live composition must add saved-attempt
admission across helper restarts before enabling the feature. No record scan,
new durable marker, credential replacement or filesystem cleanup was added.

Running recovery outside the host queue was considered, but would let setup or
runtime-selection work overlap it. Running lock only inside that queue would
delay cancellation behind native UI. The existing queue plus out-of-band scope
invalidation preserves the serialization contract without another work queue.
The admission hook follows the host's existing init/enrollment composition style.

[14 test declarations / 32 cases](../Tests/KeyCoreTests/KeyRecoveryRoutingTests.swift)
cover protocol round trips, selector bounds, roles/deadlines, disabled live
products, configured-runtime refusal, uncertain selection, pending setup guards,
late success, concurrent requests, connection cancellation and expired tickets.
Six cases run the actual restore service through host cancellation at encrypted
preparation, manifest publication and configuration selection. The retained
ownership is checked; no second agreement or new identity is requested. These
tests inject the service composition and do not establish native selector
dispatch, an actual XPC interruption or physical prompt behavior.

Stable and ordinary Preview live hosts still refuse recovery before inspecting
configuration, composing a runtime or opening a card. CLI syntax, native service
composition, restart-persistent pending guards and signed product qualification
remain. No installed product, real vault, real token or release was operated on.

Verification:

- Existing routing/protocol regressions passed 51 declarations across three
  suites before the new tests. Focused Debug passed 65 declarations across
  four suites in 8.075 seconds. The final reply-boundary recheck and disconnect
  case then passed the same 65 declarations in 9.070 seconds, including all
  14 new declarations / 32 cases.
  A test-only compiler error used an unavailable `AppError.description`; the
  test now uses the existing localized error interface.
- Full optimized suite passed 1,607 KeyCore declarations across 130 suites in
  406.112 seconds, plus six canonical-JSON tests. The separately gated large
  migration remained skipped. This run preceded the final reply-boundary
  recheck. Final optimized recompilation and affected revalidation passed all
  65 declarations across four suites in 3.099 seconds, including the new
  disconnect-during-selection-inspection case. No source changed afterward.
- Unsigned universal Preview build, including the final reply-boundary guard,
  and product-bundle isolation passed. Bundled CLI help/version `0.2.0 (19)` and
  arm64/x86_64 slices for app, CLI and helper passed; the public CLI is unchanged.
- Strict default Swift-format lint passed for the new request/scope and test
  files. Older four-space host/protocol/helper files retain their established
  formatting; default-style lint findings remain, including long strings and
  existing pattern/line-layout conventions. A HEAD host comparison confirmed
  that these conventions predate this increment; no bulk rewrite was made.
  Project plist syntax, 273 relative documentation targets and
  `git diff --check` passed.

Raw logs remain under ignored
`tmp/piv-recovery/2026-10-07-recovery-host-*`.

Next: native selector/directory/store composition and restart-persistent
saved-attempt admission, then CLI review/restore/resume syntax and the gated
profile-3 ordinary runtime. Signed two-Mac and actual XPC/hardware acceptance
remain subsequent checks, not results of this software increment.

### Second 812 restart ownership admission, 2026-10-07

Recovery dispatch now requires a paired local ownership inspector in the
[capability](../Sources/KeyCore/KeyRecoveryRequest.swift). The
[host](../Sources/KeyCore/KeyServiceHost.swift) checks it before initial restore,
init, directory-scoped enrollment and vault-directory changes. A cold configured
host also checks before composing its ordinary runtime: config selection may
have committed while final ownership cleanup remains unfinished. Explicit
resume still enters the exact source-bound service; lock remains available.
Unconfigured status reports locked without opening a runtime.

The [inspector](../Sources/KeyCore/V3ImmutableTransactionRecoveryAnchor.swift)
performs at most two noninteractive Keychain existence queries, one per existing
restore ownership namespace. Query construction shares the existing access-group,
service, synchronization and Data Protection policy. It requests no item data,
attributes or references and consumes status only. Existing anchor reads and
compare-and-swap writes still require their exact source vault account.

Either pin blocks competing admission, including a preparation-only pin after
reservation cleanup. Only two not-found results permit admission. Unavailable
storage, missing entitlements, forbidden interaction and other failures refuse
admission, with guidance to preserve state and resume or inspect it. No result
is cached. A malformed or unrelated account in either dedicated namespace
cannot be silently ignored because no account or content parsing grants an
exception. Presence grants no recovery authority.

A third durable marker was considered but would add another write/cleanup
ordering and orphan state. Checking the two pins already owned by the journal
avoids a new persisted format. Scanning local preparation files would confuse
inert leftovers with authority and would need unbounded discovery. Neither
alternative is used; the existing exact journal remains responsible for resume.
The guard operates inside the existing single-helper host serialization, not
as a cross-process transaction lock or proof against local Keychain deletion.

[Seven test declarations / 30 cases](../Tests/KeyCoreTests/KeyRecoveryOwnershipTests.swift)
cover bounded query shape, Stable/Preview/qualification namespace isolation,
both Data Protection policies, either surviving pin, uncertain status, invalid
storage configuration, cold configured/unconfigured hosts and fresh checks on
each admission. Five cases interrupt the actual restore service, replace the
host, and exercise exact resume at reservation, encrypted preparation, config
selection and each cleanup boundary. Reservation-only state does not recreate
a credential; preparation-only state still blocks ordinary composition; cleared
pins cannot retroactively claim recovery success. Successful exact resume clears
ownership and a later host can compose normal authority.

These tests use real filesystem/crypto/service logic with software native
providers and memory pin storage. The production query adapter is compiled but
the matching call is substituted in tests. Signed Keychain access, actual
helper-process restart, native dispatch and prompt behavior remain unqualified.
Stable and ordinary Preview remain disabled and have no new ownership queries
on their unchanged live paths. No token, installed product or real vault was
operated on.

Verification:

- Final focused Debug passed 78 declarations across six suites in 22.978
  seconds, including recovery, init, enrollment and XPC policy regressions.
- Full optimized suite passed 1,614 KeyCore declarations across 131 suites in
  409.291 seconds, plus six canonical-JSON tests. The separately gated large
  migration remained skipped. No implementation or test source changed after
  this run began.
- Unsigned universal Preview build and bundle isolation passed. Bundled CLI
  help and `version` (`0.2.0 (19)`) passed, as did arm64/x86_64 app, CLI and helper
  slices. No public recovery command was enabled.
- Strict default Swift-format lint passed for the request/capability and both
  recovery host test files. The existing four-space host/anchor sources retain
  their established formatting without a bulk rewrite. Default-style lint still
  reports indentation and layout conventions there; HEAD comparisons confirm
  that the style mismatch predates this increment. The compiler also reports
  the unchanged routing test's capture of the non-Sendable public request enum.
  Project plist syntax, 283 relative documentation targets and
  `git diff --check` passed.

Raw evidence remains under ignored
`tmp/piv-recovery/2026-10-07-recovery-ownership-*`.

Next: native selector/directory/store composition, including explicit local
config/cache creation for a fresh Mac and strict no-bootstrap resume. Then CLI
review/restore/resume and gated ordinary profile-3 integration. This increment
does not enable a live recovery route or claim the signed vertical slice is done.

### Third 812 native restore composition, 2026-10-07

The [workflow](../Sources/KeyCore/V3RecoveryRestoreWorkflow.swift) now resolves an
explicit request into retained source/destination-parent handles, the exact
native token candidate and its complete recipient ID. It refuses unsupported
platforms, existing destinations, wrong selectors, unrecognized anchors and
unsupported public policy before requesting agreement. No public request can
provide a native observation, PIN, admin command or source authority.

The live factory composes the existing reader/agreement, journal ownership
stores, Secure Enclave Mac identity manager, checkpoint store, contained cache
and source mutation owner. It returns the existing paired capability, not an
ordinary configured runtime. The actual restore/resume service receives the
exact host authentication generation, cancellation and deadline. Construction
performs no native or filesystem operation; shipping hosts do not install it yet.

`KeyConfigStore` now owns bounded local metadata preparation below an existing
home. Initial restore can prepare missing Library/Application Support/product
and cache directories after valid public selection, using retained parents,
nofollow child inspection, identity comparison, 0700 creation and parent fsync.
Scope/config/source checks surround creation. Physical containment reuses the
existing restore environment's walk, rather than another path-prefix policy.
Destination/metadata collisions are refused through aliased parents and case
variants, conservatively even on a case-sensitive filesystem. Resume opens
existing config/cache/destination/parent roots only and cannot repair missing
directories. Failed preparation leaves scaffolding intact for inspection.

Reusing recursive `FileManager` cache/bootstrap creation would follow replaced
or symlinked paths and could recreate missing resume state. Requiring an already
existing product directory would prevent a fresh Mac from restoring. Bounded
initial-only scaffolding handles both constraints without changing ordinary
init/enrollment bootstrap behavior or creating another metadata format. It
creates no vault, credential, ownership or config selection before source-key
authentication; those transitions still belong to the restore service.

[12 declarations / 43 cases](../Tests/KeyCoreTests/V3RecoveryRestoreWorkflowTests.swift)
cover fresh/existing metadata layouts, exact candidate selection among multiple
cards, wrong public selectors/policy/anchors, unavailable and existing locations,
symlinked local components, source/config overlap, aliased/case-variant metadata
collisions, unusable existing configs, scoped cancellation during preparation,
and missing resume roots. Three cases replace the host after actual service
interruption at encrypted preparation, config selection and reservation cleanup,
then finish exact resume without another Mac identity. Initial restores reopen
ordinary access from the selected config, saved Mac identity and actual composed
cache after token availability is removed. They do not receive a source key or
reuse a recovered-key session.

All service/filesystem/crypto integration is real; card/provider/Mac keys and
Keychain storage are software substitutes. The native factory and both universal
product slices compile, but no real Keychain, Secure Enclave, YubiKey, installed
product or vault was operated on. Actual XPC interruption, process restart,
native selector acceptance and physical prompt behavior remain unqualified.

Verification:

- Final focused Debug passed 70 declarations across six suites in 49.103
  seconds, including ownership/host, init, enrollment and cache regressions.
  The first test compile lacked `try` on a throwing assertion and used a `Void`
  callback argument; both test-only issues were corrected before the final run.
- Full optimized suite passed 1,626 KeyCore declarations across 132 suites in
  435.906 seconds, plus six canonical-JSON tests. The separately gated large
  migration remained skipped. No implementation or test source changed after
  the full run began.
- Unsigned universal Preview build and product isolation passed. Bundled CLI
  help and `version` (`0.2.0 (19)`) passed, with arm64/x86_64 app, CLI and helper
  slices. No recovery command is enabled.
- Strict default Swift-format lint passed for the new workflow and tests.
  Existing four-space config-store formatting is retained; default-style lint
  reports the established indentation/layout mismatch, confirmed against HEAD.
  The compiler also reports the unchanged routing test's non-Sendable request
  capture. Project plist syntax, 292 relative documentation targets and
  `git diff --check` passed.

Raw evidence remains under ignored
`tmp/piv-recovery/2026-10-07-recovery-workflow-*`.

Next: CLI review/restore/resume and live feature gating alongside the ordinary
profile-3 runtime. Product failure guidance and signed two-Mac/XPC/native
qualification remain required before enabling the vertical slice.

### Fourth 812 component: explicit restore/resume CLI, 2026-10-07

The [parser](../Sources/KeyCore/CLIParser.swift) now exposes `recovery restore`
and `recovery resume`; [help](../Sources/KeyCore/CLIHelp.swift) states that both
remain disabled in Stable and ordinary Preview. Both require exactly one source,
destination, token and complete recovery recipient selector. Restore also
requires a valid readable Mac name. Resume refuses a replacement name. The
recipient selector is the existing public-key identifier, not the certificate
fingerprint used by the earlier feasibility probe. No PIN, PUK, management key,
vault-key, force or confirmation-bypass option is accepted.

The [application](../Sources/KeyCore/KeyCLIApplication.swift) captures the working
directory once, resolves the two explicit paths, validates the absolute bounded
request and sends it through the existing guarded service protocol. It does not
read configuration to fill omitted selectors, inspect provider files, collect
credentials, retry, clear local state or turn resume into a fresh restore. The
existing helper owns source authentication, exact local ownership, publication,
selection and the success shutdown handshake.

A separate CLI-only recovery enum was considered, but it would duplicate the
same restore/resume variants without an independent display or confirmation
contract. Reusing the existing request keeps the protocol unchanged; path
resolution stays at the CLI boundary and is revalidated before dispatch.
Read-only review cannot use the same host flow: entering restore sets uncertain
pending state and success requires selected configuration. Its separate public
observation/response path remains the next step, not an approval to restore.

Failure guidance preserves source, destination, records and configuration. A
failed or lost reply does not establish whether selection committed. Complete
saved attempts use exact explicit resume; absent, incomplete or changed state
requires inspection, not deletion or another initial restore. Help distinguishes
restart/status from proof of completion and warns that the new vault does not
inherit recovery registration. No claim of provider freshness is added.

The [new tests](../Tests/KeyCoreTests/RecoveryCLITests.swift) contain 10 declarations
and 52 parameter cases, plus parser refusal variants exercised within cases.
They cover duplicate/missing/bounded/malformed selectors, Mac names, credential
and bypass-option refusal, local help without configuration or transport,
relative-path resolution and no credential input, response/transport failure
without retry, and both shipping products' pre-state refusal. Actual software
CLI/host/workflow/service composition restores arbitrary fixture contents,
interrupts at complete preparation, resumes through a fresh host and refuses a
completed attempt before another source agreement. Source files stay unchanged,
one Mac identity is created, and no resume-to-restore fallback occurs.

Verification for this CLI-only increment:

- Focused Debug: 168 declarations across 8 suites passed in 55.982 seconds,
  covering CLI/parser/help, host ownership and connection cancellation, actual
  workflow composition and XPC role/lifecycle policy. The final change after
  that run only replaces array-style generated usage with explicit single-value
  usage text; repeated parser/help/CLI Debug checks passed 73 declarations in
  3 suites in 8.849 seconds for that correction.
- Focused Release on the final source: the same 168 declarations across 8 suites
  passed in 31.318 seconds. The full cryptographic suite was not rerun for this
  increment; no cryptographic implementation, stored format, host admission,
  protocol encoding or native adapter changed.
- Unsigned universal Preview build passed on the final source. Product-bundle
  isolation, actual compiled recovery group/restore/resume help and `version`
  (`0.2.0 (19)`) passed. App, CLI and helper contain arm64/x86_64 slices. No
  signing, installation, token operation or publication occurred.
- Strict default formatting passed for the new CLI test file. Existing
  four-space source/help/test conventions are retained. Project plist syntax,
  303 relative documentation targets and `git diff --check` passed.
  Release compilation reports the unchanged routing test's non-Sendable
  request capture; no fix outside this increment is included.

Raw logs and compiled help stay under ignored
`tmp/piv-recovery/2026-10-07-recovery-cli-*`.

Next: bounded read-only public credential/source review, then remaining recovery
commands and gated shipping profile-3 composition. Live operations stay disabled;
signed two-Mac/XPC/native acceptance remains unqualified. This is source
self-review and software composition, not a new independent security review or
completion of `REC-812`.

### Fifth 812 component: public token/source review, 2026-10-07

The [closed public-read workflow](../Sources/KeyCore/KeyRecoveryReview.swift)
implements bounded token inventory and explicit source review. The CLI now has
`key recovery tokens [--json]` and
`key recovery review --source <directory> --token <token-id> [--json]`.
Both shipping products still refuse before filesystem/card access. Listing
returns at most 64 exact token IDs/reader names and never chooses a candidate or
opens its slot. Source review reads only the explicitly selected token's public
credential, reported policy and recognized anchor. It reuses the bounded public
history selector, repeats token/source observations and checks scope/path
identity around every filesystem read.

The workflow has no config, journal, ownership, Mac-key or agreement dependency.
Its source adapter refuses entry reads. Human output labels entry counts as
unverified and quotes control characters in the source path. JSON source results
carry `public-observation-only` assurance. Neither output establishes possession,
protected administration, PIN/touch enforcement, complete/restorable contents or
provider freshness. There is no readiness, private credential or confirmation
reference. Review is not saved approval; later restore reads everything again.

Adding review to the existing restore enum was considered, but would make the
restore-only pending guard, configuration-selection requirement and shutdown
handshake depend on another semantic variant. The new read-only wire request and
optional result keep that boundary explicit. Existing request encodings are
unchanged; older responses still decode without the optional result. An older
helper refuses the new request kind during decode rather than falling back.

The host reuses one bounded connection/lock scope and at-most-one admission for
both operations. Restore retains its exclusive barrier. Review uses a concurrent
read, so ordinary lock still reaches an already configured runtime while public
callbacks drain. Setup/config barriers wait for review. Review never sets or
clears process-local or durable pending ownership and does not require or compose
configuration. Public source observations can therefore be reviewed while an
attempt needs attention, without authorizing setup or ordinary runtime access.
Both live hooks remain uninstalled; future restore installation still requires
the paired durable ownership inspector. Utility XPC stays status/lock-only.

The [15 new declarations](../Tests/KeyCoreTests/KeyRecoveryReviewTests.swift)
exercise 44 parameter cases plus CLI refusal variants inside cases. Actual
CLI/host/reader/history/filesystem composition uses software token fixtures.
Missing entry files still yield only public observations, not protection claims.
Tests cover exact selectors/policy/anchor/history refusal, token/path/scope changes,
human path quoting and JSON assurance, configured/pending inspection, no new or
cleared ownership, lock/disconnect late-result refusal, mutual exclusion and
setup-barrier ordering. Live Stable/Preview construction remains a no-I/O smoke
check; no physical token or native lifecycle qualification is added.

Verification on the final source:

- Focused Debug: 183 declarations across 9 suites passed in 58.063 seconds.
  This covers the new review path plus CLI/help, restore workflow, ownership,
  connection/lock admission and XPC role/lifecycle regressions.
- Full Release: 1,651 KeyCore declarations across 134 suites passed in
  462.524 seconds, plus 6 canonical-JSON declarations. The separately gated
  large-migration case remains skipped as before.
- Final unsigned universal Preview build passed. Product-bundle isolation,
  actual compiled token/review help, version `0.2.0 (19)` and arm64/x86_64
  slices for app, CLI and helper passed. Nothing was signed, installed or
  published, and no physical token operation was requested.
- Strict default formatting passed for the new workflow/request/result and
  review tests. Existing four-space sources retain their conventions. Project
  plist syntax, 311 relative documentation targets and `git diff --check`
  passed. The unchanged routing-test non-Sendable request capture warning is
  still reported; build metadata extraction also reports its usual missing
  AppIntents dependency warning.

The first test pass caught a test-only configuration-read assertion that also
fired during the intentionally subsequent init; it now counts reads and proves
none occur during review. An optional-Bool assertion failed compilation and was
corrected before final verification. No production behavior was weakened to
make these tests pass. Raw logs and compiled help remain under ignored
`tmp/piv-recovery/2026-10-07-recovery-review-*`.

Next: configured recovery registration/status composition and remaining commands,
with the ordinary profile-3 runtime and reciprocal barriers required before live
opt-in. Signed two-Mac/XPC/native acceptance and a fresh independent review of
product composition remain outstanding. `REC-812` is not complete.

### 2026-10-07: authenticated registration status before configured composition

The shipping factory still composes only profile 2. Installing registration there
without profile-3 unlock, catch-up, session ownership and reciprocal barriers
would bypass the existing runtime boundary. This increment instead implements
the authenticated status service that configured registration will use.

Putting status on the registration service was considered. That would make
inspection depend on a private identity, token reader and agreement provider,
although none should be used. The separate
[status service](../Sources/KeyCore/V3RecoveryRegistrationStatus.swift) owns the
inspection checks with only source/local-store dependencies and the existing
mutation owner. It reuses the registration repository and journal rather than
adding a second preparation parser or snapshot authenticator.

Four distinct results are implemented: authenticated empty active roster,
authenticated registered roster, exact locally owned pending registration, and
attention required. Pending distinguishes pre-activation from an exact committed
candidate with unfinished cleanup. A current-key-authenticated floor and complete
current snapshot are required for positive results. Pre-commit pending inspection
also authenticates the intent MAC and dual-authorized candidate boundary; it does
not open the candidate key or claim readiness to finish. After commitment, the
candidate must be the authenticated floor. No saved token approval is inferred.

Exact source and checkpoint observations, ownership and the selected bundle are
rechecked before return. Inaccessible/corrupt local records, incomplete source,
invalid keys, competing ownership and changes during observation require attention
rather than claiming absence of recovery protection. Unowned provider bundles are
not adopted. Status cannot write, clean up, perform catch-up, contact a token,
unwrap a Mac key or select configuration. Registered reports authenticated stored
coverage, not current possession, token policy enforcement or provider freshness.

The [existing registration-service fixture](../Tests/KeyCoreTests/V3RecoveryRegistrationServiceTests.swift)
now exercises status over real codecs, crypto, journals and contained filesystem
objects. Tests cover the external-write boundary without token reads, publication
versus checkpoint commitment versus completed cleanup, incorrect current keys,
missing/corrupt local records and entry bytes, competing/unavailable ownership,
unowned bundles, a parsed but unauthenticated intent, and changing checkpoint,
ownership, source and pending bundle. Counters check no token session, hardware
agreement, private unwrap or bundle write occurs during inspection.

No CLI/protocol/host route or live feature gate changes in this increment. The
status caller still needs configured-runtime authentication and connection/lock
scope; inspection results are not admission or mutation authority. `REC-808` and
`REC-812` remain in progress. Next is the gated profile-3 configured runtime and
registration command composition. Physical/signed acceptance and integrated AI
review remain outstanding.

Verification for this increment:

- Initial focused Debug: 78 declarations across the registration service/domain
  suites passed in 11.796 seconds. Final optimized regressions: 147 declarations
  across six suites passed in 15.035 seconds, including the final nine new status
  declarations and their 22 cases. The final run also covers public review,
  host routing, content publication and adoption. The full suite was not rerun;
  no shipping host/protocol/runtime dispatch changed.
- Unsigned universal Preview build and product-bundle isolation passed. App,
  CLI and helper contain arm64/x86_64 slices; the compiled version remains
  `0.2.0 (19)`. No install, signing, publication or physical token operation.
- Strict formatting, project plist syntax, 314 relative documentation targets
  and `git diff --check` passed. The unchanged routing-test non-Sendable request
  capture warning and build metadata extraction's missing AppIntents dependency
  warning remain. Raw logs/build products are ignored
  under `tmp/piv-recovery/2026-10-07-registration-status-*` and
  `tmp/piv-recovery/registration-status-build`.

### 2026-10-07: routine profile-3 Mac unlock and cancellable reauthentication

The existing shipping unlock runtime binds its trusted-envelope type and HPKE
context to profile 2. Extending it with a recovery-profile variant would make
every permanent-profile state-loader/catch-up caller branch on that variant.
The internal [profile-3 runtime](../Sources/KeyCore/V3RecoveryVaultUnlockRuntime.swift)
instead returns the existing profile-3 floor type and reuses the current
identity-loader interface, checkpoint cache and in-memory session. It does not
project a recovery manifest into profile 2 or install a second key store.

Only exact bytes selected by a bounded device-local checkpoint can be opened.
Permanent and unknown profiles, unavailable or substituted bytes, missing or
unfamiliar identity and revoked-device metadata refuse before private unwrap.
Cold access performs one Mac wrapper opening and checks key identity, manifest
MAC and encrypted epoch-capsule/private-public correspondence. Warm access uses
only the matching resident key and repeats current authentication. It does not
load identity or open another wrapper. A mismatched warm key refuses without
automatic authentication retry. These operation counts are software evidence,
not measured native prompt counts.

Explicit unlock clears any earlier key before identity access. A new atomic
session operation requires the request's still-current admission ticket before
clearing the key and issuing its replacement ticket. Separate invalidate and
ticket-capture calls were rejected because a lock in between could be treated
as fresh approval. Runtime lock remains independent of request serialization,
so it can invalidate an outstanding authentication while native UI is active.
Checkpoint, pending ownership and generation checks surround private work,
optional cache warming, session installation and return. Failures clear the
session and do not retry. Exact cache bytes improve availability but grant no
authority; a cache write failure is best effort, while a lock during that call
still invalidates the result.

All three ordinary/registration/adoption ownership stores are mandatory.
Present or unreadable ownership blocks this ordinary unlock path. No marker is
parsed as consent, cleared or reconciled. Registration/adoption pending-state
authentication remains a separate product-composition task; their services must
not use a normal-runtime admission result to bypass their own exact guards.

The new [unlock tests](../Tests/KeyCoreTests/V3RecoveryVaultUnlockRuntimeTests.swift)
use real profile-3 publication, HPKE, capsule and contained filesystem fixtures.
Seventeen declarations exercise 39 cases, including cache/provider transport,
cold/warm access, explicit reauthentication, malformed/local/source/profile and
identity refusal, every pending namespace, revoked-device refusal, invalid MAC
and capsule correspondence, cancellation/private failures, and late changes
during identity access, unwrap, cache warming and after installation. Two new
[session declarations](../Tests/KeyCoreTests/V3DeviceWrappedVaultKeySessionTests.swift)
exercise five cases of atomic key clearing and stale/foreign admission refusal.
A concrete enrolled-Mac test unlocks, catches up through an actual rotation,
saves through the ordinary mutation service, locks and reopens the saved floor;
the complete current snapshot is then authenticated by the existing repository.

This runtime authenticates only the selected manifest/capsule, not entry
availability or provider-current contents. It never advances a checkpoint,
discovers a provider head, catches up, administers a token or selects configuration.
Read/UX composition, catch-up serialization, pending-ceremony routing, registration
commands and the gated shipping factory remain to be composed. No live hook,
protocol, CLI route or feature gate changes. Signed/native qualification and
integrated independent review remain outstanding; `REC-812` is not complete.

Verification for the unlock increment:

- Expanded Debug: 108 declarations across six suites passed in 69.384 seconds.
  This includes permanent-profile unlock, shared sessions, registration, concrete
  catch-up and the new unlock cases. After removing a redundant profile decode
  already enforced by the existing codec, final-source full Release passed:
  1,679 KeyCore declarations across 135 suites in 438.805 seconds, plus six
  canonical-JSON declarations. The separately gated large-migration test remains
  skipped as before.
- Final unsigned universal Preview build, product-bundle isolation, compiled
  version `0.2.0 (19)` and arm64/x86_64 slices for app, CLI and helper passed.
  No install, signing, publication, push, user-vault access or physical token
  operation was performed.
- Strict formatting for the new runtime/tests and session tests, project plist
  syntax, 318 relative documentation targets and `git diff --check` passed.
  The unchanged routing-test non-Sendable request capture and missing AppIntents
  metadata dependency warnings remain.

Initial verification caught two test compilation errors: a throwing property
initializer and an equality assertion on a non-Equatable floor type. A capsule
fixture also failed the cipher's key/context guard before reaching runtime
validation. The tests now initialize the fixture in its throwing initializer,
compare floor fields and use a well-shaped capsule with mismatched public/private
correspondence. No production validation was relaxed. Raw verification logs and
build products remain ignored under `tmp/piv-recovery/2026-10-07-recovery-unlock-*`
and `tmp/piv-recovery/registration-status-build`.

### 2026-10-07: exact-checkpoint profile-3 read adapter

The internal [read adapter](../Sources/KeyCore/V3RecoveryReadOnlyVaultRuntime.swift)
reuses the existing planner, executor and bounded encrypted-closure validator.
It owns profile-3 authentication and UX error translation, not graph selection
or publication. A generic profile-switching read orchestrator was considered,
but would broaden the existing permanent-profile trust boundary while product
composition is still incomplete. A separate adapter preserves explicit profile
ownership without duplicating cryptography, plans or object verification.

Unlock now provides a typed process-local read context retaining the exact
authentication ticket (the installation receipt on cold access). Key lookup and
final plaintext/metadata release revalidate generation, checkpoint and all three
pending namespaces. Reinstalling the same key cannot revive an older read.
The context is neither persistent authority nor a key container. Existing
floor-returning unlock methods remain available for their existing callers.

Status checks encrypted closure availability, hash and shape/context, not every
entry's AEAD or provider freshness. Reads independently authenticate the selected
entry. Only an explicit stale list permits unavailable encrypted files; invalid
files or budget violations refuse. History and mutation methods refuse instead
of inventing empty history or writable support. Invalid selectors are rejected
before identity access. Catch-up/stale-provider policy, ordinary write/session
composition and pending ceremony routing remain separate product work.

The [read tests](../Tests/KeyCoreTests/V3RecoveryReadOnlyVaultRuntimeTests.swift)
use actual profile-3 publication, entry AEAD and contained filesystem storage,
with software Mac keys and scripted late changes. They cover exact secret/TOTP
reads, empty/missing names, malformed selectors, unavailable/invalid ciphertext,
budgets, all pending namespaces, lock and same-key replacement, retained-context
refusal, read-only/history refusal, and actual same-epoch save plus cold reopen.
No live hook, CLI, feature gate or native operation changes; `REC-812` remains
in progress.

Verification for this increment:

- Focused Debug passed 62 declarations across six read/unlock/session suites
  in 8.442 seconds. The new suite has 12 declarations exercising 50 cases.
- Expanded Release passed 170 declarations across 11 suites in 76.051 seconds,
  adding ordinary mutation and concrete same-epoch, key-transition, merged and
  coordinated catch-up coverage. The full suite was not repeated for this bounded
  internal adapter; the preceding unlock increment records its full Release run.
- Final unsigned universal Preview build, bundle isolation, compiled version
  `0.2.0 (19)` and arm64/x86_64 app, CLI and helper slices passed. Formatting,
  project plist syntax, 321 relative documentation targets and diff whitespace
  checks passed. Existing routing-test Sendable and AppIntents metadata warnings
  remain unchanged.
- No install, signing, publishing, push, real-vault access or token operation.
  Logs remain ignored under `tmp/piv-recovery/2026-10-07-recovery-read-*`; build
  products reuse `tmp/piv-recovery/registration-status-build`.
