# PIV catastrophe recovery implementation plan

Current implementation tracker: 2026-10-04. The retained evidence summaries
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
| `REC-804` | Format, authority, lifecycle, and compatibility contract | Baseline | In progress; AI review disposition recorded; experimental direction authorized; graph/platform/adoption decisions remain |
| `REC-805` | Versioned recovery profile, contexts, codecs, fixtures, and validators | 804 | In progress; profile-3 domain codecs, contexts, proof construction/checks, and fixtures implemented; final acceptance and integrated review remain |
| `REC-806` | Token-anchored history selection and complete snapshot verification | 805 | In progress; bounded software selector and complete current-snapshot verifier implemented; native anchor provenance, integrated review, and restore-only input integration remain |
| `REC-807` | Product token binding, external administration, and credential lifecycle | 804 | In progress; reader, scoped agreement and configured key-policy checks implemented; all administration stays in owner-run vendor tools; external workflow, capabilities and physical qualification remain |
| `REC-808` | Authenticated registration and status, including interruption reconciliation | 805, 806, 807 | In progress; candidate/intent, completion crypto checks and durable preparation journal implemented; native binding, service phase reconciliation, activation and status remain |
| `REC-809` | Recovery coverage through ordinary edits, branches, and resolution | 805, 808 | Planned |
| `REC-810` | Recovery coverage through key/device/recipient changes | 805, 808, 809 | Planned |
| `REC-811` | Integrated new-vault restore and authenticated resume | 806 | Planned |
| `REC-812` | CLI/helper integration and meaningful signed Preview vertical slice | 807, 808, 809, 810, 811 | Planned |
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

The current increment is `REC-808`, with remaining `REC-807` integration,
final `REC-805`/`REC-806` acceptance and `REC-804` integrated decisions tracked
explicitly. The
[contract](piv-recovery-contract.md) describes the
experimental dual-authorization direction and its reduced historical replay
promise. The capsule, recipient roster, recovery contexts/wrappers, containing
profile, canonical proof projection, anchor codec, graph selector, snapshot
verifier, registration candidate/intent, completion checks and durable preparation
journal are implemented as internal components. Finish domain acceptance
and protected setup/product integration next. Native public-read binding and
scoped agreement are implemented but have not been physically qualified. Only
the isolated capsule has a fresh independent AI review; the new components have
software checks, not integrated review or product/hardware qualification.

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
