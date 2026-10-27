# PIV catastrophe recovery implementation plan

Current checkpoint: 2026-10-26. This file owns status and remaining acceptance.
The [contract](piv-recovery-contract.md) owns protocol/security requirements; the
[qualification record](piv-recovery-signed-test.md) owns scoped results and artifact
identities. The v3 roadmap links here rather than maintaining another status table.

Recovery is experimental and disabled in shipping Stable/ordinary Preview
configuration. Explicitly enabled, signed Preview build25 passes the one-token,
two-Mac workflow below. This is a review checkpoint, not real-vault or release
qualification. This plan authorizes no hardware administration, authentication,
real-vault conversion, installation, publication or release.

## Completion contract

After explicit registration, either independently provisioned primary or backup
token, its PIN/touch approval and the available encrypted vault files must recover
all supported current entries on a replacement Mac. Recovery needs no source Mac
identity, checkpoint/cache, receipt, separate certificate file, setup intent,
management key or cloud escrow. Fresh destination Mac authentication is separate.
The source stays unchanged; the destination has fresh authority and no recovery
registration until separately registered.

Normal writes and supported key/device changes preserve active recovery coverage
with the tokens stored away, or refuse publication. The target is one deliberate
source hardware approval per uninterrupted recovery attempt across key epochs.
Explicit resume can require another approval. Do not weaken PIN/touch policy or
source authentication, archive historical decryption keys or silently retry.

Recovery authenticates anchored public history and all current restored contents,
without independently decrypting/revalidating every closed epoch. Ordinary
publication and catch-up retain full authentication and reseal checks. Removal
excludes recipients from fresh keys on the legitimate continuing lineage, not old
copies or hidden alternative lineages. Key refuses visible conflicts and required
missing state without falling back to older data. Provider freshness/delivery and
backup retention are external responsibilities. The
[contract](piv-recovery-contract.md#security-promise-and-limits) defines these limits;
proving global latest state is not an acceptance gate.

Full completion requires reviewed implementation, qualification with independent
primary/backup tokens on the supported platform matrix, explicit opt-in adoption,
accurate user documentation and a verified Stable release. Human expert review is
recommended; the owner selected fresh AI review as the required review gate.
Risk disclosure or a future migration cannot excuse known authentication defects
or replace missing backups.

## Current status

The main gated product path is implemented: explicit profile adoption, public
token/credential/source review, registration prepare/export/finish, ordinary
profile-3 reads/writes, token-free rotation, restore, exact resume and local release
of an incomplete reservation. Signed tests cover registration on Mini, independent
Air recovery, later edits/rotation, token-free exact secret/TOTP reads and
fresh-helper reopening. Mini cancellation, interruption/resume, missing touch,
unplug, deadline, late-PIN refusal and client disconnect have scoped results.

The tested hardware is one YubiKey 5C NFC on arm64 macOS 27.0.1 (26A434).
Independent backup hardware and the entire lifecycle/platform matrix are not
qualified. A remaining macOS PIN dialog can require manual Cancel after a stopped
request; the owner accepted that temporary Preview limitation. Automatic dismissal
is not a pass. See [qualification limits](piv-recovery-signed-test.md#known-limits).

Packages remain open until their full acceptance criteria pass. An implemented
domain component or one physical scenario does not qualify every caller. No
package is newly declared qualified/released by this consolidation.
`REC-801`–`REC-803` are the [earlier feasibility track](piv-feasibility-results.md).

| Package | Implemented / observed | Remaining acceptance |
|---|---|---|
| `REC-804` Contract/compatibility | Dual-authorization design, owner decisions and AI review dispositions recorded. | Exact codecs/contexts and format freeze, capacity, platform and rollout decisions. |
| `REC-805` Cryptographic domain | Capsule, profile, recipient/wrapper/anchor codecs and exact fixtures implemented and reviewed in scope. | Final integrated byte/usage-bound review and compatibility/format qualification. |
| `REC-806` History/snapshot | Bounded anchored graph selection and complete current-snapshot verification; signed source-only recovery on both Macs. | Complete graph/hostile-input acceptance against the final protocol and supported matrix. |
| `REC-807` Native token/setup | Bound read-only reader, scoped agreement and external administration boundary; one physical key tested. | Setup instructions, certificate/key/reset lifecycle, platform matrix and remaining enforcement cases. |
| `REC-808` Registration/adoption | Durable prepare/export/finish, authenticated status and exact reconciliation; initial signed registration/adoption passed. | Remaining interrupted setup/adoption cases and independent backup registration. |
| `REC-809` Content/branches | Mutation, merge/resolution, catch-up and coverage guards implemented; edited contents recovered on both Macs. | Signed independent-Mac branch/conflict-resolution acceptance. |
| `REC-810` Authority lifecycle | Rotation, enrollment/adoption, revocation/removal, catch-up and restart domain services implemented; signed token-free rotation recovered on Air. | Broader device/recipient product routes, informed confirmations and physical lifecycle qualification. |
| `REC-811` Restore/resume | Verified snapshot to fresh vault; encrypted preparation and exact authenticated resume; signed separate-process reads passed. | Complete durable-phase/failure matrix and restored-vault ordinary mutation acceptance. |
| `REC-812` CLI/helper | Gated workflow, progress/touch UI, configured runtime and scoped native results recorded. | Remaining lifecycle integration, helper/concurrency/history acceptance and UX review. |
| `REC-813` Backup/physical lifecycle | Primary/backup software fixtures; one physical credential tested in recorded cases. | Two independently generated physical keys and the lifecycle matrix below. |
| `REC-814` Security/release qualification | Earlier integrated AI review/fixes, historical full regression/CI pass and exact signed/notarized build25 installs. | Fresh review/CI on latest changes, full regression, compatibility/provider and exact-candidate release checks. |
| `REC-815` Adoption/publication | Explicit gated adoption implemented and exercised on disposable data. | Supported upgrade/migration/rollback qualification, real-vault opt-in gate and authorized publication. |

Dependencies: 805 depends on 804; 806 on 805; 807 on 804; 808 on 805/806/807;
809 on 805/808; 810 on 805/808/809; 811 on 806; 812 on 807–811; 813 on 812;
814 on 812/813; 815 on 814. These identify contracts, not a requirement to finish
every physical test before dependent coding or review can start.

## Next milestones

1. **Current implementation review.** Consolidate native fixes/evidence into the
   appropriate stacked PRs, update descriptions, publish and run CI. Obtain fresh
   integrated AI review. Reuse established evidence; repeat a basic two-Mac restore
   only for changed code or an unresolved question.
2. **Lifecycle completion.** Finish product routes for recovery-capable device
   enrollment/revocation/replacement and recipient management, including informed
   exact-plan confirmations. Close the matrix below with a second independently
   provisioned physical key. Its acquisition/provisioning is an owner prerequisite;
   scope hardware actions separately.
3. **Release/adoption qualification.** Freeze supported format/platform promises,
   finish regression/compatibility gates and user instructions, then qualify the
   exact release artifact and explicit adoption. Real-vault enablement follows
   813/814 and the adoption gate.

## Remaining acceptance matrix

These are required outcomes, not a separate test/commit obligation for each row.
Combine faithful cases and retain software/native evidence at its actual scope.

| Area | Required outcome |
|---|---|
| Protocol/format (`804–806`, `814`) | Exact canonical bytes, domain separation, capsule/key custody and fresh-key/nonce policy reviewed. Graph/entry and cumulative publication budgets refuse before effects; capacity never silently refreshes an anchor/floor or raises limits. |
| Graph/content (`806`, `809`) | Independent-Mac saves, automatic merge and explicit conflict choices preserve coverage. Missing parents/current ciphertext, ambiguous bases, authority/closed-epoch conflicts and invalid/over-budget input refuse without stale fallback. |
| Device authority (`810`, `813`) | Compared enrollment, joining trust, revocation, replacement, remaining-Mac catch-up and interrupted transitions honor exact reviewed decisions and continuing recovery access. Revoked Macs refuse appropriately. |
| Backup/recipients (`808`, `810`, `813`) | Each of two independent private keys recovers alone from its own floor after edits/rotation. Add/remove/last removal preserve exact policy; removed recipients lack new wrappers; no primary-token or original-Mac dependency. |
| Restored vault (`811–813`) | Ordinary read/edit/reopen without the token; separately reviewed re-registration and another recovery. No silent inheritance of registration. |
| Interrupted setup/rotation (`808`, `810–813`) | Every durable phase preserves an exact resumable candidate or refuses safely. Close remaining native registration/adoption/rotation/helper-interruption cases; no generated replacement or ambiguous cleanup. |
| Credential lifecycle (`807`, `813`) | Same-key certificate renewal/expiry, replacement-key refusal and reset invalidation follow the certificate-container policy. Simulate wrong-PIN/blocked-token errors; never deliberately exhaust physical counters. |
| Host/session (`812–814`) | Lock, expiry, same-key reauthentication, disconnect, helper death/restart, multiple clients and queued setup cannot revive stopped requests, bypass ownership or install late authority. |
| Compatibility/delivery (`804`, `814–815`) | Released old binaries refuse signed unsupported-profile adoption; coordinated upgrades, migration/interruption and rollback qualify. Supported APFS/iCloud partial delivery refuses required missing state; no provider-global freshness promise. |
| Release (`814–815`) | Full tests/static/build/release checks, isolation, entitlements, notarization, quarantine and helper registration pass for the exact artifact. User docs cover administration, backup custody, recovery/resume, limits and re-registration. Publication needs explicit approval. |

## Architecture ownership

| Boundary | Owner / invariant |
|---|---|
| Format/crypto | `KeyCore` [profile codec](../Sources/KeyCore/V3RecoveryManifest.swift), [epoch boundary](../Sources/KeyCore/V3RecoveryEpochBoundary.swift), HPKE/entry codecs and schema; preserve profile-2 bytes and explicit dispatch. |
| Ordinary data | [Runtime](../Sources/KeyCore/V3RecoveryVaultRuntime.swift), [mutation service](../Sources/KeyCore/V3RecoveryVaultMutationService.swift), independent validators and existing immutable transaction kernel. Coverage is a publication invariant. |
| Authority changes | Separate rotation/enrollment/revocation/removal policies reuse epoch construction/durability and the [lifecycle context](../Sources/KeyCore/V3RecoveryLifecycleContext.swift), while retaining their own approvals and intent checks. [Catch-up](../Sources/KeyCore/V3RecoveryCatchUpCoordinator.swift) validates existing transitions without new publication consent. |
| Restore | [Snapshot verifier](../Sources/KeyCore/V3RecoverySnapshot.swift) alone supplies verified plaintext; [restore service](../Sources/KeyCore/V3RecoveryRestoreService.swift) owns scope and fresh permanent genesis/trust/selection ordering. |
| Product admission | [Protocol](../Sources/KeyCore/KeyServiceProtocol.swift), [host](../Sources/KeyCore/KeyServiceHost.swift), mutation owner and destination/config barriers. Helper owns authority; CLI supplies reviewed inputs and renders bounded output. |
| Hardware | [Reader](../Sources/KeyCore/PIVRecoveryTokenReader.swift) and [agreement adapter](../Sources/KeyCore/PIVRecoveryAgreement.swift) share native exclusion, additional to vault serialization. Administration stays external. |

Diagnostic prototypes remain evidence, not shipping transaction owners. Reuse
existing schemas, installers, signing and distribution gates; no test-only bypass
or alternate authority store.

## Review stack and evidence

The stack preserves implementation commits and targets each PR at its predecessor.
Review copy describes final code, not the investigation chronology.

| PR | Branch / scope | Published head at 2026-10-26 check |
|---|---|---|
| [68](https://github.com/tvanreenen/key/pull/68) | `codex/user-friendly-wording`: existing CLI/help | `2adba7d` |
| [69](https://github.com/tvanreenen/key/pull/69) | `codex/recovery-foundations`: format, graph, snapshot/genesis | `22a431c` |
| [70](https://github.com/tvanreenen/key/pull/70) | `codex/recovery-registration`: reader, registration, adoption | `acd6b01` |
| [71](https://github.com/tvanreenen/key/pull/71) | `codex/recovery-content`: writes, catch-up, conflicts | `c57c2d3` |
| [72](https://github.com/tvanreenen/key/pull/72) | `codex/recovery-lifecycle`: authority lifecycle | `ac06bd8` |
| [74](https://github.com/tvanreenen/key/pull/74) | `codex/recovery-restore-engine`: fresh vault/continuation | `8dec6d8` |
| [75](https://github.com/tvanreenen/key/pull/75) | `codex/recovery-service-boundary`: scoped requests/CLI | `483cbae` |
| [76](https://github.com/tvanreenen/key/pull/76) | `codex/recovery-restore`: configured workflow integration | `0ffaee7` |
| [77](https://github.com/tvanreenen/key/pull/77) | `codex/recovery-native-integration`: native fixes, interruption handling and qualification | `93303c3` |
| [78](https://github.com/tvanreenen/key/pull/78) | `codex/recovery-lifecycle-context`: shared state checks with separate approval policies | `70d2333` |
| [79](https://github.com/tvanreenen/key/pull/79) | `codex/recovery-test-support`: shared software fixtures independent of test suites | `edd3346` |

Published heads have successful Stable, Preview and helper-security checks.
Capability cleanup follows on `codex/recovery-read-capability` above 79. Exact
checkpoint readers expose read policy without mutation or graph requirements;
composed runtimes retain those separate policies. The three selected
architecture cleanups are implemented in these follow-ups; final review and
release acceptance remain separate. Existing stack history is preserved. Use
`gh stack` for propagation and publication. Readiness is tracked on each PR;
neither review nor green CI enables the shipping recovery gates.

| Evidence | Scope and retained decision |
|---|---|
| [Design AI review](piv-recovery-ai-review.md), 2026-10-04 | Protected random epoch signing key plus Mac signature; reduced historical replay and continuing-lineage exclusion limits accepted. Human audit recommended, not mandatory. |
| Lifecycle AI review/regressions | Fixed session-generation and exact committed-ownership checks before rotation activation. [Service tests](../Tests/KeyCoreTests/V3RecoveryKeyRotationServiceTests.swift) cover same-key reauthentication as a different session. |
| Integrated AI review/fixes, 2026-10-20 | `acd6b01`/`c57c2d3`: cumulative publication usage from earliest still-active recipient floor, including merges. `483cbae`: resident lock remains out-of-band behind queued setup. Regressions failed before fixes/passed afterward; reviewer rechecked fixes. |
| Historical full Release run | At `0ffaee776050da2a5452505b9b4c76be352e5022`, `swift test -c release --no-parallel` passed 1,754 KeyCore tests/141 suites plus six canonical-JSON tests. Opt-in large mixed migration was skipped. Raw: `tmp/piv-recovery/2026-10-20-review-fixes-full-release.log`. This is not a full run on the latest local head. |
| Native follow-up review, 2026-10-26 | At `93303c3`, three fresh AI reviewers found no actionable issue in the inspected integrated paths. A fresh full Release run reported 1,784 KeyCore tests/143 suites and six canonical-JSON tests passed; opt-in large migration was skipped. Stable, Preview and helper-security CI passed. [Qualification](piv-recovery-signed-test.md) retains exact native artifact limits. This evidence predates the lifecycle cleanup and does not qualify it or a release. Raw review/regression evidence: `tmp/piv-recovery/integrated-review-2026-10-26/`. |

## Recording future work

Keep one current status per package and one scoped result per qualification case.
Record source/artifact identity, command or suite, outcome, material limits and
remaining gate. Update after a coherent code change or completed qualification
batch. Preparation, installation and diagnostic chronology belong in ignored
`tmp/piv-recovery/`, not parallel narratives in all three documents.

Preserve consequential failures and their disposition, including accepted limits
and what a later pass did not prove. Raw logs must contain no PIN/PUK/management
credentials, private keys or real-vault values. Local `tmp` references identify
maintainer evidence, not public artifacts or required recovery inputs. Source/test
links and immutable commits provide the portable review trail. Commit history
remains intact. Do not infer a completion percentage or mark a package released
solely because coding or a test batch ended.
