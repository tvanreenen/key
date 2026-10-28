# Signed Preview recovery qualification

Current checkpoint: 2026-10-26. This is a scoped evidence ledger and remaining
native-test boundary, not a claim that the entire feature is qualified.
[Plan](piv-recovery-plan.md) owns completion gates; [contract](piv-recovery-contract.md)
owns security guarantees. Use disposable data only. No test result authorizes
another authentication, hardware write, reset, installation or real-vault use.

## Artifact identity and tested environment

Tested: Mini and MacBook Air, arm64 macOS 27.0.1 (26A434), one YubiKey 5C NFC,
firmware 5.8.0, externally generated P-256 slot 9d credential with reported
PIN/touch ALWAYS. This is not a frozen macOS 26+/token support matrix or an
independent-backup-key test.

The artifacts are normal isolated Preview products, version 0.2.0, with local
experimental recovery enabled before signing. Shipping gates remain disabled.
Developer ID/team `9Q355KSV85`, normal Preview IDs, hardened runtime, strict/
all-slice signatures, helper smartcard entitlement, notarization, ticket,
Gatekeeper and channel isolation passed the recorded install checks. These
are installed test candidates, not published semver releases.

| Build | Exact source commit | Notarized transfer ZIP SHA-256 |
|---|---|---|
| 22 | `ea1f8f546fd36a078db16790a2bc2976a98abaa6` | `3f6527a01883f1ea7dc0904e07b0d635592df8c4b18ee47f0622cef9332d8ca4` |
| 23 | `9f9872f4a04be5b878b2b90dbc8e16e94bd77276` | `e600810430a4a1ce9855496154893a261d43456e37670c40c56cf40a9fe97edb` |
| 24 | `8fa8b0ddd24affafc66e8d7643414a5f0f0ec9f3` | `14170fc3df0cf241235d5896970818f8e72da8c478ffc1de80e01b1d177b9587` |
| 25 | `85ee569b0487dfcf78fa4e186295c8c63f394fcc` | `787d0259ddf133e4dd9788dcba5206df997797d7ccb1935502c2c3c73932b1aa` |

Build25 notarization: Accepted, submission
`f28c0b5e-9dac-46ab-926b-b13316e5cf99`; detailed receipt inspected, no issues.
Installed executable SHA-256:

| Component | Hash |
|---|---|
| Host | `fc32db086dfc390dcb549455b419962fcff91d18f60fa4d4a1c86eaac855ad0d` |
| CLI | `110fcc0d7c571c548dd19cf82488eaa1204c160429d83ced7b2777316c2e3b02` |
| Helper | `d8c80fa139e798869693bb3382c178f12c81a27feecc750b45f74509ded766dc` |

Older candidate receipts/component hashes remain in their ignored preparation/
install records and Git history. A result on an older build is scoped evidence,
not an automatic retest pass on build25. Recheck affected cases if later code changes.

## Completed signed cases

All rows below are real installed-product cases. Software-only evidence is
identified separately in the plan and linked test suites. App token administration
was never used; credential setup/import were separately owner-run external steps.
PINs stayed in macOS UI. Stable app/config, explicit prior disposable state and
source-preservation checks stayed within named roots; actual-vault contents were
not traversed. Prompt counts are owner observations, not native hardware-attempt
measurements. Evidence IDs resolve in the local index below.

| Case | Artifact/machine | Observed result and scope | Evidence |
|---|---|---|---|
| Protected setup/public binding | Mini, before22 | Owner configured management protection and generated compatible credential/certificate, then externally imported the reviewed anchor. Public key/anchor/policy readback matched. Metadata does not attest key provenance or secret custody. | E01 |
| Registration finish | 22 Mini | One PIN/touch activated the exact prepared candidate; no pending operation; entries-before-manifest/checkpoint result and expected file delta verified. Public postcheck unchanged, PIN/PUK 3/3. | E02 |
| Initial source-only restore | 22 Mini/Air | Published encrypted files plus key restored two entries with fresh authority and no inherited registration. Air exit0/18.837s. No Mini credentials/config/checkpoints/intent transferred. | E03/E04 |
| Ordinary token-free access | 22 Mini/Air | Exact secret including newline and independent seed/read-interval TOTP checks passed before/after normal lock/fresh helper; token absent, sources/Stable preserved. Guided Air pass does not explain its earlier health timeout. | E03/E04 |
| PIN cancellation | 22 Mini | Owner cancelled without entering PIN/touch; exit1/1.216s, no agreement/destination/config/new saved attempt; normal shutdown and unchanged public state/counters. | E05 |
| Visible touch-window Cancel | 23 Mini | Owner approved PIN, saw the foreground touch window and clicked Cancel without touching. No publication. Native exchange returned 10.238 seconds after logical cancellation, before card postchecks; this does not qualify immediate native abortion. Old22 invisible-window attempt is not a cancellation pass. | E06 |
| Incomplete reservation release | 24 Mini | Explicit exact `recovery abandon` released only reservation ownership without authentication/key operation. Empty target, reservation file and Mac credentials retained; no replacement restore. | E07 |
| Complete-preparation Publish cancellation | 24 Mini | Owner approved Prepare and cancelled Publish. Exit1/22.801s; complete reservation/preparation retained, target empty/config absent. Wrong-stage earlier attempts do not qualify this case. | E08 |
| Exact resume and token-free reopen | 24 Mini | Explicit resume through fresh helper used the same operation/vault/key/device/entry IDs and byte-identical preparation/published objects. Owner observed one PIN/touch then five Mac approvals. Later exact secret/TOTP and token-free fresh-helper reads passed. | E08/E09 |
| Missing touch | 24 Mini | One approved PIN, no touch/Cancel; window closed without Mac prompt. Exit1/23.231s, no destination/config/saved-file changes. This is provider failure-path evidence, not the 90-second application deadline. | E10 |
| Physical token removal | 24 Mini | Unplug at touch window after PIN, no touch/Cancel; window closed/no Mac prompt. Exit1/8.315s, no publication/state change; normal shutdown and public-only postcheck after reconnect matched, PIN/PUK 3/3. | E11 |
| Unanswered-PIN deadline | 25 Mini | Explicit timeout around 90 seconds, actual appCancel callback and no publication/state change. System PIN UI remained; owner manually cancelled blank dialog before normal shutdown/postcheck. Deadline/refusal pass; automatic UI cleanup fails. | E12 |
| Late PIN after confirmed timeout | 25 Mini | After 90.029 seconds timeout and passive refusal checks, owner submitted correct PIN once without touch/Mac approval. Dialog closed with no follow-on Key prompt; destination/config absent and protected files unchanged. No native late-positive callback was exercised. | E13 |
| Owned CLI disconnect | 25 Mini | Only verified owned CLI got SIGTERM at 47.051 seconds, before deadline. Helper invalidated context/received appCancel; no touch stage/publication. Owner cancelled blank PIN; normal shutdown/public postcheck passed. No helper/provider signal or retry. | E14 |
| Edits/rotation/later edits recovered | 25 Mini | Token unplugged for secret/TOTP re-save, one key rotation and postrotation add/edit. Recovery of ten manifests/three current entries passed in 29.501 seconds with one PIN/touch. Exact values and token-free fresh-helper reads passed. Recipient/generation retained; key/epoch/wrappers changed. | E15 |
| Independent edited/rotated-history recovery | 25 Air | Same published ten-manifest/twelve-entry-version copy, no source authority/local records; one PIN/touch restored three entries in 42.430 seconds. Both secrets matched twice; health ready/no conflicts/pending work; token absent before/after; new authority/no inherited registration, final helper stopped. | E16 |
| Independent TOTP comparison for Air25 | Mini, offline verifier | Both ordinary/fresh-helper fingerprints matched retained seed and actual read intervals; public vectors passed. Each interval had one matching candidate counter. No seed/code transferred or printed. TOTP edit reused original seed: continuity qualified, seed replacement not tested. | E16 |

## Known limits

- **Remaining system PIN dialog.** Programmatic invalidation can deliver actual
  appCancel while macOS PIV UI stays visible. Retained-context, main-thread,
  released-handle, fresh-context and direct-operation controls did not establish
  automatic dismissal. Ordinary Mac policy/ACL controls dismissed correctly;
  that narrows the investigation, not a proven OS/provider defect. Owner accepted
  manual Cancel for Preview on 2026-10-26. Cancel blank leftover UI before further
  card use; late PIN entry may still affect device authentication/retry counters.
  A stopped Key request cannot revive. No private API, provider termination or
  direct-operation production workaround is selected.
- **Callback scope.** Late-PIN/disconnect native results cover the observed paths.
  They did not exercise a native late-positive callback race or measure all
  framework attempts. [Software regressions](../Tests/KeyCoreTests/PIVRecoveryAgreementTests.swift)
  cover late/duplicate approval and retained exclusion until actual callback/
  provider return. Callback receipt and helper exit do not prove UI closure.
- **Mac approval cost.** Exact resume observed five Mac approvals after PIN/touch.
  These protect separate destination wrapper/trust/activation boundaries; no
  fixed count or prompt consolidation is promised.
- **Coverage.** One physical credential, two arm64 Macs/one OS build; no independent
  backup-token, full device/recipient lifecycle, complete provider/platform matrix
  or released-old-binary adoption qualification. Restored vaults remain
  unregistered until separately protected.
- **Preservation claims.** Checks cover explicit sources, destinations, prior test
  roots, apps/configs and relevant records. They are not a whole-Keychain/system
  integrity claim; restore intentionally creates new destination credentials.
  Mini PIN/PUK 3/3 observations apply to the recorded postchecks, not an unperformed
  Air25 counter query.

## Consequential failures and disposition

| Finding | Disposition / what remains unproven |
|---|---|
| Early public reads failed | Preview smartcard entitlement and bounded response framing were corrected and regression-tested. Later signed public/product runs qualify their scoped fixes; diagnostic-only binaries are not product qualification. |
| Build22 touch cue could be obscured | AppKit ordering diagnostics plus owner observation led to visible native presentation in23. The earlier no-touch failure did not qualify clicking Cancel. |
| Cancellation hit an earlier Mac stage | Clear Prepare/Publish reasons and incomplete-attempt handling shipped in24. Only the owner-confirmed complete-preparation cancellation/exact resume is counted. |
| Authentication worker released before real callback | Source fix `87e311d` retains worker/lease until actual framework reply;25 records callback lifetime and refusal. It did not solve external PIN-window dismissal. |
| Earlier Air22 health timeout | Owner was not watching; cause and old prompt completion were unconfirmed. Later guided explicit-unlock/read/fresh-helper success is separate evidence, not retrospective cancellation proof. |
| Air25 public JSON/USB guards | Successful inventory output was parsed without repeating inventory. Sandboxed registry read failed before restore; identical elevated read-only check succeeded after coordinating diagnosis. Exactly one restore was dispatched. |

## Local evidence index

Paths below are relative to ignored `tmp/piv-recovery/` on Mini unless marked Air.
They identify maintainer evidence, not files a recovering user must retain or a
claim that raw reports are in Git. Preserve old results and supersede them with
new scoped results rather than rewriting failures as passes.

| ID | Retained root / principal record |
|---|---|
| E01 | `fresh-credential-2026-10-23/`, `anchor-import-verified-2026-10-23/`, `registration-mini-2026-10-23/`; owner setup/public credential/import verification. |
| E02 | `product-touch-build22-finish-2026-10-25/postcheck-result.json`. |
| E03 | `product-touch-build22-restore-2026-10-25/verification-result.json`; source and ordinary/fresh-helper exact-value evidence. |
| E04 | `build22-air-transfer-2026-10-25/`; retrieved restore/ordinary summaries, owner observations and `air-totp-verification.json`. |
| E05 | `cancellation-resume-mini-2026-10-25/`; successful PIN-cancel record separated from accidental positive restore and failed touch-window case. |
| E06 | `cancellation-resume-mini-2026-10-25/touch-cancel-build23/`; later wrong-stage case in sibling `saved-preparation/`. |
| E07 | `approval-incomplete-build24-release-2026-10-25/`. |
| E08 | `approval-incomplete-build24-resume-retest-2026-10-25/`; exact saved/prepared/published bytes and resume result; earlier `approval-incomplete-build24-resume-2026-10-25/` preserved separately. |
| E09 | `build24-resumed-ordinary-2026-10-26/verification-result.json`. |
| E10 | `build24-touch-timeout-2026-10-26/`. |
| E11 | `build24-disconnect-2026-10-26/`. |
| E12 | `build25-deadline-2026-10-26/`; isolated controls under `pin-cancellation-*-2026-10-26/`. |
| E13 | `build25-late-pin-2026-10-26/verification-result.json`. |
| E14 | `build25-cli-disconnect-2026-10-26/verification-result.json`. |
| E15 | `build25-edits-rotation-2026-10-26/verification-result.json`. |
| E16 | `build25-air-edited-history-2026-10-26/`: packet identity, owner confirmations, Air restore/ordinary summaries, `air-totp-verification.json` and combined `verification-result.json`. |

Air25 full native records remain under
`~/.codex/visualizations/2026/10/02/01a0fe8a-6281-7272-999d-899cf6cec486/piv-air-test/`:
`air-product-build25-preparation.json`, `air-product-build25-public-preflight.json`,
`air-product-build25-restore-attempt.json` and
`air-product-build25-ordinary-access.json`. The receipt is
`~/Downloads/Key-Preview-build25-Air-20261026T183412Z-receipt/`, including rollback,
previous selection/cache, encrypted source and the new disposable restored vault.
No extra Air operation is needed merely to update this ledger.

Artifact preparation/install roots include
`product-touch-build22-2026-10-25/`, `product-touch-build23-2026-10-25/`,
`approval-incomplete-build24-2026-10-25/` and
`native-authentication-build25-2026-10-26/`, plus their named install siblings.
Checksummed verbatim pre-consolidation documents are in
`docs-consolidation-2026-10-26/`; complete tracked chronology also remains at
commit `dd2c64f70d0b72cfd75da310326a883b10b34d0f` and earlier history.

## Remaining native work and run discipline

The [plan's acceptance matrix](piv-recovery-plan.md#remaining-acceptance-matrix)
is authoritative: independent backup token, broader device/recipient product
flows, branch/conflict recovery, interrupted setup/rotation/helper cases,
restored-vault mutation/re-registration/second recovery, credential lifecycle,
compatibility/provider and release/adoption gates remain. Reuse the passes above;
no repeat of the basic two-Mac restore without changed code or an unresolved issue.

For each newly authorized case:

1. Pin source/build/OS/hardware identity and expected outcome; choose explicit
   disposable roots and preserve relevant config/cache, journals and prior vaults.
   Obtain exact-scope approval for installations, state relocation or hardware
   administration. Never reset shared state to force progress.
2. Use matching signed CLI/helper, normal trust checks and normal lifecycle.
   Refuse uncertain pending ownership and pre-existing/aliased restore targets.
   Public review/pending selectors are observations, not readiness/consent.
3. Obtain fresh owner connection/watch readiness before a private operation.
   PIN stays in macOS; physical touch is distinct from clicking OK. Mac approvals
   are separate. Never ask for credential values or deliberately consume retries.
4. Dispatch one guarded request. On timeout/failure/lost reply preserve exact
   source/destination/intent/credentials/config; do not retry, generate replacement
   setup or infer success from files. Inspect and explicitly resume the exact
   prepared attempt, or use narrowly qualified abandonment when applicable.
5. Confirm UI closure and actual callback/provider lifetime before further card
   use/postchecks; manually cancel blank stale PIN UI when necessary. Never
   force-stop a helper/provider to manufacture a clean result.
6. Verify complete authoritative reply, source/new-authority/preservation checks,
   expected current contents and token-free ordinary access as appropriate.
   Normal lock already stops the helper; verify before fresh-helper reads.
   Keep plaintext in memory, use exact-byte secret comparison and independent
   TOTP seed/read-interval comparison. End normally locked/stopped.

Retain raw commands, hashes, observations, ambiguity and failures locally. Commit
one concise completed-case update with its limits/evidence reference, not a new
narrative for each preparation, signing, installation or diagnostic transition.
