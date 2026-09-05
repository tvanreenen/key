# Config simplification compatibility design

Status: `CFG-801` implemented locally for review on 2026-09-05; `CFG-802` remains proposed. No installed config or vault-format change has been made. This work can ship independently of catastrophe recovery.

## Pre-change behavior and ownership

Baseline: `main` at `957d561`, with Stable `0.2.0` compatibility.

- `Sources/KeyCore/VaultLocationResolver.swift` owns parsing, writing, and verified selection. `KeyConfiguration` and the helper's runtime selection both carry a Keychain mode and optional vault ID.
- Missing `vault_id` selects v2; missing `keychain_mode` defaults to `local`. A canonical vault ID selects v3. Directory contents do not choose the model. Unknown config keys are ignored; writers always emit `keychain_mode`.
- `selectV3Vault` checks root identity and expected v2 mode, selects v3 last, and retains the source mode.
- `Sources/KeyCore/KeyServiceHandler.swift` uses mode for v2 lookup/migration. Its runtime consistency check compares directory, vault ID, and mode even for v3. Changes must preserve session invalidation and mutation ownership.
- `Sources/KeyCore/KeyCLIApplication.swift` reads config through `KeyConfigStore` and sends mutations through the helper. `ConfigKey` exposes `vault-dir` and `keychain-mode`; vault identity is not generally settable.
- Package requirements are macOS 14+ and Swift tools 6.2. No new dependency or service is needed for this cleanup.

For v3, the folder determines where ciphertext lives. An iCloud Drive folder does not require iCloud Keychain mode. Mode remains a real v2 key-storage choice and can identify the key needed for retained v2 data. That old snapshot does not recover later v3 changes; see the [released continuity promise](security-continuity-recovery.md).

## Alternatives

| Approach | Compatibility and maintenance | Decision |
|---|---|---|
| Delete mode everywhere | Breaks v2 lookup/migration, loses source-mode information, and alters helper consistency semantics. | Reject. |
| Change help text only | Preserves bytes but leaves callers interpreting an unrelated mode and optional ID. | Insufficient as completed cleanup. |
| Explicit runtime selection; retain old file representation initially | Separates active authority from compatibility metadata without another durable file. | Recommended first slice. |
| Immediately move mode into a permanent sidecar | Shortens config but adds ordering, identity binding, missing-record, and old-writer problems to normal v3 operation. | Do not build by default; prefer retaining source-mode information within the bounded legacy migration path. |

## CFG-801: explicit selection, preserved file compatibility

Introduce one internal active-authority value: v2 carries `KeychainMode`; v3 carries its canonical vault ID. Keep the root in the enclosing runtime selection. Parse the file once into this model. Do not add an independently editable format selector. Start internally rather than breaking public initializers merely to rename fields.

Retain legacy mode for the codec and migration boundary, not v3 cryptography. Keep current emitted file bytes and source-mode values on ordinary writes, including migrated `icloud` selections. Preserve the helper's conservative mode-change check as a separate compatibility-field comparison. An explicit authority model is not permission to weaken existing guards.

Implemented CLI contract:

- `config list` reads one snapshot. V2 retains `vault-dir` and `keychain-mode`. V3 lists `vault-dir` only; help explains that enrollment supplies authority.
- Explicit `config get keychain-mode` retains raw `local` or `icloud` stdout during deprecation for script compatibility. For v3, stderr explains that this is retained legacy metadata, not the active key-storage model.
- Setting mode remains available for v2 and refused for v3. Explain v3's folder-backed storage and device enrollment in the refusal.
- `vault_id` stays managed by verified workflows, not a general setter.

The v3 list change is observable and needs release notes and tests. Do not replace `get` output with prose or an invented mode such as `none`. No new CLI command or JSON schema is required. Choose the release version after reviewing implementation scope, not as part of this design.

## V2 retirement direction

Planning direction agreed for the next development track on 2026-09-05: warn first, require explicit migration before further v2 writes later, and target v3-only normal operation by `1.0`. These are release gates, not an implemented cutoff or a promise tied to a date. `CFG-801` does not warn about v2 retirement or restrict v2 writes.

| Stage | Proposed behavior | Gate before release |
|---|---|---|
| Next minor | Announce v2 retirement when v2 is selected and direct users to `key migrate --check`. Add explicit v3 setup for new vaults once qualified. Existing v2 vaults remain usable. | Review warning text, CLI output compatibility, and the new-vault setup path. Do not simply change the current missing-ID fallback into implicit migration. |
| Later qualified minor | Refuse ordinary v2 content writes with a migration explanation. Keep reads, necessary unlock/authentication, diagnostics, and explicit migration available. | Qualify local/iCloud migration, interruptions, supported hardware checks, skipped-release upgrades, and multi-Mac enrollment. Publish the cutoff in advance. |
| `1.0` target | Remove v2 from normal runtime and ordinary config choices; retain a narrowly scoped v2-to-v3 importer and a documented path for old installations. | Prove users can reach the importer without a working v2 normal runtime, identify their source mode, and recover from failed migration without source loss. |

Warnings must not contaminate secret stdout or machine-readable output, introduce surprise prompts in scripts, or change success exit codes during the warning stage. Define the diagnostic channel and warning frequency before implementation. Enforce any later write restriction in the helper, not just in CLI presentation. Classify administrative operations individually so the restriction does not block access or migration preparation.

Migration remains explicit. Installing an update must not convert a vault, delete its old files or Keychain items, or silently block all access to its secrets. Users can skip the warning release, so later versions must explain the migration route themselves. Unsupported hardware or failed preflight must leave the source accessible through a documented compatible reader or migration path, not an automatic repair.

Coordinate the other Macs before migration: they can otherwise keep writing to the old snapshot, and those edits do not enter v3. Require a clear continuity/recovery decision before enforcing the write cutoff. PIV availability alone is not that decision; hardware purchase is not a migration prerequisite, and catastrophe recovery remains unimplemented until its own gates pass.

## CFG-802: shorter v3 file with a bounded legacy path

The target v3 file contains `vault_dir` and `vault_id`, without an apparent Keychain mode choice. Do not implement omission by defaulting retained state to `local`. Before removing the field, specify and test:

1. Prefer retaining source mode within an explicit legacy-source/import record or retained rollback config, rather than introducing permanent metadata infrastructure into the v3 runtime. Bind retained records to the source root and selected vault ID; never infer historical mode from the current folder. Exact storage and retention remain review decisions.
2. Adoption of already-migrated Stable configs, including `icloud`, without inventing source history for enrollment-only configurations.
3. Durable ordering: retain usable old state before simplifying config. Interruption leaves an old representation or a recoverable new one. Read-only helper checks do not rewrite files.
4. Old reader/writer behavior: Stable defaults omitted mode to `local`, ignores unknown fields, and rewrites known fields. Test downgrade followed by an old writer. A renamed field alone does not preserve compatibility.
5. Deliberate access to retained v2 data with the correct source mode. While v2 runtime remains supported, preserve the controlled rollback boundary and helper restart. After retirement, provide the documented importer/legacy-reader route instead of reinstating v2 as the ordinary runtime. Neither path may silently discard v3 identity or imply an old snapshot is current.
6. Missing, malformed, stale, or conflicting provenance cannot trigger key creation, automatic v2 fallback, or trust adoption.

Retaining the field until the transition is qualified is intentional, not completion of persisted simplification. The retirement direction narrows the long-term compatibility boundary but does not make deleting the field safe today. V2 key decoding and local/iCloud source-key lookup remain necessary inside the importer after ordinary v2 operation is removed. The legacy `config get keychain-mode` compatibility behavior also needs an announced retirement point rather than an indefinite promise.

## Verification

| Boundary | Required cases |
|---|---|
| Files | V2 local/iCloud, omitted mode, and v3 with both retained modes load without changing selection or rewriting bytes. |
| Parser | Missing directory, invalid/duplicate mode or UUID, quoted paths, existing unknown-key behavior. |
| CLI | Snapshot-consistent list, exact get stdout, v3 stderr explanation, v2 setters, v3 refusal, relevant help/completion updates. |
| Helper | Changed directory, identity, mode, missing/malformed config still invalidate/refuse; lock/restart remains required. |
| Migration | Both source modes, root replacement, mid-migration mode change, interrupted selection, verified reopen, unchanged v2 source. |
| Enrollment | Interrupted selection retries the verified ceremony without arbitrary identity mutation or replacement. |
| Later persistence | Old/new readers and writers, crash boundaries, source-mode retention, deliberate retained-v2 rollback. |
| Retirement | Warning output/exit compatibility, helper-enforced write refusal, permitted access/migration operations, skipped releases, unsupported hardware, and other Macs still on the old snapshot. |

Start with `CryptoAndStorageTests`, `VaultRootChangeCoordinationTests`, `KeyProductIdentityTests`, and `V3LocalMigrationTests`. Extend CLI/enrollment tests for changed behavior, then run the full Swift suite and release checks before qualification. Use temporary homes and disposable vaults throughout.

Preparation check on 2026-09-05: all 42 tests in those four suites passed. The initial sandbox run could not access Swift's compiler cache; the host-level rerun passed. This validates the existing baseline, not the proposed behavior. No full suite or release qualification was rerun for these documentation edits.

## Unreleased change notes

V3 `config list` now omits `keychain-mode`. Scripts explicitly requesting `config get keychain-mode` still receive the same raw value on stdout, with an explanation on stderr. V2 config commands retain their existing behavior. The persisted field remains for compatibility; users should not manually remove it as part of this update.

`ConfiguredVaultAuthority` distinguishes v2 key storage from v3 identity internally. Runtime composition and verified migration use it, while the helper still refuses unexpected changes to retained mode metadata. Config listing reads one snapshot. Public configuration initialization and the on-disk representation remain compatible. No parser or completion token was removed.

`ConfigCompatibilityTests` covers six read/CLI combinations (local, iCloud, or omitted mode, with v2 or v3 selection), both migration source modes, mode-change invalidation in both models, and four malformed configs. Existing service tests also check the v3 mode-change explanation.

Implementation verification on 2026-09-05: `swift test --no-parallel` passed all 761 tests in 71 suites. Release target/publication/Homebrew dispatch tests and Preview install safety tests passed, as did whitespace checks. SwiftPM built the CLI and helper; no installed-product or signed-release qualification was performed.

Normal parallel runs were not clean: existing concurrency tests exceeded one-second semaphore deadlines, with a downstream error mismatch in one test. An isolated archive of pre-change commit `6cfbd27` reproduced the same failures (757 tests, 70 suites, five issues), so they predate this implementation. The serial run retains those tests' internal concurrent operations. Test scheduling reliability remains follow-up work; these results are not a claim that the normal parallel release gate passes.

## Next implementation boundary

Review `CFG-801` before installation or release. Next, design the warning and explicit new-v3-vault setup slice, and define the bounded legacy-source record needed for `CFG-802`. Keep write enforcement, normal-runtime removal, and recovery-format changes in separate reviewed slices. No default-format switch, v2 restriction, installed-app change, live-config rewrite, provider change, or YubiKey operation is implemented by this plan update.
