# Config simplification compatibility design

Status: proposed slices for `CFG-801` and `CFG-802`, 2026-09-05. No runtime, installed config, or vault-format change is made by this document. This work can ship independently of catastrophe recovery.

## Inspected behavior and ownership

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
| Immediately move mode into a sidecar | Shortens config but adds ordering, identity binding, missing-record, and old-writer problems. | Defer until a complete persistence contract exists. |

## CFG-801: explicit selection, preserved file compatibility

Introduce one internal active-authority value: v2 carries `KeychainMode`; v3 carries its canonical vault ID. Keep the root in the enclosing runtime selection. Parse the file once into this model. Do not add an independently editable format selector. Start internally rather than breaking public initializers merely to rename fields.

Retain legacy mode for the codec and migration boundary, not v3 cryptography. Keep current emitted file bytes and source-mode values on ordinary writes, including migrated `icloud` selections. Preserve the helper's conservative mode-change check as a separate compatibility-field comparison. An explicit authority model is not permission to weaken existing guards.

Proposed CLI contract:

- `config list` reads one snapshot. V2 retains `vault-dir` and `keychain-mode`. V3 lists `vault-dir` only; help explains that enrollment supplies authority.
- Explicit `config get keychain-mode` retains raw `local` or `icloud` stdout during deprecation for script compatibility. For v3, stderr explains that this is retained legacy metadata, not the active key-storage model.
- Setting mode remains available for v2 and refused for v3. Explain v3's folder-backed storage and device enrollment in the refusal.
- `vault_id` stays managed by verified workflows, not a general setter.

The v3 list change is observable and needs release notes and tests. Do not replace `get` output with prose or an invented mode such as `none`. No new CLI command or JSON schema is required. Choose the release version after reviewing implementation scope, not as part of this design.

## CFG-802: shorter v3 file after provenance is resolved

The target v3 file contains `vault_dir` and `vault_id`, without an apparent Keychain mode choice. Do not implement omission by defaulting retained state to `local`. Before removing the field, specify and test:

1. A dedicated device-local provenance record versus an explicit retained rollback config. Bind records to the source root and selected vault ID; never infer historical mode from the current folder.
2. Adoption of already-migrated Stable configs, including `icloud`, without inventing source history for enrollment-only configurations.
3. Durable ordering: retain usable old state before simplifying config. Interruption leaves an old representation or a recoverable new one. Read-only helper checks do not rewrite files.
4. Old reader/writer behavior: Stable defaults omitted mode to `local`, ignores unknown fields, and rewrites known fields. Test downgrade followed by an old writer. A renamed field alone does not preserve compatibility.
5. Deliberate retained-v2 selection with the correct mode and helper restart. It must not silently discard v3 identity or imply an old snapshot is current.
6. Missing, malformed, stale, or conflicting provenance cannot trigger key creation, automatic v2 fallback, or trust adoption.

Record location and rollback UX remain review decisions. Retaining the field until then is intentional, not completion of persisted simplification. Removing all v2 support is a separate deprecation decision.

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

Start with `CryptoAndStorageTests`, `VaultRootChangeCoordinationTests`, `KeyProductIdentityTests`, and `V3LocalMigrationTests`. Extend CLI/enrollment tests for changed behavior, then run the full Swift suite and release checks before qualification. Use temporary homes and disposable vaults throughout.

Preparation check on 2026-09-05: all 42 tests in those four suites passed. The initial sandbox run could not access Swift's compiler cache; the host-level rerun passed. This validates the existing baseline, not the proposed behavior. No full suite or release qualification was rerun for these documentation edits.

## Next implementation boundary

Implement `CFG-801` as a reviewable source/test change while PIV setup awaits its own approval. Keep `CFG-802` and recovery-format changes out of that diff. No change to the default new-vault format, installed app, live config, provider folder, or YubiKey is implied by this design.
