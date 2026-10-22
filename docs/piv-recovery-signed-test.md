# Signed Preview two-Mac acceptance checklist

Prepared 2026-10-22 for `REC-812`. This is a test plan, not passing hardware
evidence. Use disposable data only. The [implementation plan](piv-recovery-plan.md)
owns package status and the [contract](piv-recovery-contract.md) owns security limits.

## Candidate and permission boundaries

Source: `0ffaee776050da2a5452505b9b4c76be352e5022`, including the three integrated
review-fix commits. The app is a universal `PreviewRelease` candidate, not a new
semver release. Version/build remains `0.2.0 (19)`; distinguish it by source SHA,
artifact SHA-256, code-directory hashes and the enabled test gate, never version
alone. Raw artifacts and signing reports stay ignored under
`tmp/piv-recovery/qualification-2026-10-22-0ffaee7/`.

- [x] Verify Developer ID signatures, hardened runtime, trusted timestamps,
  expected entitlements, app/CLI/helper arm64+x86_64 slices and Preview identities.
- [x] Verify `KeyExperimentalRecoveryEnabled` is boolean `true` in the candidate
  app and embedded helper. Shipping source plists must still omit the flag.
- [x] Record the local pre-notarization ZIP SHA-256 and component hashes. Its SHA-256
  is `0dab766209c8312820724a64ed0b1a6d709d0ba25f27429edcd3f4054aa84e13`.
  The unchanged ZIP was the input to Apple submission
  `c512d968-8749-4f7d-a358-ffa0c7249025`, which returned `Accepted` with no issues.
- [x] Record the stapled transfer ZIP `Key-Preview-recovery-0ffaee7-notarized.zip`.
  SHA-256: `1b7ae213c3b98f5311a584e1bfd98aed62612114526e478f4f7301974223ca8d`.
  Transfer this ZIP, not the original unstapled submission ZIP. Compiled app,
  CLI and helper bytes remain unchanged; the stapled ticket changes the ZIP hash.
- [x] Validate the ticket, signatures, entitlements and Gatekeeper assessment on
  the stapled app and again after ZIP extraction. Gatekeeper now reports
  `accepted`, `source=Notarized Developer ID`. No policy bypass was used.
- [ ] Obtain installation approval separately. No installer, app, helper or live
  recovery command is run during candidate preparation.

The runtime's separate qualification namespace is Debug-only. This candidate uses
normal Preview app, helper, configuration and Keychain namespaces, isolated from
Stable but **not from an existing Preview installation**. A different filename,
shell variable or working directory does not isolate those namespaces.

## Stop before installation

- [ ] Identify the exact Mini and Air OS/build and architecture; record supported
  availability before running recovery (the receiver uses macOS 26+ APIs).
- [ ] Check installed Stable/Preview identities and any Preview configuration or
  saved operation on each Mac. Do not print saved secret values or Keychain contents.
- [ ] Both Preview namespaces must be confirmed disposable and the Air's Preview
  state unconfigured. If either has valued data or an existing selection, stop
  and choose a separate user/test environment with the owner. Do not delete or
  repoint configuration to make the precondition pass.
- [ ] Approve the exact installation targets and transfer method. Preserve any
  existing app/state; do not replace Stable or invoke the ordinary Preview build
  script, which installs automatically.
- [ ] On the Air, verify the received archive hash against the Mini's recorded
  final hash, then verify the extracted signature before installation. Do not
  remove quarantine or ad-hoc re-sign to work around a policy failure.
- [ ] After authorized installation, verify the running helper's exact candidate
  identity and XPC namespace on each Mac. A version string alone is insufficient.

## Credential and administration preflight

- [ ] Obtain approval for public token inspection. Select one token explicitly;
  record model/firmware and public identifiers, never PIN, PUK or management key.
- [ ] Use the candidate's `recovery tokens --json`, then
  `recovery credential --token "$token_id" --json` in an interactive terminal.
  These are public-only reads and must not request PIN/touch.
- [ ] Confirm slot 9d, P-256, generated origin, reported PIN `ALWAYS` and touch
  `ALWAYS`, matching certificate and the complete recipient ID. This metadata is
  not attestation or proof of protected administration.
- [ ] Inspect anchor occupancy. Stop on any occupied or unrecognized object,
  including an old feasibility record. Do not overwrite or regenerate a key.
- [ ] Resolve protected management-key setup with the owner before registration.
  A previous disposable default-management-key setup does not satisfy protected
  administration. Any change is a separately reviewed vendor-tool operation.
  Key does not collect credentials, configure the token or call an importer.

Keep the PIN/PUK backup available to the owner outside the evidence folder. Do not
test a wrong PIN, consume attempts, change retry limits, reset PIV or replace slot
9d. Cancel an unexpected prompt or uncertain PIN entry and inspect before retrying.

## Mini: register and use without the token

Run these steps only after the preceding approvals and preconditions. Set `cli`
to the absolute installed candidate CLI, `source_vault` to a new disposable local
directory, and `anchor_file` to a new public export path. Token/recipient selectors
must come from current public inspection, not the old certificate fingerprint.
Do not paste the whole sequence unattended; inspect each result before continuing.

1. `"$cli" init "$source_vault"`. Add synthetic secret and TOTP entries using
   ordinary interactive `add` commands. Keep expected synthetic values in local
   test notes; no real credentials or shell tracing.
2. Back up the disposable profile-2 source. Run `"$cli" recovery adopt`, inspect
   typed confirmation and Mac authentication, then verify status after helper
   restart. Adoption alone must not report recovery protection.
3. `"$cli" recovery register prepare --token "$token_id" --recipient "$recipient_id" --export-anchor "$anchor_file"`.
   Confirm the exact vault/recipient and new export. Preparation must remain
   pending, without claiming active registration or requesting token possession.
4. Stop for separate approval of the exact public-anchor import. Review device,
   object ID, occupancy and exported bytes against the implementation/vendor tool
   before giving the owner an import command. Do not substitute feasibility bytes.
   Only the owner-run vendor tool writes the approved public object; it must not
   generate a private key or collect credentials through Key.
5. `"$cli" recovery register finish --token "$token_id" --recipient "$recipient_id"`.
   Expect one deliberate possession operation. Enter PIN only in the macOS dialog
   and physically touch the metal contact when it flashes. Clicking OK is not touch.
   Record what actually happened; do not infer enforced policy from success alone.
6. Check `"$cli" recovery register status --json` after the helper restarts. Remove
   the token. Edit synthetic entries, run `"$cli" recovery rotate`, lock and reopen
   through ordinary commands. Mac authentication is separate; none of these steps
   may contact the disconnected token.
7. Record the accepted entry names/types and expected synthetic contents after
   rotation. Copy the complete source vault into a frozen transfer copy and hash
   its files. Transfer only that encrypted copy and the exact signed app to the Air.
   Do not transfer original Mac keys, local checkpoints, intents, configuration,
   exported anchor or feasibility certificate as recovery prerequisites.

## Air: restore from files and one registered token

1. Confirm Preview is still unconfigured with no competing saved attempt. Install
   only the approved candidate. Use fresh public inventory to select the connected
   token; its connection ID need not equal the Mini's. The credential recipient
   must match the registered key.
2. `"$cli" recovery review --source "$source_copy" --token "$token_id" --json`.
   This public review must request no PIN/touch and must not read entry contents.
   Its successful result is not yet proof of possession or restorable contents.
3. Choose a **missing** `destination` directory with an existing parent, separate
   from the source copy. An already-created empty destination is not accepted.
   Run `"$cli" recovery restore --source "$source_copy" --destination "$destination" --token "$token_id" --recipient "$recipient_id" --name "Recovery test Air"`.
4. Observe one deliberate source PIN/touch approval across all Mini edits and
   rotations. Count destination Mac approvals separately. If a native call fails,
   do not automatically repeat it or guess whether authentication occurred.
5. Verify source-copy hashes are unchanged. After the helper restart, remove the
   token. Read every synthetic secret, check TOTP via the same seed/counter rather
   than comparing codes from different times, edit, lock and cold-reopen normally.
6. Confirm the new vault has fresh Mac access and **no inherited recovery
   registration**. Original source registration does not protect this new vault.
   Preserve it for later separately approved re-registration qualification.

## Cancellation and exact resume

Start with benign cancellation before approving a native operation. Do not cause
wrong-PIN failures or unplug during token administration. Approve any deliberate
helper-termination test separately and target only the candidate's exact helper.

- [ ] Cancel a public review/approved native prompt, then lock; no late response may
  unlock the resident session or claim success. Record cancellation and prompt count.
- [ ] After an interrupted or ambiguous operation, preserve the source, destination,
  preparation, local pins and configuration. Do not initialize, change `vault-dir`,
  delete state or start a replacement operation to get unstuck.
- [ ] Discover selectors with `recovery pending --json`; this is not authorization
  or proof of valid pending work. Inspect operation type and exact ownership.
- [ ] Registration export: use `register resume-export` with the same selectors
  and a new output filename. Finish rechecks the exact existing candidate.
- [ ] Adoption/rotation: use their `--resume <original-operation-id>` only for the
  matching locally owned operation. Do not use a fresh operation as fallback.
- [ ] Restore: use `recovery resume` with the original source, destination, token
  and recipient, without a replacement name. Missing preparation requires
  inspection, not deletion. Completed cleared ownership is not resumable proof.

## Evidence and exit

Record per step: UTC time, machine/OS, candidate archive SHA-256, source commit,
public selectors, command/exit category, observed Mac versus token prompts,
checkpoint/ownership outcome, source hashes and expected synthetic results.
Keep raw reports in ignored `tmp/piv-recovery/`; commit only concise sanitized
findings and exact artifact identities. No credentials, tokens' private material
or real-vault contents belong in the record.

`REC-812`'s signed vertical slice passes only when the actual CLI/helper flow
completes on both Macs with one source operation, unchanged source and token-free
ordinary use afterward, plus the reviewed cancellation/resume cases. A valid
signature or green CI alone does not pass it. Independent backup-token recovery,
broader device/recipient product routes, adopted-vault/platform/provider coverage,
old-client behavior and final release gates remain separate acceptance work.
