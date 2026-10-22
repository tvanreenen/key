# Signed Preview two-Mac acceptance checklist

Prepared 2026-10-22 for `REC-812`. This is a test plan, not passing hardware
evidence. Use disposable data only. The [implementation plan](piv-recovery-plan.md)
owns package status and the [contract](piv-recovery-contract.md) owns security limits.

## Current replacement candidate: installed; credential preflight incomplete

Source: `db69f44fcb9816127e5cd0df3db18169ca5d55df`, including the Preview-only
smart-card permission fix. A fresh universal `PreviewRelease` archive was built
from this clean commit. A separate copy has Boolean recovery gates enabled in
app/helper; source shipping plists and the base archive still omit the gates.
Version/build remains `0.2.0 (19)`, so use the hashes below rather than version
alone. Preparation did not install it; the subsequently approved installation
and native results are recorded below.

Apple submission `06805524-85b9-4b43-b042-d8d6213bfdaa` accepted
`Key-Preview-recovery-db69f44-local.zip` with no issues. Its report matches the
submitted SHA-256:
`0d7bed49d6ae55a6184b7f5db8d3203e40569480cb7d069fdea7fdbaaee89083`.

Use **`Key-Preview-recovery-db69f44-notarized.zip`** for an approved replacement
installation. SHA-256:
`4dd0007d202f5e5fec5e4091b1c19ea1bbb5beeff4cf9bcd10f59a748222f341`.
It is in ignored `tmp/piv-recovery/qualification-2026-10-22-db69f44/`.
The original submission ZIP remains unchanged. A separate extracted app was
stapled without rebuilding or re-signing; its executable bytes match the
submitted candidate. Final ticket, Developer ID signatures, hardened runtime,
timestamps, exact entitlement allowlists, Gatekeeper and ZIP round-trip checks
pass. The app/CLI/helper each contain arm64 and x86_64; both helper slices carry
Boolean `com.apple.security.smartcard=true`. No app/helper was launched and no
token operation was run.

Replacement installation on both Macs and the bounded read-only native
preflight were subsequently approved. This notarization does not qualify
native token access, protected administration, recovery or the occupied prototype
anchor. Previous preflight limits below still apply.

### Replacement installation and public-read result, 2026-10-22

The exact replacement is installed on both Macs, macOS `27.0.1 (26A434)`, arm64.
The Air verified the transfer manifest and all seven payload hashes before
installation. Both Macs verified installed executable hashes, Boolean gates,
signatures/entitlements, ticket and Gatekeeper. Fresh helper registration and
actual running helper path/hash checks passed. One ordinary status request per
Mac returned the expected unconfigured error. Preview configs remain absent;
no further config/cache reset was needed. Stable app all-file/config hashes
are unchanged. Prior apps are recoverably preserved:

- Mini: `tmp/piv-recovery/qualification-2026-10-22-db69f44/mini-install/Previous Key Preview.app`.
- Air: `~/Downloads/Key-Preview-db69f44-Air-20261022T151031Z/backup-before-install/Key Preview.app`.

The single public inventory on the Air returned exit zero with no candidates.
The Mini's inventory returned exit zero with one Yubico candidate, clearing the
previous missing-permission failure. The explicitly selected Mini credential
request then returned exit one, `PIVPublicObjectError.unexpectedStatus`, with no
payload. The current diagnostic exposes neither the failed public-read stage
nor the numeric status; the adapter can also map native errors to status zero.
The cause remains unresolved. No retry or alternate token command followed.

Product certificate/metadata binding, recipient identity and anchor occupancy
remain unverified; an empty Air inventory is not credential success. No PIN or
management authentication, private-key operation, token write or vault entry/
authority operation was requested. Existing Keychain/pending ownership was not
cleared or assessed. Next is scoped public-reader diagnostics/compatibility
investigation before any registration or token administration. Native failure
does not authorize changing the key or bypassing validation.

Raw Mini evidence is in that candidate's `mini-install/` directory; the Air
record is `piv-air-test/air-db69f44-install.json` in its chat's evidence folder.
The original app/config backups and public prototype-anchor backup remain intact.

## Original candidate and permission boundaries

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
- [x] Obtain installation approval separately. The owner approved the Air
  preflight, recoverable Preview-only reset and exact-candidate installation on
  both Macs, explicitly excluding the actual vault and YubiKey. No installer,
  app, helper or live recovery command ran during candidate preparation.

The runtime's separate qualification namespace is Debug-only. This candidate uses
normal Preview app, helper, configuration and Keychain namespaces, isolated from
Stable but **not from an existing Preview installation**. A different filename,
shell variable or working directory does not isolate those namespaces.

## Stop before installation

- [x] Identify the exact Mini and Air OS/build and architecture; record supported
  availability before running recovery (the receiver uses macOS 26+ APIs).
- [x] Check installed Stable/Preview identities, public config selections and
  local config/cache boundaries on each Mac, without reading vault entries or
  Keychain contents. Protected pending-operation state remains unassessed below.
- [x] Confirm both Preview namespaces disposable with the owner before changing
  existing selections. The owner approved relocating only their local Preview
  config/cache into recoverable backups, not deleting cloud vaults or Keychain
  state. This supersedes the original separate-user proposal for this install.
- [ ] Before recovery testing, resolve any competing protected pending ownership.
  An absent config and an unconfigured status response do not prove its absence.
  Preserve and inspect any saved operation; do not clear pins to make tests pass.
- [x] Approve the exact installation targets and transfer method. Preserve any
  existing app/state; do not replace Stable or invoke the ordinary Preview build
  script, which installs automatically.
- [x] On the Air, verify the received archive hash against the Mini's recorded
  final hash, then verify the extracted signature before installation. Do not
  remove quarantine or ad-hoc re-sign to work around a policy failure.
- [x] After authorized installation, verify the running helper's exact candidate
  identity and XPC namespace on each Mac. A version string alone is insufficient.

### Installation checkpoint, 2026-10-22

Both Macs run macOS `27.0.1 (26A434)`, arm64. Each now has the exact universal,
notarized `0.2.0 (19)` candidate above at `/Applications/Key Preview.app`.
Installed app/CLI/helper executable hashes match the approved transfer; both
recovery gates are boolean `true`. Signatures, entitlements, Gatekeeper and the
stapled ticket passed on each Mac. No rebuild, re-sign or policy bypass was used.

Fresh preflights established distinct Stable/Preview vault paths, directory
identities and configured vault IDs. Only the local Preview Application Support
folder was relocated, after stopping Preview. Old Preview apps were copied and
verified before replacement. Recoverable owner-only backup roots:

- Mini: `tmp/piv-recovery/qualification-2026-10-22-0ffaee7/mini-install/` in this
  worktree, containing `Previous Key Preview.app` and
  `Previous Preview Application Support`.
- Air: `~/Downloads/Key-Preview-recovery-Air-20261022T142751Z/backup-before-install/`.

The received packet manifest and all six payload hashes passed on the Air.
Transfer used the separately approved Preview/test iCloud folder outside both
selected vault roots. No cloud vault directory was reset or removed.

On each Mac, the newly installed host's supported Preview-only maintenance
command unregistered the old helper, then opening Preview registered it afresh.
The running helper resolves to the installed candidate executable, with the
expected hash, team and Preview service identity. One ordinary `status --json`
per Mac returned exit `1`, "No vault is configured". The CLI's `.vaultStatus`
route correctly returns that error through XPC without composing a vault runtime;
the dashboard's separate `.status` endpoint returns locked. No initialization
was performed to obtain exit zero. Both Preview configs remain absent.

Stable app all-file hashes and its config hash stayed unchanged on both Macs.
No actual-vault entry/authority operation or YubiKey API was requested. All
Keychain items, cloud vault contents and earlier rehearsal artifacts were left
alone. Protected pending ownership remains unknown and must not be inferred
absent from this status result. Raw reports remain local and ignored; the Air
record is `piv-air-test/air-install-20261022.json` in that chat's evidence folder.
This completes installation, not a recovery or hardware acceptance test.

### Read-only preflight and permission fix, 2026-10-22

The installed candidate's public token inventory returned
`PIVRecoveryTokenError.unavailable`. Its helper lacks
`com.apple.security.smartcard`; Apple's SDK and
[API documentation](https://developer.apple.com/documentation/cryptotokenkit/tksmartcardslotmanager/default)
require that Boolean entitlement for `TKSmartCardSlotManager.default`.
Successful signing checks against the previous allowlist did not establish
native API access. The installed candidate is blocked at this preflight.

Separately approved vendor-tool reads confirmed a YubiKey 5C NFC, firmware 5.8.0,
slot 9d P-256, generated origin, PIN ALWAYS and touch ALWAYS. PIN/PUK counters
reported 3/3; no authentication was attempted. The management key remains
factory-default. Object `0x5F4B59` contains the old prototype anchor, not the
current format. Its 246 public bytes were backed up locally; no overwrite,
credential change or actual-vault operation occurred. Product certificate/key
binding and recipient identity remain unverified.

The source fix adds the entitlement only to the Preview helper and requires
Boolean true in the release checker. Stable retains its original allowlist;
the app and CLI remain unable to claim this permission. Signing-policy fixtures
failed before the fix and pass afterward, alongside all release-script and
Preview-install safety tests. The 42 focused reader/metadata/review software tests
passed. A separate signed universal `PreviewRelease` archive passes the updated
checker and both-architecture signature/entitlement checks without being launched.
These are static/software results, not a successful native preflight.

The archive retains the default disabled recovery gates. No replacement candidate
was notarized or installed, and both installed apps remain unchanged. Next:
prepare a newly gated/notarized candidate, obtain replacement-install approval,
then repeat public credential inspection. Protected administration and the occupied
prototype anchor still require separate owner-reviewed vendor-tool decisions.
Do not reset PIV, replace slot 9d or overwrite the anchor as part of this fix.
Raw evidence stays ignored under `tmp/piv-recovery/smartcard-permission-check/`
and the earlier candidate's `public-preflight/` directory.

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
