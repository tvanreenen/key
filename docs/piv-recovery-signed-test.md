# Signed Preview two-Mac acceptance checklist

Prepared 2026-10-22, updated 2026-10-24 for `REC-812`. This checklist records
scoped evidence, not passing end-to-end recovery qualification. Use disposable
data only. The [implementation plan](piv-recovery-plan.md)
owns package status and the [contract](piv-recovery-contract.md) owns security limits.

## UX side investigation: second isolated staged test passed, 2026-10-24

The owner separately requested one repeat to watch more closely. The same probe
completed ACL evaluation at08:24:26 UTC, then one matching synthetic exchange at
08:24:29 UTC with further PIN dialogs disabled. The owner confirmed one PIN dialog
and that it closed before the access-control message and flash/touch. No automatic
retry, finish, token write or actual-vault operation occurred. Public postchecks
show unchanged credential/anchor and PIN/PUK3/3; the same pending selector and
config/export/bundle hashes remain intact. Evidence is ignored under
`tmp/piv-recovery/staged-auth-repeat-2026-10-24/`. Two standalone observations on
this Mac/key support the handoff; signed-helper validation and broader reliability
remain unproven. No additional test or product integration was performed.

## Earlier UX checkpoint: isolated staged authentication passed, 2026-10-23

One separately approved test of the hash-verified standalone probe evaluated the
actual selected key ACL through macOS. The callback succeeded at03:29:38 UTC
(2026-10-24 UTC, still2026-10-23 locally), then one synthetic agreement ran with
further PIN dialogs disabled and matched its software peer at03:29:46 UTC. The
owner confirmed one PIN dialog and flash/physical touch after the access-control
step. No retry, registration finish, token write or actual-vault operation was
requested. No PIN value or shared secret was printed/saved.

This supports the desired handoff in this run, not direct touch-event detection.
`isCredentialSet(.smartCardPIN)` reported false despite successful staging; it was
diagnostic only and must not drive the touch prompt. Public postchecks confirm
unchanged credential/anchor and PIN/PUK3/3. The same registration selector remains
pending; configs, export and pending-bundle hashes are unchanged. Raw evidence is
ignored under `tmp/piv-recovery/staged-auth-test-2026-10-23/`.
Next is separately approved validation in the signed helper before UI/product
integration; repeatability, cancellation and policy-enforcement qualification
remain. No installed app or production source changed.

## Earlier UX checkpoint: actual-key ACL found without authentication, 2026-10-23

One separately approved `--check-key` run used the hash-verified standalone probe,
fresh public inventory/credential and a pinned certificate checked against fresh
serial-selected vendor reads. Exact native lookup/public binding checks passed;
the selected key exposes a validly typed access-control object. Interaction stayed
disabled; no authentication or key-agreement mode was invoked. Public postchecks
show unchanged credential/anchor and PIN/PUK3/3; config/export/bundle hashes match.
No registration, token write or actual-vault operation was requested. Evidence is
ignored under `tmp/piv-recovery/staged-auth-acl-check-2026-10-23/`.
This establishes ACL availability only, not reliable PIN/touch staging. Next is
separate approval for one isolated staged-authentication test; no finish retry.

## Earlier UX checkpoint: staged-auth probe prepared only, 2026-10-23

An isolated ignored probe under
`tmp/piv-recovery/staged-auth-preparation-2026-10-23/` compiles with Swift 6 and
warnings as errors. Software-only gate/redaction tests pass; default/help do not
access a token. Neither native-key-check nor authentication mode was run. No
installed app, production source, vault or registration workflow changed;
config/export/bundle hashes remain unchanged.

The future test requires the actual selected private key's access-control object,
with no replacement ACL. It would evaluate that ACL through macOS, then permit
one synthetic agreement with further PIN dialogs disabled. Callback success is
not assumed to mean physical PIN acceptance or touch readiness. No PIN value is
read or supplied by the probe. Next is a separately approved noninteractive ACL
check; authentication remains a later approval. Drop this route if separation is
unreliable or adds approval/weakens policy. Standalone success would still need
signed-helper qualification. Existing registration remains at the last checkpoint
below; no fresh native status or hardware claim was obtained during preparation.

## Current checkpoint: refreshed finish reached provider, no touch, 2026-10-23

The owner separately approved one finish with the refreshed selector. Exact
installed hashes, source/config/bundle/export checks, saved operation and fresh
public credential preflight passed. This second explicit finish for the same
setup passed native key lookup/binding/algorithm guards, then returned exit one,
`PIVRecoveryAgreementError` code10 (`providerFailure` at key exchange). The
provider's underlying CFError is not exposed by this build. No automatic retry
occurred. The owner confirmed seeing/submitting the PIN dialog but not physically
touching the key. A missing-touch timeout is consistent with these observations,
not a confirmed native error classification or policy-enforcement qualification.

After lock/restart, local pending/authenticated registration status confirms the
same operation, no active recipients and activation committed false. Published
vault files, configs, export/bundle hashes and public anchor/credential are
unchanged. Public PIN/PUK counters remain 3/3. Preview was locked. No token write
or actual-vault operation was requested. Raw evidence remains ignored under
`tmp/piv-recovery/registration-finish-refreshed-2026-10-23/`.
Preserve setup; no reset/reimport is needed. Any further finish requires separate
approval and an explicit physical-touch cue after PIN entry.

## Earlier checkpoint: reconnect refreshed discovery, no finish retry, 2026-10-23

Owner-approved read-only diagnosis after reconnect found a changed macOS token
selector, with unchanged recipient/certificate and recognized public anchor.
A local ad-hoc CLI probe, with interaction disabled throughout, found exactly
one native reference using the product's exact query filters. Its public key,
application label, token, P-256 attributes and advertised ECDH support match.
A selected-token-only comparison also found one reference. A second probe added
the previous selector as a noninteractive comparison: it returned zero matches
(`errSecItemNotFound`), while current-selector queries still returned one.

This strongly supports stale discovery after reprovisioning; it does not prove
the earlier helper's unlogged match count. The probe runs outside the installed
helper, so its successful lookup does not qualify helper behavior or possession.
Installed executable hashes, deep strict signatures, Developer ID/team and
expected helper entitlements pass unrestricted inspection. An initial restricted
signature failure was not reproduced unrestricted and is not evidence of damage.

Public vendor postchecks confirm the same exact anchor/credential and PIN/PUK
3/3 counters. The same registration selector remains pending; published vault
files, configs, export and bundle hashes are unchanged. No authenticated status,
finish, private operation, token write or actual-vault operation was requested.
Preview was locked. Raw probes, reports and public certificate remain ignored
under `tmp/piv-recovery/discovery-reconnect-2026-10-23/`.
Next is separately approved finish using fresh selectors, not reprepare/import.

## Earlier checkpoint: finish blocked at native key lookup, 2026-10-23

After owner approval and passing exact setup/public preflight, one explicit
`register finish` returned exit one, `KeyCore.PIVRecoveryAgreementError error 2`.
The inspected enum and a local Swift/Foundation error-code mapping identify
`ambiguousKey`: native lookup did not return exactly one matching private-key
reference. This guard precedes `session.agree`; the error does not distinguish
zero from multiple matches. No automatic retry occurred. This is not a reported
wrong PIN or agreement-provider failure. Prompt counts were not owner-confirmed.

Initial local inspection returned the helper's restarting guidance. After lock,
ordinary status refused pending state; dedicated pending and authenticated
registration inspection succeeded after restart. The same operation remains
pending, no active recipients, activation committed false. Published vault files,
export/bundle/config hashes and public credential/anchor remain unchanged.
Serial-selected public postchecks show PIN/PUK still 3/3. Preview was locked;
no token write or actual-vault operation was requested.

Raw scripts/logs/results remain ignored under
`tmp/piv-recovery/registration-finish-2026-10-23/`. Preserve all pending setup.
Stale macOS key discovery is a hypothesis, not an established cause. Next is
owner reconnect and noninteractive key-discovery diagnosis before any separately
approved finish retry; do not prepare, reimport or reset anything.

## Earlier checkpoint: imported public anchor verified, 2026-10-23

After the owner reported `Object imported.`, serial-selected public vendor reads
confirmed object `0x5F4B59` contains exactly the approved 401-byte export, with
the same SHA-256 recorded below. Certificate/public-key binding, generated P-256
origin, PIN/touch `ALWAYS`, public management settings and full PIN/PUK 3/3 counters
remain as expected. The protected management secret was not read.

One fresh installed Preview inventory and one selected credential read returned
the expected recipient with `recognized` anchor and public-only assurance. The
same local registration selector remains pending. Published manifest/entry files,
config hashes, export and pending-bundle hashes are unchanged; Preview was locked.
Verification requested no authentication, token write, finish or actual-vault
operation. Authenticated registration status was not rerun. No possession,
policy-enforcement, activation or restore qualification is established here.
Raw probe/results remain ignored under
`tmp/piv-recovery/anchor-import-verified-2026-10-23/`.

Next is separately approved `register finish`: one deliberate hardware possession
operation before activation of this disposable vault's recovery registration.
Preserve the current setup; do not repeat prepare or reimport the object.

## Earlier checkpoint: registration pending, public anchor exported, 2026-10-23

The owner approved preparation/export only for the disposable Mini Preview vault.
Fresh public inventory/credential reads matched the expected new recipient and
absent anchor. Config selection, installed candidate hashes, unregistered local
status, no pending selectors and healthy two-entry state passed before preparation.

One explicit `register prepare` exported a 401-byte public anchor to
`tmp/piv-recovery/registration-mini-2026-10-23/public-anchor.json`. It matches the
exact saved pending bundle's anchor byte-for-byte. The CLI also validated its
canonical format and vault/recipient binding before exporting without overwrite.
Export SHA-256 is
`f786d98657107ece49ca05b018a970a4eda78019c3d713cffbff5f009f6dc78e`.
Local pending inspection identifies only registration operation
`1c30b710-cf12-4d76-b031-ecc83dbb87f8`; authenticated registration status reports
`pending`, no active recipients and activation committed false. Published
manifest/entry file hashes, Preview/Stable config hashes and pre-adoption backup
hashes remained unchanged. Preview was locked afterward.

No YubiKey write, PIN/touch/private token operation, finish, actual-vault operation,
Air update or release was requested. Public reads are not possession or recovery
proof. Raw scripts/logs/results and the public export remain ignored under the
directory above; preserve them with the source vault, local ownership and pending
bundle. Do not repeat prepare or clear records. Next is separately approved,
owner-run import of these exact public bytes, after reviewing the device, object
and occupancy. Possession verification/activation remains a later step.

## Earlier checkpoint: disposable Mini vault ready for registration, 2026-10-23

The owner approved disposable Preview-vault preparation, with the actual vault
excluded and no YubiKey writes. The exact installed metadata-corrected candidate
created a fresh local vault in the ignored evidence directory below. Init's
existing configuration/pending-restore guards remained in place; no records were
cleared. Preview config now selects only this disposable vault. Stable config's
hash remained unchanged; no actual-vault operation was requested.

One synthetic secret and one synthetic TOTP entry were added. Ordinary status
reported ready, two entries and no conflicts. Secret readback matched. After
locking Preview, a complete pre-adoption vault-file copy was preserved and
compared byte-for-byte. Explicit format adoption then committed with no cleanup
pending. The subsequent local registration status reported `unregistered`, no
recipients and no activation commit; pending selectors were empty. Ordinary
status remained ready with two entries, entry names and secret readback matched,
and the pre-adoption backup passed its recorded hashes. Preview was locked.
TOTP generation/restore equivalence was not tested in this step.

No token inventory, public token read, PIN/touch request, private token operation,
anchor export/import or registration preparation/finish was requested. No app
replacement, Air update, push or release occurred. Raw logs, scripts, intentionally
public synthetic fixtures, source vault and `profile2-backup` remain ignored under
`tmp/piv-recovery/disposable-mini-2026-10-23/`; preserve them and the associated
Preview local records. The backup is not an independent recovery credential.

Next is separately scoped registration preparation/export using fresh public
selectors. That operation creates pending local setup, not active recovery.
External anchor import and possession verification remain later approvals.

## Earlier checkpoint: fresh credential publicly verified, 2026-10-23

The owner reported completing external generation of a fresh slot9d P-256 key
and its self-signed certificate. Serial-selected vendor-library public reads
report generated origin, PIN/touch `ALWAYS`, and exact certificate/metadata
public-key equality. The installed metadata-corrected Preview candidate below
returned the same independently derived new recipient ID, `absent` anchor and
`public-observation-only` assurance. One fresh inventory and one selected public
credential command were used; no native retry was requested.

The macOS token selector remained unchanged in the fresh inventory. It is not
the credential identity: the new recipient differs from the erased key's
recipient and was checked against current vendor metadata. Do not reuse old
recipient bindings, certificates or registration exports.

Public administration observations remain nondefault AES192 management key,
management touch `ALWAYS`, stored-key protection flag true, PIN-derived mode
false, and nondefault PIN/PUK with full 3/3 counters. No protected management
secret was retrieved. Installed CLI/host/helper hashes match the recorded
candidate, the running helper uses its installed path, and Preview config is
still absent. No authentication, private operation, token write or actual-vault
access occurred during verification. The owner's earlier certificate-creation
operation was separate from these public checks.

This is not attestation, proof of possession, policy-enforcement testing or
registration/restore qualification. Raw probe/results and the machine-checked
comparison remain ignored under
`tmp/piv-recovery/fresh-credential-2026-10-23/`. Next is separately scoped
disposable Preview-vault preparation and registration qualification; no new
anchor import or private-key operation is authorized by this checkpoint.

## Earlier checkpoint: protected administration reported, slot 9d empty

After the approved reset below, the owner reported privately setting a fresh PIN
and PUK, then successful completion of the reviewed `ykman` management-key change
with random generation, PIN-protected storage, AES192 and management touch enabled.
No credentials were supplied to Key or this chat.

Read-only verification on 2026-10-23 selected the same device and read only public
metadata/administrative flags. It reports nondefault AES192 management key,
management touch `ALWAYS`, stored-key protection flag true, PIN-derived mode false,
nondefault PIN/PUK with 3/3 counters, no slot9d key and absent object `0x5F4B59`.
The protected management-key object was not read. These observations and the
owner's successful command report support the intended setup; they do not prove
randomness, retrieve/validate the stored secret, exercise management authentication
or establish touch enforcement. No PIN/PUK verification, private operation,
token write or actual-vault access occurred during these checks.

Raw public evidence and the inspected read-only probe are ignored under
`tmp/piv-recovery/management-protection-2026-10-23/verified-public-settings.json`
and `verify-public-settings.py`. Next is separately approved external generation
of a fresh slot9d P-256 credential/certificate with required policies, followed by
new public binding validation. Old recipient IDs/selectors remain obsolete.

## Earlier checkpoint: disposable PIV setup reset, 2026-10-23

The owner explicitly approved discarding this test-only PIV setup after losing
track of its PIN/PUK and reporting one failed PIN in the management-protection
command. This superseded the earlier instructions to preserve slot 9d, the PUK
and prototype anchor; it did not authorize actual-vault access or a whole-device
reset. Fresh serial-selected inspection matched the known YubiKey 5C NFC,
firmware 5.8.0, with PIN 2/3, PUK 3/3 and the management key still default.

One owner-authorized `ykman 5.9.2` PIV-only reset completed. The inspected vendor
implementation blocks the old PIN/PUK as part of the reset procedure, then clears
PIV and restores defaults. No manual credential guesses or fallback full-device
reset were performed. Public verification afterward reports PIN/PUK 3/3,
default AES192 management key, no key in slot 9d and no object at `0x5F4B59`.
The old private key is erased and cannot be restored from public evidence;
the earlier 246-byte public prototype-anchor backup remains preserved.

No new PIN/PUK, protected management key, slot key or certificate has been set.
Earlier public-read results below are historical evidence for the old credential,
not qualification of a new identity. Reprovisioning will require new public
selectors/recipient identity and fresh validation; do not reuse old registration
exports or certificate bindings. Raw reset/preflight/verification evidence stays
ignored under `tmp/piv-recovery/piv-reset-2026-10-23/`. No actual-vault access,
Key config/Keychain cleanup, app change, PR push or release occurred.

## Metadata-corrected candidate: Mini public preflight passed

Source `d3db6a475d79f48782a548400f13596c3fbc9404`, signed universal
`PreviewRelease`, version `0.2.0 (19)`. Only a separate candidate copy has Boolean
recovery gates true in app/helper. Shipping source plists/base archive remain
gated off. Expected Preview signatures, exact entitlements including helper
smart-card permission, universal slices and gates pass.

Apple accepted submission `186ccea0-906b-40f5-9934-42f36016ce8f` with no issues,
matching `Key-Preview-metadata-d3db6a4-local.zip`, SHA-256
`528700d22809f59ad35ba0427f905210089b80c16a5e84e5dd66ea877e8d7680`.
Use `Key-Preview-metadata-d3db6a4-notarized.zip` for any approved later transfer;
SHA-256 `fb7ab47c2480259d2ee21f38b7a0bc18da56732b50e354f21e5788c3c0b647c7`.
The staple, signatures, Gatekeeper and ZIP round-trip pass. No executable bytes
changed after submission. Artifacts/evidence are ignored under
`tmp/piv-recovery/qualification-2026-10-23-d3db6a4/`.

### Mini installation and single public credential command, 2026-10-23

Installed files match this candidate, and running host/helper paths/hashes verify.
The previous `036cfa9` app backup at `mini-install/Previous Key Preview.app`
matches the previous artifact and retains a valid deep strict signature. The Air
remains on `036cfa9`; no remote request or Air installation was made.

The first ordinary status immediately after opening Preview returned an XPC
connection error. The script stopped before any token command. Inspection found
the exact Preview job registered, not running, with zero runs. One explicit
status recheck after that inspection returned expected exit one, unconfigured.
No app installation or helper maintenance was repeated. Two status calls are
recorded, not one; the startup sequencing explanation is not a proven product
defect or fix.

One inventory found the same single token; one explicitly selected credential
command returned exit zero with `public-observation-only` assurance and
`unrecognized` anchor state. The unchanged workflow validates reported P-256,
generated origin, PIN/touch `ALWAYS`, certificate/metadata public-key equality,
recipient derivation and observation revalidation. The signed native metadata
read now succeeds. This supports the payload correction resolving the observed
failure in this run; it is not a capture of the earlier malformed packet or a
proof of possession, policy enforcement, protected administration or recovery.

The occupied unrecognized object is consistent with the previously saved
prototype; no fresh byte-for-byte vendor comparison or overwrite was performed.
Stable app all-file/config hashes are unchanged; Preview config remains absent.
No PIN/touch, authentication, private operation, token write, actual-vault access,
config/Keychain reset, registration, restore, push or release occurred. Protected
pending ownership remains unassessed. The result is in `mini-install/RESULT.json`.
Stop here for owner-reviewed external management-key protection and exact-target
anchor handling before disposable-vault registration. Do not reset PIV or replace
slot 9d. This passing public preflight does not pass the full `REC-812` slice.

## Earlier diagnostic candidate: installation and public-read results

Source: `036cfa96bbd3f71dc2fa75d0470e6041f0f328bc`, including the public-read
step/status/native-code diagnostic fix. A fresh signed universal `PreviewRelease`
archive and separately gated copy passed the exact Preview signing/entitlement
checks. The helper contains the diagnostic message; both slices retain Boolean
smart-card permission. App/helper recovery gates are Boolean true only in the
candidate copy. Source shipping plists and the base archive remain gated off.

Apple submission `3024ad4d-4e87-47f5-8449-a4e114845306` returned `Accepted` with
no issues. Its report matches `Key-Preview-diagnostic-036cfa9-local.zip`, SHA-256
`ec8214f9283adaff30703091fb6d9e459725f82789bab1112ae15d4f59765b7a`.

For an approved installation, use `Key-Preview-diagnostic-036cfa9-notarized.zip`
in ignored `tmp/piv-recovery/qualification-2026-10-22-036cfa9/`. SHA-256:
`07c17a7c79d8e3a8e2bc22c000f5bb4053bef34763a039c0e40eacf832be8b71`.
The ticket, signatures, entitlement allowlists, Gatekeeper and final ZIP
round-trip pass. Stapling changed no executable bytes; the original submission
ZIP remains unchanged. Version/build is still `0.2.0 (19)`, not a unique selector.

Preparation did not install or launch the candidate or call the token/vault.
The subsequently approved installation and bounded public-read result follow.
Notarization alone does not qualify native access or recovery.

### Diagnostic installation and Mini result, 2026-10-22

The exact candidate is installed on the Mini, macOS `27.0.1 (26A434)`, arm64.
Installed hashes, Boolean gates, signatures/entitlements, ticket and Gatekeeper
pass. The previous app is backed up and file-compared; installed files match
the extracted candidate. Fresh helper registration and the running helper's
executable path/hash were verified. One status request returned the expected
unconfigured error. Preview config remains absent and Stable app all-file/config
hashes are unchanged. No config or Keychain reset occurred.

One public inventory returned the same single Yubico candidate. One explicitly
selected credential read then returned exit one, no payload, and:

```text
Public PIV read failed [step=read-slot-9d-metadata, status=not-reported, native=CryptoTokenKit:-2, reason=unexpected-status]. No automatic retry was attempted.
```

The active SDK's `TKError.h` identifies `-2` as `TKErrorCodeCommunicationError`.
No card status was reported; this is not evidence of card rejection or a PIN
failure. The sequential reader path establishes that application selection and
certificate parsing completed before this metadata failure. Full policy/key
binding, recipient identity and anchor validation remain incomplete. Transport/
provider or request compatibility remains unresolved; no fallback or additional
token probe followed. No PIN, management authentication, private operation,
token write or actual-vault content/authority operation was requested.

Mini evidence and recoverable previous-app backup are under ignored
`tmp/piv-recovery/qualification-2026-10-22-036cfa9/mini-install/`.
The read result is recorded in `RESULT.json`; prior backups remain intact.

### Air result retrieved after reconnection, 2026-10-23

The Air completed the approved installation on 2026-10-22, macOS
`27.0.1 (26A434)`, arm64. Its existing final result was retrieved on 2026-10-23;
no installation or token call was repeated. The transfer manifest/all seven
payloads, component identities, entitlements, Boolean gates, universal slices,
signatures, Gatekeeper and stapled ticket passed. Installed files match the
received candidate; fresh registration and running host/helper paths/hashes
were verified. One status returned expected exit one, unconfigured. One public
inventory returned exit zero with no candidates; no credential was inspected.

Stable app all-file/config hashes are unchanged, Preview config remains absent,
and the previous-app backup verifies at
`~/Downloads/Key-Preview-036cfa9-Air-20261022T155344Z/backup-before-install/Key Preview.app`.
No PIN/touch, authentication, private operation, token write, vault operation,
config/Keychain reset or recovery followed. Protected pending ownership remains
unassessed. Raw evidence is `piv-air-test/air-036cfa9-install.json` in the Air
chat's evidence directory. Empty inventory is not credential/recovery success.

Next is metadata-read compatibility investigation, not key administration or
recovery acceptance. This result does not justify changing the PIN or key.

### Metadata request investigation, 2026-10-23

Code and primary documentation identified a request-model mismatch. At this
investigation checkpoint the metadata command returned non-nil empty `Data()`
and passed it directly to `TKSmartCard.send`.
The active macOS 27.0 SDK's `TKSmartCard.h` documents `nil` when no input field
should be present. This is the only closed public command without an input
payload. Its opcode/parameters match
[Yubico's GET METADATA](https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html#_get_metadata).
Apple separately documents `le: 0` for the available response; this investigation
does not establish a reason to change it.

The installed `ykman 5.9.2` source requests slot metadata without a payload.
Offline execution of its formatters produced `00f7009d00` for short format and
`00f7009d` for extended format under its default response-length convention.
These are vendor outputs, not captured Apple bytes; the APIs have different
response-length conventions. Earlier saved vendor metadata reads succeeded.

The existing command-surface test asserts emptiness, not absence. Fake connection
responses do not exercise Apple's native encoder. An offline synthetic-card
capture attempt stopped at Apple's active-session precondition before any
transport request; it did not establish the emitted bytes. No real session or
private-API/precondition bypass was attempted.

The supported recommendation is to represent the metadata payload as `nil` at
the existing boundary and regress absent versus empty input explicitly, keeping
the opcode, slot, response handling, policies, validation and no-retry behavior.
That production fix is not implemented here. The API mismatch is established;
its causal link to the saved communication error remains unconfirmed until a
corrected request is tested. No product tests were rerun for this investigation.
No new token discovery/read, PIN/authentication, private operation, token write,
vault operation or installed-app change occurred. Raw evidence and the offline
probe stay ignored under `tmp/piv-recovery/metadata-read-investigation/`.

### Narrow metadata payload correction, 2026-10-23

After approval, the existing closed command's payload became optional. Metadata
now supplies `nil` directly to `TKSmartCard.send`; all other commands retain their
exact payload bytes. No new transport abstraction, command, retry, fallback or
policy exception was introduced. The slot/opcode, `le: 0`, diagnostics, validation,
session lifetime and timeouts are unchanged.

The new regression checks absent input versus present-but-empty input and the
exact payloads of all four commands. It failed against the old code with two
assertions, then passed after the correction. SwiftPM Debug built successfully;
66 reader/metadata/review/agreement tests in four suites passed, followed by
65 registration/restore/routing tests in three suites using that same build.
Strict formatting and diff-whitespace checks passed. Software fixtures do not
establish Apple's emitted bytes or hardware success.

Raw logs are ignored under `tmp/piv-recovery/metadata-payload-fix/`. No native
token call, authentication, private operation, token write, actual-vault access,
installed-app change, signing/notarization, push or release occurred. Installed
Preview still has the prior payload behavior. A separately approved updated
candidate and one bounded public read are needed to test the causal hypothesis.

## Previous replacement: credential preflight incomplete

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

At this checkpoint the exact replacement was installed on both Macs,
macOS `27.0.1 (26A434)`, arm64.
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
payload. That build's diagnostic exposed neither the failed public-read stage
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

### Diagnostic follow-up: software only, 2026-10-22

The source now reports the exact public-read step, status and sanitized native
category/code instead of discarding the status and throwing one opaque error.
Native descriptions, userInfo, nested error text, token IDs and reply bytes are
excluded. The regression failed before the fix; 65 focused reader/metadata/review/
agreement tests and 56 related registration/restore workflow tests now pass.
The existing command bytes, validation and no-retry policy are unchanged.
The unsigned universal Preview build and product-isolation checks pass; default
recovery gates remain absent. This is not a newly signed/installable candidate.

No hardware call or actual-vault operation was made to obtain this result.
At that software-only checkpoint, neither installed app had these diagnostics.
The cause of the prior native
failure remains unknown; its discarded stage/status cannot be recovered from
that transcript. A new diagnostic candidate, installation and public-only read
require separate approval. Do not infer a need to change the PIN, key, policies
or prototype anchor from the old generic error.

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
