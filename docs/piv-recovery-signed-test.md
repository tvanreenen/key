# Signed Preview two-Mac acceptance checklist

Prepared 2026-10-22, updated 2026-10-26 for `REC-812`. This checklist records
scoped evidence, not passing end-to-end recovery qualification. Use disposable
data only. The [implementation plan](piv-recovery-plan.md)
owns package status and the [contract](piv-recovery-contract.md) owns security limits.

## Online investigation leads to attributes-first/fresh-context control, 2026-10-26

Targeted Apple documentation/forum searches did not locate a directly matching
documented PIV PIN-UI cleanup fix; that is not an exhaustive absence claim.
[Apple's WWDC22 authorization example](https://developer.apple.com/videos/play/wwdc2022/10108/)
reads the key's ACL with an attributes-only query, evaluates it in a fresh
context, then obtains the key reference using the approved context. It demonstrates
Secure Enclave authorization, not a PIV cancellation guarantee.

Our three previous controls instead supplied the evaluation context to a
private-key-reference lookup before evaluating the ACL. Dropping the handle did
not test a context that had never been supplied to that lookup. Apple's
[published reference result processing](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/sec/Security/SecItem.m#L1127)
also distinguishes attributes-only results from token-value/reference work and
[returned-reference creation](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/sec/Security/SecItem.m#L1269).
This supports testing whether pre-evaluation query binding contributes to
cancellation ownership. It does not prove that binding caused the remaining UI
or that the reference code exactly matches the installed OS.

A separate local control now reads only attributes for the exact token, pinned
public-key label and private-P256 metadata. It retains the actual ACL, invalidates
and releases its separate noninteractive lookup context, drains lookup
temporaries, then creates the evaluation context. That fresh context is never
passed to a Keychain query. No token private-key reference is requested. The
background evaluation, 20-second invalidation, 80-second context/ACL lifetime,
100-second outer bound, diagnostic identity and entitlements match the preceding
control where applicable. All previous evidence and installed Preview25 remain
unchanged. No production code changed.

Compile, Developer ID signature/identity/entitlements, default/invalid/incomplete
argument refusal checks and passive protected hashes pass. Only those no-native
paths have run; no token lookup or authentication occurred during preparation.
The guarded launcher requires renewed owner readiness and fresh public preflight.
One actual unanswered PIN dialog must appear for a valid comparison. Real
appCancel plus owner-observed automatic UI closure would support further
production investigation; appCancel with a visible dialog would supply no fix.
Missing UI, lookup failure or early evaluation failure is inconclusive. No
agreement follows any outcome, and public card postchecking waits for confirmed
UI closure and normal control exit. Automatic cleanup remains blocking.

Source, signed app, source notes, hashes, guards and the unexecuted one-shot
launcher stay ignored under
`tmp/piv-recovery/pin-cancellation-fresh-context-2026-10-26/`.

## Released-key-handle control still requires blank Cancel, 2026-10-26

One separately owner-approved run released the temporary Mac-side `SecKey`
handle and drained lookup temporaries before evaluation. Events confirm no key
reference retained throughout the background evaluation/cancellation lane. The
20-second timer fired after approximately 21 seconds at whole-second resolution;
the real callback returned LocalAuthentication `appCancel`(-9). Context and ACL
remained retained through the approximately 84-second control lifetime, about
63 seconds after callback.

The owner observed exactly one unanswered PIN dialog and reported it still
visible before the retention-end event. After normal control exit, the owner
cancelled the blank dialog and confirmed closure. Only then did one public-only
postcheck run: metadata and PIN/PUK3/3 are unchanged, protected files match, and
Preview25's helper remains stopped. No token write, key agreement, actual-vault
access or automatic retry occurred. Raw events, launch record, owner observation,
public postcheck and `result.json` stay ignored under
`tmp/piv-recovery/pin-cancellation-released-handle-2026-10-26/`.

This control supplies no successful cleanup from releasing the client key handle.
It does not establish what framework-internal references remain or assign fault
to macOS, the PIV provider or the device. Together, the background-retention,
main-thread and released-handle runs reproduce the unresolved UI behavior in a
local app without the vault/restore or key-agreement paths. No speculative
production change follows. The owner-required automatic-cleanup gate stays
blocking and CLI-disconnect testing remains deferred.

A local reproduction report is prepared alongside the ignored control evidence
for further investigation of the macOS authentication path. It separates the
real cancelled evaluation from owner-observed UI persistence, records the
negative controls and their limits, and omits opaque credential/context IDs and
device serial numbers. Nothing has been submitted externally, and no additional
authentication attempt is scheduled.

## Main-thread control still leaves PIN UI; key-handle comparison prepared, 2026-10-26

One separately owner-approved run used the original signed control binary with
background context construction/lookup, but main-thread evaluation and
invalidation. Its 20-second timer fired after approximately 21 seconds at
whole-second resolution. The real callback returned LocalAuthentication
`appCancel`(-9) on the main thread. Context, ACL and key handle remained retained
through the approximately 84-second lifetime, about 63 seconds after callback.

The owner reported the blank PIN dialog still visible while the control was
still retaining its objects, then manually cancelled it before the control
exited. These observations were recorded before the retention-end event. This
run provides no successful cleanup from changing evaluation/invalidation to the
main thread. It does not establish a universal provider cause, and no threading
or retention workaround was added to production. Automatic cleanup stays blocking.

After confirmed UI closure and normal process exit, one public-only postcheck
confirmed unchanged metadata and PIN/PUK3/3. Protected files match. Preview25 was
not replaced and its helper remains stopped; no key agreement, vault access,
token write or automatic retry occurred. Events, observations and
`main-result.json` remain ignored under
`tmp/piv-recovery/pin-cancellation-investigation-2026-10-26/`.

A bounded, app-filtered system-log read from that existing run records the
supplied authentication context being externalized and another context being
reconstructed for the token-key handle. The PIN UI transition follows explicit
ACL evaluation. Invalidation is acknowledged and the original evaluation
returns appCancel, while the owner still sees the dialog. These observations
support investigating ownership of the temporary key handle; they do not prove
that the reconstructed context causes the remaining UI or that a daemon crashed.
Private logging was not enabled. Opaque context/credential identifiers remain
in ignored local evidence and are omitted from this record.

A separate local comparison now releases the temporary Mac-side `SecKey` handle
and drains lookup temporaries before evaluating the same ACL. It retains the
original context and ACL, uses background evaluation/invalidation, and performs
no token cryptography or writes. It uses ordinary reference lifetime management,
with no private API or token deletion. Compile, Developer ID signature,
entitlement and noninteractive default/refusal checks pass. Its source and app
are separate from the preserved original control; installed Preview is unchanged.
The comparison has not run and requires fresh owner readiness. A missing PIN
dialog or failed evaluation would not count as successful cleanup. Even a
positive result would need confirmation in the production helper. Raw preparation
stays ignored under
`tmp/piv-recovery/pin-cancellation-released-handle-2026-10-26/`.

## Retained-object background control did not demonstrate PIN cleanup, 2026-10-26

One separately owner-approved local control evaluated the pinned key's ACL and
requested invalidation on background threads. It performed no key agreement or
vault access. The 20-second timer fired after approximately 22 seconds at the
recorded whole-second resolution. The actual callback again returned
LocalAuthentication `appCancel`(-9). Context, ACL and key handle were deliberately
retained through the approximately 84-second control lifetime, about 62 seconds
after callback. The owner reported the unanswered PIN dialog still visible and
then confirmed cancelling it blank; no automatic cleanup was demonstrated.

The observation was recorded after the retention-end event and was not
independently timestamped at the callback. Together with the different diagnostic
app identity, that limits causal conclusions; this is not a complete exclusion
of every lifetime-related explanation. It supplies no evidence for adding a
retention delay to production. Automatic cleanup remains blocking.

After owner-confirmed UI closure and normal control-process exit, one public-only
postcheck confirmed unchanged key/certificate/anchor/policies and PIN/PUK3/3.
Protected files match, installed Preview25 was not replaced, and its helper stays
stopped. No authentication/read retry, token write or actual-vault traversal
occurred. The first lane's source, events, owner observations and result remain
ignored under `tmp/piv-recovery/pin-cancellation-investigation-2026-10-26/`.

The next prepared lane uses the same signed binary, background context
construction/lookup and object retention, changing only evaluation/invalidation
dispatch to the main thread. Its wrapper preserves first-lane evidence and
requires renewed owner readiness. It has not run; CLI-disconnect remains deferred.

## Owner keeps PIN cleanup blocking; isolated controls prepared, 2026-10-26

The owner explicitly declined accepting manual Cancel as a Preview limitation.
Automatic PIN-dialog cleanup remains blocking; CLI-disconnect testing stays
deferred. No new authentication has occurred during this investigation.

Apple's published Security reference implementation externalizes supplied
contexts during
[SecItem query preparation](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/sec/Security/SecItem.m#L1418)
and can reconstruct a separate context for a
[token-backed key session](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/sec/Security/SecCTKKey.m#L132).
That supports investigating context ownership/lifetime; it does not establish
the installed macOS binary's implementation or the cause of the remaining UI.
The apparent rebinding route, `SecKeySetParameter`, is declared
[private SPI](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/headers/SecKeyPriv.h#L968)
and absent from the public SDK headers. It was ruled out and not used.

A separate local arm64 control app was compiled with public APIs and signed
with the existing Developer ID, a unique diagnostic bundle ID and the helper
smart-card/Preview-group entitlement set. It cannot open vault data, collect a PIN,
perform key agreement/signing, generate/import a key or write to the token.
Only its non-UI default/refusal paths were executed; they exit before lookup
or authentication. Strict signature/identity/entitlement checks pass. It is not
a replacement Preview build, notarized transfer or native test result.

The first planned control constructs context/looks up the exact pinned test
key on a background queue, then evaluates and invalidates there. It invalidates
after 20 seconds but retains context, ACL and key handle through an 80-second
event loop. A second separately approved lane would retain the same objects
but dispatch evaluation/invalidation on the main thread. Neither lane has run.
The different diagnostic app identity limits inference: a positive control still
needs confirmation in the actual helper. No retention delay or speculative
threading change was added to production. Next requires owner readiness for
one background-retention control with the PIN left unanswered; any card postcheck
waits for owner-confirmed UI closure and control-process exit.

Raw source, signed local app, guard checks, hashes and primary-source notes stay
ignored under `tmp/piv-recovery/pin-cancellation-investigation-2026-10-26/`.

## Build25 deadline and cancellation callback pass; system PIN UI still remains, 2026-10-26

On the Mini, one owner-approved installed build25 restore reached an unanswered
PIN dialog after fresh public checks passed. The request returned its explicit
deadline error after 90.021 seconds, exit 1. No touch-required or destination
Mac-approval progress occurred; no destination/configuration or saved-attempt
file was created. Expanded protected hashes match.

The filtered native trace contains one evaluation-start event, one context
invalidation request, one actual callback and one invalidation-return event.
At expiry the real callback reports `success=false`, `error=true`,
`local-authentication=true`, `code=-9` (`appCancel`), before invalidation returns.
The helper image matches the installed build25. This verifies delivery of the
new native diagnostics and confirms policy cancellation reached the framework.
The owner nevertheless reported the unanswered system PIN dialog still visible.
Automatic dialog dismissal therefore still fails. The earlier worker-lifetime
fix addresses premature local completion but did not resolve this UI behavior;
neither callback acknowledgement nor helper exit proves downstream UI completion.

No card postcheck or helper lock was performed while awaiting that observation.
The owner then cancelled the blank PIN dialog and confirmed it closed. Only our
identified diagnostic log client was interrupted, then normal lock stopped the
helper. One public-only vendor postcheck now passed: exact expected key,
certificate, anchor and policies unchanged, PIN/PUK counters 3/3. Protected
files, prior test vaults/backups and installed hashes still match. No automatic
authentication/read retry, token write or actual-vault traversal occurred.

The inspected public cancellation surfaces did not establish another handle for
this managed PIN dialog. `TKTokenAuthOperation` belongs to the token provider's
authentication protocol. Apple's
[smart-card interaction cancellation](https://developer.apple.com/documentation/cryptotokenkit/tksmartcarduserinteraction/cancel())
applies to an interaction object the caller starts and may be unsupported;
[reader PIN interactions](https://developer.apple.com/documentation/cryptotokenkit/tksmartcarduserinteraction)
are a different surface from the current Security/LocalAuthentication evaluation.
No replacement provider, custom PIN collection or speculative new build was
introduced. The exact downstream owner/cause remains unconfirmed. Record the
system-dialog behavior as an open compatibility/UX issue, not a passing gate.
The CLI-disconnect test remains deferred pending that disposition.

Installed build25 remains unconfigured with its helper stopped and the key
connected. Raw trace, owner reports, OS/version, preserved-state checks and the
partial qualification receipt remain ignored under
`tmp/piv-recovery/build25-deadline-2026-10-26/`.

## Build25 installed on Mini; authentication retest not started, 2026-10-26

The exact receipt-verified notarized build25 was installed with normal Preview
quit/helper unregistration and the existing atomic installer. A complete,
byte-identical, ticket/Gatekeeper-verified copy of the previous installed build24
is retained for rollback, in addition to its accepted ZIP. Installed executables
match build25's receipt; bundle comparison, strict all-architecture signatures,
ticket and Gatekeeper checks pass.

Normal app startup registered helper build25. One ordinary status request
confirmed Preview unconfigured, without authentication. The running helper's
executable mapped to the expected installed path; normal lock then stopped it.
Expanded protected snapshots match outside the expected Preview app replacement,
including Stable/config/support and prior disposable vaults/selection backups.
The original support-root identity is retained. No actual-vault traversal,
configuration reset, vault/token authentication or token API/write occurred.

A fresh missing destination and guarded deadline harness are prepared. Passive
USB topology confirms the key connected; no native request or log capture has
started. Next requires owner readiness to leave one PIN dialog unanswered.
Capture native lifecycle events across expiry and obtain the owner's UI report
before any card postcheck; helper exit alone is not proof of dialog cleanup.
Runtime callback/log delivery and automatic PIN-dialog dismissal remain open.
CLI-disconnect remains held. Raw installation/rollback and test preparation
remain ignored under
`tmp/piv-recovery/native-authentication-build25-install-2026-10-26/` and
`tmp/piv-recovery/build25-deadline-2026-10-26/`.

## Build25 notarization and distribution checks passed, 2026-10-26

One submission of the exact build25 review ZIP was accepted by Apple:
`f28c0b5e-9dac-46ab-926b-b13316e5cf99`. The detailed log was retrieved and
inspected; job ID, archive filename and submitted SHA256
`c167d8947c419d3e9bac2227ab6e6146086579e468a387ee0d9557be34b0d611`
match, with `issues: null`. No resubmission or credential changes were needed.

The ticket was stapled to an isolated extracted copy. Ticket validation,
Gatekeeper, strict signatures and both-architecture release checks pass.
Executables and host/helper plists remain byte-identical to the submitted
candidate. The final transfer ZIP was extracted again; ticket/Gatekeeper and
signature checks pass and the complete bundle compares byte-for-byte. Final ZIP
SHA256 is `787d0259ddf133e4dd9788dcba5206df997797d7ccb1935502c2c3c73932b1aa`.

Protected snapshots match, including installed apps/config/support and prior
disposable vaults/selection backups. Build24 and its accepted rollback remain
intact. No installation, launch, new vault/token authentication, token API/write
or actual-vault traversal occurred. This is distribution qualification only;
runtime log delivery and automatic PIN-dialog cleanup still need the observed
build25 deadline retest after separate installation. CLI-disconnect stays held.

Receipt, accepted log, final ZIP and verification evidence remain ignored under
`tmp/piv-recovery/native-authentication-build25-2026-10-26/notarization/`.

## Native authentication build25 signed and packaged; not submitted, 2026-10-26

The normal universal PreviewRelease product was archived from clean pinned
source `85ee569b0487dfcf78fa4e186295c8c63f394fcc`, including the callback lifetime
fix and bounded native diagnostics. Version is 0.2.0 with archive-only build
override 25; no project version, release tag or default feature gate changed.
The base archive keeps recovery disabled. Only the copied candidate's host and
helper plists enable local recovery, with no diagnostic helper replacement.

Existing Developer ID certificate `14E20BC6A127E95F2C34B22E276A76EC8E48755E`,
team `9Q355KSV85`, signed the candidate. Exact Preview identifiers, hardened
runtime/timestamps, strict deep/all-architecture signatures, helper smart-card
and Preview-only keychain entitlements, accessory role and arm64/x86_64 images
passed. Complete ZIP extraction preserves the bundle byte-for-byte and passes
signature checks. The review ZIP SHA256 is
`c167d8947c419d3e9bac2227ab6e6146086579e468a387ee0d9557be34b0d611`.

The accepted build24 ZIP was preserved byte-identically as rollback, SHA256
`14170fc3df0cf241235d5896970818f8e72da8c478ffc1de80e01b1d177b9587`.
Expanded protected snapshots include installed apps/config/support and prior
disposable vaults/selection backups and match before/after. Installed build24
remains unchanged; Preview stays unconfigured with its helper stopped. No actual
vault traversal, token API/write, new authentication, installation, launch or
notarization submission occurred. Native log delivery/PIN-dialog dismissal
remain unqualified. Next is notarization of this exact candidate, followed by
separate installation and observed deadline retest; CLI-disconnect stays held.

Raw candidate, hashes, signing reports, protected snapshots and rollback remain
ignored under `tmp/piv-recovery/native-authentication-build25-2026-10-26/`.

## Native authentication lifetime fixed in source; signed retest pending, 2026-10-26

The native session previously completed its local approval waiter during
invalidation, before receiving the real framework callback. That could release
the process's card-operation lease and mutate the context's interaction setting
while native authentication remained unresolved. The source fix in `87e311d`
keeps that worker/lease until the actual callback arrives. The outer request
still returns at cancellation/deadline; late approval cannot start touch or
agreement, duplicate callbacks cannot revive the request, and invalidation stays
idempotent. No provider-interface, persistent-format or token-policy change was
needed. If the callback never returns, the process gate remains busy. This
corrects premature local release; it does not establish the cause or repair of
the observed external PIN dialog. Timeout text now instructs cancelling any
remaining PIN dialog without entering a PIN before using the key again.

Three software regressions exercise the native reply coordinator and the
composed operation lease, including late positive/negative callbacks after
cancellation/deadline and inline invalidation callbacks. With the old synthetic
completion preserved during extraction, two regressions failed with nine
issues; all three passed after removing it. A combined run initially failed
short worker-entry/synchronization waits, including in existing tests. With
test-level parallelism explicitly disabled, all 72 tests across agreement,
reader, progress, anonymous XPC and recovery-routing suites passed. Explicit
in-test races remain active; no production deadline or unrelated test timeout
was changed. The final rebuilt run passed in 11.085 seconds.

Native-only diagnostics distinguish evaluation start, invalidation request and
return, and actual authentication callback delivery. Logs use the bundle
subsystem/category `PIVAuthentication`, fixed labels, booleans and a numeric
error code; no native descriptions/userInfo, PIN, token/key/certificate IDs,
secret, peer point or vault path. These compiled paths have not yet been
exercised in a new signed native run and do not prove UI dismissal.

The normal PreviewRelease host, CLI and helper build succeeds for arm64 and
x86_64 with signing disabled in an isolated ignored directory. No build was
installed/launched, signed/notarized, or used for further authentication. The
installed build24 and its failed UI-cleanup observation remain unchanged.
Next is preparing a signed diagnostic candidate and a separately observed
deadline retest before the CLI-disconnect test. Raw evidence remains ignored
under `tmp/piv-recovery/native-authentication-lifetime-2026-10-26/`.

## Mini build24 deadline enforced; unanswered PIN dialog remained, 2026-10-26

After explicit owner readiness and fresh public preflight, one disposable
restore was left at its unanswered system PIN dialog. The product returned the
explicit request-timeout error after 90.024 seconds, exit 1. No touch-required
or destination Mac-approval progress occurred. The destination remains missing,
Preview configuration absent, and support/saved-attempt and protected file
hashes match. Normal lock stopped the helper, with last exit code 0. Prior
disposable vaults, source, selection backups, installed apps and Stable config
remain intact. There was no automatic authentication retry or token write.

The owner reported still seeing the unanswered PIN dialog after the timeout
and helper shutdown. Automatic system-dialog dismissal therefore **failed**;
this is not a passing end-to-end deadline case. One public-only vendor metadata
postcheck, started after normal helper shutdown, also timed out after 45 seconds
while that dialog remained. It was not retried. Post-test PIN/PUK counters are
not established; only the pretest 3/3 readings are available. The owner then
cancelled the blank PIN dialog and confirmed it closed. Passive hashes still
match after this manual cleanup. No new authentication attempt followed.

Code inspection confirms timeout requests `LAContext.invalidate()`. Apple's
[documented invalidation API](https://developer.apple.com/documentation/localauthentication/lacontext/invalidate())
stops pending policy evaluations, but this observation does not establish why
the smart-card dialog remained. The native session currently wakes its local
approval waiter before context invalidation; that local completion must not be
confused with observing the framework's real callback or dismissal of its UI.
Trace the invalidation/callback lifecycle before choosing a change. Helper exit
alone is insufficient evidence that an external PIN dialog or provider work has
finished, as this run demonstrates. Do not automatically start another card read
or authentication to resolve the ambiguity.

Two existing software-only regressions passed: late approval after cancellation
cannot start touch/agreement, and a pending provider remains excluded after
cancellation/deadline (2 tests, 1.010 seconds, existing build). These verify the
scripted adapter boundaries, not native callback delivery or OS-dialog cleanup.
No production fix, replacement candidate or native retest is claimed. Hold the
CLI-disconnect authentication test until this cleanup issue is investigated.
Raw evidence and the partial-result receipt remain ignored under
`tmp/piv-recovery/build24-deadline-2026-10-26/`.

## Mini build24 physical token removal stopped recovery safely, 2026-10-26

Read-only preflight confirmed unchanged protected files, preserved prior
disposable vaults/selection backups, unconfigured Preview, installed build24
and its stopped helper. No further selection reset or movement was needed.
After explicit owner readiness, fresh public token/credential/source review
and vendor metadata checks passed. One restore targeted another missing
disposable destination. The owner confirmed exactly one approved PIN dialog,
unplugging when the touch window appeared without physical touch or Cancel,
the window closing itself and no Mac vault-approval prompt.

The request reached touch-required progress, then failed after 8.315 seconds,
exit 1, without automatic retry. The destination remains missing and Preview
configuration absent; all support/saved-attempt and protected file hashes match.
Prior source/vaults/selection backups remain intact. Normal lock stopped the
helper. Nonempty IORegistry USB topology then showed four XHCI controllers,
eleven nodes and no YubiKey. After separate owner-confirmed reconnect, one
public-only vendor postcheck confirmed unchanged key/certificate/anchor/policy
metadata and PIN/PUK counters at 3/3. Protected hashes still match afterward.

This qualifies safe failure after physical token removal during the touch wait.
The generic product error does not identify the native cause, qualify an XPC
client disconnect or establish application-deadline expiration. No further
authentication, token write, actual-vault traversal, credential deletion,
forced stop, resume or abandon occurred. Preview stays unconfigured with its
helper stopped; the key is reconnected. Raw evidence stays ignored under
`tmp/piv-recovery/build24-disconnect-2026-10-26/`.

## Mini build24 missing-touch failure stopped safely, 2026-10-26

The completed resumed vault `a7354dc7-6278-4041-b453-4c209e55178a` and its
contents remain intact. After normal Preview quit/helper unregistration, its
selection and checkpoint cache were moved byte-for-byte into the ignored test
folder's `completed-preview-selection/`. The original support-root identity,
saved journals and Mac credentials were retained. Installed build24 hashes,
helper registration and actual executable image were verified; ordinary status
confirmed Preview unconfigured without authentication. A local registration
guard initially expected an absolute executable path, but ServiceManagement
reports a bundle-relative program identifier. That guard stopped before any
status/authentication request; the observed identifier and parent/version/signing
constraints were checked before the one status request and executable inspection.

After explicit owner readiness, fresh public token/credential/source review and
vendor metadata checks passed. One installed product restore targeted a new,
missing disposable destination. The owner confirmed exactly one approved PIN
dialog, no physical touch or Cancel click, the touch window closing itself and
no Mac vault-approval prompt. The request reached touch-required progress, then
reported that the key operation did not complete: exit 1 after 23.231 seconds.
No automatic retry or cancellation was injected. This qualifies the observed
missing-touch failure path; the product's generic error does not identify the
provider error or establish expiration of the separate 90-second request deadline.

The destination remains missing and Preview configuration absent. All support
and saved-attempt file hashes are unchanged. Source, installed apps, Stable
config, prior successful disposable vaults and selection backups match their
baselines. Normal lock stopped the helper before public token postchecks;
logical failure alone was not treated as proof of native-operation termination.
Public credential/anchor/policy metadata match and PIN/PUK counters remain 3/3.
No actual-vault traversal, token write, credential deletion, forced process stop
or resume/abandon operation occurred. Preview remains unconfigured with the
helper stopped; the completed resumed vault's selection/cache backup is retained.

Raw evidence remains ignored under
`tmp/piv-recovery/build24-touch-timeout-2026-10-26/`. Disconnect, application
deadline, independent backup-token and remaining history/lifecycle qualification
are separate cases; no further authentication is implied by this result.

## Mini build24 resumed-vault token-free reads and reopening passed, 2026-10-26

Read-only preflight verified the installed build24 hashes, original physical
location bindings and selection of resumed disposable vault
`a7354dc7-6278-4041-b453-4c209e55178a`. Protected state matched the prior resume
receipt. The owner confirmed the YubiKey unplugged and readiness to watch for
Mac authentication. On macOS27.0.1 (26A434), ordinary health reported ready with
two entries/no issues. Both the exact synthetic secret, including its newline,
and TOTP against the known seed within the actual read interval matched.

Normal lock stopped the first helper; subsequent ordinary secret/TOTP reads
passed through a distinct helper, PID57013 replacing56773. Both mapped the
installed build24 executable. TOTP had one counter candidate in each read,
counter59767173. Final normal lock stopped the helper, with no subsequent vault
request. No secret, seed or generated TOTP value/fingerprint was printed or
persisted. Sensitive outputs stayed in memory; logs retain metadata/results only.
Process freshness does not establish an exact user prompt count; that observation
is separate from the data/process acceptance.

The initial USB safety guard rejected an empty legacy `SPUSBDataType` result
before any app/authentication request. Available profiler types include
`SPUSBHostDataType`, not that legacy name. Direct IORegistry USB topology then
provided the four absence checks: each showed four XHCI controllers, eleven
nodes and no YubiKey. A nonempty controller topology was required; an unavailable
or empty inventory was never counted as proof of absence. The stopped marker was
preserved separately; no authentication or entry read was retried.

Source and resumed published files, prior successful vault/selection backup,
installed Stable/Preview, Stable config and Preview support hashes match their
baselines. No recovery command, token API/write, entry mutation, actual-vault
traversal, forced process stop or configuration reset occurred. This qualifies
same-Mac ordinary use after exact resume without the token; independent Air
recovery remains scoped to its earlier results. Raw evidence stays ignored under
`tmp/piv-recovery/build24-resumed-ordinary-2026-10-26/`.

## Mini build24 complete-preparation cancellation and exact resume passed, 2026-10-25

The first build24 attempt completed a full two-entry disposable restore after
the owner approved everything, exit0 in20.521 seconds. This was preserved as
successful restore evidence, not counted as cancellation. Passive checks confirmed
fresh authority IDs, exact ciphertext digests and a permanent device-wrapped
profile without inherited recovery registration. Vault
`ec38fc5d-e3b4-488f-b6f6-29309dfbfa2f` remains intact. Its Preview selection/cache
were backed up before another fresh disposable attempt; original support-root
identity and inert completed journals were retained. The first unconfigured
status check reported a closed helper connection; a separate read-only check
after verified build24 registration passed. No failed authentication was retried.

On the explicitly renewed attempt the owner approved source PIN/touch and
`Prepare restored vault on this Mac`, then confirmed cancelling
`Publish prepared restored vault`. The request stopped after the complete-saved
and Publish progress stages, exit1 in22.801 seconds, without reaching activation.
Configuration remained absent and the new destination empty. Both exact records
remained for operation `d523f9a4-1da4-4e4a-9d79-77ba1d4c2515`, reserving vault
`a7354dc7-6278-4041-b453-4c209e55178a`. Passive checks confirmed canonical bundle,
manifest/entry digests, source/location bindings and unchanged prior records.
Normal lock stopped the helper without changing saved records or ownership.
This qualifies complete-preparation cancellation, unlike the earlier
reservation-only cancellation. Parsing alone was not treated as cryptographic
authority; explicit resume still performed the native ownership/crypto checks.

The owner then separately approved one explicit resume with the exact original
source/destination/token/recipient. It succeeded through a fresh helper, selected
the original reserved vault and completed normal helper shutdown. The retained
reservation and preparation files are byte-identical; published genesis and both
entry objects are byte-identical to the saved bundle. Operation, vault, key,
device and entry IDs match. No new identity or resealing was substituted. Source,
prior successful vaults/selection backup, installed code and Stable state match;
only the expected new selection and checkpoint cache were added to local files.
The resulting vault remains permanent device-wrapped with no recovery key
registered. Public token checks report unchanged expected state and PIN/PUK3/3.
No actual-vault traversal, token write or automatic retry occurred.

The owner confirmed YubiKey PIN/touch followed by **five Mac approvals** during
resume. These are separate local wrapper/trust/activation checks, not additional
YubiKey approvals. The count is an observed UX cost to review; this acceptance
does not relax those checks or promise a fixed prompt count. Ordinary entry reads
after this completed resume were not requested in this run; earlier two-Mac
ordinary-access qualification remains separately scoped below.

Raw evidence remains ignored under
`tmp/piv-recovery/approval-incomplete-build24-resume-2026-10-25/` and
`tmp/piv-recovery/approval-incomplete-build24-resume-retest-2026-10-25/`.
The latter contains saved preparation, exact-resume and public postcheck receipts;
the first contains the preserved complete vault and its selection/cache backup.

## Mini build24 explicit incomplete-reservation release passed, 2026-10-25

After direct owner permission superseded preservation of only this disposable
reservation, one installed build24 `recovery abandon` request addressed source
vault `8b67cabc-7c4a-4eae-a67e-edc06cf47ea4`, its original source/destination and
operation `3ec1cec1-50da-4200-b9d9-31956003cef4`. The authoritative reply confirms
release of that exact incomplete operation; normal helper shutdown completed.
All protected file hashes match. The source, empty destination, original
reservation file and saved Mac credentials were retained; only local reservation
ownership was released. No authentication, token operation/write, actual-vault
traversal, automatic retry or replacement restore occurred.

The first local validation invocation used an incorrect nested JSON anchor field
and stopped before its dispatch marker or any request. The check was corrected
against the actual anchor codec (`sourceAnchor.vaultID`) before the single
product request. This was not a second release or authentication attempt.
Raw evidence remains ignored under
`tmp/piv-recovery/approval-incomplete-build24-release-2026-10-25/`.
Next is a separately guided fresh disposable restore: approve Prepare, then
cancel Publish after complete preparation is saved, followed by exact resume.

## Mini build24 installed; non-authenticating checks passed, 2026-10-25

The exact receipt-verified build24 was installed on the Mini using normal
Preview-only quit/helper unregistration and the existing installer. A complete,
byte-identical, ticket/Gatekeeper-verified build23 rollback remains. Installed
executable hashes, bundle comparison, strict signatures and ticket checks pass.
The registered/running helper reports parent bundle version24 and maps the
expected installed executable. The CLI exposes the new abandonment help; an
ordinary status request confirms Preview remains unconfigured.

The configuration-root identity, Preview support files, Stable app/config,
scoped disposable sources and earlier restores match the protected snapshots.
Reservation `3ec1cec1-50da-4200-b9d9-31956003cef4` still has SHA256
`4f08e3c0f59996853bfddea06e2b0198f6eb40d82335ddf3d9a9c0bd52dc9db1`;
its original destination remains empty and no complete preparation exists.
No recovery, abandonment, Mac/YubiKey authentication, token operation/write or
actual-vault traversal occurred. Native approval-cue/abandonment/resume acceptance
remains open. The owner is being asked for explicit permission before releasing
this disposable reservation, because the prior instruction was to preserve it.

Raw installation/postcheck evidence and rollback remain ignored under
`tmp/piv-recovery/approval-incomplete-build24-install-2026-10-25/`.

## Build24 notarization and detailed receipt verified, 2026-10-25

Normal universal PreviewRelease build24 was archived from clean source
`8fa8b0ddd24affafc66e8d7643414a5f0f0ec9f3`, including both approval-cue and
incomplete-attempt commits. Recovery was enabled only in copied host/helper
Info.plists, with no diagnostic replacement. Exact identifiers/team, hardened
runtime, helper entitlements in both slices, strict signatures and ZIP roundtrip
passed. Apple accepted submission `f1ed4c59-5ac8-4ea6-be9e-60455a4a6f0a` for the
submitted ZIP pinned locally by SHA256
`65504eb3256bfea39ba2ed55c5a9932451b2a4a1d5235edee86a3550e66ddc66`.

The subsequent detailed-log lookup returned exit69, reporting no password item
for `key-notary`. Both the default lookup and an explicit login-Keychain lookup
failed. Read-only checks confirmed the login Keychain is the search/default
path and reports unlocked; why the earlier upload/wait succeeded but log lookup
failed is unresolved. No credential values, profile/settings changes, unlock
request or resubmission occurred. The owner was asked to retrieve the same log
from Terminal, without recreating credentials or sharing passwords.

The owner then downloaded the receipt using that existing profile in Terminal.
Inspection confirmed the original job ID, archive filename and exact SHA256,
Accepted status and `issues: null`. The deferred finalizer reverified submitted
and final checksums plus protected snapshots, then recorded completed candidate
metadata. Elevated agent retries, including direct system `xcrun` without login
shell setup, had still failed; Terminal success establishes profile usability in
that context, but the precise agent lookup restriction remains unresolved.

Independent of that receipt lookup, the exact submitted candidate was extracted,
stapled and validated against Apple's ticket; Gatekeeper, strict signatures,
unchanged executable/Info.plist bytes and final transfer-ZIP roundtrip passed.
The final ZIP SHA256 is
`14170fc3df0cf241235d5896970818f8e72da8c478ffc1de80e01b1d177b9587`.
Detailed receipt/archive-digest inspection and warning review are complete, with
no reported issues. `finish-after-log.py` completed the final gate without
resubmitting or repeating stapling. Build24 is ready for installation; signed
product UI/abandonment/resume acceptance is still pending.

Protected installed apps, Stable config, Preview support and explicitly scoped
disposable vault files match before/after snapshots, including retained
reservation `3ec1cec1-50da-4200-b9d9-31956003cef4`. Build23 remains installed.
No installation, product launch, recovery authentication, abandonment, token
operation/write, actual-vault traversal or public release occurred. Raw evidence
and the package stay ignored under
`tmp/piv-recovery/approval-incomplete-build24-2026-10-25/`.

## Local approval cues and incomplete-attempt handling implemented, 2026-10-25

The local source now distinguishes Mac preparation, reopening, publication and
activation in bounded request progress, with distinct native reasons for
`Prepare restored vault on this Mac`, `Reopen saved restore preparation on this
Mac` and `Publish prepared restored vault`. Complete saved preparation is
announced separately after confirmation, never for a reservation alone. Progress
does not authorize an operation, extend a deadline or replace the final reply.
Anonymous XPC and real software workflow tests cover the initial/resume branches,
skipped publication after selection, early interruption and ordering/closure.

Incomplete resume now explains its state and reports the source vault and
original operation IDs. The new gated `recovery abandon` route takes those IDs
and the original source/destination paths. It bypasses token/private-key adapters
and releases only the exact reservation pin after checking physical bindings,
unselected config, no preparation pin/file and an empty original destination.
Files, the directory and Mac credentials remain. Prepared, changed, unavailable
or conflicting attempts refuse; nothing is automatically retried or recreated.
The [contract](piv-recovery-contract.md#explicit-abandonment-before-complete-restore-preparation)
records the boundary, alternatives and retained-file behavior.

The broader software regression passed120 tests in11 suites. The final targeted
pass exercised52 tests; its sole issue was an existing CLI assertion for the
preservation message's wording. That wording was retained, and the complete
13-test CLI suite then passed. The remaining final targeted suites passed,
including the new exact-ID diagnostics, no-token abandonment, prepared/invalid
state refusals, changed ownership and resume-stage behavior. The helper builds
successfully and diff checks pass. These checks use disposable files/software
keys and test XPC endpoints, not installed product authentication.

Protected before/after hashes match for installed Stable/Preview, Stable config,
Preview support (including reservation `3ec1cec1-50da-4200-b9d9-31956003cef4`),
the source fixtures and earlier disposable restores. No installed app was changed
or launched, no real Mac authentication/token operation occurred, and the current
incomplete attempt was not abandoned or modified. No actual-vault traversal.
Raw logs/snapshots remain ignored under
`tmp/piv-recovery/approval-incomplete-implementation-2026-10-25/`.

The new source still needs a signed candidate and observed product acceptance.
Build23 remains installed; its previous native results below are unchanged.

## Mini build23 touch Cancel passed; later-cancellation target not reached, 2026-10-25

One owner-guided build23 request returned `Recovery was cancelled`, exit1 after
15.308 seconds. The owner confirmed the touch window appeared visibly after the
PIN dialog closed and its Cancel button was clicked without physically touching
the key. No destination, configuration or new restore journal was created.
The admitted native key-exchange call returned separately10.238 seconds after
the logical cancellation reply; its completion was observed before public token
postchecks. PIN/PUK counters remained3/3, protected source/earlier disposable
vaults and Stable matched, and normal Preview lock stopped the helper. This
qualifies the Mini touch-window Cancel path, not immediate native-call abortion.

A subsequent explicitly guided request approved source PIN/touch and stopped at
a Mac wrapper check, exit1 after18.582 seconds. The owner believed the later
prepared-vault prompt was cancelled. However, the helper log records user
cancellation of `Verify this Mac's saved restored-vault access.`; no context for
the later prepared-vault check was requested. Filesystem evidence agrees: only
reservation `3ec1cec1-50da-4200-b9d9-31956003cef4` exists, the destination is empty,
configuration is absent and no complete preparation was saved. The prompt
guidance did not reliably distinguish these stages; do not count this as the
intended complete-preparation cancellation or a successful resumable attempt.

One explicit negative resume with the original selectors refused in0.044 seconds
without any authentication-stage callback. Its opaque
`KeyCore.V3RecoveryRestoreServiceError error 5` is consistent with the inspected
incomplete-preparation preflight, but does not explain that state to the user.
The harness's expectation of an explanatory diagnostic failed; it did not rerun
the request. Independent postchecks then verified the unchanged reservation,
empty destination, absence of configuration/preparation, protected files and
PIN/PUK3/3; normal Preview lock stopped the helper. Opaque Keychain ownership and
the incomplete attempt remain intact; no cleanup, reconstruction or automatic
retry occurred. No actual-vault traversal or token write occurred.

Successful resume from complete encrypted preparation is still pending. Before
another attempt, clarify preparation/publication progress and incomplete-attempt
diagnostics/handling; a reservation alone must not authorize reconstruction.
Raw evidence is ignored under
`tmp/piv-recovery/cancellation-resume-mini-2026-10-25/`, specifically
`touch-cancel-build23/` and `saved-preparation/`.

## Mini build23 installation and public preflight passed, 2026-10-25

The exact notarized build23 was installed on the Mini after normal Preview-only
quit/helper unregistration. A byte-identical, trust-verified build22 rollback was
retained. Installed executable hashes, complete bundle-copy comparison, ticket,
Gatekeeper and strict signatures passed. The running helper maps the expected
installed executable, with parent bundle version23.

Preview remains unconfigured. Its support-root identity and saved records,
Stable app/config, original disposable source, published-files-only source copy
and earlier disposable restores match their snapshots. Public-only product
token/credential/source review and vendor metadata checks passed, recognizing the
expected anchor/recipient/head with PIN/PUK counters3/3. No authentication or
YubiKey write was requested, and no actual-vault traversal occurred.

The owner is being asked for readiness before one fresh build23 touch-window
Cancel attempt. Neither that observed cancellation nor later saved-preparation
cancellation/resume passes yet. Raw installation/preflight evidence and rollback
remain ignored under `tmp/piv-recovery/product-touch-build23-install-2026-10-25/`.

## Build23 touch-cue visibility candidate notarized, 2026-10-25

Normal PreviewRelease build23 was archived from clean source
`9f9872f4a04be5b878b2b90dbc8e16e94bd77276`. Its only product-source difference
from build22 is the touch-window visibility fix described below. Recovery was
enabled only in copied host/helper Info.plists, with no diagnostic replacement.
Developer ID identifiers/team, hardened runtime, universal arm64/x86_64 slices,
exact helper entitlements in both slices, accessory UI metadata, strict deep
signatures and ZIP roundtrip passed.

Apple accepted submission `908bd701-ec68-4bc0-950b-dee4d2a7f47f` with no issues.
Its log matches the submitted ZIP's SHA256
`d1aab95228d93491cfc32391f960c1f427af1e1c46eb0531591b6351673f6952`.
The ticket was stapled to a separate extracted copy; ticket validation,
Gatekeeper, signatures and final transfer-ZIP roundtrip all passed. Executable
and Info.plist bytes still match the submitted candidate.
The final transfer ZIP's SHA256 is
`e600810430a4a1ce9855496154893a261d43456e37670c40c56cf40a9fe97edb`.

Installed Stable/Preview, Stable config, Preview support records and the
explicitly scoped disposable vault files match their preparation snapshots.
No installation, product launch, helper restart, authentication, token operation,
actual-vault traversal or public release occurred. Installed Preview remains
build22. Build23's signed UI/cancellation acceptance is pending; next install it
on the Mini and guide a fresh observed touch-window Cancel test before proceeding
to saved-preparation cancellation/resume. Raw artifacts and final ZIP remain
ignored under `tmp/piv-recovery/product-touch-build23-2026-10-25/`.

## Mini cancellation checks: PIN passed; touch-window case unresolved, 2026-10-25

The exact installed build22 was tested on the Mini using the published-files-only
disposable source. Preview's prior selection/cache were preserved locally; its
configuration-root identity and existing completed journals were retained. The
initial intended PIN-cancel attempt was instead approved by the owner and
completed a separate disposable restore. That success and its selection/cache
were preserved, and it is not counted as cancellation evidence.

A separately guided PIN cancellation returned in1.216 seconds with the explicit
no-key-agreement diagnostic. The owner confirmed cancelling without entering a
PIN. No destination, selection or new saved attempt was created. Source, earlier
disposable vaults, Stable app/config and public token state remained unchanged;
PIN/PUK counters were3/3. Normal Preview lock stopped its helper.

The next request emitted the terminal touch cue and failed after29.683 seconds.
The owner approved the PIN without touching the key and reported seeing no touch
window. This is **not a touch-window cancellation pass**; the prompt handling and
failure cause were investigated separately. Postchecks establish only that no
destination, selection or new saved attempt remained and the same protected
state/counters were unchanged.
No automatic retry occurred. Later saved-preparation cancellation and explicit
resume remain pending. The seven focused software suites passed83 tests.

The matching build22 helper log records successful access-control approval,
followed by creation of alert window1551 with AppKit's warning that ordering from
an inactive app may place it beneath the active application's windows. The ECDH
call failed14.35 seconds later with CryptoTokenKit-3/card6982. This supports a
presentation problem and is consistent with withheld touch; the log does not
prove the window's actual screen position or uniquely diagnose a touch timeout.
All three installed executable hashes still match the qualified build22.

The local presentation fix explicitly orders the temporary cue to the front even
while inactive, keeps it above ordinary windows, and disables hiding on
deactivation. It retains the native alert, Cancel action and completion-driven
dismissal. Source authentication, touch policy and recovery state are unchanged.
The helper compiles and all six focused progress/anonymous-XPC regression tests
pass. Signed installation and observed UI/cancellation acceptance of this change
remain pending. The installed build22 was not replaced.

All raw evidence remains ignored under
`tmp/piv-recovery/cancellation-resume-mini-2026-10-25/`. No actual-vault access or
YubiKey write occurred. No source export to the Air was needed or performed;
the Air task confirmed it left its successful disposable restore unchanged.

## Air token-free ordinary access and fresh-helper checks passed, 2026-10-25

The owner renewed a guided attempt after confirming the old prompt closed and
readiness. Ordinary health reported ready/v3/two entries, no conflicts/issues.
The exact secret fingerprint matched before and after normal lock/shutdown,
including the fixture newline. A fresh helper (PID19502 replacing3559) mapped
the expected build22 executable/hash and completed the fresh read. Token absence
was checked before/after by public USB inspection only. Final normal lock and
stopped helper state were verified, with no subsequent vault command.

The parent independently verified both returned TOTP fingerprints against the
original synthetic seed and their exact read intervals: counters59765374 and
59765377, one candidate each. No seed/code was transferred, printed or persisted.
The initial explicit unlock may have used a warm session; the separate successful
post-lock fresh-helper read establishes reopening without the old process key.
No Mac prompt-count claim is inferred from runtime or success.

Source-copy and destination published files, Stable app/config, installed Preview
and selected config hashes match. Local caches/metadata were not required to stay
byte-identical. No actual-vault traversal, recovery operation, token API/write,
config reset, forced termination or discretionary edit occurred. The Air remains
on its restored disposable vault, locked, without a recovery key registered.

The earlier30.029-second health timeout remains incomplete evidence with cause
unconfirmed; the guided test was explicitly renewed, not automatically retried.
Air-local evidence is `piv-air-test/air-product-build22-ordinary-guided-20261025T204510Z.json`.
Parent snapshots and independent TOTP results stay ignored under
`tmp/piv-recovery/build22-air-transfer-2026-10-25/`. Successful independent restore
and token-free fresh-helper access now pass; cancellation/resume, timeout/
disconnect, backup-token and remaining history qualification are still open.

## Earlier: independent Air restore passed; ordinary-access check pending, 2026-10-25

After separate direct owner approvals in the Air task, public token/credential/
source review passed, followed by one actual build22 restore. The authoritative
reply reports two entries restored, exit0 in18.837 seconds, from20:23:13 to20:23:32
UTC. The owner confirmed exactly one YubiKey PIN dialog and the expected touch
window/physical-touch/automatic-dismissal sequence. No retries or token writes.

Air Preview now selects fresh vault `f0c576c3-4055-4b27-9c41-ef15b3fc2ddf` at
`~/Downloads/Key-Preview-build22-Air-20261025-receipt/Air-Restore-20261025/`.
Passive metadata checks confirm fresh vault/key/device/signing/wrapping authority,
two entries, one active Air device and a permanent device-wrapped profile with no
inherited recovery registration. Source and Stable app/config hashes match; no
actual-vault traversal occurred. Only published encrypted files were transferred
from the Mini, with no source Mac credentials/config/checkpoints/setup records.
This establishes an independent successful restore, not merely a same-Mac run.

The parent retrieved complete bounded execution and passive-check results into
ignored `tmp/piv-recovery/build22-air-transfer-2026-10-25/`. Full Air-local evidence
is `piv-air-test/air-product-build22-restore-attempt.json`. The Air stopped before
follow-up ordinary entry reads; token-free secret/TOTP comparison and fresh-helper
reopening on Air remain pending. The successful restore already includes normal
helper shutdown; no automatic restore repeat or forced restart is needed.
Next approve those ordinary-access checks, then continue cancellation/resume,
timeout/disconnect, backup-token and further history acceptance.

The owner then approved token-free ordinary reads/reopening and confirmed the
key unplugged. The first health request timed out after30.029 seconds, exit1,
before any secret/TOTP read, lock or reopening check. Public USB inspection showed
no key; source/destination published files, Stable, Preview config and installed
app hashes match. The owner was not watching, so prompt handling and the server's
final state are unconfirmed. No automatic retry or lock was attempted. The owner
requested a guided new attempt; the Air is awaiting confirmation that any old
Mac dialog is closed and the owner is watching. The timeout remains incomplete
evidence, not an ordinary-access pass or a restore-failure conclusion. Exact
timeout evidence is preserved in the parent's ignored Air-transfer folder and
the Air's `air-product-build22-ordinary-access.json`.

## Earlier: Air build22 installed; public recovery preflight pending, 2026-10-25

The reconnected Air completed fresh read-only app/config preflight on arm64
macOS27.0.1 (26A434), then received the exact notarized build22 and a source copy
containing only five published manifests and six encrypted entry versions. All
nine packet payloads, source checksums, signatures, exact entitlements, universal
slices, gates, accessory UI metadata, ticket and Gatekeeper passed. Installed
whole-bundle/executable hashes match the Mini candidate; a verified old-app
rollback remains. Normal helper registration reports parent build22. The helper
is idle, so a running helper identity was not claimed. Preview remains
unconfigured; Stable app/config and encrypted source hashes are unchanged.

The owner confirmed the known YubiKey plugged into the Air, but also directly
instructed the Air task to install only and stop before any recovery or YubiKey
operation. That narrower limit was honored: no recovery command, device API or
authentication ran. The initial parent API-preflight request was withdrawn.
Public key/source preflight and independent restore remain pending, not passing.
No Mini credentials/config/checkpoints/setup records or plaintext fixtures were
transferred; only verification fingerprints accompany the encrypted source.

Air receipt: `~/Downloads/Key-Preview-build22-Air-20261025-receipt/`, source
`source/RecoverySource`, rollback `rollback/Key Preview.app`. Local parent
evidence stays ignored under `tmp/piv-recovery/build22-air-transfer-2026-10-25/`;
the Air result is in that task's `piv-air-test/air-product-build22-install.json`.
The pinned ditto ZIP's normal AppleDouble metadata required an archive guard
correction, preserving signed bytes and all trust checks. No policy bypass.
Next is approval for public-only Air preflight, then a separately approved
single restore into a missing disposable destination.

## Earlier: first product restore and token-free reopening passed on Mini, 2026-10-25

One approved build22 restore completed from19:55:18 to19:55:51 UTC, exit0, using
only a copy of the disposable source's published manifests/encrypted entries and
the existing registered key. Preview's three local config/cache files were first
preserved in a verified backup and Preview was cold-started unconfigured. No source
Mac credentials, checkpoints or setup bundles were copied into the restore source.
The owner confirmed exactly one YubiKey PIN dialog and the expected touch-window
handoff/dismissal. No key write or automatic restore retry/resume occurred.

Both entries restored into fresh vault `5e7481e7-4399-4242-b878-29d013bd15c9`,
now selected by Preview. New vault/key/device/entry/transition IDs were verified;
its permanent device-wrapped genesis has no inherited recovery registration.
After unplugging the YubiKey, public inventory confirmed zero token candidates
and normal reads matched the exact source fixture bytes and expected TOTP
seed/time counter. Normal lock stopped the helper, and reads through a fresh
helper also passed without the token. Final Preview state is locked/helper stopped.
Entry values were not printed or logged.

The copied source, original source, previous Preview config/cache backup, Stable
app/config and installed code hashes match. Post-restore public key/anchor/policy
metadata matches with PIN/PUK3/3. No actual-vault traversal occurred. Evidence stays
ignored under `tmp/piv-recovery/product-touch-build22-restore-2026-10-25/`.
Two harness assumptions were corrected: preserve the fixture's literal newline,
and use lock's existing shutdown rather than expecting a still-running helper.
There was one restore; only ordinary token-free reads were repeated.

This is same-Mac success: original source Mac credentials remain in the local
Preview Keychain, so independent Air recovery is still required. Cancellation,
timeout/disconnect, exact resume, backup-token and further history qualification
also remain. Preserve both vaults and the old config/cache backup; do not replay
the completed restore or automatically revert Preview's new selection.

## Earlier: first real product registration and touch UI passed on Mini, 2026-10-25

One separately approved finish request completed through exact installed build22
on arm64 macOS27.0.1 (26A434), from19:47:31 to19:47:57 UTC, exit0. The actual
product reported approval, touch and hardware completion once each, then committed
the disposable vault's recovery registration with cleanup pending false. Manifest:
`y6x1_pue0dRG8eWNQhMamkzdy2qkPVWV_HSkwjvH0w4`.
The owner affirmed the expected PIN-close/touch-window foreground/physical-touch/
automatic-dismissal sequence and separately confirmed exactly one YubiKey PIN
dialog. This is owner observation, not a direct touch signal or enforcement test.

Public postchecks show no pending operation and successful signed source review
for the expected recipient/new registration/head. Exactly one manifest and two
encrypted entry versions were added; their hashes match the committed manifest.
All prior disposable-vault and Stable-app files, installed code, both configs and
public export match. The journal clears local ownership and retains the encrypted
preparation for audit. Public token state and exact anchor match with PIN/PUK3/3.
No token write, actual-vault traversal, automatic retry or second authentication.
The normal success shutdown handshake completed; subsequent public-only checks
used a fresh normal helper, not another private operation.

Raw evidence is ignored under `tmp/piv-recovery/product-touch-build22-finish-2026-10-25/`.
An initially incorrect file-delta check was corrected against the product's
entry-publication/ownership-cleanup code, using captured successful public results;
no finish was repeated or product code changed. Recovery is now active for this
disposable source. Do not replay its old pending setup. Cancellation, timeout,
disconnect, restore/resume, backup-token and two-Mac qualification remain. Next is
a separately approved restore test into a fresh disposable destination.

## Earlier: product build22 installed on Mini; public preflight passed, 2026-10-25

The exact notarized build22 installed on the Mini through the existing Preview
installer after preserving and verifying a complete build21 rollback. Installed
executable hashes, signatures, ticket, Gatekeeper and whole-bundle comparison
match the candidate. Opening Preview registered build22; observed helper PID86048
maps the expected installed executable and launchd reports parent build22.

One each of public token discovery, credential inspection and pending-operation
inspection passed through the real product CLI/helper. The expected recipient and
recognized public anchor match, and registration operation
`1c30b710-cf12-4d76-b031-ecc83dbb87f8` remains pending. Vendor public verification
matches certificate, anchor, setup/policies and PIN/PUK3/3. No PIN verification,
management authentication, secret read, private-key operation or token write ran.
Both configs, public export, pending preparation and full disposable-vault/Stable-app
snapshots are unchanged. The actual vault was not traversed. Only this Mac was
updated; the Air was not contacted.

Evidence and build21 rollback stay ignored under
`tmp/piv-recovery/product-touch-build22-install-2026-10-25/`. An initial path guard
stopped before installation because of the config's existing trailing slash;
comparing normalized Path values resolved the guard without editing the config.
No authentication or registration finish occurred. Next is a separately approved
single finish attempt for this disposable registration, observing PIN closure,
touch cue/focus and automatic dismissal. That attempt can activate the disposable
registration; the key itself is not provisioned or rewritten. Live window behavior,
cancellation, restore/resume and two-Mac acceptance remain outstanding.

## Earlier: product touch-window build22 notarized, 2026-10-25

The matching real product candidate was archived from `ea1f8f5` as universal
PreviewRelease build22, Developer ID-signed and notarized. The separate candidate
enables recovery in its host/helper Info.plists; repository defaults remain off.
It contains the ordinary product CLI/helper, not the build21 diagnostic substitutes.
Both architectures, existing signing requirements, exact helper entitlements,
accessory UI declaration and ZIP round-trip pass. The implementing agent's scoped
review found no additional blocker; this is not an independent audit.

Apple accepted submission `4429d137-a01d-45f1-81d9-ba4067a66708` with no issues.
The submission log matches ZIP SHA-256
`61ca5fc4a22af29957338a7d837636cc5b7ac161f17133807a50d4e04a308540`.
The stapled package passes Gatekeeper as Notarized Developer ID and a second
round-trip verification; all three executable bytes match the submitted candidate.
Transfer ZIP SHA-256:
`3f6527a01883f1ea7dc0904e07b0d635592df8c4b18ee47f0622cef9332d8ca4`.
Raw evidence is ignored under `tmp/piv-recovery/product-touch-build22-2026-10-25/`.
An initial architecture-check command failed after successful archive/signing;
verification resumed with the corrected command without rebuilding or re-signing.

No installation, product launch, helper restart, authentication, registration
finish or token request occurred. Installed build21 and the protected config,
public export, pending preparation and disposable-vault/Stable-app snapshots
remain unchanged. Next install this exact package with rollback preserved, then
perform read-only preflight. One real disposable registration-finish attempt and
native touch-window/cancellation checks require separate authentication approval.
Notarization does not establish the window's runtime behavior or recovery success.

## Product staging and touch UI implemented; native acceptance pending, 2026-10-25

The real registration-finish and restore/resume paths now carry scoped progress
into actual-key ACL approval and one noninteractive ECDH. The helper owns a native
Cancel-only touch window after approval, with AppKit layout checked offscreen.
The CLI writes correlated progress to stderr; only the final service response
determines completion. Disconnect/lock/deadline cancellation, closed progress,
one-use agreement and durable publication checks remain in force. The additive
XPC selector requires matching CLI/helper bundles; legacy hardware requests are
refused before dispatch. See the [contract](piv-recovery-contract.md#staged-approval-and-request-scoped-presentation).

Standard software tests passed serially: 1772 KeyCore tests and six canonical-JSON
tests. A final 48-test focused run passed after strict native CFError guards were
aligned with the diagnostic probe. This includes actual anonymous XPC callback
interoperability, cancellation before/after approval, late approval refusal,
bounded/correlated progress and CLI final-response handling. A valid dash-prefixed
recipient exposed an existing parser defect; five deterministic cases reproduce
it before the two option declarations were fixed. Validation remains strict.

Stable/Preview Debug builds, bundle isolation, CLI help, install-safety and release
script checks pass. Universal PreviewRelease builds with normal repository flags;
both CLI/helper architectures were checked. Global warnings-as-errors conflicted
with the dependency's warning suppression, so that attempt was replaced by the
normal Release build; code warnings are absent. The initial unconstrained parallel
suite hit existing short synchronization timeouts and was stopped; the complete
serialized run passed without relaxing those tests. Raw logs and the offscreen
render stay ignored under `tmp/piv-recovery/product-staging-validation/` and
adjacent `product-staging-*.log` files.

No new product was signed, notarized, installed or launched, and no hardware test
or registration finish ran. Installed diagnostic build21 and protected-file
hashes remain unchanged. Its staged attempt remains spent. Next is review and a
matching signed product Preview candidate for native window/cancellation and
pending-registration acceptance, followed by restore qualification. The earlier
diagnostic success does not establish this product UI's runtime behavior.

## Earlier UX checkpoint: first signed-helper staged synthetic test passed, 2026-10-25

The owner separately approved one isolated staged synthetic test. Exact installed
build21 hashes, the same running helper PID19584/launch count1, unchanged protected
files, fresh public state and a noninteractive key/ACL preflight passed. One request
completed through the signed CLI/helper, exit0, with no automatic retry or helper
restart. Its complete reply records five ordered events: noninteractive key check,
access-control start, access-control success, agreement start and synthetic match.
ACL evaluation completed at14:45:15 UTC; one native exchange with additional PIN
dialogs disabled matched the software peer at14:45:17 UTC. No vault authority was
involved. `pin_credential_present` remained false and was diagnostic only.

The owner confirmed one PIN dialog closed, followed by the cue/flash and physical
touch. This supports the intended PIN-then-touch handoff in one signed helper run
on arm64 macOS27.0.1 (26A434). It is not direct touch-event detection, enforcement,
repeatability, cancellation, cross-Mac or end-to-end recovery qualification. The
native core's inherited generic caution text does not change this scoped result.

Public postchecks match credential, anchor and policies with PIN/PUK3/3. Installed
executables, full disposable-vault/Stable-app snapshots, configs, export and
encrypted pending bundle are unchanged. No registration finish, key write or
actual-vault operation occurred. Raw evidence remains ignored under
`tmp/piv-recovery/signed-helper-staged-2026-10-25/`. Build21 remains temporarily
installed, with ordinary Preview commands disabled. Its one staged attempt is
spent; do not restart/retry automatically. Preserve rollback and pending setup.

Next is product integration of actual-key ACL staging and scoped touch progress,
followed by signed product acceptance, including cancellation/failure cases and
the pending registration. Do not infer product readiness from this diagnostic run
or run another hardware/authentication operation without its own approval.

## Earlier UX checkpoint: build21 helper startup and read-only inspection passed, 2026-10-25

After approved public/state preflight and a verified original-app rollback copy,
the exact notarized build21 installed. Signatures, ticket, Gatekeeper, complete
copy comparison and installed CLI/helper startup-only checks pass. Opening Preview
registered build21 through SMAppService. One explicit helper start remains running
as PID19584, with the exact expected mapped executable/hash, signing identity and
entitlements. Fixed startup logs confirm capsule validation and listener activation.
Its command line is bundle-relative, consistent with the reproduced old guard
defect; the original failed process's arguments remain unavailable.

One `staged-helper --inspect` request completed through the signed CLI/helper XPC
boundary on arm64 macOS27.0.1 (26A434), exit0. The complete reply contains exactly one noninteractive key-check
event: actual key ACL available true, authentication requested false. Native exact
key/certificate/token binding and algorithm guards passed. No authenticated
request, private-key agreement or retry occurred. This establishes readiness and
ACL availability in this signed helper context, not PIN/touch ordering or recovery.

Fresh public postchecks match credential, anchor, policies and PIN/PUK3/3. Entire
disposable-vault and Stable-app snapshots, both configs, public export and encrypted
pending bundle are unchanged. The same registration selector was pending at
preflight; no registration operation was requested after replacement. No actual
vault operation or key write occurred. Raw evidence and rollback remain ignored
under `tmp/piv-recovery/signed-helper-build21-install-2026-10-25/`.

Build21 remains temporarily installed, with normal Preview commands disabled.
Next is separately approved one isolated staged PIN/touch synthetic test in this
signed helper, with no registration finish. Preserve rollback and pending setup;
stop before authentication until that approval. UI, cancellation, repeatability,
policy enforcement and end-to-end recovery qualification remain outstanding.

## Earlier UX checkpoint: startup fix notarized, not installed, 2026-10-25

Apple accepted the exact build21 review ZIP in submission
`27e65935-3299-4c0a-a91f-58b43ca00922`, with no issues. The submitted hash matches
the preparation record below. An extracted copy was stapled and repackaged as
`Key-Preview-staged-helper-build21-notarized.zip`, SHA-256
`458c0f7b7337c866a9e020b1bd5aba327d7da3e61b9107317dfcadcd2f888097`.
Ticket, signing/entitlement, deep strict all-architecture and Gatekeeper checks
pass, including ZIP round-trip. Executable and app/helper plist bytes match the
submitted source; diagnostic-only settings remain intact. No rebuild/re-sign.

Installed build19, disposable/Stable file snapshots, configs, export and pending
bundle hashes are unchanged. No install, helper launch, token API, authentication,
vault/registration operation or public release occurred. Evidence and transfer
artifact remain ignored in the startup-fix preparation's `final/notarization/`.
Next is approved temporary Preview-only installation with rollback preservation,
then startup-only and read-only helper checks. Pause before authentication. This
notarization does not establish actual LaunchAgent or native behavior.

## Earlier UX checkpoint: startup fix prepared and signed, 2026-10-25

A local process reproduction of the original capsule guard passes with absolute
`argv[0]` and rejects the same executable with basename or bundle-relative labels.
This establishes a guard defect consistent with the failed launch; the original
process's arguments were not captured, so its precise failure remains inferred.
The corrected diagnostic sources locate the loaded executable using
`_NSGetExecutablePath` and resolve symlinks, following existing `KeyVersionInfo`
code without linking KeyCore. Expected executable layout and all capsule metadata
checks remain required. Each guard now has a fixed nonsecret reason code; a signed
local refusal check confirms that code reaches unified logging and JSON output.

Both architectures compile with Swift6 warnings as errors. Thirty-five local
process tests pass for launch labels, symlinks, changed cwd, metadata/layout
refusals, software core/boundary checks, ordinary-command refusal and rejection of
noninteractive authentication before XPC. Six signed startup-only launch-label
checks also pass. The new `--startup-check` exits before listener activation,
XPC or token access. Intel execution and actual SMAppService launch remain untested.

Diagnostic-only build21 is signed and packaged, not notarized or installed. Exact
signing/entitlement, both-slice, deep strict, host-code and ZIP round-trip checks
pass. Its review ZIP SHA-256 is
`0d5b7774a149bd68e2c53e2a84601f7b0233112ecb56300453e6e2ad1d96aa67`.
The native core is byte-identical to build20; production XPC requirements and
recovery-disabled/validation-only gates are retained. A local packaging-command
syntax error was corrected, then verification resumed without re-signing.

Installed build19, prior candidate, disposable/Stable file snapshots and
config/export/pending-bundle hashes remain unchanged. No listener, hardware query,
authentication, key write, registration/vault operation, install or public release
was requested. Corrected sources, tests, logs and candidate remain ignored under
`tmp/piv-recovery/signed-helper-startup-fix-2026-10-25/`; use `final/` only.
Next is separately approved notarization of those exact bytes, then temporary
Preview installation and read-only helper checks. Pause before authentication.

## Earlier UX checkpoint: diagnostic helper startup blocked, original Preview restored, 2026-10-25

Owner-approved preflight verified the exact notarized build20 archive, installed
build19 hashes, disposable config and same pending registration. Fresh public
reads matched the certificate, recognized anchor, policies and PIN/PUK3/3 counters.
A complete original-app rollback copy passed byte comparison, signatures,
Gatekeeper and ticket validation before replacement. The exact diagnostic app
installed and passed the same checks; ordinary recovery remained disabled.

Opening Preview registered build20 through SMAppService. One explicit helper
start returned PID50430, then launchd recorded exit1 before readiness. Focused
logs confirm resolution to the installed build20 helper executable, but contain
no diagnostic listener/native result. The helper source checks startup arguments
and capsule metadata before activating its listener. Its capsule path derives
from `argv[0]`; launch-context path handling is a suspect, not an established root
cause. The catch reports only a generic startup error, so the exact guard failure
remains unresolved. No diagnostic `--inspect` or authenticated request was sent.
No second diagnostic-helper launch or authentication retry was requested.

The exact original notarized build19 was restored and re-registered. Its helper
is running; original executable hashes and whole-app rollback comparison pass.
Read-only pending inspection returns the same saved operation. Full disposable
vault and Stable-app file snapshots, both configs, public export and encrypted
pending bundle are unchanged. Public postchecks again match credential/anchor,
policies and PIN/PUK3/3. No PIN, touch, private operation, token write, registration
finish, actual-vault operation, rebuild/re-sign, push or release was requested.

Raw evidence, verified rollback app and unchanged candidate remain ignored under
`tmp/piv-recovery/signed-helper-install-2026-10-25/` and the earlier preparation
directory. Signed-helper native inspection and authentication are unqualified.
Next is diagnosis of the startup guard with bounded nonsecret failure reporting
and launch-context coverage before another candidate is signed or installed.
Preserve the pending registration; authentication remains a separate later step.

## Earlier UX checkpoint: signed-helper candidate notarized, not installed, 2026-10-24

Apple accepted the exact recorded build20 review ZIP in submission
`3a10e32d-7cc7-43bd-81a8-0862bf1daeb7`, with no issues. The submitted SHA-256
matches the preparation record below. No rebuild or re-sign occurred. An extracted
copy was stapled and repackaged as
`Key-Preview-staged-helper-build20-notarized.zip`, SHA-256
`eddb4a3d7b296c84c53ba26979f32b8336455f06522099eddb126478af86e5a9`.
Ticket validation, repository signing/entitlement checks, deep strict verification
for both architectures and Gatekeeper acceptance pass, including ZIP round-trip.
All three executables and app/helper plists match the submitted source bytes;
validation-only remains true and ordinary recovery remains disabled.

The installed app, config files, public export and pending-bundle hashes are
unchanged. No install, host/helper launch, live XPC, token API, authentication,
vault/registration operation or key write occurred. No release was published.
Raw logs, transfer ZIP and `NOTARIZED-CANDIDATE.json` remain ignored under
`tmp/piv-recovery/signed-helper-preparation-2026-10-24/final/notarization/`.

Next is separately approved temporary Preview-only installation with a verified
original-app rollback copy and preserved pending records, followed by running
helper identity checks and noninteractive inspection. Pause before authentication.
Signed-helper native behavior and PIN/touch ordering remain untested.

## Earlier UX checkpoint: signed-helper candidate prepared only, 2026-10-24

A diagnostic-only universal build20 candidate is signed and packaged, but not
notarized, installed or run as a helper service. The normal Preview identities,
production XPC requirements, hardened runtime and exact helper entitlements are
retained. Its replacement CLI/helper do not link KeyCore or expose vault or
registration commands. The original host code is retained and re-signed; owned
signature-stripped copies match. Ordinary recovery gates are false and a separate
validation-only marker is required. This is not a public release or product UI.

Swift 6 warnings-as-errors builds, software core/boundary checks, signed help/
self-tests, ordinary-command and noninteractive staged-request refusal pass.
Repository signing/entitlement checks, both slices, deep strict verification and
ZIP round-trip pass. No live XPC, token query, authentication, agreement, finish,
key write or actual-vault operation was requested. Installed executable and
config/export/pending-bundle hashes are unchanged. No production source changed.

Use only `final/` under ignored
`tmp/piv-recovery/signed-helper-preparation-2026-10-24/`; earlier assemblies are
retained intermediate evidence. The review ZIP SHA-256 is
`19d48976263f5ecef9fd02ff73ef598f10b8f01015b272ea227b69fba508f012`.
Next is separately approved notarization/temporary Preview-only installation,
then running-helper identity checks and noninteractive inspection. Pause again
before any authenticated test. The diagnostic candidate disables normal Preview
commands; preserve a verified original app rollback copy and all pending records.

## Earlier UX checkpoint: second isolated staged test passed, 2026-10-24

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
