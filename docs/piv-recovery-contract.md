# PIV recovery contract

Experimental contract, updated 2026-10-26. The [plan](piv-recovery-plan.md) owns
implementation/acceptance status; the [qualification record](piv-recovery-signed-test.md)
owns observed results. This document defines the selected design and required
boundaries, not a frozen shipping format, hardware instruction or approval for
real-vault use. The [design AI review](piv-recovery-ai-review.md) retains its
historical findings and dispositions. Human expert review remains recommended;
the owner selected AI-reviewed experimental implementation.

## Experience and scope

An independently registered primary or backup token, PIN/touch and the available
encrypted vault files must restore supported current entries onto a replacement
Mac. No original Mac, checkpoint/cache, receipt, separate certificate file,
registration intent, management key or cloud escrow is recovery input. Fresh
destination Mac authentication is separate. Recovery preserves the source,
creates fresh vault authority and does not revoke old devices/copies. The new
vault has no recovery registration until separately registered.

Normal edits and supported key/device changes use stored public recipient keys
with the tokens put away. The target is one deliberate source private-key
approval per uninterrupted recovery attempt across key epochs. Explicit restart/
resume can require a new approval. No automatic authentication retry, alternate
epoch/key/algorithm, software fallback or weaker PIN/touch policy is allowed.
Application call counts and observed PIN/touch counts do not establish the
framework's internal hardware-attempt count.

Initial support policy is macOS 26+ recovery using an explicitly selected slot 9d
on-token P-256 credential, matching certificate and readable Yubico metadata
(firmware 5.3+), reported generated origin and PIN/touch `ALWAYS`. The target is one
registration per token and independently generated primary/backup private keys.
The qualified OS/token combinations are recorded separately; the support matrix
is not frozen. The package's ordinary macOS 14/profile-2 policy is unchanged.
Automatic provisioning, other slots/algorithms, multi-vault allocation, silent
same-vault takeover, arbitrary conflict selection and older-state salvage are
outside the initial scope.

## Security promise and limits

Recovery verifies token-anchored public hash commitments, both authority
signatures, allowed structural transitions and all selected current contents.
After opening the final key it checks its derived ID, required final-epoch MACs,
final capsule private/public correspondence, every selected entry's digest/
context/AEAD and payload semantics.

It does **not** independently replay closed-epoch MACs, old entry AEAD, old capsule
correspondence or every historical plaintext-preserving reseal. Ordinary
publication and catch-up retain those full checks. Dual public signatures do not
prove historical plaintext equality or stop a writer with both capabilities from
authorizing a semantically invalid transition.

A Mac-signing capability alone or epoch-signing capability alone cannot authorize
a new epoch. Both are software capabilities available to an authorized unlocked
Mac, not independent human factors. Retaining an exported epoch capability is not
proof of present vault-key possession.

Removal excludes a recipient from fresh keys on the legitimate continuing
lineage. Retained pre-removal dual capabilities can authorize an earlier-parent
alternative lineage, including different contents. Visible competing authority
requires refusal; a stable older anchor cannot identify a globally current
lineage when the provider hides its competitor. Old secrets/ciphertext cannot be
revoked retroactively.

Key refuses required missing objects, incomplete visible descendants, unsupported
states and unresolved visible conflicts. It never silently falls back to an older
complete snapshot. Provider delivery, backup retention and withheld newer files
remain external responsibilities. Public recovery/history metadata is observable.
Conservative refusal of malformed/unclassifiable objects can permit denial of
recovery through injected garbage; it does not supply provider freshness.

## Selected design

| Decision | Reason / retained limit |
|---|---|
| Integrated explicit manifest profile | Manifest already owns rosters, wrappers, entries and publication. A mutable sidecar needs another atomicity/authority linkage. Shipping profile 2 is unchanged. |
| Stable token-held registration anchor | Normal use must work with the token absent. Repinning every snapshot would require hardware writes during ordinary use. |
| Random protected epoch-signing key plus existing Mac signature | Strengthens public authority over the rejected signature-only chain. Random P-256 keys avoid introducing a scalar-derivation algorithm. |
| Current-key-only wrappers | New holders receive no old vault-key archive. Backward key links would grant historical decryption access. |
| Public history followed by one current-key opening | Keeps the source approval budget independent of epoch count, with the reduced historical replay promise above. Per-epoch opening remains the fuller-replay comparison baseline. |
| External administration | Owner-operated vendor tools provision credentials and install anchors. Key has no management writer; external import cannot be an atomic reviewed-state compare-and-write. |

The [design comparison tests](../Tests/KeyCoreTests/PIVRecoveryAuthorityDesignTests.swift)
show why signature-only current-key checks do not replace normal full reseal
validation. Established primitives do not prove this custom protocol composition:
[HKDF context guidance](https://www.rfc-editor.org/rfc/rfc5869.html#section-3.2),
[AEAD nonce requirements](https://www.rfc-editor.org/rfc/rfc5116.html#section-3.1),
[HPKE Base limits](https://www.rfc-editor.org/rfc/rfc9180.html#section-9.1) and
[MLS authentication distinctions](https://www.rfc-editor.org/rfc/rfc9420.html#section-16.5)
support their respective boundaries, not whole-protocol certification.

## Format and cryptographic binding

Outer manifest/envelope version 3 remains. Explicit `device-wrapped` profile 3
adds `epochAuthority` and `recovery`; profile 2 retains its own parser, validators
and bytes. No profile projection or auto-detection grants authority. Exact
experimental [schema](schemas/v3-recovery-manifest-body.schema.json), codecs and
canonical fixtures require review before release freeze.

### Capsule and epoch proof

[Capsule version 1](../Sources/KeyCore/V3EpochSigningKey.swift) protects a fresh
independent P-256 signing key with HKDF-SHA256 and AES-256-GCM. Require a 32-byte
vault key with matching derived key ID, valid uncompressed 65-byte public point
and 60-byte combined box (12-byte nonce, 32-byte private representation, 16-byte tag).
HKDF salt is vault-UUID bytes; fixed info is
`work.tvr.key/v3/epoch-signing-key-kek/v1`. Complete authenticated context binds
profile, vault/key/transition identity, algorithm/version and advertised public key.
Opening must validate the private representation and exact public correspondence.
Keep decrypted vault/epoch-key capabilities in operation-scoped memory; never
persist or export them. Encrypted wrappers/capsules are their durable forms.

Use separate entry-encryption and capsule key/nonce domains. Prepare one capsule
per fresh vault/signing-key pair, preserve exact bytes through edits and resume,
and use fresh epoch keys if the whole candidate must be prepared again. A
stateless cipher cannot enforce durable nonce budgets or detect key reuse;
usage/failure policy remains part of final review. Scoped closures cannot prevent
deliberate retention or guarantee Swift/CryptoKit memory zeroization.

The authority record has version 1, capsule and nullable `transitionProof`.
A null proof denotes a separately validated origin, not a continuing authority
change. A proof binds version/algorithm, exact parent-envelope digest and canonical
low-S signature. Reject cross-role reuse of epoch/recovery keys as Mac signing/
wrapping keys. Construct an authority boundary in this order:

1. Build the complete fresh key epoch: vault key, independent signing capsule,
   unchanged-plaintext resealed entries and all required device/recovery wrappers.
2. Sign the domain-separated canonical transition statement using the **parent**
   epoch key. The production projection omits only
   `epochAuthority.transitionProof.signature`, retaining the rest of candidate
   content, exact parent, new authority, rosters, wrappers and entry references.
   Its domain is `work.tvr.key/v3/epoch-transition-authorization/v1`, NUL delimiter,
   then canonical projected content.
3. Insert that proof; the existing active Mac signs finalized content with the
   normal manifest domain. Compute the MAC with the new vault key. The outer MAC
   tag is outside both signature inputs.
4. Independently check both signatures, old/new key identities and MACs, exact
   operation policy, new capsule correspondence, local wrapper opening and
   complete old/new same-plaintext resealing before publication.

Profile-2 adoption has no prior epoch key. It requires explicit local review,
old Mac signature, both MACs, full resealing and a fresh origin capsule. Initial
registration pins an exact fully validated profile-3 manifest; recovery starts
there, without claiming to audit pre-registration history.

### Recipients, wrappers and anchor

The [recipient roster](../Sources/KeyCore/V3RecoveryRecipients.swift) has record
version 1, a random generation UUID, canonically ordered recipients and wrappers.
Each recipient binds registration UUID, domain-separated public-key-derived ID,
validated P-256 point, slot 9d and active/revoked status. Credential IDs and
registrations are unique. Every active recipient has exactly one addressed current
wrapper; revoked/unknown recipients have none. Empty/all-revoked rosters are
structurally valid, not evidence of protection or permission to remove the last
recipient. Independent backup keys must differ.

[Recovery HPKE](../Sources/KeyCore/V3RecoveryVaultKeyHPKE.swift) uses Base mode,
P-256/SHA-256/AES-256-GCM (suite mode 0/KEM 16/KDF 1/AEAD 2). Context binds profile/suite,
vault/key/transition, generation, recipient, registration and slot. Separate
`work.tvr.key/v3/hpke-recovery-key-info/v1` and
`work.tvr.key/v3/hpke-recovery-key-aad/v1` labels are NUL-framed with canonical
context. Do not include the resulting envelope digest in its own wrapper context.
The signed/MACed manifest authenticates wrapper bytes. Check address and adapter
public key before agreement, then AEAD and recovered key ID. HPKE opening alone
is neither origin authentication nor snapshot verification.

The [anchor](../Sources/KeyCore/V3RecoveryAnchor.swift) pins format/version,
profile/suite, vault, recipient, registration, slot and exact
`registrationManifestDigest`. It is stored in application PIV object `0x5F4B59`,
not a standard object or certificate extension. Parsing provider JSON does not
establish token provenance. The registration manifest supplies the initial floor/
wrapper; later dual-authorized epoch roots supply current wrappers. No separately
retained registration receipt or permanent old-key capsule is recovery input.
A backup token starts at its own registration floor, not the primary's older one.

### Bounds and parsing

Require exact canonical fields/encodings, supported algorithms/versions, valid
points/lengths and canonical identifiers. Reject unknown/duplicate fields and
noncanonical encodings. Enforce budgets before decoding, native activation,
candidate signing/reservation and publication, with projected new objects included.

| Experimental bound | Limit / owner |
|---|---|
| Capsule and anchor encoded bytes | 1,024 each; separate codecs. |
| Recovery roster | 64 recipients/wrappers; 65,536 encoded bytes. |
| Public key metadata | 256 bytes; exact supported fields/P-256 representation. |
| Manifest | 2 MiB and canonical parser nesting bound. |
| Source graph | 4,096 objects; 1,024 depth; 16,384 entry references and 16,384 parent edges; existing per-object/aggregate-byte bounds. |
| Product/progress processing | 64 KiB public recovery request;1 KiB progress payload; token inventory at most 64 candidates. |

See [repository limits](../Sources/KeyCore/V3ImmutableObjectRepository.swift).
Nondigest directory names and required-but-unlisted objects consume object budget.
All reachable manifest entry references count even when old ciphertext is not
opened. These are resource limits, not promised product capacities or framework
allocation caps.

Ordinary publication, including automatic/manual merges, projects cumulative
history usage from the earliest still-active recipient's visible registration
floor. The latest Mac checkpoint or later backup registration cannot reset that
obligation. First registration excludes earlier history. At capacity refuse
before ownership/publication/checkpoint effects; no implicit anchor refresh,
rollover or limit increase.

## Anchored history and current snapshot

The [history selector](../Sources/KeyCore/V3RecoveryHistory.swift) hashes observed
manifests against exact object addresses and starts trust at the bound token
floor. Credential-derived ID, registration, slot and active floor record must
match. Follow all visible descendants and required parents, with iterative
bounded closure and no timestamp, filename or highest-revision winner. Traversal
stops at the exact anchor floor; missing objects below it cannot make a backup
credential depend on the primary token's earlier registration.

Same-epoch edges preserve exact authority/capsule/proof, rosters/wrappers and
vault/key/transition identities across every parent. Retained records keep the
highest unchanged parent revision or advance by one; new records begin at one;
deletion is permitted. Merges must share an epoch root. Inherited proof bytes
refer to that root, not a new signature on each edit.

A boundary has one exact parent, both authorizations, new visible key/transition/
epoch-public-key identities, continuing active signer, retained immutable roster
identities/tombstones and unchanged entry IDs/names/types/revisions. Recipient
authority changes replace generation; unchanged recipients retain it.
Publication still owns fresh randomness, ceremony-specific policy, wrapper opening
and same-plaintext resealing; public signatures cannot establish those by themselves.

Refuse competing content heads, competing authority lineages, closed-epoch
off-path heads not covered by signed commitments, and listed same-vault tips with
no available anchored path. Resolve same-epoch content before an authority change
from one checkpoint.
Known pre-floor ancestors and valid outer objects naming another vault can be
excluded without private replay/body-profile interpretation. Unreadable,
hash-invalid or malformed outer objects, or objects without usable vault identity,
cannot be declared unrelated and refuse even outside the reachable graph.
No hidden-file freshness guarantee follows.

The [snapshot verifier](../Sources/KeyCore/V3RecoverySnapshot.swift) reselects the
public plan before one final-epoch HPKE opening. It verifies recovered key ID,
final root MAC/capsule correspondence, required current-epoch MACs and every
selected entry's digest, context, AEAD, UTF-8/type semantics and canonical Base32
TOTP seed. Only selected current entry ciphertext is read; closed epochs are not
decrypted. Only complete verification constructs the verifier-only snapshot.
Public proof state must never become a MAC-trusted ordinary checkpoint.

Recheck source listing/manifests/current-entry bytes before return and immediately
before restore publication, with fresh native and physical-location checks.
A snapshot retains scoped plaintext, not the raw source vault key. Restore
accepts no caller-fabricated plaintext snapshot or archive diagnostic.

## Ordinary use and publication

[Unlock/read/runtime composition](../Sources/KeyCore/V3RecoveryVaultRuntime.swift)
starts from an exact local MAC-trusted checkpoint, not a recovery anchor or
provider-selected head. Cold access opens the addressed Mac wrapper and
authenticates MAC/capsule; warm access requires the matching live key and repeats
authentication. A mismatched session refuses without cold fallback/retry. Unlock
alone proves neither entry availability nor provider-current status.

A read context carries exact checkpoint and authentication-generation ticket,
not a key or reusable approval. Validate context before/after key lookup, after
decryption and against the observed source before returning values. Explicit
lock, expiry or same-key reauthentication invalidates old contexts. Failed access
clears resident state. Cache writes do not establish or undo checkpoint authority.
Ready encrypted-closure status is not AEAD opening of every entry or provider
freshness. Explicit stale permission admits content competition or transport
incompleteness only at the unchanged authenticated admission floor. Missing
ciphertext may permit a last-trusted names-only list; invalid objects or exceeded
budgets refuse even that list. Missing entry plaintext is never returned.
Invalidity, source changes, authority competition, revocation, budget
or pending/session failures never yield stale success. No rollback after an
authenticated checkpoint advance.

Same-epoch catch-up authenticates MAC/capsule, unchanged authority, revision
progress and complete required snapshots before checkpoint CAS. A resolved fork
advances its common join without first checkpointing either branch. Retain the
operation's original floor and source observation to detect late siblings.
A later call can reconstruct exact checkpoint-committed same-epoch ancestry to
explain a late co-parent; it must not rewind trust or reopen old committed
ciphertext solely for comparison. Required manifests and current/new/unselected
branch snapshots still authenticate. Unrelated/missing required ancestry refuses.
Step budgets preserve accepted prefixes but do not claim terminal success.

Branch comparison uses the authenticated DAG and nearest common base. Multiple
nearest bases remain history conflict; neither automatic nor explicit-entry
resolution may choose an arbitrary base. Shared entry policy preserves independent
stable-ID edits; edit/delete/rename/collision ambiguity remains explicit, including
different ciphertext for equal plaintext. Complete exact-head conflict/version
choices are required; selectors are not file addresses or reusable consent.
Automatic merge retains selected immutable ciphertext without resealing.
Resolution reseals selected conflicted values at one revision above every parent
version (overflow refuses); selected deletion stays absent. Destination-name
choices retain the chosen record and remove only reported colliding identities.
New collisions refuse. Merge candidates preserve all authority and sorted exact
parents. Same-epoch edits/merges have no fresh outer device authorization; the MAC
protects new content and inherited epoch proof stays exact. Conflict-value reads revalidate the
sealed selection, full head set, ciphertext and session/source state, without
stale fallback.

[Mutation](../Sources/KeyCore/V3RecoveryVaultMutationService.swift) uses the
helper's existing mutation owner and exact live key, without nested serialization,
token calls or private identity operations. Authenticate the full before/after
snapshots and allowed add/edit/copy/move/remove/merge/resolve deltas. Copy must match
a retained unchanged source of the same type; move preserves its source payload.
Changed authority is never an ordinary edit.
An automatic merge commits under its own operation ID before a requested save is
freshly planned; save failure does not undo that merge.

All publishers reuse the immutable transaction kernel: pin exact intent before
staging, publish/reopen/synchronize entries before the manifest, then advance the
checkpoint by exact CAS and clean up ownership. Recheck source inventory,
checkpoint, session and all competing ownership at effect boundaries. Only the
candidate's exact own published bytes can be excluded from head discovery, while
still counting in budgets; other branches/children cannot be hidden.

Resume only the locally pinned operation's exact encrypted bytes, never regenerate
an edit/epoch. Before commitment require the appropriate complete source/parent
snapshots and full policy validation. Missing unpublished staging may be safely
abandoned at the exact old floor; a published manifest missing references retains
ownership and refuses. After exact commitment, cleanup authenticates current
MAC/capsule, complete snapshot and pinned bytes without obsolete keys/ciphertext/
cache. Never overwrite competing pins/checkpoints or roll back committed trust.

Merge intent version 3 binds sorted heads and bounded sorted conflict selectors;
empty selectors mean automatic merge. Ordinary content version 1 and enrollment
version 2 retain their own shapes. Lifecycle kinds include `rotateVaultKey`,
`revokeDevice` and `removeRecoveryRecipient`. Explicit dispatch rejects another
kind/profile before checkpoint-based abandonment, including exact routed-anchor
checks for unarmed work. Provider intent files alone grant no resume authority.

## Authority lifecycle

All authority changes require an authenticated active Mac and exact reviewed
checkpoint/decision. Preparation authenticates without signing, generating a key,
reserving work or saving approval. Execution rechecks the decision, then generates
fresh epoch material and uses its dedicated independent policy validator. Every
new key/device/recipient-authority boundary rotates both vault and epoch-signing
keys and reseals all current entries; exact resume preserves that candidate.

| Operation | Exact policy |
|---|---|
| Key rotation | Preserve all device/recipient identities/statuses, generation and entry metadata/plaintexts; replace vault key, transition ID, epoch key/capsule and active wrappers. |
| Compared device enrollment | Add one new active identity from exact signed inviter/joiner comparison, role, phase, expiry and transcript-derived transition ID. Refuse identity/key reuse. Preserve old records/recipients/generation; rotate and reseal. |
| Joining-Mac adoption | Require exact local joining messages and explicitly compared digest, sole matching direct enrollment, public boundary policy and complete current authentication. Insert-only local checkpoint precedes consumed-ceremony bookkeeping and guarded session installation. No configuration selection or implicit catch-up. |
| Device revocation | Reconstruct one other active Mac becoming revoked; no self/unknown/already-revoked/last-active removal. Preserve identities/tombstones, recipients/generation and approving-Mac access; rotate and omit revoked wrappers. |
| Recipient addition | Possession-verified registration adds the exact independently keyed recipient and its own anchor floor. Fresh epoch/generation and complete active coverage; no primary-token/private-state dependency. |
| Recipient removal | One active recipient becomes a tombstone retaining public identity/registration/slot; other recipients/Macs stay exact. Replace vault/epoch keys and recovery generation, reseal unchanged contents and omit removed wrapper. Never clear its external anchor. |
| Last-recipient removal | Also require informed loss-of-protection acknowledgment bound to the entire reviewed plan before randomness/signing/private work/reservation. An in-memory acknowledgment is not evidence that UI ran or general override consent. |
| Profile adoption | Exact reviewed profile 2 to profile 3 migration, preserved Mac roster/entry metadata, fresh epoch, empty recovery roster and null origin proof; old signature, both MACs, full reseal and new local wrapper check. Adoption alone is not protection. |

Every active resulting device/recipient gets exactly one current wrapper; revoked
records get none. New holders get no historical vault-key archive. Full old/new
authentication, metadata/policy and plaintext equality precede addressed local
wrapper verification, followed by fresh source/session/ownership checks before
reservation. Token-free rotation/device/removal construction uses public keys,
not recovery-token agreement.

Enrollment publication additionally pins exact local signed ceremony/transcript
bytes. Fresh approval must be unexpired/awaiting comparison; owned exact restart
can finish after expiry without a new comparison, signature or epoch. Consume the
exact inviter ceremony after authenticated commitment while the pin remains;
marker failure retains ownership, and consumed-marker cleanup is idempotent.
Joining trust is nil-or-exact only and cannot substitute a later/competing epoch.

Initial and interrupted authority services bind authentication tickets before
loading keys. Lock, expiry or reauthentication with the same old key is a different
session. Authenticate exact committed current state and absent-or-exact committed
ownership before atomic session installation. An initial error retains the old
session only while its reviewed checkpoint remains exact; otherwise lock. Restart
errors lock. Cleanup failure permits current-session installation only under its
exact committed intent, which still blocks new work. No error installs a key,
deletes another operation or reverses trust.

The internal [lifecycle context](../Sources/KeyCore/V3RecoveryLifecycleContext.swift)
owns current-state authentication, post-approval revalidation and committed-session
installation for rotation, access changes and enrollment. It retains the supplied
session generation and checks stable checkpoint/ownership around full current
snapshot verification. Services still own their reviewed approval policies and
exact retained-intent checks; those checks run even when cleanup has removed the
transaction pin. Exact restart selection, publication and failure handling remain
with the individual services. The context performs no private operation or retry.

Cold uncommitted epoch restart opens old then new addressed Mac wrappers, checking
each before the next and retaining full old/new comparison. Cold committed cleanup
needs only the new/current key; exact warm keys avoid corresponding openings.
These two/one/one/zero software budgets are not physical Mac prompt guarantees.
Restart does not renew approval, regenerate/sign/rewrap or contact a token.
Nothing pending is not a general cold unlock.

[Key-transition catch-up](../Sources/KeyCore/V3RecoveryKeyTransitionCatchUpService.swift)
validates published rotation/enrollment/revocation/recipient policies without
renewing the original ceremonies. Refuse combined unrelated changes, identity
substitution, reactivation, missing tombstones and visible authority/closed-epoch
competition. A visibly revoked Mac refuses before private opening. Each step opens
only its addressed next wrapper, authenticates full boundary plaintext equality
and selected epoch snapshots, then commits that epoch root. Later epochs remain
publicly checked until opened by separate steps; all required forward ciphertext
must be available. It does not claim latest state after one step.

The [mixed coordinator](../Sources/KeyCore/V3RecoveryCatchUpCoordinator.swift)
holds one mutation owner, initial source/floor key only for that operation and
generation-continuation receipts through every committed step and final return.
Unrelated new session generations cannot be adopted. Changed source, pending work,
budget exhaustion or cancellation locks without undoing committed prefixes.
A terminal head at the exact step bound succeeds. Current means the unique head
of the unchanged observed source, never provider-global freshness.

## Registration and protected external setup

### Owner operated setup boundary

All credential provisioning and anchor installation stay in owner-run supported
vendor tools. Key must not collect PIN/PUK/management credentials, invoke an
importer, provide management-writing hooks, reset PIV or regenerate an occupied
credential. Ordinary possession uses the macOS provider. An incompatible occupied
slot refuses; changing PIN/touch policy requires another generated/imported key,
not an in-place policy toggle on a registered key. See Yubico's
[policy guide](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html).

Before real registration, require a vendor-generated random nondefault AES
management key with management touch. Prefer vendor PIN-protected storage;
device plus PIN can then authorize administration, not an independent human
factor. Offline management-key custody is an alternative backup obligation.
Neither choice changes recovery inputs. Public metadata cannot prove randomness,
custody, protected storage, generated-key attestation or actual PIN/touch
enforcement. Reported generated origin is not independent proof a key was never
copied. Supported vendor references:
[PIV CLI](https://docs.yubico.com/software/yubikey/tools/ykman/PIV_Commands.html),
[application objects](https://docs.yubico.com/yesdk/users-manual/application-piv/get-and-put-data.html).

Management changes affect the PIV application, not only slot 9d, and require
exact-scope owner approval. Keep credentials out of arguments, environment, Key/
XPC, logs and repository/provider files. Vendor generation without protected
storage may print a key; never capture it as evidence. Owner PIN/PUK backup and
vendor PIN-unblock guidance remain separate. Never deliberately exhaust attempts,
change retry limits or propose reset/regeneration as a forgotten-PIN shortcut.

### Prepare, external import, finish

1. Authenticate the complete current vault/checkpoint and exact active approving
   Mac. Bind compatible credential and **absent** application-object occupancy.
   Even recognized occupied anchors need separate reconciliation/replacement;
   no silent takeover or overwrite.
2. Prepare one exact dual-authorized, fully resealed candidate and authenticated
   intent. The intent binds parent/owner/candidate/recipient/anchor/staged addresses.
   Pin a complete canonical encrypted bundle in a separate nonsync local namespace:
   reserve before atomic no-overwrite install, synchronize/read back exact file/
   directory bytes, then promote recoverable ownership. Only then export its
   exact public anchor. Staging is not a current manifest or saved approval.
3. Owner independently runs the reviewed vendor import with explicit device/object
   selection and private credential entry. Key may display reviewed nonsecret
   instructions but cannot run them. Vendor import is unconditional: preflight/
   readback cannot prevent an intervening overwrite. App exclusion does not
   serialize other clients. No atomic prior-state preservation is promised.
4. Discard old native observations. Finish freshly reselects the token, checks
   exact installed anchor and authenticates the same intent/parent/candidate,
   both authorizations, MAC/capsule, full same-plaintext snapshots and local
   candidate wrapper. Then request one candidate recovery opening to prove
   possession. An installed anchor alone is pending registration, not protection.
5. Recheck source/checkpoint/token/pending state, publish entries then activation
   manifest, read back exact bytes and advance checkpoint. Authenticate committed
   state before session installation and ownership cleanup. Retain encrypted
   preparation as inert audit evidence.

Resume follows exact locally owned bytes, not synchronized-file discovery.
Repeat intent and full snapshot authentication under fresh Mac keys; do not
regenerate/rebase, restore old token bytes or auto-repeat an uncertain vendor write.
An incomplete reservation or missing/changed bundle remains attention-required.
Before checkpoint commitment require fresh possession even if the candidate is
already published. After exact commitment, reconcile authenticated current
session/ownership without another hardware approval/publication. A lost reply
after cleanup can recognize only an existing exact local checkpoint with matching
token floor and authenticated recipient; token/provider files cannot create trust.

Authenticated status is `unregistered`, `pending`, `registered` or
`attention-required`. Stored coverage is not present possession, anchor integrity,
protected administration, backup availability, PIN/touch enforcement or freshness.
Inspection rechecks source/checkpoint/ownership and cannot open a candidate
wrapper, repair a session or promote a provider head. Ambiguity never means empty
or protected. Configured authenticated status/health can request Mac approval;
public review and pending selectors are separate nonauthenticating operations.

## Restore, durable ownership and exact resume

### Publication and activation

1. Independently open supplied source and destination-parent handles. Require an
   unconfigured product and missing final destination, including no empty folder,
   file/link or dangling configuration. Reject physical source/config/destination
   overlap, symlink ancestry, replaced identities and reserved metadata-name
   aliases/case variants. Retain paths plus device/file identity.
2. Initial workflow may prepare bounded 0700 local metadata directories below the
   existing home with nofollow parent-relative creation, synchronization and
   identity/scope checks. It creates no selected config, ownership, credentials
   or restored vault. Factory construction alone performs no I/O. Resume creates
   no missing roots or destination.
3. Resolve exact token/recipient and freshly validate reader-issued observation,
   source graph and scope. Close public card sessions before private operations.
   Authenticate the complete source snapshot through one scoped agreement.
   Revalidate source/native state; only then create the missing destination.
4. Durably pin a public reservation before creating fresh Mac credentials. It
   binds operation, source/head/anchor/history commitment, physical locations and
   fresh destination vault/transition/entry identities. Reopen the persisted Mac
   identity and independently verify the prepared wrapper. A reservation grants
   no right to regenerate credentials.
5. Stage complete encrypted preparation: authenticated restore intent, exact fresh
   permanent genesis and all encrypted entries. Restore-only HKDF/HMAC context is
   keyed by the destination key, never the source key. New vault/key/transition/
   device/entry IDs and signing/wrapping keys cannot reuse source authority.
   Destination has revision-one entries, no source ancestry/capsule/registration,
   and exactly equal entry names/types/plaintext bytes. Unicode-equivalent but
   byte-different secrets are unequal.
6. Confirm local ownership and complete preparation before publication. Verify
   saved destination wrapper in a temporary session. Install/read back/synchronize
   entries before the exact genesis manifest with contained no-overwrite writes.
   While manifest is absent, only subsets of owned object addresses and known
   empty interrupted directories are allowed. Unknown files, links, extra objects
   or orphan partial files refuse without cleanup.
7. Reconfirm complete published objects and saved wrapper before insert-only
   checkpoint trust and exact encrypted cache. Existing trust must be absent or
   exact; config cannot reconstruct missing trust. Invalidate preparation sessions.
   Independently load destination Mac credentials into a new empty ordinary
   runtime, open its wrapper and compare every plaintext/type/name; never inject
   the prepared key.
8. Only after fresh ordinary verification, atomically select no-overwrite normal
   config and recheck source/ownership/files/cache/trust. Finalization performs
   fresh ordinary reopening again, then CAS-removes reservation ownership **before**
   preparation ownership, with checks around each boundary. Encrypted files and
   credentials remain; final report contains public IDs/path/count, not secrets
   or reusable approval.

The [journal](../Sources/KeyCore/V3RecoveryRestoreJournal.swift) keeps separate
nonsync reservation/preparation pins keyed by the source vault ID. Each pins exact
canonical bytes by digest; files are under
`v3-restore-attempts/<operationID>/reservation.json` and `preparation.json`.
Select only the locally pinned operation, never scan files or follow JSON paths.
Missing, changed, oversized or symlinked records refuse. Files without ownership
are inert. Local synchronization is not cloud upload or remote durability.

### Resume and completion

Explicit resume requires complete exact owned preparation before agreement;
reservation-only state is insufficient. Reauthenticate source and saved destination
identity/wrapper, intent and full saved snapshot. Never generate another key,
credential, ciphertext, ID or directory. Source selection, path identities,
config root and expected checkpoint/cache must remain exact.

Before manifest publication, resume may install missing owned entries. Once the
exact manifest exists, every referenced entry must already have exact prepared
bytes; do not repair committed damage. Selected completion requires byte-exact
config, existing exact trust/cache and fresh complete reopening, and skips
publication/selection. Formatting changes or later ordinary edits are not adopted
as this exact-genesis completion.

Reservation-first cleanup leaves the complete-bundle digest available if
interrupted. Preparation-only ownership permits only dedicated selected completion
with existing trust, never normal preparation/publication/selection. Reconstruct
public reservation bytes exactly from the pinned bundle, not new authority.
With both pins absent, return no locally owned pending attempt; leftover files
cannot prove retrospective success after a lost reply. Inspect ordinary configured
status instead. Failures preserve committed trust/config and exact evidence;
no rollback or automatic retry.

### Explicit abandonment before complete restore preparation

`recovery abandon` requires original explicit source/destination, source vault ID
and operation ID, unconfigured state, exact local reservation and physical paths,
empty destination and absence of both preparation pin and any preparation
directory entry. Absence requires nofollow `fstatat` returning `ENOENT`, not a
broader unavailable classification. Links/placeholders/directories, invalid/
missing evidence, selected config or destination data refuse.

Under host/mutation barriers remove only the exact reservation pin by CAS.
Keep source, destination folder, reservation file and Mac credentials. No token
inventory/read, authentication, publication, trust or selection. A later restore
must choose a new missing destination. Complete preparation requires authenticated
resume; changed/missing state needs inspection. Automatic cleanup or reconstruction
from reservation-only state is not supported. Lost reply/shutdown ambiguity does
not authorize repeating abandonment or claiming successful recovery.

## Native token and authentication boundary

The [reader](../Sources/KeyCore/PIVRecoveryTokenReader.swift) binds one retained
native card connection; removal/reinsertion cannot silently substitute a same-named
reader. Inventory sends no card commands. Public read has only four expressible
commands: select PIV; GET DATA for slot 9d certificate; GET METADATA for slot 9d; GET DATA application
object `0x5F4B59`. There is no raw APDU, PIN/management authentication, write,
reset or private-operation interface. Certificate and metadata P-256 points must
match; a recognized anchor must match credential identity. Certificate is a
public-key container, not issuer/expiry/attestation authority or separate receipt.

Absent, recognized and unrecognized anchor occupancy are distinct. Unknown bytes
are withheld; an internal digest supports exact revalidation. Only anchor GET
accepts absent-object status `0x6a82` with nil/empty data. Success plus native error
is failure. Diagnostics retain fixed command step/reason, reported status (or
not-reported for zero) and allowlisted native domain/category/code, never response
bytes, native descriptions/userInfo/nested payloads or token identifiers.
Malformed/unsupported metadata refuses with no certificate-only fallback.

The [agreement adapter](../Sources/KeyCore/PIVRecoveryAgreement.swift) is scoped
and one-use; construction performs no lookup/authentication. A shared lease spans
fresh public revalidation, noninteractive exact token-ID/application-label key
lookup, independent handle validation, another public revalidation, authentication/
ECDH and final public revalidation. Public sessions close before provider work.
Require exactly one private EC 256-bit handle matching actual token/public point/type/
size and standard ECDH support; application label alone is not identity proof.
No private key export, alternative key or retry. Require reported generated origin
and explicit PIN/touch `ALWAYS`; DEFAULT/ONCE/NEVER, biometric alternatives,
cached touch and imported origin are outside this support policy, not a general
judgment that every vendor alternative is unsafe.

### Staged approval and request-scoped presentation

Obtain the selected key's actual `SecAccessControl`; missing ACL fails closed.
Evaluate `.useKeyKeyExchange` through the lookup's `LAContext`, then set
`interactionNotAllowed` before admitting exchange. Do not construct a replacement
ACL, inject a PIN credential or treat `isCredentialSet` as proof of approval.
Only actual successful ACL completion admits touch progress and the one exchange.

The helper owns a native Cancel-only touch window with no PIN field, shown after
ACL approval and closed after exchange/termination. Cancel invalidates that
connection's scope. It is a cue, not a touch sensor, timer or credential dialog.
AppKit accessory activation/event loop, completed alert layout and visible
nonmodal presentation keep UI with native execution without another privileged
prompt service. The [touch prompt](../Sources/KeyLaunchAgentHelper/KeyRecoveryTouchPrompt.swift)
owns presentation, not authorization.

Progress binds ephemeral UUID and enum only: authentication, touch, hardware
completion, Mac preparation/reopen, complete encrypted preparation saved,
publication and activation. The sequence is bounded/acyclic with explicit initial/
resume/selected-completion branches. Saved-preparation progress follows complete
durability, never reservation alone. Mac reasons distinguish Prepare, Reopen saved
preparation and Publish; further activation checks may prompt. No fixed Mac
prompt count is promised. Progress is not persisted authority or final success.

Use the existing mutually authenticated full-CLI XPC connection, additive progress
selector and exported callbacks. Only restore/resume and registration finish use
hardware progress; utility callers remain status/lock-only. One such request per
connection runs off the delivery queue so cancellation can arrive. Validate UUID,
stage order, size and closure; discard duplicate/unknown/late messages. Callbacks
run only on the sending thread, stderr-only, and never after send returns.
Older hardware clients refuse before dispatch; no fallback selector after uncertain
reply. Deploy matching CLI/helper bundles. Local abandonment uses the ordinary
selector without hardware progress. These are wire/presentation changes, not
vault-format or config changes.

### Cancellation, lifetime and known UI limitation

Scope closure, lock, expiry, deadline and disconnect permanently stop the attempt.
Late positive/duplicate results cannot revive approval, start a new touch/agreement
step, install authority or publish. An already admitted native operation may
finish, but its stopped result is discarded. No automatic retry.

The host deadline is 90 seconds including queue time; client reply bound 120 seconds. The agreement
scope's standalone default is 60 seconds; composed requests pass their existing deadline.
These bounds stop caller waiting, not guaranteed native execution. Retain the
worker/key/context and shared native gate until the actual framework callback/
provider return and cleanup, including pending public begin/send callbacks.
Context invalidation is idempotent; never synthesize a framework reply to release
the native waiter/lease. If it never replies, the gate remains busy.

A real ACL `appCancel` callback still does not prove a separately hosted PIN UI
closed or all downstream interactions ended. Helper exit does not prove that
either. The tested macOS PIV dialog can remain after cancellation/deadline. The
owner accepted manual dismissal for Preview; automatic dismissal remains
unqualified. Cancel leftover PIN UI **without entering a PIN** before another
token use or postcheck. A late PIN can still be processed by macOS, including
consuming an incorrect-PIN attempt, despite Key refusing to resume. No private
API, provider termination or direct-operation production workaround is selected.

Native lifecycle logging uses the bundle subsystem/`PIVAuthentication`, fixed
evaluation/invalidation/callback labels, success/error/domain booleans and numeric
code only. No native error text/userInfo, credential/token/key identifier, peer
point, secret or vault path. Logs/callbacks are not UI-closure evidence.
[Qualification](piv-recovery-signed-test.md#known-limits) separates observed refusal,
manual dismissal and unexercised native late-positive races.

## Product admission, sessions and compatibility

The helper owns one mutation queue and source/destination/config barriers.
Token exclusion supplements, not replaces, these owners and cannot serialize
external vendor tools. Recheck exact source, checkpoint, ownership and session
before/after private calls, durable effects, installation and return. Filesystem
observations are not globally atomic locks against provider/external changes.

Ordinary transaction, registration and adoption namespaces reciprocally block
competing work; unreadable/malformed state is not absence. Dedicated pending
authentication selects the exact owned kind and cannot be passed to normal
readers. Process-local, store-bound tickets/receipts are neither keys nor consent;
they are not persisted or sent through IPC. Legitimate epoch installation
returns a continuation receipt, not permission to capture an unrelated new
generation. Lock stays independent of serialization/native UI. Durable effects
are retained when lock makes a late success invalid.

Host admits at most one active/pending recovery request; concurrent clients
refuse immediately. Public review uses read admission so lock can reach a resident
configured session even with setup queued behind review. Lock invalidates generation
and registered connection scopes out-of-band. A closed connection also cancels
scopes registered later on it; it cannot cancel another client's scope.
Hardware requests accept only public bounded selectors/paths, not credentials,
reader observations, keys or consent. Resolve explicit paths from one captured
working directory; reject repeated/malformed options before dispatch. Restore
requires name; resume cannot replace it. Recipient ID is not a certificate hash.

After restore entry, process-local uncertainty blocks competing setup/config.
Config present on any exit requires the existing helper shutdown/restart handshake,
including ambiguous failure. Restart-persistent admission pairs recovery dispatch
with a native ownership inspector: two nonsync, noninteractive existence queries
for reservation/preparation namespaces, no returned data/account enumeration.
Only two not-found results mean absence. Either pin or any uncertain error blocks
init, directory enrollment, vault-dir change and cold configured runtime admission.
Lock and unconfigured locked status remain available; explicit exact resume has
its own validation. Presence is refusal evidence, not validated pending authority.

Public tokens/credential/source review never authenticates, reads entry objects,
saves attempts/consent, chooses config or proves possession/restorable contents.
Results say `public-observation-only`. `recovery pending` lists at most the bounded
local transaction/registration/adoption selectors; it authenticates nothing and
cannot activate a token. Public review can inspect a source while the Mac is
configured or has a saved attempt; it does not inspect local ownership or grant
setup/ordinary-runtime authority. The actual resuming service checks ownership, kind and
contents. Configured health/status may authenticate with Mac credentials.

Adoption is explicit, signed, key-rotating profile 2 to profile 3 conversion. Upgrade all
participating Macs first. Unsupported clients must refuse before writing a sibling,
including when stale reads were requested. Concurrent conversions/authority changes
are conflicts. Source-level old-client refusal evidence is not released-binary
qualification. Rollback is an explicit retained older snapshot under compatible
software, not in-place downgrade retaining new-format edits or undoing remote
adoption. Never delete ordinary config, Keychain state or source on upgrade.

Adoption pins one complete encrypted preparation in its own nonsync namespace,
reserved unarmed before atomic install and promoted only after exact readback/
synchronization. Resume authenticates exact bytes without new signing/randomness.
Manifest-last/checkpoint-last commitment precedes session install/cleanup.
Only exact unarmed abandonment is permitted; recoverable ownership is retained.
Committed reconciliation authenticates current state without old ciphertext or
republishing. Files without pins cannot create ownership/checkpoint authority.

The gated Preview CLI includes public review, registration status/prepare/
resume-export/finish, pending selectors, adoption/rotation with exact resume,
restore/resume and incomplete-reservation abandonment. Broader recipient/device
flows retain separate integration/qualification gates. Shipping plists keep
recovery disabled; qualified real-vault adoption and publication remain explicit.
No PIN, PUK, management credential or raw vault/epoch key crosses CLI/XPC or logs.
Restore results expose public metadata only; ordinary entry I/O retains its
existing explicit data-handling boundary.

## Implementation and review map

Exact codecs and tests are the byte-level reference, not duplicated JSON examples
or historical increment notes. A parser, builder, review result or saved plan
alone never grants publication, native activation or checkpoint authority.

| Boundary | Primary implementation | Representative verification |
|---|---|---|
| Profile/capsule/proof | [Manifest](../Sources/KeyCore/V3RecoveryManifest.swift), [capsule](../Sources/KeyCore/V3EpochSigningKey.swift), [boundary](../Sources/KeyCore/V3RecoveryEpochBoundary.swift) | [Manifest fixtures](../Tests/KeyCoreTests/V3RecoveryManifestTests.swift), [capsule tests](../Tests/KeyCoreTests/V3EpochSigningKeyTests.swift), design AI review. |
| Recipients/anchor/HPKE | [Roster](../Sources/KeyCore/V3RecoveryRecipients.swift), [anchor](../Sources/KeyCore/V3RecoveryAnchor.swift), [context](../Sources/KeyCore/V3RecoveryVaultKeyHPKE.swift) | [HPKE tests](../Tests/KeyCoreTests/V3RecoveryVaultKeyHPKETests.swift), exact codec fixtures. |
| History/snapshot/budgets | [History](../Sources/KeyCore/V3RecoveryHistory.swift), [snapshot](../Sources/KeyCore/V3RecoverySnapshot.swift) | [Publication budgets](../Tests/KeyCoreTests/V3RecoveryPublicationBudgetTests.swift), graph/snapshot tests. |
| Ordinary state/conflicts | [Runtime](../Sources/KeyCore/V3RecoveryVaultRuntime.swift), [mutation](../Sources/KeyCore/V3RecoveryVaultMutationService.swift), [merge publisher](../Sources/KeyCore/V3RecoveryMergeMutationPublisher.swift) | [Mutation tests](../Tests/KeyCoreTests/V3RecoveryVaultMutationServiceTests.swift), [conflict reads](../Tests/KeyCoreTests/V3RecoveryConflictReadTests.swift). |
| Authority policy/services | [Rotation](../Sources/KeyCore/V3RecoveryKeyRotationService.swift), [enrollment](../Sources/KeyCore/V3RecoveryEnrollmentOwnerService.swift), [revocation/removal](../Sources/KeyCore/V3RecoveryAuthorityChangeService.swift), [catch-up](../Sources/KeyCore/V3RecoveryCatchUpCoordinator.swift) | [Lifecycle composition](../Tests/KeyCoreTests/V3RecoveryLifecycleIntegrationTests.swift) and dedicated publisher/restart suites. |
| Setup/adoption | [Registration](../Sources/KeyCore/V3RecoveryRegistrationService.swift), [adoption](../Sources/KeyCore/V3RecoveryAdoptionService.swift) | Registration/status/journal/adoption suites and scoped signed setup evidence. |
| Restore durability | [Service](../Sources/KeyCore/V3RecoveryRestoreService.swift), [journal](../Sources/KeyCore/V3RecoveryRestoreJournal.swift), [finalizer](../Sources/KeyCore/V3RecoveryRestoreFinalizer.swift) | [Completion tests](../Tests/KeyCoreTests/V3RecoveryRestoreCompletionServiceTests.swift), publisher/trust/selection/workflow suites. |
| Native/XPC/presentation | [Reader](../Sources/KeyCore/PIVRecoveryTokenReader.swift), [agreement](../Sources/KeyCore/PIVRecoveryAgreement.swift), [host](../Sources/KeyCore/KeyServiceHost.swift) | [Agreement](../Tests/KeyCoreTests/PIVRecoveryAgreementTests.swift), [routing](../Tests/KeyCoreTests/KeyRecoveryRoutingTests.swift), [progress/XPC](../Tests/KeyCoreTests/RecoveryProgressXPCTests.swift), signed qualification. |

See the [remaining acceptance matrix](piv-recovery-plan.md#remaining-acceptance-matrix)
for release gates. Software fixtures, AI review, normal signatures or notarization
alone do not qualify physical policy enforcement, all lifecycle/platform paths,
independent backup hardware, complete protocol security or real-vault rollout.
