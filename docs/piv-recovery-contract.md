# PIV recovery contract

Experimental implementation direction, 2026-10-04. The
[implementation plan](piv-recovery-plan.md) owns package status; the
[AI review](piv-recovery-ai-review.md) records findings and accepted limits.
This is not the shipping storage specification, a frozen encoding, a hardware
instruction, or qualification for real-vault activation. The owner authorized
AI-reviewed experimental implementation. Human expert review remains welcome.

## Experience and scope

Either independently registered primary or backup token, its PIN/touch approval,
and the available encrypted vault files must restore supported current entries
onto a replacement Mac. No original Mac, checkpoint/cache, receipt, separate
certificate file, registration intent, management key, or cloud escrow is
recovery input. Normal edits and key/device changes work with the token stored
away. Local Mac authentication for fresh destination credentials is separate.

Recovery creates a new vault, preserves its source, and does not revoke old
devices or erase old ciphertext. The destination is unprotected by recovery
until separately registered. Reusing a token requires explicit review of its
existing anchor, not silent overwrite.

The design target is one deliberate private-key operation per uninterrupted
source-recovery attempt, independent of the number of key changes. Do not lower
PIN/touch policy, rely on unqualified caching, export the token private key,
or add a guessable secret to achieve it. A restarted or explicitly resumed
attempt may require a new approval. The integrated operation count is unqualified.

Initial proposed scope: macOS 26+ recovery, existing on-token P-256 credentials
in explicitly selected slot 9d with readable Yubico metadata (firmware 5.3+),
reported generated origin and explicit PIN/touch `ALWAYS`, one registration per token, and independent
primary/backup tokens. YubiKey 5C NFC is the tested model; the supported OS/token
matrix is not frozen. Ordinary profile-2 support retains its platform policy.
Automatic provisioning, other slots/algorithms, multi-vault allocation,
same-vault takeover, arbitrary conflict selection, and older-state salvage
are outside the initial scope.

## Security promise and limits

Recovery authenticates token-anchored public hash commitments, both authority
signatures, allowed structural transitions, and all selected current contents.
After opening the final vault key, it verifies the key ID, required final-epoch
MACs, final capsule private/public correspondence, every selected entry's
digest/context/AEAD, and payload semantics.

Recovery does not independently replay closed-epoch MACs, old entry AEAD,
old capsule correspondence, or every historical plaintext-preserving reseal.
It is not security-equivalent to full historical replay. Normal publication and
catch-up retain those full checks. Two public signatures do not establish
historical plaintext equality or prevent a fully authorized writer from making
a semantically invalid change.

A device-signing capability alone or epoch-signing capability alone cannot
authorize a new epoch. Both are software capabilities on an authorized unlocked
Mac, not independent human factors. Retaining an exported epoch capability is
not proof of present vault-key possession.

Removal excludes a recipient from fresh keys on the legitimate continuing
lineage. Retained pre-removal dual capabilities can authorize an alternative
earlier-parent lineage, including different contents. Visible competing
authority lineages require refusal; a stable older anchor cannot identify the
globally current lineage if the provider hides its competitor. Old captured
secrets/ciphertext cannot be retroactively revoked.

Provider delivery and backup retention are external responsibilities. Key
refuses required missing objects, incomplete visible descendants, unsupported
states, and visible unresolved conflicts. It never silently falls back to an
older complete snapshot. It cannot prove that the provider disclosed the latest
state. Public recovery/history metadata is observable.

## Design choices

An integrated new manifest profile keeps rosters, wrappers, entries, and
publication under existing authority. A sidecar would add another atomicity
and authority linkage. A stable registration anchor permits token-free normal
use; repinning every snapshot does not.

Opening every historical epoch would support fuller replay but requires one
hardware operation per traversed epoch. Backward key links or historical-key
archives could allow one opening but give new holders access to old decryption
keys. Neither is selected. A signature-only chain was rejected after the
[design comparison tests](../Tests/KeyCoreTests/PIVRecoveryAuthorityDesignTests.swift):
public/current-key checks accepted a changed-value rotation that the ordinary
full validator rejected. The selected dual-capability design strengthens
authority while retaining the historical limits above.

## Concrete dual authorization candidate

In plain terms, a key change must carry both the Mac's approval and an approval
from a capability unlocked with the old vault key. Recovery checks these public
approvals through the committed history, then asks the YubiKey to open only the
current vault key. The extra signature is software work inside the existing
approved key-change operation, not another PIN/touch prompt or independent
hardware factor. Normal content edits keep their current MAC-only workflow.

Compare two ways to obtain that second capability:

| Construction | Cost and boundary | Proposed choice |
|---|---|---|
| Generate a random P-256 signing key and encrypt its private representation under an HKDF-derived vault subkey | One public key and one small immutable encrypted private-key capsule per epoch. Uses existing CryptoKit primitives and separates signing from entry encryption. The decrypted capability must be scoped to the operation. | Recommend this form. |
| Deterministically derive a P-256 signing scalar from the vault key | Avoids the encrypted capsule but needs a specified, validated scalar-derivation algorithm, retry behavior, and key-domain separation. Plainly treating arbitrary HKDF output as a valid scalar is not a complete construction. | Do not introduce that additional algorithm for this milestone. |

The capsule uses a separate HKDF-SHA256 key-encryption domain and AES-256-GCM
with a fresh nonce. Its authenticated context includes the profile, vault ID,
key ID, transition ID, algorithm/version, and advertised epoch public key.
The HKDF `info` is a fixed purpose label, not a value derived from the vault
secret. On opening, validate the recovered private key and require that its
public key equals the advertised key. Do not reuse entry-encryption key/nonce
space, export raw keys through CLI/XPC, or persist decrypted capabilities.
Retain the prepared capsule's exact bytes on retry rather than regenerating it
after signatures or publication state have been bound. Random-nonce use still
needs a production usage bound and failure policy; the software round trip
does not qualify those limits.

The implemented capsule version 1 requires a 32-byte vault key with a matching
derived key ID, a validated 65-byte uncompressed public point, and a 60-byte
combined box (12-byte nonce, 32-byte private representation, 16-byte tag).
Its bounded exact canonical codec and context fixtures live in
[the capsule component](../Sources/KeyCore/V3EpochSigningKey.swift). HKDF salt
is the vault UUID's bytes; the fixed purpose label and complete AAD are explicit.
Prepare once per fresh vault/signing-key pair. Restarting preparation abandons
the whole candidate and requires fresh epoch keys. Durable services must enforce
that policy. Scoped callbacks do not guarantee zeroization or prevent a caller
from retaining key material deliberately.

These choices use established primitives, but their composition is a custom
application protocol. [HKDF's context guidance](https://www.rfc-editor.org/rfc/rfc5869.html#section-3.2)
and [AEAD nonce requirements](https://www.rfc-editor.org/rfc/rfc5116.html#section-3.1)
support the primitive requirements, not this protocol's complete security.
[MLS authentication](https://www.rfc-editor.org/rfc/rfc9420.html#section-16.5)
distinguishes group-secret authentication from member signatures; it does not
specify or validate this public epoch-signature construction.

### Signing order and binding

Put the epoch public key, protected private-key capsule, and boundary proof in
the new profile's manifest body. Keep exactly one ordinary Mac authorization
in the outer envelope for an authority change; do not disguise the epoch key
as a Mac or add a second outer device authorization.

1. Prepare the complete next epoch: fresh vault key and independent epoch
   signing key, its encrypted capsule, complete entry resealing, active device
   wrappers, active recovery wrappers, and the intended rosters/generation.
2. Construct a domain-separated canonical transition statement over the exact
   parent-envelope digest and the entire candidate content, omitting only its
   newly created epoch-transition signature. Its profile, algorithms, next
   authority material, rosters, wrappers, entry metadata and ciphertext digests
   must all be covered. Verify using the parent epoch public key obtained from
   anchored authority, never a replacement key selected by the candidate.
3. Insert the old epoch's canonical low-S signature. The existing Mac signs the
   finalized canonical content, including that proof. Compute the ordinary
   new-key MAC over the finalized content. Neither signature includes the outer
   MAC tag; final-epoch MAC checks remain mandatory.
4. Before publication, independently validate both signatures, old/new key
   identities and MACs, exact roster policy, the next capsule/private-public
   correspondence, local wrapper opening, and complete same-plaintext resealing.
   Existing publication and ordinary catch-up requirements are not relaxed.

This order avoids signing a field that contains its own signature. Production
projection codecs must remove exactly the named proof field, reject unexpected
fields/encodings, and have exact canonical-byte fixtures. The tests use explicit
`test-only` domains and provisional fields, not those production fixtures.

### Lifecycle and verification ownership

Adoption from profile 2 has no pre-existing epoch public key to verify. Treat it
as an explicit, locally validated migration using the old authority signature,
old/new MACs, and full resealing checks. First registration pins an exact fully
validated new-profile manifest that contains the initial epoch public key.
Recovery starts at that floor; it cannot independently derive the initial
authority from an untrusted public key or audit pre-registration history.

Every subsequent key or device/recovery roster change rotates both the vault
key and epoch signing key. Every active recipient gets only the new vault key;
new Macs do not receive old vault keys or a private-key archive. Removed Macs
and tokens may retain earlier secrets but must not receive the next key or its
protected signing capability on the continuing lineage. Retained earlier dual
capabilities can authorize an alternative lineage before removal; hidden
competition is outside the stable anchor's global freshness guarantee, while
visible competing authority histories require refusal. The public verifier
cannot prove that a writer
used independent randomness or distributed every capsule correctly; publication
validation and the applicable lifecycle qualification must check their scope.

Same-epoch edits preserve the complete epoch-authority record and proof bytes,
alongside unchanged authority rosters and wrappers. An inherited proof refers
to the epoch root, not a fresh signature on that edit. Content merges require
identical epoch authority across all parents; resolve the content merge first,
then permit an authority change from one exact checkpoint. Competing authority
changes remain conflicts. No automatic choice or additional hardware attempt
is introduced. Closed-epoch branches outside signed commitments still require
the conservative refusal policy under recovery ordering below.

The public history checker receives only anchored public authority, canonical
envelopes, and bounded graph state. It verifies both authorizations before
selecting an exact final-epoch recovery wrapper. Only after the one deliberate
unwrap may current-key MAC and complete current-entry checks yield a restorable
snapshot. The public proof state must not become an ordinary MAC-verified
checkpoint. Graph selection, recipient policy, source rechecks, and durable
resume remain implementation tasks; the small proof helper tests none of them.

### Implemented ordinary edits and durable publication

The internal profile-3 builder now constructs add, edit, copy, move and remove
candidates from an exact MAC/capsule-authenticated checkpoint and complete
current snapshot. It shares the existing permanent-profile entry planner and
content-delta policy. Profile-specific envelope authentication/serialization
remain separate; profile 3 is never projected into an artificial profile-2
manifest to perform an edit.

Each candidate retains the vault-key epoch, Mac roster/wrappers, epoch capsule,
inherited proof, recovery generation/recipient roster and recovery wrappers
exactly. It names the exact old checkpoint as its only parent and has no fresh
device or epoch authorization. There is no token dependency or private device
operation. Empty/unregistered vaults retain their existing protection state;
edits cannot establish or remove registration.

The independent validator authenticates both manifests and complete before/after
snapshots, checks permitted revisions and content deltas, and requires exact
changed-entry staging. Copy must match a retained unchanged source of the same
type; move preserves its source payload. UTF-8 and canonical TOTP checks, entry
and aggregate bounds apply to the complete snapshots. Changed authority,
capsule/proof, recipient status or wrappers are not ordinary edits, even if the
replacement fixture has a valid current-key MAC.

The internal publisher now uses the existing immutable transaction ordering
through explicit profile-specific validators. It pins the exact content intent
locally before staging, publishes entries before the manifest, reopens exact
published bytes and compare-and-replaces only the expected local checkpoint.
The wire intent and staging layout are unchanged. Shipping profile-2 callers
retain their own parser/authenticator and cannot interpret profile-3 recovery.

Profile-3 publication/resume requires separately supplied registration and
adoption ownership stores. Either pending state blocks content work. Exact
ownership/checkpoint and bounded source inventory are rechecked before
publication and activation. The visible locally trusted floor is required;
a cache alone does not authorize selecting an alternative provider head.
Same-vault branches or changed inventory refuse this single-parent publisher.
The exact candidate's own addition is allowed; provider files alone cannot
authorize interrupted-save recovery without the local intent pin.

Resume validates and publishes the original pinned candidate, never regenerating
an edit. An incomplete unpublished preparation can be abandoned at the old
checkpoint; a published manifest with missing/corrupt references retains the
pin and refuses. After checkpoint commitment, reconciliation authenticates the
current MAC/capsule, complete current snapshot and exact published bytes before
cleanup. It does not require removed entry versions or decrypt old snapshots.
The source inventory still refuses unconnected same-vault objects; missing
intermediate history can leave an older object unclassifiable rather than
granting permission to ignore it. Cache replacement follows successful cleanup.

Software tests publish add/edit/copy/move/remove through this production library
path, then recover the selected current contents using only encrypted files,
the pinned anchor and a software token private key. Original Mac authority and
the session key leave scope before recovery. One agreement opens the snapshot;
ordinary publication makes no private-device or token call. This is filesystem
and crypto evidence, not shipping service/CLI dispatch, branch resolution,
full multi-Mac catch-up coordination, native local-store or physical-token qualification. These
integration tasks still gate product enablement.

### Implemented ordinary same-epoch catch-up

The internal ordinary observer starts at an exact local checkpoint and supplied
unlocked session key, not a recovery-token anchor. It shares bounded published
inventory, ancestry traversal and revision progression with catastrophe history
selection. Authentication remains separate: every visible forward same-epoch
manifest MAC/capsule, unchanged authority/coverage and complete entry snapshot
must check before an ordinary head is reported. Entries have the usual byte,
reference, UTF-8 and canonical TOTP bounds. Snapshots already committed as ancestors
of the supplied checkpoint are not decrypted merely to explain a late branch.

The serialized step service refuses pending ordinary, registration or adoption
work. It repeats the observation and checks exact checkpoint/ownership state
before returning an unchanged floor, reporting multiple authenticated content
heads, or compare-and-replacing the checkpoint with the next authenticated
advance point. A linear path advances its direct child. A resolved fork advances
to the first join lying on every path to the sole visible head, without first
checkpointing either side. All exact parents and required complete snapshots
authenticate before this join can be accepted. The service never constructs an
implicit merge, writes provider objects or requests a device/token operation.
Cache failure after successful CAS cannot undo the new checkpoint's authority.

The one-step API returns one committed step, not a completed access gate or
installed key session. Its caller must rediscover after each step. The internal
coordinated API instead owns one mutation boundary for the entire same-epoch
walk and retains the original authenticated floor. It repeats complete source
authentication and equality checks before every forward checkpoint CAS and
terminal return. A sibling delivered after CAS is authenticated from that retained floor
and reported with all visible heads, retaining committed progress without
choosing a winner. The currently committed manifest must remain present with
exact bytes. A step budget can stop the walk without undoing accepted checkpoints
or claiming current status; reaching a terminal result at the exact bound is allowed.

The retained floor is operation-local. A later invocation can explain a sibling
or merge co-parent below its advanced checkpoint by reconstructing exact
hash-linked same-epoch ancestry committed by that checkpoint. This path runs only
when the ordinary forward cut cannot explain the visible graph. It checks every
required ancestor's MAC/capsule, unchanged metadata, revision progress, graph
closure and existing resource bounds. The unique origin or checkpoint-linked
authorized epoch boundary is the graph cut; its older parent is not reopened or
authenticated with the current key. Unrelated branches and missing required
ancestral manifests still refuse.

The older graph cut never replaces the durable checkpoint. Current and newly
encountered branch snapshots, including unselected co-parents, fully authenticate;
already committed ancestor records can supply a comparison base without reopening
their ciphertext. No second trusted journal, cache authority, persisted schema or
new private-key operation is introduced. Fresh observation equality and exact
checkpoint CAS still gate every forward advancement. Merged-history observation
and explicit merge/resolution publication are implemented internally. Changed-key
descendants refuse this path; no fallback key, private unwrap, token
retry or automatic resolution is available. Key-epoch refusal is not
authentication of that new epoch. Neither API installs a native session or
provides a shipping read/write access gate.

Software tests use independent local checkpoint/cache states and real immutable
filesystem publication, including offline writes before file delivery. They
cover one-step and coordinated advancement, whole-forward-history
availability/authentication, competing heads, late delivery, pending work,
CAS loss, bounded partial progress and source substitution. Published automatic
and explicit-choice merges, repeated joins, post-merge saves and late sibling
delivery use the same complete source/pending/checkpoint checks. Missing ciphertext
in an uncommitted unselected parent still blocks advancement. Late siblings can be
reported, reconciled and durably merged from an advanced checkpoint without
rewinding. Missing older committed ciphertext does not block link reconstruction;
missing required manifests or current/new branch contents do. A pure bounded DAG
policy chooses advance points with linear retained state; independent set-based reference tests
cover all 9,765 rooted topologically ordered six-node DAGs.
They do not qualify two physical Macs, provider delivery, native session unlock,
the local Keychain stores or a shipping workflow.

### Implemented same-epoch branch comparison

The internal profile-3 reconciler consumes the ordinary observer's authenticated
forward DAG, not raw manifests or a profile-2 projection. Every visible branch
has already passed current MAC/capsule, exact unchanged authority/coverage,
revision and complete snapshot checks. The reconciler finds the nearest common
ancestors within that graph, stopping at the checkpoint-linked graph cut. A unique
nearest base feeds entry comparison. Multiple nearest bases produce the existing
history-conflict type; no base is chosen arbitrarily and the merge builder refuses
automatic or explicit-entry resolution of that history shape. The reconciler does
not grant an older or new checkpoint. An older comparison base is usable only
after exact ancestry links have authenticated from the existing local checkpoint.

The shared entry comparison policy keeps independent changes to different stable
entry IDs, including additions and deletions. Competing edits, edit-versus-delete,
rename-versus-edit, different renames and concurrent creation of the same identity
remain explicit conflicts. Distinct identities sharing a destination name also
remain ambiguous. Different ciphertext versions remain a conflict even when the
plaintext happens to match; there is no new content-equality or rename exception.
Conflict reports retain exact head references and changed entry versions, including
nil for a deleted version. Shared comparison retains the older profile's revision
rollback and same-revision-substitution checks.

An automatic merge result is logical entries plus exact parent heads and comparison
base. It is not an encoded manifest, fresh source observation, publication permit
or local trust advancement. No entries are resealed, provider files published,
checkpoint replaced or token/device operation requested. A future merge/resolution
transaction must independently authenticate all exact parents and complete snapshots,
preserve coverage/authority, recheck provider and local pending state, and publish
manifest last. The existing one-parent persisted content intent was not widened.

The observer accepts closed same-epoch merged history and checkpoint-linked late
siblings/co-parents but still refuses changed-key histories. Service/CLI integration
remains unfinished. Explicit choices have
internal construction and durable publication, as described below.
The new tests use real crypto and separate filesystem providers for independent
ordinary publications before immutable file delivery. They are not native session,
Keychain, physical-token or multi-Mac qualification.

### Implemented all-parent content construction

Internal builders now encode automatic merges and complete explicit conflict
choices from an ordinary authenticated forward-DAG observation. Automatic merges
reuse exact independently reconciled ciphertext records without staging or resealing.
Resolution uses the existing head-bound conflict/version IDs and complete-choice
planner. A chosen conflicted entry retains its stable identity, selected name/type
and plaintext, but is resealed at one revision above every parent version of that
identity. Counter overflow refuses resealing; an explicitly chosen deletion stays
absent without incrementing or staging an entry. A destination-name choice removes
only the other identities in that reported collision and retains the chosen
ciphertext exactly. New name collisions created by otherwise complete choices
refuse construction instead of silently deleting another selection.

Every candidate carries all exact sorted parent heads and preserves key identity,
authority transition, Mac roster/wrappers, capsule, inherited proof and complete
recovery roster/generation/wrappers exactly. Fresh boundary authorizations remain
empty. Independent validation rechecks the supplied floor/session key and every
parent's complete snapshot, recomputes the merge or resolution policy, and checks
candidate MAC/capsule, metadata/progression, exact retained records and exact staged
objects. The complete candidate snapshot passes context, AEAD, UTF-8 and TOTP checks;
resealed values must match the selected source plaintexts. Projected object/reference,
byte and history-depth limits include the new manifest and new ciphertext objects.

The builder and domain validator still have no provider writer, checkpoint store,
token operation or native session capability. Their observations can age. Durable
publication must independently recheck source, exact heads, local checkpoint and
all pending namespaces; a constructed candidate alone grants no write permission.

### Implemented all-parent content publication

An explicitly selected internal merge publisher now reuses the ordinary
manifest-last transaction kernel with a separate merge validator. Before intent,
it freshly authenticates the local floor, complete forward parent history and
snapshots, recomputes the exact head-bound merge or choices, and checks the candidate
and projected limits. It writes a local intent pin before staging, publishes all
required ciphertext before the manifest, reads back exact published bytes and
rechecks provider/checkpoint/pending state before local checkpoint CAS. New branches,
changed objects or competing local authority work prevent activation.

Merge intents use a strict canonical version 3 shape containing the exact sorted
heads and bounded sorted conflict/version selectors, with no plaintext or key
material. Empty selectors identify an automatic merge. Selectors are saved evidence,
not saved approval or authority. The device-local pin binds the exact intent digest;
synchronized intents without that pin cannot resume. Existing version 1 content
and version 2 enrollment schemas keep their shapes. Ordinary profile-2/profile-3
content publishers and the older generic recoverer refuse this merge-intent shape;
the merge publisher refuses their ordinary intents. There is no profile auto-detection.

Interrupted publication resumes the exact staged encrypted bytes and candidate;
it does not generate replacement ciphertext or silently choose another version.
Before commitment, all parents, selectors and snapshots are freshly revalidated.
If the exact merge is already published, only its exact bytes are excluded from
parent-head discovery, while remaining in inventory budgets. Other delivered
branches or children are not hidden. A missing unpublished preparation can be
abandoned at the old checkpoint. A published candidate missing required ciphertext
retains its pin and refuses. After local commitment, cleanup authenticates the
current complete snapshot and pinned immutable bytes without reopening superseded
entries or requiring old manifest/cache files. Competing checkpoint/pin values are
never overwritten.

Software tests use real crypto and contained filesystem publication, including
automatic and explicit-choice interruptions at every applicable durable phase,
exact resource budgets, checkpoint/ownership races, changed ciphertext, late branches,
pending authority work, strict intent parsing and cross-publisher refusal. Both
durably published merge kinds open through the public history/snapshot verifier
with one software agreement. Ordinary saves from an accepted merge retain coverage.
These are not native-token operations or measured physical approval budgets.
Merged-history catch-up includes checkpoint-linked same-epoch siblings/co-parents
below a later floor. Service/CLI integration and native/product qualification
remain unfinished.

### Implemented internal ordinary mutation service

The explicitly selected [profile-3 service](../Sources/KeyCore/V3RecoveryVaultMutationService.swift)
implements the existing ordinary add/edit/copy/move/remove/resolve interface.
The helper must own serialization and provide the operation ID. The service
reuses that boundary rather than creating a nested queue. Its only key source is
the existing in-memory session, bound to the exact vault and current key ID.
Missing, invalidated or mismatched sessions refuse; this service cannot sign,
unwrap, prompt for native authentication or administer a token.

Before planning a save it authenticates the current provider manifest against
the exact local checkpoint, resumes only a locally pinned content intent, catches
up through verified same-epoch history, and repeats source/checkpoint/pending
checks. An automatic merge commits under a separate operation ID before the
requested save is freshly planned. If that save then fails, the committed merge
remains but the caller receives failure. Explicit resolution uses freshly
observed conflict selectors; stale choices do not authorize publication.

Interruption routing reads only the operation bound by local ownership, not
arbitrary synchronized intents. The selected publisher independently revalidates
that exact ownership record before resuming or abandoning an unstaged reservation.
Changed or missing ownership cannot switch validators or clean up another
operation. Missing recoverable evidence retains its pin and refuses.

[Integration tests](../Tests/KeyCoreTests/V3RecoveryVaultMutationServiceTests.swift)
use the real session and filesystem publishers. They cover ordinary edit chains,
catch-up, automatic/explicit and late-branch resolution, interruption routing,
source/session failures and authority work appearing during publication. A cold
software recovery test opens service-saved contents after the original session
and service leave scope. This is not native unlock or physical-token qualification.
The conflict projection is serialized metadata inspection, not a concurrent-safe
product read/status service. No shipping dispatch is enabled.

### Implemented authenticated registration status

The internal [registration status service](../Sources/KeyCore/V3RecoveryRegistrationStatus.swift)
inspects an exact locally selected profile-3 checkpoint with its already
authenticated helper key. It uses the existing registration repository and
journal under the shared mutation owner. It has no token, private identity,
agreement, configuration or checkpoint-writer dependency. It does not select a
new provider head, perform catch-up, repair a session or clean up ownership.

An authenticated complete current snapshot with no locally owned attempt is
`unregistered` when its active roster is empty, or `registered` with the stored
active recipient IDs. Registered describes authenticated stored coverage. It
does not prove current possession, anchor presence, protected administration,
PIN/touch enforcement, independent backup availability or provider freshness.
Token absence does not change that stored status.

An exact locally owned preparation takes precedence as `pending`. Before local
commitment, its intent MAC and dual-authorized boundary are checked against the
authenticated floor. After commitment, its exact candidate must be that floor.
The result distinguishes activation awaiting finish from committed activation
awaiting local cleanup. Neither result claims that the external write succeeded
or that finish can complete. No candidate wrapper is opened for status.

Checkpoint, ownership, bundle or source failures, competing mutation ownership,
invalid authentication and changes during inspection yield `attention-required`,
never an empty or protected roster. The service repeats exact source, local
checkpoint, ownership and bundle checks before returning a positive status.
Unowned provider bundles remain inert. Caller admission errors still propagate;
the future product route must enforce connection, lock and deadline scope.
This is not a shipping status command or profile-2 adoption path.

### Implemented internal routine profile-3 unlock

The [profile-3 unlock runtime](../Sources/KeyCore/V3RecoveryVaultUnlockRuntime.swift)
opens only the manifest selected by this Mac's bounded local checkpoint. It
reuses the existing native identity-loader interface, exact-manifest cache and
in-memory Mac-key session. Its explicit recovery-profile codec rejects profile 2
and unknown profiles before a private operation; no profile projection or
provider-head discovery grants authority.

Cold access verifies the exact manifest digest and active Mac identity, opens
that Mac's profile-3 HPKE wrapper once, and authenticates the current manifest
MAC and epoch capsule before installing a resident key. Warm access uses only a
matching resident key and repeats manifest/capsule authentication. A mismatched
resident session refuses rather than retrying authentication automatically.
Neither path checks entry availability, advances a checkpoint, repairs pending
work, opens historical keys or contacts a token. Returned floor metadata is not
a complete snapshot or a current-provider-head claim. Entry reads, catch-up and
status retain their own validation responsibilities.

Ordinary-transaction, registration and adoption ownership stores are required.
Any present record, including malformed bytes, blocks ordinary unlock; any read
failure refuses. These are ordinary-runtime barriers, not an implementation of
the separate authenticated registration/adoption reconciliation route. Pending
ceremonies will need their dedicated scoped authentication path.

Requests capture a session ticket before serialization. Explicit reauthentication
atomically discards the prior key and replaces that still-current ticket inside
the session store. Lock does not wait for the request mutex or native UI. Exact
checkpoint, pending ownership and ticket checks surround identity access, unwrap,
optional cache warming, installation and return. A lock, expiry or replacement
invalidates late authentication. Failed access clears resident state. Cache-write
failure alone does not undo verified authority; cache callbacks cannot bypass
the final state checks. No private operation is retried.

Software integration opens a real enrolled-Mac profile-3 floor, runs the existing
rotation catch-up and ordinary mutation services, then locks and freshly opens
the saved state. This is not native authentication qualification or a shipping
runtime factory. Live Stable/Preview dispatch remains unchanged.

### Implemented internal exact-checkpoint profile-3 reads

The [read adapter](../Sources/KeyCore/V3RecoveryReadOnlyVaultRuntime.swift) uses
the existing read planner, encrypted-entry executor and bounded encrypted-closure
validator. It selects entries only from the authenticated local floor. It does
not discover provider heads, advance authority, or grant provider-current status;
catch-up and stale-provider policy must be composed by a surrounding runtime.

Unlock returns an internal read context bound to its exact checkpoint and
authentication-generation ticket. The context contains no key. Cold access
retains the installation receipt, rather than capturing a new ticket after
authentication; warm access retains its original ticket. Exact checkpoint,
pending ownership and generation are checked before and after key lookup, and
again after decryption before plaintext is returned. Lock, expiry or replacement
invalidates this context even if the same key ID is installed again.

Entry reads verify the pinned immutable object's digest, context and AEAD.
Names are normalized and validated before authentication. List and status check
the bounded encrypted closure, then revalidate the context before returning
metadata. A ready status here means encrypted-object availability, digest and
shape/context checks at that exact floor, not independent AEAD opening of every
entry or proof that the provider supplied its newest state. Missing ciphertext
allows a last-trusted names-only list only with explicit stale permission;
invalid objects and exceeded budgets refuse even that list. Missing entry
plaintext is never returned under stale permission.

Read authorization validates a selector against the authenticated floor; it
does not open the entry or grant a reusable plaintext capability. The adapter
refuses mutation and history methods because it has no publication or graph
observation responsibility. It does not claim an empty conflict set. The internal
composition below now surrounds it with catch-up and ordinary publication.
Pending-ceremony routing and the gated factory remain outstanding. No CLI,
protocol, live dispatch or token operation changes.

### Implemented internal profile-3 runtime composition

The [runtime](../Sources/KeyCore/V3RecoveryVaultRuntime.swift) combines existing
unlock, catch-up, exact reads, ordinary publication and memory-session services.
It is not installed by a shipping factory. Reads and catch-up run inside the
helper's shared mutation owner. Mutation methods reuse the helper-supplied
operation ID and direct owners, rather than nesting that queue. Mutation
authorization only opens the local floor; publication independently catches up,
reconciles and checks its source. Lock remains independent of the queue and
native UI. Memory-session status does not read provider files or authenticate.

Admission is captured before read serialization and carried into unlock and
catch-up. Catch-up returns its exact floor and live ticket, including receipts
from legitimate epoch installations. The unlock runtime continues that floor
without a cold fallback. Final read/list/status return checks the same context,
the observed manifest inventory and published bytes, then the context again.
This last source check opens no historical key and requests no private operation;
its closure retains ciphertext and manifest evidence, not old vault keys.
It detects changes to the observed files, not files a provider never disclosed.

Explicit stale permission admits content competition or transport incompleteness
only at the unchanged authenticated admission floor. Missing files after any
checkpoint advance cannot roll back to that floor. Invalidity, source changes,
authority competition, revocation, budget violations, pending ownership, lock
and unrelated session replacement do not grant stale success. Status distinguishes
an incomplete graph or competing edits from ready state. Ordinary writes retain
the existing automatic-merge behavior for compatible edits; unresolved conflicts
require explicit, freshly validated choices. Metadata conflict list/show and
helper-owned resolution are composed. Conflict-value reads use the same fresh
authenticated projection as metadata and resolution. Conflict/version IDs must
match its exact membership; they are not file addresses or reusable approvals.
A deletion has no plaintext and is distinct from an unknown version or an empty
secret. Linear and automatically mergeable history do not invent conflicts.

The sealed read plan binds the selected entry, exact checkpoint and complete
head set. The existing executor authenticates its ciphertext and checks authority
after opening it. The runtime reobserves the complete same-epoch graph and requires
equality with the selection observation; then its outer read guard rechecks the
session, pending ownership and published source. Conflict values have no stale
fallback. These software checks request no additional private-key operation.

Pending registration or adoption still blocks routine runtime admission.
Interrupted ordinary content saves use a separate pending-authentication context:
one exact bounded device-local anchor must remain unchanged, and both other
namespaces must stay empty. This context cannot be passed to an ordinary reader.
The existing content/merge publication kernel reconciles only that pinned intent;
normal unlock and catch-up then continue the same live session ticket against the
resulting checkpoint, with no cold fallback. Malformed or competing ownership
refuses before identity access. Explicit registration/adoption routing remains.
If lock follows a
durable publication, the saved bytes are not undone; the request's late success
is refused. No automatic authentication retry, token administration, configuration
change or source repair is added. Software operation counts do not qualify native
prompt counts. Registration commands, gated product factories, integrated review
and signed hardware qualification remain required before real-vault opt-in.

### Implemented reciprocal internal pending-work guards

Registration now requires explicit ordinary-transaction and adoption ownership
stores, matching adoption's existing dependency pattern. Any present competing
record blocks prepare, export resume, finish, committed repair and lost-reply
recognition before private work. Read failures propagate; malformed records do
not count as an empty namespace. The ordinary service already blocks registration
and adoption work in the reverse direction.

Both authority services recheck competing ownership with the exact checkpoint
at effect boundaries, including session repair and final ownership cleanup.
Registration also checks after public token revalidation and before publication
and checkpoint CAS. Work delivered during an approval causes refusal of the
remaining effects. An already completed checkpoint CAS is not undone; its exact
preparation and pin remain for explicit reconciliation after competing work is
resolved. Before commitment, a subsequent finish requires fresh possession.
After commitment, reconciliation does not republish or repeat hardware agreement.
An in-flight platform operation cannot be guaranteed cancellable by these guards.

These are durable-resume checks, not a new lock or cross-process atomic protocol.
All composed services must share the existing serialized mutation owner and exact
device-local namespaces. Internal filesystem/software fixtures test both directions,
including a real pinned save, registration-to-session activation, a following edit
and software recovery. Product routing and shipping-runtime barriers still require
integration. Adoption's explicit exact-operation abandonment of an unarmed
reservation remains local-only: it can release its own pin without advancing
trust, publishing or clearing competing work.

### Implemented unchanged-roster rotation foundation

The [rotation builder/validator](../Sources/KeyCore/V3RecoveryKeyRotation.swift)
implements an internal, unpublished profile-3 key epoch. It preserves exact
device and recipient identities/statuses, the recovery generation and all entry
IDs, names, types, revisions and plaintext values. A fresh vault key, transition
ID and epoch signing capsule replace the old epoch. Every active device and
recovery recipient gets exactly one new wrapper; revoked records remain without
wrappers. Stored public keys suffice. No token discovery, agreement, administration
or private recipient key is a construction dependency.

Registration and rotation now share unsigned epoch material construction while
retaining separate independent policy validators. That component consumes a
caller-authenticated exact plaintext identity map, bounds work, reseals entries,
creates wrappers/capsule, and strictly parses bounded output before Mac signing.
It cannot authorize a roster change, publish or establish a checkpoint.
The older shipping profile-2 rotation builder and persisted formats are unchanged.

The independent normal-publication validator checks the exact current checkpoint,
parent MAC/capsule, both boundary authorizations, unchanged rosters/generation,
new current MAC/capsule, exact complete staged objects and old/new plaintext
equality. Optional local-wrapper verification follows those checks and makes
one addressed unwrap; cancellation and mismatches do not retry. This is not a
physical prompt-budget qualification. Recovery still follows authenticated public
history and verifies the selected current snapshot without decrypting all old
epochs or reopening superseded ciphertext.

[Software tests](../Tests/KeyCoreTests/V3RecoveryKeyRotationTests.swift) include
primary and backup recovery after three rotations and a production ordinary
service edit. Old snapshot ciphertext is removed and the original session/Mac
identity leaves scope before one software agreement opens the final state for
each credential. Those foundation tests seed and checkpoint rotation candidates
as setup. The internal durable rotation publisher below now covers publication
and resume. The internal unlocked-session service below now composes initial
rotation and exact interrupted-rotation recovery. Shipping native restart routing
and key-transition catch-up remain.
Compared-device enrollment, reviewed device revocation and recipient
removal now have the internal components below. No public
command or real-vault opt-in is enabled.

### Implemented durable unchanged-roster rotation

The [rotation publisher and source validator](../Sources/KeyCore/V3RecoveryKeyRotationPublisher.swift)
reuse the existing immutable transaction kernel rather than add another ordering
or interruption engine. Rotation validation remains separate from ordinary edit,
enrollment, revocation and recipient-removal policy. The shared source inventory
also owns the unchanged-byte comparison used by ordinary publication.

Initial publication authenticates the exact parent checkpoint, both key epochs,
unchanged rosters/generation, boundary authorizations, complete staged objects and
old/new plaintext equality. Bounded source inventory and projected usage precede
one addressed local-Mac wrapper verification. Cancellation reserves nothing;
source and pending authority work are rechecked after the private operation.
No recovery token or administrative operation is required.

The same mutation-owner operation ID spans local intent reservation, immutable
entry staging/publication, exact manifest readback, checkpoint-last activation
and cleanup. Every write retains the existing local ownership/checkpoint guards.
Competing registration/adoption, changed source, unavailable objects and resource
limits refuse without silently selecting another candidate or branch.

A new internal `rotateVaultKey` intent kind uses the existing version-1 intent
shape; existing kinds and manifest formats are unchanged. Older readers do not
recognize this kind and refuse it. Both ordinary-profile resume routes now admit
only ordinary edit kinds before acting on an intent. Rotation resume accepts only
its exact locally pinned rotation intent, never an enrollment/removal approval or
an ordinary transaction. There is no automatic profile or lifecycle fallback.

Before checkpoint commitment, resume requires helper-scoped old and new keys,
both complete snapshots and full rotation validation. It resumes the same bytes
without re-signing, rewrapping or generating a replacement epoch. Once the local
checkpoint is the exact candidate, cleanup authenticates the pinned current
snapshot without the old key, old ciphertext or old manifest cache. That is
reconciliation of a committed decision, not permission to bypass initial checks.
Keys are not persisted in intents or provided by CLI/XPC callers. Initial and
interrupted-rotation session orchestration is now composed below. Shipping native
restart routing and physical qualification remain separate work.

[Software tests](../Tests/KeyCoreTests/V3RecoveryKeyRotationPublisherTests.swift)
cover every publication boundary, checkpoint failures, committed cleanup,
unavailable published entries, pending/changed state and cross-kind refusal.
Primary and backup credentials each recover the latest secret and TOTP after an
actual durable rotation and ordinary-service save, with one software agreement
and without original Mac private state or superseded ciphertext. Physical prompt
counts and native restart behavior are not qualified. Other lifecycle publication,
service/product integration and key-transition catch-up remain; no public command
or real-vault opt-in is enabled.

### Implemented unlocked-session rotation service

The [internal service](../Sources/KeyCore/V3RecoveryKeyRotationService.swift)
composes authenticated review, random key generation, construction, publication
and live-session replacement. It requires an already unlocked, exact vault/key
session and this Mac's signing/unwrapping identity. The helper owns serialization
and supplies one operation ID; no new queue, signing protocol, token adapter or
public command is added. Ordinary saves retain their separate no-private-operation
service.

Preparation authenticates the local checkpoint, active exact Mac identity and
complete current plaintext snapshot against bounded immutable inventory. It
neither generates a key nor signs or reserves work. Execution requires the reviewed
checkpoint to remain exact and refuses any existing ordinary, rotation,
registration or adoption work. It does not resume or replace that pending work.
After Mac signing, source bytes, checkpoint, pending work and the old session are
rechecked before the publisher's addressed local-wrapper verification. The
process-local session-generation ticket is captured before loading the base key
and checked after base validation and signing. Lock followed by reauthentication
with the same old key is a different session, not continued approval. The existing
publisher still owns full old/new snapshot comparison, projected limits, source
rechecks, durable intent and manifest-last/checkpoint-last publication.

After successful publication, the service authenticates the committed current
MAC/capsule and complete snapshot before replacing the live session. Before and
after that validation, ordinary ownership must be absent or bind this operation's
exact committed rotation intent. Malformed, foreign, unreadable or mismatched
ownership refuses activation. The
[session store](../Sources/KeyCore/V3DeviceWrappedVaultKeySession.swift) owns an
atomic generation-ticket installation check: lock, expiry or same-key
reauthentication during publication cannot be undone by installation. Returned
commit data contains no raw key; raw keys remain scoped in memory and are never
written into the intent.

An error does not imply that the checkpoint failed to advance. The service keeps
the old session only if the checkpoint remains the exact reviewed checkpoint;
changed, missing or unreadable checkpoint state locks the session. It never
installs a key from an error path, rolls back a committed checkpoint, erases the
intent or retries authentication. Best-effort cleanup may fail without preventing
successful commitment and session replacement; the exact pending rotation then
still needs its dedicated reconciliation route before another save.

[Thirteen service test declarations](../Tests/KeyCoreTests/V3RecoveryKeyRotationServiceTests.swift)
exercise actual random-key rotation and continued ordinary saving, all 14
publication interruption points, checkpoint/cleanup failures, cancellation,
invalid or changed sources, identity/session/pending barriers and post-commit
refusal, including same-key reauthentication during signing/wrapper verification
and changed/unreadable post-commit ownership.
[Session declarations](../Tests/KeyCoreTests/V3DeviceWrappedVaultKeySessionTests.swift)
exercise exact prior-epoch replacement, generation tickets, invalid keys, foreign
vaults, locked or absent sessions and expiry. These use real epoch crypto and
contained filesystem publication with software Mac identities, not physical
prompt qualification.
The following internal restart path now opens addressed old/new wrappers and
composes exact resume-to-session orchestration. Product confirmation/runtime
dispatch and integrated review remain.

### Implemented interrupted-rotation service

The same [rotation service](../Sources/KeyCore/V3RecoveryKeyRotationService.swift)
now resumes only a locally pinned rotation without generating, signing or
rewrapping another epoch. It reuses the immutable kernel's bounded pending-state
preparation rather than scan transaction files or duplicate staged/published
selection. Preparation may safely abandon locally owned work that never became
publishable. Its returned ciphertext state is not authentication or permission
to advance a checkpoint.

Before private operations, the service checks strict profile-3 bytes, exact
intent/checkpoint ownership, complete encrypted-object addresses and contexts,
active exact Mac identity, source inventory and budgets. For an uncommitted
rotation it also verifies unchanged device/recipient rosters, recovery generation,
entry metadata and both public boundary authorizations against the exact local
parent floor. The public preflight is shared with normal rotation validation;
it does not replace parent MAC/capsule or plaintext checks.

A cold uncommitted restart opens this Mac's old wrapper, authenticates the old
epoch and complete plaintext snapshot, then rechecks pending/source state before
opening its new wrapper. With both keys, full old/new authentication and plaintext
comparison precede exact kernel resume. If the checkpoint already equals the
pinned candidate, only the new wrapper and exact current snapshot are needed;
old keys, ciphertext, manifests and cache are not required. An exact live session
can supply its matching old or committed current key. It cannot supply another
epoch or select a replacement candidate.

The software private-operation budget is two addressed Mac unwraps for a cold
uncommitted restart, one for cold committed cleanup, one when the uncommitted old
key is already live, and zero when the committed current key is already live.
This is not a physical Touch ID/prompt count. No recovery-token agreement,
administrative operation, automatic authentication retry or new signature occurs.

After authentication, exact intent bytes, checkpoint, ownership, source and
authority barriers are checked again. The kernel retains manifest-last ordering,
checkpoint CAS and full profile validation. Unavailable already-published objects
retain the pending operation without requesting authentication until exact bytes
return. Safe incomplete-staging abandonment retains the old checkpoint; a changed
staged source may use that existing abandonment path on recheck too.

Before session installation, the exact committed current MAC/capsule and complete
snapshot authenticate again. A process-local, store-bound authentication ticket
prevents an intervening explicit lock, actual expiry or session replacement from
being undone. Polling an already locked session does not cancel authentication.
The ticket contains no key, is not persisted or sent over IPC, and proves neither
authentication nor consent. Errors lock the session; they never roll back a
committed checkpoint or silently delete an otherwise valid pending operation.
A no-pending result is not a general cold-unlock operation.

[Fifteen restart declarations](../Tests/KeyCoreTests/V3RecoveryKeyRotationRecoveryTests.swift)
exercise the actual random-key service interrupted at all 14 publication points,
exact recovery and continued saving, committed cleanup without obsolete objects,
warm-key reuse, cancellation, lock/source/authority/checkpoint changes, provider
result validation, malformed inputs, aggregate/projected budgets and post-commit
refusal. Four additional [session declarations](../Tests/KeyCoreTests/V3DeviceWrappedVaultKeySessionTests.swift)
cover status polling, explicit empty-session lock, store/session replacement and
expiry across guarded authentication. All use software private keys and contained
filesystem publication. Shipping cold unlock/routing, other lifecycle publication,
key-transition catch-up, integrated review and physical acceptance remain.

### Implemented compared-device enrollment foundation

The [enrollment builder/validator](../Sources/KeyCore/V3RecoveryDeviceEnrollment.swift)
adds exactly one active Mac from the signed comparison ceremony. It verifies both
message signatures, inviter role, awaiting-comparison phase, expiration, exact
vault/checkpoint and active inviting identity. The existing transcript-derived
transition ID binds the resulting signed epoch and wrappers to that comparison.
No caller-selected unrelated transition ID is accepted. Enrolled identities and
reused signing/wrapping keys refuse before signing.

Every old device record/status, including revoked tombstones, remains exact.
Recovery recipients, registrations/statuses and generation are unchanged. A fresh
vault-key epoch reseals all entries without changing metadata or plaintext; every
active Mac/recipient gets a current-key wrapper and revoked records get none.
Construction requires stored public keys, not a connected recovery token.

Rotation and enrollment share bounded cryptographic and full snapshot checks,
while independent policy validators enforce their distinct roster decisions.
Enrollment additionally checks exact transcript binding and the complete expected
roster, not just a valid epoch signature. Full software checks precede optional
one addressed inviting-Mac unwrap; cancellation is propagated without retry.
This does not qualify physical prompt counts or create durable approval.

[Software tests](../Tests/KeyCoreTests/V3RecoveryDeviceEnrollmentTests.swift)
recover after two successive enrollments, an ordinary mutation-service save and
removal of obsolete ciphertext, with one software agreement per primary/backup
credential. The original Mac identities/sessions leave scope before recovery.
Those foundation tests materialize enrollment epochs/checkpoints in test setup.
The internal durable component below exercises actual enrollment publication.
Joining-Mac adoption, key-transition catch-up and shipping/native integration
remain. The internal owner service below composes publication and sessions.
Existing profile-2 dispatch and persisted
formats are unchanged. No public command or real-vault opt-in is enabled.

### Implemented durable compared-device enrollment

The [enrollment publisher/source validator](../Sources/KeyCore/V3RecoveryDeviceEnrollmentPublisher.swift)
accepts only an explicitly approved transcript matching exact device-local signed
ceremony bytes. Awaiting-comparison state alone does not establish human consent;
the helper caller must supply the digest of the comparison the user approved.
Both messages, inviter identity, exact parent checkpoint, transcript-derived
transition ID, single joining identity, unchanged existing devices/recipients and
fresh complete key epoch are validated before one addressed inviting-Mac wrapper
verification. Cancellation and changed source, local ceremony or pending authority
refuse before any transaction is reserved.

The dedicated enrollment validator reuses the immutable transaction kernel rather
than rotation policy. It persists the existing version-2 intent with the exact
transcript digest and encrypted candidate selectors. The device-local anchor
pins that entire intent; provider intent files cannot authorize publication.
Keys and a prepared owner-approval carrier are not persisted in it. Every source
recheck also reloads the exact signed local ceremony and checks competing
registration/adoption work. Entries publish first, the manifest last, and the
checkpoint advances only after exact readback and full validation.

Fresh approvals require an unexpired awaiting-comparison ceremony. Exact pending
work can finish after expiry without new comparison, signature, key generation,
wrapper verification or token agreement. Before commitment both scoped keys and
full old/new plaintext comparison remain required. After commitment, authenticated
current ciphertext, current key/capsule and exact pinned transcript/intent suffice;
obsolete ciphertext and the old key are not required for completion cleanup.
Other transaction kinds and mismatched transcripts refuse before owned cleanup,
including when the local checkpoint has changed. Existing safe abandonment of
incomplete unpublished staging remains; it does not consume the ceremony.

A [shared domain completion hook](../Sources/KeyCore/V3ContentTransactionValidation.swift)
marks this exact inviter ceremony consumed by local CAS after commitment, while
the pending anchor still exists. The publisher and recoverer check exact checkpoint
and ownership around the hook. Enrollment reopens the authenticated current
snapshot before writing the marker. A marker failure retains pending ownership;
a consumed marker is idempotent when later cleanup fails. Consumption is
bookkeeping, not authority, cannot admit another transcript, and prevents fresh
reuse. Other validators use a no-op hook; profile-2 enrollment is unchanged.

[Software publication tests](../Tests/KeyCoreTests/V3RecoveryDeviceEnrollmentPublisherTests.swift)
exercise all 14 interruption points, empty snapshots, exact intent binding,
expiry, cancellation, source/local/pending changes, incorrect keys, checkpoint
and completion failures, current-only cleanup and cross-kind refusal. They also
open the joining-Mac wrapper and recover with either primary or backup after
actual enrollment publication, an ordinary save and obsolete ciphertext removal.
The tested one-operation wrapper check and one-agreement recovery are software
counts, not physical prompt qualification. This component neither presents
comparison UI nor installs an owner/joiner session. Owner-service restart and
session orchestration are implemented separately below; joining adoption,
product routing and native acceptance remain.

### Implemented enrollment owner service and exact restart

The [internal owner service](../Sources/KeyCore/V3RecoveryEnrollmentOwnerService.swift)
loads the exact signed local ceremony and authenticates the entire current
snapshot with an already unlocked session. Preparation returns the pinned
checkpoint and comparison transcript; it does not sign, generate a key or save
approval. Execution requires the exact reviewed checkpoint and explicitly approved
transcript digest. An expired, consumed, replaced, conflicting or unavailable
ceremony cannot create a fresh enrollment. Existing pending work and invalid
source/session/identity refuse before signing.

Initial execution generates a random 256-bit key with CryptoKit and calls the
existing builder and durable enrollment publisher. After signing it rechecks
source, checkpoint, local ceremony, pending work and the live session before
the addressed Mac wrapper is opened. The session's process-local authentication
ticket is checked before and after that operation; a lock or replacement during
the operation prevents reservation. Successful publication must authenticate
the exact committed current key/capsule and full snapshot, verify consumed local
ceremony bytes and recheck checkpoint/ownership before guarded installation.

An initial cleanup failure may leave the exact committed enrollment pending
while its authenticated new session is installed. Before selecting such pending
work, the service reconstructs this operation's exact transcript-bearing intent
digest and checks its local anchor, then verifies the selected committed bytes.
A substituted operation or intent is not cleaned up or used for installation.
Failure after checkpoint advancement locks without rollback. Before commitment,
failure retains the old session only if the reviewed checkpoint is still exact;
it never reinstalls a key or removes pending approval from an error path.

Restart loads the exact local transcript without reapplying invitation expiry
and selects only its locally anchored enrollment. Public preflight checks the
full roster/recipient decision, transcript-derived transition ID, both public
boundary authorizations, snapshot metadata, source inventory and projected
budgets before opening an uncommitted old Mac wrapper. That result must
authenticate the old key/capsule and complete plaintext snapshot. Exact pending,
source, ceremony and session checks precede the new Mac wrapper. Full old/new
comparison remains in the publisher before commitment. Committed reconciliation
uses only the current epoch and key, not old ciphertext, manifest or cache.

No new comparison, signing, random epoch, rewrapping or recovery-token agreement
occurs on restart. Software counts are two/one/one/zero Mac unwraps for cold
uncommitted, cold committed, warm old-key and warm committed-key sessions.
They are not physical prompt guarantees. All recovery errors lock, and successful
installation cannot undo explicit lock, expiry or replacement. Nothing-to-recover
is not a general unlock or a fresh approval; incomplete unpublished staging may
still be safely abandoned without consuming the ceremony.

[Twenty-three software declarations](../Tests/KeyCoreTests/V3RecoveryEnrollmentOwnerServiceTests.swift)
exercise actual random-key service publication and restart at all 14 boundaries,
continued ordinary saves, warm reuse, cancellation, same-key session replacement,
source/ceremony/pending changes before further private operations, bad provider
results, malformed and over-budget input, checkpoint/completion/cleanup failures
and post-commit refusal. Primary/backup recovery after an owner-service enrollment
and save uses one software agreement each. This owner-service increment adds no
public command, comparison UI, joining-Mac adoption, native qualification or
real-vault opt-in. Internal joining adoption is implemented separately below.

### Implemented joining-Mac adoption

The [internal joining service](../Sources/KeyCore/V3RecoveryEnrollmentAdoption.swift)
establishes exact local first trust without enabling a shipping enrollment route.
Its [seventeen software test declarations](../Tests/KeyCoreTests/V3RecoveryEnrollmentAdoptionTests.swift)
use actual owner-service publication, separate owner/joiner local stores and
contained immutable filesystem storage. Only Mac identity operations and local
failure/interruption boundaries are supplied by owned software fixtures.

It requires this Mac's exact authenticated local joining messages and an explicitly
compared transcript digest. Public transition policy is shared without fabricating
an inviter ceremony or relaxing owner publication approval. Before opening a Mac
wrapper, bounded graph/source checks require a sole direct matching enrollment,
both boundary authorizations, the exact roster addition, unchanged recovery
recipient/generation policy and preserved snapshot metadata. A different local
checkpoint, competing pending work, ambiguous approval or visible later/competing
state refuses; exact adoption does not perform catch-up or claim provider-global
freshness. Public parent/history bytes remain required on retry, not old ciphertext.

One cold addressed Mac-wrapper result must authenticate the current MAC/capsule
and every current entry. Warm exact session reuse avoids that operation. All local
and source state is rechecked before persistence and completion. The encrypted
cache is non-authoritative. Insert-only checkpoint trust precedes consumed-ceremony
bookkeeping so interruptions cannot permit a different matching epoch to replace
the pinned one. Retry is nil-or-exact only. Guarded session installation is last;
lock, expiry or replacement during authentication cannot be undone, and errors
invalidate the session without rolling back or deleting committed local trust.

The result names the verified enrollment/checkpoint. It does not select a config
vault, claim an active shipping runtime, publish shared files or call/provision
a recovery token. Product activation and key-transition catch-up remain separate.

Tests cover empty/full snapshots, exact cold/warm retry, interruption and lock
at approval verification, checkpoint installation and ceremony consumption,
checkpoint/cache/completion failures, cancellation and wrong provider results,
local/source/session changes, competing pending work, invalid signatures and
inventory limits. Primary and backup software credentials each recover with one
agreement after an actual owner approval, joining adoption and joining-Mac save,
even with obsolete ciphertext removed. These are software operation counts, not
native prompt or two-physical-token qualification.

### Implemented reviewed-device revocation foundation

The [revocation planner/builder/validator](../Sources/KeyCore/V3RecoveryDeviceRevocation.swift)
authenticates the exact profile-3 parent and reconstructs the complete reviewed
checkpoint/device/roster decision. Exactly one other active Mac becomes revoked;
all identities and tombstones remain. The approving Mac retains access. Unknown,
already revoked and self selections refuse, and the last active Mac cannot be
removed. A changed plan cannot approve another checkpoint or device.

Both profiles reuse the [existing roster rule](../Sources/KeyCore/V3DeviceRevocationRosterPolicy.swift)
while keeping separate profile/checkpoint authentication boundaries. The pure rule
establishes no authority or durable approval. Profile-2 behavior, plan types,
persisted formats and shipping dispatch remain unchanged.

Recovery recipients/registrations/statuses and generation remain exact. A fresh
key epoch reseals the complete snapshot without changing metadata or values.
Public keys create new wrappers for every remaining active Mac and recovery
recipient; revoked devices receive none. Full independent software validation
precedes optional one addressed approving-Mac unwrap, without automatic retry.
No token or administrative operation is required for construction.

[Software tests](../Tests/KeyCoreTests/V3RecoveryDeviceRevocationTests.swift)
show remaining devices opening new wrappers, the revoked Mac's old key failing
to open the new snapshot, and primary/backup recovery after materialized enrollment,
revocation and an actual ordinary-service save. Recovery uses one software agreement
per credential after original Mac private state and superseded ciphertext leave
scope. Old copied states remain readable with their old keys; revocation is
forward-only. Durable publication/resume is implemented separately below;
confirmation, session orchestration, remaining-Mac catch-up and product/native
integration remain. No public command or real-vault opt-in is enabled.

### Implemented durable reviewed-device revocation

The [internal revocation publisher](../Sources/KeyCore/V3RecoveryDeviceRevocationPublisher.swift)
requires an independently supplied approved plan exactly equal to the candidate's
plan. That value is supplied by the caller, not proof that a confirmation UI ran.
The caller owns user confirmation and scoped keys; this component owns exact
publication and restart through the shared immutable durability kernel.

Before the addressed approving-Mac wrapper is opened, it authenticates the old
checkpoint/key/capsule, reconstructs the complete reviewed roster decision,
verifies both epoch boundary authorizations and unchanged recovery policy, and
compares every old/new entry's metadata and plaintext. Bounded source inventory,
projected snapshot usage and all pending-work guards must pass. After the private
operation returns, everything is rechecked before a local intent is reserved.
Cancellation or an incorrect wrapper result never reserves work or retries.

The existing version-1 `revokeDevice` intent pins the exact old checkpoint, sole
parent, candidate digest and staged entry selectors. No keys, duplicate reviewed
roster or new consent carrier are persisted. Manifest-last publication and exact
checkpoint CAS retain the original old floor until complete immutable readback
and full software revalidation succeed. Visible competitors, changed authority
ownership/checkpoint, or pending registration/adoption stop publication.

Restart selects only this locally anchored kind and exact candidate. When an
intent is present, another kind refuses before checkpoint-based abandonment;
an explicitly routed anchor must also remain exact before prepared/no-intent
cleanup. Incomplete unpublished work can be safely abandoned by the existing
kernel, never adopted as a new review. Selection itself authenticates nothing.

Before commitment, both keys and complete snapshots remain necessary. The
validator reconstructs exactly one active-to-revoked change with unchanged
identities, other statuses, recipients and generation. An unchanged-roster or
recipient-removal epoch is not a device revocation even if its public signature
and encoding are valid. After the exact candidate checkpoint has committed,
cleanup authenticates only the current key/MAC/capsule and complete snapshot; old
keys, ciphertext, manifest and cache are unnecessary. Missing or invalid current
objects retain pending work and never rewind the checkpoint. Restart performs no
signing, new epoch generation, target selection, native unwrap or token operation.

[Twenty software test declarations](../Tests/KeyCoreTests/V3RecoveryDeviceRevocationPublisherTests.swift)
exercise actual enrollment followed by revocation publication, all 14 interruption
points, empty/full snapshots, exact review/key/identity guards, checkpoint and
cleanup failures, source/pending changes, cancellation, incorrect provider output,
missing required snapshots, bounded input and reciprocal kind refusal. Primary
and backup software credentials each recover after durable enrollment, revocation
and an ordinary save with one agreement and without superseded ciphertext.
Old copied vault states remain readable under their old keys; removal is forward-only.

No helper/session workflow, confirmation UI, public command, remaining-Mac
catch-up, real-vault opt-in or hardware qualification is enabled by this increment.
Profile-2 dispatch and persisted intent formats remain unchanged.

### Implemented reviewed-recipient removal foundation

The [removal planner/builder/validator](../Sources/KeyCore/V3RecoveryRecipientRemoval.swift)
authenticates the exact parent checkpoint and reconstructs the complete reviewed
recipient decision. Exactly one active credential becomes revoked. Its public key,
registration and slot remain as a tombstone; every other recipient and all Mac
records remain exact. Unknown and already revoked selections refuse.

Removal replaces the vault key, transition ID, signing capsule and recovery
generation. Every entry is resealed with unchanged identity, metadata and plaintext.
Stored public keys create new wrappers for all active Macs and remaining recovery
recipients; revoked records receive none. No token operation is needed, including
on the removed token. Key must not clear, overwrite or reset its external anchor.

Removing the last active recipient requires a loss-of-protection acknowledgment
bound to the entire reviewed plan. Both construction and independent validation
require that exact value. A different checkpoint, authorizer or recipient cannot
reuse it, and ordinary removal does not accept it as a general override. The
product must collect informed confirmation before constructing the value. The
in-memory type is not proof of human consent, durable approval or authority to
resume. It is not persisted in the candidate or manifest.

Independent validation checks the exact recipient/device policy before the shared
boundary and complete old/new snapshot checks. Optional one addressed local-Mac
unwrap follows full software validation; cancellation propagates without retry.
This does not qualify physical prompt counts.

[Software tests](../Tests/KeyCoreTests/V3RecoveryRecipientRemovalTests.swift)
materialize primary, backup and last-recipient removal, followed by an actual
ordinary-service save. A remaining credential opens the latest secret and TOTP
with one software agreement after original Mac private state and superseded-epoch
ciphertext leave scope. A removed credential is refused at the visible new head
during public selection, before agreement and without falling back to older
wrappers. Existing copied old states remain readable with old keys: removal is
forward-only, not remote erasure or protection against withheld newer files.
With no active recovery recipients, ordinary Mac-authorized saves still work.
Durable removal publication/resume is implemented separately below; user
confirmation, remaining-Mac catch-up and product/native integration remain.
No public command or real-vault opt-in is
enabled; profile-2 behavior and persisted formats are unchanged.

### Implemented durable reviewed-recipient removal

The [internal removal publisher](../Sources/KeyCore/V3RecoveryRecipientRemovalPublisher.swift)
requires a separately supplied exact plan and, for the last active recipient,
its exact protection-loss acknowledgment before any Mac operation or reservation.
The caller still owns informed confirmation; the typed value is not proof that
the user saw a warning. Complete source/transition/snapshot checks precede one
addressed Mac-wrapper opening, then source and local state are checked again.
Cancellation or mismatched provider output cannot pin new work.

The existing immutable kernel publishes entries before the manifest and advances
the checkpoint last. Version-1 local intent retains its original fields, with a
new `removeRecoveryRecipient` operation kind. Existing kind encodings do not
change; older decoders refuse the unknown kind. No consent marker or duplicate
recipient roster is persisted. Kind checks precede checkpoint-based abandonment;
an explicit routed anchor must match before cleanup of an unarmed reservation.

Uncommitted restart reconstructs exactly one active-to-revoked recipient change
from the authenticated parent and pinned candidate, retaining all identities and
Mac records, changing the recovery generation and checking complete old/new
plaintext equality. Transition-only validation is not fresh approval: the kernel
must already establish exact local intent ownership. Restart requests no renewed
acknowledgment, signing, key generation, Mac unwrap or token operation. A missing
unpublished preparation may be abandoned, not regenerated as a new removal.

Already committed cleanup authenticates the current key, capsule/MAC and complete
snapshot at the exact pinned checkpoint without old keys, ciphertext or manifests.
Missing current state retains ownership and trust. Other valid epoch policies and
ordinary/rotation/revocation/enrollment intents cannot stand in for removal.

[Twenty software declarations](../Tests/KeyCoreTests/V3RecoveryRecipientRemovalPublisherTests.swift)
cover all 14 publication interruptions with and without remaining protection,
exact review and acknowledgment, current-only cleanup, source/pending/CAS guards,
missing state and resource bounds. Primary/backup/last removal uses actual durable
publication followed by an ordinary save; only continuing software recipients
recover the latest snapshot. Retained old copies remain outside removal promises.
No owner/session orchestration, shipping route or physical qualification is added.

### Implemented initial authority-change session service

The [internal authority-change service](../Sources/KeyCore/V3RecoveryAuthorityChangeService.swift)
has separate preparation/execution methods for device revocation and recovery-key
removal. It shares source, session and error handling, not their decision policies.
Preparation authenticates the complete current snapshot without private identity
operations, new keys, saved approval or durable reservation. Execution recomputes
the exact reviewed plan and requires last-recipient acknowledgment before random-key
generation or signing, then uses the corresponding existing builder and publisher.
The helper must serialize the operation and supply its operation ID.

After signing, the service rechecks the session generation, source, checkpoint and
pending work before Mac-wrapper verification. After publication, exact committed
authority and the complete current snapshot authenticate before an atomic session
installation. Lock, expiry or same-old-key reauthentication during native UI cannot
be undone by that installation. An error retains the old session only while its
reviewed checkpoint remains exact; otherwise it locks without rolling back trust
or deleting pending ownership. Best-effort cleanup failure allows the new session
only with the exact matching committed intent; pending work still blocks new saves.

[Fifteen software declarations](../Tests/KeyCoreTests/V3RecoveryAuthorityChangeServiceTests.swift)
cover continuing/last-recipient removal and device revocation through all 14
publication boundaries, independent review and acknowledgment, cancellation,
incorrect provider output, lock/reauthentication races, source/pending/CAS changes,
missing snapshots and bounds. Ordinary saving continues from the installed new
session; only continuing software recipients can recover that saved state.
Session-aware interrupted-change reconciliation is described below. Remaining-Mac
catch-up, shipping confirmation/runtime/CLI and native/physical qualification
remain separate work.
No persisted format or shipping route changes in this increment.

### Implemented interrupted authority-change session reconciliation

The [authority-change service](../Sources/KeyCore/V3RecoveryAuthorityChangeService.swift)
has explicit, separate interrupted-revocation and interrupted-removal entry points.
The established kernel selects only exact locally owned intent; wrong kinds refuse
before checkpoint-based abandonment. An optional routed anchor must match even
before unarmed cleanup. Restart neither signs nor generates another epoch, changes
the selected target, renews a protection-loss acknowledgment or operates on a token.

Public preflight reconstructs the exact one-device or one-recipient tombstone and
checks the matching policy, parent-bound public proofs, entry contexts, complete
ciphertext availability, source inventory and projected limits before Mac-key
opening. Public metadata is not authenticated review or authority. Uncommitted
restart subsequently authenticates the old key/snapshot and new key/snapshot,
including full plaintext equality, before commitment. Committed cleanup needs only
the exact current key and snapshot, not old manifests, keys, ciphertext or cache.

Cold uncommitted restart opens two addressed Mac wrappers. An exact warm session
supplies the old key, leaving one opening. Committed restart opens only the current
wrapper, or none if its exact key is resident. Each result authenticates before
another operation; cancellation and wrong output do not retry. Source, checkpoint,
ownership and session-generation checks bracket native UI. Only authenticated
committed state with no pending work installs a session; failures lock without
rolling back trust or deleting pinned work. Nothing pending leaves an existing
exact live session unchanged and does not unlock a cold session.

[Eighteen software declarations](../Tests/KeyCoreTests/V3RecoveryAuthorityChangeRecoveryTests.swift)
cover all 14 initial interruption boundaries for revocation and continuing/last
removal, cold/warm operation counts, cancellation, lock/reauthentication, routed
anchors, policy/kind/owner refusal, source/pending/CAS/cleanup failures, current-only
cleanup and ordinary-save/software-recovery composition. Mac identities and
recovery credentials are software fixtures, not physical qualification. No new
persisted format, shipping route or real-vault activation is added.

### Implemented remaining-Mac key-transition step

The [key-transition service](../Sources/KeyCore/V3RecoveryKeyTransitionCatchUpService.swift)
adds one serialized epoch step from an exact unlocked profile-3 Mac checkpoint.
It uses ordinary Mac credentials, not a token anchor or a fabricated recovery
selection. This is an internal step, not shipping dispatch or a complete mixed
content/key-epoch coordinator.

Bounded discovery reuses the manifest graph, checkpoint-linked same-epoch
ancestry, public epoch proofs and existing roster planners. Rotation, one compared
device addition, one device revocation, one recipient addition and one recipient
removal remain separate permitted policies. Catch-up verifies already-published
authority; it does not renew an enrollment comparison, registration possession
ceremony or last-recipient acknowledgment, or authorize a new publication.
Changed identities, missing tombstones, combined unrelated roster changes and
reactivation are not accepted transitions.

Every visible forward boundary verifies both parent-bound signatures. Same-epoch
metadata and revision progression, epoch uniqueness, graph/entry budgets, exact
ciphertext addresses and contexts check before native opening. Visible competing
authority, content heads or closed-epoch branches refuse rather than select by
time or provider order. Current-epoch snapshots authenticate completely; exact
committed older same-epoch ancestors explain late joins without reopening their
obsolete ciphertext. Required forward ciphertext, including unopened later
epochs, must be available.

Only the addressed continuing Mac wrapper is opened, once per successful step.
The resulting key authenticates its MAC and signing capsule, the complete boundary
snapshots must have identical plaintexts, and every visible content snapshot in
that selected next epoch fully authenticates. This retains ordinary catch-up's
full reseal checks, not catastrophe recovery's reduced historical replay. Later
epochs remain publicly checked but not MAC/AEAD-trusted until separate steps open
their keys. Success returns only the first committed epoch root, never a claim
that the latest state or global provider freshness was reached. Same-epoch-only
work returns `noKeyTransition` without advancing content trust.

Exact checkpoint, all three pending-work namespaces, source bytes and session
generation bracket UI and checkpoint CAS. Cancellation and incorrect output do
not retry. Failures lock without rolling back committed trust or creating/deleting
intent. A cache failure cannot undo an authenticated advance. A Mac visibly
revoked at the selected history head refuses before a private operation.

[Twenty-four software declarations](../Tests/KeyCoreTests/V3RecoveryKeyTransitionCatchUpTests.swift)
exercise independent local checkpoints/sessions over contained filesystem
publication, mixed edits/epochs, late joins, removal, coverage, limits, cancellation,
source/session/pending/CAS races and software recovery after both Macs leave scope.
Rotation/enrollment/revocation/removal use actual publishers; recipient-addition
bytes use the domain builder and fixture materialization, not another registration
possession ceremony. No native prompt or physical-token qualification is claimed.

### Implemented mixed content/key-epoch coordination

The [ordinary catch-up coordinator](../Sources/KeyCore/V3RecoveryCatchUpCoordinator.swift)
composes the existing content and epoch steps from an exact unlocked Mac floor.
One mutation owner surrounds the full walk. Direct component owners reuse its
operation ID without nesting the serialization queue. Cold unlock, shipping
dispatch and UI remain separate responsibilities.

The coordinator retains the initial bounded observation and its original-floor
key only for this operation. It rechecks that exact source across steps and at
return, including old-floor branches and ciphertext. A changed source stops the
walk; it does not silently choose a newly arrived head or retry a private opening.
An initial authenticated same-epoch content conflict returns both heads without
choosing either. Mixed-history authority or closed-epoch competition refuses.
Each selected epoch retains complete old/new plaintext equality and current
authentication; the final content steps use the already installed epoch key.

Session generation continues through a receipt returned atomically by guarded
key installation. The coordinator cannot adopt a fresh generation observed after
an unrelated lock or unlock, even if the same key was reinstalled. Pending work,
checkpoint changes, source changes, cancellation and step-budget exhaustion lock
the session without reversing committed trust. Restart requires an explicit
authenticated session at that exact prefix. Cache failure does not undo trust.

`current` means the fully authenticated unique head of the unchanged observed
source, not provider-global freshness. Progress counts actual content-checkpoint
replacements and key-epoch replacements. Content prefixes fully checked within
an epoch jump are not counted as separate replacements. A terminal head at the
exact step budget succeeds; another required advancement refuses before opening.
No token operation, new persisted format or source publication is introduced.

[Fourteen coordinator declarations](../Tests/KeyCoreTests/V3RecoveryCatchUpCoordinatorTests.swift)
reuse the two-Mac filesystem fixture and concrete step services. They cover all
supported lifecycle kinds, edits before/between/after epochs, initial conflicts,
late siblings, budgets, cancellation after a committed epoch, session replacement,
pending/checkpoint races, cold or wrong state, missing future ciphertext, cache
failure and concurrent stale callers. A separate session test checks installation
receipts. These are software checks, not native-prompt or hardware qualification.

### Integrated software lifecycle checks

The [lifecycle integration tests](../Tests/KeyCoreTests/V3RecoveryLifecycleIntegrationTests.swift)
combine enrollment, rotation, recipient addition, revocation and recipient removal
with ordinary edits and coordinated catch-up. Each Mac has its own checkpoint and
session; both take turns saving and then catch up to the other's save. A revoked
Mac refuses without opening a wrapper. After sessions are invalidated, caches are
removed and the Mac fixtures leave scope, the software backup recipient must
recover the final snapshot with one agreement callback and preserve both saves,
the latest edit and a TOTP entry. Explicitly removing all recovery recipients
must instead refuse recovery while ordinary Mac access continues.

Publication and cryptography are concrete. Recipient addition uses the existing
domain builder with fixture materialization, not another possession ceremony.
These checks do not qualify a physical token, native prompt behavior or shipping
dispatch, and they are not an independent security audit.

## Proposed data contract

Keep outer vault/envelope version 3 and the understood envelope shape.
Recommend a new explicit `device-wrapped` profile version 3; do not alter
profile 2. The number is provisional until reviewed fixtures lock dispatch.
The new profile can have no recovery recipients until explicit registration.

Keep device records, device wrappers, key identity, and entry codecs under
their established ownership. Add an authenticated `recovery` object containing
an unordered-in-time random generation UUID, ordered recipient records, and
ordered recovery wrappers. Current-key-only wrapping remains the target;
the candidate proof is specified above, but its encoding remains unfrozen and
the complete profile and integrated verifier remain experimental.
Generation changes identify recipient-authority
changes, not a global freshness counter. Device/key transitions preserve the
recipient generation while binding wrappers to the new epoch/transition.

Recipient records distinguish recovery authority from Mac authority. Proposed
fields are registration UUID, recipient ID, P-256 public key, PIV slot, and
active/revoked status. Recipient ID is a domain-separated public-key digest;
the experimental domain/encoding now has exact 805 fixtures. Require unique
active credentials, canonical ordering, and exactly one recovery wrapper per active recipient,
with none for revoked/unknown recipients. Independent backup keys must differ.
Public labels, if needed, cannot replace cryptographic identity.

Recovery HPKE contexts bind the profile/suite, vault ID, key ID, authority
transition ID, recipient ID, registration UUID, recovery generation, and slot.
Use separate recovery `info` and AAD domains. Do not put the resulting envelope
digest in an in-envelope wrapper context; that would be self-referential.
The signed/MACed manifest authenticates the wrapper bytes themselves.

The token anchor pins the exact registration manifest digest, vault ID,
recipient identity, registration UUID, slot, and supported profile/suite under
an explicit format/version. The registration manifest supplies the initial
trust floor and wrapper when no later epoch exists. After key changes, the
dual-authorized final epoch root supplies the selected wrapper; registration does not
need a permanent snapshot capsule or separately retained artifact.
Bound the anchor to 1,024 bytes and reuse ordinary repository limits for source
objects. The [internal anchor codec](../Sources/KeyCore/V3RecoveryAnchor.swift)
has exact experimental field fixtures, including `registrationManifestDigest`.
Parsing establishes shape, not protected token provenance. Native storage
framing and administration remain unqualified; these are not frozen release bytes.

Use the already tested application-specific PIV object, with unknown occupancy
refusal, not an overloaded standard object or certificate extension. Its
public readability is not decryption authority; its protected administrative
integrity is essential. Yubico recommends undefined application tags over
overloading defined objects: [GET and PUT DATA](https://docs.yubico.com/yesdk/users-manual/application-piv/get-and-put-data.html).
The existing disposable object is occupied. This document does not authorize
replacing it, any slot contents, or management credentials.

### Implemented recipient and wrapper increment

The [recipient roster](../Sources/KeyCore/V3RecoveryRecipients.swift) implements
record version 1 with a generation UUID, ordered recipients, and ordered
wrappers. Each recipient has a validated P-256 point, derived credential ID,
registration UUID, slot 9d, and active/revoked status. Wrapper addresses bind both
credential and registration. The roster requires unique credentials and
registrations, canonical ordering, and exact active-recipient coverage. Empty or
all-revoked rosters are structurally valid; they do not establish recovery
readiness or authorize removing the last active recipient.

The experimental codec limits the roster to 64 recipients/wrappers and 65,536
encoded bytes. These are resource bounds, not a settled product-capacity promise.
The containing profile must enforce its own input budget before decoding.

The [recovery context](../Sources/KeyCore/V3RecoveryVaultKeyHPKE.swift) binds
profile 3, the complete HPKE suite, vault/key/transition identity, generation,
recipient, registration, and slot through separate recovery info/AAD domains.
The shared CryptoKit sender preserves profile-2 inputs. Opening checks the
address and adapter public key before agreement, then authenticates the box and
checks the recovered key ID. Software fixtures establish one agreement callback
and cancellation propagation without retry, not integrated hardware approval
counts or PIN/touch policy.

These bytes remain experimental until integrated review and qualification.
Parsing or opening alone proves neither origin, token possession,
anchor state, nor a verified snapshot. No product caller is enabled.

### Implemented profile and boundary transcripts

The [profile codec](../Sources/KeyCore/V3RecoveryManifest.swift) now dispatches
explicit device-wrapped versions 2 and 3 inside the existing version-3 envelope.
Shipping services still accept only profile 2. Both bodies share device/suite/
entry shape and semantic validation; their typed profile discriminators remain
separate. Parsing a canonical body/envelope is bounded by the existing 2 MiB
manifest budget, with the canonical parser's existing nesting bound. Graph
object/depth/aggregate budgets remain a separate responsibility.

Profile 3 adds `epochAuthority` record version 1 and the recovery roster above.
The authority contains the capsule and a nullable `transitionProof`. A stored
`null` proof denotes an independently validated origin, not an authorized
continuing boundary. A boundary proof has version 1, a fixed algorithm, exact
parent-envelope digest, and canonical low-S signature. Cross-role reuse of an
epoch/recovery credential as a Mac signing/wrapping key is rejected.

[Boundary construction and checks](../Sources/KeyCore/V3RecoveryEpochBoundary.swift)
use `work.tvr.key/v3/epoch-transition-authorization/v1`, a NUL delimiter, and
canonical candidate content with only `epochAuthority.transitionProof.signature`
omitted. The parent reference, algorithms, new capsule, device/recovery records,
wrappers, and entries remain covered. The old epoch signs this statement, then
the existing Mac signer signs finalized content through the existing manifest
domain. The MAC is computed under the new vault key. A public check verifies
both signatures against the exact parent, without treating historical MACs as
verified. Separate current-key checks verify the MAC and capsule correspondence.

Same-epoch metadata checks require unchanged device/recovery rosters, wrappers,
epoch capsule and proof, vault/key/transition identity across every parent.
These checks do not select or authorize a provider graph. Boundary construction
does not replace roster policy, full publication validation, fresh-key policy,
wrapper checks, or complete resealing. Its output is parsed state, not a
publication-approved candidate or trusted checkpoint. The [experimental schema](schemas/v3-recovery-manifest-body.schema.json)
and exact software fixtures are retained for review; shipping schemas are unchanged.

## Recovery ordering and operation budget

1. Read the public credential and anchor in one bound native session. Validate
   framing/identity, find the exact pinned manifest, and bound the required
   canonical graph before private activation. Close the reader session before
   activating the private key. The token certificate is a public-key container,
   not a separately retained trust receipt.
2. Validate all required paths from that token's floor, authority records,
   inherited proofs, permitted roster transitions, and both signatures at each
   epoch boundary. Select one exact final-epoch root and its addressed wrapper,
   never a provider-selected unsigned latest wrapper.
3. After explicit review, request one HPKE decapsulation. No automatic retry,
   implicit second epoch attempt, or software fallback is permitted. HPKE Base
   opening alone does not authenticate origin; see
   [RFC 9180 §9.1](https://www.rfc-editor.org/rfc/rfc9180.html#section-9.1).
4. Check the recovered key ID, final root and required current-epoch MACs, final
   capsule correspondence, content/merge rules, and all selected current entries.
   Only complete verification produces a restorable snapshot.
5. Revalidate source bytes and token/directory identities before publication.
   Restore under fresh vault/key/device IDs, prove fresh ordinary Mac-bound
   reopen, then select the destination. Clear scoped key material on failure;
   do not persist plaintext or raw keys for resume.

The public proof state is distinct from a MAC-trusted checkpoint and a verified
snapshot. Do not bypass ordinary validator MAC checks or manufacture a trusted
checkpoint from public commitments. Only a verified snapshot may enter restore.

Content merges require identical authority across every required parent path.
Resolve content before an authority change from one exact checkpoint. Competing
authority transitions are conflicts. Closed-epoch off-path branches not covered
by signed commitments cannot be authenticated or dismissed using only the final
key. Conservatively refuse reachable unresolved branches/placeholders. This can
permit denial of recovery through injected garbage; provider availability control
does not remove the need to define and test this classification.

The internal verifier below implements these software checks. Final `REC-806`
acceptance still requires integrated review, native anchor provenance and the
restore service's input boundary. PIN/touch policy and prompt behavior are
separately qualified under `REC-807`, not assumed from caching.

### Implemented history and snapshot verification

The [history selector](../Sources/KeyCore/V3RecoveryHistory.swift) uses the existing
bounded, read-only immutable-object interface. It hashes every observed manifest
against its exact object address and starts trust at the supplied anchor floor.
The supplied credential's derived ID, registration, slot, and active floor
record must match. Platform code must obtain the anchor and public credential
from one bound token read; parsing provider JSON is not an equivalent authority.
No product caller supplies that native provenance yet.

Selection follows all visible descendants and every required parent path,
stopping replay at the exact floor. Iterative traversal rejects missing or
unanchored parents and enforces depth and aggregate parent-edge bounds. Every
same-epoch edge preserves exact authority, capsule, proof, rosters, and wrappers.
Content records retain the highest unchanged parent revision or advance it by
one; new records start at one and deletion is permitted. Merges must share the
same epoch root. An authority boundary has one parent, both valid signatures,
new visible key/transition/epoch-public-key identities, retained immutable roster
identities and revoked tombstones, an active continuing signer, and unchanged
entry IDs/names/types/revisions. Rotation preserves revisions while resealing.
Recipient changes require a changed generation; unchanged recipients retain it.
Publication remains responsible for fresh randomness, ceremony-specific roster
policy, wrapper opening and complete same-plaintext resealing.

One unresolved head in each of two same-epoch branches is a content conflict.
Competing epoch lineages are an authority conflict. An older off-path head beside
a continuing newer epoch is a closed-epoch branch refusal. No timestamp or
revision breaks these ties. A listed same-vault tip with an unavailable path to
the floor also refuses selection. Known pre-floor ancestors and valid outer
objects naming a different vault do not require body-profile interpretation or
private replay. Unreadable, hash-invalid, malformed outer objects, or objects
without a usable vault identity cannot be established as unrelated and refuse
selection even outside the reachable graph. This conservative policy permits
denial of recovery through opaque garbage; it does not claim provider freshness.

The domain defaults reuse the ordinary 4,096-object, 1,024-depth,
16,384-entry-reference, per-object and aggregate-byte limits, with an additional
16,384 aggregate parent-edge cap. Nondigest directory names consume object
budget, as do required objects missing from the listing. These are experimental
resource limits, not a product capacity guarantee. All reachable manifest entry
references count, but only selected current entry ciphertexts are read.

The [snapshot verifier](../Sources/KeyCore/V3RecoverySnapshot.swift) reselects the
public plan before one final-epoch HPKE opening. It then checks the recovered
key ID, final root MAC and capsule correspondence, every required current-epoch
MAC, and every selected entry's digest, context, AEAD, UTF-8 and type semantics.
TOTP values must be valid normalized Base32 seeds. It never opens older epochs
or falls back after failure. Only complete verification constructs the internal
snapshot type. Cancellation preserves the callback error without retry.

Source listing/manifest bytes and selected entry bytes are checked again before
returning. Restore must repeat these checks immediately before publication and
combine them with fresh native token/credential, directory-identity and
destination-transaction checks. Plaintext stays in the returned in-memory
snapshot; the raw vault key is not a snapshot field. Swift data and string
lifetimes do not guarantee zeroization. No plaintext persistence or resume
format is implemented. Software callback counts and disposable filesystem tests
do not qualify hardware prompts, protected administration, or a complete restore.

### Implemented restore candidate preparation

The [internal restore candidate](../Sources/KeyCore/V3RecoveryRestoreCandidate.swift)
accepts the verifier-only complete snapshot, not caller-supplied plaintext or an
archive diagnostic. It rechecks exact source observations and reuses permanent
genesis construction. Its future owner must supply fresh random identifiers/key
material and new platform Mac credentials; preparation neither generates nor
persists them. Selected source namespace/entry/transition IDs and device/recipient
public keys cannot be reused as destination authority.

The output contains scoped in-memory plaintext and encrypted candidate objects,
not a durable intent or permission to publish. Independent validation reparses
the permanent envelope and checks its digest/MAC, exact one-Mac roster/wrapper,
complete encrypted snapshot, limits, revision-one entries and source-byte/type
equality. Unicode-equivalent but byte-different secrets are not interchangeable.
The source is rechecked afterward. No source ancestry, epoch capsule or recovery
roster is inherited; the destination starts without recovery registration.

[Six software declarations](../Tests/KeyCoreTests/V3RecoveryRestoreCandidateTests.swift)
cover ordinary rotation/edit-to-recovery composition, empty and populated inputs,
changed sources, reused authority, mismatched objects and bounded resources.
The destination wrapper still requires a Mac opening. Internal durable ownership
and encrypted preparation, plus internal manifest-last publication, are
implemented below, together with internal checkpoint installation and an ordinary
runtime reopen, exact configuration selection/reconciliation and ordered ownership
finalization. The native-bound service now composes complete initial restore and
exact reauthenticated resume below. Product dispatch/barriers, separate-process
and physical qualification remain. No product restore route is enabled.

### Implemented authenticated restore preparation service

The internal [restore service](../Sources/KeyCore/V3RecoveryRestoreService.swift)
requires independently retained source/parent directory handles, an unconfigured
Mac and an observation issued by its native public reader. It rejects a foreign
reader observation, changed card/key/anchor, unrecognized anchor, weaker policy,
wrong journal/config root or existing local attempt before requesting recovery
agreement. Public source selection precedes the one-operation native adapter;
the existing verifier then authenticates the complete current snapshot.

A shared source mutation owner spans the request. The existing session's
authentication-generation ticket, cancellation and deadline are checked before
and after authentication and at subsequent admission boundaries. The ticket is
only a race guard; no recovered key is installed in that store. After recovery
agreement drains, a token-operation lease spans preparation. Rechecks verify
the same native token observation and source contents; public card sessions
close before Mac private operations. Source, destination and config observations
are not globally atomic filesystem locks. The future host must serialize this
work against init/enrollment/configured requests and invalidate the generation
on lock or disconnect.

The new folder is created only after source authentication. A complete public
reservation is durably pinned before the service creates fresh Mac credentials.
The service independently reloads the persisted identity and opens the prepared
Mac wrapper, comparing the opened key before admitting complete encrypted
preparation. Random destination key bytes and plaintext remain scoped memory;
the temporary wrapper-proof session is invalidated before staging. The result
contains operation/checkpoint identifiers, path and entry count, not saved
approval, recovered secrets or publication authority.

Journal scope callbacks are synchronous and nonescaping. They check before
ownership transitions and at the synchronized no-overwrite record rename
boundary. Locks, cancellation, stale source/token state and uncertain credential
creation leave exact durable evidence for investigation or later explicit
completion. A reservation never authorizes generating replacement credentials;
another prepare refuses before another native agreement or directory creation.
The internal `prepare` method publishes no destination objects, trust/cache,
configuration or cleanup. It remains an isolated preparation entry point, not a
proposed two-command product flow. Full `restore` now completes under the same
one-agreement source scope; `resume` authenticates afresh for interruptions.

[14 software declarations / 45 cases](../Tests/KeyCoreTests/V3RecoveryRestoreServiceTests.swift)
exercise these boundaries with actual binding adapters, crypto, files and the
mutation owner. Native I/O and local ownership storage alone are substituted.
No hardware prompt count or real Secure Enclave acceptance is established here.

### Implemented scoped restore completion and resume

The service's initial `restore` composes the existing manifest-last publisher,
insert-only trust installer, ordinary-runtime reopen, no-overwrite configuration
selection and ordered finalizer inside the same authenticated source scope.
Source/token observation, authentication generation, cancellation and deadline
checks remain synchronous and nonescaping at private-operation admission,
atomic publication boundaries and ownership removal. The report contains only
operation/checkpoint identifiers, path and entry count. It cannot authorize a
later operation or retain consent.

Explicit `resume` requires exact device-local ownership before recovery
agreement. It rejects incomplete reservation-only state, changed source
selection, changed preparation, replaced locations and unrelated configuration.
Complete bytes with a still-prepared pin can be verified and promoted; no new
credential, random destination key, resealing or destination creation occurs.
Resume independently reloads the saved Mac identity and opens the saved wrapper
in a temporary session, which is invalidated before continuation.

An unselected resume completes publication, trust and selection. If the exact
configuration is already selected, resume requires the exact existing
checkpoint/cache before authentication, skips publication/selection and runs
fresh completion verification before cleanup. It does not repair trust or
silently adopt later ordinary edits. Reservation removal precedes preparation
removal. Preparation-only ownership can finish this half-completed cleanup;
with neither pin remaining, resume reports no pending attempt rather than
claiming retrospective success after a lost reply.

[Nine software declarations / 83 cases](../Tests/KeyCoreTests/V3RecoveryRestoreCompletionServiceTests.swift)
exercise initial restore, 21 interruption boundaries, cancellation/lock guards,
late atomic-renaming guards, exact resume and existing-trust requirements. A
freshly composed ordinary runtime reads, mutates and cold-reopens the restored
vault without recovery-token availability or an injected restore key. This is
a same-process test, not separate-process or physical acceptance. Initial
restore uses one source agreement and five saved Mac-wrapper operations in
these tests; Mac operation counts do not establish physical Touch ID prompts.
Shipping host serialization, lock/disconnect invalidation, product dispatch and
native acceptance remain unwired.

### Gated host and connection integration

The [service request](../Sources/KeyCore/KeyRecoveryRequest.swift) now represents
initial restore and explicit resume with bounded public locations, token ID and
the existing recipient ID. It does not carry credentials, secrets, native
observations or consent. Structural validation is not native binding. The
native [workflow](../Sources/KeyCore/V3RecoveryRestoreWorkflow.swift) independently
resolves the exact selector and invokes the restore service using the supplied
host scope's authentication store, cancellation and deadline. Its live factory
exists but is not installed in the shipping host.

The [host](../Sources/KeyCore/KeyServiceHost.swift) admits at most one pending or
active recovery request through its existing exclusive barrier. Other recovery
clients are refused immediately. Active recovery requires no configured handler.
Lock invalidates the generation and cancels the scope before waiting on the host
queue; an active-recovery lock can therefore reply while native UI still drains.
The native gate is not released early and a late response cannot become success.
The [helper](../Sources/KeyLaunchAgentHelper/main.swift) cancels scopes registered
on an interrupted/invalidated connection, including later registration on that
same closed connection, without cancelling another connection's scope.

The client reply bound is 120 seconds; the host scope deadline is 90 seconds and
includes queue waiting. These bounds do not promise immediate native termination.
The utility role remains limited to status/lock. Restore/resume success requires an
actual configuration and the existing post-reply helper shutdown handshake.
Restart timeout guidance refuses a second initial restore.

Once restore/resume enters, process-local uncertainty blocks competing setup and
configuration changes; explicit resume remains available. Configuration present
on any exit requires helper restart, even after an error or cancelled/lost reply.
Restart-persistent admission now checks the presence of either existing local
restore ownership namespace. The in-memory guard is not durable recovery
authority. Recovery dispatch and this inspector are supplied as one capability;
the host cannot accept the dispatch hook without an ownership dependency.
Stable and ordinary Preview live hosts keep that capability disabled. Public
token/source review and restore/resume now have CLI syntax and help, but no shipping recovery operation,
saved-attempt scan, replacement credential or cleanup is enabled here.
[Host tests](../Tests/KeyCoreTests/KeyRecoveryRoutingTests.swift) include actual
restore-service cancellation but substitute native I/O and service composition;
actual XPC interruptions and hardware acceptance remain unqualified.

### Restore and resume CLI boundary

The [parser](../Sources/KeyCore/CLIParser.swift) exposes `key recovery restore`
and `key recovery resume`, both requiring exactly one `--source`,
`--destination`, `--token` and complete `--recipient`. Initial restore also
requires exactly one valid `--name`; resume refuses a replacement name. Repeated
options, incomplete or malformed selectors, credentials and force/bypass flags
are rejected before dispatch. The recipient ID is the existing recovery public
key identifier, not the earlier feasibility certificate fingerprint.

The [application](../Sources/KeyCore/KeyCLIApplication.swift) resolves both
explicit paths against one captured working directory and validates the bounded
absolute request before sending it. No configuration default, CLI credential
collection, automatic retry, resume-to-restore fallback or local cleanup is
introduced. The existing full-CLI XPC role and success shutdown handshake are
unchanged. Failure or lost-reply guidance preserves all state and directs exact
saved attempts to explicit resume; absent, incomplete or changed state still
requires inspection. Help warns that live operations remain disabled and that
the new vault does not inherit recovery registration.

The [CLI tests](../Tests/KeyCoreTests/RecoveryCLITests.swift) compose the actual
parser, application, host, workflow and restore service over real software
crypto/files with substituted native keys and local pins. They cover initial
completion, durable-preparation interruption, fresh-host exact resume and
completed-attempt refusal without another agreement. They do not establish
signed XPC/helper restart or native prompt behavior. Public read-only review now
has its own nonmutating admission/response path; it does not reuse restore's
pending guard or requirement to select configuration.

### Public token/source review

The [read-only wire request and workflow](../Sources/KeyCore/KeyRecoveryReview.swift)
expose token inventory and explicit source review separately from restore.
`key recovery tokens [--json]` lists at most 64 public candidates without choosing
one or opening a credential. `key recovery review --source <directory> --token
<token-id> [--json]` requires an existing independently opened source and exactly
one selected token. No destination, private credential or approval is accepted.

Source review requires the existing reported generated/PIN-always/touch-always
policy and a recognized key-bound anchor, then reuses the public history selector.
It compares repeated public token/source observations, preserves resource limits
and checks path identity, cancellation, generation and deadline around filesystem
reads. Its source adapter refuses all entry-object reads. No agreement, Keychain,
local ownership, Mac-key, config or mutation dependency is present.

The result contains only public identifiers/policy, the observed public head and
unverified entry/manifest counts. JSON source reports explicitly carry
`public-observation-only` assurance; human output makes the same limits clear.
Review proves neither possession, protected token administration, PIN/touch
enforcement, restorable contents nor provider freshness. It never supplies a
confirmation reference or saves consent, so restore independently rechecks its
selectors and source before fresh private authentication.

The host shares at-most-one admission and the existing bounded connection/lock
scope with restore, but review does not mark or clear pending state, inspect
ownership, select configuration or authorize helper shutdown. It runs as a
concurrent read, allowing lock to reach an active configured runtime; setup/config
barriers wait for it to finish. Public review can inspect a source on a configured
Mac or while saved-attempt ownership remains, without granting ordinary runtime
or setup authority. No live hook is installed in Stable/ordinary Preview.
The full-CLI role is required; utility access remains status/lock-only.

[Review tests](../Tests/KeyCoreTests/KeyRecoveryReviewTests.swift) include real
public selector/filesystem/CLI composition and asynchronous host ordering over
software token fixtures. They do not qualify physical card behavior, actual XPC
disconnect, signed helper distribution or protected administration.

### Restart ownership admission

The [Keychain inspector](../Sources/KeyCore/V3ImmutableTransactionRecoveryAnchor.swift)
uses the exact service/access-group construction already used for local pins.
It checks only the restore-reservation and restore-preparation namespaces, with
one match per query, synchronization disabled and a noninteractive authentication
context. It supplies no return type and a nil result pointer. It neither lists
accounts nor reads or parses item contents. Namespace-wide queries are never
used for writes; existing pin reads and compare-and-swap updates still require
the exact source vault ID.

Only two not-found results establish absence. Either pin blocks admission even
if its contents, account or accompanying files are unusable. Any other status,
including unavailable storage, missing entitlement or forbidden interaction,
refuses admission rather than assuming a clean Mac. The result is not cached.
This is a refusal guard, not evidence that a particular attempt is valid or that
recovery succeeded.

Before initial restore, init, directory-scoped enrollment or changing the vault
directory, the host requires both its process-local guard and the durable
inspector to permit admission. A cold configured host also checks before
composing ordinary authority, since selection can precede final pin cleanup.
Lock remains available without that query. Unconfigured status remains a locked
status without composing anything. Explicit resume bypasses the broad presence
guard but still runs the existing exact source-bound journal, physical-location,
trust and fresh-authentication checks. Cleared pins and inert files cannot
retrospectively authorize resume or claim success.

The [tests](../Tests/KeyCoreTests/KeyRecoveryOwnershipTests.swift) run real restore
and resume services across fresh host instances, with software crypto and native
I/O substituted at the existing boundaries. Keychain status/query-shape tests
substitute only the matching call. They do not establish signed Keychain access,
actual helper-process restart, Secure Enclave behavior or physical prompt counts.
The shipping host must install the native factory's paired capability before
enablement; live Stable and Preview remain unchanged and disabled.

### Native restore composition boundary

The [workflow](../Sources/KeyCore/V3RecoveryRestoreWorkflow.swift) opens source and
destination-parent handles from the independently supplied request paths. Initial
restore requires a missing final destination, including refusal of existing
empty directories, files and links. Resume opens the existing destination. It
resolves exactly one requested native token ID, reads only that candidate and
requires the complete recipient ID, fixed recovery policy and recognized anchor.
No automatic key selection, admin command, PIN value or saved observation is
accepted. The existing service revalidates the reader-issued observation and
source selection before its one fresh agreement.

`KeyConfigStore` owns local metadata preparation. Initial restore may create
`Library`, `Application Support`, the product directory and the checkpoint-cache
directory below an existing home. Each component is a bounded retained-parent
operation, with 0700 mode for newly created directories, parent synchronization,
nofollow child resolution, descriptor-identity comparison and scope/path
rechecks. Existing permissions and contents are not replaced. Physical ancestry
reuses the restore environment's parent walk; a source/config overlap or a
destination in the config tree is refused. A requested destination cannot double
as a metadata component, even through an aliased parent or a case variant.
Reserved metadata names are compared case-insensitively even on a case-sensitive
filesystem.

This local scaffolding may precede source-key authentication. No selected config,
journal ownership, Mac credential or restored destination is created at this stage. A
failure can leave those local directories in place for inspection; no rollback
deletion is attempted. Vault creation and durable reservation still occur only
inside the authenticated restore service. The scope is checked throughout local
preparation and the exact host authentication/cancellation/deadline dependencies
are passed to the service. Resume creates no metadata directory and refuses a
missing config root, cache root, destination or parent before agreement.

The live factory composes the existing public token reader, native agreement
provider, local ownership stores, Secure Enclave device identity manager,
checkpoint store and filesystem cache. Construction alone performs no native
operation or filesystem mutation. The paired capability is per-workflow and is
not a configured ordinary runtime. Successful output contains public restore
metadata and warns that the new vault has no recovery registration. It does not
carry a key session or authority from the source.

[Workflow tests](../Tests/KeyCoreTests/V3RecoveryRestoreWorkflowTests.swift) use
actual selectors, config/cache locations, restore/resume services and contained
files with software native providers and memory Keychain storage. Ordinary
access is independently reopened from the selected config, saved Mac identity
and composed cache after recovery-token availability is removed. This does not
qualify native selectors on a real token, signed Keychain/Secure Enclave access,
actual process restart, XPC interruption or physical PIN/touch behavior. Live
dispatch and CLI commands remain disabled until their separate rollout work.

### Implemented restore locations and intent format

The [filesystem environment](../Sources/KeyCore/V3RecoveryRestoreEnvironment.swift)
creates only a missing final destination folder beneath an independently opened
parent. It checks physical ancestry before creation, including symlinked
ancestors, so the source and local configuration tree cannot contain the
destination. Existing empty folders are refused, not adopted. The source,
destination, destination parent and configuration root retain exact standardized
paths and device/file identities. Later checks reject replaced folders or any
configuration, including malformed files, directories and dangling symlinks.
This initial path supports an unconfigured Mac only. The internal environment
requires an existing configuration directory and never bootstraps it or
overwrites a selection. The explicit workflow prepares local scaffolding for an
initial restore; resume and inspection continue to require existing roots.

The [restore intent format](../Sources/KeyCore/V3RecoveryRestoreIntent.swift) binds
those locations, one operation ID, the source anchor/credential/head, a stable
commitment to the observed public history/listing, and the destination genesis
digest/key ID/owner. The exact genesis digest commits its roster, transition,
wrapper and complete encrypted entry references. Record authentication uses
HKDF-SHA256 and HMAC-SHA256 with a restore-only domain, keyed by the new
destination vault key. It does not retain the source key. Canonical parsing
requires exact fields, bounded bytes, canonical identifiers and paths; it does
not authenticate the record or establish token provenance.

Record construction revalidates the verifier-only snapshot through the retained
source descriptor before and after authentication. A snapshot from an unrelated
reader cannot be accepted solely because the caller supplied plausible paths.
The saved anchor is still a binding, not a substitute for a fresh native token
read during an actual recovery ceremony.

This format is not saved approval. The internal journal below now reserves local
ownership and stores complete encrypted preparations. Product resume must first
establish local ownership of the exact saved preparation before opening its
addressed Mac wrapper, then authenticate this record and reverify the source and
complete destination contents. A matching MAC alone cannot authorize publication.
Internal components now install checkpoint trust and select configuration after
ordinary reopening. Source/native binding, session-generation checks, explicit
reauthentication and serialized composition remain the restore owner's
responsibilities. The checks observe filesystem state;
they do not lock folders against concurrent external changes.

### Implemented local restore reservation and encrypted preparation

The [restore journal](../Sources/KeyCore/V3RecoveryRestoreJournal.swift) owns two
separate non-synchronizing device-local records, using the existing ownership
store and contained atomic file writer. Both are keyed by the source vault ID,
not the newly generated destination ID. One pending attempt blocks another
attempt for the same source on that Mac/product. The namespaces cannot collide
with ordinary transactions, registration or profile adoption. The ownership
anchor format and those existing workflows are unchanged.

Before any platform credential is created, `reserve` pins the operation and
SHA-256 digest of a [public reservation](../Sources/KeyCore/V3RecoveryRestoreReservation.swift).
That record binds the exact reviewed source, physical locations, and fresh vault,
transition and entry IDs. The journal writes and synchronizes its canonical
bytes, reads them back and rechecks the source and pins before returning. The
new-directory gate is shared across environment copies and consumed once;
independently reopened handles cannot start another reservation. The record
contains no raw key, credential or saved authorization.

After full candidate validation, `stage` pins the SHA-256 digest of the complete
[encrypted bundle](../Sources/KeyCore/V3RecoveryRestoreBundle.swift) before writing
it. The bundle contains the authenticated intent, exact genesis envelope and all
encrypted entries. It is local-only at
`v3-restore-attempts/<operationID>/preparation.json`, beside `reservation.json`
under the configuration root, not in the recovery source. Both records use
bounded canonical parsing and exact bindings. Parsing alone does not authenticate
the MAC, ciphertext or plaintext equality.

`loadPending` follows only the operation ID in the local reservation pin. It
does not scan for files, adopt a provider record, or open source/destination paths
from JSON. It checks the complete saved bytes against both ownership digests
before returning any candidate wrapper. Files without local ownership are inert.
Missing, changed, oversized, symlinked or otherwise invalid records stop the
operation. A reservation without a complete preparation does not authorize
replacement credential creation or automatic reconstruction.

Explicit `confirmPreparation` takes a freshly recovered source snapshot,
destination key and expected Mac identity from its caller. It authenticates the
intent and validates the saved manifest and every ciphertext against that source
using the existing full genesis checks. It neither encrypts again nor generates
new IDs, wrappers or credentials. The source and live locations are rechecked;
both files are read back and synchronized; both ownership pins are compared
before and after the preparation becomes durable. A final reload checks that the
records still match. These observations do not replace the future service's
serialized mutation owner, current authentication scope or lock-generation checks.

The journal itself has no private-key caller, cleanup, publication, checkpoint,
configuration selection or product resume route. Software tests use real
disposable filesystem writes and software keys, including a fresh journal reader,
independently opened handles and a new destination wrapper opening. They do not
qualify a separate OS process, native credential provenance, the new Keychain
namespaces or physical-token behavior. Interrupted partial reservations remain
pending for later explicit reconciliation; they are not silently abandoned.

### Implemented restore publication and exact reconciliation

The internal [restore publisher](../Sources/KeyCore/V3RecoveryRestorePublisher.swift)
accepts a fresh source snapshot, destination key and already loaded addressed Mac
identity. It confirms the exact owned preparation and validates it under the
publication limits before a private operation or destination write. The existing
permanent-profile checkpoint unlocker opens the saved Mac wrapper once and checks
the resulting key against the supplied destination key. Its validation session
is scoped to the call and invalidated on success and failure. No platform
credential is created, and no private operation is automatically retried.

The complete encrypted preparation is already durable staging. Publication uses
the existing contained no-overwrite atomic writer directly at the final immutable
addresses, rather than creating another transaction namespace and later deleting
it. Entries are installed, read back and synchronized before the genesis manifest
becomes visible. Full existing genesis checks compare the published bytes with
the freshly verified source contents. Live source/location bindings and both
ownership records are rechecked across publication and before return.

Destination inspection accepts only a subset of the exact owned object addresses
before the manifest exists. Known empty parent directories left by an interrupted
creation are allowed. Unknown files, extra entries or manifests, symlinks,
malformed bytes and orphan `.partial` files stop the operation and remain
untouched. Root and child listings are bounded and use fresh directory-open
descriptions, not a reused directory cursor.

A later explicit call validates the saved preparation and opens its addressed
Mac wrapper again. It may install missing entries only while the manifest is
absent. If the exact manifest is already present, every referenced entry must
already exist with its exact prepared bytes; the publisher does not repair a
committed snapshot. Existing exact objects are rechecked and synchronized, not
resealed or replaced. Cancellation and other failures leave the owned preparation
available for a separate explicit call, subject to the same fresh checks.

The returned report identifies the published checkpoint, not permission to
install local trust or select the vault. The publisher writes no checkpoint,
manifest cache, configuration, token object or persistent key session and does
not clear ownership. Product requests, native source/identity provenance,
session-generation checks and serialized helper ownership still need service
integration. Filesystem observations cannot lock out concurrent external changes;
a detected change stops the operation without rolling back published objects.

[Software tests](../Tests/KeyCoreTests/V3RecoveryRestorePublisherTests.swift) cover
empty/populated publication, each observer boundary, interrupted atomic writes,
explicit later reconciliation, cancellation, wrapper mismatch, source/config/pin
changes, destination damage and bounds. They use real disposable files and
software wrapper operations. They do not qualify native authentication, actual
process termination, separate-process ordinary reopening, large-vault performance
or real-token recovery. A process crash that leaves an unknown partial file is
not claimed to be automatically resumable.

### Implemented restore trust and ordinary-runtime reopening

The [trust installer](../Sources/KeyCore/V3RecoveryRestoreTrustInstaller.swift)
rechecks complete published objects through the publisher's non-repairing
confirmation path. A previous publication report is not authority. Missing or
altered files stop the operation before a wrapper opening or checkpoint insert.
Only an absent checkpoint can be inserted. An existing exact checkpoint supports
explicit continuation; malformed or different trust is never replaced.

The existing identity loader reconstructs the addressed Mac identity. Its saved
wrapper must open to the prepared key before first trust. Exact encrypted manifest
bytes are cached with the existing filesystem cache, then the absent checkpoint
is inserted using the existing store's compare-and-replace boundary. Failures
retain any committed exact trust and ownership rather than rolling it back.

The validation session is cleared. A new empty session and ordinary permanent
read runtime load the identity again and independently open the published wrapper.
Every item name, type and plaintext byte is compared with the scoped recovered
snapshot. The prepared key is never injected into that ordinary session. Both
temporary sessions are invalidated on exit. These two Mac-wrapper operations are
software-qualified calls, not a guarantee about native authentication prompts.
This component makes no recovery-token operation.

Source, locations, saved records, checkpoint and exact cache bytes are rechecked
across durable steps and final reopening. The report is not saved consent or
configuration selection. No configuration or token is written, no credentials
are created, and no ownership is cleared. Current native authentication scope,
session generation and helper serialization remain service responsibilities.
Software tests use real files/cache and memory checkpoints; separate-process,
Secure Enclave, large-vault and physical recovery qualification remain.

### Implemented restore configuration selection and exact continuation

The [selection installer](../Sources/KeyCore/V3RecoveryRestoreSelectionInstaller.swift)
loads the locally owned preparation and independently supplied physical handles.
It repeats trust installation and fresh ordinary-runtime verification rather
than accepting a saved success report. Only then does the existing atomic
no-overwrite writer publish the normal local configuration. The exact source,
files, ownership, cache and checkpoint are checked again after the temporary
config is synchronized, before publication, and after selection.

An explicit later call can accept an already-selected config only when its bytes
exactly match the intended destination path, vault ID and local mode. It requires
existing exact checkpoint trust before loading credentials; config cannot
reconstruct missing trust. The saved identity opens the wrapper again through
new temporary sessions, and the actual complete snapshot is verified again.
Selected configuration is synchronized without rewriting it. Even a formatting
change is not normalized or overwritten by this continuation path.

Ordinary preparation/reopening still requires absent config. A completion
environment cannot stage or publish a restore again. Missing or damaged objects,
different trust, changed source or replaced folders stop continuation. Committed
config/trust are retained, not rolled back. Later ordinary edits that advance
the restored checkpoint need separate reconciliation; this exact-genesis path
does not adopt them as completed restore evidence.

This selection component retains both ownership pins and encrypted records.
The separate finalizer below can retire exact selected ownership. Native
approval/session binding, serialized service composition and product routing
remain unimplemented. This component neither creates credentials
nor accesses a token. Tests use disposable config files, software identities,
memory checkpoints and the real filesystem cache/runtime, not native hardware or
a separate OS process.

### Implemented selected restore ownership finalization

The [finalizer](../Sources/KeyCore/V3RecoveryRestoreFinalizer.swift) loads only
locally pinned restore state. It requires exact selected config, the existing
destination checkpoint/cache, matching source observation and complete published
files. A new empty ordinary-runtime session independently loads the saved Mac
identity, opens its wrapper once and compares all restored item names, types and
plaintext bytes. It does not inject the prepared key. The temporary session is
invalidated on every exit; native authentication prompt counts are unqualified.

Only then does the journal clear the exact reservation pin, recheck all state,
and clear the exact preparation pin. Both removals use the existing store's
compare-and-replace contract. Clearing preparation first would leave no local
digest for the complete bundle. Reservation-first leaves that digest intact,
so a dedicated finalization reader can verify the same bundle after interruption.
Every original reservation field is retained in that pinned bundle; reconstructing
those public bytes must exactly match the existing reservation file. No file,
credential, key or ownership record is regenerated or rearmed.

Preparation-only ownership is never accepted by normal preparation, publication,
trust insertion or config selection. Completion checks still require selected
config and existing exact trust. Changes, unavailable state and ambiguous errors
stop further cleanup without retry or rollback. Final checks cover the actual
source, config, files, cache/checkpoint and expected absence of both pins before
returning success. The cleared state exists only in the current scoped call.

After both pins are absent, a later call returns only "no locally owned pending
attempt" without loading leftover files or credentials. It does not claim that
an old operation succeeded. If the final reply was lost, ordinary configured-vault
status is the appropriate subsequent check. Encrypted records remain inert audit
evidence; config, credentials, checkpoint and vault/source files are not deleted.
No new namespace or persisted format is introduced. Native scope/session binding,
host serialization, product restore/resume and separate-process acceptance remain.

### Implemented native public reader

The [internal reader](../Sources/KeyCore/PIVRecoveryTokenReader.swift) replaces the
prototype's fixed reader name and certificate-file input with bounded token
inventory, explicit candidate selection and token-to-slot metadata. A retained
native card instance and removal invalidation prevent a same-named reinsertion
from silently replacing the reviewed connection. Slot 9d's public certificate,
key metadata and the application object are read in one exclusive session. The
metadata point must equal the certificate point, and that validated P-256 point
must match a recognized anchor's recipient ID. The certificate is a
public-key container, not issuer, expiry or attestation authority.

Discovery requests no card commands. Reading has only four expressible commands:
select PIV, GET DATA for the 9d certificate, GET METADATA for slot 9d, and GET DATA
for object `0x5F4B59`.
There is no raw APDU, PIN, management authentication, write, reset or private
operation interface. Absent, recognized and unrecognized occupancy are distinct;
unknown bytes are withheld, with an internal digest for exact revalidation.
A recognized anchor does not establish protected administration or possession.
The [metadata codec](../Sources/KeyCore/PIVRecoveryKeyMetadata.swift) bounds
responses to 256 bytes with exact fields, lengths and supported
P-256 encoding. Missing, malformed or unsupported metadata fails without a
certificate-only fallback. Revalidation compares origin and policies as well as
the public key and anchor.

The live process-wide gate remains claimed while a native begin/send callback is
pending after the public-read deadline. A successful session closes once after
pending completion; no authentication retry or guessed cancellation is used.
Software tests cover orchestration and lifetime behavior, not native delivery or
physical identity. The reader has no product caller and does not make 806
snapshots eligible for real-vault restore.

### Implemented scoped agreement adapter

The [internal adapter](../Sources/KeyCore/PIVRecoveryAgreement.swift) supplies a
scoped, one-use receiver to the existing recovery HPKE boundary. Constructing it
does not discover tokens, look up keys or request authentication. On agreement,
one reader operation lease spans fresh public revalidation, noninteractive key
lookup, another public revalidation, standard P-256 ECDH and final public
revalidation. Every public session closes before the provider operation.

Lookup specifies the observed token ID and the public key's application label,
private EC key class, 256-bit size and data-protection keychain. Exactly one
result is required. The returned handle's token ID, exported public point, key
class/type/size and ECDH support are checked independently. The label is a query
constraint, not identity proof. No private key is exported, no other credential
or algorithm is tried, and failure cannot trigger a second operation through
that receiver. Scope exit invalidates an escaped receiver and any pending attempt.
Before lookup, the receiver requires reported generated origin and explicit PIN
`ALWAYS` and touch `ALWAYS`. `DEFAULT`, `ONCE`, `NEVER`, biometric alternatives,
cached touch and imported origin are not accepted by the initial adapter. This
is a Key support policy, not a claim that every excluded vendor option is unsafe.

The caller waits until explicit cancellation or an absolute deadline, defaulting
to 60 seconds for the scope. Stopped or late results are discarded. Context
invalidation requests cancellation of authentication; it does not prove native
termination. A pending worker retains the shared operation lease until provider
return and cleanup, or pending public-read completion. Process termination clears
local state but does not establish the token's authentication-cache state.
Native provider failures expose a fixed category, not arbitrary diagnostic text.

Scripted tests cover binding checks, session ordering, scope closure,
cancellation, deadline, removal, anchor changes, and exclusion until delayed
completion. They do not qualify native query delivery, physical identity, PIN or
touch enforcement, prompt cancellation, or hardware session/cache behavior.
Configured-policy checks are implemented; actual PIN/touch enforcement,
protected setup, signed-product capability and actual
hardware qualification remain 807 requirements. Neither adapter has a product
caller; an absent or unrecognized anchor is not permission to register or restore.

### Owner operated setup boundary

Use Yubico's supported tools for all device administration initially, including
credential preparation and registration-anchor installation. Key must not
collect an administrative PIN, PUK or management key, invoke an importer, or
provide a management writer. Ordinary possession/recovery agreement remains
through the macOS hardware provider. The installed `ykman` 5.9.2 implementation
was inspected without running it against a token. Key's public checks and scoped
agreement remain separate from administration. This decision does not authorize
changing the owner's test credential, default management key or occupied object.

Credential requirements are an on-device P-256 key in reviewed slot 9d with PIN
and touch `ALWAYS`, plus a matching certificate. An incompatible occupied slot
is refused, not repaired. Policy changes require generation/import of another
key, so do not suggest an in-place policy toggle or silently regenerate a
registered key. Yubico documents these limits in its
[policy guide](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html).
Reported generated origin is not verified attestation or independent assurance
that a private key was never copied. Actual driver policy enforcement remains
a separate hardware qualification.

Before real registration, management authentication must use a vendor-generated
random, nondefault AES key with management touch required. Prefer Yubico's
PIN-protected storage for the initial owner-operated setup: it avoids placing a
separate management secret in Key. It also means device plus PIN can authorize
administration; the management key is not an independent human factor. Separate
offline management-key custody is an alternative with another backup obligation.
Neither management-key custody choice changes ordinary recovery inputs.
Yubico's [PIV CLI guide](https://docs.yubico.com/software/yubikey/tools/ykman/PIV_Commands.html)
documents both random generation and PIN-protected storage. Management changes
affect the PIV application's administration, not just slot 9d. Obtain exact-scope
owner approval and preserve recovery access before changing it.

Keep secret values out of arguments, environment variables, Key/XPC, repository
files and captured terminal output. The inspected vendor command can prompt for
credentials; generation without protected storage can print the generated key.
Do not capture such output as project evidence. Owner PIN/PUK backup and vendor
PIN-unblock guidance remain outside Key. Never change retry limits, deliberately
consume attempts, reset PIV or use key regeneration as a forgotten-PIN remedy.
Randomness, secret custody and protected storage cannot be proven by the public
key metadata implemented here. Do not label that metadata registration readiness.

The external-write decision explicitly excludes an atomic reviewed-state write
guarantee. The vendor object importer accepts an ID and bytes but does not
compare prior occupancy. Key refuses occupied application objects before
preparing a first registration and verifies exact installed bytes afterward;
it cannot prevent the owner or another administrator from changing or
overwriting that object during the external step. Closing competing clients and
selecting the device explicitly reduce mistakes, not eliminate this gap. Do not
describe successful vendor import as verified registration or protection against
an unexpected overwrite. Key's process-wide gate does not serialize the vendor
tool or other applications.

Initial preparation accepts only an absent application object and an existing
compatible slot-9d credential. Even recognized occupied records require a
separate replacement/reconciliation operation; they are not permission for a
new registration. An immutable public export and an authenticated pending intent
bind one exact candidate, recipient and expected parent. The product can display
the exact owner-run vendor command after review, but must not execute it, accept
arbitrary command hooks, or include secrets in it. A serial is a selection aid,
not cryptographic authority. After any external step, discard prior native
observations and freshly select/review the credential and installed anchor.
Exact readback, authenticated candidate verification, possession and publication
are required before verified registration. Preparation files and pending intents
are not inputs required on a replacement Mac during ordinary recovery.

## Registration and authority lifecycle

Only an authenticated active Mac can authorize registration or recipient
changes. Preserve normal content authentication; do not require a new signature
for every edit. Subsequent new-profile device/recipient authority changes require
both the active parent Mac and parent epoch signatures, rotate both keys,
reseal the complete current snapshot, and provide
all resulting active device and recovery wrappers before publication.

Registration prepares one exact candidate from a complete reviewed checkpoint.
Persist an authenticated local intent and stage/verify immutable encrypted
candidate objects without selecting them as ordinary current state. Review the
token/object and absent prior occupancy, and explain the externally prepared
administration prerequisite and unconditional-import limitation. Export only the
exact public anchor for an owner-run vendor write. Read back exact anchor bytes
from a fresh bound token observation and verify possession against that
candidate; revalidate the base and publish the activation manifest last, then
advance local checkpoint and report verified registration.

The anchor can be installed while final activation is incomplete. That is a
pending registration, not protection of an adopted current vault. Source reads
must not promote staging to a recoverable current head. A concurrent base
change, transport failure, or ambiguous administrative write retains the exact
attempt and prior-anchor backup for explicit reconciliation. Never silently
repin, rebase, replace a candidate, or restore old token bytes. Resume must
reauthenticate and review any dependent hardware operation.

The pending intent must authenticate the exact parent checkpoint, approving Mac,
candidate envelope, recipient, anchor and staged-entry addresses. It contains no
raw vault/epoch key, PIN, PUK, management key or saved possession approval.
Completion authenticates the same intent after owner reauthentication, checks
the candidate's dual authorization and MAC/capsule, independently compares all
current and resealed entry plaintexts, and verifies the local Mac wrapper before
requesting one hardware opening of the exact candidate recovery wrapper. A
restart before local checkpoint advancement requires a fresh possession check;
never persist or reuse that result. An exact candidate already committed in the
local checkpoint needs authenticated session/cleanup reconciliation, not another
hardware approval or publication.

The internal preparation journal stores one complete canonical bundle containing
the authenticated intent, candidate envelope and encrypted resealed entries.
It reuses the contained atomic no-overwrite writer, with file synchronization
before installation and directory synchronization afterward. Separate artifact
writes were rejected because an interruption could leave randomized candidate
bytes incomplete. The bundle is non-authoritative staging, never a current
manifest, and contains no raw vault/epoch key or saved approval.

A dedicated non-synchronizing device-local ownership record pins the operation,
vault and exact intent digest. Its Keychain namespace and provider directory are
separate from ordinary transaction recovery. Reserve ownership before installing
the bundle; promote it to recoverable only after exact readback, full
registration validation and confirmation of exact-file/directory local
synchronization. Readable bytes alone cannot establish that an interrupted
installation completed its durability steps. Return public anchor bytes only
after that promotion and an ownership recheck. Recoverable means preparation
retained, not token installation, possession, activation or registration readiness.
Local synchronization does not establish provider upload, remote durability or
freshness; those remain outside Key's storage-provider contract.

Resume selects only the locally owned bundle, not synchronized records found by
directory scanning. It repeats intent authentication, parent/owner checks,
boundary/MAC/capsule verification and complete same-plaintext validation with
newly authenticated keys. The service must still obtain fresh native observations
and guard the current source/head/directory under mutation ownership. Parsed
pending data is not permission to unwrap, export or publish without those checks.
No candidate is regenerated, rebased or automatically deleted. A reservation
interrupted before the complete bundle was installed stays attention-required;
it cannot resume from a partial file or silently start a replacement. Missing,
changed or invalid state also retains ownership for explicit reconciliation.

The internal profile-3 registration service owns prepare, exact resume/export,
finish and committed-state reconciliation under the shared mutation owner. It
uses the native reader/agreement adapters, with scripted native calls in software
tests. Preparation checks the current source and token before and after its
durable handoff. Finish checks the complete old/new snapshots, opens the local
candidate wrapper once and requests one token agreement. It publishes and checks
entries first, rechecks source/checkpoint/token state, then publishes the manifest
last. Exact readback and current authentication precede local checkpoint
advancement and session installation. Only then may local ownership be cleared;
the encrypted preparation bundle remains inert for audit.

The local authenticated checkpoint is the publication floor, as in the shipping
observer. Above it, this service accepts only its exact locally owned registration
transition with full same-plaintext checks. Other same-vault edits, rotations or
branches refuse; this is not a general profile-3 catch-up implementation. It does
not use recovery's reduced historical replay checks to authorize publication.

Interruption tests exercise real filesystem publication and cryptography, but
native checkpoint storage, physical hardware policies and product routing remain
unqualified. Before checkpoint advancement, retries require fresh possession
even if the candidate manifest is already present. After exact checkpoint
advancement, reconciliation reauthenticates local current contents and repairs
only session/ownership state. If ownership cleanup completed but the reply was
lost, only an exact local checkpoint matching the token floor and authenticated
active recipient is recognized as already activated. No token/provider record
can establish that local checkpoint. Successful local possession verification
cannot be treated as a reusable hardware proof after restart.

Shipping dispatch and CLI/XPC commands remain disabled. Global status should
describe authenticated configured coverage and the scope/time of last verified
registration, not guarantee an absent token is unchanged, available, or unblocked.

Adding a backup starts its independent anchor at that token's registration
checkpoint, not at the primary's original floor. It must recover without the
primary token or any earlier key not covered by its own bootstrap.

Required recovery history begins at that token's pinned floor, not before it.
Missing objects below the floor cannot become a dependency on the primary
token's older registration. Competing or incomplete reachable descendants
above the floor remain refusal cases.

### Planned external registration experience

This is a product workflow description, not a runnable command reference or
permission to modify the current disposable credential. Preparation through
Yubico tools is documented separately from Key's registration. Existing
compatible credentials skip generation; occupied incompatible slot-9d
credentials are not overwritten. PIN/PUK backup and administrative settings
remain owner responsibilities.

1. Connect and explicitly select the prepared device. Key reviews the
   authenticated vault, credential fingerprint, fixed slot/policies and absent
   application object. Cancel if anything differs from the intended target.
2. After local owner authorization, Key durably retains and checks one encrypted
   candidate and authenticated pending intent. It exports only that candidate's
   public anchor and explains the owner-run vendor import, including explicit
   target selection and its overwrite limitation. No administrative secret is
   entered in Key. Report pending, not enabled, at this point.
3. Run the reviewed vendor import independently. Enter administrative credentials
   only in the vendor tool, never in a command argument or saved script. Vendor
   success reports only that a write completed. Do not automatically repeat an
   uncertain or interrupted write.
4. Return to Key for finish. Reselect/review the token from fresh native reads
   and authenticate the pending candidate and unchanged parent. Key verifies
   the exact installed anchor, all resealed contents and the local wrapper,
   then requests one candidate recovery opening through the macOS provider.
   Enter the PIN in its system dialog and physically touch when requested.
5. Recheck source/token bindings, publish the activation manifest last and
   advance the local checkpoint. Only then report verified registration. Any
   incomplete step stays pending or attention-required for explicit review.

Repeat with an independently prepared backup device. Normal use does not need
either token connected; replacement-Mac recovery must not require this export,
pending intent, original configuration or administrative credential.

Removing a recipient rotates the key and omits its future wrapper on the
continuing lineage. Removing
the last recipient requires explicit loss-of-protection confirmation.
Neither removal nor a reset erases historical ciphertext or secrets.

## Compatibility and product boundary

Adoption is an explicit signed, key-rotating profile-2-to-new-profile transition,
not an install-time rewrite. Upgrade all participating Macs first; a client
must refuse an unsupported profile rather than write a sibling ignoring recovery.
Prove that the old client's existing signed-future-child guard covers the exact
adoption candidate. Concurrent conversions/authority changes are conflicts.

Retain source/history and existing local state for inspection. Rollback is an
explicit return to a retained older snapshot under compatible software, not
an in-place downgrade that keeps new-format edits or undoes remote adoption.
Never delete ordinary config or Keychain material during upgrade. New-profile
genesis, no-recipient mode, and recovery registration are separate operations.

The internal adoption builder and independent validator now construct this
transition from an exact authenticated profile-2 checkpoint. They preserve the
complete Mac roster and entry identities, names, types and revisions, rotate the
vault key, reseal all current contents and create profile-3 device wrappers and
a fresh epoch capsule. The initial recovery roster is empty and the epoch proof
is null because profile 2 has no prior epoch signing authority. The existing
active Mac signs the complete new content and exact old parent digest. Both
manifest MACs, the new capsule and full same-plaintext comparison are required;
publication validation also opens the local new wrapper once.

Software tests feed the exact candidate through the existing profile-2 discovery
and access gate, which refuse it as upgrade-required even with stale reads
requested. The discovery and owner-signature guard source is unchanged from
`v0.2.0`; the outer parser differs only in shared visibility and comments, and
the coordinator's difference is prompt copy. This is source-level compatibility
evidence, not an execution of the released binary or multi-Mac qualification.

The internal adoption service now owns durable preparation, exact resume and
manifest-last publication. It shares the contained immutable writer, bounded
source reader, mutation owner and checkpoint compare-and-swap with existing
publication mechanisms. It refuses competing same-vault changes and pending
ordinary transactions or registrations instead of rebasing the conversion.
Before publication it checks the complete old/new snapshot, both MACs, the
capsule, old active Mac signature and one addressed new local wrapper opening.

The complete canonical preparation contains encrypted entries and the signed
candidate, not plaintext or raw keys. Its full SHA-256 digest is pinned in a
dedicated non-sync local ownership namespace. That local record, not a file
provided by the storage provider, identifies the approved exact preparation.
Ownership is reserved as unarmed before atomic installation. Exact readback
and file/directory synchronization must succeed before ownership becomes
recoverable and any current object can be published. Resume repeats those
checks without generating keys or signing a replacement candidate.

Entries are published and checked first, the manifest last. Exact source,
ownership and checkpoint checks precede checkpoint advancement. The session
receives the verified new key only after that advancement; ownership is cleared
after session installation. A failure after checkpoint advancement reconciles
the already committed current snapshot with one local wrapper opening, without
reopening old entries, re-signing or repeating publication. A lost reply after
ownership cleanup can reconcile only a preparation matching the exact existing
local checkpoint. Provider files cannot establish a checkpoint or new local
ownership, and do not prove attribution to an operation after cleanup.

A reserved operation missing its preparation requires attention. Only an
explicit exact-operation abandonment can clear an unarmed reservation; the
service never automatically abandons it or abandons recoverable ownership.
Encrypted preparation files remain inert for inspection, not discovery-based
publication authority. No source/configuration/Keychain deletion is performed.

No shipping recovery composition or real-vault opt-in is enabled.
Adoption alone does not claim recovery protection; that requires separate
registration. Reciprocal pending-state barriers and ordinary profile-3
writes/catch-up are now composed behind the Preview gate. Broader lifecycle
integration, implementation review and distribution qualification remain
required before real-vault opt-in.

The gated public `recovery` workflow now includes token/credential/source review,
registration status/prepare/resume-export/finish, exact local pending selectors,
explicit adoption/resume, token-free key rotation/resume and restore/resume.
Native configured factories and the ordinary profile-3 runtime are composed
only by an explicitly enabled Preview bundle; shipping plists remain disabled.
Recipient-removal and broader device-lifecycle product flows still need separate
integration and qualification. Software fixtures do not establish native
PIN/touch enforcement, prompt counts or signed separate-process behavior.

`recovery pending` returns bounded device-local operation IDs only. It neither
authenticates an intent nor establishes readiness or resume approval. The actual
resuming service checks exact ownership, authenticated contents and operation
kind. A missing intent is preserved for inspection, not treated as new authority.
Checkpoint-changing requests retire an existing runtime even after ambiguous
failure; explicit restart/reconciliation must precede ordinary use.

No PIN, PUK, management key, or raw vault key crosses CLI arguments or XPC. Destructive
changes use exact-target review and opaque confirmation references.

Product services own normal mutations and destination/config barriers. Token
exclusion is additional to, not a replacement for, vault serialization.
Helper disconnect/death and late replies reconcile through durable intent;
they cannot automatically repeat authentication or create another destination.
Status is bounded and noninteractive. Sensitive values stay out of diagnostics.

## Representative acceptance scenarios

These are contract cases, not passing implementation tests or frozen JSON.
Real canonical byte fixtures are generated from the approved 805 codecs.

| Scenario | Required outcome |
|---|---|
| Register at A, ordinary edit B, lose original Mac | Recover B with the token and files; one source-recovery approval; no original Mac records. |
| Register at A, edit B, enroll a Mac at C, edit D | Authenticate the required history and transition invariants, recover D with one source-recovery approval across key epochs. |
| Backup registers at C, primary is unavailable | Backup recovers C/D from its own floor; does not depend on primary or A's private key. |
| Recipient removed at E | Remaining recipient recovers E; removed recipient lacks E's wrapper; older copied states remain outside revocation claims. |
| Provider supplies a self-consistent fake wrapper/history | Refuse because it does not extend token-pinned trust, even if HPKE opening succeeds. |
| Visible descendant lacks an entry or required parent | Refuse incomplete source; no silent recovery of the previous complete snapshot. |
| Source lists two competing authority transitions | Refuse conflict before promoting either to current state. |
| Anchor write succeeded but activation did not | Pending state; reconcile exact candidate explicitly; no automatic token rewrite or ready claim. |
| Cancel the hardware approval or interrupt later verification | No automatic retry or destination selection; preserve only appropriately authenticated attempt state; explicit resume follows the reviewed protocol. |
| Restore completes and token is removed | Ordinary Mac read/edit/reopen succeeds; new vault reports no recovery registration until separately registered. |
| Old client sees signed adoption to unknown profile | Upgrade-required refusal before publishing a competing ordinary child. |

## Evidence and implementation boundary

The [feasibility summary](piv-feasibility-results.md) records disposable two-Mac,
one-token results. [Twelve design tests](../Tests/KeyCoreTests/PIVRecoveryAuthorityDesignTests.swift)
exercise real cryptography and ordinary validators, but not a complete graph,
recipient lifecycle, token trust propagation, or hardware-operation budget.
The [epoch capsule](../Sources/KeyCore/V3EpochSigningKey.swift) and its
[13 tests](../Tests/KeyCoreTests/V3EpochSigningKeyTests.swift) implement the isolated
local capsule contract. Capsule version 1 is distinct from proposed profile 3.

Keep profile dispatch, recipient types, wrappers, and contexts in the existing
manifest/HPKE domain. Services retain mutation serialization and destination
barriers. The [tracker](piv-recovery-plan.md#architecture-ownership) records
ownership and package acceptance; do not ship archive diagnostics as product
integration.

Next is profile-3 lifecycle and restore-service integration, final domain acceptance,
shipping-runtime barriers and integrated review. Native token binding and scoped
agreement are implemented but not physically qualified in their final adapters.
Shipping profile-2 bytes remain unchanged. Review exact bytes before format
freeze; transcript checks alone are not a complete service validator.
Remaining gates include integrated graph/platform decisions, owner-operated
protected setup instructions, product interruption reconciliation, independent
backup-token and OS qualification, a fresh integrated AI review, and explicit
opt-in rollout. No whole-protocol approval or real-vault safety is implied.
Versioning permits improvements but cannot undo disclosure or replace lost files.
