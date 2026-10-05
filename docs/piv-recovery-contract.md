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
in explicitly selected slot 9d, one registration per token, and independent
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
token/object, prior occupancy and protected administration before any approved
anchor write. Read back exact anchor bytes and verify possession against that
candidate; revalidate the base and publish the activation manifest last, then
advance local checkpoint and report verified registration.

The anchor can be installed while final activation is incomplete. That is a
pending registration, not protection of an adopted current vault. Source reads
must not promote staging to a recoverable current head. A concurrent base
change, transport failure, or ambiguous administrative write retains the exact
attempt and prior-anchor backup for explicit reconciliation. Never silently
repin, rebase, replace a candidate, or restore old token bytes. Resume must
reauthenticate and review any dependent hardware operation.

This ordering is proposed for 808 and needs durable-phase tests. In particular,
successful local possession verification cannot be treated as a reusable
hardware proof after restart. Global status should describe authenticated
configured coverage and the scope/time of last verified registration, not
guarantee an absent token is unchanged, available, or unblocked.

Adding a backup starts its independent anchor at that token's registration
checkpoint, not at the primary's original floor. It must recover without the
primary token or any earlier key not covered by its own bootstrap.

Required recovery history begins at that token's pinned floor, not before it.
Missing objects below the floor cannot become a dependency on the primary
token's older registration. Competing or incomplete reachable descendants
above the floor remain refusal cases.

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

The proposed public workflow is a `recovery` command group for status,
credential review, registration, recipient listing/removal, restore review,
restore, and explicit resume. Names/options are reviewed with service fixtures
before implementation; this is not a runnable command listing. No PIN, PUK,
management key, or raw vault key crosses CLI arguments or XPC. Destructive
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

Next is final domain acceptance and integrated review, followed by native token
binding and restore-service integration. Shipping profile-2 bytes remain
unchanged. Review the
new exact bytes before format freeze; do not enable publication/recovery by
treating transcript checks as a complete service validator.
Graph/platform/adoption decisions remain open in 804 and dependent packages.
Protected administration, durable-phase reconciliation, independent backup-token
and OS qualification, a fresh integrated AI review, and explicit opt-in adoption
remain gates. No whole-protocol approval or real-vault safety is implied.
Versioning permits improvements but cannot undo disclosure or replace lost files.
