# PIV recovery AI review and disposition

2026-10-04. A fresh AI reviewer, separate from the implementation work, reviewed
the then-current protocol brief and
[contract](piv-recovery-contract.md), design tests, and relevant existing code.
The owner authorized AI review followed by experimental implementation for this
solo-maintained open-source project. Qualified human review is recommended,
not a prerequisite chosen by the owner.

This records the reviewer conclusions and the implementing agent's dispositions.
It is not a human audit, certification, cryptographic proof, or hardware
qualification. The reviewer made no edits or token operations. It ran the built
design suite with `swift test --skip-build --filter PIVRecoveryAuthorityDesignTests`:
12 tests passed. That was not a fresh compilation.

## Design decision and findings

Accept with conditions for the isolated experimental epoch-key capsule component.
Revise the recovery security promise before implementing the integrated verifier.
The complete protocol is not sufficiently specified for production format freeze
or real-vault activation.

### Future exclusion applies to the continuing lineage

Reviewer severity: high for the unqualified promise. Confirmed by inspection,
not by an integrated recovery reproduction. Address the wording now; accept the
limit and require graph scenarios in `REC-806` and `REC-810`.

A removed Mac retaining its earlier device key and epoch signing capability can
authorize a new alternative lineage from a parent where it was active, including
fresh keys, contents, and wrappers to the token's public key. The
[draft verifier](../Tests/KeyCoreTests/PIVRecoveryAuthorityDesignTests.swift)
checks active status in the supplied exact parent. Its revoked-signer test checks
a parent that already contains revocation, not an earlier-parent alternative.

Removal excludes a recipient from subsequent keys on the legitimate continuing
lineage, provided fresh independent keys omit removed wrappers. Visible competing
authority lineages require refusal. A stable earlier anchor cannot determine
which lineage is globally current if the provider hides its competitor. This
includes newly authored alternative contents, not just an unchanged old snapshot;
it does not reveal the continuing lineage's fresh keys to the removed Mac.

### Public commitments do not fully authenticate closed epochs

Reviewer severity: medium. Confirmed by the design tests and
[full rotation validator](../Sources/KeyCore/V3DeviceWrappedKeyRotationValidation.swift).
Clarify now, preserve ordinary full checks, and require final-capsule validation
in `REC-806` after the one opening.

With only the final vault key, recovery verifies anchored hash commitments,
public authorizations, and allowed structural authority transitions. It does
not independently verify closed-epoch MACs, old entry AEAD, old capsule
private/public correspondence, or every historical plaintext-preserving reseal.
Both valid signing capabilities can authorize a semantically invalid rotation
that the ordinary validator rejects. After opening the final key, verify its ID,
required final-epoch MACs, final capsule correspondence, selected entry objects,
and semantics in software. No second token operation is needed.

### Specify capsule bytes and preparation policy

Reviewer severity: medium. Confirmed implementation gap in the provisional
draft, not a primitive failure. Address local requirements in the first
`REC-805` increment; durable preparation belongs to later builders/services.

Validate canonical epoch IDs and the supplied 32-byte key's derived ID. Fix
version, algorithms, vault-UUID-byte HKDF salt, purpose label, and complete AAD.
Require a validated uncompressed 65-byte P-256 public key and a 60-byte combined
AES-GCM box. Bound bytes before parsing; reject unknown/duplicate fields,
noncanonical encodings, unsupported versions/algorithms, bad points and lengths.
Open AEAD and check the private/public correspondence before scoped internal use.
A closure cannot prevent deliberate key retention or guarantee memory zeroization.

Prepare one capsule with fresh keys per epoch; preserve exact bytes for edits and
retries. Abandon the whole candidate and choose fresh epoch keys if preparation
restarts. The [new component](../Sources/KeyCore/V3EpochSigningKey.swift) and
[tests](../Tests/KeyCoreTests/V3EpochSigningKeyTests.swift) address local requirements,
not durable nonce accounting or profile activation.

### Graph and inherited proofs require a complete algorithm

Reviewer severity: medium. Confirmed specification gap. Defer from the capsule
increment to `REC-806`, with inheritance integration in `REC-809`/`REC-810`.

Specify exact roots/boundary parents, identical same-epoch authority records,
all merge paths, competing boundaries, missing objects, off-path closed-epoch
branches, and count/depth/byte budgets before hardware activation. An inherited
proof is not a new signature on an edit; public proof is not a MAC-trusted
checkpoint. Conservative refusal can permit denial of recovery through injected
garbage. The design's linear test helper does not implement this algorithm.

### Protected administration is required for real registration

Reviewer severity: high for real registration. Confirmed gap in the recorded
disposable setup. Retain requirements in `REC-807`/`REC-808`; no hardware change
is authorized by this increment.

Registration must fully validate the pinned checkpoint, bind the actual token
credential, protect anchor administration, and read back exact bytes. HPKE Base
mode is not origin or replay authentication. The disposable default management
credentials do not qualify real registration.

## Architectural comparisons

Prefer the integrated new profile over a mutable recovery sidecar: the manifest
already owns rosters, wrappers, entries, and publication. A sidecar adds another
atomicity and authority linkage. Prefer random protected signing keys over a new
deterministic scalar-derivation algorithm. Prefer dual capabilities over backward
vault-key links for current-key-only enrollment: backward links would grant new
holders access to old decryption keys. Per-epoch opening remains the stronger
historical replay baseline, with additional hardware operations.

Keep recovery recipients distinct from Macs, separate HPKE contexts, independent
token floors, activation-last registration, and distinct public-proof/verified
snapshot types. Preserve one outer Mac signature and explicit locally validated
adoption. Existing future-profile refusal is not completed migration qualification.

## Implementation review

The fresh reviewer then inspected the capsule, tests, and four Xcode inclusion
entries. Decision: **accept this isolated experimental component; no blocking
findings found within this read-only AI review**. It inspected the completed
regression log, not a second run: fresh compilation and 89 tests passed across
seven suites. `REC-805` remains incomplete; profile/proof integration, recipients,
recovery contexts, graph logic, lifecycle, and adoption remain to implement.

The review checked full AAD framing, bounded exact codecs, key-ID validation,
private/public correspondence, callback ordering/error propagation, nonce/custody
limits, independent fixture construction, malformed inputs, and tampering. The
independent constructions use the same CryptoKit library, not independent-library
interoperability vectors. No product callers use the new component yet.

## Review identity and implementation policy

Review base: `2adba7de353acce68f5a3a0303259cba25d851f5`, with local changes,
not a published artifact. Reviewed capsule and test SHA-256 identities:

- Source: `fcfd2e9fffacb7a2f9f6d687e34b12fc7d1b3675da6b5b0f10682af9e5b6037a`.
- Tests: `1d6b882adb5c97fe4a2020b519db2db39f15c30343bb72deb49fe2034e322735`.

The full input inventory and raw review packet are locally archived. The
contract/tracker were consolidated after review; the capsule and tests remain
unchanged. Earlier Xcode inclusion review does not certify the cleaned build
or an integrated recovery implementation.

AI review and risk disclosure replace the proposed mandatory human-audit gate.
Resolve known correctness defects and qualify the actual product path before
opt-in real-vault activation. External expert review remains welcome.
Experimental changes require explicit versions, migration tests, backup/rollback
guidance, old-client refusal, and failure-safe adoption. Future migration cannot
undo disclosure or repair missing backups; at-own-risk notices do not make
known broken authentication acceptable.
