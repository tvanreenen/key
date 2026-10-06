# PIV feasibility evidence summary

Recorded experiments: 2026-09-06 through 2026-10-04. One YubiKey 5C NFC
worked on two Macs with disposable data. This establishes usable primitives
and a frozen-checkpoint rehearsal, not production recovery qualification.
The [implementation plan](piv-recovery-plan.md) tracks the remaining work.

## Scope and provenance

Tool results establish compilation, software tests, native discovery, metadata,
readback, and artifact checks. Interactive PIN/touch outcomes are owner-reported
Terminal output and observations, not independently instrumented enforcement
tests. No real vault authority was used.

| Component | Recorded configuration |
|---|---|
| Hosts | Mac mini and MacBook Air; later private-product runs reported macOS 27.0 build 26A428 on the Mini and 27.0.1 build 26A434 on the Air |
| Token | Owner-identified YubiKey 5C NFC, USB, PIV firmware 5.8.0 |
| Credential | Slot 9d, ECCP256, metadata origin GENERATED, PIN ALWAYS, touch ALWAYS |
| Administration | Owner changed PIN/PUK; management key retained at factory default without PIN protection |
| Public certificate | Matching self-signed test certificate; recorded validity 2026-09-06 through 2026-10-06 |
| Runtime | Apple PIV driver, CryptoTokenKit/Security key agreement, CryptoKit HPKE |
| Storage | Disposable application-specific public object `0x5F4B59` |
| Latest private test artifact | `0.2.0-piv-test.2 (21)`; not a published prerelease |

Generation metadata is not verified attestation. The certificate is a public-key
container, not a vault trust root. CHUID creation made native discovery work on
the first host after the driver reported a missing CHUID; CCC remained absent.
This is an observed host requirement, not permission to rewrite another card's
identifier. No PIV reset, Mac-login pairing, unrelated-slot change, or trust-store
modification was performed.

## Results worth retaining

| Milestone | Observed result | Boundary |
|---|---|---|
| Native P-256 agreement | Hardware-provider result matched the software peer on both Macs; owner confirmed PIN and physical touch | Same token on both hosts, not independent backup recovery |
| Withheld touch on first host | No completion; failed after 21.46 seconds with CryptoTokenKit `-3 corruptedData`; subsequent reconnect/PIN/touch passed | Supports missed-touch interpretation for that run, not a universal meaning of provider code -3 |
| PIN-dialog cancellation | Failed with LocalAuthentication `-2`; local helper cancellation also failed without application retry | No deliberate wrong-PIN test or counter exhaustion |
| Encrypted-key opening | HPKE test key opened through the hardware provider and matched on the second Mac | Disposable key, no vault authority |
| Public-object reads | Vendor readback, local Air build, then signed-helper certificate-bound reads passed | Public storage/readback does not establish protected registration integrity |
| Signed distribution | Private test app notarized/stapled, AirDropped, verified, installed, and registered on the Air under normal quarantine/Gatekeeper handling | No quarantine stripping or re-signing; no public release |
| Source-only restore | Encrypted toy source plus token restored two fixed entries to a new device-bound vault on the Air | One exact pinned checkpoint; no original-Mac records transferred |
| Token-free destination use | Fresh ordinary read, fixed secret edit/reopen, and separate later read passed without a YubiKey API call | Isolated disposable workspace, not ongoing source recovery coverage |

The original Air agreement run first reported a 32.99-second communication error,
then a zero-match discovery result, then success. A controlled reconnect/repeat
also passed; the initial cause remains unresolved.

An AirDropped ad-hoc storage-inspection binary was terminated by SIGKILL with
no output. Launch-policy blocking was suspected, not confirmed by returned logs.
A local build subsequently passed. The later notarized product flow passed
normal distribution checks; do not reinterpret the earlier failure as proven.

The toy registration replaced a disposable public object only after exact-target
approval and prior-record backup. Readback matched the candidate. It used default
management credentials and therefore does not qualify real registration.
The latest token-free edit and separate verification both exited 0 on 2026-10-04.
Source, ordinary configurations, and Stable hashes were preserved. The owner
approved prompts but could not attribute them to individual checks.

## Remaining qualification

- Protected token administration is required before real registration. The
  disposable factory-default management key is unsuitable for that purpose.
- Independent backup-token recovery, full authenticated history/epoch coverage,
  recipient removal, ongoing edits, authenticated resume, and explicit adoption
  are not implemented or qualified by these experiments.
- PIN/touch enforcement, prompt/cache behavior, certificate expiry/renewal,
  unplugging during an operation, helper death, OS restart, and deadline behavior
  still need supported-product qualification. Do not deliberately consume retry
  counters or reset the owner's token; simulate error paths where appropriate.
- The test credential, certificate, CHUID, and disposable anchor remain on the
  token. Cleanup did not alter them. Any hardware change needs exact-scope approval.

## Repository boundary

The experiment CLI/XPC hooks, toy workflows, standalone scripts, detailed run
notes, and raw review packet were removed from active sources during cleanup
on 2026-10-04. They are locally preserved under the ignored root `tmp/` folder;
that folder is not a backup and is not required to build or understand the repo.
Already installed private test apps were not changed.

Retained regression evidence includes the
[HPKE receiver vector/compatibility tests](../Tests/KeyCoreTests/PIVHPKEReceiverTests.swift),
[public-object framing tests](../Tests/KeyCoreTests/PIVPublicObjectCodecTests.swift),
[authority comparison tests](../Tests/KeyCoreTests/PIVRecoveryAuthorityDesignTests.swift),
and [epoch capsule tests](../Tests/KeyCoreTests/V3EpochSigningKeyTests.swift).
These are software-only checks, not hardware qualification.
