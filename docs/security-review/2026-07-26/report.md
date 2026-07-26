# Security Review: tvanreenen/key

## Scope

Standard repository-wide review of the enclave-based, file-backed vault sharing model with emphasis on CLI security, device lifecycle, synchronized-state integrity, user experience, elegance, and crash durability.

- Scan mode: repository
- Target kind: git_worktree
- Target ID: sha256:657cf15a3742fd8ad1cc5f5927b1220fc524815614813a415f5415daa33dff42
- Revision: 84e7ddb79141d8f1665f3c1bf2e4254677a988a2
- Snapshot digest: codex-security-snapshot/v1:sha256:1d74df0bc5da366ec7aad16a4841552de3d91d1cb5319d4e849096130ccb54eb
- Inventory strategy: repository
- Included paths: .
- Excluded paths: .build/\*\*, AppIcon.icon/\*\*
- Runtime or test status: swift test built and ran 131 tests, but 42 failed because every EntryStore protected write returned Cocoa 513/POSIX EPERM; a plain write succeeded. The helper is not built by SwiftPM. A local symlink escape probe reproduced. Defensive key-retention and metadata-selector models ran successfully.
- Artifacts reviewed: All shipped Swift sources, XPC and launchd configuration, entitlements and Xcode project, SwiftPM package and tests, release/build scripts, README and security-model documentation
- Scan context: The threat model was generated from repository source and product documentation during this scan. The clean Git worktree was reviewed at the recorded revision.

Limitations and exclusions:
- No installed hostile XPC client integration run.
- No two-device Secure Enclave/Multipeer enrollment run.
- No real sync-provider conflict/rollback matrix.
- The current test environment cannot write with Data.WritingOptions.completeFileProtection.
- Excluded .build/\*\*: Generated SwiftPM build products; source counterparts were fully reviewed.
- Excluded AppIcon.icon/\*\*: Static icon asset with no executable or security-sensitive content.

### Scan Summary

| Field | Value |
| --- | --- |
| Reportable findings | 8 |
| Severity mix | medium: 4, low: 4 |
| Confidence mix | high: 8 |
| Coverage | complete |
| Validation mode | Complete static source/control/sink tracing with bounded local defensive probes where proportionate; no live targets and no two-device Secure Enclave enrollment run. |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

The vault stores AES-GCM encrypted entry files in a user-selected local or synchronized directory. Local mode stores the AES key in a user-presence Keychain item. Enclave mode gives each device a Secure Enclave private key and synchronizes a common AES key wrapped to each authorized device. The helper process is trusted while it holds the unwrapped AES key; same-session processes, enrollment peers, synchronized-storage writers, stale backups, compromised formerly authorized devices, concurrent devices, and interruption are relevant attackers or failure sources.

### Assets

- Secret plaintext and TOTP seeds
- Shared AES vault key
- Secure Enclave device identities
- Membership, epoch, and wrapped-key metadata
- Vault availability and current entry state

### Trust Boundaries

- CLI to per-user XPC helper
- Helper to Keychain and Secure Enclave
- Approving device to joining device
- Local helper to synchronized filesystem/provider
- One authorized device to another
- Committed state across crash/restart

### Attacker Capabilities

- Run an untrusted process in the same login session
- Race nearby enrollment or substitute a manual request
- Read, replace, replay, or conflict synchronized files
- Retain key material on a compromised formerly authorized endpoint
- Interrupt or overlap lifecycle operations

### Security Objectives

- Only intended signed clients may invoke helper authority
- Enrollment binds the intended peer and vault
- Removal cryptographically revokes future access
- Entry and metadata authenticity includes identity and freshness
- Vault transitions are serializable and crash recoverable

### Assumptions

- A fully compromised currently authorized device can access plaintext and is outside preventable scope.
- macOS Secure Enclave, CryptoKit primitives, and correctly configured Keychain protections behave as documented.
- The file-sync provider is not trusted for confidentiality, integrity, freshness, ordering, or atomic multi-file commits.

## Findings

| Finding | Severity | Confidence | Detailed write-up |
| --- | --- | --- | --- |
| [LaunchAgent accepts unauthenticated callers for every privileged vault operation](#finding-1) | medium | high | [Open report](findings/unauthenticated-xpc-vault-authority/unauthenticated-xpc-vault-authority.md) |
| [Enrollment verification code authenticates the joining peer to itself](#finding-2) | medium | high | [Open report](findings/self-authenticating-enrollment-code/self-authenticating-enrollment-code.md) |
| [Removing a device does not rotate the shared vault key](#finding-3) | medium | high | [Open report](findings/device-removal-without-key-rotation/device-removal-without-key-rotation.md) |
| [Concurrent helper requests can interleave with key transitions](#finding-4) | medium | high | [Open report](findings/concurrent-key-transition-race/concurrent-key-transition-race.md) |
| [Entry ciphertext is not bound to its vault, logical name, or semantic type](#finding-5) | low | high | [Open report](findings/entry-context-not-authenticated/entry-context-not-authenticated.md) |
| [Historical entry versions can be replayed without detection](#finding-6) | low | high | [Open report](findings/entry-replay-without-freshness/entry-replay-without-freshness.md) |
| [Intermediate symlinks can escape the configured vault root](#finding-7) | low | high | [Open report](findings/vault-symlink-escape/vault-symlink-escape.md) |
| [Shared authorization metadata is unauthenticated and rollbackable](#finding-8) | low | high | [Open report](findings/unauthenticated-vault-metadata/unauthenticated-vault-metadata.md) |

### Confidence Scale

| Label | Meaning |
| --- | --- |
| high | Direct evidence supports the finding with no material unresolved blocker. |
| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |
| low | Evidence is incomplete and the item is retained only for explicit follow-up. |

<a id="finding-1"></a>

### [1] LaunchAgent accepts unauthenticated callers for every privileged vault operation

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Direct source and deployment review shows unconditional admission and no caller-authentication guard; an installed hostile-client integration test remains to be run. |
| Category | Missing authentication for a critical function |
| CWE | CWE-306 |
| Affected lines | Sources/KeyLaunchAgentHelper/main.swift:51-55, Sources/KeyCore/KeyServiceHandler.swift:115-137 |

#### Summary

See the [detailed technical write-up](findings/unauthenticated-xpc-vault-authority/unauthenticated-xpc-vault-authority.md).

#### Validation

See the [detailed technical write-up](findings/unauthenticated-xpc-vault-authority/unauthenticated-xpc-vault-authority.md).

#### Dataflow

See the [detailed technical write-up](findings/unauthenticated-xpc-vault-authority/unauthenticated-xpc-vault-authority.md).

#### Reachability

See the [detailed technical write-up](findings/unauthenticated-xpc-vault-authority/unauthenticated-xpc-vault-authority.md).

#### Severity

See the [detailed technical write-up](findings/unauthenticated-xpc-vault-authority/unauthenticated-xpc-vault-authority.md).

#### Remediation

See the [detailed technical write-up](findings/unauthenticated-xpc-vault-authority/unauthenticated-xpc-vault-authority.md).

<a id="finding-2"></a>

### [2] Enrollment verification code authenticates the joining peer to itself

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | The complete generation, signature-validation, staging, CLI prompt, and key-wrapping path is explicit in source; a two-device race was not executed. |
| Category | Insufficient peer authentication |
| CWE | CWE-345 |
| Affected lines | Sources/KeyCore/VaultKeyStore.swift:882-914, Sources/KeyCore/VaultKeyStore.swift:918-965, Sources/KeyCore/KeyCLIApplication.swift:219-222 |

#### Summary

See the [detailed technical write-up](findings/self-authenticating-enrollment-code/self-authenticating-enrollment-code.md).

#### Validation

See the [detailed technical write-up](findings/self-authenticating-enrollment-code/self-authenticating-enrollment-code.md).

#### Dataflow

See the [detailed technical write-up](findings/self-authenticating-enrollment-code/self-authenticating-enrollment-code.md).

#### Reachability

See the [detailed technical write-up](findings/self-authenticating-enrollment-code/self-authenticating-enrollment-code.md).

#### Severity

See the [detailed technical write-up](findings/self-authenticating-enrollment-code/self-authenticating-enrollment-code.md).

#### Remediation

See the [detailed technical write-up](findings/self-authenticating-enrollment-code/self-authenticating-enrollment-code.md).

<a id="finding-3"></a>

### [3] Removing a device does not rotate the shared vault key

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | The complete leave implementation and request protocol contain no epoch advance, re-encryption, or remaining-device rewrap; a safe model PoC reproduced continued AES-GCM decryption with a retained key. |
| Category | Cryptographic key management error |
| CWE | CWE-320 |
| Affected lines | Sources/KeyCore/VaultKeyStore.swift:505-525, Sources/KeyCore/KeyServiceProtocol.swift:9-16 |

#### Summary

See the [detailed technical write-up](findings/device-removal-without-key-rotation/device-removal-without-key-rotation.md).

#### Validation

See the [detailed technical write-up](findings/device-removal-without-key-rotation/device-removal-without-key-rotation.md).

#### Dataflow

See the [detailed technical write-up](findings/device-removal-without-key-rotation/device-removal-without-key-rotation.md).

#### Reachability

See the [detailed technical write-up](findings/device-removal-without-key-rotation/device-removal-without-key-rotation.md).

#### Severity

See the [detailed technical write-up](findings/device-removal-without-key-rotation/device-removal-without-key-rotation.md).

#### Remediation

See the [detailed technical write-up](findings/device-removal-without-key-rotation/device-removal-without-key-rotation.md).

<a id="finding-4"></a>

### [4] Concurrent helper requests can interleave with key transitions

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | The shared exported object, partial queues, and unshare/add state transitions establish a concrete interleaving; installed concurrent XPC execution was not performed. |
| Category | Concurrent execution with improper synchronization |
| CWE | CWE-362 |
| Affected lines | Sources/KeyLaunchAgentHelper/main.swift:51-55, Sources/KeyCore/KeyServiceHandler.swift:44-144, Sources/KeyCore/KeyServiceHandler.swift:284-323 |

#### Summary

See the [detailed technical write-up](findings/concurrent-key-transition-race/concurrent-key-transition-race.md).

#### Validation

See the [detailed technical write-up](findings/concurrent-key-transition-race/concurrent-key-transition-race.md).

#### Dataflow

See the [detailed technical write-up](findings/concurrent-key-transition-race/concurrent-key-transition-race.md).

#### Reachability

See the [detailed technical write-up](findings/concurrent-key-transition-race/concurrent-key-transition-race.md).

#### Severity

See the [detailed technical write-up](findings/concurrent-key-transition-race/concurrent-key-transition-race.md).

#### Remediation

See the [detailed technical write-up](findings/concurrent-key-transition-race/concurrent-key-transition-race.md).

<a id="finding-5"></a>

### [5] Entry ciphertext is not bound to its vault, logical name, or semantic type

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | The CryptoKit calls and handler type use are explicit, and no associated-data path exists. |
| Category | Insufficient verification of data authenticity |
| CWE | CWE-345 |
| Affected lines | Sources/KeyCore/VaultCipher.swift:7-20, Sources/KeyCore/VaultCipher.swift:23-43, Sources/KeyCore/KeyServiceHandler.swift:115-122 |

#### Summary

See the [detailed technical write-up](findings/entry-context-not-authenticated/entry-context-not-authenticated.md).

#### Validation

See the [detailed technical write-up](findings/entry-context-not-authenticated/entry-context-not-authenticated.md).

#### Dataflow

See the [detailed technical write-up](findings/entry-context-not-authenticated/entry-context-not-authenticated.md).

#### Reachability

See the [detailed technical write-up](findings/entry-context-not-authenticated/entry-context-not-authenticated.md).

#### Severity

See the [detailed technical write-up](findings/entry-context-not-authenticated/entry-context-not-authenticated.md).

#### Remediation

See the [detailed technical write-up](findings/entry-context-not-authenticated/entry-context-not-authenticated.md).

<a id="finding-6"></a>

### [6] Historical entry versions can be replayed without detection

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | The complete entry schema and decrypt path contain no freshness input; provider-level replay was not executed. |
| Category | Replay of valid encrypted state |
| CWE | CWE-294 |
| Affected lines | Sources/KeyCore/SecretFile.swift:3-25, Sources/KeyCore/VaultCipher.swift:23-43 |

#### Summary

See the [detailed technical write-up](findings/entry-replay-without-freshness/entry-replay-without-freshness.md).

#### Validation

See the [detailed technical write-up](findings/entry-replay-without-freshness/entry-replay-without-freshness.md).

#### Dataflow

See the [detailed technical write-up](findings/entry-replay-without-freshness/entry-replay-without-freshness.md).

#### Reachability

See the [detailed technical write-up](findings/entry-replay-without-freshness/entry-replay-without-freshness.md).

#### Severity

See the [detailed technical write-up](findings/entry-replay-without-freshness/entry-replay-without-freshness.md).

#### Remediation

See the [detailed technical write-up](findings/entry-replay-without-freshness/entry-replay-without-freshness.md).

<a id="finding-7"></a>

### [7] Intermediate symlinks can escape the configured vault root

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Source lacks symlink containment and a disposable Foundation probe created the target file outside the lexical vault root; provider reach remains uncertain. |
| Category | Improper link resolution before file access |
| CWE | CWE-59 |
| Affected lines | Sources/KeyCore/EntryStore.swift:36-64, Sources/KeyCore/EntryStore.swift:107-143, Sources/KeyCore/EntryStore.swift:152-230 |

#### Summary

See the [detailed technical write-up](findings/vault-symlink-escape/vault-symlink-escape.md).

#### Validation

See the [detailed technical write-up](findings/vault-symlink-escape/vault-symlink-escape.md).

#### Dataflow

See the [detailed technical write-up](findings/vault-symlink-escape/vault-symlink-escape.md).

#### Reachability

See the [detailed technical write-up](findings/vault-symlink-escape/vault-symlink-escape.md).

#### Severity

See the [detailed technical write-up](findings/vault-symlink-escape/vault-symlink-escape.md).

#### Remediation

See the [detailed technical write-up](findings/vault-symlink-escape/vault-symlink-escape.md).

<a id="finding-8"></a>

### [8] Shared authorization metadata is unauthenticated and rollbackable

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Metadata schema, read, authorization selection, and write paths were fully reviewed; real provider rollback was not executed. |
| Category | Insufficient verification of data authenticity |
| CWE | CWE-345 |
| Affected lines | Sources/KeyCore/VaultKeyStore.swift:37-59, Sources/KeyCore/VaultKeyStore.swift:683-693, Sources/KeyCore/VaultKeyStore.swift:706-715 |

#### Summary

See the [detailed technical write-up](findings/unauthenticated-vault-metadata/unauthenticated-vault-metadata.md).

#### Validation

See the [detailed technical write-up](findings/unauthenticated-vault-metadata/unauthenticated-vault-metadata.md).

#### Dataflow

See the [detailed technical write-up](findings/unauthenticated-vault-metadata/unauthenticated-vault-metadata.md).

#### Reachability

See the [detailed technical write-up](findings/unauthenticated-vault-metadata/unauthenticated-vault-metadata.md).

#### Severity

See the [detailed technical write-up](findings/unauthenticated-vault-metadata/unauthenticated-vault-metadata.md).

#### Remediation

See the [detailed technical write-up](findings/unauthenticated-vault-metadata/unauthenticated-vault-metadata.md).

## Structural Hardening

The scan also produced derived, unsealed design guidance based on the complete finding collection. These proposals describe options and tradeoffs; they do not indicate that any finding has been remediated.

[Open the structural hardening portfolio](hardening/hardening.md)

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| CLI to LaunchAgent XPC | caller authentication, confused deputy, plaintext exposure | Reported | Unconditional client admission became CAND-001; request-level concurrency became CAND-011. |
| Synchronized enclave metadata | authorization integrity, rollback, conflicts | Reported | Unauthenticated/rollbackable state became CAND-004. Last-writer-wins conflict behavior remains a structural hardening item. |
| Device enrollment | peer authentication and key substitution | Reported | Self-authenticating approval code became CAND-002. |
| Secure Enclave and Keychain | private-key and local key protection | No issue found | Device-only Secure Enclave private keys and Keychain user-presence policy were confirmed. The shared AES key necessarily exists in helper memory after unwrap. |
| Per-file secret envelope | AEAD context and freshness | Reported | Missing context binding became CAND-005; replay acceptance became CAND-006. |
| Vault filesystem paths | path traversal, symlink containment, file mutation | Reported | Intermediate symlink escape became CAND-008 and was reproduced with a disposable local probe. |
| Share, leave, revoke, and unshare lifecycle | revocation, rotation, crash consistency, concurrency | Reported | No-rotation removal became CAND-003 and concurrent transition race became CAND-011. Non-journaled unshare remains a release-blocking durability issue. |
| CLI secret handling | argv, TTY, pipeline, clipboard, terminal output | No issue found | Secure TTY input, no argv secrets, and noninteractive remove safeguards were confirmed. Raw control characters in names remain suppressed Low hardening. |
| Configuration and vault selection | mode/path confusion and unsafe initialization | No issue found | No security-reportable finding survived policy; a warm helper retaining the old path remains a UX/durability blocker. |
| Release and privileged packaging | signing, entitlements, notarization, helper registration | No issue found | Signing and notarization verification exists. SwiftPM omits the helper target, so installed XPC integration coverage is still required. |
| Dynamic command, code, query, and template execution | RCE and injection | Not applicable | Shipped Swift runtime has no database, dynamic evaluator, template engine, or process-execution sink. |
| Outbound network destinations | SSRF and callback abuse | Not applicable | Runtime uses MultipeerConnectivity enrollment and has no attacker-selected URL fetch. |
| Structured parsing | untrusted JSON and schema enforcement | Reported | Fixed Codable structures avoid object injection; authorization metadata authenticity is covered by CAND-004. |
| Utility app and dashboard | local privileged status and control exposure | No issue found | No separate privileged sink survived beyond the shared XPC boundary. |

## Open Questions And Follow Up

- What recovery mechanism is acceptable if every authorized Secure Enclave identity is lost?
  - Follow-up prompt: Design and threat-model recovery options for the shared vault without weakening routine device security.
- Must multiple devices support offline concurrent writes, or is one serialized writer acceptable?
  - Follow-up prompt: Choose the vault consistency model and specify conflict, retry, and merge semantics.
- Which file-sync providers and filesystem semantics are supported?
  - Follow-up prompt: Run the generation-commit, atomic replacement, symlink, placeholder, and conflict test matrix on every supported provider.
- Why does .completeFileProtection return EPERM in the current macOS build/test environment?
  - Follow-up prompt: Diagnose protected-write behavior in the shipping sandbox/entitlement context and define the release gate.
