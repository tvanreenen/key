# Unauthenticated XPC clients receive vault authority

## Executive Summary

The Key macOS LaunchAgent exposes its vault service through a per-user Mach
service, but the listener accepts every connection without validating the
caller's audit identity or code signature. The same exported object handles
plaintext reads, vault mutations, and sharing operations. This makes the helper
a confused deputy for any process that can reach the service in the logged-in
user session.

The confidentiality impact is strongest while the helper's 15-minute key cache
is warm: a request can reuse the cached vault key without a new user-presence
event. A cold cache still benefits from Keychain or Secure Enclave
user-presence controls, but those controls authorize key use by the helper; they
do not authenticate the XPC peer that receives the response. The authorization
defect also reaches operations that do not require key access.

The issue is CWE-306, Missing Authentication for Critical Function. I reviewed
revision `84e7ddb79141d8f1665f3c1bf2e4254677a988a2` directly and confirmed the
complete source path from listener admission to vault dispatch. I did not
execute a trigger or connect a test client to an installed helper. No fixed
revision was available for comparison. The exact introduction version is
unknown; the reviewed revision is confirmed affected.

The affected surface is local and limited to the same logged-in Aqua session.
Given that exposure, the recommended calibration is **Medium (P2)** despite the
potential whole-vault confidentiality and integrity impact.

## Background

Key separates its CLI from the component holding cryptographic authority. The
CLI sends high-level requests over XPC; the LaunchAgent loads or unwraps the
vault key, performs encryption or decryption, accesses the configured vault
directory, and returns a structured response. This architecture keeps Keychain
and Secure Enclave access out of the short-lived CLI process.

That split creates a critical authorization boundary. A process admitted to
the helper can ask it to exercise authority that the process does not hold
itself, particularly access to a vault key already cached in helper memory.
Therefore, the listener must establish that a connection belongs to the
intended signed client before it exports the service object.

The helper is registered as `work.tvr.key.agent` in the user's Aqua launchd
session. Per-user registration narrows exposure to the local login session and
prevents ordinary remote access. It does not, by itself, distinguish the Key
CLI from unrelated processes in that same session.

## Vulnerability Details

We first reach the connection boundary in
`Sources/KeyLaunchAgentHelper/main.swift`. The complete decision is:

```swift
func listener(
    _ listener: NSXPCListener,
    shouldAcceptNewConnection newConnection: NSXPCConnection
) -> Bool {
    newConnection.exportedInterface = NSXPCInterface(
        with: KeyXPCProtocol.self
    )
    newConnection.exportedObject = exportedObject
    newConnection.resume()
    return true
}
```

The decisive behavior is at lines 51-55: the implementation assigns the
interface and privileged object, resumes the connection, and returns `true`
without inspecting the connection's audit token or resolving the peer's
signing identity. There is no fail-closed branch.

Once admitted, the exported service decodes a high-level request and calls
`KeyServiceHandler.handle`. The handler's complete dispatch at
`Sources/KeyCore/KeyServiceHandler.swift:44-144` includes diagnostics,
plaintext access, sharing transitions, enrollment, and filesystem mutations.
The plaintext branch illustrates the authority crossing most clearly:

```swift
case let .get(name):
    let encrypted = try entryStore.load(name)
    let keyData = try loadVaultKey(
        reason: "Unlock key vault to read '\(name)'.",
        createIfMissing: false
    )
    let decrypted = try decryptSecret(
        encrypted,
        named: name,
        keyData: keyData
    )
    return .success(
        try renderValue(
            for: encrypted.type,
            decryptedValue: decrypted
        )
    )
```

If we carry an admitted request into this branch, the caller-selected logical
name determines which encrypted entry is loaded. The helper then obtains the
vault key, decrypts the entry, and places the resulting value in its reply.
Nothing between listener admission and this sink re-establishes caller
identity.

The same dispatch also reaches mutation and sharing operations:

```swift
case .shareVault:
    try ensureLocalMode()
    try keyStore.migrateLocalVaultToEnclave(
        vaultRootURL: entryStore.rootURL,
        reason: "Unlock key vault to share this vault."
    )
    try persistSecurityMode(.enclave)
    return .success("Vault is now shared in enclave mode.\n")

// ...

case let .addManual(name, secret, type):
    try storeAddedSecret(secret, as: name, type: type)
    return .success()
case let .editManual(name, secret, type):
    try storeEditedSecret(secret, as: name, type: type)
    return .success()
case let .removeEntry(name):
    try entryStore.removeEntry(name)
    return .success()
```

The broken invariant is not cryptographic. Keychain access control can
correctly authorize the helper, and AES-GCM can correctly authenticate stored
ciphertext, while the overall system still authorizes the wrong client. The
helper assumes that reaching its Mach service proves the caller is the Key CLI;
the listener never establishes that premise.

## Exploitability Analysis

The practical security impact depends on endpoint state and caller
capabilities.

The highest-impact condition is a warm helper session. A legitimate operation
can leave the symmetric vault key cached in the LaunchAgent for the configured
idle window. During that interval, a second admitted connection can reach the
same handler and reuse the cached key. The security boundary crossed here is
real: same-user execution does not ordinarily grant one process access to
another process's cached secret key or decrypted response.

A cold helper provides meaningful counterpressure. Key-backed requests still
invoke LocalAuthentication-backed Keychain or Secure Enclave policy, so silent
plaintext access is not established from source in that state. A request may
cause a user-presence prompt, but I did not assess prompt-confusion behavior or
claim a bypass of LocalAuthentication.

Several operations in the reviewed handler do not load the key. Listing,
copying, moving, and removing entries therefore do not benefit from the cold-key
authentication boundary. Their incremental privilege impact may be smaller
because a same-user process could also have direct filesystem access to a
user-owned vault directory, depending on sandboxing and directory permissions.
They remain relevant because they show that the exported object conveys broad,
undifferentiated authority.

The following constraints bound the finding:

- the caller must execute locally in the same logged-in session and be able to
  resolve the per-user Mach service;
- a remote network actor cannot directly reach this XPC path;
- application sandbox policy may prevent some processes from looking up the
  service;
- silent key-backed access depends on a warm helper cache;
- the reviewed API returns decrypted entries but does not directly expose the
  raw shared vault key.

Existing controls do not authenticate the peer. launchd registration protects
service ownership, not client identity. Helper code signing and hardened
runtime establish properties of the server process, not the connecting
process. Secure Enclave non-exportability protects the device private key, but
the helper is already the component authorized to unwrap and use the shared
vault key.

## Proof of Concept

No trigger was executed, and this report does not distribute an exploitation
client. The sibling `poc/README.md` instead specifies a harmless defensive
regression-test design for an isolated macOS test account and a synthetic vault.

The test begins with a non-secret operation and verifies a property of the
connection boundary: an unrelated, deliberately unsigned test client must be
rejected before `KeyAgentService.sendRequest` is invoked. A second phase uses a
synthetic entry containing a fixed non-sensitive marker and a deliberately
warmed helper session. It confirms that the unauthorized connection is still
rejected in the state where the original defect would otherwise have the
largest privilege delta.

The expected result on a corrected build is:

```text
[PASS] trusted signed CLI connection accepted
[PASS] unsigned test client rejected before handler dispatch
[PASS] same-team wrong-identifier client rejected
[PASS] warm-cache state does not change peer authorization
```

The test should record only connection disposition and handler invocation
counts. It should never print or retain a real vault value. The test account,
vault directory, Keychain items, and launchd job must be disposable and removed
after the run.

## Remediation

The invariant to restore is: **the helper must authenticate the peer using
kernel-bound connection identity before exporting or resuming the privileged
object**.

On supported deployment targets, prefer a first-party XPC code-signing
requirement API. Otherwise, resolve `SecCode` from `NSXPCConnection.auditToken`
and validate it against a precompiled `SecRequirement` that pins both:

- the expected Apple Developer Team ID; and
- the exact signing identifier of the shipped Key CLI.

The fixed listener should have this shape:

```swift
func listener(
    _ listener: NSXPCListener,
    shouldAcceptNewConnection connection: NSXPCConnection
) -> Bool {
    guard clientValidator.isAuthorized(auditToken: connection.auditToken) else {
        return false
    }

    connection.exportedInterface = NSXPCInterface(
        with: KeyXPCProtocol.self
    )
    connection.exportedObject = exportedObject
    connection.resume()
    return true
}
```

`clientValidator` should construct the guest-code reference from the audit
token, not from a PID or executable path. PID and path checks introduce
substitution and lifetime races. Checking only the effective UID would preserve
the current vulnerability, while checking only the Team ID could admit
unrelated software signed by the same developer account. Validation errors must
fail closed before the object is assigned or the connection is resumed.

Defense in depth should reduce the authority behind any single mistake:

- separate diagnostic requests from plaintext and mutation interfaces;
- version and size-bound the wire protocol;
- record authorization failures without logging request contents or entry
  names;
- consider a short-lived capability tied to a successfully authenticated
  client connection after explicit unlock;
- keep the signed CLI's identifier stable and verify it as part of release
  packaging.

Regression tests should cover the real installed XPC boundary:

1. The shipped, correctly signed CLI is accepted.
2. An unsigned test client is rejected before handler dispatch.
3. A client signed by the same team under a different identifier is rejected.
4. A copied or renamed untrusted binary remains rejected, demonstrating that
   the decision is not path-based.
5. Rejection remains effective while the vault-key cache is warm.
6. Diagnostic and plaintext requests share the same peer requirement.
7. Local and enclave vault modes enforce identical peer validation.
8. Missing or malformed signing state fails closed.
9. Authorization tests run against the packaged LaunchAgent rather than only
   invoking `KeyServiceHandler` in process.

## Summary

The LaunchAgent centralizes vault authority effectively, but its XPC listener
does not authenticate the process asking it to exercise that authority. We
traced the defect from the unconditional acceptance at
`Sources/KeyLaunchAgentHelper/main.swift:51-55` through the full handler
dispatch at `Sources/KeyCore/KeyServiceHandler.swift:44-144`. In a warm helper
session, this can cross the intended boundary around cached vault plaintext;
the same missing check also exposes broad mutation authority.

The finding is local and same-session, and cold key-backed operations retain
user-presence protection. Those constraints justify Medium/P2 calibration, but
they do not replace peer authentication. The durable fix is a fail-closed audit
token and code-signing requirement check performed before the privileged object
is exported, backed by packaged-boundary regression tests.
