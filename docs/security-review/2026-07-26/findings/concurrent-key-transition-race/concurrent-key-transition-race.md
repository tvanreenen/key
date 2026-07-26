# Concurrent requests can strand entries across a key transition

## Executive Summary

Key exports one shared `KeyServiceHandler` to multiple XPC connections, but
does not serialize complete vault operations. An enclave-to-local `unshare`
transition can snapshot existing names while a concurrent add retains the old
enclave key and writes a new name outside that snapshot. Unshare then selects
the new local key. Both requests can succeed, yet the new entry remains
encrypted under the retired key.

This is CWE-362, Concurrent Execution Using Shared Resource with Improper
Synchronization. I reviewed revision
`84e7ddb79141d8f1665f3c1bf2e4254677a988a2` directly and validated the
interleaving statically. I did not run concurrent requests or modify a live
vault. No fixed revision was available. The issue is local, timing-dependent,
and can cause persistent loss of access to affected entries; severity is
**Medium (P2)**.

## Background

Each CLI invocation uses XPC, while the helper can remain alive across
invocations. The listener assigns the same service object to each connection:

```swift
// Sources/KeyLaunchAgentHelper/main.swift:51-55
func listener(
    _ listener: NSXPCListener,
    shouldAcceptNewConnection connection: NSXPCConnection
) -> Bool {
    connection.exportedInterface = NSXPCInterface(
        with: KeyXPCProtocol.self
    )
    connection.exportedObject = exportedObject
    connection.resume()
    return true
}
```

`KeyAgentService` holds one handler, and each decoded message calls it directly:

```swift
// Sources/KeyLaunchAgentHelper/main.swift:70-86
func sendRequest(
    _ requestData: NSData,
    withReply reply: @escaping (NSData?, NSString?) -> Void
) {
    let request = try decoder.decode(
        KeyServiceRequest.self,
        from: requestData as Data
    )
    let response = handler.handle(request)
    let responseData = try encoder.encode(response)
    reply(responseData as NSData, nil)
}
```

The required invariant is that every entry write occurs wholly before a key
transition and is included in its rewrite, or wholly after it and uses the new
key.

## Vulnerability Details

The handler dispatch has no whole-request executor:

```swift
// Sources/KeyCore/KeyServiceHandler.swift:112-125
case .unshareVault:
    try ensureEnclaveMode()
    return .success(try unshareVault())

case let .addManual(name, secret, type):
    try storeAddedSecret(secret, as: name, type: type)
    return .success()
```

Unshare loads the old key and captures a fixed name set:

```swift
// Sources/KeyCore/KeyServiceHandler.swift:284-304
let oldKey = try loadVaultKeyFromEnclave(
    reason: "Unlock key vault to convert this shared vault back to local-only mode."
)
let entryNames = try entryStore.listEntries()
let existingFiles = try Dictionary(
    uniqueKeysWithValues: entryNames.map { name in
        (name, try entryStore.load(name))
    }
)
// Decrypt snapshot, generate newLocalKey, and prepare rewrittenFiles.
```

It later stores the new key, rewrites only `entryNames`, then commits local
mode:

```swift
// Sources/KeyCore/KeyServiceHandler.swift:306-323
try keyStore.storeKey(
    newLocalKey,
    mode: .local,
    overwriteExisting: true
)
for name in entryNames {
    guard let rewritten = rewrittenFiles[name] else { continue }
    try entryStore.save(rewritten, as: name, overwrite: true)
}
try persistSecurityMode(.local)
let cleanupMessage = try keyStore.removeEnclaveArtifacts(
    vaultRootURL: entryStore.rootURL
)
```

Meanwhile, add loads a key before saving its new file. The mode queue does not
span that complete operation; `securityMode()` only serializes one read at
lines 336-339.

A deterministic schedule proves the bad state. Starting with active enclave
key `K0` and entry `alpha`:

| Step | Unshare | Concurrent add |
|---|---|---|
| 1 | Load `K0`; snapshot `{alpha}` | — |
| 2 | Prepare `alpha` under new `K1` | Load and retain `K0` for `beta` |
| 3 | Store `K1`; rewrite `alpha` | Save `beta` under `K0` |
| 4 | Commit local mode using `K1` | Return success |

Unshare also returns success. The final vault is
`{alpha: K1, beta: K0}` with active key `K1`, so a later read of `beta` fails
authentication.

## Exploitability Analysis

This race can arise from two overlapping CLI processes; it needs no
cryptographic failure or filesystem error. The vulnerable interval begins
after unshare snapshots names and ends when local mode is committed. Larger
vaults make that interval longer because every snapshotted entry is decrypted,
re-encrypted, and rewritten.

The impact is bounded:

- the caller needs local access and precise request overlap;
- sequential CLI use avoids the race;
- affected writes can be stranded, but this path does not disclose plaintext;
- entries included in the snapshot may remain readable.

Existing queues serialize individual key-store calls and mode reads, and entry
writes are individually atomic. Those controls are useful but insufficient:
the invariant spans key selection, mode, configuration, and the whole entry
set. Atomic components do not create an atomic transaction.

## Proof of Concept

No live or destructive trigger was executed. The sibling `poc/` artifacts
contain a harmless symbolic state-machine model using only labels `K0`, `K1`,
`alpha`, and `beta`. It performs no XPC, cryptography, filesystem, Keychain, or
vault operation.

The vulnerable model ends with:

```text
mode=local active=K1 entries={alpha:K1,beta:K0}
[FAIL] beta uses retired key K0
```

The fixed model must permit only either serialized result:

```text
[PASS] add then unshare: entries={alpha:K1,beta:K1}
[PASS] unshare then add: entries={alpha:K1,beta:K1}
```

## Remediation

The invariant to restore is: **a key or mode transition is exclusive with every
entry and authorization mutation from its first state read through final
commit**.

The clearest repair is one vault-level executor above the key store, entry
store, and configuration:

```swift
public final class KeyServiceHandler {
    private let operationQueue = DispatchQueue(
        label: "work.tvr.key.vault-operations"
    )

    public func handle(
        _ request: KeyServiceRequest
    ) -> KeyServiceResponse {
        operationQueue.sync {
            handleExclusively(request)
        }
    }

    private func handleExclusively(
        _ request: KeyServiceRequest
    ) -> KeyServiceResponse {
        // Existing complete request switch.
    }
}
```

This conservative serialization suits a CLI-first vault. If concurrent reads
are later required, use an explicit reader/writer coordinator and keep
unshare, share, add, edit, copy, move, remove, enrollment, and authorization
changes exclusive. Do not rely on separate component locks; they lack a single
transaction order.

Regression tests should use deterministic barriers:

1. Pause unshare immediately after its name snapshot.
2. Start an add and pause it after key selection.
3. Assert the coordinator prevents both critical sections from overlapping.
4. Verify add-before-unshare includes and rewrites the new name.
5. Verify unshare-before-add makes add use the new key.
6. After both schedules, decrypt every entry with the selected key.
7. Repeat through two packaged test XPC connections.
8. Cover edit, copy, move, remove, share, leave, and enrollment mutations.

## Summary

One shared handler can execute complete vault operations concurrently, while
its queues protect only isolated state. We traced an interleaving where unshare
misses a concurrently added name, the add commits with the old key, and
unshare selects a new key. Both calls can succeed while the new entry becomes
unreadable.

A single vault-level transaction executor is the durable fix. Deterministic
barrier tests should prove that every mutation is ordered entirely before or
after each key transition.
