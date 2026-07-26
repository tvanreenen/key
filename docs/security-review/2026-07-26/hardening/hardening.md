# Security Hardening Review: key

## Evidence Basis

I inspected the complete repository at revision
`84e7ddb79141d8f1665f3c1bf2e4254677a988a2`, including the CLI, XPC helper,
Secure Enclave/Keychain integration, file formats, tests, and release
configuration. The individual issues converge on one structural condition:
cryptographic operations are sound, but caller identity and distributed vault
state transitions are owned by loosely coordinated callers and mutable files.

## Constraints

We assume a CLI-first product, ordinary file-sync providers, per-device Secure
Enclave identities, local/offline operation, and no supplied latency or memory
budget. Local-only mode must remain available and readable throughout rollout.

## Opportunity Portfolio

| Opportunity | Evidence | Options | Recommendation | Proposal |
|---|---|---|---|---|
| Make sharing an authenticated, versioned vault state machine | XPC caller auth, enrollment identity, revocation, rollback, concurrency, and migration findings (CAND-001–CAND-011) | 1. Local guards; 2. Versioned transaction layer; 3. Append-only signed operation log | Option 2 under current constraints | [Authenticated vault state machine](proposals/authenticated-vault-state-machine.md) |

## Recommendation Summary

I recommend Option 2: keep the file-based vault and CLI shape, but put all
privileged operations behind an authenticated helper and one serialized,
versioned transaction engine. A signed/MACed manifest commits the current
generation; entries authenticate vault ID, logical name, type, and revision;
enrollment binds both peers to one transcript; revoke rotates the data key; and
rekey operations stage a complete generation before one commit point.

This is a larger change than tactical guards, but it preserves the product's
most elegant property—portable ordinary files—without taking on the operational
and compaction complexity of a full distributed operation log.

## Next Decisions

Decide the recovery policy, the manifest authority model (single writer versus
multi-device quorum/merge), and whether `vault path set` should be refused while
the helper is running or become a helper-owned transaction.

Execution is tracked in the
[Enclave Vault Security Implementation Tracker](../implementation/versioned-transactions.md).
