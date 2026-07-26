# Defensive concurrent-transition model

This is a harmless regression specification. It uses no application code,
XPC, cryptography, files, Keychain, Secure Enclave, or user data.

Model only these in-memory values:

```text
mode = enclave
activeKey = K0
entries = {alpha: K0}
```

Advance two symbolic operations through explicit checkpoints:

| Checkpoint | Unshare operation | Add operation |
|---|---|---|
| T0 | Snapshot `{alpha}` | — |
| A0 | — | Retain `K0` for `beta` |
| T1 | Store `K1`; rewrite `alpha` | — |
| A1 | — | Commit `beta:K0` |
| T2 | Commit local mode, active `K1` | — |

Current-state assertion:

```text
[FAIL] beta key K0 differs from active key K1
```

Fixed-state assertions through an exclusive coordinator:

```text
[PASS] add then unshare: {alpha:K1,beta:K1}
[PASS] unshare then add: {alpha:K1,beta:K1}
```

An application regression test may implement equivalent test-only barriers
against a temporary synthetic vault, but must never use real entries or
synchronized storage.
