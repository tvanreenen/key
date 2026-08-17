# Installed Migration Qualification

The migration qualification harness exercises the real installed CLI,
LaunchAgent helper, local Keychain, Secure Enclave, checkpoint cache, and
filesystem publisher without repointing either Stable or Preview.

Run the complete gate with:

```sh
just test-migration-installed
```

The gate rebuilds every scenario app from the current checkout by default so
an older installed qualification binary cannot satisfy a newer source gate.
Set `KEY_MIGRATION_QUALIFICATION_REBUILD=0` only for an intentional rerun of
the exact installed binaries.

macOS requests user presence when each disposable corpus first creates its
local vault key and when migration creates its Secure Enclave identity. The
runner waits for helper registration and restart until a configurable deadline
instead of assuming one fixed launch delay. Override the default 120-second
deadline only when diagnosing an unusually slow machine:

```sh
KEY_MIGRATION_QUALIFICATION_HELPER_WAIT_SECONDS=240 \
  scripts/run-migration-qualification.sh
```

The runner must execute outside a parent application sandbox because its CLI
needs Mach lookup access to the qualification LaunchAgent. A sandbox denial is
reported by macOS as `deny mach-lookup work.tvr.key.agent.qualification...`;
it is not a helper, signing, or vault failure.

## Isolation boundary

Qualification builds exist only under `#if DEBUG`. Their CLI retains the
Stable CLI signing identifier, and their helper retains Stable's Keychain
access group so the real signed components can use authenticated XPC,
Keychain, and Secure Enclave. Both the parent app and helper receive distinct
bundle identifiers so LaunchServices, Background Task Management, and
`xpcproxy` cannot resolve a qualification service to Stable or another
qualification install. Each corpus receives all of these separate mutable
namespaces:

- parent app and helper bundle identifiers, Keychain service, and vault-key
  account;
- Application Support directory and default vault directory;
- LaunchAgent label, plist name, primary Mach service, and status service; and
- disposable APFS corpus root.

The runner snapshots Stable and Preview files before and after the complete
selected run. It never unregisters, repoints, copies, resets, or restores
either real product's configuration, helper, Keychain service, enrollment
identity, or checkpoint.

## Scenarios and evidence

The default run covers deliberately invalid encrypted input, an 8-entry mixed
vault, and a 300-entry nested vault containing 240 secrets and 60 TOTP entries.
Reports contain only inventories, counts, status JSON, and SHA-256 digests.
Secret plaintext is piped directly into the CLI, never printed or written to
the evidence directory. The runner also scans qualification files for its
generated plaintext markers.

Successful migration requires exact v2 source hashes before and after,
identical v2/v3 inventories, identical externally comparable secret-value
hashes, functional TOTP reads, a cold helper restart, and an exact retained-v2
rollback reopen. Invalid preflight and apply must both fail without changing
the v2 source or selecting v3.

Evidence is retained in the temporary directory printed at completion.
Qualification-only Keychain and Secure Enclave records remain available for
inspection; they do not share a service with Stable or Preview.

Run only selected scenarios while developing the harness:

```sh
KEY_MIGRATION_QUALIFICATION_SCENARIOS="invalid small" \
  scripts/run-migration-qualification.sh
```

Use a fresh namespace prefix when macOS still retains Background Task
Management history for a retired qualification install. This avoids resetting
the machine-wide background-item database or disturbing Stable and Preview:

```sh
KEY_MIGRATION_QUALIFICATION_NAMESPACE_PREFIX=migration-rerun \
KEY_MIGRATION_QUALIFICATION_SCENARIOS=invalid \
  scripts/run-migration-qualification.sh
```
