# Entry-freshness defensive model

This directory contains a harmless, deterministic model of the freshness
invariant described in the report. It does not open or modify a Key vault,
perform cryptography, contact synchronized storage, or contain instructions
for replacing files.

The model distinguishes two properties:

- authentication answers whether an envelope is valid and unmodified; and
- freshness answers whether that valid envelope is the current revision.

Both the historical and current test envelopes are marked authentic. The
legacy policy accepts both. The defensive policy also consults trusted current
state and rejects the historical revision.

## Run

On macOS with Swift installed:

```sh
swift replay_freshness_model.swift
```

Expected output:

```text
[legacy] current authentic envelope accepted: true
[legacy] historical authentic envelope accepted: true
[fixed] historical revision 1 vs pinned revision 2 accepted: false
[+] regression invariant holds
```

The script is read-only and creates no persistent files, so no cleanup is
required.

## Production regression mapping

The model should become repository tests around the final trusted-state
design:

```swift
@Test func historicalAuthenticEnvelopeIsRejectedAfterNewerRevisionObserved()
@Test func currentAuthenticEnvelopeIsAccepted()
@Test func unauthenticatedEnvelopeIsRejectedRegardlessOfRevision()
@Test func pinnedEntryStateSurvivesHelperRestart()
@Test func newlyEnrolledDeviceReceivesAuthenticatedCurrentCheckpoint()
@Test func concurrentUpdateConflictDoesNotSilentlyLowerRevision()
@Test func interruptedEntryAndManifestUpdateFailsClosedAndRecovers()
```

The production tests should use an isolated temporary directory and an
in-memory trusted-state test double. They should not depend on iCloud or any
live synchronization provider.
