# Security, Continuity, and Recovery

This is the user-facing security and recovery promise for Key version 3 in
`0.2.0`.

## Storage Qualification

Version 3 is directly qualified with vaults on local APFS and in iCloud Drive.
Other ordinary folder-backed providers may work when they preserve the
required filesystem semantics, but they have not been directly validated and
are not covered by the `0.2.0` compatibility guarantee. Every configured root
must still pass Key's containment, type, atomicity, hydration, and naming-safety
checks. Key trusts only authenticated, content-addressed vault history; it
never trusts provider ordering, timestamps, mutable metadata, or a claimed
latest file.

Missing provider objects are treated as incomplete delivery. Normal reads and
all writes fail closed until the authenticated state is complete. An explicit
`--allow-stale` read may use only the last complete version already trusted on
that Mac. Malformed, substituted, rolled-back, or authority-conflicting objects
are security or recovery failures, not synchronization delays.

## Keep Two Enrolled Macs

Keep at least two active enrolled Macs. Each active Mac holds its own
non-exportable Secure Enclave identity and has equal authority to enroll a new
Mac or revoke another one after local authentication and explicit review. A
file provider cannot enroll, revoke, or impersonate a device.

With one surviving active Mac, you can enroll a replacement for a lost or
revoked Mac. With no surviving enrolled Mac, you cannot unlock or recover the
vault.

Inspect the authenticated roster with:

```sh
key share devices
```

## Invitations and Device Comparison

An enrollment invitation lasts 10 minutes and is bound to one vault, trusted
checkpoint, inviting identity, and new device. The joining Mac creates its own
fresh identity and answers that exact invitation. Before approval, compare the
displayed device pair and comparison code on the two Macs.

Provider delay does not extend an invitation or authorize a different
ceremony. A joining Mac may finish only an exact approval that was durably
prepared while the invitation was valid. Otherwise, create a new invitation.

## Revocation and Replacement

Revoking a Mac rotates the vault key, re-encrypts the current snapshot, and
omits the revoked identity from new key wrappers. The revoked Mac keeps any old
material it already possessed, but it cannot open the new current snapshot or
future history.

If the revoked Mac later returns, start a fresh invitation on a surviving
active Mac and run the ordinary join command on the revoked Mac. Key displays a
replacement review and requires the literal `REJOIN` confirmation before it
removes only that Mac's unusable local enrollment state. It revalidates the
invitation immediately before cleanup. If helper restart exceeds the bounded
wait, rerun the same join command; enrollment resumes from the completed state
without repeating cleanup.

## What the Provider Cannot Recover

iCloud Drive or local APFS stores encrypted entries, authenticated manifests,
device public keys, and enrollment messages. It does not store the current
vault key, a password-derived recovery key, cloud escrow, or a support
override. Retained version 2 files can support migration rollback while you
validate a migration, but they are not a recovery key for the version 3 vault.

If every enrolled Mac and Secure Enclave identity is lost, the synchronized
version 3 files are permanently unrecoverable in `0.2.0`. Key will not generate
a replacement key, silently trust provider files, or offer a destructive
repair that pretends otherwise.
