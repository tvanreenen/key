# Using recovery-capable vaults

These commands describe explicitly enabled experimental builds. Shipping Stable and ordinary Preview keep recovery disabled. Use disposable data while the [remaining qualification](piv-recovery-plan.md#remaining-acceptance-matrix) is open.

## Register independent recovery keys

Set up each hardware key outside Key, following the [external setup requirements](piv-recovery-contract.md#owner-operated-setup-boundary). Key expects a generated-on-device P-256 key in PIV slot 9d, its matching certificate, and the required PIN, touch and management protection. Key does not initialize or provision that hardware.

Use `key recovery tokens` and `key recovery credential --token <token-id>` to inspect public selectors and compatibility. A successful public inspection does not prove possession or that recovery will work.

On an enrolled Mac, explicitly adopt the recovery-capable format with `key recovery adopt`. Adoption alone does not protect the vault. Then register a key:

```sh
key recovery register prepare --token <token-id> --recipient <recipient-id> --export-anchor <new-anchor-file>
```

Install that exact exported public anchor through the external PIV administration workflow, then finish:

```sh
key recovery register finish --token <token-id> --recipient <recipient-id>
key recovery register status
```

Finish requests native hardware approval. Enter the PIN in the macOS dialog, then physically touch the flashing key when prompted. Keep PIN/PUK and hardware administration separate from Key's configuration.

Register each independent backup key through the same process; each has its own anchor and public recipient ID. Retain keys separately and qualify each one independently. The original key need not be connected when registering its backup.

## Add, remove or replace a Mac

Use the existing sharing workflow for the same vault folder:

```sh
key share invite --name <existing-mac-name>
key share join <invitation-id> --name <joining-mac-name> --vault-dir <existing-vault-folder>
```

The joining Mac uses the same encrypted folder delivered by the owner’s chosen storage provider. The invitation comes from a Mac that already has access. Follow the displayed `requests`, `compare`, `approve` and `accept` steps. Compare the exact code and both Mac names before approving. The joining Mac verifies the approved current contents before selecting the folder. The recovery keys can remain disconnected.

Use `key share devices` to identify an enrolled Mac and `key share revoke <device-id>` to review removal of its access. Confirmation changes the vault key for the remaining active Macs and recovery keys. Old copies remain accessible with their old credentials.

A revoked Mac can use a fresh invitation with `key share join` to begin replacement. Review and confirm deletion of its exact old local credentials and checkpoint, then continue ordinary compared enrollment with a new identity. Replacement does not switch vaults. Interrupted cleanup retains its exact progress; continue the displayed workflow instead of deleting saved records or initializing another vault.

## Remove a recovery key

Inspect public recipient IDs with `key recovery register status`, then run:

```sh
key recovery remove-recipient <recipient-id>
```

The hardware key can stay disconnected. Review the exact ID and the number of recovery keys remaining, then type `REMOVE`. Removing the last key requires typing `REMOVE LAST RECOVERY KEY` after the protection-loss notice. Register another while an enrolled Mac is still available; losing all enrolled Macs before then leaves no recovery path.

Removal changes future versions on the continuing vault history. It leaves the physical key and its public anchor unchanged, and it cannot revoke access to old copies. An ID beginning with `-` must follow `--` on the command line.

A committed removal can still have local cleanup pending. Preserve its files and records, and explicitly run the command again to review and finish that same saved operation. A failed or lost reply does not prove nothing committed. Key does not retry automatically or create a replacement candidate during resume.

## Recover after losing the Macs

Start on an unconfigured Mac with the encrypted source files, one registered recovery key, its PIN/touch approval and a fresh destination. Use `key recovery restore --help` for the explicit source/destination options. Recovery does not overwrite a selected vault. The recovered vault has new Mac credentials and must be separately registered for recovery again.

The folder/provider supplies available files; delivery freshness and backup retention remain external responsibilities. Key refuses visible conflicts and required missing state. It cannot prove that a provider has delivered every newer file.
