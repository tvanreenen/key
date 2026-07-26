# Suggested unit-test matrix

| Test | Input variation | Expected v3 result |
|---|---|---|
| Exact round trip | No variation | Decrypts |
| Name binding | `test/alpha` to `test/bravo` | Authentication failure |
| Vault binding | Vault ID 1 to vault ID 2 | Authentication failure |
| Type binding | `totp` to `secret` | Authentication failure |
| Version binding | v3 to another format version | Rejected |
| Suite binding | AES-256-GCM to another suite label | Rejected |
| Envelope exchange | Exchange alpha and bravo files | Both rejected |
| Copy | Copy alpha to a new logical name | Re-encrypted and decrypts only at destination |
| Move | Move alpha to a new logical name | Re-encrypted and source context rejected |

All fixtures are synthetic and must remain in memory or under a test-created
temporary directory.
