# Defensive entry-context regression model

This directory contains no exploit and does not operate on a live vault. It
specifies harmless unit tests using fixed synthetic data to verify the
authenticated-context contract for the next entry format.

## Test fixture

Use only in-memory values or a framework-created temporary directory:

- fixed 32-byte test key;
- vault IDs `00000000-0000-0000-0000-000000000001` and
  `00000000-0000-0000-0000-000000000002`;
- logical names `test/alpha` and `test/bravo`;
- marker plaintexts `ALPHA_TEST_VALUE` and `BRAVO_TEST_VALUE`;
- synthetic TOTP seed `JBSWY3DPEHPK3PXP`.

Do not access Keychain, Secure Enclave, XPC, cloud synchronization, configured
vault paths, or user secrets.

## Current-format characterization

The v2 characterization model should document, without touching persistent
state, that:

1. Encrypt the two marker values under the same synthetic key.
2. Associate each returned envelope with the opposite synthetic logical name.
3. Observe that current `VaultCipher.decrypt` has no name parameter and
   therefore authenticates both envelopes.
4. Encrypt the synthetic TOTP seed with outer type `totp`.
5. Construct an otherwise identical in-memory envelope with outer type
   `secret`.
6. Observe that current `VaultCipher.decrypt` authenticates the ciphertext
   because outer type is not associated data.

These are unit-level characterization assertions, not instructions for altering
a vault.

## Fixed-format assertions

For v3, use the same synthetic fixture and require:

```text
[PASS] exact entry context decrypts
[PASS] changed logical name is rejected
[PASS] changed vault ID is rejected
[PASS] changed semantic type is rejected
[PASS] swapped envelopes are rejected
```

The tests should assert `CryptoKitError.authenticationFailure` for each context
mismatch. They should also verify that copy and move operations re-encrypt under
the destination context and that the authenticated inner type controls
rendering.

## Migration checks

Create only synthetic v2 fixtures in a temporary directory. Exercise a staged
v2-to-v3 migration, inject a test-only interruption before commit, then verify
that the migration resumes or rolls back without losing either fixture. Remove
the temporary directory at test teardown.

No test in this model should print plaintext beyond the fixed marker strings.
