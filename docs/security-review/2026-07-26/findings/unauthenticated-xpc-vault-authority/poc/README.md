# Defensive XPC authorization regression-test design

No exploit or trigger is included. This directory documents a defensive test
setup for verifying that the Key LaunchAgent authenticates callers before
exporting vault authority.

## Safety boundary

Run only in a disposable macOS test account with:

- a test-signed Key application and LaunchAgent;
- a synthetic vault containing no real secrets;
- a dedicated Keychain namespace;
- no synchronized cloud-storage path; and
- cleanup scripts that unload the test job and remove test-only files and
  Keychain items.

The test must never inspect, print, or retain a real vault value.

## Test actors

Prepare three minimal clients that implement the expected XPC interface but send
only a harmless status request:

1. the correctly signed and packaged Key CLI;
2. an unsigned or ad hoc-signed test client; and
3. a client signed by the expected team under a different identifier.

Instrument the test-only helper to count whether
`KeyAgentService.sendRequest` is entered. Do not log request payloads.

## Assertions

The corrected listener must satisfy all of these assertions:

- the packaged Key CLI is accepted;
- the unsigned client is rejected before handler dispatch;
- the same-team, wrong-identifier client is rejected before handler dispatch;
- renaming or copying the untrusted client does not change the result;
- invalid code-signing metadata fails closed;
- the result is unchanged when a synthetic helper session is marked warm;
- local and enclave test configurations use the same peer requirement.

Expected summary:

```text
[PASS] trusted signed CLI connection accepted
[PASS] unsigned test client rejected before handler dispatch
[PASS] same-team wrong-identifier client rejected
[PASS] warm-cache state does not change peer authorization
```

## Cleanup

After the test, unload the test-only LaunchAgent, delete the synthetic vault and
configuration, remove the dedicated Keychain items, and delete the disposable
test account. Confirm that no test helper remains registered.
