# Defensive enrollment-authentication regression design

This directory intentionally contains no executable exploit or live enrollment
client. The associated report is based on source review, and no two-device
trigger was executed.

The recommended regression fixture is a local, deterministic protocol model
with two distinct requester identities:

- identity A represents the device the operator intends to approve;
- identity B represents a different, substituted requester;
- both requests are internally valid and signed by their corresponding test
  keys;
- the vault identifier is the same for both requests; and
- no Keychain, Secure Enclave, MultipeerConnectivity, vault file, or real
  secret is used.

## Required assertions

The fixed implementation should satisfy all of these properties:

1. A comparison string displayed for identity A cannot confirm identity B.
2. Changing the requester public key changes the comparison string.
3. Changing the vault identifier, either peer nonce, approver identity,
   protocol version, or expiration invalidates or changes the transcript.
4. The requester cannot supply the value against which confirmation is
   checked.
5. Confirmation references a locally generated pending-approval identifier.
6. Expired, replayed, and already-consumed approvals are rejected.
7. Manual-file approval requires an independent fingerprint or transcript
   comparison.
8. The wrapped vault key is created only for the public key covered by the
   confirmed transcript.

## Suggested Swift Testing cases

```swift
@Test func substitutedRequesterCannotReuseComparison()
@Test func requesterKeyIsBoundToAuthenticationString()
@Test func bothNoncesAreBoundToAuthenticationString()
@Test func expiredTranscriptIsRejected()
@Test func consumedApprovalCannotBeReplayed()
@Test func manualApprovalRequiresIndependentComparison()
@Test func confirmedTranscriptSelectsWrappedKeyRecipient()
```

These tests should use fixed in-memory keys and timestamps so results are
repeatable. They should call extracted transcript-derivation and confirmation
logic directly. Nearby transport behavior can be covered separately with a
mock peer-selection layer; the tests must not browse for or contact real
devices.
