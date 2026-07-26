# Self-authenticating enrollment code does not bind the intended device

## Executive Summary

Key's shared-vault enrollment flow presents a six-digit verification code
during device approval, but the joining device chooses that code and includes
it in its self-signed enrollment request. The approving CLI then displays the
same request field and asks the user to type it back. This interaction confirms
that the operator can repeat a displayed value; it does not establish that the
request came from the device the operator intended to authorize.

The defect matters at a sensitive boundary. Successful approval causes the
existing device to wrap the shared vault key to the requester's public key.
If the selected nearby request or manually transferred request belongs to a
different device, completing the current prompt authorizes that different
key. Existing cryptographic checks prove possession of the advertised private
key and protect the request from modification, but they do not bind that key
to the intended peer.

The issue is assessed as **Medium severity (P2)**. The resulting
confidentiality impact is high because an incorrectly authorized device
receives a normal vault-key wrapper. Likelihood is moderated by the need for
the operator to initiate enrollment and complete an interactive,
user-presence-protected approval.

I reviewed revision
`84e7ddb79141d8f1665f3c1bf2e4254677a988a2` directly. The enrollment code
appears to have been introduced in that revision on May 12, 2026. I did not
execute a nearby race, contact live devices, modify a vault, or perform a
two-device Secure Enclave enrollment because two provisioned test devices
were not available. No fixed revision was supplied or reviewed.

## Background

In enclave mode, Key encrypts vault entries with one symmetric vault key.
Each authorized Mac owns a P-256 private key held by its Secure Enclave, while
shared vault metadata stores a copy of the symmetric key wrapped separately
for each authorized public key. Enrollment is therefore the authorization
decision that determines whether a new public key receives access to the
vault key.

The joining Mac constructs `DeviceEnrollmentRequest`. In
`Sources/KeyCore/VaultKeyStore.swift::makeEnrollmentRequest`, it generates the
human-facing code and places that code beside its identity fields before
signing the request:

```swift
let verificationCode = String(format: "%06d", Int.random(in: 0..<1_000_000))
let requestTemplate = DeviceEnrollmentRequest(
    version: 1,
    vaultID: vaultID,
    deviceID: identity.deviceID,
    deviceName: identity.deviceName,
    publicKey: identity.publicKeyData.base64EncodedString(),
    requestedAt: Date(),
    verificationCode: verificationCode,
    signature: ""
)
let payload = try encoder.encode(requestTemplate)
guard let signature = SecKeyCreateSignature(
    identity.privateKey,
    Self.signingAlgorithm,
    payload as CFData,
    &error
) as Data? else {
    // Error handling omitted.
}
```

This is a sound proof-of-possession construction for the advertised key. We
can verify that one actor controls the private key corresponding to the
request's public key and that the signed fields were not altered afterward.
Before enrollment, however, the approving device has no trusted record saying
which public key belongs to the Mac the operator intends to add. A
self-signature cannot create that missing identity binding.

Two input paths deliver the request. Manual approval reads a request file
selected by the operator. Nearby approval uses MultipeerConnectivity and
selects the first discovered peer:

```swift
func browser(
    _ browser: MCNearbyServiceBrowser,
    foundPeer peerID: MCPeerID,
    withDiscoveryInfo info: [String : String]?
) {
    queue.sync {
        guard invitedPeerID == nil else { return }
        invitedPeerID = peerID
        browser.invitePeer(peerID, to: session, withContext: nil, timeout: 10)
    }
}
```

The connection requires encryption, but the browser accepts the presented
peer certificate without establishing an application-level identity:

```swift
func session(
    _ session: MCSession,
    didReceiveCertificate certificate: [Any]?,
    fromPeer peerID: MCPeerID,
    certificateHandler: @escaping (Bool) -> Void
) {
    certificateHandler(true)
}
```

That does not make Multipeer encryption ineffective. It means transport
security and peer authorization are separate questions. The human comparison
step must bind the encrypted session's requester key to the intended physical
device.

## Vulnerability Details

We can see the missing binding by following the verification code from request
validation to approval confirmation.

`decodeAndValidateEnrollmentRequest` first confirms that the request names the
current vault. It then verifies the signature using the public key carried
inside that same request and ensures `deviceID` is the hash of that key:

```swift
guard request.vaultID == metadata.vaultID else {
    throw AppError.invalidConfiguration(
        "Device enrollment request targets a different vault."
    )
}

let unsignedRequest = DeviceEnrollmentRequest(
    version: request.version,
    vaultID: request.vaultID,
    deviceID: request.deviceID,
    deviceName: request.deviceName,
    publicKey: request.publicKey,
    requestedAt: request.requestedAt,
    verificationCode: request.verificationCode,
    signature: ""
)
let unsignedData = try encoder.encode(unsignedRequest)
let publicKey = try makePublicKey(from: publicKeyData)
guard SecKeyVerifySignature(
    publicKey,
    Self.signingAlgorithm,
    unsignedData as CFData,
    signatureData as CFData,
    nil
) else {
    throw AppError.invalidConfiguration(
        "Device enrollment request signature verification failed."
    )
}
guard deviceID(for: publicKeyData) == request.deviceID else {
    throw AppError.invalidConfiguration(
        "Device enrollment request fingerprint does not match the advertised public key."
    )
}
```

These checks establish three useful facts: the vault identifier has the
expected value, the request is internally consistent, and the requester
possesses the private key for its advertised public key. They do not establish
that the public key is the one displayed by the intended joining Mac over an
independent channel.

The helper then stages the request and returns its code to the CLI:

```swift
pendingApproval = PendingDeviceApproval(request: request)
return DeviceApprovalInfo(
    deviceName: request.deviceName,
    deviceID: request.deviceID,
    verificationCode: request.verificationCode
)
```

At this point, the expected answer remains exactly the value supplied by the
untrusted pre-enrollment peer. There is no approver contribution, no
independently derived transcript digest, and no requirement that the operator
read a value from the joining device.

`Sources/KeyCore/KeyCLIApplication.swift` makes the problem visible in the
user interaction:

```swift
guard io.stdinIsTTY else {
    throw AppError.operationRefused(
        "Vault approval requires an interactive terminal so you can confirm the verification code."
    )
}

let enteredCode = try io.readLine(
    prompt: "Approve device '\(approvalInfo.deviceName)' " +
        "(\(approvalInfo.deviceID)) by typing code " +
        "\(approvalInfo.verificationCode): "
).trimmingCharacters(in: .whitespacesAndNewlines)
let confirmResponse = try transport.send(
    .confirmVaultApproval(verificationCode: enteredCode)
)
```

The TTY requirement and explicit typing step ensure that approval is
interactive. They do not add an authentication input because the prompt
reveals the value it expects.

When confirmation reaches `VaultKeyStore`, the implementation compares the
typed text with the staged request field. Equality permits the helper to load
the vault key and wrap it to `staged.request.publicKey`:

```swift
guard verificationCode == staged.request.verificationCode else {
    throw AppError.operationRefused(
        "Verification code did not match the pending device approval request."
    )
}

let keyData = try loadEnclaveVaultKey(
    vaultRootURL: vaultRootURL,
    reason: "Unlock key vault to approve device '\(staged.request.deviceName)'."
)
let wrapped = try wrapVaultKey(
    keyData,
    publicKeyData: Data(base64Encoded: staged.request.publicKey) ?? Data()
)
```

We therefore arrive at the authorization sink without introducing any trusted
evidence about the intended device. The code comparison is true whenever the
operator repeats the displayed request field, regardless of which internally
valid requester produced it.

## Exploitability Analysis

The bounded security scenario is device substitution during an enrollment
that the operator already intends to perform.

For nearby approval, the implementation chooses one discovered peer before
the human ceremony. If that selected peer is not the intended joining Mac, the
request can still pass every current cryptographic check because each device
can validly sign its own public key and fields. The prompt then refers to the
selected request's device name, fingerprint, and code.

For manual approval, the same condition arises if the request file presented
to the CLI is not the file produced by the intended joining device. The file
can remain perfectly well formed and correctly self-signed; file integrity
relative to its embedded key does not authenticate who supplied the file.

The scenario has meaningful constraints:

- the operator must initiate `key vault approve`;
- the request must target the correct vault identifier;
- the request signature and public-key fingerprint must be valid;
- approval must occur at an interactive terminal;
- local authentication must authorize use of the existing device's enclave
  key; and
- a user who independently compares the complete fingerprint with a trusted
  display on the intended Mac can detect substitution.

Those controls prevent silent or arbitrary enrollment. They do not repair the
normal UX because the shipped prompt does not require an independent
fingerprint comparison and instead emphasizes a request-provided six-digit
value.

Simply increasing the number of digits would not restore the invariant while
the requester remains free to supply the expected value. Likewise, request
signatures and encrypted transport solve integrity and possession problems,
not initial identity binding. The durable answer is to compare a value that
both devices derive independently from the exact enrollment transcript.

## Proof of Concept

No offensive PoC or live two-device trigger was created. The accompanying
`poc/README.md` specifies a harmless, in-memory regression model for the
authentication invariant.

The model uses two fixed test identities, A and B, with no Secure Enclave,
Multipeer session, vault files, or real secret. Both identities may produce
internally valid test requests. The central assertion is defensive:

```text
comparison(transcript for requester A)
    must not confirm
pending approval for requester B
```

The model should also change or invalidate its comparison value whenever the
vault identifier, requester key, approver identity, peer nonce, protocol
version, or expiration changes. This directly tests the intended binding
without teaching or exercising a live substitution procedure.

Because the current implementation copies `request.verificationCode` into both
the displayed value and the confirmation comparison, it cannot satisfy the
first assertion: the value is a property of whichever request was staged,
not an independently observed property of identity A.

The README lists deterministic Swift Testing cases for the fixed protocol. It
contains no executable code and requires no cleanup.

## Remediation

The fixed invariant should be:

> A vault-key wrapper is created only after both devices independently confirm
> the same fresh transcript, and that transcript names the exact vault,
> requester public key, and approving device.

For nearby enrollment, use a two-party transcript containing at least:

- protocol version;
- vault identifier;
- requester device identifier and public key;
- approver device identifier;
- fresh nonces contributed by both peers; and
- expiration time.

Both devices should sign or otherwise bind their contributions, canonically
encode the completed transcript, and derive a human-comparable authentication
string from its hash. Neither device should transmit that string as an
authoritative free-form request field. Each device displays its locally
derived value, and the operator confirms that the two displays match.

A defensive source shape could begin with:

```swift
private struct EnrollmentTranscript: Codable {
    let version: Int
    let vaultID: String
    let requesterDeviceID: String
    let requesterPublicKey: String
    let approverDeviceID: String
    let requesterNonce: Data
    let approverNonce: Data
    let expiresAt: Date
}

private func authenticationDigest(
    for transcript: EnrollmentTranscript
) throws -> SHA256.Digest {
    let canonicalTranscript = try encoder.encode(transcript)
    return SHA256.hash(data: canonicalTranscript)
}
```

The digest should be encoded with enough entropy for the product's threat
model, such as several human-readable words or a QR representation. The code
must be derived on both devices from the same canonical bytes. The approving
CLI should ask the operator to confirm a match with the joining device; it
should not print an expected value and ask the operator to repeat it.

Confirmation should also reference locally staged state rather than accept
the requester-provided code through `KeyServiceRequest`. For example:

```swift
case confirmVaultApproval(
    approvalID: UUID,
    comparisonConfirmed: Bool
)

guard comparisonConfirmed,
      pendingApproval.id == approvalID,
      pendingApproval.expiresAt > Date(),
      pendingApproval.transcriptDigest == recomputedDigest else {
    throw AppError.operationRefused(
        "Enrollment comparison was not confirmed or has expired."
    )
}
```

The actual implementation should avoid treating a Boolean alone as security
proof: `approvalID`, expiry, digest, requester key, and consumed state must all
be held and checked by the trusted helper. Confirmation must be one-shot, and
the wrapped-key recipient must be taken from that exact confirmed transcript.

Manual enrollment needs the same identity guarantee. If a two-way transcript
is unavailable, the CLI should require an independent comparison of the full
public-key fingerprint or a strong digest displayed on both devices. Possession
of the request file alone is not an independent comparison.

Regression coverage should include:

- substituting the requester key changes the authentication value;
- a comparison for requester A cannot approve requester B;
- both peer nonces, both identities, vault ID, protocol version, and expiry are
  bound to the digest;
- expired and consumed pending approvals are rejected;
- nearby transport cannot silently select a different peer after comparison;
- manual approval requires independent fingerprint or digest confirmation;
  and
- the vault key is wrapped only to the public key in the confirmed transcript.

## Summary

The enrollment request's self-signature correctly proves possession of its
advertised private key, and the vault-ID and fingerprint checks correctly
establish internal consistency. The missing control is external identity
binding: the approving device never obtains trustworthy evidence that the
request key belongs to the Mac the operator intended to add.

The current six-digit interaction does not supply that evidence because the
joining request chooses the code, the approving CLI displays it, and
confirmation compares against the same field. In the bounded substitution
scenario, a different but internally valid requester can therefore reach the
vault-key wrapping decision if the operator completes the normal prompt.

The remediation is protocol-level rather than cosmetic. We should bind the
vault, requester key, approver identity, fresh peer contributions, version,
and expiration into one canonical transcript; derive the comparison value
independently on both devices; and make pending approval one-shot and
transcript-specific. The supplied defensive test design captures those
invariants without contacting real devices or exercising a live trigger.
