# Offline Recovery Models

Status: design record for recovery after every enrolled device is lost. The
`0.2.0` release does not implement catastrophe recovery; it relies on explicit
multi-device continuity and states that loss of every enrolled device means
permanent loss. This document preserves the later recovery candidates and the
tradeoffs that must be resolved before a recovery schema becomes permanent.

## Scope

Continuity and catastrophe recovery are separate product capabilities.

### Device continuity

At least one enrolled device survives. That Mac can authorize a replacement,
rotate the vault key, and revoke the lost device without exporting its Secure
Enclave private keys. This is the supported `0.2.0` continuity model.

Key recommends at least two enrolled devices. Provider storage alone is
not a recoverable backup because it contains ciphertext but none of the
device-bound authority needed to open it.

### Catastrophe recovery

Offline recovery begins only after the final enrolled device is unavailable.
The user has:

- the encrypted, authenticated vault obtained from its storage or sync
  provider;
- a new Mac with no trusted checkpoint or enrolled Secure Enclave identity;
  and
- whatever recovery material they deliberately stored beforehand.

The recovery design must not assume a Key service, Apple-account escrow,
provider honesty, or access to any previous device.

`0.2.0` deliberately implements no such authority. If every enrolled device is
lost, the vault is permanently inaccessible. This is safer than weakening the
device-bound model with a recovery mechanism that has not been settled and
physically qualified.

The [PIV feasibility procedure](piv-feasibility-procedure.md) defines the next
hardware experiment, its setup choices, and separate approval gates. It does
not change this released promise or authorize real-vault enrollment.

## The Unavoidable Tradeoff

Secure Enclave private keys are non-exportable and available only on the
device that created them. Once every enrolled device is gone, those keys and
their biometric access path are gone too. Recovery therefore needs independent
authority that exists outside the enrolled devices.

That authority must not be a human-chosen password. An attacker who obtains
the provider-backed vault can test password guesses offline without a server
to throttle or stop them. A password-based KDF can make each guess more
expensive, but it cannot turn a typical password into the equivalent of a
random device key.

An acceptable offline design therefore uses cryptographically random recovery
material. Its remaining question is how many independent artifacts or devices
must be kept, and what happens when one is stolen, destroyed, or unavailable.

## Options

The options below are ordered by their present fit for Key, not by theoretical
cryptographic strength alone.

### 1. Primary and backup PIV recovery keys

**What the user keeps**

The user registers two separately stored physical smart cards. Each generates
its own non-exportable P-256 recovery key through PIV. Either token can recover
the vault; neither token contains an exportable clone of the other.

**Recovery experience**

1. Install Key on a new Mac and select the existing provider-backed vault.
2. Insert either registered recovery key.
3. Enter its activation PIN and physically touch the token.
4. Authenticate locally while Key creates a new enrolled Secure Enclave
   identity.
5. Key recovers the current vault key, revokes the lost roster, rotates the
   vault key, and asks the user to restore two-key recovery redundancy.

**Why this is stronger than a password**

- The recovery private keys remain non-exportable hardware keys.
- The PIN activates a physical token; it is not a vault decryption password
  that can be guessed against copied provider bytes.
- Losing or damaging one token does not make recovery impossible.
- No online account, recovery service, or trusted storage provider is needed.

**Cost and failure mode**

Users must buy, register, test, and safely retain compatible hardware. Key
would own PIV provisioning, protocol compatibility, slot-safety, PIN and touch
behavior, and replacement semantics. An attacker with the vault, a registered
token, and its PIN has recovery authority.

This is the leading later candidate because its primary-plus-backup UX is
recognizable and its authority remains hardware-bound. It must first pass a
physical feasibility prototype on both Macs. The vault format should describe
a generic compatible PIV P-256 recipient rather than depend on one vendor.

FIDO, CTAP, and U2F credentials are not substitutes for this operation: they
authenticate possession to a relying party but do not expose the general P-256
ECDH operation needed to recover an offline vault. A multi-protocol token may
support both uses, but Key would use its PIV application.

### 2. Two-of-three recovery shares

**What the user keeps**

Key creates three independently storable, random recovery shares. Any two can
reconstruct recovery authority; one cannot. Each share can be represented as
checksummed words, a QR code, or a small file.

**Recovery experience**

1. Install Key on a new Mac and select the existing provider-backed vault.
2. Scan, enter, or import any two recovery shares.
3. Authenticate locally while Key creates a new enrolled Secure Enclave
   identity.
4. Key recovers the current vault key, revokes the lost roster, rotates the
   vault key, and creates a replacement recovery kit.

**Why this is stronger than a password**

- Every share is generated with cryptographic randomness rather than chosen
  or memorized.
- One stolen share does not authorize recovery or enable offline guessing.
- One lost or destroyed share does not make recovery impossible.
- No online account, recovery service, or trusted storage provider is needed.

**Cost and failure mode**

The user must keep the shares in separate places. Storing all three together
quietly reduces the practical protection to that of one bearer document.
Anyone who obtains the vault and any two shares can take control. The model
has good loss and theft properties but asks the user to become a careful
backup operator.

### 3. Two-part recovery kit

**What the user keeps**

One random recovery file and one separately stored random printed code. Both
are required.

**Recovery experience**

1. Select the provider-backed vault.
2. Attach or import the recovery file.
3. Enter or scan the printed code.
4. Create the replacement enrolled Secure Enclave identity.

**Why this is stronger than a password**

Both components are random and neither is useful alone. There is no
human-selected secret to guess.

**Cost and failure mode**

This is effectively a fixed two-of-two scheme. Losing either component makes
recovery impossible, and storing both together defeats the separation. It is
simpler to implement than threshold shares but provides no loss tolerance.

### 4. One random recovery key

**What the user keeps**

One high-entropy recovery key represented as checksummed words, printable
characters, and/or a QR code.

**Recovery experience**

1. Select the provider-backed vault.
2. Scan or enter the recovery key.
3. Create the replacement enrolled Secure Enclave identity.

**Why this is stronger than a password**

The value is generated with enough entropy to resist offline guessing. It is a
recovery key that must be recorded, not a password expected to be remembered.

**Cost and failure mode**

It is a bearer credential. Anyone who copies it and obtains the vault can
recover the vault; losing every copy means permanent loss. This is the
simplest defensible model, but it has the single-artifact weakness that
prompted this review.

### 5. Trusted-person recovery

**What the user keeps**

The user keeps one recovery share and gives another to a trusted person. This
is a distribution choice for a threshold kit, not necessarily a separate
cryptographic format.

**Recovery experience**

Recovery requires the user's material plus the trusted person's material.
Neither person can recover alone.

**Cost and failure mode**

Recovery now depends on a relationship, availability, and cooperation. The
trusted person should hold only an opaque share rather than receive ordinary
vault access. Two cooperating share holders can still recover the vault.

### 6. Online, rate-limited recovery PIN

**What the user keeps**

A memorable PIN or passphrase. A Key-operated service retains complementary
recovery material and enforces a strict guess limit.

**Why this can protect a weak secret**

An online service can prevent unlimited offline guessing, monitor attempts,
and require additional account checks.

**Cost and failure mode**

Key would become an identity, availability, and recovery-service provider.
The design would require durable online infrastructure, abuse controls,
account recovery, notification, and service trust. This conflicts with the
current provider-neutral architecture.

### 7. Password or passphrase alone

This option should be rejected.

The provider-backed vault gives an attacker everything needed to test guesses
offline. Key stretching changes the cost of each guess but does not impose an
attempt limit. A passphrase made sufficiently random to resist that attack is
no longer meaningfully a password; it is a recovery key that the user must
store.

## Selected `0.2.0` Posture

`0.2.0` selects the following deliberately small model:

1. Recommend at least two enrolled devices.
2. Use any surviving device to enroll a replacement and revoke a lost device.
3. State plainly that provider storage alone is not a recoverable backup.
4. If every enrolled device is unavailable, report permanent loss without
   offering a password, cloud escrow, destructive repair, or hidden fallback.

One enrolled device is allowed, but Key must describe it as an at-risk
configuration. Revoking from two devices down to one requires a prominent
permanent-loss warning. Migration cleanup must likewise explain that deleting
the retained source removes any fallback outside the new device-bound vault.

## Later Recovery Track

Offline catastrophe recovery is deferred to a later minor release and is not
a stable `0.2.0` compatibility promise. Before selecting a permanent format,
the recovery track must:

- physically prototype two independent PIV P-256 recovery keys on supported
  Macs, including safe empty-slot selection, on-token generation, ECDH, PIN,
  required touch, removal, restart, and blocked-token behavior;
- determine whether macOS exposes the required operation cleanly through
  Security and CryptoTokenKit without external operator tooling;
- specify independently wrapped recovery recipients rather than copying one
  private key across two tokens;
- retain threshold shares as the leading hardware-free alternative; and
- define how recovery communicates the existing freshness limitation when no
  trusted device checkpoint survives.

## Security Boundary To State Plainly

No offline recovery design can recreate the lost Secure Enclave keys or prove
that an untrusted provider has revealed the latest state it ever received.
Recovery can authenticate and decrypt the newest complete state currently
available to the new Mac. It cannot prove that the provider is not withholding
a later authentic state.

For any selected model, possession of the vault plus sufficient recovery
material is equivalent to control. Successful recovery must replace that
material rather than treating it as a reusable ordinary unlock credential.

## References

- Apple, [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- Apple, [CryptoTokenKit](https://developer.apple.com/documentation/cryptotokenkit)
- FIDO Alliance, [Displace password and OTP authentication with passkeys](https://fidoalliance.org/white-paper-displace-password-otp-authentication-with-passkeys/)
- NIST, [SP 800-63B account recovery requirements](https://pages.nist.gov/800-63-4/sp800-63b.html#account-recovery)
- Signal, [Technology preview for secure value recovery](https://signal.org/blog/secure-value-recovery/)
- KeePass, [Master key components](https://keepass.info/help/base/keys.html)
- Apple Platform Security, [Account recovery contact security](https://support.apple.com/guide/security/account-recovery-contact-security-secafa525057/web)
- Trezor, [What is Shamir backup?](https://trezor.io/learn/advanced/standards-proposals/what-is-shamir-backup)
- Yubico, [PIV P-256 key agreement](https://docs.yubico.com/yesdk/users-manual/application-piv/key-agreement.html)
- Yubico, [PIV PIN and touch policies](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html)
