# PIV feasibility setup and safety procedure

Status: proposed procedure, 2026-09-05. One-token inspection is complete; setup and cryptographic testing have not begun. This document does not authorize hardware changes. Key `0.2.0` has no catastrophe recovery.

## Purpose and evidence

The experiment asks the YubiKey to generate a P-256 private key internally, then checks hardware key agreement with a software test peer. Only generated test data will depend on it. No real vault will be opened, copied, modified, or registered by the probe. Creation is a persistent storage change, not a firmware update. "Disposable" does not mean the key disappears automatically. Product recovery enrollment will be separate from this experiment.

Read-only inspection on 2026-09-05 found:

- User-reported model: YubiKey 5C NFC, connected over USB.
- macOS recognizes a Yubico OTP+FIDO+CCID reader and its built-in PIV driver.
- PIV firmware reports `5.8.0`.
- Slots `9a`, `9c`, `9d`, `9e`, and `82` through `95` returned `6a88` for metadata: no key in these 24 user slots. Certificates and other applications were not inventoried. This does not establish device authenticity.
- PIN and PUK each reported three configured and three remaining attempts, with default-value flags set. The management key reported a default value and AES-192 algorithm.

The probe used macOS PC/SC with only SELECT, GET VERSION, and GET METADATA. No PIN verification or administrative authentication was sent. Host-level inspection corrected an empty sandbox inventory. Detection does not qualify Security/CryptoTokenKit key agreement or the shipped helper's permissions. [Yubico documents the metadata commands and firmware extensions](https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html). Reinspect before writes; this record is not permanent permission to use a slot. Keep serial numbers and personal identifiers out of committed logs.

## What the credentials mean

The PIV PIN authorizes credential use. Its counter is shared across PIV slots, so a disposable slot does not isolate PIN mistakes. Three remaining attempts is the full wrong-entry allowance, not three successful uses left. A correct PIN restores the allowance. The PUK unblocks the PIN and has its own counter. If both are blocked, PIV reset erases PIV keys. On this model, that reset does not erase FIDO or OTP applications. Changing retry limits also resets PIN/PUK values. Neither reset nor retry-limit changes are part of this procedure. See [Yubico's credential reference](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-puk-mgmt-key.html).

The management key authorizes administrative changes. For this probe, propose a separately retained random management key. Optional PIN-protected storage reduces typing but gives PIN possession management access through compatible software. Leave that option off initially to keep the authentication boundaries explicit. This is a project choice, not a universal requirement.

## Gate A: owner-controlled setup

Review and approve these choices before changing credentials. The owner uses Yubico Authenticator's Certificates screen, following [Yubico's setup instructions](https://docs.yubico.com/software/yubikey/tools/authenticator/auth-guide/piv-certificates.html), to replace the default PIN, PUK, and management key. Generate the management key randomly in the app and retain a secure copy. Leave retry limits and other YubiKey applications unchanged.

Project handling requirements:

1. Arrange storage for these credentials that survives loss of all enrolled Macs. Their only copy must not be inside Key's vault. Keep activation information separate from the token where practical.
2. Enter secrets locally, never in chat, screenshots, repository files, command arguments, environment variables, shell history, or logs.
3. Change one credential at a time. Record completion, not its value. An interruption may leave setup partly complete; do not retry the whole sequence assuming every credential is still the default.
4. Stop at the first unexpected authentication error. Resolve it before another attempt. Never guess or automatically fall back to defaults.
5. Read back non-default flags and intact counters. Metadata alone does not prove that the saved credential copies are correct.

Setup persists even if we abandon PIV recovery. Deleting a later test key does not restore the old PIN, PUK, or management key.

## Gate B: one test credential

Prepare and review the probe before requesting approval. Its write path must name the token, freshly checked empty slot, algorithm, and policies. Proposed slot: `9d`, subject to fresh inspection and owner agreement. An existing key or certificate, ambiguous token match, or unsupported inspection response stops provisioning. Leave other slots and attestation material alone.

Generate on-device with PIN `Always` and touch `Always`. These policies are chosen at creation; changing them requires replacing the key. [Yubico's policy reference](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html) defines their behavior. Read back policies, generation origin, and public key; record a public-key fingerprint identifying this exact test credential.

If native macOS integration needs a certificate or other PIV object, explain that extra persistent write before approval. Do not silently add certificates, pair the token for Mac login, or install middleware. Prefer maintained Yubico tooling for provisioning; custom administrative APDUs require justification and review. Tool versions and the secret-entry path must be settled first.

No automatic deletion, overwrite, reset, PIN change, retry-limit change, or default-credential fallback belongs in the probe. After uncertain creation, inspect the slot; do not generate another key over an uncertain result.

## Feasibility checks

Record macOS and tool versions, token firmware, slot, policies, and API path. Do not log PINs, management credentials, shared secrets, or vault keys.

| Check | Required observation |
|---|---|
| Native integration | Determine whether Security/CryptoTokenKit supports the operation in the intended process and signing context. Reader detection alone is insufficient. |
| Key agreement | Hardware and software peer derive matching P-256 ECDH output without exporting the token's private key. |
| Access control | Withheld PIN or withheld touch prevents completion; correct owner-entered PIN and touch permit it. No deliberate incorrect PIN/PUK entries. |
| Lifecycle | Cancellation, bounded timeout, unplug/replug, and process restart produce clear outcomes without accidentally authorizing a later operation. |
| Uncertain completion | Lost responses cause inspection or safe read-operation retries, never key replacement or guessed authentication. |

Use simulated responses for blocked-counter and wrong-PIN handling. Physical destructive cases need a separately designated sacrificial token and approval; simulation is not physical qualification.

Compare high-level macOS integration with direct smart-card access before choosing production ownership. Prefer the high-level path if it satisfies policy, cancellation, and deployment requirements. Direct access adds protocol and authentication responsibilities. Neither is selected by the inspection.

One token is enough to begin. Full qualification requires both supported Macs and a second independently generated recovery credential; either token must work alone. No purchase or real-vault enrollment is part of this procedure.

## Gate C: keep or delete the test credential

Present the fingerprint and slot, confirm no real data depends on it, and obtain a cleanup decision. With verified per-slot deletion support, delete only that test key and any separately approved test certificate. Inspect afterward. Never substitute PIV reset for targeted cleanup. If identity or tool support is uncertain, leave the credential in place and report it. Deletion makes the test private key unrecoverable; the slot remains reusable. The changed PIN, PUK, and management key remain in effect.

## Separate approval for product recovery

No probe result changes the released continuity promise. Real-vault enrollment requires format and security review, authority replacement and lost-token procedures, documented provider-history limitations, and a two-token rehearsal. The [recovery alternatives](offline-recovery-models.md) retain two-of-three random shares if PIV is unreliable or too burdensome to operate.
