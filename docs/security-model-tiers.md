# Security Model Tiers

This document is not a literal product roadmap. It is a transparent description of the security and portability tiers that `key` has today, plus the ones it could plausibly grow into over time.

The goal is to make the tradeoffs explicit. "More sync" is not automatically "more secure," and "more secure" is not automatically "better UX." The current default is intentionally local-only. The later tiers describe ways to widen portability while changing the trust boundary in different ways.

The section order below follows a narrative progression:

1. current local-only model
2. iCloud-syncable keychain model
3. explicit import/export model
4. Secure Enclave multi-device model

That narrative order is not the same thing as the recommended order. The comparative recommendation appears near the end.

## Current State In Key

Today, `key` stores encrypted secret files on disk and protects them with a single randomly generated 256-bit vault key. The secret files themselves are regular JSON envelopes encrypted with AES-256-GCM, implemented in [VaultCipher.swift](../Sources/KeyCore/VaultCipher.swift). The vault key is not stored in the vault. It lives in Keychain, behind local authentication, and is retrieved through the helper process rather than by the CLI directly.

That split is not just process architecture. It is part of the security boundary. The user-facing CLI in [Sources/key/main.swift](../Sources/key/main.swift) talks to a short-lived LaunchAgent helper over XPC. The helper loads the vault key from Keychain, decrypts or encrypts as needed, and keeps the unlocked vault key only in memory for a short idle window. The relevant pieces today are [VaultKeyStore.swift](../Sources/KeyCore/VaultKeyStore.swift), [SessionVaultKeyStore.swift](../Sources/KeyCore/SessionVaultKeyStore.swift), and [Sources/KeyLaunchAgentHelper/main.swift](../Sources/KeyLaunchAgentHelper/main.swift).

The current vault key item is deliberately device-local. It is created with [`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`](https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly?language=objc), which Apple documents as non-migrating to another device. The helper also uses the macOS data protection keychain via [`kSecUseDataProtectionKeychain`](https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain?changes=__8&language=objc), and the access control requirement is local authentication through [`SecAccessControlCreateFlags.userPresence`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence).

That combination gives the current model a specific shape:

- sync the `.secret` files anywhere you want
- keep the vault key local to one Mac unless you deliberately move it
- require macOS local authentication before the helper can read the vault key
- cache the unlocked vault key in memory for convenience, but only briefly

This is why copying only the encrypted secret files to another Mac does not work. AES-GCM authenticates the ciphertext against the exact key and nonce used to encrypt it. If a second Mac has different vault-key material in Keychain, decryption fails as an authentication failure rather than "partially decrypting" into garbage. In practice that is why a mismatched-key scenario surfaces as a generic CryptoKit AES-GCM error rather than a friendly "wrong vault key" message.

This is also why "local-only by default" should be viewed as a deliberate property, not as a missing sync feature. The project currently chooses a narrow trust boundary: one vault key, one Mac, local authentication, short-lived in-memory reuse.

## Tier 1: Current Local-Only Model

### What The Model Is

The current model stores one symmetric vault key in the local Mac's Keychain and uses that key to encrypt and decrypt all vault entries. Secret files may be copied freely, but the vault key is expected to remain on the original machine unless the user explicitly moves it by some external means.

### What The Trust Boundary Becomes

The trust boundary is narrow and concrete: this Mac, this login session, this helper, this Keychain item. A private Git repository, cloud backup, or synced filesystem can hold the encrypted `.secret` files without also granting decrypt capability, because the decrypt capability lives in the local Keychain item rather than in the synced data.

### What The End-To-End UX Feels Like

The user installs `Key.app`, opens it once so the helper can register, and then works mostly through the CLI. On first unlock, macOS asks for Touch ID, Apple Watch approval, or the user's system password. The helper warms a short session. Repeated CLI calls reuse that session. Another Mac that clones the secret files does not automatically gain access, which is occasionally surprising but consistent with the model.

### What Improves Relative To A Simpler Design

Compared with a design where the CLI stores or loads the vault key directly, this model makes better use of the macOS security model. The helper can carry the signing context, shared keychain access-group behavior, LaunchAgent lifecycle, and local-auth prompts in one place. The user gets CLI ergonomics without turning the CLI itself into the long-lived holder of protected key material.

### What Gets Worse Or More Dangerous

The sharpest cost is portability. A technical user can sync the encrypted vault files and still be unable to decrypt anything on a second Mac. Operationally, the model also depends on the helper registration and signing story remaining correct, because the helper is not an incidental component. It is the component that actually owns access to the vault key.

### What Key Would Need To Change

Nothing for this tier itself. The work here is mostly documentation and error handling:

- keep the current local-only default
- make cross-device mismatch errors more explicit
- explain more clearly that file sync does not imply key sync

### Who This Tier Is For

This is the best fit for users who want the smallest, clearest trust boundary and are comfortable with the vault being effectively bound to one Mac unless they perform an explicit recovery or transfer step.

## Tier 2: iCloud-Syncable Keychain Model

### What The Model Is

This model keeps the same basic "one symmetric vault key encrypts the vault" design, but stores that vault key as a synchronizable keychain item so the same logical item follows the user across devices in their iCloud Keychain trust domain.

The important distinction is that this behavior would come from [`kSecAttrSynchronizable`](https://developer.apple.com/documentation/security/ksecattrsynchronizable), not merely from using the data protection keychain. Apple is explicit that [`kSecUseDataProtectionKeychain`](https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain?changes=__8&language=objc) gives macOS keychain items iOS-like behavior without synchronization, while `kSecAttrSynchronizable = true` additionally causes iCloud synchronization.

### What The Trust Boundary Becomes

The trust boundary moves from "this Mac" to "devices that participate in this user's iCloud Keychain domain." That is a meaningful change. The user is no longer explicitly authorizing each new Mac through `key`; they are implicitly trusting the Apple-account-level device set that can receive synchronizable keychain items.

### What The End-To-End UX Feels Like

The UX is the simplest of all multi-device options. A user can install `key` on another Mac, sync the `.secret` files, and likely find that the vault key simply appears once the machine is in the same iCloud Keychain universe. From a convenience perspective, this is excellent. From a trust-model perspective, it is much less explicit than the local-only tier.

### What Improves Relative To The Current Tier

This is the least complicated portability story. There is no custom key export flow, no additional wrapped vault-key metadata, no device-enrollment protocol, and no user-managed recovery bundle. If the goal is "make multiple personal Macs work with minimal product surface area," this is the shortest path.

### What Gets Worse Or More Dangerous

The security story changes materially:

- the vault key is no longer intentionally device-bound
- portability becomes implicit rather than explicit
- the trust boundary expands to the user's iCloud Keychain device set
- the product can no longer honestly say that the vault key is local to one machine by default if this becomes the default behavior

This does not make the model inherently weak. It does make it categorically different. The user is choosing convenience and Apple-account-level sync over the current narrow "this device only" stance.

### What Key Would Need To Change

A lightweight implementation would likely require:

- a configuration mode that switches vault-key storage from `ThisDeviceOnly` to a synchronizable accessibility class such as [`kSecAttrAccessibleWhenUnlocked`](https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlocked)
- updated create/read/update/delete queries in [VaultKeyStore.swift](../Sources/KeyCore/VaultKeyStore.swift) to include synchronizable behavior
- clear UI and CLI messaging that this mode widens the trust boundary
- migration logic for moving an existing local-only vault key into a synchronizable item only when the user explicitly opts in

### Who This Tier Is For

This is a fit for users who mostly want their own Macs to "just work" and are comfortable treating their Apple account and iCloud Keychain domain as the place where cross-device trust is anchored.

## Tier 3: Explicit Import/Export Model

### What The Model Is

This model keeps ordinary operation local-only, but adds an explicit way to move the vault key between Macs as a wrapped artifact. The vault key would still live locally in Keychain during day-to-day use. Portability happens only when the user intentionally exports a wrapped bundle and imports it elsewhere.

The wrapping mechanism matters. The most plausible first version is a strong passphrase-wrapped or recovery-code-wrapped export bundle. The key point is that the exported artifact should never be the raw vault key in plaintext. It should be a transport package that is only useful with the separate secret the user chooses or records.

### What The Trust Boundary Becomes

The normal trust boundary remains local-only until export happens. At export time, the user deliberately creates a portable representation of the master vault key. That is a wider trust boundary than the current tier, but it is still explicit and user-mediated rather than ambient.

### What The End-To-End UX Feels Like

A technical user could keep encrypted `.secret` files in a private Git repository, then separately move a wrapped vault-key bundle to a second Mac through an out-of-band channel. On the destination Mac, `key` would import the bundle, unwrap the vault key after local auth plus the wrapping secret, and then store the recovered vault key back into that Mac's local-only Keychain item.

This feels less magical than iCloud sync, but much easier to reason about. It also gives the user a recovery artifact if implemented carefully.

### What Improves Relative To The iCloud Tier

Compared with iCloud sync, this model preserves explicit control. Nothing moves unless the user asks it to move. That makes the portability event legible:

- the user knows when the vault key left the first machine
- the user knows what artifact now exists
- the user can store that artifact according to their own operational model
- the default local-only story remains intact for users who never export

### What Gets Worse Or More Dangerous

This is still a step down from the strongest device-bound models because the master vault key becomes exportable. Once the vault key has been unwrapped on another device, that device now has the same core decrypt capability as the original one. The safety of the transport process also depends heavily on the wrapping design and the user's handling of the export bundle and recovery secret.

In other words, this is a pragmatic model, not a magic one. It improves portability and recovery while giving up the strongest possible claim that the master secret never leaves device-local protection.

### What Key Would Need To Change

A practical implementation would likely add:

- explicit `export` and `import` commands or an equivalent app flow
- a format for wrapped vault-key bundles with versioning and metadata
- passphrase or recovery-code based wrapping and unwrapping
- clear warnings that export creates a portable capability, not just a backup file
- optional recovery-oriented features such as verifying a bundle before the user needs it

The current Keychain storage path in [VaultKeyStore.swift](../Sources/KeyCore/VaultKeyStore.swift) could remain the steady-state storage model after import. The new work would mostly sit around controlled extraction, wrapping, transfer, and re-ingestion.

### Who This Tier Is For

This is the pragmatic fit for reasonably technical users who want local-only by default, want predictable recovery and transfer, and are comfortable handling a wrapped export artifact with care.

## Tier 4: Secure Enclave Multi-Device Model

### What The Model Is

This is the strongest multi-device direction within the native Apple security model. The vault still uses one shared symmetric vault key for actual secret encryption. What changes is how each device gains access to that key.

Instead of copying the vault key between devices, each authorized Mac would generate its own device-bound keypair in the Secure Enclave. Apple documents this flow in [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave) and notes that Secure Enclave keys are created on-device, are limited to specific key types, and cannot import preexisting private keys through [`kSecAttrTokenIDSecureEnclave`](https://developer.apple.com/documentation/security/ksecattrtokenidsecureenclave?language=objc).

The shared vault key would then be wrapped separately to each device's public key. Shared storage could hold those per-device wrapped blobs without ever containing the raw vault key.

### What The Trust Boundary Becomes

The trust boundary becomes "devices explicitly enrolled into this vault," not "devices on this Apple ID" and not "any device that ever received a copied master key." That is the strongest portability story because each device gets its own unwrap capability without receiving an exportable private key.

### What The End-To-End UX Feels Like

The user experience would feel more like device authorization than file transfer:

- first Mac initializes the vault and becomes the first authorized device
- second Mac generates a local Secure Enclave-backed device identity
- an already-authorized device approves that new device
- the shared vault key is wrapped to the new device's public key
- the new Mac can now unwrap its own copy locally after local authentication

Day to day, the UX can still resemble the current helper-session model. The helper would unwrap the vault key on demand, cache it briefly in memory, and then drop it on idle timeout. The big change is in enrollment and recovery, not in ordinary `key get` usage.

### What Improves Relative To The Import/Export Tier

This model avoids the most uncomfortable part of explicit export/import: making the master vault key itself transportable. The shared vault key still exists, but its cross-device movement happens as device-specific wrapped copies rather than as a single portable recovery bundle that can be imported anywhere with the wrapping secret.

This also improves revocation shape. In principle, a device can be removed by deleting its wrapped copy and rotating the vault key for the remaining devices. That is more structured than reasoning about which machines may have imported a passphrase-wrapped export at some point in the past.

### What Gets Worse Or More Dangerous

The price is complexity:

- device enrollment becomes a protocol, not a file transfer
- metadata for authorized devices and per-device wrapped copies must exist somewhere
- recovery becomes a first-class problem
- losing every authorized device could strand the vault unless a separate recovery path exists

This is also the tier where implementation mistakes become much more expensive. The cryptographic primitives are standard, but the product behavior around authorization, revocation, metadata integrity, and recovery becomes more subtle.

### What Key Would Need To Change

A realistic implementation would likely require:

- a per-vault metadata format for device identities and per-device wrapped vault-key blobs
- Secure Enclave-backed key generation using [`kSecAttrTokenIDSecureEnclave`](https://developer.apple.com/documentation/security/ksecattrtokenidsecureenclave?language=objc)
- device-authorization flows that exchange or publish device public keys
- asymmetric wrapping or key-agreement operations using `SecKey`, such as the APIs documented in [Using Keys for Encryption](https://developer.apple.com/documentation/security/using-keys-for-encryption) and related key-exchange APIs in [Keys](https://developer.apple.com/documentation/security/keys)
- a separate disaster-recovery story, because "all devices lost" must not silently mean "all data lost forever" unless the product says so very clearly

### Who This Tier Is For

This is the fit for users who want the strongest Apple-native multi-device posture and are willing to accept a more opinionated authorization and recovery model in exchange for tighter device-bound control.

## Comparative Synthesis

These tiers are not a simple ladder where each later one is unambiguously better. They optimize different things.

### Ranking By Security Posture And Trust-Boundary Tightness

If the ranking is based on how tightly the decrypt capability can be scoped and reasoned about, the order is:

1. current local-only model
2. Secure Enclave multi-device model
3. explicit import/export model
4. iCloud-syncable keychain model

The current local-only model stays first because the trust boundary is the smallest and most concrete. Secure Enclave multi-device comes next because it preserves explicit device authorization and device-bound private material even while enabling multi-device use. Explicit import/export is a pragmatic middle ground, but it makes the master vault key portable. iCloud sync is the broadest trust boundary of the four because it delegates portability to the user's iCloud Keychain device set.

### Ranking By User Convenience

If the ranking is based on day-to-day convenience for a user with multiple Macs, the order is almost reversed:

1. iCloud-syncable keychain model
2. Secure Enclave multi-device model
3. explicit import/export model
4. current local-only model

iCloud sync is the easiest because it minimizes product surface area and user action. Secure Enclave pairing could become very smooth after initial enrollment, but it still requires explicit device authorization and recovery planning. Import/export is straightforward but manual. Local-only remains the clearest model, but the least portable one.

### Default Recommendation If All Four Ever Existed

If `key` ever offered all four models, the default should remain the current local-only tier. It is the cleanest statement of the project's security posture and the easiest one to defend without a long list of caveats.

The most pragmatic next tier to add would be explicit wrapped import/export. It preserves the local-only default, introduces portability only when the user asks for it, and creates a tractable recovery story. iCloud sync is viable, but it should be treated as a convenience mode with a deliberately wider trust boundary. Secure Enclave multi-device authorization is the most compelling long-term multi-device design, but it is also the most operationally complex and the easiest to get subtly wrong.

Configurability itself adds risk. The moment a product offers multiple security tiers, it also creates more room for misunderstanding, migration mistakes, inconsistent team expectations, and "I thought I was on the stricter mode" failures. If multiple tiers ever exist, the mode must be explicit, inspectable, and hard to misunderstand.

## Recommended Positioning

The strongest public stance for `key` is still:

- local-only remains the default and most defensible baseline
- explicit wrapped import/export is the pragmatic next step
- iCloud sync is a real convenience tier, but it widens the trust boundary
- Secure Enclave device authorization is the strongest Apple-native multi-device design, but it comes with the highest implementation and recovery complexity

That framing keeps the current model honest, gives portability-conscious users a realistic path forward, and makes it clear that future multi-device support is not a single switch but a set of distinct security choices.
