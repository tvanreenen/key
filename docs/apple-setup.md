# Apple Setup

This project depends on a small amount of Apple Developer setup outside the repo.

The checked-in [Key.xcodeproj](../Key.xcodeproj) is the source of truth for the local build settings. This document is only the companion record of the Apple-side objects the project expects to exist.

## Developer objects

Keep these identifiers and profiles in the Apple Developer portal:

| Product | Type | Identifier | Developer ID profile |
| --- | --- | --- | --- |
| Key app | App ID | `work.tvr.key.app` | `Key App Developer ID` |
| Key helper | App ID | `work.tvr.key.xpc` | `Key XPC Developer ID` |
| Key Preview app | App ID | `work.tvr.key.preview.app` | `Key Preview App Developer ID` |
| Key Preview helper | App ID | `work.tvr.key.preview.xpc` | `Key Preview XPC Developer ID` |

All four are explicit macOS App IDs under team `9Q355KSV85`. The Stable helper
uses keychain group `9Q355KSV85.work.tvr.key.shared`; the Preview helper uses
`9Q355KSV85.work.tvr.key.preview.shared`.

The CLI, `KeyCore`, and `JSONCanonicalization` targets do not need App IDs or
provisioning profiles. Any old CLI identifier or profile from earlier
experiments can be removed if it still exists.

## Xcode project mapping

The checked-in project maps the Stable product to `work.tvr.key.app`,
`work.tvr.key.xpc`, `work.tvr.key.agent`, and
`9Q355KSV85.work.tvr.key.shared`. It maps Preview to the corresponding
`work.tvr.key.preview.*` identifiers and
`9Q355KSV85.work.tvr.key.preview.shared`.

The claimed keychain groups are recorded in:

- [KeyLaunchAgentHelper.entitlements](../Config/KeyLaunchAgentHelper.entitlements)
- [KeyPreviewLaunchAgentHelper.entitlements](../Config/KeyPreviewLaunchAgentHelper.entitlements)

## Portal setup

Create and keep these explicit App IDs:

1. `work.tvr.key.app`
2. `work.tvr.key.xpc`
3. `work.tvr.key.preview.app`
4. `work.tvr.key.preview.xpc`

Then create the matching Developer ID provisioning profiles:

1. `Key App Developer ID`
2. `Key XPC Developer ID`
3. `Key Preview App Developer ID`
4. `Key Preview XPC Developer ID`

Download and install those profiles locally so Xcode can use them for Release archives.

The current portal does not present a separate Keychain Sharing capability for
this Developer ID setup. The helper claims its exact group through the checked-in
entitlements file, while the generated profile authorizes the team's keychain
namespace. Confirm the downloaded helper profiles contain
`keychain-access-groups = [9Q355KSV85.*]` before relying on them. See Apple's
[keychain access group entitlement documentation](https://developer.apple.com/documentation/BundleResources/Entitlements/keychain-access-groups)
and [TN3125](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles).

## Xcode setup

In Xcode, the important targets are:

- `KeyApp`
- `KeyLaunchAgentHelper`

Expected manual Developer ID signing values:

### `KeyApp`

- `Code Signing Identity`: `Developer ID Application`
- `Code Signing Style`: `Manual`
- `Provisioning Profile`: `Key App Developer ID`
- `Product Bundle Identifier`: `work.tvr.key.app`

### `KeyLaunchAgentHelper`

- `Code Signing Identity`: `Developer ID Application`
- `Code Signing Style`: `Manual`
- `Provisioning Profile`: `Key XPC Developer ID`
- `Product Bundle Identifier`: `work.tvr.key.xpc`
- helper keychain group: `9Q355KSV85.work.tvr.key.shared`

The `PreviewRelease` configuration uses the same two targets with these values:

- app profile: `Key Preview App Developer ID`
- app bundle ID: `work.tvr.key.preview.app`
- helper profile: `Key Preview XPC Developer ID`
- helper bundle ID: `work.tvr.key.preview.xpc`
- helper keychain group: `9Q355KSV85.work.tvr.key.preview.shared`

For local development, Debug builds can remain automatic and use `Apple Development`.

## Notarization setup

Releases use `notarytool`, not the old `altool` workflow.

Create a local keychain credential profile once:

```bash
xcrun notarytool store-credentials "key-notary" \
  --apple-id "you@example.com" \
  --team-id "9Q355KSV85" \
  --password "APP_SPECIFIC_PASSWORD"
```

The `APP_SPECIFIC_PASSWORD` is an Apple app-specific password from your Apple account:

- go to [account.apple.com](https://account.apple.com)
- open `Sign-In and Security`
- open `App-Specific Passwords`
- generate one for notarization, for example `key-notary`

The release script uses that profile here:

- [build-release.sh](../scripts/build-release.sh)

## Release flow

Once signing and notarization are configured locally:

```bash
just build-release v0.1.0-alpha.1
just publish-release v0.1.0-alpha.1 "$HOME/Library/Developer/Xcode/Releases/key/v0.1.0-alpha.1/Key-Preview-v0.1.0-alpha.1.zip"
```

The tag selects the signing profile and product identity. Stable tags build
`Key.app`; numbered alpha, beta, and rc tags build `Key Preview.app`.

Supporting scripts:

- [verify-signing.sh](../scripts/verify-signing.sh)
- [verify-release.sh](../scripts/verify-release.sh)
- [Justfile](../Justfile)

## Sanity checks

Before debugging Keychain issues, verify the signed app and helper actually carry the expected entitlements:

```bash
just verify-signing "$HOME/Library/Developer/Xcode/Archives/<date>/<archive>.xcarchive/Products/Applications/Key.app"
```

After notarization and stapling, run:

```bash
just verify-release "$HOME/Library/Developer/Xcode/Archives/<date>/<archive>.xcarchive/Products/Applications/Key.app"
```

Signing verification fails unless the Stable helper executable has:

- signing identifier `work.tvr.key.xpc`
- the sole entitlement `keychain-access-groups = [9Q355KSV85.work.tvr.key.shared]`

If the keychain access group is missing from the signed helper executable, the protected vault-key path will not work.

The Preview helper must instead have:

- signing identifier `work.tvr.key.preview.xpc`
- the sole entitlement `keychain-access-groups = [9Q355KSV85.work.tvr.key.preview.shared]`

`verify-signing.sh` also requires Apple Developer ID Application signatures from
team `9Q355KSV85`, each product's exact app, CLI, and helper signing identifier,
hardened runtime, the app's team-bound application identifier, and no CLI
entitlements. Any unexpected entitlement fails the release before notarization.
