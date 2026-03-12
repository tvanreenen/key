# Apple Setup

This project depends on a small amount of Apple Developer setup outside the repo.

The checked-in [Key.xcodeproj](../Key.xcodeproj) is the source of truth for the local build settings. This document is only the companion record of the Apple-side objects the project expects to exist.

## Developer objects

Keep these identifiers and profiles in the Apple Developer portal:

- Team ID: `9Q355KSV85`
- App ID: `work.tvr.key.app`
- App ID: `work.tvr.key.xpc`
- Shared keychain access group: `9Q355KSV85.work.tvr.key.shared`
- Developer ID provisioning profile: `Key Developer ID App`
- Developer ID provisioning profile: `Key Developer ID XPC`

The `KeyCore` target does not need its own App ID or provisioning profile. Any old `work.tvr.key.cli` identifier or profile from earlier experiments can be removed if it still exists.

## Xcode project mapping

The current project expects these values:

- [Key.xcodeproj](../Key.xcodeproj)
- app bundle ID: `work.tvr.key.app`
- XPC bundle ID: `work.tvr.key.xpc`
- vault key service: `work.tvr.key.secure-vault`
- vault key account: `default-vault`

The shared keychain group is recorded in:

- [KeyXPCService.entitlements](../Config/KeyXPCService.entitlements)
- [Key-Info.plist](../Config/Key-Info.plist)
- [KeyXPCService-Info.plist](../Config/KeyXPCService-Info.plist)

## Portal setup

Create and keep two explicit App IDs:

1. `work.tvr.key.app`
2. `work.tvr.key.xpc`

Both should use the same team and both should allow Keychain Sharing for:

- `9Q355KSV85.work.tvr.key.shared`

Then create the matching Developer ID provisioning profiles:

1. `Key Developer ID App`
2. `Key Developer ID XPC`

Download and install those profiles locally so Xcode can use them for Release archives.

## Xcode setup

In Xcode, the important targets are:

- `KeyApp`
- `KeyXPCService`

Expected Release signing values:

### `KeyApp`

- `Code Signing Identity`: `Developer ID Application`
- `Code Signing Style`: `Manual`
- `Provisioning Profile`: `Key Developer ID App`
- `Product Bundle Identifier`: `work.tvr.key.app`

### `KeyXPCService`

- `Code Signing Identity`: `Developer ID Application`
- `Code Signing Style`: `Manual`
- `Provisioning Profile`: `Key Developer ID XPC`
- `Product Bundle Identifier`: `work.tvr.key.xpc`
- `Keychain Sharing`: `work.tvr.key.shared`

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
just publish-release v0.1.0-alpha.1 "$HOME/Library/Developer/Xcode/Releases/key/v0.1.0-alpha.1/Key-v0.1.0-alpha.1.zip"
```

Supporting scripts:

- [verify-signing.sh](../scripts/verify-signing.sh)
- [Justfile](../Justfile)

## Sanity checks

Before debugging Keychain issues, verify the signed app and XPC service actually carry the expected entitlements:

```bash
just verify-signing "$HOME/Library/Developer/Xcode/Archives/<date>/<archive>.xcarchive/Products/Applications/Key.app"
```

The XPC service should show:

- `com.apple.application-identifier = 9Q355KSV85.work.tvr.key.xpc`
- `keychain-access-groups = [9Q355KSV85.work.tvr.key.shared]`

If the keychain access group is missing from the signed XPC service, the protected vault-key path will not work.
