# Release Notes

The checked-in [Key.xcodeproj](../Key.xcodeproj) is the project source of truth.

Apple-side identifiers, profiles, and notarization prerequisites are documented in:

- [apple-setup.md](apple-setup.md)

## Build the project

```bash
just build-debug
```

This builds the checked-in [Key.xcodeproj](../Key.xcodeproj) and leaves the app in Xcode's default DerivedData location under `~/Library/Developer/Xcode/DerivedData/...`.

For a signed archive that can exercise the entitled keychain path:

```bash
just build-release-archive
```

The release archive script archives the checked-in [Key.xcodeproj](../Key.xcodeproj) with the signing identities and provisioning profiles already recorded in the project and writes the archive under `~/Library/Developer/Xcode/Archives/<date>/`.
Debug builds remain automatic or unsigned for local iteration.
The bundled CLI now lives at `Key.app/Contents/MacOS/key`, and the privileged runtime lives in `Key.app/Contents/XPCServices/KeyXPCService.xpc`.

For a semver release flow, this repo also includes:

```bash
just build-release <version>
just update-homebrew-tap <version> <download-url> <sha256>
just publish-release <version> <zip-path>
```

Use tags and release names like `v0.1.0`, `v0.1.1`, or `v0.2.0-alpha.1`.
Versions with a prerelease suffix such as `-alpha.1`, `-beta.1`, or `-rc.1` will be published as GitHub prereleases automatically.

`build-release.sh` builds, notarizes, staples, and zips the app.
`update-homebrew-tap.sh` updates `Casks/key.rb` in a local tap checkout. It defaults to `~/Code/homebrew-tap` and can be overridden with `KEY_TAP_REPO`.
`publish-release.sh` uses `gh` to create or update a GitHub release, upload the zip asset, and then refresh the tap cask automatically. It uses the version as the release title and GitHub's generated release notes.

This project currently publishes its cask through:

- [tvanreenen/homebrew-tap](https://github.com/tvanreenen/homebrew-tap)

One-time local setup:

```bash
git clone https://github.com/tvanreenen/homebrew-tap ~/Code/homebrew-tap
```

## Verify signing inputs

```bash
just verify-signing "$HOME/Library/Developer/Xcode/Archives/<date>/<archive>.xcarchive/Products/Applications/Key.app"
```

Use `just verify-release ...` after notarization and stapling if you want the full Gatekeeper check as well.

## Notarize and staple

`just build-release <version>` uses the `key-notary` `notarytool` keychain profile directly.
See [apple-setup.md](apple-setup.md) for the one-time `notarytool store-credentials` command and where to create the Apple app-specific password.
