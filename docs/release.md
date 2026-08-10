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
The bundled CLI now lives at `Key.app/Contents/MacOS/key`, the LaunchAgent helper app lives at `Key.app/Contents/Helpers/Key Agent.app`, and the LaunchAgent plist lives at `Key.app/Contents/Library/LaunchAgents/work.tvr.key.agent.plist`.

For a semver release flow, this repo also includes:

```bash
just release <tag>
just bump-version <tag>
just build-release <tag>
just publish-release <tag> <zip-path>
just update-homebrew-tap <tag> <download-url> <sha256>
just publish-homebrew-tap <tag>
```

Use tags and release names like `v0.1.0`, `v0.1.1`, or `v0.2.0-alpha.1`.
Stable tags build `Key.app` and `key`. Numbered `alpha`, `beta`, and `rc`
tags build the isolated `Key Preview.app` and `key-preview` product and publish
it as a GitHub prerelease automatically. The tag is the only release selector;
the operator does not choose the product separately.
The release tag includes the leading `v`; the app and CLI marketing version do not.
The planned version 3 prerelease checkpoints and their security boundaries are tracked in [v3-vault-implementation.md](v3-vault-implementation.md#alpha-release-checkpoints).

Following [Homebrew's alternative release channel convention](https://docs.brew.sh/Cask-Cookbook#casks-for-alternative-release-channels),
prereleases use separate, opt-in casks. Stable tags update `key`, while numbered
prereleases update `key@alpha`, `key@beta`, or `key@rc`. The stable cask installs
`Key.app` and `key`; prerelease casks install `Key Preview.app` and
`key-preview`. This keeps an ordinary `brew upgrade` from moving a stable
installation onto a prerelease while allowing Stable and Preview to coexist. A
tester opts into the current alpha with:

```bash
brew install --cask tvanreenen/tap/key@alpha
```

The prerelease casks are mutually exclusive because alpha, beta, and rc all
install the same Preview app and CLI. Switch prerelease channels by uninstalling
the currently installed prerelease cask first. Stable `key` does not conflict
with these casks because it installs a different app and CLI.

Alpha releases through `v0.2.0-alpha.6` used the Mainstream `Key.app` identity.
Before installing the first side-by-side Preview alpha, remove that older cask
installation and reinstall the channel:

```bash
brew uninstall --cask tvanreenen/tap/key@alpha
brew install --cask tvanreenen/tap/key@alpha
```

`release-target.sh` validates the tag and resolves the product variant, Homebrew cask, and exact artifact name as one decision. Stable tags resolve to `Key`; numbered prerelease tags resolve to `Key Preview`.
`bump-version.sh` validates that same release target, updates Xcode's `MARKETING_VERSION`, auto-increments `CURRENT_PROJECT_VERSION`, and commits the version bump on `main`. It deliberately leaves the commit untagged until a complete release artifact has passed validation.
`build-release.sh` builds, notarizes, staples, and zips the selected product. Before notarization, it requires valid Apple Developer ID signatures from team `9Q355KSV85`, the product's exact app, CLI, and helper signing identifiers, hardened runtime, and the exact Stable or Preview Keychain entitlement set. A Stable zip includes `Key.app` plus `completions/_key`; a prerelease zip contains the isolated `Key Preview.app`.
`publish-release.sh` revalidates the artifact, creates or resumes the annotated tag at the exact version commit, pushes `main` plus the tag, then uses `gh` to create or update a GitHub release, upload the zip asset, and print the final download URL plus sha256 needed for the tap cask. It uses the tag as the release title and GitHub's generated release notes, and rejects an artifact whose product identity does not match the tag.
`update-homebrew-tap.sh` fast-forwards a local tap checkout and updates the cask selected from the tag: `Casks/key.rb` for a stable release or the matching `Casks/key@<channel>.rb` for a Preview release. It writes product-specific app and CLI artifacts and rejects a download URL whose artifact name does not match the tag. It defaults to `~/Code/homebrew-tap` and can be overridden with `KEY_TAP_REPO`.
`publish-homebrew-tap.sh` derives the same channel from the tag, stages only that cask, commits it, and pushes it.
`release.sh` runs the full release flow end to end on `main`: version bump, signed/notarized build, GitHub release publish, Homebrew tap update, and Homebrew tap publish.
`CURRENT_PROJECT_VERSION` is treated as an internal Apple/Xcode build counter and auto-increments with each release bump. The semver or prerelease string remains the primary release identity.

The intended release flow is:

0. Start from a clean, up-to-date `main`:

   ```bash
   git checkout main
   git pull --ff-only
   git status --short
   ```

1. Fast path: `just release vX.Y.Z[-prerelease]`

Manual path, if you want to inspect each stage:

1. `just bump-version vX.Y.Z[-prerelease]`
2. `just build-release vX.Y.Z[-prerelease]`
3. Inspect the selected product and artifact printed by the builder.
4. `just publish-release vX.Y.Z[-prerelease] <zip-path>`
5. `just update-homebrew-tap vX.Y.Z[-prerelease] <download-url> <sha256>`
6. Inspect the cask path and product artifacts printed by `update-homebrew-tap.sh` (`Casks/key.rb` for Stable or `Casks/key@<channel>.rb` for Preview).
7. `just publish-homebrew-tap vX.Y.Z[-prerelease]`

This project currently publishes its cask through:

- [tvanreenen/homebrew-tap](https://github.com/tvanreenen/homebrew-tap)

One-time local setup:

```bash
git clone https://github.com/tvanreenen/homebrew-tap ~/Code/homebrew-tap
```

## Test zsh completion locally

Use an isolated shell so the completion path and `compinit` order are unambiguous:

```zsh
zsh -f
autoload -Uz compinit
fpath=(/Users/tim.vanreenen/Code/key/completions $fpath)
compinit -i
```

The `fpath` update must happen before `compinit`.
If you change the completion file and want to reload it in the same shell, rerun `compinit -i`.

To test dynamic entry completion against a fake vault:

```zsh
mkdir -p /tmp/keycomp/github /tmp/keycomp/personal
touch /tmp/keycomp/github/personal.secret
touch /tmp/keycomp/personal/gmail.secret
zstyle ':completion:*:*:key:*' vault-root /tmp/keycomp
```

Then verify:

```zsh
key <TAB><TAB>
key get <TAB><TAB>
key edit <TAB><TAB>
key copy <TAB><TAB>
```

Expected behavior:

- `key <TAB><TAB>` offers `get`, `copy`, `add`, `edit`, `duplicate`, `rename`, `remove`, `list`, `unlock`, `lock`, `version`, and `help`
- `key get <TAB><TAB>` offers `github/personal` and `personal/gmail`

## Verify signing inputs

```bash
just verify-signing "$HOME/Library/Developer/Xcode/Archives/<date>/<archive>.xcarchive/Products/Applications/Key.app"
```

Use `just verify-release ...` after notarization and stapling if you want the full Gatekeeper check as well.

## Notarize and staple

`just build-release <tag>` uses the `key-notary` `notarytool` keychain profile directly.
See [apple-setup.md](apple-setup.md) for the one-time `notarytool store-credentials` command and where to create the Apple app-specific password.
