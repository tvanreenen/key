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
Versions with a prerelease suffix such as `-alpha.1`, `-beta.1`, or `-rc.1` will be published as GitHub prereleases automatically.
The release tag includes the leading `v`; the app and CLI marketing version do not.

`bump-version.sh` updates Xcode's `MARKETING_VERSION`, auto-increments `CURRENT_PROJECT_VERSION`, commits the version bump on `main`, and creates the local release tag.
`build-release.sh` builds, notarizes, staples, and zips the app. The final zip includes both `Key.app` and `completions/_key` for Homebrew-installed zsh completion.
`publish-release.sh` pushes `main` plus the release tag, then uses `gh` to create or update a GitHub release, upload the zip asset, and print the final download URL plus sha256 needed for the tap cask. It uses the tag as the release title and GitHub's generated release notes.
`update-homebrew-tap.sh` fast-forwards a local tap checkout and then updates `Casks/key.rb`. It defaults to `~/Code/homebrew-tap` and can be overridden with `KEY_TAP_REPO`.
`publish-homebrew-tap.sh` stages the generated cask, commits it, and pushes it.
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
3. `just publish-release vX.Y.Z[-prerelease] <zip-path>`
4. `just update-homebrew-tap vX.Y.Z[-prerelease] <download-url> <sha256>`
5. `git -C "$HOME/Code/homebrew-tap" diff -- Casks/key.rb`
6. `just publish-homebrew-tap vX.Y.Z[-prerelease]`

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
