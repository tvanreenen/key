# Show the available development and release commands.
default:
  @just --list --unsorted

# Run the Swift test suite.
test:
  swift test

# Build the app in Debug using the checked-in Xcode project.
build-debug:
  scripts/build-debug-app.sh

# Clear stale LaunchAgent/debug-install state so the next debug build starts clean.
reset-debug:
  scripts/reset-debug-helper-state.sh

# Create a signed Release archive in Xcode's archive location.
build-release-archive:
  scripts/build-release-archive.sh

# Inspect entitlements and signing state for a built app bundle.
verify-signing app_path:
  scripts/verify-signing.sh "{{app_path}}"

# Verify a notarized app bundle, including Gatekeeper assessment.
verify-release app_path:
  scripts/verify-release.sh "{{app_path}}"

# Notarize and staple an existing Xcode archive using the key-notary profile.
notarize archive_path:
  scripts/notarize-release.sh "{{archive_path}}"

# Build, notarize, staple, and zip a semver release artifact.
build-release version:
  scripts/build-release.sh "{{version}}"

# Fast-forward the Homebrew tap checkout, then write the updated cask.
update-homebrew-tap version download_url sha256:
  scripts/update-homebrew-tap.sh "{{version}}" "{{download_url}}" "{{sha256}}"

# Stage, commit, and push the generated Homebrew tap cask update.
publish-homebrew-tap version:
  scripts/publish-homebrew-tap.sh "{{version}}"

# Publish a GitHub release asset and print the data needed for the tap cask.
publish-release version zip_path:
  scripts/publish-release.sh "{{version}}" "{{zip_path}}"
