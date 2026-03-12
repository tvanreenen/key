# Show the available development and release commands.
default:
  @just --list --unsorted

# Run the Swift test suite.
test:
  swift test

# Build the app in Debug using the checked-in Xcode project.
build-debug:
  scripts/build-debug-app.sh

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

# Update the Homebrew tap cask with a release version, asset URL, and sha256.
update-homebrew-tap version download_url sha256:
  scripts/update-homebrew-tap.sh "{{version}}" "{{download_url}}" "{{sha256}}"

# Publish a GitHub release asset and refresh the Homebrew tap automatically.
publish-release version zip_path:
  scripts/publish-release.sh "{{version}}" "{{zip_path}}"
