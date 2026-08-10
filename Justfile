# Show the available development and release commands.
default:
  @just --list --unsorted

# Run the Swift and release-script test suites.
test:
  swift test
  Tests/ReleaseScripts/homebrew-cask-token-tests.sh
  Tests/PreviewScripts/preview-install-tests.sh

# Verify stable and prerelease Homebrew channel selection.
test-release-scripts:
  Tests/ReleaseScripts/homebrew-cask-token-tests.sh

# Build the app in Debug using the checked-in Xcode project.
build-debug:
  scripts/build-debug-app.sh

# Build and install the isolated Preview app plus its key-preview CLI link.
install-preview:
  scripts/build-preview-app.sh

# Remove only the Preview app and CLI link while preserving Preview vault state.
uninstall-preview:
  scripts/uninstall-preview-app.sh

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

# Update the Xcode version fields and commit the release version on main.
bump-version tag:
  scripts/bump-version.sh "{{tag}}"

# Build, notarize, staple, and zip the product selected by the release tag.
build-release tag:
  scripts/build-release.sh "{{tag}}"

# Run the full release flow: bump version, build, publish GitHub release, and update/publish the Homebrew tap.
release tag:
  scripts/release.sh "{{tag}}"

# Fast-forward the Homebrew tap checkout, then write the tag's stable or prerelease cask.
update-homebrew-tap tag download_url sha256:
  scripts/update-homebrew-tap.sh "{{tag}}" "{{download_url}}" "{{sha256}}"

# Stage, commit, and push the generated Homebrew tap cask update.
publish-homebrew-tap tag:
  scripts/publish-homebrew-tap.sh "{{tag}}"

# Publish a GitHub release asset and print the data needed for the tap cask.
publish-release tag zip_path:
  scripts/publish-release.sh "{{tag}}" "{{zip_path}}"
