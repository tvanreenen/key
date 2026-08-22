# Show the available development and release commands.
default:
  @just --list --unsorted

# Run the Swift and release-script test suites.
test:
  swift test
  Tests/ReleaseScripts/release-tests.sh
  Tests/PreviewScripts/preview-install-tests.sh

# Verify release targeting, publication, and Homebrew dispatch behavior.
test-release-scripts:
  Tests/ReleaseScripts/release-tests.sh

# Run the opt-in 300-entry in-process migration scale gate.
test-migration-scale:
  scripts/test-migration-qualification.sh

# Build, install, and run the isolated installed migration qualification.
test-migration-installed:
  scripts/run-migration-qualification.sh

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

# Build, notarize, staple, zip, and verify the product selected by the release tag.
build-release tag:
  scripts/build-release.sh "{{tag}}"

# Bump, build, and publish the source release; Homebrew remains a manual checkpoint.
release tag:
  scripts/release.sh "{{tag}}"

# Dispatch the tap-owned Homebrew pull request after source release publication.
publish-homebrew tag:
  scripts/publish-homebrew.sh "{{tag}}"

# Verify the ZIP, atomically publish main plus its tag, and upload the exact release assets.
publish-release tag zip_path:
  scripts/publish-release.sh "{{tag}}" "{{zip_path}}"
