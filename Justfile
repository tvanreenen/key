# Show the available development and release commands.
default:
  @just --list --unsorted

# Run the Swift and release-script test suites.
test:
  swift test --no-parallel --force-resolved-versions
  Tests/ReleaseScripts/release-tests.sh
  Tests/PreviewScripts/preview-install-tests.sh

# Install the exact checksum-pinned CLI used by CI (see .github/ci-tools.json).
install-verify-tool tool:
  python3 scripts/ci-tool.py install "{{tool}}"

# Compile package tests with warnings as errors and run them without suite oversubscription.
verify-tests:
  mkdir -p .build/verification
  swift package resolve --force-resolved-versions
  swift build --build-tests --force-resolved-versions -Xswiftc -warnings-as-errors
  rm -f .build/verification/swift-tests*.xml
  swift test --skip-build --no-parallel --force-resolved-versions --xunit-output .build/verification/swift-tests.xml
  python3 scripts/verify-test-results.py .build/verification/swift-tests.xml

# Build both unsigned configurations, verify product identities, and exercise bundled CLIs.
verify-products variant="stable":
  scripts/verify-product.sh "{{variant}}" debug build
  scripts/verify-product.sh "{{variant}}" debug bundle
  scripts/verify-product.sh "{{variant}}" debug cli
  scripts/verify-product.sh "{{variant}}" release build
  scripts/verify-product.sh "{{variant}}" release bundle
  scripts/verify-product.sh "{{variant}}" release cli

# Verify one product configuration, matching the Stable Release PR gate.
verify-product variant="stable" mode="release":
  scripts/verify-product.sh "{{variant}}" "{{mode}}" build
  scripts/verify-product.sh "{{variant}}" "{{mode}}" bundle
  scripts/verify-product.sh "{{variant}}" "{{mode}}" cli

# Run the repository checks grouped together in PR CI.
verify-repository: verify-style verify-static-analysis verify-scripts verify-dependencies

# Verify script syntax, CI failure boundaries, release behavior, and Preview installation safety.
verify-scripts:
  scripts/verify-shell-syntax.sh
  python3 -m unittest discover -s Tests/CIScripts -p '*_tests.py'
  Tests/ReleaseScripts/release-tests.sh
  Tests/PreviewScripts/preview-install-tests.sh

# Check repository Swift formatting without rewriting files.
verify-style:
  python3 scripts/ci-tool.py run swiftformat . --lint --cache ignore
  git diff --check

# Apply the same conservative SwiftFormat rules used by CI.
format:
  python3 scripts/ci-tool.py run swiftformat . --cache ignore

# Check workflow syntax and security; GH_TOKEN enables online Action advisory checks.
verify-workflows:
  python3 scripts/ci-tool.py run actionlint
  python3 scripts/ci-tool.py run zizmor --strict-collection .github/workflows

# Scan all reachable history by default, or an explicit base..head range.
verify-secrets revision_range="--all":
  scripts/verify-secrets.sh "{{revision_range}}"

# Compare parsed dependency declarations and both committed resolution files.
verify-dependencies:
  python3 scripts/verify-dependencies.py

# Run correctness-focused SwiftLint; full CodeQL product extraction runs in CI.
verify-static-analysis:
  python3 scripts/ci-tool.py run swiftlint lint --strict --no-cache

# Verify release targeting, publication, and Homebrew dispatch behavior.
test-release-scripts:
  Tests/ReleaseScripts/release-tests.sh

# Build and verify real CLI help at narrow, standard, and wide terminal widths.
test-cli-help:
  swift build --product key
  zsh Tests/CLIScripts/help-tests.sh .build/debug/key

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

# Commit the release version on a PR branch or final stack layer before verification.
bump-version tag:
  scripts/bump-version.sh "{{tag}}"

# Build, notarize, staple, zip, and verify the product selected by the release tag.
build-release tag:
  scripts/build-release.sh "{{tag}}"

# Build and publish the already-merged version; Homebrew remains a manual checkpoint.
release tag:
  scripts/release.sh "{{tag}}"

# Dispatch the tap-owned Homebrew pull request after source release publication.
publish-homebrew tag:
  scripts/publish-homebrew.sh "{{tag}}"

# Verify published main and the ZIP, publish its tag, and upload the exact release assets.
publish-release tag zip_path:
  scripts/publish-release.sh "{{tag}}" "{{zip_path}}"
