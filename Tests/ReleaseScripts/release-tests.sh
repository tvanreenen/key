#!/bin/zsh
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
target_resolver="${repo_root}/scripts/release-target.sh"
token_resolver="${repo_root}/scripts/homebrew-cask-token.sh"

assert_target() {
  local tag="$1"
  local expected_variant="$2"
  local expected_token="$3"
  local expected_artifact="$4"
  local variant
  local token
  local artifact
  IFS=$'\t' read -r variant token artifact <<< "$("${target_resolver}" "${tag}")"

  if [[ "${variant}" != "${expected_variant}" || \
        "${token}" != "${expected_token}" || \
        "${artifact}" != "${expected_artifact}" ]]; then
    echo "unexpected release target for ${tag}: ${variant}, ${token}, ${artifact}" >&2
    exit 1
  fi

  if [[ "$("${token_resolver}" "${tag}")" != "${expected_token}" ]]; then
    echo "Homebrew token wrapper disagrees with the release target for ${tag}" >&2
    exit 1
  fi
}

assert_rejected() {
  local tag="$1"

  if "${target_resolver}" "${tag}" >/dev/null 2>&1; then
    echo "expected ${tag} to be rejected" >&2
    exit 1
  fi
}

assert_target "v0.1.1" "stable" "key" "Key-v0.1.1.zip"
assert_target "v0.2.0-alpha.2" "preview" "key@alpha" "Key-Preview-v0.2.0-alpha.2.zip"
assert_target "v0.2.0-beta.1" "preview" "key@beta" "Key-Preview-v0.2.0-beta.1.zip"
assert_target "v0.2.0-rc.1" "preview" "key@rc" "Key-Preview-v0.2.0-rc.1.zip"

assert_rejected "0.2.0-alpha.2"
assert_rejected "v0.2.0-preview.1"
assert_rejected "v0.2.0-alpha"
assert_rejected "v01.2.3"
assert_rejected "v1.02.3"
assert_rejected "v1.2.03"
assert_rejected "v1.2.3-alpha.01"
assert_rejected "v1.2.3+build.1"

if "${repo_root}/scripts/bump-version.sh" "v0.2.0-preview.1" >/dev/null 2>&1; then
  echo "expected version bumping to reject an unsupported release tag" >&2
  exit 1
fi

if "${repo_root}/scripts/build-release.sh" \
  "preview" \
  "v0.2.0-alpha.2" \
  >/dev/null 2>&1; then
  echo "expected release building to reject an independent product selector" >&2
  exit 1
fi

test_root="$(mktemp -d)"
trap 'rm -rf -- "${test_root}"' EXIT

create_test_product_bundle() {
  local variant="$1"
  local app_path="$2"
  local marketing_version="$3"
  local build_version="${4:-11}"
  local app_id
  local app_executable
  local cli_name
  local helper_name
  local helper_id
  local agent_label
  local agent_status_label

  case "${variant}" in
    stable)
      app_id="work.tvr.key.app"
      app_executable="KeyHost"
      cli_name="key"
      helper_name="Key Agent"
      helper_id="work.tvr.key.xpc"
      agent_label="work.tvr.key.agent"
      agent_status_label="work.tvr.key.agent.status"
      ;;
    preview)
      app_id="work.tvr.key.preview.app"
      app_executable="KeyPreviewHost"
      cli_name="key-preview"
      helper_name="Key Preview Agent"
      helper_id="work.tvr.key.preview.xpc"
      agent_label="work.tvr.key.preview.agent"
      agent_status_label="work.tvr.key.preview.agent.status"
      ;;
  esac

  local helper_path="${app_path}/Contents/Helpers/${helper_name}.app"
  local agent_path="${app_path}/Contents/Library/LaunchAgents/${agent_label}.plist"
  mkdir -p \
    "${app_path}/Contents/MacOS" \
    "${helper_path}/Contents/MacOS" \
    "${agent_path:h}"

  cat > "${app_path}/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>${app_id}</string>
  <key>CFBundleExecutable</key><string>${app_executable}</string>
  <key>CFBundleShortVersionString</key><string>${marketing_version}</string>
  <key>CFBundleVersion</key><string>${build_version}</string>
  <key>KeyProductVariant</key><string>${variant}</string>
</dict></plist>
EOF
  cat > "${helper_path}/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>${helper_id}</string>
  <key>CFBundleExecutable</key><string>${helper_name}</string>
  <key>CFBundleShortVersionString</key><string>${marketing_version}</string>
  <key>CFBundleVersion</key><string>${build_version}</string>
  <key>KeyProductVariant</key><string>${variant}</string>
</dict></plist>
EOF
  cat > "${agent_path}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${agent_label}</string>
  <key>BundleProgram</key><string>Contents/Helpers/${helper_name}.app/Contents/MacOS/${helper_name}</string>
  <key>SpawnConstraint</key><dict>
    <key>signing-identifier</key><string>${helper_id}</string>
  </dict>
  <key>MachServices</key><dict>
    <key>${agent_label}</key><true/>
    <key>${agent_status_label}</key><true/>
  </dict>
</dict></plist>
EOF

  touch \
    "${app_path}/Contents/MacOS/${app_executable}" \
    "${app_path}/Contents/MacOS/${cli_name}" \
    "${helper_path}/Contents/MacOS/${helper_name}"
  chmod +x \
    "${app_path}/Contents/MacOS/${app_executable}" \
    "${app_path}/Contents/MacOS/${cli_name}" \
    "${helper_path}/Contents/MacOS/${helper_name}"
}

artifact_fixture_root="${test_root}/release-artifacts"
stable_package="${artifact_fixture_root}/stable"
preview_package="${artifact_fixture_root}/preview"
mkdir -p "${stable_package}/completions" "${preview_package}"
create_test_product_bundle "stable" "${stable_package}/Key.app" "0.2.0"
create_test_product_bundle \
  "preview" \
  "${preview_package}/Key Preview.app" \
  "0.2.0-alpha.2"
touch "${stable_package}/completions/_key"

artifact_verifier_root="${test_root}/artifact-verifier"
artifact_verifier_scripts="${artifact_verifier_root}/scripts"
artifact_verifier_project="${artifact_verifier_root}/Key.xcodeproj/project.pbxproj"
signing_verification_log="${artifact_verifier_root}/signing-verifications"
gatekeeper_verification_log="${artifact_verifier_root}/gatekeeper-verifications"
artifact_verifier_bin="${artifact_verifier_root}/bin"
mkdir -p \
  "${artifact_verifier_scripts}" \
  "${artifact_verifier_project:h}" \
  "${artifact_verifier_bin}"
cp \
  "${repo_root}/scripts/project-version.sh" \
  "${repo_root}/scripts/release-target.sh" \
  "${repo_root}/scripts/verify-product-bundle.sh" \
  "${repo_root}/scripts/verify-release-artifact.sh" \
  "${artifact_verifier_scripts}/"
cat > "${artifact_verifier_scripts}/verify-signing.sh" <<'EOF'
#!/bin/zsh
set -euo pipefail

if [[ $# -ne 2 || ! -d "$1" ]]; then
  exit 1
fi

case "$2" in
  stable|preview) ;;
  *) exit 1 ;;
esac

if [[ -n "${SIGNING_VERIFICATION_LOG:-}" ]]; then
  echo "$2" >> "${SIGNING_VERIFICATION_LOG}"
fi
EOF
chmod +x "${artifact_verifier_scripts}/verify-signing.sh"
cat > "${artifact_verifier_bin}/xcrun" <<'EOF'
#!/bin/zsh
set -euo pipefail

if [[ "$#" -ne 3 || "$1" != "stapler" || "$2" != "validate" || ! -d "$3" ]]; then
  exit 64
fi
if [[ "${ARTIFACT_GATEKEEPER_FAILURE:-}" == "stapler" ]]; then
  exit 1
fi
if [[ -n "${ARTIFACT_GATEKEEPER_LOG:-}" ]]; then
  echo "stapler" >> "${ARTIFACT_GATEKEEPER_LOG}"
fi
EOF
cat > "${artifact_verifier_bin}/spctl" <<'EOF'
#!/bin/zsh
set -euo pipefail

if [[ "$#" -ne 5 || "$1" != "--assess" || "$2" != "--type" || \
      "$3" != "execute" || "$4" != "--verbose" || ! -d "$5" ]]; then
  exit 64
fi
if [[ "${ARTIFACT_GATEKEEPER_FAILURE:-}" == "spctl" ]]; then
  exit 1
fi
if [[ -n "${ARTIFACT_GATEKEEPER_LOG:-}" ]]; then
  echo "spctl" >> "${ARTIFACT_GATEKEEPER_LOG}"
fi
EOF
chmod +x "${artifact_verifier_bin}/xcrun" "${artifact_verifier_bin}/spctl"
artifact_verifier="${artifact_verifier_scripts}/verify-release-artifact.sh"

set_artifact_project_version() {
  local marketing_version="$1"
  local build_version="$2"
  cat > "${artifact_verifier_project}" <<EOF
MARKETING_VERSION = ${marketing_version};
CURRENT_PROJECT_VERSION = ${build_version};
EOF
}

stable_artifact="${artifact_fixture_root}/Key-v0.2.0.zip"
preview_artifact="${artifact_fixture_root}/Key-Preview-v0.2.0-alpha.2.zip"
(
  cd "${stable_package}"
  /usr/bin/zip -qry "${stable_artifact}" "Key.app" "completions"
)
(
  cd "${preview_package}"
  /usr/bin/zip -qry "${preview_artifact}" "Key Preview.app"
)

set_artifact_project_version "0.2.0" "11"
PATH="${artifact_verifier_bin}:${PATH}" \
ARTIFACT_GATEKEEPER_LOG="${gatekeeper_verification_log}" \
SIGNING_VERIFICATION_LOG="${signing_verification_log}" \
  "${artifact_verifier}" \
  "v0.2.0" \
  "${stable_artifact}" \
  >/dev/null
set_artifact_project_version "0.2.0-alpha.2" "11"
PATH="${artifact_verifier_bin}:${PATH}" \
ARTIFACT_GATEKEEPER_LOG="${gatekeeper_verification_log}" \
SIGNING_VERIFICATION_LOG="${signing_verification_log}" \
  "${artifact_verifier}" \
  "v0.2.0-alpha.2" \
  "${preview_artifact}" \
  >/dev/null

grep -q '^stable$' "${signing_verification_log}"
grep -q '^preview$' "${signing_verification_log}"
[[ "$(grep -c '^stapler$' "${gatekeeper_verification_log}")" -eq 2 ]]
[[ "$(grep -c '^spctl$' "${gatekeeper_verification_log}")" -eq 2 ]]

set_artifact_project_version "0.2.0" "11"
if PATH="${artifact_verifier_bin}:${PATH}" \
  ARTIFACT_GATEKEEPER_FAILURE="stapler" \
  "${artifact_verifier}" "v0.2.0" "${stable_artifact}" \
  >/dev/null 2>&1; then
  echo "expected artifact verification to reject a missing staple" >&2
  exit 1
fi
if PATH="${artifact_verifier_bin}:${PATH}" \
  ARTIFACT_GATEKEEPER_FAILURE="spctl" \
  "${artifact_verifier}" "v0.2.0" "${stable_artifact}" \
  >/dev/null 2>&1; then
  echo "expected artifact verification to reject a failed Gatekeeper assessment" >&2
  exit 1
fi

renamed_stable_artifact="${artifact_fixture_root}/Key-Preview-v0.2.0-alpha.3.zip"
cp "${stable_artifact}" "${renamed_stable_artifact}"
set_artifact_project_version "0.2.0-alpha.3" "11"
if "${artifact_verifier}" \
  "v0.2.0-alpha.3" \
  "${renamed_stable_artifact}" \
  >/dev/null 2>&1; then
  echo "expected Preview verification to reject renamed Stable contents" >&2
  exit 1
fi

renamed_preview_artifact="${artifact_fixture_root}/Key-v0.2.1.zip"
cp "${preview_artifact}" "${renamed_preview_artifact}"
set_artifact_project_version "0.2.1" "11"
if "${artifact_verifier}" \
  "v0.2.1" \
  "${renamed_preview_artifact}" \
  >/dev/null 2>&1; then
  echo "expected Stable verification to reject renamed Preview contents" >&2
  exit 1
fi

wrong_version_package="${artifact_fixture_root}/wrong-version/package"
wrong_version_artifact="${artifact_fixture_root}/wrong-version/Key-v0.2.0.zip"
set_artifact_project_version "0.2.0" "11"
mkdir -p "${wrong_version_package}/completions"
create_test_product_bundle \
  "stable" \
  "${wrong_version_package}/Key.app" \
  "0.2.1"
touch "${wrong_version_package}/completions/_key"
(
  cd "${wrong_version_package}"
  /usr/bin/zip -qry "${wrong_version_artifact}" "Key.app" "completions"
)
if "${artifact_verifier}" \
  "v0.2.0" \
  "${wrong_version_artifact}" \
  >/dev/null 2>&1; then
  echo "expected artifact verification to reject the wrong embedded version" >&2
  exit 1
fi

wrong_build_package="${artifact_fixture_root}/wrong-build/package"
wrong_build_artifact="${artifact_fixture_root}/wrong-build/Key-v0.2.0.zip"
set_artifact_project_version "0.2.0" "11"
mkdir -p "${wrong_build_package}/completions"
create_test_product_bundle \
  "stable" \
  "${wrong_build_package}/Key.app" \
  "0.2.0" \
  "12"
touch "${wrong_build_package}/completions/_key"
(
  cd "${wrong_build_package}"
  /usr/bin/zip -qry "${wrong_build_artifact}" "Key.app" "completions"
)
if "${artifact_verifier}" \
  "v0.2.0" \
  "${wrong_build_artifact}" \
  >/dev/null 2>&1; then
  echo "expected artifact verification to reject the wrong embedded build" >&2
  exit 1
fi

wrong_alpha_asset="${test_root}/Key-v0.2.0-alpha.2.zip"
touch "${wrong_alpha_asset}"
if "${repo_root}/scripts/publish-release.sh" \
  "v0.2.0-alpha.2" \
  "${wrong_alpha_asset}" \
  >/dev/null 2>&1; then
  echo "expected alpha publishing to reject a Stable artifact" >&2
  exit 1
fi

wrong_stable_asset="${test_root}/Key-Preview-v0.2.0.zip"
touch "${wrong_stable_asset}"
if "${repo_root}/scripts/publish-release.sh" \
  "v0.2.0" \
  "${wrong_stable_asset}" \
  >/dev/null 2>&1; then
  echo "expected stable publishing to reject a Preview artifact" >&2
  exit 1
fi

publication_origin="${test_root}/publication-origin.git"
publication_repo="${test_root}/publication-repo"
publication_fake_bin="${test_root}/publication-bin"
publication_tag="v0.2.0"
publication_artifact_root="${artifact_fixture_root}/publication"
publication_artifact="${publication_artifact_root}/Key-${publication_tag}.zip"

git init --bare --initial-branch=main "${publication_origin}" >/dev/null
git init --initial-branch=main "${publication_repo}" >/dev/null
git -C "${publication_repo}" config user.name "Release Script Tests"
git -C "${publication_repo}" config user.email "release-tests@example.invalid"
mkdir -p "${publication_repo}/scripts" "${publication_fake_bin}"
cp "${artifact_verifier_bin}/xcrun" "${artifact_verifier_bin}/spctl" \
  "${publication_fake_bin}/"
cp \
  "${repo_root}/scripts/publish-release.sh" \
  "${artifact_verifier_scripts}/project-version.sh" \
  "${artifact_verifier_scripts}/release-target.sh" \
  "${artifact_verifier_scripts}/verify-product-bundle.sh" \
  "${artifact_verifier_scripts}/verify-release-artifact.sh" \
  "${artifact_verifier_scripts}/verify-signing.sh" \
  "${publication_repo}/scripts/"
mkdir -p "${publication_repo}/Key.xcodeproj"
set_artifact_project_version "0.2.0" "11"
cp "${artifact_verifier_project}" "${publication_repo}/Key.xcodeproj/project.pbxproj"
touch "${publication_repo}/release-marker"
git -C "${publication_repo}" add Key.xcodeproj scripts release-marker
git -C "${publication_repo}" commit -m "Initial publication state" >/dev/null
git -C "${publication_repo}" remote add origin "${publication_origin}"
git -C "${publication_repo}" push --set-upstream origin main >/dev/null 2>&1

publication_initial_commit="$(git -C "${publication_repo}" rev-parse HEAD)"
git -C "${publication_repo}" tag -a "${publication_tag}" -m "Existing remote tag"
git -C "${publication_repo}" push origin "${publication_tag}" >/dev/null 2>&1
git -C "${publication_repo}" tag --delete "${publication_tag}" >/dev/null

echo "release" > "${publication_repo}/release-marker"
git -C "${publication_repo}" add release-marker
git -C "${publication_repo}" commit -m "Prepare release" >/dev/null
mkdir -p "${publication_artifact_root}"
cp "${stable_artifact}" "${publication_artifact}"
ln -s /usr/bin/true "${publication_fake_bin}/gh"

if (
  cd "${publication_repo}"
  PATH="${publication_fake_bin}:${PATH}" \
    ./scripts/publish-release.sh "${publication_tag}" "${publication_artifact}" \
    >/dev/null 2>&1
); then
  echo "expected publication to reject a conflicting remote tag" >&2
  exit 1
fi

if git -C "${publication_repo}" rev-parse --verify --quiet "refs/tags/${publication_tag}" \
  >/dev/null; then
  echo "failed atomic publication left its newly-created local tag behind" >&2
  exit 1
fi

if [[ "$(git --git-dir="${publication_origin}" rev-parse refs/heads/main)" != \
      "${publication_initial_commit}" ]]; then
  echo "failed atomic publication partially advanced remote main" >&2
  exit 1
fi

successful_origin="${test_root}/successful-origin.git"
successful_repo="${test_root}/successful-repo"
successful_fake_bin="${test_root}/successful-bin"
successful_gh_state="${test_root}/successful-gh-state"
successful_gh_log="${test_root}/successful-gh.log"
successful_artifact_root="${artifact_fixture_root}/successful-publication"
successful_artifact="${successful_artifact_root}/Key-${publication_tag}.zip"

git init --bare --initial-branch=main "${successful_origin}" >/dev/null
git init --initial-branch=main "${successful_repo}" >/dev/null
git -C "${successful_repo}" config user.name "Release Script Tests"
git -C "${successful_repo}" config user.email "release-tests@example.invalid"
mkdir -p \
  "${successful_repo}/scripts" \
  "${successful_repo}/Key.xcodeproj" \
  "${successful_fake_bin}" \
  "${successful_gh_state}/assets" \
  "${successful_artifact_root}"
cp "${artifact_verifier_bin}/xcrun" "${artifact_verifier_bin}/spctl" \
  "${successful_fake_bin}/"
cp \
  "${repo_root}/scripts/publish-release.sh" \
  "${artifact_verifier_scripts}/project-version.sh" \
  "${artifact_verifier_scripts}/release-target.sh" \
  "${artifact_verifier_scripts}/verify-product-bundle.sh" \
  "${artifact_verifier_scripts}/verify-release-artifact.sh" \
  "${artifact_verifier_scripts}/verify-signing.sh" \
  "${successful_repo}/scripts/"
set_artifact_project_version "0.2.0" "11"
cp "${artifact_verifier_project}" "${successful_repo}/Key.xcodeproj/project.pbxproj"
cp "${stable_artifact}" "${successful_artifact}"
touch "${successful_repo}/release-marker"
git -C "${successful_repo}" add Key.xcodeproj scripts release-marker
git -C "${successful_repo}" commit -m "Prepare release" >/dev/null
git -C "${successful_repo}" remote add origin "${successful_origin}"
git -C "${successful_repo}" push --set-upstream origin main >/dev/null 2>&1

cat > "${successful_fake_bin}/gh" <<'EOF'
#!/bin/zsh
set -euo pipefail

state="${FAKE_GH_STATE:?}"
log="${FAKE_GH_LOG:?}"
print -r -- "$*" >> "${log}"

store_asset() {
  local source_path="$1"
  cp "${source_path}" "${state}/assets/${source_path:t}"
}

if [[ "$1 $2" == "release view" ]]; then
  [[ -f "${state}/release" ]]
  exit
fi

if [[ "$1 $2" == "release create" ]]; then
  touch "${state}/release"
  shift 3
  for argument in "$@"; do
    [[ "${argument}" == --* ]] && continue
    [[ -f "${argument}" ]] && store_asset "${argument}"
  done
  exit
fi

if [[ "$1 $2" == "release upload" ]]; then
  shift 3
  for argument in "$@"; do
    if [[ "${argument}" == "--clobber" ]]; then
      echo "release publication must not replace assets" >&2
      exit 1
    fi
    store_asset "${argument}"
  done
  exit
fi

if [[ "$1" == "api" ]]; then
  jq_expression=""
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == "--jq" ]]; then
      jq_expression="$2"
      break
    fi
    shift
  done

  if [[ "${jq_expression}" == '.assets[].name' ]]; then
    for asset_path in "${state}/assets"/*(N); do
      print -r -- "${asset_path:t}"
    done
    exit
  fi

  asset_name="$(
    print -r -- "${jq_expression}" | \
      sed -n 's/.*select(.name == "\([^"]*\)").*/\1/p'
  )"
  asset_path="${state}/assets/${asset_name}"
  if [[ "${jq_expression}" == *'| length' ]]; then
    [[ -f "${asset_path}" ]] && echo 1 || echo 0
  elif [[ "${jq_expression}" == *'.digest'* ]]; then
    if [[ -f "${asset_path}" ]]; then
      echo "sha256:$(shasum -a 256 "${asset_path}" | awk '{print $1}')"
    fi
  elif [[ "${jq_expression}" == *'.browser_download_url'* && -f "${asset_path}" ]]; then
    echo "https://example.invalid/${asset_name}"
  fi
  exit
fi

echo "unsupported fake gh invocation: $*" >&2
exit 64
EOF
chmod +x "${successful_fake_bin}/gh"

run_successful_publication() {
  (
    cd "${successful_repo}"
    PATH="${successful_fake_bin}:${PATH}" \
    FAKE_GH_STATE="${successful_gh_state}" \
    FAKE_GH_LOG="${successful_gh_log}" \
      ./scripts/publish-release.sh "${publication_tag}" "${successful_artifact}"
  )
}

run_successful_publication > "${test_root}/first-publication.out" 2>&1
successful_sha="$(shasum -a 256 "${successful_artifact}" | awk '{print $1}')"
if [[ "$(<"${successful_artifact_root}/checksums.txt")" != \
      "${successful_sha}  ${successful_artifact:t}" ]]; then
  echo "release publication wrote a nondeterministic checksum manifest" >&2
  exit 1
fi
if [[ "$(print -l "${successful_gh_state}/assets"/*(N:t) | LC_ALL=C sort)" != \
      "$(printf '%s\n' checksums.txt "${successful_artifact:t}" | LC_ALL=C sort)" ]]; then
  echo "release publication did not create the exact supported asset set" >&2
  exit 1
fi
grep -q '^release create .*checksums.txt .*--verify-tag' "${successful_gh_log}"
if grep -q -- '--clobber' "${successful_gh_log}"; then
  echo "release publication attempted to replace an asset" >&2
  exit 1
fi

cp "${successful_gh_state}/assets/checksums.txt" \
  "${test_root}/published-checksums.txt"
rm "${successful_gh_state}/assets/checksums.txt"
run_successful_publication > "${test_root}/resumed-publication.out" 2>&1
cmp "${successful_gh_state}/assets/checksums.txt" \
  "${test_root}/published-checksums.txt"
grep -q "^release upload ${publication_tag} ${successful_artifact_root}/checksums.txt$" \
  "${successful_gh_log}"

upload_count_before="$(grep -c '^release upload ' "${successful_gh_log}")"
run_successful_publication > "${test_root}/idempotent-publication.out" 2>&1
upload_count_after="$(grep -c '^release upload ' "${successful_gh_log}")"
if [[ "${upload_count_after}" != "${upload_count_before}" ]]; then
  echo "an exact publication retry uploaded an asset again" >&2
  exit 1
fi

echo "different published bytes" > \
  "${successful_gh_state}/assets/${successful_artifact:t}"
if run_successful_publication > "${test_root}/differing-publication.out" 2>&1; then
  echo "expected publication to reject a differing published asset" >&2
  exit 1
fi
grep -q 'publish a new version instead of replacing an existing asset' \
  "${test_root}/differing-publication.out"
if [[ "$(grep -c '^release upload ' "${successful_gh_log}")" != \
      "${upload_count_before}" ]]; then
  echo "a differing publication retry attempted an upload" >&2
  exit 1
fi

cp "${successful_artifact}" \
  "${successful_gh_state}/assets/${successful_artifact:t}"
echo "unexpected" > "${successful_gh_state}/assets/unexpected.txt"
if run_successful_publication > "${test_root}/unexpected-publication.out" 2>&1; then
  echo "expected publication to reject an unexpected release asset" >&2
  exit 1
fi
grep -q 'contains an unexpected asset: unexpected.txt' \
  "${test_root}/unexpected-publication.out"

dispatcher_fake_bin="${test_root}/dispatcher-bin"
dispatcher_log="${test_root}/dispatcher.log"
mkdir -p "${dispatcher_fake_bin}"
cat > "${dispatcher_fake_bin}/gh" <<'EOF'
#!/bin/zsh
set -euo pipefail
print -r -- "$*" >> "${DISPATCHER_LOG:?}"
EOF
chmod +x "${dispatcher_fake_bin}/gh"

assert_dispatch() {
  local version="$1"
  local expected_cask="$2"
  local output="${test_root}/dispatch-${version}.out"

  PATH="${dispatcher_fake_bin}:${PATH}" \
  DISPATCHER_LOG="${dispatcher_log}" \
    "${repo_root}/scripts/publish-homebrew.sh" "${version}" > "${output}"
  tail -n 1 "${dispatcher_log}" | grep -qx \
    "workflow run publish-package.yml --repo tvanreenen/homebrew-tap --ref main --raw-field package=key --raw-field version=${version}"
  grep -q "^  cask:       ${expected_cask}$" "${output}"
}

assert_dispatch "v1.2.3" "key"
assert_dispatch "v1.2.3-alpha.1" "key@alpha"
assert_dispatch "v1.2.3-beta.2" "key@beta"
assert_dispatch "v1.2.3-rc.3" "key@rc"
dispatch_count="$(wc -l < "${dispatcher_log}" | tr -d ' ')"
for invalid_version in \
  "1.2.3" \
  "v01.2.3" \
  "v1.2.3-alpha.01" \
  "v1.2.3-preview.1"; do
  if PATH="${dispatcher_fake_bin}:${PATH}" \
    DISPATCHER_LOG="${dispatcher_log}" \
      "${repo_root}/scripts/publish-homebrew.sh" "${invalid_version}" \
      >/dev/null 2>&1; then
    echo "expected Homebrew dispatch to reject ${invalid_version}" >&2
    exit 1
  fi
done
if [[ "$(wc -l < "${dispatcher_log}" | tr -d ' ')" != "${dispatch_count}" ]]; then
  echo "invalid Homebrew versions reached gh workflow dispatch" >&2
  exit 1
fi

if grep -q 'scripts/publish-homebrew.sh.*"${version}"' \
  "${repo_root}/scripts/release.sh"; then
  echo "the source release flow still dispatches Homebrew automatically" >&2
  exit 1
fi

echo "Release target, artifact publication, and Homebrew dispatch tests passed."
