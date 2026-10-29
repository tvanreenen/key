#!/bin/zsh
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
export ZDOTDIR="${repo_root}/Tests/ScriptFixtures"
test_root="$(mktemp -d)"
trap 'rm -rf -- "${test_root}"' EXIT

origin="${test_root}/origin.git"
fixture="${test_root}/source"
git init --bare --initial-branch=main "${origin}" >/dev/null
git init --initial-branch=main "${fixture}" >/dev/null
git -C "${fixture}" config user.name 'Release Script Tests'
git -C "${fixture}" config user.email 'release-tests@example.invalid'
mkdir -p "${fixture}/scripts" "${fixture}/Key.xcodeproj"
cp "${repo_root}/scripts/"{bump-version,release-target,project-version,verify-release-source}.sh \
  "${fixture}/scripts/"
cat > "${fixture}/Key.xcodeproj/project.pbxproj" <<'PROJECT'
MARKETING_VERSION = 1.2.3;
CURRENT_PROJECT_VERSION = 7;
PROJECT
git -C "${fixture}" add scripts Key.xcodeproj
git -C "${fixture}" commit -m 'Initial source' >/dev/null
git -C "${fixture}" remote add origin "${origin}"
git -C "${fixture}" push -u origin main >/dev/null 2>&1
initial_commit="$(git -C "${fixture}" rev-parse HEAD)"

reject_source() {
  local expected="$1"
  local tag="${2:-v1.2.3}"
  if "${fixture}/scripts/verify-release-source.sh" "${tag}" > "${test_root}/source-error" 2>&1; then
    echo "expected release source rejection: ${expected}" >&2
    exit 1
  fi
  grep -q "${expected}" "${test_root}/source-error"
}

"${fixture}/scripts/verify-release-source.sh" v1.2.3
if "${fixture}/scripts/bump-version.sh" v1.2.4 > "${test_root}/bump-error" 2>&1; then
  echo 'expected version preparation to reject main' >&2
  exit 1
fi
grep -q 'PR branch or final stack layer' "${test_root}/bump-error"
[[ "$(git -C "${fixture}" rev-parse HEAD)" == "${initial_commit}" ]]
reject_source 'does not match project version' v1.2.4

echo dirty >> "${fixture}/Key.xcodeproj/project.pbxproj"
reject_source 'must be clean'
git -C "${fixture}" restore Key.xcodeproj/project.pbxproj
touch "${fixture}/untracked"
reject_source 'must be clean'
rm "${fixture}/untracked"
git -C "${fixture}" switch --detach >/dev/null 2>&1
reject_source 'must be on main'
if "${fixture}/scripts/bump-version.sh" v1.2.4 >/dev/null 2>&1; then
  echo 'expected version preparation to reject detached HEAD' >&2
  exit 1
fi
git -C "${fixture}" switch -c release-version >/dev/null 2>&1
reject_source 'must be on main'
touch "${fixture}/untracked"
if "${fixture}/scripts/bump-version.sh" v1.2.4 >/dev/null 2>&1; then
  echo 'expected version preparation to reject dirty source' >&2
  exit 1
fi
rm "${fixture}/untracked"
"${fixture}/scripts/bump-version.sh" v1.2.4 > "${test_root}/bump-output"
[[ "$("${fixture}/scripts/project-version.sh")" == $'1.2.4\t8' ]]
[[ -z "$(git -C "${fixture}" status --porcelain)" ]]
[[ -z "$(git -C "${fixture}" tag --list)" ]]
[[ "$(git --git-dir="${origin}" rev-parse refs/heads/main)" == "${initial_commit}" ]]
grep -q 'After merging' "${test_root}/bump-output"
git -C "${fixture}" tag v1.2.4
if "${fixture}/scripts/bump-version.sh" v1.2.4 >/dev/null 2>&1; then
  echo 'expected version preparation to reject an existing tag' >&2
  exit 1
fi
git -C "${fixture}" tag --delete v1.2.4 >/dev/null

git -C "${fixture}" switch main >/dev/null 2>&1
git -C "${fixture}" merge --ff-only release-version >/dev/null
reject_source 'must match published main' v1.2.4
lagging="${test_root}/lagging"
git clone "${origin}" "${lagging}" >/dev/null 2>&1
# Simulate a merged version PR in the disposable remote.
git -C "${fixture}" push origin main >/dev/null 2>&1
"${fixture}/scripts/verify-release-source.sh" v1.2.4
if "${lagging}/scripts/verify-release-source.sh" v1.2.3 >/dev/null 2>&1; then
  echo 'expected release source to reject main behind its remote' >&2
  exit 1
fi
git -C "${fixture}" remote set-url origin "${test_root}/missing.git"
reject_source 'could not confirm published main' v1.2.4
git -C "${fixture}" remote set-url origin "${origin}"
"${fixture}/scripts/verify-release-source.sh" v1.2.4

git -C "${fixture}" switch -c preview-version >/dev/null 2>&1
"${fixture}/scripts/bump-version.sh" v1.3.0-beta.1 > "${test_root}/preview-bump-output"
[[ "$("${fixture}/scripts/project-version.sh")" == $'1.3.0-beta.1\t9' ]]
[[ -z "$(git -C "${fixture}" tag --list)" ]]

if grep -q 'scripts/bump-version.sh' "${repo_root}/scripts/release.sh"; then
  echo 'release must use the merged version without creating another version commit' >&2
  exit 1
fi
print 'Release source and version preparation tests passed.'
