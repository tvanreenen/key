#!/bin/zsh
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <tag>" >&2
  exit 1
fi

tag="$1"
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
"${repo_root}/scripts/release-target.sh" "${tag}" >/dev/null
project_file="${repo_root}/Key.xcodeproj/project.pbxproj"

branch="$(git -C "${repo_root}" symbolic-ref --quiet --short HEAD || true)"
if [[ "${branch}" != "main" ]]; then
  echo "version bumps must be created on main (current branch: ${branch:-detached HEAD})" >&2
  exit 1
fi

if [[ -n "$(git -C "${repo_root}" status --porcelain)" ]]; then
  echo "worktree must be clean before bumping the release version" >&2
  exit 1
fi

if git -C "${repo_root}" rev-parse --verify --quiet "refs/tags/${tag}" >/dev/null; then
  echo "tag ${tag} already exists" >&2
  exit 1
fi

marketing_version="${tag#v}"
IFS=$'\t' read -r old_marketing_version old_build_version \
  <<< "$("${repo_root}/scripts/project-version.sh")"

new_build_version="$(( old_build_version + 1 ))"
tmp_file="$(mktemp)"
trap 'rm -f "${tmp_file}"' EXIT

awk \
  -v new_marketing_version="${marketing_version}" \
  -v new_build_version="${new_build_version}" \
  '
    {
      line = $0
      if (line ~ /MARKETING_VERSION = /) {
        sub(/MARKETING_VERSION = [^;]+;/, "MARKETING_VERSION = " new_marketing_version ";", line)
      }
      if (line ~ /CURRENT_PROJECT_VERSION = /) {
        sub(/CURRENT_PROJECT_VERSION = [^;]+;/, "CURRENT_PROJECT_VERSION = " new_build_version ";", line)
      }
      print line
    }
  ' "${project_file}" > "${tmp_file}"

mv "${tmp_file}" "${project_file}"
trap - EXIT

IFS=$'\t' read -r updated_marketing_version updated_build_version \
  <<< "$("${repo_root}/scripts/project-version.sh")"

if [[ "${updated_marketing_version}" != "${marketing_version}" ]]; then
  echo "failed to update MARKETING_VERSION consistently" >&2
  exit 1
fi

if [[ "${updated_build_version}" != "${new_build_version}" ]]; then
  echo "failed to update CURRENT_PROJECT_VERSION consistently" >&2
  exit 1
fi

git -C "${repo_root}" add "${project_file}"
git -C "${repo_root}" commit -m "Bump version to ${marketing_version} (${new_build_version})"

commit_sha="$(git -C "${repo_root}" rev-parse --short HEAD)"

echo "Bumped release version:"
echo "  old marketing version: ${old_marketing_version}"
echo "  new marketing version: ${marketing_version}"
echo "  old build version:     ${old_build_version}"
echo "  new build version:     ${new_build_version}"
echo "  commit:                ${commit_sha}"
echo "  planned tag:           ${tag}"
echo
echo "Next:"
echo "  just build-release \"${tag}\""
