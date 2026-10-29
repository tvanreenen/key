#!/bin/zsh
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <tag>" >&2
  exit 1
fi

tag="$1"
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
"${repo_root}/scripts/release-target.sh" "${tag}" >/dev/null

branch="$(git -C "${repo_root}" symbolic-ref --quiet --short HEAD || true)"
if [[ "${branch}" != "main" ]]; then
  echo "release source must be on main (current branch: ${branch:-detached HEAD})" >&2
  exit 1
fi

if [[ -n "$(git -C "${repo_root}" status --porcelain)" ]]; then
  echo "release source must be clean before building or publishing" >&2
  exit 1
fi

IFS=$'\t' read -r marketing_version _ \
  <<< "$("${repo_root}/scripts/project-version.sh")"
if [[ "${marketing_version}" != "${tag#v}" ]]; then
  echo "release tag ${tag} does not match project version ${marketing_version}" >&2
  exit 1
fi

head_commit="$(git -C "${repo_root}" rev-parse HEAD)"
if ! remote_main="$(git -C "${repo_root}" ls-remote --exit-code origin refs/heads/main)"; then
  echo "could not confirm published main; check origin and network access" >&2
  exit 1
fi
remote_commit="${remote_main%%$'\t'*}"
if [[ "${head_commit}" != "${remote_commit}" ]]; then
  echo "release source must match published main; merge the version PR and update local main first" >&2
  exit 1
fi
