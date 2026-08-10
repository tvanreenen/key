#!/bin/zsh
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <tag> <zip-path>" >&2
  exit 1
fi

version="$1"
zip_path="$2"
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
IFS=$'\t' read -r product_variant _ _ \
  <<< "$("${repo_root}/scripts/release-target.sh" "${version}")"

"${repo_root}/scripts/verify-release-artifact.sh" "${version}" "${zip_path}"

tag="${version}"
sha256="$(shasum -a 256 "${zip_path}" | awk '{print $1}')"
asset_name="$(basename "${zip_path}")"

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI is required." >&2
  exit 1
fi

is_prerelease=0
if [[ "${version}" == *-* ]]; then
  is_prerelease=1
fi

cd "${repo_root}"

branch="$(git symbolic-ref --quiet --short HEAD || true)"
if [[ "${branch}" != "main" ]]; then
  echo "publish-release must run from main (current branch: ${branch:-detached HEAD})" >&2
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "worktree must be clean before tagging and publishing the release" >&2
  exit 1
fi

head_commit="$(git rev-parse HEAD)"
tag_commit="$(git rev-list -n 1 "${tag}" 2>/dev/null || true)"
if [[ -n "${tag_commit}" && "${tag_commit}" != "${head_commit}" ]]; then
  echo "tag ${tag} already points to ${tag_commit}, not HEAD ${head_commit}" >&2
  exit 1
fi

created_tag=0
if [[ -z "${tag_commit}" ]]; then
  git tag -a "${tag}" -m "${tag}"
  created_tag=1
fi

if ! git push --atomic origin main "${tag}"; then
  if [[ "${created_tag}" -eq 1 ]]; then
    git tag --delete "${tag}" >/dev/null
  fi
  echo "failed to publish main and ${tag} atomically; no remote release state was changed" >&2
  exit 1
fi

if gh release view "${tag}" >/dev/null 2>&1; then
  gh release upload "${tag}" "${zip_path}" --clobber
else
  create_args=(
    "${tag}"
    "${zip_path}"
    --title "${version}"
    --generate-notes
  )
  if [[ "${is_prerelease}" -eq 1 ]]; then
    create_args+=(--prerelease)
  fi
  gh release create "${create_args[@]}"
fi

download_url="$(gh api "repos/{owner}/{repo}/releases/tags/${tag}" --jq ".assets[] | select(.name == \"${asset_name}\") | .browser_download_url")"

if [[ -z "${download_url}" ]]; then
  echo "failed to resolve uploaded asset URL for ${asset_name}" >&2
  exit 1
fi

echo
echo "Published release:"
echo "  tag:         ${tag}"
echo "  product:     ${product_variant}"
echo "  prerelease:  $([[ "${is_prerelease}" -eq 1 ]] && echo yes || echo no)"
echo "  branch:      ${branch}"
echo "  asset:       ${asset_name}"
echo "  download URL:${download_url}"
echo "  sha256:      ${sha256}"
echo
echo "Next:"
echo "  just update-homebrew-tap \"${version}\" \"${download_url}\" \"${sha256}\""
