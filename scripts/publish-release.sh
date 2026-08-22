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
checksums_path="${zip_path:h}/checksums.txt"
printf '%s  %s\n' "${sha256}" "${asset_name}" > "${checksums_path}"

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
  echo "failed to confirm atomic publication of main and ${tag}" >&2
  echo "main and the tag cannot advance independently; inspect the remote refs before retrying" >&2
  exit 1
fi

release_api="repos/{owner}/{repo}/releases/tags/${tag}"
if gh release view "${tag}" >/dev/null 2>&1; then
  actual_assets="$(gh api "${release_api}" --jq '.assets[].name' | LC_ALL=C sort)"
  while IFS= read -r release_asset; do
    [[ -z "${release_asset}" ]] && continue
    if [[ "${release_asset}" != "${asset_name}" && \
          "${release_asset}" != "checksums.txt" ]]; then
      echo "release ${tag} contains an unexpected asset: ${release_asset}" >&2
      echo "publish a new version instead of changing the published release" >&2
      exit 1
    fi
  done <<< "${actual_assets}"

  upload_paths=()
  for release_asset in "${asset_name}" checksums.txt; do
    asset_count="$(
      gh api "${release_api}" \
        --jq "[.assets[] | select(.name == \"${release_asset}\")] | length"
    )"
    local_path="${zip_path:h}/${release_asset}"
    if [[ "${asset_count}" == "0" ]]; then
      upload_paths+=("${local_path}")
      continue
    fi
    if [[ "${asset_count}" != "1" ]]; then
      echo "release ${tag} contains ${release_asset} more than once" >&2
      exit 1
    fi

    remote_digest="$(
      gh api "${release_api}" \
        --jq ".assets[] | select(.name == \"${release_asset}\") | .digest // \"\""
    )"
    local_digest="sha256:$(shasum -a 256 "${local_path}" | awk '{print $1}')"
    if [[ "${remote_digest}" != "${local_digest}" ]]; then
      echo "published release asset ${release_asset} differs from the local artifact" >&2
      echo "publish a new version instead of replacing an existing asset" >&2
      exit 1
    fi
  done

  if [[ ${#upload_paths[@]} -gt 0 ]]; then
    gh release upload "${tag}" "${upload_paths[@]}"
  fi
else
  create_args=(
    "${tag}"
    "${zip_path}"
    "${checksums_path}"
    --title "${version}"
    --generate-notes
    --verify-tag
  )
  if [[ "${is_prerelease}" -eq 1 ]]; then
    create_args+=(--prerelease)
  fi
  gh release create "${create_args[@]}"
fi

actual_assets="$(gh api "${release_api}" --jq '.assets[].name' | LC_ALL=C sort)"
expected_assets="$(printf '%s\n' checksums.txt "${asset_name}" | LC_ALL=C sort)"
if [[ "${actual_assets}" != "${expected_assets}" ]]; then
  echo "release ${tag} must contain exactly ${asset_name} and checksums.txt" >&2
  exit 1
fi

for release_asset in "${asset_name}" checksums.txt; do
  remote_digest="$(
    gh api "${release_api}" \
      --jq ".assets[] | select(.name == \"${release_asset}\") | .digest // \"\""
  )"
  local_path="${zip_path:h}/${release_asset}"
  local_digest="sha256:$(shasum -a 256 "${local_path}" | awk '{print $1}')"
  if [[ "${remote_digest}" != "${local_digest}" ]]; then
    echo "release asset ${release_asset} does not match the local artifact" >&2
    exit 1
  fi
done

download_url="$(
  gh api "${release_api}" \
    --jq ".assets[] | select(.name == \"${asset_name}\") | .browser_download_url"
)"

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
echo "  checksums:   checksums.txt"
echo "  download URL:${download_url}"
echo "  sha256:      ${sha256}"
echo
echo "Next:"
echo "  just publish-homebrew \"${version}\""
