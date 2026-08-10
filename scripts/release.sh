#!/bin/zsh
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <tag>" >&2
  exit 1
fi

version="$1"
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
IFS=$'\t' read -r product_variant homebrew_cask_token artifact_name \
  <<< "$("${repo_root}/scripts/release-target.sh" "${version}")"
release_root="${HOME}/Library/Developer/Xcode/Releases/key/${version}"
final_zip="${release_root}/${artifact_name}"

echo "==> Product: ${product_variant}"
echo "==> Homebrew channel: ${homebrew_cask_token}"

echo "==> Bump version"
"${repo_root}/scripts/bump-version.sh" "${version}"

echo
echo "==> Build release"
"${repo_root}/scripts/build-release.sh" "${version}"

if [[ ! -f "${final_zip}" ]]; then
  echo "missing release zip at ${final_zip}" >&2
  exit 1
fi

echo
echo "==> Publish GitHub release"
"${repo_root}/scripts/publish-release.sh" "${version}" "${final_zip}"

asset_name="$(basename "${final_zip}")"
sha256="$(shasum -a 256 "${final_zip}" | awk '{print $1}')"
download_url="$(
  cd "${repo_root}"
  gh api "repos/{owner}/{repo}/releases/tags/${version}" \
    --jq ".assets[] | select(.name == \"${asset_name}\") | .browser_download_url"
)"

if [[ -z "${download_url}" ]]; then
  echo "failed to resolve uploaded asset URL for ${asset_name}" >&2
  exit 1
fi

echo
echo "==> Update Homebrew tap"
"${repo_root}/scripts/update-homebrew-tap.sh" "${version}" "${download_url}" "${sha256}"

echo
echo "==> Publish Homebrew tap"
"${repo_root}/scripts/publish-homebrew-tap.sh" "${version}"

echo
echo "Release complete:"
echo "  tag:         ${version}"
echo "  zip:         ${final_zip}"
echo "  download URL:${download_url}"
echo "  sha256:      ${sha256}"
