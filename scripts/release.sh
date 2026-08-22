#!/bin/zsh
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <tag>" >&2
  exit 1
fi

version="$1"
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
IFS=$'\t' read -r product_variant _ artifact_name \
  <<< "$("${repo_root}/scripts/release-target.sh" "${version}")"
release_root="${HOME}/Library/Developer/Xcode/Releases/key/${version}"
final_zip="${release_root}/${artifact_name}"

echo "==> Product: ${product_variant}"

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

echo
echo "Source release complete:"
echo "  tag:         ${version}"
echo "  zip:         ${final_zip}"
echo
echo "Manual Homebrew checkpoint:"
echo "  just publish-homebrew \"${version}\""
