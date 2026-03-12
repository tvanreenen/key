#!/bin/zsh
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <version> <zip-path>" >&2
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI is required." >&2
  exit 1
fi

version="$1"
zip_path="$2"
if [[ ! "${version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "version must look like v#.#.# or v#.#.#-prerelease" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
tap_repo_root="${KEY_TAP_REPO:-$HOME/Code/homebrew-tap}"

if [[ ! -f "${zip_path}" ]]; then
  echo "missing release zip at ${zip_path}" >&2
  exit 1
fi

if [[ ! -d "${tap_repo_root}" ]]; then
  echo "missing Homebrew tap checkout at ${tap_repo_root}" >&2
  echo "clone https://github.com/tvanreenen/homebrew-tap or set KEY_TAP_REPO" >&2
  exit 1
fi

tag="${version}"
sha256="$(shasum -a 256 "${zip_path}" | awk '{print $1}')"
asset_name="$(basename "${zip_path}")"
is_prerelease=0
if [[ "${version}" == *-* ]]; then
  is_prerelease=1
fi

cd "${repo_root}"

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

download_url="$(gh api "repos/:owner/:repo/releases/tags/${tag}" --jq ".assets[] | select(.name == \"${asset_name}\") | .browser_download_url")"

if [[ -z "${download_url}" ]]; then
  echo "failed to resolve uploaded asset URL for ${asset_name}" >&2
  exit 1
fi

"${repo_root}/scripts/update-homebrew-tap.sh" "${version}" "${download_url}" "${sha256}"

echo
echo "Published release:"
echo "  tag:         ${tag}"
echo "  prerelease:  $([[ "${is_prerelease}" -eq 1 ]] && echo yes || echo no)"
echo "  asset:       ${asset_name}"
echo "  download URL:${download_url}"
echo "  sha256:      ${sha256}"
echo
echo "Next:"
echo "  git -C \"${tap_repo_root}\" diff -- Casks/key.rb"
echo "  git -C \"${tap_repo_root}\" add Casks/key.rb"
echo "  git -C \"${tap_repo_root}\" commit -m \"Update key cask to ${version}\""
