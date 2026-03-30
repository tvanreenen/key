#!/bin/zsh
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <tag> <zip-path>" >&2
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

if [[ ! -f "${zip_path}" ]]; then
  echo "missing release zip at ${zip_path}" >&2
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

branch="$(git symbolic-ref --quiet --short HEAD || true)"
if [[ "${branch}" != "main" ]]; then
  echo "publish-release must run from main (current branch: ${branch:-detached HEAD})" >&2
  exit 1
fi

head_tag="$(git tag --points-at HEAD | grep -x "${tag}" || true)"
if [[ -z "${head_tag}" ]]; then
  echo "HEAD must be tagged ${tag} before publishing the release" >&2
  exit 1
fi

git push origin main
git push origin "${tag}"

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
echo "  prerelease:  $([[ "${is_prerelease}" -eq 1 ]] && echo yes || echo no)"
echo "  branch:      ${branch}"
echo "  asset:       ${asset_name}"
echo "  download URL:${download_url}"
echo "  sha256:      ${sha256}"
echo
echo "Next:"
echo "  just update-homebrew-tap \"${version}\" \"${download_url}\" \"${sha256}\""
