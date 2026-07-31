#!/bin/zsh
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
resolver="${repo_root}/scripts/homebrew-cask-token.sh"

assert_token() {
  local tag="$1"
  local expected="$2"
  local actual
  actual="$("${resolver}" "${tag}")"

  if [[ "${actual}" != "${expected}" ]]; then
    echo "expected ${tag} to select ${expected}; got ${actual}" >&2
    exit 1
  fi
}

assert_rejected() {
  local tag="$1"

  if "${resolver}" "${tag}" >/dev/null 2>&1; then
    echo "expected ${tag} to be rejected" >&2
    exit 1
  fi
}

assert_token "v0.1.1" "key"
assert_token "v0.2.0-alpha.2" "key@alpha"
assert_token "v0.2.0-beta.1" "key@beta"
assert_token "v0.2.0-rc.1" "key@rc"

assert_rejected "0.2.0-alpha.2"
assert_rejected "v0.2.0-preview.1"
assert_rejected "v0.2.0-alpha"

test_root="$(mktemp -d)"
trap 'rm -rf -- "${test_root}"' EXIT
tap_origin="${test_root}/origin.git"
tap_checkout="${test_root}/tap"

git init --bare --initial-branch=main "${tap_origin}" >/dev/null
git clone "${tap_origin}" "${tap_checkout}" >/dev/null 2>&1
git -C "${tap_checkout}" config user.name "Release Script Tests"
git -C "${tap_checkout}" config user.email "release-tests@example.invalid"
mkdir -p "${tap_checkout}/Casks"
echo 'cask "key" do; version "v0.1.1"; end' > "${tap_checkout}/Casks/key.rb"
git -C "${tap_checkout}" add Casks/key.rb
git -C "${tap_checkout}" commit -m "Add stable cask" >/dev/null
git -C "${tap_checkout}" push --set-upstream origin main >/dev/null 2>&1

stable_before="$(shasum -a 256 "${tap_checkout}/Casks/key.rb")"
KEY_TAP_REPO="${tap_checkout}" "${repo_root}/scripts/update-homebrew-tap.sh" \
  "v0.2.0-alpha.2" \
  "https://example.invalid/Key-v0.2.0-alpha.2.zip" \
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  >/dev/null
stable_after="$(shasum -a 256 "${tap_checkout}/Casks/key.rb")"

if [[ "${stable_after}" != "${stable_before}" ]]; then
  echo "alpha update changed the stable cask" >&2
  exit 1
fi

alpha_cask="${tap_checkout}/Casks/key@alpha.rb"
grep -q '^cask "key@alpha" do$' "${alpha_cask}"
grep -q '^  version "v0.2.0-alpha.2"$' "${alpha_cask}"
grep -q '^  desc "File-based secret manager with native authentication"$' "${alpha_cask}"
grep -q '^  depends_on :macos$' "${alpha_cask}"
grep -q '^  conflicts_with cask: \["key", "key@beta", "key@rc"\]$' "${alpha_cask}"
ruby -c "${alpha_cask}" >/dev/null

KEY_TAP_REPO="${tap_checkout}" "${repo_root}/scripts/publish-homebrew-tap.sh" \
  "v0.2.0-alpha.2" \
  >/dev/null 2>&1

if [[ -n "$(git -C "${tap_checkout}" status --porcelain)" ]]; then
  echo "publishing the alpha cask left unexpected tap changes" >&2
  exit 1
fi

if [[ "$(git -C "${tap_checkout}" log -1 --format=%s)" != \
  "Update key@alpha cask to v0.2.0-alpha.2" ]]; then
  echo "alpha cask was committed with the wrong release identity" >&2
  exit 1
fi

echo "Homebrew cask channel tests passed."
