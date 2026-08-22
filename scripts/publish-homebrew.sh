#!/bin/zsh
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <tag>" >&2
  exit 1
fi

version="$1"
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
release_target="$("${repo_root}/scripts/release-target.sh" "${version}")"
IFS=$'\t' read -r _ homebrew_cask_token _ \
  <<< "${release_target}"

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI is required." >&2
  exit 1
fi

gh workflow run publish-package.yml \
  --repo tvanreenen/homebrew-tap \
  --ref main \
  --raw-field package=key \
  --raw-field version="${version}"

echo "Dispatched Homebrew publication:"
echo "  repository: tvanreenen/homebrew-tap"
echo "  workflow:   publish-package.yml"
echo "  ref:        main"
echo "  package:    key"
echo "  version:    ${version}"
echo "  cask:       ${homebrew_cask_token}"
echo
echo "Follow the run:"
echo "  gh run list --repo tvanreenen/homebrew-tap --workflow publish-package.yml"
