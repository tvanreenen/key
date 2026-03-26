#!/bin/zsh
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <version>" >&2
  exit 1
fi

version="$1"
tap_repo_root="${KEY_TAP_REPO:-$HOME/Code/homebrew-tap}"

if [[ ! -d "${tap_repo_root}" ]]; then
  echo "missing Homebrew tap checkout at ${tap_repo_root}" >&2
  echo "clone https://github.com/tvanreenen/homebrew-tap or set KEY_TAP_REPO" >&2
  exit 1
fi

tap_repo="$(cd "${tap_repo_root}" && pwd)"
cask_path="Casks/key.rb"

if [[ ! -f "${tap_repo}/${cask_path}" ]]; then
  echo "missing ${cask_path} in ${tap_repo}" >&2
  exit 1
fi

dirty_paths="$(git -C "${tap_repo}" status --porcelain)"
if [[ -n "${dirty_paths}" ]]; then
  unexpected_paths="$(printf '%s\n' "${dirty_paths}" | awk '{print $2}' | grep -v "^${cask_path}$" || true)"
  if [[ -n "${unexpected_paths}" ]]; then
    echo "Homebrew tap repo has unrelated local changes:" >&2
    printf '%s\n' "${unexpected_paths}" >&2
    echo "clean them up or commit them before running this command" >&2
    exit 1
  fi
fi

git -C "${tap_repo}" add "${cask_path}"

if git -C "${tap_repo}" diff --cached --quiet; then
  echo "No staged Homebrew tap changes to commit."
  exit 0
fi

git -C "${tap_repo}" commit -m "Update key cask to ${version}"
git -C "${tap_repo}" push

echo "Published Homebrew tap update:"
echo "  repo:    ${tap_repo}"
echo "  cask:    ${cask_path}"
echo "  version: ${version}"
