#!/bin/zsh
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <tag>" >&2
  exit 1
fi

script_dir="$(cd "$(dirname "$0")" && pwd)"
IFS=$'\t' read -r _ cask_token _ <<< "$("${script_dir}/release-target.sh" "$1")"
print -r -- "${cask_token}"
