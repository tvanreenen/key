#!/bin/zsh
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <tag>" >&2
  exit 1
fi

tag="$1"
if [[ ! "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "tag must look like v#.#.# or v#.#.#-prerelease" >&2
  exit 1
fi

case "${tag}" in
  v0.1.*)
    print -r -- "release/0.1"
    ;;
  *)
    print -r -- "main"
    ;;
esac
