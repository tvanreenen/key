#!/bin/zsh
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <tag>" >&2
  exit 1
fi

version="$1"

if [[ "${version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "key"
  exit 0
fi

if [[ ! "${version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-(alpha|beta|rc)\.[0-9]+$ ]]; then
  echo "Homebrew releases require a stable tag or a numbered alpha, beta, or rc tag." >&2
  echo "expected v#.#.#, v#.#.#-alpha.#, v#.#.#-beta.#, or v#.#.#-rc.#" >&2
  exit 1
fi

prerelease="${version#*-}"
channel="${prerelease%%.*}"
echo "key@${channel}"
