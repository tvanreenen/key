#!/bin/zsh
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <tag>" >&2
  exit 1
fi

tag="$1"

if [[ "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  product_variant="stable"
  cask_token="key"
  artifact_name="Key-${tag}.zip"
elif [[ "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-(alpha|beta|rc)\.[0-9]+$ ]]; then
  prerelease="${tag#*-}"
  channel="${prerelease%%.*}"
  product_variant="preview"
  cask_token="key@${channel}"
  artifact_name="Key-Preview-${tag}.zip"
else
  echo "releases require a stable tag or a numbered alpha, beta, or rc tag" >&2
  echo "expected v#.#.#, v#.#.#-alpha.#, v#.#.#-beta.#, or v#.#.#-rc.#" >&2
  exit 1
fi

printf '%s\t%s\t%s\n' \
  "${product_variant}" \
  "${cask_token}" \
  "${artifact_name}"
