#!/bin/zsh
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <tag>" >&2
  exit 1
fi

tag="$1"

semver_number='(0|[1-9][0-9]*)'

if [[ "${tag}" =~ ^v${semver_number}\.${semver_number}\.${semver_number}$ ]]; then
  product_variant="stable"
  cask_token="key"
  artifact_name="Key-${tag}.zip"
elif [[ "${tag}" =~ ^v${semver_number}\.${semver_number}\.${semver_number}-(alpha|beta|rc)\.${semver_number}$ ]]; then
  prerelease="${tag#*-}"
  channel="${prerelease%%.*}"
  product_variant="preview"
  cask_token="key@${channel}"
  artifact_name="Key-Preview-${tag}.zip"
else
  echo "releases require a strict v-prefixed Semantic Version for a supported channel" >&2
  echo "expected v#.#.#, v#.#.#-alpha.#, v#.#.#-beta.#, or v#.#.#-rc.#" >&2
  exit 1
fi

printf '%s\t%s\t%s\n' \
  "${product_variant}" \
  "${cask_token}" \
  "${artifact_name}"
