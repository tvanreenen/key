#!/bin/zsh
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <tag> <zip-path>" >&2
  exit 1
fi

tag="$1"
zip_path="$2"
script_dir="$(cd "$(dirname "$0")" && pwd)"
IFS=$'\t' read -r product_variant _ expected_asset_name \
  <<< "$("${script_dir}/release-target.sh" "${tag}")"

if [[ ! -f "${zip_path}" ]]; then
  echo "missing release zip at ${zip_path}" >&2
  exit 1
fi

asset_name="$(basename "${zip_path}")"
if [[ "${asset_name}" != "${expected_asset_name}" ]]; then
  echo "${tag} must publish ${expected_asset_name}, not ${asset_name}" >&2
  exit 1
fi

extraction_root="$(mktemp -d)"
trap 'rm -rf -- "${extraction_root}"' EXIT
ditto -x -k "${zip_path}" "${extraction_root}"

case "${product_variant}" in
  stable)
    app_name="Key.app"
    allowed_top_level=("Key.app" "completions")
    if [[ ! -f "${extraction_root}/completions/_key" ]]; then
      echo "Stable release artifact is missing completions/_key" >&2
      exit 1
    fi
    completion_entries=("${extraction_root}/completions/"*(DN))
    if [[ ${#completion_entries[@]} -ne 1 || "${completion_entries[1]:t}" != "_key" ]]; then
      echo "Stable release artifact contains unexpected completion files" >&2
      exit 1
    fi
    ;;
  preview)
    app_name="Key Preview.app"
    allowed_top_level=("Key Preview.app")
    ;;
esac

top_level_entries=("${extraction_root}/"*(DN))
if [[ ${#top_level_entries[@]} -ne ${#allowed_top_level[@]} ]]; then
  echo "${product_variant} release artifact contains unexpected top-level items" >&2
  exit 1
fi

for entry in "${top_level_entries[@]}"; do
  entry_name="${entry:t}"
  if (( ${allowed_top_level[(Ie)${entry_name}]} == 0 )); then
    echo "${product_variant} release artifact contains unexpected top-level item ${entry_name}" >&2
    exit 1
  fi
done

"${script_dir}/verify-product-bundle.sh" \
  "${product_variant}" \
  "${extraction_root}/${app_name}" \
  >/dev/null

echo "Verified ${product_variant} release artifact: ${zip_path}"
