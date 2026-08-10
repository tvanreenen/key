#!/bin/zsh
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <tag> <zip-path>" >&2
  exit 1
fi

tag="$1"
zip_path="$2"
script_dir="$(cd "$(dirname "$0")" && pwd)"
expected_marketing_version="${tag#v}"
IFS=$'\t' read -r product_variant _ expected_asset_name \
  <<< "$("${script_dir}/release-target.sh" "${tag}")"
IFS=$'\t' read -r project_marketing_version expected_build_version \
  <<< "$("${script_dir}/project-version.sh")"

if [[ "${project_marketing_version}" != "${expected_marketing_version}" ]]; then
  echo "release tag ${tag} does not match project version ${project_marketing_version}" >&2
  exit 1
fi

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
    helper_name="Key Agent"
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
    helper_name="Key Preview Agent"
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

app_path="${extraction_root}/${app_name}"
app_info="${app_path}/Contents/Info.plist"
helper_info="${app_path}/Contents/Helpers/${helper_name}.app/Contents/Info.plist"

plist_value() {
  local plist_path="$1"
  local key="$2"
  /usr/libexec/PlistBuddy -c "Print :${key}" "${plist_path}" 2>/dev/null || true
}

require_value() {
  local label="$1"
  local actual="$2"
  local expected="$3"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "unexpected ${label} '${actual:-missing}'; expected '${expected}'" >&2
    exit 1
  fi
}

app_marketing_version="$(plist_value "${app_info}" CFBundleShortVersionString)"
helper_marketing_version="$(plist_value "${helper_info}" CFBundleShortVersionString)"
app_build_version="$(plist_value "${app_info}" CFBundleVersion)"
helper_build_version="$(plist_value "${helper_info}" CFBundleVersion)"

require_value \
  "app marketing version" \
  "${app_marketing_version}" \
  "${expected_marketing_version}"
require_value \
  "helper marketing version" \
  "${helper_marketing_version}" \
  "${expected_marketing_version}"

if [[ ! "${app_build_version}" =~ ^[0-9]+$ ]]; then
  echo "app build version must be numeric, not '${app_build_version:-missing}'" >&2
  exit 1
fi
require_value \
  "app build version" \
  "${app_build_version}" \
  "${expected_build_version}"
require_value \
  "helper build version" \
  "${helper_build_version}" \
  "${expected_build_version}"

"${script_dir}/verify-product-bundle.sh" \
  "${product_variant}" \
  "${app_path}" \
  >/dev/null

"${script_dir}/verify-signing.sh" \
  "${app_path}" \
  "${product_variant}" \
  >/dev/null

xcrun stapler validate "${app_path}" >/dev/null
spctl --assess --type execute --verbose "${app_path}" >/dev/null

echo "Verified ${product_variant} release artifact: ${zip_path}"
