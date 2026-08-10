#!/bin/zsh
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <tag>" >&2
  exit 1
fi

version="$1"
script_dir="$(cd "$(dirname "$0")" && pwd)"
IFS=$'\t' read -r variant _ artifact_name <<< "$("${script_dir}/release-target.sh" "${version}")"

case "${variant}" in
  stable)
    scheme="Key"
    configuration="Release"
    archive_name="Key.xcarchive"
    app_name="Key.app"
    package_root_name="package"
    ;;
  preview)
    scheme="Key Preview"
    configuration="PreviewRelease"
    archive_name="Key Preview.xcarchive"
    app_name="Key Preview.app"
    package_root_name="package-preview"
    ;;
esac

repo_root="$(cd "${script_dir}/.." && pwd)"
notary_profile="key-notary"
release_root="${HOME}/Library/Developer/Xcode/Releases/key/${version}"
archive_path="${release_root}/${archive_name}"
staging_app="${release_root}/${app_name}"
package_root="${release_root}/${package_root_name}"
submission_zip="${release_root}/${artifact_name%.zip}-for-notary.zip"
final_zip="${release_root}/${artifact_name}"
completion_source="${repo_root}/completions/_key"

mkdir -p "${release_root}"
rm -rf \
  "${archive_path}" \
  "${staging_app}" \
  "${package_root}" \
  "${submission_zip}" \
  "${final_zip}"

cd "${repo_root}"

xcodebuild \
  -project Key.xcodeproj \
  -scheme "${scheme}" \
  -configuration "${configuration}" \
  -archivePath "${archive_path}" \
  clean archive

app_path="${archive_path}/Products/Applications/${app_name}"
if [[ ! -d "${app_path}" ]]; then
  echo "missing app bundle at ${app_path}" >&2
  exit 1
fi

cp -R "${app_path}" "${staging_app}"

"${repo_root}/scripts/verify-signing.sh" "${staging_app}" "${variant}"

ditto -c -k --keepParent "${staging_app}" "${submission_zip}"
xcrun notarytool submit "${submission_zip}" --keychain-profile "${notary_profile}" --wait
xcrun stapler staple "${staging_app}"
spctl --assess --type execute --verbose "${staging_app}"

mkdir -p "${package_root}"
cp -R "${staging_app}" "${package_root}/${app_name}"

package_entries=("${app_name}")
if [[ "${variant}" == "stable" ]]; then
  if [[ ! -f "${completion_source}" ]]; then
    echo "missing zsh completion at ${completion_source}" >&2
    exit 1
  fi
  mkdir -p "${package_root}/completions"
  cp "${completion_source}" "${package_root}/completions/_key"
  package_entries+=("completions")
fi

rm -f "${submission_zip}"
(
  cd "${package_root}"
  /usr/bin/zip -qry "${final_zip}" "${package_entries[@]}"
)

"${repo_root}/scripts/verify-release-artifact.sh" "${version}" "${final_zip}"

sha256="$(shasum -a 256 "${final_zip}" | awk '{print $1}')"

echo "Prepared ${variant} release artifact:"
echo "  tag:     ${version}"
echo "  archive: ${archive_path}"
echo "  app:     ${staging_app}"
echo "  zip:     ${final_zip}"
echo "  sha256:  ${sha256}"
if [[ "${variant}" == "stable" ]]; then
  echo "  zsh:     ${package_root}/completions/_key"
fi
echo
echo "Next:"
echo "  just publish-release \"${version}\" \"${final_zip}\""
