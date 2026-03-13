#!/bin/zsh
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <version>" >&2
  exit 1
fi

version="$1"
if [[ ! "${version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "version must look like v#.#.# or v#.#.#-prerelease" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
notary_profile="key-notary"
release_root="${HOME}/Library/Developer/Xcode/Releases/key/${version}"
archive_path="${release_root}/Key.xcarchive"
staging_app="${release_root}/Key.app"
package_root="${release_root}/package"
submission_zip="${release_root}/Key-${version}-for-notary.zip"
final_zip="${release_root}/Key-${version}.zip"
completion_source="${repo_root}/completions/_key"

mkdir -p "${release_root}"
rm -rf "${archive_path}" "${staging_app}" "${package_root}" "${submission_zip}" "${final_zip}"

cd "${repo_root}"

xcodebuild \
  -project Key.xcodeproj \
  -scheme Key \
  -configuration Release \
  -archivePath "${archive_path}" \
  clean archive

app_path="${archive_path}/Products/Applications/Key.app"
if [[ ! -d "${app_path}" ]]; then
  echo "missing app bundle at ${app_path}" >&2
  exit 1
fi

cp -R "${app_path}" "${staging_app}"

"${repo_root}/scripts/verify-signing.sh" "${staging_app}"

ditto -c -k --keepParent "${staging_app}" "${submission_zip}"
xcrun notarytool submit "${submission_zip}" --keychain-profile "${notary_profile}" --wait
xcrun stapler staple "${staging_app}"
spctl --assess --type execute --verbose "${staging_app}"

if [[ ! -f "${completion_source}" ]]; then
  echo "missing zsh completion at ${completion_source}" >&2
  exit 1
fi

mkdir -p "${package_root}/completions"
cp -R "${staging_app}" "${package_root}/Key.app"
cp "${completion_source}" "${package_root}/completions/_key"

rm -f "${submission_zip}"
(
  cd "${package_root}"
  /usr/bin/zip -qry "${final_zip}" "Key.app" "completions"
)

sha256="$(shasum -a 256 "${final_zip}" | awk '{print $1}')"

echo "Prepared release:"
echo "  version: ${version}"
echo "  archive: ${archive_path}"
echo "  app:     ${staging_app}"
echo "  zsh:     ${package_root}/completions/_key"
echo "  zip:     ${final_zip}"
echo "  sha256:  ${sha256}"
echo
echo "Next:"
echo "  just publish-release \"${version}\" \"${final_zip}\""
