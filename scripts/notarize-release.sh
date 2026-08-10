#!/bin/zsh
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <archive-path>" >&2
  exit 1
fi

notary_profile="key-notary"
archive_path="$1"
zip_path="${archive_path%.*}.zip"

app_paths=("${archive_path}/Products/Applications/"*.app(N))
if [[ ${#app_paths[@]} -ne 1 ]]; then
  echo "expected one app bundle in ${archive_path}/Products/Applications" >&2
  exit 1
fi
app_path="${app_paths[1]}"

ditto -c -k --keepParent "${app_path}" "${zip_path}"
xcrun notarytool submit "${zip_path}" --keychain-profile "${notary_profile}" --wait
xcrun stapler staple "${app_path}"
spctl --assess --type execute --verbose "${app_path}"

echo
echo "Notarized archive:"
echo "  ${archive_path}"
echo "Stapled app:"
echo "  ${app_path}"
echo
echo "Next:"
echo "  just verify-release \"${app_path}\""
