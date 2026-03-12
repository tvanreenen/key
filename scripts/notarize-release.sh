#!/bin/zsh
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <archive-path>" >&2
  exit 1
fi

notary_profile="key-notary"
archive_path="$1"
app_path="${archive_path}/Products/Applications/Key.app"
zip_path="${archive_path%.*}.zip"

if [[ ! -d "${app_path}" ]]; then
  echo "missing app bundle at ${app_path}" >&2
  exit 1
fi

ditto -c -k --keepParent "${app_path}" "${zip_path}"
xcrun notarytool submit "${zip_path}" --keychain-profile "${notary_profile}" --wait
xcrun stapler staple "${app_path}"
spctl --assess --type execute --verbose "${app_path}"
