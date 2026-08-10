#!/bin/zsh
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
derived_data_path="${KEY_PREVIEW_DERIVED_DATA_PATH:-${HOME}/Library/Developer/Xcode/DerivedData/KeyPreviewLocal}"
app_path="${derived_data_path}/Build/Products/PreviewDebug/Key Preview.app"

cd "${repo_root}"

xcodebuild \
  -project Key.xcodeproj \
  -scheme 'Key Preview' \
  -configuration PreviewDebug \
  -destination 'platform=macOS,arch=arm64' \
  -derivedDataPath "${derived_data_path}" \
  clean build

"${script_dir}/install-preview-app.sh" "${app_path}"
