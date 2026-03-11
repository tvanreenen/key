#!/bin/zsh
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

cd "${repo_root}"

archive_date_dir="${HOME}/Library/Developer/Xcode/Archives/$(date +%Y-%m-%d)"
mkdir -p "${archive_date_dir}"
archive_path="${archive_date_dir}/Key $(date +%-m-%-d-%y, %H.%M).xcarchive"
app_path="${archive_path}/Products/Applications/Key.app"
cli_path="${app_path}/Contents/MacOS/key"
service_path="${app_path}/Contents/XPCServices/KeyXPCService.xpc"

xcodebuild \
  -project Key.xcodeproj \
  -scheme Key \
  -configuration Release \
  -archivePath "${archive_path}" \
  clean archive

echo "Built signed archive:"
echo "  ${archive_path}"
echo "Archived app:"
echo "  ${app_path}"
echo "Bundled CLI:"
echo "  ${cli_path}"
echo "Bundled XPC service:"
echo "  ${service_path}"
echo
echo "Next:"
echo "  scripts/verify-signing.sh \"${app_path}\""
