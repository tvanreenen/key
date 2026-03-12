#!/bin/zsh
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

cd "${repo_root}"

xcodebuild \
  -project Key.xcodeproj \
  -scheme Key \
  -configuration Debug \
  CODE_SIGNING_ALLOWED=NO \
  clean build

app_path="$(ls -td "${HOME}"/Library/Developer/Xcode/DerivedData/Key-*/Build/Products/Debug/Key.app 2>/dev/null | head -n 1 || true)"
if [[ -z "${app_path}" ]]; then
  echo "Failed to locate the built Debug app in Xcode DerivedData." >&2
  exit 1
fi

cli_path="${app_path}/Contents/MacOS/key"
service_path="${app_path}/Contents/XPCServices/KeyXPCService.xpc"

echo "Built unsigned debug app:"
echo "  ${app_path}"
echo "Bundled CLI:"
echo "  ${cli_path}"
echo "Bundled XPC service:"
echo "  ${service_path}"
echo
echo "Next:"
echo "  just verify-signing \"${app_path}\""
echo "  \"${cli_path}\" ls"
