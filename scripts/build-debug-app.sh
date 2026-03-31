#!/bin/zsh
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

cd "${repo_root}"

app_id="work.tvr.key.app"
agent_label="work.tvr.key.agent"

osascript -e "tell application id \"${app_id}\" to quit" >/dev/null 2>&1 || true
launchctl bootout "gui/$(id -u)/${agent_label}" >/dev/null 2>&1 || true

xcodebuild \
  -project Key.xcodeproj \
  -scheme Key \
  -configuration Debug \
  -destination 'platform=macOS,arch=arm64' \
  clean build

app_path="$(ls -td "${HOME}"/Library/Developer/Xcode/DerivedData/Key-*/Build/Products/Debug/Key.app 2>/dev/null | head -n 1 || true)"
if [[ -z "${app_path}" ]]; then
  echo "Failed to locate the built Debug app in Xcode DerivedData." >&2
  exit 1
fi

installed_app_path="/Applications/Key Debug.app"
rm -rf "${installed_app_path}"
ditto "${app_path}" "${installed_app_path}"

cli_path="${installed_app_path}/Contents/MacOS/key"
helper_path="${installed_app_path}/Contents/Helpers/Key Agent.app"
launch_agent_plist="${installed_app_path}/Contents/Library/LaunchAgents/work.tvr.key.agent.plist"

echo "Built debug app:"
echo "  ${app_path}"
echo "Installed debug app:"
echo "  ${installed_app_path}"
echo "Bundled CLI:"
echo "  ${cli_path}"
echo "Bundled helper:"
echo "  ${helper_path}"
echo "LaunchAgent plist:"
echo "  ${launch_agent_plist}"
echo
echo "Next:"
echo "  open \"${installed_app_path}\""
echo "  just verify-signing \"${installed_app_path}\""
echo "  \"${cli_path}\" list"
