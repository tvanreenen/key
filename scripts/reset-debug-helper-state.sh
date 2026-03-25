#!/bin/zsh
set -euo pipefail

app_id="work.tvr.key.app"
agent_label="work.tvr.key.agent"
installed_app_path="/Applications/Key Debug.app"

osascript -e "tell application id \"${app_id}\" to quit" >/dev/null 2>&1 || true
launchctl bootout "gui/$(id -u)/${agent_label}" >/dev/null 2>&1 || true
sfltool resetbtm
rm -rf "${installed_app_path}"

echo "Reset debug helper state:"
echo "  launchd job removed: ${agent_label}"
echo "  background task database reset"
echo "  removed installed debug app: ${installed_app_path}"
echo
echo "Next:"
echo "  just build-debug"
