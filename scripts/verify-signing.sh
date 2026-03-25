#!/bin/zsh
set -euo pipefail

if [[ $# -eq 1 ]]; then
  app_path="$1"
else
  echo "usage: $0 <app-path>" >&2
  exit 1
fi

cli_path="${app_path}/Contents/MacOS/key"
helper_path="${app_path}/Contents/Helpers/KeyLaunchAgentHelper.app"
helper_executable_path="${helper_path}/Contents/MacOS/KeyLaunchAgentHelper"
launch_agent_plist="${app_path}/Contents/Library/LaunchAgents/work.tvr.key.agent.plist"

if [[ ! -d "${app_path}" ]]; then
  echo "missing app bundle at ${app_path}" >&2
  exit 1
fi

if [[ ! -x "${cli_path}" ]]; then
  echo "missing bundled CLI executable at ${cli_path}" >&2
  exit 1
fi

if [[ ! -d "${helper_path}" ]]; then
  echo "missing bundled helper app at ${helper_path}" >&2
  exit 1
fi

if [[ ! -x "${helper_executable_path}" ]]; then
  echo "missing bundled helper executable at ${helper_executable_path}" >&2
  exit 1
fi

if [[ ! -f "${launch_agent_plist}" ]]; then
  echo "missing bundled LaunchAgent plist at ${launch_agent_plist}" >&2
  exit 1
fi

print_entitlements() {
  local target_path="$1"
  local raw

  raw="$(codesign -d --entitlements - --xml "${target_path}" 2>/dev/null)"
  if [[ -z "${raw}" ]]; then
    echo "(none)"
    return
  fi

  printf '%s\n' "${raw}"
}

echo "== App entitlements =="
print_entitlements "${app_path}"

echo
echo "== CLI executable entitlements =="
print_entitlements "${cli_path}"

echo
echo "== Helper executable entitlements =="
print_entitlements "${helper_path}"

echo
echo "== LaunchAgent plist =="
plutil -p "${launch_agent_plist}"
