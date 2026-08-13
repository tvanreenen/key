#!/bin/zsh
set -euo pipefail

if [[ $# -eq 1 ]]; then
  app_path="$1"
else
  echo "usage: $0 <app-path>" >&2
  exit 1
fi

cli_path="${app_path}/Contents/MacOS/key"
helper_path="${app_path}/Contents/Helpers/Key Agent.app"
helper_executable_path="${helper_path}/Contents/MacOS/Key Agent"
launch_agent_plist="${app_path}/Contents/Library/LaunchAgents/work.tvr.key.agent.plist"
expected_helper_signing_identifier="work.tvr.key.xpc"
expected_team_identifier="9Q355KSV85"

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

require_plist_value() {
  local description="$1"
  local key_path="$2"
  local expected="$3"
  local actual

  actual="$(plutil -extract "${key_path}" raw -o - "${launch_agent_plist}")"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "unexpected ${description}: expected ${expected}, found ${actual}" >&2
    exit 1
  fi
}

require_plist_value \
  "LaunchAgent signing constraint" \
  "SpawnConstraint.signing-identifier" \
  "${expected_helper_signing_identifier}"
require_plist_value \
  "LaunchAgent team constraint" \
  "SpawnConstraint.team-identifier" \
  "${expected_team_identifier}"

validation_categories="$(
  plutil -extract 'SpawnConstraint.validation-category.$in' json -o - "${launch_agent_plist}" \
    | tr -d '[:space:]'
)"
if [[ "${validation_categories}" != '[3,6]' ]]; then
  echo "unexpected LaunchAgent validation categories: expected [3,6], found ${validation_categories}" >&2
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
