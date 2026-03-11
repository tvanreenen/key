#!/bin/zsh
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <app-path>" >&2
  exit 1
fi

app_path="$1"
cli_path="${app_path}/Contents/MacOS/key"
xpc_service_path="${app_path}/Contents/XPCServices/KeyXPCService.xpc"
xpc_executable_path="${xpc_service_path}/Contents/MacOS/KeyXPCService"

if [[ ! -d "${app_path}" ]]; then
  echo "missing app bundle at ${app_path}" >&2
  exit 1
fi

if [[ ! -x "${cli_path}" ]]; then
  echo "missing bundled CLI executable at ${cli_path}" >&2
  exit 1
fi

if [[ ! -d "${xpc_service_path}" ]]; then
  echo "missing bundled XPC service at ${xpc_service_path}" >&2
  exit 1
fi

if [[ ! -x "${xpc_executable_path}" ]]; then
  echo "missing bundled XPC service executable at ${xpc_executable_path}" >&2
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
echo "== XPC service entitlements =="
print_entitlements "${xpc_service_path}"

echo
echo "== XPC executable entitlements =="
print_entitlements "${xpc_executable_path}"

echo
echo "== Gatekeeper =="
spctl --assess --type execute --verbose "${app_path}"
