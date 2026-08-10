#!/bin/zsh
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <stable|preview> <app-path>" >&2
  exit 1
fi

variant="$1"
app_path="$2"

case "${variant}" in
  stable)
    app_id="work.tvr.key.app"
    cli_name="key"
    helper_name="Key Agent"
    helper_id="work.tvr.key.xpc"
    agent_label="work.tvr.key.agent"
    agent_status_label="work.tvr.key.agent.status"
    ;;
  preview)
    app_id="work.tvr.key.preview.app"
    cli_name="key-preview"
    helper_name="Key Preview Agent"
    helper_id="work.tvr.key.preview.xpc"
    agent_label="work.tvr.key.preview.agent"
    agent_status_label="work.tvr.key.preview.agent.status"
    ;;
  *)
    echo "product variant must be stable or preview" >&2
    exit 1
    ;;
esac

plist_value() {
  local plist_path="$1"
  local key_path="$2"
  /usr/libexec/PlistBuddy -c "Print :${key_path}" "${plist_path}" 2>/dev/null || true
}

require_value() {
  local label="$1"
  local actual="$2"
  local expected="$3"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "unexpected ${label} '${actual:-missing}' in ${app_path}; expected '${expected}'" >&2
    exit 1
  fi
}

if [[ ! -d "${app_path}" ]]; then
  echo "missing ${variant} app bundle at ${app_path}" >&2
  exit 1
fi

app_info="${app_path}/Contents/Info.plist"
helper_path="${app_path}/Contents/Helpers/${helper_name}.app"
helper_info="${helper_path}/Contents/Info.plist"
agent_plist="${app_path}/Contents/Library/LaunchAgents/${agent_label}.plist"

require_value "app bundle identifier" "$(plist_value "${app_info}" CFBundleIdentifier)" "${app_id}"
require_value "product variant" "$(plist_value "${app_info}" KeyProductVariant)" "${variant}"
require_value "helper bundle identifier" "$(plist_value "${helper_info}" CFBundleIdentifier)" "${helper_id}"
require_value "helper product variant" "$(plist_value "${helper_info}" KeyProductVariant)" "${variant}"
require_value "LaunchAgent label" "$(plist_value "${agent_plist}" Label)" "${agent_label}"
require_value \
  "LaunchAgent helper path" \
  "$(plist_value "${agent_plist}" BundleProgram)" \
  "Contents/Helpers/${helper_name}.app/Contents/MacOS/${helper_name}"
require_value \
  "LaunchAgent signing identifier" \
  "$(plist_value "${agent_plist}" SpawnConstraint:signing-identifier)" \
  "${helper_id}"
require_value \
  "primary Mach service" \
  "$(plist_value "${agent_plist}" MachServices:${agent_label})" \
  "true"
require_value \
  "status Mach service" \
  "$(plist_value "${agent_plist}" MachServices:${agent_status_label})" \
  "true"

app_executable="$(plist_value "${app_info}" CFBundleExecutable)"
helper_executable="$(plist_value "${helper_info}" CFBundleExecutable)"
if [[ -z "${app_executable}" || ! -x "${app_path}/Contents/MacOS/${app_executable}" ]]; then
  echo "missing ${variant} app executable in ${app_path}" >&2
  exit 1
fi
if [[ ! -x "${app_path}/Contents/MacOS/${cli_name}" ]]; then
  echo "missing bundled ${cli_name} executable in ${app_path}" >&2
  exit 1
fi
if [[ -z "${helper_executable}" || ! -x "${helper_path}/Contents/MacOS/${helper_executable}" ]]; then
  echo "missing bundled ${helper_name} executable in ${app_path}" >&2
  exit 1
fi

echo "Verified ${variant} product bundle: ${app_path}"
