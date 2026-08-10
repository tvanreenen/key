#!/bin/zsh
set -euo pipefail

if [[ $# -eq 1 || $# -eq 2 ]]; then
  app_path="$1"
  expected_variant="${2:-}"
else
  echo "usage: $0 <app-path> [stable|preview]" >&2
  exit 1
fi

script_dir="$(cd "$(dirname "$0")" && pwd)"

if [[ ! -d "${app_path}" ]]; then
  echo "missing app bundle at ${app_path}" >&2
  exit 1
fi

variant="$(/usr/libexec/PlistBuddy -c 'Print :KeyProductVariant' "${app_path}/Contents/Info.plist" 2>/dev/null || true)"
if [[ -n "${expected_variant}" && "${variant}" != "${expected_variant}" ]]; then
  echo "unexpected product variant '${variant:-missing}' in ${app_path}; expected '${expected_variant}'" >&2
  exit 1
fi

case "${variant}" in
  stable)
    app_signing_id="work.tvr.key.app"
    cli_name="key"
    cli_signing_id="work.tvr.key.cli"
    helper_name="Key Agent"
    helper_signing_id="work.tvr.key.xpc"
    agent_label="work.tvr.key.agent"
    keychain_access_group="9Q355KSV85.work.tvr.key.shared"
    ;;
  preview)
    app_signing_id="work.tvr.key.preview.app"
    cli_name="key-preview"
    cli_signing_id="work.tvr.key.preview.cli"
    helper_name="Key Preview Agent"
    helper_signing_id="work.tvr.key.preview.xpc"
    agent_label="work.tvr.key.preview.agent"
    keychain_access_group="9Q355KSV85.work.tvr.key.preview.shared"
    ;;
  *)
    echo "unknown product variant '${variant:-missing}' in ${app_path}" >&2
    exit 1
    ;;
esac

team_id="9Q355KSV85"

"${script_dir}/verify-product-bundle.sh" "${variant}" "${app_path}" >/dev/null

cli_path="${app_path}/Contents/MacOS/${cli_name}"
helper_path="${app_path}/Contents/Helpers/${helper_name}.app"
launch_agent_plist="${app_path}/Contents/Library/LaunchAgents/${agent_label}.plist"

verify_developer_id_signature() {
  local label="$1"
  local target_path="$2"
  local signing_id="$3"
  local requirement
  local metadata

  # Match Xcode's Developer ID Application requirement: Apple Developer ID
  # intermediate, Developer ID Application leaf, and this exact team.
  # See TN3125: https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles
  requirement="anchor apple generic and identifier \"${signing_id}\" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"${team_id}\""

  echo "== ${label} signature =="
  codesign \
    --verify \
    --strict \
    --verbose=2 \
    -R="${requirement}" \
    "${target_path}"

  metadata="$(codesign -dv --verbose=4 "${target_path}" 2>&1)"
  if ! printf '%s\n' "${metadata}" | grep -Fqx "Identifier=${signing_id}"; then
    echo "${label} does not use signing identifier ${signing_id}" >&2
    exit 1
  fi
  if ! printf '%s\n' "${metadata}" | grep -Fqx "TeamIdentifier=${team_id}"; then
    echo "${label} does not use team ${team_id}" >&2
    exit 1
  fi
  if ! printf '%s\n' "${metadata}" | grep -Eq '^CodeDirectory .*flags=.*\(runtime\)'; then
    echo "${label} is missing the hardened runtime signature flag" >&2
    exit 1
  fi
  if ! printf '%s\n' "${metadata}" | grep -Eq '^Timestamp=.+$'; then
    echo "${label} is missing a trusted signing timestamp" >&2
    exit 1
  fi
}

capture_entitlements() {
  local target_path="$1"
  local output_path="$2"

  if ! codesign -d --entitlements - --xml "${target_path}" > "${output_path}" 2>/dev/null; then
    echo "failed to read entitlements from ${target_path}" >&2
    exit 1
  fi
  if [[ -s "${output_path}" ]]; then
    plutil -lint "${output_path}" >/dev/null
  fi
}

assert_entitlement_keys() {
  local label="$1"
  local plist_path="$2"
  shift 2
  local remainder_path
  local remaining_json

  if [[ ! -s "${plist_path}" ]]; then
    if [[ $# -eq 0 ]]; then
      return
    fi
    echo "${label} is missing its required entitlements" >&2
    exit 1
  fi

  remainder_path="${verification_root}/${label}-unexpected-entitlements.plist"
  cp "${plist_path}" "${remainder_path}"
  for expected_key in "$@"; do
    if ! /usr/libexec/PlistBuddy \
      -c "Delete :${expected_key}" \
      "${remainder_path}" \
      >/dev/null 2>&1; then
      echo "${label} is missing required entitlement ${expected_key}" >&2
      exit 1
    fi
  done

  remaining_json="$(plutil -convert json -o - "${remainder_path}")"
  if [[ "${remaining_json}" != "{}" ]]; then
    echo "${label} contains unexpected entitlements:" >&2
    plutil -p "${remainder_path}" >&2
    exit 1
  fi
}

require_entitlement_value() {
  local label="$1"
  local plist_path="$2"
  local key_path="$3"
  local expected="$4"
  local actual

  actual="$(/usr/libexec/PlistBuddy -c "Print :${key_path}" "${plist_path}" 2>/dev/null || true)"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "unexpected ${label} '${actual:-missing}'; expected '${expected}'" >&2
    exit 1
  fi
}

print_entitlements() {
  local label="$1"
  local plist_path="$2"

  echo "== ${label} entitlements =="
  if [[ -s "${plist_path}" ]]; then
    cat "${plist_path}"
  else
    echo "(none)"
  fi
}

verification_root="$(mktemp -d)"
trap 'rm -rf -- "${verification_root}"' EXIT
app_entitlements="${verification_root}/app-entitlements.plist"
cli_entitlements="${verification_root}/cli-entitlements.plist"
helper_entitlements="${verification_root}/helper-entitlements.plist"

verify_developer_id_signature "App" "${app_path}" "${app_signing_id}"
echo
verify_developer_id_signature "CLI" "${cli_path}" "${cli_signing_id}"
echo
verify_developer_id_signature "Helper" "${helper_path}" "${helper_signing_id}"

capture_entitlements "${app_path}" "${app_entitlements}"
capture_entitlements "${cli_path}" "${cli_entitlements}"
capture_entitlements "${helper_path}" "${helper_entitlements}"

assert_entitlement_keys \
  "app" \
  "${app_entitlements}" \
  "com.apple.application-identifier" \
  "com.apple.developer.team-identifier"
require_entitlement_value \
  "app application identifier" \
  "${app_entitlements}" \
  "com.apple.application-identifier" \
  "${team_id}.${app_signing_id}"
require_entitlement_value \
  "app team identifier" \
  "${app_entitlements}" \
  "com.apple.developer.team-identifier" \
  "${team_id}"

assert_entitlement_keys "CLI" "${cli_entitlements}"

assert_entitlement_keys \
  "helper" \
  "${helper_entitlements}" \
  "keychain-access-groups"
require_entitlement_value \
  "helper keychain access group" \
  "${helper_entitlements}" \
  "keychain-access-groups:0" \
  "${keychain_access_group}"
if /usr/libexec/PlistBuddy \
  -c "Print :keychain-access-groups:1" \
  "${helper_entitlements}" \
  >/dev/null 2>&1; then
  echo "helper claims more than one keychain access group" >&2
  exit 1
fi

print_entitlements "App" "${app_entitlements}"
echo
print_entitlements "CLI executable" "${cli_entitlements}"
echo
print_entitlements "Helper executable" "${helper_entitlements}"
echo
echo "== LaunchAgent plist =="
plutil -p "${launch_agent_plist}"
