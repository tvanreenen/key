#!/bin/zsh
set -euo pipefail

applications_dir="${KEY_PREVIEW_APPLICATIONS_DIR:-/Applications}"
cli_bin_dir="${KEY_PREVIEW_CLI_BIN_DIR:-${HOME}/.local/bin}"
installed_app_path="${applications_dir}/Key Preview.app"
installed_cli_path="${installed_app_path}/Contents/MacOS/key-preview"
cli_link_path="${cli_bin_dir}/key-preview"
app_id="work.tvr.key.preview.app"
agent_label="work.tvr.key.preview.agent"
unregister_argument="--unregister-preview-helper"
preview_app_executable=""

if [[ -e "${installed_app_path}" ]]; then
  bundle_id="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "${installed_app_path}/Contents/Info.plist" 2>/dev/null || true)"
  product_variant="$(/usr/libexec/PlistBuddy -c 'Print :KeyProductVariant' "${installed_app_path}/Contents/Info.plist" 2>/dev/null || true)"
  if [[ "${bundle_id}" != "${app_id}" || "${product_variant}" != "preview" ]]; then
    echo "refusing to remove app with unexpected identity at ${installed_app_path}" >&2
    exit 1
  fi
  app_executable="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "${installed_app_path}/Contents/Info.plist" 2>/dev/null || true)"
  preview_app_executable="${installed_app_path}/Contents/MacOS/${app_executable}"
  if [[ -z "${app_executable}" || ! -x "${preview_app_executable}" ]]; then
    echo "refusing to remove a Preview app without its executable at ${installed_app_path}" >&2
    exit 1
  fi
fi

if [[ -e "${cli_link_path}" || -L "${cli_link_path}" ]]; then
  if [[ ! -L "${cli_link_path}" ]]; then
    echo "refusing to remove non-symlink CLI path ${cli_link_path}" >&2
    exit 1
  fi
  target="$(readlink "${cli_link_path}")"
  if [[ "${target}" != "${installed_cli_path}" ]]; then
    echo "refusing to remove key-preview symlink targeting ${target}" >&2
    exit 1
  fi
fi

if [[ "${KEY_PREVIEW_SKIP_PROCESS_STOP:-0}" != "1" ]]; then
  osascript -e "tell application id \"${app_id}\" to quit" >/dev/null 2>&1 || true
fi

if [[ -n "${preview_app_executable}" ]]; then
  if ! "${preview_app_executable}" "${unregister_argument}"; then
    echo "Key Preview was preserved because its helper could not be unregistered." >&2
    exit 1
  fi
fi

if [[ "${KEY_PREVIEW_SKIP_PROCESS_STOP:-0}" != "1" ]]; then
  # SMAppService owns registration. This is only a fallback for inconsistent
  # local development state left by an older build or interrupted install.
  launchctl bootout "gui/$(id -u)/${agent_label}" >/dev/null 2>&1 || true
fi

if [[ -L "${cli_link_path}" ]]; then
  rm -- "${cli_link_path}"
fi
if [[ -e "${installed_app_path}" ]]; then
  rm -rf -- "${installed_app_path}"
fi

echo "Removed the isolated Preview installation:"
echo "  app: ${installed_app_path}"
echo "  CLI: ${cli_link_path}"
echo
echo "Preview configuration, vault files, and Keychain state were preserved."
echo "Stable Key was not changed."
