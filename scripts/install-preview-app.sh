#!/bin/zsh
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <built-preview-app>" >&2
  exit 1
fi

script_dir="$(cd "$(dirname "$0")" && pwd)"
source_app_path="$1"
applications_dir="${KEY_PREVIEW_APPLICATIONS_DIR:-/Applications}"
cli_bin_dir="${KEY_PREVIEW_CLI_BIN_DIR:-${HOME}/.local/bin}"
installed_app_path="${applications_dir}/Key Preview.app"
installed_cli_path="${installed_app_path}/Contents/MacOS/key-preview"
cli_link_path="${cli_bin_dir}/key-preview"
app_id="work.tvr.key.preview.app"
agent_label="work.tvr.key.preview.agent"

validate_preview_app() {
  local app_path="$1"
  "${script_dir}/verify-product-bundle.sh" preview "${app_path}" >/dev/null
}

validate_existing_cli_link() {
  if [[ ! -e "${cli_link_path}" && ! -L "${cli_link_path}" ]]; then
    return
  fi
  if [[ ! -L "${cli_link_path}" ]]; then
    echo "refusing to replace non-symlink CLI path ${cli_link_path}" >&2
    exit 1
  fi

  local target
  target="$(readlink "${cli_link_path}")"
  if [[ "${target}" != "${installed_cli_path}" ]]; then
    echo "refusing to replace key-preview symlink targeting ${target}" >&2
    exit 1
  fi
}

validate_preview_app "${source_app_path}"
if [[ -e "${installed_app_path}" ]]; then
  validate_preview_app "${installed_app_path}"
fi
validate_existing_cli_link

if [[ "${KEY_PREVIEW_SKIP_PROCESS_STOP:-0}" != "1" ]]; then
  osascript -e "tell application id \"${app_id}\" to quit" >/dev/null 2>&1 || true
  launchctl bootout "gui/$(id -u)/${agent_label}" >/dev/null 2>&1 || true
fi

mkdir -p "${applications_dir}" "${cli_bin_dir}"
staging_dir="$(mktemp -d "${applications_dir}/.key-preview-install.XXXXXX")"
trap 'rm -rf -- "${staging_dir}"' EXIT
staged_app_path="${staging_dir}/Key Preview.app"

ditto "${source_app_path}" "${staged_app_path}"
validate_preview_app "${staged_app_path}"

previous_app_path="${staging_dir}/Previous Key Preview.app"
if [[ -e "${installed_app_path}" ]]; then
  mv "${installed_app_path}" "${previous_app_path}"
fi
if ! mv "${staged_app_path}" "${installed_app_path}"; then
  if [[ -e "${previous_app_path}" ]]; then
    mv "${previous_app_path}" "${installed_app_path}"
  fi
  echo "failed to install Key Preview; the previous installation was restored" >&2
  exit 1
fi

if [[ -L "${cli_link_path}" ]]; then
  rm -- "${cli_link_path}"
fi
ln -s "${installed_cli_path}" "${cli_link_path}"

echo "Installed the isolated Preview product:"
echo "  app: ${installed_app_path}"
echo "  CLI: ${cli_link_path} -> ${installed_cli_path}"
echo
echo "Preview configuration, vault files, and Keychain state were preserved."
echo
echo "Next:"
echo "  open \"${installed_app_path}\""
echo "  key-preview status"
