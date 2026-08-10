#!/bin/zsh
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf -- "${test_root}"' EXIT

source_app="${test_root}/source/Key Preview.app"
applications_dir="${test_root}/Applications"
cli_bin_dir="${test_root}/bin"
installed_app="${applications_dir}/Key Preview.app"
cli_link="${cli_bin_dir}/key-preview"
maintenance_command_log="${test_root}/maintenance-command.log"

mkdir -p \
  "${source_app}/Contents/MacOS" \
  "${source_app}/Contents/Helpers/Key Preview Agent.app/Contents/MacOS" \
  "${source_app}/Contents/Library/LaunchAgents"

cat > "${source_app}/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>work.tvr.key.preview.app</string>
<key>CFBundleExecutable</key><string>KeyPreviewHost</string>
<key>KeyProductVariant</key><string>preview</string>
</dict></plist>
PLIST
cat > "${source_app}/Contents/Helpers/Key Preview Agent.app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>work.tvr.key.preview.xpc</string>
<key>CFBundleExecutable</key><string>Key Preview Agent</string>
<key>KeyProductVariant</key><string>preview</string>
</dict></plist>
PLIST
cat > "${source_app}/Contents/Library/LaunchAgents/work.tvr.key.preview.agent.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>work.tvr.key.preview.agent</string>
<key>BundleProgram</key><string>Contents/Helpers/Key Preview Agent.app/Contents/MacOS/Key Preview Agent</string>
<key>MachServices</key><dict>
<key>work.tvr.key.preview.agent</key><true/>
<key>work.tvr.key.preview.agent.status</key><true/>
</dict>
<key>SpawnConstraint</key><dict>
<key>signing-identifier</key><string>work.tvr.key.preview.xpc</string>
</dict>
</dict></plist>
PLIST
touch "${source_app}/Contents/MacOS/key-preview"
cat > "${source_app}/Contents/MacOS/KeyPreviewHost" <<'SCRIPT'
#!/bin/zsh
if [[ "$#" -ne 1 || "$1" != "--unregister-preview-helper" ]]; then
  exit 64
fi
print -r -- "$1" >> "${KEY_PREVIEW_TEST_COMMAND_LOG:?}"
if [[ "${KEY_PREVIEW_TEST_UNREGISTER_FAILURE:-0}" == "1" ]]; then
  exit 1
fi
SCRIPT
touch "${source_app}/Contents/Helpers/Key Preview Agent.app/Contents/MacOS/Key Preview Agent"
chmod +x \
  "${source_app}/Contents/MacOS/KeyPreviewHost" \
  "${source_app}/Contents/MacOS/key-preview" \
  "${source_app}/Contents/Helpers/Key Preview Agent.app/Contents/MacOS/Key Preview Agent"

KEY_PREVIEW_APPLICATIONS_DIR="${applications_dir}" \
KEY_PREVIEW_CLI_BIN_DIR="${cli_bin_dir}" \
KEY_PREVIEW_SKIP_PROCESS_STOP=1 \
  "${repo_root}/scripts/install-preview-app.sh" "${source_app}" >/dev/null

[[ -d "${installed_app}" ]]
[[ -L "${cli_link}" ]]
[[ "$(readlink "${cli_link}")" == "${installed_app}/Contents/MacOS/key-preview" ]]
"${repo_root}/scripts/verify-product-bundle.sh" preview "${installed_app}" >/dev/null
if "${repo_root}/scripts/verify-product-bundle.sh" stable "${installed_app}" >/dev/null 2>&1; then
  echo "expected product verification to reject a Preview app as Stable" >&2
  exit 1
fi

touch "${installed_app}/old-install-marker"
touch "${source_app}/new-install-marker"
rm "${cli_link}"
failure_bin="${test_root}/failure-bin"
mkdir -p "${failure_bin}"
cat > "${failure_bin}/mv" <<'SCRIPT'
#!/bin/zsh
if [[ "$#" -eq 2 && "$1" == */.key-preview-link.* && \
      "$2" == "${KEY_PREVIEW_TEST_CLI_LINK:?}" ]]; then
  exit 1
fi
exec /bin/mv "$@"
SCRIPT
chmod +x "${failure_bin}/mv"

if PATH="${failure_bin}:${PATH}" \
  KEY_PREVIEW_APPLICATIONS_DIR="${applications_dir}" \
  KEY_PREVIEW_CLI_BIN_DIR="${cli_bin_dir}" \
  KEY_PREVIEW_SKIP_PROCESS_STOP=1 \
  KEY_PREVIEW_TEST_CLI_LINK="${cli_link}" \
  "${repo_root}/scripts/install-preview-app.sh" "${source_app}" \
  >/dev/null 2>&1; then
  echo "expected installer to fail when the CLI link cannot be published" >&2
  exit 1
fi

[[ -f "${installed_app}/old-install-marker" ]]
[[ ! -e "${installed_app}/new-install-marker" ]]
[[ ! -e "${cli_link}" && ! -L "${cli_link}" ]]

mkdir -p "${test_root}/persistent-preview-state"
touch "${test_root}/persistent-preview-state/vault-marker"

KEY_PREVIEW_APPLICATIONS_DIR="${applications_dir}" \
KEY_PREVIEW_CLI_BIN_DIR="${cli_bin_dir}" \
KEY_PREVIEW_SKIP_PROCESS_STOP=1 \
KEY_PREVIEW_TEST_COMMAND_LOG="${maintenance_command_log}" \
  "${repo_root}/scripts/uninstall-preview-app.sh" >/dev/null

[[ ! -e "${installed_app}" ]]
[[ ! -L "${cli_link}" ]]
[[ -f "${test_root}/persistent-preview-state/vault-marker" ]]
[[ "$(cat "${maintenance_command_log}")" == "--unregister-preview-helper" ]]

KEY_PREVIEW_APPLICATIONS_DIR="${applications_dir}" \
KEY_PREVIEW_CLI_BIN_DIR="${cli_bin_dir}" \
KEY_PREVIEW_SKIP_PROCESS_STOP=1 \
  "${repo_root}/scripts/install-preview-app.sh" "${source_app}" >/dev/null

if KEY_PREVIEW_APPLICATIONS_DIR="${applications_dir}" \
  KEY_PREVIEW_CLI_BIN_DIR="${cli_bin_dir}" \
  KEY_PREVIEW_SKIP_PROCESS_STOP=1 \
  KEY_PREVIEW_TEST_COMMAND_LOG="${maintenance_command_log}" \
  KEY_PREVIEW_TEST_UNREGISTER_FAILURE=1 \
  "${repo_root}/scripts/uninstall-preview-app.sh" >/dev/null 2>&1; then
  echo "expected uninstall to stop when helper unregistration fails" >&2
  exit 1
fi

[[ -d "${installed_app}" ]]
[[ -L "${cli_link}" ]]

KEY_PREVIEW_APPLICATIONS_DIR="${applications_dir}" \
KEY_PREVIEW_CLI_BIN_DIR="${cli_bin_dir}" \
KEY_PREVIEW_SKIP_PROCESS_STOP=1 \
KEY_PREVIEW_TEST_COMMAND_LOG="${maintenance_command_log}" \
  "${repo_root}/scripts/uninstall-preview-app.sh" >/dev/null

mkdir -p "${installed_app}/Contents"
cat > "${installed_app}/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>work.tvr.key.app</string>
<key>KeyProductVariant</key><string>stable</string>
</dict></plist>
PLIST

if KEY_PREVIEW_APPLICATIONS_DIR="${applications_dir}" \
  KEY_PREVIEW_CLI_BIN_DIR="${cli_bin_dir}" \
  KEY_PREVIEW_SKIP_PROCESS_STOP=1 \
  "${repo_root}/scripts/install-preview-app.sh" "${source_app}" >/dev/null 2>&1; then
  echo "expected installer to reject a non-Preview app at the destination" >&2
  exit 1
fi

[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "${installed_app}/Contents/Info.plist")" == "work.tvr.key.app" ]]

echo "Preview install safety tests passed."
