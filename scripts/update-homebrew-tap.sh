#!/bin/zsh
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <tag> <download-url> <sha256>" >&2
  exit 1
fi

version="$1"
download_url="$2"
sha256="$3"
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
IFS=$'\t' read -r product_variant cask_token expected_artifact_name \
  <<< "$("${repo_root}/scripts/release-target.sh" "${version}")"
tap_repo_root="${KEY_TAP_REPO:-$HOME/Code/homebrew-tap}"

download_asset_name="${download_url##*/}"
if [[ "${download_asset_name}" != "${expected_artifact_name}" ]]; then
  echo "${version} requires ${expected_artifact_name}, not ${download_asset_name}" >&2
  exit 1
fi

if [[ ! -d "${tap_repo_root}" ]]; then
  echo "missing Homebrew tap checkout at ${tap_repo_root}" >&2
  echo "clone https://github.com/tvanreenen/homebrew-tap or set KEY_TAP_REPO" >&2
  exit 1
fi

tap_repo="$(cd "${tap_repo_root}" && pwd)"
cask_dir="${tap_repo}/Casks"
cask_path="${cask_dir}/${cask_token}.rb"
homepage="https://github.com/tvanreenen/key"

case "${product_variant}" in
  stable)
    display_name="Key"
    app_name="Key.app"
    cli_name="key"
    helper_name="Key Agent"
    conflicts_clause=""
    completion_clause='  zsh_completion "completions/_key"'
    ;;
  preview)
    display_name="Key Preview"
    app_name="Key Preview.app"
    cli_name="key-preview"
    helper_name="Key Preview Agent"
    completion_clause=""
    case "${cask_token}" in
      key@alpha)
        conflicting_casks='["key@beta", "key@rc"]'
        ;;
      key@beta)
        conflicting_casks='["key@alpha", "key@rc"]'
        ;;
      key@rc)
        conflicting_casks='["key@alpha", "key@beta"]'
        ;;
    esac
    conflicts_clause="  conflicts_with cask: ${conflicting_casks}"
    ;;
esac

if [[ -n "$(git -C "${tap_repo}" status --porcelain)" ]]; then
  echo "Homebrew tap repo has local changes; clean or commit them before updating the cask." >&2
  exit 1
fi

git -C "${tap_repo}" fetch origin
git -C "${tap_repo}" pull --ff-only

mkdir -p "${cask_dir}"

cat > "${cask_path}" <<EOF
cask "${cask_token}" do
  version "${version}"
  sha256 "${sha256}"

  url "${download_url}"
  name "${display_name}"
  desc "File-based secret manager with native authentication"
  homepage "${homepage}"

${conflicts_clause}
  depends_on macos: :tahoe

  app "${app_name}"
  binary "#{appdir}/${app_name}/Contents/MacOS/${cli_name}", target: "${cli_name}"
${completion_clause}

  caveats <<~EOS
    Open ${app_name} once after install so it can register ${helper_name} with macOS before you use the ${cli_name} CLI.
  EOS
end
EOF

echo "Updated cask:"
echo "  ${cask_path}"
echo
echo "Next:"
echo "  git -C \"${tap_repo}\" diff -- \"Casks/${cask_token}.rb\""
echo "  just publish-homebrew-tap \"${version}\""
