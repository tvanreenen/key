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
cask_token="$("${repo_root}/scripts/homebrew-cask-token.sh" "${version}")"
tap_repo_root="${KEY_TAP_REPO:-$HOME/Code/homebrew-tap}"

if [[ ! -d "${tap_repo_root}" ]]; then
  echo "missing Homebrew tap checkout at ${tap_repo_root}" >&2
  echo "clone https://github.com/tvanreenen/homebrew-tap or set KEY_TAP_REPO" >&2
  exit 1
fi

tap_repo="$(cd "${tap_repo_root}" && pwd)"
cask_dir="${tap_repo}/Casks"
cask_path="${cask_dir}/${cask_token}.rb"
homepage="https://github.com/tvanreenen/key"

case "${cask_token}" in
  key)
    conflicting_casks='["key@alpha", "key@beta", "key@rc"]'
    ;;
  key@alpha)
    conflicting_casks='["key", "key@beta", "key@rc"]'
    ;;
  key@beta)
    conflicting_casks='["key", "key@alpha", "key@rc"]'
    ;;
  key@rc)
    conflicting_casks='["key", "key@alpha", "key@beta"]'
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
  name "key"
  desc "File-based secret manager with native authentication"
  homepage "${homepage}"

  conflicts_with cask: ${conflicting_casks}
  depends_on :macos

  app "Key.app"
  binary "#{appdir}/Key.app/Contents/MacOS/key", target: "key"
  zsh_completion "completions/_key"

  caveats <<~EOS
    Open Key.app once after install so it can register Key Agent with macOS before you use the key CLI.
  EOS
end
EOF

echo "Updated cask:"
echo "  ${cask_path}"
echo
echo "Next:"
echo "  git -C \"${tap_repo}\" diff -- \"Casks/${cask_token}.rb\""
echo "  just publish-homebrew-tap \"${version}\""
