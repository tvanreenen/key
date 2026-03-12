#!/bin/zsh
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <version> <download-url> <sha256>" >&2
  exit 1
fi

version="$1"
download_url="$2"
sha256="$3"
tap_repo_root="${KEY_TAP_REPO:-$HOME/Code/homebrew-tap}"

if [[ ! -d "${tap_repo_root}" ]]; then
  echo "missing Homebrew tap checkout at ${tap_repo_root}" >&2
  echo "clone https://github.com/tvanreenen/homebrew-tap or set KEY_TAP_REPO" >&2
  exit 1
fi

tap_repo="$(cd "${tap_repo_root}" && pwd)"
cask_dir="${tap_repo}/Casks"
cask_path="${cask_dir}/key.rb"
homepage="https://github.com/tvanreenen/key"

mkdir -p "${cask_dir}"

cat > "${cask_path}" <<EOF
cask "key" do
  version "${version}"
  sha256 "${sha256}"

  url "${download_url}"
  name "key"
  desc "macOS file-based secret manager with native auth"
  homepage "${homepage}"

  app "Key.app"
  binary "\#{appdir}/Key.app/Contents/MacOS/key", target: "key"
end
EOF

echo "Updated cask:"
echo "  ${cask_path}"
echo
echo "Next:"
echo "  git -C \"${tap_repo}\" diff -- Casks/key.rb"
echo "  git -C \"${tap_repo}\" add Casks/key.rb"
echo "  git -C \"${tap_repo}\" commit -m \"Update key cask to ${version}\""
