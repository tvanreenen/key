#!/bin/zsh
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <app-path>" >&2
  exit 1
fi

app_path="$1"
script_dir="$(cd "$(dirname "$0")" && pwd)"

"${script_dir}/verify-signing.sh" "${app_path}"

echo
echo "== Gatekeeper =="
spctl --assess --type execute --verbose "${app_path}"
