#!/bin/zsh
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .build/verification

# Local default is a full-history scan. CI supplies an introduced-commit range.
revision_range="${1:---all}"
if [[ "${revision_range}" != --all ]]; then
  if [[ "${revision_range}" != *..* || "${revision_range}" == -* ]]; then
    echo 'expected --all or a base..head commit range' >&2
    exit 1
  fi
  git rev-list "${revision_range}" >/dev/null
fi
python3 scripts/ci-tool.py run gitleaks git \
  --redact=100 --no-banner \
  --config .gitleaks.toml \
  --log-opts="${revision_range}" \
  --report-format json \
  --report-path .build/verification/secrets.json
