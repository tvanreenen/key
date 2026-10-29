#!/bin/zsh
set -euo pipefail
cd "$(dirname "$0")/.."

# Include new files during local development as well as committed scripts.
while IFS= read -r -d '' script_path; do
  zsh -n "${script_path}"
done < <(git ls-files --cached --others --exclude-standard -z -- '*.sh' 'completions/*' 'Tests/ScriptFixtures/.zshenv')
print 'Verified Zsh script and completion syntax.'
