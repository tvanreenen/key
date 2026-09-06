#!/bin/zsh
set -euo pipefail

# Pass a freshly built CLI. Every invocation below is help, version, or an
# invalid command: none may request authentication or touch a real vault.
cli="${1:?usage: help-tests.sh /path/to/built/key}"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/key-help-tests.XXXXXX")"
trap 'rm -f -- "$scratch/stdout" "$scratch/stderr"; rmdir "$scratch"' EXIT

topics=(
  '' init share config migrate status conflict get copy add edit duplicate
  rename remove unlock lock list version
  'config get' 'config set' 'config list'
  'conflict list' 'conflict show' 'conflict get' 'conflict copy' 'conflict resolve'
  'share devices' 'share invite' 'share invitations' 'share join' 'share requests'
  'share compare' 'share approve' 'share accept' 'share revoke'
)

for columns in 0 20 40 60 80 120 invalid; do
  for topic in "${topics[@]}"; do
    words=( ${=topic} )
    env COLUMNS="$columns" "$cli" "${words[@]}" --help >"$scratch/stdout" 2>"$scratch/stderr"
    [[ -s "$scratch/stdout" && ! -s "$scratch/stderr" ]]
    LC_ALL=C awk '
      /[[:cntrl:]]/ { exit 1 }
      /[[:blank:]]$/ { exit 1 }
      /^  -h, --help / {
        if (index($0, "Show") && index($0, "Show") != 27) exit 1
        foundHelp = 1
      }
      END { if (!foundHelp) exit 1 }
    ' "$scratch/stdout"
    if [[ "$columns" == 80 || "$columns" == 120 || "$columns" == invalid ]]; then
      LC_ALL=C awk 'length($0) > 80 && $0 !~ /^USAGE:/ { exit 1 }' "$scratch/stdout"
    fi
  done
  result=0
  env COLUMNS="$columns" "$cli" >"$scratch/stdout" 2>"$scratch/stderr" || result=$?
  [[ "$result" == 2 && ! -s "$scratch/stdout" && -s "$scratch/stderr" ]]
done

# Verify option descriptions and their wrapped continuations share column 27.
COLUMNS=80 "$cli" share join --help >"$scratch/stdout"
awk '
  /^  <invitation-id>/ { if (index($0, "The") != 27) exit 1; argumentsSeen++ }
  /^  --name / { if (index($0, "This") != 27) exit 1; optionsSeen++ }
  /^  --vault-dir / { if (index($0, "An") != 27) exit 1; optionsSeen++ }
  /^ +once\./ { if (index($0, "once.") != 27) exit 1; continuationSeen++ }
  END { if (argumentsSeen != 1 || optionsSeen != 2 || continuationSeen != 1) exit 1 }
' "$scratch/stdout"

# Built-in help takes precedence, including over otherwise invalid input.
"$cli" migrate --apply --help >"$scratch/stdout" 2>"$scratch/stderr"
[[ ! -s "$scratch/stderr" ]]
"$cli" help share accept >"$scratch/stdout" 2>"$scratch/stderr"
[[ ! -s "$scratch/stderr" ]]

result=0
"$cli" migrate --check --apply >"$scratch/stdout" 2>"$scratch/stderr" || result=$?
[[ "$result" == 2 && ! -s "$scratch/stdout" && -s "$scratch/stderr" ]]

"$cli" version --json >"$scratch/stdout" 2>"$scratch/stderr"
[[ ! -s "$scratch/stderr" ]]
plutil -convert xml1 -o /dev/null -- "$scratch/stdout"

# Generated completions must also be a local presentation-only operation.
"$cli" --generate-completion-script zsh >"$scratch/stdout" 2>"$scratch/stderr"
[[ ! -s "$scratch/stderr" ]]
zsh -n "$scratch/stdout"

print 'CLI help, alignment, width bounds, output streams, usage exit, version JSON, and generated completion checks passed.'
