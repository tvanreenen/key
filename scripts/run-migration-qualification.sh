#!/bin/zsh
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
run_root="$(mktemp -d "${TMPDIR:-/tmp}/key-migration-qualification-run.XXXXXX")"
helper_wait_seconds="${KEY_MIGRATION_QUALIFICATION_HELPER_WAIT_SECONDS:-120}"
namespace_prefix="${KEY_MIGRATION_QUALIFICATION_NAMESPACE_PREFIX:-migration}"
rebuild_apps="${KEY_MIGRATION_QUALIFICATION_REBUILD:-1}"
scenario_text="${KEY_MIGRATION_QUALIFICATION_SCENARIOS:-invalid small large}"
scenarios=(${=scenario_text})
protected_before="${run_root}/protected-before.sha256"
protected_after="${run_root}/protected-after.sha256"

if [[ ! "${helper_wait_seconds}" =~ '^[1-9][0-9]*$' ]]; then
  echo "helper wait must be a positive number of seconds" >&2
  exit 1
fi
if [[ ! "${namespace_prefix}" =~ '^[a-z0-9][a-z0-9-]{0,31}$' ]]; then
  echo "qualification namespace prefix must match ^[a-z0-9][a-z0-9-]{0,31}$" >&2
  exit 1
fi
if [[ "${rebuild_apps}" != "0" && "${rebuild_apps}" != "1" ]]; then
  echo "qualification rebuild flag must be 0 or 1" >&2
  exit 1
fi

snapshot_protected_state() {
  local output_path="$1"
  local protected_path
  : > "${output_path}"
  for protected_path in \
    "${HOME}/Library/Application Support/Key" \
    "${HOME}/Library/Application Support/Key Preview" \
    "${HOME}/.key" \
    "${HOME}/.key-preview"
  do
    if [[ -d "${protected_path}" ]]; then
      find "${protected_path}" -type f -exec shasum -a 256 {} +
    elif [[ -f "${protected_path}" ]]; then
      shasum -a 256 "${protected_path}"
    else
      echo "missing  ${protected_path}"
    fi
  done | LC_ALL=C sort > "${output_path}"
}

wait_for_helper() {
  local cli="$1"
  local label="$2"
  local diagnostic_path="$3"
  local deadline=$(( $(date +%s) + helper_wait_seconds ))

  while (( $(date +%s) < deadline )); do
    if launchctl print "gui/$(id -u)/${label}" >/dev/null 2>&1 \
      && "${cli}" status --json > "${diagnostic_path}" 2>&1
    then
      return
    fi
    sleep 1
  done

  echo "helper ${label} did not become ready within ${helper_wait_seconds} seconds" >&2
  if [[ -s "${diagnostic_path}" ]]; then
    sed -n '1,20p' "${diagnostic_path}" >&2
  fi
  exit 1
}

qualification_paths() {
  local scenario="$1"
  local namespace="${namespace_prefix}-${scenario}"
  local app="/Applications/Key Migration Qualification ${namespace}.app"
  local cli="${app}/Contents/MacOS/key"

  if [[ ! -x "${cli}" || "${rebuild_apps}" == "1" ]]; then
    KEY_MIGRATION_QUALIFICATION_NAMESPACE="${namespace}" \
      "${script_dir}/install-migration-qualification-app.sh"
  fi

  open -n "${app}"
  wait_for_helper \
    "${cli}" \
    "work.tvr.key.agent.qualification.${namespace}" \
    "${run_root}/${scenario}-helper.txt"

  reply=("${namespace}" "${app}" "${cli}")
}

select_v2_root() {
  local cli="$1"
  local label="$2"
  local root="$3"
  local diagnostic_path="$4"

  mkdir -p "${root}"
  "${cli}" config set vault-dir "${root}"
  wait_for_helper "${cli}" "${label}" "${diagnostic_path}"
}

hash_v2_source() {
  local root="$1"
  local output_path="$2"
  find "${root}" -type f -name '*.secret' -exec shasum -a 256 {} + \
    | LC_ALL=C sort > "${output_path}"
}

hash_secret_values() {
  local cli="$1"
  local names_path="$2"
  local output_path="$3"
  local name
  : > "${output_path}"
  while IFS= read -r name; do
    printf '%s  %s\n' \
      "$("${cli}" get "${name}" | shasum -a 256 | awk '{print $1}')" \
      "${name}" >> "${output_path}"
  done < "${names_path}"
}

require_inventory() {
  local cli="$1"
  local expected_path="$2"
  local actual_path="$3"
  "${cli}" list > "${actual_path}"
  cmp "${expected_path}" "${actual_path}"
}

require_totp_reads() {
  local cli="$1"
  local names_path="$2"
  local name code
  while IFS= read -r name; do
    code="$("${cli}" get "${name}")"
    if [[ ! "${code}" =~ '^[0-9]{6}$' ]]; then
      echo "TOTP entry ${name} did not produce a six-digit code" >&2
      exit 1
    fi
  done < "${names_path}"
}

require_no_plaintext_files() {
  local root="$1"
  local support_path="$2"
  if rg -a -l \
    'qualification-generated-secret|JBSWY3DPEHPK3PXP' \
    "${root}" "${support_path}" > "${run_root}/plaintext-matches.txt" 2>/dev/null
  then
    echo "qualification plaintext was found in a persistent file" >&2
    sed -n '1,20p' "${run_root}/plaintext-matches.txt" >&2
    exit 1
  fi
}

seed_entry() {
  local cli="$1"
  local name="$2"
  local type="$3"
  local value="$4"
  if [[ "${type}" == "totp" ]]; then
    printf '%s' "${value}" | "${cli}" add --totp "${name}"
  else
    printf '%s' "${value}" | "${cli}" add "${name}"
  fi
}

require_v3_mutation_roundtrip() {
  local cli="$1"
  local name="$2"
  local secret expected_hash actual_hash

  secret="qualification-generated-secret-$(openssl rand -base64 36)"
  expected_hash="$(printf '%s' "${secret}" | shasum -a 256 | awk '{print $1}')"
  printf '%s' "${secret}" | "${cli}" add "${name}"
  unset secret
  actual_hash="$("${cli}" get "${name}" | shasum -a 256 | awk '{print $1}')"
  if [[ "${actual_hash}" != "${expected_hash}" ]]; then
    echo "version 3 mutation round-trip hash did not match" >&2
    exit 1
  fi
  "${cli}" remove "${name}" --force
}

run_invalid_scenario() {
  qualification_paths invalid
  local namespace="${reply[1]}"
  local cli="${reply[3]}"
  local label="work.tvr.key.agent.qualification.${namespace}"
  local root="${run_root}/invalid-v2"
  local support_path="${HOME}/Library/Application Support/Key Qualification ${namespace}"
  local config_path="${support_path}/config.toml"
  local source_before="${run_root}/invalid-source-before.sha256"
  local source_after="${run_root}/invalid-source-after.sha256"
  local secret="qualification-generated-secret-$(openssl rand -hex 32)"

  select_v2_root "${cli}" "${label}" "${root}" "${run_root}/invalid-root-helper.txt"
  seed_entry "${cli}" 'invalid/control' secret "${secret}"
  unset secret
  plutil -replace ciphertext -string '@@@' "${root}/invalid/control.secret"

  hash_v2_source "${root}" "${source_before}"
  cp "${config_path}" "${run_root}/invalid-config-before.toml"

  if "${cli}" migrate --check > "${run_root}/invalid-check.txt" 2>&1; then
    echo "invalid migration preflight unexpectedly succeeded" >&2
    exit 1
  fi
  if "${cli}" migrate --apply > "${run_root}/invalid-apply.txt" 2>&1; then
    echo "invalid migration unexpectedly succeeded" >&2
    exit 1
  fi

  hash_v2_source "${root}" "${source_after}"
  cmp "${source_before}" "${source_after}"
  cmp "${run_root}/invalid-config-before.toml" "${config_path}"
  if rg -q '^vault_id[[:space:]]*=' "${config_path}"; then
    echo "invalid migration selected version 3" >&2
    exit 1
  fi
  require_no_plaintext_files "${root}" "${support_path}"
  echo "invalid: PASS" >> "${run_root}/summary.txt"
}

run_small_scenario() {
  qualification_paths small
  local namespace="${reply[1]}"
  local cli="${reply[3]}"
  local label="work.tvr.key.agent.qualification.${namespace}"
  local root="${run_root}/small-v2"
  local support_path="${HOME}/Library/Application Support/Key Qualification ${namespace}"
  local config_path="${support_path}/config.toml"
  local inventory_before="${run_root}/small-inventory-before.txt"
  local secret_names="${run_root}/small-secret-names.txt"
  local totp_names="${run_root}/small-totp-names.txt"
  local name secret

  select_v2_root "${cli}" "${label}" "${root}" "${run_root}/small-root-helper.txt"
  : > "${secret_names}"
  for name in \
    'accounts/github' \
    'accounts/email/personal' \
    'finance/card-backup' \
    'notes/unicode-λ' \
    'servers/production/root' \
    'wifi/home'
  do
    secret="qualification-generated-secret-$(openssl rand -base64 36)"
    [[ "${name}" == 'notes/unicode-λ' ]] && secret="${secret}"$'\nsecond line ☃'
    seed_entry "${cli}" "${name}" secret "${secret}"
    echo "${name}" >> "${secret_names}"
  done
  unset secret
  : > "${totp_names}"
  for name in 'totp/email' 'totp/source-control'; do
    seed_entry "${cli}" "${name}" totp 'JBSWY3DPEHPK3PXP'
    echo "${name}" >> "${totp_names}"
  done

  "${cli}" list > "${inventory_before}"
  [[ "$(wc -l < "${inventory_before}" | tr -d ' ')" == 8 ]]
  hash_v2_source "${root}" "${run_root}/small-source-before.sha256"
  hash_secret_values "${cli}" "${secret_names}" "${run_root}/small-values-before.sha256"
  cp "${config_path}" "${run_root}/small-v2-config.toml"

  "${cli}" migrate --check > "${run_root}/small-check.txt"
  "${cli}" migrate --apply > "${run_root}/small-apply.txt"
  rg -q 'Entries migrated: 8 \(6 secrets, 2 TOTP entries\)' "${run_root}/small-apply.txt"
  hash_v2_source "${root}" "${run_root}/small-source-after.sha256"
  cmp "${run_root}/small-source-before.sha256" "${run_root}/small-source-after.sha256"
  require_inventory "${cli}" "${inventory_before}" "${run_root}/small-inventory-v3.txt"
  hash_secret_values "${cli}" "${secret_names}" "${run_root}/small-values-v3.sha256"
  cmp "${run_root}/small-values-before.sha256" "${run_root}/small-values-v3.sha256"
  require_totp_reads "${cli}" "${totp_names}"
  require_v3_mutation_roundtrip "${cli}" 'qualification/post-migration-roundtrip'
  require_inventory "${cli}" "${inventory_before}" "${run_root}/small-inventory-post-mutation.txt"

  "${cli}" lock
  wait_for_helper "${cli}" "${label}" "${run_root}/small-restart-helper.txt"
  require_inventory "${cli}" "${inventory_before}" "${run_root}/small-inventory-restart.txt"

  "${cli}" lock
  cp "${run_root}/small-v2-config.toml" "${config_path}"
  wait_for_helper "${cli}" "${label}" "${run_root}/small-rollback-helper.txt"
  rg -q '"format":"v2"' "${run_root}/small-rollback-helper.txt"
  require_inventory "${cli}" "${inventory_before}" "${run_root}/small-inventory-rollback.txt"
  hash_secret_values "${cli}" "${secret_names}" "${run_root}/small-values-rollback.sha256"
  cmp "${run_root}/small-values-before.sha256" "${run_root}/small-values-rollback.sha256"
  require_no_plaintext_files "${root}" "${support_path}"
  echo "small: PASS" >> "${run_root}/summary.txt"
}

run_large_scenario() {
  qualification_paths large
  local namespace="${reply[1]}"
  local cli="${reply[3]}"
  local label="work.tvr.key.agent.qualification.${namespace}"
  local root="${run_root}/large-v2"
  local support_path="${HOME}/Library/Application Support/Key Qualification ${namespace}"
  local config_path="${support_path}/config.toml"
  local inventory_before="${run_root}/large-inventory-before.txt"
  local secret_names="${run_root}/large-secret-names.txt"
  local totp_names="${run_root}/large-totp-names.txt"
  local index group name secret

  select_v2_root "${cli}" "${label}" "${root}" "${run_root}/large-root-helper.txt"
  : > "${secret_names}"
  for index in {1..240}; do
    printf -v group '%02d' $(( index % 12 ))
    printf -v name 'folders/group-%s/secret-%03d' "${group}" "${index}"
    secret="qualification-generated-secret-$(openssl rand -base64 48)"
    (( index % 17 == 0 )) && secret="${secret}"$'\nmultiline λ ☃'
    seed_entry "${cli}" "${name}" secret "${secret}"
    echo "${name}" >> "${secret_names}"
  done
  unset secret
  : > "${totp_names}"
  for index in {1..60}; do
    printf -v name 'totp/team-%02d/account-%03d' $(( index % 8 )) "${index}"
    seed_entry "${cli}" "${name}" totp 'JBSWY3DPEHPK3PXP'
    echo "${name}" >> "${totp_names}"
  done

  "${cli}" list > "${inventory_before}"
  [[ "$(wc -l < "${inventory_before}" | tr -d ' ')" == 300 ]]
  hash_v2_source "${root}" "${run_root}/large-source-before.sha256"
  hash_secret_values "${cli}" "${secret_names}" "${run_root}/large-values-before.sha256"
  cp "${config_path}" "${run_root}/large-v2-config.toml"

  "${cli}" migrate --check > "${run_root}/large-check.txt"
  "${cli}" migrate --apply > "${run_root}/large-apply.txt"
  rg -q 'Entries migrated: 300 \(240 secrets, 60 TOTP entries\)' "${run_root}/large-apply.txt"
  hash_v2_source "${root}" "${run_root}/large-source-after.sha256"
  cmp "${run_root}/large-source-before.sha256" "${run_root}/large-source-after.sha256"
  require_inventory "${cli}" "${inventory_before}" "${run_root}/large-inventory-v3.txt"
  hash_secret_values "${cli}" "${secret_names}" "${run_root}/large-values-v3.sha256"
  cmp "${run_root}/large-values-before.sha256" "${run_root}/large-values-v3.sha256"
  require_totp_reads "${cli}" "${totp_names}"
  require_v3_mutation_roundtrip "${cli}" 'qualification/post-migration-roundtrip'
  require_inventory "${cli}" "${inventory_before}" "${run_root}/large-inventory-post-mutation.txt"

  "${cli}" lock
  wait_for_helper "${cli}" "${label}" "${run_root}/large-restart-helper.txt"
  require_inventory "${cli}" "${inventory_before}" "${run_root}/large-inventory-restart.txt"

  "${cli}" lock
  cp "${run_root}/large-v2-config.toml" "${config_path}"
  wait_for_helper "${cli}" "${label}" "${run_root}/large-rollback-helper.txt"
  rg -q '"format":"v2"' "${run_root}/large-rollback-helper.txt"
  require_inventory "${cli}" "${inventory_before}" "${run_root}/large-inventory-rollback.txt"
  hash_secret_values "${cli}" "${secret_names}" "${run_root}/large-values-rollback.sha256"
  cmp "${run_root}/large-values-before.sha256" "${run_root}/large-values-rollback.sha256"
  require_no_plaintext_files "${root}" "${support_path}"
  echo "large: PASS" >> "${run_root}/summary.txt"
}

snapshot_protected_state "${protected_before}"
: > "${run_root}/summary.txt"

for scenario in "${scenarios[@]}"; do
  case "${scenario}" in
    invalid) run_invalid_scenario ;;
    small) run_small_scenario ;;
    large) run_large_scenario ;;
    *)
      echo "unsupported qualification scenario: ${scenario}" >&2
      exit 1
      ;;
  esac
done

snapshot_protected_state "${protected_after}"
cmp "${protected_before}" "${protected_after}"
launchctl print "gui/$(id -u)/work.tvr.key.agent" >/dev/null
launchctl print "gui/$(id -u)/work.tvr.key.preview.agent" >/dev/null

echo "protected Stable/Preview files: PASS" >> "${run_root}/summary.txt"
echo
cat "${run_root}/summary.txt"
echo
echo "Qualification evidence (hashes and reports only): ${run_root}"
echo "Qualification Keychain and Secure Enclave records were retained for inspection."
