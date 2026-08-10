#!/bin/zsh
set -euo pipefail

if [[ $# -ne 0 ]]; then
  echo "usage: $0" >&2
  exit 1
fi

script_dir="$(cd "$(dirname "$0")" && pwd)"
project_file="${script_dir}/../Key.xcodeproj/project.pbxproj"

if [[ ! -f "${project_file}" ]]; then
  echo "missing Xcode project at ${project_file}" >&2
  exit 1
fi

marketing_versions="$(
  awk -F' = |;' '
    /MARKETING_VERSION = / { print $2 }
  ' "${project_file}" | sort -u
)"

build_versions="$(
  awk -F' = |;' '
    /CURRENT_PROJECT_VERSION = / { print $2 }
  ' "${project_file}" | sort -u
)"

if [[ -z "${marketing_versions}" || -z "${build_versions}" ]]; then
  echo "failed to read version fields from ${project_file}" >&2
  exit 1
fi

if [[ "$(printf '%s\n' "${marketing_versions}" | wc -l | tr -d ' ')" -ne 1 ]]; then
  echo "expected a single MARKETING_VERSION value in ${project_file}" >&2
  printf '%s\n' "${marketing_versions}" >&2
  exit 1
fi

if [[ "$(printf '%s\n' "${build_versions}" | wc -l | tr -d ' ')" -ne 1 ]]; then
  echo "expected a single CURRENT_PROJECT_VERSION value in ${project_file}" >&2
  printf '%s\n' "${build_versions}" >&2
  exit 1
fi

if [[ ! "${build_versions}" =~ ^[0-9]+$ ]]; then
  echo "CURRENT_PROJECT_VERSION must be numeric (found ${build_versions})" >&2
  exit 1
fi

printf '%s\t%s\n' "${marketing_versions}" "${build_versions}"
