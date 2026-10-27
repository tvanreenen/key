#!/bin/zsh
set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 ]]; then
  echo "usage: $0 <stable|preview> <debug|release> <build|bundle|cli|codeql> [derived-data-path]" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
variant="$1"
mode="$2"
operation="$3"
derived_data="${4:-${repo_root}/.build/verification/products-${variant}}"

case "${variant}" in
  stable) scheme=Key; app=Key.app; cli=key; configuration=Debug ;;
  preview) scheme='Key Preview'; app='Key Preview.app'; cli=key-preview; configuration=PreviewDebug ;;
  *) echo 'expected stable or preview' >&2; exit 1 ;;
esac
case "${mode}" in
  debug) ;;
  release) configuration="${configuration/Debug/Release}" ;;
  *) echo 'expected debug or release' >&2; exit 1 ;;
esac

product="${derived_data}/Build/Products/${configuration}/${app}"
cd "${repo_root}"
case "${operation}" in
  build|codeql)
    extraction_settings=()
    build_destination='platform=macOS,arch=arm64'
    if [[ "${operation}" == codeql ]]; then
      # The x86_64 CodeQL tracer can make Xcode enumerate only a Rosetta
      # "My Mac" destination. Analysis builds do not need a runnable device.
      build_destination='generic/platform=macOS'
      # CodeQL must observe compiler subprocesses instead of in-process or
      # cached compilation. Keep these tracing settings out of product builds.
      extraction_settings=(
        CODE_SIGNING_REQUIRED=NO
        COMPILATION_CACHE_ENABLE_CACHING=NO
        SWIFT_ENABLE_COMPILE_CACHE=NO
        SWIFT_USE_INTEGRATED_DRIVER=NO
      )
    fi
    xcodebuild \
      -project Key.xcodeproj \
      -scheme "${scheme}" \
      -configuration "${configuration}" \
      -destination "${build_destination}" \
      -derivedDataPath "${derived_data}" \
      -onlyUsePackageVersionsFromResolvedFile \
      ARCHS=arm64 \
      CODE_SIGNING_ALLOWED=NO \
      "${extraction_settings[@]}" \
      build
    ;;
  bundle) scripts/verify-product-bundle.sh "${variant}" "${product}" ;;
  cli) zsh Tests/CLIScripts/help-tests.sh "${product}/Contents/MacOS/${cli}" ;;
  *) echo 'expected build, bundle, cli, or codeql' >&2; exit 1 ;;
esac
