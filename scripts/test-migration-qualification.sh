#!/bin/zsh
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"

cd "${repo_root}"
KEY_RUN_MIGRATION_QUALIFICATION=1 \
  swift test \
    --filter V3DeviceWrappedGenesisInstallerTests.migratesRealisticLargeMixedSnapshotWithoutChangingV2Source
