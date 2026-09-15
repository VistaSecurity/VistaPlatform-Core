#!/usr/bin/env bash
# Discover every Go package that holds a DB-integration test.
#
#   scripts/integration-coverage.sh          # print the discovered packages
#   scripts/integration-coverage.sh --run    # run the ones the named legs miss
#
# WHY DISCOVERY RATHER THAN A LIST
#
# run-integration-db-tests.sh named its targets one by one, and every comment in
# that list is about something the list silently missed: shared/services, then
#'s entitlement tests, then sensor-manager's RLS tests during the v0.5.0
# regression, then eight more found in gate 1 — one of which (shared/query) was
# RED the whole time. The nightly job runs `go test ./...` per module and so
# always had them; a developer following the documented local command never did.
#
# The convention is the source: a DB-integration test is named `TestIntegration_`
# (per CLAUDE.md), so grepping for it finds every one of them without anybody
# remembering to add a line.
set -euo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-print}"

# Packages the named legs in run-integration-db-tests.sh already run, with
# flags or filters a blanket sweep cannot reproduce. Listed as MODULE:PACKAGE.
#
# Each entry means "already covered", never "skip": removing one makes the sweep
# run it twice, which is slow but not wrong. Adding one wrongly is the failure
# mode, so TestIntegrationRunnerCoversEveryPackage checks the other direction.
ALREADY_RUN=(
  "services/compliance-engine:./internal/services"
  "services/compliance-engine:./internal/jobs"
  "services/device-interrogation-service:./internal/services"
  "services/monitoring-service:./internal/services"
  "shared:./services"
  "shared:./database"
  "shared:./identity/postgres"
  "shared:./entitlements"
  "services/cbom-service:./..."
  "services/notification-service:./..."
  "services/monitoring-service:./..."
  "services/cluster-sensor-service:./..."
  "services/inventory-service:./..."
  "services/admin-service:./..."
  "services/auth-service:./..."
  "services/sensor-manager:./..."
)

# discover prints "<module> <package>" for every package holding a
# TestIntegration_ function.
discover() {
  local module pkg
  # `go list` per module would be cleaner but needs a toolchain download in a
  # cold container; grep over the tree is enough for a naming convention.
  grep -rl --include='*_test.go' 'func TestIntegration_' . 2>/dev/null \
    | grep -v '/node_modules/' \
    | while read -r f; do
        pkg="$(dirname "$f")"
        module="$pkg"
        while [ "$module" != "." ] && [ ! -f "$module/go.mod" ]; do
          module="$(dirname "$module")"
        done
        [ "$module" = "." ] && continue
        # Package path relative to its module.
        rel="./${pkg#"$module"/}"
        [ "$rel" = "./" ] && rel="./"
        printf '%s %s\n' "${module#./}" "$rel"
      done | sort -u
}

covered() {
  # Trailing slashes are noise: `./internal/services` and `./internal/services/`
  # name the same package, and a mismatch between the two spellings would make
  # this sweep run a named leg twice — slow, and confusing to read.
  local key="${1%/}"
  local entry
  for entry in "${ALREADY_RUN[@]}"; do
    local mod="${entry%%:*}" pkg="${entry#*:}"
    pkg="${pkg%/}"
    [ "$key" = "$mod $pkg" ] && return 0
    # A `./...` entry covers every package under that module.
    if [ "$pkg" = "./..." ] && [ "${key%% *}" = "$mod" ]; then
      return 0
    fi
  done
  return 1
}

FAILED=0
while read -r module pkg; do
  key="$module $pkg"
  if covered "$key"; then
    [ "$MODE" = "--run" ] || echo "covered   $key"
    continue
  fi
  if [ "$MODE" != "--run" ]; then
    echo "SWEEP     $key"
    continue
  fi
  echo "▶ sweep: $module $pkg"
  ( cd "$module" && go test "${GO_TEST_FLAGS:--v}" -count=1 -run Integration "$pkg" ) || FAILED=1
done < <(discover)

exit "$FAILED"
