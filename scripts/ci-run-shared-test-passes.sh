#!/usr/bin/env bash
# Run the PR gate's two shared/ test passes CONCURRENTLY and fail if either
# fails. Used by ci.yml's backend-check `shared` leg.
#
#   pass 1 "plain"      — go test ./...
#   pass 2 "ambient-db" — go test -count=1 ./... with DATABASE_URL pointing at a
#                         port nothing listens on (see the comment on the step in
#                         ci.yml for why this pass exists; it is a guard, keep it)
#
# Usage: ci-run-shared-test-passes.sh <module-dir>
# Env:   AMBIENT_DATABASE_URL  the unreachable DSN for pass 2 (required)
#        GO                    go binary to run (default: go; the test seam)
#
# Each pass writes its own log and returns its own exit code. Both logs are
# printed in full, each under a header naming its pass and exit code, after
# both have finished, so the output is never interleaved. The script exits
# non-zero if EITHER pass did. Before this, the passes were two sequential
# steps, which took ~75s each on the shared leg. A red first pass also
# stopped the job before the guard pass ran.
#
# Regression test: scripts/test-ci-run-shared-test-passes.sh
# (`make shared-test-passes-test`), which checks both polarities with a stub go.

set -uo pipefail

MODULE_DIR="${1:?usage: ci-run-shared-test-passes.sh <module-dir>}"
: "${AMBIENT_DATABASE_URL:?AMBIENT_DATABASE_URL must be set — without it pass 2 is just pass 1 again, and the guard is inert}"
GO="${GO:-go}"

LOG_DIR="$(mktemp -d "${RUNNER_TEMP:-/tmp}/shared-test-passes.XXXXXX")"
PLAIN_LOG="$LOG_DIR/plain.log"
AMBIENT_LOG="$LOG_DIR/ambient-db.log"

cd "$MODULE_DIR" || { echo "::error::cannot cd to $MODULE_DIR"; exit 1; }

# Pass 2 must not inherit a real DATABASE_URL from the environment either way:
# pass 1 runs with none (what the PR gate has always done), pass 2 with the
# unreachable one.
env -u DATABASE_URL "$GO" test ./... >"$PLAIN_LOG" 2>&1 &
plain_pid=$!
DATABASE_URL="$AMBIENT_DATABASE_URL" "$GO" test -count=1 ./... >"$AMBIENT_LOG" 2>&1 &
ambient_pid=$!

wait "$plain_pid"; plain_rc=$?
wait "$ambient_pid"; ambient_rc=$?

print_log() { # <title> <rc> <file>
  echo "════════════════════════════════════════════════════════════════════════"
  echo "  $1 — exit $2"
  echo "════════════════════════════════════════════════════════════════════════"
  cat "$3"
  echo
}
print_log "PASS 1 (plain): go test ./..." "$plain_rc" "$PLAIN_LOG"
print_log "PASS 2 (ambient-DB guard): DATABASE_URL=<unreachable> go test -count=1 ./..." "$ambient_rc" "$AMBIENT_LOG"

fail=0
if [ "$plain_rc" -ne 0 ]; then
  echo "::error::shared/ pass 1 (plain go test) failed with exit $plain_rc — see 'PASS 1' above"
  fail=1
fi
if [ "$ambient_rc" -ne 0 ]; then
  echo "::error::shared/ pass 2 (unreachable DATABASE_URL, ambient-DB guard) failed with exit $ambient_rc — see 'PASS 2' above. A test relying on the ambient tenant-state check needs an explicit TenantState."
  fail=1
fi
rm -rf "$LOG_DIR"
[ "$fail" -eq 0 ] && echo "✅ shared/: both passes green (plain, ambient-DB guard)"
exit "$fail"
