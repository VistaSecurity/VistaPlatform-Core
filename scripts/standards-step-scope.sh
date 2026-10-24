#!/usr/bin/env bash
# standards-step-scope.sh — which expensive steps of the standards PR gate a
# change can affect. Emits GITHUB_OUTPUT lines on stdout:
#
#   chart=<count of changed files the chart render tests read>
#
# The standards workflow deliberately has NO `paths:` filter (scripts/
# test-standards-workflow-gate.mjs refuses one): the audit and the export
# leak gate must see every PR. But the ~30 chart render tests plus helm lint
# cost ~110 s per PR and read a known set of inputs, so THAT STEP is gated
# here, inside the job, on whether any of those inputs changed. A Go-only or
# UI-only PR skips them; anything that can change a rendered chart runs them.
#
# Inputs the chart tests read (keep in step with scripts/test-chart-*.mjs,
# scripts/chart-*.mjs, scripts/stage-chart-seed-stub.sh and the Makefile
# chart-* targets): the chart itself, customer overlays, the registry and
# every standards/ catalogue, generator and test scripts, the public/ overlay,
# docs the chart references (chart-doc-refs-test), the OpenAPI specs, generated
# config, the Makefile, this workflow, compose files, every service's
# Dockerfiles and ee/ presence (chart-enterprise-services-test), and the two
# Go files individual tests parse (feed-spool reads admin-service's catalog
# feeds; ai-provider reads auth-service's ai_settings.go).
#
# Failure policy mirrors scripts/detect-changed-files.sh: a base commit that
# cannot be obtained, or any event that is not a pull_request, FAILS OPEN
# (chart=1). Skipping on a diff that could not be read is how a gate goes
# green having checked nothing.
#
# Inputs (environment):
#   EVENT_NAME    pull_request | anything else (→ fail open)
#   PR_BASE_SHA   github.event.pull_request.base.sha
#   PR_HEAD_SHA   github.event.pull_request.head.sha
#   GIT_REMOTE    remote to deepen from (default: origin)
#   CHANGED_FILES_OVERRIDE   test seam (newline-separated paths); CI never sets it

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVENT_NAME="${EVENT_NAME:-}"
PR_BASE_SHA="${PR_BASE_SHA:-}"
PR_HEAD_SHA="${PR_HEAD_SHA:-}"
GIT_REMOTE="${GIT_REMOTE:-origin}"

fail_open() {
  echo "::warning::standards-step-scope: $1 — running every step" >&2
  echo "chart=1"
  exit 0
}

if [ -n "${CHANGED_FILES_OVERRIDE+x}" ]; then
  CHANGED_FILES="$CHANGED_FILES_OVERRIDE"
elif [ "$EVENT_NAME" = "merge_queue" ]; then
  # A merge-queue candidate (merge-queue.yml): main + the PR as a merge commit.
  # Its diff against its first parent is exactly the PR's change as it lands.
  base="$(git rev-parse -q --verify HEAD^1 2>/dev/null || true)"
  [ -n "$base" ] || fail_open "merge_queue candidate has no first parent"
  CHANGED_FILES="$(git diff --name-only "$base" HEAD)"
else
  [ "$EVENT_NAME" = "pull_request" ] || fail_open "event '$EVENT_NAME' is not a pull_request"
  [ -n "$PR_BASE_SHA" ] && [ -n "$PR_HEAD_SHA" ] || fail_open "no base/head commit"
  "$SCRIPT_DIR/ci-ensure-commit.sh" "$PR_BASE_SHA" "$GIT_REMOTE" || fail_open "base commit $PR_BASE_SHA is unobtainable"
  "$SCRIPT_DIR/ci-ensure-commit.sh" "$PR_HEAD_SHA" "$GIT_REMOTE" || fail_open "head commit $PR_HEAD_SHA is unobtainable"
  CHANGED_FILES="$(git diff --name-only "$PR_BASE_SHA" "$PR_HEAD_SHA")"
fi

CHART_INPUTS='^(charts/|customer-packages/|standards/|scripts/|public/|docsv4/|api/|config/|Makefile$|\.github/workflows/standards\.yml$|docker-compose[^/]*\.yml$|services/[^/]+/(ee/|Dockerfile)|services/admin-service/internal/jobs/catalogfeeds/|services/auth-service/internal/api/ai_settings\.go$)'
CHART="$(printf '%s\n' "$CHANGED_FILES" | grep -cE "$CHART_INPUTS" || true)"

echo "chart=$CHART"
echo "standards-step-scope: chart render tests $([ "$CHART" = 0 ] && echo 'SKIPPED (no chart input changed)' || echo "armed by $CHART changed input(s)")" >&2
