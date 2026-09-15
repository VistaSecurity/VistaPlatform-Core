#!/usr/bin/env bash
# Run golangci-lint over every Go module go.work declares — one module at a
# time, from INSIDE that module.
#
# WHY PER-MODULE: this repository is a multi-module go.work workspace with no
# module at the root. A root-level `golangci-lint run ./...` (or `./services/...`)
# cannot load anything — the go command refuses the pattern with
#
#   pattern ./...: directory prefix . does not contain modules listed in go.work
#
# and golangci-lint then prints "0 issues." next to that typechecking error. In
# 2.x that exits 7; older releases exited 0. Either way it has linted NOTHING,
# and `make lint` / `make standards-check` carried that false green for the
# life of the workspace (the "0 issues" false-green is recorded in the project
# notes; see also docsv4/internal/operations/INERT_GUARD_AUDIT.md).
#
# This script is the ONE implementation both `make lint` and
# scripts/enforce-standards.sh call, so the two gates cannot drift apart again.
#
# Usage:
#   scripts/lint-go.sh                                # every `use` entry in go.work
#   scripts/lint-go.sh services/auth-service sensor   # a subset (repo-relative dirs)
#
# Environment:
#   GOLANGCI_LINT_ARGS  extra golangci-lint arguments appended to every run,
#                       word-split (e.g. "--new-from-patch=/tmp/pr.patch --new=false"
#                       to lint diff-scoped the way CI does).
#   GOTOOLCHAIN         honoured when already set (`make` exports the exact pin);
#                       otherwise derived from go.work via scripts/lib/go-toolchain.sh
#                       so a direct invocation can never fall back to `auto`
#                       (Critical Rule #1).
#   GOLANGCI_LINT_CACHE honoured when already set (a caller that wants a
#                       specific cache location, e.g. CI, is never overridden);
#                       otherwise derived per WORKTREE from
#                       `git rev-parse --absolute-git-dir` (a git worktree's
#                       git-dir is its own `.git/worktrees/<name>`, distinct
#                       from every sibling worktree's) so this script never
#                       falls back to golangci-lint's default
#                       `~/.cache/golangci-lint`. That default is shared by
#                       every worktree of this repo on the host, and
#                       golangci-lint's cache keys packages by file path: a
#                       cache entry built while linting one worktree resolves
#                       to the SAME path in a sibling worktree, so once that
#                       sibling is deleted (or just holds different content at
#                       that path) the cached result is either stale or points
#                       at files that no longer exist — and a `//nolint`
#                       directive keyed to the wrong file content is silently
#                       unread, which is how `make standards-check` reported a
#                       false lint failure here three times in one week. Not a
#                       git checkout (or `git` unavailable): falls back to a
#                       location keyed by this repository's own path so
#                       unrelated checkouts on the same host still don't
#                       collide.
#
# Flags always passed:
#   --max-same-issues=0 --max-issues-per-linter=0
#       golangci-lint SILENTLY drops repeated findings past 3 and caps each
#       linter at 50. Every count quoted without these flags is wrong — that is
#       how real defects hid behind lint debt here once (sensor reported 49
#       findings; it had 72).
#   --allow-parallel-runners
#       concurrent runs on one host share ~/.cache/golangci-lint; without it a
#       sibling run dies with "parallel golangci-lint is running" (exit 3).
#   --path-prefix=<module>
#       findings print as repo-root-relative paths, so 21 modules' output
#       aggregates into something you can click on.
#
# Exit status: 0 when every module linted clean; 1 when any module reported
# findings, failed to typecheck, or is listed in go.work but missing from the
# tree; 127 when golangci-lint is not on PATH (callers that want to *skip* on
# an absent tool check `command -v golangci-lint` first — this script does not
# skip, because a lint step that quietly does nothing is the bug it replaces).

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT" || exit 1

# shellcheck source=scripts/lib/go-toolchain.sh
source "$SCRIPT_DIR/lib/go-toolchain.sh"
# shellcheck source=scripts/lib/golangci-cache.sh
source "$SCRIPT_DIR/lib/golangci-cache.sh"

if ! command -v golangci-lint >/dev/null 2>&1; then
    echo "❌ golangci-lint is not on PATH — install the release CI pins (see .github/workflows/ci.yml, GOLANGCI_LINT_VERSION) into a job-private directory, not \$HOME" >&2
    exit 127
fi

if [ ! -f go.work ]; then
    echo "❌ go.work not found at $ROOT — this repository is a Go workspace, so its absence is drift, not an empty tree" >&2
    exit 1
fi

if [ -z "${GOTOOLCHAIN:-}" ]; then
    GOTOOLCHAIN="$(go_toolchain_pin "$ROOT")"
    export GOTOOLCHAIN
fi

if [ -z "${GOLANGCI_LINT_CACHE:-}" ]; then
    # Derived BEFORE the per-module loop below `cd`s away from $ROOT —
    # golangci-lint resolves a relative GOLANGCI_LINT_CACHE against its OWN
    # cwd at run time, which would silently re-derive a different path (or
    # none) once we are three directories deep in a module. The function
    # (scripts/lib/golangci-cache.sh) always returns an absolute path.
    export GOLANGCI_LINT_CACHE="$(golangci_lint_cache_dir "$ROOT")"
fi

# Module list: the `use (...)` block of go.work, or the caller's subset.
MODULES=()
if [ "$#" -gt 0 ]; then
    MODULES=("$@")
else
    mapfile -t MODULES < <(awk '/^use \(/{f=1;next} /^\)/{f=0} f{gsub(/[ \t]/,"");print}' go.work)
fi
if [ "${#MODULES[@]}" -eq 0 ]; then
    echo "❌ go.work declares no modules (empty \`use (...)\` block) — nothing would be linted" >&2
    exit 1
fi

FLAGS=(--timeout=5m --allow-parallel-runners --max-same-issues=0 --max-issues-per-linter=0)
# Intentionally unquoted: GOLANGCI_LINT_ARGS is a word-split list of extra flags.
# shellcheck disable=SC2206
EXTRA=(${GOLANGCI_LINT_ARGS:-})

echo "golangci-lint $(golangci-lint version 2>/dev/null | head -1 | sed 's/^golangci-lint has //') · GOTOOLCHAIN=$GOTOOLCHAIN · GOLANGCI_LINT_CACHE=$GOLANGCI_LINT_CACHE · ${#MODULES[@]} module(s)"

FAILED=()
PASSED=0
for m in "${MODULES[@]}"; do
    m="${m#./}"
    m="${m%/}"
    if [ ! -f "$m/go.mod" ]; then
        echo "❌ $m: no go.mod there, but go.work (or the caller) lists it — fix go.work rather than skipping"
        FAILED+=("$m")
        continue
    fi
    echo "==> $m"
    # Capture rather than stream so the verdict can look at the output: a
    # typecheck failure is NOT a lint pass whatever the exit status says —
    # golangci-lint has printed "0 issues." next to a level=error line before.
    out="$(cd "$m" && golangci-lint run "${FLAGS[@]}" "${EXTRA[@]}" --path-prefix="$m" ./... 2>&1)"
    rc=$?
    [ -n "$out" ] && printf '%s\n' "$out"
    if [ "$rc" -ne 0 ] || grep -q 'level=error' <<<"$out"; then
        echo "❌ $m: golangci-lint exit $rc"
        FAILED+=("$m")
    else
        PASSED=$((PASSED + 1))
    fi
done

echo ""
if [ "${#FAILED[@]}" -gt 0 ]; then
    echo "❌ Go lint FAILED in ${#FAILED[@]} of ${#MODULES[@]} module(s): ${FAILED[*]}"
    exit 1
fi
echo "✅ Go lint clean: $PASSED/${#MODULES[@]} module(s)"
exit 0
