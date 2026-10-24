#!/usr/bin/env bash
# ci-go-module-deps.sh — the in-repo import closure of every go.work module.
#
# Prints ONE JSON object on stdout:
#   { "<module dir>": ["github.com/vistasecurity/vistaplatform/shared/x", ...], ... }
# For each module in go.work's `use` block, the sorted, unique set of
# vistaplatform import paths reachable from ANY package in the module —
# including the module's own packages, test-only imports (`-test`), and both
# the default and the `-tags ee` build (their union), so an Enterprise-only
# import is never missed.
#
# This is what lets the PR gate's backend matrix (scripts/ci-backend-matrix.mjs)
# answer "which modules does a change to shared/<pkg> affect?" with the import
# graph instead of "all of them". It asks `go list`, the same resolver the
# build uses; there is no hand-kept dependency table to drift.
#
# Failure policy: any module whose closure cannot be listed is an ERROR (exit
# 1, the module named on stderr). The caller treats that as "run every leg" —
# a partial map must never read as "nothing depends on this package".
#
# Usage:  scripts/ci-go-module-deps.sh > deps.json
#         GOTOOLCHAIN is pinned to go.work's version (CLAUDE.md rule 1).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PREFIX="github.com/vistasecurity/vistaplatform/"
export GOTOOLCHAIN="go$(awk '/^go /{print $2; exit}' go.work)"
# Workspace mode: `go list` resolves every module through go.work (readonly is
# the only -mod it accepts). Missing modules are downloaded to the module cache.

modules="$(awk '/^use \(/{f=1;next} /^\)/{f=0} f{gsub(/[\t ]/,""); sub(/^\.\//,""); print}' go.work)"
[ -n "$modules" ] || { echo "ci-go-module-deps: go.work lists no modules" >&2; exit 1; }

closure() { # <module dir> → import paths, one per line (empty on failure, rc≠0)
  local m="$1"
  (
    cd "$m"
    go list -deps -test -f '{{.ImportPath}}' ./...
    go list -deps -test -tags ee -f '{{.ImportPath}}' ./...
  ) \
    | sed -E 's/ \[.*\]$//; s/\.test$//; s/_test$//' \
    | grep -E "^${PREFIX}" \
    | sort -u
}

printf '{'
first=1
while IFS= read -r m; do
  [ -n "$m" ] || continue
  if ! paths="$(closure "$m" 2>"${TMPDIR:-/tmp}/ci-go-module-deps.err")"; then
    echo "ci-go-module-deps: cannot list the import closure of module '$m':" >&2
    sed 's/^/  /' "${TMPDIR:-/tmp}/ci-go-module-deps.err" >&2
    exit 1
  fi
  [ -n "$paths" ] || { echo "ci-go-module-deps: module '$m' yielded an EMPTY closure (not even its own packages)" >&2; exit 1; }
  [ "$first" = 1 ] || printf ','
  first=0
  printf '"%s":[' "$m"
  sep=""
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    printf '%s"%s"' "$sep" "$p"; sep=","
  done <<< "$paths"
  printf ']'
done <<< "$modules"
printf '}\n'
