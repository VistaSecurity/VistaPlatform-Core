#!/usr/bin/env bash
# verify-merge.sh — the verify-then-merge chain, as ONE set -e script.
#
# Run from a checkout of the PR branch that has origin/main merged in (or
# rebased onto it) with every conflict resolved. It verifies the merged tree
# and exits 0 only if every gate passes. It does NOT push or merge: landing
# is a separate, explicit step (and will be the merge queue's job).
#
# Why one script: on a verify-and-merge chain joined with `;`
# merged a PR after the schema harness and api-contract had FAILED. Every
# step here runs under `set -euo pipefail`; there is no way to reach the end
# with a failed gate.
#
# Gates re-run only when the merge from main touched their inputs. What the
# PR gate already verified is the PR head; what main added since is the diff
# PR-head → HEAD, so that is the diff that decides.
#
# Usage:
#   scripts/merge/verify-merge.sh [--since <sha>] [--base <ref>]
#     --since  the commit the PR gate verified (default: the merge-base of
#              HEAD and --base; pass the PR head for a merge-from-main checkout)
#     --base   the branch being merged into (default origin/main)
#     --all    ignore --since and run every gate

set -euo pipefail

root="$(git rev-parse --show-toplevel)"; cd "$root"
export PATH="$PATH:$(go env GOPATH)/bin"
# Pin to go.work's exact version (CLAUDE.md rule 1); never auto.
export GOTOOLCHAIN="go$(awk '/^go /{print $2; exit}' go.work)"

BASE="origin/main"; SINCE=""; ALL=0; DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --since)   SINCE="$2"; shift 2 ;;
    --base)    BASE="$2";  shift 2 ;;
    --all)     ALL=1; shift ;;
    --dry-run) DRY=1; shift ;;   # print what each gate would do; run nothing
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ -n "$SINCE" ] || SINCE="$(git merge-base HEAD "$BASE")"

CURRENT_STEP="(setup)"
step() { CURRENT_STEP="$*"; printf '\n── %s\n' "$*"; }
refuse() { echo "REFUSE at [$CURRENT_STEP]: $*" >&2; exit 1; }
# Gate output is captured and shown in full only on failure, so a green run
# stays readable and a red one shows the actual diagnostics. Any failing
# command names the gate it belonged to: a chain that stops silently is how
# a failed gate gets mistaken for a passed one. ONE trap — a second
# `trap … EXIT` would silently replace the first.
LOG="$(mktemp)"
on_exit() {
  rc=$?
  [ "$rc" = 0 ] || echo "verify-merge: FAILED at [$CURRENT_STEP] (exit $rc)" >&2
  rm -f "$LOG"
}
trap on_exit EXIT
run() {
  if [ "$DRY" = 1 ]; then echo "  would run: $*"; return 0; fi
  if "$@" >"$LOG" 2>&1; then
    last="$(tail -n 1 "$LOG")"; [ -z "$last" ] || echo "  $last"
  else
    rc=$?; sed 's/^/  /' "$LOG" >&2; return "$rc"
  fi
}

if [ "$ALL" = 1 ]; then changed="$(git ls-files)"; else changed="$(git diff --name-only "$SINCE" HEAD)"; fi
touched() { printf '%s\n' "$changed" | grep -qE "$1"; }

step "conflict markers"
# Only `<<<<<<< ` and `>>>>>>> ` (marker + space): a bare `=======` line is a
# Markdown setext underline and must not count.
if [ -n "$changed" ] && git grep -nE '^(<<<<<<<|>>>>>>>) ' -- $changed; then
  refuse "conflict markers present"
fi
echo "none"

step "stale-base guard (deletions / whole-file reverts against $BASE)"
run scripts/merge/stale-base-guard.sh "$BASE" HEAD

step "schema stamp (chart files/schema/schema.sha256 ↔ scripts/database/schema.sql)"
run node scripts/audit-schema-mirror.mjs --strict

step "OpenAPI YAML parses with unique keys"
# `yaml` lives in scripts/node_modules (the generators' deps); a worktree root
# often has no node_modules of its own.
openapi_check() {
  [ -d scripts/node_modules/yaml ] || (cd scripts && npm ci --no-fund --no-audit >/dev/null)
  node -e "const y=require('./scripts/node_modules/yaml');const fs=require('fs');for(const f of fs.readdirSync('api/openapi').filter(f=>f.endsWith('.yaml'))){y.parse(fs.readFileSync('api/openapi/'+f,'utf8'),{uniqueKeys:true})};console.log('openapi yaml ok')"
}
run openapi_check

step "api-contract"
api_contract() {
  (cd api && npm run generate --silent >/dev/null)
  if ! git diff --quiet -- api/clients/typescript; then
    refuse "generated TypeScript client drifted from api/openapi — run 'npm run generate' in api/ and commit"
  fi
  make api-contract >/dev/null 2>&1 || refuse "api-contract"
  echo "ok"
}
if [ "$ALL" = 1 ] || touched '^api/openapi/|^api/clients/|^services/.*handlers.*\.go$|^services/.*/cmd/.*\.go$'; then
  run api_contract
else echo "inputs unchanged since $(git rev-parse --short "$SINCE"), skipped"; fi

step "go build + vet (every go.work module touched)"
# Walk up from each changed Go file to its go.mod: exact for nested modules
# (shared/rbac inside shared/) and for any future layout. A go.work change
# means every module. No regex, nothing to fail quietly.
all_modules() { awk '/^use \(/{f=1;next} /^\)/{f=0} f{gsub(/[\t ]/,""); sub(/^\.\//,""); print}' go.work; }
mods=""
if [ "$ALL" = 1 ] || printf '%s\n' "$changed" | grep -qx 'go.work'; then
  mods="$(all_modules)"
else
  while IFS= read -r f; do
    case "$f" in *.go|go.mod|go.sum|*/go.mod|*/go.sum) ;; *) continue ;; esac
    d="$(dirname "$f")"
    while [ "$d" != "." ] && [ ! -f "$d/go.mod" ]; do d="$(dirname "$d")"; done
    [ -f "$d/go.mod" ] && mods="$mods"$'\n'"$d"
  done <<< "$changed"
  mods="$(printf '%s\n' "$mods" | grep -v '^$' | sort -u || true)"
fi
go_gate() { (cd "$1" && go build ./... && go vet ./... >/dev/null); }
if [ -n "$mods" ]; then
  while IFS= read -r m; do echo "  $m"; run go_gate "$m"; done <<< "$mods"
else echo "no Go module touched, skipped"; fi

step "schema applies twice (idempotency) + seed"
schema_twice() { bash scripts/database/tools/schema-normalised-dump.sh --twice scripts/database/schema.sql scripts/database/seed.sql >/dev/null && echo "ok"; }
if [ "$ALL" = 1 ] || touched '^scripts/database/|^charts/vistaplatform/files/schema/'; then
  run schema_twice
else echo "schema unchanged since $(git rev-parse --short "$SINCE"), skipped"; fi

step "frontend typecheck"
# A worktree root without node_modules resolves @vistasecurity/* from the MAIN
# checkout (CLAUDE.md "Fresh worktree setup"); install once if missing.
tsc_in() { [ -d node_modules ] || npm ci --no-fund --no-audit >/dev/null; (cd "$1" && npx tsc --noEmit -p .) && echo "$1 ok"; }
if [ "$ALL" = 1 ] || touched '^frontend-v2/|^packages/|^api/clients/'; then
  run tsc_in frontend-v2
else echo "frontend-v2 unchanged, skipped"; fi
if [ "$ALL" = 1 ] || touched '^admin-ui-v2/|^packages/|^api/clients/'; then
  run tsc_in admin-ui-v2
else echo "admin-ui-v2 unchanged, skipped"; fi

echo
if [ "$DRY" = 1 ]; then
  echo "DRY RUN complete: nothing verified (gates scoped to changes since $(git rev-parse --short "$SINCE"))"
else
  echo "VERIFIED: $(git rev-parse --short HEAD) (gates scoped to changes since $(git rev-parse --short "$SINCE"))"
fi
