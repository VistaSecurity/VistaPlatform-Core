#!/usr/bin/env bash
# ci-leg-input-hash.sh <leg name> <module dir> — the content key of ONE backend
# leg's inputs at HEAD, as an Actions-cache key:
#
#   verified-v1-<leg>-<sha256>
#
# A backend-check leg's result is a pure function of these git trees:
#   * the module itself,
#   * shared/ (every module imports it; nested shared/rbac is inside),
#   * go.work and go.work.sum (the workspace and its module graph),
#   * the PR gate workflow (step list, tool versions, Go version, flags),
#   * .github/actions/ (the libpcap composite action),
#   * scripts/ (the leg's steps call ci-run-shared-test-passes.sh,
#     go-module-has-ee.sh and the generators the shared leg's tests need),
#   * .golangci.yml if present (the lint ruleset).
#
# A green leg saves a marker under this key (ci.yml backend-check); on a
# later run — a re-push that touched only the UI, a merge from main that
# touched other modules — detect-changes asks the cache for the key and
# drops a leg whose exact input trees were already verified. The hash is
# over git TREE ids, so it costs nothing and cannot disagree between the two
# jobs as long as both run on the same commit (github.sha for the run).
#
# v1 in the key is the schema: bump it whenever the input list changes, or
# markers written under the old list would read as verified.
#
# Exit non-zero (and print nothing on stdout) if a tree cannot be resolved;
# the caller must then fail OPEN (run the leg), never skip.

set -euo pipefail

LEG="${1:?leg name}"
MODULE="${2:?module dir}"
[ -d "$MODULE" ] || { echo "ci-leg-input-hash: no such module dir '$MODULE'" >&2; exit 1; }

inputs=(
  "$MODULE"
  shared
  go.work
  go.work.sum
  .github/workflows/ci.yml
  .github/actions
  scripts
  .golangci.yml
)

parts=""
for p in "${inputs[@]}"; do
  if id="$(git rev-parse -q --verify "HEAD:$p" 2>/dev/null)"; then
    parts+="$p=$id"$'\n'
  else
    # Optional inputs (.golangci.yml, go.work.sum) may be absent; a REQUIRED
    # one missing means the checkout is not what we think it is.
    case "$p" in
      .golangci.yml|go.work.sum) parts+="$p=absent"$'\n' ;;
      *) echo "ci-leg-input-hash: cannot resolve HEAD:$p" >&2; exit 1 ;;
    esac
  fi
done

hash="$(printf '%s' "$parts" | sha256sum | cut -d' ' -f1)"
echo "verified-v1-${LEG}-${hash}"
