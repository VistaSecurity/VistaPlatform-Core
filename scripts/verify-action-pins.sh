#!/usr/bin/env bash
# Verify every third-party GitHub Action is pinned to a commit SHA that exists.
#
# Two failure modes, both of which have bitten this repository:
#
#   1. A pin that is not a SHA at all. Tag-pinned actions resolve to whatever
#      commit the maintainer points the tag at, so a compromised tag-mover lands
#      their code in our release pipeline. That policy is documented in
#      .github/workflows/PIN-ACTIONS.md; this enforces it.
#
#   2. A pin that is a SHA but does not exist. Found the hard way: the Core
#      release pipeline carried
#        docker/build-push-action@471d1dc4e07e5cdedd4c2171b7358c9fef2fb2b4
#      whose first 24 characters match the real v6.15.0 commit and whose tail is
#      invented. Nothing in the repo could tell the difference, because a SHA is
#      opaque by design — it looks equally correct whether or not it exists.
#      GitHub only discovers it when a runner tries to resolve the action, so it
#      failed 16 of 19 jobs on the first real Core build and not one moment
#      earlier. It fails closed, which is the one mercy: an unresolvable action
#      cannot execute. But it turns a release into a debugging session.
#
# Checked over the API rather than by pattern, because the only thing that can
# answer "does this commit exist" is the repository that would host it.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ "${VERIFY_ACTION_PINS:-1}" == "0" ]]; then
  echo "⚠️  action-pin verification disabled by VERIFY_ACTION_PINS=0"
  exit 0
fi

# Deliberately no silent degradation when the API is unreachable. A check that
# quietly passes when it cannot check is worse than no check: it reports the
# thing it did not do. Set VERIFY_ACTION_PINS=0 to opt out on purpose.
api() {
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    curl -sS -o /dev/null -w '%{http_code}' \
      -H "Authorization: Bearer ${GITHUB_TOKEN}" \
      -H "Accept: application/vnd.github+json" \
      "https://api.github.com/repos/$1/commits/$2"
  elif command -v gh >/dev/null 2>&1; then
    gh api "repos/$1/commits/$2" --jq '.sha' >/dev/null 2>&1 && echo 200 || echo 404
  else
    echo "❌ need either GITHUB_TOKEN or the gh CLI to verify action pins." >&2
    echo "   Set VERIFY_ACTION_PINS=0 to skip deliberately." >&2
    exit 2
  fi
}

files=$(
  [[ ! -d .github/workflows ]] || find .github/workflows \( -name '*.yml' -o -name '*.yaml' \)
  [[ ! -d .github/actions ]] || find .github/actions \( -name 'action.yml' -o -name 'action.yaml' \)
)
[[ -n "$files" ]] || { echo "no workflow files found"; exit 0; }

fail=0
checked=0

# Local actions (./.github/actions/...) and reusable workflows in this repo are
# not third-party and have no SHA to pin.
unpinned=$(
  grep -hoE '^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]+[^.#][^[:space:]]*' $files \
    | sed -E 's/^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]+//' \
    | grep -vE '@[0-9a-f]{40}$' \
    || true
)
if [[ -n "$unpinned" ]]; then
  echo "❌ actions not pinned to a commit SHA:"
  echo "$unpinned" | sed 's/^/     /'
  fail=1
fi

while read -r ref; do
  [[ -z "$ref" ]] && continue
  repo="${ref%@*}"
  sha="${ref#*@}"
  code=$(api "$repo" "$sha")
  checked=$((checked + 1))
  if [[ "$code" != "200" ]]; then
    echo "❌ $repo@${sha:0:12}… does not exist (HTTP $code)"
    fail=1
  fi
done < <(grep -hoE 'uses:[[:space:]]+[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+@[0-9a-f]{40}' $files | sed -E 's/uses:[[:space:]]+//' | sort -u)

if [[ "$fail" -ne 0 ]]; then
  echo "❌ action-pin verification FAILED" >&2
  exit 1
fi
echo "✅ $checked pinned action(s) verified, all resolve"
