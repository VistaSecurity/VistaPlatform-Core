#!/usr/bin/env bash
# queue-candidate.sh <pr-number> — build the merge CANDIDATE for a PR: main
# with the PR merged in as a merge commit (first parent = main), exactly the
# commit that will land. Runs from any checkout of the repo; leaves HEAD on
# the candidate (detached) and prints GITHUB_OUTPUT-style lines on stdout:
#
#   pr=<n>
#   head_sha=<PR head commit>
#   head_ref=<PR head branch>
#   base_sha=<main tip the candidate was built on>
#   candidate_sha=<the merge commit>
#   title=<PR title>
#
# Exit codes: 0 built; 3 merge conflict (the conflicting paths are printed on
# stderr and the merge is aborted); 4 the PR is not open / not mergeable by
# policy (draft, closed, cross-repository); 1 anything else.
#
# The merge message mirrors what `gh pr merge --merge` writes so history
# reads the same whichever path landed a PR.

set -euo pipefail

PR="${1:?pr number}"
REMOTE="${GIT_REMOTE:-origin}"

json="$(gh pr view "$PR" --json number,state,isDraft,headRefName,headRefOid,baseRefName,title,isCrossRepository,body)"
state="$(jq -r .state <<<"$json")"
draft="$(jq -r .isDraft <<<"$json")"
cross="$(jq -r .isCrossRepository <<<"$json")"
base_ref="$(jq -r .baseRefName <<<"$json")"
head_ref="$(jq -r .headRefName <<<"$json")"
head_sha="$(jq -r .headRefOid <<<"$json")"
title="$(jq -r .title <<<"$json")"

if [ "$state" != "OPEN" ]; then echo "queue-candidate: PR #$PR is $state, not OPEN" >&2; exit 4; fi
if [ "$draft" = "true" ]; then echo "queue-candidate: PR #$PR is a draft" >&2; exit 4; fi
if [ "$cross" = "true" ]; then echo "queue-candidate: PR #$PR comes from another repository; the queue only lands same-repo branches" >&2; exit 4; fi
if [ "$base_ref" != "main" ]; then echo "queue-candidate: PR #$PR targets '$base_ref', not main" >&2; exit 4; fi

git fetch -q "$REMOTE" "refs/heads/main" "refs/pull/$PR/head"
base_sha="$(git rev-parse FETCH_HEAD^{commit} 2>/dev/null || true)"
# FETCH_HEAD after a two-ref fetch is ambiguous; resolve each explicitly.
base_sha="$(git rev-parse "refs/remotes/$REMOTE/main")"
fetched_head="$(git rev-parse "$head_sha^{commit}")"
[ "$fetched_head" = "$head_sha" ] || { echo "queue-candidate: PR head $head_sha not fetched" >&2; exit 1; }

git -c advice.detachedHead=false checkout -q --detach "$base_sha"
if ! git -c user.name="merge-queue" -c user.email="merge-queue@users.noreply.github.com" \
     merge --no-ff --no-edit -m "Merge pull request #$PR from $head_ref

$title" "$head_sha" >/dev/null 2>&1; then
  echo "queue-candidate: PR #$PR conflicts with main:" >&2
  git diff --name-only --diff-filter=U | sed 's/^/  /' >&2
  git merge --abort || true
  exit 3
fi
candidate_sha="$(git rev-parse HEAD)"

echo "pr=$PR"
echo "head_sha=$head_sha"
echo "head_ref=$head_ref"
echo "base_sha=$base_sha"
echo "candidate_sha=$candidate_sha"
echo "title=$title"
echo "queue-candidate: #$PR ($head_ref @ ${head_sha:0:9}) onto main @ ${base_sha:0:9} → candidate ${candidate_sha:0:9}" >&2
