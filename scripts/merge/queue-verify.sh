#!/usr/bin/env bash
# queue-verify.sh <ref> — run the repository's gates on a merge candidate ref
# and wait for the verdict. Dispatches (workflow_dispatch, event_mode=
# merge_queue) the three workflows that gate a PR, on the given ref, then
# waits for each run and reports.
#
#   ci.yml           the PR gate, scoped to the candidate's diff (merge_queue mode)
#   standards.yml    the standards PR gate AND the full standards-check sentinel
#   api-contract.yml the OpenAPI contract gate
#
# Prints one line per run on stdout:  <workflow>\t<conclusion>\t<url>
# Exit 0 only if every run concluded success. Exit 1 on any other
# conclusion, 2 if a run could not be found or dispatched. Needs `gh`
# authenticated with permission to dispatch workflows (actions: write).
#
# Why dispatch instead of reusing workflow_call: the gates are 900+ lines of
# jobs that check out `github.sha`; dispatching onto the candidate ref makes
# github.sha the candidate with no change to any job. workflow_dispatch is
# also the one event the job token is allowed to raise.

set -euo pipefail

REF="${1:?candidate ref}"
REPO="${GH_REPO:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
WORKFLOWS=(ci.yml standards.yml api-contract.yml)
POLL="${QUEUE_POLL_SECONDS:-20}"
WAIT_MAX="${QUEUE_WAIT_MAX_SECONDS:-3000}"

since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sleep 1
declare -A RUN
for wf in "${WORKFLOWS[@]}"; do
  if [ "$wf" = "api-contract.yml" ]; then
    gh workflow run "$wf" --repo "$REPO" --ref "$REF" >/dev/null
  else
    gh workflow run "$wf" --repo "$REPO" --ref "$REF" -f event_mode=merge_queue >/dev/null
  fi
done
echo "queue-verify: dispatched ${WORKFLOWS[*]} on $REF" >&2

# Find each dispatched run (they take a few seconds to appear).
for wf in "${WORKFLOWS[@]}"; do
  for _ in $(seq 1 30); do
    id="$(gh run list --repo "$REPO" --workflow "$wf" --branch "$REF" --event workflow_dispatch --created ">=$since" --limit 1 --json databaseId -q '.[0].databaseId' 2>/dev/null || true)"
    [ -n "$id" ] && break
    sleep 3
  done
  if [ -z "${id:-}" ]; then echo "queue-verify: no run of $wf appeared on $REF" >&2; exit 2; fi
  RUN[$wf]="$id"
  id=""
done

# Wait for all of them (polling; `gh run watch` is one run at a time).
deadline=$(( $(date +%s) + WAIT_MAX ))
rc=0
for wf in "${WORKFLOWS[@]}"; do
  id="${RUN[$wf]}"
  while :; do
    status="$(gh run view "$id" --repo "$REPO" --json status,conclusion,url -q '[.status,.conclusion,.url]|@tsv')"
    st="$(cut -f1 <<<"$status")"; concl="$(cut -f2 <<<"$status")"; url="$(cut -f3 <<<"$status")"
    if [ "$st" = "completed" ]; then
      printf '%s\t%s\t%s\n' "$wf" "$concl" "$url"
      [ "$concl" = "success" ] || rc=1
      break
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      printf '%s\t%s\t%s\n' "$wf" "timed-out" "$url"; rc=1; break
    fi
    sleep "$POLL"
  done
done
exit "$rc"
