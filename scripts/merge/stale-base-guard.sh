#!/usr/bin/env bash
# stale-base-guard.sh — refuse a branch that carries stale-base damage.
#
# Two real incidents motivate this. A branch assembled from a stale checkout
# was rebased cleanly, passed every gate, and on merge DELETED the files three
# newer PRs had added (the agent restored files from an old backup). Earlier, a
# bot PR carrying whole-file copies from an older main REVERTED a test that
# had landed after its base. Neither conflicts; both pass CI; both are only
# visible by comparing the branch's diff against what main did recently.
#
# Checks (merge-base .. HEAD, against BASE's first-parent history):
#   1. DELETION  — the branch deletes a file that BASE added within WINDOW_DAYS.
#   2. REVERT    — the branch sets a file to byte-identical content BASE held
#                  at some first-parent commit within WINDOW_DAYS other than
#                  the merge-base (the whole-file-copy signature).
#
# Either is refused unless the PR body (PR_BODY env) carries a trailer line
#     Merge-safety-ok: path/one path/two        (or:  Merge-safety-ok: all)
# naming the paths, which makes an intentional recent deletion or revert an
# explicit, reviewable statement instead of a silent side effect.
#
# Usage:
#   scripts/merge/stale-base-guard.sh [BASE] [HEAD]      (defaults origin/main, HEAD)
#   WINDOW_DAYS=14  PR_BODY="$(gh pr view N --json body -q .body)"  ...
#
# Exit: 0 clean, 1 refused (violations listed), 2 cannot evaluate (fails CLOSED:
# an unobtainable base must not read as "nothing to check").

set -euo pipefail

BASE="${1:-origin/main}"
HEAD_REF="${2:-HEAD}"
WINDOW_DAYS="${WINDOW_DAYS:-14}"
PR_BODY="${PR_BODY:-}"

die() { echo "::error::stale-base-guard: $*" >&2; exit 2; }

base_sha="$(git rev-parse --verify --quiet "${BASE}^{commit}")" || die "cannot resolve BASE '$BASE'"
head_sha="$(git rev-parse --verify --quiet "${HEAD_REF}^{commit}")" || die "cannot resolve HEAD '$HEAD_REF'"
merge_base="$(git merge-base "$base_sha" "$head_sha")" || die "no merge-base between $BASE and $HEAD_REF"
since="${WINDOW_DAYS} days ago"

# ── Allowlist from the PR body trailer ──────────────────────────────────────
ok_all=0
ok_paths=""
if [ -n "$PR_BODY" ]; then
  while IFS= read -r line; do
    rest="${line#Merge-safety-ok:}"
    rest="$(printf '%s' "$rest" | tr ',' ' ')"
    for p in $rest; do
      if [ "$p" = "all" ]; then ok_all=1; else ok_paths="$ok_paths"$'\n'"$p"; fi
    done
  done < <(printf '%s\n' "$PR_BODY" | grep -E '^Merge-safety-ok:' || true)
fi
allowed() { # <path>
  [ "$ok_all" = 1 ] && return 0
  printf '%s\n' "$ok_paths" | grep -qx -- "$1"
}

violations=0
refuse() { # <kind> <path> <detail>
  violations=$((violations + 1))
  echo "::error file=$2::stale-base-guard: $1 — $2 ($3)"
}

# ── 1. Deletions of files BASE added recently ────────────────────────────────
# First-parent with -m so a merge commit (the repo's merge convention) shows
# everything its PR added; squash and rebase merges are ordinary commits.
recently_added="$(git log --first-parent -m --since="$since" --diff-filter=A --name-only --format= "$base_sha" | sort -u)"
deleted="$(git diff --name-only --diff-filter=D "$merge_base" "$head_sha" | sort -u)"
if [ -n "$deleted" ] && [ -n "$recently_added" ]; then
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    if allowed "$path"; then echo "allowed by Merge-safety-ok: deletion of $path"; continue; fi
    added_by="$(git log --first-parent -m --since="$since" --diff-filter=A --format=%h -1 "$base_sha" -- "$path")"
    refuse "DELETES a file main added in the last $WINDOW_DAYS days" "$path" "added by $added_by"
  done < <(comm -12 <(printf '%s\n' "$deleted") <(printf '%s\n' "$recently_added"))
fi

# ── 2. Whole-file copies from an older main ──────────────────────────────────
# For every file the branch modifies, look at each first-parent commit in the
# window that changed that file on BASE, and compare the branch's blob with
# the content that commit REPLACED (its first parent's blob). A match means
# the branch's "change" is main's pre-change content coming back: exactly what
# a whole-file copy from a stale checkout looks like. The content the branch
# forked from (the merge-base blob) is never a revert, whatever its age.
modified="$(git diff --name-only --diff-filter=M "$merge_base" "$head_sha")"
if [ -n "$modified" ]; then
  blob_at() { git rev-parse --verify --quiet "$1:$2" 2>/dev/null || true; }
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    head_blob="$(blob_at "$head_sha" "$path")"
    [ -n "$head_blob" ] || continue
    base_blob="$(blob_at "$merge_base" "$path")"
    [ "$head_blob" = "$base_blob" ] && continue
    match=""
    while IFS= read -r c; do
      [ -n "$c" ] || continue
      before="$(blob_at "${c}^" "$path")"
      [ -n "$before" ] || continue             # the commit added the file: nothing to revert to
      [ "$before" = "$base_blob" ] && continue # pre-change content IS the fork point: not a revert
      if [ "$before" = "$head_blob" ]; then match="$c"; break; fi
    done < <(git log --first-parent --since="$since" --format=%H "$base_sha" -- "$path")
    if [ -n "$match" ]; then
      if allowed "$path"; then echo "allowed by Merge-safety-ok: revert of $path"; continue; fi
      refuse "REVERTS main's change $(git rev-parse --short "$match") (last $WINDOW_DAYS days)" "$path" "byte-identical to the content that commit replaced; a whole-file copy from a stale base looks exactly like this"
    fi
  done <<< "$modified"
fi

if [ "$violations" -gt 0 ]; then
  cat >&2 <<EOF

stale-base-guard: REFUSED ($violations violation(s)) — $HEAD_REF vs $BASE, window $WINDOW_DAYS days.
If every listed change is intended, add a trailer line to the PR body:
    Merge-safety-ok: <path> [<path> ...]
and re-run. The trailer is the reviewable record that the deletion or revert was deliberate.
EOF
  exit 1
fi
echo "stale-base-guard: clean ($HEAD_REF vs $BASE, merge-base $(git rev-parse --short "$merge_base"), window $WINDOW_DAYS days)"
