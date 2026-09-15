#!/usr/bin/env bash
# golangci_lint_cache_dir <root> — the per-worktree cache directory
# scripts/lint-go.sh exports as GOLANGCI_LINT_CACHE, unless a caller already
# set that variable.
#
# WHY THIS FILE EXISTS: extracted out of lint-go.sh so
# scripts/test-lint-go-cache-isolation.sh can exercise the derivation directly
# — in real git worktrees — without driving a whole lint run (which needs
# golangci-lint on PATH and a real go.work tree).
#
# WHY PER-WORKTREE AT ALL: golangci-lint's own default cache location,
# ~/.cache/golangci-lint, is shared by EVERY worktree of this repo on a host,
# and the cache keys its entries by file path. Two worktrees at different
# paths mostly don't collide directly, but a worktree that has since been
# DELETED can still leave entries a sibling worktree resolves to the same
# path — and a stale cached result means a `//nolint` directive sitting right
# there in the real file is never read, because golangci-lint never re-parsed
# it. `make standards-check` reported exactly that: a lint failure with no
# repro under a hand-run `golangci-lint run`, three times in one week.
#
# `git rev-parse --absolute-git-dir` is the right key: a worktree's git-dir is
# its own `.git/worktrees/<name>` under the main checkout's `.git`, distinct
# from every sibling worktree's and from the main checkout's own `.git`, and
# it survives a worktree being moved (unlike hashing the worktree's own
# working-tree path, which is stable only until someone renames the
# directory).
golangci_lint_cache_dir() {
    local root="$1"
    local git_dir
    if git_dir="$(cd "$root" 2>/dev/null && git rev-parse --absolute-git-dir 2>/dev/null)" && [ -n "$git_dir" ]; then
        printf '%s/golangci-cache' "$git_dir"
    else
        # Not a git checkout (a tarball extraction, say) or git unavailable:
        # key by ROOT's own path instead, so distinct checkouts on the same
        # host still don't share a cache keyed by file path.
        printf '%s/golangci-lint-cache-%s' "${TMPDIR:-/tmp}" "$(printf '%s' "$root" | cksum | cut -d' ' -f1)"
    fi
}
