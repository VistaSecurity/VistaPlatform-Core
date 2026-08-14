#!/usr/bin/env bash
# Single source of truth for the GOTOOLCHAIN pin used by shell scripts.
#
# WHY THIS FILE EXISTS: PR replaced `GOTOOLCHAIN=local` with an exact
# `goX.Y.Z` pin derived from go.work, but it swept only the Makefile and the
# public-tree export. Four scripts kept the hardcode, and `local` cannot fetch
# the sanctioned patch release — so on any machine whose installed Go lags
# go.work (1.26.5 vs 1.26.6, say) they die with
#
#   go: go.work requires go >= 1.26.6 (running go 1.26.5; GOTOOLCHAIN=local)
#
# which broke `make session-init`, the documented bootstrap for a fresh clone.
#
# The three options, and why the pin is the only one that does both jobs
# (repeated from the Makefile because this is where a script author looks):
#
#   GOTOOLCHAIN=local    blocks 1.27 (good) but refuses to provision the
#                        sanctioned patch, so it breaks lagging machines.
#   GOTOOLCHAIN=auto     provisions the patch (good) but ALSO silently
#                        downloads 1.27+ — it removes the Critical Rule #1
#                        tripwire entirely. NEVER emit this, on any path.
#   GOTOOLCHAIN=goX.Y.Z  provisions exactly that toolchain and still hard-fails
#                        any module requiring a newer one.
#
# Usage:
#   source "$(dirname "$0")/lib/go-toolchain.sh"    # from repo root
#   GO_PIN="$(go_toolchain_pin)"
#   GOTOOLCHAIN="$GO_PIN" go build ./...
#
# Every degenerate case falls back to `local` — restrictive, never permissive.
# A derivation that failed must not quietly drop the 1.27 tripwire.

# Echoes the toolchain name to use. Never fails; diagnostics go to stderr.
# $1 (optional): repository root. Defaults to the current directory.
go_toolchain_pin() {
    local repo_root="${1:-.}"
    local policy version

    # The policy line lives in the Makefile (GO_POLICY_LINE), which is also what
    # the Makefile asserts its own derivation against. Reading it here keeps the
    # scripts from drifting into a second opinion about which Go line is legal.
    policy="${GO_POLICY_LINE:-$(awk -F':= *' '/^GO_POLICY_LINE[[:space:]]*:=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$repo_root/Makefile" 2>/dev/null)}"
    version="$(awk '/^go /{print $2; exit}' "$repo_root/go.work" 2>/dev/null)"

    if [ -z "$policy" ] || [ -z "$version" ]; then
        echo "⚠️  cannot derive the Go toolchain pin (no GO_POLICY_LINE and/or no go.work 'go' directive) — falling back to GOTOOLCHAIN=local" >&2
        echo "local"
        return 0
    fi

    # A go.work bumped off the policy line must NOT drag the pin along with it —
    # that would disarm the guard rather than trip it. Fall back to `local`,
    # which then fails the build loudly, and say why.
    case "$version" in
        "$policy".*) ;;
        *)
            echo "⚠️  go.work declares 'go $version', which is not on the Go $policy line (Critical Rule #1) — falling back to GOTOOLCHAIN=local" >&2
            echo "local"
            return 0
            ;;
    esac

    # `go1.26` is a language version, not a toolchain name; Go rejects it. Only
    # a full X.Y.Z can be pinned.
    case "$version" in
        *.*.*) echo "go$version" ;;
        *)
            echo "⚠️  go.work declares 'go $version', not a full X.Y.Z version, so GOTOOLCHAIN cannot be pinned exactly — falling back to GOTOOLCHAIN=local" >&2
            echo "local"
            ;;
    esac
}
