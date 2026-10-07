#!/usr/bin/env bash
# Does this Go module carry Enterprise-edition code?
#
#   go-module-has-ee.sh <module-dir>     exit 0: yes   exit 1: no   exit 2: error
#
# "Yes" means some .go file under the directory has a //go:build line that
# selects the `ee` tag positively (`ee`, `ee && linux`, `(ee || x)`). A file
# that only says `!ee` is the Core half of a seam and proves nothing is gated.
#
# Why this is the test and not "has an ee/ directory": the ee/ packages
# themselves carry no build tag, so a plain `go build ./...` and `go test ./...`
# already compile and run them. What only exists under `-tags ee` is the glue
# (cmd/edition_ee.go, shared/ai/edition/*_ee.go) that links them in, and the
# *_ee_test.go tests that drive the linked build. CI used to run no
# `-tags ee` pass at all, so a change that broke the linked build, or seven of
# its tests, was green on every check.
#
# One definition, two consumers: scripts/ci-backend-matrix.mjs (the PR gate's
# `matrix.ee`) and nightly.yml's test-backend step. Both ask THIS script, so
# the two gates cannot disagree about which modules have an ee build.
# Regression test: scripts/test-go-module-has-ee.sh (`make go-module-has-ee-test`).
set -euo pipefail

[ $# -eq 1 ] || { echo "usage: go-module-has-ee.sh <module-dir>" >&2; exit 2; }
dir="$1"
[ -d "$dir" ] || { echo "go-module-has-ee: '$dir' is not a directory" >&2; exit 2; }

# grep exits 0 on a match, 1 on none, 2 on an error: exactly this script's contract.
exec grep -rqP --include='*.go' \
  --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=vendor --exclude-dir=testdata \
  '^//go:build\s.*(?<![!\w])ee(?!\w)' "$dir"
