#!/bin/bash
#
# Remove THIS project's data volumes, for a genuinely clean database.
#
# Scope: volumes carrying this compose project's label. Volumes belonging to
# other stacks on the same daemon are not touched, and neither are their
# containers — this script used to run `docker ps -q | xargs docker stop`
# twice, which stopped every container on the host, including ones it had no
# business knowing about.
#
# Usage: ./scripts/clean-all-volumes.sh [--dry-run]
#
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# shellcheck source=lib/docker-scope.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/docker-scope.sh"

BLUE='\033[0;34m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log() { echo -e "${BLUE}$*${NC}"; }
ok() { echo -e "${GREEN}$*${NC}"; }
warn() { echo -e "${YELLOW}$*${NC}"; }
err() { echo -e "${RED}$*${NC}"; }

DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

log "🧹 Volume Cleanup"
log "================="

DCMD=$(detect_compose_cmd) || exit 1
PROJECT=$(compose_project_name "$PROJECT_ROOT")
assert_project_scope "$PROJECT" || exit 1
log "Project: $PROJECT"
echo ""

# `down -v` removes this project's containers and its named volumes together,
# in the right order. Stopping containers by hand first is what the previous
# version did globally; compose already does it, scoped.
log "1. docker compose down -v --remove-orphans"
if [[ "$DRY_RUN" == "true" ]]; then
    echo "   [dry-run] skipped"
else
    $DCMD down -v --remove-orphans 2>&1 | sed 's/^/   /' || warn "   compose down reported errors — sweeping leftovers below"
fi

echo ""
log "2. Sweeping volumes still labelled $PROJECT..."
volumes=$(project_volumes "$PROJECT")
if [[ -z "$volumes" ]]; then
    ok "   ✅ none left"
    exit 0
fi

removed=0
failed=0
while IFS= read -r vol; do
    [[ -z "$vol" ]] && continue
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "   [dry-run] would remove $vol"
        continue
    fi
    if docker volume rm -f "$vol" >/dev/null 2>&1; then
        log "   ✅ removed $vol"
        removed=$((removed + 1))
    else
        # Almost always "volume is in use": a container outside this compose
        # file has it mounted. Name it rather than force the issue.
        warn "   ⚠️  could not remove $vol"
        using=$(docker ps -a --filter volume="$vol" --format '{{.Names}}' 2>/dev/null || true)
        [[ -n "$using" ]] && warn "      in use by: $using"
        failed=$((failed + 1))
    fi
done <<< "$volumes"

echo ""
if [[ $failed -eq 0 ]]; then
    ok "✅ Volume cleanup complete ($removed removed)"
else
    warn "⚠️  Finished with $failed failure(s) ($removed removed)"
fi
