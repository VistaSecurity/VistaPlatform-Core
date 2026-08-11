#!/usr/bin/env bash
# Mark discovery jobs stuck in 'running' as 'failed' so they no longer show "in progress".
# Run from repo root. Requires: docker compose with postgres service and crypto_inventory DB.
#
# Usage:
#   ./scripts/fix-stuck-discovery-jobs.sh           # mark all running jobs as failed
#   ./scripts/fix-stuck-discovery-jobs.sh --dry-run # show what would be updated

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

DRY_RUN=false
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
  esac
done

if [ "$DRY_RUN" = true ]; then
  echo "Dry run: listing discovery_jobs with status = 'running'..."
  docker compose exec -T postgres psql -U crypto_user -d crypto_inventory -c \
    "SELECT id, tenant_id, execution_mode, status, started_at, created_at FROM discovery_jobs WHERE status = 'running' ORDER BY created_at DESC;"
  echo ""
  echo "To fix: run without --dry-run"
  exit 0
fi

echo "Marking discovery jobs stuck in 'running' as 'failed'..."
docker compose exec -T postgres psql -U crypto_user -d crypto_inventory -c "
  UPDATE discovery_jobs
  SET status = 'failed',
      error_message = 'Marked failed (was stuck in running; run scripts/fix-stuck-discovery-jobs.sh)',
      completed_at = NOW(),
      updated_at = NOW()
  WHERE status = 'running';
"
echo "Done. Re-run with --dry-run to confirm no jobs remain in 'running'."
