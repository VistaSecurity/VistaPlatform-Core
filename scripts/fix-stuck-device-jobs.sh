#!/usr/bin/env bash
# Mark device_jobs stuck in 'in_progress' as 'failed' so they no longer show in the UI.
# Run from repo root. Requires: docker compose with postgres service and crypto_inventory DB.
#
# Usage:
#   ./scripts/fix-stuck-device-jobs.sh           # mark all in_progress jobs as failed
#   ./scripts/fix-stuck-device-jobs.sh --dry-run # show what would be updated

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
  echo "Dry run: listing device_jobs with status = 'in_progress'..."
  docker compose exec -T postgres psql -U crypto_user -d crypto_inventory -c \
    "SELECT id, job_type, status, started_at, created_at FROM device_jobs WHERE status = 'in_progress' ORDER BY created_at DESC;"
  echo ""
  echo "To fix: run without --dry-run"
  exit 0
fi

echo "Marking device_jobs stuck in 'in_progress' as 'failed'..."
docker compose exec -T postgres psql -U crypto_user -d crypto_inventory -c "
  UPDATE device_jobs
  SET status = 'failed',
      error_message = 'Marked failed (was stuck in in_progress; run scripts/fix-stuck-device-jobs.sh)',
      completed_at = NOW(),
      updated_at = NOW()
  WHERE status = 'in_progress';
"
echo "Done. Re-run with --dry-run to confirm no jobs remain in 'in_progress'."
