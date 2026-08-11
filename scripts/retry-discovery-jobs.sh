#!/bin/bash
# Script to retry stuck discovery jobs

echo "Finding queued jobs..."
JOB_IDS=$(docker compose exec -T postgres psql -U crypto_user -d crypto_inventory -t -c "
SELECT id FROM discovery_jobs WHERE status = 'queued' ORDER BY created_at DESC LIMIT 5;
" | tr -d ' ' | grep -v '^$')

if [ -z "$JOB_IDS" ]; then
    echo "No queued jobs found."
    exit 0
fi

echo "Found queued jobs. Retrying via API..."
for JOB_ID in $JOB_IDS; do
    echo "Retrying job: $JOB_ID"
    # Note: This requires authentication token - you'll need to get one from the browser
    # For now, we'll just show the command
    echo "  Run: curl -X POST http://localhost:8080/api/v1/discovery/jobs/$JOB_ID/retry -H 'Authorization: Bearer YOUR_TOKEN'"
done

echo ""
echo "Or create a new job - it should process immediately now that the fix is deployed."
