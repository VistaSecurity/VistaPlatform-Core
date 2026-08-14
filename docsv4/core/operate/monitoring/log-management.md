---
render_macros: false
---

# Compliance Log Management & Retention

## Overview
The monitoring-service owns platform-wide compliance logging. Raw JSON logs are stored in S3 (SSE-KMS) while metadata, access audit trails, PII rules, and retention history live in Postgres.

## Required Configuration
- `S3_LOG_BUCKET` – S3 bucket for raw logs
- `S3_REGION` – AWS region for the bucket
- `S3_KMS_KEY_ID` – KMS key used for SSE-KMS encryption
- `ENABLE_INCIDENT_HOOKS=true` – controls automated incident hooks/notifications (defaults to `true`; set to `false` only when S3/KMS access isn’t available)
- `LOG_RETENTION_INTERVAL_HOURS` – cadence for the retention job (default 24h)

Set these variables in `.env`, `.env.prod`, or through AWS parameter stores before deploying monitoring-service.

## Incident Hooks & Notifications
When `ENABLE_INCIDENT_HOOKS=true`, monitoring-service will:
1. Evaluate each stored log via `IncidentResponseHook`
2. Auto-create a security incident when PII/security patterns trip
3. Send notifications through configured monitoring notification channels (Slack, webhook, PagerDuty, email)
4. Record an audit entry (`access_type=incident`) in `platform_log_access_audit` with `access_result=created`
5. If the hook fails (missing channel, API error, etc.) an `access_type=incident` entry is still added with `access_result=error` and the error message for audit/replay

Use admin UI → Settings → Notifications to configure channels.

## Retention & Archival
- Hot storage policy: 90 days (logs remain `status=active`)
- Archive policy: after 90 days entries are marked `status=archived`
- Deletion policy: after 365 days entries are soft-deleted (`status=deleted`)
- Job history recorded in `platform_log_retention_jobs`

The retention worker runs via `jobs.LogRetentionJob` on the monitoring-service process. Adjust `LOG_RETENTION_INTERVAL_HOURS` if needed.

## Validation Workflow
There is no bundled validation script — check both things by hand before enabling logging:

1. Required env vars are set (`S3_LOG_BUCKET`, `S3_REGION`, `S3_KMS_KEY_ID`, `ENABLE_INCIDENT_HOOKS`, `LOG_RETENTION_INTERVAL_HOURS`).
2. Core logging tables exist (`platform_log_metadata`, `platform_log_access_audit`, `platform_log_retention_jobs`):

```bash
docker compose exec postgres psql -U crypto_user -d crypto_inventory -c \
  "\dt platform_log_metadata platform_log_access_audit platform_log_retention_jobs"
```

## Deployment Notes
1. These tables are part of `scripts/database/schema.sql` (there is no separate migration file — the schema is applied as a whole; see [Database Migrations](../deployment/database-migrations.md)). Confirm they're present before enabling logging.
2. Ensure monitoring-service IAM role has access to the S3 log bucket and KMS key.
3. Verify retention job logs (`monitoring-service` container) to confirm archival/deletion runs.
4. Confirm incident notifications reach Slack/PagerDuty as expected before enabling in production.

## Related Documentation
- [Monitoring Setup](./monitoring.md) - Complete monitoring and alerting setup
- [Production Deployment Checklist](../deployment/production-checklist.md) - Deployment procedures
