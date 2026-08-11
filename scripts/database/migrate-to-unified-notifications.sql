-- Migration Script: Migrate from legacy notification tables to unified notification service
-- This script migrates data from discovery_alert_configs and monitoring_notification_channels
-- to the new unified notification tables (tenant_notification_channels, platform_notification_channels)

-- =================================================================
-- Migration: Legacy to Unified Notifications
-- =================================================================
-- This script should be run after the unified notification schema (migration 39) is applied
-- It migrates existing notification configurations to the new unified system
-- =================================================================

BEGIN;

-- =================================================================
-- Step 1: Migrate discovery_alert_configs to tenant_notification_channels
-- =================================================================

-- Migrate Slack channels from discovery_alert_configs
INSERT INTO tenant_notification_channels (
    id,
    tenant_id,
    channel_name,
    channel_type,
    config,
    enabled,
    test_status,
    created_at,
    updated_at
)
SELECT
    gen_random_uuid(),
    tenant_id,
    'Discovery Slack - ' || alert_type,
    'slack',
    jsonb_build_object(
        'webhook_url', slack_webhook_url,
        'channel', COALESCE(slack_channel, '#alerts')
    ),
    enabled AND slack_enabled,
    'not_tested',
    created_at,
    updated_at
FROM discovery_alert_configs
WHERE slack_enabled = true
  AND slack_webhook_url IS NOT NULL
  AND slack_webhook_url != ''
ON CONFLICT (tenant_id, channel_name) DO NOTHING;

-- Migrate Email channels from discovery_alert_configs
-- Note: Email uses tenant email config, so we create a placeholder channel
-- that will use the tenant's email configuration
INSERT INTO tenant_notification_channels (
    id,
    tenant_id,
    channel_name,
    channel_type,
    config,
    enabled,
    test_status,
    created_at,
    updated_at
)
SELECT
    gen_random_uuid(),
    tenant_id,
    'Discovery Email - ' || alert_type,
    'email',
    jsonb_build_object(
        'recipients', ARRAY[]::text[]  -- Will be configured via tenant email settings
    ),
    enabled AND email_enabled,
    'not_tested',
    created_at,
    updated_at
FROM discovery_alert_configs
WHERE email_enabled = true
ON CONFLICT (tenant_id, channel_name) DO NOTHING;

-- Migrate In-App notifications (already handled by in_app_notifications table)
-- No migration needed as in-app is handled separately

-- =================================================================
-- Step 2: Migrate monitoring_notification_channels to platform_notification_channels
-- =================================================================

INSERT INTO platform_notification_channels (
    id,
    channel_name,
    channel_type,
    config,
    enabled,
    test_status,
    created_at,
    updated_at
)
SELECT
    id,  -- Keep existing ID for reference
    channel_name,
    channel_type,
    config,
    enabled,
    test_status,
    created_at,
    updated_at
FROM monitoring_notification_channels
ON CONFLICT (channel_name) DO UPDATE
SET
    channel_type = EXCLUDED.channel_type,
    config = EXCLUDED.config,
    enabled = EXCLUDED.enabled,
    test_status = EXCLUDED.test_status,
    updated_at = EXCLUDED.updated_at;

-- =================================================================
-- Step 3: Create default notification rules for discovery alerts
-- =================================================================

-- Create rules for each alert type in discovery_alert_configs
INSERT INTO tenant_notification_rules (
    id,
    tenant_id,
    rule_name,
    alert_source,
    alert_type,
    channel_ids,
    severity_filter,
    frequency,
    enabled,
    priority,
    created_at,
    updated_at
)
SELECT
    gen_random_uuid(),
    tenant_id,
    'Discovery Rule - ' || alert_type,
    'discovery',
    alert_type,
    ARRAY(
        SELECT id FROM tenant_notification_channels
        WHERE tenant_id = dac.tenant_id
          AND channel_name LIKE 'Discovery%'
          AND enabled = true
    )::uuid[],
    NULL,  -- No severity filter (discovery alerts are typically medium)
    'immediate',
    enabled,
    5,  -- Default priority
    created_at,
    updated_at
FROM discovery_alert_configs dac
WHERE enabled = true
  AND (
    email_enabled = true
    OR slack_enabled = true
    OR in_app_enabled = true
  )
ON CONFLICT (tenant_id, rule_name) DO NOTHING;

-- =================================================================
-- Step 4: Create default platform notification rules for monitoring
-- =================================================================

-- Create a default rule for monitoring alerts to use platform channels
INSERT INTO platform_notification_rules (
    id,
    rule_name,
    alert_source,
    alert_type,
    channel_ids,
    severity_filter,
    frequency,
    enabled,
    priority,
    created_at,
    updated_at
)
SELECT
    gen_random_uuid(),
    'Platform Monitoring - All Alerts',
    'monitoring',
    NULL,  -- All alert types
    ARRAY(
        SELECT id FROM platform_notification_channels
        WHERE enabled = true
    )::uuid[],
    NULL,  -- All severities
    'immediate',
    true,
    10,  -- High priority
    NOW(),
    NOW()
WHERE EXISTS (
    SELECT 1 FROM platform_notification_channels WHERE enabled = true
)
ON CONFLICT (rule_name) DO NOTHING;

-- =================================================================
-- Step 5: Migrate notification history (optional - for reference)
-- =================================================================

-- Migrate discovery_alert_history to notification_history
INSERT INTO notification_history (
    id,
    tenant_id,
    notification_type,
    alert_source,
    alert_type,
    severity,
    message,
    channels_used,
    status,
    metadata,
    created_at
)
SELECT
    id,
    tenant_id,
    'discovery',
    'discovery',
    alert_type,
    'medium',  -- Default severity for discovery alerts
    message,
    sent_via,
    CASE
        WHEN status = 'sent' THEN 'sent'
        WHEN status = 'failed' THEN 'failed'
        ELSE 'pending'
    END,
    jsonb_build_object(
        'job_id', job_id,
        'finding_id', finding_id
    ),
    sent_at
FROM discovery_alert_history
WHERE sent_at > NOW() - INTERVAL '90 days'  -- Only migrate recent history
ON CONFLICT DO NOTHING;

-- =================================================================
-- Step 6: Update channel names to be unique per tenant
-- =================================================================

-- Ensure channel names are unique by adding tenant identifier if needed
UPDATE tenant_notification_channels tnc1
SET channel_name = channel_name || ' (' ||
    (SELECT COUNT(*) FROM tenant_notification_channels tnc2
     WHERE tnc2.tenant_id = tnc1.tenant_id
       AND tnc2.channel_name = tnc1.channel_name
       AND tnc2.id < tnc1.id) || ')'
WHERE EXISTS (
    SELECT 1 FROM tenant_notification_channels tnc2
    WHERE tnc2.tenant_id = tnc1.tenant_id
      AND tnc2.channel_name = tnc1.channel_name
      AND tnc2.id < tnc1.id
);

COMMIT;

-- =================================================================
-- Verification Queries
-- =================================================================

-- Count migrated channels
SELECT
    'Tenant Channels Migrated' as metric,
    COUNT(*) as count
FROM tenant_notification_channels
WHERE channel_name LIKE 'Discovery%';

SELECT
    'Platform Channels Migrated' as metric,
    COUNT(*) as count
FROM platform_notification_channels;

SELECT
    'Tenant Rules Created' as metric,
    COUNT(*) as count
FROM tenant_notification_rules
WHERE rule_name LIKE 'Discovery Rule%';

SELECT
    'Platform Rules Created' as metric,
    COUNT(*) as count
FROM platform_notification_rules;

-- =================================================================
-- Notes
-- =================================================================
-- 1. Legacy tables (discovery_alert_configs, monitoring_notification_channels)
--    are kept for backward compatibility during transition period
-- 2. After verification, these tables can be deprecated
-- 3. Email channels created from discovery_alert_configs use tenant email config
-- 4. In-app notifications continue to use the existing in_app_notifications table
-- 5. Test all migrated channels after migration completes
