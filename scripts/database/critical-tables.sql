-- Critical Tables (legacy fallback)
-- Permission reconciliation (super_admin catch-all, platform.analytics, is_platform_default)
-- is now at the end of schema.sql and runs at init. This file is kept for
-- database-validation.sh repair path only (when applying schema.sql is not possible).
-- Docker init runs only 01-schema.sql and 02-seed.sql.

-- NOTE: report_templates is intentionally NOT recreated here. It (and `reports`)
-- were demolished in the CBOM Phase 5 reporting redesign and are dropped at the
-- end of schema.sql. Recreating it here would resurrect a removed table on the
-- repair path, so it has been removed.

-- Platform frameworks table (if it doesn't exist)
-- Mirrors definition in schema.sql; created_by/published_by reference platform_users.
CREATE TABLE IF NOT EXISTS platform_frameworks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code VARCHAR(100) NOT NULL,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(20) NOT NULL,
    description TEXT,
    organization VARCHAR(255),
    status VARCHAR(20) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived')),
    published_at TIMESTAMP WITH TIME ZONE,
    published_by UUID REFERENCES platform_users(id),
    created_by UUID NOT NULL REFERENCES platform_users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT unique_platform_framework_code_version UNIQUE (code, version)
);

-- Add is_platform_default column if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'platform_frameworks' 
        AND column_name = 'is_platform_default'
    ) THEN
        ALTER TABLE platform_frameworks 
        ADD COLUMN is_platform_default BOOLEAN NOT NULL DEFAULT false;
        
        COMMENT ON COLUMN platform_frameworks.is_platform_default IS 
            'Indicates if this framework is the platform default (Best Practices). Only one framework can be marked as default. Available to all subscription tiers.';
    END IF;
END $$;

-- Platform integrations table (if it doesn't exist)
CREATE TABLE IF NOT EXISTS platform_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_type VARCHAR(50) NOT NULL,
    integration_name VARCHAR(100) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    config JSONB NOT NULL DEFAULT '{}',
    config_version INTEGER DEFAULT 1,
    is_enabled BOOLEAN DEFAULT true,
    is_active BOOLEAN DEFAULT true,
    status VARCHAR(20) DEFAULT 'pending',
    status_message TEXT,
    last_tested_at TIMESTAMP WITH TIME ZONE,
    last_successful_connection_at TIMESTAMP WITH TIME ZONE,
    account_id VARCHAR(100),
    region VARCHAR(50),
    environment VARCHAR(50),
    description TEXT,
    tags JSONB DEFAULT '[]',
    metadata JSONB DEFAULT '{}',
    created_by UUID REFERENCES platform_users(id) ON DELETE SET NULL,
    updated_by UUID REFERENCES platform_users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT valid_integration_type CHECK (integration_type IN ('aws', 'azure', 'gcp', 'slack', 'pagerduty', 'datadog', 'splunk', 'custom')),
    CONSTRAINT valid_provider CHECK (provider IN ('cloud', 'saas', 'custom')),
    CONSTRAINT valid_status CHECK (status IN ('pending', 'configured', 'connected', 'error', 'disconnected'))
);

-- Unique index for platform_integrations (partial index for active integrations only)
CREATE UNIQUE INDEX IF NOT EXISTS idx_platform_integrations_unique_name 
    ON platform_integrations(integration_type, integration_name) 
    WHERE deleted_at IS NULL;

-- Indexes for platform_integrations
CREATE INDEX IF NOT EXISTS idx_platform_integrations_type ON platform_integrations(integration_type);
CREATE INDEX IF NOT EXISTS idx_platform_integrations_status ON platform_integrations(status);
CREATE INDEX IF NOT EXISTS idx_platform_integrations_enabled ON platform_integrations(is_enabled) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_platform_integrations_active ON platform_integrations(is_active) WHERE deleted_at IS NULL;

-- Comprehensive super_admin permission catch-all (idempotent)
-- Ensures super_admin always has ALL platform permissions regardless of when individual
-- permissions were inserted relative to role_permission assignments in schema.sql.
-- This is the definitive fix for "admin user missing permission X" on fresh deployments.
INSERT INTO platform_role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM platform_roles r
CROSS JOIN platform_permissions p
WHERE r.name = 'super_admin'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Ensure platform.analytics exists and is assigned to platform_admin
-- (Required for admin-ui dashboard; platform_admin may not receive it via schema.sql
-- if the permission was inserted after the platform_admin role_permissions block ran.)
INSERT INTO platform_permissions (name, resource, action, description)
SELECT 'platform.analytics', 'platform', 'read', 'View platform analytics'
WHERE NOT EXISTS (SELECT 1 FROM platform_permissions WHERE name = 'platform.analytics');

INSERT INTO platform_role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM platform_roles r
CROSS JOIN platform_permissions p
WHERE r.name = 'platform_admin'
  AND p.name = 'platform.analytics'
ON CONFLICT (role_id, permission_id) DO NOTHING;
