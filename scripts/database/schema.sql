-- =================================================================
-- VistaPlatform - Consolidated Database Schema
-- =================================================================
-- Single source of truth for database initialization. On fresh deploy,
-- PostgreSQL runs this file as 01-schema.sql from docker-entrypoint-initdb.d.
-- All schema changes are made directly here; no migration scripts are run.
--
-- Last consolidated:
--
-- This file is re-applied by the chart's schema-migration Job on every
-- helm upgrade under `psql -v ON_ERROR_STOP=1`. Every statement here must
-- be idempotent: CREATE * uses IF NOT EXISTS (or OR REPLACE for views and
-- triggers, or a DO/EXCEPTION wrap for policies which have neither form),
-- ALTER TABLE ADD CONSTRAINT is wrapped in a pg_constraint existence check,
-- and ATTACH PARTITION is gated on pg_inherits. The previous safety
-- override (`\set ON_ERROR_STOP off`) was removed once all non-idempotent
-- statements were patched, so a real schema bug in any future change
-- will now halt the migration instead of being silently swallowed.
-- =================================================================


-- SCHEMA: analytics
CREATE SCHEMA IF NOT EXISTS analytics;


-- SCHEMA: audit
CREATE SCHEMA IF NOT EXISTS audit;


-- SCHEMA: compliance
CREATE SCHEMA IF NOT EXISTS compliance;


-- EXTENSION: pg_trgm
CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;


-- EXTENSION: pgcrypto
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


-- EXTENSION: uuid-ossp
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


-- TYPE: asset_type
DO $$ BEGIN CREATE TYPE public.asset_type AS ENUM (
    'server', 'endpoint', 'service', 'appliance'
); EXCEPTION WHEN duplicate_object THEN NULL; END $$;


-- TYPE: device_job_status
DO $$ BEGIN CREATE TYPE public.device_job_status AS ENUM (
    'pending', 'assigned', 'in_progress', 'completed', 'failed', 'cancelled'
); EXCEPTION WHEN duplicate_object THEN NULL; END $$;


-- TYPE: device_job_type
DO $$ BEGIN CREATE TYPE public.device_job_type AS ENUM (
    'device_interrogation', 'cloud_discovery'
); EXCEPTION WHEN duplicate_object THEN NULL; END $$;


-- TYPE: discovery_method
DO $$ BEGIN CREATE TYPE public.discovery_method AS ENUM (
    'passive', 'active', 'manual', 'integration',
    'device_interrogation', 'cloud_api', 'source_code_scan', 'host_scan'
); EXCEPTION WHEN duplicate_object THEN NULL; END $$;


-- TYPE: environment_type
DO $$ BEGIN CREATE TYPE public.environment_type AS ENUM (
    'production', 'staging', 'development', 'test'
); EXCEPTION WHEN duplicate_object THEN NULL; END $$;


-- TYPE: file_format
DO $$ BEGIN CREATE TYPE public.file_format AS ENUM (
    'PDF', 'Excel', 'CSV', 'JSON'
); EXCEPTION WHEN duplicate_object THEN NULL; END $$;


-- TYPE: location_type
DO $$ BEGIN CREATE TYPE public.location_type AS ENUM (
    'region', 'country', 'datacenter', 'cloud_region',
    'office', 'site', 'colo', 'building', 'floor', 'rack'
); EXCEPTION WHEN duplicate_object THEN NULL; END $$;


-- TYPE: protocol_type
DO $$ BEGIN CREATE TYPE public.protocol_type AS ENUM (
    'TLS', 'SSH', 'IPSec', 'VPN', 'Database', 'API', 'SMB', 'Kerberos',
    -- OT/ICS protocols the sensor's industrial discovery emits.
    'Modbus', 'DNP3', 'MMS', 'ICCP', 'IEC62351', 'OPC_UA',
    'EtherNet_IP', 'BACnet', 'BACnet_SC', 'HART_IP', 'S7'
); EXCEPTION WHEN duplicate_object THEN NULL; END $$;


-- TYPE: report_status
DO $$ BEGIN CREATE TYPE public.report_status AS ENUM (
    'pending', 'generating', 'completed', 'failed', 'expired'
); EXCEPTION WHEN duplicate_object THEN NULL; END $$;


-- TYPE: report_type
DO $$ BEGIN CREATE TYPE public.report_type AS ENUM (
    'compliance', 'inventory', 'risk', 'certificate'
); EXCEPTION WHEN duplicate_object THEN NULL; END $$;


-- TYPE: sensor_status
DO $$ BEGIN CREATE TYPE public.sensor_status AS ENUM (
    'active', 'inactive', 'error', 'maintenance'
); EXCEPTION WHEN duplicate_object THEN NULL; END $$;


-- TYPE: sensor_type
DO $$ BEGIN CREATE TYPE public.sensor_type AS ENUM (
    'network', 'endpoint', 'cloud', 'api'
); EXCEPTION WHEN duplicate_object THEN NULL; END $$;


-- TYPE: subscription_tier
DO $$ BEGIN CREATE TYPE public.subscription_tier AS ENUM (
    'basic', 'professional', 'enterprise'
); EXCEPTION WHEN duplicate_object THEN NULL; END $$;


-- TYPE: user_role
DO $$ BEGIN CREATE TYPE public.user_role AS ENUM (
    'admin', 'analyst', 'viewer'
); EXCEPTION WHEN duplicate_object THEN NULL; END $$;


-- FUNCTION: create_activity_logs_partition(integer, integer)
CREATE OR REPLACE FUNCTION audit.create_activity_logs_partition(p_year integer, p_month integer) RETURNS text
    LANGUAGE plpgsql
    -- SECURITY DEFINER so this runs as the function owner (crypto_user, who owns
    -- audit.activity_logs). Under enforced RLS the audit-service calls this as
    -- the non-owner crypto_app role, which cannot CREATE a partition of an
    -- owner-owned table ("must be owner of table activity_logs"). Running
    -- the DDL as the definer keeps partition management working without granting
    -- the app role table ownership. search_path is pinned per SECURITY DEFINER
    -- best practice.
    SECURITY DEFINER
    SET search_path = audit, pg_catalog, pg_temp
    AS $$
DECLARE
    partition_name TEXT;
    start_date DATE;
    end_date DATE;
    create_stmt TEXT;
BEGIN
    partition_name := format('activity_logs_y%sm%s', p_year, lpad(p_month::text, 2, '0'));
    start_date := make_date(p_year, p_month, 1);
    end_date := start_date + interval '1 month';


    -- Check if partition already exists
    IF NOT EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'audit' AND c.relname = partition_name
    ) THEN
        create_stmt := format(
            'CREATE TABLE IF NOT EXISTS audit.%I PARTITION OF audit.activity_logs FOR VALUES FROM (%L) TO (%L)',
            partition_name,
            start_date,
            end_date
        );
        EXECUTE create_stmt;
        RETURN partition_name;
    END IF;


    RETURN NULL;
END;
$$;


-- FUNCTION: ensure_future_partitions(integer)
CREATE OR REPLACE FUNCTION audit.ensure_future_partitions(p_months_ahead integer DEFAULT 3) RETURNS TABLE(partition_name text, created boolean)
    LANGUAGE plpgsql
    -- SECURITY DEFINER (see create_activity_logs_partition above): it calls
    -- that function to materialize future partitions and must run as the owner.
    SECURITY DEFINER
    SET search_path = audit, pg_catalog, pg_temp
    AS $$
DECLARE
    current_date_val DATE := CURRENT_DATE;
    target_date DATE;
    i INT;
    part_name TEXT;
BEGIN
    FOR i IN 0..p_months_ahead LOOP
        target_date := current_date_val + (i || ' months')::interval;
        part_name := audit.create_activity_logs_partition(
            EXTRACT(YEAR FROM target_date)::INT,
            EXTRACT(MONTH FROM target_date)::INT
        );
        IF part_name IS NOT NULL THEN
            partition_name := part_name;
            created := true;
            RETURN NEXT;
        END IF;
    END LOOP;
END;
$$;


-- FUNCTION: auto_license_best_practices()
CREATE OR REPLACE FUNCTION public.auto_license_best_practices() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    best_practices_framework_id UUID;
    other_license_count INTEGER;
    default_count INTEGER;
BEGIN
    -- Scope app.tenant_id to the new tenant so the RLS policy on
    -- tenant_framework_licenses passes for both the reads and the INSERT.
    -- is_local=true limits the effect to this transaction.
    PERFORM set_config('app.tenant_id', NEW.id::text, true);


    -- Get Best Practices framework ID
    SELECT id INTO best_practices_framework_id
    FROM platform_frameworks
    WHERE is_platform_default = true AND status = 'published'
    LIMIT 1;


    -- Only proceed if Best Practices framework exists
    IF best_practices_framework_id IS NOT NULL THEN
        -- Check if tenant already has any licenses
        SELECT COUNT(*) INTO other_license_count
        FROM tenant_framework_licenses
        WHERE tenant_id = NEW.id;


        -- Check if tenant already has a default framework
        SELECT COUNT(*) INTO default_count
        FROM tenant_framework_licenses
        WHERE tenant_id = NEW.id
          AND is_default = true;


        -- Create Best Practices license (default if no other licenses OR no default exists)
        INSERT INTO tenant_framework_licenses (
            id, tenant_id, platform_framework_id, is_locked, locked_at, locked_by,
            is_default, purchased_at, created_at, updated_at
        ) VALUES (
            gen_random_uuid(), NEW.id, best_practices_framework_id, false, NULL, NULL,
            (other_license_count = 0 OR default_count = 0), NOW(), NOW(), NOW()
        )
        ON CONFLICT (tenant_id, platform_framework_id) DO UPDATE SET
            -- If license exists but no default, set Best Practices as default
            is_default = CASE
                WHEN default_count = 0 THEN true
                ELSE tenant_framework_licenses.is_default
            END,
            updated_at = NOW();
    END IF;


    RETURN NEW;
END;
$$;


-- FUNCTION: auto_license_iec62351_for_enterprise()
--
-- Auto-licenses the IEC 62351-3 / OT Crypto Profile platform framework
-- to Enterprise-tier tenants on INSERT to public.tenants. Mirrors the
-- auto_license_best_practices() pattern.
--
-- Tier choice: this targets the `enterprise` tier as a stand-in for an
-- explicit Energy/Utility tier that doesn't exist yet — Enterprise is
-- the only tier today that has `ot_active_probing` enabled, so it's the
-- closest match for "tenants who paid to do OT discovery." When an
-- explicit Energy/Utility tier is added to subscription_tiers, update
-- the WHERE clause below to include it.
--
-- is_default stays false: Best Practices keeps the default-framework
-- slot to avoid silently changing existing scoring semantics for
-- tenants who happen to have the IEC 62351-3 framework added.
CREATE OR REPLACE FUNCTION public.auto_license_iec62351_for_enterprise() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    iec62351_framework_id UUID;
    tier_name TEXT;
BEGIN
    -- Scope app.tenant_id to the new tenant so the RLS policy on
    -- tenant_framework_licenses passes for the INSERT below.
    -- is_local=true limits the effect to this transaction.
    PERFORM set_config('app.tenant_id', NEW.id::text, true);


    -- Tier check: only auto-license Enterprise tenants.
    SELECT name INTO tier_name
    FROM subscription_tiers
    WHERE id = NEW.subscription_tier_id;


    IF tier_name IS NULL OR tier_name <> 'enterprise' THEN
        RETURN NEW;
    END IF;


    -- Look up the IEC 62351-3 framework by its stable code. The seed
    -- file UPSERTs this on every install, but during a fresh-install
    -- ordering the seed runs *after* the schema, so for tenants
    -- created from `02-seed.sql` (e.g. democorp) this query returns
    -- NULL and the trigger no-ops gracefully — same defensive pattern
    -- auto_license_best_practices uses.
    SELECT id INTO iec62351_framework_id
    FROM platform_frameworks
    WHERE code = 'iec-62351-3' AND status = 'published'
    ORDER BY version DESC NULLS LAST
    LIMIT 1;


    IF iec62351_framework_id IS NULL THEN
        RETURN NEW;
    END IF;


    -- Idempotent: ON CONFLICT skips when the license already exists.
    INSERT INTO tenant_framework_licenses (
        id, tenant_id, platform_framework_id, is_locked, locked_at, locked_by,
        is_default, purchased_at, created_at, updated_at
    ) VALUES (
        gen_random_uuid(), NEW.id, iec62351_framework_id, false, NULL, NULL,
        false, NOW(), NOW(), NOW()
    )
    ON CONFLICT (tenant_id, platform_framework_id) DO NOTHING;


    RETURN NEW;
END;
$$;


-- FUNCTION: calculate_health_score(uuid, numeric, numeric, numeric, numeric, numeric, numeric, numeric, numeric, integer, integer, numeric, integer, integer, numeric, numeric, numeric)
CREATE OR REPLACE FUNCTION public.calculate_health_score(p_tenant_id uuid, p_cpu_util numeric, p_memory_util numeric, p_storage_util numeric, p_network_util numeric, p_response_time numeric, p_error_rate numeric, p_throughput numeric, p_uptime numeric, p_failed_logins integer, p_security_alerts integer, p_compliance_score numeric, p_active_users integer, p_api_calls integer, p_user_engagement numeric, p_cost_per_user numeric, p_cost_efficiency numeric) RETURNS numeric
    LANGUAGE plpgsql
    AS $$
DECLARE
    resource_score DECIMAL;
    performance_score DECIMAL;
    security_score DECIMAL;
    business_score DECIMAL;
    cost_score DECIMAL;
    overall_score DECIMAL;
BEGIN
    -- Resource Efficiency (25% weight)
    resource_score := (
        GREATEST(0, 100 - ABS(p_cpu_util - 65) * 2) * 0.3 +
        GREATEST(0, 100 - ABS(p_memory_util - 75) * 1.5) * 0.3 +
        GREATEST(0, 100 - ABS(p_storage_util - 80) * 1.2) * 0.25 +
        GREATEST(0, 100 - ABS(p_network_util - 55) * 1.8) * 0.15
    );


    -- Performance Metrics (25% weight)
    performance_score := (
        GREATEST(0, 100 - (p_response_time - 200) / 3) * 0.3 +
        GREATEST(0, 100 - p_error_rate * 5000) * 0.3 +
        LEAST(100, p_throughput / 10) * 0.2 +
        GREATEST(0, (p_uptime - 99) / 0.9 * 100) * 0.2
    );


    -- Security Posture (20% weight)
    security_score := (
        GREATEST(0, 100 - p_failed_logins * 10) * 0.25 +
        GREATEST(0, 100 - p_security_alerts * 20) * 0.25 +
        p_compliance_score * 0.3 +
        CASE
            WHEN p_compliance_score > 0 THEN 100
            ELSE 0
        END * 0.2
    );


    -- Business Activity (15% weight)
    business_score := (
        LEAST(100, p_active_users / 10) * 0.3 +
        LEAST(100, p_api_calls / 100) * 0.3 +
        p_user_engagement * 0.25 +
        50 * 0.15 -- Placeholder for feature usage
    );


    -- Cost Optimization (15% weight)
    cost_score := (
        GREATEST(0, 100 - (p_cost_per_user - 10) * 5) * 0.4 +
        p_cost_efficiency * 0.4 +
        50 * 0.2 -- Placeholder for resource cost optimization
    );


    -- Calculate weighted overall score
    overall_score := (
        resource_score * 0.25 +
        performance_score * 0.25 +
        security_score * 0.20 +
        business_score * 0.15 +
        cost_score * 0.15
    );


    RETURN GREATEST(0, LEAST(100, overall_score));
END;
$$;


-- FUNCTION: calculate_tenant_cost(uuid, timestamp with time zone, timestamp with time zone)
CREATE OR REPLACE FUNCTION public.calculate_tenant_cost(p_tenant_id uuid, p_period_start timestamp with time zone, p_period_end timestamp with time zone) RETURNS numeric
    LANGUAGE plpgsql
    AS $$
DECLARE
    total_cost DECIMAL(10,4) := 0;
    cost_rates JSONB;
BEGIN
    -- Get cost rates from config
    SELECT config_value INTO cost_rates
    FROM resource_tracking_config
    WHERE config_key = 'cost_rates';


    -- Calculate total cost for the period
    SELECT COALESCE(SUM(
        (api_calls * (cost_rates->>'api_call_cost')::DECIMAL) +
        (database_queries * (cost_rates->>'database_query_cost')::DECIMAL) +
        (storage_used_mb * (cost_rates->>'storage_cost_per_gb_month')::DECIMAL / 1024) +
        (cpu_usage_percent * (cost_rates->>'cpu_cost_per_percent')::DECIMAL) +
        (network_bytes * (cost_rates->>'network_cost_per_gb')::DECIMAL / (1024 * 1024 * 1024))
    ), 0) INTO total_cost
    FROM tenant_resource_usage
    WHERE tenant_id = p_tenant_id
    AND timestamp BETWEEN p_period_start AND p_period_end;


    RETURN total_cost;
END;
$$;


-- FUNCTION: cleanup_expired_dashboard_cache()
CREATE OR REPLACE FUNCTION public.cleanup_expired_dashboard_cache() RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM dashboard_cache WHERE expires_at < NOW();
END;
$$;


-- FUNCTION: cleanup_old_aws_cost_data(integer)
CREATE OR REPLACE FUNCTION public.cleanup_old_aws_cost_data(retention_days integer DEFAULT 365) RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    -- Delete AWS cost data older than retention_days
    DELETE FROM aws_cost_data
    WHERE cost_date < CURRENT_DATE - (retention_days || ' days')::INTERVAL;


    GET DIAGNOSTICS deleted_count = ROW_COUNT;


    -- Delete old sync job records (keep last 90 days)
    DELETE FROM aws_cost_sync_jobs
    WHERE created_at < NOW() - INTERVAL '90 days'
    AND status IN ('completed', 'failed');


    RETURN deleted_count;
END;
$$;


-- FUNCTION: cleanup_old_resource_usage()
CREATE OR REPLACE FUNCTION public.cleanup_old_resource_usage() RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Delete resource usage data older than 90 days
    DELETE FROM tenant_resource_usage
    WHERE timestamp < NOW() - INTERVAL '90 days';


    -- Delete resolved alerts older than 30 days
    DELETE FROM resource_alerts
    WHERE is_active = false
    AND resolved_at < NOW() - INTERVAL '30 days';
END;
$$;


-- FUNCTION: clear_tenant_context()
CREATE OR REPLACE FUNCTION public.clear_tenant_context() RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    AS $$
BEGIN
    PERFORM set_config('app.tenant_id', '', true);
END;
$$;


-- FUNCTION: create_system_sensors_for_tenant()
CREATE OR REPLACE FUNCTION public.create_system_sensors_for_tenant() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Insert Platform Discovery Sensor for the new tenant
    INSERT INTO sensors (
        id, tenant_id, name, description, platform, version, profile,
        sensor_type, status, network_interfaces, tags, last_heartbeat, created_at, updated_at
    ) VALUES (
        gen_random_uuid(),
        NEW.id,
        'Platform Discovery Sensor',
        'Platform-managed sensor for network discovery operations. This shared resource performs cryptographic asset discovery scans on your behalf.',
        'platform',
        'system',
        'discovery',
        'network',
        'active',
        ARRAY[]::TEXT[],
        ARRAY['system', 'platform', 'discovery']::TEXT[],
        NOW(),
        NOW(),
        NOW()
    )
    ON CONFLICT DO NOTHING;


    -- Insert Platform Device Interrogation Agent for the new tenant
    INSERT INTO sensors (
        id, tenant_id, name, description, platform, version, profile,
        sensor_type, status, network_interfaces, tags, last_heartbeat, created_at, updated_at
    ) VALUES (
        gen_random_uuid(),
        NEW.id,
        'Platform Device Interrogation Agent',
        'Platform-managed agent for device interrogation operations. This shared resource queries devices and cloud providers for cryptographic inventory on your behalf.',
        'platform',
        'system',
        'device_interrogation',
        'api',
        'active',
        ARRAY[]::TEXT[],
        ARRAY['system', 'platform', 'device_interrogation']::TEXT[],
        NOW(),
        NOW(),
        NOW()
    )
    ON CONFLICT DO NOTHING;


    RETURN NEW;
END;
$$;


-- FUNCTION: determine_health_status(numeric)
CREATE OR REPLACE FUNCTION public.determine_health_status(p_score numeric) RETURNS character varying
    LANGUAGE plpgsql
    AS $$
BEGIN
    CASE
        WHEN p_score >= 90 THEN RETURN 'excellent';
        WHEN p_score >= 75 THEN RETURN 'good';
        WHEN p_score >= 60 THEN RETURN 'fair';
        WHEN p_score >= 40 THEN RETURN 'poor';
        ELSE RETURN 'critical';
    END CASE;
END;
$$;


-- FUNCTION: expire_pending_sensors()
CREATE OR REPLACE FUNCTION public.expire_pending_sensors() RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE pending_sensor_registrations
    SET status = 'expired'
    WHERE status = 'pending'
      AND expires_at < NOW();
END;
$$;


-- FUNCTION: generate_tenant_slug(text)
CREATE OR REPLACE FUNCTION public.generate_tenant_slug(tenant_name text) RETURNS text
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN lower(regexp_replace(trim(tenant_name), '[^a-zA-Z0-9]+', '-', 'g'));
END;
$$;


-- FUNCTION: get_api_usage_stats(timestamp with time zone, timestamp with time zone)
CREATE OR REPLACE FUNCTION public.get_api_usage_stats(p_start_time timestamp with time zone, p_end_time timestamp with time zone) RETURNS TABLE(endpoint character varying, method character varying, total_requests bigint, avg_response_time numeric, error_count bigint, success_rate numeric)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT
        aul.endpoint,
        aul.method,
        COUNT(*) as total_requests,
        AVG(aul.response_time_ms) as avg_response_time,
        COUNT(*) FILTER (WHERE aul.status_code >= 400) as error_count,
        (COUNT(*) FILTER (WHERE aul.status_code < 400) * 100.0 / COUNT(*)) as success_rate
    FROM api_usage_logs aul
    WHERE aul.timestamp BETWEEN p_start_time AND p_end_time
    GROUP BY aul.endpoint, aul.method
    ORDER BY total_requests DESC;
END;
$$;


-- FUNCTION: get_platform_setting(character varying, jsonb)
CREATE OR REPLACE FUNCTION public.get_platform_setting(key_name character varying, default_value jsonb DEFAULT NULL::jsonb) RETURNS jsonb
    LANGUAGE plpgsql
    AS $$
DECLARE
    result JSONB;
BEGIN
    SELECT setting_value INTO result
    FROM platform_settings
    WHERE setting_key = key_name;


    RETURN COALESCE(result, default_value);
END;
$$;


-- FUNCTION: get_platform_setting_bool(character varying, boolean)
CREATE OR REPLACE FUNCTION public.get_platform_setting_bool(key_name character varying, default_value boolean DEFAULT false) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
DECLARE
    result JSONB;
BEGIN
    SELECT setting_value INTO result
    FROM platform_settings
    WHERE setting_key = key_name;


    IF result IS NULL THEN
        RETURN default_value;
    END IF;


    RETURN (result::text)::boolean;
END;
$$;


-- FUNCTION: get_system_health_summary()
CREATE OR REPLACE FUNCTION public.get_system_health_summary() RETURNS TABLE(service_name character varying, health_status character varying, avg_response_time numeric, error_rate numeric, last_check timestamp with time zone)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT
        shm.service_name,
        shm.health_status,
        AVG(shm.response_time_ms) as avg_response_time,
        (COUNT(*) FILTER (WHERE shm.health_status = 'down') * 100.0 / COUNT(*)) as error_rate,
        MAX(shm.timestamp) as last_check
    FROM system_health_metrics shm
    WHERE shm.timestamp > NOW() - INTERVAL '1 hour'
    GROUP BY shm.service_name, shm.health_status
    ORDER BY shm.service_name;
END;
$$;


-- FUNCTION: get_tenant_email_config(uuid)
CREATE OR REPLACE FUNCTION public.get_tenant_email_config(tenant_uuid uuid) RETURNS jsonb
    LANGUAGE plpgsql
    AS $$
DECLARE
    tenant_config JSONB;
    platform_config JSONB;
    use_platform_default BOOLEAN;
    tenant_email_config JSONB;
BEGIN
    -- Get platform default email config
    SELECT setting_value INTO platform_config
    FROM platform_settings
    WHERE setting_key = 'email_config';


    -- Get tenant admin settings
    SELECT config INTO tenant_config
    FROM tenant_admin_settings
    WHERE tenant_id = tenant_uuid;


    -- If no tenant settings, return platform default
    IF tenant_config IS NULL THEN
        RETURN platform_config;
    END IF;


    -- Extract email_config from tenant settings
    tenant_email_config := tenant_config->'email_config';


    -- If no email_config in tenant settings, return platform default
    IF tenant_email_config IS NULL THEN
        RETURN platform_config;
    END IF;


    -- Check if tenant wants to use platform default
    use_platform_default := COALESCE((tenant_email_config->>'use_platform_default')::boolean, true);


    IF use_platform_default THEN
        RETURN platform_config;
    END IF;


    -- Check if tenant has SMTP host configured (indicates custom SMTP)
    IF tenant_email_config->>'smtp_host' IS NOT NULL AND tenant_email_config->>'smtp_host' != '' THEN
        -- Return tenant config (password will be decrypted in application code)
        RETURN tenant_email_config;
    END IF;


    -- Fall back to platform default
    RETURN platform_config;
END;
$$;


-- FUNCTION: get_user_permissions(uuid, uuid)
CREATE OR REPLACE FUNCTION public.get_user_permissions(p_user_id uuid, p_tenant_id uuid) RETURNS TABLE(permission_name character varying, resource character varying, action character varying, scope character varying)
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public, pg_catalog, pg_temp
    AS $$
BEGIN
    RETURN QUERY
    SELECT tp.name, tp.resource, tp.action, tp.scope
    FROM user_tenant_roles utr
    JOIN tenant_role_permissions trp ON utr.role_id = trp.role_id
    JOIN tenant_permissions tp ON trp.permission_id = tp.id
    WHERE utr.user_id = p_user_id
      AND utr.tenant_id = p_tenant_id
      AND utr.is_active = true
      AND (utr.expires_at IS NULL OR utr.expires_at > NOW());
END;
$$;


-- FUNCTION: get_user_role(uuid, uuid)
CREATE OR REPLACE FUNCTION public.get_user_role(p_user_id uuid, p_tenant_id uuid) RETURNS character varying
    LANGUAGE plpgsql STABLE
    AS $$
DECLARE
    role_name VARCHAR(50);
BEGIN
    SELECT tr.name
    INTO role_name
    FROM user_tenant_roles utr
    JOIN tenant_roles tr ON utr.role_id = tr.id
    WHERE utr.user_id = p_user_id
      AND utr.tenant_id = p_tenant_id
      AND utr.is_active = true
    ORDER BY utr.assigned_at DESC
    LIMIT 1;


    -- Return default role if none found
    RETURN COALESCE(role_name, 'viewer');
END;
$$;


-- FUNCTION: log_tenant_admin_settings_change()
CREATE OR REPLACE FUNCTION public.log_tenant_admin_settings_change() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO tenant_admin_settings_audit (
        tenant_id,
        config_before,
        config_after,
        version_before,
        version_after,
        changed_by,
        change_reason,
        created_at
    )
    VALUES (
        NEW.tenant_id,
        OLD.config,
        NEW.config,
        OLD.version,
        NEW.version,
        NEW.updated_by,
        NULL, -- change_reason can be set in application code
        NOW()
    );
    RETURN NEW;
END;
$$;


-- FUNCTION: log_tier_change()
CREATE OR REPLACE FUNCTION public.log_tier_change() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    change_type_val VARCHAR(50);
    changes_json_val JSONB;
BEGIN
    -- Determine change type
    IF TG_OP = 'INSERT' THEN
        change_type_val := 'created';
        changes_json_val := jsonb_build_object(
            'after', to_jsonb(NEW)
        );
    ELSIF TG_OP = 'UPDATE' THEN
        change_type_val := 'modified';
        changes_json_val := jsonb_build_object(
            'before', to_jsonb(OLD),
            'after', to_jsonb(NEW)
        );
    ELSIF TG_OP = 'DELETE' THEN
        change_type_val := 'deprecated';
        changes_json_val := jsonb_build_object(
            'before', to_jsonb(OLD)
        );
    END IF;


    -- Insert history record
    INSERT INTO subscription_tier_history (tier_id, change_type, changes_json, changed_at)
    VALUES (
        COALESCE(NEW.id, OLD.id),
        change_type_val,
        changes_json_val,
        NOW()
    );


    RETURN COALESCE(NEW, OLD);
END;
$$;


-- FUNCTION: platform_user_has_permission(uuid, character varying)
CREATE OR REPLACE FUNCTION public.platform_user_has_permission(p_user_id uuid, p_permission_name character varying) RETURNS boolean
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public, pg_catalog, pg_temp
    AS $$
DECLARE
    has_permission BOOLEAN := FALSE;
BEGIN
    -- Check if platform user has the permission through their role
    SELECT EXISTS(
        SELECT 1
        FROM platform_users pu
        JOIN platform_role_permissions prp ON pu.role_id = prp.role_id
        JOIN platform_permissions pp ON prp.permission_id = pp.id
        WHERE pu.id = p_user_id
          AND pu.is_active = true
          AND pu.deleted_at IS NULL
          AND pp.name = p_permission_name
    ) INTO has_permission;


    RETURN has_permission;
END;
$$;


-- FUNCTION: refresh_operational_views()
CREATE OR REPLACE FUNCTION public.refresh_operational_views() RETURNS void
    LANGUAGE plpgsql
    -- SECURITY DEFINER: REFRESH MATERIALIZED VIEW requires OWNERSHIP of the
    -- matview, and since the Phase 4 role split the caller (inventory-service's
    -- pool) is the non-owner crypto_app role — a plain-invoker call fails with
    -- "must be owner of materialized view" and the operational views silently
    -- go stale. Run as the definer (crypto_user, the owner) instead.
    -- search_path is pinned per SECURITY DEFINER best practice.
    SECURITY DEFINER
    SET search_path = public, pg_catalog, pg_temp
    AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_location_finding_summary;
    REFRESH MATERIALIZED VIEW mv_remediation_queue;
END;
$$;


-- FUNCTION: refresh_tenant_cost_summary()
-- SECURITY DEFINER for the same ownership reason as refresh_operational_views.
CREATE OR REPLACE FUNCTION public.refresh_tenant_cost_summary() RETURNS void
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public, pg_catalog, pg_temp
    AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY tenant_cost_summary;
END;
$$;


-- FUNCTION: set_tenant_context(uuid)
CREATE OR REPLACE FUNCTION public.set_tenant_context(tenant_uuid uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    AS $$
BEGIN
    -- NULL tenant_id must raise an error, not silently grant access
    IF tenant_uuid IS NULL THEN
        RAISE EXCEPTION 'tenant_uuid must not be NULL';
    END IF;
    PERFORM set_config('app.tenant_id', tenant_uuid::text, true);
END;
$$;


-- FUNCTION: set_trial_end_date()
CREATE OR REPLACE FUNCTION public.set_trial_end_date() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Set trial end date to 30 days from now if not specified
    IF NEW.trial_ends_at IS NULL THEN
        NEW.trial_ends_at = NOW() + INTERVAL '30 days';
    END IF;
    RETURN NEW;
END;
$$;


-- FUNCTION: update_algorithms_updated_at()
CREATE OR REPLACE FUNCTION public.update_algorithms_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


-- FUNCTION: update_certificates_updated_at()
CREATE OR REPLACE FUNCTION public.update_certificates_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    NEW.last_data_update = NOW();
    RETURN NEW;
END;
$$;


-- FUNCTION: update_device_jobs_updated_at()
CREATE OR REPLACE FUNCTION public.update_device_jobs_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


-- FUNCTION: update_tenant_usage(uuid, character varying, integer)
CREATE OR REPLACE FUNCTION public.update_tenant_usage(p_tenant_id uuid, p_metric_type character varying, p_delta integer) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO tenant_usage_tracking (tenant_id, metric_type, current_count, last_updated)
    VALUES (p_tenant_id, p_metric_type, GREATEST(0, p_delta), NOW())
    ON CONFLICT (tenant_id, metric_type)
    DO UPDATE SET
        current_count = GREATEST(0, tenant_usage_tracking.current_count + p_delta),
        last_updated = NOW();
END;
$$;


-- FUNCTION: update_tenant_user_count()
CREATE OR REPLACE FUNCTION public.update_tenant_user_count() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_tenant_id UUID;
BEGIN
    v_tenant_id := COALESCE(NEW.tenant_id, OLD.tenant_id);


    -- Skip if tenant no longer exists (e.g. during a cascade purge delete).
    -- Attempting to upsert tenant_usage for a deleted tenant violates the FK.
    IF NOT EXISTS (SELECT 1 FROM tenants WHERE id = v_tenant_id) THEN
        RETURN COALESCE(NEW, OLD);
    END IF;


    -- Update user count in current period usage
    INSERT INTO tenant_usage (tenant_id, users_count, billing_period_start, billing_period_end)
    VALUES (
        v_tenant_id,
        (SELECT COUNT(*) FROM users WHERE tenant_id = v_tenant_id AND deleted_at IS NULL),
        DATE_TRUNC('month', NOW())::DATE,
        (DATE_TRUNC('month', NOW()) + INTERVAL '1 month - 1 day')::DATE
    )
    ON CONFLICT (tenant_id, billing_period_start)
    DO UPDATE SET
        users_count = EXCLUDED.users_count,
        last_calculated_at = NOW();


    RETURN COALESCE(NEW, OLD);
END;
$$;


-- FUNCTION: update_updated_at_column()
CREATE OR REPLACE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


-- FUNCTION: user_has_permission(uuid, uuid, character varying)
CREATE OR REPLACE FUNCTION public.user_has_permission(p_user_id uuid, p_tenant_id uuid, p_permission_name character varying) RETURNS boolean
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public, pg_catalog, pg_temp
    AS $$
DECLARE
    has_permission BOOLEAN := FALSE;
BEGIN
    -- Check if user has the permission through their tenant role
    SELECT EXISTS(
        SELECT 1
        FROM user_tenant_roles utr
        JOIN tenant_role_permissions trp ON utr.role_id = trp.role_id
        JOIN tenant_permissions tp ON trp.permission_id = tp.id
        WHERE utr.user_id = p_user_id
          AND utr.tenant_id = p_tenant_id
          AND utr.is_active = true
          AND (utr.expires_at IS NULL OR utr.expires_at > NOW())
          AND tp.name = p_permission_name
    ) INTO has_permission;


    RETURN has_permission;
END;
$$;


SET default_tablespace = '';


-- TABLE: activity_logs
CREATE TABLE IF NOT EXISTS audit.activity_logs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    user_id uuid,
    user_type character varying(20) NOT NULL,
    user_email character varying(255),
    event_type character varying(100) NOT NULL,
    event_category character varying(50) NOT NULL,
    action character varying(100) NOT NULL,
    resource_type character varying(100),
    resource_id uuid,
    old_values jsonb,
    new_values jsonb,
    changed_fields text[],
    ip_address inet,
    user_agent text,
    request_id character varying(255),
    session_id character varying(255),
    success boolean DEFAULT true,
    error_message text,
    error_code character varying(50),
    compliance_tags text[],
    requires_attention boolean DEFAULT false,
    metadata jsonb DEFAULT '{}'::jsonb,
    tags text[],
    occurred_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_event_category CHECK (((event_category)::text = ANY ((ARRAY['asset'::character varying, 'discovery'::character varying, 'compliance'::character varying, 'user'::character varying, 'tenant'::character varying, 'system'::character varying, 'report'::character varying, 'certificate'::character varying, 'data'::character varying, 'config'::character varying, 'job'::character varying, 'authentication'::character varying])::text[]))),
    CONSTRAINT valid_user_type CHECK (((user_type)::text = ANY ((ARRAY['tenant'::character varying, 'platform'::character varying])::text[])))
)
PARTITION BY RANGE (occurred_at);


SET default_table_access_method = heap;


-- TABLE: activity_logs_y2026m04
CREATE TABLE IF NOT EXISTS audit.activity_logs_y2026m04 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    user_id uuid,
    user_type character varying(20) NOT NULL,
    user_email character varying(255),
    event_type character varying(100) NOT NULL,
    event_category character varying(50) NOT NULL,
    action character varying(100) NOT NULL,
    resource_type character varying(100),
    resource_id uuid,
    old_values jsonb,
    new_values jsonb,
    changed_fields text[],
    ip_address inet,
    user_agent text,
    request_id character varying(255),
    session_id character varying(255),
    success boolean DEFAULT true,
    error_message text,
    error_code character varying(50),
    compliance_tags text[],
    requires_attention boolean DEFAULT false,
    metadata jsonb DEFAULT '{}'::jsonb,
    tags text[],
    occurred_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_event_category CHECK (((event_category)::text = ANY ((ARRAY['asset'::character varying, 'discovery'::character varying, 'compliance'::character varying, 'user'::character varying, 'tenant'::character varying, 'system'::character varying, 'report'::character varying, 'certificate'::character varying, 'data'::character varying, 'config'::character varying, 'job'::character varying, 'authentication'::character varying])::text[]))),
    CONSTRAINT valid_user_type CHECK (((user_type)::text = ANY ((ARRAY['tenant'::character varying, 'platform'::character varying])::text[])))
);


-- TABLE: activity_logs_y2026m05
CREATE TABLE IF NOT EXISTS audit.activity_logs_y2026m05 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    user_id uuid,
    user_type character varying(20) NOT NULL,
    user_email character varying(255),
    event_type character varying(100) NOT NULL,
    event_category character varying(50) NOT NULL,
    action character varying(100) NOT NULL,
    resource_type character varying(100),
    resource_id uuid,
    old_values jsonb,
    new_values jsonb,
    changed_fields text[],
    ip_address inet,
    user_agent text,
    request_id character varying(255),
    session_id character varying(255),
    success boolean DEFAULT true,
    error_message text,
    error_code character varying(50),
    compliance_tags text[],
    requires_attention boolean DEFAULT false,
    metadata jsonb DEFAULT '{}'::jsonb,
    tags text[],
    occurred_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_event_category CHECK (((event_category)::text = ANY ((ARRAY['asset'::character varying, 'discovery'::character varying, 'compliance'::character varying, 'user'::character varying, 'tenant'::character varying, 'system'::character varying, 'report'::character varying, 'certificate'::character varying, 'data'::character varying, 'config'::character varying, 'job'::character varying, 'authentication'::character varying])::text[]))),
    CONSTRAINT valid_user_type CHECK (((user_type)::text = ANY ((ARRAY['tenant'::character varying, 'platform'::character varying])::text[])))
);


-- TABLE: activity_logs_y2026m06
CREATE TABLE IF NOT EXISTS audit.activity_logs_y2026m06 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    user_id uuid,
    user_type character varying(20) NOT NULL,
    user_email character varying(255),
    event_type character varying(100) NOT NULL,
    event_category character varying(50) NOT NULL,
    action character varying(100) NOT NULL,
    resource_type character varying(100),
    resource_id uuid,
    old_values jsonb,
    new_values jsonb,
    changed_fields text[],
    ip_address inet,
    user_agent text,
    request_id character varying(255),
    session_id character varying(255),
    success boolean DEFAULT true,
    error_message text,
    error_code character varying(50),
    compliance_tags text[],
    requires_attention boolean DEFAULT false,
    metadata jsonb DEFAULT '{}'::jsonb,
    tags text[],
    occurred_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_event_category CHECK (((event_category)::text = ANY ((ARRAY['asset'::character varying, 'discovery'::character varying, 'compliance'::character varying, 'user'::character varying, 'tenant'::character varying, 'system'::character varying, 'report'::character varying, 'certificate'::character varying, 'data'::character varying, 'config'::character varying, 'job'::character varying, 'authentication'::character varying])::text[]))),
    CONSTRAINT valid_user_type CHECK (((user_type)::text = ANY ((ARRAY['tenant'::character varying, 'platform'::character varying])::text[])))
);


-- TABLE: activity_logs_y2026m07
CREATE TABLE IF NOT EXISTS audit.activity_logs_y2026m07 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    user_id uuid,
    user_type character varying(20) NOT NULL,
    user_email character varying(255),
    event_type character varying(100) NOT NULL,
    event_category character varying(50) NOT NULL,
    action character varying(100) NOT NULL,
    resource_type character varying(100),
    resource_id uuid,
    old_values jsonb,
    new_values jsonb,
    changed_fields text[],
    ip_address inet,
    user_agent text,
    request_id character varying(255),
    session_id character varying(255),
    success boolean DEFAULT true,
    error_message text,
    error_code character varying(50),
    compliance_tags text[],
    requires_attention boolean DEFAULT false,
    metadata jsonb DEFAULT '{}'::jsonb,
    tags text[],
    occurred_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_event_category CHECK (((event_category)::text = ANY ((ARRAY['asset'::character varying, 'discovery'::character varying, 'compliance'::character varying, 'user'::character varying, 'tenant'::character varying, 'system'::character varying, 'report'::character varying, 'certificate'::character varying, 'data'::character varying, 'config'::character varying, 'job'::character varying, 'authentication'::character varying])::text[]))),
    CONSTRAINT valid_user_type CHECK (((user_type)::text = ANY ((ARRAY['tenant'::character varying, 'platform'::character varying])::text[])))
);


-- TABLE: activity_logs_y2026m08
CREATE TABLE IF NOT EXISTS audit.activity_logs_y2026m08 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    user_id uuid,
    user_type character varying(20) NOT NULL,
    user_email character varying(255),
    event_type character varying(100) NOT NULL,
    event_category character varying(50) NOT NULL,
    action character varying(100) NOT NULL,
    resource_type character varying(100),
    resource_id uuid,
    old_values jsonb,
    new_values jsonb,
    changed_fields text[],
    ip_address inet,
    user_agent text,
    request_id character varying(255),
    session_id character varying(255),
    success boolean DEFAULT true,
    error_message text,
    error_code character varying(50),
    compliance_tags text[],
    requires_attention boolean DEFAULT false,
    metadata jsonb DEFAULT '{}'::jsonb,
    tags text[],
    occurred_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_event_category CHECK (((event_category)::text = ANY ((ARRAY['asset'::character varying, 'discovery'::character varying, 'compliance'::character varying, 'user'::character varying, 'tenant'::character varying, 'system'::character varying, 'report'::character varying, 'certificate'::character varying, 'data'::character varying, 'config'::character varying, 'job'::character varying, 'authentication'::character varying])::text[]))),
    CONSTRAINT valid_user_type CHECK (((user_type)::text = ANY ((ARRAY['tenant'::character varying, 'platform'::character varying])::text[])))
);


-- TABLE: alert_instances
CREATE TABLE IF NOT EXISTS audit.alert_instances (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rule_id uuid NOT NULL,
    tenant_id uuid,
    severity character varying(20) NOT NULL,
    event_count integer DEFAULT 1 NOT NULL,
    first_event_at timestamp without time zone NOT NULL,
    last_event_at timestamp without time zone NOT NULL,
    triggering_event jsonb NOT NULL,
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    acknowledged_by uuid,
    acknowledged_at timestamp without time zone,
    resolved_at timestamp without time zone,
    notes text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT alert_instances_severity_check CHECK (((severity)::text = ANY ((ARRAY['critical'::character varying, 'high'::character varying, 'medium'::character varying, 'low'::character varying])::text[]))),
    CONSTRAINT alert_instances_status_check CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'acknowledged'::character varying, 'resolved'::character varying])::text[])))
);


-- TABLE: alert_rules
CREATE TABLE IF NOT EXISTS audit.alert_rules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    name character varying(255) NOT NULL,
    description text,
    rule_type character varying(50) NOT NULL,
    is_enabled boolean DEFAULT true NOT NULL,
    severity character varying(20) NOT NULL,
    conditions jsonb NOT NULL,
    actions jsonb NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT alert_rules_rule_type_check CHECK (((rule_type)::text = ANY ((ARRAY['threshold'::character varying, 'pattern'::character varying, 'anomaly'::character varying])::text[]))),
    CONSTRAINT alert_rules_severity_check CHECK (((severity)::text = ANY ((ARRAY['critical'::character varying, 'high'::character varying, 'medium'::character varying, 'low'::character varying])::text[])))
);


-- TABLE: audit_logs
CREATE TABLE IF NOT EXISTS audit.audit_logs (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid,
    user_id uuid,
    action character varying(100) NOT NULL,
    resource_type character varying(100),
    resource_id uuid,
    old_values jsonb,
    new_values jsonb,
    ip_address inet,
    user_agent text,
    success boolean DEFAULT true,
    error_message text,
    created_at timestamp with time zone DEFAULT now()
);


-- TABLE: job_execution_logs
CREATE TABLE IF NOT EXISTS audit.job_execution_logs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    job_id uuid NOT NULL,
    job_type character varying(100) NOT NULL,
    job_name character varying(255),
    tenant_id uuid,
    initiated_by uuid,
    status character varying(50) NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    duration_ms integer,
    items_processed integer DEFAULT 0,
    items_succeeded integer DEFAULT 0,
    items_failed integer DEFAULT 0,
    error_message text,
    error_details jsonb,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_job_status CHECK (((status)::text = ANY ((ARRAY['queued'::character varying, 'running'::character varying, 'completed'::character varying, 'failed'::character varying, 'cancelled'::character varying])::text[])))
);


-- VIEW: partition_info
CREATE OR REPLACE VIEW audit.partition_info AS
 SELECT c.relname AS partition_name,
    pg_get_expr(c.relpartbound, c.oid, true) AS partition_bounds,
    pg_size_pretty(pg_relation_size((c.oid)::regclass)) AS partition_size,
    pg_stat_user_tables.n_live_tup AS row_count
   FROM ((pg_class c
     JOIN pg_namespace n ON ((n.oid = c.relnamespace)))
     LEFT JOIN pg_stat_user_tables ON ((pg_stat_user_tables.relid = c.oid)))
  WHERE ((n.nspname = 'audit'::name) AND (c.relname ~~ 'activity_logs_y%'::text))
  ORDER BY c.relname;


-- TABLE: retention_jobs
CREATE TABLE IF NOT EXISTS audit.retention_jobs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    policy_id uuid,
    job_type character varying(50) NOT NULL,
    logs_processed integer DEFAULT 0,
    logs_archived integer DEFAULT 0,
    logs_deleted integer DEFAULT 0,
    logs_moved_to_cold_storage integer DEFAULT 0,
    started_at timestamp with time zone DEFAULT now(),
    completed_at timestamp with time zone,
    duration_ms integer,
    error_message text,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_job_type CHECK (((job_type)::text = ANY ((ARRAY['archive'::character varying, 'delete'::character varying, 'cold_storage'::character varying, 'full_retention'::character varying])::text[])))
);


-- TABLE: retention_policies
CREATE TABLE IF NOT EXISTS audit.retention_policies (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    policy_name character varying(100) NOT NULL,
    event_type character varying(100),
    compliance_framework character varying(50),
    hot_storage_days integer NOT NULL,
    cold_storage_days integer,
    total_retention_days integer NOT NULL,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_compliance_framework CHECK ((((compliance_framework)::text = ANY ((ARRAY['soc2'::character varying, 'iso27001'::character varying, 'gdpr'::character varying, 'hipaa'::character varying, 'pci_dss'::character varying])::text[])) OR (compliance_framework IS NULL))),
    CONSTRAINT valid_retention_days CHECK ((total_retention_days >= hot_storage_days))
);


-- TABLE: scheduled_compliance_reports
CREATE TABLE IF NOT EXISTS audit.scheduled_compliance_reports (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    framework character varying(50) NOT NULL,
    schedule character varying(100) NOT NULL,
    is_enabled boolean DEFAULT true NOT NULL,
    email_recipients jsonb DEFAULT '[]'::jsonb NOT NULL,
    include_summary boolean DEFAULT true NOT NULL,
    include_details boolean DEFAULT true NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    last_run_at timestamp without time zone,
    next_run_at timestamp without time zone,
    CONSTRAINT scheduled_compliance_reports_framework_check CHECK (((framework)::text = ANY ((ARRAY['soc2'::character varying, 'iso27001'::character varying, 'gdpr'::character varying, 'hipaa'::character varying, 'pci_dss'::character varying])::text[])))
);


-- TABLE: scheduled_report_executions
CREATE TABLE IF NOT EXISTS audit.scheduled_report_executions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    schedule_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    started_at timestamp without time zone DEFAULT now() NOT NULL,
    completed_at timestamp without time zone,
    report_data jsonb,
    error_message text,
    email_sent_at timestamp without time zone,
    email_recipients jsonb DEFAULT '[]'::jsonb NOT NULL,
    CONSTRAINT scheduled_report_executions_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'running'::character varying, 'completed'::character varying, 'failed'::character varying])::text[])))
);


-- TABLE: siem_health_checks
CREATE TABLE IF NOT EXISTS audit.siem_health_checks (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    integration_id uuid NOT NULL,
    checked_at timestamp without time zone DEFAULT now() NOT NULL,
    status character varying(20) NOT NULL,
    response_time_ms integer,
    error_message text,
    metadata jsonb,
    CONSTRAINT siem_health_checks_status_check CHECK (((status)::text = ANY ((ARRAY['healthy'::character varying, 'degraded'::character varying, 'unhealthy'::character varying])::text[])))
);


-- TABLE: siem_integrations
CREATE TABLE IF NOT EXISTS audit.siem_integrations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    name character varying(255) NOT NULL,
    type character varying(50) NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    config jsonb DEFAULT '{}'::jsonb NOT NULL,
    filters jsonb DEFAULT '{}'::jsonb NOT NULL,
    health_status character varying(20) DEFAULT 'unknown'::character varying,
    last_health_check timestamp without time zone,
    last_successful_send timestamp without time zone,
    last_error text,
    consecutive_failures integer DEFAULT 0,
    total_events_sent bigint DEFAULT 0,
    total_events_failed bigint DEFAULT 0,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT siem_integrations_health_status_check CHECK (((health_status)::text = ANY ((ARRAY['healthy'::character varying, 'degraded'::character varying, 'unhealthy'::character varying, 'unknown'::character varying])::text[]))),
    CONSTRAINT siem_integrations_type_check CHECK (((type)::text = ANY ((ARRAY['splunk'::character varying, 'datadog'::character varying, 'elastic'::character varying, 'generic_webhook'::character varying])::text[])))
);


-- TABLE: access_pattern_analysis
CREATE TABLE IF NOT EXISTS public.access_pattern_analysis (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    pattern_type character varying(50) NOT NULL,
    pattern_key character varying(255) NOT NULL,
    baseline_metrics jsonb DEFAULT '{}'::jsonb,
    current_metrics jsonb DEFAULT '{}'::jsonb,
    anomaly_score numeric(5,2) DEFAULT 0.0,
    is_anomaly boolean DEFAULT false,
    anomaly_details jsonb DEFAULT '{}'::jsonb,
    confidence numeric(5,2) DEFAULT 0.0,
    tenant_id uuid,
    user_id uuid,
    service_name character varying(100),
    analysis_period_start timestamp with time zone NOT NULL,
    analysis_period_end timestamp with time zone NOT NULL,
    analyzed_at timestamp with time zone DEFAULT now(),
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_anomaly_score CHECK (((anomaly_score >= 0.0) AND (anomaly_score <= 100.0))),
    CONSTRAINT valid_confidence CHECK (((confidence >= 0.0) AND (confidence <= 100.0))),
    CONSTRAINT valid_pattern_type CHECK (((pattern_type)::text = ANY ((ARRAY['user_access'::character varying, 'ip_access'::character varying, 'endpoint_access'::character varying, 'geographic'::character varying, 'temporal'::character varying, 'behavioral'::character varying])::text[])))
);


-- TABLE: resource_alerts
CREATE TABLE IF NOT EXISTS public.resource_alerts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    alert_type character varying(50) NOT NULL,
    metric character varying(100) NOT NULL,
    threshold numeric(10,4) NOT NULL,
    current_value numeric(10,4) NOT NULL,
    message text NOT NULL,
    severity character varying(20) NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone
);


-- TABLE: tenants
CREATE TABLE IF NOT EXISTS public.tenants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    slug character varying(100) NOT NULL,
    domain character varying(255),
    subscription_tier_id uuid,
    trial_ends_at timestamp with time zone DEFAULT (now() + '30 days'::interval),
    billing_email character varying(255),
    payment_status character varying(50) DEFAULT 'trial'::character varying,
    stripe_customer_id character varying(255),
    stripe_subscription_id character varying(255),
    sso_enabled boolean DEFAULT false,
    authentication_policy character varying(50) DEFAULT 'password_only'::character varying,
    custom_branding jsonb DEFAULT '{}'::jsonb,
    ui_config jsonb DEFAULT '{}'::jsonb,
    settings jsonb DEFAULT '{}'::jsonb,
    grace_period_ends_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    onboarding_status character varying(50) DEFAULT 'pending'::character varying,
    CONSTRAINT valid_authentication_policy CHECK (((authentication_policy)::text = ANY ((ARRAY['password_only'::character varying, 'prefer_sso'::character varying, 'enforce_sso'::character varying, 'sso_only'::character varying])::text[]))),
    CONSTRAINT valid_onboarding_status CHECK (((onboarding_status)::text = ANY ((ARRAY['pending'::character varying, 'tier_selected'::character varying, 'billing_complete'::character varying, 'onboarding_complete'::character varying])::text[]))),
    CONSTRAINT valid_payment_status CHECK (((payment_status)::text = ANY ((ARRAY['trial'::character varying, 'active'::character varying, 'past_due'::character varying, 'canceled'::character varying, 'incomplete'::character varying, 'suspended'::character varying])::text[]))),
    CONSTRAINT valid_slug CHECK (((slug)::text ~ '^[a-z0-9-]+$'::text))
);


-- VIEW: active_resource_alerts
CREATE OR REPLACE VIEW public.active_resource_alerts AS
 SELECT ra.id,
    ra.tenant_id,
    t.name AS tenant_name,
    ra.alert_type,
    ra.metric,
    ra.threshold,
    ra.current_value,
    ra.message,
    ra.severity,
    ra.created_at
   FROM (public.resource_alerts ra
     JOIN public.tenants t ON ((ra.tenant_id = t.id)))
  WHERE (ra.is_active = true)
  ORDER BY ra.severity DESC, ra.created_at DESC;


-- TABLE: agent_ca_certificates
CREATE TABLE IF NOT EXISTS public.agent_ca_certificates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    ca_cert_pem text NOT NULL,
    ca_key_pem_encrypted text NOT NULL,
    serial_number bigint NOT NULL,
    issued_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone NOT NULL,
    is_active boolean DEFAULT true,
    revoked_certificates text[] DEFAULT ARRAY[]::text[],
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: agent_certificates
CREATE TABLE IF NOT EXISTS public.agent_certificates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    certificate_pem text NOT NULL,
    serial_number character varying(255) NOT NULL,
    issued_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    revocation_reason character varying(50),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: ai_analysis_results
CREATE TABLE IF NOT EXISTS public.ai_analysis_results (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    model_id uuid NOT NULL,
    target_type character varying(50) NOT NULL,
    target_id uuid NOT NULL,
    analysis_type character varying(100) NOT NULL,
    confidence_score numeric(3,2),
    results jsonb NOT NULL,
    anomaly_detected boolean DEFAULT false,
    risk_level character varying(20),
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_confidence CHECK (((confidence_score IS NULL) OR ((confidence_score >= 0.0) AND (confidence_score <= 1.0)))),
    CONSTRAINT valid_risk_level CHECK (((risk_level IS NULL) OR ((risk_level)::text = ANY ((ARRAY['low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying])::text[]))))
);


-- TABLE: ai_models
CREATE TABLE IF NOT EXISTS public.ai_models (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(255) NOT NULL,
    version character varying(50) NOT NULL,
    model_type character varying(100) NOT NULL,
    description text,
    file_path character varying(500),
    hyperparameters jsonb DEFAULT '{}'::jsonb,
    metrics jsonb DEFAULT '{}'::jsonb,
    active boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: algorithms
CREATE TABLE IF NOT EXISTS public.algorithms (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    code character varying(100) NOT NULL,
    category character varying(50) NOT NULL,
    subcategory character varying(50),
    name character varying(255) NOT NULL,
    description text,
    strength character varying(20) DEFAULT 'acceptable'::character varying NOT NULL,
    deprecation_status character varying(20) DEFAULT 'current'::character varying,
    deprecation_date date,
    risk_score integer DEFAULT 50,
    recommended_alternatives text[],
    migration_guidance text,
    remediation_guidance jsonb DEFAULT '{}'::jsonb,
    compliance_mappings jsonb DEFAULT '{}'::jsonb,
    metadata jsonb DEFAULT '{}'::jsonb,
    is_standard boolean DEFAULT true,
    is_pqc boolean DEFAULT false,
    pqc_standardization_status character varying(20) DEFAULT 'none'::character varying,
    algorithm_family character varying(100),
    primitive character varying(50),
    mode character varying(50),
    padding character varying(50),
    oid character varying(100),
    crypto_functions text[],
    classical_security_level integer,
    nist_quantum_security_level integer,
    parameter_set_identifier character varying(100),
    curve character varying(100),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_category CHECK (((category)::text = ANY ((ARRAY['hash'::character varying, 'symmetric'::character varying, 'key_exchange'::character varying, 'signature'::character varying, 'protocol_version'::character varying, 'cipher_suite'::character varying])::text[]))),
    CONSTRAINT valid_classical_security_level CHECK (((classical_security_level IS NULL) OR (classical_security_level > 0))),
    CONSTRAINT valid_deprecation_status CHECK (((deprecation_status)::text = ANY ((ARRAY['current'::character varying, 'deprecated'::character varying, 'obsolete'::character varying])::text[]))),
    CONSTRAINT valid_nist_quantum_level CHECK (((nist_quantum_security_level IS NULL) OR ((nist_quantum_security_level >= 0) AND (nist_quantum_security_level <= 5)))),
    CONSTRAINT valid_pqc_status CHECK (((pqc_standardization_status)::text = ANY ((ARRAY['none'::character varying, 'standardized'::character varying, 'candidate'::character varying, 'alternative'::character varying])::text[]))),
    CONSTRAINT valid_primitive CHECK (((primitive IS NULL) OR ((primitive)::text = ANY ((ARRAY['ae'::character varying, 'signature'::character varying, 'hash'::character varying, 'kem'::character varying, 'key-agree'::character varying, 'pke'::character varying, 'key-wrap'::character varying, 'combiner'::character varying, 'mac'::character varying, 'block-cipher'::character varying, 'stream-cipher'::character varying, 'kdf'::character varying, 'xof'::character varying, 'drbg'::character varying, 'other'::character varying])::text[])))),
    CONSTRAINT valid_risk_score CHECK (((risk_score >= 0) AND (risk_score <= 100))),
    CONSTRAINT valid_strength CHECK (((strength)::text = ANY ((ARRAY['weak'::character varying, 'acceptable'::character varying, 'strong'::character varying, 'recommended'::character varying])::text[])))
);


-- TABLE: api_format_preferences
CREATE TABLE IF NOT EXISTS public.api_format_preferences (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    endpoint_formats jsonb DEFAULT '{}'::jsonb,
    global_preferences jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: api_security_monitoring
CREATE TABLE IF NOT EXISTS public.api_security_monitoring (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    request_id character varying(255) NOT NULL,
    correlation_id character varying(255),
    endpoint character varying(500) NOT NULL,
    method character varying(10) NOT NULL,
    service_name character varying(100) NOT NULL,
    source_ip inet NOT NULL,
    user_agent text,
    user_id uuid,
    tenant_id uuid,
    request_size integer,
    response_size integer,
    response_status integer NOT NULL,
    latency_ms integer,
    is_rate_limited boolean DEFAULT false,
    rate_limit_reason character varying(100),
    is_suspicious boolean DEFAULT false,
    suspicious_reasons text[],
    abuse_score numeric(5,2) DEFAULT 0.0,
    abuse_patterns text[],
    "timestamp" timestamp with time zone NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb,
    tags text[],
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_abuse_score CHECK (((abuse_score >= 0.0) AND (abuse_score <= 100.0))),
    CONSTRAINT valid_method CHECK (((method)::text = ANY ((ARRAY['GET'::character varying, 'POST'::character varying, 'PUT'::character varying, 'PATCH'::character varying, 'DELETE'::character varying, 'HEAD'::character varying, 'OPTIONS'::character varying])::text[])))
);


-- TABLE: api_usage_logs
CREATE TABLE IF NOT EXISTS public.api_usage_logs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    endpoint character varying(255) NOT NULL,
    method character varying(10) NOT NULL,
    status_code integer NOT NULL,
    response_time_ms integer NOT NULL,
    user_id uuid,
    tenant_id uuid,
    ip_address inet,
    user_agent text,
    request_size_bytes integer,
    response_size_bytes integer,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL
);


-- TABLE: asset_history
CREATE TABLE IF NOT EXISTS public.asset_history (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    asset_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    actor_user_id uuid,
    source text NOT NULL,
    action text NOT NULL,
    changes_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


-- TABLE: asset_lifecycle_policies
CREATE TABLE IF NOT EXISTS public.asset_lifecycle_policies (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    stale_warning_days integer DEFAULT 30,
    stale_archived_days integer DEFAULT 60,
    auto_archive_enabled boolean DEFAULT true,
    notifications_enabled boolean DEFAULT true,
    revalidation_schedule jsonb DEFAULT '{"enabled": false, "interval_hours": 168}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: auth_audit_log
CREATE TABLE IF NOT EXISTS public.auth_audit_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    user_id uuid,
    event_type character varying(100) NOT NULL,
    event_status character varying(50) NOT NULL,
    auth_method character varying(50),
    ip_address inet,
    user_agent text,
    session_id character varying(255),
    event_data jsonb DEFAULT '{}'::jsonb,
    failure_reason text,
    occurred_at timestamp with time zone DEFAULT now()
);


-- TABLE: aws_cost_data
CREATE TABLE IF NOT EXISTS public.aws_cost_data (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    cost_date date NOT NULL,
    service_name character varying(100) NOT NULL,
    amount numeric(12,4) NOT NULL,
    currency character varying(10) DEFAULT 'USD'::character varying NOT NULL,
    usage_quantity numeric(15,6),
    usage_unit character varying(50),
    usage_type character varying(200),
    tags jsonb DEFAULT '{}'::jsonb,
    account_id character varying(20),
    region character varying(50),
    synced_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);


-- TABLE: aws_cost_sync_jobs
CREATE TABLE IF NOT EXISTS public.aws_cost_sync_jobs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    job_type character varying(50) NOT NULL,
    status character varying(20) NOT NULL,
    period_start date NOT NULL,
    period_end date NOT NULL,
    tenant_id uuid,
    start_time timestamp with time zone,
    end_time timestamp with time zone,
    records_synced integer DEFAULT 0,
    total_cost numeric(12,4),
    error_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT valid_job_type CHECK (((job_type)::text = ANY ((ARRAY['full_sync'::character varying, 'incremental'::character varying, 'tenant_sync'::character varying])::text[]))),
    CONSTRAINT valid_status CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'running'::character varying, 'completed'::character varying, 'failed'::character varying])::text[])))
);


-- VIEW: aws_daily_cost_summary
CREATE OR REPLACE VIEW public.aws_daily_cost_summary AS
 SELECT aws_cost_data.cost_date,
    aws_cost_data.tenant_id,
    count(DISTINCT aws_cost_data.service_name) AS service_count,
    sum(aws_cost_data.amount) AS total_cost_usd,
    sum(aws_cost_data.usage_quantity) AS total_usage_quantity,
    string_agg(DISTINCT (aws_cost_data.usage_unit)::text, ', '::text) AS usage_units,
    max(aws_cost_data.synced_at) AS last_synced_at
   FROM public.aws_cost_data
  GROUP BY aws_cost_data.cost_date, aws_cost_data.tenant_id;


-- VIEW: aws_daily_service_cost_summary
CREATE OR REPLACE VIEW public.aws_daily_service_cost_summary AS
 SELECT aws_cost_data.cost_date,
    aws_cost_data.service_name,
    count(DISTINCT aws_cost_data.tenant_id) AS tenant_count,
    sum(aws_cost_data.amount) AS total_cost_usd,
    sum(aws_cost_data.usage_quantity) AS total_usage_quantity,
    string_agg(DISTINCT (aws_cost_data.usage_unit)::text, ', '::text) AS usage_units,
    max(aws_cost_data.synced_at) AS last_synced_at
   FROM public.aws_cost_data
  GROUP BY aws_cost_data.cost_date, aws_cost_data.service_name;


-- VIEW: aws_tenant_monthly_cost_summary
CREATE OR REPLACE VIEW public.aws_tenant_monthly_cost_summary AS
 SELECT aws_cost_data.tenant_id,
    (date_trunc('month'::text, (aws_cost_data.cost_date)::timestamp with time zone))::date AS month,
    count(DISTINCT aws_cost_data.service_name) AS service_count,
    sum(aws_cost_data.amount) AS total_cost_usd,
    avg(aws_cost_data.amount) AS avg_daily_cost_usd,
    max(aws_cost_data.amount) AS max_daily_cost_usd,
    min(aws_cost_data.amount) AS min_daily_cost_usd,
    sum(aws_cost_data.usage_quantity) AS total_usage_quantity
   FROM public.aws_cost_data
  WHERE (aws_cost_data.tenant_id IS NOT NULL)
  GROUP BY aws_cost_data.tenant_id, ((date_trunc('month'::text, (aws_cost_data.cost_date)::timestamp with time zone))::date);


-- TABLE: billing_coupon_redemptions
CREATE TABLE IF NOT EXISTS public.billing_coupon_redemptions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    coupon_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    subscription_id uuid,
    redeemed_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone,
    is_active boolean DEFAULT true,
    metadata jsonb DEFAULT '{}'::jsonb
);


-- TABLE: billing_coupons
CREATE TABLE IF NOT EXISTS public.billing_coupons (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    code character varying(50) NOT NULL,
    name character varying(100) NOT NULL,
    discount_type character varying(20) NOT NULL,
    discount_value integer NOT NULL,
    duration character varying(20) NOT NULL,
    duration_in_months integer,
    max_redemptions integer,
    times_redeemed integer DEFAULT 0,
    valid_from timestamp with time zone DEFAULT now(),
    valid_until timestamp with time zone,
    is_active boolean DEFAULT true,
    stripe_coupon_id character varying(255),
    stripe_promotion_code_id character varying(255),
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: billing_customers
CREATE TABLE IF NOT EXISTS public.billing_customers (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    external_customer_id character varying(255) NOT NULL,
    email character varying(255),
    default_payment_method character varying(255),
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: billing_dunning_attempts
CREATE TABLE IF NOT EXISTS public.billing_dunning_attempts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    invoice_id uuid,
    attempt_number integer NOT NULL,
    status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    next_retry_at timestamp with time zone,
    error_message text,
    notification_sent boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: billing_events
CREATE TABLE IF NOT EXISTS public.billing_events (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    provider_id uuid NOT NULL,
    event_type character varying(100) NOT NULL,
    external_event_id character varying(255) NOT NULL,
    payload jsonb NOT NULL,
    received_at timestamp with time zone DEFAULT now(),
    processed_at timestamp with time zone,
    processing_status character varying(50) DEFAULT 'pending'::character varying,
    retry_count integer DEFAULT 0,
    last_error text,
    -- The async WebhookWorker and WebhookProcessor both stamp this when
    -- claiming/retrying/completing an event, and the stuck-event sweep reads it.
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: billing_invoice_line_items
CREATE TABLE IF NOT EXISTS public.billing_invoice_line_items (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    invoice_id uuid NOT NULL,
    description character varying(255) NOT NULL,
    quantity numeric(10,2) DEFAULT 1 NOT NULL,
    unit_price_cents integer NOT NULL,
    amount_cents integer NOT NULL,
    line_item_type character varying(50) NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now()
);


-- TABLE: billing_invoices
CREATE TABLE IF NOT EXISTS public.billing_invoices (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    external_invoice_id character varying(255) NOT NULL,
    amount_cents integer NOT NULL,
    currency character varying(10) DEFAULT 'USD'::character varying NOT NULL,
    status character varying(50) NOT NULL,
    issued_at timestamp with time zone,
    due_at timestamp with time zone,
    paid_at timestamp with time zone,
    pdf_url character varying(500),
    pdf_generated_at timestamp with time zone,
    invoice_number character varying(100),
    period_start timestamp with time zone,
    period_end timestamp with time zone,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    -- WebhookProcessor mirrors Stripe invoices with
    -- ON CONFLICT (provider_id, external_invoice_id); without this the upsert
    -- failed and no invoice ever persisted.
    CONSTRAINT billing_invoices_provider_external_key UNIQUE (provider_id, external_invoice_id)
);


-- TABLE: billing_providers
CREATE TABLE IF NOT EXISTS public.billing_providers (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    key character varying(50) NOT NULL,
    display_name character varying(100) NOT NULL,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: billing_subscriptions
CREATE TABLE IF NOT EXISTS public.billing_subscriptions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    external_subscription_id character varying(255) NOT NULL,
    plan_key character varying(100) NOT NULL,
    status character varying(50) NOT NULL,
    current_period_start timestamp with time zone,
    current_period_end timestamp with time zone,
    cancel_at_period_end boolean DEFAULT false,
    quantity integer DEFAULT 1,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    coupon_id uuid,
    -- 12-month contract model: every paid subscription is a one-year
    -- agreement. Stamped by admin-service at subscription creation and rolled
    -- forward by the invoice.paid webhook.
    contract_start timestamp with time zone,
    contract_end timestamp with time zone,
    -- HandleCreateSubscription upserts ON CONFLICT (tenant_id, provider_id).
    -- Without this the insert silently failed, so the local subscription cache
    -- was never written and the webhook sync could never flip a tenant to active.
    -- Current-state only; history lives in billing_invoices / billing_events.
    CONSTRAINT billing_subscriptions_tenant_provider_key UNIQUE (tenant_id, provider_id)
);


-- TABLE: billing_trial_tracking
CREATE TABLE IF NOT EXISTS public.billing_trial_tracking (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    trial_start timestamp with time zone NOT NULL,
    trial_end timestamp with time zone NOT NULL,
    notification_7days_sent boolean DEFAULT false,
    notification_1day_sent boolean DEFAULT false,
    trial_ended_notification_sent boolean DEFAULT false,
    converted_to_paid boolean DEFAULT false,
    converted_at timestamp with time zone,
    trial_extended_count integer DEFAULT 0,
    -- Phase-transition timestamps + soft-prompt notification flag. All NULL on a
    -- brand-new trial; soft_prompt_started_at populates at day trial_days_full,
    -- hard_locked_at at day trial_days_full + trial_days_soft.
    soft_prompt_started_at timestamp with time zone,
    hard_locked_at timestamp with time zone,
    notification_soft_prompt_sent boolean DEFAULT false,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: certificate_extensions
CREATE TABLE IF NOT EXISTS public.certificate_extensions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    certificate_id uuid NOT NULL,
    extension_type character varying(20) NOT NULL,
    extension_name character varying(255) NOT NULL,
    extension_value text NOT NULL,
    is_critical boolean DEFAULT false,
    extension_oid character varying(100),
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_extension_type CHECK (((extension_type)::text = ANY ((ARRAY['common'::character varying, 'custom'::character varying])::text[])))
);


-- TABLE: certificate_history
CREATE TABLE IF NOT EXISTS public.certificate_history (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    certificate_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    event_type character varying(50) NOT NULL,
    event_data jsonb DEFAULT '{}'::jsonb,
    previous_certificate_id uuid,
    discovered_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    created_by uuid,
    CONSTRAINT valid_event_type CHECK (((event_type)::text = ANY ((ARRAY['created'::character varying, 'renewed'::character varying, 'revoked'::character varying, 'expired'::character varying, 'updated'::character varying, 'data_enriched'::character varying])::text[])))
);


-- TABLE: certificates
CREATE TABLE IF NOT EXISTS public.certificates (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    serial_number character varying(255),
    subject_dn text NOT NULL,
    issuer_dn text NOT NULL,
    common_name character varying(255),
    subject_alternative_names text[],
    signature_algorithm character varying(100),
    public_key_algorithm character varying(100),
    public_key_size integer,
    not_before timestamp with time zone,
    not_after timestamp with time zone,
    fingerprint_sha1 character varying(40),
    fingerprint_sha256 character varying(64) NOT NULL,
    certificate_pem text,
    is_self_signed boolean DEFAULT false,
    is_ca_certificate boolean DEFAULT false,
    key_usage text[],
    extended_key_usage text[],
    issuer_certificate_id uuid,
    superseded_by_certificate_id uuid,
    certificate_state character varying(20) DEFAULT 'active'::character varying,
    certificate_state_reason text,
    revoked_at timestamp with time zone,
    revocation_discovered_at timestamp with time zone,
    certificate_format character varying(50) DEFAULT 'X.509'::character varying,
    activation_date timestamp with time zone,
    deactivation_date timestamp with time zone,
    destruction_date timestamp with time zone,
    signature_algorithm_oid character varying(100),
    public_key_algorithm_oid character varying(100),
    data_completeness character varying(20) DEFAULT 'complete'::character varying,
    data_source character varying(50),
    last_data_update timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    has_sct boolean,
    known_bad_ca character varying(100),
    is_ev boolean DEFAULT false,
    ocsp_status character varying(20),
    ocsp_detail text,
    cert_ownership character varying(50),
    -- Tightest expiry-alert tier (days; 0 = expired) already notified for this
    -- cert, so the scheduled certificate-expiry scan (ADR-0015 §6) escalates once
    -- per tier instead of re-notifying daily. NULL = not yet alerted / renewed
    -- beyond the widest tier.
    expiry_alert_tier integer,
    CONSTRAINT valid_certificate_format CHECK (((certificate_format)::text = ANY ((ARRAY['X.509'::character varying, 'PGP'::character varying, 'PKCS#7'::character varying, 'other'::character varying])::text[]))),
    CONSTRAINT valid_certificate_state CHECK (((certificate_state)::text = ANY ((ARRAY['pre-activation'::character varying, 'active'::character varying, 'suspended'::character varying, 'deactivated'::character varying, 'revoked'::character varying, 'expired'::character varying, 'destroyed'::character varying])::text[]))),
    CONSTRAINT valid_cert_ownership CHECK ((cert_ownership IS NULL OR (cert_ownership)::text = ANY ((ARRAY['internal'::character varying, 'third_party'::character varying])::text[]))),
    CONSTRAINT valid_data_completeness CHECK (((data_completeness)::text = ANY ((ARRAY['complete'::character varying, 'partial'::character varying, 'placeholder'::character varying])::text[]))),
    CONSTRAINT valid_fingerprint_sha1 CHECK (((fingerprint_sha1 IS NULL) OR ((fingerprint_sha1)::text ~ '^[a-fA-F0-9]{40}$'::text))),
    CONSTRAINT valid_fingerprint_sha256 CHECK (((fingerprint_sha256)::text ~ '^[a-fA-F0-9]{64}$'::text)),
    CONSTRAINT valid_key_size CHECK (((public_key_size IS NULL) OR (public_key_size > 0)))
);


-- TABLE: ci_relationships
CREATE TABLE IF NOT EXISTS public.ci_relationships (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    source_ci_type character varying(50) NOT NULL,
    source_ci_id uuid NOT NULL,
    relationship_type character varying(50) NOT NULL,
    target_ci_type character varying(50) NOT NULL,
    target_ci_id uuid NOT NULL,
    confidence_score numeric(3,2) DEFAULT 1.0,
    discovered_at timestamp with time zone DEFAULT now(),
    last_verified_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    CONSTRAINT no_self_relationship CHECK ((NOT (((source_ci_type)::text = (target_ci_type)::text) AND (source_ci_id = target_ci_id)))),
    CONSTRAINT valid_ci_confidence CHECK (((confidence_score >= 0.0) AND (confidence_score <= 1.0))),
    CONSTRAINT valid_ci_relationship_type CHECK (((relationship_type)::text = ANY ((ARRAY['uses'::character varying, 'installed_on'::character varying, 'contains'::character varying, 'issued_by'::character varying, 'depends_on'::character varying, 'protects'::character varying, 'associated_with'::character varying, 'configured_with'::character varying, 'runs_on'::character varying, 'hosts'::character varying])::text[]))),
    CONSTRAINT valid_ci_source_type CHECK (((source_ci_type)::text = ANY ((ARRAY['infrastructure_asset'::character varying, 'certificate'::character varying, 'key'::character varying, 'crypto_library'::character varying, 'crypto_configuration'::character varying])::text[]))),
    CONSTRAINT valid_ci_target_type CHECK (((target_ci_type)::text = ANY ((ARRAY['infrastructure_asset'::character varying, 'certificate'::character varying, 'key'::character varying, 'crypto_library'::character varying, 'crypto_configuration'::character varying])::text[])))
);


-- TABLE: cmdb_entity_mappings
CREATE TABLE IF NOT EXISTS public.cmdb_entity_mappings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    local_entity_type character varying(50) NOT NULL,
    local_entity_id uuid NOT NULL,
    cmdb_platform character varying(50) NOT NULL,
    cmdb_ci_type character varying(100) NOT NULL,
    cmdb_ci_id character varying(255),
    cmdb_sys_id character varying(255),
    sync_status character varying(20) DEFAULT 'pending'::character varying,
    last_synced_at timestamp with time zone,
    last_sync_error text,
    sync_direction character varying(20) DEFAULT 'push'::character varying,
    field_hash character varying(64),
    external_url text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_cmdb_entity_type CHECK (((local_entity_type)::text = ANY ((ARRAY['infrastructure_asset'::character varying, 'certificate'::character varying, 'key'::character varying, 'crypto_library'::character varying, 'crypto_configuration'::character varying])::text[]))),
    CONSTRAINT valid_cmdb_mapping_platform CHECK (((cmdb_platform)::text = ANY ((ARRAY['servicenow'::character varying, 'device42'::character varying, 'solarwinds'::character varying, 'oomnitza'::character varying])::text[]))),
    CONSTRAINT valid_cmdb_mapping_status CHECK (((sync_status)::text = ANY ((ARRAY['pending'::character varying, 'synced'::character varying, 'error'::character varying, 'stale'::character varying, 'deleted'::character varying])::text[]))),
    CONSTRAINT valid_cmdb_sync_direction CHECK (((sync_direction)::text = ANY ((ARRAY['push'::character varying, 'reconcile'::character varying])::text[])))
);


-- TABLE: cmdb_sync_jobs
CREATE TABLE IF NOT EXISTS public.cmdb_sync_jobs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    trigger_type character varying(20) DEFAULT 'manual'::character varying NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    items_pushed integer DEFAULT 0,
    items_reconciled integer DEFAULT 0,
    items_failed integer DEFAULT 0,
    items_skipped integer DEFAULT 0,
    error_log jsonb DEFAULT '[]'::jsonb,
    summary jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_sync_job_status CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'in_progress'::character varying, 'success'::character varying, 'partial'::character varying, 'failed'::character varying, 'cancelled'::character varying])::text[]))),
    CONSTRAINT valid_sync_trigger_type CHECK (((trigger_type)::text = ANY ((ARRAY['manual'::character varying, 'scheduled'::character varying, 'event'::character varying, 'retry'::character varying])::text[])))
);


-- TABLE: cmdb_sync_profiles
CREATE TABLE IF NOT EXISTS public.cmdb_sync_profiles (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    platform_type character varying(50) NOT NULL,
    connection_config jsonb DEFAULT '{}'::jsonb NOT NULL,
    field_mapping_config jsonb DEFAULT '{}'::jsonb NOT NULL,
    sync_config jsonb DEFAULT '{}'::jsonb NOT NULL,
    ci_type_mapping jsonb DEFAULT '{}'::jsonb NOT NULL,
    is_enabled boolean DEFAULT false,
    last_sync_at timestamp with time zone,
    last_sync_status character varying(20),
    sync_error text,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    CONSTRAINT valid_cmdb_platform_type CHECK (((platform_type)::text = ANY ((ARRAY['servicenow'::character varying, 'device42'::character varying, 'solarwinds'::character varying, 'oomnitza'::character varying])::text[]))),
    CONSTRAINT valid_cmdb_sync_status CHECK (((last_sync_status IS NULL) OR ((last_sync_status)::text = ANY ((ARRAY['success'::character varying, 'partial'::character varying, 'failed'::character varying, 'in_progress'::character varying, 'cancelled'::character varying])::text[]))))
);


-- TABLE: compliance_checks
CREATE TABLE IF NOT EXISTS public.compliance_checks (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    report_id uuid NOT NULL,
    rule_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    status character varying(20) NOT NULL,
    message text,
    details jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT compliance_checks_status_check CHECK (((status)::text = ANY ((ARRAY['pass'::character varying, 'fail'::character varying, 'warning'::character varying, 'error'::character varying])::text[])))
);


-- TABLE: compliance_finding_history
CREATE TABLE IF NOT EXISTS public.compliance_finding_history (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    finding_id uuid NOT NULL,
    changed_by uuid,
    changed_at timestamp with time zone DEFAULT now(),
    field_name character varying(50) NOT NULL,
    old_value text,
    new_value text,
    change_reason text
);


-- TABLE: compliance_findings
CREATE TABLE IF NOT EXISTS public.compliance_findings (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    control_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    asset_type character varying(50) DEFAULT 'network_asset'::character varying NOT NULL,
    severity character varying(20) NOT NULL,
    summary text NOT NULL,
    evidence jsonb DEFAULT '{}'::jsonb NOT NULL,
    first_seen timestamp with time zone DEFAULT now(),
    last_seen timestamp with time zone DEFAULT now(),
    assigned_to uuid,
    assigned_at timestamp with time zone,
    assigned_by uuid,
    remediation_notes text,
    detection_state character varying(20) DEFAULT 'ACTIVE'::character varying NOT NULL,
    workflow_status character varying(20) DEFAULT 'NEW'::character varying NOT NULL,
    occurrence_count integer DEFAULT 1 NOT NULL,
    resurfaced_at timestamp with time zone,
    suppressed_until timestamp with time zone,
    suppression_reason text,
    is_stale boolean DEFAULT false,
    last_evaluated_at timestamp with time zone,
    evaluation_version integer DEFAULT 1,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT compliance_findings_asset_type_check CHECK (((asset_type)::text = ANY ((ARRAY['network_asset'::character varying, 'certificate'::character varying, 'crypto_implementation'::character varying])::text[]))),
    CONSTRAINT compliance_findings_detection_state_check CHECK (((detection_state)::text = ANY ((ARRAY['ACTIVE'::character varying, 'INACTIVE'::character varying, 'ARCHIVED'::character varying])::text[]))),
    CONSTRAINT compliance_findings_severity_check CHECK (((severity)::text = ANY ((ARRAY['Low'::character varying, 'Med'::character varying, 'High'::character varying, 'Critical'::character varying])::text[]))),
    CONSTRAINT compliance_findings_workflow_status_check CHECK (((workflow_status)::text = ANY ((ARRAY['NEW'::character varying, 'NOTIFIED'::character varying, 'RESOLVED'::character varying, 'SUPPRESSED'::character varying])::text[])))
);


-- TABLE: compliance_framework_status
CREATE TABLE IF NOT EXISTS public.compliance_framework_status (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    framework_name character varying(50) NOT NULL,
    framework_version character varying(20),
    overall_status character varying(20) NOT NULL,
    compliance_score numeric(5,2) DEFAULT 0.0,
    last_assessed_at timestamp with time zone,
    next_assessment_due timestamp with time zone,
    assessment_frequency_days integer,
    total_requirements integer DEFAULT 0,
    compliant_requirements integer DEFAULT 0,
    non_compliant_requirements integer DEFAULT 0,
    pending_requirements integer DEFAULT 0,
    status_details jsonb DEFAULT '{}'::jsonb,
    findings text[],
    recommendations text[],
    evidence_urls text[],
    audit_trail_urls text[],
    assessed_by uuid,
    notes text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_compliance_score CHECK (((compliance_score >= 0.0) AND (compliance_score <= 100.0))),
    CONSTRAINT valid_framework CHECK (((framework_name)::text = ANY ((ARRAY['soc2'::character varying, 'iso27001'::character varying, 'gdpr'::character varying, 'hipaa'::character varying, 'pci_dss'::character varying, 'nist'::character varying, 'custom'::character varying])::text[]))),
    CONSTRAINT valid_status CHECK (((overall_status)::text = ANY ((ARRAY['compliant'::character varying, 'non_compliant'::character varying, 'partial'::character varying, 'not_assessed'::character varying, 'under_review'::character varying])::text[])))
);


-- TABLE: compliance_overrides
CREATE TABLE IF NOT EXISTS public.compliance_overrides (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    scenario_id uuid,
    control_id uuid NOT NULL,
    override_type character varying(20) NOT NULL,
    severity_from character varying(20),
    severity_to character varying(20),
    rationale text NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    framework_type character varying(20) DEFAULT 'platform'::character varying NOT NULL,
    CONSTRAINT compliance_overrides_framework_type_check CHECK (((framework_type)::text = ANY ((ARRAY['platform'::character varying, 'tenant'::character varying])::text[]))),
    CONSTRAINT compliance_overrides_override_type_check CHECK (((override_type)::text = ANY ((ARRAY['disregard'::character varying, 'severity'::character varying])::text[]))),
    CONSTRAINT compliance_overrides_severity_from_check CHECK (((severity_from)::text = ANY ((ARRAY['Low'::character varying, 'Med'::character varying, 'High'::character varying, 'Critical'::character varying])::text[]))),
    CONSTRAINT compliance_overrides_severity_to_check CHECK (((severity_to)::text = ANY ((ARRAY['Low'::character varying, 'Med'::character varying, 'High'::character varying, 'Critical'::character varying])::text[])))
);


-- TABLE: compliance_reports
CREATE TABLE IF NOT EXISTS public.compliance_reports (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    title character varying(255) NOT NULL,
    description text,
    status character varying(20) NOT NULL,
    summary jsonb,
    checks jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT compliance_reports_status_check CHECK (((status)::text = ANY ((ARRAY['running'::character varying, 'completed'::character varying, 'failed'::character varying])::text[])))
);


-- TABLE: compliance_requirements
CREATE TABLE IF NOT EXISTS public.compliance_requirements (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    framework_id uuid NOT NULL,
    requirement_code character varying(100) NOT NULL,
    requirement_name character varying(255) NOT NULL,
    requirement_description text,
    category character varying(100),
    status character varying(20) NOT NULL,
    compliance_score numeric(5,2) DEFAULT 0.0,
    evidence_urls text[],
    evidence_notes text,
    last_assessed_at timestamp with time zone,
    assessed_by uuid,
    assessment_notes text,
    priority character varying(20) DEFAULT 'medium'::character varying,
    tags text[],
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_compliance_score CHECK (((compliance_score >= 0.0) AND (compliance_score <= 100.0))),
    CONSTRAINT valid_priority CHECK (((priority)::text = ANY ((ARRAY['low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying])::text[]))),
    CONSTRAINT valid_status CHECK (((status)::text = ANY ((ARRAY['compliant'::character varying, 'non_compliant'::character varying, 'partial'::character varying, 'pending'::character varying, 'not_applicable'::character varying])::text[])))
);


-- TABLE: compliance_rules
CREATE TABLE IF NOT EXISTS public.compliance_rules (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    category character varying(100) NOT NULL,
    severity character varying(20) NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT compliance_rules_severity_check CHECK (((severity)::text = ANY ((ARRAY['low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying])::text[])))
);


-- TABLE: compliance_scenarios
CREATE TABLE IF NOT EXISTS public.compliance_scenarios (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    framework_id uuid NOT NULL,
    framework_version character varying(20) NOT NULL,
    filters jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_by uuid NOT NULL,
    updated_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    framework_type character varying(20) DEFAULT 'platform'::character varying NOT NULL,
    CONSTRAINT compliance_scenarios_framework_type_check CHECK (((framework_type)::text = ANY ((ARRAY['platform'::character varying, 'tenant'::character varying])::text[])))
);


-- TABLE: control_measurements
CREATE TABLE IF NOT EXISTS public.control_measurements (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    control_id uuid NOT NULL,
    framework_type character varying(20) NOT NULL,
    measurement_type_id uuid NOT NULL,
    rule_type character varying(20) NOT NULL,
    predicate jsonb NOT NULL,
    severity_override character varying(20),
    weight integer DEFAULT 1,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT control_measurements_framework_type_check CHECK (((framework_type)::text = ANY ((ARRAY['platform'::character varying, 'tenant'::character varying])::text[]))),
    CONSTRAINT control_measurements_rule_type_check CHECK (((rule_type)::text = ANY ((ARRAY['threshold'::character varying, 'presence'::character varying, 'pattern'::character varying, 'range'::character varying])::text[]))),
    CONSTRAINT control_measurements_severity_override_check CHECK (((severity_override)::text = ANY ((ARRAY['Low'::character varying, 'Med'::character varying, 'High'::character varying, 'Critical'::character varying])::text[]))),
    CONSTRAINT valid_weight CHECK (((weight >= 1) AND (weight <= 10)))
);


-- TABLE: crypto_applications
CREATE TABLE IF NOT EXISTS public.crypto_applications (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    asset_id uuid,
    resource_type character varying(50) NOT NULL,
    resource_identifier text NOT NULL,
    resource_name character varying(255),
    encryption_context character varying(50) NOT NULL,
    algorithm_id uuid,
    key_id uuid,
    library_id uuid,
    certificate_id uuid,
    execution_environment character varying(50),
    implementation_platform character varying(50),
    certification_level text[],
    cipher_suite character varying(255),
    key_size integer,
    mode character varying(50),
    configuration_source text,
    configuration_data jsonb DEFAULT '{}'::jsonb,
    discovery_method public.discovery_method DEFAULT 'manual'::public.discovery_method NOT NULL,
    confidence_score numeric(3,2) DEFAULT 1.0,
    risk_score integer DEFAULT 0,
    compliance_status jsonb DEFAULT '{}'::jsonb,
    first_discovered_at timestamp with time zone DEFAULT now(),
    last_verified_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    CONSTRAINT valid_crypto_app_confidence CHECK (((confidence_score >= 0.0) AND (confidence_score <= 1.0))),
    CONSTRAINT valid_crypto_app_encryption_context CHECK (((encryption_context)::text = ANY ((ARRAY['at_rest'::character varying, 'in_transit'::character varying, 'in_use'::character varying, 'key_storage'::character varying, 'signing'::character varying, 'hashing'::character varying, 'authentication'::character varying, 'other'::character varying])::text[]))),
    CONSTRAINT valid_crypto_app_resource_type CHECK (((resource_type)::text = ANY ((ARRAY['disk_volume'::character varying, 'file'::character varying, 'database'::character varying, 'cloud_storage'::character varying, 'hsm'::character varying, 'application'::character varying, 'build_artifact'::character varying, 'container'::character varying, 'vm_image'::character varying, 'backup'::character varying, 'communication'::character varying, 'other'::character varying])::text[]))),
    CONSTRAINT valid_crypto_app_risk CHECK (((risk_score >= 0) AND (risk_score <= 100)))
);




-- TABLE: crypto_implementation_algorithms
CREATE TABLE IF NOT EXISTS public.crypto_implementation_algorithms (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    crypto_implementation_id uuid NOT NULL,
    algorithm_id uuid NOT NULL,
    algorithm_type character varying(50) NOT NULL,
    is_inferred boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_algorithm_type CHECK (((algorithm_type)::text = ANY ((ARRAY['hash'::character varying, 'symmetric'::character varying, 'key_exchange'::character varying, 'signature'::character varying, 'protocol_version'::character varying, 'cipher_suite'::character varying])::text[])))
);


-- TABLE: crypto_implementation_certificates
CREATE TABLE IF NOT EXISTS public.crypto_implementation_certificates (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    crypto_implementation_id uuid NOT NULL,
    certificate_id uuid NOT NULL,
    certificate_role character varying(50) DEFAULT 'additional'::character varying,
    certificate_order integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_certificate_role CHECK (((certificate_role)::text = ANY ((ARRAY['leaf'::character varying, 'primary'::character varying, 'additional'::character varying, 'intermediate'::character varying, 'root'::character varying])::text[])))
);


-- TABLE: crypto_implementations_partitioned
CREATE TABLE IF NOT EXISTS public.crypto_implementations_partitioned (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    protocol public.protocol_type NOT NULL,
    protocol_version character varying(100),
    cipher_suite character varying(255),
    key_exchange_algorithm character varying(100),
    signature_algorithm character varying(100),
    symmetric_encryption character varying(100),
    hash_algorithm character varying(100),
    key_size integer,
    certificate_id uuid,
    discovery_method public.discovery_method NOT NULL,
    confidence_score numeric(3,2) DEFAULT 1.0,
    source_sensor_id uuid,
    raw_data jsonb,
    risk_score integer DEFAULT 0,
    compliance_status jsonb DEFAULT '{}'::jsonb,
    pfs_support boolean,
    tls_compression_enabled boolean,
    certificate_chain_valid boolean,
    execution_environment character varying(50),
    implementation_platform character varying(50),
    certification_level text[],
    data_completeness character varying(20) DEFAULT 'complete'::character varying,
    components_inferred boolean DEFAULT false,
    first_discovered_at timestamp with time zone DEFAULT now(),
    last_verified_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone
)
PARTITION BY HASH (tenant_id);


-- VIEW: crypto_implementations
CREATE OR REPLACE VIEW public.crypto_implementations AS
 SELECT crypto_implementations_partitioned.id,
    crypto_implementations_partitioned.tenant_id,
    crypto_implementations_partitioned.asset_id,
    crypto_implementations_partitioned.protocol,
    crypto_implementations_partitioned.protocol_version,
    crypto_implementations_partitioned.cipher_suite,
    crypto_implementations_partitioned.key_exchange_algorithm,
    crypto_implementations_partitioned.signature_algorithm,
    crypto_implementations_partitioned.symmetric_encryption,
    crypto_implementations_partitioned.hash_algorithm,
    crypto_implementations_partitioned.key_size,
    crypto_implementations_partitioned.certificate_id,
    crypto_implementations_partitioned.discovery_method,
    crypto_implementations_partitioned.confidence_score,
    crypto_implementations_partitioned.source_sensor_id,
    crypto_implementations_partitioned.raw_data,
    crypto_implementations_partitioned.risk_score,
    crypto_implementations_partitioned.compliance_status,
    crypto_implementations_partitioned.pfs_support,
    crypto_implementations_partitioned.tls_compression_enabled,
    crypto_implementations_partitioned.certificate_chain_valid,
    crypto_implementations_partitioned.execution_environment,
    crypto_implementations_partitioned.implementation_platform,
    crypto_implementations_partitioned.certification_level,
    crypto_implementations_partitioned.data_completeness,
    crypto_implementations_partitioned.components_inferred,
    crypto_implementations_partitioned.first_discovered_at,
    crypto_implementations_partitioned.last_verified_at,
    crypto_implementations_partitioned.created_at,
    crypto_implementations_partitioned.updated_at,
    crypto_implementations_partitioned.deleted_at
   FROM public.crypto_implementations_partitioned;


-- TABLE: crypto_implementations_part_0
CREATE TABLE IF NOT EXISTS public.crypto_implementations_part_0 (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    protocol public.protocol_type NOT NULL,
    protocol_version character varying(100),
    cipher_suite character varying(255),
    key_exchange_algorithm character varying(100),
    signature_algorithm character varying(100),
    symmetric_encryption character varying(100),
    hash_algorithm character varying(100),
    key_size integer,
    certificate_id uuid,
    discovery_method public.discovery_method NOT NULL,
    confidence_score numeric(3,2) DEFAULT 1.0,
    source_sensor_id uuid,
    raw_data jsonb,
    risk_score integer DEFAULT 0,
    compliance_status jsonb DEFAULT '{}'::jsonb,
    pfs_support boolean,
    tls_compression_enabled boolean,
    certificate_chain_valid boolean,
    execution_environment character varying(50),
    implementation_platform character varying(50),
    certification_level text[],
    data_completeness character varying(20) DEFAULT 'complete'::character varying,
    components_inferred boolean DEFAULT false,
    first_discovered_at timestamp with time zone DEFAULT now(),
    last_verified_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone
);


-- TABLE: crypto_implementations_part_1
CREATE TABLE IF NOT EXISTS public.crypto_implementations_part_1 (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    protocol public.protocol_type NOT NULL,
    protocol_version character varying(100),
    cipher_suite character varying(255),
    key_exchange_algorithm character varying(100),
    signature_algorithm character varying(100),
    symmetric_encryption character varying(100),
    hash_algorithm character varying(100),
    key_size integer,
    certificate_id uuid,
    discovery_method public.discovery_method NOT NULL,
    confidence_score numeric(3,2) DEFAULT 1.0,
    source_sensor_id uuid,
    raw_data jsonb,
    risk_score integer DEFAULT 0,
    compliance_status jsonb DEFAULT '{}'::jsonb,
    pfs_support boolean,
    tls_compression_enabled boolean,
    certificate_chain_valid boolean,
    execution_environment character varying(50),
    implementation_platform character varying(50),
    certification_level text[],
    data_completeness character varying(20) DEFAULT 'complete'::character varying,
    components_inferred boolean DEFAULT false,
    first_discovered_at timestamp with time zone DEFAULT now(),
    last_verified_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone
);


-- TABLE: crypto_implementations_part_2
CREATE TABLE IF NOT EXISTS public.crypto_implementations_part_2 (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    protocol public.protocol_type NOT NULL,
    protocol_version character varying(100),
    cipher_suite character varying(255),
    key_exchange_algorithm character varying(100),
    signature_algorithm character varying(100),
    symmetric_encryption character varying(100),
    hash_algorithm character varying(100),
    key_size integer,
    certificate_id uuid,
    discovery_method public.discovery_method NOT NULL,
    confidence_score numeric(3,2) DEFAULT 1.0,
    source_sensor_id uuid,
    raw_data jsonb,
    risk_score integer DEFAULT 0,
    compliance_status jsonb DEFAULT '{}'::jsonb,
    pfs_support boolean,
    tls_compression_enabled boolean,
    certificate_chain_valid boolean,
    execution_environment character varying(50),
    implementation_platform character varying(50),
    certification_level text[],
    data_completeness character varying(20) DEFAULT 'complete'::character varying,
    components_inferred boolean DEFAULT false,
    first_discovered_at timestamp with time zone DEFAULT now(),
    last_verified_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone
);


-- TABLE: crypto_implementations_part_3
CREATE TABLE IF NOT EXISTS public.crypto_implementations_part_3 (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    protocol public.protocol_type NOT NULL,
    protocol_version character varying(100),
    cipher_suite character varying(255),
    key_exchange_algorithm character varying(100),
    signature_algorithm character varying(100),
    symmetric_encryption character varying(100),
    hash_algorithm character varying(100),
    key_size integer,
    certificate_id uuid,
    discovery_method public.discovery_method NOT NULL,
    confidence_score numeric(3,2) DEFAULT 1.0,
    source_sensor_id uuid,
    raw_data jsonb,
    risk_score integer DEFAULT 0,
    compliance_status jsonb DEFAULT '{}'::jsonb,
    pfs_support boolean,
    tls_compression_enabled boolean,
    certificate_chain_valid boolean,
    execution_environment character varying(50),
    implementation_platform character varying(50),
    certification_level text[],
    data_completeness character varying(20) DEFAULT 'complete'::character varying,
    components_inferred boolean DEFAULT false,
    first_discovered_at timestamp with time zone DEFAULT now(),
    last_verified_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone
);


-- TABLE: crypto_implementations_part_4
CREATE TABLE IF NOT EXISTS public.crypto_implementations_part_4 (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    protocol public.protocol_type NOT NULL,
    protocol_version character varying(100),
    cipher_suite character varying(255),
    key_exchange_algorithm character varying(100),
    signature_algorithm character varying(100),
    symmetric_encryption character varying(100),
    hash_algorithm character varying(100),
    key_size integer,
    certificate_id uuid,
    discovery_method public.discovery_method NOT NULL,
    confidence_score numeric(3,2) DEFAULT 1.0,
    source_sensor_id uuid,
    raw_data jsonb,
    risk_score integer DEFAULT 0,
    compliance_status jsonb DEFAULT '{}'::jsonb,
    pfs_support boolean,
    tls_compression_enabled boolean,
    certificate_chain_valid boolean,
    execution_environment character varying(50),
    implementation_platform character varying(50),
    certification_level text[],
    data_completeness character varying(20) DEFAULT 'complete'::character varying,
    components_inferred boolean DEFAULT false,
    first_discovered_at timestamp with time zone DEFAULT now(),
    last_verified_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone
);


-- TABLE: crypto_implementations_part_5
CREATE TABLE IF NOT EXISTS public.crypto_implementations_part_5 (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    protocol public.protocol_type NOT NULL,
    protocol_version character varying(100),
    cipher_suite character varying(255),
    key_exchange_algorithm character varying(100),
    signature_algorithm character varying(100),
    symmetric_encryption character varying(100),
    hash_algorithm character varying(100),
    key_size integer,
    certificate_id uuid,
    discovery_method public.discovery_method NOT NULL,
    confidence_score numeric(3,2) DEFAULT 1.0,
    source_sensor_id uuid,
    raw_data jsonb,
    risk_score integer DEFAULT 0,
    compliance_status jsonb DEFAULT '{}'::jsonb,
    pfs_support boolean,
    tls_compression_enabled boolean,
    certificate_chain_valid boolean,
    execution_environment character varying(50),
    implementation_platform character varying(50),
    certification_level text[],
    data_completeness character varying(20) DEFAULT 'complete'::character varying,
    components_inferred boolean DEFAULT false,
    first_discovered_at timestamp with time zone DEFAULT now(),
    last_verified_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone
);


-- TABLE: crypto_implementations_part_6
CREATE TABLE IF NOT EXISTS public.crypto_implementations_part_6 (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    protocol public.protocol_type NOT NULL,
    protocol_version character varying(100),
    cipher_suite character varying(255),
    key_exchange_algorithm character varying(100),
    signature_algorithm character varying(100),
    symmetric_encryption character varying(100),
    hash_algorithm character varying(100),
    key_size integer,
    certificate_id uuid,
    discovery_method public.discovery_method NOT NULL,
    confidence_score numeric(3,2) DEFAULT 1.0,
    source_sensor_id uuid,
    raw_data jsonb,
    risk_score integer DEFAULT 0,
    compliance_status jsonb DEFAULT '{}'::jsonb,
    pfs_support boolean,
    tls_compression_enabled boolean,
    certificate_chain_valid boolean,
    execution_environment character varying(50),
    implementation_platform character varying(50),
    certification_level text[],
    data_completeness character varying(20) DEFAULT 'complete'::character varying,
    components_inferred boolean DEFAULT false,
    first_discovered_at timestamp with time zone DEFAULT now(),
    last_verified_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone
);


-- TABLE: crypto_implementations_part_7
CREATE TABLE IF NOT EXISTS public.crypto_implementations_part_7 (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    protocol public.protocol_type NOT NULL,
    protocol_version character varying(100),
    cipher_suite character varying(255),
    key_exchange_algorithm character varying(100),
    signature_algorithm character varying(100),
    symmetric_encryption character varying(100),
    hash_algorithm character varying(100),
    key_size integer,
    certificate_id uuid,
    discovery_method public.discovery_method NOT NULL,
    confidence_score numeric(3,2) DEFAULT 1.0,
    source_sensor_id uuid,
    raw_data jsonb,
    risk_score integer DEFAULT 0,
    compliance_status jsonb DEFAULT '{}'::jsonb,
    pfs_support boolean,
    tls_compression_enabled boolean,
    certificate_chain_valid boolean,
    execution_environment character varying(50),
    implementation_platform character varying(50),
    certification_level text[],
    data_completeness character varying(20) DEFAULT 'complete'::character varying,
    components_inferred boolean DEFAULT false,
    first_discovered_at timestamp with time zone DEFAULT now(),
    last_verified_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone
);


-- TABLE: crypto_libraries
CREATE TABLE IF NOT EXISTS public.crypto_libraries (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    version text NOT NULL,
    vendor text,
    cpe text,
    purl character varying(500),
    certification_level text[],
    build_metadata jsonb DEFAULT '{}'::jsonb,
    known_vulnerabilities jsonb DEFAULT '[]'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: tenant_resource_usage
CREATE TABLE IF NOT EXISTS public.tenant_resource_usage (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    api_calls integer DEFAULT 0,
    database_queries integer DEFAULT 0,
    memory_usage_mb integer DEFAULT 0,
    cpu_usage_percent numeric(5,2) DEFAULT 0,
    storage_used_mb integer DEFAULT 0,
    network_bytes bigint DEFAULT 0,
    cost_usd numeric(10,4) DEFAULT 0,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    cost_breakdown jsonb DEFAULT '{}'::jsonb
);


-- VIEW: current_resource_usage_summary
CREATE OR REPLACE VIEW public.current_resource_usage_summary AS
 SELECT t.id AS tenant_id,
    t.name AS tenant_name,
    COALESCE(ru.total_api_calls, (0)::bigint) AS total_api_calls,
    COALESCE(ru.total_db_queries, (0)::bigint) AS total_db_queries,
    COALESCE(ru.avg_memory_mb, (0)::numeric) AS avg_memory_mb,
    COALESCE(ru.avg_cpu_percent, (0)::numeric) AS avg_cpu_percent,
    COALESCE(ru.total_storage_mb, (0)::bigint) AS total_storage_mb,
    COALESCE(ru.total_network_mb, (0)::numeric) AS total_network_mb,
    COALESCE(ru.total_cost_usd, (0)::numeric) AS total_cost_usd
   FROM (public.tenants t
     LEFT JOIN ( SELECT tenant_resource_usage.tenant_id,
            sum(tenant_resource_usage.api_calls) AS total_api_calls,
            sum(tenant_resource_usage.database_queries) AS total_db_queries,
            avg(tenant_resource_usage.memory_usage_mb) AS avg_memory_mb,
            avg(tenant_resource_usage.cpu_usage_percent) AS avg_cpu_percent,
            sum(tenant_resource_usage.storage_used_mb) AS total_storage_mb,
            (sum(tenant_resource_usage.network_bytes) / ((1024 * 1024))::numeric) AS total_network_mb,
            sum(tenant_resource_usage.cost_usd) AS total_cost_usd
           FROM public.tenant_resource_usage
          WHERE (tenant_resource_usage."timestamp" >= (now() - '24:00:00'::interval))
          GROUP BY tenant_resource_usage.tenant_id) ru ON ((t.id = ru.tenant_id)));


-- TABLE: dashboard_cache
CREATE TABLE IF NOT EXISTS public.dashboard_cache (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    cache_key character varying(255) NOT NULL,
    cache_data jsonb NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


-- TABLE: dashboard_metrics
CREATE TABLE IF NOT EXISTS public.dashboard_metrics (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    metric_type character varying(50) NOT NULL,
    metric_name character varying(100) NOT NULL,
    metric_value numeric(15,4) NOT NULL,
    metric_unit character varying(20),
    metadata jsonb,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


-- TABLE: database_encryption_states
CREATE TABLE IF NOT EXISTS public.database_encryption_states (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    device_id uuid,
    asset_id uuid,
    db_engine character varying(50) NOT NULL,
    db_version character varying(100),
    hostname character varying(255),
    port integer,
    instance_name character varying(255),
    ssl_enabled boolean,
    ssl_version character varying(50),
    ssl_cipher character varying(255),
    ssl_enforced boolean,
    certificate_id uuid,
    encryption_at_rest_enabled boolean,
    encryption_method character varying(100),
    encryption_algorithm character varying(100),
    encryption_key_source character varying(100),
    password_encryption_method character varying(50),
    ssl_algorithm_id uuid,
    encryption_algorithm_id uuid,
    password_algorithm_id uuid,
    risk_score integer DEFAULT 50,
    discovery_method public.discovery_method DEFAULT 'device_interrogation'::public.discovery_method NOT NULL,
    raw_config jsonb DEFAULT '{}'::jsonb,
    first_discovered_at timestamp with time zone DEFAULT now(),
    last_verified_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    CONSTRAINT valid_db_encryption_risk CHECK (((risk_score >= 0) AND (risk_score <= 100))),
    CONSTRAINT valid_db_engine CHECK (((db_engine)::text = ANY ((ARRAY['postgresql'::character varying, 'mysql'::character varying, 'sqlserver'::character varying, 'oracle'::character varying, 'mongodb'::character varying])::text[])))
);


-- TABLE: device_agents
CREATE TABLE IF NOT EXISTS public.device_agents (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    registration_key character varying(255) NOT NULL,
    name character varying(255),
    description text,
    platform character varying(50) NOT NULL,
    version character varying(50) NOT NULL,
    profile character varying(50),
    status character varying(20) DEFAULT 'active'::character varying,
    -- Primary address, self-reported by the agent (parity with sensors.ip_address,
    -- and typed to match it). The platform cannot observe this through NAT.
    ip_address character varying(45),
    last_heartbeat timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    CONSTRAINT valid_status CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'inactive'::character varying, 'error'::character varying])::text[])))
);


-- TABLE: device_jobs
CREATE TABLE IF NOT EXISTS public.device_jobs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    job_type public.device_job_type NOT NULL,
    device_id uuid,
    integration_id uuid,
    agent_id uuid,
    status public.device_job_status DEFAULT 'pending'::public.device_job_status,
    credentials jsonb,
    parameters jsonb DEFAULT '{}'::jsonb,
    results jsonb,
    error_message text,
    created_at timestamp with time zone DEFAULT now(),
    assigned_at timestamp with time zone,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    expires_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    CONSTRAINT valid_job_assignment CHECK ((((agent_id IS NULL) AND (job_type = 'cloud_discovery'::public.device_job_type)) OR ((agent_id IS NOT NULL) AND (job_type = 'device_interrogation'::public.device_job_type)) OR ((agent_id IS NULL) AND (job_type = 'device_interrogation'::public.device_job_type) AND (device_id IS NOT NULL))))
);


-- TABLE: devices
CREATE TABLE IF NOT EXISTS public.devices (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    device_type character varying(50) NOT NULL,
    vendor character varying(50),
    model character varying(100),
    hostname character varying(255),
    ip_address inet,
    management_url character varying(500),
    serial_number character varying(255),
    firmware_version character varying(100),
    discovery_method public.discovery_method DEFAULT 'device_interrogation'::public.discovery_method NOT NULL,
    credential_id uuid,
    username character varying(255),
    password text,
    -- TLS verification posture when the platform connects to the device's
    -- management API. Defaults to false (verify) — must be explicitly opted
    -- in per device for self-signed network gear. Defaulting to skip-verify
    -- was a MITM exposure for embedded-credential devices (HIGH-1 in the
    -- 2026-05 security audit).
    tls_insecure_skip_verify boolean NOT NULL DEFAULT false,
    connection_status character varying(20) DEFAULT 'unknown'::character varying,
    last_interrogated_at timestamp with time zone,
    interrogation_error text,
    metadata jsonb DEFAULT '{}'::jsonb,
    tags jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    CONSTRAINT device_identifier CHECK (((hostname IS NOT NULL) OR (ip_address IS NOT NULL) OR (management_url IS NOT NULL))),
    CONSTRAINT valid_connection_status CHECK (((connection_status)::text = ANY ((ARRAY['connected'::character varying, 'disconnected'::character varying, 'error'::character varying, 'unknown'::character varying])::text[])))
);


-- TABLE: discovery_alert_configs
CREATE TABLE IF NOT EXISTS public.discovery_alert_configs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    alert_type character varying(50) NOT NULL,
    enabled boolean DEFAULT true,
    email_enabled boolean DEFAULT false,
    slack_enabled boolean DEFAULT false,
    slack_webhook_url text,
    slack_channel character varying(255),
    in_app_enabled boolean DEFAULT true,
    conditions jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: discovery_alert_history
CREATE TABLE IF NOT EXISTS public.discovery_alert_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    alert_type character varying(50) NOT NULL,
    job_id uuid,
    finding_id uuid,
    message text NOT NULL,
    sent_via text[] NOT NULL,
    sent_at timestamp with time zone DEFAULT now(),
    status character varying(20) DEFAULT 'sent'::character varying NOT NULL,
    CONSTRAINT discovery_alert_history_status_check CHECK (((status)::text = ANY ((ARRAY['sent'::character varying, 'failed'::character varying, 'pending'::character varying])::text[])))
);


-- TABLE: discovery_approval_queue
CREATE TABLE IF NOT EXISTS public.discovery_approval_queue (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    job_id uuid NOT NULL,
    finding_id uuid NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    reviewed_by uuid,
    reviewed_at timestamp with time zone,
    auto_approval_rule_id uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT discovery_approval_queue_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'approved'::character varying, 'rejected'::character varying, 'auto_approved'::character varying])::text[])))
);


-- TABLE: discovery_auto_approval_rules
CREATE TABLE IF NOT EXISTS public.discovery_auto_approval_rules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    conditions jsonb NOT NULL,
    is_active boolean DEFAULT true,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: discovery_findings
CREATE TABLE IF NOT EXISTS public.discovery_findings (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    job_id uuid NOT NULL,
    target_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    executed_via text NOT NULL,
    protocol text NOT NULL,
    port integer NOT NULL,
    resolved_ip inet,
    hostname character varying(255),
    details jsonb,
    raw_blob_ref text,
    raw_blob_size integer DEFAULT 0 NOT NULL,
    error_code text,
    confidence_score numeric(3,2) DEFAULT 0.0,
    created_at timestamp with time zone DEFAULT now(),
    "timestamp" timestamp with time zone
);


-- TABLE: discovery_jobs
CREATE TABLE IF NOT EXISTS public.discovery_jobs (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    created_by uuid,
    execution_mode text NOT NULL,
    requested_sensor_ids text[],
    fanout boolean DEFAULT true,
    status text DEFAULT 'queued'::text NOT NULL,
    retention_cap_mb integer DEFAULT 25 NOT NULL,
    retention_ttl_hours integer DEFAULT 24 NOT NULL,
    -- Audit column: which OT active probes the operator opted into for this job.
    -- Empty array = no OT active probing was approved; non-empty = the listed
    -- protocols (Modbus, OPC_UA, EtherNet_IP, BACnet) were dispatched.
    ot_probe_protocols text[] DEFAULT '{}'::text[],
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    error_message text,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: discovery_rate_limits
CREATE TABLE IF NOT EXISTS public.discovery_rate_limits (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    scans_per_hour integer DEFAULT 100 NOT NULL,
    concurrent_jobs integer DEFAULT 5 NOT NULL,
    max_targets_per_job integer DEFAULT 1000 NOT NULL,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: discovery_targets
CREATE TABLE IF NOT EXISTS public.discovery_targets (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    job_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    input text NOT NULL,
    protocols text[] NOT NULL,
    ports integer[] NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    error_message text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: external_asset_mappings
CREATE TABLE IF NOT EXISTS public.external_asset_mappings (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    local_type text NOT NULL,
    local_id uuid NOT NULL,
    external_system text NOT NULL,
    external_id text NOT NULL,
    sync_status text,
    last_synced_at timestamp with time zone,
    last_sync_error text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: external_connection_history
CREATE TABLE IF NOT EXISTS public.external_connection_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    external_connection_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    change_type character varying(50) NOT NULL,
    previous_protocol_version character varying(50),
    previous_cipher_suite character varying(255),
    previous_crypto_strength character varying(20),
    previous_is_pqc_resistant boolean,
    previous_cert_fingerprint_sha256 character varying(64),
    previous_cert_not_after timestamp with time zone,
    new_protocol_version character varying(50),
    new_cipher_suite character varying(255),
    new_crypto_strength character varying(20),
    new_is_pqc_resistant boolean,
    new_cert_fingerprint_sha256 character varying(64),
    new_cert_not_after timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT external_connection_history_change_type_check CHECK (((change_type)::text = ANY ((ARRAY['first_seen'::character varying, 'cert_rotated'::character varying, 'cipher_changed'::character varying, 'protocol_upgraded'::character varying, 'protocol_downgraded'::character varying, 'crypto_strength_changed'::character varying])::text[])))
);


-- TABLE: external_connections
CREATE TABLE IF NOT EXISTS public.external_connections (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    source_ip inet NOT NULL,
    source_hostname character varying(255),
    source_asset_id uuid,
    dest_ip inet NOT NULL,
    dest_hostname character varying(255),
    dest_port integer NOT NULL,
    protocol character varying(50) NOT NULL,
    protocol_version character varying(50),
    cipher_suite character varying(255),
    key_exchange_algorithm character varying(100),
    key_size integer,
    supported_tls_versions text[],
    crypto_strength character varying(20) DEFAULT 'unknown'::character varying NOT NULL,
    is_pqc_resistant boolean DEFAULT false NOT NULL,
    weak_reasons text[] DEFAULT '{}'::text[],
    cert_subject character varying(500),
    cert_issuer character varying(500),
    cert_san text[],
    cert_not_before timestamp with time zone,
    cert_not_after timestamp with time zone,
    cert_fingerprint_sha256 character varying(64),
    cert_public_key_algorithm character varying(50),
    cert_public_key_size integer,
    cert_signature_algorithm character varying(100),
    cert_is_expired boolean DEFAULT false NOT NULL,
    cert_validation_status character varying(30),
    cert_pem text,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    observation_count bigint DEFAULT 1 NOT NULL,
    sensor_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    service_name character varying(100),
    service_version character varying(100),
    service_confidence character varying(20),
    service_identification_method character varying(50),
    -- Non-null once a tenant promotes a 3rd-party connection to a managed asset
    --links the connection to that network_asset. App-managed, no FK:
    -- network_assets is hash-partitioned and soft-deleted.
    elevated_asset_id uuid,
    CONSTRAINT external_connections_crypto_strength_check CHECK (((crypto_strength)::text = ANY ((ARRAY['good'::character varying, 'weak'::character varying, 'unknown'::character varying])::text[]))),
    CONSTRAINT external_connections_dest_port_check CHECK (((dest_port >= 1) AND (dest_port <= 65535)))
);


-- TABLE: feature_adoption_metrics
CREATE TABLE IF NOT EXISTS public.feature_adoption_metrics (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    feature_name character varying(100) NOT NULL,
    tenant_id uuid,
    user_id uuid,
    action character varying(50) NOT NULL,
    session_id character varying(100),
    metadata jsonb,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL
);


-- TABLE: feature_usage_events
CREATE TABLE IF NOT EXISTS public.feature_usage_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid,
    feature_name character varying(100) NOT NULL,
    event_type character varying(50) NOT NULL,
    event_data jsonb DEFAULT '{}'::jsonb,
    occurred_at timestamp with time zone DEFAULT now()
);


-- TABLE: health_alerts
CREATE TABLE IF NOT EXISTS public.health_alerts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    alert_type character varying(50) NOT NULL,
    severity character varying(20) NOT NULL,
    title character varying(255) NOT NULL,
    description text NOT NULL,
    category character varying(50) NOT NULL,
    current_value numeric(10,4) DEFAULT 0,
    threshold numeric(10,4) DEFAULT 0,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone
);


-- TABLE: health_benchmarks
CREATE TABLE IF NOT EXISTS public.health_benchmarks (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    category character varying(50) NOT NULL,
    benchmark_score numeric(5,2) NOT NULL,
    description text NOT NULL,
    source character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


-- TABLE: health_insights
CREATE TABLE IF NOT EXISTS public.health_insights (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    insights jsonb DEFAULT '[]'::jsonb NOT NULL,
    confidence numeric(3,2) DEFAULT 0 NOT NULL,
    generated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


-- TABLE: health_metrics
CREATE TABLE IF NOT EXISTS public.health_metrics (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    cpu_utilization numeric(5,2) DEFAULT 0,
    memory_utilization numeric(5,2) DEFAULT 0,
    storage_utilization numeric(5,2) DEFAULT 0,
    network_utilization numeric(5,2) DEFAULT 0,
    avg_response_time numeric(10,3) DEFAULT 0,
    error_rate numeric(5,4) DEFAULT 0,
    throughput numeric(10,2) DEFAULT 0,
    uptime numeric(5,2) DEFAULT 0,
    failed_logins integer DEFAULT 0,
    security_alerts integer DEFAULT 0,
    compliance_score numeric(5,2) DEFAULT 0,
    last_security_update timestamp with time zone,
    active_users integer DEFAULT 0,
    api_calls integer DEFAULT 0,
    feature_usage jsonb DEFAULT '{}'::jsonb,
    user_engagement numeric(5,2) DEFAULT 0,
    resource_cost numeric(10,2) DEFAULT 0,
    cost_per_user numeric(10,2) DEFAULT 0,
    cost_efficiency numeric(5,2) DEFAULT 0,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


-- VIEW: health_metrics_aggregated_view
CREATE OR REPLACE VIEW public.health_metrics_aggregated_view AS
 SELECT health_metrics.tenant_id,
    date_trunc('hour'::text, health_metrics."timestamp") AS hour,
    avg(health_metrics.cpu_utilization) AS avg_cpu_utilization,
    avg(health_metrics.memory_utilization) AS avg_memory_utilization,
    avg(health_metrics.storage_utilization) AS avg_storage_utilization,
    avg(health_metrics.network_utilization) AS avg_network_utilization,
    avg(health_metrics.avg_response_time) AS avg_response_time,
    avg(health_metrics.error_rate) AS avg_error_rate,
    avg(health_metrics.throughput) AS avg_throughput,
    avg(health_metrics.uptime) AS avg_uptime,
    sum(health_metrics.failed_logins) AS total_failed_logins,
    sum(health_metrics.security_alerts) AS total_security_alerts,
    avg(health_metrics.compliance_score) AS avg_compliance_score,
    avg(health_metrics.active_users) AS avg_active_users,
    sum(health_metrics.api_calls) AS total_api_calls,
    avg(health_metrics.user_engagement) AS avg_user_engagement,
    sum(health_metrics.resource_cost) AS total_resource_cost,
    avg(health_metrics.cost_per_user) AS avg_cost_per_user,
    avg(health_metrics.cost_efficiency) AS avg_cost_efficiency
   FROM public.health_metrics
  GROUP BY health_metrics.tenant_id, (date_trunc('hour'::text, health_metrics."timestamp"))
  ORDER BY health_metrics.tenant_id, (date_trunc('hour'::text, health_metrics."timestamp"));


-- TABLE: identity_link_requests
CREATE TABLE IF NOT EXISTS public.identity_link_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    primary_user_id uuid NOT NULL,
    secondary_user_id uuid NOT NULL,
    auth_method_id uuid NOT NULL,
    status character varying(50) DEFAULT 'pending'::character varying,
    requested_by_user_id uuid,
    confirmation_token character varying(255) NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '24:00:00'::interval),
    resolved_at timestamp with time zone,
    resolved_by_user_id uuid,
    rejection_reason text,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT different_users CHECK ((primary_user_id <> secondary_user_id)),
    CONSTRAINT valid_status CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'approved'::character varying, 'rejected'::character varying, 'expired'::character varying])::text[])))
);


-- TABLE: implementation_keys
CREATE TABLE IF NOT EXISTS public.implementation_keys (
    implementation_id uuid NOT NULL,
    key_id uuid NOT NULL
);


-- TABLE: implementation_libraries
CREATE TABLE IF NOT EXISTS public.implementation_libraries (
    implementation_id uuid NOT NULL,
    library_id uuid NOT NULL
);


-- TABLE: in_app_notifications
CREATE TABLE IF NOT EXISTS public.in_app_notifications (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    type character varying(50) NOT NULL,
    title character varying(255) NOT NULL,
    message text NOT NULL,
    job_id uuid,
    finding_id uuid,
    read_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_notification_type CHECK (((type)::text = ANY ((ARRAY['alert'::character varying, 'discovery'::character varying, 'compliance'::character varying, 'system'::character varying, 'billing'::character varying, 'security'::character varying, 'other'::character varying])::text[])))
);


-- TABLE: integrations
CREATE TABLE IF NOT EXISTS public.integrations (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    type text NOT NULL,
    base_url text NOT NULL,
    auth_type text NOT NULL,
    auth_config jsonb NOT NULL,
    mapping_config jsonb DEFAULT '{}'::jsonb NOT NULL,
    is_enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: interrogation_schedules
CREATE TABLE IF NOT EXISTS public.interrogation_schedules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    cron_expression character varying(100) NOT NULL,
    target_type character varying(50) NOT NULL,
    target_id uuid NOT NULL,
    is_enabled boolean DEFAULT true NOT NULL,
    last_run_at timestamp with time zone,
    last_run_status character varying(50),
    last_run_job_id uuid,
    next_run_at timestamp with time zone,
    success_count integer DEFAULT 0 NOT NULL,
    failure_count integer DEFAULT 0 NOT NULL,
    parameters jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    CONSTRAINT interrogation_schedules_target_type_check CHECK (((target_type)::text = ANY ((ARRAY['device'::character varying, 'cloud_integration'::character varying])::text[])))
);


-- TABLE: keys
CREATE TABLE IF NOT EXISTS public.keys (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    key_type text NOT NULL,
    key_usage text[],
    public_fingerprint text,
    jwk_thumbprint text,
    size_bits integer,
    curve text,
    material_type character varying(50) DEFAULT 'key'::character varying NOT NULL,
    state character varying(20) DEFAULT 'active'::character varying,
    state_reason text,
    format character varying(50),
    algorithm_id uuid,
    secured_by_mechanism character varying(100),
    secured_by_algorithm_id uuid,
    created_at timestamp with time zone,
    activation_date timestamp with time zone,
    rotated_at timestamp with time zone,
    deactivation_date timestamp with time zone,
    expires_at timestamp with time zone,
    destruction_date timestamp with time zone,
    fingerprint_algorithm character varying(20),
    fingerprint_value character varying(128),
    provenance text,
    metadata jsonb DEFAULT '{}'::jsonb,
    CONSTRAINT valid_key_state CHECK (((state IS NULL) OR ((state)::text = ANY ((ARRAY['pre-activation'::character varying, 'active'::character varying, 'suspended'::character varying, 'deactivated'::character varying, 'compromised'::character varying, 'destroyed'::character varying])::text[])))),
    CONSTRAINT valid_material_type CHECK (((material_type)::text = ANY ((ARRAY['private-key'::character varying, 'public-key'::character varying, 'secret-key'::character varying, 'shared-secret'::character varying, 'key'::character varying, 'password'::character varying, 'credential'::character varying, 'token'::character varying, 'ciphertext'::character varying, 'signature'::character varying, 'digest'::character varying, 'initialization-vector'::character varying, 'nonce'::character varying, 'seed'::character varying, 'salt'::character varying, 'tag'::character varying, 'additional-data'::character varying, 'other'::character varying, 'unknown'::character varying])::text[])))
);


-- TABLE: kms_keys
CREATE TABLE IF NOT EXISTS public.kms_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    integration_id uuid NOT NULL,
    provider character varying(20) NOT NULL,
    key_id character varying(500) NOT NULL,
    key_arn character varying(1000),
    key_name character varying(255),
    description text,
    key_spec character varying(100),
    key_usage character varying(50),
    algorithm_id uuid,
    key_size integer,
    key_state character varying(50) NOT NULL,
    creation_date timestamp with time zone,
    expiration_date timestamp with time zone,
    rotation_enabled boolean,
    last_rotated_at timestamp with time zone,
    rotation_period_days integer,
    origin character varying(50),
    key_manager character varying(50),
    multi_region boolean DEFAULT false,
    hsm_backed boolean DEFAULT false,
    risk_score integer DEFAULT 50,
    days_since_rotation integer,
    region character varying(50),
    account_id character varying(50),
    tags jsonb DEFAULT '{}'::jsonb,
    metadata jsonb DEFAULT '{}'::jsonb,
    discovery_method public.discovery_method DEFAULT 'cloud_api'::public.discovery_method NOT NULL,
    first_discovered_at timestamp with time zone DEFAULT now(),
    last_verified_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    CONSTRAINT valid_kms_provider CHECK (((provider)::text = ANY ((ARRAY['aws'::character varying, 'azure'::character varying, 'gcp'::character varying, 'vault'::character varying])::text[]))),
    CONSTRAINT valid_kms_risk CHECK (((risk_score >= 0) AND (risk_score <= 100)))
);


-- TABLE: library_provided_algorithms
CREATE TABLE IF NOT EXISTS public.library_provided_algorithms (
    library_id uuid NOT NULL,
    algorithm_id uuid NOT NULL,
    is_default boolean DEFAULT false,
    is_validated boolean DEFAULT false,
    certification_level text[]
);


-- TABLE: locations
CREATE TABLE IF NOT EXISTS public.locations (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    parent_id uuid,
    location_type public.location_type NOT NULL,
    description text,
    address text,
    city character varying(100),
    state_province character varying(100),
    country character varying(100),
    latitude numeric(10,7),
    longitude numeric(10,7),
    timezone character varying(50),
    cloud_provider character varying(50),
    cloud_region character varying(100),
    metadata jsonb DEFAULT '{}'::jsonb,
    full_path text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: maintenance_windows
CREATE TABLE IF NOT EXISTS public.maintenance_windows (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    title character varying(255) NOT NULL,
    description text,
    type character varying(50) DEFAULT 'scheduled'::character varying NOT NULL,
    status character varying(50) DEFAULT 'scheduled'::character varying NOT NULL,
    affected_services text[] DEFAULT '{}'::text[],
    starts_at timestamp with time zone NOT NULL,
    ends_at timestamp with time zone NOT NULL,
    actual_start timestamp with time zone,
    actual_end timestamp with time zone,
    notify_before_minutes integer DEFAULT 60,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


-- TABLE: measurement_templates
CREATE TABLE IF NOT EXISTS public.measurement_templates (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    code character varying(100) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    measurement_type_id uuid,
    rule_type character varying(20) NOT NULL,
    predicate jsonb NOT NULL,
    category character varying(50),
    framework_tags text[],
    version integer DEFAULT 1,
    is_active boolean DEFAULT true,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT measurement_templates_rule_type_check CHECK (((rule_type)::text = ANY ((ARRAY['threshold'::character varying, 'presence'::character varying, 'pattern'::character varying, 'range'::character varying])::text[]))),
    CONSTRAINT valid_rule_type CHECK (((rule_type)::text = ANY ((ARRAY['threshold'::character varying, 'presence'::character varying, 'pattern'::character varying, 'range'::character varying])::text[])))
);


-- TABLE: measurement_types
CREATE TABLE IF NOT EXISTS public.measurement_types (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    code character varying(100) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    data_type character varying(20) NOT NULL,
    extraction_query text,
    units character varying(50),
    valid_range jsonb,
    allowed_rule_types jsonb,
    enum_values jsonb,
    valid_operators jsonb,
    predicate_schema jsonb,
    category character varying(50),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT measurement_types_data_type_check CHECK (((data_type)::text = ANY ((ARRAY['integer'::character varying, 'string'::character varying, 'enum'::character varying, 'date'::character varying, 'boolean'::character varying])::text[])))
);


-- TABLE: monitoring_alert_history
CREATE TABLE IF NOT EXISTS public.monitoring_alert_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    threshold_id uuid,
    threshold_name character varying(100) NOT NULL,
    metric_type character varying(50) NOT NULL,
    service_name character varying(100),
    threshold_value numeric(10,3) NOT NULL,
    actual_value numeric(10,3) NOT NULL,
    severity character varying(20) NOT NULL,
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    acknowledged_by uuid,
    acknowledged_at timestamp with time zone,
    resolved_at timestamp with time zone,
    notifications_sent jsonb DEFAULT '[]'::jsonb,
    message text,
    metadata jsonb DEFAULT '{}'::jsonb,
    triggered_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_alert_severity CHECK (((severity)::text = ANY ((ARRAY['low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying])::text[]))),
    CONSTRAINT valid_alert_status CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'acknowledged'::character varying, 'resolved'::character varying, 'suppressed'::character varying])::text[])))
);


-- TABLE: monitoring_alert_thresholds
CREATE TABLE IF NOT EXISTS public.monitoring_alert_thresholds (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    threshold_name character varying(100) NOT NULL,
    metric_type character varying(50) NOT NULL,
    service_name character varying(100),
    warning_threshold numeric(10,3),
    critical_threshold numeric(10,3),
    severity character varying(20) DEFAULT 'medium'::character varying NOT NULL,
    enabled boolean DEFAULT true,
    notify_email boolean DEFAULT false,
    notify_slack boolean DEFAULT false,
    notify_webhook boolean DEFAULT false,
    notify_in_app boolean DEFAULT true,
    comparison_operator character varying(10) DEFAULT 'gt'::character varying,
    duration_minutes integer DEFAULT 5,
    description text,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    updated_by uuid,
    CONSTRAINT valid_metric_type CHECK (((metric_type)::text = ANY ((ARRAY['response_time'::character varying, 'error_rate'::character varying, 'cpu_usage'::character varying, 'memory_usage'::character varying, 'uptime'::character varying, 'throughput'::character varying, 'custom'::character varying])::text[]))),
    CONSTRAINT valid_operator CHECK (((comparison_operator)::text = ANY ((ARRAY['gt'::character varying, 'lt'::character varying, 'eq'::character varying, 'gte'::character varying, 'lte'::character varying])::text[]))),
    CONSTRAINT valid_severity CHECK (((severity)::text = ANY ((ARRAY['low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying])::text[])))
);


-- TABLE: monitoring_notification_channels
CREATE TABLE IF NOT EXISTS public.monitoring_notification_channels (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    channel_name character varying(100) NOT NULL,
    channel_type character varying(50) NOT NULL,
    config jsonb NOT NULL,
    enabled boolean DEFAULT true,
    test_status character varying(20),
    last_test_at timestamp with time zone,
    description text,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    updated_by uuid,
    CONSTRAINT valid_channel_type CHECK (((channel_type)::text = ANY ((ARRAY['email'::character varying, 'slack'::character varying, 'webhook'::character varying, 'pagerduty'::character varying, 'custom'::character varying])::text[])))
);


-- TABLE: network_assets_partitioned
CREATE TABLE IF NOT EXISTS public.network_assets_partitioned (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    hostname character varying(255),
    ip_address inet,
    port integer,
    asset_type public.asset_type NOT NULL,
    operating_system character varying(100),
    environment public.environment_type,
    business_unit character varying(100),
    owner_email character varying(255),
    description text,
    tags jsonb DEFAULT '{}'::jsonb,
    metadata jsonb DEFAULT '{}'::jsonb,
    first_discovered_at timestamp with time zone DEFAULT now(),
    last_seen_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    risk_score integer DEFAULT 0,
    risk_level character varying(20) DEFAULT 'Informational'::character varying,
    location_id uuid,
    network_segment_id uuid,
    service_name character varying(100),
    service_version character varying(100),
    service_confidence character varying(20) DEFAULT 'none'::character varying,
    service_identification_method character varying(50),
    fqdns text[],
    mac_addresses text[],
    serial_number text,
    cloud_provider text,
    cloud_account_id text,
    cloud_instance_id text,
    site text,
    region text,
    zone text,
    discovery_method text,
    confidence_score integer,
    stale_status character varying(50) DEFAULT NULL::character varying,
    asset_status character varying(50) DEFAULT 'monitoring'::character varying,
    asset_ownership character varying(50) DEFAULT 'unknown'::character varying,
    -- Active Scan per-asset crypto-scan freshness.
    --   last_scanned_at  = when the asset was last actively scanned (NULL =
    --                      never; drives the "unscanned" coverage filter)
    --   last_scan_status = outcome of the most recent scan dispatch
    --                      ('scanning' | 'completed' | 'failed')
    last_scanned_at timestamp with time zone,
    last_scan_status text,
    CONSTRAINT network_assets_partitioned_asset_ownership_check CHECK (((asset_ownership)::text = ANY ((ARRAY['internal'::character varying, 'third_party'::character varying, 'unknown'::character varying])::text[])))
)
PARTITION BY HASH (tenant_id);


-- VIEW: network_assets
-- DROP first so re-applying the file is idempotent: this view is redefined in the
-- POST-MIGRATIONS block with two extra columns (last_scanned_at, last_scan_status)
-- ALTER-added there; without the DROP, the second apply tries to shrink the
-- already-widened view and fails with "cannot drop columns from view".
DROP VIEW IF EXISTS public.network_assets;
CREATE OR REPLACE VIEW public.network_assets AS
 SELECT network_assets_partitioned.id,
    network_assets_partitioned.tenant_id,
    network_assets_partitioned.hostname,
    network_assets_partitioned.ip_address,
    network_assets_partitioned.port,
    network_assets_partitioned.asset_type,
    network_assets_partitioned.operating_system,
    network_assets_partitioned.environment,
    network_assets_partitioned.business_unit,
    network_assets_partitioned.owner_email,
    network_assets_partitioned.description,
    network_assets_partitioned.tags,
    network_assets_partitioned.metadata,
    network_assets_partitioned.first_discovered_at,
    network_assets_partitioned.last_seen_at,
    network_assets_partitioned.created_at,
    network_assets_partitioned.updated_at,
    network_assets_partitioned.deleted_at,
    network_assets_partitioned.risk_score,
    network_assets_partitioned.risk_level,
    network_assets_partitioned.location_id,
    network_assets_partitioned.network_segment_id,
    network_assets_partitioned.service_name,
    network_assets_partitioned.service_version,
    network_assets_partitioned.service_confidence,
    network_assets_partitioned.service_identification_method,
    network_assets_partitioned.fqdns,
    network_assets_partitioned.mac_addresses,
    network_assets_partitioned.serial_number,
    network_assets_partitioned.cloud_provider,
    network_assets_partitioned.cloud_account_id,
    network_assets_partitioned.cloud_instance_id,
    network_assets_partitioned.site,
    network_assets_partitioned.region,
    network_assets_partitioned.zone,
    network_assets_partitioned.discovery_method,
    network_assets_partitioned.confidence_score,
    network_assets_partitioned.stale_status,
    network_assets_partitioned.asset_status,
    network_assets_partitioned.asset_ownership,
    network_assets_partitioned.last_scanned_at,
    network_assets_partitioned.last_scan_status
   FROM public.network_assets_partitioned;


-- MATERIALIZED VIEW: mv_location_finding_summary
CREATE MATERIALIZED VIEW IF NOT EXISTS public.mv_location_finding_summary AS
 SELECT l.id AS location_id,
    l.tenant_id,
    l.name AS location_name,
    (l.location_type)::text AS location_type,
    l.full_path,
    COALESCE((a.environment)::text, 'unknown'::text) AS environment,
    count(DISTINCT a.id) AS asset_count,
    count(DISTINCT ci.id) AS crypto_config_count,
    count(DISTINCT c.id) AS certificate_count,
    count(DISTINCT a.id) FILTER (WHERE ((a.risk_level)::text = 'Critical'::text)) AS critical_findings,
    count(DISTINCT a.id) FILTER (WHERE ((a.risk_level)::text = 'High'::text)) AS high_findings,
    count(DISTINCT a.id) FILTER (WHERE ((a.risk_level)::text = 'Medium'::text)) AS medium_findings,
    count(DISTINCT a.id) FILTER (WHERE ((a.risk_level)::text = 'Low'::text)) AS low_findings,
    count(DISTINCT c.id) FILTER (WHERE ((c.not_after IS NOT NULL) AND (c.not_after > now()) AND (c.not_after <= (now() + '30 days'::interval)))) AS expiring_certs_30d,
    count(DISTINCT c.id) FILTER (WHERE ((c.not_after IS NOT NULL) AND (c.not_after < now()))) AS expired_certs
   FROM (((public.locations l
     LEFT JOIN public.network_assets_partitioned a ON (((a.location_id = l.id) AND (a.deleted_at IS NULL))))
     LEFT JOIN public.crypto_implementations_partitioned ci ON (((ci.asset_id = a.id) AND (ci.deleted_at IS NULL))))
     LEFT JOIN public.certificates c ON ((c.id = ci.certificate_id)))
  GROUP BY l.id, l.tenant_id, l.name, l.location_type, l.full_path, a.environment
  WITH DATA;


-- MATERIALIZED VIEW: mv_remediation_queue
CREATE MATERIALIZED VIEW IF NOT EXISTS public.mv_remediation_queue AS
 SELECT a.tenant_id,
    'expiring_cert'::character varying(50) AS finding_type,
        CASE
            WHEN (c.not_after <= now()) THEN 'critical'::text
            ELSE 'high'::text
        END AS severity,
    a.id AS asset_id,
    a.hostname AS asset_hostname,
    (a.ip_address)::text AS asset_ip,
    a.port AS asset_port,
    l.name AS location_name,
    l.full_path AS location_full_path,
    (a.environment)::text AS environment,
    a.service_name,
    c.id AS certificate_id,
    ci.id AS crypto_implementation_id,
    ((('Certificate '::text || (COALESCE(c.common_name, (c.subject_dn)::character varying))::text) || ' expires '::text) || (c.not_after)::text) AS detail_text,
    ci.created_at
   FROM (((public.network_assets_partitioned a
     JOIN public.crypto_implementations_partitioned ci ON (((ci.asset_id = a.id) AND (ci.deleted_at IS NULL))))
     JOIN public.certificates c ON (((c.id = ci.certificate_id) AND (c.not_after IS NOT NULL) AND ((c.not_after <= now()) OR (c.not_after <= (now() + '30 days'::interval))))))
     LEFT JOIN public.locations l ON ((l.id = a.location_id)))
  WHERE (a.deleted_at IS NULL)
UNION ALL
 SELECT a.tenant_id,
    'weak_cipher'::character varying(50) AS finding_type,
        -- Canonical risk bands (services/inventory-service/internal/models/risk_bands.go):
        -- Critical >= 90, High >= 70, Medium >= 40, Low >= 1, Informational 0.
        -- CVSS v3.1/v4.0 qualitative ratings x10. This ladder previously ran
        -- >= 80 high / >= 60 medium, so an implementation scoring 60-69 was
        -- surfaced here as "medium" while every other surface called it Medium
        -- at >= 40 and High at >= 70 — the same drift risk_bands.go exists to
        -- prevent. Labels are lowercase because the consumer
        -- (OperationalService.GetRemediationQueue) filters and orders on them.
        CASE
            WHEN (ci.risk_score >= 90) THEN 'critical'::text
            WHEN (ci.risk_score >= 70) THEN 'high'::text
            WHEN (ci.risk_score >= 40) THEN 'medium'::text
            WHEN (ci.risk_score >= 1) THEN 'low'::text
            ELSE 'informational'::text
        END AS severity,
    a.id AS asset_id,
    a.hostname AS asset_hostname,
    (a.ip_address)::text AS asset_ip,
    a.port AS asset_port,
    l.name AS location_name,
    l.full_path AS location_full_path,
    (a.environment)::text AS environment,
    a.service_name,
    NULL::uuid AS certificate_id,
    ci.id AS crypto_implementation_id,
    ((('Risk score '::text || (ci.risk_score)::text) || ': '::text) || (COALESCE(ci.cipher_suite, ((ci.protocol)::text)::character varying))::text) AS detail_text,
    ci.created_at
   FROM ((public.network_assets_partitioned a
     -- >= 40 is the canonical Medium floor (risk_bands.go). It was >= 60, which
     -- silently hid the bottom half of the Medium band from the queue.
     JOIN public.crypto_implementations_partitioned ci ON (((ci.asset_id = a.id) AND (ci.deleted_at IS NULL) AND (ci.risk_score >= 40))))
     LEFT JOIN public.locations l ON ((l.id = a.location_id)))
  WHERE (a.deleted_at IS NULL)
UNION ALL
 SELECT a.tenant_id,
    'deprecated_protocol'::character varying(50) AS finding_type,
    'medium'::text AS severity,
    a.id AS asset_id,
    a.hostname AS asset_hostname,
    (a.ip_address)::text AS asset_ip,
    a.port AS asset_port,
    l.name AS location_name,
    l.full_path AS location_full_path,
    (a.environment)::text AS environment,
    a.service_name,
    NULL::uuid AS certificate_id,
    ci.id AS crypto_implementation_id,
    ('Protocol '::text || (COALESCE(ci.protocol_version, ((ci.protocol)::text)::character varying))::text) AS detail_text,
    ci.created_at
   FROM ((public.network_assets_partitioned a
     JOIN public.crypto_implementations_partitioned ci ON (((ci.asset_id = a.id) AND (ci.deleted_at IS NULL))))
     LEFT JOIN public.locations l ON ((l.id = a.location_id)))
  WHERE ((a.deleted_at IS NULL) AND (((ci.protocol_version)::text = ANY ((ARRAY['TLS 1.0'::character varying, 'TLS 1.1'::character varying, 'SSL 3.0'::character varying])::text[])) OR ((ci.protocol_version)::text ~~ '1.0'::text) OR ((ci.protocol_version)::text ~~ '1.1'::text)))
  WITH DATA;


-- TABLE: network_assets_part_0
CREATE TABLE IF NOT EXISTS public.network_assets_part_0 (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    hostname character varying(255),
    ip_address inet,
    port integer,
    asset_type public.asset_type NOT NULL,
    operating_system character varying(100),
    environment public.environment_type,
    business_unit character varying(100),
    owner_email character varying(255),
    description text,
    tags jsonb DEFAULT '{}'::jsonb,
    metadata jsonb DEFAULT '{}'::jsonb,
    first_discovered_at timestamp with time zone DEFAULT now(),
    last_seen_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    risk_score integer DEFAULT 0,
    risk_level character varying(20) DEFAULT 'Informational'::character varying,
    location_id uuid,
    network_segment_id uuid,
    service_name character varying(100),
    service_version character varying(100),
    service_confidence character varying(20) DEFAULT 'none'::character varying,
    service_identification_method character varying(50),
    fqdns text[],
    mac_addresses text[],
    serial_number text,
    cloud_provider text,
    cloud_account_id text,
    cloud_instance_id text,
    site text,
    region text,
    zone text,
    discovery_method text,
    confidence_score integer,
    stale_status character varying(50) DEFAULT NULL::character varying,
    asset_status character varying(50) DEFAULT 'monitoring'::character varying,
    asset_ownership character varying(50) DEFAULT 'unknown'::character varying,
    last_scanned_at timestamp with time zone,
    last_scan_status text,
    CONSTRAINT network_assets_partitioned_asset_ownership_check CHECK (((asset_ownership)::text = ANY ((ARRAY['internal'::character varying, 'third_party'::character varying, 'unknown'::character varying])::text[])))
);


-- TABLE: network_assets_part_1
CREATE TABLE IF NOT EXISTS public.network_assets_part_1 (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    hostname character varying(255),
    ip_address inet,
    port integer,
    asset_type public.asset_type NOT NULL,
    operating_system character varying(100),
    environment public.environment_type,
    business_unit character varying(100),
    owner_email character varying(255),
    description text,
    tags jsonb DEFAULT '{}'::jsonb,
    metadata jsonb DEFAULT '{}'::jsonb,
    first_discovered_at timestamp with time zone DEFAULT now(),
    last_seen_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    risk_score integer DEFAULT 0,
    risk_level character varying(20) DEFAULT 'Informational'::character varying,
    location_id uuid,
    network_segment_id uuid,
    service_name character varying(100),
    service_version character varying(100),
    service_confidence character varying(20) DEFAULT 'none'::character varying,
    service_identification_method character varying(50),
    fqdns text[],
    mac_addresses text[],
    serial_number text,
    cloud_provider text,
    cloud_account_id text,
    cloud_instance_id text,
    site text,
    region text,
    zone text,
    discovery_method text,
    confidence_score integer,
    stale_status character varying(50) DEFAULT NULL::character varying,
    asset_status character varying(50) DEFAULT 'monitoring'::character varying,
    asset_ownership character varying(50) DEFAULT 'unknown'::character varying,
    last_scanned_at timestamp with time zone,
    last_scan_status text,
    CONSTRAINT network_assets_partitioned_asset_ownership_check CHECK (((asset_ownership)::text = ANY ((ARRAY['internal'::character varying, 'third_party'::character varying, 'unknown'::character varying])::text[])))
);


-- TABLE: network_assets_part_2
CREATE TABLE IF NOT EXISTS public.network_assets_part_2 (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    hostname character varying(255),
    ip_address inet,
    port integer,
    asset_type public.asset_type NOT NULL,
    operating_system character varying(100),
    environment public.environment_type,
    business_unit character varying(100),
    owner_email character varying(255),
    description text,
    tags jsonb DEFAULT '{}'::jsonb,
    metadata jsonb DEFAULT '{}'::jsonb,
    first_discovered_at timestamp with time zone DEFAULT now(),
    last_seen_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    risk_score integer DEFAULT 0,
    risk_level character varying(20) DEFAULT 'Informational'::character varying,
    location_id uuid,
    network_segment_id uuid,
    service_name character varying(100),
    service_version character varying(100),
    service_confidence character varying(20) DEFAULT 'none'::character varying,
    service_identification_method character varying(50),
    fqdns text[],
    mac_addresses text[],
    serial_number text,
    cloud_provider text,
    cloud_account_id text,
    cloud_instance_id text,
    site text,
    region text,
    zone text,
    discovery_method text,
    confidence_score integer,
    stale_status character varying(50) DEFAULT NULL::character varying,
    asset_status character varying(50) DEFAULT 'monitoring'::character varying,
    asset_ownership character varying(50) DEFAULT 'unknown'::character varying,
    last_scanned_at timestamp with time zone,
    last_scan_status text,
    CONSTRAINT network_assets_partitioned_asset_ownership_check CHECK (((asset_ownership)::text = ANY ((ARRAY['internal'::character varying, 'third_party'::character varying, 'unknown'::character varying])::text[])))
);


-- TABLE: network_assets_part_3
CREATE TABLE IF NOT EXISTS public.network_assets_part_3 (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    hostname character varying(255),
    ip_address inet,
    port integer,
    asset_type public.asset_type NOT NULL,
    operating_system character varying(100),
    environment public.environment_type,
    business_unit character varying(100),
    owner_email character varying(255),
    description text,
    tags jsonb DEFAULT '{}'::jsonb,
    metadata jsonb DEFAULT '{}'::jsonb,
    first_discovered_at timestamp with time zone DEFAULT now(),
    last_seen_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    risk_score integer DEFAULT 0,
    risk_level character varying(20) DEFAULT 'Informational'::character varying,
    location_id uuid,
    network_segment_id uuid,
    service_name character varying(100),
    service_version character varying(100),
    service_confidence character varying(20) DEFAULT 'none'::character varying,
    service_identification_method character varying(50),
    fqdns text[],
    mac_addresses text[],
    serial_number text,
    cloud_provider text,
    cloud_account_id text,
    cloud_instance_id text,
    site text,
    region text,
    zone text,
    discovery_method text,
    confidence_score integer,
    stale_status character varying(50) DEFAULT NULL::character varying,
    asset_status character varying(50) DEFAULT 'monitoring'::character varying,
    asset_ownership character varying(50) DEFAULT 'unknown'::character varying,
    last_scanned_at timestamp with time zone,
    last_scan_status text,
    CONSTRAINT network_assets_partitioned_asset_ownership_check CHECK (((asset_ownership)::text = ANY ((ARRAY['internal'::character varying, 'third_party'::character varying, 'unknown'::character varying])::text[])))
);


-- TABLE: network_assets_part_4
CREATE TABLE IF NOT EXISTS public.network_assets_part_4 (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    hostname character varying(255),
    ip_address inet,
    port integer,
    asset_type public.asset_type NOT NULL,
    operating_system character varying(100),
    environment public.environment_type,
    business_unit character varying(100),
    owner_email character varying(255),
    description text,
    tags jsonb DEFAULT '{}'::jsonb,
    metadata jsonb DEFAULT '{}'::jsonb,
    first_discovered_at timestamp with time zone DEFAULT now(),
    last_seen_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    risk_score integer DEFAULT 0,
    risk_level character varying(20) DEFAULT 'Informational'::character varying,
    location_id uuid,
    network_segment_id uuid,
    service_name character varying(100),
    service_version character varying(100),
    service_confidence character varying(20) DEFAULT 'none'::character varying,
    service_identification_method character varying(50),
    fqdns text[],
    mac_addresses text[],
    serial_number text,
    cloud_provider text,
    cloud_account_id text,
    cloud_instance_id text,
    site text,
    region text,
    zone text,
    discovery_method text,
    confidence_score integer,
    stale_status character varying(50) DEFAULT NULL::character varying,
    asset_status character varying(50) DEFAULT 'monitoring'::character varying,
    asset_ownership character varying(50) DEFAULT 'unknown'::character varying,
    last_scanned_at timestamp with time zone,
    last_scan_status text,
    CONSTRAINT network_assets_partitioned_asset_ownership_check CHECK (((asset_ownership)::text = ANY ((ARRAY['internal'::character varying, 'third_party'::character varying, 'unknown'::character varying])::text[])))
);


-- TABLE: network_assets_part_5
CREATE TABLE IF NOT EXISTS public.network_assets_part_5 (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    hostname character varying(255),
    ip_address inet,
    port integer,
    asset_type public.asset_type NOT NULL,
    operating_system character varying(100),
    environment public.environment_type,
    business_unit character varying(100),
    owner_email character varying(255),
    description text,
    tags jsonb DEFAULT '{}'::jsonb,
    metadata jsonb DEFAULT '{}'::jsonb,
    first_discovered_at timestamp with time zone DEFAULT now(),
    last_seen_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    risk_score integer DEFAULT 0,
    risk_level character varying(20) DEFAULT 'Informational'::character varying,
    location_id uuid,
    network_segment_id uuid,
    service_name character varying(100),
    service_version character varying(100),
    service_confidence character varying(20) DEFAULT 'none'::character varying,
    service_identification_method character varying(50),
    fqdns text[],
    mac_addresses text[],
    serial_number text,
    cloud_provider text,
    cloud_account_id text,
    cloud_instance_id text,
    site text,
    region text,
    zone text,
    discovery_method text,
    confidence_score integer,
    stale_status character varying(50) DEFAULT NULL::character varying,
    asset_status character varying(50) DEFAULT 'monitoring'::character varying,
    asset_ownership character varying(50) DEFAULT 'unknown'::character varying,
    last_scanned_at timestamp with time zone,
    last_scan_status text,
    CONSTRAINT network_assets_partitioned_asset_ownership_check CHECK (((asset_ownership)::text = ANY ((ARRAY['internal'::character varying, 'third_party'::character varying, 'unknown'::character varying])::text[])))
);


-- TABLE: network_assets_part_6
CREATE TABLE IF NOT EXISTS public.network_assets_part_6 (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    hostname character varying(255),
    ip_address inet,
    port integer,
    asset_type public.asset_type NOT NULL,
    operating_system character varying(100),
    environment public.environment_type,
    business_unit character varying(100),
    owner_email character varying(255),
    description text,
    tags jsonb DEFAULT '{}'::jsonb,
    metadata jsonb DEFAULT '{}'::jsonb,
    first_discovered_at timestamp with time zone DEFAULT now(),
    last_seen_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    risk_score integer DEFAULT 0,
    risk_level character varying(20) DEFAULT 'Informational'::character varying,
    location_id uuid,
    network_segment_id uuid,
    service_name character varying(100),
    service_version character varying(100),
    service_confidence character varying(20) DEFAULT 'none'::character varying,
    service_identification_method character varying(50),
    fqdns text[],
    mac_addresses text[],
    serial_number text,
    cloud_provider text,
    cloud_account_id text,
    cloud_instance_id text,
    site text,
    region text,
    zone text,
    discovery_method text,
    confidence_score integer,
    stale_status character varying(50) DEFAULT NULL::character varying,
    asset_status character varying(50) DEFAULT 'monitoring'::character varying,
    asset_ownership character varying(50) DEFAULT 'unknown'::character varying,
    last_scanned_at timestamp with time zone,
    last_scan_status text,
    CONSTRAINT network_assets_partitioned_asset_ownership_check CHECK (((asset_ownership)::text = ANY ((ARRAY['internal'::character varying, 'third_party'::character varying, 'unknown'::character varying])::text[])))
);


-- TABLE: network_assets_part_7
CREATE TABLE IF NOT EXISTS public.network_assets_part_7 (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    hostname character varying(255),
    ip_address inet,
    port integer,
    asset_type public.asset_type NOT NULL,
    operating_system character varying(100),
    environment public.environment_type,
    business_unit character varying(100),
    owner_email character varying(255),
    description text,
    tags jsonb DEFAULT '{}'::jsonb,
    metadata jsonb DEFAULT '{}'::jsonb,
    first_discovered_at timestamp with time zone DEFAULT now(),
    last_seen_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    risk_score integer DEFAULT 0,
    risk_level character varying(20) DEFAULT 'Informational'::character varying,
    location_id uuid,
    network_segment_id uuid,
    service_name character varying(100),
    service_version character varying(100),
    service_confidence character varying(20) DEFAULT 'none'::character varying,
    service_identification_method character varying(50),
    fqdns text[],
    mac_addresses text[],
    serial_number text,
    cloud_provider text,
    cloud_account_id text,
    cloud_instance_id text,
    site text,
    region text,
    zone text,
    discovery_method text,
    confidence_score integer,
    stale_status character varying(50) DEFAULT NULL::character varying,
    asset_status character varying(50) DEFAULT 'monitoring'::character varying,
    asset_ownership character varying(50) DEFAULT 'unknown'::character varying,
    last_scanned_at timestamp with time zone,
    last_scan_status text,
    CONSTRAINT network_assets_partitioned_asset_ownership_check CHECK (((asset_ownership)::text = ANY ((ARRAY['internal'::character varying, 'third_party'::character varying, 'unknown'::character varying])::text[])))
);


-- TABLE: network_segments
CREATE TABLE IF NOT EXISTS public.network_segments (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    segment_type character varying(20) NOT NULL,
    value character varying(512) NOT NULL,
    network_type character varying(20) DEFAULT 'private'::character varying NOT NULL,
    environment public.environment_type NOT NULL,
    location_id uuid,
    business_unit character varying(100),
    owner_email character varying(255),
    description text,
    is_active boolean DEFAULT true,
    auto_approve_discoveries boolean DEFAULT false,
    tags jsonb DEFAULT '{}'::jsonb,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT network_segments_network_type_check CHECK (((network_type)::text = ANY ((ARRAY['private'::character varying, 'public'::character varying, 'vpn'::character varying, 'cloud'::character varying])::text[]))),
    CONSTRAINT network_segments_segment_type_check CHECK (((segment_type)::text = ANY ((ARRAY['cidr'::character varying, 'ip_range'::character varying, 'domain'::character varying, 'cloud_vpc'::character varying])::text[])))
);


-- TABLE: notification_delivery_queue
CREATE TABLE IF NOT EXISTS public.notification_delivery_queue (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    notification_id uuid NOT NULL,
    channel_id uuid NOT NULL,
    channel_type character varying(50) NOT NULL,
    payload jsonb NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    retry_count integer DEFAULT 0,
    next_retry_at timestamp with time zone,
    delivered_at timestamp with time zone,
    error_message text,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_delivery_status CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'sent'::character varying, 'failed'::character varying, 'retrying'::character varying])::text[])))
);


-- TABLE: notification_history
CREATE TABLE IF NOT EXISTS public.notification_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    notification_type character varying(50) NOT NULL,
    alert_source character varying(50) NOT NULL,
    alert_type character varying(100) NOT NULL,
    severity character varying(20) NOT NULL,
    message text NOT NULL,
    channels_used text[] NOT NULL,
    status character varying(20) DEFAULT 'sent'::character varying NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_notification_severity CHECK (((severity)::text = ANY ((ARRAY['critical'::character varying, 'high'::character varying, 'medium'::character varying, 'low'::character varying, 'info'::character varying])::text[]))),
    CONSTRAINT valid_notification_status CHECK (((status)::text = ANY ((ARRAY['sent'::character varying, 'failed'::character varying, 'pending'::character varying, 'partial'::character varying])::text[])))
);


-- TABLE: pcap_upload_jobs
CREATE TABLE IF NOT EXISTS public.pcap_upload_jobs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    uploaded_by uuid NOT NULL,
    original_filename text NOT NULL,
    file_size_bytes bigint NOT NULL,
    file_path text,
    status text DEFAULT 'pending'::text NOT NULL,
    discovery_count integer DEFAULT 0,
    packet_count bigint DEFAULT 0,
    protocols_found jsonb DEFAULT '{}'::jsonb,
    capture_time_range jsonb DEFAULT '{}'::jsonb,
    error_message text,
    processing_started_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT pcap_upload_jobs_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'uploading'::text, 'processing'::text, 'completed'::text, 'failed'::text, 'cancelled'::text])))
);


-- TABLE: pending_sensor_registrations
CREATE TABLE IF NOT EXISTS public.pending_sensor_registrations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    registration_key character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    ip_address inet NOT NULL,
    profile character varying(50) DEFAULT 'datacenter_host'::character varying NOT NULL,
    network_interfaces text[] DEFAULT ARRAY[]::text[],
    tags text[] DEFAULT ARRAY[]::text[],
    description text,
    metadata jsonb DEFAULT '{}'::jsonb,
    status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    CONSTRAINT key_expires_after_creation CHECK ((expires_at > created_at)),
    CONSTRAINT valid_profile CHECK (((profile)::text = ANY ((ARRAY['datacenter_host'::character varying, 'cloud_instance'::character varying, 'end_user_machine'::character varying, 'air_gapped'::character varying, 'device_interrogation'::character varying])::text[]))),
    CONSTRAINT valid_status CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'used'::character varying, 'expired'::character varying, 'cancelled'::character varying])::text[])))
);


-- TABLE: pending_sensors
CREATE TABLE IF NOT EXISTS public.pending_sensors (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    registration_key character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    ip_address inet NOT NULL,
    profile character varying(50) NOT NULL,
    network_interfaces text[],
    tags text[],
    description text,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    CONSTRAINT pending_sensors_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'used'::character varying, 'expired'::character varying, 'cancelled'::character varying])::text[])))
);


-- TABLE: permission_audit_logs
CREATE TABLE IF NOT EXISTS public.permission_audit_logs (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id uuid,
    tenant_id uuid,
    action character varying(100) NOT NULL,
    resource_type character varying(50),
    resource_id uuid,
    permission_required character varying(100),
    permission_granted boolean,
    ip_address inet,
    user_agent text,
    created_at timestamp with time zone DEFAULT now()
);


-- TABLE: platform_roles
CREATE TABLE IF NOT EXISTS public.platform_roles (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(50) NOT NULL,
    display_name character varying(100) NOT NULL,
    description text,
    is_system_role boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: platform_users
CREATE TABLE IF NOT EXISTS public.platform_users (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    email character varying(255) NOT NULL,
    password_hash character varying(255) NOT NULL,
    first_name character varying(100) NOT NULL,
    last_name character varying(100) NOT NULL,
    role_id uuid NOT NULL,
    is_active boolean DEFAULT true,
    email_verified boolean DEFAULT false,
    last_login_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    force_password_change boolean DEFAULT false NOT NULL,
    password_changed_at timestamp with time zone,
    password_reset_token character varying(255),
    password_reset_expires timestamp with time zone,
    invited_by uuid,
    invitation_accepted_at timestamp with time zone,
    -- Account lockout, mirroring the tenant `users` table.
    failed_login_attempts integer DEFAULT 0,
    locked_until timestamp with time zone
);


-- VIEW: platform_administrators
CREATE OR REPLACE VIEW public.platform_administrators AS
 SELECT pu.id,
    pu.email,
    pu.first_name,
    pu.last_name,
    pr.name AS role_name,
    pr.display_name AS role_display_name,
    pu.is_active,
    pu.last_login_at,
    pu.created_at
   FROM (public.platform_users pu
     JOIN public.platform_roles pr ON ((pu.role_id = pr.id)))
  WHERE (pu.deleted_at IS NULL);


-- TABLE: platform_announcements
CREATE TABLE IF NOT EXISTS public.platform_announcements (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    title character varying(255) NOT NULL,
    content text NOT NULL,
    type character varying(50) DEFAULT 'info'::character varying NOT NULL,
    target character varying(50) DEFAULT 'all'::character varying NOT NULL,
    target_ids uuid[] DEFAULT '{}'::uuid[],
    is_active boolean DEFAULT true NOT NULL,
    starts_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


-- TABLE: platform_bootstrap_ca
CREATE TABLE IF NOT EXISTS public.platform_bootstrap_ca (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ca_cert_pem text NOT NULL,
    ca_key_pem_encrypted text NOT NULL,
    serial_number bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone NOT NULL,
    is_active boolean DEFAULT true
);


-- TABLE: platform_bootstrap_certificates
CREATE TABLE IF NOT EXISTS public.platform_bootstrap_certificates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    service_name character varying(100) NOT NULL,
    certificate_pem text NOT NULL,
    serial_number character varying(255) NOT NULL,
    issued_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    revocation_reason character varying(50),
    created_at timestamp with time zone DEFAULT now()
);


-- TABLE: platform_framework_controls
CREATE TABLE IF NOT EXISTS public.platform_framework_controls (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    framework_id uuid NOT NULL,
    family_id uuid,
    control_id character varying(100) NOT NULL,
    title character varying(500) NOT NULL,
    description text,
    baseline_severity character varying(20) NOT NULL,
    crypto_relevant boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT platform_framework_controls_baseline_severity_check CHECK (((baseline_severity)::text = ANY ((ARRAY['Low'::character varying, 'Med'::character varying, 'High'::character varying, 'Critical'::character varying])::text[])))
);


-- TABLE: platform_framework_versions
CREATE TABLE IF NOT EXISTS public.platform_framework_versions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    framework_id uuid NOT NULL,
    version character varying(20) NOT NULL,
    snapshot jsonb NOT NULL,
    change_summary text,
    changed_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


-- TABLE: platform_frameworks
CREATE TABLE IF NOT EXISTS public.platform_frameworks (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    code character varying(100) NOT NULL,
    name character varying(255) NOT NULL,
    version character varying(20) NOT NULL,
    description text,
    organization character varying(255),
    status character varying(20) DEFAULT 'draft'::character varying NOT NULL,
    published_at timestamp with time zone,
    published_by uuid,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    is_platform_default boolean DEFAULT false NOT NULL,
    CONSTRAINT platform_frameworks_status_check CHECK (((status)::text = ANY ((ARRAY['draft'::character varying, 'published'::character varying, 'archived'::character varying])::text[])))
);


-- TABLE: platform_integration_audit_log
CREATE TABLE IF NOT EXISTS public.platform_integration_audit_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    integration_id uuid NOT NULL,
    action character varying(50) NOT NULL,
    performed_by uuid NOT NULL,
    performed_by_email character varying(255) NOT NULL,
    old_config_hash character varying(64),
    new_config_hash character varying(64),
    changed_fields jsonb DEFAULT '{}'::jsonb,
    success boolean DEFAULT true,
    error_message text,
    ip_address inet,
    user_agent text,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_action CHECK (((action)::text = ANY ((ARRAY['created'::character varying, 'updated'::character varying, 'deleted'::character varying, 'enabled'::character varying, 'disabled'::character varying, 'tested'::character varying, 'credential_rotated'::character varying, 'status_changed'::character varying])::text[])))
);


-- TABLE: platform_integration_secrets
CREATE TABLE IF NOT EXISTS public.platform_integration_secrets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    integration_id uuid NOT NULL,
    secret_key character varying(100) NOT NULL,
    encrypted_value text NOT NULL,
    encryption_key_id character varying(255),
    version integer DEFAULT 1,
    is_current boolean DEFAULT true,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    rotated_at timestamp with time zone,
    CONSTRAINT valid_secret_key CHECK (((secret_key)::text = ANY ((ARRAY['access_key_id'::character varying, 'secret_access_key'::character varying, 'session_token'::character varying, 'api_token'::character varying, 'api_key'::character varying, 'webhook_url'::character varying, 'client_id'::character varying, 'client_secret'::character varying, 'custom'::character varying])::text[])))
);


-- TABLE: platform_integrations
CREATE TABLE IF NOT EXISTS public.platform_integrations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    integration_type character varying(50) NOT NULL,
    integration_name character varying(100) NOT NULL,
    provider character varying(50) NOT NULL,
    tenant_id uuid,
    is_shared boolean DEFAULT false,
    config jsonb DEFAULT '{}'::jsonb NOT NULL,
    config_version integer DEFAULT 1,
    is_enabled boolean DEFAULT true,
    is_active boolean DEFAULT true,
    status character varying(20) DEFAULT 'pending'::character varying,
    status_message text,
    last_tested_at timestamp with time zone,
    last_successful_connection_at timestamp with time zone,
    account_id character varying(100),
    region character varying(50),
    environment character varying(50),
    description text,
    tags jsonb DEFAULT '[]'::jsonb,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    CONSTRAINT valid_integration_type CHECK (((integration_type)::text = ANY ((ARRAY['aws'::character varying, 'azure'::character varying, 'gcp'::character varying, 'slack'::character varying, 'pagerduty'::character varying, 'datadog'::character varying, 'splunk'::character varying, 'custom'::character varying, 'github'::character varying, 'gitlab'::character varying, 'bitbucket'::character varying, 'hashicorp_vault'::character varying])::text[]))),
    CONSTRAINT valid_provider CHECK (((provider)::text = ANY ((ARRAY['cloud'::character varying, 'saas'::character varying, 'custom'::character varying])::text[]))),
    CONSTRAINT valid_status CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'configured'::character varying, 'connected'::character varying, 'error'::character varying, 'disconnected'::character varying])::text[])))
);


-- VIEW: platform_integrations_summary
CREATE OR REPLACE VIEW public.platform_integrations_summary AS
 SELECT platform_integrations.id,
    platform_integrations.integration_type,
    platform_integrations.integration_name,
    platform_integrations.provider,
    platform_integrations.account_id,
    platform_integrations.region,
    platform_integrations.environment,
    platform_integrations.is_enabled,
    platform_integrations.is_active,
    platform_integrations.status,
    platform_integrations.status_message,
    platform_integrations.last_tested_at,
    platform_integrations.last_successful_connection_at,
    platform_integrations.description,
    platform_integrations.tags,
    platform_integrations.metadata,
    platform_integrations.created_at,
    platform_integrations.updated_at,
    (platform_integrations.config ->> 'config_version'::text) AS config_version,
    jsonb_object_keys(platform_integrations.config) AS config_keys
   FROM public.platform_integrations
  WHERE (platform_integrations.deleted_at IS NULL);


-- TABLE: platform_log_access_audit
CREATE TABLE IF NOT EXISTS public.platform_log_access_audit (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    accessed_by_user_id uuid NOT NULL,
    accessed_by_email character varying(255),
    access_type character varying(50) NOT NULL,
    log_id uuid,
    filter_criteria jsonb,
    result_count integer,
    api_endpoint character varying(255),
    request_method character varying(10),
    signed_url_generated boolean DEFAULT false,
    s3_signed_url character varying(2048),
    s3_access_ip inet,
    s3_access_timestamp timestamp with time zone,
    accessed_at timestamp with time zone DEFAULT now(),
    access_duration_ms integer,
    access_result character varying(20) NOT NULL,
    error_message text,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_access_result CHECK (((access_result)::text = ANY ((ARRAY['success'::character varying, 'denied'::character varying, 'error'::character varying])::text[]))),
    CONSTRAINT valid_access_type CHECK (((access_type)::text = ANY ((ARRAY['metadata'::character varying, 'download'::character varying, 'export'::character varying, 'delete'::character varying, 'search'::character varying])::text[])))
);


-- TABLE: platform_log_metadata
CREATE TABLE IF NOT EXISTS public.platform_log_metadata (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    log_id character varying(255) NOT NULL,
    correlation_id character varying(255),
    trace_id character varying(255),
    service_name character varying(100) NOT NULL,
    service_version character varying(50),
    environment character varying(50) NOT NULL,
    severity character varying(20) NOT NULL,
    event_type character varying(100) NOT NULL,
    category character varying(50),
    message_digest character varying(64) NOT NULL,
    message_preview text,
    redaction_mask text,
    tenant_id uuid,
    user_id uuid,
    user_type character varying(20),
    request_id character varying(255),
    source_ip inet,
    user_agent text,
    request_method character varying(10),
    request_path text,
    response_status integer,
    "timestamp" timestamp with time zone NOT NULL,
    duration_ms integer,
    s3_bucket character varying(255) NOT NULL,
    s3_key character varying(512) NOT NULL,
    s3_region character varying(50) NOT NULL,
    s3_etag character varying(64),
    status character varying(20) DEFAULT 'active'::character varying,
    retention_policy character varying(50) DEFAULT '90-days-hot'::character varying,
    archived_at timestamp with time zone,
    deleted_at timestamp with time zone,
    pii_detected boolean DEFAULT false,
    pii_types text[],
    scrubbed_at timestamp with time zone,
    compliance_tags text[],
    encryption_status character varying(20) DEFAULT 'encrypted'::character varying,
    metadata jsonb DEFAULT '{}'::jsonb,
    tags jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_retention_policy CHECK (((retention_policy)::text = ANY ((ARRAY['90-days-hot'::character varying, '365-days-archive'::character varying])::text[]))),
    CONSTRAINT valid_severity CHECK (((severity)::text = ANY ((ARRAY['debug'::character varying, 'info'::character varying, 'warn'::character varying, 'error'::character varying, 'critical'::character varying])::text[]))),
    CONSTRAINT valid_status CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'archived'::character varying, 'deleted'::character varying])::text[]))),
    CONSTRAINT valid_user_type CHECK ((((user_type)::text = ANY ((ARRAY['tenant'::character varying, 'platform'::character varying])::text[])) OR (user_type IS NULL)))
);


-- TABLE: platform_log_pii_rules
CREATE TABLE IF NOT EXISTS public.platform_log_pii_rules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rule_name character varying(100) NOT NULL,
    pii_type character varying(50) NOT NULL,
    pattern_type character varying(20) NOT NULL,
    pattern character varying(500) NOT NULL,
    redaction_method character varying(20) DEFAULT 'hash'::character varying,
    replacement_value character varying(100),
    priority integer DEFAULT 0,
    is_active boolean DEFAULT true,
    description text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_pattern_type CHECK (((pattern_type)::text = ANY ((ARRAY['regex'::character varying, 'keyword'::character varying, 'format'::character varying])::text[]))),
    CONSTRAINT valid_pii_type CHECK (((pii_type)::text = ANY ((ARRAY['email'::character varying, 'ssn'::character varying, 'phone'::character varying, 'credit_card'::character varying, 'ip_address'::character varying, 'name'::character varying, 'address'::character varying, 'date_of_birth'::character varying, 'custom'::character varying])::text[]))),
    CONSTRAINT valid_redaction_method CHECK (((redaction_method)::text = ANY ((ARRAY['hash'::character varying, 'mask'::character varying, 'remove'::character varying, 'replace'::character varying])::text[])))
);


-- TABLE: platform_log_retention_jobs
CREATE TABLE IF NOT EXISTS public.platform_log_retention_jobs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    job_type character varying(50) NOT NULL,
    execution_status character varying(20) NOT NULL,
    logs_processed integer DEFAULT 0,
    logs_archived integer DEFAULT 0,
    logs_deleted integer DEFAULT 0,
    logs_scrubbed integer DEFAULT 0,
    started_at timestamp with time zone DEFAULT now(),
    completed_at timestamp with time zone,
    duration_ms integer,
    error_message text,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_execution_status CHECK (((execution_status)::text = ANY ((ARRAY['running'::character varying, 'completed'::character varying, 'failed'::character varying])::text[]))),
    CONSTRAINT valid_job_type CHECK (((job_type)::text = ANY ((ARRAY['archive'::character varying, 'delete'::character varying, 'scrub_pii'::character varying, 'full_retention'::character varying])::text[])))
);


-- TABLE: platform_metrics_snapshots
CREATE TABLE IF NOT EXISTS public.platform_metrics_snapshots (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    service_name character varying(100) NOT NULL,
    window_start timestamp with time zone NOT NULL,
    window_duration integer NOT NULL,
    latency_p50 numeric(10,3),
    latency_p95 numeric(10,3),
    latency_p99 numeric(10,3),
    error_rate numeric(5,4),
    throughput numeric(15,2),
    status character varying(20) DEFAULT 'healthy'::character varying NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT valid_error_rate CHECK (((error_rate IS NULL) OR ((error_rate >= (0)::numeric) AND (error_rate <= (1)::numeric)))),
    CONSTRAINT valid_status CHECK (((status)::text = ANY ((ARRAY['healthy'::character varying, 'degraded'::character varying, 'down'::character varying])::text[]))),
    CONSTRAINT valid_window_duration CHECK ((window_duration = ANY (ARRAY[60, 3600, 86400])))
);


-- VIEW: platform_metrics_aggregations
CREATE OR REPLACE VIEW public.platform_metrics_aggregations AS
 SELECT platform_metrics_snapshots.service_name,
    platform_metrics_snapshots.window_start,
    platform_metrics_snapshots.window_duration,
    count(*) AS sample_count,
    avg(platform_metrics_snapshots.latency_p50) AS avg_latency_p50,
    avg(platform_metrics_snapshots.latency_p95) AS avg_latency_p95,
    avg(platform_metrics_snapshots.latency_p99) AS avg_latency_p99,
    avg(platform_metrics_snapshots.error_rate) AS avg_error_rate,
    sum(platform_metrics_snapshots.throughput) AS total_throughput,
    count(*) FILTER (WHERE ((platform_metrics_snapshots.status)::text = 'healthy'::text)) AS healthy_count,
    count(*) FILTER (WHERE ((platform_metrics_snapshots.status)::text = 'degraded'::text)) AS degraded_count,
    count(*) FILTER (WHERE ((platform_metrics_snapshots.status)::text = 'down'::text)) AS down_count
   FROM public.platform_metrics_snapshots
  GROUP BY platform_metrics_snapshots.service_name, platform_metrics_snapshots.window_start, platform_metrics_snapshots.window_duration;


-- TABLE: platform_notification_channels
CREATE TABLE IF NOT EXISTS public.platform_notification_channels (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    channel_name character varying(100) NOT NULL,
    channel_type character varying(50) NOT NULL,
    config jsonb NOT NULL,
    enabled boolean DEFAULT true,
    test_status character varying(20),
    last_test_at timestamp with time zone,
    last_used_at timestamp with time zone,
    description text,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    updated_by uuid,
    CONSTRAINT valid_platform_channel_type CHECK (((channel_type)::text = ANY ((ARRAY['email'::character varying, 'slack'::character varying, 'webhook'::character varying, 'pagerduty'::character varying, 'sms'::character varying, 'in_app'::character varying])::text[])))
);


-- TABLE: platform_notification_rules
CREATE TABLE IF NOT EXISTS public.platform_notification_rules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rule_name character varying(100) NOT NULL,
    alert_source character varying(50) NOT NULL,
    alert_type character varying(100),
    channel_ids uuid[] NOT NULL,
    severity_filter character varying(20)[],
    category_filter character varying(50)[],
    frequency character varying(20) DEFAULT 'immediate'::character varying,
    digest_window integer,
    enabled boolean DEFAULT true,
    priority integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_platform_frequency CHECK (((frequency)::text = ANY ((ARRAY['immediate'::character varying, 'digest_hourly'::character varying, 'digest_daily'::character varying, 'digest_weekly'::character varying])::text[])))
);


-- TABLE: platform_permissions
CREATE TABLE IF NOT EXISTS public.platform_permissions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(100) NOT NULL,
    resource character varying(50) NOT NULL,
    action character varying(50) NOT NULL,
    description text,
    created_at timestamp with time zone DEFAULT now()
);


-- TABLE: platform_refresh_tokens
CREATE TABLE IF NOT EXISTS public.platform_refresh_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    platform_user_id uuid NOT NULL,
    token_hash character varying(255) NOT NULL,
    family_id uuid NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    last_used_at timestamp with time zone DEFAULT now(),
    is_revoked boolean DEFAULT false,
    created_from_ip inet,
    user_agent text,
    created_at timestamp with time zone DEFAULT now(),
    revoked_at timestamp with time zone
);


-- TABLE: platform_role_permissions
CREATE TABLE IF NOT EXISTS public.platform_role_permissions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    role_id uuid NOT NULL,
    permission_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


-- TABLE: platform_service_ca
CREATE TABLE IF NOT EXISTS public.platform_service_ca (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ca_cert_pem text NOT NULL,
    ca_key_pem_encrypted text NOT NULL,
    serial_number bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone NOT NULL,
    is_active boolean DEFAULT true
);


-- TABLE: platform_service_certificates
CREATE TABLE IF NOT EXISTS public.platform_service_certificates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    service_name character varying(100) NOT NULL,
    server_cert_pem text NOT NULL,
    server_key_pem_encrypted text NOT NULL,
    client_cert_pem text NOT NULL,
    client_key_pem_encrypted text NOT NULL,
    serial_number character varying(255) NOT NULL,
    issued_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    revocation_reason character varying(50),
    created_at timestamp with time zone DEFAULT now()
);


-- TABLE: platform_settings
CREATE TABLE IF NOT EXISTS public.platform_settings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    setting_key character varying(100) NOT NULL,
    setting_value jsonb NOT NULL,
    description text,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


-- TABLE: platform_sso_providers
CREATE TABLE IF NOT EXISTS public.platform_sso_providers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    provider_type character varying(50) NOT NULL,
    provider_name character varying(100) NOT NULL,
    client_id character varying(255) NOT NULL,
    client_secret_encrypted text NOT NULL,
    auth_url character varying(500) NOT NULL,
    token_url character varying(500) NOT NULL,
    userinfo_url character varying(500) NOT NULL,
    scopes character varying(500) DEFAULT 'openid email profile'::character varying NOT NULL,
    is_enabled boolean DEFAULT true NOT NULL,
    --: a platform SSO provider serves one of two purposes — 'signup'
    -- (Vista's own app for tenant founders) and 'admin_login' (staff sign-in to
    -- admin-ui) — so uniqueness is (provider_type, purpose), NOT provider_type
    -- alone. See uq_platform_sso_provider_type_purpose in the index section.
    purpose character varying(20) DEFAULT 'signup' NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_platform_provider_type CHECK (((provider_type)::text = ANY ((ARRAY['google'::character varying, 'microsoft'::character varying])::text[]))),
    CONSTRAINT valid_platform_provider_purpose CHECK (((purpose)::text = ANY ((ARRAY['signup'::character varying, 'admin_login'::character varying])::text[])))
);
-- TABLE: refresh_tokens
CREATE TABLE IF NOT EXISTS public.refresh_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    token_hash character varying(255) NOT NULL,
    family_id uuid NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    last_used_at timestamp with time zone DEFAULT now(),
    is_revoked boolean DEFAULT false,
    created_from_ip inet,
    user_agent text,
    created_at timestamp with time zone DEFAULT now(),
    revoked_at timestamp with time zone
);


-- TABLE: remediation_plan_items
CREATE TABLE IF NOT EXISTS public.remediation_plan_items (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    plan_id uuid NOT NULL,
    finding_id uuid NOT NULL,
    ticket_id uuid,
    notes text,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    added_by uuid NOT NULL
);


-- TABLE: remediation_plans
CREATE TABLE IF NOT EXISTS public.remediation_plans (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    title character varying(255) NOT NULL,
    description text,
    plan_type character varying(30) DEFAULT 'remediation'::character varying NOT NULL,
    status character varying(20) DEFAULT 'draft'::character varying NOT NULL,
    priority character varying(20) DEFAULT 'medium'::character varying NOT NULL,
    owner_id uuid,
    target_date timestamp with time zone,
    framework_id uuid,
    completed_at timestamp with time zone,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT remediation_plans_plan_type_check CHECK (((plan_type)::text = ANY ((ARRAY['remediation'::character varying, 'framework'::character varying, 'pqc_migration'::character varying, 'custom'::character varying])::text[]))),
    CONSTRAINT remediation_plans_priority_check CHECK (((priority)::text = ANY ((ARRAY['low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying])::text[]))),
    CONSTRAINT remediation_plans_status_check CHECK (((status)::text = ANY ((ARRAY['draft'::character varying, 'active'::character varying, 'completed'::character varying, 'cancelled'::character varying])::text[])))
);


-- TABLE: resource_permissions
CREATE TABLE IF NOT EXISTS public.resource_permissions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    resource_type character varying(50) NOT NULL,
    resource_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    owner_id uuid NOT NULL,
    permissions jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: resource_tracking_config
CREATE TABLE IF NOT EXISTS public.resource_tracking_config (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    config_key character varying(100) NOT NULL,
    config_value jsonb NOT NULL,
    description text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


-- TABLE: rule_vulnerability_mappings
CREATE TABLE IF NOT EXISTS public.rule_vulnerability_mappings (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    rule_id uuid NOT NULL,
    finding_type character varying(100) NOT NULL,
    predicate jsonb DEFAULT '{}'::jsonb NOT NULL,
    weight integer DEFAULT 1 NOT NULL,
    framework_id character varying(100),
    framework_version character varying(20),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT rule_vulnerability_mappings_weight_check CHECK ((weight > 0))
);


-- TABLE: schedule_history
CREATE TABLE IF NOT EXISTS public.schedule_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    schedule_id uuid NOT NULL,
    job_id uuid NOT NULL,
    status character varying(50) NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    error_message text,
    assets_found integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


-- TABLE: security_events
CREATE TABLE IF NOT EXISTS public.security_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    event_id character varying(255) NOT NULL,
    correlation_id character varying(255),
    trace_id character varying(255),
    event_type character varying(100) NOT NULL,
    severity character varying(20) NOT NULL,
    category character varying(50) NOT NULL,
    title character varying(255) NOT NULL,
    description text,
    message text,
    service_name character varying(100) NOT NULL,
    source_ip inet,
    user_agent text,
    user_id uuid,
    user_type character varying(20),
    tenant_id uuid,
    request_id character varying(255),
    request_method character varying(10),
    request_path text,
    response_status integer,
    threat_score numeric(5,2) DEFAULT 0.0,
    is_anomaly boolean DEFAULT false,
    anomaly_type character varying(50),
    risk_level character varying(20) DEFAULT 'low'::character varying,
    status character varying(20) DEFAULT 'open'::character varying,
    assigned_to uuid,
    resolved_at timestamp with time zone,
    resolution_notes text,
    related_events uuid[],
    metadata jsonb DEFAULT '{}'::jsonb,
    tags text[],
    compliance_tags text[],
    requires_attention boolean DEFAULT false,
    "timestamp" timestamp with time zone NOT NULL,
    detected_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_category CHECK (((category)::text = ANY ((ARRAY['authentication'::character varying, 'authorization'::character varying, 'api'::character varying, 'data_access'::character varying, 'system'::character varying, 'network'::character varying, 'compliance'::character varying])::text[]))),
    CONSTRAINT valid_risk_level CHECK (((risk_level)::text = ANY ((ARRAY['low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying])::text[]))),
    CONSTRAINT valid_severity CHECK (((severity)::text = ANY ((ARRAY['low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying])::text[]))),
    CONSTRAINT valid_status CHECK (((status)::text = ANY ((ARRAY['open'::character varying, 'investigating'::character varying, 'resolved'::character varying, 'false_positive'::character varying, 'acknowledged'::character varying])::text[]))),
    CONSTRAINT valid_threat_score CHECK (((threat_score >= 0.0) AND (threat_score <= 100.0)))
);


-- TABLE: security_incident_webhook_deliveries
CREATE TABLE IF NOT EXISTS public.security_incident_webhook_deliveries (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    webhook_id uuid NOT NULL,
    incident_id uuid NOT NULL,
    status character varying(20) NOT NULL,
    status_code integer,
    response_body text,
    error_message text,
    attempts integer DEFAULT 1,
    delivered_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_status CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'success'::character varying, 'failed'::character varying])::text[]))),
    CONSTRAINT valid_status_code CHECK (((status_code IS NULL) OR ((status_code >= 100) AND (status_code < 600))))
);


-- TABLE: security_incident_webhooks
CREATE TABLE IF NOT EXISTS public.security_incident_webhooks (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    url text NOT NULL,
    secret text,
    events jsonb DEFAULT '[]'::jsonb NOT NULL,
    enabled boolean DEFAULT true,
    headers jsonb DEFAULT '{}'::jsonb,
    timeout_seconds integer DEFAULT 30,
    retry_attempts integer DEFAULT 3,
    retry_backoff_ms integer DEFAULT 1000,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_retry_attempts CHECK (((retry_attempts >= 0) AND (retry_attempts <= 10))),
    CONSTRAINT valid_retry_backoff CHECK (((retry_backoff_ms > 0) AND (retry_backoff_ms <= 60000))),
    CONSTRAINT valid_timeout CHECK (((timeout_seconds > 0) AND (timeout_seconds <= 300)))
);


-- TABLE: security_incidents
CREATE TABLE IF NOT EXISTS public.security_incidents (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    incident_id character varying(255) NOT NULL,
    title character varying(255) NOT NULL,
    description text,
    severity character varying(20) NOT NULL,
    category character varying(50) NOT NULL,
    status character varying(20) DEFAULT 'open'::character varying,
    priority character varying(20) DEFAULT 'medium'::character varying,
    detected_at timestamp with time zone NOT NULL,
    occurred_at timestamp with time zone,
    contained_at timestamp with time zone,
    resolved_at timestamp with time zone,
    closed_at timestamp with time zone,
    assigned_to uuid,
    reporter_id uuid,
    team character varying(100),
    related_events uuid[],
    related_incidents uuid[],
    affected_tenants uuid[],
    affected_users uuid[],
    impact_description text,
    response_plan text,
    response_actions text[],
    containment_actions text[],
    root_cause text,
    resolution_summary text,
    lessons_learned text,
    requires_notification boolean DEFAULT false,
    notified_authorities text[],
    notification_date timestamp with time zone,
    metadata jsonb DEFAULT '{}'::jsonb,
    tags text[],
    compliance_tags text[],
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    updated_by uuid,
    CONSTRAINT valid_category CHECK (((category)::text = ANY ((ARRAY['data_breach'::character varying, 'unauthorized_access'::character varying, 'ddos'::character varying, 'malware'::character varying, 'insider_threat'::character varying, 'phishing'::character varying, 'vulnerability'::character varying, 'compliance_violation'::character varying, 'other'::character varying])::text[]))),
    CONSTRAINT valid_priority CHECK (((priority)::text = ANY ((ARRAY['low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying])::text[]))),
    CONSTRAINT valid_severity CHECK (((severity)::text = ANY ((ARRAY['low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying])::text[]))),
    CONSTRAINT valid_status CHECK (((status)::text = ANY ((ARRAY['open'::character varying, 'investigating'::character varying, 'contained'::character varying, 'resolved'::character varying, 'closed'::character varying, 'archived'::character varying])::text[])))
);


-- TABLE: sensor_ca_certificates
CREATE TABLE IF NOT EXISTS public.sensor_ca_certificates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    ca_cert_pem text NOT NULL,
    ca_key_pem_encrypted text NOT NULL,
    serial_number bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone NOT NULL,
    is_active boolean DEFAULT true
);


-- TABLE: sensor_certificates
CREATE TABLE IF NOT EXISTS public.sensor_certificates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sensor_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    certificate_pem text NOT NULL,
    serial_number character varying(255) NOT NULL,
    issued_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    revocation_reason character varying(50),
    created_at timestamp with time zone DEFAULT now()
);


-- TABLE: sensor_commands
CREATE TABLE IF NOT EXISTS public.sensor_commands (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sensor_id uuid NOT NULL,
    command_type character varying(50) NOT NULL,
    payload jsonb NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone,
    delivered_at timestamp with time zone,
    acknowledged_at timestamp with time zone,
    completed_at timestamp with time zone,
    error_message text,
    -- The command round-trip (deliver/acknowledge) writes updated_at and the
    -- sensor's execution result into response_data.
    response_data jsonb,
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT sensor_commands_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'delivered'::character varying, 'acknowledged'::character varying, 'completed'::character varying, 'failed'::character varying])::text[])))
);


-- TABLE: sensor_discoveries_partitioned
CREATE TABLE IF NOT EXISTS public.sensor_discoveries_partitioned (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sensor_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    batch_id character varying(255) NOT NULL,
    protocol character varying(50) NOT NULL,
    dest_ip inet NOT NULL,
    port integer NOT NULL,
    confidence numeric(3,2) DEFAULT 0.0 NOT NULL,
    metadata jsonb,
    "timestamp" timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    processed_at timestamp with time zone,
    approval_status character varying(20) DEFAULT 'pending'::character varying,
    auto_approval_rule_id uuid,
    asset_id uuid,
    hostname character varying(255),
    source_ip inet,
    -- Batch claim marker. processNextBatch is triggered from BOTH the NATS
    -- subscription and the poll ticker (and every replica's ticker when scaled
    -- out), and discoveries are only stamped processed at the END of
    -- ProcessBatch — so selecting on `processed_at IS NULL` alone let two
    -- triggers import the same batch twice. NULL means unclaimed; a claim older
    -- than the worker's stale-claim timeout is ignored, so a worker that dies
    -- mid-batch cannot strand a batch.
    claimed_at timestamp with time zone
)
PARTITION BY HASH (tenant_id);


-- VIEW: sensor_discoveries
-- DROP first so re-applying the file is idempotent: this view is redefined in the
-- POST-MIGRATIONS block with one extra column (claimed_at) ALTER-added there;
-- without the DROP, the second apply tries to shrink the already-widened view
-- and fails with "cannot drop columns from view". Same pattern as network_assets
-- above.
DROP VIEW IF EXISTS public.sensor_discoveries;
CREATE OR REPLACE VIEW public.sensor_discoveries AS
 SELECT sensor_discoveries_partitioned.id,
    sensor_discoveries_partitioned.sensor_id,
    sensor_discoveries_partitioned.tenant_id,
    sensor_discoveries_partitioned.batch_id,
    sensor_discoveries_partitioned.protocol,
    sensor_discoveries_partitioned.dest_ip,
    sensor_discoveries_partitioned.port,
    sensor_discoveries_partitioned.confidence,
    sensor_discoveries_partitioned.metadata,
    sensor_discoveries_partitioned."timestamp",
    sensor_discoveries_partitioned.created_at,
    sensor_discoveries_partitioned.processed_at,
    sensor_discoveries_partitioned.approval_status,
    sensor_discoveries_partitioned.auto_approval_rule_id,
    sensor_discoveries_partitioned.asset_id,
    sensor_discoveries_partitioned.hostname,
    sensor_discoveries_partitioned.source_ip,
    sensor_discoveries_partitioned.claimed_at
   FROM public.sensor_discoveries_partitioned;


-- TABLE: sensor_discoveries_part_0
CREATE TABLE IF NOT EXISTS public.sensor_discoveries_part_0 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sensor_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    batch_id character varying(255) NOT NULL,
    protocol character varying(50) NOT NULL,
    dest_ip inet NOT NULL,
    port integer NOT NULL,
    confidence numeric(3,2) DEFAULT 0.0 NOT NULL,
    metadata jsonb,
    "timestamp" timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    processed_at timestamp with time zone,
    approval_status character varying(20) DEFAULT 'pending'::character varying,
    auto_approval_rule_id uuid,
    asset_id uuid,
    hostname character varying(255),
    source_ip inet,
    claimed_at timestamp with time zone
);


-- TABLE: sensor_discoveries_part_1
CREATE TABLE IF NOT EXISTS public.sensor_discoveries_part_1 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sensor_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    batch_id character varying(255) NOT NULL,
    protocol character varying(50) NOT NULL,
    dest_ip inet NOT NULL,
    port integer NOT NULL,
    confidence numeric(3,2) DEFAULT 0.0 NOT NULL,
    metadata jsonb,
    "timestamp" timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    processed_at timestamp with time zone,
    approval_status character varying(20) DEFAULT 'pending'::character varying,
    auto_approval_rule_id uuid,
    asset_id uuid,
    hostname character varying(255),
    source_ip inet,
    claimed_at timestamp with time zone
);


-- TABLE: sensor_discoveries_part_2
CREATE TABLE IF NOT EXISTS public.sensor_discoveries_part_2 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sensor_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    batch_id character varying(255) NOT NULL,
    protocol character varying(50) NOT NULL,
    dest_ip inet NOT NULL,
    port integer NOT NULL,
    confidence numeric(3,2) DEFAULT 0.0 NOT NULL,
    metadata jsonb,
    "timestamp" timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    processed_at timestamp with time zone,
    approval_status character varying(20) DEFAULT 'pending'::character varying,
    auto_approval_rule_id uuid,
    asset_id uuid,
    hostname character varying(255),
    source_ip inet,
    claimed_at timestamp with time zone
);


-- TABLE: sensor_discoveries_part_3
CREATE TABLE IF NOT EXISTS public.sensor_discoveries_part_3 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sensor_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    batch_id character varying(255) NOT NULL,
    protocol character varying(50) NOT NULL,
    dest_ip inet NOT NULL,
    port integer NOT NULL,
    confidence numeric(3,2) DEFAULT 0.0 NOT NULL,
    metadata jsonb,
    "timestamp" timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    processed_at timestamp with time zone,
    approval_status character varying(20) DEFAULT 'pending'::character varying,
    auto_approval_rule_id uuid,
    asset_id uuid,
    hostname character varying(255),
    source_ip inet,
    claimed_at timestamp with time zone
);


-- TABLE: sensor_discoveries_part_4
CREATE TABLE IF NOT EXISTS public.sensor_discoveries_part_4 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sensor_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    batch_id character varying(255) NOT NULL,
    protocol character varying(50) NOT NULL,
    dest_ip inet NOT NULL,
    port integer NOT NULL,
    confidence numeric(3,2) DEFAULT 0.0 NOT NULL,
    metadata jsonb,
    "timestamp" timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    processed_at timestamp with time zone,
    approval_status character varying(20) DEFAULT 'pending'::character varying,
    auto_approval_rule_id uuid,
    asset_id uuid,
    hostname character varying(255),
    source_ip inet,
    claimed_at timestamp with time zone
);


-- TABLE: sensor_discoveries_part_5
CREATE TABLE IF NOT EXISTS public.sensor_discoveries_part_5 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sensor_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    batch_id character varying(255) NOT NULL,
    protocol character varying(50) NOT NULL,
    dest_ip inet NOT NULL,
    port integer NOT NULL,
    confidence numeric(3,2) DEFAULT 0.0 NOT NULL,
    metadata jsonb,
    "timestamp" timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    processed_at timestamp with time zone,
    approval_status character varying(20) DEFAULT 'pending'::character varying,
    auto_approval_rule_id uuid,
    asset_id uuid,
    hostname character varying(255),
    source_ip inet,
    claimed_at timestamp with time zone
);


-- TABLE: sensor_discoveries_part_6
CREATE TABLE IF NOT EXISTS public.sensor_discoveries_part_6 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sensor_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    batch_id character varying(255) NOT NULL,
    protocol character varying(50) NOT NULL,
    dest_ip inet NOT NULL,
    port integer NOT NULL,
    confidence numeric(3,2) DEFAULT 0.0 NOT NULL,
    metadata jsonb,
    "timestamp" timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    processed_at timestamp with time zone,
    approval_status character varying(20) DEFAULT 'pending'::character varying,
    auto_approval_rule_id uuid,
    asset_id uuid,
    hostname character varying(255),
    source_ip inet,
    claimed_at timestamp with time zone
);


-- TABLE: sensor_discoveries_part_7
CREATE TABLE IF NOT EXISTS public.sensor_discoveries_part_7 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sensor_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    batch_id character varying(255) NOT NULL,
    protocol character varying(50) NOT NULL,
    dest_ip inet NOT NULL,
    port integer NOT NULL,
    confidence numeric(3,2) DEFAULT 0.0 NOT NULL,
    metadata jsonb,
    "timestamp" timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    processed_at timestamp with time zone,
    approval_status character varying(20) DEFAULT 'pending'::character varying,
    auto_approval_rule_id uuid,
    asset_id uuid,
    hostname character varying(255),
    source_ip inet,
    claimed_at timestamp with time zone
);


-- TABLE: sensor_health_metrics
CREATE TABLE IF NOT EXISTS public.sensor_health_metrics (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sensor_id uuid NOT NULL,
    uptime_seconds bigint NOT NULL,
    memory_usage_bytes bigint NOT NULL,
    cpu_usage_percent numeric(5,2) NOT NULL,
    packets_captured bigint DEFAULT 0 NOT NULL,
    discoveries_made bigint DEFAULT 0 NOT NULL,
    errors_count integer DEFAULT 0 NOT NULL,
    recorded_at timestamp with time zone DEFAULT now()
);


-- TABLE: sensors
CREATE TABLE IF NOT EXISTS public.sensors (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    platform character varying(50) NOT NULL,
    version character varying(50) NOT NULL,
    profile character varying(50) NOT NULL,
    sensor_type public.sensor_type DEFAULT 'network'::public.sensor_type NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    network_interfaces text[],
    -- Full host NIC inventory reported at registration + in heartbeats, so the UI
    -- can offer a real interface picker. Distinct from network_interfaces (the
    -- subset actually being monitored).
    available_interfaces text[] DEFAULT ARRAY[]::text[],
    tags text[],
    ip_address character varying(45),
    -- An air-gapped sensor is not expected to check in, heartbeat, or stream
    -- discoveries; the platform still shows it registered and imports its
    -- findings out-of-band.
    air_gapped boolean DEFAULT false NOT NULL,
    -- The sensor's actual data-send cadence (seconds), reported up at
    -- registration/heartbeat and operator-changeable via an update_config
    -- command. NULL when the sensor does not report one.
    reporting_interval integer,
    last_heartbeat timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    CONSTRAINT sensors_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'active'::character varying, 'inactive'::character varying, 'error'::character varying, 'offline'::character varying])::text[])))
);


-- TABLE: agent_addresses
-- Every IP an agent (sensor or discovery agent) holds, one row per bound
-- address, refreshed from the agent's own heartbeat.
--
-- A capture host is routinely multi-homed and may observe several segments at
-- once, so a single scalar address cannot describe it. sensors.ip_address /
-- device_agents.ip_address remain the PRIMARY address — the source address the
-- agent's kernel uses to reach the control plane — and this table holds the
-- full set, with the prefix, so "which segments does this fleet actually cover,
-- and what is uncovered?" is an ordinary query rather than an inference from
-- interface names.
--
-- One table serves both runtimes rather than two near-identical ones: the fleet
-- UI already merges them into a single row shape and the offline-alert job
-- already treats them as interchangeable subjects, so forking here is how the
-- two drift apart. The pair of nullable owner columns keeps real foreign keys
-- (a polymorphic owner_type/owner_id pair could not), and the CHECK makes
-- "exactly one owner" a database invariant instead of a convention.
-- The owner foreign keys are added in POST-MIGRATIONS, not inline: this file
-- follows pg_dump layout, so sensors/device_agents do not yet have their primary
-- keys at this point in the script and an inline REFERENCES fails with "no
-- unique constraint matching given keys".
CREATE TABLE IF NOT EXISTS public.agent_addresses (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    sensor_id uuid,
    device_agent_id uuid,
    interface_name character varying(255) NOT NULL,
    address inet NOT NULL,
    -- Prefix length of the address's network (e.g. 24 for 192.0.2.173/24).
    -- NULL when the agent reported a bare address without one.
    prefix_length smallint,
    -- True for the address the agent reaches the control plane from. At most one
    -- per agent, enforced by the partial unique indexes below.
    is_primary boolean DEFAULT false NOT NULL,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT agent_addresses_exactly_one_owner CHECK (
        (sensor_id IS NOT NULL AND device_agent_id IS NULL)
        OR (sensor_id IS NULL AND device_agent_id IS NOT NULL)
    )
);


-- TABLE: service_accounts
CREATE TABLE IF NOT EXISTS public.service_accounts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    service_name character varying(100) NOT NULL,
    token_hash text NOT NULL,
    -- Indexed hex-SHA-256 lookup value that narrows ValidateToken to a single
    -- candidate row in O(1) before bcrypt confirms it (SEC-3). bcrypt is one-way,
    -- so tokens issued before this column existed carry NULL and fall back to the
    -- legacy full scan restricted to `WHERE token_lookup IS NULL`.
    token_lookup text,
    description text,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    last_used_at timestamp with time zone
);


-- TABLE: service_health_events
CREATE TABLE IF NOT EXISTS public.service_health_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    service_name character varying(100) NOT NULL,
    event_type character varying(50) NOT NULL,
    status character varying(20) NOT NULL,
    message text,
    metadata jsonb DEFAULT '{}'::jsonb,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT valid_event_type CHECK (((event_type)::text = ANY ((ARRAY['heartbeat'::character varying, 'dependency_check'::character varying, 'incident'::character varying])::text[]))),
    CONSTRAINT valid_health_status CHECK (((status)::text = ANY ((ARRAY['healthy'::character varying, 'degraded'::character varying, 'down'::character varying, 'warning'::character varying])::text[])))
);


-- TABLE: service_identification_rules
CREATE TABLE IF NOT EXISTS public.service_identification_rules (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    port integer NOT NULL,
    protocol character varying(20) NOT NULL,
    service_name character varying(100) NOT NULL,
    service_category character varying(50),
    is_builtin boolean DEFAULT true,
    tenant_id uuid,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT service_identification_rules_port_check CHECK (((port >= 1) AND (port <= 65535)))
);


-- TABLE: ssh_keys
CREATE TABLE IF NOT EXISTS public.ssh_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    asset_id uuid,
    key_type character varying(50) NOT NULL,
    key_size integer,
    fingerprint_sha256 character varying(100) NOT NULL,
    public_key text,
    algorithm_id uuid,
    key_source character varying(50) NOT NULL,
    username character varying(255),
    hostname character varying(255),
    ip_address inet,
    file_path character varying(500),
    comment text,
    risk_score integer DEFAULT 50,
    is_weak boolean DEFAULT false,
    discovery_method public.discovery_method DEFAULT 'active'::public.discovery_method NOT NULL,
    first_discovered_at timestamp with time zone DEFAULT now(),
    last_seen_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    CONSTRAINT valid_ssh_key_risk CHECK (((risk_score >= 0) AND (risk_score <= 100))),
    CONSTRAINT valid_ssh_key_source CHECK (((key_source)::text = ANY ((ARRAY['host_key'::character varying, 'authorized_key'::character varying, 'user_key'::character varying])::text[])))
);


-- TABLE: sso_group_role_mappings
CREATE TABLE IF NOT EXISTS public.sso_group_role_mappings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sso_provider_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    external_group_name character varying(255) NOT NULL,
    role_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: sso_providers
CREATE TABLE IF NOT EXISTS public.sso_providers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    provider_type character varying(50) NOT NULL,
    provider_name character varying(100) NOT NULL,
    client_id character varying(255),
    client_secret_encrypted text,
    auth_url character varying(500),
    token_url character varying(500),
    userinfo_url character varying(500),
    scopes character varying(500) DEFAULT 'openid email profile'::character varying,
    saml_entity_id character varying(255),
    saml_sso_url character varying(500),
    saml_certificate text,
    saml_private_key_encrypted text,
    is_enabled boolean DEFAULT true,
    is_default boolean DEFAULT false,
    auto_provision_users boolean DEFAULT true,
    attribute_mapping jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    default_role_id uuid,
    allowed_domains text[] DEFAULT '{}'::text[],
    groups_claim_name character varying(100) DEFAULT 'groups'::character varying,
    CONSTRAINT valid_provider_type CHECK (((provider_type)::text = ANY ((ARRAY['google'::character varying, 'microsoft'::character varying, 'azure'::character varying, 'saml'::character varying, 'okta'::character varying])::text[])))
);


-- TABLE: invitations — auth-method-agnostic tenant member invitations.
-- An invitation is a tokenized intent to grant a member access with a role,
-- independent of how they will authenticate. No users row is created until the
-- invitee accepts (avoids the password-account-vs-SSO collision). The raw token
-- lives only in the emailed accept link; we store its SHA-256 hex. The public
-- accept handler reads by token_hash (the token is the authorization); tenant
-- isolation for admin operations is app-enforced via WHERE tenant_id, matching
-- every other handler. The RLS policy below mirrors peer tables for when RLS is
-- enforced (); a future enforced-RLS accept path needs a tenant-
-- resolution exemption (SECURITY DEFINER lookup) since the token implies tenant.
CREATE TABLE IF NOT EXISTS public.invitations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    email character varying(255) NOT NULL,
    role character varying(50) NOT NULL,
    invited_by uuid,
    token_hash character varying(64) NOT NULL,
    status character varying(20) NOT NULL DEFAULT 'pending',
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    accepted_at timestamp with time zone,
    accepted_user_id uuid,
    CONSTRAINT invitations_pkey PRIMARY KEY (id),
    CONSTRAINT invitations_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'accepted'::character varying, 'revoked'::character varying, 'expired'::character varying])::text[])))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_invitations_token_hash ON public.invitations (token_hash);
CREATE INDEX IF NOT EXISTS idx_invitations_tenant_status ON public.invitations (tenant_id, status);
-- At most one live pending invite per (tenant, email).
CREATE UNIQUE INDEX IF NOT EXISTS uq_invitations_pending_email ON public.invitations (tenant_id, lower((email)::text)) WHERE ((status)::text = 'pending'::text);
-- RLS for this table is declared with every other tenant-isolation policy, in
-- the canonical RLS HARDENING block in POST-MIGRATIONS. It used to be declared
-- here with USING only and no WITH CHECK; it could not be tightened in
-- place because the DO/EXCEPTION duplicate_object form cannot UPDATE an
-- existing policy — on an already-installed database it would hit the
-- duplicate and silently leave the old, write-open policy in force.


-- TABLE: subscription_tier_history
CREATE TABLE IF NOT EXISTS public.subscription_tier_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tier_id uuid NOT NULL,
    change_type character varying(50) NOT NULL,
    changes_json jsonb NOT NULL,
    changed_by uuid,
    changed_at timestamp with time zone DEFAULT now(),
    notes text,
    CONSTRAINT subscription_tier_history_change_type_check CHECK (((change_type)::text = ANY ((ARRAY['created'::character varying, 'modified'::character varying, 'deprecated'::character varying, 'reactivated'::character varying])::text[])))
);


-- TABLE: subscription_tiers
CREATE TABLE IF NOT EXISTS public.subscription_tiers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(50) NOT NULL,
    display_name character varying(100) NOT NULL,
    max_sensors integer,
    max_assets integer,
    max_users integer,
    retention_days integer,
    price_cents integer,
    billing_interval character varying(20),
    stripe_price_id character varying(255),
    annual_price_cents integer,
    stripe_price_id_annual character varying(255),
    features jsonb DEFAULT '{}'::jsonb,
    limits jsonb DEFAULT '{}'::jsonb,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    metadata jsonb DEFAULT '{}'::jsonb,
    addon_pricing jsonb DEFAULT '{}'::jsonb,
    is_custom boolean DEFAULT false,
    display_order integer DEFAULT 0,
    deprecated_at timestamp with time zone,
    -- Trial phase support. The Free tier doubles as the trial: trial_days_full =
    -- days of full access, trial_days_soft = days of soft-prompt access (banners)
    -- after that. Past both, the tenant is hard-locked until they upgrade. NULL on
    -- non-trial tiers; is_trial is the flag the admin UI reads to decide whether to
    -- render trial settings.
    is_trial boolean DEFAULT false NOT NULL,
    trial_days_full integer,
    trial_days_soft integer,
    -- How a plan is collected. 'stripe' = card-on-file (the admin UI
    -- auto-provisions the Stripe Product/Price on save); 'invoice' = record-only,
    -- entitlements enforced but no Stripe subscription created, for enterprise
    -- deals that pay by PO. Standard public tiers are always 'stripe'.
    billing_method character varying(20) DEFAULT 'stripe' NOT NULL,
    -- Scopes a custom plan to exactly one tenant. NULL = a standard/global plan
    -- offered on public signup; a tenant uuid = a private plan visible only to
    -- that tenant. Always paired with is_custom = true. The FK lives in the
    -- constraint section below: tenants' PRIMARY KEY is not in place yet here.
    owner_tenant_id uuid,
    CONSTRAINT subscription_tiers_billing_method_check
        CHECK (billing_method IN ('stripe', 'invoice'))
);


-- TABLE: support_ticket_messages
CREATE TABLE IF NOT EXISTS public.support_ticket_messages (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ticket_id uuid NOT NULL,
    author_id uuid,
    author_type character varying(20) DEFAULT 'admin'::character varying NOT NULL,
    content text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


-- TABLE: support_tickets
CREATE TABLE IF NOT EXISTS public.support_tickets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    subject character varying(500) NOT NULL,
    description text,
    status character varying(50) DEFAULT 'open'::character varying NOT NULL,
    priority character varying(20) DEFAULT 'medium'::character varying NOT NULL,
    category character varying(100),
    assigned_to uuid,
    created_by uuid,
    resolved_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


-- TABLE: sync_outbox
CREATE TABLE IF NOT EXISTS public.sync_outbox (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    entity_type text NOT NULL,
    entity_id uuid NOT NULL,
    event_type text NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: system_health_metrics
CREATE TABLE IF NOT EXISTS public.system_health_metrics (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    service_name character varying(100) NOT NULL,
    health_status character varying(20) NOT NULL,
    response_time_ms integer,
    error_count integer DEFAULT 0,
    memory_usage_mb integer,
    cpu_usage_percent numeric(5,2),
    disk_usage_percent numeric(5,2),
    active_connections integer,
    metadata jsonb,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL
);


-- TABLE: tenant_admin_settings
CREATE TABLE IF NOT EXISTS public.tenant_admin_settings (
    tenant_id uuid NOT NULL,
    config jsonb DEFAULT '{}'::jsonb NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


-- TABLE: tenant_admin_settings_audit
CREATE TABLE IF NOT EXISTS public.tenant_admin_settings_audit (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    config_before jsonb,
    config_after jsonb NOT NULL,
    version_before integer NOT NULL,
    version_after integer NOT NULL,
    changed_by uuid,
    change_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


-- TABLE: tenant_cost_analysis
CREATE TABLE IF NOT EXISTS public.tenant_cost_analysis (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    period_start timestamp with time zone NOT NULL,
    period_end timestamp with time zone NOT NULL,
    total_cost_usd numeric(10,4) NOT NULL,
    resource_breakdown jsonb NOT NULL,
    optimization_suggestions jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


-- MATERIALIZED VIEW: tenant_cost_summary
CREATE MATERIALIZED VIEW IF NOT EXISTS public.tenant_cost_summary AS
 SELECT tenant_resource_usage.tenant_id,
    date_trunc('day'::text, tenant_resource_usage."timestamp") AS cost_date,
    sum(tenant_resource_usage.cost_usd) AS daily_cost,
    sum(tenant_resource_usage.api_calls) AS total_api_calls,
    sum(tenant_resource_usage.database_queries) AS total_database_queries,
    sum(tenant_resource_usage.storage_used_mb) AS total_storage_mb,
    sum(tenant_resource_usage.network_bytes) AS total_network_bytes,
    avg(tenant_resource_usage.cpu_usage_percent) AS avg_cpu_usage,
    avg(tenant_resource_usage.memory_usage_mb) AS avg_memory_usage,
    count(*) AS metric_count
   FROM public.tenant_resource_usage
  WHERE (tenant_resource_usage."timestamp" >= (CURRENT_DATE - '90 days'::interval))
  GROUP BY tenant_resource_usage.tenant_id, (date_trunc('day'::text, tenant_resource_usage."timestamp"))
  WITH NO DATA;


-- TABLE: tenant_framework_controls
CREATE TABLE IF NOT EXISTS public.tenant_framework_controls (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    framework_id uuid NOT NULL,
    family_id uuid,
    control_id character varying(100) NOT NULL,
    title character varying(500) NOT NULL,
    description text,
    baseline_severity character varying(20) NOT NULL,
    crypto_relevant boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT tenant_framework_controls_baseline_severity_check CHECK (((baseline_severity)::text = ANY ((ARRAY['Low'::character varying, 'Med'::character varying, 'High'::character varying, 'Critical'::character varying])::text[])))
);


-- TABLE: tenant_framework_licenses
CREATE TABLE IF NOT EXISTS public.tenant_framework_licenses (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    platform_framework_id uuid NOT NULL,
    is_locked boolean DEFAULT false NOT NULL,
    locked_at timestamp with time zone,
    locked_by uuid,
    is_default boolean DEFAULT false NOT NULL,
    purchased_at timestamp with time zone DEFAULT now(),
    purchase_price_cents integer,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    subscription_status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    subscription_started_at timestamp with time zone DEFAULT now(),
    subscription_expires_at timestamp with time zone,
    provisioned_by character varying(20) DEFAULT 'admin'::character varying NOT NULL,
    CONSTRAINT tenant_framework_licenses_provisioned_by_check CHECK (((provisioned_by)::text = ANY ((ARRAY['admin'::character varying, 'self_service'::character varying, 'auto'::character varying])::text[]))),
    CONSTRAINT tenant_framework_licenses_subscription_status_check CHECK (((subscription_status)::text = ANY ((ARRAY['active'::character varying, 'expired'::character varying, 'cancelled'::character varying])::text[])))
);


-- TABLE: tenant_frameworks
CREATE TABLE IF NOT EXISTS public.tenant_frameworks (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    version character varying(20) NOT NULL,
    description text,
    source_framework_id uuid,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: tenant_geographic_data
CREATE TABLE IF NOT EXISTS public.tenant_geographic_data (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    country_code character varying(2),
    region character varying(100),
    city character varying(100),
    latitude numeric(10,8),
    longitude numeric(11,8),
    timezone character varying(50),
    is_primary boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


-- TABLE: tenant_health
CREATE TABLE IF NOT EXISTS public.tenant_health (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    overall_score numeric(5,2) DEFAULT 0 NOT NULL,
    health_status character varying(20) DEFAULT 'unknown'::character varying NOT NULL,
    last_calculated timestamp with time zone DEFAULT now() NOT NULL,
    score_breakdown jsonb DEFAULT '{}'::jsonb NOT NULL,
    recommendations jsonb DEFAULT '[]'::jsonb NOT NULL,
    trends jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


-- VIEW: tenant_health_summary_view
CREATE OR REPLACE VIEW public.tenant_health_summary_view AS
 SELECT th.tenant_id,
    th.overall_score,
    th.health_status,
    th.last_calculated,
    (th.trends ->> 'trend_direction'::text) AS trend_direction,
    COALESCE(alert_counts.critical_alerts, (0)::bigint) AS critical_alerts,
    COALESCE(alert_counts.high_alerts, (0)::bigint) AS high_alerts,
    COALESCE(alert_counts.total_alerts, (0)::bigint) AS total_alerts,
    COALESCE(jsonb_array_length(th.recommendations), 0) AS recommendations_count,
    th.created_at,
    th.updated_at
   FROM (public.tenant_health th
     LEFT JOIN ( SELECT health_alerts.tenant_id,
            count(*) FILTER (WHERE ((health_alerts.severity)::text = 'critical'::text)) AS critical_alerts,
            count(*) FILTER (WHERE ((health_alerts.severity)::text = 'high'::text)) AS high_alerts,
            count(*) AS total_alerts
           FROM public.health_alerts
          WHERE (health_alerts.is_active = true)
          GROUP BY health_alerts.tenant_id) alert_counts ON ((th.tenant_id = alert_counts.tenant_id)));


-- TABLE: tenant_measurement_overrides
CREATE TABLE IF NOT EXISTS public.tenant_measurement_overrides (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    control_measurement_id uuid NOT NULL,
    predicate_override jsonb NOT NULL,
    severity_override character varying(20),
    rationale text NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT tenant_measurement_overrides_severity_override_check CHECK (((severity_override)::text = ANY ((ARRAY['Low'::character varying, 'Med'::character varying, 'High'::character varying, 'Critical'::character varying])::text[])))
);


-- TABLE: tenant_notes
CREATE TABLE IF NOT EXISTS public.tenant_notes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    author_id uuid,
    content text NOT NULL,
    is_pinned boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


-- TABLE: tenant_notification_channels
CREATE TABLE IF NOT EXISTS public.tenant_notification_channels (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    channel_name character varying(100) NOT NULL,
    channel_type character varying(50) NOT NULL,
    config jsonb NOT NULL,
    enabled boolean DEFAULT true,
    test_status character varying(20),
    last_test_at timestamp with time zone,
    last_used_at timestamp with time zone,
    description text,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_tenant_channel_type CHECK (((channel_type)::text = ANY ((ARRAY['email'::character varying, 'slack'::character varying, 'webhook'::character varying, 'pagerduty'::character varying, 'sms'::character varying, 'in_app'::character varying])::text[])))
);


-- TABLE: tenant_notification_rules
CREATE TABLE IF NOT EXISTS public.tenant_notification_rules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    rule_name character varying(100) NOT NULL,
    alert_source character varying(50) NOT NULL,
    alert_type character varying(100),
    channel_ids uuid[] NOT NULL,
    severity_filter character varying(20)[],
    category_filter character varying(50)[],
    frequency character varying(20) DEFAULT 'immediate'::character varying,
    digest_window integer,
    enabled boolean DEFAULT true,
    priority integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_frequency CHECK (((frequency)::text = ANY ((ARRAY['immediate'::character varying, 'digest_hourly'::character varying, 'digest_daily'::character varying, 'digest_weekly'::character varying])::text[])))
);


-- TABLE: tenant_permissions
CREATE TABLE IF NOT EXISTS public.tenant_permissions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(100) NOT NULL,
    resource character varying(50) NOT NULL,
    action character varying(50) NOT NULL,
    scope character varying(50) DEFAULT 'tenant'::character varying,
    description text,
    created_at timestamp with time zone DEFAULT now()
);


-- TABLE: tenant_role_permissions
CREATE TABLE IF NOT EXISTS public.tenant_role_permissions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    role_id uuid NOT NULL,
    permission_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


-- TABLE: tenant_roles
CREATE TABLE IF NOT EXISTS public.tenant_roles (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    name character varying(50) NOT NULL,
    display_name character varying(100) NOT NULL,
    description text,
    is_system_role boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: tenant_usage
CREATE TABLE IF NOT EXISTS public.tenant_usage (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    sensors_count integer DEFAULT 0,
    assets_count integer DEFAULT 0,
    users_count integer DEFAULT 0,
    storage_bytes bigint DEFAULT 0,
    api_calls_current_month integer DEFAULT 0,
    reports_generated_month integer DEFAULT 0,
    integrations_active integer DEFAULT 0,
    billing_period_start date NOT NULL,
    billing_period_end date NOT NULL,
    last_calculated_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: tenant_usage_tracking
CREATE TABLE IF NOT EXISTS public.tenant_usage_tracking (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    metric_type character varying(50) NOT NULL,
    current_count integer DEFAULT 0 NOT NULL,
    last_updated timestamp with time zone DEFAULT now(),
    CONSTRAINT tenant_usage_tracking_metric_type_check CHECK (((metric_type)::text = ANY ((ARRAY['sensors'::character varying, 'assets'::character varying, 'users'::character varying, 'compliance_frameworks'::character varying, 'integrations'::character varying, 'reports_generated'::character varying])::text[])))
);


-- TABLE: threat_detection_rules
CREATE TABLE IF NOT EXISTS public.threat_detection_rules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rule_name character varying(100) NOT NULL,
    rule_type character varying(50) NOT NULL,
    description text,
    pattern jsonb NOT NULL,
    threshold numeric(10,2),
    time_window_seconds integer,
    severity character varying(20) NOT NULL,
    action character varying(50) DEFAULT 'alert'::character varying,
    notification_channels text[],
    applies_to_services text[],
    applies_to_tenants uuid[],
    applies_to_event_types text[],
    is_active boolean DEFAULT true,
    priority integer DEFAULT 0,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_action CHECK (((action)::text = ANY ((ARRAY['alert'::character varying, 'block'::character varying, 'rate_limit'::character varying, 'notify'::character varying, 'escalate'::character varying])::text[]))),
    CONSTRAINT valid_rule_type CHECK (((rule_type)::text = ANY ((ARRAY['pattern'::character varying, 'frequency'::character varying, 'threshold'::character varying, 'geographic'::character varying, 'behavioral'::character varying])::text[]))),
    CONSTRAINT valid_severity CHECK (((severity)::text = ANY ((ARRAY['low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying])::text[])))
);


-- TABLE: ticket_comments
CREATE TABLE IF NOT EXISTS public.ticket_comments (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    ticket_id uuid NOT NULL,
    -- NULL means "System": alert-event echoes onto linked tickets are
    -- system-authored.
    author_id uuid,
    content text NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


-- TABLE: tickets
CREATE TABLE IF NOT EXISTS public.tickets (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    category character varying(30) DEFAULT 'general'::character varying NOT NULL,
    title character varying(500) NOT NULL,
    description text,
    status character varying(20) DEFAULT 'open'::character varying NOT NULL,
    priority character varying(20) DEFAULT 'medium'::character varying NOT NULL,
    severity character varying(20),
    due_date timestamp with time zone,
    finding_id uuid,
    control_id uuid,
    asset_id uuid,
    certificate_id uuid,
    crypto_implementation_id uuid,
    external_ticket_system character varying(50),
    external_ticket_id character varying(255),
    external_ticket_url text,
    external_sync_status character varying(30) DEFAULT 'none'::character varying,
    source character varying(30) DEFAULT 'manual'::character varying NOT NULL,
    tags text[],
    assigned_to uuid,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    resolved_at timestamp with time zone,
    resolution_notes text,
    -- Links a ticket to the alert it was raised from (Remediation → Alerts).
    -- Deliberately unconstrained: alerts are created by the alerting pipeline and
    -- a ticket outlives the alert it came from.
    alert_id uuid,
    CONSTRAINT tickets_category_check CHECK (((category)::text = ANY ((ARRAY['compliance'::character varying, 'certificate'::character varying, 'remediation'::character varying, 'vulnerability'::character varying, 'operational'::character varying, 'general'::character varying])::text[]))),
    CONSTRAINT tickets_external_sync_status_check CHECK (((external_sync_status)::text = ANY ((ARRAY['none'::character varying, 'linked'::character varying, 'syncing'::character varying, 'error'::character varying])::text[]))),
    CONSTRAINT tickets_priority_check CHECK (((priority)::text = ANY ((ARRAY['low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying])::text[]))),
    CONSTRAINT tickets_severity_check CHECK (((severity)::text = ANY ((ARRAY['low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying])::text[]))),
    CONSTRAINT tickets_source_check CHECK (((source)::text = ANY ((ARRAY['manual'::character varying, 'auto_finding'::character varying, 'auto_expiry'::character varying, 'external_sync'::character varying, 'remediation_queue'::character varying])::text[]))),
    CONSTRAINT tickets_status_check CHECK (((status)::text = ANY ((ARRAY['open'::character varying, 'in_progress'::character varying, 'resolved'::character varying, 'closed'::character varying])::text[])))
);


-- TABLE: ui_themes
CREATE TABLE IF NOT EXISTS public.ui_themes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(100) NOT NULL,
    display_name character varying(200) NOT NULL,
    description text,
    theme_config jsonb NOT NULL,
    component_overrides jsonb DEFAULT '{}'::jsonb,
    is_public boolean DEFAULT true,
    is_active boolean DEFAULT true,
    pricing_tier character varying(50),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_pricing_tier CHECK (((pricing_tier)::text = ANY ((ARRAY['free'::character varying, 'professional'::character varying, 'enterprise'::character varying, 'all'::character varying])::text[])))
);


-- TABLE: user_auth_methods
CREATE TABLE IF NOT EXISTS public.user_auth_methods (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    auth_type character varying(50) NOT NULL,
    sso_provider_id uuid,
    external_user_id character varying(255),
    external_email character varying(255),
    is_primary boolean DEFAULT false,
    last_used_at timestamp with time zone,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_auth_type CHECK (((auth_type)::text = ANY ((ARRAY['password'::character varying, 'google'::character varying, 'microsoft'::character varying, 'azure'::character varying, 'saml'::character varying, 'okta'::character varying])::text[])))
);


-- TABLE: user_framework_preferences
CREATE TABLE IF NOT EXISTS public.user_framework_preferences (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    framework_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE: user_tenant_roles
CREATE TABLE IF NOT EXISTS public.user_tenant_roles (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    role_id uuid NOT NULL,
    assigned_by uuid,
    assigned_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone,
    is_active boolean DEFAULT true
);


-- TABLE: users
CREATE TABLE IF NOT EXISTS public.users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    email character varying(255) NOT NULL,
    email_verified boolean DEFAULT false,
    email_verification_token character varying(255),
    email_verification_expires timestamp with time zone,
    first_name character varying(100),
    last_name character varying(100),
    password_hash character varying(255),
    password_changed_at timestamp with time zone,
    password_reset_token character varying(255),
    password_reset_expires timestamp with time zone,
    password_history jsonb DEFAULT '[]'::jsonb,
    is_active boolean DEFAULT true,
    last_login_at timestamp with time zone,
    login_count integer DEFAULT 0,
    failed_login_attempts integer DEFAULT 0,
    locked_until timestamp with time zone,
    avatar_url character varying(500),
    timezone character varying(50) DEFAULT 'UTC'::character varying,
    preferences jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone,
    eula_accepted_at timestamp with time zone,
    eula_version character varying(50),
    onboarding_completed_at timestamp with time zone,
    -- Per-user dismissal of the Getting Started wizard, persisted
    -- server-side so it sticks across devices. NULL = not dismissed. Distinct
    -- from onboarding_completed_at (finished) and the tenant-level
    -- onboarding_required setting (org-wide disable).
    onboarding_dismissed_at timestamp with time zone,
    CONSTRAINT valid_email CHECK (((email)::text ~ '^[^@]+@[^@]+\.[^@]+$'::text))
);


-- VIEW: user_tenant_permissions
CREATE OR REPLACE VIEW public.user_tenant_permissions AS
 SELECT u.id AS user_id,
    u.email,
    u.first_name,
    u.last_name,
    t.id AS tenant_id,
    t.name AS tenant_name,
    tr.name AS role_name,
    tr.display_name AS role_display_name,
    tp.name AS permission_name,
    tp.resource,
    tp.action,
    tp.scope,
    utr.assigned_at,
    utr.expires_at,
    utr.is_active
   FROM (((((public.users u
     JOIN public.user_tenant_roles utr ON ((u.id = utr.user_id)))
     JOIN public.tenants t ON ((utr.tenant_id = t.id)))
     JOIN public.tenant_roles tr ON ((utr.role_id = tr.id)))
     JOIN public.tenant_role_permissions trp ON ((tr.id = trp.role_id)))
     JOIN public.tenant_permissions tp ON ((trp.permission_id = tp.id)))
  WHERE ((u.deleted_at IS NULL) AND (utr.is_active = true) AND ((utr.expires_at IS NULL) OR (utr.expires_at > now())));


-- TABLE: user_workflow_progress
CREATE TABLE IF NOT EXISTS public.user_workflow_progress (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    workflow_configuration_id uuid NOT NULL,
    current_step integer DEFAULT 0,
    completed_steps jsonb DEFAULT '[]'::jsonb,
    skipped_steps jsonb DEFAULT '[]'::jsonb,
    step_data jsonb DEFAULT '{}'::jsonb,
    status character varying(50) DEFAULT 'in_progress'::character varying,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_status CHECK (((status)::text = ANY ((ARRAY['not_started'::character varying, 'in_progress'::character varying, 'completed'::character varying, 'abandoned'::character varying])::text[])))
);


-- VIEW: v_ci_inventory
CREATE OR REPLACE VIEW public.v_ci_inventory AS
 SELECT network_assets_partitioned.id,
    network_assets_partitioned.tenant_id,
    'infrastructure_asset'::text AS ci_category,
        CASE network_assets_partitioned.asset_type
            WHEN 'server'::public.asset_type THEN 'cmdb_ci_server'::text
            WHEN 'endpoint'::public.asset_type THEN 'cmdb_ci_endpoint'::text
            WHEN 'service'::public.asset_type THEN 'cmdb_ci_service'::text
            WHEN 'appliance'::public.asset_type THEN 'cmdb_ci_appliance'::text
            ELSE 'cmdb_ci_hardware'::text
        END AS cmdb_ci_type,
    COALESCE(network_assets_partitioned.hostname, ((network_assets_partitioned.ip_address)::text)::character varying) AS display_name,
    network_assets_partitioned.description,
    network_assets_partitioned.risk_score,
    network_assets_partitioned.risk_level,
    network_assets_partitioned.first_discovered_at,
    network_assets_partitioned.last_seen_at AS last_verified_at,
    network_assets_partitioned.created_at,
    network_assets_partitioned.updated_at,
    network_assets_partitioned.deleted_at
   FROM public.network_assets_partitioned
UNION ALL
 SELECT certificates.id,
    certificates.tenant_id,
    'certificate'::text AS ci_category,
    'cmdb_ci_certificate'::text AS cmdb_ci_type,
    COALESCE(certificates.common_name, (certificates.subject_dn)::character varying) AS display_name,
    ('Certificate: '::text || (COALESCE(certificates.common_name, 'Unknown'::character varying))::text) AS description,
    NULL::integer AS risk_score,
    NULL::character varying AS risk_level,
    certificates.created_at AS first_discovered_at,
    certificates.updated_at AS last_verified_at,
    certificates.created_at,
    certificates.updated_at,
    NULL::timestamp with time zone AS deleted_at
   FROM public.certificates
UNION ALL
 SELECT keys.id,
    keys.tenant_id,
    'key'::text AS ci_category,
    'cmdb_ci_crypto_key'::text AS cmdb_ci_type,
    COALESCE((keys.key_type || ' key'::text), 'Unknown key'::text) AS display_name,
    ('Cryptographic key: '::text || COALESCE(keys.key_type, 'Unknown'::text)) AS description,
    NULL::integer AS risk_score,
    NULL::character varying AS risk_level,
    keys.created_at AS first_discovered_at,
    COALESCE(keys.rotated_at, keys.created_at) AS last_verified_at,
    keys.created_at,
    keys.created_at AS updated_at,
    NULL::timestamp with time zone AS deleted_at
   FROM public.keys
UNION ALL
 SELECT crypto_implementations_partitioned.id,
    crypto_implementations_partitioned.tenant_id,
    'crypto_configuration'::text AS ci_category,
    'cmdb_ci_crypto_config'::text AS cmdb_ci_type,
    COALESCE((((crypto_implementations_partitioned.protocol)::text || ' '::text) || (COALESCE(crypto_implementations_partitioned.protocol_version, ''::character varying))::text), 'Unknown protocol'::text) AS display_name,
    ((('Crypto config: '::text || COALESCE((crypto_implementations_partitioned.protocol)::text, ''::text)) || ' '::text) || (COALESCE(crypto_implementations_partitioned.cipher_suite, ''::character varying))::text) AS description,
    crypto_implementations_partitioned.risk_score,
        -- Canonical risk bands (services/inventory-service/internal/models/risk_bands.go):
        -- Critical >= 90, High >= 70, Medium >= 40, Low >= 1, Informational 0.
        -- Was >= 80 / 60 / 40 / 20, which called a 60 "High" (canonical: Medium)
        -- and a 15 "Informational" (canonical: Low). Score 0 means NOT ASSESSED,
        -- so only 0 may band as Informational.
        CASE
            WHEN (crypto_implementations_partitioned.risk_score >= 90) THEN 'Critical'::text
            WHEN (crypto_implementations_partitioned.risk_score >= 70) THEN 'High'::text
            WHEN (crypto_implementations_partitioned.risk_score >= 40) THEN 'Medium'::text
            WHEN (crypto_implementations_partitioned.risk_score >= 1) THEN 'Low'::text
            ELSE 'Informational'::text
        END AS risk_level,
    crypto_implementations_partitioned.first_discovered_at,
    crypto_implementations_partitioned.last_verified_at,
    crypto_implementations_partitioned.created_at,
    crypto_implementations_partitioned.updated_at,
    crypto_implementations_partitioned.deleted_at
   FROM public.crypto_implementations_partitioned;


-- VIEW: v_tenants
CREATE OR REPLACE VIEW public.v_tenants AS
 SELECT t.id,
    t.name,
    t.slug,
    t.subscription_tier_id,
    t.billing_email,
    t.payment_status,
    ((t.deleted_at IS NULL) AND ((COALESCE(t.payment_status, 'active'::character varying))::text = 'active'::text)) AS is_active,
    t.created_at,
    t.updated_at,
    t.deleted_at
   FROM public.tenants t;


-- TABLE: workflow_configurations
CREATE TABLE IF NOT EXISTS public.workflow_configurations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    workflow_type character varying(100) NOT NULL,
    workflow_name character varying(200) NOT NULL,
    steps jsonb NOT NULL,
    configuration jsonb DEFAULT '{}'::jsonb,
    is_active boolean DEFAULT true,
    is_default boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


-- TABLE ATTACH: activity_logs_y2026m04
DO $$ BEGIN
  IF to_regclass('audit.activity_logs') IS NOT NULL
     AND to_regclass('audit.activity_logs_y2026m04') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('audit.activity_logs')
         AND inhrelid = to_regclass('audit.activity_logs_y2026m04')
     ) THEN
    ALTER TABLE ONLY audit.activity_logs ATTACH PARTITION audit.activity_logs_y2026m04 FOR VALUES FROM ('2026-04-01 00:00:00+00') TO ('2026-05-01 00:00:00+00');
  END IF;
END $$;


-- TABLE ATTACH: activity_logs_y2026m05
DO $$ BEGIN
  IF to_regclass('audit.activity_logs') IS NOT NULL
     AND to_regclass('audit.activity_logs_y2026m05') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('audit.activity_logs')
         AND inhrelid = to_regclass('audit.activity_logs_y2026m05')
     ) THEN
    ALTER TABLE ONLY audit.activity_logs ATTACH PARTITION audit.activity_logs_y2026m05 FOR VALUES FROM ('2026-05-01 00:00:00+00') TO ('2026-06-01 00:00:00+00');
  END IF;
END $$;


-- TABLE ATTACH: activity_logs_y2026m06
DO $$ BEGIN
  IF to_regclass('audit.activity_logs') IS NOT NULL
     AND to_regclass('audit.activity_logs_y2026m06') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('audit.activity_logs')
         AND inhrelid = to_regclass('audit.activity_logs_y2026m06')
     ) THEN
    ALTER TABLE ONLY audit.activity_logs ATTACH PARTITION audit.activity_logs_y2026m06 FOR VALUES FROM ('2026-06-01 00:00:00+00') TO ('2026-07-01 00:00:00+00');
  END IF;
END $$;


-- TABLE ATTACH: activity_logs_y2026m07
DO $$ BEGIN
  IF to_regclass('audit.activity_logs') IS NOT NULL
     AND to_regclass('audit.activity_logs_y2026m07') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('audit.activity_logs')
         AND inhrelid = to_regclass('audit.activity_logs_y2026m07')
     ) THEN
    ALTER TABLE ONLY audit.activity_logs ATTACH PARTITION audit.activity_logs_y2026m07 FOR VALUES FROM ('2026-07-01 00:00:00+00') TO ('2026-08-01 00:00:00+00');
  END IF;
END $$;


-- TABLE ATTACH: activity_logs_y2026m08
DO $$ BEGIN
  IF to_regclass('audit.activity_logs') IS NOT NULL
     AND to_regclass('audit.activity_logs_y2026m08') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('audit.activity_logs')
         AND inhrelid = to_regclass('audit.activity_logs_y2026m08')
     ) THEN
    ALTER TABLE ONLY audit.activity_logs ATTACH PARTITION audit.activity_logs_y2026m08 FOR VALUES FROM ('2026-08-01 00:00:00+00') TO ('2026-09-01 00:00:00+00');
  END IF;
END $$;


-- TABLE ATTACH: crypto_implementations_part_0
DO $$ BEGIN
  IF to_regclass('public.crypto_implementations_partitioned') IS NOT NULL
     AND to_regclass('public.crypto_implementations_part_0') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.crypto_implementations_partitioned')
         AND inhrelid = to_regclass('public.crypto_implementations_part_0')
     ) THEN
    ALTER TABLE ONLY public.crypto_implementations_partitioned ATTACH PARTITION public.crypto_implementations_part_0 FOR VALUES WITH (modulus 8, remainder 0);
  END IF;
END $$;


-- TABLE ATTACH: crypto_implementations_part_1
DO $$ BEGIN
  IF to_regclass('public.crypto_implementations_partitioned') IS NOT NULL
     AND to_regclass('public.crypto_implementations_part_1') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.crypto_implementations_partitioned')
         AND inhrelid = to_regclass('public.crypto_implementations_part_1')
     ) THEN
    ALTER TABLE ONLY public.crypto_implementations_partitioned ATTACH PARTITION public.crypto_implementations_part_1 FOR VALUES WITH (modulus 8, remainder 1);
  END IF;
END $$;


-- TABLE ATTACH: crypto_implementations_part_2
DO $$ BEGIN
  IF to_regclass('public.crypto_implementations_partitioned') IS NOT NULL
     AND to_regclass('public.crypto_implementations_part_2') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.crypto_implementations_partitioned')
         AND inhrelid = to_regclass('public.crypto_implementations_part_2')
     ) THEN
    ALTER TABLE ONLY public.crypto_implementations_partitioned ATTACH PARTITION public.crypto_implementations_part_2 FOR VALUES WITH (modulus 8, remainder 2);
  END IF;
END $$;


-- TABLE ATTACH: crypto_implementations_part_3
DO $$ BEGIN
  IF to_regclass('public.crypto_implementations_partitioned') IS NOT NULL
     AND to_regclass('public.crypto_implementations_part_3') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.crypto_implementations_partitioned')
         AND inhrelid = to_regclass('public.crypto_implementations_part_3')
     ) THEN
    ALTER TABLE ONLY public.crypto_implementations_partitioned ATTACH PARTITION public.crypto_implementations_part_3 FOR VALUES WITH (modulus 8, remainder 3);
  END IF;
END $$;


-- TABLE ATTACH: crypto_implementations_part_4
DO $$ BEGIN
  IF to_regclass('public.crypto_implementations_partitioned') IS NOT NULL
     AND to_regclass('public.crypto_implementations_part_4') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.crypto_implementations_partitioned')
         AND inhrelid = to_regclass('public.crypto_implementations_part_4')
     ) THEN
    ALTER TABLE ONLY public.crypto_implementations_partitioned ATTACH PARTITION public.crypto_implementations_part_4 FOR VALUES WITH (modulus 8, remainder 4);
  END IF;
END $$;


-- TABLE ATTACH: crypto_implementations_part_5
DO $$ BEGIN
  IF to_regclass('public.crypto_implementations_partitioned') IS NOT NULL
     AND to_regclass('public.crypto_implementations_part_5') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.crypto_implementations_partitioned')
         AND inhrelid = to_regclass('public.crypto_implementations_part_5')
     ) THEN
    ALTER TABLE ONLY public.crypto_implementations_partitioned ATTACH PARTITION public.crypto_implementations_part_5 FOR VALUES WITH (modulus 8, remainder 5);
  END IF;
END $$;


-- TABLE ATTACH: crypto_implementations_part_6
DO $$ BEGIN
  IF to_regclass('public.crypto_implementations_partitioned') IS NOT NULL
     AND to_regclass('public.crypto_implementations_part_6') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.crypto_implementations_partitioned')
         AND inhrelid = to_regclass('public.crypto_implementations_part_6')
     ) THEN
    ALTER TABLE ONLY public.crypto_implementations_partitioned ATTACH PARTITION public.crypto_implementations_part_6 FOR VALUES WITH (modulus 8, remainder 6);
  END IF;
END $$;


-- TABLE ATTACH: crypto_implementations_part_7
DO $$ BEGIN
  IF to_regclass('public.crypto_implementations_partitioned') IS NOT NULL
     AND to_regclass('public.crypto_implementations_part_7') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.crypto_implementations_partitioned')
         AND inhrelid = to_regclass('public.crypto_implementations_part_7')
     ) THEN
    ALTER TABLE ONLY public.crypto_implementations_partitioned ATTACH PARTITION public.crypto_implementations_part_7 FOR VALUES WITH (modulus 8, remainder 7);
  END IF;
END $$;


-- TABLE ATTACH: network_assets_part_0
DO $$ BEGIN
  IF to_regclass('public.network_assets_partitioned') IS NOT NULL
     AND to_regclass('public.network_assets_part_0') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.network_assets_partitioned')
         AND inhrelid = to_regclass('public.network_assets_part_0')
     ) THEN
    ALTER TABLE ONLY public.network_assets_partitioned ATTACH PARTITION public.network_assets_part_0 FOR VALUES WITH (modulus 8, remainder 0);
  END IF;
END $$;


-- TABLE ATTACH: network_assets_part_1
DO $$ BEGIN
  IF to_regclass('public.network_assets_partitioned') IS NOT NULL
     AND to_regclass('public.network_assets_part_1') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.network_assets_partitioned')
         AND inhrelid = to_regclass('public.network_assets_part_1')
     ) THEN
    ALTER TABLE ONLY public.network_assets_partitioned ATTACH PARTITION public.network_assets_part_1 FOR VALUES WITH (modulus 8, remainder 1);
  END IF;
END $$;


-- TABLE ATTACH: network_assets_part_2
DO $$ BEGIN
  IF to_regclass('public.network_assets_partitioned') IS NOT NULL
     AND to_regclass('public.network_assets_part_2') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.network_assets_partitioned')
         AND inhrelid = to_regclass('public.network_assets_part_2')
     ) THEN
    ALTER TABLE ONLY public.network_assets_partitioned ATTACH PARTITION public.network_assets_part_2 FOR VALUES WITH (modulus 8, remainder 2);
  END IF;
END $$;


-- TABLE ATTACH: network_assets_part_3
DO $$ BEGIN
  IF to_regclass('public.network_assets_partitioned') IS NOT NULL
     AND to_regclass('public.network_assets_part_3') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.network_assets_partitioned')
         AND inhrelid = to_regclass('public.network_assets_part_3')
     ) THEN
    ALTER TABLE ONLY public.network_assets_partitioned ATTACH PARTITION public.network_assets_part_3 FOR VALUES WITH (modulus 8, remainder 3);
  END IF;
END $$;


-- TABLE ATTACH: network_assets_part_4
DO $$ BEGIN
  IF to_regclass('public.network_assets_partitioned') IS NOT NULL
     AND to_regclass('public.network_assets_part_4') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.network_assets_partitioned')
         AND inhrelid = to_regclass('public.network_assets_part_4')
     ) THEN
    ALTER TABLE ONLY public.network_assets_partitioned ATTACH PARTITION public.network_assets_part_4 FOR VALUES WITH (modulus 8, remainder 4);
  END IF;
END $$;


-- TABLE ATTACH: network_assets_part_5
DO $$ BEGIN
  IF to_regclass('public.network_assets_partitioned') IS NOT NULL
     AND to_regclass('public.network_assets_part_5') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.network_assets_partitioned')
         AND inhrelid = to_regclass('public.network_assets_part_5')
     ) THEN
    ALTER TABLE ONLY public.network_assets_partitioned ATTACH PARTITION public.network_assets_part_5 FOR VALUES WITH (modulus 8, remainder 5);
  END IF;
END $$;


-- TABLE ATTACH: network_assets_part_6
DO $$ BEGIN
  IF to_regclass('public.network_assets_partitioned') IS NOT NULL
     AND to_regclass('public.network_assets_part_6') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.network_assets_partitioned')
         AND inhrelid = to_regclass('public.network_assets_part_6')
     ) THEN
    ALTER TABLE ONLY public.network_assets_partitioned ATTACH PARTITION public.network_assets_part_6 FOR VALUES WITH (modulus 8, remainder 6);
  END IF;
END $$;


-- TABLE ATTACH: network_assets_part_7
DO $$ BEGIN
  IF to_regclass('public.network_assets_partitioned') IS NOT NULL
     AND to_regclass('public.network_assets_part_7') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.network_assets_partitioned')
         AND inhrelid = to_regclass('public.network_assets_part_7')
     ) THEN
    ALTER TABLE ONLY public.network_assets_partitioned ATTACH PARTITION public.network_assets_part_7 FOR VALUES WITH (modulus 8, remainder 7);
  END IF;
END $$;


-- TABLE ATTACH: sensor_discoveries_part_0
DO $$ BEGIN
  IF to_regclass('public.sensor_discoveries_partitioned') IS NOT NULL
     AND to_regclass('public.sensor_discoveries_part_0') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.sensor_discoveries_partitioned')
         AND inhrelid = to_regclass('public.sensor_discoveries_part_0')
     ) THEN
    ALTER TABLE ONLY public.sensor_discoveries_partitioned ATTACH PARTITION public.sensor_discoveries_part_0 FOR VALUES WITH (modulus 8, remainder 0);
  END IF;
END $$;


-- TABLE ATTACH: sensor_discoveries_part_1
DO $$ BEGIN
  IF to_regclass('public.sensor_discoveries_partitioned') IS NOT NULL
     AND to_regclass('public.sensor_discoveries_part_1') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.sensor_discoveries_partitioned')
         AND inhrelid = to_regclass('public.sensor_discoveries_part_1')
     ) THEN
    ALTER TABLE ONLY public.sensor_discoveries_partitioned ATTACH PARTITION public.sensor_discoveries_part_1 FOR VALUES WITH (modulus 8, remainder 1);
  END IF;
END $$;


-- TABLE ATTACH: sensor_discoveries_part_2
DO $$ BEGIN
  IF to_regclass('public.sensor_discoveries_partitioned') IS NOT NULL
     AND to_regclass('public.sensor_discoveries_part_2') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.sensor_discoveries_partitioned')
         AND inhrelid = to_regclass('public.sensor_discoveries_part_2')
     ) THEN
    ALTER TABLE ONLY public.sensor_discoveries_partitioned ATTACH PARTITION public.sensor_discoveries_part_2 FOR VALUES WITH (modulus 8, remainder 2);
  END IF;
END $$;


-- TABLE ATTACH: sensor_discoveries_part_3
DO $$ BEGIN
  IF to_regclass('public.sensor_discoveries_partitioned') IS NOT NULL
     AND to_regclass('public.sensor_discoveries_part_3') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.sensor_discoveries_partitioned')
         AND inhrelid = to_regclass('public.sensor_discoveries_part_3')
     ) THEN
    ALTER TABLE ONLY public.sensor_discoveries_partitioned ATTACH PARTITION public.sensor_discoveries_part_3 FOR VALUES WITH (modulus 8, remainder 3);
  END IF;
END $$;


-- TABLE ATTACH: sensor_discoveries_part_4
DO $$ BEGIN
  IF to_regclass('public.sensor_discoveries_partitioned') IS NOT NULL
     AND to_regclass('public.sensor_discoveries_part_4') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.sensor_discoveries_partitioned')
         AND inhrelid = to_regclass('public.sensor_discoveries_part_4')
     ) THEN
    ALTER TABLE ONLY public.sensor_discoveries_partitioned ATTACH PARTITION public.sensor_discoveries_part_4 FOR VALUES WITH (modulus 8, remainder 4);
  END IF;
END $$;


-- TABLE ATTACH: sensor_discoveries_part_5
DO $$ BEGIN
  IF to_regclass('public.sensor_discoveries_partitioned') IS NOT NULL
     AND to_regclass('public.sensor_discoveries_part_5') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.sensor_discoveries_partitioned')
         AND inhrelid = to_regclass('public.sensor_discoveries_part_5')
     ) THEN
    ALTER TABLE ONLY public.sensor_discoveries_partitioned ATTACH PARTITION public.sensor_discoveries_part_5 FOR VALUES WITH (modulus 8, remainder 5);
  END IF;
END $$;


-- TABLE ATTACH: sensor_discoveries_part_6
DO $$ BEGIN
  IF to_regclass('public.sensor_discoveries_partitioned') IS NOT NULL
     AND to_regclass('public.sensor_discoveries_part_6') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.sensor_discoveries_partitioned')
         AND inhrelid = to_regclass('public.sensor_discoveries_part_6')
     ) THEN
    ALTER TABLE ONLY public.sensor_discoveries_partitioned ATTACH PARTITION public.sensor_discoveries_part_6 FOR VALUES WITH (modulus 8, remainder 6);
  END IF;
END $$;


-- TABLE ATTACH: sensor_discoveries_part_7
DO $$ BEGIN
  IF to_regclass('public.sensor_discoveries_partitioned') IS NOT NULL
     AND to_regclass('public.sensor_discoveries_part_7') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits
       WHERE inhparent = to_regclass('public.sensor_discoveries_partitioned')
         AND inhrelid = to_regclass('public.sensor_discoveries_part_7')
     ) THEN
    ALTER TABLE ONLY public.sensor_discoveries_partitioned ATTACH PARTITION public.sensor_discoveries_part_7 FOR VALUES WITH (modulus 8, remainder 7);
  END IF;
END $$;


-- CONSTRAINT: activity_logs activity_logs_pkey
DO $$ BEGIN
  IF to_regclass('audit.activity_logs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'activity_logs_pkey' AND conrelid = to_regclass('audit.activity_logs')
     ) THEN
    ALTER TABLE ONLY audit.activity_logs
        ADD CONSTRAINT activity_logs_pkey PRIMARY KEY (id, occurred_at);
  END IF;
END $$;


-- CONSTRAINT: activity_logs_y2026m04 activity_logs_y2026m04_pkey
DO $$ BEGIN
  IF to_regclass('audit.activity_logs_y2026m04') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'activity_logs_y2026m04_pkey' AND conrelid = to_regclass('audit.activity_logs_y2026m04')
     ) THEN
    ALTER TABLE ONLY audit.activity_logs_y2026m04
        ADD CONSTRAINT activity_logs_y2026m04_pkey PRIMARY KEY (id, occurred_at);
  END IF;
END $$;


-- CONSTRAINT: activity_logs_y2026m05 activity_logs_y2026m05_pkey
DO $$ BEGIN
  IF to_regclass('audit.activity_logs_y2026m05') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'activity_logs_y2026m05_pkey' AND conrelid = to_regclass('audit.activity_logs_y2026m05')
     ) THEN
    ALTER TABLE ONLY audit.activity_logs_y2026m05
        ADD CONSTRAINT activity_logs_y2026m05_pkey PRIMARY KEY (id, occurred_at);
  END IF;
END $$;


-- CONSTRAINT: activity_logs_y2026m06 activity_logs_y2026m06_pkey
DO $$ BEGIN
  IF to_regclass('audit.activity_logs_y2026m06') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'activity_logs_y2026m06_pkey' AND conrelid = to_regclass('audit.activity_logs_y2026m06')
     ) THEN
    ALTER TABLE ONLY audit.activity_logs_y2026m06
        ADD CONSTRAINT activity_logs_y2026m06_pkey PRIMARY KEY (id, occurred_at);
  END IF;
END $$;


-- CONSTRAINT: activity_logs_y2026m07 activity_logs_y2026m07_pkey
DO $$ BEGIN
  IF to_regclass('audit.activity_logs_y2026m07') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'activity_logs_y2026m07_pkey' AND conrelid = to_regclass('audit.activity_logs_y2026m07')
     ) THEN
    ALTER TABLE ONLY audit.activity_logs_y2026m07
        ADD CONSTRAINT activity_logs_y2026m07_pkey PRIMARY KEY (id, occurred_at);
  END IF;
END $$;


-- CONSTRAINT: activity_logs_y2026m08 activity_logs_y2026m08_pkey
DO $$ BEGIN
  IF to_regclass('audit.activity_logs_y2026m08') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'activity_logs_y2026m08_pkey' AND conrelid = to_regclass('audit.activity_logs_y2026m08')
     ) THEN
    ALTER TABLE ONLY audit.activity_logs_y2026m08
        ADD CONSTRAINT activity_logs_y2026m08_pkey PRIMARY KEY (id, occurred_at);
  END IF;
END $$;


-- CONSTRAINT: alert_instances alert_instances_pkey
DO $$ BEGIN
  IF to_regclass('audit.alert_instances') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'alert_instances_pkey' AND conrelid = to_regclass('audit.alert_instances')
     ) THEN
    ALTER TABLE ONLY audit.alert_instances
        ADD CONSTRAINT alert_instances_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: alert_rules alert_rules_pkey
DO $$ BEGIN
  IF to_regclass('audit.alert_rules') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'alert_rules_pkey' AND conrelid = to_regclass('audit.alert_rules')
     ) THEN
    ALTER TABLE ONLY audit.alert_rules
        ADD CONSTRAINT alert_rules_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: audit_logs audit_logs_pkey
DO $$ BEGIN
  IF to_regclass('audit.audit_logs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'audit_logs_pkey' AND conrelid = to_regclass('audit.audit_logs')
     ) THEN
    ALTER TABLE ONLY audit.audit_logs
        ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: job_execution_logs job_execution_logs_pkey
DO $$ BEGIN
  IF to_regclass('audit.job_execution_logs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'job_execution_logs_pkey' AND conrelid = to_regclass('audit.job_execution_logs')
     ) THEN
    ALTER TABLE ONLY audit.job_execution_logs
        ADD CONSTRAINT job_execution_logs_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: retention_jobs retention_jobs_pkey
DO $$ BEGIN
  IF to_regclass('audit.retention_jobs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'retention_jobs_pkey' AND conrelid = to_regclass('audit.retention_jobs')
     ) THEN
    ALTER TABLE ONLY audit.retention_jobs
        ADD CONSTRAINT retention_jobs_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: retention_policies retention_policies_pkey
DO $$ BEGIN
  IF to_regclass('audit.retention_policies') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'retention_policies_pkey' AND conrelid = to_regclass('audit.retention_policies')
     ) THEN
    ALTER TABLE ONLY audit.retention_policies
        ADD CONSTRAINT retention_policies_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: retention_policies retention_policies_policy_name_key
DO $$ BEGIN
  IF to_regclass('audit.retention_policies') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'retention_policies_policy_name_key' AND conrelid = to_regclass('audit.retention_policies')
     ) THEN
    ALTER TABLE ONLY audit.retention_policies
        ADD CONSTRAINT retention_policies_policy_name_key UNIQUE (policy_name);
  END IF;
END $$;


-- CONSTRAINT: scheduled_compliance_reports scheduled_compliance_reports_pkey
DO $$ BEGIN
  IF to_regclass('audit.scheduled_compliance_reports') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'scheduled_compliance_reports_pkey' AND conrelid = to_regclass('audit.scheduled_compliance_reports')
     ) THEN
    ALTER TABLE ONLY audit.scheduled_compliance_reports
        ADD CONSTRAINT scheduled_compliance_reports_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: scheduled_report_executions scheduled_report_executions_pkey
DO $$ BEGIN
  IF to_regclass('audit.scheduled_report_executions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'scheduled_report_executions_pkey' AND conrelid = to_regclass('audit.scheduled_report_executions')
     ) THEN
    ALTER TABLE ONLY audit.scheduled_report_executions
        ADD CONSTRAINT scheduled_report_executions_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: siem_health_checks siem_health_checks_pkey
DO $$ BEGIN
  IF to_regclass('audit.siem_health_checks') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'siem_health_checks_pkey' AND conrelid = to_regclass('audit.siem_health_checks')
     ) THEN
    ALTER TABLE ONLY audit.siem_health_checks
        ADD CONSTRAINT siem_health_checks_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: siem_integrations siem_integrations_pkey
DO $$ BEGIN
  IF to_regclass('audit.siem_integrations') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'siem_integrations_pkey' AND conrelid = to_regclass('audit.siem_integrations')
     ) THEN
    ALTER TABLE ONLY audit.siem_integrations
        ADD CONSTRAINT siem_integrations_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: access_pattern_analysis access_pattern_analysis_pkey
DO $$ BEGIN
  IF to_regclass('public.access_pattern_analysis') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'access_pattern_analysis_pkey' AND conrelid = to_regclass('public.access_pattern_analysis')
     ) THEN
    ALTER TABLE ONLY public.access_pattern_analysis
        ADD CONSTRAINT access_pattern_analysis_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: agent_ca_certificates agent_ca_certificates_pkey
DO $$ BEGIN
  IF to_regclass('public.agent_ca_certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'agent_ca_certificates_pkey' AND conrelid = to_regclass('public.agent_ca_certificates')
     ) THEN
    ALTER TABLE ONLY public.agent_ca_certificates
        ADD CONSTRAINT agent_ca_certificates_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: agent_certificates agent_certificates_pkey
DO $$ BEGIN
  IF to_regclass('public.agent_certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'agent_certificates_pkey' AND conrelid = to_regclass('public.agent_certificates')
     ) THEN
    ALTER TABLE ONLY public.agent_certificates
        ADD CONSTRAINT agent_certificates_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: ai_analysis_results ai_analysis_results_pkey
DO $$ BEGIN
  IF to_regclass('public.ai_analysis_results') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'ai_analysis_results_pkey' AND conrelid = to_regclass('public.ai_analysis_results')
     ) THEN
    ALTER TABLE ONLY public.ai_analysis_results
        ADD CONSTRAINT ai_analysis_results_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: ai_models ai_models_pkey
DO $$ BEGIN
  IF to_regclass('public.ai_models') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'ai_models_pkey' AND conrelid = to_regclass('public.ai_models')
     ) THEN
    ALTER TABLE ONLY public.ai_models
        ADD CONSTRAINT ai_models_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: algorithms algorithms_code_key
DO $$ BEGIN
  IF to_regclass('public.algorithms') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'algorithms_code_key' AND conrelid = to_regclass('public.algorithms')
     ) THEN
    ALTER TABLE ONLY public.algorithms
        ADD CONSTRAINT algorithms_code_key UNIQUE (code);
  END IF;
END $$;


-- CONSTRAINT: algorithms algorithms_pkey
DO $$ BEGIN
  IF to_regclass('public.algorithms') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'algorithms_pkey' AND conrelid = to_regclass('public.algorithms')
     ) THEN
    ALTER TABLE ONLY public.algorithms
        ADD CONSTRAINT algorithms_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: api_format_preferences api_format_preferences_pkey
DO $$ BEGIN
  IF to_regclass('public.api_format_preferences') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'api_format_preferences_pkey' AND conrelid = to_regclass('public.api_format_preferences')
     ) THEN
    ALTER TABLE ONLY public.api_format_preferences
        ADD CONSTRAINT api_format_preferences_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: api_security_monitoring api_security_monitoring_pkey
DO $$ BEGIN
  IF to_regclass('public.api_security_monitoring') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'api_security_monitoring_pkey' AND conrelid = to_regclass('public.api_security_monitoring')
     ) THEN
    ALTER TABLE ONLY public.api_security_monitoring
        ADD CONSTRAINT api_security_monitoring_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: api_security_monitoring api_security_monitoring_request_id_key
DO $$ BEGIN
  IF to_regclass('public.api_security_monitoring') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'api_security_monitoring_request_id_key' AND conrelid = to_regclass('public.api_security_monitoring')
     ) THEN
    ALTER TABLE ONLY public.api_security_monitoring
        ADD CONSTRAINT api_security_monitoring_request_id_key UNIQUE (request_id);
  END IF;
END $$;


-- CONSTRAINT: api_usage_logs api_usage_logs_pkey
DO $$ BEGIN
  IF to_regclass('public.api_usage_logs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'api_usage_logs_pkey' AND conrelid = to_regclass('public.api_usage_logs')
     ) THEN
    ALTER TABLE ONLY public.api_usage_logs
        ADD CONSTRAINT api_usage_logs_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: asset_history asset_history_pkey
DO $$ BEGIN
  IF to_regclass('public.asset_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'asset_history_pkey' AND conrelid = to_regclass('public.asset_history')
     ) THEN
    ALTER TABLE ONLY public.asset_history
        ADD CONSTRAINT asset_history_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: asset_lifecycle_policies asset_lifecycle_policies_pkey
DO $$ BEGIN
  IF to_regclass('public.asset_lifecycle_policies') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'asset_lifecycle_policies_pkey' AND conrelid = to_regclass('public.asset_lifecycle_policies')
     ) THEN
    ALTER TABLE ONLY public.asset_lifecycle_policies
        ADD CONSTRAINT asset_lifecycle_policies_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: asset_lifecycle_policies asset_lifecycle_policies_tenant_id_key
DO $$ BEGIN
  IF to_regclass('public.asset_lifecycle_policies') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'asset_lifecycle_policies_tenant_id_key' AND conrelid = to_regclass('public.asset_lifecycle_policies')
     ) THEN
    ALTER TABLE ONLY public.asset_lifecycle_policies
        ADD CONSTRAINT asset_lifecycle_policies_tenant_id_key UNIQUE (tenant_id);
  END IF;
END $$;


-- CONSTRAINT: auth_audit_log auth_audit_log_pkey
DO $$ BEGIN
  IF to_regclass('public.auth_audit_log') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'auth_audit_log_pkey' AND conrelid = to_regclass('public.auth_audit_log')
     ) THEN
    ALTER TABLE ONLY public.auth_audit_log
        ADD CONSTRAINT auth_audit_log_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: aws_cost_data aws_cost_data_pkey
DO $$ BEGIN
  IF to_regclass('public.aws_cost_data') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'aws_cost_data_pkey' AND conrelid = to_regclass('public.aws_cost_data')
     ) THEN
    ALTER TABLE ONLY public.aws_cost_data
        ADD CONSTRAINT aws_cost_data_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: aws_cost_sync_jobs aws_cost_sync_jobs_pkey
DO $$ BEGIN
  IF to_regclass('public.aws_cost_sync_jobs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'aws_cost_sync_jobs_pkey' AND conrelid = to_regclass('public.aws_cost_sync_jobs')
     ) THEN
    ALTER TABLE ONLY public.aws_cost_sync_jobs
        ADD CONSTRAINT aws_cost_sync_jobs_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: billing_coupon_redemptions billing_coupon_redemptions_coupon_id_tenant_id_key
DO $$ BEGIN
  IF to_regclass('public.billing_coupon_redemptions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_coupon_redemptions_coupon_id_tenant_id_key' AND conrelid = to_regclass('public.billing_coupon_redemptions')
     ) THEN
    ALTER TABLE ONLY public.billing_coupon_redemptions
        ADD CONSTRAINT billing_coupon_redemptions_coupon_id_tenant_id_key UNIQUE (coupon_id, tenant_id);
  END IF;
END $$;


-- CONSTRAINT: billing_coupon_redemptions billing_coupon_redemptions_pkey
DO $$ BEGIN
  IF to_regclass('public.billing_coupon_redemptions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_coupon_redemptions_pkey' AND conrelid = to_regclass('public.billing_coupon_redemptions')
     ) THEN
    ALTER TABLE ONLY public.billing_coupon_redemptions
        ADD CONSTRAINT billing_coupon_redemptions_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: billing_coupons billing_coupons_code_key
DO $$ BEGIN
  IF to_regclass('public.billing_coupons') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_coupons_code_key' AND conrelid = to_regclass('public.billing_coupons')
     ) THEN
    ALTER TABLE ONLY public.billing_coupons
        ADD CONSTRAINT billing_coupons_code_key UNIQUE (code);
  END IF;
END $$;


-- CONSTRAINT: billing_coupons billing_coupons_pkey
DO $$ BEGIN
  IF to_regclass('public.billing_coupons') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_coupons_pkey' AND conrelid = to_regclass('public.billing_coupons')
     ) THEN
    ALTER TABLE ONLY public.billing_coupons
        ADD CONSTRAINT billing_coupons_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: billing_customers billing_customers_pkey
DO $$ BEGIN
  IF to_regclass('public.billing_customers') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_customers_pkey' AND conrelid = to_regclass('public.billing_customers')
     ) THEN
    ALTER TABLE ONLY public.billing_customers
        ADD CONSTRAINT billing_customers_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: billing_customers billing_customers_tenant_id_provider_id_key
DO $$ BEGIN
  IF to_regclass('public.billing_customers') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_customers_tenant_id_provider_id_key' AND conrelid = to_regclass('public.billing_customers')
     ) THEN
    ALTER TABLE ONLY public.billing_customers
        ADD CONSTRAINT billing_customers_tenant_id_provider_id_key UNIQUE (tenant_id, provider_id);
  END IF;
END $$;


-- CONSTRAINT: billing_dunning_attempts billing_dunning_attempts_pkey
DO $$ BEGIN
  IF to_regclass('public.billing_dunning_attempts') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_dunning_attempts_pkey' AND conrelid = to_regclass('public.billing_dunning_attempts')
     ) THEN
    ALTER TABLE ONLY public.billing_dunning_attempts
        ADD CONSTRAINT billing_dunning_attempts_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: billing_events billing_events_pkey
DO $$ BEGIN
  IF to_regclass('public.billing_events') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_events_pkey' AND conrelid = to_regclass('public.billing_events')
     ) THEN
    ALTER TABLE ONLY public.billing_events
        ADD CONSTRAINT billing_events_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: billing_events billing_events_provider_id_external_event_id_key
DO $$ BEGIN
  IF to_regclass('public.billing_events') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_events_provider_id_external_event_id_key' AND conrelid = to_regclass('public.billing_events')
     ) THEN
    ALTER TABLE ONLY public.billing_events
        ADD CONSTRAINT billing_events_provider_id_external_event_id_key UNIQUE (provider_id, external_event_id);
  END IF;
END $$;


-- CONSTRAINT: billing_invoice_line_items billing_invoice_line_items_pkey
DO $$ BEGIN
  IF to_regclass('public.billing_invoice_line_items') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_invoice_line_items_pkey' AND conrelid = to_regclass('public.billing_invoice_line_items')
     ) THEN
    ALTER TABLE ONLY public.billing_invoice_line_items
        ADD CONSTRAINT billing_invoice_line_items_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: billing_invoices billing_invoices_pkey
DO $$ BEGIN
  IF to_regclass('public.billing_invoices') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_invoices_pkey' AND conrelid = to_regclass('public.billing_invoices')
     ) THEN
    ALTER TABLE ONLY public.billing_invoices
        ADD CONSTRAINT billing_invoices_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: billing_providers billing_providers_key_key
DO $$ BEGIN
  IF to_regclass('public.billing_providers') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_providers_key_key' AND conrelid = to_regclass('public.billing_providers')
     ) THEN
    ALTER TABLE ONLY public.billing_providers
        ADD CONSTRAINT billing_providers_key_key UNIQUE (key);
  END IF;
END $$;


-- CONSTRAINT: billing_providers billing_providers_pkey
DO $$ BEGIN
  IF to_regclass('public.billing_providers') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_providers_pkey' AND conrelid = to_regclass('public.billing_providers')
     ) THEN
    ALTER TABLE ONLY public.billing_providers
        ADD CONSTRAINT billing_providers_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: billing_subscriptions billing_subscriptions_pkey
DO $$ BEGIN
  IF to_regclass('public.billing_subscriptions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_subscriptions_pkey' AND conrelid = to_regclass('public.billing_subscriptions')
     ) THEN
    ALTER TABLE ONLY public.billing_subscriptions
        ADD CONSTRAINT billing_subscriptions_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: billing_trial_tracking billing_trial_tracking_pkey
DO $$ BEGIN
  IF to_regclass('public.billing_trial_tracking') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_trial_tracking_pkey' AND conrelid = to_regclass('public.billing_trial_tracking')
     ) THEN
    ALTER TABLE ONLY public.billing_trial_tracking
        ADD CONSTRAINT billing_trial_tracking_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: billing_trial_tracking billing_trial_tracking_tenant_id_key
DO $$ BEGIN
  IF to_regclass('public.billing_trial_tracking') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_trial_tracking_tenant_id_key' AND conrelid = to_regclass('public.billing_trial_tracking')
     ) THEN
    ALTER TABLE ONLY public.billing_trial_tracking
        ADD CONSTRAINT billing_trial_tracking_tenant_id_key UNIQUE (tenant_id);
  END IF;
END $$;


-- CONSTRAINT: certificate_extensions certificate_extensions_pkey
DO $$ BEGIN
  IF to_regclass('public.certificate_extensions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'certificate_extensions_pkey' AND conrelid = to_regclass('public.certificate_extensions')
     ) THEN
    ALTER TABLE ONLY public.certificate_extensions
        ADD CONSTRAINT certificate_extensions_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: certificate_history certificate_history_pkey
DO $$ BEGIN
  IF to_regclass('public.certificate_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'certificate_history_pkey' AND conrelid = to_regclass('public.certificate_history')
     ) THEN
    ALTER TABLE ONLY public.certificate_history
        ADD CONSTRAINT certificate_history_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: certificates certificates_pkey
DO $$ BEGIN
  IF to_regclass('public.certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'certificates_pkey' AND conrelid = to_regclass('public.certificates')
     ) THEN
    ALTER TABLE ONLY public.certificates
        ADD CONSTRAINT certificates_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: ci_relationships ci_relationships_pkey
DO $$ BEGIN
  IF to_regclass('public.ci_relationships') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'ci_relationships_pkey' AND conrelid = to_regclass('public.ci_relationships')
     ) THEN
    ALTER TABLE ONLY public.ci_relationships
        ADD CONSTRAINT ci_relationships_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: cmdb_entity_mappings cmdb_entity_mappings_pkey
DO $$ BEGIN
  IF to_regclass('public.cmdb_entity_mappings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'cmdb_entity_mappings_pkey' AND conrelid = to_regclass('public.cmdb_entity_mappings')
     ) THEN
    ALTER TABLE ONLY public.cmdb_entity_mappings
        ADD CONSTRAINT cmdb_entity_mappings_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: cmdb_sync_jobs cmdb_sync_jobs_pkey
DO $$ BEGIN
  IF to_regclass('public.cmdb_sync_jobs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'cmdb_sync_jobs_pkey' AND conrelid = to_regclass('public.cmdb_sync_jobs')
     ) THEN
    ALTER TABLE ONLY public.cmdb_sync_jobs
        ADD CONSTRAINT cmdb_sync_jobs_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: cmdb_sync_profiles cmdb_sync_profiles_pkey
DO $$ BEGIN
  IF to_regclass('public.cmdb_sync_profiles') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'cmdb_sync_profiles_pkey' AND conrelid = to_regclass('public.cmdb_sync_profiles')
     ) THEN
    ALTER TABLE ONLY public.cmdb_sync_profiles
        ADD CONSTRAINT cmdb_sync_profiles_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: compliance_checks compliance_checks_pkey
DO $$ BEGIN
  IF to_regclass('public.compliance_checks') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_checks_pkey' AND conrelid = to_regclass('public.compliance_checks')
     ) THEN
    ALTER TABLE ONLY public.compliance_checks
        ADD CONSTRAINT compliance_checks_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: compliance_finding_history compliance_finding_history_pkey
DO $$ BEGIN
  IF to_regclass('public.compliance_finding_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_finding_history_pkey' AND conrelid = to_regclass('public.compliance_finding_history')
     ) THEN
    ALTER TABLE ONLY public.compliance_finding_history
        ADD CONSTRAINT compliance_finding_history_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: compliance_findings compliance_findings_pkey
DO $$ BEGIN
  IF to_regclass('public.compliance_findings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_findings_pkey' AND conrelid = to_regclass('public.compliance_findings')
     ) THEN
    ALTER TABLE ONLY public.compliance_findings
        ADD CONSTRAINT compliance_findings_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: compliance_framework_status compliance_framework_status_pkey
DO $$ BEGIN
  IF to_regclass('public.compliance_framework_status') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_framework_status_pkey' AND conrelid = to_regclass('public.compliance_framework_status')
     ) THEN
    ALTER TABLE ONLY public.compliance_framework_status
        ADD CONSTRAINT compliance_framework_status_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: compliance_overrides compliance_overrides_pkey
DO $$ BEGIN
  IF to_regclass('public.compliance_overrides') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_overrides_pkey' AND conrelid = to_regclass('public.compliance_overrides')
     ) THEN
    ALTER TABLE ONLY public.compliance_overrides
        ADD CONSTRAINT compliance_overrides_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: compliance_reports compliance_reports_pkey
DO $$ BEGIN
  IF to_regclass('public.compliance_reports') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_reports_pkey' AND conrelid = to_regclass('public.compliance_reports')
     ) THEN
    ALTER TABLE ONLY public.compliance_reports
        ADD CONSTRAINT compliance_reports_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: compliance_requirements compliance_requirements_pkey
DO $$ BEGIN
  IF to_regclass('public.compliance_requirements') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_requirements_pkey' AND conrelid = to_regclass('public.compliance_requirements')
     ) THEN
    ALTER TABLE ONLY public.compliance_requirements
        ADD CONSTRAINT compliance_requirements_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: compliance_rules compliance_rules_pkey
DO $$ BEGIN
  IF to_regclass('public.compliance_rules') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_rules_pkey' AND conrelid = to_regclass('public.compliance_rules')
     ) THEN
    ALTER TABLE ONLY public.compliance_rules
        ADD CONSTRAINT compliance_rules_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: compliance_scenarios compliance_scenarios_pkey
DO $$ BEGIN
  IF to_regclass('public.compliance_scenarios') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_scenarios_pkey' AND conrelid = to_regclass('public.compliance_scenarios')
     ) THEN
    ALTER TABLE ONLY public.compliance_scenarios
        ADD CONSTRAINT compliance_scenarios_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: control_measurements control_measurements_pkey
DO $$ BEGIN
  IF to_regclass('public.control_measurements') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'control_measurements_pkey' AND conrelid = to_regclass('public.control_measurements')
     ) THEN
    ALTER TABLE ONLY public.control_measurements
        ADD CONSTRAINT control_measurements_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: crypto_applications crypto_applications_pkey
DO $$ BEGIN
  IF to_regclass('public.crypto_applications') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'crypto_applications_pkey' AND conrelid = to_regclass('public.crypto_applications')
     ) THEN
    ALTER TABLE ONLY public.crypto_applications
        ADD CONSTRAINT crypto_applications_pkey PRIMARY KEY (id);
  END IF;
END $$;




-- CONSTRAINT: crypto_implementation_algorithms crypto_implementation_algorithms_pkey
DO $$ BEGIN
  IF to_regclass('public.crypto_implementation_algorithms') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'crypto_implementation_algorithms_pkey' AND conrelid = to_regclass('public.crypto_implementation_algorithms')
     ) THEN
    ALTER TABLE ONLY public.crypto_implementation_algorithms
        ADD CONSTRAINT crypto_implementation_algorithms_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: crypto_implementation_certificates crypto_implementation_certificates_pkey
DO $$ BEGIN
  IF to_regclass('public.crypto_implementation_certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'crypto_implementation_certificates_pkey' AND conrelid = to_regclass('public.crypto_implementation_certificates')
     ) THEN
    ALTER TABLE ONLY public.crypto_implementation_certificates
        ADD CONSTRAINT crypto_implementation_certificates_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: crypto_libraries crypto_libraries_pkey
DO $$ BEGIN
  IF to_regclass('public.crypto_libraries') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'crypto_libraries_pkey' AND conrelid = to_regclass('public.crypto_libraries')
     ) THEN
    ALTER TABLE ONLY public.crypto_libraries
        ADD CONSTRAINT crypto_libraries_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: dashboard_cache dashboard_cache_cache_key_key
DO $$ BEGIN
  IF to_regclass('public.dashboard_cache') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'dashboard_cache_cache_key_key' AND conrelid = to_regclass('public.dashboard_cache')
     ) THEN
    ALTER TABLE ONLY public.dashboard_cache
        ADD CONSTRAINT dashboard_cache_cache_key_key UNIQUE (cache_key);
  END IF;
END $$;


-- CONSTRAINT: dashboard_cache dashboard_cache_pkey
DO $$ BEGIN
  IF to_regclass('public.dashboard_cache') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'dashboard_cache_pkey' AND conrelid = to_regclass('public.dashboard_cache')
     ) THEN
    ALTER TABLE ONLY public.dashboard_cache
        ADD CONSTRAINT dashboard_cache_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: dashboard_metrics dashboard_metrics_pkey
DO $$ BEGIN
  IF to_regclass('public.dashboard_metrics') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'dashboard_metrics_pkey' AND conrelid = to_regclass('public.dashboard_metrics')
     ) THEN
    ALTER TABLE ONLY public.dashboard_metrics
        ADD CONSTRAINT dashboard_metrics_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: database_encryption_states database_encryption_states_pkey
DO $$ BEGIN
  IF to_regclass('public.database_encryption_states') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'database_encryption_states_pkey' AND conrelid = to_regclass('public.database_encryption_states')
     ) THEN
    ALTER TABLE ONLY public.database_encryption_states
        ADD CONSTRAINT database_encryption_states_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: device_agents device_agents_pkey
DO $$ BEGIN
  IF to_regclass('public.device_agents') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'device_agents_pkey' AND conrelid = to_regclass('public.device_agents')
     ) THEN
    ALTER TABLE ONLY public.device_agents
        ADD CONSTRAINT device_agents_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: device_jobs device_jobs_pkey
DO $$ BEGIN
  IF to_regclass('public.device_jobs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'device_jobs_pkey' AND conrelid = to_regclass('public.device_jobs')
     ) THEN
    ALTER TABLE ONLY public.device_jobs
        ADD CONSTRAINT device_jobs_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: devices devices_pkey
DO $$ BEGIN
  IF to_regclass('public.devices') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'devices_pkey' AND conrelid = to_regclass('public.devices')
     ) THEN
    ALTER TABLE ONLY public.devices
        ADD CONSTRAINT devices_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: discovery_alert_configs discovery_alert_configs_pkey
DO $$ BEGIN
  IF to_regclass('public.discovery_alert_configs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_alert_configs_pkey' AND conrelid = to_regclass('public.discovery_alert_configs')
     ) THEN
    ALTER TABLE ONLY public.discovery_alert_configs
        ADD CONSTRAINT discovery_alert_configs_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: discovery_alert_configs discovery_alert_configs_tenant_id_alert_type_key
DO $$ BEGIN
  IF to_regclass('public.discovery_alert_configs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_alert_configs_tenant_id_alert_type_key' AND conrelid = to_regclass('public.discovery_alert_configs')
     ) THEN
    ALTER TABLE ONLY public.discovery_alert_configs
        ADD CONSTRAINT discovery_alert_configs_tenant_id_alert_type_key UNIQUE (tenant_id, alert_type);
  END IF;
END $$;


-- CONSTRAINT: discovery_alert_history discovery_alert_history_pkey
DO $$ BEGIN
  IF to_regclass('public.discovery_alert_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_alert_history_pkey' AND conrelid = to_regclass('public.discovery_alert_history')
     ) THEN
    ALTER TABLE ONLY public.discovery_alert_history
        ADD CONSTRAINT discovery_alert_history_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: discovery_approval_queue discovery_approval_queue_pkey
DO $$ BEGIN
  IF to_regclass('public.discovery_approval_queue') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_approval_queue_pkey' AND conrelid = to_regclass('public.discovery_approval_queue')
     ) THEN
    ALTER TABLE ONLY public.discovery_approval_queue
        ADD CONSTRAINT discovery_approval_queue_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: discovery_auto_approval_rules discovery_auto_approval_rules_pkey
DO $$ BEGIN
  IF to_regclass('public.discovery_auto_approval_rules') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_auto_approval_rules_pkey' AND conrelid = to_regclass('public.discovery_auto_approval_rules')
     ) THEN
    ALTER TABLE ONLY public.discovery_auto_approval_rules
        ADD CONSTRAINT discovery_auto_approval_rules_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: discovery_findings discovery_findings_pkey
DO $$ BEGIN
  IF to_regclass('public.discovery_findings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_findings_pkey' AND conrelid = to_regclass('public.discovery_findings')
     ) THEN
    ALTER TABLE ONLY public.discovery_findings
        ADD CONSTRAINT discovery_findings_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: discovery_jobs discovery_jobs_pkey
DO $$ BEGIN
  IF to_regclass('public.discovery_jobs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_jobs_pkey' AND conrelid = to_regclass('public.discovery_jobs')
     ) THEN
    ALTER TABLE ONLY public.discovery_jobs
        ADD CONSTRAINT discovery_jobs_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: discovery_rate_limits discovery_rate_limits_pkey
DO $$ BEGIN
  IF to_regclass('public.discovery_rate_limits') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_rate_limits_pkey' AND conrelid = to_regclass('public.discovery_rate_limits')
     ) THEN
    ALTER TABLE ONLY public.discovery_rate_limits
        ADD CONSTRAINT discovery_rate_limits_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: discovery_rate_limits discovery_rate_limits_tenant_id_key
DO $$ BEGIN
  IF to_regclass('public.discovery_rate_limits') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_rate_limits_tenant_id_key' AND conrelid = to_regclass('public.discovery_rate_limits')
     ) THEN
    ALTER TABLE ONLY public.discovery_rate_limits
        ADD CONSTRAINT discovery_rate_limits_tenant_id_key UNIQUE (tenant_id);
  END IF;
END $$;


-- CONSTRAINT: discovery_targets discovery_targets_pkey
DO $$ BEGIN
  IF to_regclass('public.discovery_targets') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_targets_pkey' AND conrelid = to_regclass('public.discovery_targets')
     ) THEN
    ALTER TABLE ONLY public.discovery_targets
        ADD CONSTRAINT discovery_targets_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: external_asset_mappings external_asset_mappings_pkey
DO $$ BEGIN
  IF to_regclass('public.external_asset_mappings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'external_asset_mappings_pkey' AND conrelid = to_regclass('public.external_asset_mappings')
     ) THEN
    ALTER TABLE ONLY public.external_asset_mappings
        ADD CONSTRAINT external_asset_mappings_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: external_asset_mappings external_asset_mappings_tenant_id_local_type_local_id_exter_key
DO $$ BEGIN
  IF to_regclass('public.external_asset_mappings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'external_asset_mappings_tenant_id_local_type_local_id_exter_key' AND conrelid = to_regclass('public.external_asset_mappings')
     ) THEN
    ALTER TABLE ONLY public.external_asset_mappings
        ADD CONSTRAINT external_asset_mappings_tenant_id_local_type_local_id_exter_key UNIQUE (tenant_id, local_type, local_id, external_system);
  END IF;
END $$;


-- CONSTRAINT: external_connection_history external_connection_history_pkey
DO $$ BEGIN
  IF to_regclass('public.external_connection_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'external_connection_history_pkey' AND conrelid = to_regclass('public.external_connection_history')
     ) THEN
    ALTER TABLE ONLY public.external_connection_history
        ADD CONSTRAINT external_connection_history_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: external_connections external_connections_pkey
DO $$ BEGIN
  IF to_regclass('public.external_connections') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'external_connections_pkey' AND conrelid = to_regclass('public.external_connections')
     ) THEN
    ALTER TABLE ONLY public.external_connections
        ADD CONSTRAINT external_connections_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: feature_adoption_metrics feature_adoption_metrics_pkey
DO $$ BEGIN
  IF to_regclass('public.feature_adoption_metrics') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'feature_adoption_metrics_pkey' AND conrelid = to_regclass('public.feature_adoption_metrics')
     ) THEN
    ALTER TABLE ONLY public.feature_adoption_metrics
        ADD CONSTRAINT feature_adoption_metrics_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: feature_usage_events feature_usage_events_pkey
DO $$ BEGIN
  IF to_regclass('public.feature_usage_events') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'feature_usage_events_pkey' AND conrelid = to_regclass('public.feature_usage_events')
     ) THEN
    ALTER TABLE ONLY public.feature_usage_events
        ADD CONSTRAINT feature_usage_events_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: health_alerts health_alerts_pkey
DO $$ BEGIN
  IF to_regclass('public.health_alerts') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'health_alerts_pkey' AND conrelid = to_regclass('public.health_alerts')
     ) THEN
    ALTER TABLE ONLY public.health_alerts
        ADD CONSTRAINT health_alerts_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: health_benchmarks health_benchmarks_category_key
DO $$ BEGIN
  IF to_regclass('public.health_benchmarks') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'health_benchmarks_category_key' AND conrelid = to_regclass('public.health_benchmarks')
     ) THEN
    ALTER TABLE ONLY public.health_benchmarks
        ADD CONSTRAINT health_benchmarks_category_key UNIQUE (category);
  END IF;
END $$;


-- CONSTRAINT: health_benchmarks health_benchmarks_pkey
DO $$ BEGIN
  IF to_regclass('public.health_benchmarks') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'health_benchmarks_pkey' AND conrelid = to_regclass('public.health_benchmarks')
     ) THEN
    ALTER TABLE ONLY public.health_benchmarks
        ADD CONSTRAINT health_benchmarks_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: health_insights health_insights_pkey
DO $$ BEGIN
  IF to_regclass('public.health_insights') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'health_insights_pkey' AND conrelid = to_regclass('public.health_insights')
     ) THEN
    ALTER TABLE ONLY public.health_insights
        ADD CONSTRAINT health_insights_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: health_metrics health_metrics_pkey
DO $$ BEGIN
  IF to_regclass('public.health_metrics') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'health_metrics_pkey' AND conrelid = to_regclass('public.health_metrics')
     ) THEN
    ALTER TABLE ONLY public.health_metrics
        ADD CONSTRAINT health_metrics_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: identity_link_requests identity_link_requests_pkey
DO $$ BEGIN
  IF to_regclass('public.identity_link_requests') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'identity_link_requests_pkey' AND conrelid = to_regclass('public.identity_link_requests')
     ) THEN
    ALTER TABLE ONLY public.identity_link_requests
        ADD CONSTRAINT identity_link_requests_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: implementation_keys implementation_keys_pkey
DO $$ BEGIN
  IF to_regclass('public.implementation_keys') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'implementation_keys_pkey' AND conrelid = to_regclass('public.implementation_keys')
     ) THEN
    ALTER TABLE ONLY public.implementation_keys
        ADD CONSTRAINT implementation_keys_pkey PRIMARY KEY (implementation_id, key_id);
  END IF;
END $$;


-- CONSTRAINT: implementation_libraries implementation_libraries_pkey
DO $$ BEGIN
  IF to_regclass('public.implementation_libraries') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'implementation_libraries_pkey' AND conrelid = to_regclass('public.implementation_libraries')
     ) THEN
    ALTER TABLE ONLY public.implementation_libraries
        ADD CONSTRAINT implementation_libraries_pkey PRIMARY KEY (implementation_id, library_id);
  END IF;
END $$;


-- CONSTRAINT: in_app_notifications in_app_notifications_pkey
DO $$ BEGIN
  IF to_regclass('public.in_app_notifications') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'in_app_notifications_pkey' AND conrelid = to_regclass('public.in_app_notifications')
     ) THEN
    ALTER TABLE ONLY public.in_app_notifications
        ADD CONSTRAINT in_app_notifications_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: integrations integrations_pkey
DO $$ BEGIN
  IF to_regclass('public.integrations') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'integrations_pkey' AND conrelid = to_regclass('public.integrations')
     ) THEN
    ALTER TABLE ONLY public.integrations
        ADD CONSTRAINT integrations_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: integrations integrations_tenant_id_name_key
DO $$ BEGIN
  IF to_regclass('public.integrations') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'integrations_tenant_id_name_key' AND conrelid = to_regclass('public.integrations')
     ) THEN
    ALTER TABLE ONLY public.integrations
        ADD CONSTRAINT integrations_tenant_id_name_key UNIQUE (tenant_id, name);
  END IF;
END $$;


-- CONSTRAINT: interrogation_schedules interrogation_schedules_pkey
DO $$ BEGIN
  IF to_regclass('public.interrogation_schedules') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'interrogation_schedules_pkey' AND conrelid = to_regclass('public.interrogation_schedules')
     ) THEN
    ALTER TABLE ONLY public.interrogation_schedules
        ADD CONSTRAINT interrogation_schedules_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: keys keys_pkey
DO $$ BEGIN
  IF to_regclass('public.keys') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'keys_pkey' AND conrelid = to_regclass('public.keys')
     ) THEN
    ALTER TABLE ONLY public.keys
        ADD CONSTRAINT keys_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: kms_keys kms_keys_pkey
DO $$ BEGIN
  IF to_regclass('public.kms_keys') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'kms_keys_pkey' AND conrelid = to_regclass('public.kms_keys')
     ) THEN
    ALTER TABLE ONLY public.kms_keys
        ADD CONSTRAINT kms_keys_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: library_provided_algorithms library_provided_algorithms_pkey
DO $$ BEGIN
  IF to_regclass('public.library_provided_algorithms') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'library_provided_algorithms_pkey' AND conrelid = to_regclass('public.library_provided_algorithms')
     ) THEN
    ALTER TABLE ONLY public.library_provided_algorithms
        ADD CONSTRAINT library_provided_algorithms_pkey PRIMARY KEY (library_id, algorithm_id);
  END IF;
END $$;


-- CONSTRAINT: locations locations_name_unique_per_parent
DO $$ BEGIN
  IF to_regclass('public.locations') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'locations_name_unique_per_parent' AND conrelid = to_regclass('public.locations')
     ) THEN
    ALTER TABLE ONLY public.locations
        ADD CONSTRAINT locations_name_unique_per_parent UNIQUE (tenant_id, parent_id, name);
  END IF;
END $$;


-- CONSTRAINT: locations locations_pkey
DO $$ BEGIN
  IF to_regclass('public.locations') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'locations_pkey' AND conrelid = to_regclass('public.locations')
     ) THEN
    ALTER TABLE ONLY public.locations
        ADD CONSTRAINT locations_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: maintenance_windows maintenance_windows_pkey
DO $$ BEGIN
  IF to_regclass('public.maintenance_windows') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'maintenance_windows_pkey' AND conrelid = to_regclass('public.maintenance_windows')
     ) THEN
    ALTER TABLE ONLY public.maintenance_windows
        ADD CONSTRAINT maintenance_windows_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: measurement_templates measurement_templates_code_key
DO $$ BEGIN
  IF to_regclass('public.measurement_templates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'measurement_templates_code_key' AND conrelid = to_regclass('public.measurement_templates')
     ) THEN
    ALTER TABLE ONLY public.measurement_templates
        ADD CONSTRAINT measurement_templates_code_key UNIQUE (code);
  END IF;
END $$;


-- CONSTRAINT: measurement_templates measurement_templates_pkey
DO $$ BEGIN
  IF to_regclass('public.measurement_templates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'measurement_templates_pkey' AND conrelid = to_regclass('public.measurement_templates')
     ) THEN
    ALTER TABLE ONLY public.measurement_templates
        ADD CONSTRAINT measurement_templates_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: measurement_types measurement_types_code_key
DO $$ BEGIN
  IF to_regclass('public.measurement_types') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'measurement_types_code_key' AND conrelid = to_regclass('public.measurement_types')
     ) THEN
    ALTER TABLE ONLY public.measurement_types
        ADD CONSTRAINT measurement_types_code_key UNIQUE (code);
  END IF;
END $$;


-- CONSTRAINT: measurement_types measurement_types_pkey
DO $$ BEGIN
  IF to_regclass('public.measurement_types') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'measurement_types_pkey' AND conrelid = to_regclass('public.measurement_types')
     ) THEN
    ALTER TABLE ONLY public.measurement_types
        ADD CONSTRAINT measurement_types_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: monitoring_alert_history monitoring_alert_history_pkey
DO $$ BEGIN
  IF to_regclass('public.monitoring_alert_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'monitoring_alert_history_pkey' AND conrelid = to_regclass('public.monitoring_alert_history')
     ) THEN
    ALTER TABLE ONLY public.monitoring_alert_history
        ADD CONSTRAINT monitoring_alert_history_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: monitoring_alert_thresholds monitoring_alert_thresholds_pkey
DO $$ BEGIN
  IF to_regclass('public.monitoring_alert_thresholds') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'monitoring_alert_thresholds_pkey' AND conrelid = to_regclass('public.monitoring_alert_thresholds')
     ) THEN
    ALTER TABLE ONLY public.monitoring_alert_thresholds
        ADD CONSTRAINT monitoring_alert_thresholds_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: monitoring_alert_thresholds monitoring_alert_thresholds_threshold_name_key
DO $$ BEGIN
  IF to_regclass('public.monitoring_alert_thresholds') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'monitoring_alert_thresholds_threshold_name_key' AND conrelid = to_regclass('public.monitoring_alert_thresholds')
     ) THEN
    ALTER TABLE ONLY public.monitoring_alert_thresholds
        ADD CONSTRAINT monitoring_alert_thresholds_threshold_name_key UNIQUE (threshold_name);
  END IF;
END $$;


-- CONSTRAINT: monitoring_notification_channels monitoring_notification_channels_channel_name_key
DO $$ BEGIN
  IF to_regclass('public.monitoring_notification_channels') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'monitoring_notification_channels_channel_name_key' AND conrelid = to_regclass('public.monitoring_notification_channels')
     ) THEN
    ALTER TABLE ONLY public.monitoring_notification_channels
        ADD CONSTRAINT monitoring_notification_channels_channel_name_key UNIQUE (channel_name);
  END IF;
END $$;


-- CONSTRAINT: monitoring_notification_channels monitoring_notification_channels_pkey
DO $$ BEGIN
  IF to_regclass('public.monitoring_notification_channels') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'monitoring_notification_channels_pkey' AND conrelid = to_regclass('public.monitoring_notification_channels')
     ) THEN
    ALTER TABLE ONLY public.monitoring_notification_channels
        ADD CONSTRAINT monitoring_notification_channels_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: network_assets_partitioned network_assets_partitioned_pkey
-- HASH-partitioned on tenant_id, so the PK must include the partition column.
-- Added late: the table shipped without a PK, which broke strict GROUP BY
-- functional-dependency inference for any aggregate over the network_assets view.
-- NOT `ALTER TABLE ONLY`: the partitions are attached by this point, and a
-- parent-ONLY primary key on a partitioned table is created INVALID (no
-- per-partition indexes, uniqueness unenforced) until every partition's index
-- is attached — which nothing in this file did. The recursive form creates and
-- attaches the partition indexes in one statement.
DO $$ BEGIN
  IF to_regclass('public.network_assets_partitioned') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'network_assets_partitioned_pkey' AND conrelid = to_regclass('public.network_assets_partitioned')
     ) THEN
    ALTER TABLE public.network_assets_partitioned
        ADD CONSTRAINT network_assets_partitioned_pkey PRIMARY KEY (tenant_id, id);
  END IF;
END $$;


-- CONSTRAINT: crypto_implementations_partitioned crypto_implementations_partitioned_pkey
-- Same shape and same reasoning as network_assets_partitioned_pkey above: HASH
-- partitioned on tenant_id, so the PK must lead with the partition column, and
-- the recursive (non-ONLY) form is required for it to be VALID and usable as an
-- FK target.
DO $$ BEGIN
  IF to_regclass('public.crypto_implementations_partitioned') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conrelid = to_regclass('public.crypto_implementations_partitioned')
         AND (contype = 'p' OR conname = 'crypto_implementations_partitioned_pkey')
     ) THEN
    ALTER TABLE public.crypto_implementations_partitioned
        ADD CONSTRAINT crypto_implementations_partitioned_pkey PRIMARY KEY (tenant_id, id);
  END IF;
END $$;


-- CONSTRAINT: sensor_discoveries_partitioned sensor_discoveries_partitioned_pkey
-- The ingest hot path stamps discoveries processed by id; without this the
-- planner could neither use an index nor prune partitions, so every single-row
-- update scanned all eight and batch processing was quadratic in batch size.
-- Guarded on contype = 'p' as well as the name, because adding a second primary
-- key under any name is an error rather than a no-op.
DO $$ BEGIN
  IF to_regclass('public.sensor_discoveries_partitioned') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conrelid = to_regclass('public.sensor_discoveries_partitioned')
         AND (contype = 'p' OR conname = 'sensor_discoveries_partitioned_pkey')
     ) THEN
    ALTER TABLE public.sensor_discoveries_partitioned
        ADD CONSTRAINT sensor_discoveries_partitioned_pkey PRIMARY KEY (tenant_id, id);
  END IF;
END $$;


-- CONSTRAINT: network_segments network_segments_pkey
DO $$ BEGIN
  IF to_regclass('public.network_segments') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'network_segments_pkey' AND conrelid = to_regclass('public.network_segments')
     ) THEN
    ALTER TABLE ONLY public.network_segments
        ADD CONSTRAINT network_segments_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: network_segments network_segments_value_unique_per_tenant
DO $$ BEGIN
  IF to_regclass('public.network_segments') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'network_segments_value_unique_per_tenant' AND conrelid = to_regclass('public.network_segments')
     ) THEN
    ALTER TABLE ONLY public.network_segments
        ADD CONSTRAINT network_segments_value_unique_per_tenant UNIQUE (tenant_id, value);
  END IF;
END $$;


-- CONSTRAINT: notification_delivery_queue notification_delivery_queue_pkey
DO $$ BEGIN
  IF to_regclass('public.notification_delivery_queue') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'notification_delivery_queue_pkey' AND conrelid = to_regclass('public.notification_delivery_queue')
     ) THEN
    ALTER TABLE ONLY public.notification_delivery_queue
        ADD CONSTRAINT notification_delivery_queue_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: notification_history notification_history_pkey
DO $$ BEGIN
  IF to_regclass('public.notification_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'notification_history_pkey' AND conrelid = to_regclass('public.notification_history')
     ) THEN
    ALTER TABLE ONLY public.notification_history
        ADD CONSTRAINT notification_history_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: pcap_upload_jobs pcap_upload_jobs_pkey
DO $$ BEGIN
  IF to_regclass('public.pcap_upload_jobs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'pcap_upload_jobs_pkey' AND conrelid = to_regclass('public.pcap_upload_jobs')
     ) THEN
    ALTER TABLE ONLY public.pcap_upload_jobs
        ADD CONSTRAINT pcap_upload_jobs_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: pending_sensor_registrations pending_sensor_registrations_pkey
DO $$ BEGIN
  IF to_regclass('public.pending_sensor_registrations') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'pending_sensor_registrations_pkey' AND conrelid = to_regclass('public.pending_sensor_registrations')
     ) THEN
    ALTER TABLE ONLY public.pending_sensor_registrations
        ADD CONSTRAINT pending_sensor_registrations_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: pending_sensor_registrations pending_sensor_registrations_registration_key_key
DO $$ BEGIN
  IF to_regclass('public.pending_sensor_registrations') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'pending_sensor_registrations_registration_key_key' AND conrelid = to_regclass('public.pending_sensor_registrations')
     ) THEN
    ALTER TABLE ONLY public.pending_sensor_registrations
        ADD CONSTRAINT pending_sensor_registrations_registration_key_key UNIQUE (registration_key);
  END IF;
END $$;


-- CONSTRAINT: pending_sensors pending_sensors_pkey
DO $$ BEGIN
  IF to_regclass('public.pending_sensors') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'pending_sensors_pkey' AND conrelid = to_regclass('public.pending_sensors')
     ) THEN
    ALTER TABLE ONLY public.pending_sensors
        ADD CONSTRAINT pending_sensors_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: pending_sensors pending_sensors_registration_key_key
DO $$ BEGIN
  IF to_regclass('public.pending_sensors') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'pending_sensors_registration_key_key' AND conrelid = to_regclass('public.pending_sensors')
     ) THEN
    ALTER TABLE ONLY public.pending_sensors
        ADD CONSTRAINT pending_sensors_registration_key_key UNIQUE (registration_key);
  END IF;
END $$;


-- CONSTRAINT: permission_audit_logs permission_audit_logs_pkey
DO $$ BEGIN
  IF to_regclass('public.permission_audit_logs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'permission_audit_logs_pkey' AND conrelid = to_regclass('public.permission_audit_logs')
     ) THEN
    ALTER TABLE ONLY public.permission_audit_logs
        ADD CONSTRAINT permission_audit_logs_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_announcements platform_announcements_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_announcements') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_announcements_pkey' AND conrelid = to_regclass('public.platform_announcements')
     ) THEN
    ALTER TABLE ONLY public.platform_announcements
        ADD CONSTRAINT platform_announcements_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_bootstrap_ca platform_bootstrap_ca_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_bootstrap_ca') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_bootstrap_ca_pkey' AND conrelid = to_regclass('public.platform_bootstrap_ca')
     ) THEN
    ALTER TABLE ONLY public.platform_bootstrap_ca
        ADD CONSTRAINT platform_bootstrap_ca_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_bootstrap_certificates platform_bootstrap_certificates_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_bootstrap_certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_bootstrap_certificates_pkey' AND conrelid = to_regclass('public.platform_bootstrap_certificates')
     ) THEN
    ALTER TABLE ONLY public.platform_bootstrap_certificates
        ADD CONSTRAINT platform_bootstrap_certificates_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_framework_controls platform_framework_controls_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_framework_controls') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_framework_controls_pkey' AND conrelid = to_regclass('public.platform_framework_controls')
     ) THEN
    ALTER TABLE ONLY public.platform_framework_controls
        ADD CONSTRAINT platform_framework_controls_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_framework_versions platform_framework_versions_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_framework_versions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_framework_versions_pkey' AND conrelid = to_regclass('public.platform_framework_versions')
     ) THEN
    ALTER TABLE ONLY public.platform_framework_versions
        ADD CONSTRAINT platform_framework_versions_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_frameworks platform_frameworks_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_frameworks') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_frameworks_pkey' AND conrelid = to_regclass('public.platform_frameworks')
     ) THEN
    ALTER TABLE ONLY public.platform_frameworks
        ADD CONSTRAINT platform_frameworks_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_integration_audit_log platform_integration_audit_log_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_integration_audit_log') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_integration_audit_log_pkey' AND conrelid = to_regclass('public.platform_integration_audit_log')
     ) THEN
    ALTER TABLE ONLY public.platform_integration_audit_log
        ADD CONSTRAINT platform_integration_audit_log_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_integration_secrets platform_integration_secrets_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_integration_secrets') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_integration_secrets_pkey' AND conrelid = to_regclass('public.platform_integration_secrets')
     ) THEN
    ALTER TABLE ONLY public.platform_integration_secrets
        ADD CONSTRAINT platform_integration_secrets_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_integrations platform_integrations_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_integrations') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_integrations_pkey' AND conrelid = to_regclass('public.platform_integrations')
     ) THEN
    ALTER TABLE ONLY public.platform_integrations
        ADD CONSTRAINT platform_integrations_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_log_access_audit platform_log_access_audit_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_log_access_audit') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_log_access_audit_pkey' AND conrelid = to_regclass('public.platform_log_access_audit')
     ) THEN
    ALTER TABLE ONLY public.platform_log_access_audit
        ADD CONSTRAINT platform_log_access_audit_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_log_metadata platform_log_metadata_log_id_key
DO $$ BEGIN
  IF to_regclass('public.platform_log_metadata') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_log_metadata_log_id_key' AND conrelid = to_regclass('public.platform_log_metadata')
     ) THEN
    ALTER TABLE ONLY public.platform_log_metadata
        ADD CONSTRAINT platform_log_metadata_log_id_key UNIQUE (log_id);
  END IF;
END $$;


-- CONSTRAINT: platform_log_metadata platform_log_metadata_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_log_metadata') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_log_metadata_pkey' AND conrelid = to_regclass('public.platform_log_metadata')
     ) THEN
    ALTER TABLE ONLY public.platform_log_metadata
        ADD CONSTRAINT platform_log_metadata_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_log_pii_rules platform_log_pii_rules_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_log_pii_rules') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_log_pii_rules_pkey' AND conrelid = to_regclass('public.platform_log_pii_rules')
     ) THEN
    ALTER TABLE ONLY public.platform_log_pii_rules
        ADD CONSTRAINT platform_log_pii_rules_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_log_pii_rules platform_log_pii_rules_rule_name_key
DO $$ BEGIN
  IF to_regclass('public.platform_log_pii_rules') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_log_pii_rules_rule_name_key' AND conrelid = to_regclass('public.platform_log_pii_rules')
     ) THEN
    ALTER TABLE ONLY public.platform_log_pii_rules
        ADD CONSTRAINT platform_log_pii_rules_rule_name_key UNIQUE (rule_name);
  END IF;
END $$;


-- CONSTRAINT: platform_log_retention_jobs platform_log_retention_jobs_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_log_retention_jobs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_log_retention_jobs_pkey' AND conrelid = to_regclass('public.platform_log_retention_jobs')
     ) THEN
    ALTER TABLE ONLY public.platform_log_retention_jobs
        ADD CONSTRAINT platform_log_retention_jobs_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_metrics_snapshots platform_metrics_snapshots_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_metrics_snapshots') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_metrics_snapshots_pkey' AND conrelid = to_regclass('public.platform_metrics_snapshots')
     ) THEN
    ALTER TABLE ONLY public.platform_metrics_snapshots
        ADD CONSTRAINT platform_metrics_snapshots_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_notification_channels platform_notification_channels_channel_name_key
DO $$ BEGIN
  IF to_regclass('public.platform_notification_channels') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_notification_channels_channel_name_key' AND conrelid = to_regclass('public.platform_notification_channels')
     ) THEN
    ALTER TABLE ONLY public.platform_notification_channels
        ADD CONSTRAINT platform_notification_channels_channel_name_key UNIQUE (channel_name);
  END IF;
END $$;


-- CONSTRAINT: platform_notification_channels platform_notification_channels_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_notification_channels') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_notification_channels_pkey' AND conrelid = to_regclass('public.platform_notification_channels')
     ) THEN
    ALTER TABLE ONLY public.platform_notification_channels
        ADD CONSTRAINT platform_notification_channels_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_notification_rules platform_notification_rules_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_notification_rules') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_notification_rules_pkey' AND conrelid = to_regclass('public.platform_notification_rules')
     ) THEN
    ALTER TABLE ONLY public.platform_notification_rules
        ADD CONSTRAINT platform_notification_rules_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_notification_rules platform_notification_rules_rule_name_key
DO $$ BEGIN
  IF to_regclass('public.platform_notification_rules') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_notification_rules_rule_name_key' AND conrelid = to_regclass('public.platform_notification_rules')
     ) THEN
    ALTER TABLE ONLY public.platform_notification_rules
        ADD CONSTRAINT platform_notification_rules_rule_name_key UNIQUE (rule_name);
  END IF;
END $$;


-- CONSTRAINT: platform_permissions platform_permissions_name_key
DO $$ BEGIN
  IF to_regclass('public.platform_permissions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_permissions_name_key' AND conrelid = to_regclass('public.platform_permissions')
     ) THEN
    ALTER TABLE ONLY public.platform_permissions
        ADD CONSTRAINT platform_permissions_name_key UNIQUE (name);
  END IF;
END $$;


-- CONSTRAINT: platform_permissions platform_permissions_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_permissions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_permissions_pkey' AND conrelid = to_regclass('public.platform_permissions')
     ) THEN
    ALTER TABLE ONLY public.platform_permissions
        ADD CONSTRAINT platform_permissions_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_refresh_tokens platform_refresh_tokens_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_refresh_tokens') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_refresh_tokens_pkey' AND conrelid = to_regclass('public.platform_refresh_tokens')
     ) THEN
    ALTER TABLE ONLY public.platform_refresh_tokens
        ADD CONSTRAINT platform_refresh_tokens_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_role_permissions platform_role_permissions_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_role_permissions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_role_permissions_pkey' AND conrelid = to_regclass('public.platform_role_permissions')
     ) THEN
    ALTER TABLE ONLY public.platform_role_permissions
        ADD CONSTRAINT platform_role_permissions_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_role_permissions platform_role_permissions_role_id_permission_id_key
DO $$ BEGIN
  IF to_regclass('public.platform_role_permissions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_role_permissions_role_id_permission_id_key' AND conrelid = to_regclass('public.platform_role_permissions')
     ) THEN
    ALTER TABLE ONLY public.platform_role_permissions
        ADD CONSTRAINT platform_role_permissions_role_id_permission_id_key UNIQUE (role_id, permission_id);
  END IF;
END $$;


-- CONSTRAINT: platform_roles platform_roles_name_key
DO $$ BEGIN
  IF to_regclass('public.platform_roles') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_roles_name_key' AND conrelid = to_regclass('public.platform_roles')
     ) THEN
    ALTER TABLE ONLY public.platform_roles
        ADD CONSTRAINT platform_roles_name_key UNIQUE (name);
  END IF;
END $$;


-- CONSTRAINT: platform_roles platform_roles_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_roles') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_roles_pkey' AND conrelid = to_regclass('public.platform_roles')
     ) THEN
    ALTER TABLE ONLY public.platform_roles
        ADD CONSTRAINT platform_roles_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_service_ca platform_service_ca_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_service_ca') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_service_ca_pkey' AND conrelid = to_regclass('public.platform_service_ca')
     ) THEN
    ALTER TABLE ONLY public.platform_service_ca
        ADD CONSTRAINT platform_service_ca_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_service_certificates platform_service_certificates_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_service_certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_service_certificates_pkey' AND conrelid = to_regclass('public.platform_service_certificates')
     ) THEN
    ALTER TABLE ONLY public.platform_service_certificates
        ADD CONSTRAINT platform_service_certificates_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_settings platform_settings_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_settings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_settings_pkey' AND conrelid = to_regclass('public.platform_settings')
     ) THEN
    ALTER TABLE ONLY public.platform_settings
        ADD CONSTRAINT platform_settings_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_sso_providers platform_sso_providers_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_sso_providers') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_sso_providers_pkey' AND conrelid = to_regclass('public.platform_sso_providers')
     ) THEN
    ALTER TABLE ONLY public.platform_sso_providers
        ADD CONSTRAINT platform_sso_providers_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: platform_users platform_users_email_key
DO $$ BEGIN
  IF to_regclass('public.platform_users') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_users_email_key' AND conrelid = to_regclass('public.platform_users')
     ) THEN
    ALTER TABLE ONLY public.platform_users
        ADD CONSTRAINT platform_users_email_key UNIQUE (email);
  END IF;
END $$;


-- CONSTRAINT: platform_users platform_users_pkey
DO $$ BEGIN
  IF to_regclass('public.platform_users') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_users_pkey' AND conrelid = to_regclass('public.platform_users')
     ) THEN
    ALTER TABLE ONLY public.platform_users
        ADD CONSTRAINT platform_users_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: refresh_tokens refresh_tokens_pkey
DO $$ BEGIN
  IF to_regclass('public.refresh_tokens') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'refresh_tokens_pkey' AND conrelid = to_regclass('public.refresh_tokens')
     ) THEN
    ALTER TABLE ONLY public.refresh_tokens
        ADD CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: remediation_plan_items remediation_plan_items_pkey
DO $$ BEGIN
  IF to_regclass('public.remediation_plan_items') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'remediation_plan_items_pkey' AND conrelid = to_regclass('public.remediation_plan_items')
     ) THEN
    ALTER TABLE ONLY public.remediation_plan_items
        ADD CONSTRAINT remediation_plan_items_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: remediation_plans remediation_plans_pkey
DO $$ BEGIN
  IF to_regclass('public.remediation_plans') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'remediation_plans_pkey' AND conrelid = to_regclass('public.remediation_plans')
     ) THEN
    ALTER TABLE ONLY public.remediation_plans
        ADD CONSTRAINT remediation_plans_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: resource_alerts resource_alerts_pkey
DO $$ BEGIN
  IF to_regclass('public.resource_alerts') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'resource_alerts_pkey' AND conrelid = to_regclass('public.resource_alerts')
     ) THEN
    ALTER TABLE ONLY public.resource_alerts
        ADD CONSTRAINT resource_alerts_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: resource_permissions resource_permissions_pkey
DO $$ BEGIN
  IF to_regclass('public.resource_permissions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'resource_permissions_pkey' AND conrelid = to_regclass('public.resource_permissions')
     ) THEN
    ALTER TABLE ONLY public.resource_permissions
        ADD CONSTRAINT resource_permissions_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: resource_tracking_config resource_tracking_config_config_key_key
DO $$ BEGIN
  IF to_regclass('public.resource_tracking_config') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'resource_tracking_config_config_key_key' AND conrelid = to_regclass('public.resource_tracking_config')
     ) THEN
    ALTER TABLE ONLY public.resource_tracking_config
        ADD CONSTRAINT resource_tracking_config_config_key_key UNIQUE (config_key);
  END IF;
END $$;


-- CONSTRAINT: resource_tracking_config resource_tracking_config_pkey
DO $$ BEGIN
  IF to_regclass('public.resource_tracking_config') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'resource_tracking_config_pkey' AND conrelid = to_regclass('public.resource_tracking_config')
     ) THEN
    ALTER TABLE ONLY public.resource_tracking_config
        ADD CONSTRAINT resource_tracking_config_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: rule_vulnerability_mappings rule_vulnerability_mappings_pkey
DO $$ BEGIN
  IF to_regclass('public.rule_vulnerability_mappings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'rule_vulnerability_mappings_pkey' AND conrelid = to_regclass('public.rule_vulnerability_mappings')
     ) THEN
    ALTER TABLE ONLY public.rule_vulnerability_mappings
        ADD CONSTRAINT rule_vulnerability_mappings_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: schedule_history schedule_history_pkey
DO $$ BEGIN
  IF to_regclass('public.schedule_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'schedule_history_pkey' AND conrelid = to_regclass('public.schedule_history')
     ) THEN
    ALTER TABLE ONLY public.schedule_history
        ADD CONSTRAINT schedule_history_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: security_events security_events_event_id_key
DO $$ BEGIN
  IF to_regclass('public.security_events') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'security_events_event_id_key' AND conrelid = to_regclass('public.security_events')
     ) THEN
    ALTER TABLE ONLY public.security_events
        ADD CONSTRAINT security_events_event_id_key UNIQUE (event_id);
  END IF;
END $$;


-- CONSTRAINT: security_events security_events_pkey
DO $$ BEGIN
  IF to_regclass('public.security_events') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'security_events_pkey' AND conrelid = to_regclass('public.security_events')
     ) THEN
    ALTER TABLE ONLY public.security_events
        ADD CONSTRAINT security_events_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: security_incident_webhook_deliveries security_incident_webhook_deliveries_pkey
DO $$ BEGIN
  IF to_regclass('public.security_incident_webhook_deliveries') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'security_incident_webhook_deliveries_pkey' AND conrelid = to_regclass('public.security_incident_webhook_deliveries')
     ) THEN
    ALTER TABLE ONLY public.security_incident_webhook_deliveries
        ADD CONSTRAINT security_incident_webhook_deliveries_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: security_incident_webhooks security_incident_webhooks_pkey
DO $$ BEGIN
  IF to_regclass('public.security_incident_webhooks') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'security_incident_webhooks_pkey' AND conrelid = to_regclass('public.security_incident_webhooks')
     ) THEN
    ALTER TABLE ONLY public.security_incident_webhooks
        ADD CONSTRAINT security_incident_webhooks_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: security_incidents security_incidents_incident_id_key
DO $$ BEGIN
  IF to_regclass('public.security_incidents') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'security_incidents_incident_id_key' AND conrelid = to_regclass('public.security_incidents')
     ) THEN
    ALTER TABLE ONLY public.security_incidents
        ADD CONSTRAINT security_incidents_incident_id_key UNIQUE (incident_id);
  END IF;
END $$;


-- CONSTRAINT: security_incidents security_incidents_pkey
DO $$ BEGIN
  IF to_regclass('public.security_incidents') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'security_incidents_pkey' AND conrelid = to_regclass('public.security_incidents')
     ) THEN
    ALTER TABLE ONLY public.security_incidents
        ADD CONSTRAINT security_incidents_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: sensor_ca_certificates sensor_ca_certificates_pkey
DO $$ BEGIN
  IF to_regclass('public.sensor_ca_certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'sensor_ca_certificates_pkey' AND conrelid = to_regclass('public.sensor_ca_certificates')
     ) THEN
    ALTER TABLE ONLY public.sensor_ca_certificates
        ADD CONSTRAINT sensor_ca_certificates_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: sensor_certificates sensor_certificates_pkey
DO $$ BEGIN
  IF to_regclass('public.sensor_certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'sensor_certificates_pkey' AND conrelid = to_regclass('public.sensor_certificates')
     ) THEN
    ALTER TABLE ONLY public.sensor_certificates
        ADD CONSTRAINT sensor_certificates_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: sensor_commands sensor_commands_pkey
DO $$ BEGIN
  IF to_regclass('public.sensor_commands') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'sensor_commands_pkey' AND conrelid = to_regclass('public.sensor_commands')
     ) THEN
    ALTER TABLE ONLY public.sensor_commands
        ADD CONSTRAINT sensor_commands_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: sensor_health_metrics sensor_health_metrics_pkey
DO $$ BEGIN
  IF to_regclass('public.sensor_health_metrics') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'sensor_health_metrics_pkey' AND conrelid = to_regclass('public.sensor_health_metrics')
     ) THEN
    ALTER TABLE ONLY public.sensor_health_metrics
        ADD CONSTRAINT sensor_health_metrics_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: sensors sensors_pkey
DO $$ BEGIN
  IF to_regclass('public.sensors') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'sensors_pkey' AND conrelid = to_regclass('public.sensors')
     ) THEN
    ALTER TABLE ONLY public.sensors
        ADD CONSTRAINT sensors_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: service_accounts service_accounts_pkey
DO $$ BEGIN
  IF to_regclass('public.service_accounts') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'service_accounts_pkey' AND conrelid = to_regclass('public.service_accounts')
     ) THEN
    ALTER TABLE ONLY public.service_accounts
        ADD CONSTRAINT service_accounts_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: service_accounts service_accounts_service_name_key
DO $$ BEGIN
  IF to_regclass('public.service_accounts') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'service_accounts_service_name_key' AND conrelid = to_regclass('public.service_accounts')
     ) THEN
    ALTER TABLE ONLY public.service_accounts
        ADD CONSTRAINT service_accounts_service_name_key UNIQUE (service_name);
  END IF;
END $$;


-- CONSTRAINT: service_health_events service_health_events_pkey
DO $$ BEGIN
  IF to_regclass('public.service_health_events') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'service_health_events_pkey' AND conrelid = to_regclass('public.service_health_events')
     ) THEN
    ALTER TABLE ONLY public.service_health_events
        ADD CONSTRAINT service_health_events_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: service_identification_rules service_identification_rules_pkey
DO $$ BEGIN
  IF to_regclass('public.service_identification_rules') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'service_identification_rules_pkey' AND conrelid = to_regclass('public.service_identification_rules')
     ) THEN
    ALTER TABLE ONLY public.service_identification_rules
        ADD CONSTRAINT service_identification_rules_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: tenant_framework_licenses single_default_per_tenant
DO $$ BEGIN
  IF to_regclass('public.tenant_framework_licenses') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'single_default_per_tenant' AND conrelid = to_regclass('public.tenant_framework_licenses')
     ) THEN
    ALTER TABLE ONLY public.tenant_framework_licenses
        ADD CONSTRAINT single_default_per_tenant EXCLUDE USING btree (tenant_id WITH =) WHERE ((is_default = true));
  END IF;
END $$;


-- CONSTRAINT: ssh_keys ssh_keys_pkey
DO $$ BEGIN
  IF to_regclass('public.ssh_keys') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'ssh_keys_pkey' AND conrelid = to_regclass('public.ssh_keys')
     ) THEN
    ALTER TABLE ONLY public.ssh_keys
        ADD CONSTRAINT ssh_keys_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: sso_group_role_mappings sso_group_role_mappings_pkey
DO $$ BEGIN
  IF to_regclass('public.sso_group_role_mappings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'sso_group_role_mappings_pkey' AND conrelid = to_regclass('public.sso_group_role_mappings')
     ) THEN
    ALTER TABLE ONLY public.sso_group_role_mappings
        ADD CONSTRAINT sso_group_role_mappings_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: sso_providers sso_providers_pkey
DO $$ BEGIN
  IF to_regclass('public.sso_providers') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'sso_providers_pkey' AND conrelid = to_regclass('public.sso_providers')
     ) THEN
    ALTER TABLE ONLY public.sso_providers
        ADD CONSTRAINT sso_providers_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: subscription_tier_history subscription_tier_history_pkey
DO $$ BEGIN
  IF to_regclass('public.subscription_tier_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'subscription_tier_history_pkey' AND conrelid = to_regclass('public.subscription_tier_history')
     ) THEN
    ALTER TABLE ONLY public.subscription_tier_history
        ADD CONSTRAINT subscription_tier_history_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: subscription_tiers subscription_tiers_name_key
DO $$ BEGIN
  IF to_regclass('public.subscription_tiers') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'subscription_tiers_name_key' AND conrelid = to_regclass('public.subscription_tiers')
     ) THEN
    ALTER TABLE ONLY public.subscription_tiers
        ADD CONSTRAINT subscription_tiers_name_key UNIQUE (name);
  END IF;
END $$;


-- CONSTRAINT: subscription_tiers subscription_tiers_pkey
DO $$ BEGIN
  IF to_regclass('public.subscription_tiers') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'subscription_tiers_pkey' AND conrelid = to_regclass('public.subscription_tiers')
     ) THEN
    ALTER TABLE ONLY public.subscription_tiers
        ADD CONSTRAINT subscription_tiers_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: support_ticket_messages support_ticket_messages_pkey
DO $$ BEGIN
  IF to_regclass('public.support_ticket_messages') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'support_ticket_messages_pkey' AND conrelid = to_regclass('public.support_ticket_messages')
     ) THEN
    ALTER TABLE ONLY public.support_ticket_messages
        ADD CONSTRAINT support_ticket_messages_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: support_tickets support_tickets_pkey
DO $$ BEGIN
  IF to_regclass('public.support_tickets') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'support_tickets_pkey' AND conrelid = to_regclass('public.support_tickets')
     ) THEN
    ALTER TABLE ONLY public.support_tickets
        ADD CONSTRAINT support_tickets_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: sync_outbox sync_outbox_pkey
DO $$ BEGIN
  IF to_regclass('public.sync_outbox') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'sync_outbox_pkey' AND conrelid = to_regclass('public.sync_outbox')
     ) THEN
    ALTER TABLE ONLY public.sync_outbox
        ADD CONSTRAINT sync_outbox_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: system_health_metrics system_health_metrics_pkey
DO $$ BEGIN
  IF to_regclass('public.system_health_metrics') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'system_health_metrics_pkey' AND conrelid = to_regclass('public.system_health_metrics')
     ) THEN
    ALTER TABLE ONLY public.system_health_metrics
        ADD CONSTRAINT system_health_metrics_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: tenant_admin_settings_audit tenant_admin_settings_audit_pkey
DO $$ BEGIN
  IF to_regclass('public.tenant_admin_settings_audit') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_admin_settings_audit_pkey' AND conrelid = to_regclass('public.tenant_admin_settings_audit')
     ) THEN
    ALTER TABLE ONLY public.tenant_admin_settings_audit
        ADD CONSTRAINT tenant_admin_settings_audit_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: tenant_cost_analysis tenant_cost_analysis_pkey
DO $$ BEGIN
  IF to_regclass('public.tenant_cost_analysis') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_cost_analysis_pkey' AND conrelid = to_regclass('public.tenant_cost_analysis')
     ) THEN
    ALTER TABLE ONLY public.tenant_cost_analysis
        ADD CONSTRAINT tenant_cost_analysis_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: tenant_framework_controls tenant_framework_controls_pkey
DO $$ BEGIN
  IF to_regclass('public.tenant_framework_controls') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_framework_controls_pkey' AND conrelid = to_regclass('public.tenant_framework_controls')
     ) THEN
    ALTER TABLE ONLY public.tenant_framework_controls
        ADD CONSTRAINT tenant_framework_controls_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: tenant_framework_licenses tenant_framework_licenses_pkey
DO $$ BEGIN
  IF to_regclass('public.tenant_framework_licenses') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_framework_licenses_pkey' AND conrelid = to_regclass('public.tenant_framework_licenses')
     ) THEN
    ALTER TABLE ONLY public.tenant_framework_licenses
        ADD CONSTRAINT tenant_framework_licenses_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: tenant_frameworks tenant_frameworks_pkey
DO $$ BEGIN
  IF to_regclass('public.tenant_frameworks') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_frameworks_pkey' AND conrelid = to_regclass('public.tenant_frameworks')
     ) THEN
    ALTER TABLE ONLY public.tenant_frameworks
        ADD CONSTRAINT tenant_frameworks_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: tenant_geographic_data tenant_geographic_data_pkey
DO $$ BEGIN
  IF to_regclass('public.tenant_geographic_data') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_geographic_data_pkey' AND conrelid = to_regclass('public.tenant_geographic_data')
     ) THEN
    ALTER TABLE ONLY public.tenant_geographic_data
        ADD CONSTRAINT tenant_geographic_data_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: tenant_health tenant_health_pkey
DO $$ BEGIN
  IF to_regclass('public.tenant_health') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_health_pkey' AND conrelid = to_regclass('public.tenant_health')
     ) THEN
    ALTER TABLE ONLY public.tenant_health
        ADD CONSTRAINT tenant_health_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: tenant_health tenant_health_tenant_id_key
DO $$ BEGIN
  IF to_regclass('public.tenant_health') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_health_tenant_id_key' AND conrelid = to_regclass('public.tenant_health')
     ) THEN
    ALTER TABLE ONLY public.tenant_health
        ADD CONSTRAINT tenant_health_tenant_id_key UNIQUE (tenant_id);
  END IF;
END $$;


-- CONSTRAINT: tenant_measurement_overrides tenant_measurement_overrides_pkey
DO $$ BEGIN
  IF to_regclass('public.tenant_measurement_overrides') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_measurement_overrides_pkey' AND conrelid = to_regclass('public.tenant_measurement_overrides')
     ) THEN
    ALTER TABLE ONLY public.tenant_measurement_overrides
        ADD CONSTRAINT tenant_measurement_overrides_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: tenant_notes tenant_notes_pkey
DO $$ BEGIN
  IF to_regclass('public.tenant_notes') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_notes_pkey' AND conrelid = to_regclass('public.tenant_notes')
     ) THEN
    ALTER TABLE ONLY public.tenant_notes
        ADD CONSTRAINT tenant_notes_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: tenant_notification_channels tenant_notification_channels_pkey
DO $$ BEGIN
  IF to_regclass('public.tenant_notification_channels') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_notification_channels_pkey' AND conrelid = to_regclass('public.tenant_notification_channels')
     ) THEN
    ALTER TABLE ONLY public.tenant_notification_channels
        ADD CONSTRAINT tenant_notification_channels_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: tenant_notification_channels tenant_notification_channels_tenant_id_channel_name_key
DO $$ BEGIN
  IF to_regclass('public.tenant_notification_channels') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_notification_channels_tenant_id_channel_name_key' AND conrelid = to_regclass('public.tenant_notification_channels')
     ) THEN
    ALTER TABLE ONLY public.tenant_notification_channels
        ADD CONSTRAINT tenant_notification_channels_tenant_id_channel_name_key UNIQUE (tenant_id, channel_name);
  END IF;
END $$;


-- CONSTRAINT: tenant_notification_rules tenant_notification_rules_pkey
DO $$ BEGIN
  IF to_regclass('public.tenant_notification_rules') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_notification_rules_pkey' AND conrelid = to_regclass('public.tenant_notification_rules')
     ) THEN
    ALTER TABLE ONLY public.tenant_notification_rules
        ADD CONSTRAINT tenant_notification_rules_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: tenant_notification_rules tenant_notification_rules_tenant_id_rule_name_key
DO $$ BEGIN
  IF to_regclass('public.tenant_notification_rules') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_notification_rules_tenant_id_rule_name_key' AND conrelid = to_regclass('public.tenant_notification_rules')
     ) THEN
    ALTER TABLE ONLY public.tenant_notification_rules
        ADD CONSTRAINT tenant_notification_rules_tenant_id_rule_name_key UNIQUE (tenant_id, rule_name);
  END IF;
END $$;


-- CONSTRAINT: tenant_permissions tenant_permissions_name_key
DO $$ BEGIN
  IF to_regclass('public.tenant_permissions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_permissions_name_key' AND conrelid = to_regclass('public.tenant_permissions')
     ) THEN
    ALTER TABLE ONLY public.tenant_permissions
        ADD CONSTRAINT tenant_permissions_name_key UNIQUE (name);
  END IF;
END $$;


-- CONSTRAINT: tenant_permissions tenant_permissions_pkey
DO $$ BEGIN
  IF to_regclass('public.tenant_permissions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_permissions_pkey' AND conrelid = to_regclass('public.tenant_permissions')
     ) THEN
    ALTER TABLE ONLY public.tenant_permissions
        ADD CONSTRAINT tenant_permissions_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: tenant_resource_usage tenant_resource_usage_pkey
DO $$ BEGIN
  IF to_regclass('public.tenant_resource_usage') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_resource_usage_pkey' AND conrelid = to_regclass('public.tenant_resource_usage')
     ) THEN
    ALTER TABLE ONLY public.tenant_resource_usage
        ADD CONSTRAINT tenant_resource_usage_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: tenant_role_permissions tenant_role_permissions_pkey
DO $$ BEGIN
  IF to_regclass('public.tenant_role_permissions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_role_permissions_pkey' AND conrelid = to_regclass('public.tenant_role_permissions')
     ) THEN
    ALTER TABLE ONLY public.tenant_role_permissions
        ADD CONSTRAINT tenant_role_permissions_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: tenant_role_permissions tenant_role_permissions_role_id_permission_id_key
DO $$ BEGIN
  IF to_regclass('public.tenant_role_permissions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_role_permissions_role_id_permission_id_key' AND conrelid = to_regclass('public.tenant_role_permissions')
     ) THEN
    ALTER TABLE ONLY public.tenant_role_permissions
        ADD CONSTRAINT tenant_role_permissions_role_id_permission_id_key UNIQUE (role_id, permission_id);
  END IF;
END $$;


-- CONSTRAINT: tenant_roles tenant_roles_pkey
DO $$ BEGIN
  IF to_regclass('public.tenant_roles') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_roles_pkey' AND conrelid = to_regclass('public.tenant_roles')
     ) THEN
    ALTER TABLE ONLY public.tenant_roles
        ADD CONSTRAINT tenant_roles_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: tenant_roles tenant_roles_tenant_id_name_key
DO $$ BEGIN
  IF to_regclass('public.tenant_roles') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_roles_tenant_id_name_key' AND conrelid = to_regclass('public.tenant_roles')
     ) THEN
    ALTER TABLE ONLY public.tenant_roles
        ADD CONSTRAINT tenant_roles_tenant_id_name_key UNIQUE (tenant_id, name);
  END IF;
END $$;


-- CONSTRAINT: tenant_usage tenant_usage_pkey
DO $$ BEGIN
  IF to_regclass('public.tenant_usage') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_usage_pkey' AND conrelid = to_regclass('public.tenant_usage')
     ) THEN
    ALTER TABLE ONLY public.tenant_usage
        ADD CONSTRAINT tenant_usage_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: tenant_usage_tracking tenant_usage_tracking_pkey
DO $$ BEGIN
  IF to_regclass('public.tenant_usage_tracking') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_usage_tracking_pkey' AND conrelid = to_regclass('public.tenant_usage_tracking')
     ) THEN
    ALTER TABLE ONLY public.tenant_usage_tracking
        ADD CONSTRAINT tenant_usage_tracking_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: tenant_usage_tracking tenant_usage_tracking_tenant_id_metric_type_key
DO $$ BEGIN
  IF to_regclass('public.tenant_usage_tracking') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_usage_tracking_tenant_id_metric_type_key' AND conrelid = to_regclass('public.tenant_usage_tracking')
     ) THEN
    ALTER TABLE ONLY public.tenant_usage_tracking
        ADD CONSTRAINT tenant_usage_tracking_tenant_id_metric_type_key UNIQUE (tenant_id, metric_type);
  END IF;
END $$;


-- CONSTRAINT: tenants tenants_pkey
DO $$ BEGIN
  IF to_regclass('public.tenants') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenants_pkey' AND conrelid = to_regclass('public.tenants')
     ) THEN
    ALTER TABLE ONLY public.tenants
        ADD CONSTRAINT tenants_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: tenants tenants_slug_key
DO $$ BEGIN
  IF to_regclass('public.tenants') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenants_slug_key' AND conrelid = to_regclass('public.tenants')
     ) THEN
    ALTER TABLE ONLY public.tenants
        ADD CONSTRAINT tenants_slug_key UNIQUE (slug);
  END IF;
END $$;


-- CONSTRAINT: threat_detection_rules threat_detection_rules_pkey
DO $$ BEGIN
  IF to_regclass('public.threat_detection_rules') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'threat_detection_rules_pkey' AND conrelid = to_regclass('public.threat_detection_rules')
     ) THEN
    ALTER TABLE ONLY public.threat_detection_rules
        ADD CONSTRAINT threat_detection_rules_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: threat_detection_rules threat_detection_rules_rule_name_key
DO $$ BEGIN
  IF to_regclass('public.threat_detection_rules') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'threat_detection_rules_rule_name_key' AND conrelid = to_regclass('public.threat_detection_rules')
     ) THEN
    ALTER TABLE ONLY public.threat_detection_rules
        ADD CONSTRAINT threat_detection_rules_rule_name_key UNIQUE (rule_name);
  END IF;
END $$;


-- CONSTRAINT: ticket_comments ticket_comments_pkey
DO $$ BEGIN
  IF to_regclass('public.ticket_comments') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'ticket_comments_pkey' AND conrelid = to_regclass('public.ticket_comments')
     ) THEN
    ALTER TABLE ONLY public.ticket_comments
        ADD CONSTRAINT ticket_comments_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: tickets tickets_pkey
DO $$ BEGIN
  IF to_regclass('public.tickets') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tickets_pkey' AND conrelid = to_regclass('public.tickets')
     ) THEN
    ALTER TABLE ONLY public.tickets
        ADD CONSTRAINT tickets_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: ui_themes ui_themes_name_key
DO $$ BEGIN
  IF to_regclass('public.ui_themes') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'ui_themes_name_key' AND conrelid = to_regclass('public.ui_themes')
     ) THEN
    ALTER TABLE ONLY public.ui_themes
        ADD CONSTRAINT ui_themes_name_key UNIQUE (name);
  END IF;
END $$;


-- CONSTRAINT: ui_themes ui_themes_pkey
DO $$ BEGIN
  IF to_regclass('public.ui_themes') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'ui_themes_pkey' AND conrelid = to_regclass('public.ui_themes')
     ) THEN
    ALTER TABLE ONLY public.ui_themes
        ADD CONSTRAINT ui_themes_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: ai_models unique_active_model_type
DO $$ BEGIN
  IF to_regclass('public.ai_models') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_active_model_type' AND conrelid = to_regclass('public.ai_models')
     ) THEN
    ALTER TABLE ONLY public.ai_models
        ADD CONSTRAINT unique_active_model_type UNIQUE (model_type, active) DEFERRABLE INITIALLY DEFERRED;
  END IF;
END $$;


-- CONSTRAINT: agent_certificates unique_agent_serial
DO $$ BEGIN
  IF to_regclass('public.agent_certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_agent_serial' AND conrelid = to_regclass('public.agent_certificates')
     ) THEN
    ALTER TABLE ONLY public.agent_certificates
        ADD CONSTRAINT unique_agent_serial UNIQUE (agent_id, serial_number);
  END IF;
END $$;


-- CONSTRAINT: cmdb_entity_mappings unique_cmdb_entity_mapping
DO $$ BEGIN
  IF to_regclass('public.cmdb_entity_mappings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_cmdb_entity_mapping' AND conrelid = to_regclass('public.cmdb_entity_mappings')
     ) THEN
    ALTER TABLE ONLY public.cmdb_entity_mappings
        ADD CONSTRAINT unique_cmdb_entity_mapping UNIQUE (tenant_id, profile_id, local_entity_type, local_entity_id);
  END IF;
END $$;


-- CONSTRAINT: cmdb_sync_profiles unique_cmdb_profile_name
DO $$ BEGIN
  IF to_regclass('public.cmdb_sync_profiles') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_cmdb_profile_name' AND conrelid = to_regclass('public.cmdb_sync_profiles')
     ) THEN
    ALTER TABLE ONLY public.cmdb_sync_profiles
        ADD CONSTRAINT unique_cmdb_profile_name UNIQUE (tenant_id, name);
  END IF;
END $$;


-- CONSTRAINT: compliance_framework_status unique_compliance_framework_status_version
DO $$ BEGIN
  IF to_regclass('public.compliance_framework_status') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_compliance_framework_status_version' AND conrelid = to_regclass('public.compliance_framework_status')
     ) THEN
    ALTER TABLE ONLY public.compliance_framework_status
        ADD CONSTRAINT unique_compliance_framework_status_version UNIQUE (framework_name, framework_version);
  END IF;
END $$;


-- CONSTRAINT: platform_integration_secrets unique_current_secret
DO $$ BEGIN
  IF to_regclass('public.platform_integration_secrets') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_current_secret' AND conrelid = to_regclass('public.platform_integration_secrets')
     ) THEN
    ALTER TABLE ONLY public.platform_integration_secrets
        ADD CONSTRAINT unique_current_secret UNIQUE (integration_id, secret_key, is_current) DEFERRABLE INITIALLY DEFERRED;
  END IF;
END $$;


-- CONSTRAINT: certificates unique_fingerprint_per_tenant
DO $$ BEGIN
  IF to_regclass('public.certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_fingerprint_per_tenant' AND conrelid = to_regclass('public.certificates')
     ) THEN
    ALTER TABLE ONLY public.certificates
        ADD CONSTRAINT unique_fingerprint_per_tenant UNIQUE (tenant_id, fingerprint_sha256);
  END IF;
END $$;


-- CONSTRAINT: compliance_requirements unique_framework_requirement
DO $$ BEGIN
  IF to_regclass('public.compliance_requirements') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_framework_requirement' AND conrelid = to_regclass('public.compliance_requirements')
     ) THEN
    ALTER TABLE ONLY public.compliance_requirements
        ADD CONSTRAINT unique_framework_requirement UNIQUE (framework_id, requirement_code);
  END IF;
END $$;


-- CONSTRAINT: crypto_implementation_algorithms unique_impl_algorithm
DO $$ BEGIN
  IF to_regclass('public.crypto_implementation_algorithms') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_impl_algorithm' AND conrelid = to_regclass('public.crypto_implementation_algorithms')
     ) THEN
    ALTER TABLE ONLY public.crypto_implementation_algorithms
        ADD CONSTRAINT unique_impl_algorithm UNIQUE (crypto_implementation_id, algorithm_id, algorithm_type);
  END IF;
END $$;


-- CONSTRAINT: crypto_implementation_certificates unique_impl_cert
DO $$ BEGIN
  IF to_regclass('public.crypto_implementation_certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_impl_cert' AND conrelid = to_regclass('public.crypto_implementation_certificates')
     ) THEN
    ALTER TABLE ONLY public.crypto_implementation_certificates
        ADD CONSTRAINT unique_impl_cert UNIQUE (crypto_implementation_id, certificate_id);
  END IF;
END $$;


-- CONSTRAINT: access_pattern_analysis unique_pattern_key
DO $$ BEGIN
  IF to_regclass('public.access_pattern_analysis') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_pattern_key' AND conrelid = to_regclass('public.access_pattern_analysis')
     ) THEN
    ALTER TABLE ONLY public.access_pattern_analysis
        ADD CONSTRAINT unique_pattern_key UNIQUE (pattern_type, pattern_key, analysis_period_start);
  END IF;
END $$;


-- CONSTRAINT: remediation_plan_items unique_plan_finding
DO $$ BEGIN
  IF to_regclass('public.remediation_plan_items') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_plan_finding' AND conrelid = to_regclass('public.remediation_plan_items')
     ) THEN
    ALTER TABLE ONLY public.remediation_plan_items
        ADD CONSTRAINT unique_plan_finding UNIQUE (plan_id, finding_id);
  END IF;
END $$;


-- CONSTRAINT: platform_framework_controls unique_platform_control_per_framework
DO $$ BEGIN
  IF to_regclass('public.platform_framework_controls') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_platform_control_per_framework' AND conrelid = to_regclass('public.platform_framework_controls')
     ) THEN
    ALTER TABLE ONLY public.platform_framework_controls
        ADD CONSTRAINT unique_platform_control_per_framework UNIQUE (framework_id, control_id);
  END IF;
END $$;


-- CONSTRAINT: platform_frameworks unique_platform_framework_code_version
DO $$ BEGIN
  IF to_regclass('public.platform_frameworks') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_platform_framework_code_version' AND conrelid = to_regclass('public.platform_frameworks')
     ) THEN
    ALTER TABLE ONLY public.platform_frameworks
        ADD CONSTRAINT unique_platform_framework_code_version UNIQUE (code, version);
  END IF;
END $$;


-- CONSTRAINT: platform_refresh_tokens unique_platform_token_hash
DO $$ BEGIN
  IF to_regclass('public.platform_refresh_tokens') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_platform_token_hash' AND conrelid = to_regclass('public.platform_refresh_tokens')
     ) THEN
    ALTER TABLE ONLY public.platform_refresh_tokens
        ADD CONSTRAINT unique_platform_token_hash UNIQUE (token_hash);
  END IF;
END $$;


-- CONSTRAINT: sso_group_role_mappings unique_provider_group
DO $$ BEGIN
  IF to_regclass('public.sso_group_role_mappings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_provider_group' AND conrelid = to_regclass('public.sso_group_role_mappings')
     ) THEN
    ALTER TABLE ONLY public.sso_group_role_mappings
        ADD CONSTRAINT unique_provider_group UNIQUE (sso_provider_id, external_group_name);
  END IF;
END $$;


-- CONSTRAINT: sensor_certificates unique_sensor_serial
DO $$ BEGIN
  IF to_regclass('public.sensor_certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_sensor_serial' AND conrelid = to_regclass('public.sensor_certificates')
     ) THEN
    ALTER TABLE ONLY public.sensor_certificates
        ADD CONSTRAINT unique_sensor_serial UNIQUE (sensor_id, serial_number);
  END IF;
END $$;


-- CONSTRAINT: platform_bootstrap_certificates unique_service_name
DO $$ BEGIN
  IF to_regclass('public.platform_bootstrap_certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_service_name' AND conrelid = to_regclass('public.platform_bootstrap_certificates')
     ) THEN
    ALTER TABLE ONLY public.platform_bootstrap_certificates
        ADD CONSTRAINT unique_service_name UNIQUE (service_name);
  END IF;
END $$;


-- CONSTRAINT: platform_service_certificates unique_service_name_cert
DO $$ BEGIN
  IF to_regclass('public.platform_service_certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_service_name_cert' AND conrelid = to_regclass('public.platform_service_certificates')
     ) THEN
    ALTER TABLE ONLY public.platform_service_certificates
        ADD CONSTRAINT unique_service_name_cert UNIQUE (service_name);
  END IF;
END $$;


-- CONSTRAINT: platform_settings unique_setting_key
DO $$ BEGIN
  IF to_regclass('public.platform_settings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_setting_key' AND conrelid = to_regclass('public.platform_settings')
     ) THEN
    ALTER TABLE ONLY public.platform_settings
        ADD CONSTRAINT unique_setting_key UNIQUE (setting_key);
  END IF;
END $$;


-- CONSTRAINT: tenant_framework_controls unique_tenant_control_per_framework
DO $$ BEGIN
  IF to_regclass('public.tenant_framework_controls') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_tenant_control_per_framework' AND conrelid = to_regclass('public.tenant_framework_controls')
     ) THEN
    ALTER TABLE ONLY public.tenant_framework_controls
        ADD CONSTRAINT unique_tenant_control_per_framework UNIQUE (framework_id, control_id);
  END IF;
END $$;


-- CONSTRAINT: users unique_tenant_email
DO $$ BEGIN
  IF to_regclass('public.users') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_tenant_email' AND conrelid = to_regclass('public.users')
     ) THEN
    ALTER TABLE ONLY public.users
        ADD CONSTRAINT unique_tenant_email UNIQUE (tenant_id, email);
  END IF;
END $$;


-- CONSTRAINT: tenant_framework_licenses unique_tenant_framework_license
DO $$ BEGIN
  IF to_regclass('public.tenant_framework_licenses') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_tenant_framework_license' AND conrelid = to_regclass('public.tenant_framework_licenses')
     ) THEN
    ALTER TABLE ONLY public.tenant_framework_licenses
        ADD CONSTRAINT unique_tenant_framework_license UNIQUE (tenant_id, platform_framework_id);
  END IF;
END $$;


-- CONSTRAINT: tenant_frameworks unique_tenant_framework_name_version
DO $$ BEGIN
  IF to_regclass('public.tenant_frameworks') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_tenant_framework_name_version' AND conrelid = to_regclass('public.tenant_frameworks')
     ) THEN
    ALTER TABLE ONLY public.tenant_frameworks
        ADD CONSTRAINT unique_tenant_framework_name_version UNIQUE (tenant_id, name, version);
  END IF;
END $$;


-- CONSTRAINT: tenant_measurement_overrides unique_tenant_measurement_override
DO $$ BEGIN
  IF to_regclass('public.tenant_measurement_overrides') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_tenant_measurement_override' AND conrelid = to_regclass('public.tenant_measurement_overrides')
     ) THEN
    ALTER TABLE ONLY public.tenant_measurement_overrides
        ADD CONSTRAINT unique_tenant_measurement_override UNIQUE (tenant_id, control_measurement_id);
  END IF;
END $$;


-- CONSTRAINT: tenant_usage unique_tenant_period
DO $$ BEGIN
  IF to_regclass('public.tenant_usage') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_tenant_period' AND conrelid = to_regclass('public.tenant_usage')
     ) THEN
    ALTER TABLE ONLY public.tenant_usage
        ADD CONSTRAINT unique_tenant_period UNIQUE (tenant_id, billing_period_start);
  END IF;
END $$;


-- CONSTRAINT: api_format_preferences unique_tenant_preferences
DO $$ BEGIN
  IF to_regclass('public.api_format_preferences') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_tenant_preferences' AND conrelid = to_regclass('public.api_format_preferences')
     ) THEN
    ALTER TABLE ONLY public.api_format_preferences
        ADD CONSTRAINT unique_tenant_preferences UNIQUE (tenant_id);
  END IF;
END $$;


-- CONSTRAINT: sso_providers unique_tenant_provider
DO $$ BEGIN
  IF to_regclass('public.sso_providers') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_tenant_provider' AND conrelid = to_regclass('public.sso_providers')
     ) THEN
    ALTER TABLE ONLY public.sso_providers
        ADD CONSTRAINT unique_tenant_provider UNIQUE (tenant_id, provider_type, provider_name);
  END IF;
END $$;


-- CONSTRAINT: tenant_admin_settings unique_tenant_settings
DO $$ BEGIN
  IF to_regclass('public.tenant_admin_settings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_tenant_settings' AND conrelid = to_regclass('public.tenant_admin_settings')
     ) THEN
    ALTER TABLE ONLY public.tenant_admin_settings
        ADD CONSTRAINT unique_tenant_settings PRIMARY KEY (tenant_id);
  END IF;
END $$;


-- CONSTRAINT: workflow_configurations unique_tenant_workflow
DO $$ BEGIN
  IF to_regclass('public.workflow_configurations') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_tenant_workflow' AND conrelid = to_regclass('public.workflow_configurations')
     ) THEN
    ALTER TABLE ONLY public.workflow_configurations
        ADD CONSTRAINT unique_tenant_workflow UNIQUE (tenant_id, workflow_type, workflow_name);
  END IF;
END $$;


-- CONSTRAINT: refresh_tokens unique_token_hash
DO $$ BEGIN
  IF to_regclass('public.refresh_tokens') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_token_hash' AND conrelid = to_regclass('public.refresh_tokens')
     ) THEN
    ALTER TABLE ONLY public.refresh_tokens
        ADD CONSTRAINT unique_token_hash UNIQUE (token_hash);
  END IF;
END $$;


-- CONSTRAINT: user_auth_methods unique_user_auth_type
DO $$ BEGIN
  IF to_regclass('public.user_auth_methods') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_user_auth_type' AND conrelid = to_regclass('public.user_auth_methods')
     ) THEN
    ALTER TABLE ONLY public.user_auth_methods
        ADD CONSTRAINT unique_user_auth_type UNIQUE (user_id, auth_type, sso_provider_id);
  END IF;
END $$;


-- CONSTRAINT: user_framework_preferences unique_user_framework_preference
DO $$ BEGIN
  IF to_regclass('public.user_framework_preferences') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_user_framework_preference' AND conrelid = to_regclass('public.user_framework_preferences')
     ) THEN
    ALTER TABLE ONLY public.user_framework_preferences
        ADD CONSTRAINT unique_user_framework_preference UNIQUE (user_id, tenant_id);
  END IF;
END $$;


-- CONSTRAINT: user_workflow_progress unique_user_workflow
DO $$ BEGIN
  IF to_regclass('public.user_workflow_progress') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'unique_user_workflow' AND conrelid = to_regclass('public.user_workflow_progress')
     ) THEN
    ALTER TABLE ONLY public.user_workflow_progress
        ADD CONSTRAINT unique_user_workflow UNIQUE (user_id, workflow_configuration_id);
  END IF;
END $$;


-- CONSTRAINT: external_connections uq_external_connection
DO $$ BEGIN
  IF to_regclass('public.external_connections') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'uq_external_connection' AND conrelid = to_regclass('public.external_connections')
     ) THEN
    ALTER TABLE ONLY public.external_connections
        ADD CONSTRAINT uq_external_connection UNIQUE (tenant_id, source_ip, dest_ip, dest_port, protocol);
  END IF;
END $$;


-- CONSTRAINT: user_auth_methods user_auth_methods_pkey
DO $$ BEGIN
  IF to_regclass('public.user_auth_methods') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'user_auth_methods_pkey' AND conrelid = to_regclass('public.user_auth_methods')
     ) THEN
    ALTER TABLE ONLY public.user_auth_methods
        ADD CONSTRAINT user_auth_methods_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: user_framework_preferences user_framework_preferences_pkey
DO $$ BEGIN
  IF to_regclass('public.user_framework_preferences') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'user_framework_preferences_pkey' AND conrelid = to_regclass('public.user_framework_preferences')
     ) THEN
    ALTER TABLE ONLY public.user_framework_preferences
        ADD CONSTRAINT user_framework_preferences_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: user_tenant_roles user_tenant_roles_pkey
DO $$ BEGIN
  IF to_regclass('public.user_tenant_roles') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'user_tenant_roles_pkey' AND conrelid = to_regclass('public.user_tenant_roles')
     ) THEN
    ALTER TABLE ONLY public.user_tenant_roles
        ADD CONSTRAINT user_tenant_roles_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: user_tenant_roles user_tenant_roles_user_id_tenant_id_role_id_key
DO $$ BEGIN
  IF to_regclass('public.user_tenant_roles') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'user_tenant_roles_user_id_tenant_id_role_id_key' AND conrelid = to_regclass('public.user_tenant_roles')
     ) THEN
    ALTER TABLE ONLY public.user_tenant_roles
        ADD CONSTRAINT user_tenant_roles_user_id_tenant_id_role_id_key UNIQUE (user_id, tenant_id, role_id);
  END IF;
END $$;


-- CONSTRAINT: user_workflow_progress user_workflow_progress_pkey
DO $$ BEGIN
  IF to_regclass('public.user_workflow_progress') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'user_workflow_progress_pkey' AND conrelid = to_regclass('public.user_workflow_progress')
     ) THEN
    ALTER TABLE ONLY public.user_workflow_progress
        ADD CONSTRAINT user_workflow_progress_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: users users_pkey
DO $$ BEGIN
  IF to_regclass('public.users') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'users_pkey' AND conrelid = to_regclass('public.users')
     ) THEN
    ALTER TABLE ONLY public.users
        ADD CONSTRAINT users_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- CONSTRAINT: workflow_configurations workflow_configurations_pkey
DO $$ BEGIN
  IF to_regclass('public.workflow_configurations') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'workflow_configurations_pkey' AND conrelid = to_regclass('public.workflow_configurations')
     ) THEN
    ALTER TABLE ONLY public.workflow_configurations
        ADD CONSTRAINT workflow_configurations_pkey PRIMARY KEY (id);
  END IF;
END $$;


-- INDEX: idx_activity_logs_action
CREATE INDEX IF NOT EXISTS idx_activity_logs_action ON ONLY audit.activity_logs USING btree (action, occurred_at DESC);


-- INDEX: activity_logs_y2026m04_action_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m04_action_occurred_at_idx ON audit.activity_logs_y2026m04 USING btree (action, occurred_at DESC);


-- INDEX: idx_activity_logs_compliance
CREATE INDEX IF NOT EXISTS idx_activity_logs_compliance ON ONLY audit.activity_logs USING gin (compliance_tags);


-- INDEX: activity_logs_y2026m04_compliance_tags_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m04_compliance_tags_idx ON audit.activity_logs_y2026m04 USING gin (compliance_tags);


-- INDEX: idx_activity_logs_category
CREATE INDEX IF NOT EXISTS idx_activity_logs_category ON ONLY audit.activity_logs USING btree (event_category, occurred_at DESC);


-- INDEX: activity_logs_y2026m04_event_category_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m04_event_category_occurred_at_idx ON audit.activity_logs_y2026m04 USING btree (event_category, occurred_at DESC);


-- INDEX: idx_activity_logs_event_type
CREATE INDEX IF NOT EXISTS idx_activity_logs_event_type ON ONLY audit.activity_logs USING btree (event_type, occurred_at DESC);


-- INDEX: activity_logs_y2026m04_event_type_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m04_event_type_occurred_at_idx ON audit.activity_logs_y2026m04 USING btree (event_type, occurred_at DESC);


-- INDEX: idx_activity_logs_occurred_at
CREATE INDEX IF NOT EXISTS idx_activity_logs_occurred_at ON ONLY audit.activity_logs USING btree (occurred_at DESC);


-- INDEX: activity_logs_y2026m04_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m04_occurred_at_idx ON audit.activity_logs_y2026m04 USING btree (occurred_at DESC);


-- INDEX: idx_activity_logs_request_id
CREATE INDEX IF NOT EXISTS idx_activity_logs_request_id ON ONLY audit.activity_logs USING btree (request_id, occurred_at DESC) WHERE (request_id IS NOT NULL);


-- INDEX: activity_logs_y2026m04_request_id_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m04_request_id_occurred_at_idx ON audit.activity_logs_y2026m04 USING btree (request_id, occurred_at DESC) WHERE (request_id IS NOT NULL);


-- INDEX: idx_activity_logs_requires_attention
CREATE INDEX IF NOT EXISTS idx_activity_logs_requires_attention ON ONLY audit.activity_logs USING btree (requires_attention, occurred_at DESC) WHERE (requires_attention = true);


-- INDEX: activity_logs_y2026m04_requires_attention_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m04_requires_attention_occurred_at_idx ON audit.activity_logs_y2026m04 USING btree (requires_attention, occurred_at DESC) WHERE (requires_attention = true);


-- INDEX: idx_activity_logs_resource
CREATE INDEX IF NOT EXISTS idx_activity_logs_resource ON ONLY audit.activity_logs USING btree (resource_type, resource_id, occurred_at DESC) WHERE ((resource_type IS NOT NULL) AND (resource_id IS NOT NULL));


-- INDEX: activity_logs_y2026m04_resource_type_resource_id_occurred_a_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m04_resource_type_resource_id_occurred_a_idx ON audit.activity_logs_y2026m04 USING btree (resource_type, resource_id, occurred_at DESC) WHERE ((resource_type IS NOT NULL) AND (resource_id IS NOT NULL));


-- INDEX: idx_activity_logs_success
CREATE INDEX IF NOT EXISTS idx_activity_logs_success ON ONLY audit.activity_logs USING btree (success, occurred_at DESC) WHERE (success = false);


-- INDEX: activity_logs_y2026m04_success_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m04_success_occurred_at_idx ON audit.activity_logs_y2026m04 USING btree (success, occurred_at DESC) WHERE (success = false);


-- INDEX: idx_activity_logs_tenant_time
CREATE INDEX IF NOT EXISTS idx_activity_logs_tenant_time ON ONLY audit.activity_logs USING btree (tenant_id, occurred_at DESC) WHERE (tenant_id IS NOT NULL);


-- INDEX: activity_logs_y2026m04_tenant_id_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m04_tenant_id_occurred_at_idx ON audit.activity_logs_y2026m04 USING btree (tenant_id, occurred_at DESC) WHERE (tenant_id IS NOT NULL);


-- INDEX: idx_activity_logs_user_time
CREATE INDEX IF NOT EXISTS idx_activity_logs_user_time ON ONLY audit.activity_logs USING btree (user_id, occurred_at DESC) WHERE (user_id IS NOT NULL);


-- INDEX: activity_logs_y2026m04_user_id_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m04_user_id_occurred_at_idx ON audit.activity_logs_y2026m04 USING btree (user_id, occurred_at DESC) WHERE (user_id IS NOT NULL);


-- INDEX: idx_activity_logs_user_type
CREATE INDEX IF NOT EXISTS idx_activity_logs_user_type ON ONLY audit.activity_logs USING btree (user_type, occurred_at DESC);


-- INDEX: activity_logs_y2026m04_user_type_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m04_user_type_occurred_at_idx ON audit.activity_logs_y2026m04 USING btree (user_type, occurred_at DESC);


-- INDEX: activity_logs_y2026m05_action_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m05_action_occurred_at_idx ON audit.activity_logs_y2026m05 USING btree (action, occurred_at DESC);


-- INDEX: activity_logs_y2026m05_compliance_tags_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m05_compliance_tags_idx ON audit.activity_logs_y2026m05 USING gin (compliance_tags);


-- INDEX: activity_logs_y2026m05_event_category_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m05_event_category_occurred_at_idx ON audit.activity_logs_y2026m05 USING btree (event_category, occurred_at DESC);


-- INDEX: activity_logs_y2026m05_event_type_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m05_event_type_occurred_at_idx ON audit.activity_logs_y2026m05 USING btree (event_type, occurred_at DESC);


-- INDEX: activity_logs_y2026m05_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m05_occurred_at_idx ON audit.activity_logs_y2026m05 USING btree (occurred_at DESC);


-- INDEX: activity_logs_y2026m05_request_id_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m05_request_id_occurred_at_idx ON audit.activity_logs_y2026m05 USING btree (request_id, occurred_at DESC) WHERE (request_id IS NOT NULL);


-- INDEX: activity_logs_y2026m05_requires_attention_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m05_requires_attention_occurred_at_idx ON audit.activity_logs_y2026m05 USING btree (requires_attention, occurred_at DESC) WHERE (requires_attention = true);


-- INDEX: activity_logs_y2026m05_resource_type_resource_id_occurred_a_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m05_resource_type_resource_id_occurred_a_idx ON audit.activity_logs_y2026m05 USING btree (resource_type, resource_id, occurred_at DESC) WHERE ((resource_type IS NOT NULL) AND (resource_id IS NOT NULL));


-- INDEX: activity_logs_y2026m05_success_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m05_success_occurred_at_idx ON audit.activity_logs_y2026m05 USING btree (success, occurred_at DESC) WHERE (success = false);


-- INDEX: activity_logs_y2026m05_tenant_id_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m05_tenant_id_occurred_at_idx ON audit.activity_logs_y2026m05 USING btree (tenant_id, occurred_at DESC) WHERE (tenant_id IS NOT NULL);


-- INDEX: activity_logs_y2026m05_user_id_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m05_user_id_occurred_at_idx ON audit.activity_logs_y2026m05 USING btree (user_id, occurred_at DESC) WHERE (user_id IS NOT NULL);


-- INDEX: activity_logs_y2026m05_user_type_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m05_user_type_occurred_at_idx ON audit.activity_logs_y2026m05 USING btree (user_type, occurred_at DESC);


-- INDEX: activity_logs_y2026m06_action_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m06_action_occurred_at_idx ON audit.activity_logs_y2026m06 USING btree (action, occurred_at DESC);


-- INDEX: activity_logs_y2026m06_compliance_tags_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m06_compliance_tags_idx ON audit.activity_logs_y2026m06 USING gin (compliance_tags);


-- INDEX: activity_logs_y2026m06_event_category_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m06_event_category_occurred_at_idx ON audit.activity_logs_y2026m06 USING btree (event_category, occurred_at DESC);


-- INDEX: activity_logs_y2026m06_event_type_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m06_event_type_occurred_at_idx ON audit.activity_logs_y2026m06 USING btree (event_type, occurred_at DESC);


-- INDEX: activity_logs_y2026m06_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m06_occurred_at_idx ON audit.activity_logs_y2026m06 USING btree (occurred_at DESC);


-- INDEX: activity_logs_y2026m06_request_id_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m06_request_id_occurred_at_idx ON audit.activity_logs_y2026m06 USING btree (request_id, occurred_at DESC) WHERE (request_id IS NOT NULL);


-- INDEX: activity_logs_y2026m06_requires_attention_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m06_requires_attention_occurred_at_idx ON audit.activity_logs_y2026m06 USING btree (requires_attention, occurred_at DESC) WHERE (requires_attention = true);


-- INDEX: activity_logs_y2026m06_resource_type_resource_id_occurred_a_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m06_resource_type_resource_id_occurred_a_idx ON audit.activity_logs_y2026m06 USING btree (resource_type, resource_id, occurred_at DESC) WHERE ((resource_type IS NOT NULL) AND (resource_id IS NOT NULL));


-- INDEX: activity_logs_y2026m06_success_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m06_success_occurred_at_idx ON audit.activity_logs_y2026m06 USING btree (success, occurred_at DESC) WHERE (success = false);


-- INDEX: activity_logs_y2026m06_tenant_id_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m06_tenant_id_occurred_at_idx ON audit.activity_logs_y2026m06 USING btree (tenant_id, occurred_at DESC) WHERE (tenant_id IS NOT NULL);


-- INDEX: activity_logs_y2026m06_user_id_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m06_user_id_occurred_at_idx ON audit.activity_logs_y2026m06 USING btree (user_id, occurred_at DESC) WHERE (user_id IS NOT NULL);


-- INDEX: activity_logs_y2026m06_user_type_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m06_user_type_occurred_at_idx ON audit.activity_logs_y2026m06 USING btree (user_type, occurred_at DESC);


-- INDEX: activity_logs_y2026m07_action_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m07_action_occurred_at_idx ON audit.activity_logs_y2026m07 USING btree (action, occurred_at DESC);


-- INDEX: activity_logs_y2026m07_compliance_tags_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m07_compliance_tags_idx ON audit.activity_logs_y2026m07 USING gin (compliance_tags);


-- INDEX: activity_logs_y2026m07_event_category_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m07_event_category_occurred_at_idx ON audit.activity_logs_y2026m07 USING btree (event_category, occurred_at DESC);


-- INDEX: activity_logs_y2026m07_event_type_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m07_event_type_occurred_at_idx ON audit.activity_logs_y2026m07 USING btree (event_type, occurred_at DESC);


-- INDEX: activity_logs_y2026m07_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m07_occurred_at_idx ON audit.activity_logs_y2026m07 USING btree (occurred_at DESC);


-- INDEX: activity_logs_y2026m07_request_id_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m07_request_id_occurred_at_idx ON audit.activity_logs_y2026m07 USING btree (request_id, occurred_at DESC) WHERE (request_id IS NOT NULL);


-- INDEX: activity_logs_y2026m07_requires_attention_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m07_requires_attention_occurred_at_idx ON audit.activity_logs_y2026m07 USING btree (requires_attention, occurred_at DESC) WHERE (requires_attention = true);


-- INDEX: activity_logs_y2026m07_resource_type_resource_id_occurred_a_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m07_resource_type_resource_id_occurred_a_idx ON audit.activity_logs_y2026m07 USING btree (resource_type, resource_id, occurred_at DESC) WHERE ((resource_type IS NOT NULL) AND (resource_id IS NOT NULL));


-- INDEX: activity_logs_y2026m07_success_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m07_success_occurred_at_idx ON audit.activity_logs_y2026m07 USING btree (success, occurred_at DESC) WHERE (success = false);


-- INDEX: activity_logs_y2026m07_tenant_id_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m07_tenant_id_occurred_at_idx ON audit.activity_logs_y2026m07 USING btree (tenant_id, occurred_at DESC) WHERE (tenant_id IS NOT NULL);


-- INDEX: activity_logs_y2026m07_user_id_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m07_user_id_occurred_at_idx ON audit.activity_logs_y2026m07 USING btree (user_id, occurred_at DESC) WHERE (user_id IS NOT NULL);


-- INDEX: activity_logs_y2026m07_user_type_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m07_user_type_occurred_at_idx ON audit.activity_logs_y2026m07 USING btree (user_type, occurred_at DESC);


-- INDEX: activity_logs_y2026m08_action_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m08_action_occurred_at_idx ON audit.activity_logs_y2026m08 USING btree (action, occurred_at DESC);


-- INDEX: activity_logs_y2026m08_compliance_tags_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m08_compliance_tags_idx ON audit.activity_logs_y2026m08 USING gin (compliance_tags);


-- INDEX: activity_logs_y2026m08_event_category_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m08_event_category_occurred_at_idx ON audit.activity_logs_y2026m08 USING btree (event_category, occurred_at DESC);


-- INDEX: activity_logs_y2026m08_event_type_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m08_event_type_occurred_at_idx ON audit.activity_logs_y2026m08 USING btree (event_type, occurred_at DESC);


-- INDEX: activity_logs_y2026m08_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m08_occurred_at_idx ON audit.activity_logs_y2026m08 USING btree (occurred_at DESC);


-- INDEX: activity_logs_y2026m08_request_id_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m08_request_id_occurred_at_idx ON audit.activity_logs_y2026m08 USING btree (request_id, occurred_at DESC) WHERE (request_id IS NOT NULL);


-- INDEX: activity_logs_y2026m08_requires_attention_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m08_requires_attention_occurred_at_idx ON audit.activity_logs_y2026m08 USING btree (requires_attention, occurred_at DESC) WHERE (requires_attention = true);


-- INDEX: activity_logs_y2026m08_resource_type_resource_id_occurred_a_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m08_resource_type_resource_id_occurred_a_idx ON audit.activity_logs_y2026m08 USING btree (resource_type, resource_id, occurred_at DESC) WHERE ((resource_type IS NOT NULL) AND (resource_id IS NOT NULL));


-- INDEX: activity_logs_y2026m08_success_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m08_success_occurred_at_idx ON audit.activity_logs_y2026m08 USING btree (success, occurred_at DESC) WHERE (success = false);


-- INDEX: activity_logs_y2026m08_tenant_id_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m08_tenant_id_occurred_at_idx ON audit.activity_logs_y2026m08 USING btree (tenant_id, occurred_at DESC) WHERE (tenant_id IS NOT NULL);


-- INDEX: activity_logs_y2026m08_user_id_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m08_user_id_occurred_at_idx ON audit.activity_logs_y2026m08 USING btree (user_id, occurred_at DESC) WHERE (user_id IS NOT NULL);


-- INDEX: activity_logs_y2026m08_user_type_occurred_at_idx
CREATE INDEX IF NOT EXISTS activity_logs_y2026m08_user_type_occurred_at_idx ON audit.activity_logs_y2026m08 USING btree (user_type, occurred_at DESC);


-- INDEX: idx_alert_instances_created
CREATE INDEX IF NOT EXISTS idx_alert_instances_created ON audit.alert_instances USING btree (created_at DESC);


-- INDEX: idx_alert_instances_rule
CREATE INDEX IF NOT EXISTS idx_alert_instances_rule ON audit.alert_instances USING btree (rule_id);


-- INDEX: idx_alert_instances_severity
CREATE INDEX IF NOT EXISTS idx_alert_instances_severity ON audit.alert_instances USING btree (severity);


-- INDEX: idx_alert_instances_status
CREATE INDEX IF NOT EXISTS idx_alert_instances_status ON audit.alert_instances USING btree (status);


-- INDEX: idx_alert_instances_tenant
CREATE INDEX IF NOT EXISTS idx_alert_instances_tenant ON audit.alert_instances USING btree (tenant_id) WHERE (tenant_id IS NOT NULL);


-- INDEX: idx_alert_rules_enabled
CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled ON audit.alert_rules USING btree (is_enabled) WHERE (is_enabled = true);


-- INDEX: idx_alert_rules_severity
CREATE INDEX IF NOT EXISTS idx_alert_rules_severity ON audit.alert_rules USING btree (severity);


-- INDEX: idx_alert_rules_tenant
CREATE INDEX IF NOT EXISTS idx_alert_rules_tenant ON audit.alert_rules USING btree (tenant_id) WHERE (tenant_id IS NOT NULL);


-- INDEX: idx_alert_rules_type
CREATE INDEX IF NOT EXISTS idx_alert_rules_type ON audit.alert_rules USING btree (rule_type);


-- INDEX: idx_audit_logs_created_at
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit.audit_logs USING btree (created_at);


-- INDEX: idx_job_execution_logs_initiated_by
CREATE INDEX IF NOT EXISTS idx_job_execution_logs_initiated_by ON audit.job_execution_logs USING btree (initiated_by, started_at DESC) WHERE (initiated_by IS NOT NULL);


-- INDEX: idx_job_execution_logs_job_id
CREATE INDEX IF NOT EXISTS idx_job_execution_logs_job_id ON audit.job_execution_logs USING btree (job_id, started_at DESC);


-- INDEX: idx_job_execution_logs_job_type
CREATE INDEX IF NOT EXISTS idx_job_execution_logs_job_type ON audit.job_execution_logs USING btree (job_type, started_at DESC);


-- INDEX: idx_job_execution_logs_started_at
CREATE INDEX IF NOT EXISTS idx_job_execution_logs_started_at ON audit.job_execution_logs USING btree (started_at DESC);


-- INDEX: idx_job_execution_logs_status
CREATE INDEX IF NOT EXISTS idx_job_execution_logs_status ON audit.job_execution_logs USING btree (status, started_at DESC);


-- INDEX: idx_job_execution_logs_tenant
CREATE INDEX IF NOT EXISTS idx_job_execution_logs_tenant ON audit.job_execution_logs USING btree (tenant_id, started_at DESC) WHERE (tenant_id IS NOT NULL);


-- INDEX: idx_report_executions_schedule
CREATE INDEX IF NOT EXISTS idx_report_executions_schedule ON audit.scheduled_report_executions USING btree (schedule_id);


-- INDEX: idx_report_executions_started
CREATE INDEX IF NOT EXISTS idx_report_executions_started ON audit.scheduled_report_executions USING btree (started_at DESC);


-- INDEX: idx_report_executions_status
CREATE INDEX IF NOT EXISTS idx_report_executions_status ON audit.scheduled_report_executions USING btree (status);


-- INDEX: idx_report_executions_tenant
CREATE INDEX IF NOT EXISTS idx_report_executions_tenant ON audit.scheduled_report_executions USING btree (tenant_id);


-- INDEX: idx_retention_jobs_policy
CREATE INDEX IF NOT EXISTS idx_retention_jobs_policy ON audit.retention_jobs USING btree (policy_id, started_at DESC);


-- INDEX: idx_retention_jobs_started_at
CREATE INDEX IF NOT EXISTS idx_retention_jobs_started_at ON audit.retention_jobs USING btree (started_at DESC);


-- INDEX: idx_retention_jobs_type
CREATE INDEX IF NOT EXISTS idx_retention_jobs_type ON audit.retention_jobs USING btree (job_type, started_at DESC);


-- INDEX: idx_scheduled_reports_enabled
CREATE INDEX IF NOT EXISTS idx_scheduled_reports_enabled ON audit.scheduled_compliance_reports USING btree (is_enabled) WHERE (is_enabled = true);


-- INDEX: idx_scheduled_reports_next_run
CREATE INDEX IF NOT EXISTS idx_scheduled_reports_next_run ON audit.scheduled_compliance_reports USING btree (next_run_at) WHERE ((is_enabled = true) AND (next_run_at IS NOT NULL));


-- INDEX: idx_scheduled_reports_tenant
CREATE INDEX IF NOT EXISTS idx_scheduled_reports_tenant ON audit.scheduled_compliance_reports USING btree (tenant_id);


-- INDEX: idx_siem_health_checks_checked_at
CREATE INDEX IF NOT EXISTS idx_siem_health_checks_checked_at ON audit.siem_health_checks USING btree (checked_at DESC);


-- INDEX: idx_siem_health_checks_integration
CREATE INDEX IF NOT EXISTS idx_siem_health_checks_integration ON audit.siem_health_checks USING btree (integration_id);


-- INDEX: idx_siem_integrations_enabled
CREATE INDEX IF NOT EXISTS idx_siem_integrations_enabled ON audit.siem_integrations USING btree (enabled) WHERE (enabled = true);


-- INDEX: idx_siem_integrations_health
CREATE INDEX IF NOT EXISTS idx_siem_integrations_health ON audit.siem_integrations USING btree (health_status);


-- INDEX: idx_siem_integrations_tenant
CREATE INDEX IF NOT EXISTS idx_siem_integrations_tenant ON audit.siem_integrations USING btree (tenant_id) WHERE (tenant_id IS NOT NULL);


-- INDEX: idx_crypto_implementations_partitioned_asset_id
CREATE INDEX IF NOT EXISTS idx_crypto_implementations_partitioned_asset_id ON ONLY public.crypto_implementations_partitioned USING btree (asset_id);


-- INDEX: crypto_implementations_part_0_asset_id_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_0_asset_id_idx ON public.crypto_implementations_part_0 USING btree (asset_id);


-- INDEX: idx_crypto_implementations_partitioned_deleted_at
CREATE INDEX IF NOT EXISTS idx_crypto_implementations_partitioned_deleted_at ON ONLY public.crypto_implementations_partitioned USING btree (deleted_at) WHERE (deleted_at IS NULL);


-- INDEX: crypto_implementations_part_0_deleted_at_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_0_deleted_at_idx ON public.crypto_implementations_part_0 USING btree (deleted_at) WHERE (deleted_at IS NULL);


-- INDEX: idx_crypto_implementations_partitioned_risk_score
CREATE INDEX IF NOT EXISTS idx_crypto_implementations_partitioned_risk_score ON ONLY public.crypto_implementations_partitioned USING btree (risk_score);


-- INDEX: crypto_implementations_part_0_risk_score_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_0_risk_score_idx ON public.crypto_implementations_part_0 USING btree (risk_score);


-- INDEX: idx_crypto_implementations_partitioned_tenant_id
CREATE INDEX IF NOT EXISTS idx_crypto_implementations_partitioned_tenant_id ON ONLY public.crypto_implementations_partitioned USING btree (tenant_id);


-- INDEX: crypto_implementations_part_0_tenant_id_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_0_tenant_id_idx ON public.crypto_implementations_part_0 USING btree (tenant_id);


-- INDEX: crypto_implementations_part_1_asset_id_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_1_asset_id_idx ON public.crypto_implementations_part_1 USING btree (asset_id);


-- INDEX: crypto_implementations_part_1_deleted_at_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_1_deleted_at_idx ON public.crypto_implementations_part_1 USING btree (deleted_at) WHERE (deleted_at IS NULL);


-- INDEX: crypto_implementations_part_1_risk_score_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_1_risk_score_idx ON public.crypto_implementations_part_1 USING btree (risk_score);


-- INDEX: crypto_implementations_part_1_tenant_id_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_1_tenant_id_idx ON public.crypto_implementations_part_1 USING btree (tenant_id);


-- INDEX: crypto_implementations_part_2_asset_id_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_2_asset_id_idx ON public.crypto_implementations_part_2 USING btree (asset_id);


-- INDEX: crypto_implementations_part_2_deleted_at_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_2_deleted_at_idx ON public.crypto_implementations_part_2 USING btree (deleted_at) WHERE (deleted_at IS NULL);


-- INDEX: crypto_implementations_part_2_risk_score_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_2_risk_score_idx ON public.crypto_implementations_part_2 USING btree (risk_score);


-- INDEX: crypto_implementations_part_2_tenant_id_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_2_tenant_id_idx ON public.crypto_implementations_part_2 USING btree (tenant_id);


-- INDEX: crypto_implementations_part_3_asset_id_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_3_asset_id_idx ON public.crypto_implementations_part_3 USING btree (asset_id);


-- INDEX: crypto_implementations_part_3_deleted_at_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_3_deleted_at_idx ON public.crypto_implementations_part_3 USING btree (deleted_at) WHERE (deleted_at IS NULL);


-- INDEX: crypto_implementations_part_3_risk_score_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_3_risk_score_idx ON public.crypto_implementations_part_3 USING btree (risk_score);


-- INDEX: crypto_implementations_part_3_tenant_id_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_3_tenant_id_idx ON public.crypto_implementations_part_3 USING btree (tenant_id);


-- INDEX: crypto_implementations_part_4_asset_id_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_4_asset_id_idx ON public.crypto_implementations_part_4 USING btree (asset_id);


-- INDEX: crypto_implementations_part_4_deleted_at_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_4_deleted_at_idx ON public.crypto_implementations_part_4 USING btree (deleted_at) WHERE (deleted_at IS NULL);


-- INDEX: crypto_implementations_part_4_risk_score_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_4_risk_score_idx ON public.crypto_implementations_part_4 USING btree (risk_score);


-- INDEX: crypto_implementations_part_4_tenant_id_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_4_tenant_id_idx ON public.crypto_implementations_part_4 USING btree (tenant_id);


-- INDEX: crypto_implementations_part_5_asset_id_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_5_asset_id_idx ON public.crypto_implementations_part_5 USING btree (asset_id);


-- INDEX: crypto_implementations_part_5_deleted_at_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_5_deleted_at_idx ON public.crypto_implementations_part_5 USING btree (deleted_at) WHERE (deleted_at IS NULL);


-- INDEX: crypto_implementations_part_5_risk_score_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_5_risk_score_idx ON public.crypto_implementations_part_5 USING btree (risk_score);


-- INDEX: crypto_implementations_part_5_tenant_id_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_5_tenant_id_idx ON public.crypto_implementations_part_5 USING btree (tenant_id);


-- INDEX: crypto_implementations_part_6_asset_id_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_6_asset_id_idx ON public.crypto_implementations_part_6 USING btree (asset_id);


-- INDEX: crypto_implementations_part_6_deleted_at_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_6_deleted_at_idx ON public.crypto_implementations_part_6 USING btree (deleted_at) WHERE (deleted_at IS NULL);


-- INDEX: crypto_implementations_part_6_risk_score_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_6_risk_score_idx ON public.crypto_implementations_part_6 USING btree (risk_score);


-- INDEX: crypto_implementations_part_6_tenant_id_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_6_tenant_id_idx ON public.crypto_implementations_part_6 USING btree (tenant_id);


-- INDEX: crypto_implementations_part_7_asset_id_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_7_asset_id_idx ON public.crypto_implementations_part_7 USING btree (asset_id);


-- INDEX: crypto_implementations_part_7_deleted_at_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_7_deleted_at_idx ON public.crypto_implementations_part_7 USING btree (deleted_at) WHERE (deleted_at IS NULL);


-- INDEX: crypto_implementations_part_7_risk_score_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_7_risk_score_idx ON public.crypto_implementations_part_7 USING btree (risk_score);


-- INDEX: crypto_implementations_part_7_tenant_id_idx
CREATE INDEX IF NOT EXISTS crypto_implementations_part_7_tenant_id_idx ON public.crypto_implementations_part_7 USING btree (tenant_id);


-- INDEX: idx_access_pattern_anomaly
CREATE INDEX IF NOT EXISTS idx_access_pattern_anomaly ON public.access_pattern_analysis USING btree (is_anomaly, anomaly_score DESC) WHERE (is_anomaly = true);


-- INDEX: idx_access_pattern_tenant
CREATE INDEX IF NOT EXISTS idx_access_pattern_tenant ON public.access_pattern_analysis USING btree (tenant_id, analyzed_at DESC) WHERE (tenant_id IS NOT NULL);


-- INDEX: idx_access_pattern_type
CREATE INDEX IF NOT EXISTS idx_access_pattern_type ON public.access_pattern_analysis USING btree (pattern_type, analyzed_at DESC);


-- INDEX: idx_agent_ca_certificates_active
CREATE INDEX IF NOT EXISTS idx_agent_ca_certificates_active ON public.agent_ca_certificates USING btree (tenant_id, is_active) WHERE (is_active = true);


-- INDEX: idx_agent_ca_certificates_expires_at
CREATE INDEX IF NOT EXISTS idx_agent_ca_certificates_expires_at ON public.agent_ca_certificates USING btree (expires_at);


-- INDEX: idx_agent_ca_certificates_tenant_id
CREATE INDEX IF NOT EXISTS idx_agent_ca_certificates_tenant_id ON public.agent_ca_certificates USING btree (tenant_id);


-- INDEX: idx_agent_certificates_agent_id
CREATE INDEX IF NOT EXISTS idx_agent_certificates_agent_id ON public.agent_certificates USING btree (agent_id);


-- INDEX: idx_agent_certificates_expires_at
CREATE INDEX IF NOT EXISTS idx_agent_certificates_expires_at ON public.agent_certificates USING btree (expires_at);


-- INDEX: idx_agent_certificates_revoked
CREATE INDEX IF NOT EXISTS idx_agent_certificates_revoked ON public.agent_certificates USING btree (agent_id, revoked_at) WHERE (revoked_at IS NOT NULL);


-- INDEX: idx_agent_certificates_tenant_id
CREATE INDEX IF NOT EXISTS idx_agent_certificates_tenant_id ON public.agent_certificates USING btree (tenant_id);


-- INDEX: idx_ai_analysis_results_created_at
CREATE INDEX IF NOT EXISTS idx_ai_analysis_results_created_at ON public.ai_analysis_results USING btree (created_at);


-- INDEX: idx_ai_analysis_results_tenant_type
CREATE INDEX IF NOT EXISTS idx_ai_analysis_results_tenant_type ON public.ai_analysis_results USING btree (tenant_id, target_type, analysis_type);


-- INDEX: idx_alert_history_service_name
CREATE INDEX IF NOT EXISTS idx_alert_history_service_name ON public.monitoring_alert_history USING btree (service_name);


-- INDEX: idx_alert_history_service_status
CREATE INDEX IF NOT EXISTS idx_alert_history_service_status ON public.monitoring_alert_history USING btree (service_name, status);


-- INDEX: idx_alert_history_status
CREATE INDEX IF NOT EXISTS idx_alert_history_status ON public.monitoring_alert_history USING btree (status);


-- INDEX: idx_alert_history_threshold_id
CREATE INDEX IF NOT EXISTS idx_alert_history_threshold_id ON public.monitoring_alert_history USING btree (threshold_id);


-- INDEX: idx_alert_history_triggered_at
CREATE INDEX IF NOT EXISTS idx_alert_history_triggered_at ON public.monitoring_alert_history USING btree (triggered_at DESC);


-- INDEX: idx_alert_thresholds_enabled
CREATE INDEX IF NOT EXISTS idx_alert_thresholds_enabled ON public.monitoring_alert_thresholds USING btree (enabled);


-- INDEX: idx_alert_thresholds_metric_type
CREATE INDEX IF NOT EXISTS idx_alert_thresholds_metric_type ON public.monitoring_alert_thresholds USING btree (metric_type);


-- INDEX: idx_alert_thresholds_service_name
CREATE INDEX IF NOT EXISTS idx_alert_thresholds_service_name ON public.monitoring_alert_thresholds USING btree (service_name);


-- INDEX: idx_algorithms_category
CREATE INDEX IF NOT EXISTS idx_algorithms_category ON public.algorithms USING btree (category);


-- INDEX: idx_algorithms_code
CREATE INDEX IF NOT EXISTS idx_algorithms_code ON public.algorithms USING btree (code);


-- INDEX: idx_algorithms_family
CREATE INDEX IF NOT EXISTS idx_algorithms_family ON public.algorithms USING btree (algorithm_family) WHERE (algorithm_family IS NOT NULL);


-- INDEX: idx_algorithms_oid
CREATE INDEX IF NOT EXISTS idx_algorithms_oid ON public.algorithms USING btree (oid) WHERE (oid IS NOT NULL);


-- INDEX: idx_algorithms_pqc
CREATE INDEX IF NOT EXISTS idx_algorithms_pqc ON public.algorithms USING btree (is_pqc, pqc_standardization_status);


-- INDEX: idx_algorithms_primitive
CREATE INDEX IF NOT EXISTS idx_algorithms_primitive ON public.algorithms USING btree (primitive) WHERE (primitive IS NOT NULL);


-- INDEX: idx_algorithms_quantum_level
CREATE INDEX IF NOT EXISTS idx_algorithms_quantum_level ON public.algorithms USING btree (nist_quantum_security_level) WHERE (nist_quantum_security_level IS NOT NULL);


-- INDEX: idx_algorithms_remediation
CREATE INDEX IF NOT EXISTS idx_algorithms_remediation ON public.algorithms USING gin (remediation_guidance);


-- INDEX: idx_algorithms_risk_score
CREATE INDEX IF NOT EXISTS idx_algorithms_risk_score ON public.algorithms USING btree (risk_score);


-- INDEX: idx_algorithms_strength
CREATE INDEX IF NOT EXISTS idx_algorithms_strength ON public.algorithms USING btree (strength, deprecation_status);


-- INDEX: idx_api_security_endpoint
CREATE INDEX IF NOT EXISTS idx_api_security_endpoint ON public.api_security_monitoring USING btree (endpoint, "timestamp" DESC);


-- INDEX: idx_api_security_ip
CREATE INDEX IF NOT EXISTS idx_api_security_ip ON public.api_security_monitoring USING btree (source_ip, "timestamp" DESC);


-- INDEX: idx_api_security_rate_limited
CREATE INDEX IF NOT EXISTS idx_api_security_rate_limited ON public.api_security_monitoring USING btree (is_rate_limited, "timestamp" DESC) WHERE (is_rate_limited = true);


-- INDEX: idx_api_security_suspicious
CREATE INDEX IF NOT EXISTS idx_api_security_suspicious ON public.api_security_monitoring USING btree (is_suspicious, "timestamp" DESC) WHERE (is_suspicious = true);


-- INDEX: idx_api_security_tenant
CREATE INDEX IF NOT EXISTS idx_api_security_tenant ON public.api_security_monitoring USING btree (tenant_id, "timestamp" DESC) WHERE (tenant_id IS NOT NULL);


-- INDEX: idx_api_security_timestamp
CREATE INDEX IF NOT EXISTS idx_api_security_timestamp ON public.api_security_monitoring USING btree ("timestamp" DESC);


-- INDEX: idx_api_security_user
CREATE INDEX IF NOT EXISTS idx_api_security_user ON public.api_security_monitoring USING btree (user_id, "timestamp" DESC) WHERE (user_id IS NOT NULL);


-- INDEX: idx_api_usage_endpoint_time
CREATE INDEX IF NOT EXISTS idx_api_usage_endpoint_time ON public.api_usage_logs USING btree (endpoint, "timestamp" DESC);


-- INDEX: idx_api_usage_tenant_time
CREATE INDEX IF NOT EXISTS idx_api_usage_tenant_time ON public.api_usage_logs USING btree (tenant_id, "timestamp" DESC);


-- INDEX: idx_asset_lifecycle_policies_tenant
CREATE INDEX IF NOT EXISTS idx_asset_lifecycle_policies_tenant ON public.asset_lifecycle_policies USING btree (tenant_id);


-- INDEX: idx_auth_audit_event_type
CREATE INDEX IF NOT EXISTS idx_auth_audit_event_type ON public.auth_audit_log USING btree (event_type);


-- INDEX: idx_auth_audit_occurred_at
CREATE INDEX IF NOT EXISTS idx_auth_audit_occurred_at ON public.auth_audit_log USING btree (occurred_at);


-- INDEX: idx_auth_audit_tenant_user
CREATE INDEX IF NOT EXISTS idx_auth_audit_tenant_user ON public.auth_audit_log USING btree (tenant_id, user_id);


-- INDEX: idx_aws_cost_data_cost_date
CREATE INDEX IF NOT EXISTS idx_aws_cost_data_cost_date ON public.aws_cost_data USING btree (cost_date);


-- INDEX: idx_aws_cost_data_service
CREATE INDEX IF NOT EXISTS idx_aws_cost_data_service ON public.aws_cost_data USING btree (service_name);


-- INDEX: idx_aws_cost_data_synced_at
CREATE INDEX IF NOT EXISTS idx_aws_cost_data_synced_at ON public.aws_cost_data USING btree (synced_at);


-- INDEX: idx_aws_cost_data_tenant_date
CREATE INDEX IF NOT EXISTS idx_aws_cost_data_tenant_date ON public.aws_cost_data USING btree (tenant_id, cost_date);


-- INDEX: idx_aws_cost_data_tenant_id
CREATE INDEX IF NOT EXISTS idx_aws_cost_data_tenant_id ON public.aws_cost_data USING btree (tenant_id);


-- INDEX: idx_aws_cost_data_unique
CREATE UNIQUE INDEX IF NOT EXISTS idx_aws_cost_data_unique ON public.aws_cost_data USING btree (tenant_id, cost_date, service_name, COALESCE(usage_type, ''::character varying)) WHERE (deleted_at IS NULL);


-- INDEX: idx_aws_cost_sync_jobs_created
CREATE INDEX IF NOT EXISTS idx_aws_cost_sync_jobs_created ON public.aws_cost_sync_jobs USING btree (created_at DESC);


-- INDEX: idx_aws_cost_sync_jobs_period
CREATE INDEX IF NOT EXISTS idx_aws_cost_sync_jobs_period ON public.aws_cost_sync_jobs USING btree (period_start, period_end);


-- INDEX: idx_aws_cost_sync_jobs_status
CREATE INDEX IF NOT EXISTS idx_aws_cost_sync_jobs_status ON public.aws_cost_sync_jobs USING btree (status);


-- INDEX: idx_aws_cost_sync_jobs_tenant
CREATE INDEX IF NOT EXISTS idx_aws_cost_sync_jobs_tenant ON public.aws_cost_sync_jobs USING btree (tenant_id);


-- INDEX: idx_billing_customers_tenant
CREATE INDEX IF NOT EXISTS idx_billing_customers_tenant ON public.billing_customers USING btree (tenant_id);


-- INDEX: idx_billing_events_status
CREATE INDEX IF NOT EXISTS idx_billing_events_status ON public.billing_events USING btree (processing_status) WHERE ((processing_status)::text = 'pending'::text);


-- INDEX: idx_billing_events_updated_at
CREATE INDEX IF NOT EXISTS idx_billing_events_updated_at ON public.billing_events USING btree (received_at) WHERE ((processing_status)::text = 'pending'::text);


-- INDEX: idx_billing_invoices_tenant
CREATE INDEX IF NOT EXISTS idx_billing_invoices_tenant ON public.billing_invoices USING btree (tenant_id);


-- INDEX: idx_billing_invoices_tenant_status
CREATE INDEX IF NOT EXISTS idx_billing_invoices_tenant_status ON public.billing_invoices USING btree (tenant_id, status);


-- INDEX: idx_billing_subscriptions_tenant
CREATE INDEX IF NOT EXISTS idx_billing_subscriptions_tenant ON public.billing_subscriptions USING btree (tenant_id);


-- INDEX: idx_cert_extensions_cert_id
CREATE INDEX IF NOT EXISTS idx_cert_extensions_cert_id ON public.certificate_extensions USING btree (certificate_id);


-- INDEX: idx_cert_extensions_name
CREATE INDEX IF NOT EXISTS idx_cert_extensions_name ON public.certificate_extensions USING btree (extension_name);


-- INDEX: idx_certificate_history_cert_id
CREATE INDEX IF NOT EXISTS idx_certificate_history_cert_id ON public.certificate_history USING btree (certificate_id, created_at DESC);


-- INDEX: idx_certificate_history_tenant
CREATE INDEX IF NOT EXISTS idx_certificate_history_tenant ON public.certificate_history USING btree (tenant_id, event_type, created_at DESC);


-- INDEX: idx_certificates_algorithm
CREATE INDEX IF NOT EXISTS idx_certificates_algorithm ON public.certificates USING btree (public_key_algorithm) WHERE (public_key_algorithm IS NOT NULL);


-- INDEX: idx_certificates_common_name
CREATE INDEX IF NOT EXISTS idx_certificates_common_name ON public.certificates USING btree (common_name);


-- INDEX: idx_certificates_composite_key
CREATE UNIQUE INDEX IF NOT EXISTS idx_certificates_composite_key ON public.certificates USING btree (tenant_id, fingerprint_sha256, serial_number, issuer_dn) WHERE ((fingerprint_sha256 IS NOT NULL) AND (serial_number IS NOT NULL) AND (issuer_dn IS NOT NULL));


-- INDEX: idx_certificates_expiry
CREATE INDEX IF NOT EXISTS idx_certificates_expiry ON public.certificates USING btree (not_after);


-- INDEX: idx_certificates_fingerprint_sha256
CREATE INDEX IF NOT EXISTS idx_certificates_fingerprint_sha256 ON public.certificates USING btree (fingerprint_sha256);


-- INDEX: idx_certificates_format
CREATE INDEX IF NOT EXISTS idx_certificates_format ON public.certificates USING btree (certificate_format) WHERE ((certificate_format)::text <> 'X.509'::text);


-- INDEX: idx_certificates_issuer
CREATE INDEX IF NOT EXISTS idx_certificates_issuer ON public.certificates USING btree (issuer_dn) WHERE (issuer_dn IS NOT NULL);


-- INDEX: idx_certificates_issuer_dn
CREATE INDEX IF NOT EXISTS idx_certificates_issuer_dn ON public.certificates USING btree (tenant_id, issuer_dn);


-- INDEX: idx_certificates_issuer_id
CREATE INDEX IF NOT EXISTS idx_certificates_issuer_id ON public.certificates USING btree (issuer_certificate_id) WHERE (issuer_certificate_id IS NOT NULL);


-- INDEX: idx_certificates_key_size
CREATE INDEX IF NOT EXISTS idx_certificates_key_size ON public.certificates USING btree (public_key_size) WHERE (public_key_size IS NOT NULL);


-- INDEX: idx_certificates_state
CREATE INDEX IF NOT EXISTS idx_certificates_state ON public.certificates USING btree (tenant_id, certificate_state) WHERE ((certificate_state)::text <> 'active'::text);


-- INDEX: idx_certificates_superseded_by
CREATE INDEX IF NOT EXISTS idx_certificates_superseded_by ON public.certificates USING btree (superseded_by_certificate_id) WHERE (superseded_by_certificate_id IS NOT NULL);


-- INDEX: idx_certificates_tenant_expiry
CREATE INDEX IF NOT EXISTS idx_certificates_tenant_expiry ON public.certificates USING btree (tenant_id, not_after);


-- INDEX: idx_certificates_tenant_id
CREATE INDEX IF NOT EXISTS idx_certificates_tenant_id ON public.certificates USING btree (tenant_id);


-- INDEX: idx_ci_relationships_source
CREATE INDEX IF NOT EXISTS idx_ci_relationships_source ON public.ci_relationships USING btree (tenant_id, source_ci_type, source_ci_id) WHERE (deleted_at IS NULL);


-- INDEX: idx_ci_relationships_target
CREATE INDEX IF NOT EXISTS idx_ci_relationships_target ON public.ci_relationships USING btree (tenant_id, target_ci_type, target_ci_id) WHERE (deleted_at IS NULL);


-- INDEX: idx_ci_relationships_tenant
CREATE INDEX IF NOT EXISTS idx_ci_relationships_tenant ON public.ci_relationships USING btree (tenant_id);


-- INDEX: idx_ci_relationships_type
CREATE INDEX IF NOT EXISTS idx_ci_relationships_type ON public.ci_relationships USING btree (tenant_id, relationship_type) WHERE (deleted_at IS NULL);


-- INDEX: idx_ci_relationships_unique
CREATE UNIQUE INDEX IF NOT EXISTS idx_ci_relationships_unique ON public.ci_relationships USING btree (tenant_id, source_ci_type, source_ci_id, relationship_type, target_ci_type, target_ci_id) WHERE (deleted_at IS NULL);


-- INDEX: idx_cmdb_entity_mappings_external
CREATE INDEX IF NOT EXISTS idx_cmdb_entity_mappings_external ON public.cmdb_entity_mappings USING btree (cmdb_platform, cmdb_ci_id) WHERE (cmdb_ci_id IS NOT NULL);


-- INDEX: idx_cmdb_entity_mappings_lookup
CREATE INDEX IF NOT EXISTS idx_cmdb_entity_mappings_lookup ON public.cmdb_entity_mappings USING btree (tenant_id, local_entity_type, local_entity_id);


-- INDEX: idx_cmdb_entity_mappings_profile
CREATE INDEX IF NOT EXISTS idx_cmdb_entity_mappings_profile ON public.cmdb_entity_mappings USING btree (profile_id);


-- INDEX: idx_cmdb_entity_mappings_stale
CREATE INDEX IF NOT EXISTS idx_cmdb_entity_mappings_stale ON public.cmdb_entity_mappings USING btree (sync_status) WHERE ((sync_status)::text = ANY ((ARRAY['pending'::character varying, 'error'::character varying, 'stale'::character varying])::text[]));


-- INDEX: idx_cmdb_sync_jobs_profile
CREATE INDEX IF NOT EXISTS idx_cmdb_sync_jobs_profile ON public.cmdb_sync_jobs USING btree (profile_id, created_at DESC);


-- INDEX: idx_cmdb_sync_jobs_status
CREATE INDEX IF NOT EXISTS idx_cmdb_sync_jobs_status ON public.cmdb_sync_jobs USING btree (status) WHERE ((status)::text = ANY ((ARRAY['pending'::character varying, 'in_progress'::character varying])::text[]));


-- INDEX: idx_cmdb_sync_jobs_tenant
CREATE INDEX IF NOT EXISTS idx_cmdb_sync_jobs_tenant ON public.cmdb_sync_jobs USING btree (tenant_id, created_at DESC);


-- INDEX: idx_cmdb_sync_profiles_platform
CREATE INDEX IF NOT EXISTS idx_cmdb_sync_profiles_platform ON public.cmdb_sync_profiles USING btree (tenant_id, platform_type) WHERE (deleted_at IS NULL);


-- INDEX: idx_cmdb_sync_profiles_tenant
CREATE INDEX IF NOT EXISTS idx_cmdb_sync_profiles_tenant ON public.cmdb_sync_profiles USING btree (tenant_id) WHERE (deleted_at IS NULL);


-- INDEX: idx_compliance_checks_report_id
CREATE INDEX IF NOT EXISTS idx_compliance_checks_report_id ON public.compliance_checks USING btree (report_id);


-- INDEX: idx_compliance_checks_rule_id
CREATE INDEX IF NOT EXISTS idx_compliance_checks_rule_id ON public.compliance_checks USING btree (rule_id);


-- INDEX: idx_compliance_checks_status
CREATE INDEX IF NOT EXISTS idx_compliance_checks_status ON public.compliance_checks USING btree (status);


-- INDEX: idx_compliance_checks_tenant_id
CREATE INDEX IF NOT EXISTS idx_compliance_checks_tenant_id ON public.compliance_checks USING btree (tenant_id);


-- INDEX: idx_compliance_findings_asset_id
CREATE INDEX IF NOT EXISTS idx_compliance_findings_asset_id ON public.compliance_findings USING btree (asset_id);


-- INDEX: idx_compliance_findings_assigned_at
CREATE INDEX IF NOT EXISTS idx_compliance_findings_assigned_at ON public.compliance_findings USING btree (assigned_at) WHERE (assigned_to IS NOT NULL);


-- INDEX: idx_compliance_findings_assigned_to
CREATE INDEX IF NOT EXISTS idx_compliance_findings_assigned_to ON public.compliance_findings USING btree (tenant_id, assigned_to) WHERE (assigned_to IS NOT NULL);


-- INDEX: idx_compliance_findings_control_id
CREATE INDEX IF NOT EXISTS idx_compliance_findings_control_id ON public.compliance_findings USING btree (control_id);


-- INDEX: idx_compliance_findings_last_seen
CREATE INDEX IF NOT EXISTS idx_compliance_findings_last_seen ON public.compliance_findings USING btree (last_seen);


-- INDEX: idx_compliance_findings_severity
CREATE INDEX IF NOT EXISTS idx_compliance_findings_severity ON public.compliance_findings USING btree (severity);


-- INDEX: idx_compliance_findings_tenant_id
CREATE INDEX IF NOT EXISTS idx_compliance_findings_tenant_id ON public.compliance_findings USING btree (tenant_id);


-- INDEX: idx_compliance_framework_name
CREATE INDEX IF NOT EXISTS idx_compliance_framework_name ON public.compliance_framework_status USING btree (framework_name, updated_at DESC);


-- INDEX: idx_compliance_framework_status
CREATE INDEX IF NOT EXISTS idx_compliance_framework_status ON public.compliance_framework_status USING btree (overall_status, updated_at DESC);


-- INDEX: idx_compliance_overrides_control_id
CREATE INDEX IF NOT EXISTS idx_compliance_overrides_control_id ON public.compliance_overrides USING btree (control_id);


-- INDEX: idx_compliance_overrides_scenario_id
CREATE INDEX IF NOT EXISTS idx_compliance_overrides_scenario_id ON public.compliance_overrides USING btree (scenario_id);


-- INDEX: idx_compliance_overrides_tenant_id
CREATE INDEX IF NOT EXISTS idx_compliance_overrides_tenant_id ON public.compliance_overrides USING btree (tenant_id);


-- INDEX: idx_compliance_overrides_type
CREATE INDEX IF NOT EXISTS idx_compliance_overrides_type ON public.compliance_overrides USING btree (override_type);


-- INDEX: idx_compliance_reports_created_at
CREATE INDEX IF NOT EXISTS idx_compliance_reports_created_at ON public.compliance_reports USING btree (created_at);


-- INDEX: idx_compliance_reports_status
CREATE INDEX IF NOT EXISTS idx_compliance_reports_status ON public.compliance_reports USING btree (status);


-- INDEX: idx_compliance_reports_tenant_id
CREATE INDEX IF NOT EXISTS idx_compliance_reports_tenant_id ON public.compliance_reports USING btree (tenant_id);


-- INDEX: idx_compliance_requirements_framework
CREATE INDEX IF NOT EXISTS idx_compliance_requirements_framework ON public.compliance_requirements USING btree (framework_id, status);


-- INDEX: idx_compliance_requirements_status
CREATE INDEX IF NOT EXISTS idx_compliance_requirements_status ON public.compliance_requirements USING btree (status, priority);


-- INDEX: idx_compliance_rules_active
CREATE INDEX IF NOT EXISTS idx_compliance_rules_active ON public.compliance_rules USING btree (is_active);


-- INDEX: idx_compliance_rules_category
CREATE INDEX IF NOT EXISTS idx_compliance_rules_category ON public.compliance_rules USING btree (category);


-- INDEX: idx_compliance_rules_severity
CREATE INDEX IF NOT EXISTS idx_compliance_rules_severity ON public.compliance_rules USING btree (severity);


-- INDEX: idx_compliance_scenarios_framework_id
CREATE INDEX IF NOT EXISTS idx_compliance_scenarios_framework_id ON public.compliance_scenarios USING btree (framework_id);


-- INDEX: idx_compliance_scenarios_name
CREATE INDEX IF NOT EXISTS idx_compliance_scenarios_name ON public.compliance_scenarios USING btree (name);


-- INDEX: idx_compliance_scenarios_tenant_id
CREATE INDEX IF NOT EXISTS idx_compliance_scenarios_tenant_id ON public.compliance_scenarios USING btree (tenant_id);


-- INDEX: idx_control_measurements_control_id
CREATE INDEX IF NOT EXISTS idx_control_measurements_control_id ON public.control_measurements USING btree (control_id);


-- INDEX: idx_control_measurements_framework_type
CREATE INDEX IF NOT EXISTS idx_control_measurements_framework_type ON public.control_measurements USING btree (framework_type);


-- INDEX: idx_control_measurements_measurement_type_id
CREATE INDEX IF NOT EXISTS idx_control_measurements_measurement_type_id ON public.control_measurements USING btree (measurement_type_id);


-- INDEX: idx_control_measurements_rule_type
CREATE INDEX IF NOT EXISTS idx_control_measurements_rule_type ON public.control_measurements USING btree (rule_type);


-- INDEX: idx_coupon_redemptions_active
CREATE INDEX IF NOT EXISTS idx_coupon_redemptions_active ON public.billing_coupon_redemptions USING btree (is_active, expires_at);


-- INDEX: idx_coupon_redemptions_coupon
CREATE INDEX IF NOT EXISTS idx_coupon_redemptions_coupon ON public.billing_coupon_redemptions USING btree (coupon_id);


-- INDEX: idx_coupon_redemptions_tenant
CREATE INDEX IF NOT EXISTS idx_coupon_redemptions_tenant ON public.billing_coupon_redemptions USING btree (tenant_id);


-- INDEX: idx_coupons_active
CREATE INDEX IF NOT EXISTS idx_coupons_active ON public.billing_coupons USING btree (is_active, valid_from, valid_until);


-- INDEX: idx_coupons_code
CREATE INDEX IF NOT EXISTS idx_coupons_code ON public.billing_coupons USING btree (code) WHERE (is_active = true);


-- INDEX: idx_crypto_app_algorithm
CREATE INDEX IF NOT EXISTS idx_crypto_app_algorithm ON public.crypto_applications USING btree (algorithm_id) WHERE (algorithm_id IS NOT NULL);


-- INDEX: idx_crypto_app_asset
CREATE INDEX IF NOT EXISTS idx_crypto_app_asset ON public.crypto_applications USING btree (asset_id) WHERE (asset_id IS NOT NULL);


-- INDEX: idx_crypto_app_encryption_ctx
CREATE INDEX IF NOT EXISTS idx_crypto_app_encryption_ctx ON public.crypto_applications USING btree (tenant_id, encryption_context);


-- INDEX: idx_crypto_app_key
CREATE INDEX IF NOT EXISTS idx_crypto_app_key ON public.crypto_applications USING btree (key_id) WHERE (key_id IS NOT NULL);


-- INDEX: idx_crypto_app_library
CREATE INDEX IF NOT EXISTS idx_crypto_app_library ON public.crypto_applications USING btree (library_id) WHERE (library_id IS NOT NULL);


-- INDEX: idx_crypto_app_resource_type
CREATE INDEX IF NOT EXISTS idx_crypto_app_resource_type ON public.crypto_applications USING btree (tenant_id, resource_type);


-- INDEX: idx_crypto_app_tenant
CREATE INDEX IF NOT EXISTS idx_crypto_app_tenant ON public.crypto_applications USING btree (tenant_id);
















-- INDEX: idx_crypto_impl_algorithms_algorithm_id
CREATE INDEX IF NOT EXISTS idx_crypto_impl_algorithms_algorithm_id ON public.crypto_implementation_algorithms USING btree (algorithm_id);


-- INDEX: idx_crypto_impl_algorithms_impl_id
CREATE INDEX IF NOT EXISTS idx_crypto_impl_algorithms_impl_id ON public.crypto_implementation_algorithms USING btree (crypto_implementation_id);


-- INDEX: idx_crypto_impl_certs_cert_id
CREATE INDEX IF NOT EXISTS idx_crypto_impl_certs_cert_id ON public.crypto_implementation_certificates USING btree (certificate_id);


-- INDEX: idx_crypto_impl_certs_impl_id
CREATE INDEX IF NOT EXISTS idx_crypto_impl_certs_impl_id ON public.crypto_implementation_certificates USING btree (crypto_implementation_id);


-- INDEX: idx_crypto_libs_name_ver
CREATE INDEX IF NOT EXISTS idx_crypto_libs_name_ver ON public.crypto_libraries USING btree (name, version);


-- INDEX: idx_crypto_libs_purl
CREATE INDEX IF NOT EXISTS idx_crypto_libs_purl ON public.crypto_libraries USING btree (purl) WHERE (purl IS NOT NULL);


-- INDEX: idx_crypto_libs_tenant
CREATE INDEX IF NOT EXISTS idx_crypto_libs_tenant ON public.crypto_libraries USING btree (tenant_id);


-- INDEX: idx_dashboard_cache_expires
CREATE INDEX IF NOT EXISTS idx_dashboard_cache_expires ON public.dashboard_cache USING btree (expires_at);


-- INDEX: idx_dashboard_metrics_name_time
CREATE INDEX IF NOT EXISTS idx_dashboard_metrics_name_time ON public.dashboard_metrics USING btree (metric_name, "timestamp" DESC);


-- INDEX: idx_dashboard_metrics_type_time
CREATE INDEX IF NOT EXISTS idx_dashboard_metrics_type_time ON public.dashboard_metrics USING btree (metric_type, "timestamp" DESC);


-- INDEX: idx_db_encryption_states_at_rest
CREATE INDEX IF NOT EXISTS idx_db_encryption_states_at_rest ON public.database_encryption_states USING btree (encryption_at_rest_enabled) WHERE (deleted_at IS NULL);


-- INDEX: idx_db_encryption_states_device
CREATE INDEX IF NOT EXISTS idx_db_encryption_states_device ON public.database_encryption_states USING btree (device_id) WHERE ((device_id IS NOT NULL) AND (deleted_at IS NULL));


-- INDEX: idx_db_encryption_states_engine
CREATE INDEX IF NOT EXISTS idx_db_encryption_states_engine ON public.database_encryption_states USING btree (db_engine) WHERE (deleted_at IS NULL);


-- INDEX: idx_db_encryption_states_ssl
CREATE INDEX IF NOT EXISTS idx_db_encryption_states_ssl ON public.database_encryption_states USING btree (ssl_enabled) WHERE (deleted_at IS NULL);


-- INDEX: idx_db_encryption_states_tenant
CREATE INDEX IF NOT EXISTS idx_db_encryption_states_tenant ON public.database_encryption_states USING btree (tenant_id) WHERE (deleted_at IS NULL);


-- INDEX: idx_device_agents_active
CREATE INDEX IF NOT EXISTS idx_device_agents_active ON public.device_agents USING btree (status) WHERE (deleted_at IS NULL);


-- INDEX: idx_device_agents_registration_key
CREATE INDEX IF NOT EXISTS idx_device_agents_registration_key ON public.device_agents USING btree (registration_key);


-- INDEX: idx_device_agents_status
CREATE INDEX IF NOT EXISTS idx_device_agents_status ON public.device_agents USING btree (status);


-- INDEX: idx_device_agents_tenant_id
CREATE INDEX IF NOT EXISTS idx_device_agents_tenant_id ON public.device_agents USING btree (tenant_id);


-- INDEX: idx_device_jobs_active
CREATE INDEX IF NOT EXISTS idx_device_jobs_active ON public.device_jobs USING btree (tenant_id, status) WHERE (deleted_at IS NULL);


-- INDEX: idx_device_jobs_agent_id
CREATE INDEX IF NOT EXISTS idx_device_jobs_agent_id ON public.device_jobs USING btree (agent_id);


-- INDEX: idx_device_jobs_device_id
CREATE INDEX IF NOT EXISTS idx_device_jobs_device_id ON public.device_jobs USING btree (device_id);


-- INDEX: idx_device_jobs_expires
CREATE INDEX IF NOT EXISTS idx_device_jobs_expires ON public.device_jobs USING btree (expires_at) WHERE ((status = 'pending'::public.device_job_status) AND (expires_at IS NOT NULL));


-- INDEX: idx_device_jobs_job_type
CREATE INDEX IF NOT EXISTS idx_device_jobs_job_type ON public.device_jobs USING btree (job_type);


-- INDEX: idx_device_jobs_pending
CREATE INDEX IF NOT EXISTS idx_device_jobs_pending ON public.device_jobs USING btree (status, created_at) WHERE ((status = 'pending'::public.device_job_status) AND (deleted_at IS NULL));


-- INDEX: idx_device_jobs_status
CREATE INDEX IF NOT EXISTS idx_device_jobs_status ON public.device_jobs USING btree (status);


-- INDEX: idx_device_jobs_tenant_id
CREATE INDEX IF NOT EXISTS idx_device_jobs_tenant_id ON public.device_jobs USING btree (tenant_id);


-- INDEX: idx_device_jobs_updated_at
CREATE INDEX IF NOT EXISTS idx_device_jobs_updated_at ON public.device_jobs USING btree (updated_at);


-- INDEX: idx_devices_active
CREATE INDEX IF NOT EXISTS idx_devices_active ON public.devices USING btree (tenant_id, device_type) WHERE (deleted_at IS NULL);


-- INDEX: idx_devices_connection_status
CREATE INDEX IF NOT EXISTS idx_devices_connection_status ON public.devices USING btree (connection_status);


-- INDEX: idx_devices_credential_id
CREATE INDEX IF NOT EXISTS idx_devices_credential_id ON public.devices USING btree (credential_id);


-- INDEX: idx_devices_device_type
CREATE INDEX IF NOT EXISTS idx_devices_device_type ON public.devices USING btree (device_type);


-- INDEX: idx_devices_discovery_method
CREATE INDEX IF NOT EXISTS idx_devices_discovery_method ON public.devices USING btree (discovery_method);


-- INDEX: idx_devices_tenant_id
CREATE INDEX IF NOT EXISTS idx_devices_tenant_id ON public.devices USING btree (tenant_id);


-- INDEX: idx_devices_unique_per_tenant
CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_unique_per_tenant ON public.devices USING btree (tenant_id, device_type, management_url) WHERE (deleted_at IS NULL);


-- INDEX: idx_devices_username
CREATE INDEX IF NOT EXISTS idx_devices_username ON public.devices USING btree (username) WHERE ((username IS NOT NULL) AND (deleted_at IS NULL));


-- INDEX: idx_devices_vendor
CREATE INDEX IF NOT EXISTS idx_devices_vendor ON public.devices USING btree (vendor);


-- INDEX: idx_discovery_approval_queue_created_at
CREATE INDEX IF NOT EXISTS idx_discovery_approval_queue_created_at ON public.discovery_approval_queue USING btree (created_at);


-- INDEX: idx_discovery_approval_queue_status
CREATE INDEX IF NOT EXISTS idx_discovery_approval_queue_status ON public.discovery_approval_queue USING btree (status);


-- INDEX: idx_discovery_approval_queue_tenant_id
CREATE INDEX IF NOT EXISTS idx_discovery_approval_queue_tenant_id ON public.discovery_approval_queue USING btree (tenant_id);


-- INDEX: idx_discovery_findings_confidence_score
CREATE INDEX IF NOT EXISTS idx_discovery_findings_confidence_score ON public.discovery_findings USING btree (confidence_score);


-- INDEX: idx_discovery_findings_hostname
CREATE INDEX IF NOT EXISTS idx_discovery_findings_hostname ON public.discovery_findings USING btree (hostname);


-- INDEX: idx_discovery_findings_job_id
CREATE INDEX IF NOT EXISTS idx_discovery_findings_job_id ON public.discovery_findings USING btree (job_id);


-- INDEX: idx_discovery_findings_protocol_port
CREATE INDEX IF NOT EXISTS idx_discovery_findings_protocol_port ON public.discovery_findings USING btree (protocol, port);


-- INDEX: idx_discovery_findings_target_id
CREATE INDEX IF NOT EXISTS idx_discovery_findings_target_id ON public.discovery_findings USING btree (target_id);


-- INDEX: idx_discovery_jobs_created_at
CREATE INDEX IF NOT EXISTS idx_discovery_jobs_created_at ON public.discovery_jobs USING btree (created_at);


-- INDEX: idx_discovery_jobs_metadata
CREATE INDEX IF NOT EXISTS idx_discovery_jobs_metadata ON public.discovery_jobs USING gin (metadata);


-- INDEX: idx_discovery_jobs_status
CREATE INDEX IF NOT EXISTS idx_discovery_jobs_status ON public.discovery_jobs USING btree (status);


-- INDEX: idx_discovery_jobs_tenant_id
CREATE INDEX IF NOT EXISTS idx_discovery_jobs_tenant_id ON public.discovery_jobs USING btree (tenant_id);


-- INDEX: idx_discovery_targets_job_id
CREATE INDEX IF NOT EXISTS idx_discovery_targets_job_id ON public.discovery_targets USING btree (job_id);


-- INDEX: idx_discovery_targets_status
CREATE INDEX IF NOT EXISTS idx_discovery_targets_status ON public.discovery_targets USING btree (status);


-- INDEX: idx_dunning_attempts_invoice
CREATE INDEX IF NOT EXISTS idx_dunning_attempts_invoice ON public.billing_dunning_attempts USING btree (invoice_id);


-- INDEX: idx_dunning_attempts_next_retry
CREATE INDEX IF NOT EXISTS idx_dunning_attempts_next_retry ON public.billing_dunning_attempts USING btree (next_retry_at) WHERE ((status)::text = 'pending'::text);


-- INDEX: idx_dunning_attempts_status
CREATE INDEX IF NOT EXISTS idx_dunning_attempts_status ON public.billing_dunning_attempts USING btree (status);


-- INDEX: idx_dunning_attempts_tenant
CREATE INDEX IF NOT EXISTS idx_dunning_attempts_tenant ON public.billing_dunning_attempts USING btree (tenant_id);


-- INDEX: idx_ext_conn_cert_expiry
CREATE INDEX IF NOT EXISTS idx_ext_conn_cert_expiry ON public.external_connections USING btree (tenant_id, cert_not_after) WHERE (cert_not_after IS NOT NULL);


-- INDEX: idx_ext_conn_crypto_strength
CREATE INDEX IF NOT EXISTS idx_ext_conn_crypto_strength ON public.external_connections USING btree (tenant_id, crypto_strength);


-- INDEX: idx_ext_conn_dest
CREATE INDEX IF NOT EXISTS idx_ext_conn_dest ON public.external_connections USING btree (tenant_id, dest_ip, dest_port);


-- INDEX: idx_ext_conn_dest_hostname
CREATE INDEX IF NOT EXISTS idx_ext_conn_dest_hostname ON public.external_connections USING btree (tenant_id, dest_hostname) WHERE (dest_hostname IS NOT NULL);


-- INDEX: idx_ext_conn_history_conn
CREATE INDEX IF NOT EXISTS idx_ext_conn_history_conn ON public.external_connection_history USING btree (external_connection_id, created_at DESC);


-- INDEX: idx_ext_conn_history_tenant
CREATE INDEX IF NOT EXISTS idx_ext_conn_history_tenant ON public.external_connection_history USING btree (tenant_id, created_at DESC);


-- INDEX: idx_ext_conn_last_seen
CREATE INDEX IF NOT EXISTS idx_ext_conn_last_seen ON public.external_connections USING btree (tenant_id, last_seen_at DESC);


-- INDEX: idx_ext_conn_pqc
CREATE INDEX IF NOT EXISTS idx_ext_conn_pqc ON public.external_connections USING btree (tenant_id, is_pqc_resistant);


-- INDEX: idx_ext_conn_source
CREATE INDEX IF NOT EXISTS idx_ext_conn_source ON public.external_connections USING btree (tenant_id, source_ip);


-- INDEX: idx_ext_conn_tenant
CREATE INDEX IF NOT EXISTS idx_ext_conn_tenant ON public.external_connections USING btree (tenant_id);


-- INDEX: idx_external_map_lookup
CREATE INDEX IF NOT EXISTS idx_external_map_lookup ON public.external_asset_mappings USING btree (tenant_id, local_type, local_id);


-- INDEX: idx_feature_adoption_feature_time
CREATE INDEX IF NOT EXISTS idx_feature_adoption_feature_time ON public.feature_adoption_metrics USING btree (feature_name, "timestamp" DESC);


-- INDEX: idx_feature_adoption_tenant_time
CREATE INDEX IF NOT EXISTS idx_feature_adoption_tenant_time ON public.feature_adoption_metrics USING btree (tenant_id, "timestamp" DESC);


-- INDEX: idx_feature_usage_occurred_at
CREATE INDEX IF NOT EXISTS idx_feature_usage_occurred_at ON public.feature_usage_events USING btree (occurred_at);


-- INDEX: idx_feature_usage_tenant_feature
CREATE INDEX IF NOT EXISTS idx_feature_usage_tenant_feature ON public.feature_usage_events USING btree (tenant_id, feature_name);


-- INDEX: idx_finding_history_changed_by
CREATE INDEX IF NOT EXISTS idx_finding_history_changed_by ON public.compliance_finding_history USING btree (changed_by, changed_at DESC) WHERE (changed_by IS NOT NULL);


-- INDEX: idx_finding_history_finding_id
CREATE INDEX IF NOT EXISTS idx_finding_history_finding_id ON public.compliance_finding_history USING btree (finding_id, changed_at DESC);


-- INDEX: idx_findings_active_rollup
CREATE INDEX IF NOT EXISTS idx_findings_active_rollup ON public.compliance_findings USING btree (tenant_id, control_id, last_seen) WHERE (((detection_state)::text = 'ACTIVE'::text) AND (((workflow_status)::text <> 'SUPPRESSED'::text) OR (workflow_status IS NULL)));


-- INDEX: idx_findings_detection_state
CREATE INDEX IF NOT EXISTS idx_findings_detection_state ON public.compliance_findings USING btree (tenant_id, detection_state, last_seen);


-- INDEX: idx_findings_identity
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_identity ON public.compliance_findings USING btree (tenant_id, control_id, asset_id) WHERE ((detection_state)::text <> 'ARCHIVED'::text);


-- INDEX: idx_findings_resurfaced
CREATE INDEX IF NOT EXISTS idx_findings_resurfaced ON public.compliance_findings USING btree (tenant_id, resurfaced_at) WHERE (resurfaced_at IS NOT NULL);


-- INDEX: idx_findings_workflow_status
CREATE INDEX IF NOT EXISTS idx_findings_workflow_status ON public.compliance_findings USING btree (tenant_id, workflow_status) WHERE ((workflow_status)::text <> 'SUPPRESSED'::text);


-- INDEX: idx_framework_versions_created_at
CREATE INDEX IF NOT EXISTS idx_framework_versions_created_at ON public.platform_framework_versions USING btree (created_at);


-- INDEX: idx_framework_versions_framework_id
CREATE INDEX IF NOT EXISTS idx_framework_versions_framework_id ON public.platform_framework_versions USING btree (framework_id);


-- INDEX: idx_health_alerts_created_at
CREATE INDEX IF NOT EXISTS idx_health_alerts_created_at ON public.health_alerts USING btree (created_at);


-- INDEX: idx_health_alerts_is_active
CREATE INDEX IF NOT EXISTS idx_health_alerts_is_active ON public.health_alerts USING btree (is_active);


-- INDEX: idx_health_alerts_severity
CREATE INDEX IF NOT EXISTS idx_health_alerts_severity ON public.health_alerts USING btree (severity);


-- INDEX: idx_health_alerts_tenant_id
CREATE INDEX IF NOT EXISTS idx_health_alerts_tenant_id ON public.health_alerts USING btree (tenant_id);


-- INDEX: idx_health_events_service_time
CREATE INDEX IF NOT EXISTS idx_health_events_service_time ON public.service_health_events USING btree (service_name, "timestamp" DESC);


-- INDEX: idx_health_events_status
CREATE INDEX IF NOT EXISTS idx_health_events_status ON public.service_health_events USING btree (status, "timestamp" DESC) WHERE ((status)::text = ANY ((ARRAY['degraded'::character varying, 'down'::character varying])::text[]));


-- INDEX: idx_health_events_type
CREATE INDEX IF NOT EXISTS idx_health_events_type ON public.service_health_events USING btree (event_type, "timestamp" DESC);


-- INDEX: idx_health_insights_generated_at
CREATE INDEX IF NOT EXISTS idx_health_insights_generated_at ON public.health_insights USING btree (generated_at);


-- INDEX: idx_health_insights_tenant_id
CREATE INDEX IF NOT EXISTS idx_health_insights_tenant_id ON public.health_insights USING btree (tenant_id);


-- INDEX: idx_health_metrics_tenant_id
CREATE INDEX IF NOT EXISTS idx_health_metrics_tenant_id ON public.health_metrics USING btree (tenant_id);


-- INDEX: idx_health_metrics_tenant_id_timestamp
CREATE INDEX IF NOT EXISTS idx_health_metrics_tenant_id_timestamp ON public.health_metrics USING btree (tenant_id, "timestamp");


-- INDEX: idx_health_metrics_timestamp
CREATE INDEX IF NOT EXISTS idx_health_metrics_timestamp ON public.health_metrics USING btree ("timestamp");


-- INDEX: idx_identity_link_requests_primary_user
CREATE INDEX IF NOT EXISTS idx_identity_link_requests_primary_user ON public.identity_link_requests USING btree (primary_user_id);


-- INDEX: idx_identity_link_requests_token
CREATE INDEX IF NOT EXISTS idx_identity_link_requests_token ON public.identity_link_requests USING btree (confirmation_token);


-- INDEX: idx_in_app_notifications_created_at
CREATE INDEX IF NOT EXISTS idx_in_app_notifications_created_at ON public.in_app_notifications USING btree (created_at DESC);


-- INDEX: idx_in_app_notifications_finding_id
CREATE INDEX IF NOT EXISTS idx_in_app_notifications_finding_id ON public.in_app_notifications USING btree (finding_id) WHERE (finding_id IS NOT NULL);


-- INDEX: idx_in_app_notifications_job_id
CREATE INDEX IF NOT EXISTS idx_in_app_notifications_job_id ON public.in_app_notifications USING btree (job_id) WHERE (job_id IS NOT NULL);


-- INDEX: idx_in_app_notifications_tenant_id
CREATE INDEX IF NOT EXISTS idx_in_app_notifications_tenant_id ON public.in_app_notifications USING btree (tenant_id);


-- INDEX: idx_in_app_notifications_tenant_unread
CREATE INDEX IF NOT EXISTS idx_in_app_notifications_tenant_unread ON public.in_app_notifications USING btree (tenant_id, read_at) WHERE (read_at IS NULL);


-- INDEX: idx_in_app_notifications_type
CREATE INDEX IF NOT EXISTS idx_in_app_notifications_type ON public.in_app_notifications USING btree (type);


-- INDEX: idx_incident_webhooks_enabled
CREATE INDEX IF NOT EXISTS idx_incident_webhooks_enabled ON public.security_incident_webhooks USING btree (enabled) WHERE (enabled = true);


-- INDEX: idx_incident_webhooks_events
CREATE INDEX IF NOT EXISTS idx_incident_webhooks_events ON public.security_incident_webhooks USING gin (events);


-- INDEX: idx_integration_audit_action
CREATE INDEX IF NOT EXISTS idx_integration_audit_action ON public.platform_integration_audit_log USING btree (action);


-- INDEX: idx_integration_audit_created_at
CREATE INDEX IF NOT EXISTS idx_integration_audit_created_at ON public.platform_integration_audit_log USING btree (created_at DESC);


-- INDEX: idx_integration_audit_integration_id
CREATE INDEX IF NOT EXISTS idx_integration_audit_integration_id ON public.platform_integration_audit_log USING btree (integration_id);


-- INDEX: idx_integration_audit_performed_by
CREATE INDEX IF NOT EXISTS idx_integration_audit_performed_by ON public.platform_integration_audit_log USING btree (performed_by);


-- INDEX: idx_integration_secrets_current
CREATE INDEX IF NOT EXISTS idx_integration_secrets_current ON public.platform_integration_secrets USING btree (integration_id, secret_key) WHERE (is_current = true);


-- INDEX: idx_integration_secrets_expires
CREATE INDEX IF NOT EXISTS idx_integration_secrets_expires ON public.platform_integration_secrets USING btree (expires_at) WHERE (expires_at IS NOT NULL);


-- INDEX: idx_integration_secrets_integration_id
CREATE INDEX IF NOT EXISTS idx_integration_secrets_integration_id ON public.platform_integration_secrets USING btree (integration_id);


-- INDEX: idx_integrations_tenant
CREATE INDEX IF NOT EXISTS idx_integrations_tenant ON public.integrations USING btree (tenant_id);


-- INDEX: idx_integrations_type
CREATE INDEX IF NOT EXISTS idx_integrations_type ON public.integrations USING btree (type);


-- INDEX: idx_interrogation_schedules_enabled
CREATE INDEX IF NOT EXISTS idx_interrogation_schedules_enabled ON public.interrogation_schedules USING btree (is_enabled) WHERE (deleted_at IS NULL);


-- INDEX: idx_interrogation_schedules_next_run
CREATE INDEX IF NOT EXISTS idx_interrogation_schedules_next_run ON public.interrogation_schedules USING btree (next_run_at) WHERE ((is_enabled = true) AND (deleted_at IS NULL));


-- INDEX: idx_interrogation_schedules_target
CREATE INDEX IF NOT EXISTS idx_interrogation_schedules_target ON public.interrogation_schedules USING btree (target_type, target_id);


-- INDEX: idx_interrogation_schedules_tenant_id
CREATE INDEX IF NOT EXISTS idx_interrogation_schedules_tenant_id ON public.interrogation_schedules USING btree (tenant_id);


-- INDEX: idx_invoice_line_items_invoice
CREATE INDEX IF NOT EXISTS idx_invoice_line_items_invoice ON public.billing_invoice_line_items USING btree (invoice_id);


-- INDEX: idx_invoice_line_items_type
CREATE INDEX IF NOT EXISTS idx_invoice_line_items_type ON public.billing_invoice_line_items USING btree (line_item_type);


-- INDEX: idx_keys_algorithm
CREATE INDEX IF NOT EXISTS idx_keys_algorithm ON public.keys USING btree (algorithm_id) WHERE (algorithm_id IS NOT NULL);


-- INDEX: idx_keys_jwk
CREATE INDEX IF NOT EXISTS idx_keys_jwk ON public.keys USING btree (jwk_thumbprint);


-- INDEX: idx_keys_material_type
CREATE INDEX IF NOT EXISTS idx_keys_material_type ON public.keys USING btree (material_type);


-- INDEX: idx_keys_pubfp
CREATE INDEX IF NOT EXISTS idx_keys_pubfp ON public.keys USING btree (public_fingerprint);


-- INDEX: idx_keys_state
CREATE INDEX IF NOT EXISTS idx_keys_state ON public.keys USING btree (tenant_id, state) WHERE ((state)::text <> 'active'::text);


-- INDEX: idx_keys_tenant
CREATE INDEX IF NOT EXISTS idx_keys_tenant ON public.keys USING btree (tenant_id);


-- INDEX: idx_kms_keys_algorithm
CREATE INDEX IF NOT EXISTS idx_kms_keys_algorithm ON public.kms_keys USING btree (algorithm_id) WHERE ((algorithm_id IS NOT NULL) AND (deleted_at IS NULL));


-- INDEX: idx_kms_keys_integration
CREATE INDEX IF NOT EXISTS idx_kms_keys_integration ON public.kms_keys USING btree (integration_id) WHERE (deleted_at IS NULL);


-- INDEX: idx_kms_keys_provider
CREATE INDEX IF NOT EXISTS idx_kms_keys_provider ON public.kms_keys USING btree (provider) WHERE (deleted_at IS NULL);


-- INDEX: idx_kms_keys_rotation
CREATE INDEX IF NOT EXISTS idx_kms_keys_rotation ON public.kms_keys USING btree (rotation_enabled, last_rotated_at) WHERE (deleted_at IS NULL);


-- INDEX: idx_kms_keys_state
CREATE INDEX IF NOT EXISTS idx_kms_keys_state ON public.kms_keys USING btree (key_state) WHERE (deleted_at IS NULL);


-- INDEX: idx_kms_keys_tenant
CREATE INDEX IF NOT EXISTS idx_kms_keys_tenant ON public.kms_keys USING btree (tenant_id) WHERE (deleted_at IS NULL);


-- INDEX: idx_kms_keys_unique_provider_key
CREATE UNIQUE INDEX IF NOT EXISTS idx_kms_keys_unique_provider_key ON public.kms_keys USING btree (tenant_id, provider, key_id) WHERE (deleted_at IS NULL);


-- INDEX: idx_lib_algo_algorithm
CREATE INDEX IF NOT EXISTS idx_lib_algo_algorithm ON public.library_provided_algorithms USING btree (algorithm_id);


-- INDEX: idx_locations_cloud
CREATE INDEX IF NOT EXISTS idx_locations_cloud ON public.locations USING btree (tenant_id, cloud_provider, cloud_region) WHERE (cloud_provider IS NOT NULL);


-- INDEX: idx_locations_parent_id
CREATE INDEX IF NOT EXISTS idx_locations_parent_id ON public.locations USING btree (parent_id) WHERE (parent_id IS NOT NULL);


-- INDEX: idx_locations_tenant_id
CREATE INDEX IF NOT EXISTS idx_locations_tenant_id ON public.locations USING btree (tenant_id);


-- INDEX: idx_log_access_audit_log
CREATE INDEX IF NOT EXISTS idx_log_access_audit_log ON public.platform_log_access_audit USING btree (log_id, accessed_at DESC) WHERE (log_id IS NOT NULL);


-- INDEX: idx_log_access_audit_timestamp
CREATE INDEX IF NOT EXISTS idx_log_access_audit_timestamp ON public.platform_log_access_audit USING btree (accessed_at DESC);


-- INDEX: idx_log_access_audit_type
CREATE INDEX IF NOT EXISTS idx_log_access_audit_type ON public.platform_log_access_audit USING btree (access_type, accessed_at DESC);


-- INDEX: idx_log_access_audit_user
CREATE INDEX IF NOT EXISTS idx_log_access_audit_user ON public.platform_log_access_audit USING btree (accessed_by_user_id, accessed_at DESC);


-- INDEX: idx_log_retention_jobs_status
CREATE INDEX IF NOT EXISTS idx_log_retention_jobs_status ON public.platform_log_retention_jobs USING btree (execution_status, started_at DESC);


-- INDEX: idx_log_retention_jobs_type
CREATE INDEX IF NOT EXISTS idx_log_retention_jobs_type ON public.platform_log_retention_jobs USING btree (job_type, started_at DESC);


-- INDEX: idx_maintenance_windows_status
CREATE INDEX IF NOT EXISTS idx_maintenance_windows_status ON public.maintenance_windows USING btree (status, starts_at);


-- INDEX: idx_measurement_templates_active
CREATE INDEX IF NOT EXISTS idx_measurement_templates_active ON public.measurement_templates USING btree (is_active) WHERE (is_active = true);


-- INDEX: idx_measurement_templates_category
CREATE INDEX IF NOT EXISTS idx_measurement_templates_category ON public.measurement_templates USING btree (category);


-- INDEX: idx_measurement_templates_code
CREATE INDEX IF NOT EXISTS idx_measurement_templates_code ON public.measurement_templates USING btree (code);


-- INDEX: idx_measurement_templates_framework_tags
CREATE INDEX IF NOT EXISTS idx_measurement_templates_framework_tags ON public.measurement_templates USING gin (framework_tags);


-- INDEX: idx_measurement_templates_measurement_type_id
CREATE INDEX IF NOT EXISTS idx_measurement_templates_measurement_type_id ON public.measurement_templates USING btree (measurement_type_id);


-- INDEX: idx_measurement_types_category
CREATE INDEX IF NOT EXISTS idx_measurement_types_category ON public.measurement_types USING btree (category);


-- INDEX: idx_measurement_types_code
CREATE INDEX IF NOT EXISTS idx_measurement_types_code ON public.measurement_types USING btree (code);


-- INDEX: idx_measurement_types_data_type
CREATE INDEX IF NOT EXISTS idx_measurement_types_data_type ON public.measurement_types USING btree (data_type);


-- INDEX: idx_mv_location_finding_summary_key
CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_location_finding_summary_key ON public.mv_location_finding_summary USING btree (location_id, environment);


-- INDEX: idx_mv_remediation_queue_tenant_severity
CREATE INDEX IF NOT EXISTS idx_mv_remediation_queue_tenant_severity ON public.mv_remediation_queue USING btree (tenant_id, severity, created_at);


-- INDEX: idx_network_assets_partitioned_deleted_at
CREATE INDEX IF NOT EXISTS idx_network_assets_partitioned_deleted_at ON ONLY public.network_assets_partitioned USING btree (deleted_at) WHERE (deleted_at IS NULL);


-- INDEX: idx_network_assets_partitioned_hostname
CREATE INDEX IF NOT EXISTS idx_network_assets_partitioned_hostname ON ONLY public.network_assets_partitioned USING btree (hostname);


-- INDEX: idx_network_assets_partitioned_ip_address
CREATE INDEX IF NOT EXISTS idx_network_assets_partitioned_ip_address ON ONLY public.network_assets_partitioned USING btree (ip_address);


-- INDEX: idx_network_assets_partitioned_tenant_id
CREATE INDEX IF NOT EXISTS idx_network_assets_partitioned_tenant_id ON ONLY public.network_assets_partitioned USING btree (tenant_id);


-- INDEX: idx_network_segments_active
CREATE INDEX IF NOT EXISTS idx_network_segments_active ON public.network_segments USING btree (tenant_id, is_active) WHERE (is_active = true);


-- INDEX: idx_network_segments_location_id
CREATE INDEX IF NOT EXISTS idx_network_segments_location_id ON public.network_segments USING btree (location_id);


-- INDEX: idx_network_segments_tenant_id
CREATE INDEX IF NOT EXISTS idx_network_segments_tenant_id ON public.network_segments USING btree (tenant_id);


-- INDEX: idx_notification_delivery_queue_next_retry
CREATE INDEX IF NOT EXISTS idx_notification_delivery_queue_next_retry ON public.notification_delivery_queue USING btree (next_retry_at) WHERE ((status)::text = 'retrying'::text);


-- INDEX: idx_notification_delivery_queue_notification_id
CREATE INDEX IF NOT EXISTS idx_notification_delivery_queue_notification_id ON public.notification_delivery_queue USING btree (notification_id);


-- INDEX: idx_notification_delivery_queue_status
CREATE INDEX IF NOT EXISTS idx_notification_delivery_queue_status ON public.notification_delivery_queue USING btree (status) WHERE ((status)::text = ANY ((ARRAY['pending'::character varying, 'retrying'::character varying])::text[]));


-- INDEX: idx_notification_delivery_queue_tenant_id
CREATE INDEX IF NOT EXISTS idx_notification_delivery_queue_tenant_id ON public.notification_delivery_queue USING btree (tenant_id) WHERE (tenant_id IS NOT NULL);


-- INDEX: idx_notification_history_alert_source
CREATE INDEX IF NOT EXISTS idx_notification_history_alert_source ON public.notification_history USING btree (alert_source);


-- INDEX: idx_notification_history_alert_type
CREATE INDEX IF NOT EXISTS idx_notification_history_alert_type ON public.notification_history USING btree (alert_type);


-- INDEX: idx_notification_history_created_at
CREATE INDEX IF NOT EXISTS idx_notification_history_created_at ON public.notification_history USING btree (created_at DESC);


-- INDEX: idx_notification_history_platform
CREATE INDEX IF NOT EXISTS idx_notification_history_platform ON public.notification_history USING btree (created_at DESC) WHERE (tenant_id IS NULL);


-- INDEX: idx_notification_history_severity
CREATE INDEX IF NOT EXISTS idx_notification_history_severity ON public.notification_history USING btree (severity);


-- INDEX: idx_notification_history_tenant_created
CREATE INDEX IF NOT EXISTS idx_notification_history_tenant_created ON public.notification_history USING btree (tenant_id, created_at DESC) WHERE (tenant_id IS NOT NULL);


-- INDEX: idx_notification_history_tenant_id
CREATE INDEX IF NOT EXISTS idx_notification_history_tenant_id ON public.notification_history USING btree (tenant_id) WHERE (tenant_id IS NOT NULL);


-- INDEX: idx_pcap_upload_jobs_status
CREATE INDEX IF NOT EXISTS idx_pcap_upload_jobs_status ON public.pcap_upload_jobs USING btree (status) WHERE (status = ANY (ARRAY['pending'::text, 'processing'::text]));


-- INDEX: idx_pcap_upload_jobs_tenant
CREATE INDEX IF NOT EXISTS idx_pcap_upload_jobs_tenant ON public.pcap_upload_jobs USING btree (tenant_id, created_at DESC);


-- INDEX: idx_pending_sensors_expires_at
CREATE INDEX IF NOT EXISTS idx_pending_sensors_expires_at ON public.pending_sensors USING btree (expires_at);


-- INDEX: idx_pending_sensors_registration_key
CREATE INDEX IF NOT EXISTS idx_pending_sensors_registration_key ON public.pending_sensors USING btree (registration_key);


-- INDEX: idx_pending_sensors_status
CREATE INDEX IF NOT EXISTS idx_pending_sensors_status ON public.pending_sensors USING btree (status);


-- INDEX: idx_pending_sensors_tenant_id
CREATE INDEX IF NOT EXISTS idx_pending_sensors_tenant_id ON public.pending_sensors USING btree (tenant_id);


-- INDEX: idx_pending_sensors_tenant_status
CREATE INDEX IF NOT EXISTS idx_pending_sensors_tenant_status ON public.pending_sensor_registrations USING btree (tenant_id, status);


-- INDEX: idx_permission_audit_created
CREATE INDEX IF NOT EXISTS idx_permission_audit_created ON public.permission_audit_logs USING btree (created_at);


-- INDEX: idx_permission_audit_tenant
CREATE INDEX IF NOT EXISTS idx_permission_audit_tenant ON public.permission_audit_logs USING btree (tenant_id);


-- INDEX: idx_permission_audit_user
CREATE INDEX IF NOT EXISTS idx_permission_audit_user ON public.permission_audit_logs USING btree (user_id);


-- INDEX: idx_plan_items_finding
CREATE INDEX IF NOT EXISTS idx_plan_items_finding ON public.remediation_plan_items USING btree (finding_id);


-- INDEX: idx_plan_items_plan
CREATE INDEX IF NOT EXISTS idx_plan_items_plan ON public.remediation_plan_items USING btree (plan_id);


-- INDEX: idx_plan_items_ticket
CREATE INDEX IF NOT EXISTS idx_plan_items_ticket ON public.remediation_plan_items USING btree (ticket_id) WHERE (ticket_id IS NOT NULL);


-- INDEX: idx_platform_announcements_active
CREATE INDEX IF NOT EXISTS idx_platform_announcements_active ON public.platform_announcements USING btree (is_active, starts_at, expires_at);


-- INDEX: idx_platform_bootstrap_ca_active
CREATE INDEX IF NOT EXISTS idx_platform_bootstrap_ca_active ON public.platform_bootstrap_ca USING btree (is_active) WHERE (is_active = true);


-- INDEX: idx_platform_bootstrap_ca_expires_at
CREATE INDEX IF NOT EXISTS idx_platform_bootstrap_ca_expires_at ON public.platform_bootstrap_ca USING btree (expires_at);


-- INDEX: idx_platform_bootstrap_certificates_expires_at
CREATE INDEX IF NOT EXISTS idx_platform_bootstrap_certificates_expires_at ON public.platform_bootstrap_certificates USING btree (expires_at);


-- INDEX: idx_platform_bootstrap_certificates_revoked
CREATE INDEX IF NOT EXISTS idx_platform_bootstrap_certificates_revoked ON public.platform_bootstrap_certificates USING btree (service_name, revoked_at) WHERE (revoked_at IS NOT NULL);


-- INDEX: idx_platform_bootstrap_certificates_service_name
CREATE INDEX IF NOT EXISTS idx_platform_bootstrap_certificates_service_name ON public.platform_bootstrap_certificates USING btree (service_name);


-- INDEX: idx_platform_framework_controls_control_id
CREATE INDEX IF NOT EXISTS idx_platform_framework_controls_control_id ON public.platform_framework_controls USING btree (control_id);


-- INDEX: idx_platform_framework_controls_crypto_relevant
CREATE INDEX IF NOT EXISTS idx_platform_framework_controls_crypto_relevant ON public.platform_framework_controls USING btree (crypto_relevant);


-- INDEX: idx_platform_framework_controls_family_id
CREATE INDEX IF NOT EXISTS idx_platform_framework_controls_family_id ON public.platform_framework_controls USING btree (family_id);


-- INDEX: idx_platform_framework_controls_framework_id
CREATE INDEX IF NOT EXISTS idx_platform_framework_controls_framework_id ON public.platform_framework_controls USING btree (framework_id);


-- INDEX: idx_platform_frameworks_code
CREATE INDEX IF NOT EXISTS idx_platform_frameworks_code ON public.platform_frameworks USING btree (code);


-- INDEX: idx_platform_frameworks_is_platform_default
CREATE INDEX IF NOT EXISTS idx_platform_frameworks_is_platform_default ON public.platform_frameworks USING btree (is_platform_default) WHERE (is_platform_default = true);


-- INDEX: idx_platform_frameworks_published_at
CREATE INDEX IF NOT EXISTS idx_platform_frameworks_published_at ON public.platform_frameworks USING btree (published_at) WHERE ((status)::text = 'published'::text);


-- INDEX: idx_platform_frameworks_single_default
CREATE UNIQUE INDEX IF NOT EXISTS idx_platform_frameworks_single_default ON public.platform_frameworks USING btree (is_platform_default) WHERE (is_platform_default = true);


-- INDEX: idx_platform_frameworks_status
CREATE INDEX IF NOT EXISTS idx_platform_frameworks_status ON public.platform_frameworks USING btree (status);


-- INDEX: idx_platform_integrations_active
CREATE INDEX IF NOT EXISTS idx_platform_integrations_active ON public.platform_integrations USING btree (is_active) WHERE (deleted_at IS NULL);


-- INDEX: idx_platform_integrations_enabled
CREATE INDEX IF NOT EXISTS idx_platform_integrations_enabled ON public.platform_integrations USING btree (is_enabled) WHERE (is_active = true);


-- INDEX: idx_platform_integrations_shared
CREATE INDEX IF NOT EXISTS idx_platform_integrations_shared ON public.platform_integrations USING btree (is_shared) WHERE ((is_shared = true) AND (deleted_at IS NULL));


-- INDEX: idx_platform_integrations_status
CREATE INDEX IF NOT EXISTS idx_platform_integrations_status ON public.platform_integrations USING btree (status);


-- INDEX: idx_platform_integrations_tenant_id
CREATE INDEX IF NOT EXISTS idx_platform_integrations_tenant_id ON public.platform_integrations USING btree (tenant_id) WHERE (tenant_id IS NOT NULL);


-- INDEX: idx_platform_integrations_type
CREATE INDEX IF NOT EXISTS idx_platform_integrations_type ON public.platform_integrations USING btree (integration_type);


-- INDEX: idx_platform_integrations_unique_name
CREATE UNIQUE INDEX IF NOT EXISTS idx_platform_integrations_unique_name ON public.platform_integrations USING btree (integration_type, integration_name) WHERE (deleted_at IS NULL);


-- INDEX: idx_platform_log_metadata_compliance
CREATE INDEX IF NOT EXISTS idx_platform_log_metadata_compliance ON public.platform_log_metadata USING gin (compliance_tags);


-- INDEX: idx_platform_log_metadata_correlation_id
CREATE INDEX IF NOT EXISTS idx_platform_log_metadata_correlation_id ON public.platform_log_metadata USING btree (correlation_id, "timestamp" DESC);


-- INDEX: idx_platform_log_metadata_event_type
CREATE INDEX IF NOT EXISTS idx_platform_log_metadata_event_type ON public.platform_log_metadata USING btree (event_type, "timestamp" DESC);


-- INDEX: idx_platform_log_metadata_pii
CREATE INDEX IF NOT EXISTS idx_platform_log_metadata_pii ON public.platform_log_metadata USING btree (pii_detected, "timestamp" DESC) WHERE (pii_detected = true);


-- INDEX: idx_platform_log_metadata_retention
CREATE INDEX IF NOT EXISTS idx_platform_log_metadata_retention ON public.platform_log_metadata USING btree (retention_policy, archived_at, deleted_at);


-- INDEX: idx_platform_log_metadata_service
CREATE INDEX IF NOT EXISTS idx_platform_log_metadata_service ON public.platform_log_metadata USING btree (service_name, "timestamp" DESC);


-- INDEX: idx_platform_log_metadata_severity
CREATE INDEX IF NOT EXISTS idx_platform_log_metadata_severity ON public.platform_log_metadata USING btree (severity, "timestamp" DESC);


-- INDEX: idx_platform_log_metadata_status
CREATE INDEX IF NOT EXISTS idx_platform_log_metadata_status ON public.platform_log_metadata USING btree (status, "timestamp" DESC);


-- INDEX: idx_platform_log_metadata_tenant
CREATE INDEX IF NOT EXISTS idx_platform_log_metadata_tenant ON public.platform_log_metadata USING btree (tenant_id, "timestamp" DESC) WHERE (tenant_id IS NOT NULL);


-- INDEX: idx_platform_log_metadata_timestamp
CREATE INDEX IF NOT EXISTS idx_platform_log_metadata_timestamp ON public.platform_log_metadata USING btree ("timestamp" DESC);


-- INDEX: idx_platform_metrics_service_time
CREATE INDEX IF NOT EXISTS idx_platform_metrics_service_time ON public.platform_metrics_snapshots USING btree (service_name, window_start DESC);


-- INDEX: idx_platform_metrics_service_window
CREATE INDEX IF NOT EXISTS idx_platform_metrics_service_window ON public.platform_metrics_snapshots USING btree (service_name, window_duration, window_start DESC);


-- INDEX: idx_platform_metrics_window
CREATE INDEX IF NOT EXISTS idx_platform_metrics_window ON public.platform_metrics_snapshots USING btree (window_start DESC, window_duration);


-- INDEX: idx_platform_notification_channels_enabled
CREATE INDEX IF NOT EXISTS idx_platform_notification_channels_enabled ON public.platform_notification_channels USING btree (enabled) WHERE (enabled = true);


-- INDEX: idx_platform_notification_channels_type
CREATE INDEX IF NOT EXISTS idx_platform_notification_channels_type ON public.platform_notification_channels USING btree (channel_type);


-- INDEX: idx_platform_notification_rules_alert_source
CREATE INDEX IF NOT EXISTS idx_platform_notification_rules_alert_source ON public.platform_notification_rules USING btree (alert_source);


-- INDEX: idx_platform_notification_rules_enabled
CREATE INDEX IF NOT EXISTS idx_platform_notification_rules_enabled ON public.platform_notification_rules USING btree (enabled) WHERE (enabled = true);


-- INDEX: idx_platform_notification_rules_priority
CREATE INDEX IF NOT EXISTS idx_platform_notification_rules_priority ON public.platform_notification_rules USING btree (priority DESC);


-- INDEX: idx_platform_refresh_tokens_expires_at
CREATE INDEX IF NOT EXISTS idx_platform_refresh_tokens_expires_at ON public.platform_refresh_tokens USING btree (expires_at);


-- INDEX: idx_platform_refresh_tokens_family_id
CREATE INDEX IF NOT EXISTS idx_platform_refresh_tokens_family_id ON public.platform_refresh_tokens USING btree (family_id);


-- INDEX: idx_platform_refresh_tokens_user_id
CREATE INDEX IF NOT EXISTS idx_platform_refresh_tokens_user_id ON public.platform_refresh_tokens USING btree (platform_user_id);


-- INDEX: idx_platform_role_permissions_permission
CREATE INDEX IF NOT EXISTS idx_platform_role_permissions_permission ON public.platform_role_permissions USING btree (permission_id);


-- INDEX: idx_platform_role_permissions_role
CREATE INDEX IF NOT EXISTS idx_platform_role_permissions_role ON public.platform_role_permissions USING btree (role_id);


-- INDEX: idx_platform_service_ca_active
CREATE INDEX IF NOT EXISTS idx_platform_service_ca_active ON public.platform_service_ca USING btree (is_active) WHERE (is_active = true);


-- INDEX: idx_platform_service_ca_expires_at
CREATE INDEX IF NOT EXISTS idx_platform_service_ca_expires_at ON public.platform_service_ca USING btree (expires_at);


-- INDEX: idx_platform_service_certificates_expires_at
CREATE INDEX IF NOT EXISTS idx_platform_service_certificates_expires_at ON public.platform_service_certificates USING btree (expires_at);


-- INDEX: idx_platform_service_certificates_revoked
CREATE INDEX IF NOT EXISTS idx_platform_service_certificates_revoked ON public.platform_service_certificates USING btree (service_name, revoked_at) WHERE (revoked_at IS NOT NULL);


-- INDEX: idx_platform_service_certificates_service_name
CREATE INDEX IF NOT EXISTS idx_platform_service_certificates_service_name ON public.platform_service_certificates USING btree (service_name);


-- INDEX: idx_platform_settings_key
CREATE INDEX IF NOT EXISTS idx_platform_settings_key ON public.platform_settings USING btree (setting_key);


-- INDEX: uq_platform_sso_provider_type_purpose
-- One provider row per (provider_type, purpose) — see the note on the purpose
-- column. This replaced a provider_type-only UNIQUE constraint, which allowed
-- only ONE google row across both purposes.
CREATE UNIQUE INDEX IF NOT EXISTS uq_platform_sso_provider_type_purpose ON public.platform_sso_providers USING btree (provider_type, purpose);


-- INDEX: idx_platform_sso_providers_enabled
CREATE INDEX IF NOT EXISTS idx_platform_sso_providers_enabled ON public.platform_sso_providers USING btree (is_enabled) WHERE (is_enabled = true);


-- INDEX: idx_platform_users_email
CREATE INDEX IF NOT EXISTS idx_platform_users_email ON public.platform_users USING btree (email) WHERE (deleted_at IS NULL);


-- INDEX: idx_platform_users_reset_token
CREATE INDEX IF NOT EXISTS idx_platform_users_reset_token ON public.platform_users USING btree (password_reset_token) WHERE (password_reset_token IS NOT NULL);


-- INDEX: idx_platform_users_role
CREATE INDEX IF NOT EXISTS idx_platform_users_role ON public.platform_users USING btree (role_id) WHERE (deleted_at IS NULL);


-- INDEX: idx_refresh_tokens_expires_at
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON public.refresh_tokens USING btree (expires_at);


-- INDEX: idx_refresh_tokens_family_id
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family_id ON public.refresh_tokens USING btree (family_id);


-- INDEX: idx_refresh_tokens_user_id
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON public.refresh_tokens USING btree (user_id);


-- INDEX: idx_remediation_plans_description_trgm
CREATE INDEX IF NOT EXISTS idx_remediation_plans_description_trgm ON public.remediation_plans USING gin (description public.gin_trgm_ops);


-- INDEX: idx_remediation_plans_owner
CREATE INDEX IF NOT EXISTS idx_remediation_plans_owner ON public.remediation_plans USING btree (tenant_id, owner_id) WHERE (owner_id IS NOT NULL);


-- INDEX: idx_remediation_plans_target_date
CREATE INDEX IF NOT EXISTS idx_remediation_plans_target_date ON public.remediation_plans USING btree (tenant_id, target_date) WHERE (target_date IS NOT NULL);


-- INDEX: idx_remediation_plans_tenant
CREATE INDEX IF NOT EXISTS idx_remediation_plans_tenant ON public.remediation_plans USING btree (tenant_id);


-- INDEX: idx_remediation_plans_tenant_status
CREATE INDEX IF NOT EXISTS idx_remediation_plans_tenant_status ON public.remediation_plans USING btree (tenant_id, status);


-- INDEX: idx_remediation_plans_title_trgm
CREATE INDEX IF NOT EXISTS idx_remediation_plans_title_trgm ON public.remediation_plans USING gin (title public.gin_trgm_ops);


-- INDEX: idx_resource_alerts_is_active
CREATE INDEX IF NOT EXISTS idx_resource_alerts_is_active ON public.resource_alerts USING btree (is_active);


-- INDEX: idx_resource_alerts_severity
CREATE INDEX IF NOT EXISTS idx_resource_alerts_severity ON public.resource_alerts USING btree (severity);


-- INDEX: idx_resource_alerts_tenant_id
CREATE INDEX IF NOT EXISTS idx_resource_alerts_tenant_id ON public.resource_alerts USING btree (tenant_id);


-- INDEX: idx_resource_permissions_owner
CREATE INDEX IF NOT EXISTS idx_resource_permissions_owner ON public.resource_permissions USING btree (owner_id);


-- INDEX: idx_resource_permissions_tenant
CREATE INDEX IF NOT EXISTS idx_resource_permissions_tenant ON public.resource_permissions USING btree (tenant_id);


-- INDEX: idx_resource_permissions_type_id
CREATE INDEX IF NOT EXISTS idx_resource_permissions_type_id ON public.resource_permissions USING btree (resource_type, resource_id);


-- INDEX: idx_rule_vulnerability_mappings_finding_type
CREATE INDEX IF NOT EXISTS idx_rule_vulnerability_mappings_finding_type ON public.rule_vulnerability_mappings USING btree (finding_type);


-- INDEX: idx_rule_vulnerability_mappings_framework_id
CREATE INDEX IF NOT EXISTS idx_rule_vulnerability_mappings_framework_id ON public.rule_vulnerability_mappings USING btree (framework_id);


-- INDEX: idx_rule_vulnerability_mappings_predicate
CREATE INDEX IF NOT EXISTS idx_rule_vulnerability_mappings_predicate ON public.rule_vulnerability_mappings USING gin (predicate);


-- INDEX: idx_rule_vulnerability_mappings_rule_id
CREATE INDEX IF NOT EXISTS idx_rule_vulnerability_mappings_rule_id ON public.rule_vulnerability_mappings USING btree (rule_id);


-- INDEX: idx_schedule_history_job_id
CREATE INDEX IF NOT EXISTS idx_schedule_history_job_id ON public.schedule_history USING btree (job_id);


-- INDEX: idx_schedule_history_schedule_id
CREATE INDEX IF NOT EXISTS idx_schedule_history_schedule_id ON public.schedule_history USING btree (schedule_id);


-- INDEX: idx_schedule_history_started_at
CREATE INDEX IF NOT EXISTS idx_schedule_history_started_at ON public.schedule_history USING btree (started_at DESC);


-- INDEX: idx_security_events_anomaly
CREATE INDEX IF NOT EXISTS idx_security_events_anomaly ON public.security_events USING btree (is_anomaly, "timestamp" DESC) WHERE (is_anomaly = true);


-- INDEX: idx_security_events_compliance
CREATE INDEX IF NOT EXISTS idx_security_events_compliance ON public.security_events USING gin (compliance_tags);


-- INDEX: idx_security_events_correlation
CREATE INDEX IF NOT EXISTS idx_security_events_correlation ON public.security_events USING btree (correlation_id, "timestamp" DESC) WHERE (correlation_id IS NOT NULL);


-- INDEX: idx_security_events_requires_attention
CREATE INDEX IF NOT EXISTS idx_security_events_requires_attention ON public.security_events USING btree (requires_attention, "timestamp" DESC) WHERE (requires_attention = true);


-- INDEX: idx_security_events_risk
CREATE INDEX IF NOT EXISTS idx_security_events_risk ON public.security_events USING btree (risk_level, "timestamp" DESC);


-- INDEX: idx_security_events_severity
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON public.security_events USING btree (severity, "timestamp" DESC);


-- INDEX: idx_security_events_status
CREATE INDEX IF NOT EXISTS idx_security_events_status ON public.security_events USING btree (status, "timestamp" DESC);


-- INDEX: idx_security_events_tenant
CREATE INDEX IF NOT EXISTS idx_security_events_tenant ON public.security_events USING btree (tenant_id, "timestamp" DESC) WHERE (tenant_id IS NOT NULL);


-- INDEX: idx_security_events_timestamp
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON public.security_events USING btree ("timestamp" DESC);


-- INDEX: idx_security_events_type
CREATE INDEX IF NOT EXISTS idx_security_events_type ON public.security_events USING btree (event_type, "timestamp" DESC);


-- INDEX: idx_security_events_user
CREATE INDEX IF NOT EXISTS idx_security_events_user ON public.security_events USING btree (user_id, "timestamp" DESC) WHERE (user_id IS NOT NULL);


-- INDEX: idx_security_incidents_assigned
CREATE INDEX IF NOT EXISTS idx_security_incidents_assigned ON public.security_incidents USING btree (assigned_to, status) WHERE (assigned_to IS NOT NULL);


-- INDEX: idx_security_incidents_detected
CREATE INDEX IF NOT EXISTS idx_security_incidents_detected ON public.security_incidents USING btree (detected_at DESC);


-- INDEX: idx_security_incidents_severity
CREATE INDEX IF NOT EXISTS idx_security_incidents_severity ON public.security_incidents USING btree (severity, detected_at DESC);


-- INDEX: idx_security_incidents_status
CREATE INDEX IF NOT EXISTS idx_security_incidents_status ON public.security_incidents USING btree (status, severity, detected_at DESC);


-- INDEX: idx_security_incidents_tenant
CREATE INDEX IF NOT EXISTS idx_security_incidents_tenant ON public.security_incidents USING gin (affected_tenants);


-- INDEX: idx_sensor_ca_certificates_active
CREATE INDEX IF NOT EXISTS idx_sensor_ca_certificates_active ON public.sensor_ca_certificates USING btree (tenant_id, is_active) WHERE (is_active = true);


-- INDEX: idx_sensor_ca_certificates_expires_at
CREATE INDEX IF NOT EXISTS idx_sensor_ca_certificates_expires_at ON public.sensor_ca_certificates USING btree (expires_at);


-- INDEX: idx_sensor_ca_certificates_tenant_id
CREATE INDEX IF NOT EXISTS idx_sensor_ca_certificates_tenant_id ON public.sensor_ca_certificates USING btree (tenant_id);


-- INDEX: idx_sensor_certificates_expires_at
CREATE INDEX IF NOT EXISTS idx_sensor_certificates_expires_at ON public.sensor_certificates USING btree (expires_at);


-- INDEX: idx_sensor_certificates_revoked
CREATE INDEX IF NOT EXISTS idx_sensor_certificates_revoked ON public.sensor_certificates USING btree (sensor_id, revoked_at) WHERE (revoked_at IS NOT NULL);


-- INDEX: idx_sensor_certificates_sensor_id
CREATE INDEX IF NOT EXISTS idx_sensor_certificates_sensor_id ON public.sensor_certificates USING btree (sensor_id);


-- INDEX: idx_sensor_certificates_tenant_id
CREATE INDEX IF NOT EXISTS idx_sensor_certificates_tenant_id ON public.sensor_certificates USING btree (tenant_id);


-- INDEX: idx_sensor_commands_created_at
CREATE INDEX IF NOT EXISTS idx_sensor_commands_created_at ON public.sensor_commands USING btree (created_at);


-- INDEX: idx_sensor_commands_sensor_id
CREATE INDEX IF NOT EXISTS idx_sensor_commands_sensor_id ON public.sensor_commands USING btree (sensor_id);


-- INDEX: idx_sensor_commands_status
CREATE INDEX IF NOT EXISTS idx_sensor_commands_status ON public.sensor_commands USING btree (status);


-- INDEX: idx_sensor_discoveries_partitioned_batch_id
CREATE INDEX IF NOT EXISTS idx_sensor_discoveries_partitioned_batch_id ON ONLY public.sensor_discoveries_partitioned USING btree (batch_id);


-- INDEX: idx_sensor_discoveries_partitioned_dest_ip
CREATE INDEX IF NOT EXISTS idx_sensor_discoveries_partitioned_dest_ip ON ONLY public.sensor_discoveries_partitioned USING btree (dest_ip);


-- INDEX: idx_sensor_discoveries_partitioned_protocol
CREATE INDEX IF NOT EXISTS idx_sensor_discoveries_partitioned_protocol ON ONLY public.sensor_discoveries_partitioned USING btree (protocol);


-- INDEX: idx_sensor_discoveries_part_unprocessed
-- The poller's index. Partial, so it holds only rows that are still work: on a
-- healthy system that is near-empty and the poll is O(1) rather than O(all
-- discoveries ever).
CREATE INDEX IF NOT EXISTS idx_sensor_discoveries_part_unprocessed ON public.sensor_discoveries_partitioned USING btree (batch_id, tenant_id) WHERE (processed_at IS NULL);


-- INDEX: idx_sensor_discoveries_part_sensor_timestamp
-- sensor-manager ListSensorDiscoveries: WHERE sensor_id = $1 ORDER BY timestamp
-- DESC LIMIT $2 — the composite serves both the filter and the sort.
CREATE INDEX IF NOT EXISTS idx_sensor_discoveries_part_sensor_timestamp ON public.sensor_discoveries_partitioned USING btree (sensor_id, "timestamp" DESC);


-- INDEX: idx_sensor_discoveries_part_claimed
-- Candidate selection reads `claimed_at IS NULL OR claimed_at < now() - ...`
-- alongside `processed_at IS NULL`; same partial shape.
CREATE INDEX IF NOT EXISTS idx_sensor_discoveries_part_claimed ON public.sensor_discoveries_partitioned USING btree (claimed_at) WHERE (processed_at IS NULL);


-- INDEX: idx_sensor_discoveries_partitioned_sensor_id
CREATE INDEX IF NOT EXISTS idx_sensor_discoveries_partitioned_sensor_id ON ONLY public.sensor_discoveries_partitioned USING btree (sensor_id);


-- INDEX: idx_sensor_discoveries_partitioned_tenant_id
CREATE INDEX IF NOT EXISTS idx_sensor_discoveries_partitioned_tenant_id ON ONLY public.sensor_discoveries_partitioned USING btree (tenant_id);


-- INDEX: idx_sensor_discoveries_partitioned_timestamp
CREATE INDEX IF NOT EXISTS idx_sensor_discoveries_partitioned_timestamp ON ONLY public.sensor_discoveries_partitioned USING btree ("timestamp");


-- INDEX: idx_sensor_health_metrics_recorded_at
CREATE INDEX IF NOT EXISTS idx_sensor_health_metrics_recorded_at ON public.sensor_health_metrics USING btree (recorded_at);


-- INDEX: idx_sensor_health_metrics_sensor_id
CREATE INDEX IF NOT EXISTS idx_sensor_health_metrics_sensor_id ON public.sensor_health_metrics USING btree (sensor_id);


-- INDEX: idx_sensors_deleted_at
CREATE INDEX IF NOT EXISTS idx_sensors_deleted_at ON public.sensors USING btree (deleted_at) WHERE (deleted_at IS NULL);


-- INDEX: idx_sensors_ip_address
CREATE INDEX IF NOT EXISTS idx_sensors_ip_address ON public.sensors USING btree (ip_address);


-- INDEX: idx_sensors_last_heartbeat
CREATE INDEX IF NOT EXISTS idx_sensors_last_heartbeat ON public.sensors USING btree (last_heartbeat);


-- INDEX: idx_sensors_sensor_type
CREATE INDEX IF NOT EXISTS idx_sensors_sensor_type ON public.sensors USING btree (sensor_type);


-- INDEX: idx_sensors_status
CREATE INDEX IF NOT EXISTS idx_sensors_status ON public.sensors USING btree (status);


-- INDEX: idx_sensors_tenant_id
CREATE INDEX IF NOT EXISTS idx_sensors_tenant_id ON public.sensors USING btree (tenant_id);


-- INDEX: idx_service_accounts_is_active
CREATE INDEX IF NOT EXISTS idx_service_accounts_is_active ON public.service_accounts USING btree (is_active) WHERE (is_active = true);


-- INDEX: idx_service_accounts_service_name
CREATE INDEX IF NOT EXISTS idx_service_accounts_service_name ON public.service_accounts USING btree (service_name);


-- INDEX: idx_service_identification_rules_port_protocol
CREATE INDEX IF NOT EXISTS idx_service_identification_rules_port_protocol ON public.service_identification_rules USING btree (port, protocol);


-- INDEX: idx_service_identification_rules_tenant
CREATE INDEX IF NOT EXISTS idx_service_identification_rules_tenant ON public.service_identification_rules USING btree (tenant_id) WHERE (tenant_id IS NOT NULL);


-- INDEX: idx_ssh_keys_asset
CREATE INDEX IF NOT EXISTS idx_ssh_keys_asset ON public.ssh_keys USING btree (asset_id) WHERE ((asset_id IS NOT NULL) AND (deleted_at IS NULL));


-- INDEX: idx_ssh_keys_tenant
CREATE INDEX IF NOT EXISTS idx_ssh_keys_tenant ON public.ssh_keys USING btree (tenant_id) WHERE (deleted_at IS NULL);


-- INDEX: idx_ssh_keys_type
CREATE INDEX IF NOT EXISTS idx_ssh_keys_type ON public.ssh_keys USING btree (key_type) WHERE (deleted_at IS NULL);


-- INDEX: idx_ssh_keys_unique_fingerprint
CREATE UNIQUE INDEX IF NOT EXISTS idx_ssh_keys_unique_fingerprint ON public.ssh_keys USING btree (tenant_id, fingerprint_sha256) WHERE (deleted_at IS NULL);


-- INDEX: idx_ssh_keys_weak
CREATE INDEX IF NOT EXISTS idx_ssh_keys_weak ON public.ssh_keys USING btree (is_weak) WHERE ((is_weak = true) AND (deleted_at IS NULL));


-- INDEX: idx_sso_group_role_mappings_provider
CREATE INDEX IF NOT EXISTS idx_sso_group_role_mappings_provider ON public.sso_group_role_mappings USING btree (sso_provider_id);


-- INDEX: idx_sso_group_role_mappings_tenant
CREATE INDEX IF NOT EXISTS idx_sso_group_role_mappings_tenant ON public.sso_group_role_mappings USING btree (tenant_id);


-- INDEX: idx_sso_providers_tenant_id
CREATE INDEX IF NOT EXISTS idx_sso_providers_tenant_id ON public.sso_providers USING btree (tenant_id);


-- INDEX: idx_sso_providers_type
CREATE INDEX IF NOT EXISTS idx_sso_providers_type ON public.sso_providers USING btree (provider_type);


-- INDEX: idx_subscription_tier_history_change_type
CREATE INDEX IF NOT EXISTS idx_subscription_tier_history_change_type ON public.subscription_tier_history USING btree (change_type);


-- INDEX: idx_subscription_tier_history_changed_at
CREATE INDEX IF NOT EXISTS idx_subscription_tier_history_changed_at ON public.subscription_tier_history USING btree (changed_at);


-- INDEX: idx_subscription_tier_history_tier_id
CREATE INDEX IF NOT EXISTS idx_subscription_tier_history_tier_id ON public.subscription_tier_history USING btree (tier_id);


-- INDEX: idx_subscription_tiers_active
CREATE INDEX IF NOT EXISTS idx_subscription_tiers_active ON public.subscription_tiers USING btree (is_active, deprecated_at) WHERE ((is_active = true) AND (deprecated_at IS NULL));


-- INDEX: idx_subscription_tiers_owner_tenant
CREATE INDEX IF NOT EXISTS idx_subscription_tiers_owner_tenant ON public.subscription_tiers USING btree (owner_tenant_id) WHERE (owner_tenant_id IS NOT NULL);


-- INDEX: idx_subscription_tiers_display_order
CREATE INDEX IF NOT EXISTS idx_subscription_tiers_display_order ON public.subscription_tiers USING btree (display_order) WHERE (deprecated_at IS NULL);


-- INDEX: idx_subscription_tiers_stripe_price_annual
CREATE INDEX IF NOT EXISTS idx_subscription_tiers_stripe_price_annual ON public.subscription_tiers USING btree (stripe_price_id_annual) WHERE (stripe_price_id_annual IS NOT NULL);


-- INDEX: idx_support_ticket_messages_ticket
CREATE INDEX IF NOT EXISTS idx_support_ticket_messages_ticket ON public.support_ticket_messages USING btree (ticket_id);


-- INDEX: idx_support_tickets_status
CREATE INDEX IF NOT EXISTS idx_support_tickets_status ON public.support_tickets USING btree (status);


-- INDEX: idx_support_tickets_tenant
CREATE INDEX IF NOT EXISTS idx_support_tickets_tenant ON public.support_tickets USING btree (tenant_id);


-- INDEX: idx_sync_outbox_pending
CREATE INDEX IF NOT EXISTS idx_sync_outbox_pending ON public.sync_outbox USING btree (status, next_attempt_at);


-- INDEX: idx_sync_outbox_tenant
CREATE INDEX IF NOT EXISTS idx_sync_outbox_tenant ON public.sync_outbox USING btree (tenant_id);


-- INDEX: idx_system_health_service_time
CREATE INDEX IF NOT EXISTS idx_system_health_service_time ON public.system_health_metrics USING btree (service_name, "timestamp" DESC);


-- INDEX: idx_tenant_admin_settings_audit_tenant_time
CREATE INDEX IF NOT EXISTS idx_tenant_admin_settings_audit_tenant_time ON public.tenant_admin_settings_audit USING btree (tenant_id, created_at DESC);


-- INDEX: idx_tenant_admin_settings_audit_user
CREATE INDEX IF NOT EXISTS idx_tenant_admin_settings_audit_user ON public.tenant_admin_settings_audit USING btree (changed_by, created_at DESC);


-- INDEX: idx_tenant_admin_settings_tenant_id
CREATE INDEX IF NOT EXISTS idx_tenant_admin_settings_tenant_id ON public.tenant_admin_settings USING btree (tenant_id);


-- INDEX: idx_tenant_admin_settings_version
CREATE INDEX IF NOT EXISTS idx_tenant_admin_settings_version ON public.tenant_admin_settings USING btree (tenant_id, version);


-- INDEX: idx_tenant_cost_analysis_period
CREATE INDEX IF NOT EXISTS idx_tenant_cost_analysis_period ON public.tenant_cost_analysis USING btree (period_start, period_end);


-- INDEX: idx_tenant_cost_analysis_tenant_id
CREATE INDEX IF NOT EXISTS idx_tenant_cost_analysis_tenant_id ON public.tenant_cost_analysis USING btree (tenant_id);


-- INDEX: idx_tenant_cost_summary_unique
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_cost_summary_unique ON public.tenant_cost_summary USING btree (tenant_id, cost_date);


-- INDEX: idx_tenant_framework_controls_control_id
CREATE INDEX IF NOT EXISTS idx_tenant_framework_controls_control_id ON public.tenant_framework_controls USING btree (control_id);


-- INDEX: idx_tenant_framework_controls_crypto_relevant
CREATE INDEX IF NOT EXISTS idx_tenant_framework_controls_crypto_relevant ON public.tenant_framework_controls USING btree (crypto_relevant);


-- INDEX: idx_tenant_framework_controls_family_id
CREATE INDEX IF NOT EXISTS idx_tenant_framework_controls_family_id ON public.tenant_framework_controls USING btree (family_id);


-- INDEX: idx_tenant_framework_controls_framework_id
CREATE INDEX IF NOT EXISTS idx_tenant_framework_controls_framework_id ON public.tenant_framework_controls USING btree (framework_id);


-- INDEX: idx_tenant_framework_licenses_expires
CREATE INDEX IF NOT EXISTS idx_tenant_framework_licenses_expires ON public.tenant_framework_licenses USING btree (subscription_expires_at) WHERE (subscription_expires_at IS NOT NULL);


-- INDEX: idx_tenant_framework_licenses_is_default
CREATE INDEX IF NOT EXISTS idx_tenant_framework_licenses_is_default ON public.tenant_framework_licenses USING btree (tenant_id, is_default) WHERE (is_default = true);


-- INDEX: idx_tenant_framework_licenses_is_locked
CREATE INDEX IF NOT EXISTS idx_tenant_framework_licenses_is_locked ON public.tenant_framework_licenses USING btree (tenant_id, is_locked);


-- INDEX: idx_tenant_framework_licenses_platform_framework_id
CREATE INDEX IF NOT EXISTS idx_tenant_framework_licenses_platform_framework_id ON public.tenant_framework_licenses USING btree (platform_framework_id);


-- INDEX: idx_tenant_framework_licenses_subscription_status
CREATE INDEX IF NOT EXISTS idx_tenant_framework_licenses_subscription_status ON public.tenant_framework_licenses USING btree (tenant_id, subscription_status);


-- INDEX: idx_tenant_framework_licenses_tenant_id
CREATE INDEX IF NOT EXISTS idx_tenant_framework_licenses_tenant_id ON public.tenant_framework_licenses USING btree (tenant_id);


-- INDEX: idx_tenant_frameworks_name
CREATE INDEX IF NOT EXISTS idx_tenant_frameworks_name ON public.tenant_frameworks USING btree (name);


-- INDEX: idx_tenant_frameworks_source_framework_id
CREATE INDEX IF NOT EXISTS idx_tenant_frameworks_source_framework_id ON public.tenant_frameworks USING btree (source_framework_id);


-- INDEX: idx_tenant_frameworks_tenant_id
CREATE INDEX IF NOT EXISTS idx_tenant_frameworks_tenant_id ON public.tenant_frameworks USING btree (tenant_id);


-- INDEX: idx_tenant_geo_country
CREATE INDEX IF NOT EXISTS idx_tenant_geo_country ON public.tenant_geographic_data USING btree (country_code);


-- INDEX: idx_tenant_geo_tenant_id
CREATE INDEX IF NOT EXISTS idx_tenant_geo_tenant_id ON public.tenant_geographic_data USING btree (tenant_id);


-- INDEX: idx_tenant_health_health_status
CREATE INDEX IF NOT EXISTS idx_tenant_health_health_status ON public.tenant_health USING btree (health_status);


-- INDEX: idx_tenant_health_last_calculated
CREATE INDEX IF NOT EXISTS idx_tenant_health_last_calculated ON public.tenant_health USING btree (last_calculated);


-- INDEX: idx_tenant_health_overall_score
CREATE INDEX IF NOT EXISTS idx_tenant_health_overall_score ON public.tenant_health USING btree (overall_score);


-- INDEX: idx_tenant_health_tenant_id
CREATE INDEX IF NOT EXISTS idx_tenant_health_tenant_id ON public.tenant_health USING btree (tenant_id);


-- INDEX: idx_tenant_measurement_overrides_measurement
CREATE INDEX IF NOT EXISTS idx_tenant_measurement_overrides_measurement ON public.tenant_measurement_overrides USING btree (control_measurement_id);


-- INDEX: idx_tenant_measurement_overrides_tenant
CREATE INDEX IF NOT EXISTS idx_tenant_measurement_overrides_tenant ON public.tenant_measurement_overrides USING btree (tenant_id);


-- INDEX: idx_tenant_notes_tenant
CREATE INDEX IF NOT EXISTS idx_tenant_notes_tenant ON public.tenant_notes USING btree (tenant_id);


-- INDEX: idx_tenant_notification_channels_enabled
CREATE INDEX IF NOT EXISTS idx_tenant_notification_channels_enabled ON public.tenant_notification_channels USING btree (enabled) WHERE (enabled = true);


-- INDEX: idx_tenant_notification_channels_tenant_id
CREATE INDEX IF NOT EXISTS idx_tenant_notification_channels_tenant_id ON public.tenant_notification_channels USING btree (tenant_id);


-- INDEX: idx_tenant_notification_channels_type
CREATE INDEX IF NOT EXISTS idx_tenant_notification_channels_type ON public.tenant_notification_channels USING btree (channel_type);


-- INDEX: idx_tenant_notification_rules_alert_source
CREATE INDEX IF NOT EXISTS idx_tenant_notification_rules_alert_source ON public.tenant_notification_rules USING btree (alert_source);


-- INDEX: idx_tenant_notification_rules_enabled
CREATE INDEX IF NOT EXISTS idx_tenant_notification_rules_enabled ON public.tenant_notification_rules USING btree (enabled) WHERE (enabled = true);


-- INDEX: idx_tenant_notification_rules_priority
CREATE INDEX IF NOT EXISTS idx_tenant_notification_rules_priority ON public.tenant_notification_rules USING btree (priority DESC);


-- INDEX: idx_tenant_notification_rules_tenant_id
CREATE INDEX IF NOT EXISTS idx_tenant_notification_rules_tenant_id ON public.tenant_notification_rules USING btree (tenant_id);


-- INDEX: idx_tenant_resource_usage_tenant_cost
CREATE INDEX IF NOT EXISTS idx_tenant_resource_usage_tenant_cost ON public.tenant_resource_usage USING btree (tenant_id, "timestamp") WHERE (cost_usd > (0)::numeric);


-- INDEX: idx_tenant_resource_usage_tenant_id
CREATE INDEX IF NOT EXISTS idx_tenant_resource_usage_tenant_id ON public.tenant_resource_usage USING btree (tenant_id);


-- INDEX: idx_tenant_resource_usage_tenant_timestamp
CREATE INDEX IF NOT EXISTS idx_tenant_resource_usage_tenant_timestamp ON public.tenant_resource_usage USING btree (tenant_id, "timestamp");


-- INDEX: idx_tenant_resource_usage_timestamp
CREATE INDEX IF NOT EXISTS idx_tenant_resource_usage_timestamp ON public.tenant_resource_usage USING btree ("timestamp");


-- INDEX: idx_tenant_role_permissions_permission
CREATE INDEX IF NOT EXISTS idx_tenant_role_permissions_permission ON public.tenant_role_permissions USING btree (permission_id);


-- INDEX: idx_tenant_role_permissions_role
CREATE INDEX IF NOT EXISTS idx_tenant_role_permissions_role ON public.tenant_role_permissions USING btree (role_id);


-- INDEX: idx_tenant_roles_tenant
CREATE INDEX IF NOT EXISTS idx_tenant_roles_tenant ON public.tenant_roles USING btree (tenant_id);


-- INDEX: idx_tenant_usage_period
CREATE INDEX IF NOT EXISTS idx_tenant_usage_period ON public.tenant_usage USING btree (billing_period_start, billing_period_end);


-- INDEX: idx_tenant_usage_tenant_id
CREATE INDEX IF NOT EXISTS idx_tenant_usage_tenant_id ON public.tenant_usage USING btree (tenant_id);


-- INDEX: idx_tenant_usage_tracking_metric_type
CREATE INDEX IF NOT EXISTS idx_tenant_usage_tracking_metric_type ON public.tenant_usage_tracking USING btree (metric_type);


-- INDEX: idx_tenant_usage_tracking_tenant_id
CREATE INDEX IF NOT EXISTS idx_tenant_usage_tracking_tenant_id ON public.tenant_usage_tracking USING btree (tenant_id);


-- INDEX: idx_tenants_deleted_at
CREATE INDEX IF NOT EXISTS idx_tenants_deleted_at ON public.tenants USING btree (deleted_at) WHERE (deleted_at IS NULL);


-- INDEX: idx_tenants_onboarding_status
CREATE INDEX IF NOT EXISTS idx_tenants_onboarding_status ON public.tenants USING btree (onboarding_status) WHERE ((onboarding_status)::text <> 'onboarding_complete'::text);


-- INDEX: idx_tenants_slug
CREATE INDEX IF NOT EXISTS idx_tenants_slug ON public.tenants USING btree (slug);


-- INDEX: idx_tenants_subscription_tier
CREATE INDEX IF NOT EXISTS idx_tenants_subscription_tier ON public.tenants USING btree (subscription_tier_id);


-- INDEX: idx_ticket_comments_ticket
CREATE INDEX IF NOT EXISTS idx_ticket_comments_ticket ON public.ticket_comments USING btree (ticket_id);


-- INDEX: idx_tickets_asset
CREATE INDEX IF NOT EXISTS idx_tickets_asset ON public.tickets USING btree (asset_id) WHERE (asset_id IS NOT NULL);


-- INDEX: idx_tickets_certificate
CREATE INDEX IF NOT EXISTS idx_tickets_certificate ON public.tickets USING btree (certificate_id) WHERE (certificate_id IS NOT NULL);


-- INDEX: idx_tickets_finding
CREATE INDEX IF NOT EXISTS idx_tickets_finding ON public.tickets USING btree (finding_id) WHERE (finding_id IS NOT NULL);


-- INDEX: idx_tickets_tenant
CREATE INDEX IF NOT EXISTS idx_tickets_tenant ON public.tickets USING btree (tenant_id);


-- INDEX: idx_tickets_tenant_assigned
CREATE INDEX IF NOT EXISTS idx_tickets_tenant_assigned ON public.tickets USING btree (tenant_id, assigned_to) WHERE (assigned_to IS NOT NULL);


-- INDEX: idx_tickets_tenant_category
CREATE INDEX IF NOT EXISTS idx_tickets_tenant_category ON public.tickets USING btree (tenant_id, category);


-- INDEX: idx_tickets_tenant_due
CREATE INDEX IF NOT EXISTS idx_tickets_tenant_due ON public.tickets USING btree (tenant_id, due_date) WHERE (due_date IS NOT NULL);


-- INDEX: idx_tickets_tenant_status
CREATE INDEX IF NOT EXISTS idx_tickets_tenant_status ON public.tickets USING btree (tenant_id, status);


-- INDEX: idx_trial_tracking_notifications
CREATE INDEX IF NOT EXISTS idx_trial_tracking_notifications ON public.billing_trial_tracking USING btree (trial_end, notification_7days_sent, notification_1day_sent) WHERE (converted_to_paid = false);


-- INDEX: idx_trial_tracking_tenant
CREATE INDEX IF NOT EXISTS idx_trial_tracking_tenant ON public.billing_trial_tracking USING btree (tenant_id);


-- INDEX: idx_trial_tracking_trial_end
CREATE INDEX IF NOT EXISTS idx_trial_tracking_trial_end ON public.billing_trial_tracking USING btree (trial_end) WHERE (converted_to_paid = false);


-- INDEX: idx_user_auth_methods_external_id
CREATE INDEX IF NOT EXISTS idx_user_auth_methods_external_id ON public.user_auth_methods USING btree (external_user_id);


-- INDEX: idx_user_auth_methods_user_id
CREATE INDEX IF NOT EXISTS idx_user_auth_methods_user_id ON public.user_auth_methods USING btree (user_id);


-- INDEX: idx_user_framework_preferences_framework
CREATE INDEX IF NOT EXISTS idx_user_framework_preferences_framework ON public.user_framework_preferences USING btree (framework_id);


-- INDEX: idx_user_framework_preferences_user_tenant
CREATE INDEX IF NOT EXISTS idx_user_framework_preferences_user_tenant ON public.user_framework_preferences USING btree (user_id, tenant_id);


-- INDEX: idx_user_tenant_roles_role
CREATE INDEX IF NOT EXISTS idx_user_tenant_roles_role ON public.user_tenant_roles USING btree (role_id);


-- INDEX: idx_user_tenant_roles_tenant
CREATE INDEX IF NOT EXISTS idx_user_tenant_roles_tenant ON public.user_tenant_roles USING btree (tenant_id);


-- INDEX: idx_user_tenant_roles_user
CREATE INDEX IF NOT EXISTS idx_user_tenant_roles_user ON public.user_tenant_roles USING btree (user_id);


-- INDEX: idx_user_workflow_progress_user_id
CREATE INDEX IF NOT EXISTS idx_user_workflow_progress_user_id ON public.user_workflow_progress USING btree (user_id);


-- INDEX: idx_user_workflow_progress_workflow_id
CREATE INDEX IF NOT EXISTS idx_user_workflow_progress_workflow_id ON public.user_workflow_progress USING btree (workflow_configuration_id);


-- INDEX: idx_users_email
CREATE INDEX IF NOT EXISTS idx_users_email ON public.users USING btree (email);


-- INDEX: idx_users_email_verification_token
CREATE INDEX IF NOT EXISTS idx_users_email_verification_token ON public.users USING btree (email_verification_token) WHERE (email_verification_token IS NOT NULL);


-- INDEX: idx_users_eula_accepted_at
CREATE INDEX IF NOT EXISTS idx_users_eula_accepted_at ON public.users USING btree (eula_accepted_at) WHERE (eula_accepted_at IS NOT NULL);


-- INDEX: idx_users_password_reset_token
CREATE INDEX IF NOT EXISTS idx_users_password_reset_token ON public.users USING btree (password_reset_token) WHERE (password_reset_token IS NOT NULL);


-- INDEX: idx_users_tenant_id
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON public.users USING btree (tenant_id);


-- INDEX: idx_webhook_deliveries_incident
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_incident ON public.security_incident_webhook_deliveries USING btree (incident_id, created_at DESC);


-- INDEX: idx_webhook_deliveries_status
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status ON public.security_incident_webhook_deliveries USING btree (status, created_at DESC);


-- INDEX: idx_webhook_deliveries_webhook
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook ON public.security_incident_webhook_deliveries USING btree (webhook_id, created_at DESC);


-- INDEX: network_assets_part_0_deleted_at_idx
CREATE INDEX IF NOT EXISTS network_assets_part_0_deleted_at_idx ON public.network_assets_part_0 USING btree (deleted_at) WHERE (deleted_at IS NULL);


-- INDEX: network_assets_part_0_hostname_idx
CREATE INDEX IF NOT EXISTS network_assets_part_0_hostname_idx ON public.network_assets_part_0 USING btree (hostname);


-- INDEX: network_assets_part_0_ip_address_idx
CREATE INDEX IF NOT EXISTS network_assets_part_0_ip_address_idx ON public.network_assets_part_0 USING btree (ip_address);


-- INDEX: network_assets_part_0_tenant_id_idx
CREATE INDEX IF NOT EXISTS network_assets_part_0_tenant_id_idx ON public.network_assets_part_0 USING btree (tenant_id);


-- INDEX: network_assets_part_1_deleted_at_idx
CREATE INDEX IF NOT EXISTS network_assets_part_1_deleted_at_idx ON public.network_assets_part_1 USING btree (deleted_at) WHERE (deleted_at IS NULL);


-- INDEX: network_assets_part_1_hostname_idx
CREATE INDEX IF NOT EXISTS network_assets_part_1_hostname_idx ON public.network_assets_part_1 USING btree (hostname);


-- INDEX: network_assets_part_1_ip_address_idx
CREATE INDEX IF NOT EXISTS network_assets_part_1_ip_address_idx ON public.network_assets_part_1 USING btree (ip_address);


-- INDEX: network_assets_part_1_tenant_id_idx
CREATE INDEX IF NOT EXISTS network_assets_part_1_tenant_id_idx ON public.network_assets_part_1 USING btree (tenant_id);


-- INDEX: network_assets_part_2_deleted_at_idx
CREATE INDEX IF NOT EXISTS network_assets_part_2_deleted_at_idx ON public.network_assets_part_2 USING btree (deleted_at) WHERE (deleted_at IS NULL);


-- INDEX: network_assets_part_2_hostname_idx
CREATE INDEX IF NOT EXISTS network_assets_part_2_hostname_idx ON public.network_assets_part_2 USING btree (hostname);


-- INDEX: network_assets_part_2_ip_address_idx
CREATE INDEX IF NOT EXISTS network_assets_part_2_ip_address_idx ON public.network_assets_part_2 USING btree (ip_address);


-- INDEX: network_assets_part_2_tenant_id_idx
CREATE INDEX IF NOT EXISTS network_assets_part_2_tenant_id_idx ON public.network_assets_part_2 USING btree (tenant_id);


-- INDEX: network_assets_part_3_deleted_at_idx
CREATE INDEX IF NOT EXISTS network_assets_part_3_deleted_at_idx ON public.network_assets_part_3 USING btree (deleted_at) WHERE (deleted_at IS NULL);


-- INDEX: network_assets_part_3_hostname_idx
CREATE INDEX IF NOT EXISTS network_assets_part_3_hostname_idx ON public.network_assets_part_3 USING btree (hostname);


-- INDEX: network_assets_part_3_ip_address_idx
CREATE INDEX IF NOT EXISTS network_assets_part_3_ip_address_idx ON public.network_assets_part_3 USING btree (ip_address);


-- INDEX: network_assets_part_3_tenant_id_idx
CREATE INDEX IF NOT EXISTS network_assets_part_3_tenant_id_idx ON public.network_assets_part_3 USING btree (tenant_id);


-- INDEX: network_assets_part_4_deleted_at_idx
CREATE INDEX IF NOT EXISTS network_assets_part_4_deleted_at_idx ON public.network_assets_part_4 USING btree (deleted_at) WHERE (deleted_at IS NULL);


-- INDEX: network_assets_part_4_hostname_idx
CREATE INDEX IF NOT EXISTS network_assets_part_4_hostname_idx ON public.network_assets_part_4 USING btree (hostname);


-- INDEX: network_assets_part_4_ip_address_idx
CREATE INDEX IF NOT EXISTS network_assets_part_4_ip_address_idx ON public.network_assets_part_4 USING btree (ip_address);


-- INDEX: network_assets_part_4_tenant_id_idx
CREATE INDEX IF NOT EXISTS network_assets_part_4_tenant_id_idx ON public.network_assets_part_4 USING btree (tenant_id);


-- INDEX: network_assets_part_5_deleted_at_idx
CREATE INDEX IF NOT EXISTS network_assets_part_5_deleted_at_idx ON public.network_assets_part_5 USING btree (deleted_at) WHERE (deleted_at IS NULL);


-- INDEX: network_assets_part_5_hostname_idx
CREATE INDEX IF NOT EXISTS network_assets_part_5_hostname_idx ON public.network_assets_part_5 USING btree (hostname);


-- INDEX: network_assets_part_5_ip_address_idx
CREATE INDEX IF NOT EXISTS network_assets_part_5_ip_address_idx ON public.network_assets_part_5 USING btree (ip_address);


-- INDEX: network_assets_part_5_tenant_id_idx
CREATE INDEX IF NOT EXISTS network_assets_part_5_tenant_id_idx ON public.network_assets_part_5 USING btree (tenant_id);


-- INDEX: network_assets_part_6_deleted_at_idx
CREATE INDEX IF NOT EXISTS network_assets_part_6_deleted_at_idx ON public.network_assets_part_6 USING btree (deleted_at) WHERE (deleted_at IS NULL);


-- INDEX: network_assets_part_6_hostname_idx
CREATE INDEX IF NOT EXISTS network_assets_part_6_hostname_idx ON public.network_assets_part_6 USING btree (hostname);


-- INDEX: network_assets_part_6_ip_address_idx
CREATE INDEX IF NOT EXISTS network_assets_part_6_ip_address_idx ON public.network_assets_part_6 USING btree (ip_address);


-- INDEX: network_assets_part_6_tenant_id_idx
CREATE INDEX IF NOT EXISTS network_assets_part_6_tenant_id_idx ON public.network_assets_part_6 USING btree (tenant_id);


-- INDEX: network_assets_part_7_deleted_at_idx
CREATE INDEX IF NOT EXISTS network_assets_part_7_deleted_at_idx ON public.network_assets_part_7 USING btree (deleted_at) WHERE (deleted_at IS NULL);


-- INDEX: network_assets_part_7_hostname_idx
CREATE INDEX IF NOT EXISTS network_assets_part_7_hostname_idx ON public.network_assets_part_7 USING btree (hostname);


-- INDEX: network_assets_part_7_ip_address_idx
CREATE INDEX IF NOT EXISTS network_assets_part_7_ip_address_idx ON public.network_assets_part_7 USING btree (ip_address);


-- INDEX: network_assets_part_7_tenant_id_idx
CREATE INDEX IF NOT EXISTS network_assets_part_7_tenant_id_idx ON public.network_assets_part_7 USING btree (tenant_id);


-- INDEX: sensor_discoveries_part_0_batch_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_0_batch_id_idx ON public.sensor_discoveries_part_0 USING btree (batch_id);


-- INDEX: sensor_discoveries_part_0_dest_ip_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_0_dest_ip_idx ON public.sensor_discoveries_part_0 USING btree (dest_ip);


-- INDEX: sensor_discoveries_part_0_protocol_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_0_protocol_idx ON public.sensor_discoveries_part_0 USING btree (protocol);


-- INDEX: sensor_discoveries_part_0_sensor_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_0_sensor_id_idx ON public.sensor_discoveries_part_0 USING btree (sensor_id);


-- INDEX: sensor_discoveries_part_0_tenant_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_0_tenant_id_idx ON public.sensor_discoveries_part_0 USING btree (tenant_id);


-- INDEX: sensor_discoveries_part_0_timestamp_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_0_timestamp_idx ON public.sensor_discoveries_part_0 USING btree ("timestamp");


-- INDEX: sensor_discoveries_part_1_batch_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_1_batch_id_idx ON public.sensor_discoveries_part_1 USING btree (batch_id);


-- INDEX: sensor_discoveries_part_1_dest_ip_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_1_dest_ip_idx ON public.sensor_discoveries_part_1 USING btree (dest_ip);


-- INDEX: sensor_discoveries_part_1_protocol_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_1_protocol_idx ON public.sensor_discoveries_part_1 USING btree (protocol);


-- INDEX: sensor_discoveries_part_1_sensor_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_1_sensor_id_idx ON public.sensor_discoveries_part_1 USING btree (sensor_id);


-- INDEX: sensor_discoveries_part_1_tenant_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_1_tenant_id_idx ON public.sensor_discoveries_part_1 USING btree (tenant_id);


-- INDEX: sensor_discoveries_part_1_timestamp_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_1_timestamp_idx ON public.sensor_discoveries_part_1 USING btree ("timestamp");


-- INDEX: sensor_discoveries_part_2_batch_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_2_batch_id_idx ON public.sensor_discoveries_part_2 USING btree (batch_id);


-- INDEX: sensor_discoveries_part_2_dest_ip_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_2_dest_ip_idx ON public.sensor_discoveries_part_2 USING btree (dest_ip);


-- INDEX: sensor_discoveries_part_2_protocol_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_2_protocol_idx ON public.sensor_discoveries_part_2 USING btree (protocol);


-- INDEX: sensor_discoveries_part_2_sensor_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_2_sensor_id_idx ON public.sensor_discoveries_part_2 USING btree (sensor_id);


-- INDEX: sensor_discoveries_part_2_tenant_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_2_tenant_id_idx ON public.sensor_discoveries_part_2 USING btree (tenant_id);


-- INDEX: sensor_discoveries_part_2_timestamp_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_2_timestamp_idx ON public.sensor_discoveries_part_2 USING btree ("timestamp");


-- INDEX: sensor_discoveries_part_3_batch_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_3_batch_id_idx ON public.sensor_discoveries_part_3 USING btree (batch_id);


-- INDEX: sensor_discoveries_part_3_dest_ip_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_3_dest_ip_idx ON public.sensor_discoveries_part_3 USING btree (dest_ip);


-- INDEX: sensor_discoveries_part_3_protocol_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_3_protocol_idx ON public.sensor_discoveries_part_3 USING btree (protocol);


-- INDEX: sensor_discoveries_part_3_sensor_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_3_sensor_id_idx ON public.sensor_discoveries_part_3 USING btree (sensor_id);


-- INDEX: sensor_discoveries_part_3_tenant_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_3_tenant_id_idx ON public.sensor_discoveries_part_3 USING btree (tenant_id);


-- INDEX: sensor_discoveries_part_3_timestamp_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_3_timestamp_idx ON public.sensor_discoveries_part_3 USING btree ("timestamp");


-- INDEX: sensor_discoveries_part_4_batch_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_4_batch_id_idx ON public.sensor_discoveries_part_4 USING btree (batch_id);


-- INDEX: sensor_discoveries_part_4_dest_ip_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_4_dest_ip_idx ON public.sensor_discoveries_part_4 USING btree (dest_ip);


-- INDEX: sensor_discoveries_part_4_protocol_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_4_protocol_idx ON public.sensor_discoveries_part_4 USING btree (protocol);


-- INDEX: sensor_discoveries_part_4_sensor_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_4_sensor_id_idx ON public.sensor_discoveries_part_4 USING btree (sensor_id);


-- INDEX: sensor_discoveries_part_4_tenant_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_4_tenant_id_idx ON public.sensor_discoveries_part_4 USING btree (tenant_id);


-- INDEX: sensor_discoveries_part_4_timestamp_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_4_timestamp_idx ON public.sensor_discoveries_part_4 USING btree ("timestamp");


-- INDEX: sensor_discoveries_part_5_batch_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_5_batch_id_idx ON public.sensor_discoveries_part_5 USING btree (batch_id);


-- INDEX: sensor_discoveries_part_5_dest_ip_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_5_dest_ip_idx ON public.sensor_discoveries_part_5 USING btree (dest_ip);


-- INDEX: sensor_discoveries_part_5_protocol_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_5_protocol_idx ON public.sensor_discoveries_part_5 USING btree (protocol);


-- INDEX: sensor_discoveries_part_5_sensor_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_5_sensor_id_idx ON public.sensor_discoveries_part_5 USING btree (sensor_id);


-- INDEX: sensor_discoveries_part_5_tenant_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_5_tenant_id_idx ON public.sensor_discoveries_part_5 USING btree (tenant_id);


-- INDEX: sensor_discoveries_part_5_timestamp_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_5_timestamp_idx ON public.sensor_discoveries_part_5 USING btree ("timestamp");


-- INDEX: sensor_discoveries_part_6_batch_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_6_batch_id_idx ON public.sensor_discoveries_part_6 USING btree (batch_id);


-- INDEX: sensor_discoveries_part_6_dest_ip_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_6_dest_ip_idx ON public.sensor_discoveries_part_6 USING btree (dest_ip);


-- INDEX: sensor_discoveries_part_6_protocol_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_6_protocol_idx ON public.sensor_discoveries_part_6 USING btree (protocol);


-- INDEX: sensor_discoveries_part_6_sensor_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_6_sensor_id_idx ON public.sensor_discoveries_part_6 USING btree (sensor_id);


-- INDEX: sensor_discoveries_part_6_tenant_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_6_tenant_id_idx ON public.sensor_discoveries_part_6 USING btree (tenant_id);


-- INDEX: sensor_discoveries_part_6_timestamp_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_6_timestamp_idx ON public.sensor_discoveries_part_6 USING btree ("timestamp");


-- INDEX: sensor_discoveries_part_7_batch_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_7_batch_id_idx ON public.sensor_discoveries_part_7 USING btree (batch_id);


-- INDEX: sensor_discoveries_part_7_dest_ip_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_7_dest_ip_idx ON public.sensor_discoveries_part_7 USING btree (dest_ip);


-- INDEX: sensor_discoveries_part_7_protocol_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_7_protocol_idx ON public.sensor_discoveries_part_7 USING btree (protocol);


-- INDEX: sensor_discoveries_part_7_sensor_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_7_sensor_id_idx ON public.sensor_discoveries_part_7 USING btree (sensor_id);


-- INDEX: sensor_discoveries_part_7_tenant_id_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_7_tenant_id_idx ON public.sensor_discoveries_part_7 USING btree (tenant_id);


-- INDEX: sensor_discoveries_part_7_timestamp_idx
CREATE INDEX IF NOT EXISTS sensor_discoveries_part_7_timestamp_idx ON public.sensor_discoveries_part_7 USING btree ("timestamp");


-- INDEX: service_identification_rules_builtin_unique
CREATE UNIQUE INDEX IF NOT EXISTS service_identification_rules_builtin_unique ON public.service_identification_rules USING btree (port, protocol) WHERE (tenant_id IS NULL);


-- INDEX: service_identification_rules_tenant_unique
CREATE UNIQUE INDEX IF NOT EXISTS service_identification_rules_tenant_unique ON public.service_identification_rules USING btree (port, protocol, tenant_id) WHERE (tenant_id IS NOT NULL);


-- INDEX: unique_active_bootstrap_ca
CREATE UNIQUE INDEX IF NOT EXISTS unique_active_bootstrap_ca ON public.platform_bootstrap_ca USING btree (is_active) WHERE (is_active = true);


-- INDEX: unique_active_ca_per_tenant
CREATE UNIQUE INDEX IF NOT EXISTS unique_active_ca_per_tenant ON public.sensor_ca_certificates USING btree (tenant_id, is_active) WHERE (is_active = true);


-- INDEX: unique_active_service_ca
CREATE UNIQUE INDEX IF NOT EXISTS unique_active_service_ca ON public.platform_service_ca USING btree (is_active) WHERE (is_active = true);


-- INDEX ATTACH: activity_logs_y2026m04_action_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_action ATTACH PARTITION audit.activity_logs_y2026m04_action_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m04_compliance_tags_idx
ALTER INDEX audit.idx_activity_logs_compliance ATTACH PARTITION audit.activity_logs_y2026m04_compliance_tags_idx;


-- INDEX ATTACH: activity_logs_y2026m04_event_category_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_category ATTACH PARTITION audit.activity_logs_y2026m04_event_category_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m04_event_type_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_event_type ATTACH PARTITION audit.activity_logs_y2026m04_event_type_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m04_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_occurred_at ATTACH PARTITION audit.activity_logs_y2026m04_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m04_pkey
ALTER INDEX audit.activity_logs_pkey ATTACH PARTITION audit.activity_logs_y2026m04_pkey;


-- INDEX ATTACH: activity_logs_y2026m04_request_id_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_request_id ATTACH PARTITION audit.activity_logs_y2026m04_request_id_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m04_requires_attention_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_requires_attention ATTACH PARTITION audit.activity_logs_y2026m04_requires_attention_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m04_resource_type_resource_id_occurred_a_idx
ALTER INDEX audit.idx_activity_logs_resource ATTACH PARTITION audit.activity_logs_y2026m04_resource_type_resource_id_occurred_a_idx;


-- INDEX ATTACH: activity_logs_y2026m04_success_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_success ATTACH PARTITION audit.activity_logs_y2026m04_success_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m04_tenant_id_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_tenant_time ATTACH PARTITION audit.activity_logs_y2026m04_tenant_id_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m04_user_id_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_user_time ATTACH PARTITION audit.activity_logs_y2026m04_user_id_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m04_user_type_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_user_type ATTACH PARTITION audit.activity_logs_y2026m04_user_type_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m05_action_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_action ATTACH PARTITION audit.activity_logs_y2026m05_action_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m05_compliance_tags_idx
ALTER INDEX audit.idx_activity_logs_compliance ATTACH PARTITION audit.activity_logs_y2026m05_compliance_tags_idx;


-- INDEX ATTACH: activity_logs_y2026m05_event_category_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_category ATTACH PARTITION audit.activity_logs_y2026m05_event_category_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m05_event_type_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_event_type ATTACH PARTITION audit.activity_logs_y2026m05_event_type_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m05_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_occurred_at ATTACH PARTITION audit.activity_logs_y2026m05_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m05_pkey
ALTER INDEX audit.activity_logs_pkey ATTACH PARTITION audit.activity_logs_y2026m05_pkey;


-- INDEX ATTACH: activity_logs_y2026m05_request_id_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_request_id ATTACH PARTITION audit.activity_logs_y2026m05_request_id_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m05_requires_attention_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_requires_attention ATTACH PARTITION audit.activity_logs_y2026m05_requires_attention_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m05_resource_type_resource_id_occurred_a_idx
ALTER INDEX audit.idx_activity_logs_resource ATTACH PARTITION audit.activity_logs_y2026m05_resource_type_resource_id_occurred_a_idx;


-- INDEX ATTACH: activity_logs_y2026m05_success_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_success ATTACH PARTITION audit.activity_logs_y2026m05_success_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m05_tenant_id_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_tenant_time ATTACH PARTITION audit.activity_logs_y2026m05_tenant_id_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m05_user_id_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_user_time ATTACH PARTITION audit.activity_logs_y2026m05_user_id_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m05_user_type_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_user_type ATTACH PARTITION audit.activity_logs_y2026m05_user_type_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m06_action_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_action ATTACH PARTITION audit.activity_logs_y2026m06_action_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m06_compliance_tags_idx
ALTER INDEX audit.idx_activity_logs_compliance ATTACH PARTITION audit.activity_logs_y2026m06_compliance_tags_idx;


-- INDEX ATTACH: activity_logs_y2026m06_event_category_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_category ATTACH PARTITION audit.activity_logs_y2026m06_event_category_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m06_event_type_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_event_type ATTACH PARTITION audit.activity_logs_y2026m06_event_type_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m06_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_occurred_at ATTACH PARTITION audit.activity_logs_y2026m06_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m06_pkey
ALTER INDEX audit.activity_logs_pkey ATTACH PARTITION audit.activity_logs_y2026m06_pkey;


-- INDEX ATTACH: activity_logs_y2026m06_request_id_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_request_id ATTACH PARTITION audit.activity_logs_y2026m06_request_id_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m06_requires_attention_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_requires_attention ATTACH PARTITION audit.activity_logs_y2026m06_requires_attention_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m06_resource_type_resource_id_occurred_a_idx
ALTER INDEX audit.idx_activity_logs_resource ATTACH PARTITION audit.activity_logs_y2026m06_resource_type_resource_id_occurred_a_idx;


-- INDEX ATTACH: activity_logs_y2026m06_success_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_success ATTACH PARTITION audit.activity_logs_y2026m06_success_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m06_tenant_id_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_tenant_time ATTACH PARTITION audit.activity_logs_y2026m06_tenant_id_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m06_user_id_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_user_time ATTACH PARTITION audit.activity_logs_y2026m06_user_id_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m06_user_type_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_user_type ATTACH PARTITION audit.activity_logs_y2026m06_user_type_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m07_action_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_action ATTACH PARTITION audit.activity_logs_y2026m07_action_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m07_compliance_tags_idx
ALTER INDEX audit.idx_activity_logs_compliance ATTACH PARTITION audit.activity_logs_y2026m07_compliance_tags_idx;


-- INDEX ATTACH: activity_logs_y2026m07_event_category_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_category ATTACH PARTITION audit.activity_logs_y2026m07_event_category_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m07_event_type_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_event_type ATTACH PARTITION audit.activity_logs_y2026m07_event_type_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m07_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_occurred_at ATTACH PARTITION audit.activity_logs_y2026m07_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m07_pkey
ALTER INDEX audit.activity_logs_pkey ATTACH PARTITION audit.activity_logs_y2026m07_pkey;


-- INDEX ATTACH: activity_logs_y2026m07_request_id_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_request_id ATTACH PARTITION audit.activity_logs_y2026m07_request_id_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m07_requires_attention_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_requires_attention ATTACH PARTITION audit.activity_logs_y2026m07_requires_attention_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m07_resource_type_resource_id_occurred_a_idx
ALTER INDEX audit.idx_activity_logs_resource ATTACH PARTITION audit.activity_logs_y2026m07_resource_type_resource_id_occurred_a_idx;


-- INDEX ATTACH: activity_logs_y2026m07_success_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_success ATTACH PARTITION audit.activity_logs_y2026m07_success_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m07_tenant_id_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_tenant_time ATTACH PARTITION audit.activity_logs_y2026m07_tenant_id_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m07_user_id_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_user_time ATTACH PARTITION audit.activity_logs_y2026m07_user_id_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m07_user_type_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_user_type ATTACH PARTITION audit.activity_logs_y2026m07_user_type_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m08_action_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_action ATTACH PARTITION audit.activity_logs_y2026m08_action_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m08_compliance_tags_idx
ALTER INDEX audit.idx_activity_logs_compliance ATTACH PARTITION audit.activity_logs_y2026m08_compliance_tags_idx;


-- INDEX ATTACH: activity_logs_y2026m08_event_category_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_category ATTACH PARTITION audit.activity_logs_y2026m08_event_category_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m08_event_type_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_event_type ATTACH PARTITION audit.activity_logs_y2026m08_event_type_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m08_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_occurred_at ATTACH PARTITION audit.activity_logs_y2026m08_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m08_pkey
ALTER INDEX audit.activity_logs_pkey ATTACH PARTITION audit.activity_logs_y2026m08_pkey;


-- INDEX ATTACH: activity_logs_y2026m08_request_id_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_request_id ATTACH PARTITION audit.activity_logs_y2026m08_request_id_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m08_requires_attention_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_requires_attention ATTACH PARTITION audit.activity_logs_y2026m08_requires_attention_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m08_resource_type_resource_id_occurred_a_idx
ALTER INDEX audit.idx_activity_logs_resource ATTACH PARTITION audit.activity_logs_y2026m08_resource_type_resource_id_occurred_a_idx;


-- INDEX ATTACH: activity_logs_y2026m08_success_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_success ATTACH PARTITION audit.activity_logs_y2026m08_success_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m08_tenant_id_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_tenant_time ATTACH PARTITION audit.activity_logs_y2026m08_tenant_id_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m08_user_id_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_user_time ATTACH PARTITION audit.activity_logs_y2026m08_user_id_occurred_at_idx;


-- INDEX ATTACH: activity_logs_y2026m08_user_type_occurred_at_idx
ALTER INDEX audit.idx_activity_logs_user_type ATTACH PARTITION audit.activity_logs_y2026m08_user_type_occurred_at_idx;


-- INDEX ATTACH: crypto_implementations_part_0_asset_id_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_asset_id ATTACH PARTITION public.crypto_implementations_part_0_asset_id_idx;


-- INDEX ATTACH: crypto_implementations_part_0_deleted_at_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_deleted_at ATTACH PARTITION public.crypto_implementations_part_0_deleted_at_idx;


-- INDEX ATTACH: crypto_implementations_part_0_risk_score_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_risk_score ATTACH PARTITION public.crypto_implementations_part_0_risk_score_idx;


-- INDEX ATTACH: crypto_implementations_part_0_tenant_id_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_tenant_id ATTACH PARTITION public.crypto_implementations_part_0_tenant_id_idx;


-- INDEX ATTACH: crypto_implementations_part_1_asset_id_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_asset_id ATTACH PARTITION public.crypto_implementations_part_1_asset_id_idx;


-- INDEX ATTACH: crypto_implementations_part_1_deleted_at_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_deleted_at ATTACH PARTITION public.crypto_implementations_part_1_deleted_at_idx;


-- INDEX ATTACH: crypto_implementations_part_1_risk_score_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_risk_score ATTACH PARTITION public.crypto_implementations_part_1_risk_score_idx;


-- INDEX ATTACH: crypto_implementations_part_1_tenant_id_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_tenant_id ATTACH PARTITION public.crypto_implementations_part_1_tenant_id_idx;


-- INDEX ATTACH: crypto_implementations_part_2_asset_id_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_asset_id ATTACH PARTITION public.crypto_implementations_part_2_asset_id_idx;


-- INDEX ATTACH: crypto_implementations_part_2_deleted_at_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_deleted_at ATTACH PARTITION public.crypto_implementations_part_2_deleted_at_idx;


-- INDEX ATTACH: crypto_implementations_part_2_risk_score_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_risk_score ATTACH PARTITION public.crypto_implementations_part_2_risk_score_idx;


-- INDEX ATTACH: crypto_implementations_part_2_tenant_id_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_tenant_id ATTACH PARTITION public.crypto_implementations_part_2_tenant_id_idx;


-- INDEX ATTACH: crypto_implementations_part_3_asset_id_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_asset_id ATTACH PARTITION public.crypto_implementations_part_3_asset_id_idx;


-- INDEX ATTACH: crypto_implementations_part_3_deleted_at_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_deleted_at ATTACH PARTITION public.crypto_implementations_part_3_deleted_at_idx;


-- INDEX ATTACH: crypto_implementations_part_3_risk_score_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_risk_score ATTACH PARTITION public.crypto_implementations_part_3_risk_score_idx;


-- INDEX ATTACH: crypto_implementations_part_3_tenant_id_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_tenant_id ATTACH PARTITION public.crypto_implementations_part_3_tenant_id_idx;


-- INDEX ATTACH: crypto_implementations_part_4_asset_id_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_asset_id ATTACH PARTITION public.crypto_implementations_part_4_asset_id_idx;


-- INDEX ATTACH: crypto_implementations_part_4_deleted_at_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_deleted_at ATTACH PARTITION public.crypto_implementations_part_4_deleted_at_idx;


-- INDEX ATTACH: crypto_implementations_part_4_risk_score_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_risk_score ATTACH PARTITION public.crypto_implementations_part_4_risk_score_idx;


-- INDEX ATTACH: crypto_implementations_part_4_tenant_id_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_tenant_id ATTACH PARTITION public.crypto_implementations_part_4_tenant_id_idx;


-- INDEX ATTACH: crypto_implementations_part_5_asset_id_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_asset_id ATTACH PARTITION public.crypto_implementations_part_5_asset_id_idx;


-- INDEX ATTACH: crypto_implementations_part_5_deleted_at_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_deleted_at ATTACH PARTITION public.crypto_implementations_part_5_deleted_at_idx;


-- INDEX ATTACH: crypto_implementations_part_5_risk_score_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_risk_score ATTACH PARTITION public.crypto_implementations_part_5_risk_score_idx;


-- INDEX ATTACH: crypto_implementations_part_5_tenant_id_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_tenant_id ATTACH PARTITION public.crypto_implementations_part_5_tenant_id_idx;


-- INDEX ATTACH: crypto_implementations_part_6_asset_id_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_asset_id ATTACH PARTITION public.crypto_implementations_part_6_asset_id_idx;


-- INDEX ATTACH: crypto_implementations_part_6_deleted_at_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_deleted_at ATTACH PARTITION public.crypto_implementations_part_6_deleted_at_idx;


-- INDEX ATTACH: crypto_implementations_part_6_risk_score_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_risk_score ATTACH PARTITION public.crypto_implementations_part_6_risk_score_idx;


-- INDEX ATTACH: crypto_implementations_part_6_tenant_id_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_tenant_id ATTACH PARTITION public.crypto_implementations_part_6_tenant_id_idx;


-- INDEX ATTACH: crypto_implementations_part_7_asset_id_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_asset_id ATTACH PARTITION public.crypto_implementations_part_7_asset_id_idx;


-- INDEX ATTACH: crypto_implementations_part_7_deleted_at_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_deleted_at ATTACH PARTITION public.crypto_implementations_part_7_deleted_at_idx;


-- INDEX ATTACH: crypto_implementations_part_7_risk_score_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_risk_score ATTACH PARTITION public.crypto_implementations_part_7_risk_score_idx;


-- INDEX ATTACH: crypto_implementations_part_7_tenant_id_idx
ALTER INDEX public.idx_crypto_implementations_partitioned_tenant_id ATTACH PARTITION public.crypto_implementations_part_7_tenant_id_idx;


-- INDEX ATTACH: network_assets_part_0_deleted_at_idx
ALTER INDEX public.idx_network_assets_partitioned_deleted_at ATTACH PARTITION public.network_assets_part_0_deleted_at_idx;


-- INDEX ATTACH: network_assets_part_0_hostname_idx
ALTER INDEX public.idx_network_assets_partitioned_hostname ATTACH PARTITION public.network_assets_part_0_hostname_idx;


-- INDEX ATTACH: network_assets_part_0_ip_address_idx
ALTER INDEX public.idx_network_assets_partitioned_ip_address ATTACH PARTITION public.network_assets_part_0_ip_address_idx;


-- INDEX ATTACH: network_assets_part_0_tenant_id_idx
ALTER INDEX public.idx_network_assets_partitioned_tenant_id ATTACH PARTITION public.network_assets_part_0_tenant_id_idx;


-- INDEX ATTACH: network_assets_part_1_deleted_at_idx
ALTER INDEX public.idx_network_assets_partitioned_deleted_at ATTACH PARTITION public.network_assets_part_1_deleted_at_idx;


-- INDEX ATTACH: network_assets_part_1_hostname_idx
ALTER INDEX public.idx_network_assets_partitioned_hostname ATTACH PARTITION public.network_assets_part_1_hostname_idx;


-- INDEX ATTACH: network_assets_part_1_ip_address_idx
ALTER INDEX public.idx_network_assets_partitioned_ip_address ATTACH PARTITION public.network_assets_part_1_ip_address_idx;


-- INDEX ATTACH: network_assets_part_1_tenant_id_idx
ALTER INDEX public.idx_network_assets_partitioned_tenant_id ATTACH PARTITION public.network_assets_part_1_tenant_id_idx;


-- INDEX ATTACH: network_assets_part_2_deleted_at_idx
ALTER INDEX public.idx_network_assets_partitioned_deleted_at ATTACH PARTITION public.network_assets_part_2_deleted_at_idx;


-- INDEX ATTACH: network_assets_part_2_hostname_idx
ALTER INDEX public.idx_network_assets_partitioned_hostname ATTACH PARTITION public.network_assets_part_2_hostname_idx;


-- INDEX ATTACH: network_assets_part_2_ip_address_idx
ALTER INDEX public.idx_network_assets_partitioned_ip_address ATTACH PARTITION public.network_assets_part_2_ip_address_idx;


-- INDEX ATTACH: network_assets_part_2_tenant_id_idx
ALTER INDEX public.idx_network_assets_partitioned_tenant_id ATTACH PARTITION public.network_assets_part_2_tenant_id_idx;


-- INDEX ATTACH: network_assets_part_3_deleted_at_idx
ALTER INDEX public.idx_network_assets_partitioned_deleted_at ATTACH PARTITION public.network_assets_part_3_deleted_at_idx;


-- INDEX ATTACH: network_assets_part_3_hostname_idx
ALTER INDEX public.idx_network_assets_partitioned_hostname ATTACH PARTITION public.network_assets_part_3_hostname_idx;


-- INDEX ATTACH: network_assets_part_3_ip_address_idx
ALTER INDEX public.idx_network_assets_partitioned_ip_address ATTACH PARTITION public.network_assets_part_3_ip_address_idx;


-- INDEX ATTACH: network_assets_part_3_tenant_id_idx
ALTER INDEX public.idx_network_assets_partitioned_tenant_id ATTACH PARTITION public.network_assets_part_3_tenant_id_idx;


-- INDEX ATTACH: network_assets_part_4_deleted_at_idx
ALTER INDEX public.idx_network_assets_partitioned_deleted_at ATTACH PARTITION public.network_assets_part_4_deleted_at_idx;


-- INDEX ATTACH: network_assets_part_4_hostname_idx
ALTER INDEX public.idx_network_assets_partitioned_hostname ATTACH PARTITION public.network_assets_part_4_hostname_idx;


-- INDEX ATTACH: network_assets_part_4_ip_address_idx
ALTER INDEX public.idx_network_assets_partitioned_ip_address ATTACH PARTITION public.network_assets_part_4_ip_address_idx;


-- INDEX ATTACH: network_assets_part_4_tenant_id_idx
ALTER INDEX public.idx_network_assets_partitioned_tenant_id ATTACH PARTITION public.network_assets_part_4_tenant_id_idx;


-- INDEX ATTACH: network_assets_part_5_deleted_at_idx
ALTER INDEX public.idx_network_assets_partitioned_deleted_at ATTACH PARTITION public.network_assets_part_5_deleted_at_idx;


-- INDEX ATTACH: network_assets_part_5_hostname_idx
ALTER INDEX public.idx_network_assets_partitioned_hostname ATTACH PARTITION public.network_assets_part_5_hostname_idx;


-- INDEX ATTACH: network_assets_part_5_ip_address_idx
ALTER INDEX public.idx_network_assets_partitioned_ip_address ATTACH PARTITION public.network_assets_part_5_ip_address_idx;


-- INDEX ATTACH: network_assets_part_5_tenant_id_idx
ALTER INDEX public.idx_network_assets_partitioned_tenant_id ATTACH PARTITION public.network_assets_part_5_tenant_id_idx;


-- INDEX ATTACH: network_assets_part_6_deleted_at_idx
ALTER INDEX public.idx_network_assets_partitioned_deleted_at ATTACH PARTITION public.network_assets_part_6_deleted_at_idx;


-- INDEX ATTACH: network_assets_part_6_hostname_idx
ALTER INDEX public.idx_network_assets_partitioned_hostname ATTACH PARTITION public.network_assets_part_6_hostname_idx;


-- INDEX ATTACH: network_assets_part_6_ip_address_idx
ALTER INDEX public.idx_network_assets_partitioned_ip_address ATTACH PARTITION public.network_assets_part_6_ip_address_idx;


-- INDEX ATTACH: network_assets_part_6_tenant_id_idx
ALTER INDEX public.idx_network_assets_partitioned_tenant_id ATTACH PARTITION public.network_assets_part_6_tenant_id_idx;


-- INDEX ATTACH: network_assets_part_7_deleted_at_idx
ALTER INDEX public.idx_network_assets_partitioned_deleted_at ATTACH PARTITION public.network_assets_part_7_deleted_at_idx;


-- INDEX ATTACH: network_assets_part_7_hostname_idx
ALTER INDEX public.idx_network_assets_partitioned_hostname ATTACH PARTITION public.network_assets_part_7_hostname_idx;


-- INDEX ATTACH: network_assets_part_7_ip_address_idx
ALTER INDEX public.idx_network_assets_partitioned_ip_address ATTACH PARTITION public.network_assets_part_7_ip_address_idx;


-- INDEX ATTACH: network_assets_part_7_tenant_id_idx
ALTER INDEX public.idx_network_assets_partitioned_tenant_id ATTACH PARTITION public.network_assets_part_7_tenant_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_0_batch_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_batch_id ATTACH PARTITION public.sensor_discoveries_part_0_batch_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_0_dest_ip_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_dest_ip ATTACH PARTITION public.sensor_discoveries_part_0_dest_ip_idx;


-- INDEX ATTACH: sensor_discoveries_part_0_protocol_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_protocol ATTACH PARTITION public.sensor_discoveries_part_0_protocol_idx;


-- INDEX ATTACH: sensor_discoveries_part_0_sensor_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_sensor_id ATTACH PARTITION public.sensor_discoveries_part_0_sensor_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_0_tenant_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_tenant_id ATTACH PARTITION public.sensor_discoveries_part_0_tenant_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_0_timestamp_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_timestamp ATTACH PARTITION public.sensor_discoveries_part_0_timestamp_idx;


-- INDEX ATTACH: sensor_discoveries_part_1_batch_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_batch_id ATTACH PARTITION public.sensor_discoveries_part_1_batch_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_1_dest_ip_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_dest_ip ATTACH PARTITION public.sensor_discoveries_part_1_dest_ip_idx;


-- INDEX ATTACH: sensor_discoveries_part_1_protocol_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_protocol ATTACH PARTITION public.sensor_discoveries_part_1_protocol_idx;


-- INDEX ATTACH: sensor_discoveries_part_1_sensor_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_sensor_id ATTACH PARTITION public.sensor_discoveries_part_1_sensor_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_1_tenant_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_tenant_id ATTACH PARTITION public.sensor_discoveries_part_1_tenant_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_1_timestamp_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_timestamp ATTACH PARTITION public.sensor_discoveries_part_1_timestamp_idx;


-- INDEX ATTACH: sensor_discoveries_part_2_batch_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_batch_id ATTACH PARTITION public.sensor_discoveries_part_2_batch_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_2_dest_ip_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_dest_ip ATTACH PARTITION public.sensor_discoveries_part_2_dest_ip_idx;


-- INDEX ATTACH: sensor_discoveries_part_2_protocol_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_protocol ATTACH PARTITION public.sensor_discoveries_part_2_protocol_idx;


-- INDEX ATTACH: sensor_discoveries_part_2_sensor_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_sensor_id ATTACH PARTITION public.sensor_discoveries_part_2_sensor_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_2_tenant_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_tenant_id ATTACH PARTITION public.sensor_discoveries_part_2_tenant_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_2_timestamp_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_timestamp ATTACH PARTITION public.sensor_discoveries_part_2_timestamp_idx;


-- INDEX ATTACH: sensor_discoveries_part_3_batch_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_batch_id ATTACH PARTITION public.sensor_discoveries_part_3_batch_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_3_dest_ip_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_dest_ip ATTACH PARTITION public.sensor_discoveries_part_3_dest_ip_idx;


-- INDEX ATTACH: sensor_discoveries_part_3_protocol_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_protocol ATTACH PARTITION public.sensor_discoveries_part_3_protocol_idx;


-- INDEX ATTACH: sensor_discoveries_part_3_sensor_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_sensor_id ATTACH PARTITION public.sensor_discoveries_part_3_sensor_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_3_tenant_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_tenant_id ATTACH PARTITION public.sensor_discoveries_part_3_tenant_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_3_timestamp_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_timestamp ATTACH PARTITION public.sensor_discoveries_part_3_timestamp_idx;


-- INDEX ATTACH: sensor_discoveries_part_4_batch_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_batch_id ATTACH PARTITION public.sensor_discoveries_part_4_batch_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_4_dest_ip_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_dest_ip ATTACH PARTITION public.sensor_discoveries_part_4_dest_ip_idx;


-- INDEX ATTACH: sensor_discoveries_part_4_protocol_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_protocol ATTACH PARTITION public.sensor_discoveries_part_4_protocol_idx;


-- INDEX ATTACH: sensor_discoveries_part_4_sensor_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_sensor_id ATTACH PARTITION public.sensor_discoveries_part_4_sensor_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_4_tenant_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_tenant_id ATTACH PARTITION public.sensor_discoveries_part_4_tenant_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_4_timestamp_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_timestamp ATTACH PARTITION public.sensor_discoveries_part_4_timestamp_idx;


-- INDEX ATTACH: sensor_discoveries_part_5_batch_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_batch_id ATTACH PARTITION public.sensor_discoveries_part_5_batch_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_5_dest_ip_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_dest_ip ATTACH PARTITION public.sensor_discoveries_part_5_dest_ip_idx;


-- INDEX ATTACH: sensor_discoveries_part_5_protocol_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_protocol ATTACH PARTITION public.sensor_discoveries_part_5_protocol_idx;


-- INDEX ATTACH: sensor_discoveries_part_5_sensor_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_sensor_id ATTACH PARTITION public.sensor_discoveries_part_5_sensor_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_5_tenant_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_tenant_id ATTACH PARTITION public.sensor_discoveries_part_5_tenant_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_5_timestamp_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_timestamp ATTACH PARTITION public.sensor_discoveries_part_5_timestamp_idx;


-- INDEX ATTACH: sensor_discoveries_part_6_batch_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_batch_id ATTACH PARTITION public.sensor_discoveries_part_6_batch_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_6_dest_ip_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_dest_ip ATTACH PARTITION public.sensor_discoveries_part_6_dest_ip_idx;


-- INDEX ATTACH: sensor_discoveries_part_6_protocol_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_protocol ATTACH PARTITION public.sensor_discoveries_part_6_protocol_idx;


-- INDEX ATTACH: sensor_discoveries_part_6_sensor_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_sensor_id ATTACH PARTITION public.sensor_discoveries_part_6_sensor_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_6_tenant_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_tenant_id ATTACH PARTITION public.sensor_discoveries_part_6_tenant_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_6_timestamp_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_timestamp ATTACH PARTITION public.sensor_discoveries_part_6_timestamp_idx;


-- INDEX ATTACH: sensor_discoveries_part_7_batch_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_batch_id ATTACH PARTITION public.sensor_discoveries_part_7_batch_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_7_dest_ip_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_dest_ip ATTACH PARTITION public.sensor_discoveries_part_7_dest_ip_idx;


-- INDEX ATTACH: sensor_discoveries_part_7_protocol_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_protocol ATTACH PARTITION public.sensor_discoveries_part_7_protocol_idx;


-- INDEX ATTACH: sensor_discoveries_part_7_sensor_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_sensor_id ATTACH PARTITION public.sensor_discoveries_part_7_sensor_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_7_tenant_id_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_tenant_id ATTACH PARTITION public.sensor_discoveries_part_7_tenant_id_idx;


-- INDEX ATTACH: sensor_discoveries_part_7_timestamp_idx
ALTER INDEX public.idx_sensor_discoveries_partitioned_timestamp ATTACH PARTITION public.sensor_discoveries_part_7_timestamp_idx;


-- TRIGGER: tenants auto_license_best_practices_on_tenant_create
CREATE OR REPLACE TRIGGER auto_license_best_practices_on_tenant_create AFTER INSERT ON public.tenants FOR EACH ROW EXECUTE FUNCTION public.auto_license_best_practices();


-- TRIGGER: tenants auto_license_iec62351_for_enterprise_on_tenant_create
CREATE OR REPLACE TRIGGER auto_license_iec62351_for_enterprise_on_tenant_create AFTER INSERT ON public.tenants FOR EACH ROW EXECUTE FUNCTION public.auto_license_iec62351_for_enterprise();


-- TRIGGER: tenants create_system_sensors_on_tenant_create
CREATE OR REPLACE TRIGGER create_system_sensors_on_tenant_create AFTER INSERT ON public.tenants FOR EACH ROW EXECUTE FUNCTION public.create_system_sensors_for_tenant();


-- TRIGGER: tenants set_tenant_trial_end
CREATE OR REPLACE TRIGGER set_tenant_trial_end BEFORE INSERT ON public.tenants FOR EACH ROW EXECUTE FUNCTION public.set_trial_end_date();


-- TRIGGER: subscription_tiers subscription_tiers_change_log
CREATE OR REPLACE TRIGGER subscription_tiers_change_log AFTER INSERT OR DELETE OR UPDATE ON public.subscription_tiers FOR EACH ROW EXECUTE FUNCTION public.log_tier_change();


-- TRIGGER: tenant_admin_settings tenant_admin_settings_audit_trigger
CREATE OR REPLACE TRIGGER tenant_admin_settings_audit_trigger AFTER UPDATE ON public.tenant_admin_settings FOR EACH ROW WHEN (((old.config IS DISTINCT FROM new.config) OR (old.version IS DISTINCT FROM new.version))) EXECUTE FUNCTION public.log_tenant_admin_settings_change();


-- TRIGGER: device_jobs trigger_device_jobs_updated_at
CREATE OR REPLACE TRIGGER trigger_device_jobs_updated_at BEFORE UPDATE ON public.device_jobs FOR EACH ROW EXECUTE FUNCTION public.update_device_jobs_updated_at();


-- TRIGGER: algorithms update_algorithms_updated_at
CREATE OR REPLACE TRIGGER update_algorithms_updated_at BEFORE UPDATE ON public.algorithms FOR EACH ROW EXECUTE FUNCTION public.update_algorithms_updated_at();


-- TRIGGER: api_format_preferences update_api_format_preferences_updated_at
CREATE OR REPLACE TRIGGER update_api_format_preferences_updated_at BEFORE UPDATE ON public.api_format_preferences FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: certificates update_certificates_updated_at
CREATE OR REPLACE TRIGGER update_certificates_updated_at BEFORE UPDATE ON public.certificates FOR EACH ROW EXECUTE FUNCTION public.update_certificates_updated_at();


-- TRIGGER: ci_relationships update_ci_relationships_updated_at
CREATE OR REPLACE TRIGGER update_ci_relationships_updated_at BEFORE UPDATE ON public.ci_relationships FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: cmdb_entity_mappings update_cmdb_entity_mappings_updated_at
CREATE OR REPLACE TRIGGER update_cmdb_entity_mappings_updated_at BEFORE UPDATE ON public.cmdb_entity_mappings FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: cmdb_sync_jobs update_cmdb_sync_jobs_updated_at
CREATE OR REPLACE TRIGGER update_cmdb_sync_jobs_updated_at BEFORE UPDATE ON public.cmdb_sync_jobs FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: cmdb_sync_profiles update_cmdb_sync_profiles_updated_at
CREATE OR REPLACE TRIGGER update_cmdb_sync_profiles_updated_at BEFORE UPDATE ON public.cmdb_sync_profiles FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: compliance_findings update_compliance_findings_updated_at
CREATE OR REPLACE TRIGGER update_compliance_findings_updated_at BEFORE UPDATE ON public.compliance_findings FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: compliance_overrides update_compliance_overrides_updated_at
CREATE OR REPLACE TRIGGER update_compliance_overrides_updated_at BEFORE UPDATE ON public.compliance_overrides FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: compliance_reports update_compliance_reports_updated_at
CREATE OR REPLACE TRIGGER update_compliance_reports_updated_at BEFORE UPDATE ON public.compliance_reports FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: compliance_rules update_compliance_rules_updated_at
CREATE OR REPLACE TRIGGER update_compliance_rules_updated_at BEFORE UPDATE ON public.compliance_rules FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: compliance_scenarios update_compliance_scenarios_updated_at
CREATE OR REPLACE TRIGGER update_compliance_scenarios_updated_at BEFORE UPDATE ON public.compliance_scenarios FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: control_measurements update_control_measurements_updated_at
CREATE OR REPLACE TRIGGER update_control_measurements_updated_at BEFORE UPDATE ON public.control_measurements FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: crypto_applications update_crypto_applications_updated_at
CREATE OR REPLACE TRIGGER update_crypto_applications_updated_at BEFORE UPDATE ON public.crypto_applications FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: discovery_alert_configs update_discovery_alert_configs_updated_at
CREATE OR REPLACE TRIGGER update_discovery_alert_configs_updated_at BEFORE UPDATE ON public.discovery_alert_configs FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: discovery_approval_queue update_discovery_approval_queue_updated_at
CREATE OR REPLACE TRIGGER update_discovery_approval_queue_updated_at BEFORE UPDATE ON public.discovery_approval_queue FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: discovery_auto_approval_rules update_discovery_auto_approval_rules_updated_at
CREATE OR REPLACE TRIGGER update_discovery_auto_approval_rules_updated_at BEFORE UPDATE ON public.discovery_auto_approval_rules FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: discovery_jobs update_discovery_jobs_updated_at
CREATE OR REPLACE TRIGGER update_discovery_jobs_updated_at BEFORE UPDATE ON public.discovery_jobs FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: discovery_rate_limits update_discovery_rate_limits_updated_at
CREATE OR REPLACE TRIGGER update_discovery_rate_limits_updated_at BEFORE UPDATE ON public.discovery_rate_limits FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: discovery_targets update_discovery_targets_updated_at
CREATE OR REPLACE TRIGGER update_discovery_targets_updated_at BEFORE UPDATE ON public.discovery_targets FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: health_benchmarks update_health_benchmarks_updated_at
CREATE OR REPLACE TRIGGER update_health_benchmarks_updated_at BEFORE UPDATE ON public.health_benchmarks FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: measurement_templates update_measurement_templates_updated_at
CREATE OR REPLACE TRIGGER update_measurement_templates_updated_at BEFORE UPDATE ON public.measurement_templates FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: measurement_types update_measurement_types_updated_at
CREATE OR REPLACE TRIGGER update_measurement_types_updated_at BEFORE UPDATE ON public.measurement_types FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: pcap_upload_jobs update_pcap_upload_jobs_updated_at
CREATE OR REPLACE TRIGGER update_pcap_upload_jobs_updated_at BEFORE UPDATE ON public.pcap_upload_jobs FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: platform_framework_controls update_platform_framework_controls_updated_at
CREATE OR REPLACE TRIGGER update_platform_framework_controls_updated_at BEFORE UPDATE ON public.platform_framework_controls FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: platform_frameworks update_platform_frameworks_updated_at
CREATE OR REPLACE TRIGGER update_platform_frameworks_updated_at BEFORE UPDATE ON public.platform_frameworks FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: platform_notification_channels update_platform_notification_channels_updated_at
CREATE OR REPLACE TRIGGER update_platform_notification_channels_updated_at BEFORE UPDATE ON public.platform_notification_channels FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: platform_notification_rules update_platform_notification_rules_updated_at
CREATE OR REPLACE TRIGGER update_platform_notification_rules_updated_at BEFORE UPDATE ON public.platform_notification_rules FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: platform_roles update_platform_roles_updated_at
CREATE OR REPLACE TRIGGER update_platform_roles_updated_at BEFORE UPDATE ON public.platform_roles FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: platform_settings update_platform_settings_updated_at
CREATE OR REPLACE TRIGGER update_platform_settings_updated_at BEFORE UPDATE ON public.platform_settings FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: resource_permissions update_resource_permissions_updated_at
CREATE OR REPLACE TRIGGER update_resource_permissions_updated_at BEFORE UPDATE ON public.resource_permissions FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: rule_vulnerability_mappings update_rule_vulnerability_mappings_updated_at
CREATE OR REPLACE TRIGGER update_rule_vulnerability_mappings_updated_at BEFORE UPDATE ON public.rule_vulnerability_mappings FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: sensors update_sensors_updated_at
CREATE OR REPLACE TRIGGER update_sensors_updated_at BEFORE UPDATE ON public.sensors FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: sso_group_role_mappings update_sso_group_role_mappings_updated_at
CREATE OR REPLACE TRIGGER update_sso_group_role_mappings_updated_at BEFORE UPDATE ON public.sso_group_role_mappings FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: sso_providers update_sso_providers_updated_at
CREATE OR REPLACE TRIGGER update_sso_providers_updated_at BEFORE UPDATE ON public.sso_providers FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: tenant_admin_settings update_tenant_admin_settings_updated_at
CREATE OR REPLACE TRIGGER update_tenant_admin_settings_updated_at BEFORE UPDATE ON public.tenant_admin_settings FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: tenant_framework_controls update_tenant_framework_controls_updated_at
CREATE OR REPLACE TRIGGER update_tenant_framework_controls_updated_at BEFORE UPDATE ON public.tenant_framework_controls FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: tenant_framework_licenses update_tenant_framework_licenses_updated_at
CREATE OR REPLACE TRIGGER update_tenant_framework_licenses_updated_at BEFORE UPDATE ON public.tenant_framework_licenses FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: tenant_frameworks update_tenant_frameworks_updated_at
CREATE OR REPLACE TRIGGER update_tenant_frameworks_updated_at BEFORE UPDATE ON public.tenant_frameworks FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: tenant_health update_tenant_health_updated_at
CREATE OR REPLACE TRIGGER update_tenant_health_updated_at BEFORE UPDATE ON public.tenant_health FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: tenant_measurement_overrides update_tenant_measurement_overrides_updated_at
CREATE OR REPLACE TRIGGER update_tenant_measurement_overrides_updated_at BEFORE UPDATE ON public.tenant_measurement_overrides FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: tenant_notification_channels update_tenant_notification_channels_updated_at
CREATE OR REPLACE TRIGGER update_tenant_notification_channels_updated_at BEFORE UPDATE ON public.tenant_notification_channels FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: tenant_notification_rules update_tenant_notification_rules_updated_at
CREATE OR REPLACE TRIGGER update_tenant_notification_rules_updated_at BEFORE UPDATE ON public.tenant_notification_rules FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: tenant_roles update_tenant_roles_updated_at
CREATE OR REPLACE TRIGGER update_tenant_roles_updated_at BEFORE UPDATE ON public.tenant_roles FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: tenant_usage update_tenant_usage_updated_at
CREATE OR REPLACE TRIGGER update_tenant_usage_updated_at BEFORE UPDATE ON public.tenant_usage FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: tenants update_tenants_updated_at
CREATE OR REPLACE TRIGGER update_tenants_updated_at BEFORE UPDATE ON public.tenants FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: tickets update_tickets_updated_at
CREATE OR REPLACE TRIGGER update_tickets_updated_at BEFORE UPDATE ON public.tickets FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: ui_themes update_ui_themes_updated_at
CREATE OR REPLACE TRIGGER update_ui_themes_updated_at BEFORE UPDATE ON public.ui_themes FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: user_auth_methods update_user_auth_methods_updated_at
CREATE OR REPLACE TRIGGER update_user_auth_methods_updated_at BEFORE UPDATE ON public.user_auth_methods FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: users update_user_count_on_delete
CREATE OR REPLACE TRIGGER update_user_count_on_delete AFTER DELETE ON public.users FOR EACH ROW EXECUTE FUNCTION public.update_tenant_user_count();


-- TRIGGER: users update_user_count_on_insert
CREATE OR REPLACE TRIGGER update_user_count_on_insert AFTER INSERT ON public.users FOR EACH ROW EXECUTE FUNCTION public.update_tenant_user_count();


-- TRIGGER: users update_user_count_on_update
CREATE OR REPLACE TRIGGER update_user_count_on_update AFTER UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.update_tenant_user_count();


-- TRIGGER: user_framework_preferences update_user_framework_preferences_updated_at
CREATE OR REPLACE TRIGGER update_user_framework_preferences_updated_at BEFORE UPDATE ON public.user_framework_preferences FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: user_workflow_progress update_user_workflow_progress_updated_at
CREATE OR REPLACE TRIGGER update_user_workflow_progress_updated_at BEFORE UPDATE ON public.user_workflow_progress FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: users update_users_updated_at
CREATE OR REPLACE TRIGGER update_users_updated_at BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- TRIGGER: workflow_configurations update_workflow_configurations_updated_at
CREATE OR REPLACE TRIGGER update_workflow_configurations_updated_at BEFORE UPDATE ON public.workflow_configurations FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


-- FK CONSTRAINT: activity_logs activity_logs_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('audit.activity_logs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'activity_logs_tenant_id_fkey' AND conrelid = to_regclass('audit.activity_logs')
     ) THEN
    ALTER TABLE audit.activity_logs
        ADD CONSTRAINT activity_logs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: alert_instances alert_instances_rule_id_fkey
DO $$ BEGIN
  IF to_regclass('audit.alert_instances') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'alert_instances_rule_id_fkey' AND conrelid = to_regclass('audit.alert_instances')
     ) THEN
    ALTER TABLE ONLY audit.alert_instances
        ADD CONSTRAINT alert_instances_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES audit.alert_rules(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: alert_instances alert_instances_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('audit.alert_instances') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'alert_instances_tenant_id_fkey' AND conrelid = to_regclass('audit.alert_instances')
     ) THEN
    ALTER TABLE ONLY audit.alert_instances
        ADD CONSTRAINT alert_instances_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: alert_rules alert_rules_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('audit.alert_rules') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'alert_rules_tenant_id_fkey' AND conrelid = to_regclass('audit.alert_rules')
     ) THEN
    ALTER TABLE ONLY audit.alert_rules
        ADD CONSTRAINT alert_rules_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: audit_logs audit_logs_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('audit.audit_logs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'audit_logs_tenant_id_fkey' AND conrelid = to_regclass('audit.audit_logs')
     ) THEN
    ALTER TABLE ONLY audit.audit_logs
        ADD CONSTRAINT audit_logs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: audit_logs audit_logs_user_id_fkey
DO $$ BEGIN
  IF to_regclass('audit.audit_logs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'audit_logs_user_id_fkey' AND conrelid = to_regclass('audit.audit_logs')
     ) THEN
    ALTER TABLE ONLY audit.audit_logs
        ADD CONSTRAINT audit_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: job_execution_logs job_execution_logs_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('audit.job_execution_logs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'job_execution_logs_tenant_id_fkey' AND conrelid = to_regclass('audit.job_execution_logs')
     ) THEN
    ALTER TABLE ONLY audit.job_execution_logs
        ADD CONSTRAINT job_execution_logs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: retention_jobs retention_jobs_policy_id_fkey
DO $$ BEGIN
  IF to_regclass('audit.retention_jobs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'retention_jobs_policy_id_fkey' AND conrelid = to_regclass('audit.retention_jobs')
     ) THEN
    ALTER TABLE ONLY audit.retention_jobs
        ADD CONSTRAINT retention_jobs_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES audit.retention_policies(id);
  END IF;
END $$;


-- FK CONSTRAINT: scheduled_compliance_reports scheduled_compliance_reports_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('audit.scheduled_compliance_reports') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'scheduled_compliance_reports_tenant_id_fkey' AND conrelid = to_regclass('audit.scheduled_compliance_reports')
     ) THEN
    ALTER TABLE ONLY audit.scheduled_compliance_reports
        ADD CONSTRAINT scheduled_compliance_reports_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: scheduled_report_executions scheduled_report_executions_schedule_id_fkey
DO $$ BEGIN
  IF to_regclass('audit.scheduled_report_executions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'scheduled_report_executions_schedule_id_fkey' AND conrelid = to_regclass('audit.scheduled_report_executions')
     ) THEN
    ALTER TABLE ONLY audit.scheduled_report_executions
        ADD CONSTRAINT scheduled_report_executions_schedule_id_fkey FOREIGN KEY (schedule_id) REFERENCES audit.scheduled_compliance_reports(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: scheduled_report_executions scheduled_report_executions_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('audit.scheduled_report_executions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'scheduled_report_executions_tenant_id_fkey' AND conrelid = to_regclass('audit.scheduled_report_executions')
     ) THEN
    ALTER TABLE ONLY audit.scheduled_report_executions
        ADD CONSTRAINT scheduled_report_executions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: siem_health_checks siem_health_checks_integration_id_fkey
DO $$ BEGIN
  IF to_regclass('audit.siem_health_checks') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'siem_health_checks_integration_id_fkey' AND conrelid = to_regclass('audit.siem_health_checks')
     ) THEN
    ALTER TABLE ONLY audit.siem_health_checks
        ADD CONSTRAINT siem_health_checks_integration_id_fkey FOREIGN KEY (integration_id) REFERENCES audit.siem_integrations(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: siem_integrations siem_integrations_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('audit.siem_integrations') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'siem_integrations_tenant_id_fkey' AND conrelid = to_regclass('audit.siem_integrations')
     ) THEN
    ALTER TABLE ONLY audit.siem_integrations
        ADD CONSTRAINT siem_integrations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: access_pattern_analysis access_pattern_analysis_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.access_pattern_analysis') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'access_pattern_analysis_tenant_id_fkey' AND conrelid = to_regclass('public.access_pattern_analysis')
     ) THEN
    ALTER TABLE ONLY public.access_pattern_analysis
        ADD CONSTRAINT access_pattern_analysis_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: agent_ca_certificates agent_ca_certificates_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.agent_ca_certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'agent_ca_certificates_tenant_id_fkey' AND conrelid = to_regclass('public.agent_ca_certificates')
     ) THEN
    ALTER TABLE ONLY public.agent_ca_certificates
        ADD CONSTRAINT agent_ca_certificates_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: agent_certificates agent_certificates_agent_id_fkey
DO $$ BEGIN
  IF to_regclass('public.agent_certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'agent_certificates_agent_id_fkey' AND conrelid = to_regclass('public.agent_certificates')
     ) THEN
    ALTER TABLE ONLY public.agent_certificates
        ADD CONSTRAINT agent_certificates_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.device_agents(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: agent_certificates agent_certificates_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.agent_certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'agent_certificates_tenant_id_fkey' AND conrelid = to_regclass('public.agent_certificates')
     ) THEN
    ALTER TABLE ONLY public.agent_certificates
        ADD CONSTRAINT agent_certificates_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: ai_analysis_results ai_analysis_results_model_id_fkey
DO $$ BEGIN
  IF to_regclass('public.ai_analysis_results') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'ai_analysis_results_model_id_fkey' AND conrelid = to_regclass('public.ai_analysis_results')
     ) THEN
    ALTER TABLE ONLY public.ai_analysis_results
        ADD CONSTRAINT ai_analysis_results_model_id_fkey FOREIGN KEY (model_id) REFERENCES public.ai_models(id);
  END IF;
END $$;


-- FK CONSTRAINT: ai_analysis_results ai_analysis_results_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.ai_analysis_results') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'ai_analysis_results_tenant_id_fkey' AND conrelid = to_regclass('public.ai_analysis_results')
     ) THEN
    ALTER TABLE ONLY public.ai_analysis_results
        ADD CONSTRAINT ai_analysis_results_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: api_format_preferences api_format_preferences_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.api_format_preferences') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'api_format_preferences_tenant_id_fkey' AND conrelid = to_regclass('public.api_format_preferences')
     ) THEN
    ALTER TABLE ONLY public.api_format_preferences
        ADD CONSTRAINT api_format_preferences_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: api_security_monitoring api_security_monitoring_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.api_security_monitoring') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'api_security_monitoring_tenant_id_fkey' AND conrelid = to_regclass('public.api_security_monitoring')
     ) THEN
    ALTER TABLE ONLY public.api_security_monitoring
        ADD CONSTRAINT api_security_monitoring_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: asset_history asset_history_actor_user_id_fkey
DO $$ BEGIN
  IF to_regclass('public.asset_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'asset_history_actor_user_id_fkey' AND conrelid = to_regclass('public.asset_history')
     ) THEN
    ALTER TABLE ONLY public.asset_history
        ADD CONSTRAINT asset_history_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: asset_history asset_history_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.asset_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'asset_history_tenant_id_fkey' AND conrelid = to_regclass('public.asset_history')
     ) THEN
    ALTER TABLE ONLY public.asset_history
        ADD CONSTRAINT asset_history_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: asset_lifecycle_policies asset_lifecycle_policies_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.asset_lifecycle_policies') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'asset_lifecycle_policies_tenant_id_fkey' AND conrelid = to_regclass('public.asset_lifecycle_policies')
     ) THEN
    ALTER TABLE ONLY public.asset_lifecycle_policies
        ADD CONSTRAINT asset_lifecycle_policies_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: auth_audit_log auth_audit_log_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.auth_audit_log') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'auth_audit_log_tenant_id_fkey' AND conrelid = to_regclass('public.auth_audit_log')
     ) THEN
    ALTER TABLE ONLY public.auth_audit_log
        ADD CONSTRAINT auth_audit_log_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: auth_audit_log auth_audit_log_user_id_fkey
DO $$ BEGIN
  IF to_regclass('public.auth_audit_log') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'auth_audit_log_user_id_fkey' AND conrelid = to_regclass('public.auth_audit_log')
     ) THEN
    ALTER TABLE ONLY public.auth_audit_log
        ADD CONSTRAINT auth_audit_log_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: aws_cost_data aws_cost_data_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.aws_cost_data') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'aws_cost_data_tenant_id_fkey' AND conrelid = to_regclass('public.aws_cost_data')
     ) THEN
    ALTER TABLE ONLY public.aws_cost_data
        ADD CONSTRAINT aws_cost_data_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: aws_cost_sync_jobs aws_cost_sync_jobs_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.aws_cost_sync_jobs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'aws_cost_sync_jobs_tenant_id_fkey' AND conrelid = to_regclass('public.aws_cost_sync_jobs')
     ) THEN
    ALTER TABLE ONLY public.aws_cost_sync_jobs
        ADD CONSTRAINT aws_cost_sync_jobs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: billing_coupon_redemptions billing_coupon_redemptions_coupon_id_fkey
DO $$ BEGIN
  IF to_regclass('public.billing_coupon_redemptions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_coupon_redemptions_coupon_id_fkey' AND conrelid = to_regclass('public.billing_coupon_redemptions')
     ) THEN
    ALTER TABLE ONLY public.billing_coupon_redemptions
        ADD CONSTRAINT billing_coupon_redemptions_coupon_id_fkey FOREIGN KEY (coupon_id) REFERENCES public.billing_coupons(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: billing_coupon_redemptions billing_coupon_redemptions_subscription_id_fkey
DO $$ BEGIN
  IF to_regclass('public.billing_coupon_redemptions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_coupon_redemptions_subscription_id_fkey' AND conrelid = to_regclass('public.billing_coupon_redemptions')
     ) THEN
    ALTER TABLE ONLY public.billing_coupon_redemptions
        ADD CONSTRAINT billing_coupon_redemptions_subscription_id_fkey FOREIGN KEY (subscription_id) REFERENCES public.billing_subscriptions(id);
  END IF;
END $$;


-- FK CONSTRAINT: billing_coupon_redemptions billing_coupon_redemptions_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.billing_coupon_redemptions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_coupon_redemptions_tenant_id_fkey' AND conrelid = to_regclass('public.billing_coupon_redemptions')
     ) THEN
    ALTER TABLE ONLY public.billing_coupon_redemptions
        ADD CONSTRAINT billing_coupon_redemptions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: billing_customers billing_customers_provider_id_fkey
DO $$ BEGIN
  IF to_regclass('public.billing_customers') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_customers_provider_id_fkey' AND conrelid = to_regclass('public.billing_customers')
     ) THEN
    ALTER TABLE ONLY public.billing_customers
        ADD CONSTRAINT billing_customers_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.billing_providers(id) ON DELETE RESTRICT;
  END IF;
END $$;


-- FK CONSTRAINT: billing_customers billing_customers_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.billing_customers') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_customers_tenant_id_fkey' AND conrelid = to_regclass('public.billing_customers')
     ) THEN
    ALTER TABLE ONLY public.billing_customers
        ADD CONSTRAINT billing_customers_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: billing_dunning_attempts billing_dunning_attempts_invoice_id_fkey
DO $$ BEGIN
  IF to_regclass('public.billing_dunning_attempts') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_dunning_attempts_invoice_id_fkey' AND conrelid = to_regclass('public.billing_dunning_attempts')
     ) THEN
    ALTER TABLE ONLY public.billing_dunning_attempts
        ADD CONSTRAINT billing_dunning_attempts_invoice_id_fkey FOREIGN KEY (invoice_id) REFERENCES public.billing_invoices(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: billing_dunning_attempts billing_dunning_attempts_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.billing_dunning_attempts') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_dunning_attempts_tenant_id_fkey' AND conrelid = to_regclass('public.billing_dunning_attempts')
     ) THEN
    ALTER TABLE ONLY public.billing_dunning_attempts
        ADD CONSTRAINT billing_dunning_attempts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: billing_events billing_events_provider_id_fkey
DO $$ BEGIN
  IF to_regclass('public.billing_events') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_events_provider_id_fkey' AND conrelid = to_regclass('public.billing_events')
     ) THEN
    ALTER TABLE ONLY public.billing_events
        ADD CONSTRAINT billing_events_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.billing_providers(id) ON DELETE RESTRICT;
  END IF;
END $$;


-- FK CONSTRAINT: billing_invoice_line_items billing_invoice_line_items_invoice_id_fkey
DO $$ BEGIN
  IF to_regclass('public.billing_invoice_line_items') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_invoice_line_items_invoice_id_fkey' AND conrelid = to_regclass('public.billing_invoice_line_items')
     ) THEN
    ALTER TABLE ONLY public.billing_invoice_line_items
        ADD CONSTRAINT billing_invoice_line_items_invoice_id_fkey FOREIGN KEY (invoice_id) REFERENCES public.billing_invoices(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: billing_invoices billing_invoices_provider_id_fkey
DO $$ BEGIN
  IF to_regclass('public.billing_invoices') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_invoices_provider_id_fkey' AND conrelid = to_regclass('public.billing_invoices')
     ) THEN
    ALTER TABLE ONLY public.billing_invoices
        ADD CONSTRAINT billing_invoices_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.billing_providers(id) ON DELETE RESTRICT;
  END IF;
END $$;


-- FK CONSTRAINT: billing_invoices billing_invoices_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.billing_invoices') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_invoices_tenant_id_fkey' AND conrelid = to_regclass('public.billing_invoices')
     ) THEN
    ALTER TABLE ONLY public.billing_invoices
        ADD CONSTRAINT billing_invoices_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: billing_subscriptions billing_subscriptions_coupon_id_fkey
DO $$ BEGIN
  IF to_regclass('public.billing_subscriptions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_subscriptions_coupon_id_fkey' AND conrelid = to_regclass('public.billing_subscriptions')
     ) THEN
    ALTER TABLE ONLY public.billing_subscriptions
        ADD CONSTRAINT billing_subscriptions_coupon_id_fkey FOREIGN KEY (coupon_id) REFERENCES public.billing_coupons(id);
  END IF;
END $$;


-- FK CONSTRAINT: billing_subscriptions billing_subscriptions_provider_id_fkey
DO $$ BEGIN
  IF to_regclass('public.billing_subscriptions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_subscriptions_provider_id_fkey' AND conrelid = to_regclass('public.billing_subscriptions')
     ) THEN
    ALTER TABLE ONLY public.billing_subscriptions
        ADD CONSTRAINT billing_subscriptions_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.billing_providers(id) ON DELETE RESTRICT;
  END IF;
END $$;


-- FK CONSTRAINT: billing_subscriptions billing_subscriptions_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.billing_subscriptions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_subscriptions_tenant_id_fkey' AND conrelid = to_regclass('public.billing_subscriptions')
     ) THEN
    ALTER TABLE ONLY public.billing_subscriptions
        ADD CONSTRAINT billing_subscriptions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: billing_trial_tracking billing_trial_tracking_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.billing_trial_tracking') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'billing_trial_tracking_tenant_id_fkey' AND conrelid = to_regclass('public.billing_trial_tracking')
     ) THEN
    ALTER TABLE ONLY public.billing_trial_tracking
        ADD CONSTRAINT billing_trial_tracking_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: certificate_extensions certificate_extensions_certificate_id_fkey
DO $$ BEGIN
  IF to_regclass('public.certificate_extensions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'certificate_extensions_certificate_id_fkey' AND conrelid = to_regclass('public.certificate_extensions')
     ) THEN
    ALTER TABLE ONLY public.certificate_extensions
        ADD CONSTRAINT certificate_extensions_certificate_id_fkey FOREIGN KEY (certificate_id) REFERENCES public.certificates(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: certificate_history certificate_history_certificate_id_fkey
DO $$ BEGIN
  IF to_regclass('public.certificate_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'certificate_history_certificate_id_fkey' AND conrelid = to_regclass('public.certificate_history')
     ) THEN
    ALTER TABLE ONLY public.certificate_history
        ADD CONSTRAINT certificate_history_certificate_id_fkey FOREIGN KEY (certificate_id) REFERENCES public.certificates(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: certificate_history certificate_history_created_by_fkey
DO $$ BEGIN
  IF to_regclass('public.certificate_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'certificate_history_created_by_fkey' AND conrelid = to_regclass('public.certificate_history')
     ) THEN
    ALTER TABLE ONLY public.certificate_history
        ADD CONSTRAINT certificate_history_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: certificate_history certificate_history_previous_certificate_id_fkey
DO $$ BEGIN
  IF to_regclass('public.certificate_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'certificate_history_previous_certificate_id_fkey' AND conrelid = to_regclass('public.certificate_history')
     ) THEN
    ALTER TABLE ONLY public.certificate_history
        ADD CONSTRAINT certificate_history_previous_certificate_id_fkey FOREIGN KEY (previous_certificate_id) REFERENCES public.certificates(id);
  END IF;
END $$;


-- FK CONSTRAINT: certificate_history certificate_history_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.certificate_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'certificate_history_tenant_id_fkey' AND conrelid = to_regclass('public.certificate_history')
     ) THEN
    ALTER TABLE ONLY public.certificate_history
        ADD CONSTRAINT certificate_history_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: certificates certificates_issuer_certificate_id_fkey
DO $$ BEGIN
  IF to_regclass('public.certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'certificates_issuer_certificate_id_fkey' AND conrelid = to_regclass('public.certificates')
     ) THEN
    ALTER TABLE ONLY public.certificates
        ADD CONSTRAINT certificates_issuer_certificate_id_fkey FOREIGN KEY (issuer_certificate_id) REFERENCES public.certificates(id);
  END IF;
END $$;


-- FK CONSTRAINT: certificates certificates_superseded_by_certificate_id_fkey
DO $$ BEGIN
  IF to_regclass('public.certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'certificates_superseded_by_certificate_id_fkey' AND conrelid = to_regclass('public.certificates')
     ) THEN
    ALTER TABLE ONLY public.certificates
        ADD CONSTRAINT certificates_superseded_by_certificate_id_fkey FOREIGN KEY (superseded_by_certificate_id) REFERENCES public.certificates(id);
  END IF;
END $$;


-- FK CONSTRAINT: certificates certificates_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'certificates_tenant_id_fkey' AND conrelid = to_regclass('public.certificates')
     ) THEN
    ALTER TABLE ONLY public.certificates
        ADD CONSTRAINT certificates_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: ci_relationships ci_relationships_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.ci_relationships') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'ci_relationships_tenant_id_fkey' AND conrelid = to_regclass('public.ci_relationships')
     ) THEN
    ALTER TABLE ONLY public.ci_relationships
        ADD CONSTRAINT ci_relationships_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: cmdb_entity_mappings cmdb_entity_mappings_profile_id_fkey
DO $$ BEGIN
  IF to_regclass('public.cmdb_entity_mappings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'cmdb_entity_mappings_profile_id_fkey' AND conrelid = to_regclass('public.cmdb_entity_mappings')
     ) THEN
    ALTER TABLE ONLY public.cmdb_entity_mappings
        ADD CONSTRAINT cmdb_entity_mappings_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.cmdb_sync_profiles(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: cmdb_entity_mappings cmdb_entity_mappings_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.cmdb_entity_mappings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'cmdb_entity_mappings_tenant_id_fkey' AND conrelid = to_regclass('public.cmdb_entity_mappings')
     ) THEN
    ALTER TABLE ONLY public.cmdb_entity_mappings
        ADD CONSTRAINT cmdb_entity_mappings_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: cmdb_sync_jobs cmdb_sync_jobs_profile_id_fkey
DO $$ BEGIN
  IF to_regclass('public.cmdb_sync_jobs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'cmdb_sync_jobs_profile_id_fkey' AND conrelid = to_regclass('public.cmdb_sync_jobs')
     ) THEN
    ALTER TABLE ONLY public.cmdb_sync_jobs
        ADD CONSTRAINT cmdb_sync_jobs_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.cmdb_sync_profiles(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: cmdb_sync_jobs cmdb_sync_jobs_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.cmdb_sync_jobs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'cmdb_sync_jobs_tenant_id_fkey' AND conrelid = to_regclass('public.cmdb_sync_jobs')
     ) THEN
    ALTER TABLE ONLY public.cmdb_sync_jobs
        ADD CONSTRAINT cmdb_sync_jobs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: cmdb_sync_profiles cmdb_sync_profiles_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.cmdb_sync_profiles') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'cmdb_sync_profiles_tenant_id_fkey' AND conrelid = to_regclass('public.cmdb_sync_profiles')
     ) THEN
    ALTER TABLE ONLY public.cmdb_sync_profiles
        ADD CONSTRAINT cmdb_sync_profiles_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: compliance_checks compliance_checks_report_id_fkey
DO $$ BEGIN
  IF to_regclass('public.compliance_checks') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_checks_report_id_fkey' AND conrelid = to_regclass('public.compliance_checks')
     ) THEN
    ALTER TABLE ONLY public.compliance_checks
        ADD CONSTRAINT compliance_checks_report_id_fkey FOREIGN KEY (report_id) REFERENCES public.compliance_reports(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: compliance_checks compliance_checks_rule_id_fkey
DO $$ BEGIN
  IF to_regclass('public.compliance_checks') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_checks_rule_id_fkey' AND conrelid = to_regclass('public.compliance_checks')
     ) THEN
    ALTER TABLE ONLY public.compliance_checks
        ADD CONSTRAINT compliance_checks_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES public.compliance_rules(id);
  END IF;
END $$;


-- FK CONSTRAINT: compliance_checks compliance_checks_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.compliance_checks') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_checks_tenant_id_fkey' AND conrelid = to_regclass('public.compliance_checks')
     ) THEN
    ALTER TABLE ONLY public.compliance_checks
        ADD CONSTRAINT compliance_checks_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: compliance_finding_history compliance_finding_history_changed_by_fkey
DO $$ BEGIN
  IF to_regclass('public.compliance_finding_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_finding_history_changed_by_fkey' AND conrelid = to_regclass('public.compliance_finding_history')
     ) THEN
    ALTER TABLE ONLY public.compliance_finding_history
        ADD CONSTRAINT compliance_finding_history_changed_by_fkey FOREIGN KEY (changed_by) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: compliance_finding_history compliance_finding_history_finding_id_fkey
DO $$ BEGIN
  IF to_regclass('public.compliance_finding_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_finding_history_finding_id_fkey' AND conrelid = to_regclass('public.compliance_finding_history')
     ) THEN
    ALTER TABLE ONLY public.compliance_finding_history
        ADD CONSTRAINT compliance_finding_history_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.compliance_findings(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: compliance_findings compliance_findings_assigned_by_fkey
DO $$ BEGIN
  IF to_regclass('public.compliance_findings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_findings_assigned_by_fkey' AND conrelid = to_regclass('public.compliance_findings')
     ) THEN
    ALTER TABLE ONLY public.compliance_findings
        ADD CONSTRAINT compliance_findings_assigned_by_fkey FOREIGN KEY (assigned_by) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: compliance_findings compliance_findings_assigned_to_fkey
DO $$ BEGIN
  IF to_regclass('public.compliance_findings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_findings_assigned_to_fkey' AND conrelid = to_regclass('public.compliance_findings')
     ) THEN
    ALTER TABLE ONLY public.compliance_findings
        ADD CONSTRAINT compliance_findings_assigned_to_fkey FOREIGN KEY (assigned_to) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: compliance_findings compliance_findings_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.compliance_findings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_findings_tenant_id_fkey' AND conrelid = to_regclass('public.compliance_findings')
     ) THEN
    ALTER TABLE ONLY public.compliance_findings
        ADD CONSTRAINT compliance_findings_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: compliance_overrides compliance_overrides_created_by_fkey
DO $$ BEGIN
  IF to_regclass('public.compliance_overrides') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_overrides_created_by_fkey' AND conrelid = to_regclass('public.compliance_overrides')
     ) THEN
    ALTER TABLE ONLY public.compliance_overrides
        ADD CONSTRAINT compliance_overrides_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: compliance_overrides compliance_overrides_scenario_id_fkey
DO $$ BEGIN
  IF to_regclass('public.compliance_overrides') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_overrides_scenario_id_fkey' AND conrelid = to_regclass('public.compliance_overrides')
     ) THEN
    ALTER TABLE ONLY public.compliance_overrides
        ADD CONSTRAINT compliance_overrides_scenario_id_fkey FOREIGN KEY (scenario_id) REFERENCES public.compliance_scenarios(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: compliance_overrides compliance_overrides_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.compliance_overrides') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_overrides_tenant_id_fkey' AND conrelid = to_regclass('public.compliance_overrides')
     ) THEN
    ALTER TABLE ONLY public.compliance_overrides
        ADD CONSTRAINT compliance_overrides_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: compliance_reports compliance_reports_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.compliance_reports') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_reports_tenant_id_fkey' AND conrelid = to_regclass('public.compliance_reports')
     ) THEN
    ALTER TABLE ONLY public.compliance_reports
        ADD CONSTRAINT compliance_reports_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: compliance_requirements compliance_requirements_framework_id_fkey
DO $$ BEGIN
  IF to_regclass('public.compliance_requirements') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_requirements_framework_id_fkey' AND conrelid = to_regclass('public.compliance_requirements')
     ) THEN
    ALTER TABLE ONLY public.compliance_requirements
        ADD CONSTRAINT compliance_requirements_framework_id_fkey FOREIGN KEY (framework_id) REFERENCES public.compliance_framework_status(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: compliance_scenarios compliance_scenarios_created_by_fkey
DO $$ BEGIN
  IF to_regclass('public.compliance_scenarios') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_scenarios_created_by_fkey' AND conrelid = to_regclass('public.compliance_scenarios')
     ) THEN
    ALTER TABLE ONLY public.compliance_scenarios
        ADD CONSTRAINT compliance_scenarios_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: compliance_scenarios compliance_scenarios_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.compliance_scenarios') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_scenarios_tenant_id_fkey' AND conrelid = to_regclass('public.compliance_scenarios')
     ) THEN
    ALTER TABLE ONLY public.compliance_scenarios
        ADD CONSTRAINT compliance_scenarios_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: compliance_scenarios compliance_scenarios_updated_by_fkey
DO $$ BEGIN
  IF to_regclass('public.compliance_scenarios') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'compliance_scenarios_updated_by_fkey' AND conrelid = to_regclass('public.compliance_scenarios')
     ) THEN
    ALTER TABLE ONLY public.compliance_scenarios
        ADD CONSTRAINT compliance_scenarios_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES public.users(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: control_measurements control_measurements_measurement_type_id_fkey
DO $$ BEGIN
  IF to_regclass('public.control_measurements') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'control_measurements_measurement_type_id_fkey' AND conrelid = to_regclass('public.control_measurements')
     ) THEN
    ALTER TABLE ONLY public.control_measurements
        ADD CONSTRAINT control_measurements_measurement_type_id_fkey FOREIGN KEY (measurement_type_id) REFERENCES public.measurement_types(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: crypto_applications crypto_applications_algorithm_id_fkey
DO $$ BEGIN
  IF to_regclass('public.crypto_applications') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'crypto_applications_algorithm_id_fkey' AND conrelid = to_regclass('public.crypto_applications')
     ) THEN
    ALTER TABLE ONLY public.crypto_applications
        ADD CONSTRAINT crypto_applications_algorithm_id_fkey FOREIGN KEY (algorithm_id) REFERENCES public.algorithms(id);
  END IF;
END $$;


-- FK CONSTRAINT: crypto_applications crypto_applications_certificate_id_fkey
DO $$ BEGIN
  IF to_regclass('public.crypto_applications') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'crypto_applications_certificate_id_fkey' AND conrelid = to_regclass('public.crypto_applications')
     ) THEN
    ALTER TABLE ONLY public.crypto_applications
        ADD CONSTRAINT crypto_applications_certificate_id_fkey FOREIGN KEY (certificate_id) REFERENCES public.certificates(id);
  END IF;
END $$;


-- FK CONSTRAINT: crypto_applications crypto_applications_key_id_fkey
DO $$ BEGIN
  IF to_regclass('public.crypto_applications') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'crypto_applications_key_id_fkey' AND conrelid = to_regclass('public.crypto_applications')
     ) THEN
    ALTER TABLE ONLY public.crypto_applications
        ADD CONSTRAINT crypto_applications_key_id_fkey FOREIGN KEY (key_id) REFERENCES public.keys(id);
  END IF;
END $$;


-- FK CONSTRAINT: crypto_applications crypto_applications_library_id_fkey
DO $$ BEGIN
  IF to_regclass('public.crypto_applications') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'crypto_applications_library_id_fkey' AND conrelid = to_regclass('public.crypto_applications')
     ) THEN
    ALTER TABLE ONLY public.crypto_applications
        ADD CONSTRAINT crypto_applications_library_id_fkey FOREIGN KEY (library_id) REFERENCES public.crypto_libraries(id);
  END IF;
END $$;


-- FK CONSTRAINT: crypto_applications crypto_applications_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.crypto_applications') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'crypto_applications_tenant_id_fkey' AND conrelid = to_regclass('public.crypto_applications')
     ) THEN
    ALTER TABLE ONLY public.crypto_applications
        ADD CONSTRAINT crypto_applications_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;








-- FK CONSTRAINT: crypto_implementation_algorithms crypto_implementation_algorithms_algorithm_id_fkey
DO $$ BEGIN
  IF to_regclass('public.crypto_implementation_algorithms') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'crypto_implementation_algorithms_algorithm_id_fkey' AND conrelid = to_regclass('public.crypto_implementation_algorithms')
     ) THEN
    ALTER TABLE ONLY public.crypto_implementation_algorithms
        ADD CONSTRAINT crypto_implementation_algorithms_algorithm_id_fkey FOREIGN KEY (algorithm_id) REFERENCES public.algorithms(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: crypto_implementation_algorithms_crypto_implementation_id_fkey -- REMOVED.
-- Targeted crypto_implementations_legacy(id), an empty residual table, so it
-- could never be satisfied by live (partitioned) implementations. It is dropped
-- in POST-MIGRATIONS below; re-adding it here as well made the file NON-IDEMPOTENT
-- once the junction had rows: the ADD would fail against existing data and abort
-- the schema-migration Job under ON_ERROR_STOP=1, breaking helm upgrade.


-- FK CONSTRAINT: crypto_implementation_certificate_crypto_implementation_id_fkey -- REMOVED.
-- Targeted crypto_implementations_legacy(id), an empty residual table, so it
-- could never be satisfied by live (partitioned) implementations. It is dropped
-- in POST-MIGRATIONS below; re-adding it here as well made the file NON-IDEMPOTENT
-- once the junction had rows: the ADD would fail against existing data and abort
-- the schema-migration Job under ON_ERROR_STOP=1, breaking helm upgrade.


-- FK CONSTRAINT: crypto_implementation_certificates crypto_implementation_certificates_certificate_id_fkey
DO $$ BEGIN
  IF to_regclass('public.crypto_implementation_certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'crypto_implementation_certificates_certificate_id_fkey' AND conrelid = to_regclass('public.crypto_implementation_certificates')
     ) THEN
    ALTER TABLE ONLY public.crypto_implementation_certificates
        ADD CONSTRAINT crypto_implementation_certificates_certificate_id_fkey FOREIGN KEY (certificate_id) REFERENCES public.certificates(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: crypto_libraries crypto_libraries_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.crypto_libraries') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'crypto_libraries_tenant_id_fkey' AND conrelid = to_regclass('public.crypto_libraries')
     ) THEN
    ALTER TABLE ONLY public.crypto_libraries
        ADD CONSTRAINT crypto_libraries_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: database_encryption_states database_encryption_states_certificate_id_fkey
DO $$ BEGIN
  IF to_regclass('public.database_encryption_states') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'database_encryption_states_certificate_id_fkey' AND conrelid = to_regclass('public.database_encryption_states')
     ) THEN
    ALTER TABLE ONLY public.database_encryption_states
        ADD CONSTRAINT database_encryption_states_certificate_id_fkey FOREIGN KEY (certificate_id) REFERENCES public.certificates(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: database_encryption_states database_encryption_states_device_id_fkey
DO $$ BEGIN
  IF to_regclass('public.database_encryption_states') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'database_encryption_states_device_id_fkey' AND conrelid = to_regclass('public.database_encryption_states')
     ) THEN
    ALTER TABLE ONLY public.database_encryption_states
        ADD CONSTRAINT database_encryption_states_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: database_encryption_states database_encryption_states_encryption_algorithm_id_fkey
DO $$ BEGIN
  IF to_regclass('public.database_encryption_states') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'database_encryption_states_encryption_algorithm_id_fkey' AND conrelid = to_regclass('public.database_encryption_states')
     ) THEN
    ALTER TABLE ONLY public.database_encryption_states
        ADD CONSTRAINT database_encryption_states_encryption_algorithm_id_fkey FOREIGN KEY (encryption_algorithm_id) REFERENCES public.algorithms(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: database_encryption_states database_encryption_states_password_algorithm_id_fkey
DO $$ BEGIN
  IF to_regclass('public.database_encryption_states') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'database_encryption_states_password_algorithm_id_fkey' AND conrelid = to_regclass('public.database_encryption_states')
     ) THEN
    ALTER TABLE ONLY public.database_encryption_states
        ADD CONSTRAINT database_encryption_states_password_algorithm_id_fkey FOREIGN KEY (password_algorithm_id) REFERENCES public.algorithms(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: database_encryption_states database_encryption_states_ssl_algorithm_id_fkey
DO $$ BEGIN
  IF to_regclass('public.database_encryption_states') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'database_encryption_states_ssl_algorithm_id_fkey' AND conrelid = to_regclass('public.database_encryption_states')
     ) THEN
    ALTER TABLE ONLY public.database_encryption_states
        ADD CONSTRAINT database_encryption_states_ssl_algorithm_id_fkey FOREIGN KEY (ssl_algorithm_id) REFERENCES public.algorithms(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: database_encryption_states database_encryption_states_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.database_encryption_states') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'database_encryption_states_tenant_id_fkey' AND conrelid = to_regclass('public.database_encryption_states')
     ) THEN
    ALTER TABLE ONLY public.database_encryption_states
        ADD CONSTRAINT database_encryption_states_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: device_agents device_agents_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.device_agents') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'device_agents_tenant_id_fkey' AND conrelid = to_regclass('public.device_agents')
     ) THEN
    ALTER TABLE ONLY public.device_agents
        ADD CONSTRAINT device_agents_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: device_jobs device_jobs_agent_id_fkey
DO $$ BEGIN
  IF to_regclass('public.device_jobs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'device_jobs_agent_id_fkey' AND conrelid = to_regclass('public.device_jobs')
     ) THEN
    ALTER TABLE ONLY public.device_jobs
        ADD CONSTRAINT device_jobs_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.device_agents(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: device_jobs device_jobs_device_id_fkey
DO $$ BEGIN
  IF to_regclass('public.device_jobs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'device_jobs_device_id_fkey' AND conrelid = to_regclass('public.device_jobs')
     ) THEN
    ALTER TABLE ONLY public.device_jobs
        ADD CONSTRAINT device_jobs_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: device_jobs device_jobs_integration_id_fkey
DO $$ BEGIN
  IF to_regclass('public.device_jobs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'device_jobs_integration_id_fkey' AND conrelid = to_regclass('public.device_jobs')
     ) THEN
    ALTER TABLE ONLY public.device_jobs
        ADD CONSTRAINT device_jobs_integration_id_fkey FOREIGN KEY (integration_id) REFERENCES public.platform_integrations(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: device_jobs device_jobs_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.device_jobs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'device_jobs_tenant_id_fkey' AND conrelid = to_regclass('public.device_jobs')
     ) THEN
    ALTER TABLE ONLY public.device_jobs
        ADD CONSTRAINT device_jobs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: devices devices_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.devices') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'devices_tenant_id_fkey' AND conrelid = to_regclass('public.devices')
     ) THEN
    ALTER TABLE ONLY public.devices
        ADD CONSTRAINT devices_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: discovery_alert_configs discovery_alert_configs_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.discovery_alert_configs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_alert_configs_tenant_id_fkey' AND conrelid = to_regclass('public.discovery_alert_configs')
     ) THEN
    ALTER TABLE ONLY public.discovery_alert_configs
        ADD CONSTRAINT discovery_alert_configs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: discovery_alert_history discovery_alert_history_finding_id_fkey
DO $$ BEGIN
  IF to_regclass('public.discovery_alert_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_alert_history_finding_id_fkey' AND conrelid = to_regclass('public.discovery_alert_history')
     ) THEN
    ALTER TABLE ONLY public.discovery_alert_history
        ADD CONSTRAINT discovery_alert_history_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.discovery_findings(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: discovery_alert_history discovery_alert_history_job_id_fkey
DO $$ BEGIN
  IF to_regclass('public.discovery_alert_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_alert_history_job_id_fkey' AND conrelid = to_regclass('public.discovery_alert_history')
     ) THEN
    ALTER TABLE ONLY public.discovery_alert_history
        ADD CONSTRAINT discovery_alert_history_job_id_fkey FOREIGN KEY (job_id) REFERENCES public.discovery_jobs(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: discovery_alert_history discovery_alert_history_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.discovery_alert_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_alert_history_tenant_id_fkey' AND conrelid = to_regclass('public.discovery_alert_history')
     ) THEN
    ALTER TABLE ONLY public.discovery_alert_history
        ADD CONSTRAINT discovery_alert_history_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: discovery_approval_queue discovery_approval_queue_finding_id_fkey
DO $$ BEGIN
  IF to_regclass('public.discovery_approval_queue') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_approval_queue_finding_id_fkey' AND conrelid = to_regclass('public.discovery_approval_queue')
     ) THEN
    ALTER TABLE ONLY public.discovery_approval_queue
        ADD CONSTRAINT discovery_approval_queue_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.discovery_findings(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: discovery_approval_queue discovery_approval_queue_job_id_fkey
DO $$ BEGIN
  IF to_regclass('public.discovery_approval_queue') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_approval_queue_job_id_fkey' AND conrelid = to_regclass('public.discovery_approval_queue')
     ) THEN
    ALTER TABLE ONLY public.discovery_approval_queue
        ADD CONSTRAINT discovery_approval_queue_job_id_fkey FOREIGN KEY (job_id) REFERENCES public.discovery_jobs(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: discovery_approval_queue discovery_approval_queue_reviewed_by_fkey
DO $$ BEGIN
  IF to_regclass('public.discovery_approval_queue') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_approval_queue_reviewed_by_fkey' AND conrelid = to_regclass('public.discovery_approval_queue')
     ) THEN
    ALTER TABLE ONLY public.discovery_approval_queue
        ADD CONSTRAINT discovery_approval_queue_reviewed_by_fkey FOREIGN KEY (reviewed_by) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: discovery_approval_queue discovery_approval_queue_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.discovery_approval_queue') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_approval_queue_tenant_id_fkey' AND conrelid = to_regclass('public.discovery_approval_queue')
     ) THEN
    ALTER TABLE ONLY public.discovery_approval_queue
        ADD CONSTRAINT discovery_approval_queue_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: discovery_auto_approval_rules discovery_auto_approval_rules_created_by_fkey
DO $$ BEGIN
  IF to_regclass('public.discovery_auto_approval_rules') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_auto_approval_rules_created_by_fkey' AND conrelid = to_regclass('public.discovery_auto_approval_rules')
     ) THEN
    ALTER TABLE ONLY public.discovery_auto_approval_rules
        ADD CONSTRAINT discovery_auto_approval_rules_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: discovery_auto_approval_rules discovery_auto_approval_rules_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.discovery_auto_approval_rules') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_auto_approval_rules_tenant_id_fkey' AND conrelid = to_regclass('public.discovery_auto_approval_rules')
     ) THEN
    ALTER TABLE ONLY public.discovery_auto_approval_rules
        ADD CONSTRAINT discovery_auto_approval_rules_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: discovery_findings discovery_findings_job_id_fkey
DO $$ BEGIN
  IF to_regclass('public.discovery_findings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_findings_job_id_fkey' AND conrelid = to_regclass('public.discovery_findings')
     ) THEN
    ALTER TABLE ONLY public.discovery_findings
        ADD CONSTRAINT discovery_findings_job_id_fkey FOREIGN KEY (job_id) REFERENCES public.discovery_jobs(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: discovery_findings discovery_findings_target_id_fkey
DO $$ BEGIN
  IF to_regclass('public.discovery_findings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_findings_target_id_fkey' AND conrelid = to_regclass('public.discovery_findings')
     ) THEN
    ALTER TABLE ONLY public.discovery_findings
        ADD CONSTRAINT discovery_findings_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.discovery_targets(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: discovery_findings discovery_findings_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.discovery_findings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_findings_tenant_id_fkey' AND conrelid = to_regclass('public.discovery_findings')
     ) THEN
    ALTER TABLE ONLY public.discovery_findings
        ADD CONSTRAINT discovery_findings_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: discovery_jobs discovery_jobs_created_by_fkey
DO $$ BEGIN
  IF to_regclass('public.discovery_jobs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_jobs_created_by_fkey' AND conrelid = to_regclass('public.discovery_jobs')
     ) THEN
    ALTER TABLE ONLY public.discovery_jobs
        ADD CONSTRAINT discovery_jobs_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: discovery_jobs discovery_jobs_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.discovery_jobs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_jobs_tenant_id_fkey' AND conrelid = to_regclass('public.discovery_jobs')
     ) THEN
    ALTER TABLE ONLY public.discovery_jobs
        ADD CONSTRAINT discovery_jobs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: discovery_rate_limits discovery_rate_limits_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.discovery_rate_limits') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_rate_limits_tenant_id_fkey' AND conrelid = to_regclass('public.discovery_rate_limits')
     ) THEN
    ALTER TABLE ONLY public.discovery_rate_limits
        ADD CONSTRAINT discovery_rate_limits_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: discovery_targets discovery_targets_job_id_fkey
DO $$ BEGIN
  IF to_regclass('public.discovery_targets') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_targets_job_id_fkey' AND conrelid = to_regclass('public.discovery_targets')
     ) THEN
    ALTER TABLE ONLY public.discovery_targets
        ADD CONSTRAINT discovery_targets_job_id_fkey FOREIGN KEY (job_id) REFERENCES public.discovery_jobs(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: discovery_targets discovery_targets_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.discovery_targets') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'discovery_targets_tenant_id_fkey' AND conrelid = to_regclass('public.discovery_targets')
     ) THEN
    ALTER TABLE ONLY public.discovery_targets
        ADD CONSTRAINT discovery_targets_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: external_asset_mappings external_asset_mappings_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.external_asset_mappings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'external_asset_mappings_tenant_id_fkey' AND conrelid = to_regclass('public.external_asset_mappings')
     ) THEN
    ALTER TABLE ONLY public.external_asset_mappings
        ADD CONSTRAINT external_asset_mappings_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: external_connection_history external_connection_history_external_connection_id_fkey
DO $$ BEGIN
  IF to_regclass('public.external_connection_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'external_connection_history_external_connection_id_fkey' AND conrelid = to_regclass('public.external_connection_history')
     ) THEN
    ALTER TABLE ONLY public.external_connection_history
        ADD CONSTRAINT external_connection_history_external_connection_id_fkey FOREIGN KEY (external_connection_id) REFERENCES public.external_connections(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: external_connection_history external_connection_history_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.external_connection_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'external_connection_history_tenant_id_fkey' AND conrelid = to_regclass('public.external_connection_history')
     ) THEN
    ALTER TABLE ONLY public.external_connection_history
        ADD CONSTRAINT external_connection_history_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: external_connections external_connections_sensor_id_fkey
DO $$ BEGIN
  IF to_regclass('public.external_connections') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'external_connections_sensor_id_fkey' AND conrelid = to_regclass('public.external_connections')
     ) THEN
    ALTER TABLE ONLY public.external_connections
        ADD CONSTRAINT external_connections_sensor_id_fkey FOREIGN KEY (sensor_id) REFERENCES public.sensors(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: external_connections external_connections_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.external_connections') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'external_connections_tenant_id_fkey' AND conrelid = to_regclass('public.external_connections')
     ) THEN
    ALTER TABLE ONLY public.external_connections
        ADD CONSTRAINT external_connections_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: feature_usage_events feature_usage_events_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.feature_usage_events') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'feature_usage_events_tenant_id_fkey' AND conrelid = to_regclass('public.feature_usage_events')
     ) THEN
    ALTER TABLE ONLY public.feature_usage_events
        ADD CONSTRAINT feature_usage_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: feature_usage_events feature_usage_events_user_id_fkey
DO $$ BEGIN
  IF to_regclass('public.feature_usage_events') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'feature_usage_events_user_id_fkey' AND conrelid = to_regclass('public.feature_usage_events')
     ) THEN
    ALTER TABLE ONLY public.feature_usage_events
        ADD CONSTRAINT feature_usage_events_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: identity_link_requests identity_link_requests_auth_method_id_fkey
DO $$ BEGIN
  IF to_regclass('public.identity_link_requests') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'identity_link_requests_auth_method_id_fkey' AND conrelid = to_regclass('public.identity_link_requests')
     ) THEN
    ALTER TABLE ONLY public.identity_link_requests
        ADD CONSTRAINT identity_link_requests_auth_method_id_fkey FOREIGN KEY (auth_method_id) REFERENCES public.user_auth_methods(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: identity_link_requests identity_link_requests_primary_user_id_fkey
DO $$ BEGIN
  IF to_regclass('public.identity_link_requests') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'identity_link_requests_primary_user_id_fkey' AND conrelid = to_regclass('public.identity_link_requests')
     ) THEN
    ALTER TABLE ONLY public.identity_link_requests
        ADD CONSTRAINT identity_link_requests_primary_user_id_fkey FOREIGN KEY (primary_user_id) REFERENCES public.users(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: identity_link_requests identity_link_requests_requested_by_user_id_fkey
DO $$ BEGIN
  IF to_regclass('public.identity_link_requests') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'identity_link_requests_requested_by_user_id_fkey' AND conrelid = to_regclass('public.identity_link_requests')
     ) THEN
    ALTER TABLE ONLY public.identity_link_requests
        ADD CONSTRAINT identity_link_requests_requested_by_user_id_fkey FOREIGN KEY (requested_by_user_id) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: identity_link_requests identity_link_requests_resolved_by_user_id_fkey
DO $$ BEGIN
  IF to_regclass('public.identity_link_requests') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'identity_link_requests_resolved_by_user_id_fkey' AND conrelid = to_regclass('public.identity_link_requests')
     ) THEN
    ALTER TABLE ONLY public.identity_link_requests
        ADD CONSTRAINT identity_link_requests_resolved_by_user_id_fkey FOREIGN KEY (resolved_by_user_id) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: identity_link_requests identity_link_requests_secondary_user_id_fkey
DO $$ BEGIN
  IF to_regclass('public.identity_link_requests') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'identity_link_requests_secondary_user_id_fkey' AND conrelid = to_regclass('public.identity_link_requests')
     ) THEN
    ALTER TABLE ONLY public.identity_link_requests
        ADD CONSTRAINT identity_link_requests_secondary_user_id_fkey FOREIGN KEY (secondary_user_id) REFERENCES public.users(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: implementation_keys_implementation_id_fkey -- REMOVED.
-- Targeted crypto_implementations_legacy(id), an empty residual table, so it
-- could never be satisfied by live (partitioned) implementations. It is dropped
-- in POST-MIGRATIONS below; re-adding it here as well made the file NON-IDEMPOTENT
-- once the junction had rows: the ADD would fail against existing data and abort
-- the schema-migration Job under ON_ERROR_STOP=1, breaking helm upgrade.


-- FK CONSTRAINT: implementation_keys implementation_keys_key_id_fkey
DO $$ BEGIN
  IF to_regclass('public.implementation_keys') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'implementation_keys_key_id_fkey' AND conrelid = to_regclass('public.implementation_keys')
     ) THEN
    ALTER TABLE ONLY public.implementation_keys
        ADD CONSTRAINT implementation_keys_key_id_fkey FOREIGN KEY (key_id) REFERENCES public.keys(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: implementation_libraries_implementation_id_fkey -- REMOVED.
-- Targeted crypto_implementations_legacy(id), an empty residual table, so it
-- could never be satisfied by live (partitioned) implementations. It is dropped
-- in POST-MIGRATIONS below; re-adding it here as well made the file NON-IDEMPOTENT
-- once the junction had rows: the ADD would fail against existing data and abort
-- the schema-migration Job under ON_ERROR_STOP=1, breaking helm upgrade.


-- FK CONSTRAINT: implementation_libraries implementation_libraries_library_id_fkey
DO $$ BEGIN
  IF to_regclass('public.implementation_libraries') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'implementation_libraries_library_id_fkey' AND conrelid = to_regclass('public.implementation_libraries')
     ) THEN
    ALTER TABLE ONLY public.implementation_libraries
        ADD CONSTRAINT implementation_libraries_library_id_fkey FOREIGN KEY (library_id) REFERENCES public.crypto_libraries(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: in_app_notifications in_app_notifications_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.in_app_notifications') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'in_app_notifications_tenant_id_fkey' AND conrelid = to_regclass('public.in_app_notifications')
     ) THEN
    ALTER TABLE ONLY public.in_app_notifications
        ADD CONSTRAINT in_app_notifications_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: integrations integrations_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.integrations') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'integrations_tenant_id_fkey' AND conrelid = to_regclass('public.integrations')
     ) THEN
    ALTER TABLE ONLY public.integrations
        ADD CONSTRAINT integrations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: interrogation_schedules interrogation_schedules_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.interrogation_schedules') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'interrogation_schedules_tenant_id_fkey' AND conrelid = to_regclass('public.interrogation_schedules')
     ) THEN
    ALTER TABLE ONLY public.interrogation_schedules
        ADD CONSTRAINT interrogation_schedules_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: keys keys_algorithm_id_fkey
DO $$ BEGIN
  IF to_regclass('public.keys') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'keys_algorithm_id_fkey' AND conrelid = to_regclass('public.keys')
     ) THEN
    ALTER TABLE ONLY public.keys
        ADD CONSTRAINT keys_algorithm_id_fkey FOREIGN KEY (algorithm_id) REFERENCES public.algorithms(id);
  END IF;
END $$;


-- FK CONSTRAINT: keys keys_secured_by_algorithm_id_fkey
DO $$ BEGIN
  IF to_regclass('public.keys') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'keys_secured_by_algorithm_id_fkey' AND conrelid = to_regclass('public.keys')
     ) THEN
    ALTER TABLE ONLY public.keys
        ADD CONSTRAINT keys_secured_by_algorithm_id_fkey FOREIGN KEY (secured_by_algorithm_id) REFERENCES public.algorithms(id);
  END IF;
END $$;


-- FK CONSTRAINT: keys keys_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.keys') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'keys_tenant_id_fkey' AND conrelid = to_regclass('public.keys')
     ) THEN
    ALTER TABLE ONLY public.keys
        ADD CONSTRAINT keys_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: kms_keys kms_keys_algorithm_id_fkey
DO $$ BEGIN
  IF to_regclass('public.kms_keys') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'kms_keys_algorithm_id_fkey' AND conrelid = to_regclass('public.kms_keys')
     ) THEN
    ALTER TABLE ONLY public.kms_keys
        ADD CONSTRAINT kms_keys_algorithm_id_fkey FOREIGN KEY (algorithm_id) REFERENCES public.algorithms(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: kms_keys kms_keys_integration_id_fkey
DO $$ BEGIN
  IF to_regclass('public.kms_keys') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'kms_keys_integration_id_fkey' AND conrelid = to_regclass('public.kms_keys')
     ) THEN
    ALTER TABLE ONLY public.kms_keys
        ADD CONSTRAINT kms_keys_integration_id_fkey FOREIGN KEY (integration_id) REFERENCES public.platform_integrations(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: kms_keys kms_keys_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.kms_keys') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'kms_keys_tenant_id_fkey' AND conrelid = to_regclass('public.kms_keys')
     ) THEN
    ALTER TABLE ONLY public.kms_keys
        ADD CONSTRAINT kms_keys_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: library_provided_algorithms library_provided_algorithms_algorithm_id_fkey
DO $$ BEGIN
  IF to_regclass('public.library_provided_algorithms') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'library_provided_algorithms_algorithm_id_fkey' AND conrelid = to_regclass('public.library_provided_algorithms')
     ) THEN
    ALTER TABLE ONLY public.library_provided_algorithms
        ADD CONSTRAINT library_provided_algorithms_algorithm_id_fkey FOREIGN KEY (algorithm_id) REFERENCES public.algorithms(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: library_provided_algorithms library_provided_algorithms_library_id_fkey
DO $$ BEGIN
  IF to_regclass('public.library_provided_algorithms') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'library_provided_algorithms_library_id_fkey' AND conrelid = to_regclass('public.library_provided_algorithms')
     ) THEN
    ALTER TABLE ONLY public.library_provided_algorithms
        ADD CONSTRAINT library_provided_algorithms_library_id_fkey FOREIGN KEY (library_id) REFERENCES public.crypto_libraries(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: locations locations_parent_id_fkey
DO $$ BEGIN
  IF to_regclass('public.locations') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'locations_parent_id_fkey' AND conrelid = to_regclass('public.locations')
     ) THEN
    ALTER TABLE ONLY public.locations
        ADD CONSTRAINT locations_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.locations(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: locations locations_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.locations') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'locations_tenant_id_fkey' AND conrelid = to_regclass('public.locations')
     ) THEN
    ALTER TABLE ONLY public.locations
        ADD CONSTRAINT locations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: measurement_templates measurement_templates_created_by_fkey
DO $$ BEGIN
  IF to_regclass('public.measurement_templates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'measurement_templates_created_by_fkey' AND conrelid = to_regclass('public.measurement_templates')
     ) THEN
    ALTER TABLE ONLY public.measurement_templates
        ADD CONSTRAINT measurement_templates_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: measurement_templates measurement_templates_measurement_type_id_fkey
DO $$ BEGIN
  IF to_regclass('public.measurement_templates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'measurement_templates_measurement_type_id_fkey' AND conrelid = to_regclass('public.measurement_templates')
     ) THEN
    ALTER TABLE ONLY public.measurement_templates
        ADD CONSTRAINT measurement_templates_measurement_type_id_fkey FOREIGN KEY (measurement_type_id) REFERENCES public.measurement_types(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: monitoring_alert_history monitoring_alert_history_threshold_id_fkey
DO $$ BEGIN
  IF to_regclass('public.monitoring_alert_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'monitoring_alert_history_threshold_id_fkey' AND conrelid = to_regclass('public.monitoring_alert_history')
     ) THEN
    ALTER TABLE ONLY public.monitoring_alert_history
        ADD CONSTRAINT monitoring_alert_history_threshold_id_fkey FOREIGN KEY (threshold_id) REFERENCES public.monitoring_alert_thresholds(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: network_segments network_segments_location_id_fkey
DO $$ BEGIN
  IF to_regclass('public.network_segments') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'network_segments_location_id_fkey' AND conrelid = to_regclass('public.network_segments')
     ) THEN
    ALTER TABLE ONLY public.network_segments
        ADD CONSTRAINT network_segments_location_id_fkey FOREIGN KEY (location_id) REFERENCES public.locations(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: network_segments network_segments_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.network_segments') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'network_segments_tenant_id_fkey' AND conrelid = to_regclass('public.network_segments')
     ) THEN
    ALTER TABLE ONLY public.network_segments
        ADD CONSTRAINT network_segments_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: notification_delivery_queue notification_delivery_queue_notification_id_fkey
DO $$ BEGIN
  IF to_regclass('public.notification_delivery_queue') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'notification_delivery_queue_notification_id_fkey' AND conrelid = to_regclass('public.notification_delivery_queue')
     ) THEN
    ALTER TABLE ONLY public.notification_delivery_queue
        ADD CONSTRAINT notification_delivery_queue_notification_id_fkey FOREIGN KEY (notification_id) REFERENCES public.notification_history(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: notification_delivery_queue notification_delivery_queue_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.notification_delivery_queue') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'notification_delivery_queue_tenant_id_fkey' AND conrelid = to_regclass('public.notification_delivery_queue')
     ) THEN
    ALTER TABLE ONLY public.notification_delivery_queue
        ADD CONSTRAINT notification_delivery_queue_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: notification_history notification_history_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.notification_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'notification_history_tenant_id_fkey' AND conrelid = to_regclass('public.notification_history')
     ) THEN
    ALTER TABLE ONLY public.notification_history
        ADD CONSTRAINT notification_history_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: pcap_upload_jobs pcap_upload_jobs_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.pcap_upload_jobs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'pcap_upload_jobs_tenant_id_fkey' AND conrelid = to_regclass('public.pcap_upload_jobs')
     ) THEN
    ALTER TABLE ONLY public.pcap_upload_jobs
        ADD CONSTRAINT pcap_upload_jobs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: pending_sensor_registrations pending_sensor_registrations_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.pending_sensor_registrations') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'pending_sensor_registrations_tenant_id_fkey' AND conrelid = to_regclass('public.pending_sensor_registrations')
     ) THEN
    ALTER TABLE ONLY public.pending_sensor_registrations
        ADD CONSTRAINT pending_sensor_registrations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: pending_sensors pending_sensors_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.pending_sensors') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'pending_sensors_tenant_id_fkey' AND conrelid = to_regclass('public.pending_sensors')
     ) THEN
    ALTER TABLE ONLY public.pending_sensors
        ADD CONSTRAINT pending_sensors_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: permission_audit_logs permission_audit_logs_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.permission_audit_logs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'permission_audit_logs_tenant_id_fkey' AND conrelid = to_regclass('public.permission_audit_logs')
     ) THEN
    ALTER TABLE ONLY public.permission_audit_logs
        ADD CONSTRAINT permission_audit_logs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: permission_audit_logs permission_audit_logs_user_id_fkey
DO $$ BEGIN
  IF to_regclass('public.permission_audit_logs') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'permission_audit_logs_user_id_fkey' AND conrelid = to_regclass('public.permission_audit_logs')
     ) THEN
    ALTER TABLE ONLY public.permission_audit_logs
        ADD CONSTRAINT permission_audit_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: platform_framework_controls platform_framework_controls_framework_id_fkey
DO $$ BEGIN
  IF to_regclass('public.platform_framework_controls') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_framework_controls_framework_id_fkey' AND conrelid = to_regclass('public.platform_framework_controls')
     ) THEN
    ALTER TABLE ONLY public.platform_framework_controls
        ADD CONSTRAINT platform_framework_controls_framework_id_fkey FOREIGN KEY (framework_id) REFERENCES public.platform_frameworks(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: platform_framework_versions platform_framework_versions_changed_by_fkey
DO $$ BEGIN
  IF to_regclass('public.platform_framework_versions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_framework_versions_changed_by_fkey' AND conrelid = to_regclass('public.platform_framework_versions')
     ) THEN
    ALTER TABLE ONLY public.platform_framework_versions
        ADD CONSTRAINT platform_framework_versions_changed_by_fkey FOREIGN KEY (changed_by) REFERENCES public.platform_users(id);
  END IF;
END $$;


-- FK CONSTRAINT: platform_framework_versions platform_framework_versions_framework_id_fkey
DO $$ BEGIN
  IF to_regclass('public.platform_framework_versions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_framework_versions_framework_id_fkey' AND conrelid = to_regclass('public.platform_framework_versions')
     ) THEN
    ALTER TABLE ONLY public.platform_framework_versions
        ADD CONSTRAINT platform_framework_versions_framework_id_fkey FOREIGN KEY (framework_id) REFERENCES public.platform_frameworks(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: platform_frameworks platform_frameworks_created_by_fkey
DO $$ BEGIN
  IF to_regclass('public.platform_frameworks') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_frameworks_created_by_fkey' AND conrelid = to_regclass('public.platform_frameworks')
     ) THEN
    ALTER TABLE ONLY public.platform_frameworks
        ADD CONSTRAINT platform_frameworks_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.platform_users(id);
  END IF;
END $$;


-- FK CONSTRAINT: platform_frameworks platform_frameworks_published_by_fkey
DO $$ BEGIN
  IF to_regclass('public.platform_frameworks') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_frameworks_published_by_fkey' AND conrelid = to_regclass('public.platform_frameworks')
     ) THEN
    ALTER TABLE ONLY public.platform_frameworks
        ADD CONSTRAINT platform_frameworks_published_by_fkey FOREIGN KEY (published_by) REFERENCES public.platform_users(id);
  END IF;
END $$;


-- FK CONSTRAINT: platform_integration_audit_log platform_integration_audit_log_integration_id_fkey
DO $$ BEGIN
  IF to_regclass('public.platform_integration_audit_log') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_integration_audit_log_integration_id_fkey' AND conrelid = to_regclass('public.platform_integration_audit_log')
     ) THEN
    ALTER TABLE ONLY public.platform_integration_audit_log
        ADD CONSTRAINT platform_integration_audit_log_integration_id_fkey FOREIGN KEY (integration_id) REFERENCES public.platform_integrations(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: platform_integration_audit_log platform_integration_audit_log_performed_by_fkey
DO $$ BEGIN
  IF to_regclass('public.platform_integration_audit_log') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_integration_audit_log_performed_by_fkey' AND conrelid = to_regclass('public.platform_integration_audit_log')
     ) THEN
    ALTER TABLE ONLY public.platform_integration_audit_log
        ADD CONSTRAINT platform_integration_audit_log_performed_by_fkey FOREIGN KEY (performed_by) REFERENCES public.platform_users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: platform_integration_secrets platform_integration_secrets_integration_id_fkey
DO $$ BEGIN
  IF to_regclass('public.platform_integration_secrets') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_integration_secrets_integration_id_fkey' AND conrelid = to_regclass('public.platform_integration_secrets')
     ) THEN
    ALTER TABLE ONLY public.platform_integration_secrets
        ADD CONSTRAINT platform_integration_secrets_integration_id_fkey FOREIGN KEY (integration_id) REFERENCES public.platform_integrations(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: platform_integrations platform_integrations_created_by_fkey
DO $$ BEGIN
  IF to_regclass('public.platform_integrations') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_integrations_created_by_fkey' AND conrelid = to_regclass('public.platform_integrations')
     ) THEN
    ALTER TABLE ONLY public.platform_integrations
        ADD CONSTRAINT platform_integrations_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.platform_users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: platform_integrations platform_integrations_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.platform_integrations') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_integrations_tenant_id_fkey' AND conrelid = to_regclass('public.platform_integrations')
     ) THEN
    ALTER TABLE ONLY public.platform_integrations
        ADD CONSTRAINT platform_integrations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: platform_integrations platform_integrations_updated_by_fkey
DO $$ BEGIN
  IF to_regclass('public.platform_integrations') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_integrations_updated_by_fkey' AND conrelid = to_regclass('public.platform_integrations')
     ) THEN
    ALTER TABLE ONLY public.platform_integrations
        ADD CONSTRAINT platform_integrations_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES public.platform_users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: platform_log_access_audit platform_log_access_audit_log_id_fkey
DO $$ BEGIN
  IF to_regclass('public.platform_log_access_audit') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_log_access_audit_log_id_fkey' AND conrelid = to_regclass('public.platform_log_access_audit')
     ) THEN
    ALTER TABLE ONLY public.platform_log_access_audit
        ADD CONSTRAINT platform_log_access_audit_log_id_fkey FOREIGN KEY (log_id) REFERENCES public.platform_log_metadata(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: platform_log_metadata platform_log_metadata_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.platform_log_metadata') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_log_metadata_tenant_id_fkey' AND conrelid = to_regclass('public.platform_log_metadata')
     ) THEN
    ALTER TABLE ONLY public.platform_log_metadata
        ADD CONSTRAINT platform_log_metadata_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: platform_notification_channels platform_notification_channels_created_by_fkey
DO $$ BEGIN
  IF to_regclass('public.platform_notification_channels') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_notification_channels_created_by_fkey' AND conrelid = to_regclass('public.platform_notification_channels')
     ) THEN
    ALTER TABLE ONLY public.platform_notification_channels
        ADD CONSTRAINT platform_notification_channels_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.platform_users(id);
  END IF;
END $$;


-- FK CONSTRAINT: platform_notification_channels platform_notification_channels_updated_by_fkey
DO $$ BEGIN
  IF to_regclass('public.platform_notification_channels') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_notification_channels_updated_by_fkey' AND conrelid = to_regclass('public.platform_notification_channels')
     ) THEN
    ALTER TABLE ONLY public.platform_notification_channels
        ADD CONSTRAINT platform_notification_channels_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES public.platform_users(id);
  END IF;
END $$;


-- FK CONSTRAINT: platform_refresh_tokens platform_refresh_tokens_platform_user_id_fkey
DO $$ BEGIN
  IF to_regclass('public.platform_refresh_tokens') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_refresh_tokens_platform_user_id_fkey' AND conrelid = to_regclass('public.platform_refresh_tokens')
     ) THEN
    ALTER TABLE ONLY public.platform_refresh_tokens
        ADD CONSTRAINT platform_refresh_tokens_platform_user_id_fkey FOREIGN KEY (platform_user_id) REFERENCES public.platform_users(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: platform_role_permissions platform_role_permissions_permission_id_fkey
DO $$ BEGIN
  IF to_regclass('public.platform_role_permissions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_role_permissions_permission_id_fkey' AND conrelid = to_regclass('public.platform_role_permissions')
     ) THEN
    ALTER TABLE ONLY public.platform_role_permissions
        ADD CONSTRAINT platform_role_permissions_permission_id_fkey FOREIGN KEY (permission_id) REFERENCES public.platform_permissions(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: platform_role_permissions platform_role_permissions_role_id_fkey
DO $$ BEGIN
  IF to_regclass('public.platform_role_permissions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_role_permissions_role_id_fkey' AND conrelid = to_regclass('public.platform_role_permissions')
     ) THEN
    ALTER TABLE ONLY public.platform_role_permissions
        ADD CONSTRAINT platform_role_permissions_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.platform_roles(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: platform_settings platform_settings_updated_by_fkey
DO $$ BEGIN
  IF to_regclass('public.platform_settings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_settings_updated_by_fkey' AND conrelid = to_regclass('public.platform_settings')
     ) THEN
    ALTER TABLE ONLY public.platform_settings
        ADD CONSTRAINT platform_settings_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES public.platform_users(id);
  END IF;
END $$;


-- FK CONSTRAINT: platform_users platform_users_invited_by_fkey
DO $$ BEGIN
  IF to_regclass('public.platform_users') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_users_invited_by_fkey' AND conrelid = to_regclass('public.platform_users')
     ) THEN
    ALTER TABLE ONLY public.platform_users
        ADD CONSTRAINT platform_users_invited_by_fkey FOREIGN KEY (invited_by) REFERENCES public.platform_users(id);
  END IF;
END $$;


-- FK CONSTRAINT: platform_users platform_users_role_id_fkey
DO $$ BEGIN
  IF to_regclass('public.platform_users') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'platform_users_role_id_fkey' AND conrelid = to_regclass('public.platform_users')
     ) THEN
    ALTER TABLE ONLY public.platform_users
        ADD CONSTRAINT platform_users_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.platform_roles(id);
  END IF;
END $$;


-- FK CONSTRAINT: refresh_tokens refresh_tokens_user_id_fkey
DO $$ BEGIN
  IF to_regclass('public.refresh_tokens') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'refresh_tokens_user_id_fkey' AND conrelid = to_regclass('public.refresh_tokens')
     ) THEN
    ALTER TABLE ONLY public.refresh_tokens
        ADD CONSTRAINT refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: remediation_plan_items remediation_plan_items_added_by_fkey
DO $$ BEGIN
  IF to_regclass('public.remediation_plan_items') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'remediation_plan_items_added_by_fkey' AND conrelid = to_regclass('public.remediation_plan_items')
     ) THEN
    ALTER TABLE ONLY public.remediation_plan_items
        ADD CONSTRAINT remediation_plan_items_added_by_fkey FOREIGN KEY (added_by) REFERENCES public.users(id);
  END IF;
END $$;


-- FK CONSTRAINT: remediation_plan_items remediation_plan_items_finding_id_fkey
DO $$ BEGIN
  IF to_regclass('public.remediation_plan_items') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'remediation_plan_items_finding_id_fkey' AND conrelid = to_regclass('public.remediation_plan_items')
     ) THEN
    ALTER TABLE ONLY public.remediation_plan_items
        ADD CONSTRAINT remediation_plan_items_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.compliance_findings(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: remediation_plan_items remediation_plan_items_plan_id_fkey
DO $$ BEGIN
  IF to_regclass('public.remediation_plan_items') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'remediation_plan_items_plan_id_fkey' AND conrelid = to_regclass('public.remediation_plan_items')
     ) THEN
    ALTER TABLE ONLY public.remediation_plan_items
        ADD CONSTRAINT remediation_plan_items_plan_id_fkey FOREIGN KEY (plan_id) REFERENCES public.remediation_plans(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: remediation_plan_items remediation_plan_items_ticket_id_fkey
DO $$ BEGIN
  IF to_regclass('public.remediation_plan_items') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'remediation_plan_items_ticket_id_fkey' AND conrelid = to_regclass('public.remediation_plan_items')
     ) THEN
    ALTER TABLE ONLY public.remediation_plan_items
        ADD CONSTRAINT remediation_plan_items_ticket_id_fkey FOREIGN KEY (ticket_id) REFERENCES public.tickets(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: remediation_plans remediation_plans_created_by_fkey
DO $$ BEGIN
  IF to_regclass('public.remediation_plans') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'remediation_plans_created_by_fkey' AND conrelid = to_regclass('public.remediation_plans')
     ) THEN
    ALTER TABLE ONLY public.remediation_plans
        ADD CONSTRAINT remediation_plans_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);
  END IF;
END $$;


-- FK CONSTRAINT: remediation_plans remediation_plans_owner_id_fkey
DO $$ BEGIN
  IF to_regclass('public.remediation_plans') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'remediation_plans_owner_id_fkey' AND conrelid = to_regclass('public.remediation_plans')
     ) THEN
    ALTER TABLE ONLY public.remediation_plans
        ADD CONSTRAINT remediation_plans_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: remediation_plans remediation_plans_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.remediation_plans') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'remediation_plans_tenant_id_fkey' AND conrelid = to_regclass('public.remediation_plans')
     ) THEN
    ALTER TABLE ONLY public.remediation_plans
        ADD CONSTRAINT remediation_plans_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: resource_alerts resource_alerts_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.resource_alerts') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'resource_alerts_tenant_id_fkey' AND conrelid = to_regclass('public.resource_alerts')
     ) THEN
    ALTER TABLE ONLY public.resource_alerts
        ADD CONSTRAINT resource_alerts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: resource_permissions resource_permissions_owner_id_fkey
DO $$ BEGIN
  IF to_regclass('public.resource_permissions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'resource_permissions_owner_id_fkey' AND conrelid = to_regclass('public.resource_permissions')
     ) THEN
    ALTER TABLE ONLY public.resource_permissions
        ADD CONSTRAINT resource_permissions_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES public.users(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: resource_permissions resource_permissions_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.resource_permissions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'resource_permissions_tenant_id_fkey' AND conrelid = to_regclass('public.resource_permissions')
     ) THEN
    ALTER TABLE ONLY public.resource_permissions
        ADD CONSTRAINT resource_permissions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: rule_vulnerability_mappings rule_vulnerability_mappings_rule_id_fkey
DO $$ BEGIN
  IF to_regclass('public.rule_vulnerability_mappings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'rule_vulnerability_mappings_rule_id_fkey' AND conrelid = to_regclass('public.rule_vulnerability_mappings')
     ) THEN
    ALTER TABLE ONLY public.rule_vulnerability_mappings
        ADD CONSTRAINT rule_vulnerability_mappings_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES public.compliance_rules(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: schedule_history schedule_history_schedule_id_fkey
DO $$ BEGIN
  IF to_regclass('public.schedule_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'schedule_history_schedule_id_fkey' AND conrelid = to_regclass('public.schedule_history')
     ) THEN
    ALTER TABLE ONLY public.schedule_history
        ADD CONSTRAINT schedule_history_schedule_id_fkey FOREIGN KEY (schedule_id) REFERENCES public.interrogation_schedules(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: security_events security_events_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.security_events') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'security_events_tenant_id_fkey' AND conrelid = to_regclass('public.security_events')
     ) THEN
    ALTER TABLE ONLY public.security_events
        ADD CONSTRAINT security_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: security_incident_webhook_deliveries security_incident_webhook_deliveries_incident_id_fkey
DO $$ BEGIN
  IF to_regclass('public.security_incident_webhook_deliveries') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'security_incident_webhook_deliveries_incident_id_fkey' AND conrelid = to_regclass('public.security_incident_webhook_deliveries')
     ) THEN
    ALTER TABLE ONLY public.security_incident_webhook_deliveries
        ADD CONSTRAINT security_incident_webhook_deliveries_incident_id_fkey FOREIGN KEY (incident_id) REFERENCES public.security_incidents(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: security_incident_webhook_deliveries security_incident_webhook_deliveries_webhook_id_fkey
DO $$ BEGIN
  IF to_regclass('public.security_incident_webhook_deliveries') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'security_incident_webhook_deliveries_webhook_id_fkey' AND conrelid = to_regclass('public.security_incident_webhook_deliveries')
     ) THEN
    ALTER TABLE ONLY public.security_incident_webhook_deliveries
        ADD CONSTRAINT security_incident_webhook_deliveries_webhook_id_fkey FOREIGN KEY (webhook_id) REFERENCES public.security_incident_webhooks(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: sensor_ca_certificates sensor_ca_certificates_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.sensor_ca_certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'sensor_ca_certificates_tenant_id_fkey' AND conrelid = to_regclass('public.sensor_ca_certificates')
     ) THEN
    ALTER TABLE ONLY public.sensor_ca_certificates
        ADD CONSTRAINT sensor_ca_certificates_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: sensor_certificates sensor_certificates_sensor_id_fkey
DO $$ BEGIN
  IF to_regclass('public.sensor_certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'sensor_certificates_sensor_id_fkey' AND conrelid = to_regclass('public.sensor_certificates')
     ) THEN
    ALTER TABLE ONLY public.sensor_certificates
        ADD CONSTRAINT sensor_certificates_sensor_id_fkey FOREIGN KEY (sensor_id) REFERENCES public.sensors(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: sensor_certificates sensor_certificates_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.sensor_certificates') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'sensor_certificates_tenant_id_fkey' AND conrelid = to_regclass('public.sensor_certificates')
     ) THEN
    ALTER TABLE ONLY public.sensor_certificates
        ADD CONSTRAINT sensor_certificates_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: sensor_commands sensor_commands_sensor_id_fkey
DO $$ BEGIN
  IF to_regclass('public.sensor_commands') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'sensor_commands_sensor_id_fkey' AND conrelid = to_regclass('public.sensor_commands')
     ) THEN
    ALTER TABLE ONLY public.sensor_commands
        ADD CONSTRAINT sensor_commands_sensor_id_fkey FOREIGN KEY (sensor_id) REFERENCES public.sensors(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: sensor_health_metrics sensor_health_metrics_sensor_id_fkey
DO $$ BEGIN
  IF to_regclass('public.sensor_health_metrics') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'sensor_health_metrics_sensor_id_fkey' AND conrelid = to_regclass('public.sensor_health_metrics')
     ) THEN
    ALTER TABLE ONLY public.sensor_health_metrics
        ADD CONSTRAINT sensor_health_metrics_sensor_id_fkey FOREIGN KEY (sensor_id) REFERENCES public.sensors(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: sensors sensors_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.sensors') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'sensors_tenant_id_fkey' AND conrelid = to_regclass('public.sensors')
     ) THEN
    ALTER TABLE ONLY public.sensors
        ADD CONSTRAINT sensors_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: service_identification_rules service_identification_rules_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.service_identification_rules') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'service_identification_rules_tenant_id_fkey' AND conrelid = to_regclass('public.service_identification_rules')
     ) THEN
    ALTER TABLE ONLY public.service_identification_rules
        ADD CONSTRAINT service_identification_rules_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: ssh_keys ssh_keys_algorithm_id_fkey
DO $$ BEGIN
  IF to_regclass('public.ssh_keys') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'ssh_keys_algorithm_id_fkey' AND conrelid = to_regclass('public.ssh_keys')
     ) THEN
    ALTER TABLE ONLY public.ssh_keys
        ADD CONSTRAINT ssh_keys_algorithm_id_fkey FOREIGN KEY (algorithm_id) REFERENCES public.algorithms(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: ssh_keys ssh_keys_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.ssh_keys') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'ssh_keys_tenant_id_fkey' AND conrelid = to_regclass('public.ssh_keys')
     ) THEN
    ALTER TABLE ONLY public.ssh_keys
        ADD CONSTRAINT ssh_keys_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: sso_group_role_mappings sso_group_role_mappings_role_id_fkey
DO $$ BEGIN
  IF to_regclass('public.sso_group_role_mappings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'sso_group_role_mappings_role_id_fkey' AND conrelid = to_regclass('public.sso_group_role_mappings')
     ) THEN
    ALTER TABLE ONLY public.sso_group_role_mappings
        ADD CONSTRAINT sso_group_role_mappings_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.tenant_roles(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: sso_group_role_mappings sso_group_role_mappings_sso_provider_id_fkey
DO $$ BEGIN
  IF to_regclass('public.sso_group_role_mappings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'sso_group_role_mappings_sso_provider_id_fkey' AND conrelid = to_regclass('public.sso_group_role_mappings')
     ) THEN
    ALTER TABLE ONLY public.sso_group_role_mappings
        ADD CONSTRAINT sso_group_role_mappings_sso_provider_id_fkey FOREIGN KEY (sso_provider_id) REFERENCES public.sso_providers(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: sso_group_role_mappings sso_group_role_mappings_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.sso_group_role_mappings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'sso_group_role_mappings_tenant_id_fkey' AND conrelid = to_regclass('public.sso_group_role_mappings')
     ) THEN
    ALTER TABLE ONLY public.sso_group_role_mappings
        ADD CONSTRAINT sso_group_role_mappings_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: sso_providers sso_providers_default_role_id_fkey
DO $$ BEGIN
  IF to_regclass('public.sso_providers') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'sso_providers_default_role_id_fkey' AND conrelid = to_regclass('public.sso_providers')
     ) THEN
    ALTER TABLE ONLY public.sso_providers
        ADD CONSTRAINT sso_providers_default_role_id_fkey FOREIGN KEY (default_role_id) REFERENCES public.tenant_roles(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: sso_providers sso_providers_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.sso_providers') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'sso_providers_tenant_id_fkey' AND conrelid = to_regclass('public.sso_providers')
     ) THEN
    ALTER TABLE ONLY public.sso_providers
        ADD CONSTRAINT sso_providers_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: subscription_tier_history subscription_tier_history_changed_by_fkey
DO $$ BEGIN
  IF to_regclass('public.subscription_tier_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'subscription_tier_history_changed_by_fkey' AND conrelid = to_regclass('public.subscription_tier_history')
     ) THEN
    ALTER TABLE ONLY public.subscription_tier_history
        ADD CONSTRAINT subscription_tier_history_changed_by_fkey FOREIGN KEY (changed_by) REFERENCES public.platform_users(id);
  END IF;
END $$;


-- FK CONSTRAINT: subscription_tier_history subscription_tier_history_tier_id_fkey
DO $$ BEGIN
  IF to_regclass('public.subscription_tier_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'subscription_tier_history_tier_id_fkey' AND conrelid = to_regclass('public.subscription_tier_history')
     ) THEN
    ALTER TABLE ONLY public.subscription_tier_history
        ADD CONSTRAINT subscription_tier_history_tier_id_fkey FOREIGN KEY (tier_id) REFERENCES public.subscription_tiers(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: support_ticket_messages support_ticket_messages_ticket_id_fkey
DO $$ BEGIN
  IF to_regclass('public.support_ticket_messages') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'support_ticket_messages_ticket_id_fkey' AND conrelid = to_regclass('public.support_ticket_messages')
     ) THEN
    ALTER TABLE ONLY public.support_ticket_messages
        ADD CONSTRAINT support_ticket_messages_ticket_id_fkey FOREIGN KEY (ticket_id) REFERENCES public.support_tickets(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: support_tickets support_tickets_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.support_tickets') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'support_tickets_tenant_id_fkey' AND conrelid = to_regclass('public.support_tickets')
     ) THEN
    ALTER TABLE ONLY public.support_tickets
        ADD CONSTRAINT support_tickets_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: sync_outbox sync_outbox_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.sync_outbox') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'sync_outbox_tenant_id_fkey' AND conrelid = to_regclass('public.sync_outbox')
     ) THEN
    ALTER TABLE ONLY public.sync_outbox
        ADD CONSTRAINT sync_outbox_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_admin_settings_audit tenant_admin_settings_audit_changed_by_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_admin_settings_audit') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_admin_settings_audit_changed_by_fkey' AND conrelid = to_regclass('public.tenant_admin_settings_audit')
     ) THEN
    ALTER TABLE ONLY public.tenant_admin_settings_audit
        ADD CONSTRAINT tenant_admin_settings_audit_changed_by_fkey FOREIGN KEY (changed_by) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_admin_settings_audit tenant_admin_settings_audit_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_admin_settings_audit') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_admin_settings_audit_tenant_id_fkey' AND conrelid = to_regclass('public.tenant_admin_settings_audit')
     ) THEN
    ALTER TABLE ONLY public.tenant_admin_settings_audit
        ADD CONSTRAINT tenant_admin_settings_audit_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_admin_settings tenant_admin_settings_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_admin_settings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_admin_settings_tenant_id_fkey' AND conrelid = to_regclass('public.tenant_admin_settings')
     ) THEN
    ALTER TABLE ONLY public.tenant_admin_settings
        ADD CONSTRAINT tenant_admin_settings_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_admin_settings tenant_admin_settings_updated_by_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_admin_settings') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_admin_settings_updated_by_fkey' AND conrelid = to_regclass('public.tenant_admin_settings')
     ) THEN
    ALTER TABLE ONLY public.tenant_admin_settings
        ADD CONSTRAINT tenant_admin_settings_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_cost_analysis tenant_cost_analysis_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_cost_analysis') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_cost_analysis_tenant_id_fkey' AND conrelid = to_regclass('public.tenant_cost_analysis')
     ) THEN
    ALTER TABLE ONLY public.tenant_cost_analysis
        ADD CONSTRAINT tenant_cost_analysis_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_framework_controls tenant_framework_controls_framework_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_framework_controls') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_framework_controls_framework_id_fkey' AND conrelid = to_regclass('public.tenant_framework_controls')
     ) THEN
    ALTER TABLE ONLY public.tenant_framework_controls
        ADD CONSTRAINT tenant_framework_controls_framework_id_fkey FOREIGN KEY (framework_id) REFERENCES public.tenant_frameworks(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_framework_licenses tenant_framework_licenses_locked_by_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_framework_licenses') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_framework_licenses_locked_by_fkey' AND conrelid = to_regclass('public.tenant_framework_licenses')
     ) THEN
    ALTER TABLE ONLY public.tenant_framework_licenses
        ADD CONSTRAINT tenant_framework_licenses_locked_by_fkey FOREIGN KEY (locked_by) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_framework_licenses tenant_framework_licenses_platform_framework_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_framework_licenses') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_framework_licenses_platform_framework_id_fkey' AND conrelid = to_regclass('public.tenant_framework_licenses')
     ) THEN
    ALTER TABLE ONLY public.tenant_framework_licenses
        ADD CONSTRAINT tenant_framework_licenses_platform_framework_id_fkey FOREIGN KEY (platform_framework_id) REFERENCES public.platform_frameworks(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_framework_licenses tenant_framework_licenses_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_framework_licenses') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_framework_licenses_tenant_id_fkey' AND conrelid = to_regclass('public.tenant_framework_licenses')
     ) THEN
    ALTER TABLE ONLY public.tenant_framework_licenses
        ADD CONSTRAINT tenant_framework_licenses_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_frameworks tenant_frameworks_created_by_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_frameworks') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_frameworks_created_by_fkey' AND conrelid = to_regclass('public.tenant_frameworks')
     ) THEN
    ALTER TABLE ONLY public.tenant_frameworks
        ADD CONSTRAINT tenant_frameworks_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_frameworks tenant_frameworks_source_framework_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_frameworks') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_frameworks_source_framework_id_fkey' AND conrelid = to_regclass('public.tenant_frameworks')
     ) THEN
    ALTER TABLE ONLY public.tenant_frameworks
        ADD CONSTRAINT tenant_frameworks_source_framework_id_fkey FOREIGN KEY (source_framework_id) REFERENCES public.platform_frameworks(id);
  END IF;
END $$;


-- FK CONSTRAINT: tenant_frameworks tenant_frameworks_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_frameworks') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_frameworks_tenant_id_fkey' AND conrelid = to_regclass('public.tenant_frameworks')
     ) THEN
    ALTER TABLE ONLY public.tenant_frameworks
        ADD CONSTRAINT tenant_frameworks_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_measurement_overrides tenant_measurement_overrides_control_measurement_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_measurement_overrides') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_measurement_overrides_control_measurement_id_fkey' AND conrelid = to_regclass('public.tenant_measurement_overrides')
     ) THEN
    ALTER TABLE ONLY public.tenant_measurement_overrides
        ADD CONSTRAINT tenant_measurement_overrides_control_measurement_id_fkey FOREIGN KEY (control_measurement_id) REFERENCES public.control_measurements(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_measurement_overrides tenant_measurement_overrides_created_by_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_measurement_overrides') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_measurement_overrides_created_by_fkey' AND conrelid = to_regclass('public.tenant_measurement_overrides')
     ) THEN
    ALTER TABLE ONLY public.tenant_measurement_overrides
        ADD CONSTRAINT tenant_measurement_overrides_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);
  END IF;
END $$;


-- FK CONSTRAINT: tenant_measurement_overrides tenant_measurement_overrides_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_measurement_overrides') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_measurement_overrides_tenant_id_fkey' AND conrelid = to_regclass('public.tenant_measurement_overrides')
     ) THEN
    ALTER TABLE ONLY public.tenant_measurement_overrides
        ADD CONSTRAINT tenant_measurement_overrides_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_notes tenant_notes_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_notes') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_notes_tenant_id_fkey' AND conrelid = to_regclass('public.tenant_notes')
     ) THEN
    ALTER TABLE ONLY public.tenant_notes
        ADD CONSTRAINT tenant_notes_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_notification_channels tenant_notification_channels_created_by_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_notification_channels') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_notification_channels_created_by_fkey' AND conrelid = to_regclass('public.tenant_notification_channels')
     ) THEN
    ALTER TABLE ONLY public.tenant_notification_channels
        ADD CONSTRAINT tenant_notification_channels_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_notification_channels tenant_notification_channels_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_notification_channels') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_notification_channels_tenant_id_fkey' AND conrelid = to_regclass('public.tenant_notification_channels')
     ) THEN
    ALTER TABLE ONLY public.tenant_notification_channels
        ADD CONSTRAINT tenant_notification_channels_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_notification_rules tenant_notification_rules_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_notification_rules') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_notification_rules_tenant_id_fkey' AND conrelid = to_regclass('public.tenant_notification_rules')
     ) THEN
    ALTER TABLE ONLY public.tenant_notification_rules
        ADD CONSTRAINT tenant_notification_rules_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_resource_usage tenant_resource_usage_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_resource_usage') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_resource_usage_tenant_id_fkey' AND conrelid = to_regclass('public.tenant_resource_usage')
     ) THEN
    ALTER TABLE ONLY public.tenant_resource_usage
        ADD CONSTRAINT tenant_resource_usage_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_role_permissions tenant_role_permissions_permission_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_role_permissions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_role_permissions_permission_id_fkey' AND conrelid = to_regclass('public.tenant_role_permissions')
     ) THEN
    ALTER TABLE ONLY public.tenant_role_permissions
        ADD CONSTRAINT tenant_role_permissions_permission_id_fkey FOREIGN KEY (permission_id) REFERENCES public.tenant_permissions(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_role_permissions tenant_role_permissions_role_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_role_permissions') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_role_permissions_role_id_fkey' AND conrelid = to_regclass('public.tenant_role_permissions')
     ) THEN
    ALTER TABLE ONLY public.tenant_role_permissions
        ADD CONSTRAINT tenant_role_permissions_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.tenant_roles(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_roles tenant_roles_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_roles') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_roles_tenant_id_fkey' AND conrelid = to_regclass('public.tenant_roles')
     ) THEN
    ALTER TABLE ONLY public.tenant_roles
        ADD CONSTRAINT tenant_roles_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_usage tenant_usage_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_usage') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_usage_tenant_id_fkey' AND conrelid = to_regclass('public.tenant_usage')
     ) THEN
    ALTER TABLE ONLY public.tenant_usage
        ADD CONSTRAINT tenant_usage_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: tenant_usage_tracking tenant_usage_tracking_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tenant_usage_tracking') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_usage_tracking_tenant_id_fkey' AND conrelid = to_regclass('public.tenant_usage_tracking')
     ) THEN
    ALTER TABLE ONLY public.tenant_usage_tracking
        ADD CONSTRAINT tenant_usage_tracking_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: subscription_tiers subscription_tiers_owner_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.subscription_tiers') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'subscription_tiers_owner_tenant_id_fkey' AND conrelid = to_regclass('public.subscription_tiers')
     ) THEN
    ALTER TABLE ONLY public.subscription_tiers
        ADD CONSTRAINT subscription_tiers_owner_tenant_id_fkey FOREIGN KEY (owner_tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: tenants tenants_subscription_tier_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tenants') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenants_subscription_tier_id_fkey' AND conrelid = to_regclass('public.tenants')
     ) THEN
    ALTER TABLE ONLY public.tenants
        ADD CONSTRAINT tenants_subscription_tier_id_fkey FOREIGN KEY (subscription_tier_id) REFERENCES public.subscription_tiers(id);
  END IF;
END $$;


-- FK CONSTRAINT: ticket_comments ticket_comments_author_id_fkey
DO $$ BEGIN
  IF to_regclass('public.ticket_comments') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'ticket_comments_author_id_fkey' AND conrelid = to_regclass('public.ticket_comments')
     ) THEN
    ALTER TABLE ONLY public.ticket_comments
        ADD CONSTRAINT ticket_comments_author_id_fkey FOREIGN KEY (author_id) REFERENCES public.users(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: ticket_comments ticket_comments_ticket_id_fkey
DO $$ BEGIN
  IF to_regclass('public.ticket_comments') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'ticket_comments_ticket_id_fkey' AND conrelid = to_regclass('public.ticket_comments')
     ) THEN
    ALTER TABLE ONLY public.ticket_comments
        ADD CONSTRAINT ticket_comments_ticket_id_fkey FOREIGN KEY (ticket_id) REFERENCES public.tickets(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: tickets tickets_asset_id_fkey — INTENTIONALLY OMITTED
-- The original constraint referenced network_assets_legacy(id), which is
-- now an empty residual table. Live asset data lives in
-- network_assets_partitioned (exposed via the network_assets view), but
-- that table has no PK/UNIQUE on id alone — PG won't allow a FK to
-- reference it. The application validates asset_id via uuid.Parse and
-- joins by id at read time, so DB-level FK enforcement is skipped here
-- until the legacy/partitioned migration is finished. Same situation for
-- tickets_crypto_implementation_id_fkey below.


-- FK CONSTRAINT: tickets tickets_assigned_to_fkey
DO $$ BEGIN
  IF to_regclass('public.tickets') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tickets_assigned_to_fkey' AND conrelid = to_regclass('public.tickets')
     ) THEN
    ALTER TABLE ONLY public.tickets
        ADD CONSTRAINT tickets_assigned_to_fkey FOREIGN KEY (assigned_to) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: tickets tickets_certificate_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tickets') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tickets_certificate_id_fkey' AND conrelid = to_regclass('public.tickets')
     ) THEN
    ALTER TABLE ONLY public.tickets
        ADD CONSTRAINT tickets_certificate_id_fkey FOREIGN KEY (certificate_id) REFERENCES public.certificates(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: tickets tickets_created_by_fkey
DO $$ BEGIN
  IF to_regclass('public.tickets') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tickets_created_by_fkey' AND conrelid = to_regclass('public.tickets')
     ) THEN
    ALTER TABLE ONLY public.tickets
        ADD CONSTRAINT tickets_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: tickets tickets_crypto_implementation_id_fkey — INTENTIONALLY OMITTED
-- See note on tickets_asset_id_fkey above. crypto_implementations_legacy
-- is empty; live data lives in crypto_implementations_partitioned, which
-- has no PK on id alone, so no FK can target it.


-- FK CONSTRAINT: tickets tickets_finding_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tickets') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tickets_finding_id_fkey' AND conrelid = to_regclass('public.tickets')
     ) THEN
    ALTER TABLE ONLY public.tickets
        ADD CONSTRAINT tickets_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.compliance_findings(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: tickets tickets_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.tickets') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tickets_tenant_id_fkey' AND conrelid = to_regclass('public.tickets')
     ) THEN
    ALTER TABLE ONLY public.tickets
        ADD CONSTRAINT tickets_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: user_auth_methods user_auth_methods_sso_provider_id_fkey
DO $$ BEGIN
  IF to_regclass('public.user_auth_methods') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'user_auth_methods_sso_provider_id_fkey' AND conrelid = to_regclass('public.user_auth_methods')
     ) THEN
    ALTER TABLE ONLY public.user_auth_methods
        ADD CONSTRAINT user_auth_methods_sso_provider_id_fkey FOREIGN KEY (sso_provider_id) REFERENCES public.sso_providers(id);
  END IF;
END $$;


-- FK CONSTRAINT: user_auth_methods user_auth_methods_user_id_fkey
DO $$ BEGIN
  IF to_regclass('public.user_auth_methods') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'user_auth_methods_user_id_fkey' AND conrelid = to_regclass('public.user_auth_methods')
     ) THEN
    ALTER TABLE ONLY public.user_auth_methods
        ADD CONSTRAINT user_auth_methods_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: user_framework_preferences user_framework_preferences_framework_id_fkey
DO $$ BEGIN
  IF to_regclass('public.user_framework_preferences') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'user_framework_preferences_framework_id_fkey' AND conrelid = to_regclass('public.user_framework_preferences')
     ) THEN
    ALTER TABLE ONLY public.user_framework_preferences
        ADD CONSTRAINT user_framework_preferences_framework_id_fkey FOREIGN KEY (framework_id) REFERENCES public.platform_frameworks(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: user_framework_preferences user_framework_preferences_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.user_framework_preferences') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'user_framework_preferences_tenant_id_fkey' AND conrelid = to_regclass('public.user_framework_preferences')
     ) THEN
    ALTER TABLE ONLY public.user_framework_preferences
        ADD CONSTRAINT user_framework_preferences_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: user_framework_preferences user_framework_preferences_user_id_fkey
DO $$ BEGIN
  IF to_regclass('public.user_framework_preferences') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'user_framework_preferences_user_id_fkey' AND conrelid = to_regclass('public.user_framework_preferences')
     ) THEN
    ALTER TABLE ONLY public.user_framework_preferences
        ADD CONSTRAINT user_framework_preferences_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: user_tenant_roles user_tenant_roles_assigned_by_fkey
DO $$ BEGIN
  IF to_regclass('public.user_tenant_roles') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'user_tenant_roles_assigned_by_fkey' AND conrelid = to_regclass('public.user_tenant_roles')
     ) THEN
    ALTER TABLE ONLY public.user_tenant_roles
        ADD CONSTRAINT user_tenant_roles_assigned_by_fkey FOREIGN KEY (assigned_by) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;


-- FK CONSTRAINT: user_tenant_roles user_tenant_roles_role_id_fkey
DO $$ BEGIN
  IF to_regclass('public.user_tenant_roles') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'user_tenant_roles_role_id_fkey' AND conrelid = to_regclass('public.user_tenant_roles')
     ) THEN
    ALTER TABLE ONLY public.user_tenant_roles
        ADD CONSTRAINT user_tenant_roles_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.tenant_roles(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: user_tenant_roles user_tenant_roles_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.user_tenant_roles') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'user_tenant_roles_tenant_id_fkey' AND conrelid = to_regclass('public.user_tenant_roles')
     ) THEN
    ALTER TABLE ONLY public.user_tenant_roles
        ADD CONSTRAINT user_tenant_roles_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: user_tenant_roles user_tenant_roles_user_id_fkey
DO $$ BEGIN
  IF to_regclass('public.user_tenant_roles') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'user_tenant_roles_user_id_fkey' AND conrelid = to_regclass('public.user_tenant_roles')
     ) THEN
    ALTER TABLE ONLY public.user_tenant_roles
        ADD CONSTRAINT user_tenant_roles_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: user_workflow_progress user_workflow_progress_user_id_fkey
DO $$ BEGIN
  IF to_regclass('public.user_workflow_progress') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'user_workflow_progress_user_id_fkey' AND conrelid = to_regclass('public.user_workflow_progress')
     ) THEN
    ALTER TABLE ONLY public.user_workflow_progress
        ADD CONSTRAINT user_workflow_progress_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: user_workflow_progress user_workflow_progress_workflow_configuration_id_fkey
DO $$ BEGIN
  IF to_regclass('public.user_workflow_progress') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'user_workflow_progress_workflow_configuration_id_fkey' AND conrelid = to_regclass('public.user_workflow_progress')
     ) THEN
    ALTER TABLE ONLY public.user_workflow_progress
        ADD CONSTRAINT user_workflow_progress_workflow_configuration_id_fkey FOREIGN KEY (workflow_configuration_id) REFERENCES public.workflow_configurations(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: users users_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.users') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'users_tenant_id_fkey' AND conrelid = to_regclass('public.users')
     ) THEN
    ALTER TABLE ONLY public.users
        ADD CONSTRAINT users_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: workflow_configurations workflow_configurations_tenant_id_fkey
DO $$ BEGIN
  IF to_regclass('public.workflow_configurations') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'workflow_configurations_tenant_id_fkey' AND conrelid = to_regclass('public.workflow_configurations')
     ) THEN
    ALTER TABLE ONLY public.workflow_configurations
        ADD CONSTRAINT workflow_configurations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- tenant_id FKs for the partitioned parents and the health tables.
-- These were skipped when partitioning was introduced, which left orphaned rows
-- behind PurgeTenant (which relies solely on ON DELETE CASCADE).


DO $$ BEGIN
  IF to_regclass('public.network_assets_partitioned') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'network_assets_partitioned_tenant_id_fkey'
         AND conrelid = to_regclass('public.network_assets_partitioned')
     ) THEN
    ALTER TABLE public.network_assets_partitioned
      ADD CONSTRAINT network_assets_partitioned_tenant_id_fkey
      FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


DO $$ BEGIN
  IF to_regclass('public.crypto_implementations_partitioned') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'crypto_implementations_partitioned_tenant_id_fkey'
         AND conrelid = to_regclass('public.crypto_implementations_partitioned')
     ) THEN
    ALTER TABLE public.crypto_implementations_partitioned
      ADD CONSTRAINT crypto_implementations_partitioned_tenant_id_fkey
      FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


DO $$ BEGIN
  IF to_regclass('public.sensor_discoveries_partitioned') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'sensor_discoveries_partitioned_tenant_id_fkey'
         AND conrelid = to_regclass('public.sensor_discoveries_partitioned')
     ) THEN
    ALTER TABLE public.sensor_discoveries_partitioned
      ADD CONSTRAINT sensor_discoveries_partitioned_tenant_id_fkey
      FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


DO $$ BEGIN
  IF to_regclass('public.health_alerts') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'health_alerts_tenant_id_fkey'
         AND conrelid = to_regclass('public.health_alerts')
     ) THEN
    ALTER TABLE public.health_alerts
      ADD CONSTRAINT health_alerts_tenant_id_fkey
      FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


DO $$ BEGIN
  IF to_regclass('public.health_metrics') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'health_metrics_tenant_id_fkey'
         AND conrelid = to_regclass('public.health_metrics')
     ) THEN
    ALTER TABLE public.health_metrics
      ADD CONSTRAINT health_metrics_tenant_id_fkey
      FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


DO $$ BEGIN
  IF to_regclass('public.tenant_health') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'tenant_health_tenant_id_fkey'
         AND conrelid = to_regclass('public.tenant_health')
     ) THEN
    ALTER TABLE public.tenant_health
      ADD CONSTRAINT tenant_health_tenant_id_fkey
      FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


-- Asset references into the hash-partitioned network_assets_partitioned.
-- Composite (tenant_id, asset_id) rather than a single column because the
-- partitioned table's only unique key is (tenant_id, id) — with the welcome
-- side effect that a cross-tenant asset reference is unrepresentable at the
-- database level.
-- FK CONSTRAINT: asset_history asset_history_tenant_asset_fkey
DO $$ BEGIN
  IF to_regclass('public.asset_history') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'asset_history_tenant_asset_fkey' AND conrelid = to_regclass('public.asset_history')
     ) THEN
    ALTER TABLE ONLY public.asset_history
        ADD CONSTRAINT asset_history_tenant_asset_fkey FOREIGN KEY (tenant_id, asset_id) REFERENCES public.network_assets_partitioned(tenant_id, id) ON DELETE CASCADE;
  END IF;
END $$;


-- FK CONSTRAINT: crypto_applications crypto_applications_tenant_asset_fkey
DO $$ BEGIN
  IF to_regclass('public.crypto_applications') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'crypto_applications_tenant_asset_fkey' AND conrelid = to_regclass('public.crypto_applications')
     ) THEN
    ALTER TABLE ONLY public.crypto_applications
        ADD CONSTRAINT crypto_applications_tenant_asset_fkey FOREIGN KEY (tenant_id, asset_id) REFERENCES public.network_assets_partitioned(tenant_id, id) ON DELETE SET NULL (asset_id);
  END IF;
END $$;


-- FK CONSTRAINT: database_encryption_states database_encryption_states_tenant_asset_fkey
DO $$ BEGIN
  IF to_regclass('public.database_encryption_states') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'database_encryption_states_tenant_asset_fkey' AND conrelid = to_regclass('public.database_encryption_states')
     ) THEN
    ALTER TABLE ONLY public.database_encryption_states
        ADD CONSTRAINT database_encryption_states_tenant_asset_fkey FOREIGN KEY (tenant_id, asset_id) REFERENCES public.network_assets_partitioned(tenant_id, id) ON DELETE SET NULL (asset_id);
  END IF;
END $$;


-- FK CONSTRAINT: external_connections external_connections_tenant_source_asset_fkey
DO $$ BEGIN
  IF to_regclass('public.external_connections') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'external_connections_tenant_source_asset_fkey' AND conrelid = to_regclass('public.external_connections')
     ) THEN
    ALTER TABLE ONLY public.external_connections
        ADD CONSTRAINT external_connections_tenant_source_asset_fkey FOREIGN KEY (tenant_id, source_asset_id) REFERENCES public.network_assets_partitioned(tenant_id, id) ON DELETE SET NULL (source_asset_id);
  END IF;
END $$;


-- FK CONSTRAINT: ssh_keys ssh_keys_tenant_asset_fkey
DO $$ BEGIN
  IF to_regclass('public.ssh_keys') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'ssh_keys_tenant_asset_fkey' AND conrelid = to_regclass('public.ssh_keys')
     ) THEN
    ALTER TABLE ONLY public.ssh_keys
        ADD CONSTRAINT ssh_keys_tenant_asset_fkey FOREIGN KEY (tenant_id, asset_id) REFERENCES public.network_assets_partitioned(tenant_id, id) ON DELETE SET NULL (asset_id);
  END IF;
END $$;


-- =================================================================
-- ROW SECURITY: ticket_comments (tenant scope inherited via tickets.tenant_id;
-- ticket_comments has no tenant_id column of its own — see H1)
ALTER TABLE public.ticket_comments ENABLE ROW LEVEL SECURITY;


--
-- PostgreSQL database dump complete
--


-- =================================================================
-- POST-MIGRATIONS (idempotent, run after the pg_dump body above)
-- =================================================================
-- These statements live outside the pg_dump-style schema body so they
-- survive future schema regenerations. The chart's `schema-migration`
-- Job applies this whole file via `psql -v ON_ERROR_STOP=1`, so every
-- statement here must be safely idempotent against any prior schema
-- version.
--
-- =========================================================================
-- CBOM-CENTRIC REPORTING REDESIGN — Phase 1
-- Scopes: tenant-owned, named, versioned predicate definitions that define
-- "what's in a CBOM." A Scope is the boundary an auditor or compliance team
-- attests to. Default scopes (All, Production, Non-Dev/Test) are seeded
-- lazily on first cbom-service contact for a tenant.
-- =========================================================================


-- TABLE: scopes
CREATE TABLE IF NOT EXISTS public.scopes (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    predicate jsonb DEFAULT '{}'::jsonb NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    is_system boolean DEFAULT false NOT NULL,
    deleted_at timestamp with time zone,
    created_by uuid NOT NULL,
    updated_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT scopes_pkey PRIMARY KEY (id),
    CONSTRAINT scopes_unique_name_per_tenant UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS idx_scopes_tenant_id ON public.scopes USING btree (tenant_id);
CREATE INDEX IF NOT EXISTS idx_scopes_tenant_default ON public.scopes USING btree (tenant_id, is_default) WHERE (is_default = true);
-- TABLE: scopes_audit
-- Mirrors the tenant_admin_settings_audit pattern: every UPDATE writes a row
-- recording the prior state. The current scope row holds the latest version;
-- prior versions live in scopes_audit, keyed by (scope_id, version).
CREATE TABLE IF NOT EXISTS public.scopes_audit (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    name_before character varying(255) NOT NULL,
    name_after character varying(255) NOT NULL,
    predicate_before jsonb NOT NULL,
    predicate_after jsonb NOT NULL,
    version_before integer NOT NULL,
    version_after integer NOT NULL,
    changed_by uuid,
    change_reason text,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT scopes_audit_pkey PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS idx_scopes_audit_scope_time ON public.scopes_audit USING btree (scope_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scopes_audit_tenant_time ON public.scopes_audit USING btree (tenant_id, created_at DESC);
-- FUNCTION: log_scope_change()
-- Mirrors log_tenant_admin_settings_change(): inserts a scopes_audit row
-- whenever a scope's name, predicate, or version changes. Triggered AFTER UPDATE.
CREATE OR REPLACE FUNCTION public.log_scope_change() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO scopes_audit (
        scope_id,
        tenant_id,
        name_before,
        name_after,
        predicate_before,
        predicate_after,
        version_before,
        version_after,
        changed_by,
        change_reason,
        created_at
    )
    VALUES (
        NEW.id,
        NEW.tenant_id,
        OLD.name,
        NEW.name,
        OLD.predicate,
        NEW.predicate,
        OLD.version,
        NEW.version,
        NEW.updated_by,
        NULL,
        NOW()
    );
    RETURN NEW;
END;
$$;


DROP TRIGGER IF EXISTS scopes_audit_trigger ON public.scopes;
CREATE OR REPLACE TRIGGER scopes_audit_trigger
    AFTER UPDATE ON public.scopes
    FOR EACH ROW
    WHEN (((OLD.name IS DISTINCT FROM NEW.name)
        OR (OLD.predicate IS DISTINCT FROM NEW.predicate)
        OR (OLD.version IS DISTINCT FROM NEW.version)))
    EXECUTE FUNCTION public.log_scope_change();


DROP TRIGGER IF EXISTS update_scopes_updated_at ON public.scopes;
CREATE OR REPLACE TRIGGER update_scopes_updated_at
    BEFORE UPDATE ON public.scopes
    FOR EACH ROW
    EXECUTE FUNCTION public.update_updated_at_column();


-- =========================================================================
-- CBOM ARTIFACTS — Phase 2 of the CBOM-centric reporting redesign
--
-- A `cbom_artifacts` row is an immutable, dated, hashed snapshot of every
-- crypto-relevant asset matching a Scope at the moment of generation. It is
-- the deliverable a tenant attaches to an audit submission, a customer
-- compliance package, or an internal posture review.
--
-- Storage strategy (dual-path):
--   • If shared/storage is configured for ArtifactTypeCBOM, the canonical
--     CycloneDX 1.6 JSON lives in S3 and `storage_key` points to it.
--   • If storage is not configured (typical dev / brand-new install), the
--     JSON lives inline in `inline_content` so the feature still works.
--   • Exactly one of storage_key / inline_content is populated. We never
--     store both — that would create a drift risk against `content_hash`.
--
-- Provenance fields (scope_version, content_hash, generated_at,
-- generated_by, input_data_freshness_at) capture enough to reproduce the
-- artifact deterministically against the inventory state at generation
-- time, and to prove tamper-evidence later (Phase 4 HMAC signing reuses
-- the same content_hash).
-- =========================================================================


CREATE TABLE IF NOT EXISTS public.cbom_artifacts (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    -- Snapshotted at generation time so the artifact is reproducible against
    -- the exact scope definition that was in force, even if the scope is
    -- later edited. (Scope edits bump scope.version and write a scopes_audit row.)
    scope_version integer NOT NULL,
    scope_name_snapshot character varying(255) NOT NULL,


    -- Optional human-meaningful name (e.g. "Q2 2026 PCI Submission").
    -- Falls back to scope_name_snapshot + generated_at when not set.
    name character varying(255),


    -- Storage location. Exactly one of these is populated.
    storage_key text,
    inline_content text,


    -- The private, non-published view of the snapshot. inline_content holds the
    -- CANONICAL bytes (CycloneDX), which is what we hash, sign and serve; but
    -- CycloneDX is a publishing format and has no home for the deprecation
    -- status, known-vulnerability counts and PQC flags the Enterprise diff
    -- categorises on. This column is never served to a client and never enters
    -- the content hash — it exists so a later comparison can read the same
    -- snapshot the generator saw.
    internal_content text,


    content_hash character varying(64) NOT NULL,
    size_bytes bigint NOT NULL,
    component_count integer NOT NULL,


    -- CycloneDX spec version we emitted (currently 1.6).
    cyclonedx_spec_version character varying(10) DEFAULT '1.6' NOT NULL,


    -- When was the inventory data last refreshed (e.g. by the most-recent
    -- sensor sweep) at the moment of generation? Helps the customer judge
    -- "is this snapshot fresh enough for my audit?"
    input_data_freshness_at timestamp with time zone NOT NULL,


    generated_at timestamp with time zone DEFAULT now() NOT NULL,
    generated_by uuid NOT NULL,


    -- Phase 4 signing — populated when the tenant enables signing. Recompute
    -- HMAC-SHA256(content_hash || tenant_id || scope_id) over the secret
    -- with kid=signature_kid, compare against signature_hmac on verify.
    signature_hmac character varying(128),
    signature_kid character varying(64),


    -- Provenance: who/what/when context that doesn't fit columns.
    -- e.g. { "generator_version": "2.2.0", "request_id": "...", "ip": "..." }
    provenance jsonb DEFAULT '{}'::jsonb NOT NULL,


    -- Phase 4 optional layers attached to the artifact, e.g. a
    -- compliance_attestation layer carrying the framework evaluation snapshot.
    -- Each layer is { "type": "...", "version": "...", "data": {...} }.
    layers jsonb DEFAULT '[]'::jsonb NOT NULL,


    -- Soft-delete preserves the row (so dangling references from comparison
    -- runs surface as "deleted by tenant X on …" rather than 404).
    deleted_at timestamp with time zone,


    created_at timestamp with time zone DEFAULT now(),


    CONSTRAINT cbom_artifacts_pkey PRIMARY KEY (id),
    CONSTRAINT cbom_artifacts_storage_or_inline CHECK (
        (storage_key IS NOT NULL AND inline_content IS NULL) OR
        (storage_key IS NULL AND inline_content IS NOT NULL)
    )
);


CREATE INDEX IF NOT EXISTS idx_cbom_artifacts_tenant_generated
    ON public.cbom_artifacts USING btree (tenant_id, generated_at DESC)
    WHERE (deleted_at IS NULL);


CREATE INDEX IF NOT EXISTS idx_cbom_artifacts_scope
    ON public.cbom_artifacts USING btree (scope_id, generated_at DESC)
    WHERE (deleted_at IS NULL);


CREATE INDEX IF NOT EXISTS idx_cbom_artifacts_content_hash
    ON public.cbom_artifacts USING btree (tenant_id, content_hash)
    WHERE (deleted_at IS NULL);


-- =========================================================================
-- CBOM SUBSCRIPTIONS — STUB for roadmap (Phase 2 ships table only, no consumers)
--
-- "Email me a CBOM for scope X every Monday." Real implementation is
-- deferred to a later phase; the schema is in place so the column shape is
-- known and a future cron worker can come along and start consuming.
-- =========================================================================


CREATE TABLE IF NOT EXISTS public.cbom_subscriptions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    -- Cron expression, e.g. "0 6 * * MON" for 06:00 every Monday.
    schedule_cron character varying(64) NOT NULL,
    -- Delivery target: { "type": "email", "to": "...", "format": "pdf" } or
    -- { "type": "webhook", "url": "https://...", "format": "cyclonedx" }.
    delivery jsonb NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    last_run_at timestamp with time zone,
    last_artifact_id uuid,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT cbom_subscriptions_pkey PRIMARY KEY (id)
);


CREATE INDEX IF NOT EXISTS idx_cbom_subscriptions_tenant
    ON public.cbom_subscriptions USING btree (tenant_id);


--
--
--
--
-- =========================================================================
-- ENTITLEMENT CATALOG — PR 1 of the billing/tier-flexibility redesign
--
-- Replaces the hardcoded knownFeatures list + features JSONB + per-resource
-- max_* columns on subscription_tiers with a structured catalog:
--
--   billable_items     — every gateable/billable concept (sensors, assets,
--                        SSO, storage GB, PCAP overage, etc.). Platform-
--                        wide; no tenant scope; no RLS.
--   tier_entitlements  — what each tier includes by default. Composes a
--                        tier as (tier_id, item_id, included_value).
--   tenant_entitlements— per-tenant overrides (trials, promos, enterprise
--                        custom deals). Replaces tenant_limit_overrides in
--                        a later PR; both coexist until cutover.
--
-- The existing billing_* tables (Stripe customers, subscriptions, invoices,
-- trial_tracking) are unchanged. (billing_overage_pricing was dropped in
-- 2026-07 when metered/overage billing was removed — billing is flat
-- per-tier; tier_entitlements' overage_* columns remain as catalog
-- metadata only, nothing bills from them.)
-- =========================================================================


CREATE TABLE IF NOT EXISTS public.billable_items (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    -- Stable code identifier (snake_case). What Go and TS reference. Never rename.
    key text NOT NULL,
    display_name text NOT NULL,
    description text,
    -- Drives admin-UI grouping; not consumed by enforcement code.
    category text NOT NULL,
    -- How the resolver interprets included_value / override_value.
    --   boolean         : {"enabled": true|false}
    --   numeric_cap     : {"quantity": N}  (N=null means unlimited)
    --   numeric_metered : {"quantity": N}  (included quota; overage billed)
    --   enum_choice     : {"value": "..."}
    kind text NOT NULL,
    -- Display-only ("sensors", "GB", "calls"). NULL for booleans.
    unit text,
    -- Resolver fallback when neither tier nor tenant sets a value.
    default_value jsonb DEFAULT '{}'::jsonb NOT NULL,
    -- True when this item can be purchased outside its included tier
    -- (e.g. a Starter tenant adding OT active probing for $X/month).
    is_addon_eligible boolean DEFAULT false NOT NULL,
    -- Platform-default a la carte price for add-on purchases.
    default_addon_price_cents integer,
    -- Sunset switch. Deactivated items keep existing assignments but
    -- cannot be added to new tiers via the admin UI.
    is_active boolean DEFAULT true NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT billable_items_pkey PRIMARY KEY (id),
    CONSTRAINT billable_items_key_unique UNIQUE (key),
    CONSTRAINT billable_items_category_check
        CHECK (category IN ('capacity','meter','capability','support','addon')),
    CONSTRAINT billable_items_kind_check
        CHECK (kind IN ('boolean','numeric_cap','numeric_metered','enum_choice'))
);
CREATE INDEX IF NOT EXISTS idx_billable_items_category ON public.billable_items USING btree (category) WHERE (is_active = true);
CREATE INDEX IF NOT EXISTS idx_billable_items_active_sort ON public.billable_items USING btree (sort_order) WHERE (is_active = true);


DROP TRIGGER IF EXISTS update_billable_items_updated_at ON public.billable_items;
CREATE OR REPLACE TRIGGER update_billable_items_updated_at
    BEFORE UPDATE ON public.billable_items
    FOR EACH ROW
    EXECUTE FUNCTION public.update_updated_at_column();


-- tier_entitlements: tier × item → included default. Platform-wide table;
-- no tenant scope; no RLS. Composite PK enforces one row per (tier, item).
CREATE TABLE IF NOT EXISTS public.tier_entitlements (
    tier_id uuid NOT NULL,
    item_id uuid NOT NULL,
    -- Resolver-typed value matching billable_items.kind.
    included_value jsonb DEFAULT '{}'::jsonb NOT NULL,
    -- Metered items only. Price per overage_unit_size beyond the included
    -- quota. NULL on non-metered items.
    overage_price_cents integer,
    overage_unit_size integer,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT tier_entitlements_pkey PRIMARY KEY (tier_id, item_id)
);


-- FKs added in a DO block so re-running the schema doesn't fail with
-- "constraint already exists" — see CLAUDE.md idempotency rules.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'tier_entitlements_tier_id_fkey') THEN
    ALTER TABLE public.tier_entitlements
      ADD CONSTRAINT tier_entitlements_tier_id_fkey
      FOREIGN KEY (tier_id) REFERENCES public.subscription_tiers(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'tier_entitlements_item_id_fkey') THEN
    ALTER TABLE public.tier_entitlements
      ADD CONSTRAINT tier_entitlements_item_id_fkey
      FOREIGN KEY (item_id) REFERENCES public.billable_items(id) ON DELETE RESTRICT;
  END IF;
END $$;


DROP TRIGGER IF EXISTS update_tier_entitlements_updated_at ON public.tier_entitlements;
CREATE OR REPLACE TRIGGER update_tier_entitlements_updated_at
    BEFORE UPDATE ON public.tier_entitlements
    FOR EACH ROW
    EXECUTE FUNCTION public.update_updated_at_column();


-- tenant_entitlements: per-tenant deltas to the tier baseline.
--
-- Generalizes tenant_limit_overrides (8-type CHECK) into one table that
-- can override any billable_items entry. effective_from/expires_at let
-- this carry trials, promos, and enterprise add-ons; the unique index
-- preserves history so override changes are auditable rather than a
-- destructive update.
--
-- Plan Exceptions are non-billing (ADR-0004): an override is a pure
-- entitlement grant — a lever bumped for one tenant, never a charge.
CREATE TABLE IF NOT EXISTS public.tenant_entitlements (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    item_id uuid NOT NULL,
    override_value jsonb DEFAULT '{}'::jsonb NOT NULL,
    reason text,
    effective_from timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT tenant_entitlements_pkey PRIMARY KEY (id),
    CONSTRAINT tenant_entitlements_unique_per_period UNIQUE (tenant_id, item_id, effective_from)
);
CREATE INDEX IF NOT EXISTS idx_tenant_entitlements_tenant_item ON public.tenant_entitlements USING btree (tenant_id, item_id);
CREATE INDEX IF NOT EXISTS idx_tenant_entitlements_expires ON public.tenant_entitlements USING btree (expires_at) WHERE (expires_at IS NOT NULL);


DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'tenant_entitlements_item_id_fkey') THEN
    ALTER TABLE public.tenant_entitlements
      ADD CONSTRAINT tenant_entitlements_item_id_fkey
      FOREIGN KEY (item_id) REFERENCES public.billable_items(id) ON DELETE RESTRICT;
  END IF;
END $$;


DROP TRIGGER IF EXISTS update_tenant_entitlements_updated_at ON public.tenant_entitlements;
CREATE OR REPLACE TRIGGER update_tenant_entitlements_updated_at
    BEFORE UPDATE ON public.tenant_entitlements
    FOR EACH ROW
    EXECUTE FUNCTION public.update_updated_at_column();


-- =========================================================================
-- API TOKENS (tenant-scoped personal access tokens)
--
-- Bearer credentials for programmatic access — v1 consumer is the MCP
-- service (services/mcp-service), which exchanges a token for a short-lived
-- user JWT via auth-service's HMAC-guarded /internal/api-tokens/exchange.
--
-- token_hash is hex SHA-256 of the full plaintext token (qvpat_<random>).
-- Unlike service_accounts (bcrypt + scan-all), tokens here are looked up
-- O(1) by hash: the plaintext is 256 bits of CSPRNG output, so offline
-- brute force of a leaked hash is infeasible without a KDF, and per-tenant
-- token counts make a full-table bcrypt scan per request unscalable.
-- Tokens are revoked (revoked_at), never deleted — the row is the audit
-- record of the credential's existence.
CREATE TABLE IF NOT EXISTS public.api_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    token_hash character(64) NOT NULL,
    token_prefix character varying(16) NOT NULL,
    permissions jsonb DEFAULT '[]'::jsonb NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


DO $$ BEGIN
  IF to_regclass('public.api_tokens') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'api_tokens_pkey' AND conrelid = to_regclass('public.api_tokens')
     ) THEN
    ALTER TABLE ONLY public.api_tokens ADD CONSTRAINT api_tokens_pkey PRIMARY KEY (id);
  END IF;
END $$;


CREATE UNIQUE INDEX IF NOT EXISTS idx_api_tokens_token_hash ON public.api_tokens (token_hash);
CREATE INDEX IF NOT EXISTS idx_api_tokens_tenant_user ON public.api_tokens (tenant_id, user_id);


DO $$ BEGIN
  IF to_regclass('public.api_tokens') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'api_tokens_tenant_id_fkey' AND conrelid = to_regclass('public.api_tokens')
     ) THEN
    ALTER TABLE public.api_tokens
      ADD CONSTRAINT api_tokens_tenant_id_fkey
      FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;
  END IF;
END $$;


DO $$ BEGIN
  IF to_regclass('public.api_tokens') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
       WHERE conname = 'api_tokens_user_id_fkey' AND conrelid = to_regclass('public.api_tokens')
     ) THEN
    ALTER TABLE public.api_tokens
      ADD CONSTRAINT api_tokens_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
  END IF;
END $$;


-- OAuth 2.0 authorization codes. Short-lived (10 min) codes issued by
-- the OAuth /authorize endpoint and exchanged once for a PAT at /token.
-- Single-use enforced by used_at: a second exchange returns invalid_grant.
-- No RLS — auth-service owns this table exclusively, queries by code_hash.
CREATE TABLE IF NOT EXISTS public.oauth_authorization_codes (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash            TEXT NOT NULL UNIQUE,
    client_id            TEXT NOT NULL,
    redirect_uri         TEXT NOT NULL,
    user_id              UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    tenant_id            UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    code_challenge       TEXT NOT NULL,
    scopes               TEXT[] NOT NULL DEFAULT '{}',
    expires_at           TIMESTAMPTZ NOT NULL,
    used_at              TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_oauth_codes_expires ON public.oauth_authorization_codes (expires_at);


-- Per-(tenant, framework) score rollup written by the evaluation engine
-- reconcile (services/compliance-engine .../evaluation_engine.go). One row per
-- published framework per tenant — read for posture scorecards and the preview
-- score on unactivated frameworks. Findings (failures) stay in
-- compliance_findings; this is just the rollup.
-- =====================================================================
-- score is NULLable on purpose: a framework with no ASSESSED control has
-- no score, and the rollup must be able to say so. It used to be NOT NULL
-- DEFAULT 0, which forced the writer to pick a sentinel — and it picked 100,
-- so a half-authored framework or an empty inventory previewed as perfect.
CREATE TABLE IF NOT EXISTS public.tenant_framework_scores (
    tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    platform_framework_id uuid NOT NULL REFERENCES public.platform_frameworks(id) ON DELETE CASCADE,
    score integer,
    controls_total integer NOT NULL DEFAULT 0,
    controls_passing integer NOT NULL DEFAULT 0,
    controls_failing integer NOT NULL DEFAULT 0,
    controls_not_assessed integer NOT NULL DEFAULT 0,
    computed_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT tenant_framework_scores_pkey PRIMARY KEY (tenant_id, platform_framework_id)
);

-- Existing installs: CREATE TABLE IF NOT EXISTS above is a no-op for them, so
-- the same two changes are applied as idempotent ALTERs. DROP NOT NULL and DROP
-- DEFAULT are both no-ops when already applied.
ALTER TABLE public.tenant_framework_scores
  ADD COLUMN IF NOT EXISTS controls_not_assessed integer NOT NULL DEFAULT 0;
ALTER TABLE public.tenant_framework_scores ALTER COLUMN score DROP NOT NULL;
ALTER TABLE public.tenant_framework_scores ALTER COLUMN score DROP DEFAULT;


CREATE INDEX IF NOT EXISTS idx_tenant_framework_scores_tenant
  ON public.tenant_framework_scores (tenant_id);


-- Speeds the evaluation engine's active-finding reconcile load + posture reads.
CREATE INDEX IF NOT EXISTS idx_compliance_findings_tenant_control_state
  ON public.compliance_findings (tenant_id, control_id, detection_state);


--
--
-- =====================================================================
-- ADR-0007: Posture & Findings Read Models — posture trend time-series.
-- One row per tenant per day capturing the crypto-risk posture (the same
-- counts inventory-service GET /risk/summary returns). Written by the
-- audit-service nightly posture-snapshot job
-- (services/audit-service/internal/jobs/posture_snapshot_job.go), which calls
-- /risk/summary per tenant and upserts here (idempotent on the PK). Read by
-- inventory-service GET /risk/posture/trend?days=N for the dashboard posture
-- trend line. Forward-accruing only — a new tenant's pre-history days are
-- seeded at the current live posture by the read endpoint, never stored.
-- =====================================================================
CREATE TABLE IF NOT EXISTS public.posture_daily_snapshots (
    tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    snapshot_date date NOT NULL,
    total_assets integer NOT NULL DEFAULT 0,
    high_risk integer NOT NULL DEFAULT 0,
    medium_risk integer NOT NULL DEFAULT 0,
    low_risk integer NOT NULL DEFAULT 0,
    unknown_risk integer NOT NULL DEFAULT 0,
    total_crypto integer NOT NULL DEFAULT 0,
    critical_findings integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT posture_daily_snapshots_pkey PRIMARY KEY (tenant_id, snapshot_date)
);


-- The PK (tenant_id, snapshot_date) already serves the trend range read
-- (WHERE tenant_id = $1 AND snapshot_date >= $2 ORDER BY snapshot_date); a
-- btree scans backwards for DESC, so no separate index is needed.


-- ============================================================================
-- RLS HARDENING (ADR platform-0001) — authoritative tenant-isolation policies
-- Idempotent: DROP POLICY IF EXISTS + CREATE so WITH CHECK changes re-apply on
-- every upgrade (the DO/EXCEPTION duplicate_object pattern in the pg_dump body
-- above CANNOT update an existing policy). This block is the source of truth.
-- This block is the ONLY place tenant-isolation policies are defined; the
-- pg_dump body above no longer carries duplicates. As of that is
-- literally true: invitations and legal_acceptances, the last two declared at
-- their tables with the DO/EXCEPTION form, were moved here.
--
-- On the omitted-WITH-CHECK question, for the record, because the
-- original analysis got it backwards: Postgres REUSES the USING expression as
-- the WITH CHECK when WITH CHECK is omitted (see CREATE POLICY). A USING-only
-- tenant-isolation policy therefore already rejected cross-tenant INSERTs —
-- there was no write hole. Stating both clauses is a legibility and uniformity
-- fix, not a security fix: no reader should have to know that fallback rule to
-- audit a policy. TestIntegration_RLS_EveryTenantPolicyHasWithCheck keeps every
-- policy explicit so the question cannot arise again.
-- USING governs read/visibility; WITH CHECK governs the new-row image on
-- INSERT/UPDATE (closes the cross-tenant write hole). No FORCE here — the app
-- still connects as the table owner until the Phase 4 role flip, so this block
-- is behavior-neutral (owner bypasses RLS).
-- ============================================================================


-- Canonical tenant isolation: direct tenant_id column. 119 tables.
-- (The count is a hand-maintained comment and had drifted to "124" against an
-- actual 118 before invitations was added here — treat it as approximate. What
-- is actually enforced is the PROPERTY, by
-- TestIntegration_RLS_EveryTenantPolicyHasWithCheck: every *_tenant_isolation
-- policy in the database carries a WITH CHECK, whatever the count.)
ALTER TABLE audit.activity_logs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS activity_logs_tenant_isolation ON audit.activity_logs;
CREATE POLICY activity_logs_tenant_isolation ON audit.activity_logs
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE audit.alert_instances ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS alert_instances_tenant_isolation ON audit.alert_instances;
CREATE POLICY alert_instances_tenant_isolation ON audit.alert_instances
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE audit.alert_rules ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS alert_rules_tenant_isolation ON audit.alert_rules;
CREATE POLICY alert_rules_tenant_isolation ON audit.alert_rules
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE audit.audit_logs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_logs_tenant_isolation ON audit.audit_logs;
CREATE POLICY audit_logs_tenant_isolation ON audit.audit_logs
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE audit.job_execution_logs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS job_execution_logs_tenant_isolation ON audit.job_execution_logs;
CREATE POLICY job_execution_logs_tenant_isolation ON audit.job_execution_logs
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE audit.scheduled_compliance_reports ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scheduled_compliance_reports_tenant_isolation ON audit.scheduled_compliance_reports;
CREATE POLICY scheduled_compliance_reports_tenant_isolation ON audit.scheduled_compliance_reports
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE audit.scheduled_report_executions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scheduled_report_executions_tenant_isolation ON audit.scheduled_report_executions;
CREATE POLICY scheduled_report_executions_tenant_isolation ON audit.scheduled_report_executions
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE audit.siem_integrations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS siem_integrations_tenant_isolation ON audit.siem_integrations;
CREATE POLICY siem_integrations_tenant_isolation ON audit.siem_integrations
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.access_pattern_analysis ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS access_pattern_analysis_tenant_isolation ON public.access_pattern_analysis;
CREATE POLICY access_pattern_analysis_tenant_isolation ON public.access_pattern_analysis
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.agent_ca_certificates ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agent_ca_certificates_tenant_isolation ON public.agent_ca_certificates;
CREATE POLICY agent_ca_certificates_tenant_isolation ON public.agent_ca_certificates
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.agent_certificates ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agent_certificates_tenant_isolation ON public.agent_certificates;
CREATE POLICY agent_certificates_tenant_isolation ON public.agent_certificates
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.ai_analysis_results ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ai_analysis_results_tenant_isolation ON public.ai_analysis_results;
CREATE POLICY ai_analysis_results_tenant_isolation ON public.ai_analysis_results
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.api_format_preferences ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS api_format_preferences_tenant_isolation ON public.api_format_preferences;
CREATE POLICY api_format_preferences_tenant_isolation ON public.api_format_preferences
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.api_security_monitoring ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS api_security_monitoring_tenant_isolation ON public.api_security_monitoring;
CREATE POLICY api_security_monitoring_tenant_isolation ON public.api_security_monitoring
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.api_tokens ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS api_tokens_tenant_isolation ON public.api_tokens;
CREATE POLICY api_tokens_tenant_isolation ON public.api_tokens
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.api_usage_logs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS api_usage_logs_tenant_isolation ON public.api_usage_logs;
CREATE POLICY api_usage_logs_tenant_isolation ON public.api_usage_logs
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.asset_history ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS asset_history_tenant_isolation ON public.asset_history;
CREATE POLICY asset_history_tenant_isolation ON public.asset_history
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.asset_lifecycle_policies ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS asset_lifecycle_policies_tenant_isolation ON public.asset_lifecycle_policies;
CREATE POLICY asset_lifecycle_policies_tenant_isolation ON public.asset_lifecycle_policies
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.auth_audit_log ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS auth_audit_log_tenant_isolation ON public.auth_audit_log;
CREATE POLICY auth_audit_log_tenant_isolation ON public.auth_audit_log
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.aws_cost_data ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aws_cost_data_tenant_isolation ON public.aws_cost_data;
CREATE POLICY aws_cost_data_tenant_isolation ON public.aws_cost_data
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.aws_cost_sync_jobs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aws_cost_sync_jobs_tenant_isolation ON public.aws_cost_sync_jobs;
CREATE POLICY aws_cost_sync_jobs_tenant_isolation ON public.aws_cost_sync_jobs
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.billing_coupon_redemptions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS billing_coupon_redemptions_tenant_isolation ON public.billing_coupon_redemptions;
CREATE POLICY billing_coupon_redemptions_tenant_isolation ON public.billing_coupon_redemptions
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.billing_customers ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS billing_customers_tenant_isolation ON public.billing_customers;
CREATE POLICY billing_customers_tenant_isolation ON public.billing_customers
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.billing_dunning_attempts ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS billing_dunning_attempts_tenant_isolation ON public.billing_dunning_attempts;
CREATE POLICY billing_dunning_attempts_tenant_isolation ON public.billing_dunning_attempts
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.billing_invoices ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS billing_invoices_tenant_isolation ON public.billing_invoices;
CREATE POLICY billing_invoices_tenant_isolation ON public.billing_invoices
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.billing_subscriptions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS billing_subscriptions_tenant_isolation ON public.billing_subscriptions;
CREATE POLICY billing_subscriptions_tenant_isolation ON public.billing_subscriptions
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.billing_trial_tracking ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS billing_trial_tracking_tenant_isolation ON public.billing_trial_tracking;
CREATE POLICY billing_trial_tracking_tenant_isolation ON public.billing_trial_tracking
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.cbom_artifacts ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cbom_artifacts_tenant_isolation ON public.cbom_artifacts;
CREATE POLICY cbom_artifacts_tenant_isolation ON public.cbom_artifacts
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.cbom_subscriptions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cbom_subscriptions_tenant_isolation ON public.cbom_subscriptions;
CREATE POLICY cbom_subscriptions_tenant_isolation ON public.cbom_subscriptions
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.certificate_history ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS certificate_history_tenant_isolation ON public.certificate_history;
CREATE POLICY certificate_history_tenant_isolation ON public.certificate_history
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.certificates ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS certificates_tenant_isolation ON public.certificates;
CREATE POLICY certificates_tenant_isolation ON public.certificates
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.ci_relationships ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ci_relationships_tenant_isolation ON public.ci_relationships;
CREATE POLICY ci_relationships_tenant_isolation ON public.ci_relationships
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.cmdb_entity_mappings ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cmdb_entity_mappings_tenant_isolation ON public.cmdb_entity_mappings;
CREATE POLICY cmdb_entity_mappings_tenant_isolation ON public.cmdb_entity_mappings
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.cmdb_sync_jobs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cmdb_sync_jobs_tenant_isolation ON public.cmdb_sync_jobs;
CREATE POLICY cmdb_sync_jobs_tenant_isolation ON public.cmdb_sync_jobs
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.cmdb_sync_profiles ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cmdb_sync_profiles_tenant_isolation ON public.cmdb_sync_profiles;
CREATE POLICY cmdb_sync_profiles_tenant_isolation ON public.cmdb_sync_profiles
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.compliance_checks ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS compliance_checks_tenant_isolation ON public.compliance_checks;
CREATE POLICY compliance_checks_tenant_isolation ON public.compliance_checks
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.compliance_findings ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS compliance_findings_tenant_isolation ON public.compliance_findings;
CREATE POLICY compliance_findings_tenant_isolation ON public.compliance_findings
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.compliance_overrides ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS compliance_overrides_tenant_isolation ON public.compliance_overrides;
CREATE POLICY compliance_overrides_tenant_isolation ON public.compliance_overrides
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.compliance_reports ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS compliance_reports_tenant_isolation ON public.compliance_reports;
CREATE POLICY compliance_reports_tenant_isolation ON public.compliance_reports
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.compliance_scenarios ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS compliance_scenarios_tenant_isolation ON public.compliance_scenarios;
CREATE POLICY compliance_scenarios_tenant_isolation ON public.compliance_scenarios
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.crypto_applications ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS crypto_applications_tenant_isolation ON public.crypto_applications;
CREATE POLICY crypto_applications_tenant_isolation ON public.crypto_applications
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.crypto_implementations_partitioned ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS crypto_implementations_partitioned_tenant_isolation ON public.crypto_implementations_partitioned;
CREATE POLICY crypto_implementations_partitioned_tenant_isolation ON public.crypto_implementations_partitioned
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.crypto_libraries ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS crypto_libraries_tenant_isolation ON public.crypto_libraries;
CREATE POLICY crypto_libraries_tenant_isolation ON public.crypto_libraries
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.database_encryption_states ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS database_encryption_states_tenant_isolation ON public.database_encryption_states;
CREATE POLICY database_encryption_states_tenant_isolation ON public.database_encryption_states
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.device_agents ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS device_agents_tenant_isolation ON public.device_agents;
CREATE POLICY device_agents_tenant_isolation ON public.device_agents
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.device_jobs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS device_jobs_tenant_isolation ON public.device_jobs;
CREATE POLICY device_jobs_tenant_isolation ON public.device_jobs
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.devices ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS devices_tenant_isolation ON public.devices;
CREATE POLICY devices_tenant_isolation ON public.devices
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.discovery_alert_configs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS discovery_alert_configs_tenant_isolation ON public.discovery_alert_configs;
CREATE POLICY discovery_alert_configs_tenant_isolation ON public.discovery_alert_configs
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.discovery_alert_history ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS discovery_alert_history_tenant_isolation ON public.discovery_alert_history;
CREATE POLICY discovery_alert_history_tenant_isolation ON public.discovery_alert_history
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.discovery_approval_queue ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS discovery_approval_queue_tenant_isolation ON public.discovery_approval_queue;
CREATE POLICY discovery_approval_queue_tenant_isolation ON public.discovery_approval_queue
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.discovery_auto_approval_rules ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS discovery_auto_approval_rules_tenant_isolation ON public.discovery_auto_approval_rules;
CREATE POLICY discovery_auto_approval_rules_tenant_isolation ON public.discovery_auto_approval_rules
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.discovery_findings ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS discovery_findings_tenant_isolation ON public.discovery_findings;
CREATE POLICY discovery_findings_tenant_isolation ON public.discovery_findings
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.discovery_jobs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS discovery_jobs_tenant_isolation ON public.discovery_jobs;
CREATE POLICY discovery_jobs_tenant_isolation ON public.discovery_jobs
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.discovery_rate_limits ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS discovery_rate_limits_tenant_isolation ON public.discovery_rate_limits;
CREATE POLICY discovery_rate_limits_tenant_isolation ON public.discovery_rate_limits
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.discovery_targets ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS discovery_targets_tenant_isolation ON public.discovery_targets;
CREATE POLICY discovery_targets_tenant_isolation ON public.discovery_targets
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.external_asset_mappings ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS external_asset_mappings_tenant_isolation ON public.external_asset_mappings;
CREATE POLICY external_asset_mappings_tenant_isolation ON public.external_asset_mappings
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.external_connection_history ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS external_connection_history_tenant_isolation ON public.external_connection_history;
CREATE POLICY external_connection_history_tenant_isolation ON public.external_connection_history
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.external_connections ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS external_connections_tenant_isolation ON public.external_connections;
CREATE POLICY external_connections_tenant_isolation ON public.external_connections
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.feature_adoption_metrics ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS feature_adoption_metrics_tenant_isolation ON public.feature_adoption_metrics;
CREATE POLICY feature_adoption_metrics_tenant_isolation ON public.feature_adoption_metrics
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.feature_usage_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS feature_usage_events_tenant_isolation ON public.feature_usage_events;
CREATE POLICY feature_usage_events_tenant_isolation ON public.feature_usage_events
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.health_alerts ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS health_alerts_tenant_isolation ON public.health_alerts;
CREATE POLICY health_alerts_tenant_isolation ON public.health_alerts
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.health_insights ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS health_insights_tenant_isolation ON public.health_insights;
CREATE POLICY health_insights_tenant_isolation ON public.health_insights
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.health_metrics ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS health_metrics_tenant_isolation ON public.health_metrics;
CREATE POLICY health_metrics_tenant_isolation ON public.health_metrics
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.in_app_notifications ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS in_app_notifications_tenant_isolation ON public.in_app_notifications;
CREATE POLICY in_app_notifications_tenant_isolation ON public.in_app_notifications
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.integrations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS integrations_tenant_isolation ON public.integrations;
CREATE POLICY integrations_tenant_isolation ON public.integrations
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.interrogation_schedules ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS interrogation_schedules_tenant_isolation ON public.interrogation_schedules;
CREATE POLICY interrogation_schedules_tenant_isolation ON public.interrogation_schedules
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
-- invitations was the last USING-only policy. The DROP+CREATE here is
-- what actually tightens an EXISTING install: it replaces the write-open policy
-- the pg_dump body used to declare at the table. Every write already runs
-- inside WithTenantTx (auth-service invitations.go), so WITH CHECK is
-- behaviour-neutral for legitimate callers.
ALTER TABLE public.invitations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS invitations_tenant_isolation ON public.invitations;
CREATE POLICY invitations_tenant_isolation ON public.invitations
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.keys ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS keys_tenant_isolation ON public.keys;
CREATE POLICY keys_tenant_isolation ON public.keys
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.kms_keys ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS kms_keys_tenant_isolation ON public.kms_keys;
CREATE POLICY kms_keys_tenant_isolation ON public.kms_keys
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
-- NB: public.legal_acceptances is NOT declared here, and cannot be. It is one
-- of the tables appended to the file BELOW this block (the same late-created
-- set whose privileges had to move the blanket GRANTs to fix), so at this
-- point in the apply it does not exist yet and a policy on it aborts the run
-- under ON_ERROR_STOP=1. Its policy is tightened in place at its own
-- definition instead.
ALTER TABLE public.locations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS locations_tenant_isolation ON public.locations;
CREATE POLICY locations_tenant_isolation ON public.locations
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.network_assets_partitioned ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS network_assets_partitioned_tenant_isolation ON public.network_assets_partitioned;
CREATE POLICY network_assets_partitioned_tenant_isolation ON public.network_assets_partitioned
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.network_segments ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS network_segments_tenant_isolation ON public.network_segments;
CREATE POLICY network_segments_tenant_isolation ON public.network_segments
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.oauth_authorization_codes ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS oauth_authorization_codes_tenant_isolation ON public.oauth_authorization_codes;
CREATE POLICY oauth_authorization_codes_tenant_isolation ON public.oauth_authorization_codes
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.pcap_upload_jobs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pcap_upload_jobs_tenant_isolation ON public.pcap_upload_jobs;
CREATE POLICY pcap_upload_jobs_tenant_isolation ON public.pcap_upload_jobs
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.pending_sensor_registrations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pending_sensor_registrations_tenant_isolation ON public.pending_sensor_registrations;
CREATE POLICY pending_sensor_registrations_tenant_isolation ON public.pending_sensor_registrations
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.pending_sensors ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pending_sensors_tenant_isolation ON public.pending_sensors;
CREATE POLICY pending_sensors_tenant_isolation ON public.pending_sensors
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.permission_audit_logs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS permission_audit_logs_tenant_isolation ON public.permission_audit_logs;
CREATE POLICY permission_audit_logs_tenant_isolation ON public.permission_audit_logs
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.platform_integrations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS platform_integrations_tenant_isolation ON public.platform_integrations;
CREATE POLICY platform_integrations_tenant_isolation ON public.platform_integrations
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.platform_log_metadata ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS platform_log_metadata_tenant_isolation ON public.platform_log_metadata;
CREATE POLICY platform_log_metadata_tenant_isolation ON public.platform_log_metadata
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.posture_daily_snapshots ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS posture_daily_snapshots_tenant_isolation ON public.posture_daily_snapshots;
CREATE POLICY posture_daily_snapshots_tenant_isolation ON public.posture_daily_snapshots
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.remediation_plans ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS remediation_plans_tenant_isolation ON public.remediation_plans;
CREATE POLICY remediation_plans_tenant_isolation ON public.remediation_plans
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.resource_alerts ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS resource_alerts_tenant_isolation ON public.resource_alerts;
CREATE POLICY resource_alerts_tenant_isolation ON public.resource_alerts
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.resource_permissions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS resource_permissions_tenant_isolation ON public.resource_permissions;
CREATE POLICY resource_permissions_tenant_isolation ON public.resource_permissions
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.scopes ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scopes_tenant_isolation ON public.scopes;
CREATE POLICY scopes_tenant_isolation ON public.scopes
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.scopes_audit ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scopes_audit_tenant_isolation ON public.scopes_audit;
CREATE POLICY scopes_audit_tenant_isolation ON public.scopes_audit
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.security_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS security_events_tenant_isolation ON public.security_events;
CREATE POLICY security_events_tenant_isolation ON public.security_events
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.sensor_ca_certificates ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sensor_ca_certificates_tenant_isolation ON public.sensor_ca_certificates;
CREATE POLICY sensor_ca_certificates_tenant_isolation ON public.sensor_ca_certificates
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.sensor_certificates ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sensor_certificates_tenant_isolation ON public.sensor_certificates;
CREATE POLICY sensor_certificates_tenant_isolation ON public.sensor_certificates
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.sensor_discoveries_partitioned ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sensor_discoveries_partitioned_tenant_isolation ON public.sensor_discoveries_partitioned;
CREATE POLICY sensor_discoveries_partitioned_tenant_isolation ON public.sensor_discoveries_partitioned
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.sensors ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sensors_tenant_isolation ON public.sensors;
CREATE POLICY sensors_tenant_isolation ON public.sensors
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.service_identification_rules ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS service_identification_rules_tenant_isolation ON public.service_identification_rules;
CREATE POLICY service_identification_rules_tenant_isolation ON public.service_identification_rules
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.ssh_keys ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ssh_keys_tenant_isolation ON public.ssh_keys;
CREATE POLICY ssh_keys_tenant_isolation ON public.ssh_keys
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.sso_group_role_mappings ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sso_group_role_mappings_tenant_isolation ON public.sso_group_role_mappings;
CREATE POLICY sso_group_role_mappings_tenant_isolation ON public.sso_group_role_mappings
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.sso_providers ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sso_providers_tenant_isolation ON public.sso_providers;
CREATE POLICY sso_providers_tenant_isolation ON public.sso_providers
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.support_tickets ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS support_tickets_tenant_isolation ON public.support_tickets;
CREATE POLICY support_tickets_tenant_isolation ON public.support_tickets
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.sync_outbox ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sync_outbox_tenant_isolation ON public.sync_outbox;
CREATE POLICY sync_outbox_tenant_isolation ON public.sync_outbox
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.tenant_admin_settings ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_admin_settings_tenant_isolation ON public.tenant_admin_settings;
CREATE POLICY tenant_admin_settings_tenant_isolation ON public.tenant_admin_settings
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.tenant_admin_settings_audit ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_admin_settings_audit_tenant_isolation ON public.tenant_admin_settings_audit;
CREATE POLICY tenant_admin_settings_audit_tenant_isolation ON public.tenant_admin_settings_audit
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.tenant_cost_analysis ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_cost_analysis_tenant_isolation ON public.tenant_cost_analysis;
CREATE POLICY tenant_cost_analysis_tenant_isolation ON public.tenant_cost_analysis
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.tenant_entitlements ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_entitlements_tenant_isolation ON public.tenant_entitlements;
CREATE POLICY tenant_entitlements_tenant_isolation ON public.tenant_entitlements
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.tenant_framework_licenses ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_framework_licenses_tenant_isolation ON public.tenant_framework_licenses;
CREATE POLICY tenant_framework_licenses_tenant_isolation ON public.tenant_framework_licenses
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.tenant_framework_scores ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_framework_scores_tenant_isolation ON public.tenant_framework_scores;
CREATE POLICY tenant_framework_scores_tenant_isolation ON public.tenant_framework_scores
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.tenant_frameworks ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_frameworks_tenant_isolation ON public.tenant_frameworks;
CREATE POLICY tenant_frameworks_tenant_isolation ON public.tenant_frameworks
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.tenant_geographic_data ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_geographic_data_tenant_isolation ON public.tenant_geographic_data;
CREATE POLICY tenant_geographic_data_tenant_isolation ON public.tenant_geographic_data
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.tenant_health ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_health_tenant_isolation ON public.tenant_health;
CREATE POLICY tenant_health_tenant_isolation ON public.tenant_health
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.tenant_measurement_overrides ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_measurement_overrides_tenant_isolation ON public.tenant_measurement_overrides;
CREATE POLICY tenant_measurement_overrides_tenant_isolation ON public.tenant_measurement_overrides
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.tenant_notes ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_notes_tenant_isolation ON public.tenant_notes;
CREATE POLICY tenant_notes_tenant_isolation ON public.tenant_notes
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.tenant_notification_channels ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_notification_channels_tenant_isolation ON public.tenant_notification_channels;
CREATE POLICY tenant_notification_channels_tenant_isolation ON public.tenant_notification_channels
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.tenant_notification_rules ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_notification_rules_tenant_isolation ON public.tenant_notification_rules;
CREATE POLICY tenant_notification_rules_tenant_isolation ON public.tenant_notification_rules
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.tenant_resource_usage ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_resource_usage_tenant_isolation ON public.tenant_resource_usage;
CREATE POLICY tenant_resource_usage_tenant_isolation ON public.tenant_resource_usage
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.tenant_roles ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_roles_tenant_isolation ON public.tenant_roles;
CREATE POLICY tenant_roles_tenant_isolation ON public.tenant_roles
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.tenant_usage ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_usage_tenant_isolation ON public.tenant_usage;
CREATE POLICY tenant_usage_tenant_isolation ON public.tenant_usage
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.tenant_usage_tracking ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_usage_tracking_tenant_isolation ON public.tenant_usage_tracking;
CREATE POLICY tenant_usage_tracking_tenant_isolation ON public.tenant_usage_tracking
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.tickets ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tickets_tenant_isolation ON public.tickets;
CREATE POLICY tickets_tenant_isolation ON public.tickets
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.user_framework_preferences ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS user_framework_preferences_tenant_isolation ON public.user_framework_preferences;
CREATE POLICY user_framework_preferences_tenant_isolation ON public.user_framework_preferences
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.user_tenant_roles ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS user_tenant_roles_tenant_isolation ON public.user_tenant_roles;
CREATE POLICY user_tenant_roles_tenant_isolation ON public.user_tenant_roles
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS users_tenant_isolation ON public.users;
CREATE POLICY users_tenant_isolation ON public.users
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.workflow_configurations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS workflow_configurations_tenant_isolation ON public.workflow_configurations;
CREATE POLICY workflow_configurations_tenant_isolation ON public.workflow_configurations
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);


-- Notification tables that also expose platform-broadcast rows (tenant_id IS NULL):
-- USING lets a tenant SEE broadcasts; WITH CHECK is strict (a tenant may only
-- write its own rows — broadcasts are inserted via the bypass role).
ALTER TABLE public.notification_delivery_queue ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS notification_delivery_queue_tenant_isolation ON public.notification_delivery_queue;
CREATE POLICY notification_delivery_queue_tenant_isolation ON public.notification_delivery_queue
  USING (tenant_id IS NULL OR tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.notification_history ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS notification_history_tenant_isolation ON public.notification_history;
CREATE POLICY notification_history_tenant_isolation ON public.notification_history
  USING (tenant_id IS NULL OR tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);


-- Parent-join tables (no own tenant_id) — isolate via the owning parent row.
-- WITH CHECK uses the same EXISTS so an INSERT must reference a parent the
-- caller's tenant owns.
ALTER TABLE public.sensor_commands ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sensor_commands_tenant_isolation ON public.sensor_commands;
CREATE POLICY sensor_commands_tenant_isolation ON public.sensor_commands
  USING (EXISTS (SELECT 1 FROM public.sensors WHERE sensors.id = sensor_commands.sensor_id AND sensors.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid))
  WITH CHECK (EXISTS (SELECT 1 FROM public.sensors WHERE sensors.id = sensor_commands.sensor_id AND sensors.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid));
ALTER TABLE public.sensor_health_metrics ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sensor_health_metrics_tenant_isolation ON public.sensor_health_metrics;
CREATE POLICY sensor_health_metrics_tenant_isolation ON public.sensor_health_metrics
  USING (EXISTS (SELECT 1 FROM public.sensors WHERE sensors.id = sensor_health_metrics.sensor_id AND sensors.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid))
  WITH CHECK (EXISTS (SELECT 1 FROM public.sensors WHERE sensors.id = sensor_health_metrics.sensor_id AND sensors.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid));
ALTER TABLE public.schedule_history ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS schedule_history_tenant_isolation ON public.schedule_history;
CREATE POLICY schedule_history_tenant_isolation ON public.schedule_history
  USING (EXISTS (SELECT 1 FROM public.interrogation_schedules s WHERE s.id = schedule_history.schedule_id AND s.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid))
  WITH CHECK (EXISTS (SELECT 1 FROM public.interrogation_schedules s WHERE s.id = schedule_history.schedule_id AND s.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid));
ALTER TABLE public.ticket_comments ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ticket_comments_tenant_isolation ON public.ticket_comments;
CREATE POLICY ticket_comments_tenant_isolation ON public.ticket_comments
  USING (EXISTS (SELECT 1 FROM public.tickets t WHERE t.id = ticket_comments.ticket_id AND t.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid))
  WITH CHECK (EXISTS (SELECT 1 FROM public.tickets t WHERE t.id = ticket_comments.ticket_id AND t.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid));
ALTER TABLE public.remediation_plan_items ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS remediation_plan_items_tenant_isolation ON public.remediation_plan_items;
CREATE POLICY remediation_plan_items_tenant_isolation ON public.remediation_plan_items
  USING (EXISTS (SELECT 1 FROM public.remediation_plans rp WHERE rp.id = remediation_plan_items.plan_id AND rp.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid))
  WITH CHECK (EXISTS (SELECT 1 FROM public.remediation_plans rp WHERE rp.id = remediation_plan_items.plan_id AND rp.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid));


-- =========================================================================
-- MISSING INDEXES ON TENANT-SCOPED READ PATHS
-- (Core audit, WP-E — SQL-5)
--
-- Each of these backs a query that is issued per request (or per ingested
-- finding) and had nothing to work from but a sequential scan.
-- =========================================================================


-- asset_history had NO secondary index at all — every asset-timeline read
-- scanned the whole tenant's history. The lead columns match the access
-- pattern: one asset's history, newest first.
CREATE INDEX IF NOT EXISTS idx_asset_history_tenant_asset_created
    ON public.asset_history USING btree (tenant_id, asset_id, created_at DESC);


-- audit.audit_logs had only idx_audit_logs_created_at (global, not
-- tenant-scoped), so a tenant's audit view scanned every tenant's rows and
-- filtered afterwards. Both of these are nullable columns (platform-level
-- events carry no tenant/user), which btree indexes fine.
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_created
    ON audit.audit_logs USING btree (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id
    ON audit.audit_logs USING btree (user_id);


-- discovery_findings is indexed on job_id/target_id/hostname/protocol but not
-- on the column every RLS policy and tenant query filters on first.
CREATE INDEX IF NOT EXISTS idx_discovery_findings_tenant_id
    ON public.discovery_findings USING btree (tenant_id);


-- external_connections: the sensor_id and source_asset_id lookups (which
-- sensor observed this / which asset originated this) had no index, unlike
-- every other access path on the table.
CREATE INDEX IF NOT EXISTS idx_ext_conn_sensor_id
    ON public.external_connections USING btree (sensor_id)
    WHERE (sensor_id IS NOT NULL);
CREATE INDEX IF NOT EXISTS idx_ext_conn_source_asset_id
    ON public.external_connections USING btree (source_asset_id)
    WHERE (source_asset_id IS NOT NULL);


-- Login and invite flows look users up case-insensitively within a tenant.
-- idx_users_email is on the raw column, so lower(email) could not use it.
CREATE INDEX IF NOT EXISTS idx_users_tenant_lower_email
    ON public.users USING btree (tenant_id, lower((email)::text));


-- =========================================================================
-- Partition-aware views must run with the querying role's RLS context, not the
-- view owner's, so the parent-table policies above actually apply through them.
ALTER VIEW public.network_assets SET (security_invoker = true);
ALTER VIEW public.sensor_discoveries SET (security_invoker = true);
ALTER VIEW public.crypto_implementations SET (security_invoker = true);


-- ============================================================================
-- RLS ROLE SPLIT (ADR platform-0001, Phase 2)
-- ============================================================================
-- Today the app connects as crypto_user, which OWNS every table (the
-- schema-migration Job runs as it) — and a table owner BYPASSES RLS. These two
-- non-owner roles make RLS an enforced boundary without any FORCE:
--
--   crypto_app    — NOBYPASSRLS. Services' normal per-request path connects as
--                   this role, so every tenant_isolation policy applies. It must
--                   set app.tenant_id (via shared/database.WithTenantTx) or its
--                   tenant-scoped queries fail closed (zero rows).
--   crypto_bypass — BYPASSRLS. The deliberate cross-tenant paths (platform-admin
--                   aggregations, background workers, and auth lookups where the
--                   tenant is the query's OUTPUT) connect as this role.
--
-- Roles are created NOLOGIN here; the deploy layer grants LOGIN + a password out
-- of band (psql \set from a secret) so no credential ever lives in this file.
-- crypto_user (owner) and the schema-migration/seed Jobs are unchanged.
-- Idempotent: CREATE ROLE has no IF NOT EXISTS, so it is wrapped; GRANT and
-- ALTER DEFAULT PRIVILEGES are already idempotent.
DO $$ BEGIN CREATE ROLE crypto_app NOLOGIN NOBYPASSRLS;    EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE crypto_bypass NOLOGIN BYPASSRLS;   EXCEPTION WHEN duplicate_object THEN NULL; END $$;


-- Schema + object access for both roles.
--
-- NOTE: the blanket `GRANT ... ON ALL TABLES/SEQUENCES` used to live here, and
-- that was a latent bug. `ON ALL TABLES` is expanded ONCE, against the tables
-- that exist at the moment it runs — so every table CREATEd further down this
-- file got no privileges at all on a FRESH SINGLE APPLY. The chart's
-- schema-migration Job runs the file exactly once on install, so nine tables
-- (alerts, alert_events, legal_documents, legal_acceptances, …) shipped with
-- `permission denied for table` for the NOBYPASSRLS crypto_app role that
-- services connect as under serviceRls. A second apply masked it, which is why
-- it survived: by then the tables existed when the GRANT ran.
--
-- ALTER DEFAULT PRIVILEGES (below) does not cover this either — it applies only
-- to objects created by crypto_user AFTER it runs, and this file is applied by
-- whatever role the Job connects as.
--
-- The blanket grants now live in the ROLE GRANTS block at the very END of this
-- file, after every CREATE TABLE. `scripts/audit-schema-grant-order.mjs`
-- (in `make audit`) fails the build if any table-creating statement ever lands
-- after it again.
GRANT USAGE ON SCHEMA public TO crypto_app, crypto_bypass;
GRANT USAGE ON SCHEMA audit  TO crypto_app, crypto_bypass;
GRANT EXECUTE ON FUNCTION public.set_tenant_context(uuid) TO crypto_app, crypto_bypass;
GRANT EXECUTE ON FUNCTION public.clear_tenant_context()   TO crypto_app, crypto_bypass;


-- RBAC permission checks (/-class fail-closed fix): these read RLS-scoped
-- user_tenant_roles / tenant_roles, so under the non-owner crypto_app role with no
-- app.tenant_id set (middleware runs before any WithTenantTx) they returned zero
-- rows -> every RBAC-gated action 403'd. Make them SECURITY DEFINER (run as owner)
-- so the parameterized (user, tenant) lookup is correct regardless of tenant
-- context; they filter internally by the passed ids so no cross-tenant leak.
-- EXECUTE locked to the app roles (SECURITY DEFINER + PUBLIC execute is an
-- escalation surface).
REVOKE EXECUTE ON FUNCTION public.user_has_permission(uuid, uuid, character varying) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.get_user_permissions(uuid, uuid)                   FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.platform_user_has_permission(uuid, character varying) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION public.user_has_permission(uuid, uuid, character varying) TO crypto_app, crypto_bypass;
GRANT  EXECUTE ON FUNCTION public.get_user_permissions(uuid, uuid)                   TO crypto_app, crypto_bypass;
GRANT  EXECUTE ON FUNCTION public.platform_user_has_permission(uuid, character varying) TO crypto_app, crypto_bypass;


-- audit partition management: these are SECURITY DEFINER (run as the
-- owner so the app role can materialize partitions without owning the table).
-- Lock EXECUTE down to the app roles rather than the default PUBLIC, since a
-- SECURITY DEFINER function executable by PUBLIC is an escalation surface.
REVOKE EXECUTE ON FUNCTION audit.create_activity_logs_partition(integer, integer) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION audit.ensure_future_partitions(integer)                FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION audit.create_activity_logs_partition(integer, integer) TO crypto_app, crypto_bypass;
GRANT  EXECUTE ON FUNCTION audit.ensure_future_partitions(integer)                TO crypto_app, crypto_bypass;


-- Future objects the owner creates in later migrations are reachable too.
ALTER DEFAULT PRIVILEGES FOR ROLE crypto_user IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO crypto_app, crypto_bypass;
ALTER DEFAULT PRIVILEGES FOR ROLE crypto_user IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO crypto_app, crypto_bypass;
ALTER DEFAULT PRIVILEGES FOR ROLE crypto_user IN SCHEMA audit
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO crypto_app, crypto_bypass;
ALTER DEFAULT PRIVILEGES FOR ROLE crypto_user IN SCHEMA audit
  GRANT USAGE, SELECT ON SEQUENCES TO crypto_app, crypto_bypass;


-- ============================================================================
-- RLS HYBRID-TABLE POLICY REFINEMENT (ADR platform-0001, follow-up to Phase 0)
-- ============================================================================
-- These tables mix per-tenant rows with platform/built-in rows that carry
-- tenant_id IS NULL (industry-default alert rules, built-in port-heuristic
-- service-identification rules, the default onboarding workflow, platform-level
-- SIEM integrations and cost/log aggregates). The strict canonical policy would
-- hide those NULL-tenant rows once the app connects as the non-owner crypto_app
-- role, breaking the features that depend on the defaults.
--
-- Fix: USING allows the caller's own rows OR the global (tenant_id IS NULL) rows;
-- WITH CHECK stays strict so a tenant can only WRITE its own rows — the global
-- rows are seeded by migration/owner or written via the crypto_bypass role.
-- Idempotent (DROP POLICY IF EXISTS + CREATE).
DO $$
DECLARE t text;
BEGIN
  FOR t IN
    SELECT unnest(ARRAY[
      'audit.alert_rules','audit.alert_instances','audit.siem_integrations',
      'public.service_identification_rules','public.workflow_configurations',
      'public.aws_cost_data','public.aws_cost_sync_jobs','public.platform_log_metadata'
    ])
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %s',
                   split_part(t,'.',2)||'_tenant_isolation', t);
    EXECUTE format($f$CREATE POLICY %I ON %s
                     USING (tenant_id IS NULL OR tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
                     WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)$f$,
                   split_part(t,'.',2)||'_tenant_isolation', t);
  END LOOP;
END $$;


-- =========================================================================
-- Platform in-app notifications (admin-ui bell / operator inbox)
-- ============================================================================
-- Platform-scoped (tenant_id IS NULL) alerts previously had no in-app path —
-- the delivery service rejected them. This is the operator inbox behind the
-- admin-ui topbar bell. Global table (no RLS), same model as the other
-- platform_notification_* tables. Idempotent.
CREATE TABLE IF NOT EXISTS public.platform_in_app_notifications (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    type character varying(50) NOT NULL,
    title character varying(255) NOT NULL,
    message text NOT NULL,
    read_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_platform_notification_type CHECK (((type)::text = ANY ((ARRAY['alert'::character varying, 'discovery'::character varying, 'compliance'::character varying, 'system'::character varying, 'billing'::character varying, 'security'::character varying, 'audit'::character varying, 'other'::character varying])::text[])))
);


CREATE INDEX IF NOT EXISTS idx_platform_in_app_notifications_created_at
    ON public.platform_in_app_notifications (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_platform_in_app_notifications_unread
    ON public.platform_in_app_notifications (created_at DESC) WHERE read_at IS NULL;


-- ============================================================================
-- Stateful alerts + append-only evidence events ()
-- ============================================================================
-- An alert is a stateful condition demanding attention: severity + lifecycle
-- active → acknowledged → snoozed → resolved. alert_events is the append-only
-- evidence chain (who acknowledged/snoozed/resolved, when, and — for
-- auto-resolves — the system's observation that the condition cleared).
-- Owned by compliance-engine. RLS tenant-isolated. See
-- docsv4/internal/developer/design/NOTIFICATION_ALERTING_ARCHITECTURE.md §9.
CREATE TABLE IF NOT EXISTS public.alerts (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    tenant_id uuid NOT NULL,
    alert_type character varying(100) NOT NULL,
    source character varying(50) NOT NULL,
    subject_type character varying(50),
    subject_id uuid,
    subject_label text,
    severity character varying(20) NOT NULL,
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    title character varying(500) NOT NULL,
    message text,
    metadata jsonb DEFAULT '{}'::jsonb,
    acknowledged_by uuid,
    acknowledged_at timestamp with time zone,
    snoozed_by uuid,
    snoozed_until timestamp with time zone,
    snooze_reason text,
    resolved_at timestamp with time zone,
    resolved_by uuid,
    resolution character varying(10),
    resolution_note text,
    resolution_observation jsonb,
    ticket_id uuid,
    first_raised_at timestamp with time zone DEFAULT now() NOT NULL,
    last_event_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT alerts_severity_check CHECK (((severity)::text = ANY ((ARRAY['critical'::character varying, 'high'::character varying, 'medium'::character varying, 'low'::character varying, 'info'::character varying])::text[]))),
    CONSTRAINT alerts_status_check CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'acknowledged'::character varying, 'snoozed'::character varying, 'resolved'::character varying])::text[]))),
    CONSTRAINT alerts_resolution_check CHECK ((resolution IS NULL OR (resolution)::text = ANY ((ARRAY['manual'::character varying, 'auto'::character varying])::text[])))
);


-- One OPEN alert per (tenant, type, subject): repeated raises escalate the
-- existing alert instead of fragmenting into duplicates.
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_open_dedup
    ON public.alerts (tenant_id, alert_type, COALESCE(subject_id, '00000000-0000-0000-0000-000000000000'::uuid))
    WHERE ((status)::text <> 'resolved');
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_status ON public.alerts (tenant_id, status, last_event_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_snoozed_until ON public.alerts (snoozed_until) WHERE ((status)::text = 'snoozed');


CREATE TABLE IF NOT EXISTS public.alert_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    alert_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    event_type character varying(30) NOT NULL,
    actor_type character varying(10) DEFAULT 'system'::character varying NOT NULL,
    actor_id uuid,
    details jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT alert_events_type_check CHECK (((event_type)::text = ANY ((ARRAY['opened'::character varying, 'severity_changed'::character varying, 'acknowledged'::character varying, 'snoozed'::character varying, 'unsnoozed'::character varying, 'ticket_linked'::character varying, 'resolved'::character varying])::text[]))),
    CONSTRAINT alert_events_actor_check CHECK (((actor_type)::text = ANY ((ARRAY['system'::character varying, 'user'::character varying])::text[])))
);


DO $$ BEGIN
  IF to_regclass('public.alert_events') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'alert_events_alert_fk' AND conrelid = to_regclass('public.alert_events')) THEN
    ALTER TABLE public.alert_events
      ADD CONSTRAINT alert_events_alert_fk FOREIGN KEY (alert_id) REFERENCES public.alerts(id) ON DELETE CASCADE;
  END IF;
END $$;


CREATE INDEX IF NOT EXISTS idx_alert_events_alert ON public.alert_events (alert_id, created_at);


-- Ticket ↔ alert bridge: a ticket created from an alert records its origin.
CREATE INDEX IF NOT EXISTS idx_tickets_alert ON public.tickets (alert_id) WHERE (alert_id IS NOT NULL);


ALTER TABLE public.alerts ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS alerts_tenant_isolation ON public.alerts;
CREATE POLICY alerts_tenant_isolation ON public.alerts
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.alert_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS alert_events_tenant_isolation ON public.alert_events;
CREATE POLICY alert_events_tenant_isolation ON public.alert_events
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);


-- ============================================================================
-- Tenant alert catalog settings (alert-type registry, §8.2)
-- ============================================================================
-- Per-tenant state over the registry catalog: enable/disable a type and
-- optionally replace the product baseline rung with the tenant's own
-- preference rung ({"days": 45} for time ladders, {"percent": 90} for
-- quota ladders). Absence of a row = registry defaults apply. Policy rungs
-- (from activated frameworks) are additive and are NOT stored here.
CREATE TABLE IF NOT EXISTS public.tenant_alert_settings (
    tenant_id uuid NOT NULL,
    alert_type character varying(100) NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    preference_rung jsonb,
    updated_by uuid,
    updated_at timestamp with time zone DEFAULT now(),
    PRIMARY KEY (tenant_id, alert_type)
);


ALTER TABLE public.tenant_alert_settings ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_alert_settings_tenant_isolation ON public.tenant_alert_settings;
CREATE POLICY tenant_alert_settings_tenant_isolation ON public.tenant_alert_settings
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);


-- Detector-internal score history for the compliance_score_drop alert.
-- tenant_framework_scores keeps only the current score; this lightweight trail
-- lets the compliance-engine score-drop scan job compare against the value
-- ~24h ago. Written and pruned only by that job (no tenant-facing API, no RLS
-- policy — every query filters by tenant_id explicitly).
CREATE TABLE IF NOT EXISTS public.alert_framework_score_snapshots (
    tenant_id uuid NOT NULL,
    platform_framework_id uuid NOT NULL,
    score integer NOT NULL,
    captured_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_framework_score_snapshots_lookup
    ON public.alert_framework_score_snapshots (tenant_id, platform_framework_id, captured_at);


-- Digest/batched notification delivery. Rules with frequency 'digest_*'
-- accumulate matched notifications here per (scope, channel); a flush worker
-- composes one batched notification per group when the oldest item's window
-- elapses. tenant_id NULL = platform scope (mirrors notification_history).
CREATE TABLE IF NOT EXISTS public.notification_digest_queue (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    channel_id uuid NOT NULL,
    channel_type character varying(50) NOT NULL,
    notification_type character varying(50) DEFAULT 'alert'::character varying NOT NULL,
    alert_source character varying(50) NOT NULL,
    alert_type character varying(100) NOT NULL,
    severity character varying(20) NOT NULL,
    message text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    flush_after timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notification_digest_queue_flush
    ON public.notification_digest_queue (channel_id, flush_after);
ALTER TABLE public.notification_digest_queue ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS notification_digest_queue_tenant_isolation ON public.notification_digest_queue;
CREATE POLICY notification_digest_queue_tenant_isolation ON public.notification_digest_queue
  USING (tenant_id IS NULL OR tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);


-- Platform maintenance windows (storm control §10.3): while an active window is
-- in effect, notification-service suppresses delivery. Platform-scoped (no
-- tenant_id, no RLS — like platform_in_app_notifications); managed by platform
-- admins via /notification-service/platform/maintenance-windows.
CREATE TABLE IF NOT EXISTS public.platform_maintenance_windows (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    starts_at timestamp with time zone NOT NULL,
    ends_at timestamp with time zone NOT NULL,
    reason text,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_platform_maintenance_windows_active
    ON public.platform_maintenance_windows (starts_at, ends_at);


-- =========================================================================
-- LEGAL DOCUMENTS & ACCEPTANCE TRACKING (Terms of Service / Privacy Policy)
--
-- Platform admins author versioned legal documents (Settings -> Legal in
-- admin-ui). Each publish creates a NEW immutable version row; the previously
-- current row for that doc_type is demoted. Tenants accept the current version
-- at signup (enforced server-side) and are re-prompted on next login whenever
-- a newer version is published. Acceptance rows are an append-only legal
-- evidence trail: exact version + content hash + server-observed IP/UA + time.
--
-- legal_documents is platform-global (no tenant scope, no RLS) — the same
-- document text is shown to every tenant and must be readable unauthenticated
-- (signup page). legal_acceptances is tenant data and RLS-isolated like scopes.
-- =========================================================================


-- Platform-authored, versioned legal documents. Immutable per (doc_type, version).
CREATE TABLE IF NOT EXISTS public.legal_documents (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    doc_type character varying(50) NOT NULL,          -- 'terms_of_service' | 'privacy_policy'
    version integer NOT NULL,                          -- monotonic per doc_type, 1-based
    title character varying(255) NOT NULL,
    body text NOT NULL,                                -- document content (markdown/plain)
    content_hash character varying(64) NOT NULL,       -- sha256 hex of body; pins acceptances
    is_current boolean DEFAULT false NOT NULL,         -- exactly one true per doc_type
    effective_date timestamp with time zone DEFAULT now() NOT NULL,
    published_by uuid,                                 -- platform_users.id (NULL = system seed)
    published_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT legal_documents_pkey PRIMARY KEY (id),
    CONSTRAINT legal_documents_type_version_unique UNIQUE (doc_type, version),
    CONSTRAINT legal_documents_doc_type_check CHECK (doc_type IN ('terms_of_service', 'privacy_policy'))
);
-- At most one current version per doc_type.
CREATE UNIQUE INDEX IF NOT EXISTS idx_legal_documents_current
    ON public.legal_documents USING btree (doc_type) WHERE (is_current = true);
CREATE INDEX IF NOT EXISTS idx_legal_documents_type_version
    ON public.legal_documents USING btree (doc_type, version DESC);


-- Append-only acceptance ledger. One row per (user, document version) acceptance.
CREATE TABLE IF NOT EXISTS public.legal_acceptances (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    doc_type character varying(50) NOT NULL,
    document_id uuid NOT NULL,                         -- legal_documents.id (which version)
    version integer NOT NULL,
    content_hash character varying(64) NOT NULL,       -- copy of the accepted version's hash
    accepted_at timestamp with time zone DEFAULT now() NOT NULL,
    accepted_ip character varying(45),                 -- server-observed, IPv4/IPv6
    user_agent text,                                   -- server-observed
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT legal_acceptances_pkey PRIMARY KEY (id),
    CONSTRAINT legal_acceptances_user_document_unique UNIQUE (user_id, document_id)
);
CREATE INDEX IF NOT EXISTS idx_legal_acceptances_tenant_user
    ON public.legal_acceptances USING btree (tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_legal_acceptances_tenant_time
    ON public.legal_acceptances USING btree (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_legal_acceptances_document
    ON public.legal_acceptances USING btree (document_id);
-- Tenant isolation. This table is created below the canonical RLS HARDENING
-- block, so unlike every other policy it must be declared here — the block
-- cannot reference a table that does not exist yet.
--
-- DROP + CREATE, not the old DO/EXCEPTION duplicate_object form: that form
-- cannot UPDATE an existing policy, so on an already-installed database it
-- would hit the duplicate and silently leave the previous definition in force.
-- That is why this policy stayed USING-only through several releases.
--
-- WITH CHECK is safe here: every writer uses the BYPASSRLS crypto_bypass handle
-- (auth-service handlers.go signup paths, ee/sso platform_sso.go, and
-- AcceptLegalDocuments, which router.go wires with bypassDB), so the check is
-- never evaluated against them and ToS/Privacy acceptance is unaffected —
-- verified against a real Postgres, contrary to the original analysis.
ALTER TABLE public.legal_acceptances ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS legal_acceptances_tenant_isolation ON public.legal_acceptances;
CREATE POLICY legal_acceptances_tenant_isolation ON public.legal_acceptances
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);


-- =========================================================================
-- Cryptographic-key inventory producer (Keys lens) — unique dedup identity.
-- The key producer (services/inventory-service/internal/services/key_producer.go)
-- upserts one public-key row per discovered certificate public key, keyed on
-- (tenant_id, public_fingerprint) so the same key across renewals/hosts
-- collapses to a single row (which drives the lens "used by N assets" count).
-- This partial UNIQUE index backs that ON CONFLICT target. Idempotent; the keys
-- table had no producer before this, so no pre-dedup is required.
-- =========================================================================
CREATE UNIQUE INDEX IF NOT EXISTS keys_tenant_public_fingerprint_uniq
    ON public.keys USING btree (tenant_id, public_fingerprint)
    WHERE (public_fingerprint IS NOT NULL);


-- =========================================================================
CREATE INDEX IF NOT EXISTS idx_service_accounts_token_lookup
    ON public.service_accounts USING btree (token_lookup)
    WHERE (token_lookup IS NOT NULL);


-- ============================================================================
-- W2-2 SELF-CHECK: no tenant-isolation policy may survive on the old,
-- unindexable `(tenant_id)::text = current_setting(...)` predicate.
--
-- This is deliberately a WARNING and not an exception: a stray old-shape policy
-- is a performance regression, not a correctness or isolation failure, and
-- failing the schema-migration Job over one would take a customer's upgrade
-- down for a reason that does not warrant it. The message names every offender
-- so it is actionable from the Job log.
--
-- Mutation-tested: reverting a single policy to the old predicate makes this
-- block emit the WARNING naming exactly that policy.
-- ============================================================================
DO $$
DECLARE
    stale text;
BEGIN
    SELECT string_agg(format('%s ON %s', p.polname, c.oid::regclass), ', ' ORDER BY p.polname)
      INTO stale
      FROM pg_policy p
      JOIN pg_class c ON c.oid = p.polrelid
     WHERE pg_get_expr(p.polqual, p.polrelid) LIKE '%tenant_id)::text = current_setting%'
        OR pg_get_expr(p.polwithcheck, p.polrelid) LIKE '%tenant_id)::text = current_setting%';


    IF stale IS NOT NULL THEN
        RAISE WARNING 'W2-2: % RLS policies still use the unindexable (tenant_id)::text predicate: %',
            array_length(string_to_array(stale, ', '), 1), stale;
    END IF;
END $$;


-- =========================================================================
-- =========================================================================
-- RETAINED: legacy-table retirement drops
--
-- These are the one part of the old POST-MIGRATIONS block that is deliberately
-- NOT collapsed, because it is not expressible as base DDL: you cannot express
-- "do not have this table" in a CREATE statement. Nothing in this file creates
-- or references a *_legacy relation any more, so on a fresh install all three
-- are no-ops — they exist so a cluster installed before the partition
-- conversion loses the drained residue and everything stale that pinned it
-- (junction FKs that broke populated re-applies, views that made CMDB sync and
-- the remediation queue silently empty, FKs that kept
-- external_connections.source_asset_id NULL forever).
--
-- scripts/audit-legacy-residue.mjs enforces BOTH directions in `make audit`:
-- nothing may reference a *_legacy relation, and these three drops may not be
-- deleted. Do not remove them to tidy the file.
-- =========================================================================
DROP TABLE IF EXISTS public.crypto_implementations_legacy CASCADE;
DROP TABLE IF EXISTS public.sensor_discoveries_legacy CASCADE;
DROP TABLE IF EXISTS public.network_assets_legacy CASCADE;

-- Retired: the experimental source-code crypto scanner was removed
-- from the product (unreachable — it had no UI, no feature flag and no consumer
-- outside its own handler). Nothing in this file creates or references
-- crypto_code_findings any more, so on a fresh install this is a no-op; it
-- exists so a cluster installed before the removal drops the orphaned table.
DROP TABLE IF EXISTS public.crypto_code_findings CASCADE;


-- ============================================================================
-- VIEW ISOLATION HARDENING (close the security_invoker gap left by Phase 4)
-- ============================================================================
-- A plain view executes with its OWNER's privileges, and the owner
-- (crypto_user) both owns the base tables and is exempt from their RLS —
-- so every view below was a cross-tenant read path for the NOBYPASSRLS
-- crypto_app role. Only the three partition-wrapper views (network_assets,
-- sensor_discoveries, crypto_implementations, flipped above) had
-- security_invoker. Flip every remaining view whose base tables carry a
-- tenant_isolation policy, so RLS applies to the querying role exactly as it
-- would on the tables themselves. Deliberately NOT flipped: v_tenants,
-- platform_administrators, platform_metrics_aggregations and
-- audit.partition_info (no RLS base tables — platform/catalog data), and the
-- materialized views (security_invoker does not exist for matviews; they are
-- handled by REVOKE + tenant-scoped wrapper views below).
--
-- This block must stay AFTER every CREATE OR REPLACE VIEW / matview
-- DROP+CREATE above so a re-apply always leaves the flag set.
-- Idempotent: ALTER VIEW ... SET is a plain reloption write.
ALTER VIEW public.active_resource_alerts        SET (security_invoker = true);
ALTER VIEW public.aws_daily_cost_summary        SET (security_invoker = true);
ALTER VIEW public.aws_daily_service_cost_summary SET (security_invoker = true);
ALTER VIEW public.aws_tenant_monthly_cost_summary SET (security_invoker = true);
ALTER VIEW public.current_resource_usage_summary SET (security_invoker = true);
ALTER VIEW public.health_metrics_aggregated_view SET (security_invoker = true);
ALTER VIEW public.platform_integrations_summary SET (security_invoker = true);
ALTER VIEW public.tenant_health_summary_view    SET (security_invoker = true);
ALTER VIEW public.user_tenant_permissions       SET (security_invoker = true);
ALTER VIEW public.v_ci_inventory                SET (security_invoker = true);


-- Materialized views hold cross-tenant data by construction (populated by the
-- owner at REFRESH time; RLS and security_invoker are structurally
-- inapplicable). Give the app role a tenant-scoped face instead:
--
--   1. A wrapper view per consumed matview, executing as the owner
--      (deliberately NOT security_invoker — it must read the matview after
--      the REVOKE below) with the same fail-closed predicate the
--      tenant_isolation policies use: no app.tenant_id context => zero rows.
--   2. REVOKE direct matview access from crypto_app. crypto_bypass keeps it
--      (BYPASSRLS is the deliberate cross-tenant lane).
--
-- Created here, after the matview DROP ... CASCADE + re-CREATE above, because
-- that CASCADE takes the wrappers with it on every re-apply.
CREATE OR REPLACE VIEW public.mv_location_finding_summary_tenant AS
  SELECT * FROM public.mv_location_finding_summary
  WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid;

CREATE OR REPLACE VIEW public.mv_remediation_queue_tenant AS
  SELECT * FROM public.mv_remediation_queue
  WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid;

-- The REVOKEs that keep crypto_app off the raw matviews, and the SELECT grants
-- on these wrapper views, are NOT here: they must run AFTER the blanket
-- `GRANT ... ON ALL TABLES` (which covers views and matviews too), and that
-- block now lives at the very end of this file. See ROLE GRANTS there.

-- The refresh functions are SECURITY DEFINER (REFRESH requires matview
-- ownership — see their definitions). Same hygiene as the other definer
-- functions: not executable by PUBLIC, only by the app roles.
REVOKE EXECUTE ON FUNCTION public.refresh_operational_views()  FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.refresh_tenant_cost_summary() FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION public.refresh_operational_views()  TO crypto_app, crypto_bypass;
GRANT  EXECUTE ON FUNCTION public.refresh_tenant_cost_summary() TO crypto_app, crypto_bypass;

-- ---------------------------------------------------------------------------
-- agent_addresses: indexes, isolation, and the device_agents primary-address
-- column. The table itself is defined next to `sensors` in the body above.
-- ---------------------------------------------------------------------------

-- Existing databases predate the column; fresh ones already have it from the
-- CREATE TABLE. Both paths converge here.
ALTER TABLE public.device_agents ADD COLUMN IF NOT EXISTS ip_address character varying(45);

-- Owner foreign keys. Guarded rather than DROP-then-ADD so re-applying never
-- momentarily removes a constraint other objects depend on. ON DELETE CASCADE:
-- an agent's addresses are facts about that agent and have no meaning without it.
DO $$ BEGIN
  IF to_regclass('public.agent_addresses') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'agent_addresses_sensor_id_fkey' AND conrelid = to_regclass('public.agent_addresses'))
  THEN
    ALTER TABLE ONLY public.agent_addresses
        ADD CONSTRAINT agent_addresses_sensor_id_fkey FOREIGN KEY (sensor_id) REFERENCES public.sensors(id) ON DELETE CASCADE;
  END IF;
END $$;

DO $$ BEGIN
  IF to_regclass('public.agent_addresses') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'agent_addresses_device_agent_id_fkey' AND conrelid = to_regclass('public.agent_addresses'))
  THEN
    ALTER TABLE ONLY public.agent_addresses
        ADD CONSTRAINT agent_addresses_device_agent_id_fkey FOREIGN KEY (device_agent_id) REFERENCES public.device_agents(id) ON DELETE CASCADE;
  END IF;
END $$;

-- An agent reports each address once per interface. The partial indexes are
-- split by owner because a plain UNIQUE over (sensor_id, device_agent_id, ...)
-- would not constrain anything: NULLs never conflict, so every device-agent row
-- would be trivially unique on the sensor side and vice versa.
CREATE UNIQUE INDEX IF NOT EXISTS agent_addresses_sensor_iface_addr_key
    ON public.agent_addresses (sensor_id, interface_name, address)
    WHERE sensor_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS agent_addresses_device_agent_iface_addr_key
    ON public.agent_addresses (device_agent_id, interface_name, address)
    WHERE device_agent_id IS NOT NULL;

-- At most one primary address per agent. Enforcing it here rather than in Go
-- means a reconcile bug surfaces as a failed write instead of a fleet view that
-- quietly shows two primaries for the same host.
CREATE UNIQUE INDEX IF NOT EXISTS agent_addresses_one_primary_per_sensor
    ON public.agent_addresses (sensor_id)
    WHERE sensor_id IS NOT NULL AND is_primary;
CREATE UNIQUE INDEX IF NOT EXISTS agent_addresses_one_primary_per_device_agent
    ON public.agent_addresses (device_agent_id)
    WHERE device_agent_id IS NOT NULL AND is_primary;

CREATE INDEX IF NOT EXISTS idx_agent_addresses_sensor ON public.agent_addresses (sensor_id);
CREATE INDEX IF NOT EXISTS idx_agent_addresses_device_agent ON public.agent_addresses (device_agent_id);
-- Coverage lookups ("who sees this address/segment?") scan by address.
CREATE INDEX IF NOT EXISTS idx_agent_addresses_address ON public.agent_addresses (address);

-- Tenant isolation is inherited from whichever owner the row hangs off, mirroring
-- sensor_health_metrics / sensor_commands. Both arms are needed because the owner
-- may be either runtime; the CHECK constraint guarantees exactly one is set.
ALTER TABLE public.agent_addresses ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agent_addresses_tenant_isolation ON public.agent_addresses;
CREATE POLICY agent_addresses_tenant_isolation ON public.agent_addresses
  USING (
    EXISTS (SELECT 1 FROM public.sensors s WHERE s.id = agent_addresses.sensor_id AND s.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    OR EXISTS (SELECT 1 FROM public.device_agents a WHERE a.id = agent_addresses.device_agent_id AND a.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  )
  WITH CHECK (
    EXISTS (SELECT 1 FROM public.sensors s WHERE s.id = agent_addresses.sensor_id AND s.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    OR EXISTS (SELECT 1 FROM public.device_agents a WHERE a.id = agent_addresses.device_agent_id AND a.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  );

GRANT SELECT, INSERT, UPDATE, DELETE ON public.agent_addresses TO crypto_app, crypto_bypass;

-- discovery_auto_approval_rules.created_by must allow NULL: segment saves made
-- under HMAC service auth (no user context) still need to create the rule the
-- discovery-processor auto-approves from. With NOT NULL, such saves persisted
-- auto_approve_discoveries=true on network_segments but silently never created
-- the rule, so the flag and behavior desynced (observed live on a dev
-- cluster; PR "Known follow-up"). The CREATE TABLE in the pg_dump body
-- was updated in the same change; this ALTER upgrades existing databases.
-- DROP NOT NULL is a no-op when the column is already nullable, so this is
-- safely re-appliable.
ALTER TABLE IF EXISTS public.discovery_auto_approval_rules ALTER COLUMN created_by DROP NOT NULL;


-- Backfill: give the seeded "Default activity feed" rule the `info` severity.
--
-- seedDefaultNotificationPack shipped this rule as ARRAY['medium','low'], and
-- nothing covered 'info'. That is not a spare band — asset_limit_approaching
-- opens there at its 80% rung, billing notifications are emitted there, and
-- notification-service's NormalizeSeverity degrades ANY unrecognized producer
-- severity to 'info'. An unmatched notification is written status='sent' with
-- channels_used={}, so it looked delivered while reaching nobody.
--
-- The create-time fix (services/auth-service/internal/auth/service.go) only
-- helps tenants created after it ships; every existing tenant keeps the broken
-- rule. Hence this backfill.
--
-- Scoped deliberately narrowly: it matches only rules that still carry BOTH the
-- shipped name and the exact shipped severity array, so a tenant who edited
-- their routing — including one who removed 'medium' or 'low' on purpose — is
-- never overwritten. Re-appliable: after the first run no row matches the WHERE
-- clause, so subsequent applies update nothing.
UPDATE public.tenant_notification_rules
   SET severity_filter = ARRAY['medium','low','info']::varchar[]
 WHERE rule_name = 'Default activity feed'
   AND severity_filter = ARRAY['medium','low']::varchar[];


-- Tenant-triggered compliance re-evaluation: the persisted per-tenant cooldown.
-- One row per tenant, holding the last ACCEPTED manual re-evaluation request.
--
-- Persisted, not in-process, deliberately: compliance-engine runs multiple
-- replicas and its Deployment rolls on every config change, so an in-memory
-- timer resets on restart and disagrees between pods — a tenant could retry
-- until it hit a fresh pod. The claim is a single conditional upsert, so the
-- database arbitrates and two concurrent requests on two pods cannot both win.
--
-- Platform-admin re-evaluation (/admin/tenants/{id}/reevaluate) deliberately
-- does NOT touch this table: it is the unbounded escape hatch after an engine
-- fix or a bulk import (owner decision, 2026-08).
CREATE TABLE IF NOT EXISTS public.tenant_reevaluation_requests (
    tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    last_requested_at timestamp with time zone DEFAULT now() NOT NULL,
    last_requested_by uuid,
    request_count integer DEFAULT 0 NOT NULL,
    CONSTRAINT tenant_reevaluation_requests_pkey PRIMARY KEY (tenant_id)
);

ALTER TABLE public.tenant_reevaluation_requests ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_reevaluation_requests_tenant_isolation ON public.tenant_reevaluation_requests;
CREATE POLICY tenant_reevaluation_requests_tenant_isolation ON public.tenant_reevaluation_requests
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);


-- ============================================================================
-- AT-REST ENCRYPTION POSTURE — crypto_applications natural key
-- ============================================================================
-- crypto_applications is the at-rest sibling of crypto_implementations: one row
-- per managed resource (S3 bucket, RDS instance, …) per encryption context.
-- inventory-service's at-rest producer UPSERTs on re-discovery, so the table
-- needs a unique key to conflict on; without it every discovery run appended a
-- duplicate row for the same bucket.
--
-- (tenant_id, resource_identifier, encryption_context) is the natural key: a
-- resource ARN is globally unique, and the same resource can legitimately carry
-- separate at_rest and in_transit rows. Partial on deleted_at IS NULL so a
-- soft-deleted row never blocks re-discovery of the same resource.
CREATE UNIQUE INDEX IF NOT EXISTS uq_crypto_applications_tenant_resource_context
    ON public.crypto_applications (tenant_id, resource_identifier, encryption_context)
    WHERE deleted_at IS NULL;


-- ============================================================================
-- ROLE GRANTS — THIS BLOCK MUST BE THE LAST THING IN THIS FILE
-- ============================================================================
-- `GRANT ... ON ALL TABLES IN SCHEMA x` is not a standing rule: Postgres
-- expands it once, right now, over the tables that exist at that instant. A
-- table created later in the same file therefore gets nothing.
--
-- That is exactly what happened while this block sat in the middle of the file
-- (RLS ROLE SPLIT section): nine tables defined below it — alerts,
-- alert_events, alert_framework_score_snapshots, legal_acceptances,
-- legal_documents, notification_digest_queue, platform_in_app_notifications,
-- platform_maintenance_windows, tenant_alert_settings — had zero privileges for
-- crypto_app after a fresh single apply. Since serviceRls defaults to ON,
-- services connect as crypto_app, and the chart's schema-migration Job applies
-- this file ONCE on install, a brand-new install answered `permission denied
-- for table alerts` on the whole Remediation → Alerts surface, the notification
-- digest queue, the platform operator inbox, and the ToS/Privacy acceptance
-- write on the signup path. A second apply hid the bug, which is why it lived
-- so long.
--
-- Keeping the grants LAST is the only shape that cannot silently regress: a new
-- CREATE TABLE appended to this file is, by construction, above them.
-- `scripts/audit-schema-grant-order.mjs` (run strict by `make audit`, and by
-- the pre-commit hook) fails if any table-creating statement appears after this
-- marker, so the invariant is enforced rather than merely documented.
--
-- Idempotent: GRANT/REVOKE are unconditional writes to the ACL.

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO crypto_app, crypto_bypass;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA audit  TO crypto_app, crypto_bypass;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO crypto_app, crypto_bypass;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA audit  TO crypto_app, crypto_bypass;

-- Deliberate narrowings. These MUST stay after the blanket grants above, which
-- cover views and materialized views as well as tables.
--
-- Materialized views hold cross-tenant data by construction (the owner
-- populates them at REFRESH time; RLS and security_invoker are structurally
-- inapplicable to them). crypto_app reads them only through the tenant-scoped
-- `*_tenant` wrapper views created earlier in this file; crypto_bypass keeps
-- direct access, since BYPASSRLS is the deliberate cross-tenant lane.
REVOKE ALL ON public.mv_location_finding_summary FROM crypto_app;
REVOKE ALL ON public.mv_remediation_queue        FROM crypto_app;
REVOKE ALL ON public.tenant_cost_summary         FROM crypto_app;

-- REVOKE first: the blanket GRANT above covers views too, so on a re-apply the
-- wrappers pick up INSERT/UPDATE/DELETE they must not have. (This used to be
-- masked by a matview DROP ... CASCADE that deleted the wrappers before the
-- grant ran — an accident of ordering, not a decision.) Read-only, stated
-- outright.
REVOKE ALL ON public.mv_location_finding_summary_tenant FROM crypto_app, crypto_bypass;
REVOKE ALL ON public.mv_remediation_queue_tenant        FROM crypto_app, crypto_bypass;
GRANT SELECT ON public.mv_location_finding_summary_tenant TO crypto_app, crypto_bypass;
GRANT SELECT ON public.mv_remediation_queue_tenant        TO crypto_app, crypto_bypass;
