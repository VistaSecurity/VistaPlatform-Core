-- =================================================================
-- DemoCorp Tenant Erasure
-- =================================================================
-- Deletes the entire DemoCorp tenant and all associated data
-- This will cascade delete all related records (users, assets, certificates, etc.)
-- =================================================================

DO $$
DECLARE
    v_tenant_id UUID;
    asset_count INTEGER;
    cert_count INTEGER;
    impl_count INTEGER;
    device_count INTEGER;
    user_count INTEGER;
BEGIN
    -- Get DemoCorp tenant ID (use v_tenant_id to avoid shadowing table columns)
    SELECT id INTO v_tenant_id FROM tenants WHERE slug = 'democorp' LIMIT 1;

    IF v_tenant_id IS NULL THEN
        RAISE NOTICE 'DemoCorp tenant not found. Nothing to erase.';
        RETURN;
    END IF;

    -- Count records before deletion
    SELECT COUNT(*) INTO asset_count FROM network_assets WHERE tenant_id = v_tenant_id AND deleted_at IS NULL;
    SELECT COUNT(*) INTO cert_count FROM certificates WHERE tenant_id = v_tenant_id;
    SELECT COUNT(*) INTO impl_count FROM crypto_implementations WHERE tenant_id = v_tenant_id AND deleted_at IS NULL;
    SELECT COUNT(*) INTO device_count FROM devices WHERE tenant_id = v_tenant_id AND deleted_at IS NULL;
    SELECT COUNT(*) INTO user_count FROM users WHERE tenant_id = v_tenant_id AND deleted_at IS NULL;

    RAISE NOTICE 'Deleting DemoCorp tenant and all associated data...';
    RAISE NOTICE '  Assets: %', asset_count;
    RAISE NOTICE '  Certificates: %', cert_count;
    RAISE NOTICE '  Crypto Configurations: %', impl_count;
    RAISE NOTICE '  Devices: %', device_count;
    RAISE NOTICE '  Users: %', user_count;

    -- Delete in dependency order: tables that reference tenants(id) or users(id) without ON DELETE CASCADE
    DELETE FROM user_workflow_progress WHERE workflow_configuration_id IN (SELECT id FROM workflow_configurations WHERE tenant_id = v_tenant_id);
    DELETE FROM workflow_configurations WHERE tenant_id = v_tenant_id;
    DELETE FROM feature_usage_events WHERE tenant_id = v_tenant_id;
    DELETE FROM auth_audit_log WHERE tenant_id = v_tenant_id;
    DELETE FROM permission_audit_logs WHERE tenant_id = v_tenant_id;
    DELETE FROM resource_permissions WHERE tenant_id = v_tenant_id;
    DELETE FROM refresh_tokens WHERE user_id IN (SELECT id FROM users WHERE tenant_id = v_tenant_id);
    DELETE FROM users WHERE tenant_id = v_tenant_id;
    DELETE FROM sso_providers WHERE tenant_id = v_tenant_id;
    DELETE FROM tenant_usage WHERE tenant_id = v_tenant_id;
    DELETE FROM api_format_preferences WHERE tenant_id = v_tenant_id;

    -- Delete tenant (cascades to all tables with ON DELETE CASCADE)
    DELETE FROM tenants WHERE id = v_tenant_id;

    RAISE NOTICE 'DemoCorp tenant and all data deleted successfully.';
END $$;
