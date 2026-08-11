-- =================================================================
-- DemoCorp Data Erasure (Keep Tenant and Users)
-- =================================================================
-- Deletes only the inventory data (assets, certificates, crypto configurations, devices)
-- Keeps the tenant and users intact
-- =================================================================

DO $$
DECLARE
    v_tenant_id UUID;
    asset_count INTEGER;
    cert_count INTEGER;
    impl_count INTEGER;
    device_count INTEGER;
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

    RAISE NOTICE 'Deleting DemoCorp inventory data (keeping tenant and users)...';
    RAISE NOTICE '  Assets: %', asset_count;
    RAISE NOTICE '  Certificates: %', cert_count;
    RAISE NOTICE '  Crypto Configurations: %', impl_count;
    RAISE NOTICE '  Devices: %', device_count;

    -- Hard delete crypto_implementations first (they reference certificates)
    DELETE FROM crypto_implementations WHERE tenant_id = v_tenant_id;

    -- Delete certificates (hard delete, no soft delete)
    DELETE FROM certificates WHERE tenant_id = v_tenant_id;

    -- Soft delete infrastructure assets (network_assets)
    UPDATE network_assets SET deleted_at = NOW() WHERE tenant_id = v_tenant_id AND deleted_at IS NULL;

    -- Soft delete devices
    UPDATE devices SET deleted_at = NOW() WHERE tenant_id = v_tenant_id AND deleted_at IS NULL;

    -- Safeguard: ensure we did not remove tenant or users (this script must not touch them)
    IF (SELECT COUNT(*) FROM users WHERE tenant_id = v_tenant_id AND deleted_at IS NULL) = 0 THEN
        RAISE EXCEPTION 'DemoCorp users missing after erase-data. Tenant and users must remain. Aborting.';
    END IF;
    IF (SELECT COUNT(*) FROM tenants WHERE id = v_tenant_id AND deleted_at IS NULL) = 0 THEN
        RAISE EXCEPTION 'DemoCorp tenant missing after erase-data. This script must not delete the tenant. Aborting.';
    END IF;

    RAISE NOTICE 'DemoCorp inventory data deleted successfully.';
    RAISE NOTICE 'Tenant and users remain intact.';
END $$;
