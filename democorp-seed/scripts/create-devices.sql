-- =================================================================
-- DemoCorp Devices Creation
-- =================================================================
-- Creates physical and virtual devices for DemoCorp tenant
-- Devices include load balancers, firewalls, hypervisors, and routers
-- =================================================================

DO $$
DECLARE
    v_tenant_id UUID;
    device_id UUID;
BEGIN
    -- Get DemoCorp tenant ID (use v_tenant_id to avoid shadowing devices.tenant_id in ON CONFLICT)
    SELECT id INTO v_tenant_id FROM tenants WHERE slug = 'democorp' LIMIT 1;

    IF v_tenant_id IS NULL THEN
        RAISE EXCEPTION 'DemoCorp tenant not found. Run create-tenant.sql first.';
    END IF;

    -- =================================================================
    -- Data Center 1 Devices
    -- =================================================================

    -- Load Balancers
    INSERT INTO devices (id, tenant_id, device_type, vendor, model, hostname, ip_address, management_url, discovery_method, connection_status, created_at, updated_at)
    VALUES
        (gen_random_uuid(), v_tenant_id, 'f5', 'F5 Networks', 'BigIP-4200v', 'lb-prod-dc1-01.democorp.com', '10.0.5.10', 'https://10.0.5.10:443', 'device_interrogation', 'connected', NOW(), NOW()),
        (gen_random_uuid(), v_tenant_id, 'haproxy', 'HAProxy Technologies', 'HAProxy 2.8', 'lb-prod-dc1-02.democorp.com', '10.0.5.11', 'http://10.0.5.11:8404', 'device_interrogation', 'connected', NOW(), NOW()),
        (gen_random_uuid(), v_tenant_id, 'haproxy', 'HAProxy Technologies', 'HAProxy 2.8', 'lb-staging-dc1-01.democorp.com', '10.1.5.10', 'http://10.1.5.10:8404', 'device_interrogation', 'connected', NOW(), NOW())
    ON CONFLICT (tenant_id, device_type, management_url) WHERE deleted_at IS NULL DO NOTHING;

    -- Firewalls
    INSERT INTO devices (id, tenant_id, device_type, vendor, model, hostname, ip_address, management_url, discovery_method, connection_status, created_at, updated_at)
    VALUES
        (gen_random_uuid(), v_tenant_id, 'palo_alto', 'Palo Alto Networks', 'PA-5220', 'fw-prod-dc1-01.democorp.com', '10.0.5.20', 'https://10.0.5.20:443', 'device_interrogation', 'connected', NOW(), NOW()),
        (gen_random_uuid(), v_tenant_id, 'cisco_asa', 'Cisco', 'ASA-5525-X', 'fw-prod-dc1-02.democorp.com', '10.0.5.21', 'https://10.0.5.21:443', 'device_interrogation', 'connected', NOW(), NOW())
    ON CONFLICT (tenant_id, device_type, management_url) WHERE deleted_at IS NULL DO NOTHING;

    -- Hypervisors
    INSERT INTO devices (id, tenant_id, device_type, vendor, model, hostname, ip_address, management_url, discovery_method, connection_status, created_at, updated_at)
    VALUES
        (gen_random_uuid(), v_tenant_id, 'vmware_esxi', 'VMware', 'ESXi 8.0', 'hypervisor-dc1-01.democorp.com', '10.0.5.30', 'https://10.0.5.30:443', 'device_interrogation', 'connected', NOW(), NOW()),
        (gen_random_uuid(), v_tenant_id, 'vmware_esxi', 'VMware', 'ESXi 8.0', 'hypervisor-dc1-02.democorp.com', '10.0.5.31', 'https://10.0.5.31:443', 'device_interrogation', 'connected', NOW(), NOW()),
        (gen_random_uuid(), v_tenant_id, 'kvm', 'Red Hat', 'KVM/QEMU', 'hypervisor-dc1-03.democorp.com', '10.0.5.32', 'https://10.0.5.32:9090', 'device_interrogation', 'connected', NOW(), NOW())
    ON CONFLICT (tenant_id, device_type, management_url) WHERE deleted_at IS NULL DO NOTHING;

    -- Router
    INSERT INTO devices (id, tenant_id, device_type, vendor, model, hostname, ip_address, management_url, discovery_method, connection_status, created_at, updated_at)
    VALUES
        (gen_random_uuid(), v_tenant_id, 'cisco_router', 'Cisco', 'ASR-1000', 'router-dc1-core-01.democorp.com', '10.0.5.1', 'https://10.0.5.1:443', 'device_interrogation', 'connected', NOW(), NOW())
    ON CONFLICT (tenant_id, device_type, management_url) WHERE deleted_at IS NULL DO NOTHING;

    -- =================================================================
    -- Data Center 2 Devices
    -- =================================================================

    -- Load Balancers
    INSERT INTO devices (id, tenant_id, device_type, vendor, model, hostname, ip_address, management_url, discovery_method, connection_status, created_at, updated_at)
    VALUES
        (gen_random_uuid(), v_tenant_id, 'f5', 'F5 Networks', 'BigIP-4200v', 'lb-prod-dc2-01.democorp.com', '172.16.5.10', 'https://172.16.5.10:443', 'device_interrogation', 'connected', NOW(), NOW()),
        (gen_random_uuid(), v_tenant_id, 'haproxy', 'HAProxy Technologies', 'HAProxy 2.8', 'lb-prod-dc2-02.democorp.com', '172.16.5.11', 'http://172.16.5.11:8404', 'device_interrogation', 'connected', NOW(), NOW())
    ON CONFLICT (tenant_id, device_type, management_url) WHERE deleted_at IS NULL DO NOTHING;

    -- Firewall
    INSERT INTO devices (id, tenant_id, device_type, vendor, model, hostname, ip_address, management_url, discovery_method, connection_status, created_at, updated_at)
    VALUES
        (gen_random_uuid(), v_tenant_id, 'palo_alto', 'Palo Alto Networks', 'PA-5220', 'fw-prod-dc2-01.democorp.com', '172.16.5.20', 'https://172.16.5.20:443', 'device_interrogation', 'connected', NOW(), NOW())
    ON CONFLICT (tenant_id, device_type, management_url) WHERE deleted_at IS NULL DO NOTHING;

    -- Hypervisors
    INSERT INTO devices (id, tenant_id, device_type, vendor, model, hostname, ip_address, management_url, discovery_method, connection_status, created_at, updated_at)
    VALUES
        (gen_random_uuid(), v_tenant_id, 'vmware_esxi', 'VMware', 'ESXi 8.0', 'hypervisor-dc2-01.democorp.com', '172.16.5.30', 'https://172.16.5.30:443', 'device_interrogation', 'connected', NOW(), NOW()),
        (gen_random_uuid(), v_tenant_id, 'vmware_esxi', 'VMware', 'ESXi 8.0', 'hypervisor-dc2-02.democorp.com', '172.16.5.31', 'https://172.16.5.31:443', 'device_interrogation', 'connected', NOW(), NOW())
    ON CONFLICT (tenant_id, device_type, management_url) WHERE deleted_at IS NULL DO NOTHING;

    RAISE NOTICE 'DemoCorp devices created successfully';
END $$;

-- =================================================================
-- Verification
-- =================================================================

DO $$
DECLARE
    v_tenant_id UUID;
    device_count INTEGER;
BEGIN
    SELECT id INTO v_tenant_id FROM tenants WHERE slug = 'democorp' LIMIT 1;
    SELECT COUNT(*) INTO device_count FROM devices WHERE devices.tenant_id = v_tenant_id AND deleted_at IS NULL;

    RAISE NOTICE 'DemoCorp devices verification';
    RAISE NOTICE '  Tenant ID: %', v_tenant_id;
    RAISE NOTICE '  Devices: %', device_count;

    IF device_count < 13 THEN
        RAISE WARNING 'Expected ~13 devices, found %', device_count;
    END IF;
END $$;
