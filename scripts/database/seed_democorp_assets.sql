-- =================================================================
-- Demo Corporation - Comprehensive Asset Seed Data (Tier 2)
-- =================================================================
-- This script creates 240 varied infrastructure assets (network_assets
-- table) for democorp tenant with all required fields including
-- asset_status and asset_ownership.
--
-- CMDB Terminology:
--   network_assets table = "Infrastructure Assets" in UI/API v2
--   asset_type column maps to CMDB CI types (cmdb_ci_server, etc.)
--
-- This is part of Tier 2 demo data and should be loaded automatically
-- with load-demo-data.sh
-- =================================================================

-- =================================================================
-- Helper function to generate random data
-- =================================================================

-- Function to get random element from array
CREATE OR REPLACE FUNCTION random_array_element(arr TEXT[]) RETURNS TEXT AS $$
BEGIN
    RETURN arr[floor(random() * array_length(arr, 1)) + 1];
END;
$$ LANGUAGE plpgsql;

-- =================================================================
-- Demo Corporation Assets - Production Environment
-- =================================================================

-- Production Web Servers (20 assets)
INSERT INTO network_assets (tenant_id, hostname, ip_address, port, asset_type, operating_system, environment, business_unit, owner_email, description, tags, asset_status, asset_ownership, first_discovered_at, last_seen_at)
SELECT
    (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1),
    'web-prod-' || LPAD(i::text, 2, '0') || '.democorp.com',
    ('10.1.1.' || (10 + i))::inet,
    443,
    'server'::asset_type,
    random_array_element(ARRAY['Ubuntu 22.04', 'Ubuntu 20.04', 'CentOS 8', 'RHEL 8']),
    'production'::environment_type,
    random_array_element(ARRAY['IT Infrastructure', 'Web Services', 'E-commerce']),
    random_array_element(ARRAY['admin@democorp.com', 'webteam@democorp.com', 'devops@democorp.com']),
    'Production web server #' || i,
    jsonb_build_object(
        'service', 'web',
        'critical', CASE WHEN i <= 5 THEN true ELSE false END,
        'public_facing', true,
        'load_balancer', CASE WHEN i <= 3 THEN true ELSE false END,
        'ssl_enabled', true
    ),
    'monitoring'::VARCHAR(50),
    'internal'::VARCHAR(50),
    NOW() - INTERVAL '30 days' - (random() * INTERVAL '365 days'),
    NOW() - INTERVAL '1 hour' - (random() * INTERVAL '24 hours')
FROM generate_series(1, 20) AS i
ON CONFLICT DO NOTHING;

-- Production Database Servers (15 assets)
INSERT INTO network_assets (tenant_id, hostname, ip_address, port, asset_type, operating_system, environment, business_unit, owner_email, description, tags, asset_status, asset_ownership, first_discovered_at, last_seen_at)
SELECT
    (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1),
    'db-prod-' || LPAD(i::text, 2, '0') || '.democorp.internal',
    ('10.1.3.' || (10 + i))::inet,
    random_array_element(ARRAY['5432', '3306', '1433', '27017'])::integer,
    'server'::asset_type,
    random_array_element(ARRAY['PostgreSQL on Ubuntu', 'MySQL on CentOS', 'SQL Server on Windows', 'MongoDB on Ubuntu']),
    'production'::environment_type,
    'Database Team',
    random_array_element(ARRAY['dba@democorp.com', 'dbadmin@democorp.com', 'data@democorp.com']),
    'Production database server #' || i,
    jsonb_build_object(
        'service', 'database',
        'critical', true,
        'encrypted', true,
        'backup_enabled', true,
        'replication', CASE WHEN i <= 5 THEN 'master' WHEN i <= 10 THEN 'slave' ELSE 'standalone' END
    ),
    'monitoring'::VARCHAR(50),
    'internal'::VARCHAR(50),
    NOW() - INTERVAL '60 days' - (random() * INTERVAL '730 days'),
    NOW() - INTERVAL '30 minutes' - (random() * INTERVAL '2 hours')
FROM generate_series(1, 15) AS i
ON CONFLICT DO NOTHING;

-- Production API Services (25 assets)
INSERT INTO network_assets (tenant_id, hostname, ip_address, port, asset_type, operating_system, environment, business_unit, owner_email, description, tags, asset_status, asset_ownership, first_discovered_at, last_seen_at)
SELECT
    (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1),
    'api-prod-' || LPAD(i::text, 2, '0') || '.democorp.com',
    ('10.1.2.' || (10 + i))::inet,
    random_array_element(ARRAY['443', '8080', '8443', '9090'])::integer,
    'service'::asset_type,
    random_array_element(ARRAY['Alpine Linux', 'Ubuntu 22.04', 'Amazon Linux 2', 'Container']),
    'production'::environment_type,
    random_array_element(ARRAY['API Team', 'Backend Services', 'Microservices']),
    random_array_element(ARRAY['api@democorp.com', 'backend@democorp.com', 'services@democorp.com']),
    'Production API service #' || i,
    jsonb_build_object(
        'service', 'api',
        'version', 'v' || (1 + (i % 3))::text,
        'authentication', random_array_element(ARRAY['JWT', 'OAuth2', 'API Key']),
        'rate_limited', true,
        'monitored', true
    ),
    'monitoring'::VARCHAR(50),
    'internal'::VARCHAR(50),
    NOW() - INTERVAL '45 days' - (random() * INTERVAL '180 days'),
    NOW() - INTERVAL '5 minutes' - (random() * INTERVAL '1 hour')
FROM generate_series(1, 25) AS i
ON CONFLICT DO NOTHING;

-- Production Network Appliances (10 assets)
INSERT INTO network_assets (tenant_id, hostname, ip_address, port, asset_type, operating_system, environment, business_unit, owner_email, description, tags, asset_status, asset_ownership, first_discovered_at, last_seen_at)
SELECT
    (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1),
    'fw-prod-' || LPAD(i::text, 2, '0') || '.democorp.internal',
    ('10.1.0.' || (10 + i))::inet,
    random_array_element(ARRAY['443', '22', '8080'])::integer,
    'appliance'::asset_type,
    random_array_element(ARRAY['Cisco ASA', 'Fortinet FortiGate', 'Palo Alto PA', 'Juniper SRX']),
    'production'::environment_type,
    'Network Security',
    'netsec@democorp.com',
    'Production firewall #' || i,
    jsonb_build_object(
        'service', 'firewall',
        'critical', true,
        'redundant', CASE WHEN i <= 5 THEN true ELSE false END,
        'vpn_enabled', true,
        'threat_protection', true
    ),
    'monitoring'::VARCHAR(50),
    'internal'::VARCHAR(50),
    NOW() - INTERVAL '90 days' - (random() * INTERVAL '365 days'),
    NOW() - INTERVAL '10 minutes' - (random() * INTERVAL '1 hour')
FROM generate_series(1, 10) AS i
ON CONFLICT DO NOTHING;

-- Production Load Balancers (8 assets)
INSERT INTO network_assets (tenant_id, hostname, ip_address, port, asset_type, operating_system, environment, business_unit, owner_email, description, tags, asset_status, asset_ownership, first_discovered_at, last_seen_at)
SELECT
    (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1),
    'lb-prod-' || LPAD(i::text, 2, '0') || '.democorp.internal',
    ('10.1.4.' || (10 + i))::inet,
    random_array_element(ARRAY['443', '80', '8080'])::integer,
    'appliance'::asset_type,
    random_array_element(ARRAY['F5 BIG-IP', 'HAProxy', 'NGINX Plus', 'AWS ELB']),
    'production'::environment_type,
    'Network Infrastructure',
    'netops@democorp.com',
    'Production load balancer #' || i,
    jsonb_build_object(
        'service', 'load_balancer',
        'critical', true,
        'redundant', CASE WHEN i <= 4 THEN true ELSE false END,
        'ssl_termination', true,
        'health_checks', true
    ),
    'monitoring'::VARCHAR(50),
    'internal'::VARCHAR(50),
    NOW() - INTERVAL '120 days' - (random() * INTERVAL '180 days'),
    NOW() - INTERVAL '5 minutes' - (random() * INTERVAL '30 minutes')
FROM generate_series(1, 8) AS i
ON CONFLICT DO NOTHING;

-- Production Cache Servers (5 assets)
INSERT INTO network_assets (tenant_id, hostname, ip_address, port, asset_type, operating_system, environment, business_unit, owner_email, description, tags, asset_status, asset_ownership, first_discovered_at, last_seen_at)
SELECT
    (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1),
    'cache-prod-' || LPAD(i::text, 2, '0') || '.democorp.internal',
    ('10.1.5.' || (10 + i))::inet,
    random_array_element(ARRAY['6379', '11211', '27017'])::integer,
    'server'::asset_type,
    random_array_element(ARRAY['Redis on Ubuntu', 'Memcached on CentOS', 'MongoDB on Ubuntu']),
    'production'::environment_type,
    'Backend Services',
    random_array_element(ARRAY['cache@democorp.com', 'backend@democorp.com']),
    'Production cache server #' || i,
    jsonb_build_object(
        'service', 'cache',
        'critical', CASE WHEN i <= 2 THEN true ELSE false END,
        'cluster_mode', CASE WHEN i <= 3 THEN true ELSE false END,
        'persistence', true
    ),
    'monitoring'::VARCHAR(50),
    'internal'::VARCHAR(50),
    NOW() - INTERVAL '90 days' - (random() * INTERVAL '120 days'),
    NOW() - INTERVAL '15 minutes' - (random() * INTERVAL '1 hour')
FROM generate_series(1, 5) AS i
ON CONFLICT DO NOTHING;

-- =================================================================
-- Demo Corporation Assets - Staging Environment
-- =================================================================

-- Staging Web Servers (15 assets) - some pending approval
INSERT INTO network_assets (tenant_id, hostname, ip_address, port, asset_type, operating_system, environment, business_unit, owner_email, description, tags, asset_status, asset_ownership, first_discovered_at, last_seen_at)
SELECT
    (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1),
    'web-staging-' || LPAD(i::text, 2, '0') || '.democorp.com',
    ('10.2.1.' || (10 + i))::inet,
    443,
    'server'::asset_type,
    random_array_element(ARRAY['Ubuntu 22.04', 'Ubuntu 20.04', 'CentOS 8']),
    'staging'::environment_type,
    random_array_element(ARRAY['IT Infrastructure', 'Web Services', 'QA Team']),
    random_array_element(ARRAY['admin@democorp.com', 'qa@democorp.com', 'devops@democorp.com']),
    'Staging web server #' || i,
    jsonb_build_object(
        'service', 'web',
        'environment', 'staging',
        'testing', true,
        'ssl_enabled', true
    ),
    CASE WHEN i <= 3 THEN 'pending_approval'::VARCHAR(50) ELSE 'monitoring'::VARCHAR(50) END,
    'internal'::VARCHAR(50),
    NOW() - INTERVAL '15 days' - (random() * INTERVAL '90 days'),
    NOW() - INTERVAL '2 hours' - (random() * INTERVAL '12 hours')
FROM generate_series(1, 15) AS i
ON CONFLICT DO NOTHING;

-- Staging Database Servers (10 assets)
INSERT INTO network_assets (tenant_id, hostname, ip_address, port, asset_type, operating_system, environment, business_unit, owner_email, description, tags, asset_status, asset_ownership, first_discovered_at, last_seen_at)
SELECT
    (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1),
    'db-staging-' || LPAD(i::text, 2, '0') || '.democorp.internal',
    ('10.2.3.' || (10 + i))::inet,
    random_array_element(ARRAY['5432', '3306', '1433'])::integer,
    'server'::asset_type,
    random_array_element(ARRAY['PostgreSQL on Ubuntu', 'MySQL on CentOS', 'SQL Server on Windows']),
    'staging'::environment_type,
    'Database Team',
    random_array_element(ARRAY['dba@democorp.com', 'qa@democorp.com']),
    'Staging database server #' || i,
    jsonb_build_object(
        'service', 'database',
        'environment', 'staging',
        'testing', true,
        'data_sync', true
    ),
    'monitoring'::VARCHAR(50),
    'internal'::VARCHAR(50),
    NOW() - INTERVAL '20 days' - (random() * INTERVAL '60 days'),
    NOW() - INTERVAL '1 hour' - (random() * INTERVAL '6 hours')
FROM generate_series(1, 10) AS i
ON CONFLICT DO NOTHING;

-- Staging API Services (20 assets)
INSERT INTO network_assets (tenant_id, hostname, ip_address, port, asset_type, operating_system, environment, business_unit, owner_email, description, tags, asset_status, asset_ownership, first_discovered_at, last_seen_at)
SELECT
    (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1),
    'api-staging-' || LPAD(i::text, 2, '0') || '.democorp.com',
    ('10.2.2.' || (10 + i))::inet,
    random_array_element(ARRAY['443', '8080', '8443'])::integer,
    'service'::asset_type,
    random_array_element(ARRAY['Alpine Linux', 'Ubuntu 22.04', 'Container']),
    'staging'::environment_type,
    random_array_element(ARRAY['API Team', 'Backend Services', 'QA Team']),
    random_array_element(ARRAY['api@democorp.com', 'qa@democorp.com', 'backend@democorp.com']),
    'Staging API service #' || i,
    jsonb_build_object(
        'service', 'api',
        'environment', 'staging',
        'testing', true,
        'version', 'v' || (1 + (i % 4))::text
    ),
    'monitoring'::VARCHAR(50),
    'internal'::VARCHAR(50),
    NOW() - INTERVAL '10 days' - (random() * INTERVAL '30 days'),
    NOW() - INTERVAL '30 minutes' - (random() * INTERVAL '4 hours')
FROM generate_series(1, 20) AS i
ON CONFLICT DO NOTHING;

-- Staging Test Servers (8 assets)
INSERT INTO network_assets (tenant_id, hostname, ip_address, port, asset_type, operating_system, environment, business_unit, owner_email, description, tags, asset_status, asset_ownership, first_discovered_at, last_seen_at)
SELECT
    (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1),
    'test-staging-' || LPAD(i::text, 2, '0') || '.democorp.internal',
    ('10.2.4.' || (10 + i))::inet,
    random_array_element(ARRAY['8080', '3000', '5000'])::integer,
    'server'::asset_type,
    random_array_element(ARRAY['Ubuntu 22.04', 'CentOS 8', 'Docker']),
    'staging'::environment_type,
    'QA Team',
    'qa@democorp.com',
    'Staging test server #' || i,
    jsonb_build_object(
        'service', 'testing',
        'environment', 'staging',
        'automated_tests', true,
        'integration_tests', CASE WHEN i % 2 = 0 THEN true ELSE false END
    ),
    'monitoring'::VARCHAR(50),
    'internal'::VARCHAR(50),
    NOW() - INTERVAL '7 days' - (random() * INTERVAL '21 days'),
    NOW() - INTERVAL '3 hours' - (random() * INTERVAL '8 hours')
FROM generate_series(1, 8) AS i
ON CONFLICT DO NOTHING;

-- =================================================================
-- Demo Corporation Assets - Development Environment
-- =================================================================

-- Development Workstations (30 assets)
INSERT INTO network_assets (tenant_id, hostname, ip_address, port, asset_type, operating_system, environment, business_unit, owner_email, description, tags, asset_status, asset_ownership, first_discovered_at, last_seen_at)
SELECT
    (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1),
    'dev-ws-' || LPAD(i::text, 2, '0') || '.democorp.internal',
    ('10.3.1.' || (100 + i))::inet,
    random_array_element(ARRAY['22', '3389', '5900'])::integer,
    'endpoint'::asset_type,
    random_array_element(ARRAY['Windows 11', 'macOS 13', 'Ubuntu 22.04', 'Windows 10', 'macOS 12']),
    'development'::environment_type,
    random_array_element(ARRAY['Development Team', 'Frontend Team', 'Backend Team', 'Mobile Team']),
    random_array_element(ARRAY['dev@democorp.com', 'frontend@democorp.com', 'backend@democorp.com', 'mobile@democorp.com']),
    'Development workstation #' || i,
    jsonb_build_object(
        'service', 'development',
        'environment', 'development',
        'developer', 'dev' || i,
        'ide', random_array_element(ARRAY['VS Code', 'IntelliJ', 'Xcode', 'Android Studio']),
        'vpn_connected', true
    ),
    'monitoring'::VARCHAR(50),
    'internal'::VARCHAR(50),
    NOW() - INTERVAL '5 days' - (random() * INTERVAL '30 days'),
    NOW() - INTERVAL '1 hour' - (random() * INTERVAL '8 hours')
FROM generate_series(1, 30) AS i
ON CONFLICT DO NOTHING;

-- Development Servers (20 assets)
INSERT INTO network_assets (tenant_id, hostname, ip_address, port, asset_type, operating_system, environment, business_unit, owner_email, description, tags, asset_status, asset_ownership, first_discovered_at, last_seen_at)
SELECT
    (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1),
    'dev-srv-' || LPAD(i::text, 2, '0') || '.democorp.internal',
    ('10.3.2.' || (10 + i))::inet,
    random_array_element(ARRAY['8080', '3000', '5000', '8000'])::integer,
    'server'::asset_type,
    random_array_element(ARRAY['Ubuntu 22.04', 'Ubuntu 20.04', 'Docker', 'Alpine Linux']),
    'development'::environment_type,
    random_array_element(ARRAY['Development Team', 'Backend Team', 'DevOps Team']),
    random_array_element(ARRAY['dev@democorp.com', 'backend@democorp.com', 'devops@democorp.com']),
    'Development server #' || i,
    jsonb_build_object(
        'service', 'development',
        'environment', 'development',
        'containerized', CASE WHEN i % 3 = 0 THEN true ELSE false END,
        'debug_mode', true
    ),
    'monitoring'::VARCHAR(50),
    'internal'::VARCHAR(50),
    NOW() - INTERVAL '7 days' - (random() * INTERVAL '21 days'),
    NOW() - INTERVAL '2 hours' - (random() * INTERVAL '12 hours')
FROM generate_series(1, 20) AS i
ON CONFLICT DO NOTHING;

-- Development Services (15 assets)
INSERT INTO network_assets (tenant_id, hostname, ip_address, port, asset_type, operating_system, environment, business_unit, owner_email, description, tags, asset_status, asset_ownership, first_discovered_at, last_seen_at)
SELECT
    (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1),
    'dev-svc-' || LPAD(i::text, 2, '0') || '.democorp.internal',
    ('10.3.3.' || (10 + i))::inet,
    random_array_element(ARRAY['8080', '3000', '5000', '9090'])::integer,
    'service'::asset_type,
    random_array_element(ARRAY['Alpine Linux', 'Ubuntu 22.04', 'Container']),
    'development'::environment_type,
    random_array_element(ARRAY['Development Team', 'Backend Team', 'Microservices']),
    random_array_element(ARRAY['dev@democorp.com', 'backend@democorp.com', 'services@democorp.com']),
    'Development service #' || i,
    jsonb_build_object(
        'service', 'development',
        'environment', 'development',
        'testing', true,
        'hot_reload', true
    ),
    'monitoring'::VARCHAR(50),
    'internal'::VARCHAR(50),
    NOW() - INTERVAL '3 days' - (random() * INTERVAL '14 days'),
    NOW() - INTERVAL '30 minutes' - (random() * INTERVAL '6 hours')
FROM generate_series(1, 15) AS i
ON CONFLICT DO NOTHING;

-- Development Databases (4 assets)
INSERT INTO network_assets (tenant_id, hostname, ip_address, port, asset_type, operating_system, environment, business_unit, owner_email, description, tags, asset_status, asset_ownership, first_discovered_at, last_seen_at)
SELECT
    (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1),
    'dev-db-' || LPAD(i::text, 2, '0') || '.democorp.internal',
    ('10.3.4.' || (10 + i))::inet,
    random_array_element(ARRAY['5432', '3306', '27017'])::integer,
    'server'::asset_type,
    random_array_element(ARRAY['PostgreSQL on Ubuntu', 'MySQL on CentOS', 'MongoDB on Ubuntu']),
    'development'::environment_type,
    'Development Team',
    'dev@democorp.com',
    'Development database #' || i,
    jsonb_build_object(
        'service', 'database',
        'environment', 'development',
        'test_data', true,
        'auto_migrate', true
    ),
    'monitoring'::VARCHAR(50),
    'internal'::VARCHAR(50),
    NOW() - INTERVAL '10 days' - (random() * INTERVAL '20 days'),
    NOW() - INTERVAL '4 hours' - (random() * INTERVAL '12 hours')
FROM generate_series(1, 4) AS i
ON CONFLICT DO NOTHING;

-- =================================================================
-- Demo Corporation Assets - Test Environment
-- =================================================================

-- Test Servers (15 assets)
INSERT INTO network_assets (tenant_id, hostname, ip_address, port, asset_type, operating_system, environment, business_unit, owner_email, description, tags, asset_status, asset_ownership, first_discovered_at, last_seen_at)
SELECT
    (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1),
    'test-srv-' || LPAD(i::text, 2, '0') || '.democorp.internal',
    ('10.4.1.' || (10 + i))::inet,
    random_array_element(ARRAY['8080', '3000', '5000', '443'])::integer,
    'server'::asset_type,
    random_array_element(ARRAY['Ubuntu 22.04', 'CentOS 8', 'Windows Server 2019']),
    'test'::environment_type,
    'QA Team',
    random_array_element(ARRAY['qa@democorp.com', 'testing@democorp.com']),
    'Test server #' || i,
    jsonb_build_object(
        'service', 'testing',
        'environment', 'test',
        'automated_tests', true,
        'test_data', true
    ),
    'monitoring'::VARCHAR(50),
    'internal'::VARCHAR(50),
    NOW() - INTERVAL '10 days' - (random() * INTERVAL '45 days'),
    NOW() - INTERVAL '4 hours' - (random() * INTERVAL '24 hours')
FROM generate_series(1, 15) AS i
ON CONFLICT DO NOTHING;

-- Test Endpoints (10 assets)
INSERT INTO network_assets (tenant_id, hostname, ip_address, port, asset_type, operating_system, environment, business_unit, owner_email, description, tags, asset_status, asset_ownership, first_discovered_at, last_seen_at)
SELECT
    (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1),
    'test-ep-' || LPAD(i::text, 2, '0') || '.democorp.internal',
    ('10.4.2.' || (10 + i))::inet,
    random_array_element(ARRAY['22', '3389', '5900'])::integer,
    'endpoint'::asset_type,
    random_array_element(ARRAY['Windows 11', 'Ubuntu 22.04', 'macOS 13']),
    'test'::environment_type,
    'QA Team',
    'qa@democorp.com',
    'Test endpoint #' || i,
    jsonb_build_object(
        'service', 'testing',
        'environment', 'test',
        'test_runner', true,
        'selenium', CASE WHEN i % 2 = 0 THEN true ELSE false END
    ),
    'monitoring'::VARCHAR(50),
    'internal'::VARCHAR(50),
    NOW() - INTERVAL '5 days' - (random() * INTERVAL '20 days'),
    NOW() - INTERVAL '6 hours' - (random() * INTERVAL '18 hours')
FROM generate_series(1, 10) AS i
ON CONFLICT DO NOTHING;

-- =================================================================
-- Demo Corporation Assets - Legacy Systems
-- =================================================================

-- Legacy Servers (10 assets) - some may be third_party
INSERT INTO network_assets (tenant_id, hostname, ip_address, port, asset_type, operating_system, environment, business_unit, owner_email, description, tags, asset_status, asset_ownership, first_discovered_at, last_seen_at)
SELECT
    (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1),
    'legacy-srv-' || LPAD(i::text, 2, '0') || '.democorp.internal',
    ('10.5.1.' || (10 + i))::inet,
    random_array_element(ARRAY['21', '23', '80', '443'])::integer,
    'server'::asset_type,
    random_array_element(ARRAY['Windows Server 2008', 'Windows Server 2012', 'CentOS 6', 'Ubuntu 16.04']),
    'production'::environment_type,
    'Legacy Systems',
    'legacy@democorp.com',
    'Legacy server #' || i || ' (scheduled for decommission)',
    jsonb_build_object(
        'service', 'legacy',
        'legacy', true,
        'decommission_planned', true,
        'security_risk', true,
        'outdated_os', true
    ),
    'monitoring'::VARCHAR(50),
    CASE WHEN i <= 3 THEN 'third_party'::VARCHAR(50) ELSE 'internal'::VARCHAR(50) END,
    NOW() - INTERVAL '5 years' - (random() * INTERVAL '2 years'),
    NOW() - INTERVAL '1 day' - (random() * INTERVAL '7 days')
FROM generate_series(1, 10) AS i
ON CONFLICT DO NOTHING;

-- =================================================================
-- Demo Corporation Assets - Cloud Infrastructure
-- =================================================================

-- Cloud Services (15 assets) - mix of first_party and third_party
INSERT INTO network_assets (tenant_id, hostname, ip_address, port, asset_type, operating_system, environment, business_unit, owner_email, description, tags, asset_status, asset_ownership, first_discovered_at, last_seen_at)
SELECT
    (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1),
    'cloud-svc-' || LPAD(i::text, 2, '0') || '.democorp.com',
    NULL, -- Cloud services don't have fixed IPs
    random_array_element(ARRAY['443', '8080', '8443'])::integer,
    'service'::asset_type,
    random_array_element(ARRAY['AWS Lambda', 'Azure Functions', 'Google Cloud Run', 'Kubernetes']),
    random_array_element(ARRAY['production', 'staging', 'development'])::environment_type,
    'Cloud Infrastructure',
    'cloud@democorp.com',
    'Cloud service #' || i,
    jsonb_build_object(
        'service', 'cloud',
        'provider', random_array_element(ARRAY['AWS', 'Azure', 'GCP']),
        'serverless', CASE WHEN i % 3 = 0 THEN true ELSE false END,
        'containerized', CASE WHEN i % 2 = 0 THEN true ELSE false END
    ),
    'monitoring'::VARCHAR(50),
    CASE WHEN i <= 5 THEN 'third_party'::VARCHAR(50) ELSE 'internal'::VARCHAR(50) END,
    NOW() - INTERVAL '30 days' - (random() * INTERVAL '180 days'),
    NOW() - INTERVAL '10 minutes' - (random() * INTERVAL '2 hours')
FROM generate_series(1, 15) AS i
ON CONFLICT DO NOTHING;

-- =================================================================
-- Demo Corporation Assets - Network Appliances
-- =================================================================

-- Network Appliances (10 assets)
INSERT INTO network_assets (tenant_id, hostname, ip_address, port, asset_type, operating_system, environment, business_unit, owner_email, description, tags, asset_status, asset_ownership, first_discovered_at, last_seen_at)
SELECT
    (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1),
    'net-app-' || LPAD(i::text, 2, '0') || '.democorp.internal',
    ('10.6.1.' || (10 + i))::inet,
    random_array_element(ARRAY['443', '22', '8080', '161'])::integer,
    'appliance'::asset_type,
    random_array_element(ARRAY['Cisco IOS', 'Juniper JunOS', 'Fortinet FortiOS', 'Palo Alto PAN-OS']),
    random_array_element(ARRAY['production', 'staging'])::environment_type,
    'Network Infrastructure',
    'network@democorp.com',
    'Network appliance #' || i,
    jsonb_build_object(
        'service', 'network',
        'device_type', random_array_element(ARRAY['router', 'switch', 'load_balancer', 'monitor']),
        'redundant', CASE WHEN i % 2 = 0 THEN true ELSE false END,
        'monitored', true
    ),
    'monitoring'::VARCHAR(50),
    'internal'::VARCHAR(50),
    NOW() - INTERVAL '60 days' - (random() * INTERVAL '365 days'),
    NOW() - INTERVAL '5 minutes' - (random() * INTERVAL '1 hour')
FROM generate_series(1, 10) AS i
ON CONFLICT DO NOTHING;

-- =================================================================
-- Success Message
-- =================================================================

DO $$
DECLARE
    asset_count INTEGER;
    monitoring_count INTEGER;
    pending_count INTEGER;
    first_party_count INTEGER;
    third_party_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO asset_count FROM network_assets WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1) AND deleted_at IS NULL;
    SELECT COUNT(*) INTO monitoring_count FROM network_assets WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1) AND asset_status = 'monitoring' AND deleted_at IS NULL;
    SELECT COUNT(*) INTO pending_count FROM network_assets WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1) AND asset_status = 'pending_approval' AND deleted_at IS NULL;
    SELECT COUNT(*) INTO first_party_count FROM network_assets WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1) AND asset_ownership = 'internal' AND deleted_at IS NULL;
    SELECT COUNT(*) INTO third_party_count FROM network_assets WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1) AND asset_ownership = 'third_party' AND deleted_at IS NULL;

    RAISE NOTICE 'Demo Corporation asset seed completed successfully!';
    RAISE NOTICE 'Total assets created: %', asset_count;
    RAISE NOTICE 'Asset status distribution:';
    RAISE NOTICE '  Monitoring: %', monitoring_count;
    RAISE NOTICE '  Pending Approval: %', pending_count;
    RAISE NOTICE 'Asset ownership distribution:';
    RAISE NOTICE '  Internal: %', first_party_count;
    RAISE NOTICE '  Third Party: %', third_party_count;
    RAISE NOTICE 'Asset distribution by environment:';
    RAISE NOTICE '  Production: %', (SELECT COUNT(*) FROM network_assets WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1) AND environment = 'production' AND deleted_at IS NULL);
    RAISE NOTICE '  Staging: %', (SELECT COUNT(*) FROM network_assets WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1) AND environment = 'staging' AND deleted_at IS NULL);
    RAISE NOTICE '  Development: %', (SELECT COUNT(*) FROM network_assets WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1) AND environment = 'development' AND deleted_at IS NULL);
    RAISE NOTICE '  Test: %', (SELECT COUNT(*) FROM network_assets WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1) AND environment = 'test' AND deleted_at IS NULL);
    RAISE NOTICE 'Asset types:';
    RAISE NOTICE '  Servers: %', (SELECT COUNT(*) FROM network_assets WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1) AND asset_type = 'server' AND deleted_at IS NULL);
    RAISE NOTICE '  Services: %', (SELECT COUNT(*) FROM network_assets WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1) AND asset_type = 'service' AND deleted_at IS NULL);
    RAISE NOTICE '  Endpoints: %', (SELECT COUNT(*) FROM network_assets WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1) AND asset_type = 'endpoint' AND deleted_at IS NULL);
    RAISE NOTICE '  Appliances: %', (SELECT COUNT(*) FROM network_assets WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1) AND asset_type = 'appliance' AND deleted_at IS NULL);
END $$;

-- Clean up helper function
DROP FUNCTION IF EXISTS random_array_element(TEXT[]);
