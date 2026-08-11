-- =================================================================
-- Crypto Inventory Platform - Tier 2 Demo Data
-- =================================================================
-- This file contains OPTIONAL demo data for testing and development.
-- It should NOT be loaded automatically in production deployments.
--
-- To load: ./scripts/database/load-demo-data.sh
--
-- GRANT MODEL (.3): the role grants below mirror the canonical
-- reconciliation filters in seed.sql's "Ensure Tenant Roles for All Tenants"
-- DO block (the source of truth, also mirrored by auth-service's
-- assignRolePermissions). Keep the filters in sync with seed.sql — drift
-- here would give the demo tenant different grants until the next
-- reconciliation run.
--
-- This file creates:
--   1. Demo Corporation tenant (triggers auto-licensing of Best Practices)
--   2. Tenant roles for demo-corp
--   3. Tenant role permissions
--   4. Demo users (one per role)
--   5. User role assignments
--
-- Note: Best Practices framework license is automatically created
-- by the database trigger when the tenant is inserted.
-- =================================================================

-- =================================================================
-- Section 1: Demo Corporation Tenant
-- =================================================================

INSERT INTO tenants (name, slug, subscription_tier_id, billing_email, payment_status)
SELECT
    'Demo Corporation',
    'demo-corp',
    st.id,
    'admin@democorp.com',
    'active'
FROM subscription_tiers st
WHERE st.name = 'pro'
ON CONFLICT (slug) DO NOTHING;

-- =================================================================
-- Section 2: Tenant Roles for Demo Corporation
-- =================================================================
-- These roles match what auth-service creates dynamically for new tenants

INSERT INTO tenant_roles (tenant_id, name, display_name, description, is_system_role)
SELECT
    t.id,
    'billing_admin',
    'Billing Admin',
    'Billing and account ownership. Pays the bills; cannot perform operational work.',
    true
FROM tenants t WHERE t.slug = 'demo-corp'
ON CONFLICT (tenant_id, name) DO NOTHING;

INSERT INTO tenant_roles (tenant_id, name, display_name, description, is_system_role)
SELECT
    t.id,
    'tenant_admin',
    'Tenant Administrator',
    'Full operational and user management; reads billing but cannot change it.',
    true
FROM tenants t WHERE t.slug = 'demo-corp'
ON CONFLICT (tenant_id, name) DO NOTHING;

INSERT INTO tenant_roles (tenant_id, name, display_name, description, is_system_role)
SELECT
    t.id,
    'security_admin',
    'Security Administrator',
    'Security operations, compliance, reports; reads users and settings for incident response.',
    true
FROM tenants t WHERE t.slug = 'demo-corp'
ON CONFLICT (tenant_id, name) DO NOTHING;

INSERT INTO tenant_roles (tenant_id, name, display_name, description, is_system_role)
SELECT
    t.id,
    'viewer',
    'Viewer',
    'Read-only access to tenant operational data (no billing).',
    true
FROM tenants t WHERE t.slug = 'demo-corp'
ON CONFLICT (tenant_id, name) DO NOTHING;

INSERT INTO tenant_roles (tenant_id, name, display_name, description, is_system_role)
SELECT
    t.id,
    'api_user',
    'API User',
    'Read-only integration scope across operational data.',
    true
FROM tenants t WHERE t.slug = 'demo-corp'
ON CONFLICT (tenant_id, name) DO NOTHING;

-- =================================================================
-- Section 3: Tenant Role Permissions
-- =================================================================

-- Billing Admin — billing + read-only visibility into who has access and
-- basic tenant settings (mirrors seed.sql's reconciliation filter)
INSERT INTO tenant_role_permissions (role_id, permission_id)
SELECT tr.id, tp.id
FROM tenant_roles tr
CROSS JOIN tenant_permissions tp
WHERE tr.name = 'billing_admin'
  AND tr.tenant_id = (SELECT id FROM tenants WHERE slug = 'demo-corp')
  AND (tp.resource = 'billing' OR tp.name IN ('settings.read', 'users.read'))
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Tenant Admin — everything except billing.update (gets billing.read)
INSERT INTO tenant_role_permissions (role_id, permission_id)
SELECT tr.id, tp.id
FROM tenant_roles tr
CROSS JOIN tenant_permissions tp
WHERE tr.name = 'tenant_admin'
  AND tr.tenant_id = (SELECT id FROM tenants WHERE slug = 'demo-corp')
  AND tp.name <> 'billing.update'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Security Admin — operational/security scope + users.read + settings.read
-- for incident response
INSERT INTO tenant_role_permissions (role_id, permission_id)
SELECT tr.id, tp.id
FROM tenant_roles tr
CROSS JOIN tenant_permissions tp
WHERE tr.name = 'security_admin'
  AND tr.tenant_id = (SELECT id FROM tenants WHERE slug = 'demo-corp')
  AND (tp.resource IN ('assets', 'sensors', 'reports', 'compliance', 'pcap', 'discovery', 'alerts')
       OR tp.name IN ('users.read', 'settings.read'))
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Viewer — read-only across all operational resources (no billing)
INSERT INTO tenant_role_permissions (role_id, permission_id)
SELECT tr.id, tp.id
FROM tenant_roles tr
CROSS JOIN tenant_permissions tp
WHERE tr.name = 'viewer'
  AND tr.tenant_id = (SELECT id FROM tenants WHERE slug = 'demo-corp')
  AND tp.action = 'read' AND tp.resource <> 'billing'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- API User — read-only integration scope across operational data
INSERT INTO tenant_role_permissions (role_id, permission_id)
SELECT tr.id, tp.id
FROM tenant_roles tr
CROSS JOIN tenant_permissions tp
WHERE tr.name = 'api_user'
  AND tr.tenant_id = (SELECT id FROM tenants WHERE slug = 'demo-corp')
  AND tp.action = 'read'
  AND tp.resource IN ('assets', 'sensors', 'reports', 'compliance', 'discovery', 'pcap')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- =================================================================
-- Section 4: Demo Users
-- =================================================================
-- Password for all users: Password123! (Argon2id hash)

-- Billing Admin: owner@democorp.com
INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, is_active, email_verified, created_at, updated_at)
SELECT
    '11111111-1111-1111-1111-111111111111',
    t.id,
    'owner@democorp.com',
    '$argon2id$v=19$m=65536,t=3,p=2$8Ll1hG8Y7AO+m8hQxRuozA$nO6gHyQ3JAccN5XWX5gjdnxTx+XutgIHYGCuXpJ2LKQ',
    'Demo', 'Owner', true, true, NOW(), NOW()
FROM tenants t WHERE t.slug = 'demo-corp'
ON CONFLICT ON CONSTRAINT unique_tenant_email DO NOTHING;

-- Tenant Admin: admin@democorp.com
INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, is_active, email_verified, created_at, updated_at)
SELECT
    '22222222-2222-2222-2222-222222222222',
    t.id,
    'admin@democorp.com',
    '$argon2id$v=19$m=65536,t=3,p=2$8Ll1hG8Y7AO+m8hQxRuozA$nO6gHyQ3JAccN5XWX5gjdnxTx+XutgIHYGCuXpJ2LKQ',
    'Demo', 'Admin', true, true, NOW(), NOW()
FROM tenants t WHERE t.slug = 'demo-corp'
ON CONFLICT ON CONSTRAINT unique_tenant_email DO NOTHING;

-- Security Admin: security@democorp.com
INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, is_active, email_verified, created_at, updated_at)
SELECT
    '33333333-3333-3333-3333-333333333333',
    t.id,
    'security@democorp.com',
    '$argon2id$v=19$m=65536,t=3,p=2$8Ll1hG8Y7AO+m8hQxRuozA$nO6gHyQ3JAccN5XWX5gjdnxTx+XutgIHYGCuXpJ2LKQ',
    'Demo', 'Security', true, true, NOW(), NOW()
FROM tenants t WHERE t.slug = 'demo-corp'
ON CONFLICT ON CONSTRAINT unique_tenant_email DO NOTHING;

-- Analyst: analyst@democorp.com
INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, is_active, email_verified, created_at, updated_at)
SELECT
    '44444444-4444-4444-4444-444444444444',
    t.id,
    'analyst@democorp.com',
    '$argon2id$v=19$m=65536,t=3,p=2$8Ll1hG8Y7AO+m8hQxRuozA$nO6gHyQ3JAccN5XWX5gjdnxTx+XutgIHYGCuXpJ2LKQ',
    'Demo', 'Analyst', true, true, NOW(), NOW()
FROM tenants t WHERE t.slug = 'demo-corp'
ON CONFLICT ON CONSTRAINT unique_tenant_email DO NOTHING;

-- Viewer: viewer@democorp.com
INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, is_active, email_verified, created_at, updated_at)
SELECT
    '55555555-5555-5555-5555-555555555555',
    t.id,
    'viewer@democorp.com',
    '$argon2id$v=19$m=65536,t=3,p=2$8Ll1hG8Y7AO+m8hQxRuozA$nO6gHyQ3JAccN5XWX5gjdnxTx+XutgIHYGCuXpJ2LKQ',
    'Demo', 'Viewer', true, true, NOW(), NOW()
FROM tenants t WHERE t.slug = 'demo-corp'
ON CONFLICT ON CONSTRAINT unique_tenant_email DO NOTHING;

-- API User: api@democorp.com
INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, is_active, email_verified, created_at, updated_at)
SELECT
    '66666666-6666-6666-6666-666666666666',
    t.id,
    'api@democorp.com',
    '$argon2id$v=19$m=65536,t=3,p=2$8Ll1hG8Y7AO+m8hQxRuozA$nO6gHyQ3JAccN5XWX5gjdnxTx+XutgIHYGCuXpJ2LKQ',
    'Demo', 'API', true, true, NOW(), NOW()
FROM tenants t WHERE t.slug = 'demo-corp'
ON CONFLICT ON CONSTRAINT unique_tenant_email DO NOTHING;

-- =================================================================
-- Section 5: User Role Assignments
-- =================================================================

-- Assign billing_admin role to owner@democorp.com
INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, assigned_at, is_active)
SELECT
    u.id,
    t.id,
    tr.id,
    NOW(),
    true
FROM users u
JOIN tenants t ON u.tenant_id = t.id
JOIN tenant_roles tr ON tr.tenant_id = t.id AND tr.name = 'billing_admin'
WHERE u.email = 'owner@democorp.com' AND t.slug = 'demo-corp'
ON CONFLICT ON CONSTRAINT user_tenant_roles_user_id_tenant_id_role_id_key DO UPDATE SET is_active = true;

-- Assign tenant_admin role to admin@democorp.com
INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, assigned_at, is_active)
SELECT
    u.id,
    t.id,
    tr.id,
    NOW(),
    true
FROM users u
JOIN tenants t ON u.tenant_id = t.id
JOIN tenant_roles tr ON tr.tenant_id = t.id AND tr.name = 'tenant_admin'
WHERE u.email = 'admin@democorp.com' AND t.slug = 'demo-corp'
ON CONFLICT ON CONSTRAINT user_tenant_roles_user_id_tenant_id_role_id_key DO UPDATE SET is_active = true;

-- Assign security_admin role to security@democorp.com
INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, assigned_at, is_active)
SELECT
    u.id,
    t.id,
    tr.id,
    NOW(),
    true
FROM users u
JOIN tenants t ON u.tenant_id = t.id
JOIN tenant_roles tr ON tr.tenant_id = t.id AND tr.name = 'security_admin'
WHERE u.email = 'security@democorp.com' AND t.slug = 'demo-corp'
ON CONFLICT ON CONSTRAINT user_tenant_roles_user_id_tenant_id_role_id_key DO UPDATE SET is_active = true;

-- Assign viewer role to analyst@democorp.com (analyst role retired)
INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, assigned_at, is_active)
SELECT
    u.id,
    t.id,
    tr.id,
    NOW(),
    true
FROM users u
JOIN tenants t ON u.tenant_id = t.id
JOIN tenant_roles tr ON tr.tenant_id = t.id AND tr.name = 'viewer'
WHERE u.email = 'analyst@democorp.com' AND t.slug = 'demo-corp'
ON CONFLICT ON CONSTRAINT user_tenant_roles_user_id_tenant_id_role_id_key DO UPDATE SET is_active = true;

-- Assign viewer role to viewer@democorp.com
INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, assigned_at, is_active)
SELECT
    u.id,
    t.id,
    tr.id,
    NOW(),
    true
FROM users u
JOIN tenants t ON u.tenant_id = t.id
JOIN tenant_roles tr ON tr.tenant_id = t.id AND tr.name = 'viewer'
WHERE u.email = 'viewer@democorp.com' AND t.slug = 'demo-corp'
ON CONFLICT ON CONSTRAINT user_tenant_roles_user_id_tenant_id_role_id_key DO UPDATE SET is_active = true;

-- Assign api_user role to api@democorp.com
INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, assigned_at, is_active)
SELECT
    u.id,
    t.id,
    tr.id,
    NOW(),
    true
FROM users u
JOIN tenants t ON u.tenant_id = t.id
JOIN tenant_roles tr ON tr.tenant_id = t.id AND tr.name = 'api_user'
WHERE u.email = 'api@democorp.com' AND t.slug = 'demo-corp'
ON CONFLICT ON CONSTRAINT user_tenant_roles_user_id_tenant_id_role_id_key DO UPDATE SET is_active = true;

-- =================================================================
-- Section 6: Asset Lifecycle Policy for Demo Tenant
-- =================================================================

INSERT INTO asset_lifecycle_policies (
    tenant_id,
    stale_warning_days,
    stale_archived_days,
    auto_archive_enabled,
    notifications_enabled,
    revalidation_schedule
)
SELECT
    t.id,
    30,
    60,
    true,
    true,
    '{"enabled": false, "interval_hours": 168}'::jsonb
FROM tenants t
WHERE t.slug = 'demo-corp'
ON CONFLICT (tenant_id) DO NOTHING;

-- =================================================================
-- Section 7: Sample Certificates for Demo/Development
-- =================================================================
-- These certificates are for testing and demonstration purposes
-- They use realistic but fake data

DO $$
DECLARE
    demo_tenant_id UUID;
BEGIN
    -- Get the demo tenant ID
    SELECT id INTO demo_tenant_id FROM tenants WHERE name = 'Demo Corporation' AND deleted_at IS NULL LIMIT 1;

    IF demo_tenant_id IS NOT NULL THEN
        -- Insert 20 sample certificates with varied characteristics
        INSERT INTO certificates (
            tenant_id, serial_number, subject_dn, issuer_dn, common_name,
            subject_alternative_names, signature_algorithm, public_key_algorithm,
            public_key_size, not_before, not_after,
            fingerprint_sha1, fingerprint_sha256,
            is_self_signed, is_ca_certificate,
            key_usage, extended_key_usage
        ) VALUES
        -- Production web server certificates (Let's Encrypt style)
        (demo_tenant_id, '01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67',
         'CN=www.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
         'www.democorp.com',
         ARRAY['www.democorp.com', 'democorp.com', 'api.democorp.com'],
         'SHA256WithRSA', 'RSA', 2048,
         NOW() - INTERVAL '180 days', NOW() + INTERVAL '60 days',
         '14336801ac198e9aa64aa91cea03a8b6d7f1060c',
         'd49ef9c27a0a77a37809f2b26249be229484c24654c42c8848af9778f3762d43',
         false, false,
         ARRAY['Digital Signature', 'Key Encipherment'],
         ARRAY['Server Authentication', 'Client Authentication']),

        (demo_tenant_id, '02:34:56:78:9A:BC:DE:F0:02:34:56:78:9A:BC:DE:F0:02:34:56:78',
         'CN=api.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
         'api.democorp.com',
         ARRAY['api.democorp.com', 'api-v2.democorp.com'],
         'SHA256WithRSA', 'RSA', 2048,
         NOW() - INTERVAL '90 days', NOW() + INTERVAL '90 days',
         '2315de7b9497db44c691547d2fad72e17d037a07',
         '39f69061b9899558298d9ebad149233b5aac18138605041b67547546b03e474f',
         false, false,
         ARRAY['Digital Signature', 'Key Encipherment'],
         ARRAY['Server Authentication']),

        -- Expiring soon certificate (for testing expiration filters)
        (demo_tenant_id, '03:45:67:89:AB:CD:EF:01:03:45:67:89:AB:CD:EF:01:03:45:67:89',
         'CN=staging.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
         'staging.democorp.com',
         ARRAY['staging.democorp.com'],
         'SHA256WithRSA', 'RSA', 2048,
         NOW() - INTERVAL '80 days', NOW() + INTERVAL '25 days',
         'f252a86451ded68eac8c444b3bb54d3c59efb27c',
         'c891e828b537a840f0c3a2a9e6bbb25553fea0ff3bfc5c35b8e228e87f1e05f2',
         false, false,
         ARRAY['Digital Signature', 'Key Encipherment'],
         ARRAY['Server Authentication']),

        -- High security certificate (4096-bit RSA)
        (demo_tenant_id, '04:56:78:9A:BC:DE:F0:12:04:56:78:9A:BC:DE:F0:12:04:56:78:9A',
         'CN=secure.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'CN=DigiCert SHA2 Extended Validation Server CA,O=DigiCert Inc,C=US',
         'secure.democorp.com',
         ARRAY['secure.democorp.com', 'secure-api.democorp.com'],
         'SHA256WithRSA', 'RSA', 4096,
         NOW() - INTERVAL '365 days', NOW() + INTERVAL '365 days',
         '48a94b86a35ca90d592d401f47c21a335e5abb27',
         '71eb6bf3c33c221918a2ef02e6f8593e44ab3f42b80fbf436df3295d0518487f',
         false, false,
         ARRAY['Digital Signature', 'Key Encipherment', 'Data Encipherment'],
         ARRAY['Server Authentication', 'Client Authentication']),

        -- ECDSA certificate (modern algorithm)
        (demo_tenant_id, '05:67:89:AB:CD:EF:01:23:05:67:89:AB:CD:EF:01:23:05:67:89:AB',
         'CN=modern.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
         'modern.democorp.com',
         ARRAY['modern.democorp.com'],
         'SHA256WithECDSA', 'ECDSA', 256,
         NOW() - INTERVAL '60 days', NOW() + INTERVAL '60 days',
         'db47c522de263d071c634adce3ef6d091eb60bb6',
         '7fb63a5d741c157131f1ab950d3c1c24a182c9b3ccdd07a346f5804d574eaa9c',
         false, false,
         ARRAY['Digital Signature', 'Key Agreement'],
         ARRAY['Server Authentication']),

        -- Self-signed certificate
        (demo_tenant_id, '06:78:9A:BC:DE:F0:12:34:06:78:9A:BC:DE:F0:12:34:06:78:9A:BC',
         'CN=internal.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'CN=internal.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'internal.democorp.com',
         ARRAY['internal.democorp.com', '*.internal.democorp.com'],
         'SHA256WithRSA', 'RSA', 2048,
         NOW() - INTERVAL '730 days', NOW() + INTERVAL '730 days',
         '066018e3d66793b2866d9bd54e7957e61f3d82aa',
         'c920d3055450d9e9406240ffa10013d01614eb80de5d66fbce7aca72f3eedb3b',
         true, false,
         ARRAY['Digital Signature', 'Key Encipherment'],
         ARRAY['Server Authentication']),

        -- CA certificate
        (demo_tenant_id, '07:89:AB:CD:EF:01:23:45:07:89:AB:CD:EF:01:23:45:07:89:AB:CD',
         'CN=Demo Corp Internal CA,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'CN=Demo Corp Internal CA,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'Demo Corp Internal CA',
         NULL,
         'SHA256WithRSA', 'RSA', 4096,
         NOW() - INTERVAL '1095 days', NOW() + INTERVAL '1825 days',
         'ce4e98809776975d71d309ea31dd662c0a184ca7',
         '17c906dff9f4ce497e586e83362ec390c2ab0967dd85335f2a9680e012558c60',
         true, true,
         ARRAY['Certificate Sign', 'CRL Sign'],
         ARRAY['Any Extended Key Usage']),

        -- Wildcard certificate
        (demo_tenant_id, '08:9A:BC:DE:F0:12:34:56:08:9A:BC:DE:F0:12:34:56:08:9A:BC:DE',
         'CN=*.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
         '*.democorp.com',
         ARRAY['*.democorp.com', 'democorp.com'],
         'SHA256WithRSA', 'RSA', 2048,
         NOW() - INTERVAL '45 days', NOW() + INTERVAL '45 days',
         '363e2f3a7343a6c29ff137c5e2420de5fbed4985',
         '8b3714f44fe9fe202f8106fd746001c9aabb015e837c0c67ef5246fa81fdd4ba',
         false, false,
         ARRAY['Digital Signature', 'Key Encipherment'],
         ARRAY['Server Authentication']),

        -- Expired certificate (for testing)
        (demo_tenant_id, '09:AB:CD:EF:01:23:45:67:09:AB:CD:EF:01:23:45:67:09:AB:CD:EF',
         'CN=old.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
         'old.democorp.com',
         ARRAY['old.democorp.com'],
         'SHA256WithRSA', 'RSA', 2048,
         NOW() - INTERVAL '400 days', NOW() - INTERVAL '10 days',
         '73efa41ef12fc290c682c32f7a7fe927594648b8',
         'ac1a867f60a547662de49cbb2a10abd818223692a5f0c890c4cabf9453dac3cb',
         false, false,
         ARRAY['Digital Signature', 'Key Encipherment'],
         ARRAY['Server Authentication']),

        -- Weak key size (for testing weak crypto detection)
        (demo_tenant_id, '0A:BC:DE:F0:12:34:56:78:0A:BC:DE:F0:12:34:56:78:0A:BC:DE:F0',
         'CN=legacy.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'CN=Legacy CA,O=Legacy Certificate Authority,C=US',
         'legacy.democorp.com',
         ARRAY['legacy.democorp.com'],
         'SHA1WithRSA', 'RSA', 1024,
         NOW() - INTERVAL '2000 days', NOW() + INTERVAL '365 days',
         '5ee111c3e234fcb848d48073c5e7e6a1789d0754',
         'b5cd52656466b57cb80574b736e125831f5ec1234ea1acb4bee65b1bbe8cf694',
         false, false,
         ARRAY['Digital Signature', 'Key Encipherment'],
         ARRAY['Server Authentication']),

        -- Multi-domain certificate
        (demo_tenant_id, '0B:CD:EF:01:23:45:67:89:0B:CD:EF:01:23:45:67:89:0B:CD:EF:01',
         'CN=www.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'CN=DigiCert SHA2 High Assurance Server CA,O=DigiCert Inc,C=US',
         'www.democorp.com',
         ARRAY['www.democorp.com', 'democorp.com', 'www.democorp.net', 'democorp.net', 'www.democorp.org'],
         'SHA256WithRSA', 'RSA', 2048,
         NOW() - INTERVAL '120 days', NOW() + INTERVAL '240 days',
         '8eb8cc1e782015d9e23b20ef66003a1a14051e6b',
         'bf2dfbf1ee951abdbf5e88a7fefb2660d633250abb0d94cd55b329faf9b09deb',
         false, false,
         ARRAY['Digital Signature', 'Key Encipherment'],
         ARRAY['Server Authentication']),

        -- Development certificate
        (demo_tenant_id, '0C:DE:F0:12:34:56:78:9A:0C:DE:F0:12:34:56:78:9A:0C:DE:F0:12',
         'CN=dev.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'CN=Demo Corp Internal CA,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'dev.democorp.com',
         ARRAY['dev.democorp.com', '*.dev.democorp.com'],
         'SHA256WithRSA', 'RSA', 2048,
         NOW() - INTERVAL '30 days', NOW() + INTERVAL '335 days',
         '234559fa28c5b9bbfcc89f45da99ae7c5620674e',
         '091390026372850e5a0cc7deaa0fa5d4b74194fcfe7ac529dbc4ca902535a1c6',
         false, false,
         ARRAY['Digital Signature', 'Key Encipherment'],
         ARRAY['Server Authentication']),

        -- Email certificate
        (demo_tenant_id, '0D:EF:01:23:45:67:89:AB:0D:EF:01:23:45:67:89:AB:0D:EF:01:23',
         'CN=mail.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
         'mail.democorp.com',
         ARRAY['mail.democorp.com', 'smtp.democorp.com', 'imap.democorp.com'],
         'SHA256WithRSA', 'RSA', 2048,
         NOW() - INTERVAL '15 days', NOW() + INTERVAL '75 days',
         'a67710b012a955b79b5aba4d7f40b80e26cda587',
         '647aa29b2b121152cdd7100754d802ddaa500708cdfd40fd0add5b2ca56a6678',
         false, false,
         ARRAY['Digital Signature', 'Key Encipherment'],
         ARRAY['Server Authentication', 'Email Protection']),

        -- Long validity certificate
        (demo_tenant_id, '0E:F0:12:34:56:78:9A:BC:0E:F0:12:34:56:78:9A:BC:0E:F0:12:34',
         'CN=longterm.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'CN=DigiCert SHA2 Extended Validation Server CA,O=DigiCert Inc,C=US',
         'longterm.democorp.com',
         ARRAY['longterm.democorp.com'],
         'SHA256WithRSA', 'RSA', 4096,
         NOW() - INTERVAL '180 days', NOW() + INTERVAL '730 days',
         'a3ef59eb6bb09103b094e76bcfe389b1a990f7d2',
         'b94b128934dbfdd138e6c80ac16ae90714c94d0d9075bb7f01968577e97f65a2',
         false, false,
         ARRAY['Digital Signature', 'Key Encipherment'],
         ARRAY['Server Authentication']),

        -- ECDSA P-384 certificate
        (demo_tenant_id, '0F:01:23:45:67:89:AB:CD:0F:01:23:45:67:89:AB:CD:0F:01:23:45',
         'CN=ecdsa.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
         'ecdsa.democorp.com',
         ARRAY['ecdsa.democorp.com'],
         'SHA384WithECDSA', 'ECDSA', 384,
         NOW() - INTERVAL '20 days', NOW() + INTERVAL '40 days',
         '8edd1a5699b344317499609a53319c1b418a873c',
         '557bb67de6d372092479a1e9962dff3aba0c0e9cb24ee7a2f03be53152b489ac',
         false, false,
         ARRAY['Digital Signature', 'Key Agreement'],
         ARRAY['Server Authentication']),

        -- Code signing certificate
        (demo_tenant_id, '10:12:34:56:78:9A:BC:DE:10:12:34:56:78:9A:BC:DE:10:12:34:56',
         'CN=Demo Corporation Code Signing,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'CN=DigiCert SHA2 Assured ID Code Signing CA,O=DigiCert Inc,C=US',
         'Demo Corporation Code Signing',
         NULL,
         'SHA256WithRSA', 'RSA', 2048,
         NOW() - INTERVAL '365 days', NOW() + INTERVAL '365 days',
         '873e1ba4ef60b34b8270203a60b0ccc1e81a1f15',
         '5f750c9477a8d0140baeecf1eb713bea3f97fec565584150841085a2a96f1ade',
         false, false,
         ARRAY['Digital Signature'],
         ARRAY['Code Signing']),

        -- Client certificate
        (demo_tenant_id, '11:23:45:67:89:AB:CD:EF:11:23:45:67:89:AB:CD:EF:11:23:45:67',
         'CN=client.democorp.com,OU=IT Department,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'CN=Demo Corp Internal CA,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'client.democorp.com',
         NULL,
         'SHA256WithRSA', 'RSA', 2048,
         NOW() - INTERVAL '100 days', NOW() + INTERVAL '265 days',
         'b5ce0030092f7f388354111af98e441814710924',
         'bfb33035d535ee66b0d34b7b82c60a9e7373c9469853902afa95e5a2c3ea01d9',
         false, false,
         ARRAY['Digital Signature', 'Key Encipherment'],
         ARRAY['Client Authentication']),

        -- Intermediate CA certificate
        (demo_tenant_id, '12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:34:56:78',
         'CN=Demo Corp Intermediate CA,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'CN=Demo Corp Internal CA,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'Demo Corp Intermediate CA',
         NULL,
         'SHA256WithRSA', 'RSA', 4096,
         NOW() - INTERVAL '730 days', NOW() + INTERVAL '1095 days',
         'e0e1a13ce255f6c81abc72a7ff628e919b6e73c0',
         'abeae7c1a51c4c18c783ca48c01e00c39a502c88861ecbd11a574054c91cb654',
         false, true,
         ARRAY['Certificate Sign', 'CRL Sign'],
         ARRAY['Any Extended Key Usage']),

        -- Very short validity (testing)
        (demo_tenant_id, '13:45:67:89:AB:CD:EF:01:13:45:67:89:AB:CD:EF:01:13:45:67:89',
         'CN=short.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
         'short.democorp.com',
         ARRAY['short.democorp.com'],
         'SHA256WithRSA', 'RSA', 2048,
         NOW() - INTERVAL '5 days', NOW() + INTERVAL '5 days',
         '312557148a0f2d76e04a64d799bc6dc28aeedbba',
         '526ffebc98ea66e1ea10631f8a02c04262d5a4ca124580b39c64f4d52105e496',
         false, false,
         ARRAY['Digital Signature', 'Key Encipherment'],
         ARRAY['Server Authentication']),

        -- Mobile app API certificate
        (demo_tenant_id, '14:56:78:9A:BC:DE:F0:12:14:56:78:9A:BC:DE:F0:12:14:56:78:9A',
         'CN=api-mobile.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
         'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
         'api-mobile.democorp.com',
         ARRAY['api-mobile.democorp.com', 'mobile-api.democorp.com'],
         'SHA256WithRSA', 'RSA', 2048,
         NOW() - INTERVAL '30 days', NOW() + INTERVAL '60 days',
         '6478b413aaed77d267483b9f69f119df41af2999',
         '42054664bbc3f6dadfb6dd677544d4efd953d2b4e5d2bdf9304e1106936616c2',
         false, false,
         ARRAY['Digital Signature', 'Key Encipherment'],
         ARRAY['Server Authentication'])

        ON CONFLICT (tenant_id, fingerprint_sha256) DO NOTHING;

        RAISE NOTICE 'Inserted sample certificates for demo tenant';

        -- Link certificates to assets via crypto_implementations
        -- This allows the "certificates" filter on the assets page to work
        DECLARE
            asset_ids UUID[];
            cert_ids UUID[];
            i INT;
            asset_id UUID;
            cert_id UUID;
        BEGIN
            -- Get some asset IDs (web servers)
            SELECT ARRAY_AGG(id) INTO asset_ids
            FROM network_assets
            WHERE tenant_id = demo_tenant_id
            AND deleted_at IS NULL
            AND asset_type = 'server'
            LIMIT 15;

            -- Get some certificate IDs
            SELECT ARRAY_AGG(id) INTO cert_ids
            FROM certificates
            WHERE tenant_id = demo_tenant_id
            LIMIT 15;

            -- Link certificates to assets via crypto_implementations
            IF asset_ids IS NOT NULL AND cert_ids IS NOT NULL THEN
                FOR i IN 1..LEAST(ARRAY_LENGTH(asset_ids, 1), ARRAY_LENGTH(cert_ids, 1)) LOOP
                    asset_id := asset_ids[i];
                    cert_id := cert_ids[i];

                    -- Create a crypto_implementation linking the asset to the certificate
                    INSERT INTO crypto_implementations (
                        tenant_id,
                        asset_id,
                        certificate_id,
                        protocol,
                        protocol_version,
                        cipher_suite,
                        hash_algorithm,
                        key_size,
                        discovery_method,
                        confidence_score,
                        risk_score,
                        first_discovered_at,
                        last_verified_at
                    ) VALUES (
                        demo_tenant_id,
                        asset_id,
                        cert_id,
                        'TLS',
                        CASE
                            WHEN i % 3 = 0 THEN 'TLSv1.2'
                            WHEN i % 3 = 1 THEN 'TLSv1.3'
                            ELSE 'TLSv1.2'
                        END,
                        CASE
                            WHEN i % 2 = 0 THEN 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
                            ELSE 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
                        END,
                        CASE
                            WHEN i % 4 = 0 THEN 'SHA256'
                            WHEN i % 4 = 1 THEN 'SHA384'
                            WHEN i % 4 = 2 THEN 'SHA256'
                            ELSE 'SHA512'
                        END,
                        CASE
                            WHEN i % 3 = 0 THEN 2048
                            WHEN i % 3 = 1 THEN 4096
                            ELSE 2048
                        END,
                        'manual',
                        0.95,
                        CASE
                            WHEN i % 5 = 0 THEN 75  -- High risk
                            WHEN i % 5 = 1 THEN 50  -- Medium risk
                            WHEN i % 5 = 2 THEN 25  -- Low risk
                            ELSE 10  -- Low risk
                        END,
                        NOW() - INTERVAL '30 days',
                        NOW()
                    )
                    ON CONFLICT DO NOTHING;
                END LOOP;

                RAISE NOTICE 'Created crypto_implementations linking % assets to certificates', LEAST(ARRAY_LENGTH(asset_ids, 1), ARRAY_LENGTH(cert_ids, 1));
            END IF;
        END;
    END IF;
END $$;

-- =================================================================
-- Verification
-- =================================================================

DO $$
DECLARE
    demo_tenant_id UUID;
    tenant_count INTEGER;
    user_count INTEGER;
    role_count INTEGER;
    permission_count INTEGER;
    assignment_count INTEGER;
    certificate_count INTEGER;
BEGIN
    SELECT id INTO demo_tenant_id FROM tenants WHERE slug = 'demo-corp';
    SELECT COUNT(*) INTO tenant_count FROM tenants WHERE slug = 'demo-corp';
    SELECT COUNT(*) INTO user_count FROM users WHERE tenant_id = demo_tenant_id;
    SELECT COUNT(*) INTO role_count FROM tenant_roles WHERE tenant_id = demo_tenant_id;
    SELECT COUNT(*) INTO permission_count FROM tenant_role_permissions trp
        JOIN tenant_roles tr ON trp.role_id = tr.id
        WHERE tr.tenant_id = demo_tenant_id;
    SELECT COUNT(*) INTO assignment_count FROM user_tenant_roles WHERE tenant_id = demo_tenant_id;

    -- =========================================================
    -- CMDB Integration Demo Profiles
    -- =========================================================
    -- Create sample CMDB sync profiles for demo-corp to showcase
    -- integration capabilities with external CMDB platforms.
    -- =========================================================

    INSERT INTO cmdb_sync_profiles (tenant_id, name, platform_type, connection_config, field_mapping_config, sync_config, ci_type_mapping, is_enabled, created_by, updated_by)
    VALUES
    (
        demo_tenant_id,
        'ServiceNow Production',
        'servicenow',
        '{
            "instance_url": "https://democorp.service-now.com",
            "auth_type": "oauth2",
            "client_id": "demo-client-id",
            "client_secret_ref": "vault:servicenow/democorp/client_secret"
        }'::jsonb,
        '{
            "infrastructure_asset": {
                "hostname": "name",
                "ip_address": "ip_address",
                "operating_system": "os",
                "environment": "u_environment",
                "business_unit": "department",
                "risk_score": "u_risk_score",
                "risk_level": "u_risk_level"
            },
            "certificate": {
                "common_name": "name",
                "serial_number": "serial_number",
                "not_after": "expiration_date",
                "issuer_dn": "issuer",
                "fingerprint_sha256": "u_fingerprint"
            }
        }'::jsonb,
        '{
            "schedule": "daily",
            "batch_size": 100,
            "conflict_resolution": "source_wins",
            "sync_deletions": false
        }'::jsonb,
        '{
            "infrastructure_asset": {
                "server": "cmdb_ci_server",
                "endpoint": "cmdb_ci_computer",
                "service": "cmdb_ci_service",
                "appliance": "cmdb_ci_hardware"
            },
            "certificate": "cmdb_ci_certificate",
            "key": "cmdb_ci_credential"
        }'::jsonb,
        false,
        (SELECT id FROM users WHERE email = 'admin@democorp.com' AND tenant_id = demo_tenant_id LIMIT 1),
        (SELECT id FROM users WHERE email = 'admin@democorp.com' AND tenant_id = demo_tenant_id LIMIT 1)
    ),
    (
        demo_tenant_id,
        'Device42 Sync',
        'device42',
        '{
            "base_url": "https://democorp.device42.net",
            "auth_type": "api_token",
            "api_token_ref": "vault:device42/democorp/api_token"
        }'::jsonb,
        '{
            "infrastructure_asset": {
                "hostname": "name",
                "ip_address": "ip_addresses",
                "operating_system": "os",
                "asset_type": "type"
            },
            "certificate": {
                "common_name": "name",
                "not_after": "valid_to"
            }
        }'::jsonb,
        '{
            "schedule": "weekly",
            "batch_size": 50,
            "conflict_resolution": "source_wins",
            "sync_deletions": false
        }'::jsonb,
        '{
            "infrastructure_asset": {
                "server": "device",
                "endpoint": "device",
                "service": "service_instance",
                "appliance": "device"
            },
            "certificate": "certificate"
        }'::jsonb,
        false,
        (SELECT id FROM users WHERE email = 'admin@democorp.com' AND tenant_id = demo_tenant_id LIMIT 1),
        (SELECT id FROM users WHERE email = 'admin@democorp.com' AND tenant_id = demo_tenant_id LIMIT 1)
    )
    ON CONFLICT (tenant_id, name) DO NOTHING;

    RAISE NOTICE '';
    RAISE NOTICE '=== Tier 2 Demo Data Loaded Successfully ===';
    RAISE NOTICE '';
    SELECT COUNT(*) INTO certificate_count FROM certificates WHERE tenant_id = demo_tenant_id;

    RAISE NOTICE 'Demo Corporation Tenant: % (id: %)', tenant_count, demo_tenant_id;
    RAISE NOTICE 'Tenant Roles: %', role_count;
    RAISE NOTICE 'Role Permissions: %', permission_count;
    RAISE NOTICE 'Demo Users: %', user_count;
    RAISE NOTICE 'User Role Assignments: %', assignment_count;
    RAISE NOTICE 'Sample Certificates: %', certificate_count;
    RAISE NOTICE 'CMDB Sync Profiles: 2 (ServiceNow, Device42)';
    RAISE NOTICE '';
    RAISE NOTICE 'Demo User Credentials (all passwords: Password123!):';
    RAISE NOTICE '  - owner@democorp.com    (Billing Admin)';
    RAISE NOTICE '  - admin@democorp.com    (Tenant Admin)';
    RAISE NOTICE '  - security@democorp.com (Security Admin)';
    RAISE NOTICE '  - analyst@democorp.com  (Viewer)';
    RAISE NOTICE '  - viewer@democorp.com   (Viewer)';
    RAISE NOTICE '  - api@democorp.com      (API User)';
    RAISE NOTICE '';
    RAISE NOTICE '=============================================';
END $$;
