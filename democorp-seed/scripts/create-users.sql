-- =================================================================
-- DemoCorp Users Creation
-- =================================================================
-- Creates 6 demo users for the DemoCorp tenant (one per default tenant
-- role, plus an analyst user who holds viewer — the analyst role was
-- retired in)
-- Password for all users: Password123! (Argon2id hash)
--
-- GRANT MODEL (.3): the role grants below mirror the canonical
-- reconciliation filters in seed.sql's "Ensure Tenant Roles for All Tenants"
-- DO block (the source of truth, also mirrored by auth-service's
-- assignRolePermissions). Keep the filters in sync with seed.sql — drift
-- here would give the demo tenant different grants until the next
-- reconciliation run.
-- =================================================================

-- =================================================================
-- Section 1: Tenant Roles for DemoCorp
-- =================================================================
-- These roles match what auth-service creates dynamically for new tenants

INSERT INTO tenant_roles (tenant_id, name, display_name, description, is_system_role)
SELECT
    t.id,
    'billing_admin',
    'Billing Admin',
    'Billing and account ownership. Pays the bills; cannot perform operational work.',
    true
FROM tenants t WHERE t.slug = 'democorp'
ON CONFLICT (tenant_id, name) DO NOTHING;

INSERT INTO tenant_roles (tenant_id, name, display_name, description, is_system_role)
SELECT
    t.id,
    'tenant_admin',
    'Tenant Administrator',
    'Full operational and user management; reads billing but cannot change it.',
    true
FROM tenants t WHERE t.slug = 'democorp'
ON CONFLICT (tenant_id, name) DO NOTHING;

INSERT INTO tenant_roles (tenant_id, name, display_name, description, is_system_role)
SELECT
    t.id,
    'security_admin',
    'Security Administrator',
    'Security operations, compliance, reports; reads users and settings for incident response.',
    true
FROM tenants t WHERE t.slug = 'democorp'
ON CONFLICT (tenant_id, name) DO NOTHING;

INSERT INTO tenant_roles (tenant_id, name, display_name, description, is_system_role)
SELECT
    t.id,
    'viewer',
    'Viewer',
    'Read-only access to tenant operational data (no billing).',
    true
FROM tenants t WHERE t.slug = 'democorp'
ON CONFLICT (tenant_id, name) DO NOTHING;

INSERT INTO tenant_roles (tenant_id, name, display_name, description, is_system_role)
SELECT
    t.id,
    'api_user',
    'API User',
    'Read-only integration scope across operational data.',
    true
FROM tenants t WHERE t.slug = 'democorp'
ON CONFLICT (tenant_id, name) DO NOTHING;

-- =================================================================
-- Section 2: Tenant Role Permissions
-- =================================================================

-- Billing Admin — billing + read-only visibility into who has access and
-- basic tenant settings (mirrors seed.sql's reconciliation filter)
INSERT INTO tenant_role_permissions (role_id, permission_id)
SELECT tr.id, tp.id
FROM tenant_roles tr
CROSS JOIN tenant_permissions tp
WHERE tr.name = 'billing_admin'
  AND tr.tenant_id = (SELECT id FROM tenants WHERE slug = 'democorp')
  AND (tp.resource = 'billing' OR tp.name IN ('settings.read', 'users.read'))
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Tenant Admin — everything except billing.update (gets billing.read)
INSERT INTO tenant_role_permissions (role_id, permission_id)
SELECT tr.id, tp.id
FROM tenant_roles tr
CROSS JOIN tenant_permissions tp
WHERE tr.name = 'tenant_admin'
  AND tr.tenant_id = (SELECT id FROM tenants WHERE slug = 'democorp')
  AND tp.name <> 'billing.update'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Security Admin — operational/security scope + users.read + settings.read
-- for incident response
INSERT INTO tenant_role_permissions (role_id, permission_id)
SELECT tr.id, tp.id
FROM tenant_roles tr
CROSS JOIN tenant_permissions tp
WHERE tr.name = 'security_admin'
  AND tr.tenant_id = (SELECT id FROM tenants WHERE slug = 'democorp')
  AND (tp.resource IN ('assets', 'sensors', 'reports', 'compliance', 'pcap', 'discovery', 'alerts')
       OR tp.name IN ('users.read', 'settings.read'))
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Viewer — read-only across all operational resources (no billing)
INSERT INTO tenant_role_permissions (role_id, permission_id)
SELECT tr.id, tp.id
FROM tenant_roles tr
CROSS JOIN tenant_permissions tp
WHERE tr.name = 'viewer'
  AND tr.tenant_id = (SELECT id FROM tenants WHERE slug = 'democorp')
  AND tp.action = 'read' AND tp.resource <> 'billing'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- API User — read-only integration scope across operational data
INSERT INTO tenant_role_permissions (role_id, permission_id)
SELECT tr.id, tp.id
FROM tenant_roles tr
CROSS JOIN tenant_permissions tp
WHERE tr.name = 'api_user'
  AND tr.tenant_id = (SELECT id FROM tenants WHERE slug = 'democorp')
  AND tp.action = 'read'
  AND tp.resource IN ('assets', 'sensors', 'reports', 'compliance', 'discovery', 'pcap')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- =================================================================
-- Section 3: DemoCorp Users
-- =================================================================
-- Password for all users: Password123! (Argon2id hash)

-- Billing Admin: owner@democorp.com
INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, is_active, email_verified, created_at, updated_at)
SELECT
    gen_random_uuid(),
    t.id,
    'owner@democorp.com',
    '$argon2id$v=19$m=65536,t=3,p=2$8Ll1hG8Y7AO+m8hQxRuozA$nO6gHyQ3JAccN5XWX5gjdnxTx+XutgIHYGCuXpJ2LKQ',
    'DemoCorp', 'Owner', true, true, NOW(), NOW()
FROM tenants t WHERE t.slug = 'democorp'
ON CONFLICT ON CONSTRAINT unique_tenant_email DO NOTHING;

-- Tenant Admin: admin@democorp.com
INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, is_active, email_verified, created_at, updated_at)
SELECT
    gen_random_uuid(),
    t.id,
    'admin@democorp.com',
    '$argon2id$v=19$m=65536,t=3,p=2$8Ll1hG8Y7AO+m8hQxRuozA$nO6gHyQ3JAccN5XWX5gjdnxTx+XutgIHYGCuXpJ2LKQ',
    'DemoCorp', 'Admin', true, true, NOW(), NOW()
FROM tenants t WHERE t.slug = 'democorp'
ON CONFLICT ON CONSTRAINT unique_tenant_email DO NOTHING;

-- Security Admin: security@democorp.com
INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, is_active, email_verified, created_at, updated_at)
SELECT
    gen_random_uuid(),
    t.id,
    'security@democorp.com',
    '$argon2id$v=19$m=65536,t=3,p=2$8Ll1hG8Y7AO+m8hQxRuozA$nO6gHyQ3JAccN5XWX5gjdnxTx+XutgIHYGCuXpJ2LKQ',
    'DemoCorp', 'Security', true, true, NOW(), NOW()
FROM tenants t WHERE t.slug = 'democorp'
ON CONFLICT ON CONSTRAINT unique_tenant_email DO NOTHING;

-- Analyst: analyst@democorp.com
INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, is_active, email_verified, created_at, updated_at)
SELECT
    gen_random_uuid(),
    t.id,
    'analyst@democorp.com',
    '$argon2id$v=19$m=65536,t=3,p=2$8Ll1hG8Y7AO+m8hQxRuozA$nO6gHyQ3JAccN5XWX5gjdnxTx+XutgIHYGCuXpJ2LKQ',
    'DemoCorp', 'Analyst', true, true, NOW(), NOW()
FROM tenants t WHERE t.slug = 'democorp'
ON CONFLICT ON CONSTRAINT unique_tenant_email DO NOTHING;

-- Viewer: viewer@democorp.com
INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, is_active, email_verified, created_at, updated_at)
SELECT
    gen_random_uuid(),
    t.id,
    'viewer@democorp.com',
    '$argon2id$v=19$m=65536,t=3,p=2$8Ll1hG8Y7AO+m8hQxRuozA$nO6gHyQ3JAccN5XWX5gjdnxTx+XutgIHYGCuXpJ2LKQ',
    'DemoCorp', 'Viewer', true, true, NOW(), NOW()
FROM tenants t WHERE t.slug = 'democorp'
ON CONFLICT ON CONSTRAINT unique_tenant_email DO NOTHING;

-- API User: api@democorp.com
INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, is_active, email_verified, created_at, updated_at)
SELECT
    gen_random_uuid(),
    t.id,
    'api@democorp.com',
    '$argon2id$v=19$m=65536,t=3,p=2$8Ll1hG8Y7AO+m8hQxRuozA$nO6gHyQ3JAccN5XWX5gjdnxTx+XutgIHYGCuXpJ2LKQ',
    'DemoCorp', 'API', true, true, NOW(), NOW()
FROM tenants t WHERE t.slug = 'democorp'
ON CONFLICT ON CONSTRAINT unique_tenant_email DO NOTHING;

-- =================================================================
-- Section 4: User Role Assignments
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
WHERE u.email = 'owner@democorp.com' AND t.slug = 'democorp'
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
WHERE u.email = 'admin@democorp.com' AND t.slug = 'democorp'
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
WHERE u.email = 'security@democorp.com' AND t.slug = 'democorp'
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
WHERE u.email = 'analyst@democorp.com' AND t.slug = 'democorp'
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
WHERE u.email = 'viewer@democorp.com' AND t.slug = 'democorp'
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
WHERE u.email = 'api@democorp.com' AND t.slug = 'democorp'
ON CONFLICT ON CONSTRAINT user_tenant_roles_user_id_tenant_id_role_id_key DO UPDATE SET is_active = true;

-- =================================================================
-- Verification
-- =================================================================

DO $$
DECLARE
    v_tenant_id UUID;
    user_count INTEGER;
    role_count INTEGER;
BEGIN
    SELECT id INTO v_tenant_id FROM tenants WHERE slug = 'democorp' LIMIT 1;
    SELECT COUNT(*) INTO user_count FROM users WHERE tenant_id = v_tenant_id AND deleted_at IS NULL;
    SELECT COUNT(*) INTO role_count FROM tenant_roles WHERE tenant_id = v_tenant_id;

    RAISE NOTICE 'DemoCorp users created/verified';
    RAISE NOTICE '  Tenant ID: %', v_tenant_id;
    RAISE NOTICE '  Users: %', user_count;
    RAISE NOTICE '  Roles: %', role_count;

    IF user_count < 6 THEN
        RAISE WARNING 'Expected 6 users, found %', user_count;
    END IF;

    IF role_count < 6 THEN
        RAISE WARNING 'Expected 6 roles, found %', role_count;
    END IF;
END $$;
