-- Ensure su_admin@vistaplatform.invalid has ALL platform permissions
-- This script ensures the super_admin role has all available permissions

-- First, ensure all platform permissions exist
INSERT INTO platform_permissions (name, resource, action, description) VALUES
-- Tenant management
('tenants.create', 'tenants', 'create', 'Create new tenants'),
('tenants.read', 'tenants', 'read', 'View tenant information'),
('tenants.update', 'tenants', 'update', 'Update tenant settings'),
('tenants.delete', 'tenants', 'delete', 'Delete tenants'),
('tenants.manage', 'tenants', 'manage', 'Full tenant management'),
('tenants.activate', 'tenants', 'update', 'Activate tenants'),
('tenants.suspend', 'tenants', 'update', 'Suspend tenants'),

-- Platform user management
('platform_users.create', 'platform_users', 'create', 'Create platform users'),
('platform_users.read', 'platform_users', 'read', 'View platform users'),
('platform_users.update', 'platform_users', 'update', 'Update platform users'),
('platform_users.delete', 'platform_users', 'delete', 'Delete platform users'),

-- Platform roles
('platform_roles.read', 'platform_roles', 'read', 'View platform roles'),
('platform_roles.assign', 'platform_roles', 'manage', 'Assign platform roles to platform users'),

-- Platform permissions
('platform_permissions.read', 'platform_permissions', 'read', 'View platform permissions'),

-- Tenant roles
('tenant_roles.assign', 'tenant_roles', 'manage', 'Assign tenant roles across tenants'),

-- Platform settings
('platform.settings', 'platform', 'manage', 'Manage platform settings'),
('platform.billing', 'platform', 'manage', 'Manage platform billing'),
('platform.analytics', 'platform', 'read', 'View platform analytics'),
('platform.health', 'platform', 'read', 'View platform health and monitoring dashboards'),
('platform.logs', 'platform', 'read', 'View platform logs'),
('platform.logs.manage', 'platform', 'manage', 'Manage platform logging configuration'),
('platform.security', 'platform', 'read', 'View security dashboard and events'),
('platform.security.manage', 'platform', 'manage', 'Manage security settings and incidents'),
('platform.audit', 'platform', 'read', 'View platform audit logs'),
('platform.override', 'platform', 'manage', 'Override permissions in exceptional cases'),

-- Support access
('support.tenants', 'tenants', 'read', 'View tenant data for support'),
('support.users', 'users', 'read', 'View user data for support')
ON CONFLICT (name) DO NOTHING;

-- Ensure super_admin role exists
INSERT INTO platform_roles (name, display_name, description, is_system_role) VALUES
('super_admin', 'Super Administrator', 'Full platform access, can manage all tenants and platform settings', true)
ON CONFLICT (name) DO NOTHING;

-- Assign ALL permissions to super_admin role
INSERT INTO platform_role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM platform_roles r, platform_permissions p
WHERE r.name = 'super_admin'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Ensure su_admin@vistaplatform.invalid has super_admin role
UPDATE platform_users
SET 
    role_id = (SELECT id FROM platform_roles WHERE name = 'super_admin' LIMIT 1),
    is_active = true,
    email_verified = true,
    deleted_at = NULL,
    updated_at = NOW()
WHERE email = 'su_admin@vistaplatform.invalid';

-- Verify the setup
SELECT 
    'Verification:' as status,
    pu.email,
    pr.name as role_name,
    COUNT(DISTINCT pp.id) as permission_count,
    (SELECT COUNT(*) FROM platform_permissions) as total_permissions
FROM platform_users pu
JOIN platform_roles pr ON pu.role_id = pr.id
JOIN platform_role_permissions prp ON pr.id = prp.role_id
JOIN platform_permissions pp ON prp.permission_id = pp.id
WHERE pu.email = 'su_admin@vistaplatform.invalid'
GROUP BY pu.email, pr.name;
