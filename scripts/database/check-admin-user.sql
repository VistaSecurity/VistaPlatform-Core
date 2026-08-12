-- Diagnostic script to check admin user status
-- Run this to verify the admin user exists and is configured correctly

-- Check if platform_roles exist
SELECT 'Platform Roles:' as check_type, COUNT(*) as count FROM platform_roles;
SELECT name, display_name, is_system_role FROM platform_roles;

-- Check if admin user exists
SELECT 'Admin User Exists:' as check_type, COUNT(*) as count 
FROM platform_users 
WHERE email = 'su_admin@vistaplatform.invalid';

-- Check admin user details
SELECT 
    pu.id,
    pu.email,
    pu.first_name,
    pu.last_name,
    pu.role_id,
    pr.name as role_name,
    pu.is_active,
    pu.email_verified,
    pu.deleted_at,
    CASE 
        WHEN pu.password_hash IS NULL THEN 'NULL'
        WHEN pu.password_hash = '' THEN 'EMPTY'
        ELSE 'SET'
    END as password_status,
    LEFT(pu.password_hash, 50) as password_hash_preview
FROM platform_users pu
LEFT JOIN platform_roles pr ON pu.role_id = pr.id
WHERE pu.email = 'su_admin@vistaplatform.invalid';

-- Check if the login query would work
SELECT 
    'Login Query Test:' as check_type,
    CASE 
        WHEN COUNT(*) > 0 THEN 'SUCCESS - User can login'
        ELSE 'FAIL - User cannot login'
    END as result
FROM platform_users pu
JOIN platform_roles pr ON pu.role_id = pr.id
WHERE pu.email = 'su_admin@vistaplatform.invalid' 
  AND pu.is_active = true 
  AND pu.deleted_at IS NULL;
