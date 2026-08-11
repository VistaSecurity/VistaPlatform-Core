-- Quick check: Does the admin user exist and can they login?
-- This simulates the exact login query

SELECT 
    'User exists:' as check_type,
    pu.email,
    pu.is_active,
    pu.deleted_at,
    pu.role_id,
    pr.name as role_name,
    CASE 
        WHEN pu.password_hash IS NULL THEN 'MISSING'
        WHEN pu.password_hash = '' THEN 'EMPTY'
        ELSE 'OK'
    END as password_status
FROM platform_users pu
LEFT JOIN platform_roles pr ON pu.role_id = pr.id
WHERE pu.email = 'su_admin@vistasecurity.io';

-- This is the exact query the login handler uses
SELECT 
    'Login query result:' as check_type,
    pu.id,
    pu.email,
    pr.name as role_name
FROM platform_users pu
JOIN platform_roles pr ON pu.role_id = pr.id
WHERE pu.email = 'su_admin@vistasecurity.io' 
  AND pu.is_active = true 
  AND pu.deleted_at IS NULL;
