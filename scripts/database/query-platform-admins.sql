-- Query all platform admin users
SELECT 
    pu.id,
    pu.email,
    pu.first_name,
    pu.last_name,
    pr.name as role_name,
    pr.display_name as role_display_name,
    pu.is_active,
    pu.email_verified,
    pu.deleted_at,
    pu.last_login_at,
    pu.created_at,
    CASE 
        WHEN pu.password_hash IS NULL THEN 'MISSING'
        WHEN pu.password_hash = '' THEN 'EMPTY'
        ELSE 'SET'
    END as password_status
FROM platform_users pu
LEFT JOIN platform_roles pr ON pu.role_id = pr.id
ORDER BY pu.created_at DESC;

-- Count by role
SELECT 
    pr.name as role_name,
    COUNT(*) as user_count
FROM platform_users pu
JOIN platform_roles pr ON pu.role_id = pr.id
WHERE pu.deleted_at IS NULL
GROUP BY pr.name
ORDER BY user_count DESC;
