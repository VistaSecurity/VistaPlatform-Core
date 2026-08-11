-- Revoke all refresh tokens for a user to force fresh login
-- This fixes JWT tokens with wrong tenant IDs

-- Revoke all refresh tokens for admin@democorp.com
UPDATE refresh_tokens
SET is_revoked = true, revoked_at = NOW()
WHERE user_id = (SELECT id FROM users WHERE email = 'admin@democorp.com')
  AND is_revoked = false;

-- Display summary
DO $$
DECLARE
    revoked_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO revoked_count
    FROM refresh_tokens
    WHERE user_id = (SELECT id FROM users WHERE email = 'admin@democorp.com')
      AND is_revoked = true;
    
    RAISE NOTICE '✅ Revoked % refresh tokens for admin@democorp.com', revoked_count;
    RAISE NOTICE '📝 User must log out and log back in to get fresh tokens with correct tenant ID';
END $$;
