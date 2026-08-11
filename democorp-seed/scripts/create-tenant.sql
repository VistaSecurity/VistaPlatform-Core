-- =================================================================
-- DemoCorp Tenant Creation
-- =================================================================
-- Creates the DemoCorp tenant with the 'pro' subscription tier
-- This triggers auto-licensing of Best Practices framework via database trigger
-- =================================================================

INSERT INTO tenants (name, slug, subscription_tier_id, billing_email, payment_status, domain)
SELECT
    'DemoCorp',
    'democorp',
    st.id,
    'admin@democorp.com',
    'active',
    'democorp.com'
FROM subscription_tiers st
WHERE st.name = 'pro'
ON CONFLICT (slug) DO NOTHING;

-- Verify tenant creation
DO $$
DECLARE
    tenant_id UUID;
    tenant_count INTEGER;
BEGIN
    SELECT id INTO tenant_id FROM tenants WHERE slug = 'democorp' LIMIT 1;
    SELECT COUNT(*) INTO tenant_count FROM tenants WHERE slug = 'democorp';

    IF tenant_count > 0 THEN
        RAISE NOTICE 'DemoCorp tenant created/verified (id: %)', tenant_id;
    ELSE
        RAISE EXCEPTION 'Failed to create DemoCorp tenant';
    END IF;
END $$;
