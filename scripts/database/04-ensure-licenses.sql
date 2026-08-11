-- =================================================================
-- Ensure Best Practices Licenses for All Tenants
-- =================================================================
-- This script runs during session-init to ensure all tenants
-- have Best Practices framework licenses, regardless of when they were created.
-- This fixes timing issues where tenants might be created before frameworks
-- are seeded, causing the trigger to fail silently.
--
-- This script is idempotent and safe to run multiple times.
-- =================================================================

DO $$
DECLARE
    best_practices_framework_id UUID;
    tenant_record RECORD;
    license_count INTEGER;
    default_count INTEGER;
    total_tenants INTEGER := 0;
    licenses_created INTEGER := 0;
    licenses_existing INTEGER := 0;
    defaults_set INTEGER := 0;
BEGIN
    -- Get Best Practices framework ID
    SELECT id INTO best_practices_framework_id
    FROM platform_frameworks
    WHERE is_platform_default = true AND status = 'published'
    LIMIT 1;

    -- If framework doesn't exist yet, this is a timing issue - skip silently
    IF best_practices_framework_id IS NULL THEN
        RAISE NOTICE 'Best Practices framework not found yet. Skipping license creation.';
        RETURN;
    END IF;

    RAISE NOTICE 'Found Best Practices framework: %', best_practices_framework_id;

    -- Loop through all tenants
    FOR tenant_record IN
        SELECT id, name, slug
        FROM tenants
        WHERE deleted_at IS NULL
        ORDER BY created_at
    LOOP
        total_tenants := total_tenants + 1;

        -- Check if Best Practices license already exists
        SELECT COUNT(*) INTO license_count
        FROM tenant_framework_licenses
        WHERE tenant_id = tenant_record.id
          AND platform_framework_id = best_practices_framework_id;

        -- Check if tenant has any default framework
        SELECT COUNT(*) INTO default_count
        FROM tenant_framework_licenses
        WHERE tenant_id = tenant_record.id
          AND is_default = true;

        IF license_count = 0 THEN
            -- Check if tenant has any other licenses to determine if this should be default
            SELECT COUNT(*) INTO license_count
            FROM tenant_framework_licenses
            WHERE tenant_id = tenant_record.id;

            -- Create Best Practices license
            -- Make it default if tenant has no other licenses OR no default exists
            INSERT INTO tenant_framework_licenses (
                id,
                tenant_id,
                platform_framework_id,
                is_locked,
                locked_at,
                locked_by,
                is_default,
                purchased_at,
                created_at,
                updated_at
            ) VALUES (
                gen_random_uuid(),
                tenant_record.id,
                best_practices_framework_id,
                false, -- Not locked (Best Practices is always available)
                NULL,
                NULL,
                (license_count = 0 OR default_count = 0), -- Default if no other licenses exist OR no default exists
                NOW(),
                NOW(),
                NOW()
            )
            ON CONFLICT (tenant_id, platform_framework_id) DO NOTHING;

            -- Check if insert succeeded (re-check Best Practices license count)
            SELECT COUNT(*) INTO license_count
            FROM tenant_framework_licenses
            WHERE tenant_id = tenant_record.id
              AND platform_framework_id = best_practices_framework_id;

            IF license_count > 0 THEN
                licenses_created := licenses_created + 1;
                RAISE NOTICE 'Created Best Practices license for tenant: % (slug: %, id: %)',
                    tenant_record.name, tenant_record.slug, tenant_record.id;
            END IF;
        ELSE
            licenses_existing := licenses_existing + 1;
        END IF;

        -- CRITICAL FIX: If tenant has Best Practices license but no default framework,
        -- set Best Practices as default
        -- Re-check both counts to ensure accuracy
        SELECT COUNT(*) INTO license_count
        FROM tenant_framework_licenses
        WHERE tenant_id = tenant_record.id
          AND platform_framework_id = best_practices_framework_id;

        SELECT COUNT(*) INTO default_count
        FROM tenant_framework_licenses
        WHERE tenant_id = tenant_record.id
          AND is_default = true;

        IF license_count > 0 AND default_count = 0 THEN
            -- First, unset any other defaults (shouldn't be any, but be safe)
            UPDATE tenant_framework_licenses
            SET is_default = false,
                updated_at = NOW()
            WHERE tenant_id = tenant_record.id
              AND is_default = true;

            -- Set Best Practices as default
            UPDATE tenant_framework_licenses
            SET is_default = true,
                updated_at = NOW()
            WHERE tenant_id = tenant_record.id
              AND platform_framework_id = best_practices_framework_id;

            defaults_set := defaults_set + 1;
            RAISE NOTICE 'Set Best Practices as default framework for tenant: % (slug: %, id: %)',
                tenant_record.name, tenant_record.slug, tenant_record.id;
        END IF;
    END LOOP;

    -- Summary
    IF total_tenants > 0 THEN
        RAISE NOTICE '========================================';
        RAISE NOTICE 'License Check Complete';
        RAISE NOTICE '========================================';
        RAISE NOTICE 'Total tenants processed: %', total_tenants;
        RAISE NOTICE 'Licenses created: %', licenses_created;
        RAISE NOTICE 'Licenses already existing: %', licenses_existing;
        RAISE NOTICE 'Defaults set: %', defaults_set;
        RAISE NOTICE '========================================';
    ELSE
        RAISE NOTICE 'No tenants found in database.';
    END IF;
END $$;
