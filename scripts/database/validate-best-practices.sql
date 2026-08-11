-- =================================================================
-- Validation Script: Best Practices Framework
-- Verifies that Best Practices framework is properly configured
-- =================================================================

DO $$
DECLARE
    best_practices_framework_id UUID;
    controls_count INTEGER;
    measurements_count INTEGER;
    tenants_with_framework INTEGER;
BEGIN
    -- Check if Best Practices framework exists
    SELECT id INTO best_practices_framework_id
    FROM platform_frameworks
    WHERE code = 'best-practices' AND version = '1.0' AND is_platform_default = true
    LIMIT 1;
    
    IF best_practices_framework_id IS NULL THEN
        RAISE NOTICE '❌ Best Practices framework not found';
        RAISE NOTICE '   Run: scripts/database/33-seed-best-practices-framework.sql';
    ELSE
        RAISE NOTICE '✅ Best Practices framework exists: %', best_practices_framework_id;
        
        -- Check controls
        SELECT COUNT(*) INTO controls_count
        FROM platform_framework_controls
        WHERE framework_id = best_practices_framework_id;
        
        IF controls_count >= 10 THEN
            RAISE NOTICE '✅ Best Practices has % controls (expected: 10+)', controls_count;
        ELSE
            RAISE NOTICE '⚠️  Best Practices has only % controls (expected: 10+)', controls_count;
        END IF;
        
        -- Check measurements
        SELECT COUNT(*) INTO measurements_count
        FROM control_measurements cm
        JOIN platform_framework_controls pfc ON cm.control_id = pfc.id
        WHERE pfc.framework_id = best_practices_framework_id
        AND cm.framework_type = 'platform';
        
        IF measurements_count >= 10 THEN
            RAISE NOTICE '✅ Best Practices controls have % measurements mapped', measurements_count;
        ELSE
            RAISE NOTICE '⚠️  Best Practices controls have only % measurements (expected: 10+)', measurements_count;
        END IF;
        
        -- Check tenant assignments (sample check - count tenants with Best Practices)
        SELECT COUNT(DISTINCT tenant_id) INTO tenants_with_framework
        FROM tenant_frameworks
        WHERE source_framework_id = best_practices_framework_id;
        
        RAISE NOTICE 'ℹ️  % tenant(s) have Best Practices framework assigned', tenants_with_framework;
    END IF;
    
END $$;
