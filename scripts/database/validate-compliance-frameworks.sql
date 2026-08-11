-- =================================================================
-- Validation Script: Compliance Frameworks
-- Verifies that all compliance frameworks are properly configured
-- =================================================================

DO $$
DECLARE
    framework_record RECORD;
    controls_count INTEGER;
    measurements_count INTEGER;
    total_frameworks INTEGER := 0;
    total_controls INTEGER := 0;
    total_measurements INTEGER := 0;
BEGIN
    RAISE NOTICE '=================================================================';
    RAISE NOTICE 'Compliance Framework Validation Report';
    RAISE NOTICE '=================================================================';
    RAISE NOTICE '';
    
    FOR framework_record IN
        SELECT id, code, name, version, status, is_platform_default
        FROM platform_frameworks
        WHERE status = 'published'
        ORDER BY is_platform_default DESC, code
    LOOP
        total_frameworks := total_frameworks + 1;
        
        -- Count controls
        SELECT COUNT(*) INTO controls_count
        FROM platform_framework_controls
        WHERE framework_id = framework_record.id;
        
        -- Count measurements
        SELECT COUNT(*) INTO measurements_count
        FROM control_measurements cm
        JOIN platform_framework_controls pfc ON cm.control_id = pfc.id
        WHERE pfc.framework_id = framework_record.id
        AND cm.framework_type = 'platform';
        
        total_controls := total_controls + controls_count;
        total_measurements := total_measurements + measurements_count;
        
        RAISE NOTICE 'Framework: % (%)', framework_record.name, framework_record.code;
        RAISE NOTICE '  Version: %', framework_record.version;
        RAISE NOTICE '  Status: %', framework_record.status;
        IF framework_record.is_platform_default THEN
            RAISE NOTICE '  Platform Default: YES (Best Practices)';
        END IF;
        RAISE NOTICE '  Controls: %', controls_count;
        RAISE NOTICE '  Measurements: %', measurements_count;
        
        IF controls_count = 0 THEN
            RAISE WARNING '  ⚠️  Framework has no controls!';
        ELSIF measurements_count = 0 THEN
            RAISE WARNING '  ⚠️  Framework has no measurements mapped!';
        ELSIF measurements_count < controls_count THEN
            RAISE NOTICE '  ⚠️  Some controls may be missing measurements';
        ELSE
            RAISE NOTICE '  ✅ Framework configuration looks good';
        END IF;
        
        RAISE NOTICE '';
    END LOOP;
    
    RAISE NOTICE '=================================================================';
    RAISE NOTICE 'Summary:';
    RAISE NOTICE '  Total Frameworks: %', total_frameworks;
    RAISE NOTICE '  Total Controls: %', total_controls;
    RAISE NOTICE '  Total Measurements: %', total_measurements;
    RAISE NOTICE '=================================================================';
    
END $$;
