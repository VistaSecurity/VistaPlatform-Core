-- =================================================================
-- Demo Corporation - Compliance Framework Configuration (Tier 2)
-- =================================================================
-- This script configures compliance frameworks for the demo tenant.
-- It creates a tenant framework copy of the Best Practices framework
-- and optionally sets it as the selected framework.
--
-- Note: Best Practices framework license is automatically created
-- by the database trigger (auto_license_best_practices_on_tenant_create)
-- when the tenant is created, so no manual license creation is needed here.
-- =================================================================

DO $$
DECLARE
    demo_tenant_id UUID;
    best_practices_framework_id UUID;
    tenant_framework_id UUID;
    platform_control_record RECORD;
    tenant_control_id UUID;
    control_measurement_record RECORD;
    platform_admin_id UUID;
    demo_finding_id UUID;
    demo_control_id UUID;
    demo_asset_id UUID;
    security_user_id UUID;
    admin_user_id UUID;
    demo_ticket_id UUID;
    nist_framework_id UUID;
    nist_control_id UUID;
    nist_finding_id UUID;
BEGIN
    -- Get demo tenant ID
    SELECT id INTO demo_tenant_id
    FROM tenants
    WHERE slug = 'demo-corp'
    LIMIT 1;

    IF demo_tenant_id IS NULL THEN
        RAISE NOTICE 'Demo tenant (demo-corp) not found. Run seed_demo.sql first.';
        RETURN;
    END IF;

    -- Get Best Practices framework ID
    SELECT id INTO best_practices_framework_id
    FROM platform_frameworks
    WHERE code = 'best-practices' AND version = '1.0' AND is_platform_default = true AND status = 'published'
    LIMIT 1;

    IF best_practices_framework_id IS NULL THEN
        RAISE NOTICE 'Best Practices framework not found. Run seed.sql first.';
        RETURN;
    END IF;

    -- Get a user from the demo tenant for created_by field
    -- tenant_frameworks.created_by references users(id), not platform_users
    SELECT id INTO platform_admin_id
    FROM users
    WHERE tenant_id = demo_tenant_id
    AND deleted_at IS NULL
    ORDER BY created_at ASC
    LIMIT 1;

    -- Check if tenant already has Best Practices framework
    SELECT id INTO tenant_framework_id
    FROM tenant_frameworks
    WHERE tenant_id = demo_tenant_id
    AND source_framework_id = best_practices_framework_id
    LIMIT 1;

    -- Create tenant framework copy if it doesn't exist
    IF tenant_framework_id IS NULL THEN
        INSERT INTO tenant_frameworks (
            id, tenant_id, name, version, description, source_framework_id, created_by, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            demo_tenant_id,
            'Security Best Practices',
            '1.0',
            'Core security best practices for cryptographic implementations. Available to all subscription tiers.',
            best_practices_framework_id,
            platform_admin_id,
            NOW(),
            NOW()
        )
        ON CONFLICT (tenant_id, name, version) DO NOTHING
        RETURNING id INTO tenant_framework_id;

        IF tenant_framework_id IS NOT NULL THEN
            RAISE NOTICE 'Created tenant framework copy for demo-corp (id: %)', tenant_framework_id;

            -- Copy all controls from platform framework to tenant framework
            FOR platform_control_record IN
                SELECT id, control_id, title, description, baseline_severity, crypto_relevant
                FROM platform_framework_controls
                WHERE framework_id = best_practices_framework_id
            LOOP
                -- Create tenant control
                INSERT INTO tenant_framework_controls (
                    id, framework_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at
                ) VALUES (
                    gen_random_uuid(),
                    tenant_framework_id,
                    platform_control_record.control_id,
                    platform_control_record.title,
                    platform_control_record.description,
                    platform_control_record.baseline_severity,
                    platform_control_record.crypto_relevant,
                    NOW(),
                    NOW()
                )
                ON CONFLICT (framework_id, control_id) DO NOTHING
                RETURNING id INTO tenant_control_id;

                -- Copy control measurements for this control
                IF tenant_control_id IS NOT NULL THEN
                    FOR control_measurement_record IN
                        SELECT measurement_type_id, rule_type, predicate, severity_override, weight
                        FROM control_measurements
                        WHERE control_id = platform_control_record.id
                        AND framework_type = 'platform'
                    LOOP
                        INSERT INTO control_measurements (
                            id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at
                        ) VALUES (
                            gen_random_uuid(),
                            tenant_control_id,
                            'tenant',
                            control_measurement_record.measurement_type_id,
                            control_measurement_record.rule_type,
                            control_measurement_record.predicate,
                            control_measurement_record.severity_override,
                            control_measurement_record.weight,
                            NOW(),
                            NOW()
                        )
                        ON CONFLICT DO NOTHING;
                    END LOOP;
                END IF;
            END LOOP;

            RAISE NOTICE 'Copied all controls and measurements to tenant framework';
        ELSE
            RAISE WARNING 'Failed to create tenant framework (may already exist)';
        END IF;
    ELSE
        RAISE NOTICE 'Tenant framework already exists for demo-corp (id: %)', tenant_framework_id;
    END IF;

    -- Set the tenant framework as selected in tenant settings
    -- Update tenants.settings JSONB field with frameworkId
    UPDATE tenants
    SET settings = jsonb_set(
        COALESCE(settings, '{}'::jsonb),
        '{frameworkId}',
        to_jsonb(tenant_framework_id::text)
    ),
    updated_at = NOW()
    WHERE id = demo_tenant_id
    AND (settings->>'frameworkId' IS NULL OR settings->>'frameworkId' != tenant_framework_id::text);

    IF FOUND THEN
        RAISE NOTICE 'Set Best Practices framework as selected for demo-corp tenant';
    ELSE
        RAISE NOTICE 'Framework already selected or settings update not needed';
    END IF;

    RAISE NOTICE '✅ Compliance configuration complete for demo-corp tenant';

    -- =================================================================
    -- Event-Driven Findings Generation
    -- =================================================================
    -- Instead of directly inserting compliance findings, we now use an
    -- event-driven approach:
    --
    -- 1. Seed assets/certificates with actual violations (see
    --    seed_democorp_compliance_violations.sql)
    -- 2. Trigger AssetChangedEvent events for these assets
    -- 3. The compliance engine evaluates controls and generates findings
    --    naturally through the normal evaluation flow
    --
    -- This ensures findings persist through re-evaluation and match
    -- actual asset violations.
    --
    -- The violation seeding and event triggering is handled by:
    -- - seed_democorp_compliance_violations.sql (seeds violations)
    -- - trigger-compliance-evaluation.sh (triggers events)
    --
    -- These are called from load-demo-data.sh after this script completes.
    -- =================================================================

    RAISE NOTICE 'ℹ️  Compliance findings will be generated via event-driven evaluation';
    RAISE NOTICE '   Run seed_democorp_compliance_violations.sql and trigger-compliance-evaluation.sh';

END $$;
