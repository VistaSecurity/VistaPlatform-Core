-- =================================================================
-- Demo Corporation - Crypto Configurations Seed Data
-- =================================================================
-- This script creates realistic crypto configurations (stored in
-- crypto_implementations table) linking infrastructure assets to
-- certificates, enabling proper compliance evaluation and unified
-- inventory views.
--
-- CMDB Terminology:
--   crypto_implementations table = "Crypto Configurations" in UI/API v2
--   Each row represents a specific cryptographic protocol configuration
--   observed on an infrastructure asset.
--
-- This is part of Tier 2 demo data and should be loaded after
-- assets and certificates are created.
-- =================================================================

DO $$
DECLARE
    demo_tenant_id UUID;
    asset_record RECORD;
    cert_record RECORD;
    crypto_impl_id UUID;
    cert_count INTEGER;
    impl_count INTEGER := 0;
    -- Arrays for realistic crypto configurations
    tls_versions TEXT[] := ARRAY['TLSv1.2', 'TLSv1.3'];
    tls12_cipher_suites TEXT[] := ARRAY[
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'TLS_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_RSA_WITH_AES_128_GCM_SHA256'
    ];
    tls13_cipher_suites TEXT[] := ARRAY[
        'TLS_AES_256_GCM_SHA384',
        'TLS_AES_128_GCM_SHA256',
        'TLS_CHACHA20_POLY1305_SHA256'
    ];
    hash_algorithms TEXT[] := ARRAY['SHA256', 'SHA384', 'SHA512'];
    key_sizes INTEGER[] := ARRAY[2048, 3072, 4096];
    random_idx INTEGER;
BEGIN
    -- Get demo tenant ID
    SELECT id INTO demo_tenant_id
    FROM tenants
    WHERE slug = 'demo-corp'
    LIMIT 1;

    IF demo_tenant_id IS NULL THEN
        RAISE EXCEPTION 'Demo tenant (demo-corp) not found. Run seed_demo.sql first.';
    END IF;

    RAISE NOTICE 'Creating crypto implementations for demo-corp tenant...';

    -- =================================================================
    -- Link Web Servers (port 443) to Certificates
    -- =================================================================
    -- Web servers typically use TLS/HTTPS, so link them to leaf certificates
    FOR asset_record IN
        SELECT id, hostname, ip_address, port, asset_type, environment
        FROM network_assets
        WHERE tenant_id = demo_tenant_id
        AND deleted_at IS NULL
        AND port = 443
        AND asset_type IN ('server', 'service')
        ORDER BY RANDOM()
        LIMIT 50  -- Link up to 50 web servers
    LOOP
        -- Find a matching certificate (leaf certificate, not CA)
        SELECT id INTO cert_record
        FROM certificates
        WHERE tenant_id = demo_tenant_id
        AND is_ca_certificate = false
        AND (
            -- Match by hostname if available
            (asset_record.hostname IS NOT NULL AND common_name LIKE '%' || SPLIT_PART(asset_record.hostname, '.', 1) || '%')
            OR
            -- Or just pick a random certificate
            true
        )
        ORDER BY RANDOM()
        LIMIT 1;

        IF cert_record.id IS NOT NULL THEN
            -- Randomly choose TLS version (70% TLS 1.3, 30% TLS 1.2 for modern setup)
            random_idx := CASE WHEN random() < 0.7 THEN 2 ELSE 1 END;
            DECLARE
                protocol_ver TEXT := tls_versions[random_idx];
                cipher_suite TEXT;
                hash_alg TEXT;
                key_size_val INTEGER;
            BEGIN
                -- Select cipher suite based on TLS version
                IF protocol_ver = 'TLSv1.3' THEN
                    cipher_suite := tls13_cipher_suites[1 + floor(random() * array_length(tls13_cipher_suites, 1))::int];
                ELSE
                    cipher_suite := tls12_cipher_suites[1 + floor(random() * array_length(tls12_cipher_suites, 1))::int];
                END IF;

                hash_alg := hash_algorithms[1 + floor(random() * array_length(hash_algorithms, 1))::int];
                key_size_val := key_sizes[1 + floor(random() * array_length(key_sizes, 1))::int];

                -- Create crypto implementation
                INSERT INTO crypto_implementations (
                    tenant_id,
                    asset_id,
                    certificate_id,
                    protocol,
                    protocol_version,
                    cipher_suite,
                    key_exchange_algorithm,
                    signature_algorithm,
                    symmetric_encryption,
                    hash_algorithm,
                    key_size,
                    discovery_method,
                    confidence_score,
                    risk_score,
                    first_discovered_at,
                    last_verified_at,
                    created_at,
                    updated_at
                ) VALUES (
                    demo_tenant_id,
                    asset_record.id,
                    cert_record.id,
                    'TLS'::protocol_type,
                    protocol_ver,
                    cipher_suite,
                    CASE WHEN protocol_ver = 'TLSv1.3' THEN NULL ELSE 'ECDHE' END,
                    CASE WHEN protocol_ver = 'TLSv1.3' THEN NULL ELSE 'RSA' END,
                    CASE
                        WHEN cipher_suite LIKE '%AES_256%' THEN 'AES-256-GCM'
                        WHEN cipher_suite LIKE '%AES_128%' THEN 'AES-128-GCM'
                        WHEN cipher_suite LIKE '%CHACHA20%' THEN 'ChaCha20-Poly1305'
                        ELSE 'AES-256-GCM'
                    END,
                    hash_alg,
                    key_size_val,
                    'manual'::discovery_method,
                    0.95,
                    CASE
                        WHEN protocol_ver = 'TLSv1.2' AND key_size_val < 2048 THEN 60
                        WHEN protocol_ver = 'TLSv1.2' THEN 30
                        ELSE 10
                    END,
                    NOW() - INTERVAL '30 days' - (random() * INTERVAL '90 days'),
                    NOW() - INTERVAL '1 hour' - (random() * INTERVAL '24 hours'),
                    NOW() - INTERVAL '30 days' - (random() * INTERVAL '90 days'),
                    NOW()
                )
                ON CONFLICT DO NOTHING
                RETURNING id INTO crypto_impl_id;

                IF crypto_impl_id IS NOT NULL THEN
                    impl_count := impl_count + 1;

                    -- Link certificate to crypto implementation via junction table
                    -- Link certificate to crypto implementation via junction table
                    -- Note: Primary certificate is already in crypto_implementations.certificate_id
                    -- Junction table is for additional certificates in chain, but we'll add it here too for completeness
                    INSERT INTO crypto_implementation_certificates (
                        crypto_implementation_id,
                        certificate_id,
                        certificate_role,
                        certificate_order
                    ) VALUES (
                        crypto_impl_id,
                        cert_record.id,
                        'additional',
                        0
                    )
                    ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
                END IF;
            END;
        END IF;
    END LOOP;

    -- =================================================================
    -- Link API Services to Certificates
    -- =================================================================
    -- API services on ports 8080, 8443, 9090 should also have TLS
    FOR asset_record IN
        SELECT id, hostname, ip_address, port, asset_type, environment
        FROM network_assets
        WHERE tenant_id = demo_tenant_id
        AND deleted_at IS NULL
        AND port IN (8080, 8443, 9090)
        AND asset_type = 'service'
        ORDER BY RANDOM()
        LIMIT 30
    LOOP
        -- Find a matching certificate
        SELECT id INTO cert_record
        FROM certificates
        WHERE tenant_id = demo_tenant_id
        AND is_ca_certificate = false
        AND (
            (asset_record.hostname IS NOT NULL AND (common_name LIKE '%api%' OR common_name LIKE '%service%'))
            OR true
        )
        ORDER BY RANDOM()
        LIMIT 1;

        IF cert_record.id IS NOT NULL THEN
            random_idx := CASE WHEN random() < 0.6 THEN 2 ELSE 1 END;
            DECLARE
                protocol_ver TEXT := tls_versions[random_idx];
                cipher_suite TEXT;
                hash_alg TEXT;
                key_size_val INTEGER;
            BEGIN
                IF protocol_ver = 'TLSv1.3' THEN
                    cipher_suite := tls13_cipher_suites[1 + floor(random() * array_length(tls13_cipher_suites, 1))::int];
                ELSE
                    cipher_suite := tls12_cipher_suites[1 + floor(random() * array_length(tls12_cipher_suites, 1))::int];
                END IF;

                hash_alg := hash_algorithms[1 + floor(random() * array_length(hash_algorithms, 1))::int];
                key_size_val := key_sizes[1 + floor(random() * array_length(key_sizes, 1))::int];

                INSERT INTO crypto_implementations (
                    tenant_id,
                    asset_id,
                    certificate_id,
                    protocol,
                    protocol_version,
                    cipher_suite,
                    key_exchange_algorithm,
                    signature_algorithm,
                    symmetric_encryption,
                    hash_algorithm,
                    key_size,
                    discovery_method,
                    confidence_score,
                    risk_score,
                    first_discovered_at,
                    last_verified_at,
                    created_at,
                    updated_at
                ) VALUES (
                    demo_tenant_id,
                    asset_record.id,
                    cert_record.id,
                    'TLS'::protocol_type,
                    protocol_ver,
                    cipher_suite,
                    CASE WHEN protocol_ver = 'TLSv1.3' THEN NULL ELSE 'ECDHE' END,
                    CASE WHEN protocol_ver = 'TLSv1.3' THEN NULL ELSE 'RSA' END,
                    CASE
                        WHEN cipher_suite LIKE '%AES_256%' THEN 'AES-256-GCM'
                        WHEN cipher_suite LIKE '%AES_128%' THEN 'AES-128-GCM'
                        WHEN cipher_suite LIKE '%CHACHA20%' THEN 'ChaCha20-Poly1305'
                        ELSE 'AES-256-GCM'
                    END,
                    hash_alg,
                    key_size_val,
                    'manual'::discovery_method,
                    0.90,
                    CASE
                        WHEN protocol_ver = 'TLSv1.2' AND key_size_val < 2048 THEN 65
                        WHEN protocol_ver = 'TLSv1.2' THEN 35
                        ELSE 15
                    END,
                    NOW() - INTERVAL '45 days' - (random() * INTERVAL '120 days'),
                    NOW() - INTERVAL '2 hours' - (random() * INTERVAL '48 hours'),
                    NOW() - INTERVAL '45 days' - (random() * INTERVAL '120 days'),
                    NOW()
                )
                ON CONFLICT DO NOTHING
                RETURNING id INTO crypto_impl_id;

                IF crypto_impl_id IS NOT NULL THEN
                    impl_count := impl_count + 1;

                    -- Link certificate to crypto implementation via junction table
                    -- Note: Primary certificate is already in crypto_implementations.certificate_id
                    -- Junction table is for additional certificates in chain, but we'll add it here too for completeness
                    INSERT INTO crypto_implementation_certificates (
                        crypto_implementation_id,
                        certificate_id,
                        certificate_role,
                        certificate_order
                    ) VALUES (
                        crypto_impl_id,
                        cert_record.id,
                        'additional',
                        0
                    )
                    ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
                END IF;
            END;
        END IF;
    END LOOP;

    -- =================================================================
    -- Link Database Servers (with TLS)
    -- =================================================================
    -- Some database servers use TLS for encrypted connections
    FOR asset_record IN
        SELECT id, hostname, ip_address, port, asset_type, environment
        FROM network_assets
        WHERE tenant_id = demo_tenant_id
        AND deleted_at IS NULL
        AND asset_type = 'server'
        AND port IN (5432, 3306, 1433, 27017)  -- PostgreSQL, MySQL, SQL Server, MongoDB
        AND environment = 'production'
        ORDER BY RANDOM()
        LIMIT 15
    LOOP
        -- Find a certificate (internal certificates for databases)
        SELECT id INTO cert_record
        FROM certificates
        WHERE tenant_id = demo_tenant_id
        AND is_ca_certificate = false
        AND (
            common_name LIKE '%internal%'
            OR common_name LIKE '%db%'
            OR true
        )
        ORDER BY RANDOM()
        LIMIT 1;

        IF cert_record.id IS NOT NULL THEN
            -- Databases often use TLS 1.2 (more conservative)
            DECLARE
                protocol_ver TEXT := 'TLSv1.2';
                cipher_suite TEXT := tls12_cipher_suites[1 + floor(random() * array_length(tls12_cipher_suites, 1))::int];
                hash_alg TEXT := 'SHA256';
                key_size_val INTEGER := 2048;
            BEGIN
                INSERT INTO crypto_implementations (
                    tenant_id,
                    asset_id,
                    certificate_id,
                    protocol,
                    protocol_version,
                    cipher_suite,
                    key_exchange_algorithm,
                    signature_algorithm,
                    symmetric_encryption,
                    hash_algorithm,
                    key_size,
                    discovery_method,
                    confidence_score,
                    risk_score,
                    first_discovered_at,
                    last_verified_at,
                    created_at,
                    updated_at
                ) VALUES (
                    demo_tenant_id,
                    asset_record.id,
                    cert_record.id,
                    'TLS'::protocol_type,
                    protocol_ver,
                    cipher_suite,
                    'ECDHE',
                    'RSA',
                    'AES-256-GCM',
                    hash_alg,
                    key_size_val,
                    'manual'::discovery_method,
                    0.85,
                    25,
                    NOW() - INTERVAL '60 days' - (random() * INTERVAL '180 days'),
                    NOW() - INTERVAL '6 hours' - (random() * INTERVAL '72 hours'),
                    NOW() - INTERVAL '60 days' - (random() * INTERVAL '180 days'),
                    NOW()
                )
                ON CONFLICT DO NOTHING
                RETURNING id INTO crypto_impl_id;

                IF crypto_impl_id IS NOT NULL THEN
                    impl_count := impl_count + 1;

                    -- Link certificate to crypto implementation via junction table
                    -- Note: Primary certificate is already in crypto_implementations.certificate_id
                    -- Junction table is for additional certificates in chain, but we'll add it here too for completeness
                    INSERT INTO crypto_implementation_certificates (
                        crypto_implementation_id,
                        certificate_id,
                        certificate_role,
                        certificate_order
                    ) VALUES (
                        crypto_impl_id,
                        cert_record.id,
                        'additional',
                        0
                    )
                    ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
                END IF;
            END;
        END IF;
    END LOOP;

    -- =================================================================
    -- Link Remaining Assets (variety of ports and types)
    -- =================================================================
    -- Link some additional assets to ensure good coverage
    FOR asset_record IN
        SELECT id, hostname, ip_address, port, asset_type, environment
        FROM network_assets
        WHERE tenant_id = demo_tenant_id
        AND deleted_at IS NULL
        AND id NOT IN (
            SELECT DISTINCT asset_id
            FROM crypto_implementations
            WHERE tenant_id = demo_tenant_id
            AND deleted_at IS NULL
        )
        AND asset_type IN ('server', 'service', 'endpoint')
        ORDER BY RANDOM()
        LIMIT 30
    LOOP
        SELECT id INTO cert_record
        FROM certificates
        WHERE tenant_id = demo_tenant_id
        AND is_ca_certificate = false
        ORDER BY RANDOM()
        LIMIT 1;

        IF cert_record.id IS NOT NULL THEN
            random_idx := CASE WHEN random() < 0.5 THEN 2 ELSE 1 END;
            DECLARE
                protocol_ver TEXT := tls_versions[random_idx];
                cipher_suite TEXT;
                hash_alg TEXT;
                key_size_val INTEGER;
            BEGIN
                IF protocol_ver = 'TLSv1.3' THEN
                    cipher_suite := tls13_cipher_suites[1 + floor(random() * array_length(tls13_cipher_suites, 1))::int];
                ELSE
                    cipher_suite := tls12_cipher_suites[1 + floor(random() * array_length(tls12_cipher_suites, 1))::int];
                END IF;

                hash_alg := hash_algorithms[1 + floor(random() * array_length(hash_algorithms, 1))::int];
                key_size_val := key_sizes[1 + floor(random() * array_length(key_sizes, 1))::int];

                INSERT INTO crypto_implementations (
                    tenant_id,
                    asset_id,
                    certificate_id,
                    protocol,
                    protocol_version,
                    cipher_suite,
                    key_exchange_algorithm,
                    signature_algorithm,
                    symmetric_encryption,
                    hash_algorithm,
                    key_size,
                    discovery_method,
                    confidence_score,
                    risk_score,
                    first_discovered_at,
                    last_verified_at,
                    created_at,
                    updated_at
                ) VALUES (
                    demo_tenant_id,
                    asset_record.id,
                    cert_record.id,
                    'TLS'::protocol_type,
                    protocol_ver,
                    cipher_suite,
                    CASE WHEN protocol_ver = 'TLSv1.3' THEN NULL ELSE 'ECDHE' END,
                    CASE WHEN protocol_ver = 'TLSv1.3' THEN NULL ELSE 'RSA' END,
                    CASE
                        WHEN cipher_suite LIKE '%AES_256%' THEN 'AES-256-GCM'
                        WHEN cipher_suite LIKE '%AES_128%' THEN 'AES-128-GCM'
                        WHEN cipher_suite LIKE '%CHACHA20%' THEN 'ChaCha20-Poly1305'
                        ELSE 'AES-256-GCM'
                    END,
                    hash_alg,
                    key_size_val,
                    'manual'::discovery_method,
                    0.80,
                    CASE
                        WHEN protocol_ver = 'TLSv1.2' AND key_size_val < 2048 THEN 70
                        WHEN protocol_ver = 'TLSv1.2' THEN 40
                        ELSE 20
                    END,
                    NOW() - INTERVAL '90 days' - (random() * INTERVAL '270 days'),
                    NOW() - INTERVAL '12 hours' - (random() * INTERVAL '7 days'),
                    NOW() - INTERVAL '90 days' - (random() * INTERVAL '270 days'),
                    NOW()
                )
                ON CONFLICT DO NOTHING
                RETURNING id INTO crypto_impl_id;

                IF crypto_impl_id IS NOT NULL THEN
                    impl_count := impl_count + 1;

                    -- Link certificate to crypto implementation via junction table
                    -- Note: Primary certificate is already in crypto_implementations.certificate_id
                    -- Junction table is for additional certificates in chain, but we'll add it here too for completeness
                    INSERT INTO crypto_implementation_certificates (
                        crypto_implementation_id,
                        certificate_id,
                        certificate_role,
                        certificate_order
                    ) VALUES (
                        crypto_impl_id,
                        cert_record.id,
                        'additional',
                        0
                    )
                    ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
                END IF;
            END;
        END IF;
    END LOOP;

    -- =================================================================
    -- Create Critical and High Risk Crypto Implementations
    -- =================================================================
    -- Add some legacy/weak crypto implementations to demonstrate
    -- critical issues (risk_score >= 80) and high risk (risk_score >= 70)
    RAISE NOTICE 'Creating critical and high-risk crypto implementations...';

    -- Critical issues: TLS 1.0, weak ciphers, small keys, SHA-1
    FOR asset_record IN
        SELECT id, hostname, ip_address, port, asset_type, environment
        FROM network_assets
        WHERE tenant_id = demo_tenant_id
        AND deleted_at IS NULL
        AND port IN (443, 8443, 8080)
        AND asset_type IN ('server', 'service')
        ORDER BY RANDOM()
        LIMIT 8  -- Create 8 critical issues
    LOOP
        -- Find a certificate (preferably expired or expiring soon)
        SELECT id INTO cert_record
        FROM certificates
        WHERE tenant_id = demo_tenant_id
        AND is_ca_certificate = false
        ORDER BY RANDOM()
        LIMIT 1;

        IF cert_record.id IS NOT NULL THEN
            INSERT INTO crypto_implementations (
                tenant_id,
                asset_id,
                certificate_id,
                protocol,
                protocol_version,
                cipher_suite,
                key_exchange_algorithm,
                signature_algorithm,
                symmetric_encryption,
                hash_algorithm,
                key_size,
                discovery_method,
                confidence_score,
                risk_score,
                first_discovered_at,
                last_verified_at,
                created_at,
                updated_at
            ) VALUES (
                demo_tenant_id,
                asset_record.id,
                cert_record.id,
                'TLS'::protocol_type,
                CASE WHEN random() < 0.5 THEN 'TLSv1.0' ELSE 'TLSv1.1' END,
                CASE
                    WHEN random() < 0.33 THEN 'TLS_RSA_WITH_RC4_128_SHA'
                    WHEN random() < 0.66 THEN 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
                    ELSE 'TLS_RSA_WITH_AES_128_CBC_SHA'
                END,
                'RSA',
                'RSA',
                CASE
                    WHEN random() < 0.5 THEN 'RC4-128'
                    ELSE '3DES'
                END,
                'SHA1',
                CASE
                    WHEN random() < 0.5 THEN 1024
                    ELSE 512
                END,
                'manual'::discovery_method,
                0.85,
                85,  -- Critical risk score (>= 80)
                NOW() - INTERVAL '60 days' - (random() * INTERVAL '180 days'),
                NOW() - INTERVAL '3 hours' - (random() * INTERVAL '72 hours'),
                NOW() - INTERVAL '60 days' - (random() * INTERVAL '180 days'),
                NOW()
            )
            ON CONFLICT DO NOTHING
            RETURNING id INTO crypto_impl_id;

            IF crypto_impl_id IS NOT NULL THEN
                impl_count := impl_count + 1;
            END IF;
        END IF;
    END LOOP;

    -- High risk issues: TLS 1.1 with weak configs, or TLS 1.2 with very small keys
    FOR asset_record IN
        SELECT id, hostname, ip_address, port, asset_type, environment
        FROM network_assets
        WHERE tenant_id = demo_tenant_id
        AND deleted_at IS NULL
        AND port IN (443, 8443, 8080, 3306, 5432)
        AND asset_type IN ('server', 'service')
        ORDER BY RANDOM()
        LIMIT 12  -- Create 12 high-risk issues
    LOOP
        SELECT id INTO cert_record
        FROM certificates
        WHERE tenant_id = demo_tenant_id
        AND is_ca_certificate = false
        ORDER BY RANDOM()
        LIMIT 1;

        IF cert_record.id IS NOT NULL THEN
            INSERT INTO crypto_implementations (
                tenant_id,
                asset_id,
                certificate_id,
                protocol,
                protocol_version,
                cipher_suite,
                key_exchange_algorithm,
                signature_algorithm,
                symmetric_encryption,
                hash_algorithm,
                key_size,
                discovery_method,
                confidence_score,
                risk_score,
                first_discovered_at,
                last_verified_at,
                created_at,
                updated_at
            ) VALUES (
                demo_tenant_id,
                asset_record.id,
                cert_record.id,
                'TLS'::protocol_type,
                CASE
                    WHEN random() < 0.4 THEN 'TLSv1.1'
                    WHEN random() < 0.7 THEN 'TLSv1.2'
                    ELSE 'TLSv1.0'
                END,
                CASE
                    WHEN random() < 0.25 THEN 'TLS_RSA_WITH_AES_128_CBC_SHA'
                    WHEN random() < 0.5 THEN 'TLS_RSA_WITH_AES_256_CBC_SHA'
                    WHEN random() < 0.75 THEN 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
                    ELSE 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'
                END,
                CASE WHEN random() < 0.5 THEN 'RSA' ELSE 'ECDHE' END,
                'RSA',
                CASE
                    WHEN random() < 0.5 THEN 'AES-128-CBC'
                    ELSE 'AES-256-CBC'
                END,
                CASE
                    WHEN random() < 0.5 THEN 'SHA1'
                    ELSE 'SHA256'
                END,
                CASE
                    WHEN random() < 0.4 THEN 1024
                    WHEN random() < 0.7 THEN 1536
                    ELSE 2048
                END,
                'manual'::discovery_method,
                0.90,
                CASE
                    -- TLS 1.0/1.1 with weak configs: 75-80
                    WHEN random() < 0.3 THEN 80
                    WHEN random() < 0.6 THEN 75
                    -- TLS 1.2 with very small keys: 70-74
                    ELSE 72
                END,
                NOW() - INTERVAL '45 days' - (random() * INTERVAL '120 days'),
                NOW() - INTERVAL '2 hours' - (random() * INTERVAL '48 hours'),
                NOW() - INTERVAL '45 days' - (random() * INTERVAL '120 days'),
                NOW()
            )
            ON CONFLICT DO NOTHING
            RETURNING id INTO crypto_impl_id;

            IF crypto_impl_id IS NOT NULL THEN
                impl_count := impl_count + 1;
            END IF;
        END IF;
    END LOOP;

    RAISE NOTICE 'Created % crypto implementations (including critical/high-risk)', impl_count;

    -- Verification
    SELECT COUNT(*) INTO cert_count
    FROM crypto_implementations
    WHERE tenant_id = demo_tenant_id
    AND deleted_at IS NULL
    AND certificate_id IS NOT NULL;

    RAISE NOTICE 'Total crypto implementations with certificates: %', cert_count;
    RAISE NOTICE 'Crypto implementations created successfully!';
END $$;

-- =================================================================
-- Verification
-- =================================================================

DO $$
DECLARE
    demo_tenant_id UUID;
    impl_count INTEGER;
    cert_linked_count INTEGER;
    asset_linked_count INTEGER;
BEGIN
    SELECT id INTO demo_tenant_id
    FROM tenants
    WHERE slug = 'demo-corp'
    LIMIT 1;

    IF demo_tenant_id IS NOT NULL THEN
        SELECT COUNT(*) INTO impl_count
        FROM crypto_implementations
        WHERE tenant_id = demo_tenant_id
        AND deleted_at IS NULL;

        SELECT COUNT(DISTINCT certificate_id) INTO cert_linked_count
        FROM crypto_implementations
        WHERE tenant_id = demo_tenant_id
        AND deleted_at IS NULL
        AND certificate_id IS NOT NULL;

        SELECT COUNT(DISTINCT asset_id) INTO asset_linked_count
        FROM crypto_implementations
        WHERE tenant_id = demo_tenant_id
        AND deleted_at IS NULL;

        RAISE NOTICE '========================================';
        RAISE NOTICE 'Crypto Implementations Summary:';
        RAISE NOTICE '  Total implementations: %', impl_count;
        RAISE NOTICE '  Certificates linked: %', cert_linked_count;
        RAISE NOTICE '  Assets linked: %', asset_linked_count;
        RAISE NOTICE '========================================';
    END IF;
END $$;
