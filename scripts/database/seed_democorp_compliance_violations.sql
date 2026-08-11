-- =================================================================
-- Demo Corporation - Compliance Violations Seeding (Tier 2)
-- =================================================================
-- This script seeds assets and certificates with actual violations
-- that will naturally generate compliance findings through the
-- event-driven evaluation system.
--
-- Instead of directly inserting findings, we create assets/certificates
-- with violations that match NIST CSF control measurements:
-- - PR.DS-1: Weak key sizes (< 2048 bits)
-- - PR.DS-2: Weak TLS versions (TLS 1.0/1.1)
-- - PR.DS-3: Certificates expiring soon (< 30 days)
--
-- After seeding, trigger AssetChangedEvent events to generate findings
-- through the normal evaluation flow.
-- =================================================================

DO $$
DECLARE
    demo_tenant_id UUID;
    violation_asset_id UUID;
    violation_cert_id UUID;
    violation_cert_id_2 UUID;
    violation_cert_id_3 UUID;
    crypto_impl_id UUID;
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

    RAISE NOTICE 'Seeding compliance violations for demo tenant...';

    -- =================================================================
    -- Violation 1: PR.DS-1 - Weak Key Size (< 2048 bits)
    -- =================================================================
    -- Create a certificate with 1024-bit RSA key (violates PR.DS-1)
    INSERT INTO certificates (
        tenant_id, serial_number, subject_dn, issuer_dn, common_name,
        subject_alternative_names, signature_algorithm, public_key_algorithm,
        public_key_size, not_before, not_after,
        fingerprint_sha1, fingerprint_sha256,
        is_self_signed, is_ca_certificate,
        key_usage, extended_key_usage
    ) VALUES (
        demo_tenant_id,
        'AA:BB:CC:DD:EE:FF:00:11:AA:BB:CC:DD:EE:FF:00:11:AA:BB:CC:DD',
        'CN=weak-key.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
        'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
        'weak-key.democorp.com',
        ARRAY['weak-key.democorp.com'],
        'SHA256WithRSA', 'RSA', 1024,  -- 1024-bit key violates PR.DS-1
        NOW() - INTERVAL '90 days',
        NOW() + INTERVAL '60 days',
        'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0',
        'f1e2d3c4b5a697887766554433221100ffeeddccbbaa99887766554433221100',
        false, false,
        ARRAY['Digital Signature', 'Key Encipherment'],
        ARRAY['Server Authentication']
    )
    ON CONFLICT (tenant_id, fingerprint_sha256) DO NOTHING
    RETURNING id INTO violation_cert_id;

    -- Get or create an asset for this certificate
    SELECT id INTO violation_asset_id
    FROM network_assets
    WHERE tenant_id = demo_tenant_id
    AND hostname = 'weak-key.democorp.com'
    AND deleted_at IS NULL
    LIMIT 1;

    IF violation_asset_id IS NULL THEN
        INSERT INTO network_assets (
            tenant_id, hostname, ip_address, port, asset_type, operating_system,
            environment, business_unit, owner_email, description, tags,
            asset_status, asset_ownership, first_discovered_at, last_seen_at
        ) VALUES (
            demo_tenant_id,
            'weak-key.democorp.com',
            '10.1.100.1'::inet,
            443,
            'server'::asset_type,
            'Ubuntu 22.04',
            'production'::environment_type,
            'IT Infrastructure',
            'admin@democorp.com',
            'Production server with weak 1024-bit RSA certificate (violates PR.DS-1)',
            jsonb_build_object('compliance_violation', 'weak_key_size', 'control', 'PR.DS-1'),
            'monitoring'::VARCHAR(50),
            'internal'::VARCHAR(50),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO violation_asset_id;
    END IF;

    -- Link certificate to asset via crypto_implementation
    IF violation_cert_id IS NOT NULL AND violation_asset_id IS NOT NULL THEN
        INSERT INTO crypto_implementations (
            id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
            key_exchange_algorithm, signature_algorithm, symmetric_encryption,
            hash_algorithm, key_size, certificate_id, discovery_method,
            confidence_score, raw_data, risk_score, compliance_status,
            first_discovered_at, last_verified_at, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            demo_tenant_id,
            violation_asset_id,
            'TLS'::protocol_type,
            '1.2',
            'TLS_RSA_WITH_AES_256_CBC_SHA256',
            'RSA',
            'SHA256WithRSA',
            'AES-256-CBC',
            'SHA256',
            1024,  -- Weak key size
            violation_cert_id,
            'manual'::discovery_method,
            1.0,
            jsonb_build_object('violation', 'weak_key_size', 'key_size', 1024),
            85,  -- High risk score
            '{}'::jsonb,
            NOW() - INTERVAL '30 days',
            NOW(),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO crypto_impl_id;

        -- Link certificate to crypto implementation
        IF crypto_impl_id IS NOT NULL THEN
            INSERT INTO crypto_implementation_certificates (
                crypto_implementation_id, certificate_id, certificate_role, certificate_order
            ) VALUES (
                crypto_impl_id, violation_cert_id, 'additional', 0
            )
            ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
        END IF;
    END IF;

    -- =================================================================
    -- Violation 2: PR.DS-2 - Weak TLS Version (TLS 1.0)
    -- =================================================================
    -- Get or create an asset for TLS 1.0 violation
    SELECT id INTO violation_asset_id
    FROM network_assets
    WHERE tenant_id = demo_tenant_id
    AND hostname = 'legacy-tls.democorp.com'
    AND deleted_at IS NULL
    LIMIT 1;

    IF violation_asset_id IS NULL THEN
        INSERT INTO network_assets (
            tenant_id, hostname, ip_address, port, asset_type, operating_system,
            environment, business_unit, owner_email, description, tags,
            asset_status, asset_ownership, first_discovered_at, last_seen_at
        ) VALUES (
            demo_tenant_id,
            'legacy-tls.democorp.com',
            '10.1.100.2'::inet,
            443,
            'server'::asset_type,
            'CentOS 7',
            'production'::environment_type,
            'Legacy Systems',
            'admin@democorp.com',
            'Legacy server using TLS 1.0 (violates PR.DS-2)',
            jsonb_build_object('compliance_violation', 'weak_tls_version', 'control', 'PR.DS-2'),
            'monitoring'::VARCHAR(50),
            'internal'::VARCHAR(50),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO violation_asset_id;
    END IF;

    -- Create a certificate for this asset
    IF violation_asset_id IS NOT NULL THEN
        INSERT INTO certificates (
            tenant_id, serial_number, subject_dn, issuer_dn, common_name,
            subject_alternative_names, signature_algorithm, public_key_algorithm,
            public_key_size, not_before, not_after,
            fingerprint_sha1, fingerprint_sha256,
            is_self_signed, is_ca_certificate,
            key_usage, extended_key_usage
        ) VALUES (
            demo_tenant_id,
            'BB:CC:DD:EE:FF:00:11:22:BB:CC:DD:EE:FF:00:11:22:BB:CC:DD:EE',
            'CN=legacy-tls.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
            'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
            'legacy-tls.democorp.com',
            ARRAY['legacy-tls.democorp.com'],
            'SHA256WithRSA', 'RSA', 2048,
            NOW() - INTERVAL '90 days',
            NOW() + INTERVAL '60 days',
            'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1',
            'e2d3c4b5a697887766554433221100ffeeddccbbaa99887766554433221100aa',
            false, false,
            ARRAY['Digital Signature', 'Key Encipherment'],
            ARRAY['Server Authentication']
        )
        ON CONFLICT (tenant_id, fingerprint_sha256) DO NOTHING
        RETURNING id INTO violation_cert_id_2;

        -- Create crypto implementation with TLS 1.0 (violates PR.DS-2)
        IF violation_cert_id_2 IS NOT NULL THEN
            INSERT INTO crypto_implementations (
                id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
                key_exchange_algorithm, signature_algorithm, symmetric_encryption,
                hash_algorithm, key_size, certificate_id, discovery_method,
                confidence_score, raw_data, risk_score, compliance_status,
                first_discovered_at, last_verified_at, created_at, updated_at
            ) VALUES (
                gen_random_uuid(),
                demo_tenant_id,
                violation_asset_id,
                'TLS'::protocol_type,
                '1.0',  -- Weak TLS version violates PR.DS-2
                'TLS_RSA_WITH_RC4_128_SHA',
                'RSA',
                'SHA1WithRSA',
                'RC4',
                'SHA1',
                2048,
                violation_cert_id_2,
                'manual'::discovery_method,
                1.0,
                jsonb_build_object('violation', 'weak_tls_version', 'tls_version', '1.0'),
                90,  -- Very high risk score
                '{}'::jsonb,
                NOW() - INTERVAL '30 days',
                NOW(),
                NOW() - INTERVAL '30 days',
                NOW()
            )
            ON CONFLICT DO NOTHING
            RETURNING id INTO crypto_impl_id;

            -- Link certificate to crypto implementation
            IF crypto_impl_id IS NOT NULL THEN
                INSERT INTO crypto_implementation_certificates (
                    crypto_implementation_id, certificate_id, certificate_role, certificate_order
                ) VALUES (
                    crypto_impl_id, violation_cert_id_2, 'additional', 0
                )
                ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
            END IF;
        END IF;
    END IF;

    -- =================================================================
    -- Violation 3: PR.DS-3 - Certificate Expiring Soon (< 30 days)
    -- =================================================================
    -- Create a certificate expiring in 15 days (violates PR.DS-3)
    INSERT INTO certificates (
        tenant_id, serial_number, subject_dn, issuer_dn, common_name,
        subject_alternative_names, signature_algorithm, public_key_algorithm,
        public_key_size, not_before, not_after,
        fingerprint_sha1, fingerprint_sha256,
        is_self_signed, is_ca_certificate,
        key_usage, extended_key_usage
    ) VALUES (
        demo_tenant_id,
        'CC:DD:EE:FF:00:11:22:33:CC:DD:EE:FF:00:11:22:33:CC:DD:EE:FF',
        'CN=expiring-soon.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
        'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
        'expiring-soon.democorp.com',
        ARRAY['expiring-soon.democorp.com'],
        'SHA256WithRSA', 'RSA', 2048,
        NOW() - INTERVAL '60 days',
        NOW() + INTERVAL '15 days',  -- Expiring in 15 days violates PR.DS-3
        'c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2',
        'd3c4b5a697887766554433221100ffeeddccbbaa99887766554433221100aabb',
        false, false,
        ARRAY['Digital Signature', 'Key Encipherment'],
        ARRAY['Server Authentication']
    )
    ON CONFLICT (tenant_id, fingerprint_sha256) DO NOTHING
    RETURNING id INTO violation_cert_id_3;

    -- Get or create an asset for this certificate
    SELECT id INTO violation_asset_id
    FROM network_assets
    WHERE tenant_id = demo_tenant_id
    AND hostname = 'expiring-soon.democorp.com'
    AND deleted_at IS NULL
    LIMIT 1;

    IF violation_asset_id IS NULL THEN
        INSERT INTO network_assets (
            tenant_id, hostname, ip_address, port, asset_type, operating_system,
            environment, business_unit, owner_email, description, tags,
            asset_status, asset_ownership, first_discovered_at, last_seen_at
        ) VALUES (
            demo_tenant_id,
            'expiring-soon.democorp.com',
            '10.1.100.3'::inet,
            443,
            'server'::asset_type,
            'Ubuntu 22.04',
            'production'::environment_type,
            'Web Services',
            'admin@democorp.com',
            'Production server with certificate expiring in 15 days (violates PR.DS-3)',
            jsonb_build_object('compliance_violation', 'cert_expiring_soon', 'control', 'PR.DS-3'),
            'monitoring'::VARCHAR(50),
            'internal'::VARCHAR(50),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO violation_asset_id;
    END IF;

    -- Link certificate to asset via crypto_implementation
    IF violation_cert_id_3 IS NOT NULL AND violation_asset_id IS NOT NULL THEN
        INSERT INTO crypto_implementations (
            id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
            key_exchange_algorithm, signature_algorithm, symmetric_encryption,
            hash_algorithm, key_size, certificate_id, discovery_method,
            confidence_score, raw_data, risk_score, compliance_status,
            first_discovered_at, last_verified_at, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            demo_tenant_id,
            violation_asset_id,
            'TLS'::protocol_type,
            '1.2',
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            'ECDHE',
            'SHA256WithRSA',
            'AES-256-GCM',
            'SHA384',
            2048,
            violation_cert_id_3,
            'manual'::discovery_method,
            1.0,
            jsonb_build_object('violation', 'cert_expiring_soon', 'expiration_days', 15),
            60,  -- Medium risk score
            '{}'::jsonb,
            NOW() - INTERVAL '30 days',
            NOW(),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO crypto_impl_id;

        -- Link certificate to crypto implementation
        IF crypto_impl_id IS NOT NULL THEN
            INSERT INTO crypto_implementation_certificates (
                crypto_implementation_id, certificate_id, certificate_role, certificate_order
            ) VALUES (
                crypto_impl_id, violation_cert_id_3, 'additional', 0
            )
            ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
        END IF;
    END IF;

    -- =================================================================
    -- Additional Violations for NIST CSF (to ensure at least 2 per control)
    -- =================================================================

    -- Violation 4: PR.DS-1 - Another weak key size (512-bit RSA - even weaker)
    INSERT INTO certificates (
        tenant_id, serial_number, subject_dn, issuer_dn, common_name,
        subject_alternative_names, signature_algorithm, public_key_algorithm,
        public_key_size, not_before, not_after,
        fingerprint_sha1, fingerprint_sha256,
        is_self_signed, is_ca_certificate,
        key_usage, extended_key_usage
    ) VALUES (
        demo_tenant_id,
        'DD:EE:FF:00:11:22:33:44:DD:EE:FF:00:11:22:33:44:DD:EE:FF:00',
        'CN=very-weak-key.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
        'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
        'very-weak-key.democorp.com',
        ARRAY['very-weak-key.democorp.com'],
        'SHA256WithRSA', 'RSA', 512,  -- 512-bit key violates PR.DS-1 (even worse)
        NOW() - INTERVAL '90 days',
        NOW() + INTERVAL '60 days',
        'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3',
        'e4d5c6b7a897887766554433221100ffeeddccbbaa99887766554433221100cc',
        false, false,
        ARRAY['Digital Signature', 'Key Encipherment'],
        ARRAY['Server Authentication']
    )
    ON CONFLICT (tenant_id, fingerprint_sha256) DO NOTHING
    RETURNING id INTO violation_cert_id;

    -- Get or create asset for this certificate
    SELECT id INTO violation_asset_id
    FROM network_assets
    WHERE tenant_id = demo_tenant_id
    AND hostname = 'very-weak-key.democorp.com'
    AND deleted_at IS NULL
    LIMIT 1;

    IF violation_asset_id IS NULL THEN
        INSERT INTO network_assets (
            tenant_id, hostname, ip_address, port, asset_type, operating_system,
            environment, business_unit, owner_email, description, tags,
            asset_status, asset_ownership, first_discovered_at, last_seen_at
        ) VALUES (
            demo_tenant_id,
            'very-weak-key.democorp.com',
            '10.1.100.4'::inet,
            443,
            'server'::asset_type,
            'Ubuntu 20.04',
            'production'::environment_type,
            'Legacy Systems',
            'admin@democorp.com',
            'Legacy server with very weak 512-bit RSA certificate (violates PR.DS-1)',
            jsonb_build_object('compliance_violation', 'very_weak_key_size', 'control', 'PR.DS-1'),
            'monitoring'::VARCHAR(50),
            'internal'::VARCHAR(50),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO violation_asset_id;
    END IF;

    -- Link certificate to asset
    IF violation_cert_id IS NOT NULL AND violation_asset_id IS NOT NULL THEN
        INSERT INTO crypto_implementations (
            id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
            key_exchange_algorithm, signature_algorithm, symmetric_encryption,
            hash_algorithm, key_size, certificate_id, discovery_method,
            confidence_score, raw_data, risk_score, compliance_status,
            first_discovered_at, last_verified_at, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            demo_tenant_id,
            violation_asset_id,
            'TLS'::protocol_type,
            '1.2',
            'TLS_RSA_WITH_AES_256_CBC_SHA256',
            'RSA',
            'SHA256WithRSA',
            'AES-256-CBC',
            'SHA256',
            512,  -- Very weak key size
            violation_cert_id,
            'manual'::discovery_method,
            1.0,
            jsonb_build_object('violation', 'very_weak_key_size', 'key_size', 512),
            95,  -- Very high risk score
            '{}'::jsonb,
            NOW() - INTERVAL '30 days',
            NOW(),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO crypto_impl_id;

        IF crypto_impl_id IS NOT NULL THEN
            INSERT INTO crypto_implementation_certificates (
                crypto_implementation_id, certificate_id, certificate_role, certificate_order
            ) VALUES (
                crypto_impl_id, violation_cert_id, 'additional', 0
            )
            ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
        END IF;
    END IF;

    -- Violation 5: PR.DS-2 - Another weak TLS version (TLS 1.1)
    SELECT id INTO violation_asset_id
    FROM network_assets
    WHERE tenant_id = demo_tenant_id
    AND hostname = 'tls11-violation.democorp.com'
    AND deleted_at IS NULL
    LIMIT 1;

    IF violation_asset_id IS NULL THEN
        INSERT INTO network_assets (
            tenant_id, hostname, ip_address, port, asset_type, operating_system,
            environment, business_unit, owner_email, description, tags,
            asset_status, asset_ownership, first_discovered_at, last_seen_at
        ) VALUES (
            demo_tenant_id,
            'tls11-violation.democorp.com',
            '10.1.100.5'::inet,
            443,
            'server'::asset_type,
            'CentOS 6',
            'production'::environment_type,
            'Legacy Systems',
            'admin@democorp.com',
            'Legacy server using TLS 1.1 (violates PR.DS-2)',
            jsonb_build_object('compliance_violation', 'weak_tls_version_11', 'control', 'PR.DS-2'),
            'monitoring'::VARCHAR(50),
            'internal'::VARCHAR(50),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO violation_asset_id;
    END IF;

    -- Create certificate for this asset
    IF violation_asset_id IS NOT NULL THEN
        INSERT INTO certificates (
            tenant_id, serial_number, subject_dn, issuer_dn, common_name,
            subject_alternative_names, signature_algorithm, public_key_algorithm,
            public_key_size, not_before, not_after,
            fingerprint_sha1, fingerprint_sha256,
            is_self_signed, is_ca_certificate,
            key_usage, extended_key_usage
        ) VALUES (
            demo_tenant_id,
            'EE:FF:00:11:22:33:44:55:EE:FF:00:11:22:33:44:55:EE:FF:00:11',
            'CN=tls11-violation.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
            'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
            'tls11-violation.democorp.com',
            ARRAY['tls11-violation.democorp.com'],
            'SHA256WithRSA', 'RSA', 2048,
            NOW() - INTERVAL '90 days',
            NOW() + INTERVAL '60 days',
            'e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4',
            'f5e6d7c8b9a897887766554433221100ffeeddccbbaa99887766554433221100',
            false, false,
            ARRAY['Digital Signature', 'Key Encipherment'],
            ARRAY['Server Authentication']
        )
        ON CONFLICT (tenant_id, fingerprint_sha256) DO NOTHING
        RETURNING id INTO violation_cert_id_2;

        -- Create crypto implementation with TLS 1.1 (violates PR.DS-2)
        IF violation_cert_id_2 IS NOT NULL THEN
            INSERT INTO crypto_implementations (
                id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
                key_exchange_algorithm, signature_algorithm, symmetric_encryption,
                hash_algorithm, key_size, certificate_id, discovery_method,
                confidence_score, raw_data, risk_score, compliance_status,
                first_discovered_at, last_verified_at, created_at, updated_at
            ) VALUES (
                gen_random_uuid(),
                demo_tenant_id,
                violation_asset_id,
                'TLS'::protocol_type,
                '1.1',  -- Weak TLS version violates PR.DS-2
                'TLS_RSA_WITH_AES_128_CBC_SHA',
                'RSA',
                'SHA256WithRSA',
                'AES-128-CBC',
                'SHA256',
                2048,
                violation_cert_id_2,
                'manual'::discovery_method,
                1.0,
                jsonb_build_object('violation', 'weak_tls_version', 'tls_version', '1.1'),
                85,  -- High risk score
                '{}'::jsonb,
                NOW() - INTERVAL '30 days',
                NOW(),
                NOW() - INTERVAL '30 days',
                NOW()
            )
            ON CONFLICT DO NOTHING
            RETURNING id INTO crypto_impl_id;

            IF crypto_impl_id IS NOT NULL THEN
                INSERT INTO crypto_implementation_certificates (
                    crypto_implementation_id, certificate_id, certificate_role, certificate_order
                ) VALUES (
                    crypto_impl_id, violation_cert_id_2, 'additional', 0
                )
                ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
            END IF;
        END IF;
    END IF;

    -- Violation 6: PR.DS-3 - Another expiring certificate (20 days)
    INSERT INTO certificates (
        tenant_id, serial_number, subject_dn, issuer_dn, common_name,
        subject_alternative_names, signature_algorithm, public_key_algorithm,
        public_key_size, not_before, not_after,
        fingerprint_sha1, fingerprint_sha256,
        is_self_signed, is_ca_certificate,
        key_usage, extended_key_usage
    ) VALUES (
        demo_tenant_id,
        'FF:00:11:22:33:44:55:66:FF:00:11:22:33:44:55:66:FF:00:11:22',
        'CN=expiring-20days.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
        'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
        'expiring-20days.democorp.com',
        ARRAY['expiring-20days.democorp.com'],
        'SHA256WithRSA', 'RSA', 2048,
        NOW() - INTERVAL '60 days',
        NOW() + INTERVAL '20 days',  -- Expiring in 20 days violates PR.DS-3
        'f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5',
        'a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c600112233445566778899aa',
        false, false,
        ARRAY['Digital Signature', 'Key Encipherment'],
        ARRAY['Server Authentication']
    )
    ON CONFLICT (tenant_id, fingerprint_sha256) DO NOTHING
    RETURNING id INTO violation_cert_id_3;

    -- Get or create asset for this certificate
    SELECT id INTO violation_asset_id
    FROM network_assets
    WHERE tenant_id = demo_tenant_id
    AND hostname = 'expiring-20days.democorp.com'
    AND deleted_at IS NULL
    LIMIT 1;

    IF violation_asset_id IS NULL THEN
        INSERT INTO network_assets (
            tenant_id, hostname, ip_address, port, asset_type, operating_system,
            environment, business_unit, owner_email, description, tags,
            asset_status, asset_ownership, first_discovered_at, last_seen_at
        ) VALUES (
            demo_tenant_id,
            'expiring-20days.democorp.com',
            '10.1.100.6'::inet,
            443,
            'server'::asset_type,
            'Ubuntu 22.04',
            'production'::environment_type,
            'Web Services',
            'admin@democorp.com',
            'Production server with certificate expiring in 20 days (violates PR.DS-3)',
            jsonb_build_object('compliance_violation', 'cert_expiring_soon', 'control', 'PR.DS-3'),
            'monitoring'::VARCHAR(50),
            'internal'::VARCHAR(50),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO violation_asset_id;
    END IF;

    -- Link certificate to asset
    IF violation_cert_id_3 IS NOT NULL AND violation_asset_id IS NOT NULL THEN
        INSERT INTO crypto_implementations (
            id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
            key_exchange_algorithm, signature_algorithm, symmetric_encryption,
            hash_algorithm, key_size, certificate_id, discovery_method,
            confidence_score, raw_data, risk_score, compliance_status,
            first_discovered_at, last_verified_at, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            demo_tenant_id,
            violation_asset_id,
            'TLS'::protocol_type,
            '1.2',
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            'ECDHE',
            'SHA256WithRSA',
            'AES-256-GCM',
            'SHA384',
            2048,
            violation_cert_id_3,
            'manual'::discovery_method,
            1.0,
            jsonb_build_object('violation', 'cert_expiring_soon', 'expiration_days', 20),
            65,  -- Medium-high risk score
            '{}'::jsonb,
            NOW() - INTERVAL '30 days',
            NOW(),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO crypto_impl_id;

        IF crypto_impl_id IS NOT NULL THEN
            INSERT INTO crypto_implementation_certificates (
                crypto_implementation_id, certificate_id, certificate_role, certificate_order
            ) VALUES (
                crypto_impl_id, violation_cert_id_3, 'additional', 0
            )
            ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
        END IF;
    END IF;

    -- =================================================================
    -- Violations for Best Practices Framework
    -- =================================================================

    -- Violation 7: BP-001/BP-006 - Weak TLS version (TLS 1.0) for Best Practices
    -- (Already covered by PR.DS-2 violation, but we'll add another for Best Practices specifically)
    -- Note: The same TLS 1.0 violation will trigger findings for both NIST and Best Practices

    -- Violation 8: BP-003/BP-010 - Weak cipher (RC4) for Best Practices
    SELECT id INTO violation_asset_id
    FROM network_assets
    WHERE tenant_id = demo_tenant_id
    AND hostname = 'weak-cipher-rc4.democorp.com'
    AND deleted_at IS NULL
    LIMIT 1;

    IF violation_asset_id IS NULL THEN
        INSERT INTO network_assets (
            tenant_id, hostname, ip_address, port, asset_type, operating_system,
            environment, business_unit, owner_email, description, tags,
            asset_status, asset_ownership, first_discovered_at, last_seen_at
        ) VALUES (
            demo_tenant_id,
            'weak-cipher-rc4.democorp.com',
            '10.1.100.7'::inet,
            443,
            'server'::asset_type,
            'Windows Server 2012',
            'production'::environment_type,
            'Legacy Systems',
            'admin@democorp.com',
            'Legacy server using weak RC4 cipher (violates BP-003/BP-010)',
            jsonb_build_object('compliance_violation', 'weak_cipher_rc4', 'control', 'BP-003'),
            'monitoring'::VARCHAR(50),
            'internal'::VARCHAR(50),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO violation_asset_id;
    END IF;

    -- Create certificate for this asset
    IF violation_asset_id IS NOT NULL THEN
        INSERT INTO certificates (
            tenant_id, serial_number, subject_dn, issuer_dn, common_name,
            subject_alternative_names, signature_algorithm, public_key_algorithm,
            public_key_size, not_before, not_after,
            fingerprint_sha1, fingerprint_sha256,
            is_self_signed, is_ca_certificate,
            key_usage, extended_key_usage
        ) VALUES (
            demo_tenant_id,
            '00:11:22:33:44:55:66:77:00:11:22:33:44:55:66:77:00:11:22:33',
            'CN=weak-cipher-rc4.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
            'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
            'weak-cipher-rc4.democorp.com',
            ARRAY['weak-cipher-rc4.democorp.com'],
            'SHA256WithRSA', 'RSA', 2048,
            NOW() - INTERVAL '90 days',
            NOW() + INTERVAL '60 days',
            'a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6',
            'b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d700112233445566778899bb',
            false, false,
            ARRAY['Digital Signature', 'Key Encipherment'],
            ARRAY['Server Authentication']
        )
        ON CONFLICT (tenant_id, fingerprint_sha256) DO NOTHING
        RETURNING id INTO violation_cert_id_2;

        -- Create crypto implementation with RC4 cipher (violates BP-003/BP-010)
        IF violation_cert_id_2 IS NOT NULL THEN
            INSERT INTO crypto_implementations (
                id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
                key_exchange_algorithm, signature_algorithm, symmetric_encryption,
                hash_algorithm, key_size, certificate_id, discovery_method,
                confidence_score, raw_data, risk_score, compliance_status,
                first_discovered_at, last_verified_at, created_at, updated_at
            ) VALUES (
                gen_random_uuid(),
                demo_tenant_id,
                violation_asset_id,
                'TLS'::protocol_type,
                '1.2',
                'TLS_RSA_WITH_RC4_128_SHA',  -- RC4 cipher violates BP-003/BP-010
                'RSA',
                'SHA1WithRSA',
                'RC4',  -- Weak cipher
                'SHA1',
                2048,
                violation_cert_id_2,
                'manual'::discovery_method,
                1.0,
                jsonb_build_object('violation', 'weak_cipher', 'cipher', 'RC4'),
                90,  -- Very high risk score
                '{}'::jsonb,
                NOW() - INTERVAL '30 days',
                NOW(),
                NOW() - INTERVAL '30 days',
                NOW()
            )
            ON CONFLICT DO NOTHING
            RETURNING id INTO crypto_impl_id;

            IF crypto_impl_id IS NOT NULL THEN
                INSERT INTO crypto_implementation_certificates (
                    crypto_implementation_id, certificate_id, certificate_role, certificate_order
                ) VALUES (
                    crypto_impl_id, violation_cert_id_2, 'additional', 0
                )
                ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
            END IF;
        END IF;
    END IF;

    -- Violation 9: BP-005 - Weak key size (1536-bit RSA) for Best Practices
    INSERT INTO certificates (
        tenant_id, serial_number, subject_dn, issuer_dn, common_name,
        subject_alternative_names, signature_algorithm, public_key_algorithm,
        public_key_size, not_before, not_after,
        fingerprint_sha1, fingerprint_sha256,
        is_self_signed, is_ca_certificate,
        key_usage, extended_key_usage
    ) VALUES (
        demo_tenant_id,
        '11:22:33:44:55:66:77:88:11:22:33:44:55:66:77:88:11:22:33:44',
        'CN=weak-key-bp.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
        'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
        'weak-key-bp.democorp.com',
        ARRAY['weak-key-bp.democorp.com'],
        'SHA256WithRSA', 'RSA', 1536,  -- 1536-bit key violates BP-005 (< 2048)
        NOW() - INTERVAL '90 days',
        NOW() + INTERVAL '60 days',
        'b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7',
        'c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e800112233445566778899cc',
        false, false,
        ARRAY['Digital Signature', 'Key Encipherment'],
        ARRAY['Server Authentication']
    )
    ON CONFLICT (tenant_id, fingerprint_sha256) DO NOTHING
    RETURNING id INTO violation_cert_id;

    -- Get or create asset for this certificate
    SELECT id INTO violation_asset_id
    FROM network_assets
    WHERE tenant_id = demo_tenant_id
    AND hostname = 'weak-key-bp.democorp.com'
    AND deleted_at IS NULL
    LIMIT 1;

    IF violation_asset_id IS NULL THEN
        INSERT INTO network_assets (
            tenant_id, hostname, ip_address, port, asset_type, operating_system,
            environment, business_unit, owner_email, description, tags,
            asset_status, asset_ownership, first_discovered_at, last_seen_at
        ) VALUES (
            demo_tenant_id,
            'weak-key-bp.democorp.com',
            '10.1.100.8'::inet,
            443,
            'server'::asset_type,
            'Ubuntu 20.04',
            'production'::environment_type,
            'IT Infrastructure',
            'admin@democorp.com',
            'Production server with weak 1536-bit RSA certificate (violates BP-005)',
            jsonb_build_object('compliance_violation', 'weak_key_size', 'control', 'BP-005'),
            'monitoring'::VARCHAR(50),
            'internal'::VARCHAR(50),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO violation_asset_id;
    END IF;

    -- Link certificate to asset
    IF violation_cert_id IS NOT NULL AND violation_asset_id IS NOT NULL THEN
        INSERT INTO crypto_implementations (
            id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
            key_exchange_algorithm, signature_algorithm, symmetric_encryption,
            hash_algorithm, key_size, certificate_id, discovery_method,
            confidence_score, raw_data, risk_score, compliance_status,
            first_discovered_at, last_verified_at, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            demo_tenant_id,
            violation_asset_id,
            'TLS'::protocol_type,
            '1.2',
            'TLS_RSA_WITH_AES_256_CBC_SHA256',
            'RSA',
            'SHA256WithRSA',
            'AES-256-CBC',
            'SHA256',
            1536,  -- Weak key size
            violation_cert_id,
            'manual'::discovery_method,
            1.0,
            jsonb_build_object('violation', 'weak_key_size', 'key_size', 1536),
            80,  -- High risk score
            '{}'::jsonb,
            NOW() - INTERVAL '30 days',
            NOW(),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO crypto_impl_id;

        IF crypto_impl_id IS NOT NULL THEN
            INSERT INTO crypto_implementation_certificates (
                crypto_implementation_id, certificate_id, certificate_role, certificate_order
            ) VALUES (
                crypto_impl_id, violation_cert_id, 'additional', 0
            )
            ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
        END IF;
    END IF;

    -- Violation 10: BP-002 - Certificate expiring soon (25 days) for Best Practices
    INSERT INTO certificates (
        tenant_id, serial_number, subject_dn, issuer_dn, common_name,
        subject_alternative_names, signature_algorithm, public_key_algorithm,
        public_key_size, not_before, not_after,
        fingerprint_sha1, fingerprint_sha256,
        is_self_signed, is_ca_certificate,
        key_usage, extended_key_usage
    ) VALUES (
        demo_tenant_id,
        '22:33:44:55:66:77:88:99:22:33:44:55:66:77:88:99:22:33:44:55',
        'CN=expiring-bp.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
        'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
        'expiring-bp.democorp.com',
        ARRAY['expiring-bp.democorp.com'],
        'SHA256WithRSA', 'RSA', 2048,
        NOW() - INTERVAL '60 days',
        NOW() + INTERVAL '25 days',  -- Expiring in 25 days violates BP-002
        'c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8',
        'd9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9001122334455667788eeaa',
        false, false,
        ARRAY['Digital Signature', 'Key Encipherment'],
        ARRAY['Server Authentication']
    )
    ON CONFLICT (tenant_id, fingerprint_sha256) DO NOTHING
    RETURNING id INTO violation_cert_id_3;

    -- Get or create asset for this certificate
    SELECT id INTO violation_asset_id
    FROM network_assets
    WHERE tenant_id = demo_tenant_id
    AND hostname = 'expiring-bp.democorp.com'
    AND deleted_at IS NULL
    LIMIT 1;

    IF violation_asset_id IS NULL THEN
        INSERT INTO network_assets (
            tenant_id, hostname, ip_address, port, asset_type, operating_system,
            environment, business_unit, owner_email, description, tags,
            asset_status, asset_ownership, first_discovered_at, last_seen_at
        ) VALUES (
            demo_tenant_id,
            'expiring-bp.democorp.com',
            '10.1.100.9'::inet,
            443,
            'server'::asset_type,
            'Ubuntu 22.04',
            'production'::environment_type,
            'Web Services',
            'admin@democorp.com',
            'Production server with certificate expiring in 25 days (violates BP-002)',
            jsonb_build_object('compliance_violation', 'cert_expiring_soon', 'control', 'BP-002'),
            'monitoring'::VARCHAR(50),
            'internal'::VARCHAR(50),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO violation_asset_id;
    END IF;

    -- Link certificate to asset
    IF violation_cert_id_3 IS NOT NULL AND violation_asset_id IS NOT NULL THEN
        INSERT INTO crypto_implementations (
            id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
            key_exchange_algorithm, signature_algorithm, symmetric_encryption,
            hash_algorithm, key_size, certificate_id, discovery_method,
            confidence_score, raw_data, risk_score, compliance_status,
            first_discovered_at, last_verified_at, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            demo_tenant_id,
            violation_asset_id,
            'TLS'::protocol_type,
            '1.2',
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            'ECDHE',
            'SHA256WithRSA',
            'AES-256-GCM',
            'SHA384',
            2048,
            violation_cert_id_3,
            'manual'::discovery_method,
            1.0,
            jsonb_build_object('violation', 'cert_expiring_soon', 'expiration_days', 25),
            55,  -- Medium risk score
            '{}'::jsonb,
            NOW() - INTERVAL '30 days',
            NOW(),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO crypto_impl_id;

        IF crypto_impl_id IS NOT NULL THEN
            INSERT INTO crypto_implementation_certificates (
                crypto_implementation_id, certificate_id, certificate_role, certificate_order
            ) VALUES (
                crypto_impl_id, violation_cert_id_3, 'additional', 0
            )
            ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
        END IF;
    END IF;

    -- =================================================================
    -- Violations for SOC 2 Framework
    -- =================================================================

    -- Violation 11: CC6.6.1 - Weak TLS version (TLS 1.0) for SOC 2
    -- (Can reuse existing TLS 1.0 violation, but adding another for SOC 2 specifically)
    SELECT id INTO violation_asset_id
    FROM network_assets
    WHERE tenant_id = demo_tenant_id
    AND hostname = 'soc2-tls10.democorp.com'
    AND deleted_at IS NULL
    LIMIT 1;

    IF violation_asset_id IS NULL THEN
        INSERT INTO network_assets (
            tenant_id, hostname, ip_address, port, asset_type, operating_system,
            environment, business_unit, owner_email, description, tags,
            asset_status, asset_ownership, first_discovered_at, last_seen_at
        ) VALUES (
            demo_tenant_id,
            'soc2-tls10.democorp.com',
            '10.1.100.10'::inet,
            443,
            'server'::asset_type,
            'CentOS 7',
            'production'::environment_type,
            'Compliance Systems',
            'admin@democorp.com',
            'SOC 2 compliance server using TLS 1.0 (violates CC6.6.1)',
            jsonb_build_object('compliance_violation', 'weak_tls_version', 'control', 'CC6.6.1'),
            'monitoring'::VARCHAR(50),
            'internal'::VARCHAR(50),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO violation_asset_id;
    END IF;

    -- Create certificate for this asset
    IF violation_asset_id IS NOT NULL THEN
        INSERT INTO certificates (
            tenant_id, serial_number, subject_dn, issuer_dn, common_name,
            subject_alternative_names, signature_algorithm, public_key_algorithm,
            public_key_size, not_before, not_after,
            fingerprint_sha1, fingerprint_sha256,
            is_self_signed, is_ca_certificate,
            key_usage, extended_key_usage
        ) VALUES (
            demo_tenant_id,
            '33:44:55:66:77:88:99:AA:33:44:55:66:77:88:99:AA:33:44:55:66',
            'CN=soc2-tls10.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
            'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
            'soc2-tls10.democorp.com',
            ARRAY['soc2-tls10.democorp.com'],
            'SHA256WithRSA', 'RSA', 2048,
            NOW() - INTERVAL '90 days',
            NOW() + INTERVAL '60 days',
            'd0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9',
            'e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0001122334455667788ffbb',
            false, false,
            ARRAY['Digital Signature', 'Key Encipherment'],
            ARRAY['Server Authentication']
        )
        ON CONFLICT (tenant_id, fingerprint_sha256) DO NOTHING
        RETURNING id INTO violation_cert_id_2;

        -- Create crypto implementation with TLS 1.0 (violates CC6.6.1)
        IF violation_cert_id_2 IS NOT NULL THEN
            INSERT INTO crypto_implementations (
                id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
                key_exchange_algorithm, signature_algorithm, symmetric_encryption,
                hash_algorithm, key_size, certificate_id, discovery_method,
                confidence_score, raw_data, risk_score, compliance_status,
                first_discovered_at, last_verified_at, created_at, updated_at
            ) VALUES (
                gen_random_uuid(),
                demo_tenant_id,
                violation_asset_id,
                'TLS'::protocol_type,
                '1.0',  -- Weak TLS version violates CC6.6.1
                'TLS_RSA_WITH_RC4_128_SHA',
                'RSA',
                'SHA1WithRSA',
                'RC4',
                'SHA1',
                2048,
                violation_cert_id_2,
                'manual'::discovery_method,
                1.0,
                jsonb_build_object('violation', 'weak_tls_version', 'tls_version', '1.0'),
                88,  -- High risk score
                '{}'::jsonb,
                NOW() - INTERVAL '30 days',
                NOW(),
                NOW() - INTERVAL '30 days',
                NOW()
            )
            ON CONFLICT DO NOTHING
            RETURNING id INTO crypto_impl_id;

            IF crypto_impl_id IS NOT NULL THEN
                INSERT INTO crypto_implementation_certificates (
                    crypto_implementation_id, certificate_id, certificate_role, certificate_order
                ) VALUES (
                    crypto_impl_id, violation_cert_id_2, 'additional', 0
                )
                ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
            END IF;
        END IF;
    END IF;

    -- Violation 12: CC6.6.4 - Weak key size (1536-bit RSA) for SOC 2
    INSERT INTO certificates (
        tenant_id, serial_number, subject_dn, issuer_dn, common_name,
        subject_alternative_names, signature_algorithm, public_key_algorithm,
        public_key_size, not_before, not_after,
        fingerprint_sha1, fingerprint_sha256,
        is_self_signed, is_ca_certificate,
        key_usage, extended_key_usage
    ) VALUES (
        demo_tenant_id,
        '44:55:66:77:88:99:AA:BB:44:55:66:77:88:99:AA:BB:44:55:66:77',
        'CN=soc2-weak-key.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
        'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
        'soc2-weak-key.democorp.com',
        ARRAY['soc2-weak-key.democorp.com'],
        'SHA256WithRSA', 'RSA', 1536,  -- 1536-bit key violates CC6.6.4
        NOW() - INTERVAL '90 days',
        NOW() + INTERVAL '60 days',
        'e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0',
        'f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b10011223344556677ab00cc',
        false, false,
        ARRAY['Digital Signature', 'Key Encipherment'],
        ARRAY['Server Authentication']
    )
    ON CONFLICT (tenant_id, fingerprint_sha256) DO NOTHING
    RETURNING id INTO violation_cert_id;

    -- Get or create asset for this certificate
    SELECT id INTO violation_asset_id
    FROM network_assets
    WHERE tenant_id = demo_tenant_id
    AND hostname = 'soc2-weak-key.democorp.com'
    AND deleted_at IS NULL
    LIMIT 1;

    IF violation_asset_id IS NULL THEN
        INSERT INTO network_assets (
            tenant_id, hostname, ip_address, port, asset_type, operating_system,
            environment, business_unit, owner_email, description, tags,
            asset_status, asset_ownership, first_discovered_at, last_seen_at
        ) VALUES (
            demo_tenant_id,
            'soc2-weak-key.democorp.com',
            '10.1.100.11'::inet,
            443,
            'server'::asset_type,
            'Ubuntu 22.04',
            'production'::environment_type,
            'Compliance Systems',
            'admin@democorp.com',
            'SOC 2 compliance server with weak 1536-bit RSA certificate (violates CC6.6.4)',
            jsonb_build_object('compliance_violation', 'weak_key_size', 'control', 'CC6.6.4'),
            'monitoring'::VARCHAR(50),
            'internal'::VARCHAR(50),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO violation_asset_id;
    END IF;

    -- Link certificate to asset
    IF violation_cert_id IS NOT NULL AND violation_asset_id IS NOT NULL THEN
        INSERT INTO crypto_implementations (
            id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
            key_exchange_algorithm, signature_algorithm, symmetric_encryption,
            hash_algorithm, key_size, certificate_id, discovery_method,
            confidence_score, raw_data, risk_score, compliance_status,
            first_discovered_at, last_verified_at, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            demo_tenant_id,
            violation_asset_id,
            'TLS'::protocol_type,
            '1.2',
            'TLS_RSA_WITH_AES_256_CBC_SHA256',
            'RSA',
            'SHA256WithRSA',
            'AES-256-CBC',
            'SHA256',
            1536,  -- Weak key size
            violation_cert_id,
            'manual'::discovery_method,
            1.0,
            jsonb_build_object('violation', 'weak_key_size', 'key_size', 1536),
            82,  -- High risk score
            '{}'::jsonb,
            NOW() - INTERVAL '30 days',
            NOW(),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO crypto_impl_id;

        IF crypto_impl_id IS NOT NULL THEN
            INSERT INTO crypto_implementation_certificates (
                crypto_implementation_id, certificate_id, certificate_role, certificate_order
            ) VALUES (
                crypto_impl_id, violation_cert_id, 'additional', 0
            )
            ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
        END IF;
    END IF;

    -- =================================================================
    -- Violations for PCI-DSS Framework
    -- =================================================================

    -- Violation 13: PCI 4.1.1/4.1.2 - Weak TLS version (TLS 1.0) for PCI-DSS
    SELECT id INTO violation_asset_id
    FROM network_assets
    WHERE tenant_id = demo_tenant_id
    AND hostname = 'pci-tls10.democorp.com'
    AND deleted_at IS NULL
    LIMIT 1;

    IF violation_asset_id IS NULL THEN
        INSERT INTO network_assets (
            tenant_id, hostname, ip_address, port, asset_type, operating_system,
            environment, business_unit, owner_email, description, tags,
            asset_status, asset_ownership, first_discovered_at, last_seen_at
        ) VALUES (
            demo_tenant_id,
            'pci-tls10.democorp.com',
            '10.1.100.12'::inet,
            443,
            'server'::asset_type,
            'CentOS 7',
            'production'::environment_type,
            'Payment Processing',
            'admin@democorp.com',
            'PCI-DSS payment server using TLS 1.0 (violates PCI 4.1.1/4.1.2)',
            jsonb_build_object('compliance_violation', 'weak_tls_version', 'control', 'PCI 4.1.1'),
            'monitoring'::VARCHAR(50),
            'internal'::VARCHAR(50),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO violation_asset_id;
    END IF;

    -- Create certificate for this asset
    IF violation_asset_id IS NOT NULL THEN
        INSERT INTO certificates (
            tenant_id, serial_number, subject_dn, issuer_dn, common_name,
            subject_alternative_names, signature_algorithm, public_key_algorithm,
            public_key_size, not_before, not_after,
            fingerprint_sha1, fingerprint_sha256,
            is_self_signed, is_ca_certificate,
            key_usage, extended_key_usage
        ) VALUES (
            demo_tenant_id,
            '55:66:77:88:99:AA:BB:CC:55:66:77:88:99:AA:BB:CC:55:66:77:88',
            'CN=pci-tls10.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
            'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
            'pci-tls10.democorp.com',
            ARRAY['pci-tls10.democorp.com'],
            'SHA256WithRSA', 'RSA', 2048,
            NOW() - INTERVAL '90 days',
            NOW() + INTERVAL '60 days',
            'f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1',
            'a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2001122334455667700aadd',
            false, false,
            ARRAY['Digital Signature', 'Key Encipherment'],
            ARRAY['Server Authentication']
        )
        ON CONFLICT (tenant_id, fingerprint_sha256) DO NOTHING
        RETURNING id INTO violation_cert_id_2;

        -- Create crypto implementation with TLS 1.0 (violates PCI 4.1.1/4.1.2)
        IF violation_cert_id_2 IS NOT NULL THEN
            INSERT INTO crypto_implementations (
                id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
                key_exchange_algorithm, signature_algorithm, symmetric_encryption,
                hash_algorithm, key_size, certificate_id, discovery_method,
                confidence_score, raw_data, risk_score, compliance_status,
                first_discovered_at, last_verified_at, created_at, updated_at
            ) VALUES (
                gen_random_uuid(),
                demo_tenant_id,
                violation_asset_id,
                'TLS'::protocol_type,
                '1.0',  -- Weak TLS version violates PCI 4.1.1/4.1.2
                'TLS_RSA_WITH_RC4_128_SHA',
                'RSA',
                'SHA1WithRSA',
                'RC4',
                'SHA1',
                2048,
                violation_cert_id_2,
                'manual'::discovery_method,
                1.0,
                jsonb_build_object('violation', 'weak_tls_version', 'tls_version', '1.0'),
                95,  -- Critical risk score
                '{}'::jsonb,
                NOW() - INTERVAL '30 days',
                NOW(),
                NOW() - INTERVAL '30 days',
                NOW()
            )
            ON CONFLICT DO NOTHING
            RETURNING id INTO crypto_impl_id;

            IF crypto_impl_id IS NOT NULL THEN
                INSERT INTO crypto_implementation_certificates (
                    crypto_implementation_id, certificate_id, certificate_role, certificate_order
                ) VALUES (
                    crypto_impl_id, violation_cert_id_2, 'additional', 0
                )
                ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
            END IF;
        END IF;
    END IF;

    -- Violation 14: PCI 3.2.1 - Weak key size (1536-bit RSA) for PCI-DSS
    INSERT INTO certificates (
        tenant_id, serial_number, subject_dn, issuer_dn, common_name,
        subject_alternative_names, signature_algorithm, public_key_algorithm,
        public_key_size, not_before, not_after,
        fingerprint_sha1, fingerprint_sha256,
        is_self_signed, is_ca_certificate,
        key_usage, extended_key_usage
    ) VALUES (
        demo_tenant_id,
        '66:77:88:99:AA:BB:CC:DD:66:77:88:99:AA:BB:CC:DD:66:77:88:99',
        'CN=pci-weak-key.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
        'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
        'pci-weak-key.democorp.com',
        ARRAY['pci-weak-key.democorp.com'],
        'SHA256WithRSA', 'RSA', 1536,  -- 1536-bit key violates PCI 3.2.1
        NOW() - INTERVAL '90 days',
        NOW() + INTERVAL '60 days',
        'a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
        'b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3001122334455667700bbee',
        false, false,
        ARRAY['Digital Signature', 'Key Encipherment'],
        ARRAY['Server Authentication']
    )
    ON CONFLICT (tenant_id, fingerprint_sha256) DO NOTHING
    RETURNING id INTO violation_cert_id;

    -- Get or create asset for this certificate
    SELECT id INTO violation_asset_id
    FROM network_assets
    WHERE tenant_id = demo_tenant_id
    AND hostname = 'pci-weak-key.democorp.com'
    AND deleted_at IS NULL
    LIMIT 1;

    IF violation_asset_id IS NULL THEN
        INSERT INTO network_assets (
            tenant_id, hostname, ip_address, port, asset_type, operating_system,
            environment, business_unit, owner_email, description, tags,
            asset_status, asset_ownership, first_discovered_at, last_seen_at
        ) VALUES (
            demo_tenant_id,
            'pci-weak-key.democorp.com',
            '10.1.100.13'::inet,
            443,
            'server'::asset_type,
            'Ubuntu 22.04',
            'production'::environment_type,
            'Payment Processing',
            'admin@democorp.com',
            'PCI-DSS payment server with weak 1536-bit RSA certificate (violates PCI 3.2.1)',
            jsonb_build_object('compliance_violation', 'weak_key_size', 'control', 'PCI 3.2.1'),
            'monitoring'::VARCHAR(50),
            'internal'::VARCHAR(50),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO violation_asset_id;
    END IF;

    -- Link certificate to asset
    IF violation_cert_id IS NOT NULL AND violation_asset_id IS NOT NULL THEN
        INSERT INTO crypto_implementations (
            id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
            key_exchange_algorithm, signature_algorithm, symmetric_encryption,
            hash_algorithm, key_size, certificate_id, discovery_method,
            confidence_score, raw_data, risk_score, compliance_status,
            first_discovered_at, last_verified_at, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            demo_tenant_id,
            violation_asset_id,
            'TLS'::protocol_type,
            '1.2',
            'TLS_RSA_WITH_AES_256_CBC_SHA256',
            'RSA',
            'SHA256WithRSA',
            'AES-256-CBC',
            'SHA256',
            1536,  -- Weak key size
            violation_cert_id,
            'manual'::discovery_method,
            1.0,
            jsonb_build_object('violation', 'weak_key_size', 'key_size', 1536),
            92,  -- Critical risk score
            '{}'::jsonb,
            NOW() - INTERVAL '30 days',
            NOW(),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO crypto_impl_id;

        IF crypto_impl_id IS NOT NULL THEN
            INSERT INTO crypto_implementation_certificates (
                crypto_implementation_id, certificate_id, certificate_role, certificate_order
            ) VALUES (
                crypto_impl_id, violation_cert_id, 'additional', 0
            )
            ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
        END IF;
    END IF;

    -- Violation 15: BP-003/BP-010 - Another weak cipher (3DES) for Best Practices
    SELECT id INTO violation_asset_id
    FROM network_assets
    WHERE tenant_id = demo_tenant_id
    AND hostname = 'weak-cipher-3des.democorp.com'
    AND deleted_at IS NULL
    LIMIT 1;

    IF violation_asset_id IS NULL THEN
        INSERT INTO network_assets (
            tenant_id, hostname, ip_address, port, asset_type, operating_system,
            environment, business_unit, owner_email, description, tags,
            asset_status, asset_ownership, first_discovered_at, last_seen_at
        ) VALUES (
            demo_tenant_id,
            'weak-cipher-3des.democorp.com',
            '10.1.100.14'::inet,
            443,
            'server'::asset_type,
            'Windows Server 2008',
            'production'::environment_type,
            'Legacy Systems',
            'admin@democorp.com',
            'Legacy server using weak 3DES cipher (violates BP-003/BP-010)',
            jsonb_build_object('compliance_violation', 'weak_cipher_3des', 'control', 'BP-003'),
            'monitoring'::VARCHAR(50),
            'internal'::VARCHAR(50),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO violation_asset_id;
    END IF;

    -- Create certificate for this asset
    IF violation_asset_id IS NOT NULL THEN
        INSERT INTO certificates (
            tenant_id, serial_number, subject_dn, issuer_dn, common_name,
            subject_alternative_names, signature_algorithm, public_key_algorithm,
            public_key_size, not_before, not_after,
            fingerprint_sha1, fingerprint_sha256,
            is_self_signed, is_ca_certificate,
            key_usage, extended_key_usage
        ) VALUES (
            demo_tenant_id,
            '77:88:99:AA:BB:CC:DD:EE:77:88:99:AA:BB:CC:DD:EE:77:88:99:AA',
            'CN=weak-cipher-3des.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
            'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
            'weak-cipher-3des.democorp.com',
            ARRAY['weak-cipher-3des.democorp.com'],
            'SHA256WithRSA', 'RSA', 2048,
            NOW() - INTERVAL '90 days',
            NOW() + INTERVAL '60 days',
            'b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3',
            'c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d300112233445566778899aabb',
            false, false,
            ARRAY['Digital Signature', 'Key Encipherment'],
            ARRAY['Server Authentication']
        )
        ON CONFLICT (tenant_id, fingerprint_sha256) DO NOTHING
        RETURNING id INTO violation_cert_id_2;

        -- Create crypto implementation with 3DES cipher (violates BP-003/BP-010)
        IF violation_cert_id_2 IS NOT NULL THEN
            INSERT INTO crypto_implementations (
                id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
                key_exchange_algorithm, signature_algorithm, symmetric_encryption,
                hash_algorithm, key_size, certificate_id, discovery_method,
                confidence_score, raw_data, risk_score, compliance_status,
                first_discovered_at, last_verified_at, created_at, updated_at
            ) VALUES (
                gen_random_uuid(),
                demo_tenant_id,
                violation_asset_id,
                'TLS'::protocol_type,
                '1.2',
                'TLS_RSA_WITH_3DES_EDE_CBC_SHA',  -- 3DES cipher violates BP-003/BP-010
                'RSA',
                'SHA1WithRSA',
                '3DES',  -- Weak cipher
                'SHA1',
                2048,
                violation_cert_id_2,
                'manual'::discovery_method,
                1.0,
                jsonb_build_object('violation', 'weak_cipher', 'cipher', '3DES'),
                88,  -- High risk score
                '{}'::jsonb,
                NOW() - INTERVAL '30 days',
                NOW(),
                NOW() - INTERVAL '30 days',
                NOW()
            )
            ON CONFLICT DO NOTHING
            RETURNING id INTO crypto_impl_id;

            IF crypto_impl_id IS NOT NULL THEN
                INSERT INTO crypto_implementation_certificates (
                    crypto_implementation_id, certificate_id, certificate_role, certificate_order
                ) VALUES (
                    crypto_impl_id, violation_cert_id_2, 'additional', 0
                )
                ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
            END IF;
        END IF;
    END IF;

    -- Violation 16: BP-005 - Another weak key size (1024-bit RSA) for Best Practices
    INSERT INTO certificates (
        tenant_id, serial_number, subject_dn, issuer_dn, common_name,
        subject_alternative_names, signature_algorithm, public_key_algorithm,
        public_key_size, not_before, not_after,
        fingerprint_sha1, fingerprint_sha256,
        is_self_signed, is_ca_certificate,
        key_usage, extended_key_usage
    ) VALUES (
        demo_tenant_id,
        '88:99:AA:BB:CC:DD:EE:FF:88:99:AA:BB:CC:DD:EE:FF:88:99:AA:BB',
        'CN=weak-key-bp2.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
        'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
        'weak-key-bp2.democorp.com',
        ARRAY['weak-key-bp2.democorp.com'],
        'SHA256WithRSA', 'RSA', 1024,  -- 1024-bit key violates BP-005
        NOW() - INTERVAL '90 days',
        NOW() + INTERVAL '60 days',
            'c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4',
        'd5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e400112233445566778899aabb',
        false, false,
        ARRAY['Digital Signature', 'Key Encipherment'],
        ARRAY['Server Authentication']
    )
    ON CONFLICT (tenant_id, fingerprint_sha256) DO NOTHING
    RETURNING id INTO violation_cert_id;

    -- Get or create asset for this certificate
    SELECT id INTO violation_asset_id
    FROM network_assets
    WHERE tenant_id = demo_tenant_id
    AND hostname = 'weak-key-bp2.democorp.com'
    AND deleted_at IS NULL
    LIMIT 1;

    IF violation_asset_id IS NULL THEN
        INSERT INTO network_assets (
            tenant_id, hostname, ip_address, port, asset_type, operating_system,
            environment, business_unit, owner_email, description, tags,
            asset_status, asset_ownership, first_discovered_at, last_seen_at
        ) VALUES (
            demo_tenant_id,
            'weak-key-bp2.democorp.com',
            '10.1.100.15'::inet,
            443,
            'server'::asset_type,
            'Ubuntu 20.04',
            'production'::environment_type,
            'IT Infrastructure',
            'admin@democorp.com',
            'Production server with weak 1024-bit RSA certificate (violates BP-005)',
            jsonb_build_object('compliance_violation', 'weak_key_size', 'control', 'BP-005'),
            'monitoring'::VARCHAR(50),
            'internal'::VARCHAR(50),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO violation_asset_id;
    END IF;

    -- Link certificate to asset
    IF violation_cert_id IS NOT NULL AND violation_asset_id IS NOT NULL THEN
        INSERT INTO crypto_implementations (
            id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
            key_exchange_algorithm, signature_algorithm, symmetric_encryption,
            hash_algorithm, key_size, certificate_id, discovery_method,
            confidence_score, raw_data, risk_score, compliance_status,
            first_discovered_at, last_verified_at, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            demo_tenant_id,
            violation_asset_id,
            'TLS'::protocol_type,
            '1.2',
            'TLS_RSA_WITH_AES_256_CBC_SHA256',
            'RSA',
            'SHA256WithRSA',
            'AES-256-CBC',
            'SHA256',
            1024,  -- Weak key size
            violation_cert_id,
            'manual'::discovery_method,
            1.0,
            jsonb_build_object('violation', 'weak_key_size', 'key_size', 1024),
            85,  -- High risk score
            '{}'::jsonb,
            NOW() - INTERVAL '30 days',
            NOW(),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO crypto_impl_id;

        IF crypto_impl_id IS NOT NULL THEN
            INSERT INTO crypto_implementation_certificates (
                crypto_implementation_id, certificate_id, certificate_role, certificate_order
            ) VALUES (
                crypto_impl_id, violation_cert_id, 'additional', 0
            )
            ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
        END IF;
    END IF;

    -- Violation 17: BP-002 - Another expiring certificate (28 days) for Best Practices
    INSERT INTO certificates (
        tenant_id, serial_number, subject_dn, issuer_dn, common_name,
        subject_alternative_names, signature_algorithm, public_key_algorithm,
        public_key_size, not_before, not_after,
        fingerprint_sha1, fingerprint_sha256,
        is_self_signed, is_ca_certificate,
        key_usage, extended_key_usage
    ) VALUES (
        demo_tenant_id,
        '99:AA:BB:CC:DD:EE:FF:00:99:AA:BB:CC:DD:EE:FF:00:99:AA:BB:CC',
        'CN=expiring-bp2.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
        'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
        'expiring-bp2.democorp.com',
        ARRAY['expiring-bp2.democorp.com'],
        'SHA256WithRSA', 'RSA', 2048,
        NOW() - INTERVAL '60 days',
        NOW() + INTERVAL '28 days',  -- Expiring in 28 days violates BP-002
        'd6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5',
        'e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f500112233445566778899aabb',
        false, false,
        ARRAY['Digital Signature', 'Key Encipherment'],
        ARRAY['Server Authentication']
    )
    ON CONFLICT (tenant_id, fingerprint_sha256) DO NOTHING
    RETURNING id INTO violation_cert_id_3;

    -- Get or create asset for this certificate
    SELECT id INTO violation_asset_id
    FROM network_assets
    WHERE tenant_id = demo_tenant_id
    AND hostname = 'expiring-bp2.democorp.com'
    AND deleted_at IS NULL
    LIMIT 1;

    IF violation_asset_id IS NULL THEN
        INSERT INTO network_assets (
            tenant_id, hostname, ip_address, port, asset_type, operating_system,
            environment, business_unit, owner_email, description, tags,
            asset_status, asset_ownership, first_discovered_at, last_seen_at
        ) VALUES (
            demo_tenant_id,
            'expiring-bp2.democorp.com',
            '10.1.100.16'::inet,
            443,
            'server'::asset_type,
            'Ubuntu 22.04',
            'production'::environment_type,
            'Web Services',
            'admin@democorp.com',
            'Production server with certificate expiring in 28 days (violates BP-002)',
            jsonb_build_object('compliance_violation', 'cert_expiring_soon', 'control', 'BP-002'),
            'monitoring'::VARCHAR(50),
            'internal'::VARCHAR(50),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO violation_asset_id;
    END IF;

    -- Link certificate to asset
    IF violation_cert_id_3 IS NOT NULL AND violation_asset_id IS NOT NULL THEN
        INSERT INTO crypto_implementations (
            id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
            key_exchange_algorithm, signature_algorithm, symmetric_encryption,
            hash_algorithm, key_size, certificate_id, discovery_method,
            confidence_score, raw_data, risk_score, compliance_status,
            first_discovered_at, last_verified_at, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            demo_tenant_id,
            violation_asset_id,
            'TLS'::protocol_type,
            '1.2',
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            'ECDHE',
            'SHA256WithRSA',
            'AES-256-GCM',
            'SHA384',
            2048,
            violation_cert_id_3,
            'manual'::discovery_method,
            1.0,
            jsonb_build_object('violation', 'cert_expiring_soon', 'expiration_days', 28),
            52,  -- Medium risk score
            '{}'::jsonb,
            NOW() - INTERVAL '30 days',
            NOW(),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO crypto_impl_id;

        IF crypto_impl_id IS NOT NULL THEN
            INSERT INTO crypto_implementation_certificates (
                crypto_implementation_id, certificate_id, certificate_role, certificate_order
            ) VALUES (
                crypto_impl_id, violation_cert_id_3, 'additional', 0
            )
            ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
        END IF;
    END IF;

    -- Violation 18: CC6.6.1 - Another weak TLS version (TLS 1.1) for SOC 2
    SELECT id INTO violation_asset_id
    FROM network_assets
    WHERE tenant_id = demo_tenant_id
    AND hostname = 'soc2-tls11.democorp.com'
    AND deleted_at IS NULL
    LIMIT 1;

    IF violation_asset_id IS NULL THEN
        INSERT INTO network_assets (
            tenant_id, hostname, ip_address, port, asset_type, operating_system,
            environment, business_unit, owner_email, description, tags,
            asset_status, asset_ownership, first_discovered_at, last_seen_at
        ) VALUES (
            demo_tenant_id,
            'soc2-tls11.democorp.com',
            '10.1.100.17'::inet,
            443,
            'server'::asset_type,
            'CentOS 6',
            'production'::environment_type,
            'Compliance Systems',
            'admin@democorp.com',
            'SOC 2 compliance server using TLS 1.1 (violates CC6.6.1)',
            jsonb_build_object('compliance_violation', 'weak_tls_version', 'control', 'CC6.6.1'),
            'monitoring'::VARCHAR(50),
            'internal'::VARCHAR(50),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO violation_asset_id;
    END IF;

    -- Create certificate for this asset
    IF violation_asset_id IS NOT NULL THEN
        INSERT INTO certificates (
            tenant_id, serial_number, subject_dn, issuer_dn, common_name,
            subject_alternative_names, signature_algorithm, public_key_algorithm,
            public_key_size, not_before, not_after,
            fingerprint_sha1, fingerprint_sha256,
            is_self_signed, is_ca_certificate,
            key_usage, extended_key_usage
        ) VALUES (
            demo_tenant_id,
            'AA:BB:CC:DD:EE:FF:00:11:AA:BB:CC:DD:EE:FF:00:11:AA:BB:CC:DD',
            'CN=soc2-tls11.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
            'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
            'soc2-tls11.democorp.com',
            ARRAY['soc2-tls11.democorp.com'],
            'SHA256WithRSA', 'RSA', 2048,
            NOW() - INTERVAL '90 days',
            NOW() + INTERVAL '60 days',
            'e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6',
            'f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a600112233445566778899aabb',
            false, false,
            ARRAY['Digital Signature', 'Key Encipherment'],
            ARRAY['Server Authentication']
        )
        ON CONFLICT (tenant_id, fingerprint_sha256) DO NOTHING
        RETURNING id INTO violation_cert_id_2;

        -- Create crypto implementation with TLS 1.1 (violates CC6.6.1)
        IF violation_cert_id_2 IS NOT NULL THEN
            INSERT INTO crypto_implementations (
                id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
                key_exchange_algorithm, signature_algorithm, symmetric_encryption,
                hash_algorithm, key_size, certificate_id, discovery_method,
                confidence_score, raw_data, risk_score, compliance_status,
                first_discovered_at, last_verified_at, created_at, updated_at
            ) VALUES (
                gen_random_uuid(),
                demo_tenant_id,
                violation_asset_id,
                'TLS'::protocol_type,
                '1.1',  -- Weak TLS version violates CC6.6.1
                'TLS_RSA_WITH_AES_128_CBC_SHA',
                'RSA',
                'SHA256WithRSA',
                'AES-128-CBC',
                'SHA256',
                2048,
                violation_cert_id_2,
                'manual'::discovery_method,
                1.0,
                jsonb_build_object('violation', 'weak_tls_version', 'tls_version', '1.1'),
                83,  -- High risk score
                '{}'::jsonb,
                NOW() - INTERVAL '30 days',
                NOW(),
                NOW() - INTERVAL '30 days',
                NOW()
            )
            ON CONFLICT DO NOTHING
            RETURNING id INTO crypto_impl_id;

            IF crypto_impl_id IS NOT NULL THEN
                INSERT INTO crypto_implementation_certificates (
                    crypto_implementation_id, certificate_id, certificate_role, certificate_order
                ) VALUES (
                    crypto_impl_id, violation_cert_id_2, 'additional', 0
                )
                ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
            END IF;
        END IF;
    END IF;

    -- Violation 19: CC6.6.4 - Another weak key size (1024-bit RSA) for SOC 2
    INSERT INTO certificates (
        tenant_id, serial_number, subject_dn, issuer_dn, common_name,
        subject_alternative_names, signature_algorithm, public_key_algorithm,
        public_key_size, not_before, not_after,
        fingerprint_sha1, fingerprint_sha256,
        is_self_signed, is_ca_certificate,
        key_usage, extended_key_usage
    ) VALUES (
        demo_tenant_id,
        'BB:CC:DD:EE:FF:00:11:22:BB:CC:DD:EE:FF:00:11:22:BB:CC:DD:EE',
        'CN=soc2-weak-key2.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
        'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
        'soc2-weak-key2.democorp.com',
        ARRAY['soc2-weak-key2.democorp.com'],
        'SHA256WithRSA', 'RSA', 1024,  -- 1024-bit key violates CC6.6.4
        NOW() - INTERVAL '90 days',
        NOW() + INTERVAL '60 days',
        'f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7',
        'a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b700112233445566778899aabb',
        false, false,
        ARRAY['Digital Signature', 'Key Encipherment'],
        ARRAY['Server Authentication']
    )
    ON CONFLICT (tenant_id, fingerprint_sha256) DO NOTHING
    RETURNING id INTO violation_cert_id;

    -- Get or create asset for this certificate
    SELECT id INTO violation_asset_id
    FROM network_assets
    WHERE tenant_id = demo_tenant_id
    AND hostname = 'soc2-weak-key2.democorp.com'
    AND deleted_at IS NULL
    LIMIT 1;

    IF violation_asset_id IS NULL THEN
        INSERT INTO network_assets (
            tenant_id, hostname, ip_address, port, asset_type, operating_system,
            environment, business_unit, owner_email, description, tags,
            asset_status, asset_ownership, first_discovered_at, last_seen_at
        ) VALUES (
            demo_tenant_id,
            'soc2-weak-key2.democorp.com',
            '10.1.100.18'::inet,
            443,
            'server'::asset_type,
            'Ubuntu 22.04',
            'production'::environment_type,
            'Compliance Systems',
            'admin@democorp.com',
            'SOC 2 compliance server with weak 1024-bit RSA certificate (violates CC6.6.4)',
            jsonb_build_object('compliance_violation', 'weak_key_size', 'control', 'CC6.6.4'),
            'monitoring'::VARCHAR(50),
            'internal'::VARCHAR(50),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO violation_asset_id;
    END IF;

    -- Link certificate to asset
    IF violation_cert_id IS NOT NULL AND violation_asset_id IS NOT NULL THEN
        INSERT INTO crypto_implementations (
            id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
            key_exchange_algorithm, signature_algorithm, symmetric_encryption,
            hash_algorithm, key_size, certificate_id, discovery_method,
            confidence_score, raw_data, risk_score, compliance_status,
            first_discovered_at, last_verified_at, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            demo_tenant_id,
            violation_asset_id,
            'TLS'::protocol_type,
            '1.2',
            'TLS_RSA_WITH_AES_256_CBC_SHA256',
            'RSA',
            'SHA256WithRSA',
            'AES-256-CBC',
            'SHA256',
            1024,  -- Weak key size
            violation_cert_id,
            'manual'::discovery_method,
            1.0,
            jsonb_build_object('violation', 'weak_key_size', 'key_size', 1024),
            87,  -- High risk score
            '{}'::jsonb,
            NOW() - INTERVAL '30 days',
            NOW(),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO crypto_impl_id;

        IF crypto_impl_id IS NOT NULL THEN
            INSERT INTO crypto_implementation_certificates (
                crypto_implementation_id, certificate_id, certificate_role, certificate_order
            ) VALUES (
                crypto_impl_id, violation_cert_id, 'additional', 0
            )
            ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
        END IF;
    END IF;

    -- Violation 20: PCI 4.1.1/4.1.2 - Another weak TLS version (TLS 1.1) for PCI-DSS
    SELECT id INTO violation_asset_id
    FROM network_assets
    WHERE tenant_id = demo_tenant_id
    AND hostname = 'pci-tls11.democorp.com'
    AND deleted_at IS NULL
    LIMIT 1;

    IF violation_asset_id IS NULL THEN
        INSERT INTO network_assets (
            tenant_id, hostname, ip_address, port, asset_type, operating_system,
            environment, business_unit, owner_email, description, tags,
            asset_status, asset_ownership, first_discovered_at, last_seen_at
        ) VALUES (
            demo_tenant_id,
            'pci-tls11.democorp.com',
            '10.1.100.19'::inet,
            443,
            'server'::asset_type,
            'CentOS 6',
            'production'::environment_type,
            'Payment Processing',
            'admin@democorp.com',
            'PCI-DSS payment server using TLS 1.1 (violates PCI 4.1.1/4.1.2)',
            jsonb_build_object('compliance_violation', 'weak_tls_version', 'control', 'PCI 4.1.1'),
            'monitoring'::VARCHAR(50),
            'internal'::VARCHAR(50),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO violation_asset_id;
    END IF;

    -- Create certificate for this asset
    IF violation_asset_id IS NOT NULL THEN
        INSERT INTO certificates (
            tenant_id, serial_number, subject_dn, issuer_dn, common_name,
            subject_alternative_names, signature_algorithm, public_key_algorithm,
            public_key_size, not_before, not_after,
            fingerprint_sha1, fingerprint_sha256,
            is_self_signed, is_ca_certificate,
            key_usage, extended_key_usage
        ) VALUES (
            demo_tenant_id,
            'CC:DD:EE:FF:00:11:22:33:CC:DD:EE:FF:00:11:22:33:CC:DD:EE:FF',
            'CN=pci-tls11.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
            'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
            'pci-tls11.democorp.com',
            ARRAY['pci-tls11.democorp.com'],
            'SHA256WithRSA', 'RSA', 2048,
            NOW() - INTERVAL '90 days',
            NOW() + INTERVAL '60 days',
            'a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8',
            'b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c800112233445566778899aabb',
            false, false,
            ARRAY['Digital Signature', 'Key Encipherment'],
            ARRAY['Server Authentication']
        )
        ON CONFLICT (tenant_id, fingerprint_sha256) DO NOTHING
        RETURNING id INTO violation_cert_id_2;

        -- Create crypto implementation with TLS 1.1 (violates PCI 4.1.1/4.1.2)
        IF violation_cert_id_2 IS NOT NULL THEN
            INSERT INTO crypto_implementations (
                id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
                key_exchange_algorithm, signature_algorithm, symmetric_encryption,
                hash_algorithm, key_size, certificate_id, discovery_method,
                confidence_score, raw_data, risk_score, compliance_status,
                first_discovered_at, last_verified_at, created_at, updated_at
            ) VALUES (
                gen_random_uuid(),
                demo_tenant_id,
                violation_asset_id,
                'TLS'::protocol_type,
                '1.1',  -- Weak TLS version violates PCI 4.1.1/4.1.2
                'TLS_RSA_WITH_AES_128_CBC_SHA',
                'RSA',
                'SHA256WithRSA',
                'AES-128-CBC',
                'SHA256',
                2048,
                violation_cert_id_2,
                'manual'::discovery_method,
                1.0,
                jsonb_build_object('violation', 'weak_tls_version', 'tls_version', '1.1'),
                93,  -- Critical risk score
                '{}'::jsonb,
                NOW() - INTERVAL '30 days',
                NOW(),
                NOW() - INTERVAL '30 days',
                NOW()
            )
            ON CONFLICT DO NOTHING
            RETURNING id INTO crypto_impl_id;

            IF crypto_impl_id IS NOT NULL THEN
                INSERT INTO crypto_implementation_certificates (
                    crypto_implementation_id, certificate_id, certificate_role, certificate_order
                ) VALUES (
                    crypto_impl_id, violation_cert_id_2, 'additional', 0
                )
                ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
            END IF;
        END IF;
    END IF;

    -- Violation 21: PCI 3.2.1 - Another weak key size (1024-bit RSA) for PCI-DSS
    INSERT INTO certificates (
        tenant_id, serial_number, subject_dn, issuer_dn, common_name,
        subject_alternative_names, signature_algorithm, public_key_algorithm,
        public_key_size, not_before, not_after,
        fingerprint_sha1, fingerprint_sha256,
        is_self_signed, is_ca_certificate,
        key_usage, extended_key_usage
    ) VALUES (
        demo_tenant_id,
        'DD:EE:FF:00:11:22:33:44:DD:EE:FF:00:11:22:33:44:DD:EE:FF:00',
        'CN=pci-weak-key2.democorp.com,O=Demo Corporation,L=San Francisco,ST=California,C=US',
        'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt,C=US',
        'pci-weak-key2.democorp.com',
        ARRAY['pci-weak-key2.democorp.com'],
        'SHA256WithRSA', 'RSA', 1024,  -- 1024-bit key violates PCI 3.2.1
        NOW() - INTERVAL '90 days',
        NOW() + INTERVAL '60 days',
        'b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9',
        'c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d900112233445566778899aabb',
        false, false,
        ARRAY['Digital Signature', 'Key Encipherment'],
        ARRAY['Server Authentication']
    )
    ON CONFLICT (tenant_id, fingerprint_sha256) DO NOTHING
    RETURNING id INTO violation_cert_id;

    -- Get or create asset for this certificate
    SELECT id INTO violation_asset_id
    FROM network_assets
    WHERE tenant_id = demo_tenant_id
    AND hostname = 'pci-weak-key2.democorp.com'
    AND deleted_at IS NULL
    LIMIT 1;

    IF violation_asset_id IS NULL THEN
        INSERT INTO network_assets (
            tenant_id, hostname, ip_address, port, asset_type, operating_system,
            environment, business_unit, owner_email, description, tags,
            asset_status, asset_ownership, first_discovered_at, last_seen_at
        ) VALUES (
            demo_tenant_id,
            'pci-weak-key2.democorp.com',
            '10.1.100.20'::inet,
            443,
            'server'::asset_type,
            'Ubuntu 22.04',
            'production'::environment_type,
            'Payment Processing',
            'admin@democorp.com',
            'PCI-DSS payment server with weak 1024-bit RSA certificate (violates PCI 3.2.1)',
            jsonb_build_object('compliance_violation', 'weak_key_size', 'control', 'PCI 3.2.1'),
            'monitoring'::VARCHAR(50),
            'internal'::VARCHAR(50),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO violation_asset_id;
    END IF;

    -- Link certificate to asset
    IF violation_cert_id IS NOT NULL AND violation_asset_id IS NOT NULL THEN
        INSERT INTO crypto_implementations (
            id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
            key_exchange_algorithm, signature_algorithm, symmetric_encryption,
            hash_algorithm, key_size, certificate_id, discovery_method,
            confidence_score, raw_data, risk_score, compliance_status,
            first_discovered_at, last_verified_at, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            demo_tenant_id,
            violation_asset_id,
            'TLS'::protocol_type,
            '1.2',
            'TLS_RSA_WITH_AES_256_CBC_SHA256',
            'RSA',
            'SHA256WithRSA',
            'AES-256-CBC',
            'SHA256',
            1024,  -- Weak key size
            violation_cert_id,
            'manual'::discovery_method,
            1.0,
            jsonb_build_object('violation', 'weak_key_size', 'key_size', 1024),
            94,  -- Critical risk score
            '{}'::jsonb,
            NOW() - INTERVAL '30 days',
            NOW(),
            NOW() - INTERVAL '30 days',
            NOW()
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO crypto_impl_id;

        IF crypto_impl_id IS NOT NULL THEN
            INSERT INTO crypto_implementation_certificates (
                crypto_implementation_id, certificate_id, certificate_role, certificate_order
            ) VALUES (
                crypto_impl_id, violation_cert_id, 'additional', 0
            )
            ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING;
        END IF;
    END IF;

    RAISE NOTICE '✅ Seeded compliance violations for all frameworks';
    RAISE NOTICE '   NIST CSF:';
    RAISE NOTICE '     - PR.DS-1: Weak key sizes (1024-bit, 512-bit) - 2 violations';
    RAISE NOTICE '     - PR.DS-2: Weak TLS versions (TLS 1.0, TLS 1.1) - 2 violations';
    RAISE NOTICE '     - PR.DS-3: Certificates expiring soon (15 days, 20 days) - 2 violations';
    RAISE NOTICE '   Best Practices:';
    RAISE NOTICE '     - BP-002: Certificates expiring soon (25 days, 28 days) - 2 violations';
    RAISE NOTICE '     - BP-003/BP-010: Weak ciphers (RC4, 3DES) - 2 violations';
    RAISE NOTICE '     - BP-005: Weak key sizes (1536-bit, 1024-bit) - 2 violations';
    RAISE NOTICE '   SOC 2:';
    RAISE NOTICE '     - CC6.6.1: Weak TLS versions (TLS 1.0, TLS 1.1) - 2 violations';
    RAISE NOTICE '     - CC6.6.4: Weak key sizes (1536-bit, 1024-bit) - 2 violations';
    RAISE NOTICE '   PCI-DSS:';
    RAISE NOTICE '     - PCI 4.1.1/4.1.2: Weak TLS versions (TLS 1.0, TLS 1.1) - 2 violations';
    RAISE NOTICE '     - PCI 3.2.1: Weak key sizes (1536-bit, 1024-bit) - 2 violations';
    RAISE NOTICE '';
    RAISE NOTICE 'Total: 21 violations across all frameworks';
    RAISE NOTICE 'Next step: Trigger AssetChangedEvent events to generate findings';

END $$;
