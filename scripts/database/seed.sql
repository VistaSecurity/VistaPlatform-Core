-- =================================================================
-- Vista Platform - Tier 1 Core Seed Data
-- =================================================================
-- This file contains core system data required for the platform to function.
-- It should be loaded in ALL environments (dev, smoke, prod).
--
-- DOES NOT INCLUDE:
--   - Demo-corp tenant (see seed_demo.sql for Tier 2 demo data)
--   - Demo users or test data
--
-- Note: Tenant roles are created dynamically by the auth-service when
-- a new tenant is onboarded. No tenant-specific data is included here.
-- =================================================================

-- =================================================================
-- Platform Roles
-- =================================================================
-- These must exist before platform_users can be inserted (users SELECT from this table).
INSERT INTO platform_roles (name, display_name, description, is_system_role) VALUES
    ('super_admin',    'Super Administrator', 'Full platform access, can manage all tenants and platform settings', true),
    ('platform_admin', 'Platform Admin',      'Standard platform administration',                                   true),
    ('support_agent',  'Support Agent',       'Read-only support access',                                          true)
ON CONFLICT (name) DO NOTHING;

-- =================================================================
-- Platform Permissions + Role Assignments
-- =================================================================
INSERT INTO platform_permissions (name, resource, action, description) VALUES
('tenants.create',            'tenants',            'create', 'Create new tenants'),
('tenants.read',              'tenants',            'read',   'View tenant information'),
('tenants.update',            'tenants',            'update', 'Update tenant settings'),
('tenants.delete',            'tenants',            'delete', 'Delete tenants'),
('tenants.manage',            'tenants',            'manage', 'Full tenant management'),
('tenants.activate',          'tenants',            'update', 'Activate tenants'),
('tenants.suspend',           'tenants',            'update', 'Suspend tenants'),
('platform_users.create',     'platform_users',     'create', 'Create platform users'),
('platform_users.read',       'platform_users',     'read',   'View platform users'),
('platform_users.update',     'platform_users',     'update', 'Update platform users'),
('platform_users.delete',     'platform_users',     'delete', 'Delete platform users'),
('platform_users.manage',     'platform_users',     'manage', 'Create and update platform users (gate for the create/update routes)'),
('platform_roles.read',       'platform_roles',     'read',   'View platform roles'),
('platform_roles.assign',     'platform_roles',     'manage', 'Assign platform roles to platform users'),
('platform_roles.manage',     'platform_roles',     'manage', 'Create/edit/delete platform roles and set their permissions'),
('platform_permissions.read', 'platform_permissions','read',  'View platform permissions'),
('algorithms.manage',         'algorithms',         'manage', 'Create, edit, and deprecate algorithm definitions (the crypto-assessment source of truth)'),
('tenant_roles.assign',       'tenant_roles',       'manage', 'Assign tenant roles across tenants'),
('platform.settings',         'platform',           'manage', 'Manage platform settings'),
('platform.billing',          'platform',           'manage', 'Manage platform billing'),
('platform.analytics',        'platform',           'read',   'View platform analytics'),
('platform.health',           'platform',           'read',   'View platform health and monitoring dashboards'),
('platform.logs',             'platform',           'read',   'View platform logs'),
('platform.logs.manage',      'platform',           'manage', 'Manage platform logging configuration'),
('platform.security',         'platform',           'read',   'View security dashboard and events'),
('platform.security.manage',  'platform',           'manage', 'Manage security settings and incidents'),
('platform.audit',            'platform',           'read',   'View platform audit logs'),
('platform.override',         'platform',           'manage', 'Override permissions in exceptional cases'),
('platform.notifications.manage','platform',        'manage', 'Manage platform notification channels, rules, and announcements'),
('platform.impersonate',      'platform',           'manage', 'Initiate and audit tenant impersonation (break-glass)'),
('platform.logs.read',        'platform',           'read',   'View platform logs (the .read gate used by the log routes)'),
('support.tenants',           'tenants',            'read',   'View tenant data for support'),
('support.users',             'users',              'read',   'View user data for support')
ON CONFLICT (name) DO NOTHING;

-- Assign all permissions to super_admin; assign read/support subset to platform_admin and support_agent
INSERT INTO platform_role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM platform_roles r, platform_permissions p
WHERE r.name = 'super_admin'
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO platform_role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM platform_roles r, platform_permissions p
WHERE r.name = 'platform_admin'
  AND p.name IN (
    'tenants.read','tenants.update','tenants.manage','tenants.activate','tenants.suspend',
    'platform_users.read','platform_users.create','platform_users.update','platform_users.manage',
    'platform_roles.read','platform_permissions.read','tenant_roles.assign',
    'algorithms.manage',
    'platform.settings','platform.billing','platform.analytics',
    'platform.health','platform.logs','platform.logs.read','platform.security','platform.audit',
    'platform.notifications.manage','platform.impersonate'
  )
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO platform_role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM platform_roles r, platform_permissions p
WHERE r.name = 'support_agent'
  AND p.name IN (
    'tenants.read','platform_users.read','platform_roles.read',
    'platform.health','platform.logs','platform.audit',
    'support.tenants','support.users'
  )
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- =================================================================
-- Billing Providers
-- =================================================================
-- Seed the provider rows that webhook_processor + billing handlers look up via
-- `SELECT id FROM billing_providers WHERE key = 'stripe'`. Without this, the
-- receive-path `INSERT INTO billing_events (provider_id NOT NULL, ...)` fails
-- (the lookup returns NULL) and the handler swallows the error with `_, _ =`,
-- so Stripe webhooks silently return 200 while every event is dropped before
-- the worker ever sees it. archive/07-billing.sql used to seed this row; the
-- consolidated seed.sql never picked it up, which surfaced in prod when wiring
-- Stripe for v2.5.4.
INSERT INTO billing_providers (key, display_name, is_active) VALUES
    ('stripe', 'Stripe', true)
ON CONFLICT (key) DO NOTHING;

-- =================================================================
-- Subscription Tiers
-- =================================================================
-- Backward-compat rename: any cluster seeded before PR 1 has a 'professional'
-- row. Rename it to 'pro' BEFORE the INSERT so the INSERT's ON CONFLICT can
-- short-circuit and not race the post-INSERT rename step (which would fail
-- with a unique-constraint violation on subsequent runs).
UPDATE subscription_tiers SET name = 'pro', display_name = 'Pro' WHERE name = 'professional';

INSERT INTO subscription_tiers (name, display_name, max_sensors, max_assets, max_users, retention_days, price_cents, billing_interval, features, display_order, is_active) VALUES
('free',       'Free',       1,  50,   1,    7,    0,     'monthly', '{"compliance_frameworks":0,"ai_insights":false,"integrations_max":0,"priority_support":false,"reporting_enabled":false}'::jsonb,  1, true),
('starter',    'Starter',    5,  1000, -1,   90,   4900,  'monthly', '{"compliance_frameworks":0,"ai_insights":false,"integrations_max":1,"priority_support":false,"reporting_enabled":true,"report_types":["pdf"]}'::jsonb, 2, true),
('pro',        'Pro',        10, 5000, 25,   365,  19900, 'monthly', '{"compliance_frameworks":3,"ai_insights":true,"integrations_max":5,"priority_support":true,"reporting_enabled":true,"report_types":["pdf","excel"]}'::jsonb, 3, true),
('enterprise', 'Enterprise', -1, -1,   -1,   1095, 0,     'monthly', '{"compliance_frameworks":-1,"ai_insights":true,"integrations_max":-1,"priority_support":true,"reporting_enabled":true,"report_types":["pdf","excel","custom"],"sso":true,"custom_branding":true,"dedicated_success_manager":true,"sla_uptime":99.9,"ot_active_probing":true}'::jsonb, 4, true),
-- Community is the Core edition's tier: unlimited CAPACITY, zero paid
-- CAPABILITIES. It exists because a tenant with no tier at all resolves every
-- numeric cap to billable_items.default_value, and those defaults are
-- deliberately conservative (max_sensors 0, max_assets 0) — so a self-hosted
-- Core install with no tier could register no sensors and track no assets.
--
-- display_order 0 and is_active=false keep it off the customer-facing
-- plan-comparison surface: it is not something anyone buys or selects, it is
-- the floor a Core deployment runs on. Edition gating still applies
-- independently via shared/entitlements/editions.go, so listing a paid item
-- here as false is belt-and-suspenders, not the only defence.
('community',  'Community',  -1, -1,   -1,   365,  0,     'monthly', '{"compliance_frameworks":0,"ai_insights":false,"integrations_max":-1,"priority_support":false,"reporting_enabled":true}'::jsonb, 0, false)
ON CONFLICT (name) DO NOTHING;

-- Converge Starter to PR 1 design for clusters seeded against the earlier
-- main-branch starter row (max_sensors=3, max_assets=500, max_users=5,
-- compliance_frameworks=1, integrations=2). Idempotent: re-runs are no-ops
-- once the row already matches.
UPDATE subscription_tiers SET
    max_sensors = 5,
    max_assets = 1000,
    max_users = -1,
    retention_days = 90,
    price_cents = 4900,
    features = features || '{"compliance_frameworks":0,"integrations_max":1,"reporting_enabled":true,"report_types":["pdf"]}'::jsonb
WHERE name = 'starter';

-- Backfill ot_active_probing on the Enterprise tier for clusters where the
-- INSERT above was a no-op (ON CONFLICT DO NOTHING). Adds the flag without
-- disturbing other features. Safe to re-run; jsonb || takes the latest
-- value for any duplicated key.
UPDATE subscription_tiers
SET features = features || '{"ot_active_probing":true}'::jsonb
WHERE name = 'enterprise'
  AND NOT (features ? 'ot_active_probing');

-- =================================================================
-- Subscription Tiers — PR 1 of billing/tier-flexibility redesign
--
-- Four-tier model: Free (trial) / Starter / Pro / Enterprise.
--   • Legacy 'professional' → 'pro' rename happens above, before the
--     main INSERT, so re-runs don't race the unique-name constraint.
--   • Starter is created by the main INSERT above; this section just
--     marks Free as the trial tier and unlimits users everywhere.
--   • All statements are idempotent.
-- =================================================================

-- Mark Free as a trial: 14 days full access + 14 days soft prompt + hard lock
UPDATE subscription_tiers SET is_trial = true, trial_days_full = 14, trial_days_soft = 14 WHERE name = 'free';

-- Users are not gated per PR 1 design; unlimit across every tier
UPDATE subscription_tiers SET max_users = -1 WHERE max_users IS NOT NULL AND max_users != -1;

-- =================================================================
-- Billable Items Catalog — PR 1 (seed ~15 items)
--
-- Each row defines one gateable/billable concept. New items can be added
-- without code changes once the resolver layer lands (PR 2). is_addon_eligible
-- = true means a tenant on a tier that doesn't include this item can buy
-- it a la carte at default_addon_price_cents (sales can override per-tenant).
-- =================================================================
INSERT INTO billable_items (key, display_name, description, category, kind, unit, default_value, is_addon_eligible, default_addon_price_cents, sort_order) VALUES
-- Capacity caps
('max_sensors',               'Sensors',                    'Maximum number of sensors a tenant may register',          'capacity',   'numeric_cap',     'sensors',    '{"quantity": 0}'::jsonb,             true,  4900,  10),
('max_assets',                'Assets',                     'Maximum number of inventory assets a tenant may track',     'capacity',   'numeric_cap',     'assets',     '{"quantity": 0}'::jsonb,             true,  2900,  20),
('max_users',                 'Users',                      'Maximum tenant members (active users plus pending invitations); null = unlimited', 'capacity', 'numeric_cap', 'users', '{"quantity": null}'::jsonb, true, NULL, 25),
('retention_days',            'Data Retention',             'Days of historical data retained before pruning',           'capacity',   'numeric_cap',     'days',       '{"quantity": 7}'::jsonb,             false, NULL,  30),
('compliance_frameworks_max', 'Compliance Frameworks',      'Maximum subscribed compliance frameworks beyond the auto-licensed Best Practices policy', 'capacity', 'numeric_cap', 'frameworks', '{"quantity": 0}'::jsonb, true, 9900, 40),
('integrations_max',          'External Integrations',      'Maximum configured third-party integrations (Jira, ServiceNow, Slack, etc.)', 'capacity', 'numeric_cap', 'integrations', '{"quantity": 0}'::jsonb, true, 1900, 50),

-- Meters (numeric_metered: included quota; NOT billed — billing is flat
-- per-tier since the 2026-07 overage-pipeline removal, so no seeded
-- overage prices. Quotas are monitoring/enforcement metadata only.)
('storage_gb',                'Storage',                    'Total tenant data storage, tracked against the included quota (monitoring only; not billed)', 'meter', 'numeric_metered', 'GB',  '{"quantity": 1}'::jsonb,  false, NULL, 100),
('pcap_gb_per_month',         'PCAP Processed per Month',   'Monthly PCAP bytes processed by pcap-processor, tracked against the included quota (monitoring only; not billed)', 'meter', 'numeric_metered', 'GB',  '{"quantity": 0}'::jsonb,  false, NULL, 110),

-- Capabilities (boolean gates)
('custom_policies',           'Custom Compliance Policies', 'Tenant may author their own compliance frameworks beyond platform-published ones', 'capability', 'boolean', NULL, '{"enabled": false}'::jsonb, true, 19900, 200),
('threshold_overrides',       'Threshold Overrides',        'Tenant may customize measurement thresholds on subscribed platform-framework controls', 'capability', 'boolean', NULL, '{"enabled": false}'::jsonb, true, 4900, 210),
('ot_active_probing',         'OT Active Probing',          'Active TLS/protocol probing of OT/ICS devices (Modbus, DNP3, BACnet, etc.); risk-managed feature', 'capability', 'boolean', NULL, '{"enabled": false}'::jsonb, true, 14900, 220),
('ot_primary_lens',           'OT Inventory Lens',          'OT-specific inventory view and dashboards', 'capability', 'boolean', NULL, '{"enabled": false}'::jsonb, true, 4900, 230),
('cbom_signing',              'CBOM Signing & Attestation', 'Cryptographic signing of CBOM artifacts with compliance-attestation layers', 'capability', 'boolean', NULL, '{"enabled": false}'::jsonb, true, 9900, 240),
('sso_saml',                  'SSO / SAML',                 'Single sign-on via your own identity provider — OIDC (Google, Microsoft, Azure AD) or SAML 2.0 — with group-to-role mapping and an org-wide authentication policy', 'capability', 'boolean', NULL, '{"enabled": false}'::jsonb, true, 9900, 250),
('cmdb_sync',                 'CMDB / ITSM Sync',           'Sync inventory out to an external CMDB or ITSM (ServiceNow, Device42, SolarWinds)', 'capability', 'boolean', NULL, '{"enabled": false}'::jsonb, false, NULL,  67),
('siem_export',               'SIEM Export',                'Forward audit events to an external SIEM (Splunk, Datadog, Elastic, webhook)',      'capability', 'boolean', NULL, '{"enabled": false}'::jsonb, false, NULL,  68),
('custom_branding',           'Custom Branding',            'White-label admin and web UI with custom logos and colors', 'capability', 'boolean', NULL, '{"enabled": false}'::jsonb, true, 14900, 260),
('billing_portal',            'Self-Service Billing',       'Tenant-facing subscription, invoices, plan change and payment portal (admin-service /my-billing). Absent from Core; usage-against-limits is unconditional.', 'capability', 'boolean', NULL, '{"enabled": false}'::jsonb, false, NULL,  69),

-- Support tier (enum)
('support_sla_tier',          'Support SLA',                'Response-time tier for support requests', 'support', 'enum_choice', NULL, '{"value": "community"}'::jsonb, false, NULL, 300)
ON CONFLICT (key) DO NOTHING;

-- =================================================================
-- Tier Entitlements — populate the matrix
--
-- Resolves tier name + item key to UUIDs at insert time; ON CONFLICT
-- skips already-populated cells so this is fully idempotent.
-- included_value shape matches billable_items.kind:
--   numeric_cap     : {"quantity": N}  (N=null means unlimited)
--   numeric_metered : {"quantity": N}  (N is the included quota)
--   boolean         : {"enabled": true|false}
--   enum_choice     : {"value": "..."}
-- =================================================================
INSERT INTO tier_entitlements (tier_id, item_id, included_value)
SELECT t.id, i.id, v.included_value::jsonb
FROM (VALUES
    -- Tier         | Item                         | included_value
    -- Community (Core edition floor: unlimited capacity, no paid capability)
    ('community',     'max_sensors',                 '{"quantity": null}'),
    ('community',     'max_assets',                  '{"quantity": null}'),
    ('community',     'max_users',                   '{"quantity": null}'),
    ('community',     'retention_days',              '{"quantity": 365}'),
    ('community',     'compliance_frameworks_max',   '{"quantity": 0}'),
    ('community',     'integrations_max',            '{"quantity": null}'),
    ('community',     'storage_gb',                  '{"quantity": null}'),
    ('community',     'pcap_gb_per_month',           '{"quantity": null}'),
    ('community',     'custom_policies',             '{"enabled": false}'),
    ('community',     'threshold_overrides',         '{"enabled": false}'),
    ('community',     'ot_active_probing',           '{"enabled": false}'),
    ('community',     'ot_primary_lens',             '{"enabled": false}'),
    ('community',     'cbom_signing',                '{"enabled": false}'),
    ('community',     'sso_saml',                    '{"enabled": false}'),
    ('community',     'custom_branding',             '{"enabled": false}'),
    ('community',     'cmdb_sync',                   '{"enabled": false}'),
    ('community',     'siem_export',                 '{"enabled": false}'),
    ('community',     'billing_portal',              '{"enabled": false}'),
    ('community',     'support_sla_tier',            '{"value": "community"}'),

    -- Free (trial; minimal caps; nothing enabled)
    ('free',          'max_sensors',                 '{"quantity": 1}'),
    ('free',          'max_assets',                  '{"quantity": 100}'),
    ('free',          'max_users',                   '{"quantity": 1}'),
    ('free',          'retention_days',              '{"quantity": 30}'),
    ('free',          'compliance_frameworks_max',   '{"quantity": 0}'),
    ('free',          'integrations_max',            '{"quantity": 0}'),
    ('free',          'storage_gb',                  '{"quantity": 1}'),
    ('free',          'pcap_gb_per_month',           '{"quantity": 1}'),
    ('free',          'custom_policies',             '{"enabled": false}'),
    ('free',          'threshold_overrides',         '{"enabled": false}'),
    ('free',          'ot_active_probing',           '{"enabled": false}'),
    ('free',          'ot_primary_lens',             '{"enabled": false}'),
    ('free',          'cbom_signing',                '{"enabled": false}'),
    ('free',          'sso_saml',                    '{"enabled": false}'),
    ('free',          'custom_branding',             '{"enabled": false}'),
    ('free',          'cmdb_sync',                   '{"enabled": false}'),
    ('free',          'siem_export',                 '{"enabled": false}'),
    ('free',          'billing_portal',              '{"enabled": false}'),
    ('free',          'support_sla_tier',            '{"value": "community"}'),

    -- Starter (small shop; no compliance framework beyond auto-licensed Best Practices)
    ('starter',       'max_sensors',                 '{"quantity": 5}'),
    ('starter',       'max_assets',                  '{"quantity": 1000}'),
    ('starter',       'max_users',                   '{"quantity": 5}'),
    ('starter',       'retention_days',              '{"quantity": 90}'),
    ('starter',       'compliance_frameworks_max',   '{"quantity": 0}'),
    ('starter',       'integrations_max',            '{"quantity": 1}'),
    ('starter',       'storage_gb',                  '{"quantity": 25}'),
    ('starter',       'pcap_gb_per_month',           '{"quantity": 10}'),
    ('starter',       'custom_policies',             '{"enabled": false}'),
    ('starter',       'threshold_overrides',         '{"enabled": false}'),
    ('starter',       'ot_active_probing',           '{"enabled": false}'),
    ('starter',       'ot_primary_lens',             '{"enabled": false}'),
    ('starter',       'cbom_signing',                '{"enabled": false}'),
    ('starter',       'sso_saml',                    '{"enabled": false}'),
    ('starter',       'custom_branding',             '{"enabled": false}'),
    ('starter',       'cmdb_sync',                   '{"enabled": false}'),
    ('starter',       'siem_export',                 '{"enabled": false}'),
    ('starter',       'billing_portal',              '{"enabled": false}'),
    ('starter',       'support_sla_tier',            '{"value": "business"}'),

    -- Pro (Starter + 1 platform compliance framework + OT + CBOM signing + threshold overrides)
    ('pro',           'max_sensors',                 '{"quantity": 25}'),
    ('pro',           'max_assets',                  '{"quantity": 10000}'),
    ('pro',           'max_users',                   '{"quantity": 25}'),
    ('pro',           'retention_days',              '{"quantity": 365}'),
    ('pro',           'compliance_frameworks_max',   '{"quantity": 1}'),
    ('pro',           'integrations_max',            '{"quantity": 3}'),
    ('pro',           'storage_gb',                  '{"quantity": 250}'),
    ('pro',           'pcap_gb_per_month',           '{"quantity": 100}'),
    ('pro',           'custom_policies',             '{"enabled": false}'),
    ('pro',           'threshold_overrides',         '{"enabled": true}'),
    ('pro',           'ot_active_probing',           '{"enabled": true}'),
    ('pro',           'ot_primary_lens',             '{"enabled": true}'),
    ('pro',           'cbom_signing',                '{"enabled": true}'),
    ('pro',           'sso_saml',                    '{"enabled": false}'),
    ('pro',           'custom_branding',             '{"enabled": false}'),
    ('pro',           'cmdb_sync',                   '{"enabled": false}'),
    ('pro',           'siem_export',                 '{"enabled": false}'),
    ('pro',           'billing_portal',              '{"enabled": false}'),
    ('pro',           'support_sla_tier',            '{"value": "nbd"}'),

    -- Enterprise
    --
    -- Every EDITION-GATED item below is seeded false on purpose. This file ships
    -- in the open-source repository, so a Core deployment has these tier rows
    -- too — and if they were true, a platform admin could unlock every paid
    -- capability just by assigning this tier from the tier editor. That is not
    -- circumvention requiring intent; it is using the product as designed, which
    -- makes it a footgun rather than a bypass.
    --
    -- Edition-gated capability is granted by an entitlement TOKEN, which seeds
    -- tenant_entitlements overrides (admin-service/ee/edition/seeder.go). An
    -- override outranks the tier in the resolver, so a licensed deployment gets
    -- these regardless of what the tier says. Non-gated knobs (caps, retention,
    -- integrations_max) stay true here — those are ordinary packaging.
    --
    -- An operator can still hand-add a gated item to a tier. That is a
    -- deliberate act and an unambiguous licence violation, which is the line
    -- worth drawing: no runtime check can stop someone with database access, so
    -- the goal is to make the honest path obvious rather than to build a wall. (everything; quantities null = unlimited; sales applies tenant_entitlements overrides per deal)
    ('enterprise',    'max_sensors',                 '{"quantity": null}'),
    ('enterprise',    'max_assets',                  '{"quantity": null}'),
    ('enterprise',    'max_users',                   '{"quantity": null}'),
    ('enterprise',    'retention_days',              '{"quantity": 1095}'),
    ('enterprise',    'compliance_frameworks_max',   '{"quantity": null}'),
    ('enterprise',    'integrations_max',            '{"quantity": null}'),
    ('enterprise',    'storage_gb',                  '{"quantity": 1000}'),
    ('enterprise',    'pcap_gb_per_month',           '{"quantity": 500}'),
    ('enterprise',    'custom_policies',             '{"enabled": false}'),
    ('enterprise',    'threshold_overrides',         '{"enabled": false}'),
    ('enterprise',    'ot_active_probing',           '{"enabled": false}'),
    ('enterprise',    'ot_primary_lens',             '{"enabled": false}'),
    ('enterprise',    'cbom_signing',                '{"enabled": false}'),
    ('enterprise',    'sso_saml',                    '{"enabled": false}'),
    ('enterprise',    'custom_branding',             '{"enabled": false}'),
    ('enterprise',    'cmdb_sync',                   '{"enabled": false}'),
    ('enterprise',    'siem_export',                 '{"enabled": false}'),
    ('enterprise',    'billing_portal',              '{"enabled": false}'),
    ('enterprise',    'support_sla_tier',            '{"value": "premium"}')
) AS v(tier_name, item_key, included_value)
JOIN subscription_tiers t ON t.name = v.tier_name
JOIN billable_items i ON i.key = v.item_key
ON CONFLICT (tier_id, item_id) DO NOTHING;

-- =================================================================
-- Backfill: tier-less tenants land on the default floor
-- =================================================================
-- Every tenant created before auth-service started assigning a default tier at
-- signup sits at subscription_tier_id = NULL. A tenant with no tier resolves
-- every numeric cap to billable_items.default_value, and those are deliberately
-- conservative — max_sensors 0, max_assets 0 — so such a tenant cannot register
-- a sensor ("Sensor limit exceeded: 0/0", HTTP 402) or track an asset. Sensors
-- are the platform's primary collection path, so those tenants have a product
-- that cannot collect anything.
--
-- Only fills NULLs: never moves a tenant off a tier an operator or a purchase
-- put them on. A commercial deployment that wants new/legacy self-signups on
-- the trial tier instead sets DEFAULT_SIGNUP_TIER=free on auth-service and
-- reassigns these tenants from the admin UI — this statement is a floor, not a
-- plan decision. Idempotent: re-runs match nothing once every tenant has a tier.
UPDATE tenants
SET subscription_tier_id = (SELECT id FROM subscription_tiers WHERE name = 'community'),
    updated_at = NOW()
WHERE subscription_tier_id IS NULL
  AND EXISTS (SELECT 1 FROM subscription_tiers WHERE name = 'community');

-- =================================================================
-- Measurement Types (required for compliance framework controls)
-- =================================================================
INSERT INTO measurement_types (code, name, description, data_type, units, valid_range, allowed_rule_types, enum_values, valid_operators, category) VALUES
('cert_expiration_days',   'Certificate Expiration Days',        'Number of days until certificate expiration',                                        'integer', 'days',    '{"min":0,"max":36500}'::jsonb,  '["threshold","range"]'::jsonb,    NULL,                                                                                                                   '["<=",">=","<",">","==","!="]'::jsonb, 'certificate'),
('tls_version',            'TLS Protocol Version',               'TLS protocol version (TLS1.0, TLS1.1, TLS1.2, TLS1.3)',                              'enum',    'version', NULL,                            '["pattern","presence"]'::jsonb,   '["TLS1.0","TLS1.1","TLS1.2","TLS1.3"]'::jsonb,                                                                         NULL,                                   'tls'),
-- Key size is split by algorithm family, because one number means two different
-- things. 2048 bits is the SP 800-131A floor for RSA/DSA/DH; an elliptic-curve
-- key of 256 bits is STRONGER than RSA-2048 (SP 800-57 comparable strength:
-- 128-bit vs 112-bit). A single `key_size >= 2048` rule flagged every P-256 and
-- Ed25519 certificate as weak. The extractor routes each certificate to exactly
-- one of these by public_key_algorithm, and emits neither when the algorithm
-- cannot be classified (not assessed beats wrongly assessed).
('key_size',               'Key Size (RSA/DSA/DH)',              'Cryptographic key size in bits for the finite-field family (RSA, DSA, Diffie-Hellman). Minimum 2048 bits (NIST SP 800-131A).', 'integer', 'bits',    '{"min":0,"max":16384}'::jsonb,  '["threshold","range"]'::jsonb,    NULL,                                                                                                                   '["<=",">=","<",">","==","!="]'::jsonb, 'certificate'),
('key_size_ec',            'Key Size (Elliptic Curve)',          'Cryptographic key size in bits for the elliptic-curve family (ECDSA, EdDSA, X25519). Minimum 256 bits — equivalent to 128-bit classical security, above the RSA-2048 floor.', 'integer', 'bits',    '{"min":0,"max":1024}'::jsonb,   '["threshold","range"]'::jsonb,    NULL,                                                                                                                   '["<=",">=","<",">","==","!="]'::jsonb, 'certificate'),
('cert_algorithm',         'Certificate Algorithm',              'Public key algorithm used in certificate (RSA, ECDSA, EdDSA, etc.)',                  'enum',    NULL,      NULL,                            '["pattern","presence"]'::jsonb,   '["RSA","ECDSA","EdDSA","DSA"]'::jsonb,                                                                                 NULL,                                   'certificate'),
('key_exchange_algorithm', 'Key Exchange Algorithm',             'Key exchange algorithm used in TLS (ECDHE, DHE, RSA, ECDH, DH, NULL)',               'enum',    NULL,      NULL,                            '["pattern","presence"]'::jsonb,   '["ECDHE","DHE","RSA","ECDH","DH","NULL"]'::jsonb,                                                                       NULL,                                   'cipher'),
('symmetric_encryption',   'Symmetric Encryption Algorithm',     'Symmetric encryption algorithm (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, etc.)', 'enum',    NULL,      NULL,                            '["pattern","presence"]'::jsonb,   '["AES-128-GCM","AES-256-GCM","AES-128-CBC","AES-256-CBC","ChaCha20-Poly1305","3DES","DES","RC4"]'::jsonb,               NULL,                                   'cipher'),
('hash_algorithm',         'Hash Algorithm',                     'Hash algorithm used in cipher suite (SHA256, SHA384, SHA512, SHA1, MD5)',             'enum',    NULL,      NULL,                            '["pattern","presence"]'::jsonb,   '["SHA256","SHA384","SHA512","SHA1","MD5"]'::jsonb,                                                                      NULL,                                   'cipher'),
('cipher_suite_name',      'Cipher Suite Name',                  'Full cipher suite name (e.g., TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)',               'string',  NULL,      NULL,                            '["pattern","presence"]'::jsonb,   NULL,                                                                                                                   NULL,                                   'cipher'),
('pfs_support',            'Perfect Forward Secrecy Support',    'Whether the connection supports Perfect Forward Secrecy (PFS)',                       'boolean', NULL,      NULL,                            '["presence"]'::jsonb,             NULL,                                                                                                                   NULL,                                   'tls'),
('tls_compression_enabled','TLS Compression Enabled',            'Whether TLS compression is enabled (should be disabled)',                            'boolean', NULL,      NULL,                            '["presence"]'::jsonb,             NULL,                                                                                                                   NULL,                                   'tls'),
('certificate_chain_valid','Certificate Chain Valid',             'Whether the certificate chain is valid and trusted',                                 'boolean', NULL,      NULL,                            '["presence"]'::jsonb,             NULL,                                                                                                                   NULL,                                   'certificate'),
('ot_protocol_encryption', 'OT Protocol Encryption',              'Encryption status of an industrial / OT protocol session (Modbus, DNP3, MMS, ICCP, BACnet, EtherNet/IP). Returns the literal string "absent" when the protocol carries no cryptographic protection (a high-severity finding for OT cryptographic audits) and "present" when crypto is observed.', 'enum',    NULL,      NULL,                            '["pattern"]'::jsonb,              '["absent","present"]'::jsonb,                                                                                          NULL,                                   'ot'),
('cert_pqc_status',        'Certificate PQC Status',             'Post-quantum readiness of a certificate public-key algorithm: quantum_vulnerable (classical RSA/ECDSA/EdDSA/DSA/DH) or quantum_safe (NIST PQC: ML-KEM/ML-DSA/SLH-DSA).', 'enum', NULL, NULL, '["pattern","presence"]'::jsonb, '["quantum_vulnerable","quantum_safe"]'::jsonb, NULL, 'certificate'),
('cert_validity_days',     'Certificate Validity Period (days)', 'Total validity period of a certificate in days (not_after - not_before); distinct from days-until-expiry. Flags over-long certificate lifetimes (CA/Browser Forum max validity is trending toward 47 days).', 'integer', 'days', '{"min":0,"max":36500}'::jsonb, '["threshold","range"]'::jsonb, NULL, '["<=",">=","<",">","==","!="]'::jsonb, 'certificate'),
-- PQC Readiness framework controls: certificate signature + crypto-config key-exchange/signature/symmetric.
-- Quantum (Shor) breaks asymmetric crypto (key exchange + signatures); symmetric (Grover) only loses half its margin.
('cert_sig_pqc_status',    'Certificate Signature PQC Status',   'Post-quantum readiness of the algorithm a certificate was SIGNED with (the CA''s signature): quantum_vulnerable (classical RSA/ECDSA/EdDSA/DSA) or quantum_safe (NIST PQC: ML-DSA/SLH-DSA/FN-DSA).', 'enum', NULL, NULL, '["pattern","presence"]'::jsonb, '["quantum_vulnerable","quantum_safe"]'::jsonb, NULL, 'certificate'),
('config_kex_pqc_status',  'Config Key-Exchange PQC Status',     'Post-quantum readiness of a crypto-config key-exchange algorithm: quantum_vulnerable (classical RSA/ECDH/DH) or quantum_safe (NIST PQC ML-KEM or a hybrid such as X25519MLKEM768). The most urgent PQC control — harvest-now-decrypt-later exposure.', 'enum', NULL, NULL, '["pattern","presence"]'::jsonb, '["quantum_vulnerable","quantum_safe"]'::jsonb, NULL, 'cipher'),
('config_sig_pqc_status',  'Config Signature PQC Status',        'Post-quantum readiness of a crypto-config signature/authentication algorithm: quantum_vulnerable (classical RSA/ECDSA/EdDSA) or quantum_safe (NIST PQC: ML-DSA/SLH-DSA/FN-DSA).', 'enum', NULL, NULL, '["pattern","presence"]'::jsonb, '["quantum_vulnerable","quantum_safe"]'::jsonb, NULL, 'cipher'),
('config_sym_strength',    'Config Symmetric Quantum Margin',    'Quantum strength margin of a crypto-config symmetric cipher: quantum_safe (AES-192/256 or ChaCha20, retain >=128-bit security under Grover) or quantum_marginal (AES-128 and weaker, below the post-quantum / CNSA 2.0 margin). Advisory.', 'enum', NULL, NULL, '["pattern","presence"]'::jsonb, '["quantum_safe","quantum_marginal"]'::jsonb, NULL, 'cipher')
ON CONFLICT (code) DO NOTHING;

-- =================================================================
-- Tenant Permissions (assigned to tenant roles when tenants are created)
-- =================================================================
-- BEGIN GENERATED: tenant permission catalogue — from standards/permissions.yaml (make generate)
INSERT INTO tenant_permissions (name, resource, action, scope, description) VALUES
('assets.create',     'assets',     'create', 'tenant', 'Create network assets'),
('assets.read',       'assets',     'read',   'tenant', 'View network assets'),
('assets.update',     'assets',     'update', 'tenant', 'Update network assets'),
('assets.delete',     'assets',     'delete', 'tenant', 'Delete network assets'),
('assets.manage',     'assets',     'manage', 'tenant', 'Full asset management'),
('sensors.create',    'sensors',    'create', 'tenant', 'Create sensors'),
('sensors.read',      'sensors',    'read',   'tenant', 'View sensors'),
('sensors.update',    'sensors',    'update', 'tenant', 'Update sensors'),
('sensors.delete',    'sensors',    'delete', 'tenant', 'Delete sensors'),
('sensors.manage',    'sensors',    'manage', 'tenant', 'Full sensor management'),
-- reports.read and reports.manage are retained because the web-ui uses
-- them as frontend-only gates for the CBOM page (reports.read) and the
-- scheduled-reports view (reports.manage). reports.{create,update,delete}
-- were retired with the legacy templated-report surface in Phase 5
-- (see CLAUDE.md) — no backend handler exists and no UI references them.
-- The retired-permission cleanup below removes any rows that may have
-- been seeded by an older release.
('reports.read',      'reports',    'read',   'tenant', 'View CBOM artifacts and scheduled report listings (frontend route gate)'),
('reports.manage',    'reports',    'manage', 'tenant', 'Manage scheduled report configuration (frontend route gate)'),
('users.create',      'users',      'create', 'tenant', 'Create tenant users'),
('users.read',        'users',      'read',   'tenant', 'View tenant users'),
('users.update',      'users',      'update', 'tenant', 'Update tenant users'),
('users.delete',      'users',      'delete', 'tenant', 'Delete tenant users'),
('users.manage',      'users',      'manage', 'tenant', 'Full user management'),
('settings.read',     'settings',   'read',   'tenant', 'View tenant settings'),
('settings.update',   'settings',   'update', 'tenant', 'Update tenant settings'),
('settings.manage',   'settings',   'manage', 'tenant', 'Full settings management'),
('billing.read',      'billing',    'read',   'tenant', 'View billing information'),
('billing.update',    'billing',    'update', 'tenant', 'Update billing settings'),
('compliance.read',   'compliance', 'read',   'tenant', 'View compliance data'),
('compliance.update', 'compliance', 'update', 'tenant', 'Update compliance settings'),
('compliance.manage', 'compliance', 'manage', 'tenant', 'Full compliance management'),
-- Stateful alert lifecycle. Reads are open to members;
-- acknowledge/snooze/resolve/ticket-create sit behind alerts.manage.
('alerts.read',       'alerts',     'read',   'tenant', 'View alerts and their evidence timeline'),
('alerts.manage',     'alerts',     'manage', 'tenant', 'Acknowledge, snooze, resolve alerts and create tickets from them'),
('discovery.read',    'discovery',  'read',   'tenant', 'View discovery jobs, devices, and interrogation results'),
('discovery.create',  'discovery',  'create', 'tenant', 'Register devices for interrogation'),
('discovery.update',  'discovery',  'update', 'tenant', 'Update device configuration and interrogation jobs'),
('discovery.manage',  'discovery',  'manage', 'tenant', 'Manage devices for interrogation, run discovery and interrogation jobs'),
('pcap.read',         'pcap',       'read',   'tenant', 'View PCAP upload jobs and processing status'),
('pcap.upload',       'pcap',       'upload', 'tenant', 'Upload PCAP files for offline processing'),
('pcap.delete',       'pcap',       'delete', 'tenant', 'Delete PCAP upload jobs'),
-- Audit trail. audit-service previously ran a private permission
-- system: a hardcoded switch on the role NAME inventing audit.read /
-- audit.manage / audit.security / audit.export, none of which existed
-- here, in shared/rbac/permissions.go, or in tenant_role_permissions. No
-- tenant could grant audit access to anyone. Two permissions replace all
-- four — audit.security and audit.export were demanded by no route at all.
('audit.read',        'audit',      'read',   'tenant', 'View the audit trail, retention policies and SIEM integration list'),
('audit.manage',      'audit',      'manage', 'tenant', 'Manage retention policies, alert rules, scheduled reports and SIEM integrations')
ON CONFLICT (name) DO NOTHING;

-- Both rows were added earlier but have no backend endpoint and no UI
-- gate. Dropping them collapses the audit's "GRANTED but no UI gates it"
-- noise and prevents anyone granting a permission that can never be
-- meaningful.
-- CASCADE on tenant_role_permissions removes the matching grants automatically.
DELETE FROM tenant_permissions WHERE name IN ('discovery.delete', 'pcap.manage');

-- Phase 5 retired the legacy templated-report surface (see CLAUDE.md).
-- These three permissions had no backend handler before and no UI
-- reference now. reports.read and reports.manage are kept — the web-ui
-- still uses them as frontend route gates for the CBOM and
-- scheduled-reports pages.
-- CASCADE on tenant_role_permissions removes the matching grants automatically.
DELETE FROM tenant_permissions WHERE name IN ('reports.create', 'reports.update', 'reports.delete');
-- END GENERATED: tenant permission catalogue

-- =================================================================
-- Platform Admin Users
-- =================================================================
-- These users have platform-level access (not tenant-level)

-- Re-home the seeded default-admin rows onto the current product domain.
--
-- The domain is `vistaplatform.invalid` deliberately: RFC 6761 reserves
-- `.invalid` as permanently undelegatable, so these seeded addresses can never
-- resolve to a real mailbox no matter who registers what. An earlier revision
-- seeded them under a live company domain, which meant a stock install shipped
-- two accounts whose addresses were deliverable to someone. Do NOT "fix" this
-- to a real-looking domain -- the address is an identifier here, not a mailbox,
-- and nothing about the seeded account should ever receive mail. (Consequence,
-- documented in INSTALL.md: password-reset mail to a seeded admin bounces. The
-- rotation flow below is the intended path, and an operator who wants a
-- reachable admin creates their own user.)
--
-- Keyed on the stable seeded id so a cluster provisioned under an earlier
-- domain is RENAMED in place on its next helm upgrade (preserving whatever
-- password the admin already set) rather than gaining a second, duplicate
-- admin row -- the INSERTs below key on id, so a legacy row under a different
-- address would otherwise collide on the primary key.
--
-- Matched on "email is not already the target" rather than on the specific
-- legacy address, so no retired brand string has to live in this file. These
-- two ids are the chart-seeded platform admins and are ours to name; an
-- operator who wants a different address should create their own platform
-- admin user rather than renaming a seeded row, which this would revert.
-- No-op on fresh deploys and on every re-run after the first.
-- The NOT EXISTS arm matters: platform_users.email is UNIQUE, and this file is
-- applied WITHOUT ON_ERROR_STOP, so a collision would abort this statement
-- silently and leave later email-keyed statements acting on the wrong row.
UPDATE platform_users
SET email = 'su_admin@vistaplatform.invalid', updated_at = NOW()
WHERE id = '00000000-0000-0000-0000-000000000001'
  AND email <> 'su_admin@vistaplatform.invalid'
  AND NOT EXISTS (
    SELECT 1 FROM platform_users existing
    WHERE existing.email = 'su_admin@vistaplatform.invalid'
  );

UPDATE platform_users
SET email = 'admin@vistaplatform.invalid', updated_at = NOW()
WHERE id = '550e8400-e29b-41d4-a716-446655440004'
  AND email <> 'admin@vistaplatform.invalid'
  AND NOT EXISTS (
    SELECT 1 FROM platform_users existing
    WHERE existing.email = 'admin@vistaplatform.invalid'
  );

-- Create a default super admin platform user
-- SECURITY: force_password_change is seeded TRUE — the published default
-- password below only buys a limited change-password-only session; admin-service
-- refuses everything else until a new password is set.
-- Default dev password: 'PlatformAdm!n2026' (hashed with Argon2id)
INSERT INTO platform_users (id, email, password_hash, first_name, last_name, role_id, is_active, email_verified, force_password_change)
SELECT
    '00000000-0000-0000-0000-000000000001',
    'su_admin@vistaplatform.invalid',
    '$argon2id$v=19$m=65536,t=3,p=2$4RwIVrBNkLem0R8ROlv4Ow$GPQNlbYkh6VHvxmSREntWjyw/xIRCRSaNEVzli1M+cc',
    'Platform',
    'Administrator',
    pr.id,
    true,
    true,
    true
FROM platform_roles pr
WHERE pr.name = 'super_admin'
ON CONFLICT (email) DO UPDATE SET
    role_id = EXCLUDED.role_id,
    is_active = true,
    email_verified = true,
    deleted_at = NULL,
    updated_at = NOW();

-- Create Vista Platform platform admin user
-- SECURITY: seeded with force_password_change = true — see note above.
-- Default dev password: 'PlatformAdm!n2026' (hashed with Argon2id)
INSERT INTO platform_users (id, email, password_hash, first_name, last_name, role_id, is_active, email_verified, force_password_change)
SELECT
    '550e8400-e29b-41d4-a716-446655440004',
    'admin@vistaplatform.invalid',
    '$argon2id$v=19$m=65536,t=3,p=2$SXJIXrL7Gu9gg6XF1+TyJA$a6piiFbcgYGBpmWOlvW7Cgs0VKRaGIAQmS2aSqqwzKM',
    'Platform',
    'Admin',
    pr.id,
    true,
    true,
    true
FROM platform_roles pr
WHERE pr.name = 'platform_admin'
ON CONFLICT (email) DO NOTHING;

--: existing deployments that STILL carry the published default password
-- (the exact seeded Argon2id hashes above) must also change it on next login.
-- Admins who already rotated their password have a different hash and are left
-- untouched. Idempotent: once the password changes, the hash no longer matches
-- and re-runs are a no-op; the change-password flow clears the flag.
UPDATE platform_users
SET force_password_change = true, updated_at = NOW()
WHERE password_hash IN (
    '$argon2id$v=19$m=65536,t=3,p=2$4RwIVrBNkLem0R8ROlv4Ow$GPQNlbYkh6VHvxmSREntWjyw/xIRCRSaNEVzli1M+cc',
    '$argon2id$v=19$m=65536,t=3,p=2$SXJIXrL7Gu9gg6XF1+TyJA$a6piiFbcgYGBpmWOlvW7Cgs0VKRaGIAQmS2aSqqwzKM',
    -- Retired third hash: seeded ONLY by the super_admin fallback branch near
    -- the end of this file, which used to omit force_password_change (column
    -- default false). Any cluster that took that branch is still sitting on a
    -- published password with a full session, so it must be listed here even
    -- though nothing seeds it any more.
    '$argon2id$v=19$m=65536,t=3,p=2$8Ll1hG8Y7AO+m8hQxRuozA$nO6gHyQ3JAccN5XWX5gjdnxTx+XutgIHYGCuXpJ2LKQ'
)
AND force_password_change = false;

-- =================================================================
-- Service Accounts
-- =================================================================
-- Service accounts are used by platform services for auto-registration
-- and secure service-to-service authentication.
--
-- IMPORTANT: Service account tokens must be generated securely and stored
-- in environment variables. The tokens in this seed file are placeholders.
-- For production, generate new tokens using:
--   go run scripts/generate-service-account-token.go <service-name>
--
-- Tokens are hashed using bcrypt before storage. The plaintext token should
-- be stored securely (e.g., in environment variables, secrets manager).
--
-- Default tokens (for development only - CHANGE IN PRODUCTION):
--   cluster-sensor-service: See environment variable CLUSTER_SENSOR_SERVICE_TOKEN
--   device-interrogation-service: See environment variable DEVICE_INTERROGATION_SERVICE_TOKEN
--
-- To generate a token hash, use bcrypt with cost 10:
--   hash, _ := bcrypt.GenerateFromPassword([]byte(token), 10)

-- Service account for cluster-sensor-service
-- Token hash placeholder (will be replaced during deployment)
-- For development, use a test token: "dev-cluster-sensor-service-token-$(openssl rand -hex 16)"
INSERT INTO service_accounts (id, service_name, token_hash, description, is_active, created_at, updated_at)
VALUES (
    'a1b2c3d4-e5f6-4789-a012-345678901234',
    'cluster-sensor-service',
    '$2a$10$placeholder.hash.for.cluster.sensor.service.token.replace.in.production',
    'Service account for cluster-sensor-service platform discovery sensor auto-registration',
    true,
    NOW(),
    NOW()
)
ON CONFLICT (service_name) DO UPDATE SET
    description = EXCLUDED.description,
    is_active = true,
    updated_at = NOW();

-- Service account for device-interrogation-service
-- Token hash placeholder (will be replaced during deployment)
-- For development, use a test token: "dev-device-interrogation-service-token-$(openssl rand -hex 16)"
INSERT INTO service_accounts (id, service_name, token_hash, description, is_active, created_at, updated_at)
VALUES (
    'b2c3d4e5-f6a7-4890-b123-456789012345',
    'device-interrogation-service',
    '$2a$10$placeholder.hash.for.device.interrogation.service.token.replace.in.production',
    'Service account for device-interrogation-service platform agent auto-registration',
    true,
    NOW(),
    NOW()
)
ON CONFLICT (service_name) DO UPDATE SET
    description = EXCLUDED.description,
    is_active = true,
    updated_at = NOW();

-- =================================================================
-- Platform System Sensors for All Existing Tenants
-- =================================================================
-- Creates two platform-managed system sensors for each tenant:
-- 1. Platform Discovery Sensor - performs network discovery scans
-- 2. Platform Device Interrogation Agent - interrogates devices for crypto inventory
--
-- New tenants get these automatically via trigger (create_system_sensors_for_tenant)
-- This section ensures existing tenants also have them.

-- Insert Platform Discovery Sensor for all existing tenants
INSERT INTO sensors (
    id, tenant_id, name, description, platform, version, profile,
    sensor_type, status, network_interfaces, tags, last_heartbeat, created_at, updated_at
)
SELECT
    gen_random_uuid(),
    t.id,
    'Platform Discovery Sensor',
    'Platform-managed sensor for network discovery operations. This shared resource performs cryptographic asset discovery scans on your behalf.',
    'platform',
    'system',
    'discovery',
    'network',
    'active',
    ARRAY[]::TEXT[],
    ARRAY['system', 'platform', 'discovery']::TEXT[],
    NOW(),
    NOW(),
    NOW()
FROM tenants t
WHERE t.deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM sensors s
      WHERE s.tenant_id = t.id
        AND s.platform = 'platform'
        AND s.profile = 'discovery'
        AND 'system' = ANY(s.tags)
  );

-- Insert Platform Device Interrogation Agent for all existing tenants
INSERT INTO sensors (
    id, tenant_id, name, description, platform, version, profile,
    sensor_type, status, network_interfaces, tags, last_heartbeat, created_at, updated_at
)
SELECT
    gen_random_uuid(),
    t.id,
    'Platform Device Interrogation Agent',
    'Platform-managed agent for device interrogation operations. This shared resource queries devices and cloud providers for cryptographic inventory on your behalf.',
    'platform',
    'system',
    'device_interrogation',
    'api',
    'active',
    ARRAY[]::TEXT[],
    ARRAY['system', 'platform', 'device_interrogation']::TEXT[],
    NOW(),
    NOW(),
    NOW()
FROM tenants t
WHERE t.deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM sensors s
      WHERE s.tenant_id = t.id
        AND s.platform = 'platform'
        AND s.profile = 'device_interrogation'
        AND 'system' = ANY(s.tags)
  );

-- =================================================================
-- Asset Lifecycle Policies - Default Policies for All Tenants
-- =================================================================
-- When new tenants are created, they will get these default policies

INSERT INTO asset_lifecycle_policies (
    tenant_id,
    stale_warning_days,
    stale_archived_days,
    auto_archive_enabled,
    notifications_enabled,
    revalidation_schedule
)
SELECT
    t.id,
    30,  -- Default: 30 days for warning
    60,  -- Default: 60 days for archived
    true,  -- Auto-archive enabled by default
    true,  -- Notifications enabled by default
    '{"enabled": false, "interval_hours": 168}'::jsonb  -- Weekly revalidation disabled by default
FROM tenants t
WHERE t.deleted_at IS NULL
ON CONFLICT (tenant_id) DO NOTHING;

-- =================================================================
-- Algorithm Taxonomy Seed Data (Tier 1 - Core Reference Data)
-- =================================================================
-- This algorithm taxonomy is required for all environments (dev, smoke, prod)
-- It provides classification, risk scoring, and recommendations for cryptographic algorithms

-- Hash Algorithms
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard) VALUES
('MD5', 'hash', 'MD5', 'Message Digest 5 - cryptographically broken', 'weak', 'obsolete', 90, ARRAY['SHA256', 'SHA512'], 'MD5 is cryptographically broken and should not be used. Migrate to SHA-256 or SHA-512.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true),
('SHA1', 'hash', 'SHA-1', 'Secure Hash Algorithm 1 - deprecated', 'weak', 'deprecated', 75, ARRAY['SHA256', 'SHA512'], 'SHA-1 is deprecated due to collision attacks. Migrate to SHA-256 or SHA-512.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true),
('SHA256', 'hash', 'SHA-256', 'Secure Hash Algorithm 256-bit', 'strong', 'current', 20, ARRAY[]::text[], NULL, '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true),
('SHA512', 'hash', 'SHA-512', 'Secure Hash Algorithm 512-bit', 'strong', 'current', 15, ARRAY[]::text[], NULL, '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true),
('SHA384', 'hash', 'SHA-384', 'Secure Hash Algorithm 384-bit', 'strong', 'current', 15, ARRAY[]::text[], NULL, '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true)
ON CONFLICT (code) DO NOTHING;

-- Symmetric Encryption Algorithms
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard) VALUES
('DES', 'symmetric', 'DES', 'Data Encryption Standard - cryptographically broken', 'weak', 'obsolete', 95, ARRAY['AES128', 'AES256'], 'DES is cryptographically broken. Migrate to AES-128 or AES-256.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true),
('3DES', 'symmetric', '3DES', 'Triple DES - deprecated', 'weak', 'deprecated', 70, ARRAY['AES128', 'AES256'], '3DES is deprecated. Migrate to AES-128 or AES-256.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true),
('RC4', 'symmetric', 'RC4', 'Rivest Cipher 4 - cryptographically broken', 'weak', 'obsolete', 90, ARRAY['AES128', 'AES256', 'ChaCha20'], 'RC4 is cryptographically broken. Migrate to AES-128, AES-256, or ChaCha20.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true),
('AES128', 'symmetric', 'AES-128', 'Advanced Encryption Standard 128-bit', 'strong', 'current', 25, ARRAY[]::text[], NULL, '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true),
('AES256', 'symmetric', 'AES-256', 'Advanced Encryption Standard 256-bit', 'strong', 'current', 15, ARRAY[]::text[], NULL, '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true),
('ChaCha20', 'symmetric', 'ChaCha20', 'ChaCha20 stream cipher', 'strong', 'current', 20, ARRAY[]::text[], NULL, '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true)
ON CONFLICT (code) DO NOTHING;

-- Key Exchange Algorithms
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard) VALUES
('RSA-1024', 'key_exchange', 'RSA 1024-bit', 'RSA key exchange with 1024-bit keys - weak', 'weak', 'deprecated', 80, ARRAY['RSA-2048', 'ECDHE'], 'RSA 1024-bit is too weak. Migrate to RSA-2048 or ECDHE.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true),
('RSA-2048', 'key_exchange', 'RSA 2048-bit', 'RSA key exchange with 2048-bit keys', 'acceptable', 'current', 40, ARRAY['ECDHE'], 'RSA-2048 is acceptable but ECDHE is preferred for forward secrecy.', '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true),
('RSA-4096', 'key_exchange', 'RSA 4096-bit', 'RSA key exchange with 4096-bit keys', 'strong', 'current', 25, ARRAY[]::text[], NULL, '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true),
('ECDHE', 'key_exchange', 'ECDHE', 'Elliptic Curve Diffie-Hellman Ephemeral', 'strong', 'current', 15, ARRAY[]::text[], NULL, '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true),
('DHE', 'key_exchange', 'DHE', 'Diffie-Hellman Ephemeral', 'acceptable', 'current', 35, ARRAY['ECDHE'], 'DHE is acceptable but ECDHE is preferred for better performance.', '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true),
('DH-1024', 'key_exchange', 'DH 1024-bit', 'Diffie-Hellman with 1024-bit keys - weak', 'weak', 'deprecated', 75, ARRAY['DHE', 'ECDHE'], 'DH 1024-bit is too weak. Migrate to DHE or ECDHE.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true),
('DH-480', 'key_exchange', 'DH 480-bit', 'Diffie-Hellman with 480-bit modulus - critically weak (Logjam)', 'weak', 'obsolete', 98, ARRAY['ECDHE'], 'DH 480-bit is trivially factorable. Vulnerable to Logjam (CVE-2015-4000). Migrate to ECDHE immediately.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true),
('DH-512', 'key_exchange', 'DH 512-bit', 'Diffie-Hellman with 512-bit modulus - critically weak (Logjam)', 'weak', 'obsolete', 97, ARRAY['ECDHE'], 'DH 512-bit was crackable in 1999. Vulnerable to Logjam (CVE-2015-4000). Migrate to ECDHE immediately.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true),
('DH-768', 'key_exchange', 'DH 768-bit', 'Diffie-Hellman with 768-bit modulus - weak', 'weak', 'deprecated', 90, ARRAY['ECDHE'], 'DH 768-bit is too weak for modern security. Migrate to ECDHE.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true),
('DH-2048', 'key_exchange', 'DH 2048-bit', 'Diffie-Hellman with 2048-bit modulus', 'acceptable', 'current', 35, ARRAY['ECDHE'], 'DH 2048-bit meets minimum NIST requirements but ECDHE is preferred.', '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true),
('STATIC-RSA', 'key_exchange', 'Static RSA', 'Static RSA key exchange - no forward secrecy', 'weak', 'deprecated', 70, ARRAY['ECDHE', 'DHE'], 'Static RSA provides no forward secrecy. Past traffic can be decrypted if the server key is compromised. Migrate to ECDHE.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true),
('NULL', 'symmetric', 'NULL Cipher', 'No encryption - plaintext', 'weak', 'obsolete', 99, ARRAY['AES128', 'AES256', 'ChaCha20'], 'NULL cipher provides no encryption. All data is transmitted in plaintext. This must be disabled immediately.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true),
('RSA-512', 'key_exchange', 'RSA 512-bit', 'RSA key exchange with 512-bit keys - critically weak', 'weak', 'obsolete', 98, ARRAY['RSA-2048', 'ECDHE'], 'RSA 512-bit is trivially factorable. Migrate to RSA-2048 or ECDHE immediately.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true),
('CBC', 'symmetric', 'CBC Mode', 'Cipher Block Chaining mode - vulnerable to padding oracle attacks', 'acceptable', 'current', 45, ARRAY['AES128', 'AES256'], 'CBC mode is susceptible to padding oracle attacks (POODLE, Lucky13). Prefer GCM or ChaCha20-Poly1305.', '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true)
ON CONFLICT (code) DO NOTHING;

-- Remediation guidance for weak DH key exchanges
UPDATE algorithms SET remediation_guidance = '{
    "summary": "DH 480-bit modulus is trivially factorable and critically broken.",
    "impact": "CRITICAL - An attacker can passively decrypt all traffic using precomputed discrete logs (Logjam attack, CVE-2015-4000).",
    "steps": [
        "1. Identify all servers using DH key exchange with sub-1024-bit parameters",
        "2. Reconfigure servers to use ECDHE (preferred) or DHE with 2048+ bit parameters",
        "3. Disable DHE cipher suites if ECDHE is available",
        "4. Verify configuration with tools like testssl.sh or Qualys SSL Labs",
        "5. Monitor for any clients that cannot negotiate stronger key exchange"
    ],
    "timeline": "Immediate - within 7 days",
    "cve_references": ["CVE-2015-4000"],
    "resources": [
        "https://weakdh.org/",
        "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final"
    ]
}'::jsonb WHERE code = 'DH-480';

UPDATE algorithms SET remediation_guidance = '{
    "summary": "DH 512-bit modulus was crackable in 1999 and is critically broken.",
    "impact": "CRITICAL - An attacker can passively decrypt all traffic using precomputed discrete logs (Logjam attack, CVE-2015-4000).",
    "steps": [
        "1. Identify all servers using DH key exchange with sub-1024-bit parameters",
        "2. Reconfigure servers to use ECDHE (preferred) or DHE with 2048+ bit parameters",
        "3. Disable DHE cipher suites if ECDHE is available",
        "4. Verify configuration with tools like testssl.sh or Qualys SSL Labs",
        "5. Monitor for any clients that cannot negotiate stronger key exchange"
    ],
    "timeline": "Immediate - within 7 days",
    "cve_references": ["CVE-2015-4000"],
    "resources": [
        "https://weakdh.org/",
        "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final"
    ]
}'::jsonb WHERE code = 'DH-512';

UPDATE algorithms SET remediation_guidance = '{
    "summary": "DH 768-bit modulus is below the NIST minimum of 2048 bits and considered weak.",
    "impact": "HIGH - Academic research has factored 768-bit integers; state-level actors can likely break this in real-time.",
    "steps": [
        "1. Identify all servers using DH key exchange with sub-2048-bit parameters",
        "2. Reconfigure servers to use ECDHE (preferred) or DHE with 2048+ bit parameters",
        "3. Disable DHE cipher suites if ECDHE is available",
        "4. Verify configuration with tools like testssl.sh or Qualys SSL Labs"
    ],
    "timeline": "Within 30 days",
    "resources": [
        "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final"
    ]
}'::jsonb WHERE code = 'DH-768';

UPDATE algorithms SET remediation_guidance = '{
    "summary": "Static RSA key exchange provides no forward secrecy.",
    "impact": "HIGH - If the server private key is ever compromised, all past recorded traffic can be decrypted retroactively.",
    "steps": [
        "1. Reconfigure the server to prefer ECDHE cipher suites",
        "2. Disable static RSA key exchange cipher suites",
        "3. Ensure server cipher suite ordering prefers forward-secret suites",
        "4. Verify with testssl.sh or Qualys SSL Labs that forward secrecy is enabled"
    ],
    "timeline": "Within 30 days",
    "resources": [
        "https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final"
    ]
}'::jsonb WHERE code = 'STATIC-RSA';

UPDATE algorithms SET remediation_guidance = '{
    "summary": "NULL cipher means no encryption - all data is transmitted in plaintext.",
    "impact": "CRITICAL - Any network observer can read all data in transit. This is equivalent to no TLS at all.",
    "steps": [
        "1. Immediately disable NULL cipher suites on all servers",
        "2. Verify that all cipher suites in the server configuration provide encryption",
        "3. Test with openssl s_client to confirm NULL ciphers are rejected"
    ],
    "timeline": "Immediate - within 24 hours",
    "resources": [
        "https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final"
    ]
}'::jsonb WHERE code = 'NULL';

-- Signature Algorithms
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard) VALUES
('RSA-SHA1', 'signature', 'RSA-SHA1', 'RSA signature with SHA-1 - deprecated', 'weak', 'deprecated', 70, ARRAY['RSA-SHA256', 'ECDSA-SHA256'], 'RSA-SHA1 is deprecated. Migrate to RSA-SHA256 or ECDSA-SHA256.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true),
('RSA-SHA256', 'signature', 'RSA-SHA256', 'RSA signature with SHA-256', 'strong', 'current', 20, ARRAY[]::text[], NULL, '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true),
('RSA-SHA512', 'signature', 'RSA-SHA512', 'RSA signature with SHA-512', 'strong', 'current', 15, ARRAY[]::text[], NULL, '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true),
('ECDSA-SHA256', 'signature', 'ECDSA-SHA256', 'ECDSA signature with SHA-256', 'strong', 'current', 15, ARRAY[]::text[], NULL, '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true),
('ECDSA-SHA512', 'signature', 'ECDSA-SHA512', 'ECDSA signature with SHA-512', 'strong', 'current', 15, ARRAY[]::text[], NULL, '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true)
ON CONFLICT (code) DO NOTHING;

-- Protocol Versions
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard) VALUES
('SSLv2', 'protocol_version', 'SSL 2.0', 'SSL Protocol Version 2.0 - obsolete', 'weak', 'obsolete', 95, ARRAY['TLS1.2', 'TLS1.3'], 'SSL 2.0 is obsolete and insecure. Migrate to TLS 1.2 or TLS 1.3.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true),
('SSLv3', 'protocol_version', 'SSL 3.0', 'SSL Protocol Version 3.0 - obsolete', 'weak', 'obsolete', 90, ARRAY['TLS1.2', 'TLS1.3'], 'SSL 3.0 is obsolete and insecure. Migrate to TLS 1.2 or TLS 1.3.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true),
('TLS1.0', 'protocol_version', 'TLS 1.0', 'TLS Protocol Version 1.0 - deprecated', 'weak', 'deprecated', 75, ARRAY['TLS1.2', 'TLS1.3'], 'TLS 1.0 is deprecated. Migrate to TLS 1.2 or TLS 1.3.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true),
('TLS1.1', 'protocol_version', 'TLS 1.1', 'TLS Protocol Version 1.1 - deprecated', 'weak', 'deprecated', 70, ARRAY['TLS1.2', 'TLS1.3'], 'TLS 1.1 is deprecated. Migrate to TLS 1.2 or TLS 1.3.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true),
('TLS1.2', 'protocol_version', 'TLS 1.2', 'TLS Protocol Version 1.2', 'strong', 'current', 25, ARRAY['TLS1.3'], 'TLS 1.2 is acceptable but TLS 1.3 is preferred.', '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true),
('TLS1.3', 'protocol_version', 'TLS 1.3', 'TLS Protocol Version 1.3', 'recommended', 'current', 10, ARRAY[]::text[], NULL, '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true)
ON CONFLICT (code) DO NOTHING;

-- Common Cipher Suites (representative sample - comprehensive list would be much longer)
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard) VALUES
('TLS_RSA_WITH_RC4_128_SHA', 'cipher_suite', 'TLS_RSA_WITH_RC4_128_SHA', 'TLS cipher suite using RC4 - obsolete', 'weak', 'obsolete', 90, ARRAY['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256'], 'RC4-based cipher suites are obsolete. Migrate to AES-GCM or ChaCha20-Poly1305.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true),
('TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'cipher_suite', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS cipher suite using 3DES - deprecated', 'weak', 'deprecated', 70, ARRAY['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256'], '3DES-based cipher suites are deprecated. Migrate to AES-GCM or ChaCha20-Poly1305.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true),
('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'cipher_suite', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS cipher suite with ECDHE, AES-128-GCM, SHA-256', 'strong', 'current', 20, ARRAY[]::text[], NULL, '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true),
('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'cipher_suite', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS cipher suite with ECDHE, AES-256-GCM, SHA-384', 'strong', 'current', 15, ARRAY[]::text[], NULL, '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true),
('TLS_AES_256_GCM_SHA384', 'cipher_suite', 'TLS_AES_256_GCM_SHA384', 'TLS 1.3 cipher suite with AES-256-GCM, SHA-384', 'recommended', 'current', 10, ARRAY[]::text[], NULL, '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true),
('TLS_AES_128_GCM_SHA256', 'cipher_suite', 'TLS_AES_128_GCM_SHA256', 'TLS 1.3 cipher suite with AES-128-GCM, SHA-256', 'recommended', 'current', 15, ARRAY[]::text[], NULL, '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true),
('TLS_CHACHA20_POLY1305_SHA256', 'cipher_suite', 'TLS_CHACHA20_POLY1305_SHA256', 'TLS 1.3 cipher suite with ChaCha20-Poly1305, SHA-256', 'recommended', 'current', 10, ARRAY[]::text[], NULL, '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true),
('TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'cipher_suite', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'TLS cipher suite with ECDHE, ECDSA, AES-128-GCM, SHA-256', 'strong', 'current', 20, ARRAY[]::text[], NULL, '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true),
('TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'cipher_suite', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS cipher suite with ECDHE, ECDSA, AES-256-GCM, SHA-384', 'strong', 'current', 15, ARRAY[]::text[], NULL, '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true)
ON CONFLICT (code) DO NOTHING;

-- Update existing algorithms to mark as non-PQC
UPDATE algorithms SET is_pqc = false, pqc_standardization_status = 'none' WHERE is_pqc IS NULL;

-- Add PQC migration recommendations to existing algorithms
UPDATE algorithms SET
    recommended_alternatives = ARRAY['ML-KEM-768', 'ML-KEM-1024'] || recommended_alternatives,
    migration_guidance = COALESCE(migration_guidance, '') || E'\n\nPQC Migration: This algorithm is not quantum-resistant. Consider migrating to ML-KEM (formerly CRYSTALS-Kyber) for key exchange or ML-DSA (formerly CRYSTALS-Dilithium) for signatures per NIST PQC standards.'
WHERE code IN ('RSA-2048', 'RSA-4096', 'ECDHE', 'DHE');

UPDATE algorithms SET
    recommended_alternatives = ARRAY['ML-DSA-65', 'ML-DSA-87'] || recommended_alternatives,
    migration_guidance = COALESCE(migration_guidance, '') || E'\n\nPQC Migration: This algorithm is not quantum-resistant. Consider migrating to ML-DSA (formerly CRYSTALS-Dilithium) or SLH-DSA (formerly SPHINCS+) for digital signatures per NIST PQC standards.'
WHERE code IN ('ECDSA-SHA256', 'ECDSA-SHA512', 'RSA-SHA256', 'RSA-SHA512');

-- =================================================================
-- NIST Post-Quantum Cryptography (PQC) Algorithms
-- =================================================================
-- Three finalized NIST PQC standards (August 2024): ML-KEM (FIPS 203), ML-DSA (FIPS 204),
-- SLH-DSA (FIPS 205). FN-DSA (formerly FALCON; draft FIPS 206) and HQC (selected March 2025,
-- draft expected 2026) are NIST-selected but NOT yet finalized standards — they are seeded
-- with pqc_standardization_status = 'candidate', not 'standardized'.
-- All are quantum-resistant and recommended (or expected) migration targets.

-- ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) - formerly CRYSTALS-Kyber
-- Primary standard for key exchange/encryption
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard, is_pqc, pqc_standardization_status, metadata) VALUES
('ML-KEM-512', 'key_exchange', 'ML-KEM-512', 'Module-Lattice-Based Key-Encapsulation Mechanism 512 (formerly CRYSTALS-Kyber-512)', 'recommended', 'current', 5, ARRAY[]::text[], 'NIST standardized PQC algorithm for key encapsulation. Provides security equivalent to AES-128. Standardized August 2024.', '{"NIST": "standardized", "FIPS": "approved"}'::jsonb, true, true, 'standardized', '{"pqc_family": "ML-KEM", "fips_reference": "FIPS 203", "security_level": 1, "variant_group": "ml-kem-variants", "standardization_date": "2024-08-13", "quantum_resistance": true}'::jsonb),
('ML-KEM-768', 'key_exchange', 'ML-KEM-768', 'Module-Lattice-Based Key-Encapsulation Mechanism 768 (formerly CRYSTALS-Kyber-768)', 'recommended', 'current', 5, ARRAY[]::text[], 'NIST standardized PQC algorithm for key encapsulation. Provides security equivalent to AES-192. Standardized August 2024. Recommended for most use cases.', '{"NIST": "standardized", "FIPS": "approved"}'::jsonb, true, true, 'standardized', '{"pqc_family": "ML-KEM", "fips_reference": "FIPS 203", "security_level": 3, "variant_group": "ml-kem-variants", "standardization_date": "2024-08-13", "quantum_resistance": true}'::jsonb),
('ML-KEM-1024', 'key_exchange', 'ML-KEM-1024', 'Module-Lattice-Based Key-Encapsulation Mechanism 1024 (formerly CRYSTALS-Kyber-1024)', 'recommended', 'current', 5, ARRAY[]::text[], 'NIST standardized PQC algorithm for key encapsulation. Provides security equivalent to AES-256. Standardized August 2024. Recommended for high-security use cases.', '{"NIST": "standardized", "FIPS": "approved"}'::jsonb, true, true, 'standardized', '{"pqc_family": "ML-KEM", "fips_reference": "FIPS 203", "security_level": 5, "variant_group": "ml-kem-variants", "standardization_date": "2024-08-13", "quantum_resistance": true}'::jsonb),
('HQC-128', 'key_exchange', 'HQC-128', 'Hamming Quasi-Cyclic 128 (Backup PQC Key Encapsulation, NIST-selected)', 'strong', 'current', 10, ARRAY['ML-KEM-768'], 'Selected by NIST (March 2025) as the backup PQC key-encapsulation algorithm; draft standard expected 2026 — not yet a finalized NIST standard. Provides security equivalent to AES-128. ML-KEM remains the primary NIST-standardized KEM.', '{"NIST": "selected", "FIPS": "pending"}'::jsonb, true, true, 'candidate', '{"pqc_family": "HQC", "security_level": 1, "variant_group": "hqc-variants", "selected_date": "2025-03-11", "standard_status": "draft", "quantum_resistance": true}'::jsonb),
('HQC-192', 'key_exchange', 'HQC-192', 'Hamming Quasi-Cyclic 192 (Backup PQC Key Encapsulation, NIST-selected)', 'strong', 'current', 10, ARRAY['ML-KEM-768'], 'Selected by NIST (March 2025) as the backup PQC key-encapsulation algorithm; draft standard expected 2026 — not yet a finalized NIST standard. Provides security equivalent to AES-192. ML-KEM remains the primary NIST-standardized KEM.', '{"NIST": "selected", "FIPS": "pending"}'::jsonb, true, true, 'candidate', '{"pqc_family": "HQC", "security_level": 3, "variant_group": "hqc-variants", "selected_date": "2025-03-11", "standard_status": "draft", "quantum_resistance": true}'::jsonb),
('HQC-256', 'key_exchange', 'HQC-256', 'Hamming Quasi-Cyclic 256 (Backup PQC Key Encapsulation, NIST-selected)', 'strong', 'current', 10, ARRAY['ML-KEM-1024'], 'Selected by NIST (March 2025) as the backup PQC key-encapsulation algorithm; draft standard expected 2026 — not yet a finalized NIST standard. Provides security equivalent to AES-256. ML-KEM remains the primary NIST-standardized KEM.', '{"NIST": "selected", "FIPS": "pending"}'::jsonb, true, true, 'candidate', '{"pqc_family": "HQC", "security_level": 5, "variant_group": "hqc-variants", "selected_date": "2025-03-11", "standard_status": "draft", "quantum_resistance": true}'::jsonb)
ON CONFLICT (code) DO NOTHING;

-- ML-DSA (Module-Lattice-Based Digital Signature Algorithm) - formerly CRYSTALS-Dilithium
-- Primary standard for digital signatures
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard, is_pqc, pqc_standardization_status, metadata) VALUES
('ML-DSA-44', 'signature', 'ML-DSA-44', 'Module-Lattice-Based Digital Signature Algorithm 44 (formerly CRYSTALS-Dilithium-2)', 'recommended', 'current', 5, ARRAY[]::text[], 'NIST standardized PQC algorithm for digital signatures. Provides security equivalent to 128-bit classical. Standardized August 2024.', '{"NIST": "standardized", "FIPS": "approved"}'::jsonb, true, true, 'standardized', '{"pqc_family": "ML-DSA", "fips_reference": "FIPS 204", "security_level": 2, "variant_group": "ml-dsa-variants", "standardization_date": "2024-08-13", "quantum_resistance": true}'::jsonb),
('ML-DSA-65', 'signature', 'ML-DSA-65', 'Module-Lattice-Based Digital Signature Algorithm 65 (formerly CRYSTALS-Dilithium-3)', 'recommended', 'current', 5, ARRAY[]::text[], 'NIST standardized PQC algorithm for digital signatures. Provides security equivalent to 192-bit classical. Standardized August 2024. Recommended for most use cases.', '{"NIST": "standardized", "FIPS": "approved"}'::jsonb, true, true, 'standardized', '{"pqc_family": "ML-DSA", "fips_reference": "FIPS 204", "security_level": 3, "variant_group": "ml-dsa-variants", "standardization_date": "2024-08-13", "quantum_resistance": true}'::jsonb),
('ML-DSA-87', 'signature', 'ML-DSA-87', 'Module-Lattice-Based Digital Signature Algorithm 87 (formerly CRYSTALS-Dilithium-5)', 'recommended', 'current', 5, ARRAY[]::text[], 'NIST standardized PQC algorithm for digital signatures. Provides security equivalent to 256-bit classical. Standardized August 2024. Recommended for high-security use cases.', '{"NIST": "standardized", "FIPS": "approved"}'::jsonb, true, true, 'standardized', '{"pqc_family": "ML-DSA", "fips_reference": "FIPS 204", "security_level": 5, "variant_group": "ml-dsa-variants", "standardization_date": "2024-08-13", "quantum_resistance": true}'::jsonb)
ON CONFLICT (code) DO NOTHING;

-- SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) - formerly SPHINCS+
-- Backup standard for digital signatures (stateless hash-based)
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard, is_pqc, pqc_standardization_status, metadata) VALUES
('SLH-DSA-128s', 'signature', 'SLH-DSA-128s (Small)', 'Stateless Hash-Based Digital Signature Algorithm 128s (formerly SPHINCS+-128s)', 'strong', 'current', 10, ARRAY['ML-DSA-44'], 'NIST standardized backup PQC algorithm for digital signatures. Stateless hash-based approach. Provides security equivalent to 128-bit classical. Standardized August 2024.', '{"NIST": "standardized", "FIPS": "approved"}'::jsonb, true, true, 'standardized', '{"pqc_family": "SLH-DSA", "fips_reference": "FIPS 205", "security_level": 1, "variant_group": "slh-dsa-variants", "standardization_date": "2024-08-13", "quantum_resistance": true, "signature_type": "small"}'::jsonb),
('SLH-DSA-128f', 'signature', 'SLH-DSA-128f (Fast)', 'Stateless Hash-Based Digital Signature Algorithm 128f (formerly SPHINCS+-128f)', 'strong', 'current', 10, ARRAY['ML-DSA-44'], 'NIST standardized backup PQC algorithm for digital signatures. Stateless hash-based approach. Provides security equivalent to 128-bit classical. Standardized August 2024.', '{"NIST": "standardized", "FIPS": "approved"}'::jsonb, true, true, 'standardized', '{"pqc_family": "SLH-DSA", "fips_reference": "FIPS 205", "security_level": 1, "variant_group": "slh-dsa-variants", "standardization_date": "2024-08-13", "quantum_resistance": true, "signature_type": "fast"}'::jsonb),
('SLH-DSA-192s', 'signature', 'SLH-DSA-192s (Small)', 'Stateless Hash-Based Digital Signature Algorithm 192s (formerly SPHINCS+-192s)', 'strong', 'current', 10, ARRAY['ML-DSA-65'], 'NIST standardized backup PQC algorithm for digital signatures. Stateless hash-based approach. Provides security equivalent to 192-bit classical. Standardized August 2024.', '{"NIST": "standardized", "FIPS": "approved"}'::jsonb, true, true, 'standardized', '{"pqc_family": "SLH-DSA", "fips_reference": "FIPS 205", "security_level": 3, "variant_group": "slh-dsa-variants", "standardization_date": "2024-08-13", "quantum_resistance": true, "signature_type": "small"}'::jsonb),
('SLH-DSA-192f', 'signature', 'SLH-DSA-192f (Fast)', 'Stateless Hash-Based Digital Signature Algorithm 192f (formerly SPHINCS+-192f)', 'strong', 'current', 10, ARRAY['ML-DSA-65'], 'NIST standardized backup PQC algorithm for digital signatures. Stateless hash-based approach. Provides security equivalent to 192-bit classical. Standardized August 2024.', '{"NIST": "standardized", "FIPS": "approved"}'::jsonb, true, true, 'standardized', '{"pqc_family": "SLH-DSA", "fips_reference": "FIPS 205", "security_level": 3, "variant_group": "slh-dsa-variants", "standardization_date": "2024-08-13", "quantum_resistance": true, "signature_type": "fast"}'::jsonb),
('SLH-DSA-256s', 'signature', 'SLH-DSA-256s (Small)', 'Stateless Hash-Based Digital Signature Algorithm 256s (formerly SPHINCS+-256s)', 'strong', 'current', 10, ARRAY['ML-DSA-87'], 'NIST standardized backup PQC algorithm for digital signatures. Stateless hash-based approach. Provides security equivalent to 256-bit classical. Standardized August 2024.', '{"NIST": "standardized", "FIPS": "approved"}'::jsonb, true, true, 'standardized', '{"pqc_family": "SLH-DSA", "fips_reference": "FIPS 205", "security_level": 5, "variant_group": "slh-dsa-variants", "standardization_date": "2024-08-13", "quantum_resistance": true, "signature_type": "small"}'::jsonb),
('SLH-DSA-256f', 'signature', 'SLH-DSA-256f (Fast)', 'Stateless Hash-Based Digital Signature Algorithm 256f (formerly SPHINCS+-256f)', 'strong', 'current', 10, ARRAY['ML-DSA-87'], 'NIST standardized backup PQC algorithm for digital signatures. Stateless hash-based approach. Provides security equivalent to 256-bit classical. Standardized August 2024.', '{"NIST": "standardized", "FIPS": "approved"}'::jsonb, true, true, 'standardized', '{"pqc_family": "SLH-DSA", "fips_reference": "FIPS 205", "security_level": 5, "variant_group": "slh-dsa-variants", "standardization_date": "2024-08-13", "quantum_resistance": true, "signature_type": "fast"}'::jsonb)
ON CONFLICT (code) DO NOTHING;

-- FN-DSA (FFT NTRU-Based Digital Signature Algorithm) - formerly FALCON
-- Alternative standard for digital signatures
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard, is_pqc, pqc_standardization_status, metadata) VALUES
('FN-DSA-512', 'signature', 'FN-DSA-512', 'FFT NTRU-Based Digital Signature Algorithm 512 (formerly FALCON-512; draft FIPS 206)', 'strong', 'current', 10, ARRAY['ML-DSA-44'], 'Selected by NIST for standardization as FN-DSA (draft FIPS 206); not yet a finalized NIST standard. Provides security equivalent to 128-bit classical. ML-DSA remains the primary NIST-standardized signature algorithm.', '{"NIST": "selected", "FIPS": "pending"}'::jsonb, true, true, 'candidate', '{"pqc_family": "FN-DSA", "security_level": 1, "variant_group": "fn-dsa-variants", "selected_date": "2022-07-05", "standard_status": "draft", "fips_reference": "FIPS 206 (draft)", "quantum_resistance": true}'::jsonb),
('FN-DSA-1024', 'signature', 'FN-DSA-1024', 'FFT NTRU-Based Digital Signature Algorithm 1024 (formerly FALCON-1024; draft FIPS 206)', 'strong', 'current', 10, ARRAY['ML-DSA-87'], 'Selected by NIST for standardization as FN-DSA (draft FIPS 206); not yet a finalized NIST standard. Provides security equivalent to 256-bit classical. ML-DSA remains the primary NIST-standardized signature algorithm.', '{"NIST": "selected", "FIPS": "pending"}'::jsonb, true, true, 'candidate', '{"pqc_family": "FN-DSA", "security_level": 5, "variant_group": "fn-dsa-variants", "selected_date": "2022-07-05", "standard_status": "draft", "fips_reference": "FIPS 206 (draft)", "quantum_resistance": true}'::jsonb)
ON CONFLICT (code) DO NOTHING;

-- Correction (re-runnable): FN-DSA and HQC were previously mis-seeded as NIST-standardized.
-- Neither is a finalized NIST standard — FN-DSA (formerly FALCON) is still a draft (future
-- FIPS 206) and HQC was only selected in March 2025 (draft expected 2026). Existing
-- deployments got the old rows via ON CONFLICT DO NOTHING, so fix them in place here.
UPDATE algorithms SET
    pqc_standardization_status = 'candidate',
    compliance_mappings = '{"NIST": "selected", "FIPS": "pending"}'::jsonb,
    migration_guidance = 'Selected by NIST (March 2025) as the backup PQC key-encapsulation algorithm; draft standard expected 2026 — not yet a finalized NIST standard. Provides security equivalent to AES-' ||
        CASE code WHEN 'HQC-128' THEN '128' WHEN 'HQC-192' THEN '192' ELSE '256' END ||
        '. ML-KEM remains the primary NIST-standardized KEM.',
    metadata = (metadata - 'standardization_date') || jsonb_build_object(
        'selected_date', '2025-03-11', 'standard_status', 'draft')
WHERE code IN ('HQC-128', 'HQC-192', 'HQC-256')
  AND pqc_standardization_status = 'standardized';

UPDATE algorithms SET
    pqc_standardization_status = 'candidate',
    compliance_mappings = '{"NIST": "selected", "FIPS": "pending"}'::jsonb,
    migration_guidance = 'Selected by NIST for standardization as FN-DSA (draft FIPS 206); not yet a finalized NIST standard. Provides security equivalent to ' ||
        CASE code WHEN 'FN-DSA-512' THEN '128' ELSE '256' END ||
        '-bit classical. ML-DSA remains the primary NIST-standardized signature algorithm.',
    metadata = (metadata - 'standardization_date') || jsonb_build_object(
        'selected_date', '2022-07-05', 'standard_status', 'draft', 'fips_reference', 'FIPS 206 (draft)')
WHERE code IN ('FN-DSA-512', 'FN-DSA-1024')
  AND pqc_standardization_status = 'standardized';

-- Correction (re-runnable): stamp the finalized standards with their FIPS references and
-- publication date (FIPS 203/204/205 published; the old rows said FIPS "pending").
UPDATE algorithms SET
    compliance_mappings = jsonb_set(compliance_mappings, '{FIPS}', '"approved"'),
    metadata = metadata || jsonb_build_object(
        'standardization_date', '2024-08-13',
        'fips_reference', CASE
            WHEN code LIKE 'ML-KEM-%' THEN 'FIPS 203'
            WHEN code LIKE 'ML-DSA-%' THEN 'FIPS 204'
            ELSE 'FIPS 205'
        END)
WHERE code IN ('ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024',
               'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87',
               'SLH-DSA-128s', 'SLH-DSA-128f', 'SLH-DSA-192s',
               'SLH-DSA-192f', 'SLH-DSA-256s', 'SLH-DSA-256f')
  AND (metadata ->> 'fips_reference') IS NULL;

-- =================================================================
-- WireGuard VPN Protocol Algorithms
-- =================================================================
-- WireGuard uses a fixed cryptographic suite with no negotiation.
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard, algorithm_family, primitive) VALUES
('CURVE25519', 'key_exchange', 'Curve25519', 'Elliptic curve Diffie-Hellman key exchange using Curve25519. Used by WireGuard, Signal, and SSH.', 'strong', 'current', 15, ARRAY[]::text[], 'Curve25519 is a modern, strong key exchange algorithm. No migration needed.', '{"NIST": "acceptable", "PCI-DSS": "compliant"}'::jsonb, true, 'Curve25519', 'key-agree'),
('BLAKE2S', 'hash', 'BLAKE2s', 'BLAKE2s hash function optimized for 32-bit platforms. Used by WireGuard for key derivation and MAC.', 'strong', 'current', 15, ARRAY[]::text[], 'BLAKE2s is a modern, efficient hash function. No migration needed.', '{"NIST": "acceptable"}'::jsonb, true, 'BLAKE2', 'hash'),
('WIREGUARD', 'protocol_version', 'WireGuard', 'WireGuard VPN protocol using fixed suite: Curve25519 + ChaCha20-Poly1305 + BLAKE2s.', 'strong', 'current', 10, ARRAY[]::text[], 'WireGuard uses a modern, audited cryptographic suite. No migration needed.', '{"NIST": "acceptable", "PCI-DSS": "compliant"}'::jsonb, true, 'WireGuard', 'other')
ON CONFLICT (code) DO NOTHING;

-- =================================================================
-- IPSec / IKE Protocol Algorithms
-- =================================================================
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard, algorithm_family, primitive) VALUES
('ENCR-AES-CBC-128', 'symmetric', 'AES-CBC-128 (IPSec)', 'AES-128 in CBC mode for IPSec ESP encryption.', 'acceptable', 'current', 30, ARRAY['ENCR-AES-GCM-256'], 'Consider migrating to AES-GCM for authenticated encryption.', '{"NIST": "approved", "PCI-DSS": "compliant"}'::jsonb, true, 'AES', 'ae'),
('ENCR-AES-CBC-256', 'symmetric', 'AES-CBC-256 (IPSec)', 'AES-256 in CBC mode for IPSec ESP encryption.', 'strong', 'current', 25, ARRAY['ENCR-AES-GCM-256'], 'Consider migrating to AES-GCM for authenticated encryption.', '{"NIST": "approved", "PCI-DSS": "compliant"}'::jsonb, true, 'AES', 'ae'),
('ENCR-AES-GCM-128', 'symmetric', 'AES-GCM-128 (IPSec)', 'AES-128 in GCM mode for IPSec. Provides authenticated encryption.', 'strong', 'current', 20, ARRAY[]::text[], 'AES-GCM is recommended for new deployments.', '{"NIST": "approved", "PCI-DSS": "compliant"}'::jsonb, true, 'AES', 'ae'),
('ENCR-AES-GCM-256', 'symmetric', 'AES-GCM-256 (IPSec)', 'AES-256 in GCM mode for IPSec. Provides authenticated encryption.', 'strong', 'current', 15, ARRAY[]::text[], 'AES-256-GCM is the recommended choice for IPSec.', '{"NIST": "approved", "PCI-DSS": "compliant"}'::jsonb, true, 'AES', 'ae'),
('ENCR-CHACHA20-POLY1305-IPSEC', 'symmetric', 'ChaCha20-Poly1305 (IPSec)', 'ChaCha20-Poly1305 AEAD for IPSec. Strong modern cipher.', 'strong', 'current', 15, ARRAY[]::text[], 'ChaCha20-Poly1305 is a modern, efficient AEAD cipher.', '{"NIST": "acceptable"}'::jsonb, true, 'ChaCha20', 'ae'),
('PRF-HMAC-SHA2-256', 'hash', 'PRF-HMAC-SHA2-256', 'HMAC-SHA2-256 pseudo-random function for IKEv2 key derivation.', 'strong', 'current', 20, ARRAY[]::text[], 'Standard PRF for modern IKEv2 deployments.', '{"NIST": "approved"}'::jsonb, true, 'SHA-2', 'mac'),
('AUTH-HMAC-SHA2-256-128', 'hash', 'AUTH-HMAC-SHA2-256-128', 'HMAC-SHA2-256 truncated to 128 bits for IPSec ESP integrity.', 'strong', 'current', 20, ARRAY[]::text[], 'Recommended integrity algorithm for IPSec.', '{"NIST": "approved"}'::jsonb, true, 'SHA-2', 'mac'),
('DH-MODP-2048', 'key_exchange', 'MODP-2048', '2048-bit Modular Exponentiation DH group for IKE key exchange.', 'acceptable', 'current', 35, ARRAY['DH-ECP-256', 'DH-MODP-4096'], 'MODP-2048 is the minimum acceptable DH group. Prefer ECP-256 or larger.', '{"NIST": "approved", "PCI-DSS": "compliant"}'::jsonb, true, 'DH', 'key-agree'),
('DH-ECP-256', 'key_exchange', 'ECP-256', 'NIST P-256 elliptic curve DH group for IKE key exchange.', 'strong', 'current', 15, ARRAY[]::text[], 'ECP-256 provides strong key exchange with efficient computation.', '{"NIST": "approved", "PCI-DSS": "compliant"}'::jsonb, true, 'ECDH', 'key-agree'),
('DH-ECP-384', 'key_exchange', 'ECP-384', 'NIST P-384 elliptic curve DH group for IKE key exchange.', 'strong', 'current', 15, ARRAY[]::text[], 'ECP-384 provides strong key exchange.', '{"NIST": "approved", "PCI-DSS": "compliant"}'::jsonb, true, 'ECDH', 'key-agree')
ON CONFLICT (code) DO NOTHING;

-- =================================================================
-- SMB Encryption Cipher Algorithms
-- =================================================================
-- SMB 3.0+ supports transport encryption. SMB 3.1.1 negotiates ciphers via negotiate contexts.
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard, algorithm_family, primitive) VALUES
('SMB-AES-128-CCM', 'symmetric', 'AES-128-CCM (SMB)', 'AES-128 in CCM mode for SMB 3.0+ transport encryption.', 'acceptable', 'current', 30, ARRAY['SMB-AES-256-GCM'], 'AES-128-CCM is the default SMB 3.0 cipher. Prefer AES-256-GCM on SMB 3.1.1.', '{"NIST": "approved", "PCI-DSS": "compliant"}'::jsonb, true, 'AES', 'ae'),
('SMB-AES-128-GCM', 'symmetric', 'AES-128-GCM (SMB)', 'AES-128 in GCM mode for SMB 3.1.1 transport encryption.', 'strong', 'current', 20, ARRAY['SMB-AES-256-GCM'], 'AES-128-GCM provides authenticated encryption for SMB 3.1.1.', '{"NIST": "approved", "PCI-DSS": "compliant"}'::jsonb, true, 'AES', 'ae'),
('SMB-AES-256-CCM', 'symmetric', 'AES-256-CCM (SMB)', 'AES-256 in CCM mode for SMB 3.1.1 transport encryption.', 'strong', 'current', 20, ARRAY['SMB-AES-256-GCM'], 'AES-256-CCM provides strong encryption for SMB 3.1.1.', '{"NIST": "approved", "PCI-DSS": "compliant"}'::jsonb, true, 'AES', 'ae'),
('SMB-AES-256-GCM', 'symmetric', 'AES-256-GCM (SMB)', 'AES-256 in GCM mode for SMB 3.1.1 transport encryption. Strongest available.', 'strong', 'current', 15, ARRAY[]::text[], 'AES-256-GCM is the recommended SMB encryption cipher.', '{"NIST": "approved", "PCI-DSS": "compliant"}'::jsonb, true, 'AES', 'ae')
ON CONFLICT (code) DO NOTHING;

-- =================================================================
-- Kerberos Encryption Type (etype) Algorithms
-- =================================================================
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard, algorithm_family, primitive) VALUES
('AES256-CTS-HMAC-SHA1-96', 'symmetric', 'AES256-CTS-HMAC-SHA1-96', 'Kerberos etype 18. AES-256 in CTS mode with HMAC-SHA1-96. Default for modern AD.', 'strong', 'current', 15, ARRAY[]::text[], 'This is the recommended Kerberos encryption type for Active Directory.', '{"NIST": "approved", "PCI-DSS": "compliant"}'::jsonb, true, 'AES', 'ae'),
('AES128-CTS-HMAC-SHA1-96', 'symmetric', 'AES128-CTS-HMAC-SHA1-96', 'Kerberos etype 17. AES-128 in CTS mode with HMAC-SHA1-96.', 'strong', 'current', 20, ARRAY['AES256-CTS-HMAC-SHA1-96'], 'AES-128 is acceptable but prefer AES-256 where possible.', '{"NIST": "approved", "PCI-DSS": "compliant"}'::jsonb, true, 'AES', 'ae'),
('RC4-HMAC-KRB', 'symmetric', 'RC4-HMAC (Kerberos)', 'Kerberos etype 23. RC4 with HMAC. Deprecated due to known weaknesses in RC4.', 'weak', 'deprecated', 75, ARRAY['AES256-CTS-HMAC-SHA1-96'], 'Disable RC4-HMAC in Active Directory. Set AES as required etype via Group Policy.', '{"NIST": "deprecated", "PCI-DSS": "non-compliant"}'::jsonb, true, 'RC4', 'ae'),
('DES-CBC-MD5-KRB', 'symmetric', 'DES-CBC-MD5 (Kerberos)', 'Kerberos etype 3. DES in CBC mode with MD5. Cryptographically broken.', 'weak', 'obsolete', 95, ARRAY['AES256-CTS-HMAC-SHA1-96'], 'Immediately disable DES encryption in Active Directory Group Policy.', '{"NIST": "not-allowed", "PCI-DSS": "non-compliant", "FIPS": "non-compliant"}'::jsonb, true, 'DES', 'ae')
ON CONFLICT (code) DO NOTHING;

-- =================================================================
-- SSH (Secure Shell) Algorithms
-- =================================================================
-- SSH names its algorithms on the wire (RFC 4250 §4.2 / IANA "Secure Shell
-- (SSH) Protocol Parameters"), and those wire names are what both the passive
-- sensor (SSH_MSG_KEXINIT name-lists) and the active prober report. The `code`
-- of every row below is therefore the EXACT wire name, lower-case, including
-- the '@openssh.com' vendor suffix where the algorithm has one.
--
-- That is deliberate, and it is the only spelling that resolves safely.
-- AlgorithmService.ClassifyAlgorithm tries a case-insensitive EXACT code match
-- first, so an observed "aes256-ctr" lands on this row before the fuzzy
-- fallbacks run. Spelling these as, say, 'AES256-CTR' would still match (the
-- exact lookup is case-insensitive), but spelling them as bare family names
-- would push resolution into the ambiguous-substring path — the path that once
-- resolved "RSA" to RSA-MD5 and SSH's "2.0" to the name "SSL 2.0".
--
-- Assessment basis is cited per row. The general anchors are:
--   RFC 4253 (SSH transport), RFC 8268 (larger MODP groups),
--   RFC 8332 (rsa-sha2-*), RFC 8709 (ssh-ed25519),
--   NIST SP 800-131A Rev.2 (SHA-1 and 3DES retirement),
--   RFC 8996 (deprecating obsolete transport versions),
--   OpenSSH release notes (what upstream disabled, and when).
-- Risk numbers follow models.RiskBands (CVSS v3.1 qualitative ratings x10):
--   Critical >=90, High 70-89, Medium 40-69, Low 1-39, Informational 0.

-- SSH protocol versions.
-- The version is read from the identification-string banner ("SSH-2.0-OpenSSH_9.6").
-- SSH-1.99 is the RFC 4253 §5.1 compatibility advertisement: a server sending it
-- speaks BOTH 2.0 and the broken 1.x protocol, so it is scored as an exposed
-- downgrade path rather than as a clean 2.0 server.
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard, algorithm_family, primitive, crypto_functions, metadata) VALUES
('SSH-1.3', 'protocol_version', 'SSH 1.3', 'SSH protocol version 1.3 - obsolete. The SSH-1 protocol uses CRC-32 for integrity, which is not a MAC; this permits the CRC compensation attack (CVE-2001-0361) and packet insertion.', 'weak', 'obsolete', 92, ARRAY['SSH-2.0'], 'SSH-1 is obsolete and cannot be made safe. Disable protocol 1 entirely (OpenSSH: "Protocol 2" / remove any Protocol 1 support) and require SSH-2.0.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true, 'SSH', 'other', ARRAY[]::text[], '{"protocol": "ssh", "cve_references": ["CVE-2001-0361", "CVE-2001-1473"]}'::jsonb),
('SSH-1.5', 'protocol_version', 'SSH 1.5', 'SSH protocol version 1.5 - obsolete. Same CRC-32 integrity flaw as SSH 1.3 (CVE-2001-0361, the CRC compensation attack), plus a weak key-exchange design with no forward secrecy.', 'weak', 'obsolete', 92, ARRAY['SSH-2.0'], 'SSH-1 is obsolete and cannot be made safe. Disable protocol 1 entirely and require SSH-2.0.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true, 'SSH', 'other', ARRAY[]::text[], '{"protocol": "ssh", "cve_references": ["CVE-2001-0361", "CVE-2001-1473"]}'::jsonb),
('SSH-1.99', 'protocol_version', 'SSH 1.99 (1.x/2.0 compatibility)', 'RFC 4253 5.1 compatibility advertisement: the server speaks SSH-2.0 but ALSO accepts the obsolete SSH-1 protocol. A client can be downgraded onto SSH-1, whose CRC-32 integrity check is broken.', 'weak', 'deprecated', 78, ARRAY['SSH-2.0'], 'Turn off SSH-1 fallback so the server advertises SSH-2.0 rather than SSH-1.99. On OpenSSH this means building/configuring without protocol 1 support.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true, 'SSH', 'other', ARRAY[]::text[], '{"protocol": "ssh", "cve_references": ["CVE-2001-0361"]}'::jsonb),
('SSH-2.0', 'protocol_version', 'SSH 2.0', 'SSH protocol version 2.0 (RFC 4251-4254). The current protocol version; its security depends entirely on the negotiated key exchange, cipher, MAC and host-key algorithms.', 'strong', 'current', 15, ARRAY[]::text[], 'SSH-2.0 is the current protocol version. Review the negotiated key exchange, cipher, MAC and host key algorithms rather than the protocol version itself.', '{"PCI-DSS": "compliant", "NIST": "approved", "FIPS": "approved"}'::jsonb, true, 'SSH', 'other', ARRAY[]::text[], '{"protocol": "ssh"}'::jsonb)
ON CONFLICT (code) DO NOTHING;

-- SSH key exchange algorithms (RFC 4253 s6.5 name-list "kex_algorithms").
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard, algorithm_family, primitive, crypto_functions, classical_security_level, curve, is_pqc, pqc_standardization_status, nist_quantum_security_level, metadata) VALUES
('curve25519-sha256', 'key_exchange', 'curve25519-sha256 (SSH)', 'ECDH over Curve25519 with SHA-256 (RFC 8731). The preferred classical SSH key exchange.', 'strong', 'current', 15, ARRAY['mlkem768x25519-sha256'], 'Curve25519 is the strongest widely-deployed classical SSH key exchange. For quantum resistance, add a hybrid group such as mlkem768x25519-sha256 or sntrup761x25519-sha512@openssh.com.', '{"NIST": "acceptable", "PCI-DSS": "compliant"}'::jsonb, true, 'Curve25519', 'key-agree', ARRAY['keygen', 'keyderive'], 128, 'curve25519', false, 'none', 3, '{"protocol": "ssh", "rfc": "RFC 8731"}'::jsonb),
('curve25519-sha256@libssh.org', 'key_exchange', 'curve25519-sha256@libssh.org (SSH)', 'The pre-standardisation vendor name for curve25519-sha256 (RFC 8731). Cryptographically identical.', 'strong', 'current', 15, ARRAY['curve25519-sha256'], 'Identical to curve25519-sha256; the vendor-prefixed name is kept only for older client compatibility.', '{"NIST": "acceptable", "PCI-DSS": "compliant"}'::jsonb, true, 'Curve25519', 'key-agree', ARRAY['keygen', 'keyderive'], 128, 'curve25519', false, 'none', NULL, '{"protocol": "ssh", "rfc": "RFC 8731"}'::jsonb),
('ecdh-sha2-nistp256', 'key_exchange', 'ecdh-sha2-nistp256 (SSH)', 'ECDH over NIST P-256 with SHA-256 (RFC 5656). 128-bit classical security.', 'strong', 'current', 20, ARRAY['curve25519-sha256'], 'Acceptable. Curve25519 is preferred for its simpler, misuse-resistant implementation.', '{"NIST": "approved", "PCI-DSS": "compliant", "FIPS": "approved"}'::jsonb, true, 'ECDH', 'key-agree', ARRAY['keygen', 'keyderive'], 128, 'P-256', false, 'none', NULL, '{"protocol": "ssh", "rfc": "RFC 5656"}'::jsonb),
('ecdh-sha2-nistp384', 'key_exchange', 'ecdh-sha2-nistp384 (SSH)', 'ECDH over NIST P-384 with SHA-384 (RFC 5656). 192-bit classical security.', 'strong', 'current', 15, ARRAY[]::text[], 'Strong classical key exchange. No migration needed until post-quantum transition.', '{"NIST": "approved", "PCI-DSS": "compliant", "FIPS": "approved"}'::jsonb, true, 'ECDH', 'key-agree', ARRAY['keygen', 'keyderive'], 192, 'P-384', false, 'none', NULL, '{"protocol": "ssh", "rfc": "RFC 5656"}'::jsonb),
('ecdh-sha2-nistp521', 'key_exchange', 'ecdh-sha2-nistp521 (SSH)', 'ECDH over NIST P-521 with SHA-512 (RFC 5656). 256-bit classical security.', 'strong', 'current', 15, ARRAY[]::text[], 'Strong classical key exchange. No migration needed until post-quantum transition.', '{"NIST": "approved", "PCI-DSS": "compliant", "FIPS": "approved"}'::jsonb, true, 'ECDH', 'key-agree', ARRAY['keygen', 'keyderive'], 256, 'P-521', false, 'none', NULL, '{"protocol": "ssh", "rfc": "RFC 5656"}'::jsonb),
('diffie-hellman-group14-sha256', 'key_exchange', 'diffie-hellman-group14-sha256 (SSH)', 'Finite-field DH over the 2048-bit MODP group 14 with SHA-256 (RFC 8268). Meets the SP 800-131A 2048-bit floor; ~112-bit classical security.', 'acceptable', 'current', 35, ARRAY['curve25519-sha256', 'diffie-hellman-group16-sha512'], 'Acceptable but slow and only ~112-bit strength. Prefer curve25519-sha256 or, if finite-field DH is required, group16/group18.', '{"NIST": "approved", "PCI-DSS": "compliant", "FIPS": "approved"}'::jsonb, true, 'DH', 'key-agree', ARRAY['keygen', 'keyderive'], 112, NULL, false, 'none', NULL, '{"protocol": "ssh", "rfc": "RFC 8268", "modp_bits": 2048}'::jsonb),
('diffie-hellman-group16-sha512', 'key_exchange', 'diffie-hellman-group16-sha512 (SSH)', 'Finite-field DH over the 4096-bit MODP group 16 with SHA-512 (RFC 8268).', 'strong', 'current', 25, ARRAY['curve25519-sha256'], 'Strong but computationally expensive. Elliptic-curve key exchange gives equivalent strength far more cheaply.', '{"NIST": "approved", "PCI-DSS": "compliant", "FIPS": "approved"}'::jsonb, true, 'DH', 'key-agree', ARRAY['keygen', 'keyderive'], 152, NULL, false, 'none', NULL, '{"protocol": "ssh", "rfc": "RFC 8268", "modp_bits": 4096}'::jsonb),
('diffie-hellman-group18-sha512', 'key_exchange', 'diffie-hellman-group18-sha512 (SSH)', 'Finite-field DH over the 8192-bit MODP group 18 with SHA-512 (RFC 8268).', 'strong', 'current', 25, ARRAY['curve25519-sha256'], 'Strong but very computationally expensive. Elliptic-curve key exchange gives equivalent strength far more cheaply.', '{"NIST": "approved", "PCI-DSS": "compliant", "FIPS": "approved"}'::jsonb, true, 'DH', 'key-agree', ARRAY['keygen', 'keyderive'], 192, NULL, false, 'none', NULL, '{"protocol": "ssh", "rfc": "RFC 8268", "modp_bits": 8192}'::jsonb),
('diffie-hellman-group-exchange-sha256', 'key_exchange', 'diffie-hellman-group-exchange-sha256 (SSH)', 'Negotiated-group finite-field DH with SHA-256 (RFC 4419). Strength depends on the group the server offers; OpenSSH will not accept groups below 2048 bits.', 'acceptable', 'current', 35, ARRAY['curve25519-sha256'], 'Acceptable when the server moduli file contains only 2048-bit or larger groups. Prefer curve25519-sha256, whose strength does not depend on server configuration.', '{"NIST": "approved", "PCI-DSS": "compliant"}'::jsonb, true, 'DH', 'key-agree', ARRAY['keygen', 'keyderive'], 112, NULL, false, 'none', NULL, '{"protocol": "ssh", "rfc": "RFC 4419"}'::jsonb),
('diffie-hellman-group14-sha1', 'key_exchange', 'diffie-hellman-group14-sha1 (SSH)', 'Finite-field DH over the 2048-bit MODP group 14, but with SHA-1 as the key-exchange hash (RFC 4253). The group is adequate; the hash is not.', 'weak', 'deprecated', 70, ARRAY['diffie-hellman-group14-sha256', 'curve25519-sha256'], 'Retire SHA-1 in key exchange per NIST SP 800-131A Rev.2. Switch to diffie-hellman-group14-sha256 or curve25519-sha256. OpenSSH removed this from the default proposal in 8.2.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true, 'DH', 'key-agree', ARRAY['keygen', 'keyderive'], 112, NULL, false, 'none', NULL, '{"protocol": "ssh", "rfc": "RFC 4253", "modp_bits": 2048}'::jsonb),
('diffie-hellman-group-exchange-sha1', 'key_exchange', 'diffie-hellman-group-exchange-sha1 (SSH)', 'Negotiated-group finite-field DH with SHA-1 as the key-exchange hash (RFC 4419). Both the SHA-1 hash and the historically small negotiable groups are problems.', 'weak', 'deprecated', 72, ARRAY['diffie-hellman-group14-sha256', 'curve25519-sha256'], 'Disable. Use diffie-hellman-group-exchange-sha256 at minimum, curve25519-sha256 preferably. OpenSSH removed this from the default proposal in 8.2.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true, 'DH', 'key-agree', ARRAY['keygen', 'keyderive'], 112, NULL, false, 'none', NULL, '{"protocol": "ssh", "rfc": "RFC 4419"}'::jsonb),
('diffie-hellman-group1-sha1', 'key_exchange', 'diffie-hellman-group1-sha1 (SSH)', 'Finite-field DH over the 1024-bit MODP group 2 with SHA-1 (RFC 4253). A 1024-bit fixed, universally-shared modulus is a precomputation target (Logjam, CVE-2015-4000), and the hash is SHA-1.', 'weak', 'obsolete', 82, ARRAY['curve25519-sha256', 'diffie-hellman-group14-sha256'], 'Disable immediately. The 1024-bit group is below the SP 800-131A floor and its fixed modulus makes precomputed discrete-log attacks practical for well-resourced adversaries. OpenSSH disabled it by default in 7.0.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true, 'DH', 'key-agree', ARRAY['keygen', 'keyderive'], 80, NULL, false, 'none', NULL, '{"protocol": "ssh", "rfc": "RFC 4253", "modp_bits": 1024, "cve_references": ["CVE-2015-4000"]}'::jsonb),
('sntrup761x25519-sha512@openssh.com', 'key_exchange', 'sntrup761x25519-sha512@openssh.com (SSH)', 'Hybrid post-quantum key exchange combining Streamlined NTRU Prime sntrup761 with X25519. OpenSSH default since 9.0. Not a NIST standard, but the hybrid construction is no weaker than X25519 alone.', 'recommended', 'current', 10, ARRAY['mlkem768x25519-sha256'], 'A quantum-resistant hybrid key exchange. Where both peers support it, mlkem768x25519-sha256 is preferable because ML-KEM is the NIST standard (FIPS 203).', '{"NIST": "not-standardized", "PCI-DSS": "compliant"}'::jsonb, true, 'NTRU Prime', 'kem', ARRAY['encapsulate', 'decapsulate', 'keyderive'], 128, NULL, true, 'alternative', 3, '{"protocol": "ssh", "hybrid": true, "hybrid_classical": "X25519", "quantum_resistance": true}'::jsonb),
('mlkem768x25519-sha256', 'key_exchange', 'mlkem768x25519-sha256 (SSH)', 'Hybrid post-quantum key exchange combining ML-KEM-768 (FIPS 203) with X25519. OpenSSH default since 10.0.', 'recommended', 'current', 5, ARRAY[]::text[], 'The recommended quantum-resistant SSH key exchange. No migration needed.', '{"NIST": "standardized", "PCI-DSS": "compliant", "FIPS": "approved"}'::jsonb, true, 'ML-KEM', 'kem', ARRAY['encapsulate', 'decapsulate', 'keyderive'], 192, NULL, true, 'standardized', 3, '{"protocol": "ssh", "hybrid": true, "hybrid_classical": "X25519", "fips_reference": "FIPS 203", "quantum_resistance": true}'::jsonb)
ON CONFLICT (code) DO NOTHING;

-- SSH encryption algorithms (RFC 4253 s6.3 name-lists "encryption_algorithms_*").
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard, algorithm_family, primitive, mode, crypto_functions, classical_security_level, metadata) VALUES
('chacha20-poly1305@openssh.com', 'symmetric', 'chacha20-poly1305@openssh.com (SSH)', 'ChaCha20-Poly1305 AEAD as specified by OpenSSH, encrypting both the packet length and the payload. OpenSSH default cipher.', 'strong', 'current', 15, ARRAY[]::text[], 'A modern AEAD cipher. No migration needed.', '{"NIST": "acceptable", "PCI-DSS": "compliant"}'::jsonb, true, 'ChaCha20', 'ae', NULL, ARRAY['encrypt', 'decrypt', 'tag'], 256, '{"protocol": "ssh"}'::jsonb),
('aes256-gcm@openssh.com', 'symmetric', 'aes256-gcm@openssh.com (SSH)', 'AES-256 in GCM mode (RFC 5647 semantics, OpenSSH naming). Authenticated encryption; the MAC name-list is ignored when a GCM cipher is negotiated.', 'strong', 'current', 15, ARRAY[]::text[], 'A modern AEAD cipher. No migration needed.', '{"NIST": "approved", "PCI-DSS": "compliant", "FIPS": "approved"}'::jsonb, true, 'AES', 'ae', 'gcm', ARRAY['encrypt', 'decrypt', 'tag'], 256, '{"protocol": "ssh"}'::jsonb),
('aes128-gcm@openssh.com', 'symmetric', 'aes128-gcm@openssh.com (SSH)', 'AES-128 in GCM mode (RFC 5647 semantics, OpenSSH naming). Authenticated encryption.', 'strong', 'current', 20, ARRAY['aes256-gcm@openssh.com'], 'A modern AEAD cipher. AES-256 is preferred where performance allows.', '{"NIST": "approved", "PCI-DSS": "compliant", "FIPS": "approved"}'::jsonb, true, 'AES', 'ae', 'gcm', ARRAY['encrypt', 'decrypt', 'tag'], 128, '{"protocol": "ssh"}'::jsonb),
('aes256-ctr', 'symmetric', 'aes256-ctr (SSH)', 'AES-256 in counter mode (RFC 4344). Not authenticated on its own — integrity comes from the separately negotiated MAC, so pair it with an encrypt-then-MAC algorithm.', 'strong', 'current', 20, ARRAY['aes256-gcm@openssh.com', 'chacha20-poly1305@openssh.com'], 'Safe when paired with an encrypt-then-MAC (-etm) MAC. Prefer an AEAD cipher (aes256-gcm@openssh.com or chacha20-poly1305@openssh.com), which cannot be misconfigured this way.', '{"NIST": "approved", "PCI-DSS": "compliant", "FIPS": "approved"}'::jsonb, true, 'AES', 'block-cipher', 'ctr', ARRAY['encrypt', 'decrypt'], 256, '{"protocol": "ssh", "rfc": "RFC 4344"}'::jsonb),
('aes192-ctr', 'symmetric', 'aes192-ctr (SSH)', 'AES-192 in counter mode (RFC 4344). Not authenticated on its own.', 'strong', 'current', 22, ARRAY['aes256-gcm@openssh.com'], 'Safe when paired with an encrypt-then-MAC (-etm) MAC. Prefer an AEAD cipher.', '{"NIST": "approved", "PCI-DSS": "compliant", "FIPS": "approved"}'::jsonb, true, 'AES', 'block-cipher', 'ctr', ARRAY['encrypt', 'decrypt'], 192, '{"protocol": "ssh", "rfc": "RFC 4344"}'::jsonb),
('aes128-ctr', 'symmetric', 'aes128-ctr (SSH)', 'AES-128 in counter mode (RFC 4344). Not authenticated on its own.', 'strong', 'current', 25, ARRAY['aes256-gcm@openssh.com'], 'Safe when paired with an encrypt-then-MAC (-etm) MAC. Prefer an AEAD cipher.', '{"NIST": "approved", "PCI-DSS": "compliant", "FIPS": "approved"}'::jsonb, true, 'AES', 'block-cipher', 'ctr', ARRAY['encrypt', 'decrypt'], 128, '{"protocol": "ssh", "rfc": "RFC 4344"}'::jsonb),
('aes256-cbc', 'symmetric', 'aes256-cbc (SSH)', 'AES-256 in CBC mode. SSH CBC modes are vulnerable to the 2008 plaintext-recovery attack against the SSH binary packet protocol (CVE-2008-5161), which recovers 32 bits of plaintext with probability 2^-18.', 'weak', 'deprecated', 60, ARRAY['aes256-ctr', 'aes256-gcm@openssh.com'], 'Disable CBC ciphers. Use aes256-ctr with an -etm MAC, or an AEAD cipher. OpenSSH removed CBC ciphers from the default proposal in 6.7.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated"}'::jsonb, true, 'AES', 'block-cipher', 'cbc', ARRAY['encrypt', 'decrypt'], 256, '{"protocol": "ssh", "cve_references": ["CVE-2008-5161"]}'::jsonb),
('aes192-cbc', 'symmetric', 'aes192-cbc (SSH)', 'AES-192 in CBC mode. Vulnerable to the SSH CBC plaintext-recovery attack (CVE-2008-5161).', 'weak', 'deprecated', 61, ARRAY['aes256-ctr', 'aes256-gcm@openssh.com'], 'Disable CBC ciphers. Use aes256-ctr with an -etm MAC, or an AEAD cipher.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated"}'::jsonb, true, 'AES', 'block-cipher', 'cbc', ARRAY['encrypt', 'decrypt'], 192, '{"protocol": "ssh", "cve_references": ["CVE-2008-5161"]}'::jsonb),
('aes128-cbc', 'symmetric', 'aes128-cbc (SSH)', 'AES-128 in CBC mode. Vulnerable to the SSH CBC plaintext-recovery attack (CVE-2008-5161).', 'weak', 'deprecated', 62, ARRAY['aes256-ctr', 'aes256-gcm@openssh.com'], 'Disable CBC ciphers. Use aes256-ctr with an -etm MAC, or an AEAD cipher.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated"}'::jsonb, true, 'AES', 'block-cipher', 'cbc', ARRAY['encrypt', 'decrypt'], 128, '{"protocol": "ssh", "cve_references": ["CVE-2008-5161"]}'::jsonb),
('3des-cbc', 'symmetric', '3des-cbc (SSH)', 'Triple-DES in CBC mode. Two independent problems: a 64-bit block size (Sweet32 birthday attack, CVE-2016-2183) and CBC mode in SSH (CVE-2008-5161). NIST SP 800-131A Rev.2 disallowed 3DES for encryption after 2023.', 'weak', 'deprecated', 72, ARRAY['aes256-ctr', 'aes256-gcm@openssh.com'], 'Disable 3des-cbc. It is disallowed by NIST SP 800-131A Rev.2 and was removed from the OpenSSH default proposal in 7.0.', '{"PCI-DSS": "non-compliant", "NIST": "disallowed", "FIPS": "non-compliant"}'::jsonb, true, '3DES', 'block-cipher', 'cbc', ARRAY['encrypt', 'decrypt'], 112, '{"protocol": "ssh", "block_bits": 64, "cve_references": ["CVE-2016-2183", "CVE-2008-5161"]}'::jsonb),
('arcfour', 'symmetric', 'arcfour (SSH)', 'RC4 stream cipher. RC4 has statistical biases that leak plaintext (RFC 7465 prohibits it in TLS for this reason); this variant additionally does not discard the weak initial keystream.', 'weak', 'obsolete', 92, ARRAY['aes256-ctr', 'chacha20-poly1305@openssh.com'], 'Disable immediately. RC4 is cryptographically broken. OpenSSH removed arcfour in 7.6.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true, 'RC4', 'stream-cipher', NULL, ARRAY['encrypt', 'decrypt'], NULL, '{"protocol": "ssh"}'::jsonb),
('arcfour128', 'symmetric', 'arcfour128 (SSH)', 'RC4 with a 128-bit key, discarding the first 1536 keystream bytes (RFC 4345). Discarding helps but does not fix RC4''s keystream biases.', 'weak', 'obsolete', 90, ARRAY['aes256-ctr', 'chacha20-poly1305@openssh.com'], 'Disable immediately. RC4 is cryptographically broken. OpenSSH removed the arcfour ciphers in 7.6.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true, 'RC4', 'stream-cipher', NULL, ARRAY['encrypt', 'decrypt'], NULL, '{"protocol": "ssh", "rfc": "RFC 4345"}'::jsonb),
('arcfour256', 'symmetric', 'arcfour256 (SSH)', 'RC4 with a 256-bit key, discarding the first 1536 keystream bytes (RFC 4345). A longer key does not repair RC4''s keystream biases.', 'weak', 'obsolete', 90, ARRAY['aes256-ctr', 'chacha20-poly1305@openssh.com'], 'Disable immediately. RC4 is cryptographically broken. OpenSSH removed the arcfour ciphers in 7.6.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true, 'RC4', 'stream-cipher', NULL, ARRAY['encrypt', 'decrypt'], NULL, '{"protocol": "ssh", "rfc": "RFC 4345"}'::jsonb)
ON CONFLICT (code) DO NOTHING;

-- SSH MAC algorithms (RFC 4253 s6.4 name-lists "mac_algorithms_*").
-- Categorised as 'hash' because that is the crypto_implementation_algorithms
-- role SSH integrity maps onto (the table's algorithm_type CHECK has no 'mac'
-- value); the CycloneDX primitive is 'mac', which is what the PQC classifier
-- reads.
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard, algorithm_family, primitive, crypto_functions, classical_security_level, metadata) VALUES
('hmac-sha2-256-etm@openssh.com', 'hash', 'hmac-sha2-256-etm@openssh.com (SSH)', 'HMAC-SHA-256 in encrypt-then-MAC construction. EtM authenticates the packet length as well as the payload, which the RFC 4253 MAC-then-encrypt ordering does not.', 'strong', 'current', 15, ARRAY[]::text[], 'The preferred SSH MAC construction. No migration needed.', '{"NIST": "approved", "PCI-DSS": "compliant", "FIPS": "approved"}'::jsonb, true, 'SHA-2', 'mac', ARRAY['tag'], 256, '{"protocol": "ssh", "etm": true}'::jsonb),
('hmac-sha2-512-etm@openssh.com', 'hash', 'hmac-sha2-512-etm@openssh.com (SSH)', 'HMAC-SHA-512 in encrypt-then-MAC construction.', 'strong', 'current', 15, ARRAY[]::text[], 'The preferred SSH MAC construction. No migration needed.', '{"NIST": "approved", "PCI-DSS": "compliant", "FIPS": "approved"}'::jsonb, true, 'SHA-2', 'mac', ARRAY['tag'], 512, '{"protocol": "ssh", "etm": true}'::jsonb),
('hmac-sha2-256', 'hash', 'hmac-sha2-256 (SSH)', 'HMAC-SHA-256 in the RFC 4253 MAC-then-encrypt ordering (RFC 6668). Sound, but the packet length is encrypted without being authenticated.', 'strong', 'current', 20, ARRAY['hmac-sha2-256-etm@openssh.com'], 'Acceptable. Prefer the -etm variant, which also authenticates the packet length.', '{"NIST": "approved", "PCI-DSS": "compliant", "FIPS": "approved"}'::jsonb, true, 'SHA-2', 'mac', ARRAY['tag'], 256, '{"protocol": "ssh", "rfc": "RFC 6668", "etm": false}'::jsonb),
('hmac-sha2-512', 'hash', 'hmac-sha2-512 (SSH)', 'HMAC-SHA-512 in the RFC 4253 MAC-then-encrypt ordering (RFC 6668).', 'strong', 'current', 20, ARRAY['hmac-sha2-512-etm@openssh.com'], 'Acceptable. Prefer the -etm variant, which also authenticates the packet length.', '{"NIST": "approved", "PCI-DSS": "compliant", "FIPS": "approved"}'::jsonb, true, 'SHA-2', 'mac', ARRAY['tag'], 512, '{"protocol": "ssh", "rfc": "RFC 6668", "etm": false}'::jsonb),
('umac-128-etm@openssh.com', 'hash', 'umac-128-etm@openssh.com (SSH)', 'UMAC (RFC 4418) with a 128-bit tag, encrypt-then-MAC. 128-bit tags give a negligible forgery probability.', 'strong', 'current', 20, ARRAY['hmac-sha2-256-etm@openssh.com'], 'Strong. Not a FIPS-approved MAC; use an HMAC-SHA-2 variant where FIPS 140 validation is required.', '{"NIST": "not-approved", "PCI-DSS": "compliant", "FIPS": "non-compliant"}'::jsonb, true, 'UMAC', 'mac', ARRAY['tag'], 128, '{"protocol": "ssh", "rfc": "RFC 4418", "etm": true, "tag_bits": 128}'::jsonb),
('umac-128@openssh.com', 'hash', 'umac-128@openssh.com (SSH)', 'UMAC (RFC 4418) with a 128-bit tag, MAC-then-encrypt.', 'strong', 'current', 25, ARRAY['hmac-sha2-256-etm@openssh.com'], 'Acceptable. Prefer an -etm variant, and an HMAC-SHA-2 variant where FIPS 140 validation is required.', '{"NIST": "not-approved", "PCI-DSS": "compliant", "FIPS": "non-compliant"}'::jsonb, true, 'UMAC', 'mac', ARRAY['tag'], 128, '{"protocol": "ssh", "rfc": "RFC 4418", "etm": false, "tag_bits": 128}'::jsonb),
('umac-64-etm@openssh.com', 'hash', 'umac-64-etm@openssh.com (SSH)', 'UMAC (RFC 4418) with a 64-bit tag, encrypt-then-MAC. A 64-bit tag admits a 2^-64 per-attempt forgery probability, well below the 128-bit alternatives.', 'acceptable', 'current', 45, ARRAY['umac-128-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com'], 'Prefer a 128-bit tag: umac-128-etm@openssh.com or hmac-sha2-256-etm@openssh.com.', '{"NIST": "not-approved", "PCI-DSS": "compliant", "FIPS": "non-compliant"}'::jsonb, true, 'UMAC', 'mac', ARRAY['tag'], 64, '{"protocol": "ssh", "rfc": "RFC 4418", "etm": true, "tag_bits": 64}'::jsonb),
('umac-64@openssh.com', 'hash', 'umac-64@openssh.com (SSH)', 'UMAC (RFC 4418) with a 64-bit tag, MAC-then-encrypt.', 'acceptable', 'current', 48, ARRAY['umac-128-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com'], 'Prefer a 128-bit tag and an -etm construction.', '{"NIST": "not-approved", "PCI-DSS": "compliant", "FIPS": "non-compliant"}'::jsonb, true, 'UMAC', 'mac', ARRAY['tag'], 64, '{"protocol": "ssh", "rfc": "RFC 4418", "etm": false, "tag_bits": 64}'::jsonb),
('hmac-sha1-etm@openssh.com', 'hash', 'hmac-sha1-etm@openssh.com (SSH)', 'HMAC-SHA-1, encrypt-then-MAC. HMAC-SHA-1 is not broken by SHA-1 collisions, but SHA-1 is retired for new use by NIST SP 800-131A Rev.2 and by PCI-DSS.', 'weak', 'deprecated', 60, ARRAY['hmac-sha2-256-etm@openssh.com'], 'Retire SHA-1. Switch to hmac-sha2-256-etm@openssh.com.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true, 'SHA-1', 'mac', ARRAY['tag'], 160, '{"protocol": "ssh", "etm": true}'::jsonb),
('hmac-sha1', 'hash', 'hmac-sha1 (SSH)', 'HMAC-SHA-1 in the RFC 4253 MAC-then-encrypt ordering. Retired for new use by NIST SP 800-131A Rev.2 and non-compliant under PCI-DSS.', 'weak', 'deprecated', 65, ARRAY['hmac-sha2-256-etm@openssh.com'], 'Retire SHA-1. Switch to hmac-sha2-256-etm@openssh.com.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true, 'SHA-1', 'mac', ARRAY['tag'], 160, '{"protocol": "ssh", "etm": false}'::jsonb),
('hmac-sha1-96', 'hash', 'hmac-sha1-96 (SSH)', 'HMAC-SHA-1 truncated to 96 bits (RFC 4253). Both the SHA-1 primitive and the truncated tag are below current guidance.', 'weak', 'deprecated', 68, ARRAY['hmac-sha2-256-etm@openssh.com'], 'Disable. Switch to hmac-sha2-256-etm@openssh.com.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true, 'SHA-1', 'mac', ARRAY['tag'], 96, '{"protocol": "ssh", "etm": false, "tag_bits": 96}'::jsonb),
('hmac-md5', 'hash', 'hmac-md5 (SSH)', 'HMAC-MD5 (RFC 4253). MD5 is cryptographically broken and disallowed for any new use; no modern SSH deployment should offer this.', 'weak', 'obsolete', 78, ARRAY['hmac-sha2-256-etm@openssh.com'], 'Disable immediately. Switch to hmac-sha2-256-etm@openssh.com. OpenSSH removed the MD5 MACs in 7.6.', '{"PCI-DSS": "non-compliant", "NIST": "disallowed", "FIPS": "non-compliant"}'::jsonb, true, 'MD5', 'mac', ARRAY['tag'], 128, '{"protocol": "ssh", "etm": false}'::jsonb),
('hmac-md5-96', 'hash', 'hmac-md5-96 (SSH)', 'HMAC-MD5 truncated to 96 bits (RFC 4253). Broken primitive plus a truncated tag.', 'weak', 'obsolete', 80, ARRAY['hmac-sha2-256-etm@openssh.com'], 'Disable immediately. Switch to hmac-sha2-256-etm@openssh.com. OpenSSH removed the MD5 MACs in 7.6.', '{"PCI-DSS": "non-compliant", "NIST": "disallowed", "FIPS": "non-compliant"}'::jsonb, true, 'MD5', 'mac', ARRAY['tag'], 96, '{"protocol": "ssh", "etm": false, "tag_bits": 96}'::jsonb)
ON CONFLICT (code) DO NOTHING;

-- SSH host key / public key algorithms (RFC 4253 s6.6 name-list "server_host_key_algorithms").
-- These are the SIGNATURE component of an SSH configuration: the algorithm the
-- server uses to prove its identity during key exchange.
--
-- 'Ed25519' (the generic row, no ssh- prefix) is seeded alongside them
-- deliberately. Without it an observed bare "ED25519" in the signature category
-- would substring-match exactly one row — 'ssh-ed25519' — and a TLS or
-- certificate observation would silently acquire an SSH-specific assessment.
-- An exact code match wins over the substring path, so the generic row keeps
-- that resolution honest.
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard, algorithm_family, primitive, crypto_functions, classical_security_level, curve, metadata) VALUES
('ssh-ed25519', 'signature', 'ssh-ed25519 (SSH host key)', 'EdDSA host key over Curve25519 (RFC 8709). The preferred classical SSH host key algorithm.', 'strong', 'current', 10, ARRAY[]::text[], 'The strongest widely-supported SSH host key type. Quantum-vulnerable like all classical signatures (NIST IR 8547); no classical migration needed.', '{"NIST": "approved", "PCI-DSS": "compliant"}'::jsonb, true, 'EdDSA', 'signature', ARRAY['sign', 'verify'], 128, 'ed25519', '{"protocol": "ssh", "rfc": "RFC 8709"}'::jsonb),
('ssh-ed448', 'signature', 'ssh-ed448 (SSH host key)', 'EdDSA host key over Curve448 (RFC 8709). Rarely deployed but cryptographically strong.', 'strong', 'current', 10, ARRAY[]::text[], 'Cryptographically strong. Quantum-vulnerable like all classical signatures (NIST IR 8547).', '{"NIST": "approved", "PCI-DSS": "compliant"}'::jsonb, true, 'EdDSA', 'signature', ARRAY['sign', 'verify'], 224, 'ed448', '{"protocol": "ssh", "rfc": "RFC 8709"}'::jsonb),
('ecdsa-sha2-nistp256', 'signature', 'ecdsa-sha2-nistp256 (SSH host key)', 'ECDSA host key over NIST P-256 with SHA-256 (RFC 5656).', 'strong', 'current', 20, ARRAY['ssh-ed25519'], 'Acceptable. Ed25519 is preferred for its deterministic signing, which removes the catastrophic nonce-reuse failure mode of ECDSA.', '{"NIST": "approved", "PCI-DSS": "compliant", "FIPS": "approved"}'::jsonb, true, 'ECDSA', 'signature', ARRAY['sign', 'verify'], 128, 'P-256', '{"protocol": "ssh", "rfc": "RFC 5656"}'::jsonb),
('ecdsa-sha2-nistp384', 'signature', 'ecdsa-sha2-nistp384 (SSH host key)', 'ECDSA host key over NIST P-384 with SHA-384 (RFC 5656).', 'strong', 'current', 15, ARRAY['ssh-ed25519'], 'Strong. Ed25519 is preferred for its deterministic signing.', '{"NIST": "approved", "PCI-DSS": "compliant", "FIPS": "approved"}'::jsonb, true, 'ECDSA', 'signature', ARRAY['sign', 'verify'], 192, 'P-384', '{"protocol": "ssh", "rfc": "RFC 5656"}'::jsonb),
('ecdsa-sha2-nistp521', 'signature', 'ecdsa-sha2-nistp521 (SSH host key)', 'ECDSA host key over NIST P-521 with SHA-512 (RFC 5656).', 'strong', 'current', 15, ARRAY['ssh-ed25519'], 'Strong. Ed25519 is preferred for its deterministic signing.', '{"NIST": "approved", "PCI-DSS": "compliant", "FIPS": "approved"}'::jsonb, true, 'ECDSA', 'signature', ARRAY['sign', 'verify'], 256, 'P-521', '{"protocol": "ssh", "rfc": "RFC 5656"}'::jsonb),
('rsa-sha2-512', 'signature', 'rsa-sha2-512 (SSH host key)', 'RSA host key signed with RSASSA-PKCS1-v1_5 over SHA-512 (RFC 8332). The modern replacement for ssh-rsa; the key is the same, the signature hash is not.', 'strong', 'current', 15, ARRAY[]::text[], 'The recommended RSA host key algorithm. Ensure the underlying RSA key is at least 2048 bits (SP 800-131A Rev.2), preferably 3072 or more.', '{"NIST": "approved", "PCI-DSS": "compliant", "FIPS": "approved"}'::jsonb, true, 'RSA', 'signature', ARRAY['sign', 'verify'], 112, NULL, '{"protocol": "ssh", "rfc": "RFC 8332"}'::jsonb),
('rsa-sha2-256', 'signature', 'rsa-sha2-256 (SSH host key)', 'RSA host key signed with RSASSA-PKCS1-v1_5 over SHA-256 (RFC 8332).', 'strong', 'current', 20, ARRAY['rsa-sha2-512', 'ssh-ed25519'], 'Acceptable. Ensure the underlying RSA key is at least 2048 bits (SP 800-131A Rev.2).', '{"NIST": "approved", "PCI-DSS": "compliant", "FIPS": "approved"}'::jsonb, true, 'RSA', 'signature', ARRAY['sign', 'verify'], 112, NULL, '{"protocol": "ssh", "rfc": "RFC 8332"}'::jsonb),
('ssh-rsa', 'signature', 'ssh-rsa (SSH host key, SHA-1)', 'RSA host key signed over SHA-1 (RFC 4253). The signature hash is SHA-1, for which chosen-prefix collisions are practical (SHA-1 is a Shambles, 2020). OpenSSH disabled this algorithm by default in 8.8.', 'weak', 'deprecated', 70, ARRAY['rsa-sha2-512', 'ssh-ed25519'], 'Enable the rsa-sha2-256/rsa-sha2-512 host key algorithms — the existing RSA key can be reused, only the signature hash changes — or migrate the host key to Ed25519.', '{"PCI-DSS": "non-compliant", "NIST": "deprecated", "FIPS": "non-compliant"}'::jsonb, true, 'RSA', 'signature', ARRAY['sign', 'verify'], 112, NULL, '{"protocol": "ssh", "rfc": "RFC 4253", "signature_hash": "SHA-1"}'::jsonb),
('ssh-dss', 'signature', 'ssh-dss (SSH host key, DSA)', 'DSA host key (RFC 4253). SSH fixes DSA at a 1024-bit modulus with SHA-1, below the SP 800-131A Rev.2 floor, and DSA fails catastrophically on nonce reuse. OpenSSH disabled it by default in 7.0 and removed it entirely in 9.8.', 'weak', 'obsolete', 82, ARRAY['ssh-ed25519', 'rsa-sha2-512'], 'Remove the DSA host key and regenerate as Ed25519 (preferred) or RSA with rsa-sha2-512. Clients pinning the old host key will need to re-accept the new one.', '{"PCI-DSS": "non-compliant", "NIST": "disallowed", "FIPS": "non-compliant"}'::jsonb, true, 'DSA', 'signature', ARRAY['sign', 'verify'], 80, NULL, '{"protocol": "ssh", "rfc": "RFC 4253", "modulus_bits": 1024, "signature_hash": "SHA-1"}'::jsonb),
('Ed25519', 'signature', 'Ed25519', 'EdDSA signature over Curve25519 (RFC 8032), protocol-independent. Used for SSH host keys, X.509 certificates (RFC 8410) and code signing.', 'strong', 'current', 10, ARRAY[]::text[], 'A modern, strong signature algorithm. Quantum-vulnerable like all classical signatures (NIST IR 8547); no classical migration needed.', '{"NIST": "approved", "PCI-DSS": "compliant"}'::jsonb, true, 'EdDSA', 'signature', ARRAY['sign', 'verify'], 128, 'ed25519', '{"rfc": "RFC 8032"}'::jsonb)
ON CONFLICT (code) DO NOTHING;

-- =================================================================
-- Algorithm Remediation Guidance
-- =================================================================
-- Add detailed remediation guidance for weak/deprecated algorithms

-- Hash Algorithms
UPDATE algorithms SET remediation_guidance = '{
    "summary": "MD5 is cryptographically broken and must be replaced immediately.",
    "impact": "HIGH - MD5 collisions can be exploited to forge certificates and tamper with data integrity.",
    "steps": [
        "1. Identify all systems using MD5 for data integrity or authentication",
        "2. Replace MD5 hash functions with SHA-256 or SHA-512 in application code",
        "3. Update database schemas to store longer hash values (SHA-256: 64 chars, SHA-512: 128 chars)",
        "4. Regenerate all stored hashes using the new algorithm",
        "5. Update API clients and consumers to use new hash format",
        "6. Test thoroughly before deploying to production"
    ],
    "timeline": "Immediate - within 30 days",
    "resources": [
        "https://csrc.nist.gov/publications/detail/fips/180/4/final",
        "https://nvd.nist.gov/vuln/detail/CVE-2004-2761"
    ]
}'::jsonb WHERE code = 'MD5';

UPDATE algorithms SET remediation_guidance = '{
    "summary": "SHA-1 is deprecated due to collision attacks and should be replaced.",
    "impact": "MEDIUM - SHA-1 collisions have been demonstrated, making it unsuitable for security applications.",
    "steps": [
        "1. Audit all systems using SHA-1 for digital signatures or certificates",
        "2. Plan migration to SHA-256 (most common) or SHA-384/SHA-512 for higher security",
        "3. For TLS certificates, request new certificates with SHA-256 signatures",
        "4. Update code signing certificates to SHA-256",
        "5. Update password hashing to bcrypt, scrypt, or Argon2 (not just SHA-256)",
        "6. Test all integrations that may depend on SHA-1"
    ],
    "timeline": "High priority - within 90 days",
    "resources": [
        "https://csrc.nist.gov/projects/hash-functions",
        "https://shattered.io/"
    ]
}'::jsonb WHERE code = 'SHA1';

-- Symmetric Encryption
UPDATE algorithms SET remediation_guidance = '{
    "summary": "DES provides only 56-bit security and can be broken in hours.",
    "impact": "CRITICAL - DES encryption can be brute-forced using modern hardware.",
    "steps": [
        "1. Identify all systems and applications using DES encryption",
        "2. Replace DES with AES-256-GCM for symmetric encryption needs",
        "3. Re-encrypt stored data using AES-256",
        "4. Update key management systems for 256-bit keys",
        "5. Update legacy protocols that may require DES",
        "6. Verify compliance with PCI-DSS and other standards"
    ],
    "timeline": "Critical - within 14 days",
    "resources": [
        "https://csrc.nist.gov/publications/detail/fips/197/final",
        "https://nvd.nist.gov/vuln/detail/CVE-2016-2183"
    ]
}'::jsonb WHERE code = 'DES';

UPDATE algorithms SET remediation_guidance = '{
    "summary": "3DES (Triple DES) is deprecated and vulnerable to Sweet32 attacks.",
    "impact": "MEDIUM - 64-bit block size makes 3DES vulnerable to birthday attacks after 2^32 blocks.",
    "steps": [
        "1. Inventory all systems using 3DES/TDEA",
        "2. Plan migration to AES-256-GCM (preferred) or AES-128-GCM",
        "3. Update TLS configurations to disable 3DES cipher suites",
        "4. Re-encrypt data at rest using AES",
        "5. Update VPN and legacy system configurations",
        "6. Test payment processing systems that may use 3DES"
    ],
    "timeline": "High priority - within 60 days",
    "resources": [
        "https://sweet32.info/",
        "https://csrc.nist.gov/publications/detail/sp/800-67/rev-2/final"
    ]
}'::jsonb WHERE code = '3DES';

UPDATE algorithms SET remediation_guidance = '{
    "summary": "RC4 is cryptographically broken and banned in TLS.",
    "impact": "CRITICAL - Multiple attacks (RC4 NOMORE, Bar Mitzvah) can decrypt TLS traffic.",
    "steps": [
        "1. Disable all RC4 cipher suites in TLS/SSL configurations",
        "2. Update web servers: Apache, Nginx, IIS to exclude RC4",
        "3. Update load balancers and reverse proxies",
        "4. Verify clients support AES-GCM or ChaCha20-Poly1305",
        "5. Test all encrypted connections after disabling RC4",
        "6. Update legacy applications that may require RC4"
    ],
    "timeline": "Critical - within 7 days",
    "resources": [
        "https://www.rc4nomore.com/",
        "https://tools.ietf.org/html/rfc7465"
    ]
}'::jsonb WHERE code = 'RC4';

-- Protocol Versions
UPDATE algorithms SET remediation_guidance = '{
    "summary": "TLS 1.0 has known vulnerabilities (BEAST, POODLE) and is non-compliant with PCI-DSS.",
    "impact": "HIGH - Active attacks can decrypt TLS 1.0 traffic in certain scenarios.",
    "steps": [
        "1. Enable TLS 1.2 and TLS 1.3 on all servers before disabling TLS 1.0",
        "2. Configure servers to prefer TLS 1.3, then TLS 1.2",
        "3. Test client compatibility - most modern clients support TLS 1.2+",
        "4. Update legacy clients that only support TLS 1.0",
        "5. Disable TLS 1.0 in server configurations",
        "6. Verify PCI-DSS compliance scan passes"
    ],
    "timeline": "High priority - within 30 days for PCI compliance",
    "resources": [
        "https://www.pcisecuritystandards.org/documents/Migrating-from-SSL-Early-TLS-Info-Supp-v1_1.pdf",
        "https://wiki.mozilla.org/Security/Server_Side_TLS"
    ]
}'::jsonb WHERE code = 'TLS1.0';

UPDATE algorithms SET remediation_guidance = '{
    "summary": "TLS 1.1 is deprecated and does not support modern AEAD cipher suites.",
    "impact": "MEDIUM - TLS 1.1 lacks support for authenticated encryption modes.",
    "steps": [
        "1. Verify TLS 1.2 and TLS 1.3 are enabled before disabling TLS 1.1",
        "2. Configure cipher suite order to prefer AEAD ciphers",
        "3. Test client compatibility - most browsers dropped TLS 1.1 support",
        "4. Update any legacy integrations requiring TLS 1.1",
        "5. Disable TLS 1.1 in server configurations",
        "6. Document exceptions for legacy systems requiring TLS 1.1"
    ],
    "timeline": "Medium priority - within 60 days",
    "resources": [
        "https://blog.mozilla.org/security/2018/10/15/removing-old-versions-of-tls/",
        "https://tools.ietf.org/html/rfc8996"
    ]
}'::jsonb WHERE code = 'TLS1.1';

UPDATE algorithms SET remediation_guidance = '{
    "summary": "SSL 3.0 is obsolete and vulnerable to POODLE attack.",
    "impact": "CRITICAL - SSL 3.0 can be fully decrypted using the POODLE attack.",
    "steps": [
        "1. Immediately disable SSL 3.0 on all servers",
        "2. No client supports only SSL 3.0 - this is safe to disable",
        "3. Update server configurations: Apache, Nginx, IIS, etc.",
        "4. Update load balancers and reverse proxies",
        "5. Scan network for any remaining SSL 3.0 endpoints",
        "6. Update firewall rules to block SSL 3.0 if possible"
    ],
    "timeline": "Critical - immediate action required",
    "resources": [
        "https://www.openssl.org/~bodo/ssl-poodle.pdf",
        "https://tools.ietf.org/html/rfc7568"
    ]
}'::jsonb WHERE code = 'SSLv3';

UPDATE algorithms SET remediation_guidance = '{
    "summary": "SSL 2.0 is completely broken and must never be used.",
    "impact": "CRITICAL - SSL 2.0 has multiple critical vulnerabilities including DROWN.",
    "steps": [
        "1. Immediately disable SSL 2.0 on all systems",
        "2. Check for SSLv2 support: openssl s_client -ssl2 -connect host:port",
        "3. Update all server configurations to explicitly disable SSLv2",
        "4. Ensure private keys are not shared with SSLv2-enabled servers (DROWN)",
        "5. Scan entire network for SSLv2-enabled services",
        "6. Replace any systems that cannot disable SSLv2"
    ],
    "timeline": "Critical - immediate action required",
    "resources": [
        "https://drownattack.com/",
        "https://tools.ietf.org/html/rfc6176"
    ]
}'::jsonb WHERE code = 'SSLv2';

-- Key Exchange Algorithms
UPDATE algorithms SET remediation_guidance = '{
    "summary": "1024-bit RSA keys are too weak and can be factored with sufficient resources.",
    "impact": "HIGH - 1024-bit RSA provides insufficient security margin.",
    "steps": [
        "1. Generate new 2048-bit (minimum) or 4096-bit RSA key pairs",
        "2. Request new certificates with larger key sizes",
        "3. Update all services to use new certificates",
        "4. Revoke old certificates with 1024-bit keys",
        "5. Update code signing certificates",
        "6. Consider migrating to ECDSA P-256 for better performance"
    ],
    "timeline": "High priority - within 30 days",
    "resources": [
        "https://www.keylength.com/",
        "https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final"
    ]
}'::jsonb WHERE code = 'RSA-1024';

UPDATE algorithms SET remediation_guidance = '{
    "summary": "1024-bit Diffie-Hellman is vulnerable to Logjam attack.",
    "impact": "HIGH - State-level adversaries can break 1024-bit DH in real-time.",
    "steps": [
        "1. Generate new DH parameters with at least 2048-bit modulus",
        "2. Configure servers to use ECDHE instead of DHE where possible",
        "3. Update TLS configurations to disable weak DH groups",
        "4. Test with SSL Labs to verify DH parameter strength",
        "5. Update VPN configurations to use stronger DH groups",
        "6. Consider migrating to X25519 for key exchange"
    ],
    "timeline": "High priority - within 30 days",
    "resources": [
        "https://weakdh.org/",
        "https://wiki.mozilla.org/Security/Server_Side_TLS"
    ]
}'::jsonb WHERE code = 'DH-1024';

-- =================================================================
-- Summary and Validation
-- =================================================================

-- =================================================================
-- Seed Complete Verification
-- =================================================================

DO $$
DECLARE
    platform_user_count INTEGER;
    platform_role_count INTEGER;
    algorithm_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO platform_user_count FROM platform_users WHERE is_active = true;
    SELECT COUNT(*) INTO platform_role_count FROM platform_roles;
    SELECT COUNT(*) INTO algorithm_count FROM algorithms;

    RAISE NOTICE '=== Tier 1 Core Seed Data Loaded ===';
    RAISE NOTICE 'Platform Users: %', platform_user_count;
    RAISE NOTICE 'Platform Roles: %', platform_role_count;
    RAISE NOTICE 'Algorithm Taxonomy: % algorithms', algorithm_count;
    RAISE NOTICE '';
    RAISE NOTICE 'Note: Tenant roles are created dynamically when tenants are onboarded.';
    RAISE NOTICE 'Note: Report templates are seeded by the report-generator service on startup.';
    RAISE NOTICE '      If templates are missing, ensure report-generator service has started.';
    RAISE NOTICE 'For demo data, run: ./scripts/database/load-demo-data.sh';
    RAISE NOTICE '====================================';
END $$;

-- -----------------------------------------------------------------
-- Measurement Templates (from 29-seed-measurement-templates.sql)
-- -----------------------------------------------------------------

DO $$
DECLARE
    tls_version_mt_id UUID;
    cert_expiration_mt_id UUID;
    key_size_mt_id UUID;
    pfs_support_mt_id UUID;
    hash_algorithm_mt_id UUID;
    key_exchange_mt_id UUID;
    symmetric_encryption_mt_id UUID;
    platform_admin_id UUID;
BEGIN
    -- Get measurement type IDs
    SELECT id INTO tls_version_mt_id FROM measurement_types WHERE code = 'tls_version';
    SELECT id INTO cert_expiration_mt_id FROM measurement_types WHERE code = 'cert_expiration_days';
    SELECT id INTO key_size_mt_id FROM measurement_types WHERE code = 'key_size';
    SELECT id INTO pfs_support_mt_id FROM measurement_types WHERE code = 'pfs_support';
    SELECT id INTO hash_algorithm_mt_id FROM measurement_types WHERE code = 'hash_algorithm';
    SELECT id INTO key_exchange_mt_id FROM measurement_types WHERE code = 'key_exchange_algorithm';
    SELECT id INTO symmetric_encryption_mt_id FROM measurement_types WHERE code = 'symmetric_encryption';

    -- Prefer a platform user as created_by, but allow NULL
    -- NOTE: measurement_templates.created_by currently references users(id),
    -- so we intentionally use NULL here to avoid cross-table FK mismatches.
    SELECT NULL::uuid INTO platform_admin_id;

    -- Template 1: TLS 1.2+ Required
    IF tls_version_mt_id IS NOT NULL THEN
        INSERT INTO measurement_templates (
            id, code, name, description, measurement_type_id, rule_type, predicate,
            category, framework_tags, version, is_active, created_by, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            'tls-1.2-required',
            'TLS 1.2+ Required',
            'Requires TLS 1.2 or higher. TLS 1.0 and 1.1 are prohibited.',
            tls_version_mt_id,
            'pattern',
            '{"pattern": "^(TLS.?1\\.0|TLS.?1\\.1|1\\.0|1\\.1|SSL.?[23](\\.0)?|Unknown-0x0300|Unknown-0x0002)$", "flags": "i", "match_means_violation": true}'::jsonb,
            'tls',
            ARRAY['SOC2', 'PCI-DSS', 'NIST']::text[],
            1,
            true,
            NULL,
            NOW(),
            NOW()
        ) ON CONFLICT (code) DO NOTHING;
    END IF;

    -- Template 2: Certificate Expiration Warning (30 days)
    IF cert_expiration_mt_id IS NOT NULL THEN
        INSERT INTO measurement_templates (
            id, code, name, description, measurement_type_id, rule_type, predicate,
            category, framework_tags, version, is_active, created_by, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            'cert-expiration-30-days',
            'Certificate Expiration Warning',
            'Certificates must have at least 30 days remaining before expiration.',
            cert_expiration_mt_id,
            'threshold',
            '{"operator": ">=", "value": 30}'::jsonb,
            'certificate',
            ARRAY['SOC2', 'PCI-DSS', 'NIST', 'ISO27001']::text[],
            1,
            true,
            NULL,
            NOW(),
            NOW()
        ) ON CONFLICT (code) DO NOTHING;
    END IF;

    -- Template 3: Minimum Key Size RSA (2048 bits)
    IF key_size_mt_id IS NOT NULL THEN
        INSERT INTO measurement_templates (
            id, code, name, description, measurement_type_id, rule_type, predicate,
            category, framework_tags, version, is_active, created_by, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            'min-key-size-rsa-2048',
            'Minimum RSA Key Size 2048 bits',
            'RSA keys must be at least 2048 bits.',
            key_size_mt_id,
            'threshold',
            '{"operator": ">=", "value": 2048}'::jsonb,
            'certificate',
            ARRAY['SOC2', 'PCI-DSS', 'NIST']::text[],
            1,
            true,
            NULL,
            NOW(),
            NOW()
        ) ON CONFLICT (code) DO NOTHING;
    END IF;

    -- Template 4: PFS Required
    IF pfs_support_mt_id IS NOT NULL THEN
        INSERT INTO measurement_templates (
            id, code, name, description, measurement_type_id, rule_type, predicate,
            category, framework_tags, version, is_active, created_by, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            'pfs-required',
            'Perfect Forward Secrecy Required',
            'All TLS connections must support Perfect Forward Secrecy (PFS).',
            pfs_support_mt_id,
            'presence',
            '{"exists": true}'::jsonb,
            'tls',
            ARRAY['SOC2', 'NIST']::text[],
            1,
            true,
            NULL,
            NOW(),
            NOW()
        ) ON CONFLICT (code) DO NOTHING;
    END IF;

    -- Template 5: SHA256+ Hash Required
    IF hash_algorithm_mt_id IS NOT NULL THEN
        INSERT INTO measurement_templates (
            id, code, name, description, measurement_type_id, rule_type, predicate,
            category, framework_tags, version, is_active, created_by, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            'sha256-hash-required',
            'SHA256+ Hash Algorithm Required',
            'Hash algorithms must be SHA256 or stronger. SHA1 and MD5 are prohibited.',
            hash_algorithm_mt_id,
            'pattern',
            '{"pattern": "^(SHA1|MD5)$", "flags": "i", "match_means_violation": true}'::jsonb,
            'cipher',
            ARRAY['SOC2', 'PCI-DSS', 'NIST']::text[],
            1,
            true,
            NULL,
            NOW(),
            NOW()
        ) ON CONFLICT (code) DO NOTHING;
    END IF;

    -- Template 6: Strong Key Exchange (ECDHE/DHE only)
    IF key_exchange_mt_id IS NOT NULL THEN
        INSERT INTO measurement_templates (
            id, code, name, description, measurement_type_id, rule_type, predicate,
            category, framework_tags, version, is_active, created_by, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            'strong-key-exchange-only',
            'Strong Key Exchange Required',
            'Key exchange must use ECDHE or DHE. Static RSA is vulnerable and should be avoided.',
            key_exchange_mt_id,
            'pattern',
            '{"pattern": "^(RSA|NULL|ECDH(_[A-Z0-9]+)*|DH(_[A-Z0-9]+)*)$", "flags": "i", "match_means_violation": true}'::jsonb,
            'cipher',
            ARRAY['SOC2', 'NIST']::text[],
            1,
            true,
            NULL,
            NOW(),
            NOW()
        ) ON CONFLICT (code) DO NOTHING;
    END IF;

    -- Template 7: Strong Symmetric Encryption (AES-256 or ChaCha20)
    IF symmetric_encryption_mt_id IS NOT NULL THEN
        INSERT INTO measurement_templates (
            id, code, name, description, measurement_type_id, rule_type, predicate,
            category, framework_tags, version, is_active, created_by, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            'strong-symmetric-encryption',
            'Strong Symmetric Encryption Required',
            'Symmetric encryption must be AES-256-GCM, AES-256-CBC, or ChaCha20-Poly1305. Weak ciphers (3DES, DES, RC4) are prohibited.',
            symmetric_encryption_mt_id,
            'pattern',
            '{"pattern": "^(3DES|DES|RC4)(-[A-Z0-9]+)*$", "flags": "i", "match_means_violation": true}'::jsonb,
            'cipher',
            ARRAY['SOC2', 'PCI-DSS', 'NIST']::text[],
            1,
            true,
            platform_admin_id,
            NOW(),
            NOW()
        ) ON CONFLICT (code) DO NOTHING;
    END IF;

END $$;

-- -----------------------------------------------------------------
-- Platform Frameworks (Best Practices, SOC2, PCI, ISO 27001, NIST)
-- -----------------------------------------------------------------

-- Best Practices Framework (Migration 33)
DO $$
DECLARE
    best_practices_framework_id UUID;
    platform_admin_id UUID;

    -- Control IDs (will be populated as we create controls)
    control_tls_version_id UUID;
    control_cert_expiration_id UUID;
    control_weak_cipher_id UUID;
    control_pfs_id UUID;
    control_key_size_id UUID;
    control_deprecated_protocol_id UUID;
    control_cert_chain_id UUID;
    control_hash_algorithm_id UUID;
    control_key_exchange_id UUID;
    control_symmetric_encryption_id UUID;
    control_ot_unencrypted_id UUID;

    -- Measurement type IDs
    tls_version_mt_id UUID;
    cert_expiration_mt_id UUID;
    key_size_mt_id UUID;
    key_size_ec_mt_id UUID;
    pfs_support_mt_id UUID;
    hash_algorithm_mt_id UUID;
    key_exchange_mt_id UUID;
    symmetric_encryption_mt_id UUID;
    cert_chain_valid_mt_id UUID;
    ot_protocol_encryption_mt_id UUID;

    -- Measurement template IDs (for reference, we'll use measurement types directly)
    tls_template_id UUID;
    cert_exp_template_id UUID;
    key_size_template_id UUID;
    pfs_template_id UUID;
    hash_template_id UUID;
    key_exchange_template_id UUID;
    symmetric_template_id UUID;
BEGIN
    -- Get platform admin user ID (optional). Frameworks use platform_users
    -- for created_by/published_by to match platform_frameworks schema.
    SELECT id INTO platform_admin_id
    FROM platform_users
    WHERE email IN ('admin@vistaplatform.invalid', 'su_admin@vistaplatform.invalid')
      AND deleted_at IS NULL
    ORDER BY created_at ASC
    LIMIT 1;

    -- Validate measurement_types table exists and has data
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'measurement_types') THEN
        RAISE EXCEPTION 'measurement_types table does not exist. Schema must be applied before seeding frameworks.';
    END IF;

    -- Get measurement type IDs
    SELECT id INTO tls_version_mt_id FROM measurement_types WHERE code = 'tls_version';
    SELECT id INTO cert_expiration_mt_id FROM measurement_types WHERE code = 'cert_expiration_days';
    SELECT id INTO key_size_mt_id FROM measurement_types WHERE code = 'key_size';
    SELECT id INTO pfs_support_mt_id FROM measurement_types WHERE code = 'pfs_support';
    SELECT id INTO hash_algorithm_mt_id FROM measurement_types WHERE code = 'hash_algorithm';
    SELECT id INTO key_exchange_mt_id FROM measurement_types WHERE code = 'key_exchange_algorithm';
    SELECT id INTO symmetric_encryption_mt_id FROM measurement_types WHERE code = 'symmetric_encryption';
    SELECT id INTO cert_chain_valid_mt_id FROM measurement_types WHERE code = 'certificate_chain_valid';
    SELECT id INTO ot_protocol_encryption_mt_id FROM measurement_types WHERE code = 'ot_protocol_encryption';
    SELECT id INTO key_size_ec_mt_id FROM measurement_types WHERE code = 'key_size_ec';

    -- Warn if critical measurement types are missing
    IF tls_version_mt_id IS NULL THEN
        RAISE WARNING 'CRITICAL: measurement_types.tls_version not found - Best Practices framework controls will be skipped';
    END IF;
    IF cert_expiration_mt_id IS NULL THEN
        RAISE WARNING 'CRITICAL: measurement_types.cert_expiration_days not found - Certificate controls will be skipped';
    END IF;
    IF key_size_mt_id IS NULL THEN
        RAISE WARNING 'CRITICAL: measurement_types.key_size not found - Key size controls will be skipped';
    END IF;
    IF symmetric_encryption_mt_id IS NULL THEN
        RAISE WARNING 'CRITICAL: measurement_types.symmetric_encryption not found - Cipher controls will be skipped';
    END IF;

    -- Check if we have minimum required types to create frameworks
    IF tls_version_mt_id IS NULL AND cert_expiration_mt_id IS NULL AND key_size_mt_id IS NULL THEN
        RAISE EXCEPTION 'CRITICAL: No required measurement_types found. Framework seeding cannot proceed. Ensure schema.sql has been applied and measurement_types are populated.';
    END IF;

    -- Create Best Practices framework
    INSERT INTO platform_frameworks (
        id, code, name, version, description, organization, status,
        is_platform_default, published_at, published_by, created_by, created_at, updated_at
    ) VALUES (
        gen_random_uuid(),
        'best-practices',
        'Security Best Practices',
        '1.0',
        'Core security best practices for cryptographic configurations. Available to all subscription tiers. Covers TLS configuration, certificate management, cipher selection, and key management.',
        'Vista Platform',
        'published',
        true,
        NOW(),
        COALESCE(platform_admin_id, '00000000-0000-0000-0000-000000000001'::uuid),
        COALESCE(platform_admin_id, '00000000-0000-0000-0000-000000000001'::uuid),
        NOW(),
        NOW()
    )
    ON CONFLICT (code, version) DO UPDATE SET
        is_platform_default = true,
        status = 'published',
        updated_at = NOW()
    RETURNING id INTO best_practices_framework_id;

    IF best_practices_framework_id IS NULL THEN
        RAISE WARNING 'Failed to create Best Practices framework (may already exist)';
    ELSE
        RAISE NOTICE 'Created Best Practices framework (id: %)', best_practices_framework_id;
    END IF;

    -- Control 1: TLS Version Requirements
    INSERT INTO platform_framework_controls (
        id, framework_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at
    ) VALUES (
        gen_random_uuid(),
        best_practices_framework_id,
        'BP-001',
        'TLS Version Requirements',
        'All TLS connections must use TLS 1.2 or higher. TLS 1.0 and TLS 1.1 are deprecated and must not be used.',
        'High',
        true,
        NOW(),
        NOW()
    )
    ON CONFLICT (framework_id, control_id) DO UPDATE SET
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        baseline_severity = EXCLUDED.baseline_severity,
        updated_at = NOW()
    RETURNING id INTO control_tls_version_id;

    -- Control 2: Certificate Expiration Monitoring
    INSERT INTO platform_framework_controls (
        id, framework_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at
    ) VALUES (
        gen_random_uuid(),
        best_practices_framework_id,
        'BP-002',
        'Certificate Expiration Monitoring',
        'Certificates must have at least 30 days remaining before expiration. Certificates expiring within 30 days should be renewed immediately.',
        'Med',
        true,
        NOW(),
        NOW()
    )
    ON CONFLICT (framework_id, control_id) DO UPDATE SET
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        baseline_severity = EXCLUDED.baseline_severity,
        updated_at = NOW()
    RETURNING id INTO control_cert_expiration_id;

    -- Control 3: Weak Cipher Detection
    INSERT INTO platform_framework_controls (
        id, framework_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at
    ) VALUES (
        gen_random_uuid(),
        best_practices_framework_id,
        'BP-003',
        'Weak Cipher Detection',
        'Weak and deprecated ciphers (3DES, DES, RC4) must not be used. Only modern, secure cipher suites should be enabled.',
        'High',
        true,
        NOW(),
        NOW()
    )
    ON CONFLICT (framework_id, control_id) DO UPDATE SET
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        baseline_severity = EXCLUDED.baseline_severity,
        updated_at = NOW()
    RETURNING id INTO control_weak_cipher_id;

    -- Control 4: Perfect Forward Secrecy
    INSERT INTO platform_framework_controls (
        id, framework_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at
    ) VALUES (
        gen_random_uuid(),
        best_practices_framework_id,
        'BP-004',
        'Perfect Forward Secrecy Support',
        'All TLS connections should support Perfect Forward Secrecy (PFS) to protect past communications even if private keys are compromised.',
        'Med',
        true,
        NOW(),
        NOW()
    )
    ON CONFLICT (framework_id, control_id) DO UPDATE SET
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        baseline_severity = EXCLUDED.baseline_severity,
        updated_at = NOW()
    RETURNING id INTO control_pfs_id;

    -- Control 5: Key Size Requirements
    INSERT INTO platform_framework_controls (
        id, framework_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at
    ) VALUES (
        gen_random_uuid(),
        best_practices_framework_id,
        'BP-005',
        'Minimum Key Size Requirements',
        'RSA keys must be at least 2048 bits. ECC keys must be at least 256 bits. Smaller key sizes are cryptographically weak.',
        'High',
        true,
        NOW(),
        NOW()
    )
    ON CONFLICT (framework_id, control_id) DO UPDATE SET
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        baseline_severity = EXCLUDED.baseline_severity,
        updated_at = NOW()
    RETURNING id INTO control_key_size_id;

    -- Control 6: Deprecated Protocol Detection
    INSERT INTO platform_framework_controls (
        id, framework_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at
    ) VALUES (
        gen_random_uuid(),
        best_practices_framework_id,
        'BP-006',
        'Deprecated Protocol Detection',
        'SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1 are deprecated and must not be used. Only TLS 1.2 and TLS 1.3 are acceptable.',
        'Critical',
        true,
        NOW(),
        NOW()
    )
    ON CONFLICT (framework_id, control_id) DO UPDATE SET
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        baseline_severity = EXCLUDED.baseline_severity,
        updated_at = NOW()
    RETURNING id INTO control_deprecated_protocol_id;

    -- Control 7: Certificate Chain Validation
    INSERT INTO platform_framework_controls (
        id, framework_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at
    ) VALUES (
        gen_random_uuid(),
        best_practices_framework_id,
        'BP-007',
        'Certificate Chain Validation',
        'All certificates must have valid certificate chains. Self-signed certificates or broken chains indicate misconfiguration.',
        'Med',
        true,
        NOW(),
        NOW()
    )
    ON CONFLICT (framework_id, control_id) DO UPDATE SET
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        baseline_severity = EXCLUDED.baseline_severity,
        updated_at = NOW()
    RETURNING id INTO control_cert_chain_id;

    -- Control 8: Hash Algorithm Requirements
    INSERT INTO platform_framework_controls (
        id, framework_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at
    ) VALUES (
        gen_random_uuid(),
        best_practices_framework_id,
        'BP-008',
        'Hash Algorithm Requirements',
        'Hash algorithms must be SHA-256 or stronger. SHA-1 and MD5 are cryptographically broken and must not be used.',
        'High',
        true,
        NOW(),
        NOW()
    )
    ON CONFLICT (framework_id, control_id) DO UPDATE SET
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        baseline_severity = EXCLUDED.baseline_severity,
        updated_at = NOW()
    RETURNING id INTO control_hash_algorithm_id;

    -- Control 9: Key Exchange Algorithm
    INSERT INTO platform_framework_controls (
        id, framework_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at
    ) VALUES (
        gen_random_uuid(),
        best_practices_framework_id,
        'BP-009',
        'Secure Key Exchange',
        'Key exchange must use ephemeral methods (ECDHE or DHE). Static RSA key exchange is vulnerable and should be avoided.',
        'Med',
        true,
        NOW(),
        NOW()
    )
    ON CONFLICT (framework_id, control_id) DO UPDATE SET
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        baseline_severity = EXCLUDED.baseline_severity,
        updated_at = NOW()
    RETURNING id INTO control_key_exchange_id;

    -- Control 10: Symmetric Encryption Standards
    INSERT INTO platform_framework_controls (
        id, framework_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at
    ) VALUES (
        gen_random_uuid(),
        best_practices_framework_id,
        'BP-010',
        'Symmetric Encryption Standards',
        'Symmetric encryption must use AES-128 or stronger (AES-256 preferred) or ChaCha20-Poly1305. Weak algorithms (3DES, DES, RC4) are prohibited.',
        'High',
        true,
        NOW(),
        NOW()
    )
    ON CONFLICT (framework_id, control_id) DO UPDATE SET
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        baseline_severity = EXCLUDED.baseline_severity,
        updated_at = NOW()
    RETURNING id INTO control_symmetric_encryption_id;

    -- Now create control_measurements mappings

    -- Control 1: TLS Version - map to tls_version measurement type
    IF tls_version_mt_id IS NOT NULL AND control_tls_version_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=control_tls_version_id AND measurement_type_id=tls_version_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (
            id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            control_tls_version_id,
            'platform',
            tls_version_mt_id,
            'pattern',
            '{"pattern": "^(TLS.?1\\.0|TLS.?1\\.1|1\\.0|1\\.1|SSL.?[23](\\.0)?|Unknown-0x0300|Unknown-0x0002)$", "flags": "i", "match_means_violation": true}'::jsonb,
            'High',
            8,
            NOW(),
            NOW()
        );
    END IF;

    -- Control 2: Certificate Expiration - map to cert_expiration_days measurement type
    IF cert_expiration_mt_id IS NOT NULL AND control_cert_expiration_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=control_cert_expiration_id AND measurement_type_id=cert_expiration_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (
            id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            control_cert_expiration_id,
            'platform',
            cert_expiration_mt_id,
            'threshold',
            '{"operator": ">=", "value": 30}'::jsonb,
            'Med',
            6,
            NOW(),
            NOW()
        );
    END IF;

    -- Control 3: Weak Cipher - map to symmetric_encryption measurement type
    IF symmetric_encryption_mt_id IS NOT NULL AND control_weak_cipher_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=control_weak_cipher_id AND measurement_type_id=symmetric_encryption_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (
            id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            control_weak_cipher_id,
            'platform',
            symmetric_encryption_mt_id,
            'pattern',
            '{"pattern": "^(3DES|DES|RC4)(-[A-Z0-9]+)*$", "flags": "i", "match_means_violation": true}'::jsonb,
            'High',
            8,
            NOW(),
            NOW()
        );
    END IF;

    -- Control 4: PFS Support - map to pfs_support measurement type
    IF pfs_support_mt_id IS NOT NULL AND control_pfs_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=control_pfs_id AND measurement_type_id=pfs_support_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (
            id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            control_pfs_id,
            'platform',
            pfs_support_mt_id,
            'presence',
            -- `exists` states the PASS condition: the property must be PRESENT.
            -- pfs_support is a boolean measurement, so "present" means the value
            -- is true (RuleEvaluator.measurementPresent). The old
            -- `{"exists": false}` said "passes when PFS is absent" — the exact
            -- inverse of the control — and could not fire either way while
            -- booleans were compared against nil/"" (CMP-1).
            '{"exists": true}'::jsonb,
            'Med',
            5,
            NOW(),
            NOW()
        );
    END IF;

    -- Control 5: Key Size — TWO measurements, one per algorithm family.
    -- key_size covers RSA/DSA/DH (floor 2048, SP 800-131A); key_size_ec covers
    -- ECDSA/EdDSA (floor 256, which is 128-bit classical security — stronger
    -- than RSA-2048). A certificate is emitted by exactly one extractor, so the
    -- two measurements never both fire on the same asset. Before the split, the
    -- 2048 rule was applied to every certificate and flagged every P-256 cert
    -- as a weak key (CMP-4).
    IF key_size_mt_id IS NOT NULL AND control_key_size_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=control_key_size_id AND measurement_type_id=key_size_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (
            id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            control_key_size_id,
            'platform',
            key_size_mt_id,
            'threshold',
            '{"operator": ">=", "value": 2048}'::jsonb,
            'High',
            9,
            NOW(),
            NOW()
        );
    END IF;

    IF key_size_ec_mt_id IS NOT NULL AND control_key_size_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=control_key_size_id AND measurement_type_id=key_size_ec_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (
            id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            control_key_size_id,
            'platform',
            key_size_ec_mt_id,
            'threshold',
            '{"operator": ">=", "value": 256}'::jsonb,
            'High',
            9,
            NOW(),
            NOW()
        );
    END IF;

    -- Control 6: Deprecated Protocol - map to tls_version measurement type (same as Control 1, but with Critical severity)
    IF tls_version_mt_id IS NOT NULL AND control_deprecated_protocol_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=control_deprecated_protocol_id AND measurement_type_id=tls_version_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (
            id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            control_deprecated_protocol_id,
            'platform',
            tls_version_mt_id,
            'pattern',
            '{"pattern": "^(TLS.?1\\.0|TLS.?1\\.1|1\\.0|1\\.1|SSL.?[23](\\.0)?|Unknown-0x0300|Unknown-0x0002)$", "flags": "i", "match_means_violation": true}'::jsonb,
            'Critical',
            10,
            NOW(),
            NOW()
        );
    END IF;

    -- Control 7: Certificate Chain - map to certificate_chain_valid measurement type
    IF cert_chain_valid_mt_id IS NOT NULL AND control_cert_chain_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=control_cert_chain_id AND measurement_type_id=cert_chain_valid_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (
            id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            control_cert_chain_id,
            'platform',
            cert_chain_valid_mt_id,
            'presence',
            -- See BP-004 above: `exists: true` = the chain must be valid.
            '{"exists": true}'::jsonb,
            'Med',
            6,
            NOW(),
            NOW()
        );
    END IF;

    -- Control 8: Hash Algorithm - map to hash_algorithm measurement type
    IF hash_algorithm_mt_id IS NOT NULL AND control_hash_algorithm_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=control_hash_algorithm_id AND measurement_type_id=hash_algorithm_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (
            id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            control_hash_algorithm_id,
            'platform',
            hash_algorithm_mt_id,
            'pattern',
            '{"pattern": "^(SHA1|MD5)$", "flags": "i", "match_means_violation": true}'::jsonb,
            'High',
            8,
            NOW(),
            NOW()
        );
    END IF;

    -- Control 9: Key Exchange - map to key_exchange_algorithm measurement type
    IF key_exchange_mt_id IS NOT NULL AND control_key_exchange_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=control_key_exchange_id AND measurement_type_id=key_exchange_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (
            id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            control_key_exchange_id,
            'platform',
            key_exchange_mt_id,
            'pattern',
            '{"pattern": "^(RSA|NULL|ECDH(_[A-Z0-9]+)*|DH(_[A-Z0-9]+)*)$", "flags": "i", "match_means_violation": true}'::jsonb,
            'Med',
            6,
            NOW(),
            NOW()
        );
    END IF;

    -- Control 10: Symmetric Encryption - map to symmetric_encryption measurement type (same as Control 3)
    IF symmetric_encryption_mt_id IS NOT NULL AND control_symmetric_encryption_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=control_symmetric_encryption_id AND measurement_type_id=symmetric_encryption_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (
            id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            control_symmetric_encryption_id,
            'platform',
            symmetric_encryption_mt_id,
            'pattern',
            '{"pattern": "^(3DES|DES|RC4)(-[A-Z0-9]+)*$", "flags": "i", "match_means_violation": true}'::jsonb,
            'High',
            8,
            NOW(),
            NOW()
        );
    END IF;

    -- Control 11: OT Protocol Encryption — flag any industrial protocol session
    -- (Modbus, DNP3, MMS, ICCP, BACnet, EtherNet/IP) that has no cryptographic
    -- protection. Added in PR 1 of the phased OT discovery rollout. Tenants
    -- with no OT assets see zero findings here (extractor returns empty).
    INSERT INTO platform_framework_controls (
        id, framework_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at
    ) VALUES (
        gen_random_uuid(),
        best_practices_framework_id,
        'BP-011',
        'OT Protocol Encryption',
        'Industrial / OT protocol sessions (Modbus, DNP3, MMS, ICCP, BACnet, BACnet/SC, EtherNet/IP CIP, OPC UA, HART-IP, Siemens S7) must use cryptographic protection. Plaintext OT traffic detected on the wire is a high-severity finding for cryptographic asset audits and is non-compliant with NERC CIP and IEC 62443.',
        'High',
        true,
        NOW(),
        NOW()
    )
    ON CONFLICT (framework_id, control_id) DO UPDATE SET
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        baseline_severity = EXCLUDED.baseline_severity,
        updated_at = NOW()
    RETURNING id INTO control_ot_unencrypted_id;

    -- Control 11 measurement: ot_protocol_encryption with pattern "^absent$".
    -- The extractor emits one MeasurementValue per OT crypto_implementation
    -- ("absent" or "present"); pattern match on "absent" produces a finding.
    IF ot_protocol_encryption_mt_id IS NOT NULL AND control_ot_unencrypted_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=control_ot_unencrypted_id AND measurement_type_id=ot_protocol_encryption_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (
            id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            control_ot_unencrypted_id,
            'platform',
            ot_protocol_encryption_mt_id,
            'pattern',
            '{"pattern": "^absent$", "flags": "i", "match_means_violation": true}'::jsonb,
            'High',
            9,
            NOW(),
            NOW()
        );
    END IF;

    -- Summary: Report framework creation status
    IF best_practices_framework_id IS NOT NULL THEN
        RAISE NOTICE '✅ Best Practices framework created successfully with controls';
    ELSE
        RAISE WARNING '⚠️  Best Practices framework creation may have failed - check for errors above';
    END IF;

END $$;

-- =====================================================================
-- Certificate-focused opt-in frameworks (ADR-0015; measurements from).
-- All are status='published' but is_platform_default=false, so they are
-- visible/activatable yet NEVER auto-licensed (auto_license_best_practices()
-- only targets the is_platform_default framework). Activating one is a deliberate
-- tenant choice, so seeding them does not change any tenant's compliance score.
-- Predicate convention (RuleEvaluator.evaluateThreshold/evaluatePattern): for
-- thresholds the operator describes the PASS condition (violation when the
-- comparison is false); a pattern MATCH is a violation. control_measurements has
-- no unique key, so every measurement insert is guarded with IF NOT EXISTS to keep
-- re-seeding idempotent.
-- =====================================================================
DO $$
DECLARE
    platform_admin_id UUID;
    cert_expiration_mt_id UUID;
    key_size_mt_id UUID;
    key_size_ec_mt_id UUID;
    cert_validity_mt_id UUID;
    cert_pqc_mt_id UUID;
    cert_sig_pqc_mt_id UUID;
    config_kex_pqc_mt_id UUID;
    config_sig_pqc_mt_id UUID;
    config_sym_mt_id UUID;
    fw_id UUID;
    ctl_id UUID;
BEGIN
    SELECT NULL::uuid INTO platform_admin_id;
    SELECT id INTO cert_expiration_mt_id FROM measurement_types WHERE code = 'cert_expiration_days';
    SELECT id INTO key_size_mt_id        FROM measurement_types WHERE code = 'key_size';
    SELECT id INTO key_size_ec_mt_id     FROM measurement_types WHERE code = 'key_size_ec';
    SELECT id INTO cert_validity_mt_id   FROM measurement_types WHERE code = 'cert_validity_days';
    SELECT id INTO cert_pqc_mt_id        FROM measurement_types WHERE code = 'cert_pqc_status';
    SELECT id INTO cert_sig_pqc_mt_id    FROM measurement_types WHERE code = 'cert_sig_pqc_status';
    SELECT id INTO config_kex_pqc_mt_id  FROM measurement_types WHERE code = 'config_kex_pqc_status';
    SELECT id INTO config_sig_pqc_mt_id  FROM measurement_types WHERE code = 'config_sig_pqc_status';
    SELECT id INTO config_sym_mt_id      FROM measurement_types WHERE code = 'config_sym_strength';

    -- ===================== Post-Quantum Readiness =====================
    INSERT INTO platform_frameworks (id, code, name, version, description, organization, status, is_platform_default, published_at, published_by, created_by, created_at, updated_at)
    VALUES (gen_random_uuid(), 'pqc-readiness', 'Post-Quantum Readiness', '1.0',
        'Tracks post-quantum exposure across certificates AND crypto-configurations. Quantum (Shor) breaks asymmetric crypto — certificate keys/signatures and config key-exchange/signatures — while symmetric ciphers only lose half their margin (Grover). Activate to inventory quantum-vulnerable crypto and prioritize migration to NIST PQC algorithms (ML-KEM, ML-DSA, SLH-DSA).',
        'Vista Platform', 'published', false, NOW(),
        COALESCE(platform_admin_id, '00000000-0000-0000-0000-000000000001'::uuid),
        COALESCE(platform_admin_id, '00000000-0000-0000-0000-000000000001'::uuid), NOW(), NOW())
    ON CONFLICT (code, version) DO UPDATE SET status='published', is_platform_default=false, description=EXCLUDED.description, updated_at=NOW()
    RETURNING id INTO fw_id;

    INSERT INTO platform_framework_controls (id, framework_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at)
    VALUES (gen_random_uuid(), fw_id, 'PQC-001', 'Quantum-vulnerable certificate algorithm',
        'The certificate uses a public-key algorithm that is not quantum-safe. Plan migration to a NIST post-quantum algorithm.', 'Med', true, NOW(), NOW())
    ON CONFLICT (framework_id, control_id) DO UPDATE SET title=EXCLUDED.title, description=EXCLUDED.description, baseline_severity=EXCLUDED.baseline_severity, updated_at=NOW()
    RETURNING id INTO ctl_id;

    IF cert_pqc_mt_id IS NOT NULL AND ctl_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=ctl_id AND measurement_type_id=cert_pqc_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at)
        VALUES (gen_random_uuid(), ctl_id, 'platform', cert_pqc_mt_id, 'pattern', '{"pattern": "^quantum_vulnerable$", "flags": "i", "match_means_violation": true}'::jsonb, 'Med', 5, NOW(), NOW());
    END IF;

    -- PQC-002: Certificate signature algorithm quantum-vulnerable (the CA's signature over the leaf).
    -- Advisory (Low) — remediation is usually "your CA must issue PQC certs", outside the tenant's direct control.
    INSERT INTO platform_framework_controls (id, framework_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at)
    VALUES (gen_random_uuid(), fw_id, 'PQC-002', 'Quantum-vulnerable certificate signature',
        'The certificate was signed (by its CA) with a classical signature algorithm vulnerable to quantum forgery. Track and raise with your CA; migration depends on the issuer offering PQC signatures.', 'Low', true, NOW(), NOW())
    ON CONFLICT (framework_id, control_id) DO UPDATE SET title=EXCLUDED.title, description=EXCLUDED.description, baseline_severity=EXCLUDED.baseline_severity, updated_at=NOW()
    RETURNING id INTO ctl_id;

    IF cert_sig_pqc_mt_id IS NOT NULL AND ctl_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=ctl_id AND measurement_type_id=cert_sig_pqc_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at)
        VALUES (gen_random_uuid(), ctl_id, 'platform', cert_sig_pqc_mt_id, 'pattern', '{"pattern": "^quantum_vulnerable$", "flags": "i", "match_means_violation": true}'::jsonb, 'Low', 3, NOW(), NOW());
    END IF;

    -- PQC-003: Crypto-config key-exchange quantum-vulnerable. The MOST urgent PQC control —
    -- harvest-now-decrypt-later: traffic captured today is decryptable once a quantum computer exists.
    INSERT INTO platform_framework_controls (id, framework_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at)
    VALUES (gen_random_uuid(), fw_id, 'PQC-003', 'Quantum-vulnerable key exchange',
        'A crypto-configuration negotiates session keys with a classical key-exchange algorithm (RSA/ECDH/DH). This is the highest-priority post-quantum exposure (harvest-now-decrypt-later). Migrate to ML-KEM or a hybrid (e.g. X25519MLKEM768).', 'Critical', true, NOW(), NOW())
    ON CONFLICT (framework_id, control_id) DO UPDATE SET title=EXCLUDED.title, description=EXCLUDED.description, baseline_severity=EXCLUDED.baseline_severity, updated_at=NOW()
    RETURNING id INTO ctl_id;

    IF config_kex_pqc_mt_id IS NOT NULL AND ctl_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=ctl_id AND measurement_type_id=config_kex_pqc_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at)
        VALUES (gen_random_uuid(), ctl_id, 'platform', config_kex_pqc_mt_id, 'pattern', '{"pattern": "^quantum_vulnerable$", "flags": "i", "match_means_violation": true}'::jsonb, 'Critical', 10, NOW(), NOW());
    END IF;

    -- PQC-004: Crypto-config signature/authentication quantum-vulnerable.
    INSERT INTO platform_framework_controls (id, framework_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at)
    VALUES (gen_random_uuid(), fw_id, 'PQC-004', 'Quantum-vulnerable authentication signature',
        'A crypto-configuration authenticates with a classical signature algorithm (RSA/ECDSA/EdDSA) vulnerable to quantum forgery, enabling future impersonation. Migrate to a NIST PQC signature (ML-DSA, SLH-DSA, FN-DSA).', 'High', true, NOW(), NOW())
    ON CONFLICT (framework_id, control_id) DO UPDATE SET title=EXCLUDED.title, description=EXCLUDED.description, baseline_severity=EXCLUDED.baseline_severity, updated_at=NOW()
    RETURNING id INTO ctl_id;

    IF config_sig_pqc_mt_id IS NOT NULL AND ctl_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=ctl_id AND measurement_type_id=config_sig_pqc_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at)
        VALUES (gen_random_uuid(), ctl_id, 'platform', config_sig_pqc_mt_id, 'pattern', '{"pattern": "^quantum_vulnerable$", "flags": "i", "match_means_violation": true}'::jsonb, 'High', 8, NOW(), NOW());
    END IF;

    -- PQC-005: Crypto-config symmetric quantum margin (advisory). Symmetric crypto is only
    -- weakened (not broken) by Grover, so this is Low/advisory: flag < AES-256-equivalent.
    INSERT INTO platform_framework_controls (id, framework_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at)
    VALUES (gen_random_uuid(), fw_id, 'PQC-005', 'Insufficient symmetric quantum margin',
        'A crypto-configuration uses a symmetric cipher below the post-quantum margin (AES-128 or weaker). Grover halves the effective key strength, so AES-256 / ChaCha20 are recommended (CNSA 2.0). Advisory.', 'Low', true, NOW(), NOW())
    ON CONFLICT (framework_id, control_id) DO UPDATE SET title=EXCLUDED.title, description=EXCLUDED.description, baseline_severity=EXCLUDED.baseline_severity, updated_at=NOW()
    RETURNING id INTO ctl_id;

    IF config_sym_mt_id IS NOT NULL AND ctl_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=ctl_id AND measurement_type_id=config_sym_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at)
        VALUES (gen_random_uuid(), ctl_id, 'platform', config_sym_mt_id, 'pattern', '{"pattern": "^quantum_marginal$", "flags": "i", "match_means_violation": true}'::jsonb, 'Low', 2, NOW(), NOW());
    END IF;

    -- ===================== Certificate Hygiene =====================
    INSERT INTO platform_frameworks (id, code, name, version, description, organization, status, is_platform_default, published_at, published_by, created_by, created_at, updated_at)
    VALUES (gen_random_uuid(), 'cert-hygiene', 'Certificate Hygiene', '1.0',
        'Baseline certificate cryptographic hygiene: minimum key size and maximum validity period. Activate to track certificates that fall short of modern issuance standards.',
        'Vista Platform', 'published', false, NOW(),
        COALESCE(platform_admin_id, '00000000-0000-0000-0000-000000000001'::uuid),
        COALESCE(platform_admin_id, '00000000-0000-0000-0000-000000000001'::uuid), NOW(), NOW())
    ON CONFLICT (code, version) DO UPDATE SET status='published', is_platform_default=false, description=EXCLUDED.description, updated_at=NOW()
    RETURNING id INTO fw_id;

    INSERT INTO platform_framework_controls (id, framework_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at)
    VALUES (gen_random_uuid(), fw_id, 'CH-001', 'Minimum certificate key size',
        'Certificate keys must be at least 2048-bit (RSA) / 256-bit (EC) equivalent. Smaller keys are considered weak.', 'High', true, NOW(), NOW())
    ON CONFLICT (framework_id, control_id) DO UPDATE SET title=EXCLUDED.title, description=EXCLUDED.description, baseline_severity=EXCLUDED.baseline_severity, updated_at=NOW()
    RETURNING id INTO ctl_id;

    -- Two family-specific measurements — see BP-005 for why one 2048 rule over
    -- both families is wrong (CMP-4). The control's own text already promised
    -- "2048-bit (RSA) / 256-bit (EC)"; only the measurement said otherwise.
    IF key_size_mt_id IS NOT NULL AND ctl_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=ctl_id AND measurement_type_id=key_size_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at)
        VALUES (gen_random_uuid(), ctl_id, 'platform', key_size_mt_id, 'threshold', '{"operator": ">=", "value": 2048}'::jsonb, 'High', 7, NOW(), NOW());
    END IF;

    IF key_size_ec_mt_id IS NOT NULL AND ctl_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=ctl_id AND measurement_type_id=key_size_ec_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at)
        VALUES (gen_random_uuid(), ctl_id, 'platform', key_size_ec_mt_id, 'threshold', '{"operator": ">=", "value": 256}'::jsonb, 'High', 7, NOW(), NOW());
    END IF;

    INSERT INTO platform_framework_controls (id, framework_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at)
    VALUES (gen_random_uuid(), fw_id, 'CH-002', 'Maximum certificate validity period',
        'Certificate validity period should not exceed 398 days (CA/Browser Forum max; trending toward 47 days). Over-long lifetimes increase exposure when a key is compromised.', 'Med', true, NOW(), NOW())
    ON CONFLICT (framework_id, control_id) DO UPDATE SET title=EXCLUDED.title, description=EXCLUDED.description, baseline_severity=EXCLUDED.baseline_severity, updated_at=NOW()
    RETURNING id INTO ctl_id;

    IF cert_validity_mt_id IS NOT NULL AND ctl_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=ctl_id AND measurement_type_id=cert_validity_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at)
        VALUES (gen_random_uuid(), ctl_id, 'platform', cert_validity_mt_id, 'threshold', '{"operator": "<=", "value": 398}'::jsonb, 'Med', 5, NOW(), NOW());
    END IF;

    -- ===================== Certificate Expiry: Not Expired =====================
    INSERT INTO platform_frameworks (id, code, name, version, description, organization, status, is_platform_default, published_at, published_by, created_by, created_at, updated_at)
    VALUES (gen_random_uuid(), 'cert-expiry-not-expired', 'Certificate Expiry: Not Expired', '1.0',
        'Flags certificates that have already expired. Activate to track and alert on expired certificates in your inventory.',
        'Vista Platform', 'published', false, NOW(),
        COALESCE(platform_admin_id, '00000000-0000-0000-0000-000000000001'::uuid),
        COALESCE(platform_admin_id, '00000000-0000-0000-0000-000000000001'::uuid), NOW(), NOW())
    ON CONFLICT (code, version) DO UPDATE SET status='published', is_platform_default=false, description=EXCLUDED.description, updated_at=NOW()
    RETURNING id INTO fw_id;

    INSERT INTO platform_framework_controls (id, framework_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at)
    VALUES (gen_random_uuid(), fw_id, 'CE-NE-001', 'Certificate must not be expired',
        'The certificate has passed its not_after date and is expired.', 'High', true, NOW(), NOW())
    ON CONFLICT (framework_id, control_id) DO UPDATE SET title=EXCLUDED.title, description=EXCLUDED.description, baseline_severity=EXCLUDED.baseline_severity, updated_at=NOW()
    RETURNING id INTO ctl_id;

    IF cert_expiration_mt_id IS NOT NULL AND ctl_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=ctl_id AND measurement_type_id=cert_expiration_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at)
        VALUES (gen_random_uuid(), ctl_id, 'platform', cert_expiration_mt_id, 'threshold', '{"operator": ">", "value": 0}'::jsonb, 'High', 8, NOW(), NOW());
    END IF;

    -- ===================== Certificate Expiry: 30-Day Notice =====================
    INSERT INTO platform_frameworks (id, code, name, version, description, organization, status, is_platform_default, published_at, published_by, created_by, created_at, updated_at)
    VALUES (gen_random_uuid(), 'cert-expiry-30-day', 'Certificate Expiry: 30-Day Notice', '1.0',
        'Flags certificates expiring within 30 days. Activate for advance renewal warnings.',
        'Vista Platform', 'published', false, NOW(),
        COALESCE(platform_admin_id, '00000000-0000-0000-0000-000000000001'::uuid),
        COALESCE(platform_admin_id, '00000000-0000-0000-0000-000000000001'::uuid), NOW(), NOW())
    ON CONFLICT (code, version) DO UPDATE SET status='published', is_platform_default=false, description=EXCLUDED.description, updated_at=NOW()
    RETURNING id INTO fw_id;

    INSERT INTO platform_framework_controls (id, framework_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at)
    VALUES (gen_random_uuid(), fw_id, 'CE-30-001', 'Certificate expires within 30 days',
        'The certificate has fewer than 30 days of validity remaining and should be renewed.', 'Med', true, NOW(), NOW())
    ON CONFLICT (framework_id, control_id) DO UPDATE SET title=EXCLUDED.title, description=EXCLUDED.description, baseline_severity=EXCLUDED.baseline_severity, updated_at=NOW()
    RETURNING id INTO ctl_id;

    IF cert_expiration_mt_id IS NOT NULL AND ctl_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=ctl_id AND measurement_type_id=cert_expiration_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at)
        VALUES (gen_random_uuid(), ctl_id, 'platform', cert_expiration_mt_id, 'threshold', '{"operator": ">=", "value": 30}'::jsonb, 'Med', 6, NOW(), NOW());
    END IF;

    -- ===================== Certificate Expiry: 90-Day Notice =====================
    INSERT INTO platform_frameworks (id, code, name, version, description, organization, status, is_platform_default, published_at, published_by, created_by, created_at, updated_at)
    VALUES (gen_random_uuid(), 'cert-expiry-90-day', 'Certificate Expiry: 90-Day Notice', '1.0',
        'Flags certificates expiring within 90 days. Activate for early renewal planning.',
        'Vista Platform', 'published', false, NOW(),
        COALESCE(platform_admin_id, '00000000-0000-0000-0000-000000000001'::uuid),
        COALESCE(platform_admin_id, '00000000-0000-0000-0000-000000000001'::uuid), NOW(), NOW())
    ON CONFLICT (code, version) DO UPDATE SET status='published', is_platform_default=false, description=EXCLUDED.description, updated_at=NOW()
    RETURNING id INTO fw_id;

    INSERT INTO platform_framework_controls (id, framework_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at)
    VALUES (gen_random_uuid(), fw_id, 'CE-90-001', 'Certificate expires within 90 days',
        'The certificate has fewer than 90 days of validity remaining; begin renewal planning.', 'Low', true, NOW(), NOW())
    ON CONFLICT (framework_id, control_id) DO UPDATE SET title=EXCLUDED.title, description=EXCLUDED.description, baseline_severity=EXCLUDED.baseline_severity, updated_at=NOW()
    RETURNING id INTO ctl_id;

    IF cert_expiration_mt_id IS NOT NULL AND ctl_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM control_measurements WHERE control_id=ctl_id AND measurement_type_id=cert_expiration_mt_id AND framework_type='platform') THEN
        INSERT INTO control_measurements (id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at)
        VALUES (gen_random_uuid(), ctl_id, 'platform', cert_expiration_mt_id, 'threshold', '{"operator": ">=", "value": 90}'::jsonb, 'Low', 4, NOW(), NOW());
    END IF;

    RAISE NOTICE 'Seeded certificate opt-in frameworks (PQC Readiness, Certificate Hygiene, Expiry: Not-Expired/30/90)';
END $$;

-- =====================================================================
-- Corrections (re-runnable): measurement predicates that could not match
-- what the producers actually emit.
-- =====================================================================
-- Every control_measurement above is inserted under an IF NOT EXISTS guard, so
-- a deployment that seeded before these fixes keeps its ORIGINAL predicate
-- forever. These UPDATEs repair the stored rows in place. Each is keyed on the
-- exact broken predicate, so it is a no-op on a fresh install (already correct)
-- and on a re-run (already repaired), and it will never overwrite a predicate a
-- tenant or admin has since edited to something else.
--
-- Findings CMP-1 / CMP-3 / CMP-5 of the Core audit.

-- CMP-3: weak symmetric ciphers. The old pattern's `RC4-.*` branch was the only
-- one that tolerated a suffix, so `3DES-EDE-CBC` and `DES-CBC` slipped through
-- while nothing matched the bare catalogue codes' suffixed forms. The anchored
-- alternation cannot match AES128/AES256/CHACHA20 (a "DES" branch would, if it
-- were unanchored — hence the leading ^).
UPDATE control_measurements
SET predicate = '{"pattern": "^(3DES|DES|RC4)(-[A-Z0-9]+)*$", "flags": "i", "match_means_violation": true}'::jsonb,
    updated_at = NOW()
WHERE predicate ->> 'pattern' = '^(3DES|DES|RC4|RC4-.*)$';

UPDATE measurement_templates
SET predicate = '{"pattern": "^(3DES|DES|RC4)(-[A-Z0-9]+)*$", "flags": "i", "match_means_violation": true}'::jsonb,
    updated_at = NOW()
WHERE predicate ->> 'pattern' = '^(3DES|DES|RC4|RC4-.*)$';

-- CMP-3: non-PFS key exchange. The old pattern only matched the bare codes, so
-- every compound form the passive sensor emits — `ECDH_RSA`, `DH_DSS`,
-- `ECDH_ECDSA`, … — went unflagged. Those ARE the static suites BP-009 exists
-- to catch. The replacement still must not match the ephemeral `ECDHE*`/`DHE*`
-- forms, which is why the branches are `ECDH(_…)*` / `DH(_…)*` and not a
-- prefix match.
UPDATE control_measurements
SET predicate = '{"pattern": "^(RSA|NULL|ECDH(_[A-Z0-9]+)*|DH(_[A-Z0-9]+)*)$", "flags": "i", "match_means_violation": true}'::jsonb,
    updated_at = NOW()
WHERE predicate ->> 'pattern' = '^(RSA|ECDH|DH|NULL)$';

UPDATE measurement_templates
SET predicate = '{"pattern": "^(RSA|NULL|ECDH(_[A-Z0-9]+)*|DH(_[A-Z0-9]+)*)$", "flags": "i", "match_means_violation": true}'::jsonb,
    updated_at = NOW()
WHERE predicate ->> 'pattern' = '^(RSA|ECDH|DH|NULL)$';

-- CMP-5: deprecated protocols. SSLv3/SSLv2 were absent from the pattern
-- entirely — including the `Unknown-0x0300` / `Unknown-0x0002` spellings the
-- sensor's TLS enricher produces for versions Go's crypto/tls has no name for,
-- which is exactly how SSLv3 reaches the inventory.
UPDATE control_measurements
SET predicate = jsonb_set(predicate, '{pattern}',
        '"^(TLS.?1\\.0|TLS.?1\\.1|1\\.0|1\\.1|SSL.?[23](\\.0)?|Unknown-0x0300|Unknown-0x0002)$"'::jsonb),
    updated_at = NOW()
WHERE predicate ->> 'pattern' = '^(TLS.?1\.0|TLS.?1\.1|1\.0|1\.1)$';

UPDATE measurement_templates
SET predicate = jsonb_set(predicate, '{pattern}',
        '"^(TLS.?1\\.0|TLS.?1\\.1|1\\.0|1\\.1|SSL.?[23](\\.0)?|Unknown-0x0300|Unknown-0x0002)$"'::jsonb),
    updated_at = NOW()
WHERE predicate ->> 'pattern' = '^(TLS.?1\.0|TLS.?1\.1|1\.0|1\.1)$';

-- CMP-4: `key_size` used to mean "any certificate's key size" and carried the
-- 2048-bit floor for all of them. It is now the finite-field (RSA/DSA/DH)
-- measurement, with `key_size_ec` alongside it for the elliptic-curve family.
-- measurement_types is seeded ON CONFLICT DO NOTHING, so the renamed row needs
-- an explicit update on existing deployments. Keyed on the old text.
UPDATE measurement_types
SET name = 'Key Size (RSA/DSA/DH)',
    description = 'Cryptographic key size in bits for the finite-field family (RSA, DSA, Diffie-Hellman). Minimum 2048 bits (NIST SP 800-131A).',
    updated_at = NOW()
WHERE code = 'key_size'
  AND description = 'Cryptographic key size in bits';

-- CMP-1: boolean presence predicates were inverted. `exists` states the PASS
-- condition, so BP-004 ("PFS must be supported") and BP-007 ("chain must be
-- valid") needed `exists: true`. They shipped `exists: false`, which reads as
-- "passes when the property is missing" — and, because the evaluator compared
-- booleans against nil/"" and so treated every boolean as present, produced a
-- violation on every asset regardless of its crypto. Scoped by measurement type
-- so it cannot touch a presence rule that legitimately wants `exists: false`.
UPDATE control_measurements cm
SET predicate = '{"exists": true}'::jsonb,
    updated_at = NOW()
FROM measurement_types mt
WHERE mt.id = cm.measurement_type_id
  AND mt.code IN ('pfs_support', 'certificate_chain_valid')
  AND cm.rule_type = 'presence'
  AND cm.predicate = '{"exists": false, "match_means_violation": true}'::jsonb;

-- =====================================================================
-- Regulated compliance frameworks live in the Enterprise content bundle
-- =====================================================================
-- SOC 2 Type 2, PCI-DSS 4.0, ISO/IEC 27001:2022, NIST CSF 1.1 and
-- IEC 62351-3 are Enterprise content. They are no longer seeded here; the
-- Helm chart applies them from a separately signed content bundle when
-- `enterprise.contentBundle.enabled=true`.
--
-- Core seeds six frameworks, all of them free and all of them above:
--   best-practices (platform default, auto-licensed), pqc-readiness,
--   cert-hygiene, cert-expiry-not-expired, cert-expiry-30-day,
--   cert-expiry-90-day.
--
-- Nothing below depends on the regulated frameworks: the auto-license
-- triggers in schema.sql look their frameworks up by code and no-op when the
-- row is absent, so a Core install is complete and consistent without them.
-- =====================================================================

-- Final summary of framework seeding.
--
-- Counts only the six FREE frameworks Core is responsible for. It deliberately
-- does NOT count all published frameworks: an Enterprise install also carries
-- the regulated content bundle, so a total count would differ by edition and
-- could not be asserted here.
DO $$
DECLARE
    free_framework_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO free_framework_count
    FROM platform_frameworks
    WHERE status = 'published'
      AND code IN ('best-practices', 'pqc-readiness', 'cert-hygiene',
                   'cert-expiry-not-expired', 'cert-expiry-30-day', 'cert-expiry-90-day');

    IF free_framework_count = 6 THEN
        RAISE NOTICE '✅ Framework seeding complete: all 6 free frameworks published';
    ELSIF free_framework_count > 0 THEN
        RAISE WARNING '⚠️  Framework seeding incomplete: only % of 6 free frameworks published', free_framework_count;
        RAISE WARNING '   Check logs above for missing measurement_types or other errors';
    ELSE
        RAISE EXCEPTION 'CRITICAL: No frameworks were created! Check that measurement_types table exists and is populated.';
    END IF;
END $$;

-- =================================================================
-- RBAC Initialization (consolidated from ensure-rbac-initialization.sql)
-- =================================================================
-- Ensures platform admin user and tenant roles/permissions for all tenants.
-- Idempotent; safe to run as part of Tier 1 seed.

-- Ensure Platform Admin User Configuration
DO $$
DECLARE
    super_admin_role_id UUID;
    admin_user_id UUID;
    permission_count INTEGER;
BEGIN
    SELECT id INTO super_admin_role_id FROM platform_roles WHERE name = 'super_admin' LIMIT 1;
    IF super_admin_role_id IS NULL THEN
        RAISE EXCEPTION 'super_admin role not found. Platform roles must be created first.';
    END IF;

    SELECT id INTO admin_user_id FROM platform_users WHERE email = 'su_admin@vistaplatform.invalid' LIMIT 1;
    IF admin_user_id IS NULL THEN
        -- SECURITY: this is a fallback path (the canonical super_admin INSERT
        -- earlier in this file normally wins), but it must seed the SAME
        -- published hash and force_password_change = true as that one.
        --
        -- It previously carried a THIRD, distinct Argon2id hash and omitted
        -- force_password_change entirely -- and the column defaults to false.
        -- Any cluster that reached this branch would therefore get a super_admin
        -- whose published default password grants a FULL session, and whose hash
        -- was absent from the "still on the default password" remediation UPDATE
        -- above, so nothing would ever force it to rotate.
        INSERT INTO platform_users (id, email, password_hash, first_name, last_name, role_id, is_active, email_verified, force_password_change)
        VALUES (
            '00000000-0000-0000-0000-000000000001',
            'su_admin@vistaplatform.invalid',
            '$argon2id$v=19$m=65536,t=3,p=2$4RwIVrBNkLem0R8ROlv4Ow$GPQNlbYkh6VHvxmSREntWjyw/xIRCRSaNEVzli1M+cc',
            'Platform', 'Administrator', super_admin_role_id, true, true, true
        )
        RETURNING id INTO admin_user_id;
        RAISE NOTICE '✅ Created su_admin@vistaplatform.invalid user with super_admin role';
    ELSE
        UPDATE platform_users
        SET role_id = super_admin_role_id, is_active = true, email_verified = true, deleted_at = NULL, updated_at = NOW()
        WHERE id = admin_user_id AND (role_id IS NULL OR role_id != super_admin_role_id OR deleted_at IS NOT NULL OR NOT is_active OR NOT email_verified);
        IF FOUND THEN RAISE NOTICE '✅ Updated su_admin@vistaplatform.invalid to super_admin role'; END IF;
    END IF;

    SELECT COUNT(*) INTO permission_count
    FROM platform_users pu
    JOIN platform_roles pr ON pu.role_id = pr.id
    JOIN platform_role_permissions prp ON pr.id = prp.role_id
    WHERE pu.email = 'su_admin@vistaplatform.invalid' AND pr.name = 'super_admin';
    IF permission_count = 0 THEN
        RAISE WARNING '⚠️  Admin user may not have all permissions - verify platform_role_permissions assignments';
    ELSE
        RAISE NOTICE '✅ Verified su_admin@vistaplatform.invalid has super_admin role with % permissions', permission_count;
    END IF;
END $$;

-- Ensure Tenant Roles for All Tenants (idempotent)
--
-- IMPORTANT: This block is the source of truth for system tenant roles and
-- their permission grants. It is mirrored by Go code in
-- services/auth-service/internal/auth/service.go (ensureTenantRoles /
-- assignRolePermissions). Any filter change here MUST be applied in both
-- places — that is the path new tenants take when they're onboarded
-- between helm upgrades.
--
-- `billing_admin` (display name "Billing Admin") is a finance/billing scope
-- only: it pays the bills and has read-only visibility into users and settings,
-- with no operational access. It was renamed from the legacy internal
-- identifier `tenant_owner` in (the migration below brings existing
-- tenants in line before the role INSERTs run).
DO $$
DECLARE
    tenant_record RECORD;
BEGIN
    FOR tenant_record IN SELECT id, name FROM tenants WHERE deleted_at IS NULL
    LOOP
        -- Rename the legacy 'tenant_owner' role identifier to
        -- 'billing_admin' for tenants created before the rename. user_tenant_roles
        -- references roles by role_id, so assignments follow the rename
        -- automatically. Idempotent: a no-op once a tenant has no 'tenant_owner'
        -- row. Must run BEFORE the INSERT below — otherwise the INSERT would
        -- create a second 'billing_admin' row and orphan the legacy one. If a
        -- tenant somehow already has BOTH (e.g. ensureTenantRoles inserted the
        -- new name post-deploy before this seed ran), merge the legacy role's
        -- assignments into the existing 'billing_admin' and drop the duplicate
        -- rather than violate the (tenant_id, name) unique constraint.
        UPDATE user_tenant_roles utr
        SET role_id = b.id
        FROM tenant_roles o
        JOIN tenant_roles b ON b.tenant_id = o.tenant_id AND b.name = 'billing_admin'
        WHERE utr.role_id = o.id
          AND o.tenant_id = tenant_record.id AND o.name = 'tenant_owner' AND o.is_system_role = true
          AND NOT EXISTS (
            SELECT 1 FROM user_tenant_roles u2
            WHERE u2.user_id = utr.user_id AND u2.tenant_id = utr.tenant_id AND u2.role_id = b.id
          );
        DELETE FROM user_tenant_roles utr
        USING tenant_roles o, tenant_roles b
        WHERE utr.role_id = o.id
          AND b.tenant_id = o.tenant_id AND b.name = 'billing_admin'
          AND o.tenant_id = tenant_record.id AND o.name = 'tenant_owner' AND o.is_system_role = true;
        DELETE FROM tenant_role_permissions trp
        USING tenant_roles o, tenant_roles b
        WHERE trp.role_id = o.id
          AND b.tenant_id = o.tenant_id AND b.name = 'billing_admin'
          AND o.tenant_id = tenant_record.id AND o.name = 'tenant_owner' AND o.is_system_role = true;
        DELETE FROM tenant_roles o
        USING tenant_roles b
        WHERE b.tenant_id = o.tenant_id AND b.name = 'billing_admin'
          AND o.tenant_id = tenant_record.id AND o.name = 'tenant_owner' AND o.is_system_role = true;
        -- Plain rename when no 'billing_admin' row exists yet for the tenant.
        UPDATE tenant_roles
        SET name = 'billing_admin', display_name = 'Billing Admin'
        WHERE tenant_id = tenant_record.id AND name = 'tenant_owner' AND is_system_role = true
          AND NOT EXISTS (
            SELECT 1 FROM tenant_roles b2
            WHERE b2.tenant_id = tenant_record.id AND b2.name = 'billing_admin'
          );

        INSERT INTO tenant_roles (tenant_id, name, display_name, description, is_system_role)
        VALUES (tenant_record.id, 'billing_admin', 'Billing Admin', 'Billing and account ownership. Pays the bills; cannot perform operational work.', true)
        ON CONFLICT (tenant_id, name) DO NOTHING;
        INSERT INTO tenant_roles (tenant_id, name, display_name, description, is_system_role)
        VALUES (tenant_record.id, 'tenant_admin', 'Tenant Administrator', 'Full operational and user management; reads billing but cannot change it.', true)
        ON CONFLICT (tenant_id, name) DO NOTHING;
        INSERT INTO tenant_roles (tenant_id, name, display_name, description, is_system_role)
        VALUES (tenant_record.id, 'security_admin', 'Security Administrator', 'Security operations, compliance, reports; reads users and settings for incident response.', true)
        ON CONFLICT (tenant_id, name) DO NOTHING;
        INSERT INTO tenant_roles (tenant_id, name, display_name, description, is_system_role)
        VALUES (tenant_record.id, 'viewer', 'Viewer', 'Read-only access to tenant operational data (no billing).', true)
        ON CONFLICT (tenant_id, name) DO NOTHING;
        INSERT INTO tenant_roles (tenant_id, name, display_name, description, is_system_role)
        VALUES (tenant_record.id, 'api_user', 'API User', 'Read-only integration scope across operational data.', true)
        ON CONFLICT (tenant_id, name) DO NOTHING;

        -- Refresh display_name and description on existing rows so re-runs
        -- of this seed bring the labels in line with the current design.
        -- (INSERT ... ON CONFLICT DO NOTHING would skip these for existing
        -- tenants. The UPDATE only touches system roles to avoid stomping
        -- on a tenant's customizations of any user-defined role.)
        UPDATE tenant_roles SET
            display_name = 'Billing Admin',
            description  = 'Billing and account ownership. Pays the bills; cannot perform operational work.'
        WHERE tenant_id = tenant_record.id AND name = 'billing_admin' AND is_system_role = true;
        UPDATE tenant_roles SET
            display_name = 'Tenant Administrator',
            description  = 'Full operational and user management; reads billing but cannot change it.'
        WHERE tenant_id = tenant_record.id AND name = 'tenant_admin' AND is_system_role = true;
        UPDATE tenant_roles SET
            display_name = 'Security Administrator',
            description  = 'Security operations, compliance, reports; reads users and settings for incident response.'
        WHERE tenant_id = tenant_record.id AND name = 'security_admin' AND is_system_role = true;
        UPDATE tenant_roles SET
            description  = 'Read-only access to tenant operational data (no billing).'
        WHERE tenant_id = tenant_record.id AND name = 'viewer' AND is_system_role = true;
        UPDATE tenant_roles SET
            description  = 'Read-only integration scope across operational data.'
        WHERE tenant_id = tenant_record.id AND name = 'api_user' AND is_system_role = true;

        -- Retire the analyst role: it became functionally identical to
        -- viewer after Phase 5. Reassign any analyst users to viewer (skipping
        -- users who already hold viewer to avoid the (user,tenant,role) unique
        -- collision), drop leftover analyst assignments, then drop the role.
        -- Idempotent: once analyst is gone for this tenant these are no-ops.
        UPDATE user_tenant_roles utr
        SET role_id = v.id
        FROM tenant_roles a
        JOIN tenant_roles v ON v.tenant_id = a.tenant_id AND v.name = 'viewer'
        WHERE utr.role_id = a.id
          AND a.tenant_id = tenant_record.id AND a.name = 'analyst' AND a.is_system_role = true
          AND NOT EXISTS (
            SELECT 1 FROM user_tenant_roles u2
            WHERE u2.user_id = utr.user_id AND u2.tenant_id = utr.tenant_id AND u2.role_id = v.id
          );
        DELETE FROM user_tenant_roles utr
        USING tenant_roles a
        WHERE utr.role_id = a.id
          AND a.tenant_id = tenant_record.id AND a.name = 'analyst' AND a.is_system_role = true;
        DELETE FROM tenant_role_permissions trp
        USING tenant_roles a
        WHERE trp.role_id = a.id
          AND a.tenant_id = tenant_record.id AND a.name = 'analyst' AND a.is_system_role = true;
        DELETE FROM tenant_roles
        WHERE tenant_id = tenant_record.id AND name = 'analyst' AND is_system_role = true;

        -- BEGIN GENERATED: system role grant filters — from standards/permissions.yaml (make generate)
        -- ----------------------------------------------------------------
        -- Reconcile permission grants on SYSTEM roles to match the
        -- canonical filters below. The DELETE removes grants that no
        -- longer satisfy the current filter; the INSERT adds any new
        -- ones. Both are no-ops once the role is in the desired state.
        -- Only touches is_system_role=true; custom user-created roles
        -- are never modified here.
        -- ----------------------------------------------------------------

        -- Billing Admin (internal: billing_admin)
        -- Billing + read-only visibility into who has access and basic tenant
        -- settings.
        DELETE FROM tenant_role_permissions trp
        USING tenant_roles tr, tenant_permissions tp
        WHERE trp.role_id = tr.id AND trp.permission_id = tp.id
          AND tr.tenant_id = tenant_record.id AND tr.name = 'billing_admin' AND tr.is_system_role = true
          AND NOT (tp.resource = 'billing' OR tp.name IN ('settings.read', 'users.read'));
        INSERT INTO tenant_role_permissions (role_id, permission_id)
        SELECT tr.id, tp.id FROM tenant_roles tr CROSS JOIN tenant_permissions tp
        WHERE tr.tenant_id = tenant_record.id AND tr.name = 'billing_admin' AND tr.is_system_role = true
          AND (tp.resource = 'billing' OR tp.name IN ('settings.read', 'users.read'))
        ON CONFLICT (role_id, permission_id) DO NOTHING;

        -- Tenant Administrator (internal: tenant_admin)
        -- Everything except billing.update. Gets billing.read so they can see
        -- invoices, usage and payment history without being able to alter payment
        -- methods or cancel.
        DELETE FROM tenant_role_permissions trp
        USING tenant_roles tr, tenant_permissions tp
        WHERE trp.role_id = tr.id AND trp.permission_id = tp.id
          AND tr.tenant_id = tenant_record.id AND tr.name = 'tenant_admin' AND tr.is_system_role = true
          AND tp.name = 'billing.update';
        INSERT INTO tenant_role_permissions (role_id, permission_id)
        SELECT tr.id, tp.id FROM tenant_roles tr CROSS JOIN tenant_permissions tp
        WHERE tr.tenant_id = tenant_record.id AND tr.name = 'tenant_admin' AND tr.is_system_role = true
          AND tp.name <> 'billing.update'
        ON CONFLICT (role_id, permission_id) DO NOTHING;

        -- Security Administrator (internal: security_admin)
        -- Operational/security scope + users.read + settings.read for incident
        -- response.
        --
        -- audit.read is granted BY NAME, not by adding 'audit' to the resource
        -- list: the resource form would also hand over audit.manage, which the
        -- pre- role switch never gave security_admin (it granted
        -- audit.read/security/export only). This filter is a RESOURCE ALLOWLIST —
        -- a new resource is not granted unless it is named here, so omitting
        -- audit.read entirely would have silently STRIPPED security_admin's audit
        -- access in the migration.
        DELETE FROM tenant_role_permissions trp
        USING tenant_roles tr, tenant_permissions tp
        WHERE trp.role_id = tr.id AND trp.permission_id = tp.id
          AND tr.tenant_id = tenant_record.id AND tr.name = 'security_admin' AND tr.is_system_role = true
          AND NOT (tp.resource IN ('assets', 'sensors', 'reports', 'compliance', 'pcap', 'discovery', 'alerts')
                   OR tp.name IN ('users.read', 'settings.read', 'audit.read'));
        INSERT INTO tenant_role_permissions (role_id, permission_id)
        SELECT tr.id, tp.id FROM tenant_roles tr CROSS JOIN tenant_permissions tp
        WHERE tr.tenant_id = tenant_record.id AND tr.name = 'security_admin' AND tr.is_system_role = true
          AND (tp.resource IN ('assets', 'sensors', 'reports', 'compliance', 'pcap', 'discovery', 'alerts')
               OR tp.name IN ('users.read', 'settings.read', 'audit.read'))
        ON CONFLICT (role_id, permission_id) DO NOTHING;

        -- Viewer (internal: viewer)
        -- Read-only across all operational resources (no billing).
        --
        -- NOTE: this filter is action-based, so seeding the `audit`
        -- resource hands viewer audit.read automatically. That is a real, if
        -- small, WIDENING versus the pre- role switch, which denied every
        -- audit.* permission to viewer. It is left in place deliberately: the
        -- routes audit.read gates (activity-logs/by-user, /by-resource, the SIEM
        -- integration list) are tenant-scoped in the handler, and viewer can
        -- already read the same tenant's full audit trail through the ungated
        -- GET /activity-logs. Carving `audit` out would make viewer's "read
        -- everything non-billing" rule a special case. If audit reads should be
        -- privileged, change it HERE — one edit now reaches every mirror.
        DELETE FROM tenant_role_permissions trp
        USING tenant_roles tr, tenant_permissions tp
        WHERE trp.role_id = tr.id AND trp.permission_id = tp.id
          AND tr.tenant_id = tenant_record.id AND tr.name = 'viewer' AND tr.is_system_role = true
          AND NOT (tp.action = 'read' AND tp.resource <> 'billing');
        INSERT INTO tenant_role_permissions (role_id, permission_id)
        SELECT tr.id, tp.id FROM tenant_roles tr CROSS JOIN tenant_permissions tp
        WHERE tr.tenant_id = tenant_record.id AND tr.name = 'viewer' AND tr.is_system_role = true
          AND tp.action = 'read' AND tp.resource <> 'billing'
        ON CONFLICT (role_id, permission_id) DO NOTHING;

        -- API User (internal: api_user)
        -- Read-only integration scope across operational data.
        DELETE FROM tenant_role_permissions trp
        USING tenant_roles tr, tenant_permissions tp
        WHERE trp.role_id = tr.id AND trp.permission_id = tp.id
          AND tr.tenant_id = tenant_record.id AND tr.name = 'api_user' AND tr.is_system_role = true
          AND NOT (tp.action = 'read' AND tp.resource IN ('assets', 'sensors', 'reports', 'compliance', 'discovery', 'pcap'));
        INSERT INTO tenant_role_permissions (role_id, permission_id)
        SELECT tr.id, tp.id FROM tenant_roles tr CROSS JOIN tenant_permissions tp
        WHERE tr.tenant_id = tenant_record.id AND tr.name = 'api_user' AND tr.is_system_role = true
          AND tp.action = 'read' AND tp.resource IN ('assets', 'sensors', 'reports', 'compliance', 'discovery', 'pcap')
        ON CONFLICT (role_id, permission_id) DO NOTHING;
        -- END GENERATED: system role grant filters
    END LOOP;
    RAISE NOTICE '✅ Reconciled tenant roles and permissions for all tenants';
END $$;

-- =================================================================
-- CycloneDX CBOM: Populate algorithm identity properties
-- These UPDATE statements enrich existing algorithm records with
-- CycloneDX-conformant fields (algorithm_family, primitive, mode,
-- oid, crypto_functions, classical_security_level, nist_quantum_security_level).
-- =================================================================

-- Hash Algorithms
UPDATE algorithms SET
    algorithm_family = 'MD5', primitive = 'hash', oid = '1.2.840.113549.2.5',
    crypto_functions = ARRAY['digest'], classical_security_level = 64, nist_quantum_security_level = 0
WHERE code = 'MD5';

UPDATE algorithms SET
    algorithm_family = 'SHA-1', primitive = 'hash', oid = '1.3.14.3.2.26',
    crypto_functions = ARRAY['digest'], classical_security_level = 80, nist_quantum_security_level = 0
WHERE code = 'SHA1';

UPDATE algorithms SET
    algorithm_family = 'SHA-2', primitive = 'hash', oid = '2.16.840.1.101.3.4.2.1',
    crypto_functions = ARRAY['digest'], classical_security_level = 128, nist_quantum_security_level = 0
WHERE code = 'SHA256';

UPDATE algorithms SET
    algorithm_family = 'SHA-2', primitive = 'hash', oid = '2.16.840.1.101.3.4.2.3',
    crypto_functions = ARRAY['digest'], classical_security_level = 256, nist_quantum_security_level = 0
WHERE code = 'SHA512';

UPDATE algorithms SET
    algorithm_family = 'SHA-2', primitive = 'hash', oid = '2.16.840.1.101.3.4.2.2',
    crypto_functions = ARRAY['digest'], classical_security_level = 192, nist_quantum_security_level = 0
WHERE code = 'SHA384';

-- Symmetric Encryption Algorithms
UPDATE algorithms SET
    algorithm_family = 'DES', primitive = 'block-cipher', mode = 'ecb', oid = '1.3.14.3.2.7',
    crypto_functions = ARRAY['keygen', 'encrypt', 'decrypt'], classical_security_level = 56,
    nist_quantum_security_level = 0, parameter_set_identifier = '56'
WHERE code = 'DES';

UPDATE algorithms SET
    algorithm_family = '3DES', primitive = 'block-cipher', mode = 'cbc', oid = '1.2.840.113549.3.7',
    crypto_functions = ARRAY['keygen', 'encrypt', 'decrypt'], classical_security_level = 112,
    nist_quantum_security_level = 0, parameter_set_identifier = '168'
WHERE code = '3DES';

UPDATE algorithms SET
    algorithm_family = 'RC4', primitive = 'stream-cipher',
    crypto_functions = ARRAY['keygen', 'encrypt', 'decrypt'], classical_security_level = NULL,
    nist_quantum_security_level = 0, parameter_set_identifier = '128'
WHERE code = 'RC4';

UPDATE algorithms SET
    algorithm_family = 'AES', primitive = 'block-cipher', oid = '2.16.840.1.101.3.4.1',
    crypto_functions = ARRAY['keygen', 'encrypt', 'decrypt'], classical_security_level = 128,
    nist_quantum_security_level = 1, parameter_set_identifier = '128'
WHERE code = 'AES128';

UPDATE algorithms SET
    algorithm_family = 'AES', primitive = 'block-cipher', oid = '2.16.840.1.101.3.4.1',
    crypto_functions = ARRAY['keygen', 'encrypt', 'decrypt'], classical_security_level = 256,
    nist_quantum_security_level = 5, parameter_set_identifier = '256'
WHERE code = 'AES256';

UPDATE algorithms SET
    algorithm_family = 'ChaCha', primitive = 'ae',
    crypto_functions = ARRAY['keygen', 'encrypt', 'decrypt', 'tag'], classical_security_level = 256,
    nist_quantum_security_level = 0, parameter_set_identifier = '256'
WHERE code = 'ChaCha20';

UPDATE algorithms SET
    algorithm_family = 'NULL', primitive = 'other',
    crypto_functions = ARRAY[]::text[], classical_security_level = NULL, nist_quantum_security_level = 0
WHERE code = 'NULL';

UPDATE algorithms SET
    algorithm_family = 'AES', primitive = 'block-cipher', mode = 'cbc',
    crypto_functions = ARRAY['keygen', 'encrypt', 'decrypt'], classical_security_level = 128,
    nist_quantum_security_level = 0
WHERE code = 'CBC';

-- Key Exchange Algorithms
UPDATE algorithms SET
    algorithm_family = 'RSA', primitive = 'pke', oid = '1.2.840.113549.1.1.1',
    crypto_functions = ARRAY['keygen', 'encrypt', 'decrypt'], classical_security_level = 80,
    nist_quantum_security_level = 0, parameter_set_identifier = '1024'
WHERE code = 'RSA-1024';

UPDATE algorithms SET
    algorithm_family = 'RSA', primitive = 'pke', oid = '1.2.840.113549.1.1.1',
    crypto_functions = ARRAY['keygen', 'encrypt', 'decrypt'], classical_security_level = 112,
    nist_quantum_security_level = 0, parameter_set_identifier = '2048'
WHERE code = 'RSA-2048';

UPDATE algorithms SET
    algorithm_family = 'RSA', primitive = 'pke', oid = '1.2.840.113549.1.1.1',
    crypto_functions = ARRAY['keygen', 'encrypt', 'decrypt'], classical_security_level = 150,
    nist_quantum_security_level = 0, parameter_set_identifier = '4096'
WHERE code = 'RSA-4096';

UPDATE algorithms SET
    algorithm_family = 'RSA', primitive = 'pke', oid = '1.2.840.113549.1.1.1',
    crypto_functions = ARRAY['keygen', 'encrypt', 'decrypt'], classical_security_level = 56,
    nist_quantum_security_level = 0, parameter_set_identifier = '512'
WHERE code = 'RSA-512';

UPDATE algorithms SET
    algorithm_family = 'ECDH', primitive = 'key-agree', curve = 'secp256r1',
    crypto_functions = ARRAY['keygen', 'keyderive'], classical_security_level = 128,
    nist_quantum_security_level = 0
WHERE code = 'ECDHE';

UPDATE algorithms SET
    algorithm_family = 'DH', primitive = 'key-agree',
    crypto_functions = ARRAY['keygen', 'keyderive'], classical_security_level = 112,
    nist_quantum_security_level = 0
WHERE code = 'DHE';

UPDATE algorithms SET
    algorithm_family = 'DH', primitive = 'key-agree',
    crypto_functions = ARRAY['keygen', 'keyderive'], classical_security_level = 56,
    nist_quantum_security_level = 0, parameter_set_identifier = '1024'
WHERE code = 'DH-1024';

UPDATE algorithms SET
    algorithm_family = 'DH', primitive = 'key-agree',
    crypto_functions = ARRAY['keygen', 'keyderive'], classical_security_level = 32,
    nist_quantum_security_level = 0, parameter_set_identifier = '480'
WHERE code = 'DH-480';

UPDATE algorithms SET
    algorithm_family = 'DH', primitive = 'key-agree',
    crypto_functions = ARRAY['keygen', 'keyderive'], classical_security_level = 40,
    nist_quantum_security_level = 0, parameter_set_identifier = '512'
WHERE code = 'DH-512';

UPDATE algorithms SET
    algorithm_family = 'DH', primitive = 'key-agree',
    crypto_functions = ARRAY['keygen', 'keyderive'], classical_security_level = 48,
    nist_quantum_security_level = 0, parameter_set_identifier = '768'
WHERE code = 'DH-768';

UPDATE algorithms SET
    algorithm_family = 'DH', primitive = 'key-agree',
    crypto_functions = ARRAY['keygen', 'keyderive'], classical_security_level = 112,
    nist_quantum_security_level = 0, parameter_set_identifier = '2048'
WHERE code = 'DH-2048';

UPDATE algorithms SET
    algorithm_family = 'RSA', primitive = 'pke', oid = '1.2.840.113549.1.1.1',
    crypto_functions = ARRAY['encrypt', 'decrypt'], classical_security_level = NULL,
    nist_quantum_security_level = 0
WHERE code = 'STATIC-RSA';

-- Signature Algorithms
UPDATE algorithms SET
    algorithm_family = 'RSASSA-PKCS1', primitive = 'signature', padding = 'pkcs1v15',
    oid = '1.2.840.113549.1.1.5',
    crypto_functions = ARRAY['sign', 'verify'], classical_security_level = 80,
    nist_quantum_security_level = 0
WHERE code = 'RSA-SHA1';

UPDATE algorithms SET
    algorithm_family = 'RSASSA-PKCS1', primitive = 'signature', padding = 'pkcs1v15',
    oid = '1.2.840.113549.1.1.11',
    crypto_functions = ARRAY['sign', 'verify'], classical_security_level = 112,
    nist_quantum_security_level = 0
WHERE code = 'RSA-SHA256';

UPDATE algorithms SET
    algorithm_family = 'RSASSA-PKCS1', primitive = 'signature', padding = 'pkcs1v15',
    oid = '1.2.840.113549.1.1.13',
    crypto_functions = ARRAY['sign', 'verify'], classical_security_level = 128,
    nist_quantum_security_level = 0
WHERE code = 'RSA-SHA512';

UPDATE algorithms SET
    algorithm_family = 'ECDSA', primitive = 'signature', curve = 'secp256r1',
    oid = '1.2.840.10045.4.3.2',
    crypto_functions = ARRAY['sign', 'verify'], classical_security_level = 128,
    nist_quantum_security_level = 0
WHERE code = 'ECDSA-SHA256';

UPDATE algorithms SET
    algorithm_family = 'ECDSA', primitive = 'signature', curve = 'secp521r1',
    oid = '1.2.840.10045.4.3.4',
    crypto_functions = ARRAY['sign', 'verify'], classical_security_level = 256,
    nist_quantum_security_level = 0
WHERE code = 'ECDSA-SHA512';

-- Protocol Versions (primitive = 'other' since protocols are containers, not primitives)
UPDATE algorithms SET
    algorithm_family = 'SSL', primitive = 'other', nist_quantum_security_level = 0
WHERE code = 'SSLv2';

UPDATE algorithms SET
    algorithm_family = 'SSL', primitive = 'other', nist_quantum_security_level = 0
WHERE code = 'SSLv3';

UPDATE algorithms SET
    algorithm_family = 'TLS', primitive = 'other', oid = '1.3.6.1.5.5.7.3.1',
    nist_quantum_security_level = 0
WHERE code IN ('TLS1.0', 'TLS1.1', 'TLS1.2', 'TLS1.3');

-- PQC Algorithms — ML-KEM (key encapsulation)
UPDATE algorithms SET
    algorithm_family = 'ML-KEM', primitive = 'kem',
    crypto_functions = ARRAY['keygen', 'encapsulate', 'decapsulate'],
    classical_security_level = 128, nist_quantum_security_level = 1,
    parameter_set_identifier = '512', oid = '2.16.840.1.101.3.4.1.44'
WHERE code = 'ML-KEM-512';

UPDATE algorithms SET
    algorithm_family = 'ML-KEM', primitive = 'kem',
    crypto_functions = ARRAY['keygen', 'encapsulate', 'decapsulate'],
    classical_security_level = 192, nist_quantum_security_level = 3,
    parameter_set_identifier = '768', oid = '2.16.840.1.101.3.4.1.45'
WHERE code = 'ML-KEM-768';

UPDATE algorithms SET
    algorithm_family = 'ML-KEM', primitive = 'kem',
    crypto_functions = ARRAY['keygen', 'encapsulate', 'decapsulate'],
    classical_security_level = 256, nist_quantum_security_level = 5,
    parameter_set_identifier = '1024', oid = '2.16.840.1.101.3.4.1.48'
WHERE code = 'ML-KEM-1024';

-- PQC Algorithms — HQC (key encapsulation backup)
UPDATE algorithms SET
    algorithm_family = 'HQC', primitive = 'kem',
    crypto_functions = ARRAY['keygen', 'encapsulate', 'decapsulate'],
    classical_security_level = 128, nist_quantum_security_level = 1,
    parameter_set_identifier = '128'
WHERE code = 'HQC-128';

UPDATE algorithms SET
    algorithm_family = 'HQC', primitive = 'kem',
    crypto_functions = ARRAY['keygen', 'encapsulate', 'decapsulate'],
    classical_security_level = 192, nist_quantum_security_level = 3,
    parameter_set_identifier = '192'
WHERE code = 'HQC-192';

UPDATE algorithms SET
    algorithm_family = 'HQC', primitive = 'kem',
    crypto_functions = ARRAY['keygen', 'encapsulate', 'decapsulate'],
    classical_security_level = 256, nist_quantum_security_level = 5,
    parameter_set_identifier = '256'
WHERE code = 'HQC-256';

-- PQC Algorithms — ML-DSA (digital signatures)
UPDATE algorithms SET
    algorithm_family = 'ML-DSA', primitive = 'signature',
    crypto_functions = ARRAY['keygen', 'sign', 'verify'],
    classical_security_level = 128, nist_quantum_security_level = 2,
    parameter_set_identifier = '44', oid = '2.16.840.1.101.3.4.3.17'
WHERE code = 'ML-DSA-44';

UPDATE algorithms SET
    algorithm_family = 'ML-DSA', primitive = 'signature',
    crypto_functions = ARRAY['keygen', 'sign', 'verify'],
    classical_security_level = 192, nist_quantum_security_level = 3,
    parameter_set_identifier = '65', oid = '2.16.840.1.101.3.4.3.18'
WHERE code = 'ML-DSA-65';

UPDATE algorithms SET
    algorithm_family = 'ML-DSA', primitive = 'signature',
    crypto_functions = ARRAY['keygen', 'sign', 'verify'],
    classical_security_level = 256, nist_quantum_security_level = 5,
    parameter_set_identifier = '87', oid = '2.16.840.1.101.3.4.3.19'
WHERE code = 'ML-DSA-87';

-- PQC Algorithms — SLH-DSA (stateless hash-based signatures)
UPDATE algorithms SET
    algorithm_family = 'SLH-DSA', primitive = 'signature',
    crypto_functions = ARRAY['keygen', 'sign', 'verify'],
    classical_security_level = 128, nist_quantum_security_level = 1,
    parameter_set_identifier = '128s'
WHERE code = 'SLH-DSA-128s';

UPDATE algorithms SET
    algorithm_family = 'SLH-DSA', primitive = 'signature',
    crypto_functions = ARRAY['keygen', 'sign', 'verify'],
    classical_security_level = 128, nist_quantum_security_level = 1,
    parameter_set_identifier = '128f'
WHERE code = 'SLH-DSA-128f';

UPDATE algorithms SET
    algorithm_family = 'SLH-DSA', primitive = 'signature',
    crypto_functions = ARRAY['keygen', 'sign', 'verify'],
    classical_security_level = 192, nist_quantum_security_level = 3,
    parameter_set_identifier = '192s'
WHERE code = 'SLH-DSA-192s';

UPDATE algorithms SET
    algorithm_family = 'SLH-DSA', primitive = 'signature',
    crypto_functions = ARRAY['keygen', 'sign', 'verify'],
    classical_security_level = 192, nist_quantum_security_level = 3,
    parameter_set_identifier = '192f'
WHERE code = 'SLH-DSA-192f';

UPDATE algorithms SET
    algorithm_family = 'SLH-DSA', primitive = 'signature',
    crypto_functions = ARRAY['keygen', 'sign', 'verify'],
    classical_security_level = 256, nist_quantum_security_level = 5,
    parameter_set_identifier = '256s'
WHERE code = 'SLH-DSA-256s';

UPDATE algorithms SET
    algorithm_family = 'SLH-DSA', primitive = 'signature',
    crypto_functions = ARRAY['keygen', 'sign', 'verify'],
    classical_security_level = 256, nist_quantum_security_level = 5,
    parameter_set_identifier = '256f'
WHERE code = 'SLH-DSA-256f';

-- PQC Algorithms — FN-DSA (FFT NTRU-based signatures)
UPDATE algorithms SET
    algorithm_family = 'FN-DSA', primitive = 'signature',
    crypto_functions = ARRAY['keygen', 'sign', 'verify'],
    classical_security_level = 128, nist_quantum_security_level = 1,
    parameter_set_identifier = '512'
WHERE code = 'FN-DSA-512';

UPDATE algorithms SET
    algorithm_family = 'FN-DSA', primitive = 'signature',
    crypto_functions = ARRAY['keygen', 'sign', 'verify'],
    classical_security_level = 256, nist_quantum_security_level = 5,
    parameter_set_identifier = '1024'
WHERE code = 'FN-DSA-1024';

-- =================================================================
-- OT / ICS Protocol Algorithms (PR 1 of phased OT discovery rollout)
-- =================================================================
-- Catalog entries for the cryptographic primitives (or absence thereof)
-- used by industrial protocols. The sensor emits Protocol="Modbus"|"DNP3"|
-- "MMS"|"ICCP"|"OPC_UA" with RawMetadata identifying the negotiated
-- algorithm; these rows let the report-generator and compliance-engine
-- look those identifiers up against canonical strength assessments.
--
-- The IEC 62351-3 reference cipher set (ECDHE+AES-GCM) is already covered
-- by the existing TLS cipher seed rows — no duplicates added here.

-- Modbus: no native security at all. Detecting Modbus IS the finding;
-- this sentinel row gives the UI / reports a stable code to reference
-- when surfacing "Modbus, no encryption" findings.
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard, algorithm_family, primitive) VALUES
('MODBUS-NO-SECURITY', 'protocol_version', 'Modbus/TCP (No Security)', 'Modbus/TCP has no native authentication or encryption. Every session is plaintext. Detection of Modbus on the wire is itself a high-severity finding for OT cryptographic audits.', 'weak', 'current', 95, ARRAY['MODBUS-TLS', 'OPC-UA-Basic256Sha256'], 'Migrate to Modbus/TLS (RFC 8184, port 802) for transport security, or replace with OPC UA which has native authentication and encryption. Where neither is feasible, isolate Modbus traffic to a dedicated VLAN with strict ACLs.', '{"NIST": "not-allowed-on-untrusted-networks", "IEC-62443": "non-compliant", "NERC-CIP": "non-compliant"}'::jsonb, true, 'Modbus', 'other'),
('S7-NO-SECURITY', 'protocol_version', 'Siemens S7 (No Security)', 'Siemens S7 (S7-300/400/1200/1500) over TCP 102 is a vendor-proprietary protocol with no native authentication or encryption. Dominant in European manufacturing and rail. Detection of plaintext S7 is a high-severity OT finding — the protocol allows arbitrary read/write to PLC memory blocks.', 'weak', 'current', 92, ARRAY['OPC-UA-Basic256Sha256', 'PROFINET-Security'], 'For new deployments prefer OPC UA over S7 where the device firmware supports it (S7-1500 V2.0+, S7-1200 V4.0+). For existing brownfield S7, isolate to a dedicated cell/zone with strict cell-protection firewall ACLs. Siemens S7-Plus (firmware ≥ V2.0 on 1500-series) adds session-key authentication but is not yet recognized as a transport-security replacement.', '{"NIST": "not-allowed-on-untrusted-networks", "IEC-62443": "non-compliant"}'::jsonb, true, 'S7', 'other'),
('ENIP-NO-SECURITY', 'protocol_version', 'EtherNet/IP CIP (No Security)', 'EtherNet/IP CIP (ODVA) over TCP 44818 is the Allen-Bradley / Rockwell ecosystem industrial protocol — manufacturing, water/wastewater, automotive. Classic CIP is plaintext with no native authentication or encryption. Detection of plaintext EtherNet/IP is a high-severity OT finding for cryptographic asset audits.', 'weak', 'current', 90, ARRAY['ENIP-CIP-SECURITY'], 'Migrate to CIP Security (ODVA CIP Volume 8) which wraps EtherNet/IP traffic in TLS / DTLS with per-device x509 certificates. CIP Security adoption requires firmware that supports it (Rockwell ControlLogix 5580 series and later, some Cognex / Omron devices). For existing brownfield, isolate EtherNet/IP traffic to a dedicated cell/zone with strict cell-protection firewall ACLs.', '{"NIST": "not-allowed-on-untrusted-networks", "IEC-62443": "non-compliant"}'::jsonb, true, 'EtherNet/IP', 'other'),
('HART-IP-NO-SECURITY', 'protocol_version', 'HART-IP (No Security)', 'HART-IP (HCF Spec 85) over TCP/UDP 5094 carries HART field-instrument communications in process industries — oil & gas, refineries, water treatment, chemical plants. The classic profile has no native authentication or encryption. Detection of plaintext HART-IP is a high-severity OT finding; field instruments often run in safety-critical loops where unauthenticated commands are a direct hazard.', 'weak', 'current', 90, ARRAY['HART-IP-SECURITY'], 'HART-IP Security (per the HCF Spec 85 security profile) wraps HART-IP in TLS. Field deployment is rare — most installations are still classic HART-IP. Where the profile is unavailable, isolate HART-IP traffic to a dedicated safety-network VLAN with strict firewall ACLs and no remote access.', '{"NIST": "not-allowed-on-untrusted-networks", "IEC-62443": "non-compliant"}'::jsonb, true, 'HART-IP', 'other'),
('MODBUS-TLS', 'protocol_version', 'Modbus/TLS (RFC 8184)', 'Modbus/TCP wrapped in TLS on port 802. Inherits the security properties of the negotiated TLS cipher suite — apply IEC 62351-3 cipher requirements.', 'strong', 'current', 25, ARRAY[]::text[], 'Use with TLS 1.2+ and IEC 62351-3 compliant cipher suites (ECDHE + AES-GCM).', '{"NIST": "approved-with-strong-tls", "IEC-62443": "compliant", "NERC-CIP": "compliant"}'::jsonb, true, 'Modbus', 'other'),
('BACNET-SC-TLS-WRAPPER', 'protocol_version', 'BACnet Secure Connect (BACnet/SC)', 'BACnet Secure Connect (ASHRAE 135-2020 Annex AB) wraps BACnet building-automation traffic in TLS with an ALPN identifier of "bacnet.sc". The sensor detects BACnet/SC via the TLS ClientHello ALPN extension and the underlying TLS handshake is processed by the existing TLS pipeline. Protocol-level strength derives from the negotiated TLS cipher suite — apply IEC 62351-3 cipher requirements. Detection of BACnet/SC is a positive finding versus plaintext BACnet over BVLC/UDP.', 'strong', 'current', 25, ARRAY[]::text[], 'Cipher strength is determined by the negotiated TLS cipher suite. Require TLS 1.2+ with ECDHE key exchange and AES-GCM AEAD, mirroring the IEC 62351-3 cipher profile.', '{"NIST": "approved-with-strong-tls", "IEC-62443": "compliant"}'::jsonb, true, 'BACnet', 'other')
ON CONFLICT (code) DO NOTHING;

-- DNP3 Secure Authentication MAC algorithm IDs (IEEE 1815-2012 Annex A,
-- Table 7-1). The sensor emits the numeric ID in RawMetadata.mac_algorithm_id
-- and the symbolic name in RawMetadata.mac_algorithm_name; these rows hold
-- the strength assessment per current NIST guidance.
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard, algorithm_family, primitive) VALUES
('DNP3-SA-HMAC-SHA1-4', 'hash', 'DNP3 SA HMAC-SHA-1-4', 'DNP3 Secure Authentication MAC algorithm 1: HMAC-SHA-1 truncated to 4 bytes. SHA-1 is deprecated by NIST and the 4-byte truncation provides only 32 bits of MAC security — well below modern thresholds.', 'weak', 'deprecated', 80, ARRAY['DNP3-SA-HMAC-SHA256-16', 'DNP3-SA-AES-GMAC-12'], 'SHA-1 is deprecated. Migrate to SAv5 with HMAC-SHA-256-16 (id 3) or AES-128-GMAC-12 (id 5). Coordinate with utility/EMS vendor for firmware updates.', '{"NIST": "deprecated", "NERC-CIP": "non-compliant"}'::jsonb, true, 'SHA-1', 'mac'),
('DNP3-SA-HMAC-SHA256-8', 'hash', 'DNP3 SA HMAC-SHA-256-8', 'DNP3 Secure Authentication MAC algorithm 2: HMAC-SHA-256 truncated to 8 bytes. Acceptable for SAv5 sessions where bandwidth is constrained, but the 16-byte variant is preferred.', 'acceptable', 'current', 40, ARRAY['DNP3-SA-HMAC-SHA256-16'], 'Prefer DNP3-SA-HMAC-SHA256-16 (id 3) when device performance and bandwidth allow.', '{"NIST": "approved", "NERC-CIP": "compliant"}'::jsonb, true, 'SHA-2', 'mac'),
('DNP3-SA-HMAC-SHA256-16', 'hash', 'DNP3 SA HMAC-SHA-256-16', 'DNP3 Secure Authentication MAC algorithm 3: HMAC-SHA-256 with full 16-byte MAC. The recommended baseline for SAv5 deployments.', 'strong', 'current', 20, ARRAY[]::text[], 'No migration needed. This is the recommended SAv5 MAC algorithm.', '{"NIST": "approved", "NERC-CIP": "compliant"}'::jsonb, true, 'SHA-2', 'mac'),
('DNP3-SA-HMAC-SHA1-10', 'hash', 'DNP3 SA HMAC-SHA-1-10', 'DNP3 Secure Authentication MAC algorithm 4: HMAC-SHA-1 truncated to 10 bytes. SHA-1 is deprecated regardless of truncation length.', 'weak', 'deprecated', 75, ARRAY['DNP3-SA-HMAC-SHA256-16', 'DNP3-SA-AES-GMAC-12'], 'SHA-1 is deprecated. Migrate to a SHA-256 or AES-GMAC variant.', '{"NIST": "deprecated", "NERC-CIP": "non-compliant"}'::jsonb, true, 'SHA-1', 'mac'),
('DNP3-SA-AES-GMAC-12', 'hash', 'DNP3 SA AES-128-GMAC-12', 'DNP3 Secure Authentication MAC algorithm 5: AES-128 in GMAC mode with 12-byte tag. Modern, hardware-accelerated, and recommended for high-throughput SAv5 deployments.', 'strong', 'current', 20, ARRAY[]::text[], 'AES-128-GMAC-12 is the preferred SAv5 MAC where AES hardware is available.', '{"NIST": "approved", "NERC-CIP": "compliant"}'::jsonb, true, 'AES', 'mac'),
('DNP3-SA-HMAC-SHA256-10', 'hash', 'DNP3 SA HMAC-SHA-256-10', 'DNP3 Secure Authentication MAC algorithm 6: HMAC-SHA-256 truncated to 10 bytes. Acceptable for bandwidth-constrained SAv5 sessions.', 'acceptable', 'current', 35, ARRAY['DNP3-SA-HMAC-SHA256-16'], 'Prefer the full-length 16-byte variant (id 3) when bandwidth permits.', '{"NIST": "approved", "NERC-CIP": "compliant"}'::jsonb, true, 'SHA-2', 'mac')
ON CONFLICT (code) DO NOTHING;

-- DNP3 protocol-level entries: plaintext (no SA) is itself the finding.
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard, algorithm_family, primitive) VALUES
('DNP3-PLAINTEXT', 'protocol_version', 'DNP3 (Plaintext)', 'DNP3 (IEEE 1815) without Secure Authentication. The dominant SCADA protocol for North American electric T&D, frequently deployed without any cryptographic protection. Detection of plaintext DNP3 is a high-severity finding for utility-sector audits.', 'weak', 'current', 90, ARRAY['DNP3-SAv5'], 'Enable DNP3 Secure Authentication (SAv5) on RTUs and master stations. Coordinate with vendors for firmware updates where SA is not yet supported. Where SA is infeasible, isolate DNP3 traffic to dedicated VLANs with strict ACLs.', '{"NIST": "not-allowed-on-untrusted-networks", "NERC-CIP": "non-compliant", "IEC-62443": "non-compliant"}'::jsonb, true, 'DNP3', 'other'),
('DNP3-SAv2', 'protocol_version', 'DNP3 SAv2', 'DNP3 Secure Authentication version 2. Uses SHA-1 family MACs which are deprecated by NIST. Found on legacy IEDs and older master stations.', 'weak', 'deprecated', 70, ARRAY['DNP3-SAv5'], 'SAv2 uses SHA-1 which is deprecated. Upgrade devices to SAv5 (HMAC-SHA-256 or AES-GMAC).', '{"NIST": "deprecated", "NERC-CIP": "non-compliant"}'::jsonb, true, 'DNP3', 'other'),
('DNP3-SAv5', 'protocol_version', 'DNP3 SAv5', 'DNP3 Secure Authentication version 5 (IEEE 1815-2012 Annex A). HMAC-based challenge/response with SHA-256 or AES-128-GMAC. The current standard for DNP3 link authentication.', 'strong', 'current', 25, ARRAY[]::text[], 'No migration needed. Verify the negotiated MAC algorithm is HMAC-SHA-256-16 (id 3) or AES-128-GMAC-12 (id 5).', '{"NIST": "approved", "NERC-CIP": "compliant"}'::jsonb, true, 'DNP3', 'other'),
('DNP3-SAv6', 'protocol_version', 'DNP3 SAv6', 'DNP3 Secure Authentication version 6 (IEEE 1815.1). Replaces SAv5 pre-shared HMAC keys with asymmetric PKI — per-outstation x509 certificates. Adoption is starting at the federal-utility / NERC-CIP-audited tier where SAv5 key management has become operationally painful. Detection is the strongest classification the sensor produces for DNP3.', 'strong', 'current', 15, ARRAY[]::text[], 'No migration needed — SAv6 is the recommended target for new-build utility deployments. Existing SAv5 outstations can be staged through coordinated firmware updates.', '{"NIST": "approved", "NERC-CIP": "compliant"}'::jsonb, true, 'DNP3', 'other')
ON CONFLICT (code) DO NOTHING;

-- OPC UA SecurityPolicies (OPC 10000-7 §6.1). The sensor emits the
-- SecurityPolicy URI in RawMetadata when an OPC UA OpenSecureChannel is
-- observed; these rows hold the strength assessment for each policy.
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score, recommended_alternatives, migration_guidance, compliance_mappings, is_standard, algorithm_family, primitive) VALUES
('OPC-UA-None', 'protocol_version', 'OPC UA SecurityPolicy: None', 'OPC UA session with no signing or encryption. Equivalent to plaintext communication.', 'weak', 'current', 90, ARRAY['OPC-UA-Basic256Sha256'], 'Configure OPC UA servers and clients to require Basic256Sha256 or stronger. Disable the None policy except for initial server discovery.', '{"NIST": "not-allowed-on-untrusted-networks", "IEC-62443": "non-compliant"}'::jsonb, true, 'OPC-UA', 'other'),
('OPC-UA-Basic128Rsa15', 'protocol_version', 'OPC UA SecurityPolicy: Basic128Rsa15', 'OPC UA policy using AES-128-CBC, RSA-PKCS#1-v1.5, SHA-1. Deprecated by the OPC Foundation due to SHA-1 and RSA padding weaknesses.', 'weak', 'deprecated', 75, ARRAY['OPC-UA-Basic256Sha256'], 'Disable Basic128Rsa15 in OPC UA server configuration. Migrate clients and servers to Basic256Sha256 or stronger.', '{"NIST": "deprecated", "IEC-62443": "non-compliant"}'::jsonb, true, 'OPC-UA', 'other'),
('OPC-UA-Basic256', 'protocol_version', 'OPC UA SecurityPolicy: Basic256', 'OPC UA policy using AES-256-CBC, RSA-OAEP, SHA-1. Deprecated by the OPC Foundation due to SHA-1.', 'weak', 'deprecated', 70, ARRAY['OPC-UA-Basic256Sha256'], 'Disable Basic256 in OPC UA server configuration. Migrate to Basic256Sha256 or stronger.', '{"NIST": "deprecated", "IEC-62443": "non-compliant"}'::jsonb, true, 'OPC-UA', 'other'),
('OPC-UA-Basic256Sha256', 'protocol_version', 'OPC UA SecurityPolicy: Basic256Sha256', 'OPC UA policy using AES-256-CBC, RSA-OAEP, SHA-256. The baseline modern OPC UA policy and the recommended default.', 'strong', 'current', 25, ARRAY['OPC-UA-Aes256Sha256RsaPss'], 'Acceptable; consider Aes256_Sha256_RsaPss for forward-looking deployments using PSS padding.', '{"NIST": "approved", "IEC-62443": "compliant"}'::jsonb, true, 'OPC-UA', 'other'),
('OPC-UA-Aes128Sha256RsaOaep', 'protocol_version', 'OPC UA SecurityPolicy: Aes128_Sha256_RsaOaep', 'OPC UA policy using AES-128-CBC, RSA-OAEP, SHA-256.', 'strong', 'current', 25, ARRAY[]::text[], 'No migration needed.', '{"NIST": "approved", "IEC-62443": "compliant"}'::jsonb, true, 'OPC-UA', 'other'),
('OPC-UA-Aes256Sha256RsaPss', 'protocol_version', 'OPC UA SecurityPolicy: Aes256_Sha256_RsaPss', 'OPC UA policy using AES-256-CBC, RSA-PSS, SHA-256. Modernized RSA padding (PSS) over the older OAEP-based policy.', 'strong', 'current', 20, ARRAY[]::text[], 'No migration needed. This is the strongest pre-PQC OPC UA policy currently standardized.', '{"NIST": "approved", "IEC-62443": "compliant"}'::jsonb, true, 'OPC-UA', 'other')
ON CONFLICT (code) DO NOTHING;


-- ============================================================================
-- Algorithm catalogue: completeness + correctness pass
-- ============================================================================
-- Re-runnable. Appended after the algorithm seed blocks. Three parts:
--   1. New algorithms a cryptographer would expect and that were absent
--      (EdDSA, SHA-3 family, hybrid PQC KEX, several classical sig/KEX rows).
--   2. OID CORRECTIONS (overwrite): the ML-KEM OIDs were on the AES arc
--      (2.16.840.1.101.3.4.1.x) instead of the KEM arc (…3.4.4.x), and the
--      TLS/SSL protocol-version rows carried the id-kp-serverAuth EKU OID,
--      which is not a protocol-version identifier.
--   3. Gap-fill (COALESCE, never overwrite): crypto_functions / classical /
--      nist_quantum / curve on the OT/IPsec/SMB/Kerberos/finite-field-DH rows
--      that were seeded before those columns existed.
--
-- nist_quantum_security_level follows the CycloneDX/NIST rule:
--   0 = classical asymmetric (Shor) or sub-AES-128 symmetric or broken;
--   1/3/5 = AES-128/192/256 key-search categories;
--   2/4 = SHA-256/384 collision categories; PQC = its own claimed category.
-- OIDs populated only where the standard value is unambiguous — a wrong OID
-- discredits the table, a NULL one does not.
-- ============================================================================

-- ── Part 1: new algorithms ──────────────────────────────────────────────────

-- EdDSA signatures (SSH host/user keys, TLS 1.3 certs, code signing)
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score,
    recommended_alternatives, migration_guidance, compliance_mappings, is_standard,
    algorithm_family, primitive, oid, crypto_functions, classical_security_level, nist_quantum_security_level, curve) VALUES
('ED25519', 'signature', 'Ed25519', 'Edwards-curve Digital Signature Algorithm over Curve25519 (RFC 8032). Widely used for SSH host/user keys, TLS 1.3 certificates and code signing.', 'strong', 'current', 15,
    ARRAY['ML-DSA-65'], 'Strong classical signature; not quantum-resistant. Plan migration to ML-DSA (FIPS 204) for post-quantum assurance.', '{"NIST": "approved", "FIPS": "186-5"}'::jsonb, true,
    'EdDSA', 'signature', '1.3.101.112', ARRAY['keygen','sign','verify'], 128, 0, 'Ed25519'),
('ED448', 'signature', 'Ed448', 'Edwards-curve Digital Signature Algorithm over Curve448 (RFC 8032). Higher security margin than Ed25519.', 'strong', 'current', 12,
    ARRAY['ML-DSA-87'], 'Strong classical signature; not quantum-resistant. Plan migration to ML-DSA (FIPS 204).', '{"NIST": "approved", "FIPS": "186-5"}'::jsonb, true,
    'EdDSA', 'signature', '1.3.101.113', ARRAY['keygen','sign','verify'], 224, 0, 'Ed448')
ON CONFLICT (code) DO NOTHING;

-- Additional classical signature schemes. ECDSA/RSA hash-named variants leave
-- classical_security_level NULL because the curve/modulus sets it, not the code.
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score,
    recommended_alternatives, migration_guidance, compliance_mappings, is_standard,
    algorithm_family, primitive, oid, crypto_functions, nist_quantum_security_level) VALUES
('ECDSA-SHA384', 'signature', 'ECDSA-SHA384', 'Elliptic Curve Digital Signature Algorithm with SHA-384. Signature component of the CNSA suite (with P-384).', 'strong', 'current', 15,
    ARRAY['ML-DSA-65'], 'Strong classical signature; not quantum-resistant. Plan migration to ML-DSA (FIPS 204).', '{"NIST": "approved", "FIPS": "186-5"}'::jsonb, true,
    'ECDSA', 'signature', '1.2.840.10045.4.3.3', ARRAY['keygen','sign','verify'], 0),
('RSA-SHA384', 'signature', 'RSA-SHA384', 'RSASSA-PKCS1-v1_5 or PSS signature with SHA-384.', 'strong', 'current', 20,
    ARRAY['ML-DSA-65'], 'Strong classical signature; not quantum-resistant. Plan migration to ML-DSA (FIPS 204).', '{"NIST": "approved", "FIPS": "186-5"}'::jsonb, true,
    'RSA', 'signature', '1.2.840.113549.1.1.12', ARRAY['keygen','sign','verify'], 0),
('RSA-PSS', 'signature', 'RSASSA-PSS', 'RSA Probabilistic Signature Scheme (PKCS#1 v2.1). Preferred over PKCS1-v1_5 for new deployments.', 'strong', 'current', 18,
    ARRAY['ML-DSA-65'], 'Strong classical signature; not quantum-resistant. Plan migration to ML-DSA (FIPS 204).', '{"NIST": "approved", "FIPS": "186-5"}'::jsonb, true,
    'RSA', 'signature', '1.2.840.113549.1.1.10', ARRAY['keygen','sign','verify'], 0),
('DSA', 'signature', 'DSA', 'Digital Signature Algorithm. Signature generation withdrawn in FIPS 186-5; legacy verification only.', 'weak', 'deprecated', 70,
    ARRAY['ECDSA-SHA256','ML-DSA-65'], 'DSA signature generation is withdrawn (FIPS 186-5). Migrate to ECDSA or Ed25519 now, and to ML-DSA for post-quantum assurance.', '{"NIST": "withdrawn", "FIPS": "186-5"}'::jsonb, true,
    'DSA', 'signature', '1.2.840.10040.4.1', ARRAY['keygen','sign','verify'], 0),
('ECDSA-SHA1', 'signature', 'ECDSA-SHA1', 'ECDSA with SHA-1. SHA-1 is collision-broken; unsuitable for signatures.', 'weak', 'deprecated', 70,
    ARRAY['ECDSA-SHA256','ML-DSA-65'], 'SHA-1 is collision-broken. Reissue with ECDSA-SHA256 or stronger immediately.', '{"NIST": "disallowed"}'::jsonb, true,
    'ECDSA', 'signature', '1.2.840.10045.4.1', ARRAY['sign','verify'], 0),
('RSA-MD5', 'signature', 'RSA-MD5', 'RSASSA-PKCS1-v1_5 with MD5. MD5 is collision-broken; forgeable.', 'weak', 'obsolete', 90,
    ARRAY['RSA-SHA256','ML-DSA-65'], 'MD5 is collision-broken and has produced real certificate forgeries. Reissue with SHA-256 or stronger immediately.', '{"NIST": "disallowed"}'::jsonb, true,
    'RSA', 'signature', '1.2.840.113549.1.1.4', ARRAY['sign','verify'], 0)
ON CONFLICT (code) DO NOTHING;

-- SHA-3 family (FIPS 202) + BLAKE2b + SHA-224
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score,
    recommended_alternatives, migration_guidance, compliance_mappings, is_standard,
    algorithm_family, primitive, oid, crypto_functions, classical_security_level, nist_quantum_security_level) VALUES
('SHA3-256', 'hash', 'SHA3-256', 'SHA-3 256-bit hash (FIPS 202, Keccak).', 'strong', 'current', 20,
    ARRAY[]::text[], NULL, '{"NIST": "approved", "FIPS": "202"}'::jsonb, true, 'SHA-3', 'hash', '2.16.840.1.101.3.4.2.8', ARRAY['digest'], 128, 2),
('SHA3-384', 'hash', 'SHA3-384', 'SHA-3 384-bit hash (FIPS 202, Keccak).', 'strong', 'current', 15,
    ARRAY[]::text[], NULL, '{"NIST": "approved", "FIPS": "202"}'::jsonb, true, 'SHA-3', 'hash', '2.16.840.1.101.3.4.2.9', ARRAY['digest'], 192, 4),
('SHA3-512', 'hash', 'SHA3-512', 'SHA-3 512-bit hash (FIPS 202, Keccak).', 'strong', 'current', 15,
    ARRAY[]::text[], NULL, '{"NIST": "approved", "FIPS": "202"}'::jsonb, true, 'SHA-3', 'hash', '2.16.840.1.101.3.4.2.10', ARRAY['digest'], 256, 5),
('SHAKE128', 'hash', 'SHAKE128', 'SHA-3 extendable-output function, 128-bit security (FIPS 202).', 'strong', 'current', 20,
    ARRAY[]::text[], NULL, '{"NIST": "approved", "FIPS": "202"}'::jsonb, true, 'SHA-3', 'xof', '2.16.840.1.101.3.4.2.11', ARRAY['digest'], 128, 2),
('SHAKE256', 'hash', 'SHAKE256', 'SHA-3 extendable-output function, 256-bit security (FIPS 202). Used internally by ML-DSA and SLH-DSA.', 'strong', 'current', 15,
    ARRAY[]::text[], NULL, '{"NIST": "approved", "FIPS": "202"}'::jsonb, true, 'SHA-3', 'xof', '2.16.840.1.101.3.4.2.12', ARRAY['digest'], 256, 5),
('SHA224', 'hash', 'SHA-224', 'SHA-2 224-bit hash (FIPS 180-4).', 'acceptable', 'current', 30,
    ARRAY['SHA256'], 'Acceptable, but SHA-256 is preferred for new designs.', '{"NIST": "approved", "FIPS": "180-4"}'::jsonb, true, 'SHA-2', 'hash', '2.16.840.1.101.3.4.2.4', ARRAY['digest'], 112, 0),
('BLAKE2B', 'hash', 'BLAKE2b', 'BLAKE2b cryptographic hash (RFC 7693), optimized for 64-bit platforms.', 'strong', 'current', 15,
    ARRAY[]::text[], NULL, '{"RFC": "7693"}'::jsonb, true, 'BLAKE2', 'hash', NULL, ARRAY['digest'], 256, 5)
ON CONFLICT (code) DO NOTHING;

-- Classical key-exchange gaps (X25519/X448 named groups, P-521, RSA-3072)
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score,
    recommended_alternatives, migration_guidance, compliance_mappings, is_standard,
    algorithm_family, primitive, oid, crypto_functions, classical_security_level, nist_quantum_security_level, curve) VALUES
('X25519', 'key_exchange', 'X25519', 'Elliptic-curve Diffie-Hellman over Curve25519 (RFC 7748). The default TLS 1.3 key-agreement group.', 'strong', 'current', 15,
    ARRAY['X25519MLKEM768'], 'Strong classical key agreement; not quantum-resistant. Migrate to a hybrid group (X25519MLKEM768) that adds ML-KEM.', '{"NIST": "approved", "RFC": "7748"}'::jsonb, true,
    'ECDH', 'key-agree', '1.3.101.110', ARRAY['keygen','key-agree'], 128, 0, 'Curve25519'),
('X448', 'key_exchange', 'X448', 'Elliptic-curve Diffie-Hellman over Curve448 (RFC 7748). Higher security margin than X25519.', 'strong', 'current', 12,
    ARRAY['X25519MLKEM768'], 'Strong classical key agreement; not quantum-resistant. Add an ML-KEM hybrid for post-quantum assurance.', '{"NIST": "approved", "RFC": "7748"}'::jsonb, true,
    'ECDH', 'key-agree', '1.3.101.111', ARRAY['keygen','key-agree'], 224, 0, 'Curve448'),
('DH-ECP-521', 'key_exchange', 'ECP-521', 'Elliptic-curve Diffie-Hellman over NIST P-521 (secp521r1).', 'strong', 'current', 12,
    ARRAY['X25519MLKEM768'], 'Strong classical key agreement; not quantum-resistant. Add an ML-KEM hybrid for post-quantum assurance.', '{"NIST": "approved"}'::jsonb, true,
    'ECDH', 'key-agree', '1.3.132.0.35', ARRAY['keygen','key-agree'], 256, 0, 'P-521'),
('RSA-3072', 'key_exchange', 'RSA 3072-bit', 'RSA key transport / key with a 3072-bit modulus (~128-bit classical security).', 'strong', 'current', 20,
    ARRAY['ML-KEM-768'], 'Strong classical strength; not quantum-resistant, and Shor breaks it entirely once a CRQC exists. Migrate to ML-KEM (FIPS 203).', '{"NIST": "approved"}'::jsonb, true,
    'RSA', 'pke', '1.2.840.113549.1.1.1', ARRAY['keygen','encrypt','decrypt'], 128, 0, NULL)
ON CONFLICT (code) DO NOTHING;

-- Hybrid PQC key exchange — what TLS 1.3 stacks (Chrome, Cloudflare, OpenSSH)
-- ship today. The COMBINED wire format is an IETF draft, so
-- pqc_standardization_status is 'candidate' even though the ML-KEM component
-- alone is FIPS 203. An inventory that cannot name these is missing the single
-- most important PQC signal now visible on the wire.
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score,
    recommended_alternatives, migration_guidance, compliance_mappings, is_standard, is_pqc, pqc_standardization_status,
    algorithm_family, primitive, crypto_functions, nist_quantum_security_level, metadata) VALUES
('X25519MLKEM768', 'key_exchange', 'X25519MLKEM768', 'Hybrid key exchange: X25519 ECDH combined with ML-KEM-768. IANA TLS group 0x11EC. De-facto default hybrid in current TLS 1.3 deployments.', 'recommended', 'current', 5,
    ARRAY[]::text[], 'Recommended migration target: retains classical X25519 security while adding ML-KEM-768 post-quantum protection. Safe even if one component is later broken.', '{"NIST": "hybrid", "IETF": "draft-ietf-tls-hybrid-design"}'::jsonb, true, true, 'candidate',
    'Hybrid-KEM', 'kem', ARRAY['keygen','encapsulate','decapsulate'], 3, '{"hybrid": true, "classical_component": "X25519", "pqc_component": "ML-KEM-768", "iana_group": "0x11EC", "quantum_resistance": true}'::jsonb),
('SecP256r1MLKEM768', 'key_exchange', 'SecP256r1MLKEM768', 'Hybrid key exchange: ECDH over NIST P-256 combined with ML-KEM-768. IANA TLS group 0x11EB.', 'recommended', 'current', 5,
    ARRAY[]::text[], 'Recommended migration target for stacks on NIST curves: P-256 ECDH plus ML-KEM-768 post-quantum protection.', '{"NIST": "hybrid", "IETF": "draft-ietf-tls-hybrid-design"}'::jsonb, true, true, 'candidate',
    'Hybrid-KEM', 'kem', ARRAY['keygen','encapsulate','decapsulate'], 3, '{"hybrid": true, "classical_component": "P-256", "pqc_component": "ML-KEM-768", "iana_group": "0x11EB", "quantum_resistance": true}'::jsonb)
ON CONFLICT (code) DO NOTHING;

-- ── Part 2: OID corrections (overwrite — these values are wrong) ─────────────
-- ML-KEM was seeded on the AES arc (…3.4.1.x). The KEM arc is …3.4.4.x
-- (NIST CSOR id-alg-ml-kem-512/768/1024 = …3.4.4.1/2/3).
UPDATE algorithms SET oid = '2.16.840.1.101.3.4.4.1' WHERE code = 'ML-KEM-512'  AND oid = '2.16.840.1.101.3.4.1.44';
UPDATE algorithms SET oid = '2.16.840.1.101.3.4.4.2' WHERE code = 'ML-KEM-768'  AND oid = '2.16.840.1.101.3.4.1.45';
UPDATE algorithms SET oid = '2.16.840.1.101.3.4.4.3' WHERE code = 'ML-KEM-1024' AND oid = '2.16.840.1.101.3.4.1.48';
-- Protocol versions carried id-kp-serverAuth (1.3.6.1.5.5.7.3.1), an EKU, not a
-- protocol-version identifier. A TLS/SSL version has no algorithm OID.
UPDATE algorithms SET oid = NULL WHERE category = 'protocol_version' AND oid = '1.3.6.1.5.5.7.3.1';

-- Primitive corrections: CBC is confidentiality-only, not authenticated
-- encryption. AES-CBC (IPSec ESP pairs it with a separate AUTH-HMAC) and the
-- Kerberos DES-CBC-MD5 enctype (MD5 here is an UNKEYED checksum, not a MAC) are
-- block ciphers, not AEAD.
UPDATE algorithms SET primitive = 'block-cipher' WHERE code IN ('ENCR-AES-CBC-128','ENCR-AES-CBC-256','DES-CBC-MD5-KRB') AND primitive = 'ae';

-- ── Part 3: gap-fill (COALESCE) on rows seeded before these columns existed ──
-- crypto_functions
UPDATE algorithms SET crypto_functions = COALESCE(crypto_functions, ARRAY['encrypt','decrypt']) WHERE code IN
  ('ENCR-AES-CBC-128','ENCR-AES-CBC-256','ENCR-AES-GCM-128','ENCR-AES-GCM-256','ENCR-CHACHA20-POLY1305-IPSEC',
   'SMB-AES-128-GCM','SMB-AES-256-GCM','SMB-AES-128-CCM','SMB-AES-256-CCM',
   'AES128-CTS-HMAC-SHA1-96','AES256-CTS-HMAC-SHA1-96','DES-CBC-MD5-KRB','RC4-HMAC-KRB');
UPDATE algorithms SET crypto_functions = COALESCE(crypto_functions, ARRAY['tag']) WHERE code IN
  ('PRF-HMAC-SHA2-256','AUTH-HMAC-SHA2-256-128','DNP3-SA-AES-GMAC-12',
   'DNP3-SA-HMAC-SHA1-10','DNP3-SA-HMAC-SHA1-4','DNP3-SA-HMAC-SHA256-10','DNP3-SA-HMAC-SHA256-16','DNP3-SA-HMAC-SHA256-8');
UPDATE algorithms SET crypto_functions = COALESCE(crypto_functions, ARRAY['keygen','key-agree']) WHERE code IN
  ('DH-MODP-2048','DH-ECP-256','DH-ECP-384','CURVE25519');
UPDATE algorithms SET crypto_functions = COALESCE(crypto_functions, ARRAY['digest']) WHERE code = 'BLAKE2S';

-- classical_security_level (only where the code fixes the size)
UPDATE algorithms SET classical_security_level = COALESCE(classical_security_level, 128) WHERE code IN
  ('ENCR-AES-CBC-128','ENCR-AES-GCM-128','SMB-AES-128-GCM','SMB-AES-128-CCM','AES128-CTS-HMAC-SHA1-96','DH-ECP-256','CURVE25519');
UPDATE algorithms SET classical_security_level = COALESCE(classical_security_level, 256) WHERE code IN
  ('ENCR-AES-CBC-256','ENCR-AES-GCM-256','SMB-AES-256-GCM','SMB-AES-256-CCM','AES256-CTS-HMAC-SHA1-96','ENCR-CHACHA20-POLY1305-IPSEC');
UPDATE algorithms SET classical_security_level = COALESCE(classical_security_level, 192) WHERE code = 'DH-ECP-384';
UPDATE algorithms SET classical_security_level = COALESCE(classical_security_level, 112) WHERE code = 'DH-MODP-2048';
UPDATE algorithms SET classical_security_level = COALESCE(classical_security_level, 56)  WHERE code = 'DES-CBC-MD5-KRB';

-- nist_quantum_security_level (CycloneDX/NIST rule; MAC/HMAC left NULL)
UPDATE algorithms SET nist_quantum_security_level = COALESCE(nist_quantum_security_level, 1) WHERE code IN
  ('ENCR-AES-CBC-128','ENCR-AES-GCM-128','SMB-AES-128-GCM','SMB-AES-128-CCM','AES128-CTS-HMAC-SHA1-96');
UPDATE algorithms SET nist_quantum_security_level = COALESCE(nist_quantum_security_level, 5) WHERE code IN
  ('ENCR-AES-CBC-256','ENCR-AES-GCM-256','SMB-AES-256-GCM','SMB-AES-256-CCM','AES256-CTS-HMAC-SHA1-96','ENCR-CHACHA20-POLY1305-IPSEC','BLAKE2S');
UPDATE algorithms SET nist_quantum_security_level = COALESCE(nist_quantum_security_level, 0) WHERE code IN
  ('CURVE25519','DH-MODP-2048','DH-ECP-256','DH-ECP-384','RC4-HMAC-KRB','DES-CBC-MD5-KRB');

-- curve (only where the code names it)
UPDATE algorithms SET curve = COALESCE(curve, 'Curve25519') WHERE code = 'CURVE25519';
UPDATE algorithms SET curve = COALESCE(curve, 'P-256')      WHERE code = 'DH-ECP-256';
UPDATE algorithms SET curve = COALESCE(curve, 'P-384')      WHERE code = 'DH-ECP-384';

-- ============================================================================
-- ALGORITHM CATALOGUE — Part 4: the key-exchange vocabulary the parsers emit
-- ============================================================================
-- Re-runnable. The cipher-suite parsers emit catalogue CODES, and their
-- key-exchange vocabulary is ECDHE | DHE | ECDH | DH | RSA. Three of those five
-- had no row, so a static (non-forward-secret) suite resolved to NOTHING:
-- "RSA" in the key_exchange category substring-matched RSA-512/1024/2048/3072/
-- 4096 — ambiguous, so correctly refused — and the component was left unlinked.
-- The result was that TLS_RSA_WITH_*, TLS_ECDH_* and TLS_DH_* endpoints, the
-- exact population the no-PFS controls exist to find, carried no key-exchange
-- assessment at all.
--
-- Assessment: all three are STATIC key transport/agreement. The server's
-- long-term key decrypts (RSA) or fixes (static ECDH/DH) the session secret, so
-- one key compromise retroactively exposes every recorded session. TLS 1.3
-- removed all of them for this reason (RFC 8446 §1.2). Rated alongside the
-- existing STATIC-RSA row (weak/deprecated/70) rather than worse: the primitive
-- itself is sound at these sizes; what is missing is forward secrecy.
INSERT INTO algorithms (code, category, name, description, strength, deprecation_status, risk_score,
    recommended_alternatives, migration_guidance, compliance_mappings, is_standard,
    algorithm_family, primitive, crypto_functions, nist_quantum_security_level) VALUES
('RSA', 'key_exchange', 'RSA key transport (static)', 'Static RSA key transport, as negotiated by the TLS_RSA_WITH_* suites. The client encrypts the premaster secret to the server''s long-term public key, so there is no forward secrecy. Removed in TLS 1.3.', 'weak', 'deprecated', 70,
    ARRAY['ECDHE', 'X25519', 'X25519MLKEM768'], 'Static RSA key transport provides no forward secrecy: recording traffic today and compromising the server key later decrypts all of it. Disable the TLS_RSA_WITH_* suites and negotiate ECDHE (or X25519) instead. It is also Shor-breakable — plan for ML-KEM.', '{"NIST": "deprecated", "PCI-DSS": "non-compliant", "RFC": "8446 removed"}'::jsonb, true,
    'RSA', 'pke', ARRAY['keygen','encrypt','decrypt'], 0),
('ECDH', 'key_exchange', 'ECDH (static)', 'Static elliptic-curve Diffie-Hellman, as negotiated by the TLS_ECDH_* suites, where the server''s certified EC key is reused for every session. No forward secrecy. Removed in TLS 1.3.', 'weak', 'deprecated', 65,
    ARRAY['ECDHE', 'X25519', 'X25519MLKEM768'], 'Static ECDH reuses one server key for every session, so a single key compromise exposes all past traffic. Switch to the ephemeral form (ECDHE / X25519), which is otherwise identical in cost.', '{"NIST": "deprecated", "PCI-DSS": "non-compliant", "RFC": "8446 removed"}'::jsonb, true,
    'ECDH', 'key-agree', ARRAY['keygen','key-agree'], 0),
('DH', 'key_exchange', 'Diffie-Hellman (static)', 'Static finite-field Diffie-Hellman, as negotiated by the TLS_DH_* suites, where the server''s certified DH key is reused for every session. No forward secrecy. Removed in TLS 1.3.', 'weak', 'deprecated', 70,
    ARRAY['DHE', 'ECDHE', 'X25519'], 'Static finite-field DH reuses one server key for every session and is commonly deployed with under-sized groups. Switch to ephemeral DHE with a 2048-bit-or-larger group, or preferably to ECDHE / X25519.', '{"NIST": "deprecated", "PCI-DSS": "non-compliant", "RFC": "8446 removed"}'::jsonb, true,
    'DH', 'key-agree', ARRAY['keygen','key-agree'], 0)
ON CONFLICT (code) DO NOTHING;

-- Finite-field DH security levels. NIST SP 800-57 Part 1 Rev 5 Table 2 gives
-- FFC and IFC of the same modulus size the same security strength, and the RSA
-- rows in this catalogue already follow it (RSA-1024 = 80, RSA-512 = 56). The
-- DH rows did not: DH-1024 claimed 56 — the RSA-512 figure — which understated
-- a 1024-bit group by three orders of magnitude of work while overstating
-- nothing anyone would notice. Sub-1024 sizes are extrapolated on the same
-- IFC/FFC equivalence; all of them are broken in practice either way.
UPDATE algorithms SET classical_security_level = 80 WHERE code = 'DH-1024' AND classical_security_level IS DISTINCT FROM 80;
UPDATE algorithms SET classical_security_level = 64 WHERE code = 'DH-768'  AND classical_security_level IS DISTINCT FROM 64;
UPDATE algorithms SET classical_security_level = 56 WHERE code = 'DH-512'  AND classical_security_level IS DISTINCT FROM 56;

-- NIST PQC security categories for symmetric primitives and hashes. The rule
-- (stated at the head of Part 1) is: 1/3/5 = AES-128/192/256 key search,
-- 2/4 = SHA-256/SHA-384 collision search. These rows were left at 0, which in
-- this table means "classically breakable by Shor or already broken" — the
-- opposite of true for AES-class and SHA-2 primitives, and the reason a
-- ChaCha20 endpoint looked no better than an RSA one on the quantum axis.
-- (AES128/AES256 and the SHA-3 family were already correct.)
UPDATE algorithms SET nist_quantum_security_level = 5 WHERE code = 'ChaCha20' AND nist_quantum_security_level = 0;
UPDATE algorithms SET nist_quantum_security_level = 2 WHERE code = 'SHA256'   AND nist_quantum_security_level = 0;
UPDATE algorithms SET nist_quantum_security_level = 4 WHERE code = 'SHA384'   AND nist_quantum_security_level = 0;
UPDATE algorithms SET nist_quantum_security_level = 5 WHERE code = 'SHA512'   AND nist_quantum_security_level = 0;
-- BLAKE2s is a 256-bit hash (128-bit collision resistance) — category 2, like
-- SHA-256. The Part 3 gap-fill grouped it with the 256-bit CIPHERS and gave it
-- category 5.
UPDATE algorithms SET nist_quantum_security_level = 2 WHERE code = 'BLAKE2S' AND nist_quantum_security_level = 5;

-- Retire the bare 'CBC' pseudo-algorithm. CBC is a block-cipher MODE, not an
-- algorithm: it has no key size, no security level of its own, and rating it
-- 'acceptable'/45 meant an AES-256-CBC configuration could be scored on the
-- mode rather than on the cipher. The mode belongs to the cipher-suite row
-- (and to algorithms.mode, which AES-CBC rows already carry).
-- Deleted only when nothing references it; several FKs into algorithms(id) have
-- no ON DELETE action, so on a database that did link something to it we fall
-- back to neutralising the row (risk 0 = "not assessed", which the risk roll-up
-- ignores) rather than failing the seed.
DO $$
BEGIN
    DELETE FROM algorithms WHERE code = 'CBC';
EXCEPTION WHEN foreign_key_violation THEN
    UPDATE algorithms
       SET risk_score = 0,
           name = 'CBC Mode (not an algorithm)',
           description = 'Cipher Block Chaining is a block-cipher MODE, not an algorithm. Retained only because existing rows reference it; it carries no assessment of its own — the cipher and the cipher suite do.'
     WHERE code = 'CBC';
END $$;


-- =================================================================
-- Default onboarding workflow (tenant guided setup)
-- =================================================================
-- The default (tenant_id IS NULL, is_default) workflow consumed by
-- auth-service GET /onboarding/workflow. It was seeded in the old auth
-- schema but dropped when the schema was consolidated, which left the
-- onboarding endpoints returning 404 (no steps). Re-seeded here.
--
-- The Go handler reads {id, title, description, required} and derives
-- `order` from array position; `type` is passed through for the web-ui
-- to choose deep-link behavior. Core 3 steps only (see feature spec
-- docsv4/internal/developer/standards/features/onboarding-wizard.md).
--
-- Idempotent: a NULL tenant_id bypasses the unique_tenant_workflow
-- constraint, so guard with WHERE NOT EXISTS to avoid duplicate defaults.
INSERT INTO public.workflow_configurations (tenant_id, workflow_type, workflow_name, steps, is_default, is_active)
SELECT NULL, 'onboarding', 'Default Onboarding', '[
    {"id": "define_networks", "type": "navigation", "title": "Add network segments", "description": "Define your network segments so discovery is scoped and results carry location and environment context.", "required": true},
    {"id": "add_locations", "type": "navigation", "title": "Add locations", "description": "Create locations to organize your assets by site or cloud region.", "required": true},
    {"id": "deploy_agent", "type": "action", "title": "Add an agent", "description": "Register a sensor or discovery agent to start finding assets on your network.", "required": true}
]'::jsonb, true, true
WHERE NOT EXISTS (
    SELECT 1 FROM public.workflow_configurations
    WHERE workflow_type = 'onboarding' AND is_default = true AND tenant_id IS NULL
);

-- =====================================================================
-- ONE-TIME DATA MIGRATIONS — platform control_measurements (ADR-0015)
-- ---------------------------------------------------------------------
-- Repairs DBs seeded before the framework DO blocks above were made
-- idempotent + predicate-correct. Every statement is a no-op on a
-- converged DB, so the seed-data Job re-runs it safely on each helm
-- upgrade. NOTE: this corrects the *rules*; stored compliance_findings
-- converge on the next reconcile or manual re-evaluation per tenant.
-- =====================================================================

-- (1) De-duplicate platform control_measurements.
-- Earlier releases seeded these with a bare INSERT (no ON CONFLICT, and the
-- table has no unique key), so every re-seed appended a fresh copy. Collapse
-- each (control_id, measurement_type_id, framework_type) group to its oldest
-- row. tenant_measurement_overrides.control_measurement_id references this
-- table ON DELETE CASCADE, so first re-point any overrides onto the survivor
-- where that does not violate the per-tenant unique key; the rare conflicting
-- override is then removed by the CASCADE when its duplicate row is deleted.
UPDATE tenant_measurement_overrides o
SET control_measurement_id = k.keep_id
FROM (
    SELECT id,
           first_value(id) OVER w AS keep_id,
           row_number()    OVER w AS rn
    FROM control_measurements
    WHERE framework_type = 'platform'
    WINDOW w AS (PARTITION BY control_id, measurement_type_id, framework_type
                 ORDER BY created_at, id)
) k
WHERE o.control_measurement_id = k.id
  AND k.rn > 1
  AND NOT EXISTS (
      SELECT 1 FROM tenant_measurement_overrides o2
      WHERE o2.tenant_id = o.tenant_id
        AND o2.control_measurement_id = k.keep_id
  );

DELETE FROM control_measurements c
USING (
    SELECT id,
           row_number() OVER (PARTITION BY control_id, measurement_type_id, framework_type
                              ORDER BY created_at, id) AS rn
    FROM control_measurements
    WHERE framework_type = 'platform'
) d
WHERE c.id = d.id AND d.rn > 1;

-- (2) Correct inverted threshold predicates on the surviving platform rows.
-- evaluateThreshold returns the operator comparison as the PASS condition and a
-- finding is raised when it is false, so the operator must describe the healthy
-- state. cert_expiration_days and key_size were seeded with "<", which inverted
-- the check (healthy certs/keys were flagged; expiring/weak ones passed).
UPDATE control_measurements cm
SET predicate  = jsonb_set(cm.predicate, '{operator}', '">="'),
    updated_at = NOW()
FROM measurement_types mt
WHERE cm.measurement_type_id = mt.id
  AND mt.code = 'cert_expiration_days'
  AND cm.framework_type = 'platform'
  AND cm.rule_type = 'threshold'
  AND cm.predicate->>'operator' = '<'
  AND cm.predicate->>'value' = '30';

UPDATE control_measurements cm
SET predicate  = jsonb_set(cm.predicate, '{operator}', '">="'),
    updated_at = NOW()
FROM measurement_types mt
WHERE cm.measurement_type_id = mt.id
  AND mt.code = 'key_size'
  AND cm.framework_type = 'platform'
  AND cm.rule_type = 'threshold'
  AND cm.predicate->>'operator' = '<'
  AND cm.predicate->>'value' = '2048';

-- =================================================================
-- Legal documents (Terms of Service + Privacy Policy) — seed v1
-- =================================================================
-- TEMPLATE content, not legal advice. Vista Platform is self-hosted: the
-- organization running the deployment is the service provider and the data
-- controller, so these are THEIR terms with THEIR users. Every [BRACKETED]
-- value must be replaced and the whole thing reviewed by counsel before anyone
-- is asked to accept it. Platform admins edit and publish at Settings -> Legal;
-- publishing a new version asks existing users to re-accept.
--
-- The body appears ONCE and content_hash is derived from it in the same
-- statement. It used to be written out twice — once as the value, once inside
-- sha256() — which meant an edit to one copy and not the other produced a row
-- whose hash silently did not match its own text.
--
-- Idempotent: ON CONFLICT (doc_type, version) DO NOTHING.
INSERT INTO public.legal_documents
    (doc_type, version, title, body, content_hash, is_current, effective_date, published_at)
SELECT
    d.doc_type,
    d.version,
    d.title,
    d.body,
    encode(sha256(convert_to(d.body, 'UTF8')), 'hex'),
    true,
    now(),
    now()
FROM (VALUES
    ('terms_of_service', 1, 'Terms of Service', $tos$# Terms of Service

_Last updated: [DATE]_

> **This is a template, not legal advice.** Vista Platform is self-hosted
> software: **you**, the organization running this deployment, are the service
> provider, and these are **your** terms with **your** users — not the software
> author's. Replace every `[BRACKETED]` value and have counsel review the whole
> document before you let anyone accept it. Platform administrators can edit and
> publish a new version at **Settings → Legal**; accepted versions are recorded
> per user, so publishing a change asks existing users to re-accept.

## 1. Who these terms are between

These Terms govern use of the Vista Platform deployment operated by
**[YOUR LEGAL ENTITY]** ("we", "us"), reachable at **[YOUR SERVICE URL]** (the
"Service"). By creating an account or using the Service you ("you", "your")
agree to them. If you are agreeing on behalf of an organization, you confirm you
have authority to bind it.

## 2. The Service

The Service discovers, inventories and assesses cryptographic assets across
systems you direct it at, and produces compliance findings and cryptographic
bills of materials from what it finds. Features change over time; we may add,
alter or withdraw functionality.

## 3. Accounts

You must provide accurate registration details and keep your credentials
confidential. You are responsible for activity under your account. Tell us
promptly at **[YOUR CONTACT]** if you believe an account has been compromised.

## 4. Acceptable use

You may not use the Service to:

- scan, probe or interrogate systems you are not authorized to assess;
- break any applicable law, or infringe anyone's rights;
- attempt to gain unauthorized access to the Service, other tenants' data, or
  the infrastructure it runs on;
- interfere with or degrade the Service's operation.

**Authorization is yours to establish.** The Service performs active network
probing and device interrogation when you configure it to. You are solely
responsible for holding the necessary permission for every system you point it
at.

## 5. Your data

You retain all rights in the data you supply and in the inventory, findings and
CBOM artifacts the Service generates for you ("Your Data"). We process Your Data
only to provide and support the Service, as described in our Privacy Policy.

You are responsible for the lawfulness of the data you put into the Service,
including any personal data contained in discovered configurations.

## 6. Confidentiality

Each party will protect the other's non-public information with at least
reasonable care and use it only for the purposes of these Terms.

## 7. Availability and support

[DESCRIBE YOUR AVAILABILITY COMMITMENT, OR STATE THERE IS NONE.] Unless a
separate written agreement says otherwise, the Service is provided without a
service-level commitment, and maintenance may make it temporarily unavailable.

## 8. Fees

[IF YOU CHARGE: state the fees, billing period, payment terms, taxes, and what
happens on non-payment. IF YOU DO NOT: say so plainly.]

## 9. Term and termination

These Terms apply for as long as you use the Service. Either party may terminate
[NOTICE PERIOD]. We may suspend or terminate access immediately for a material
breach of section 4.

On termination you may export Your Data for **[EXPORT WINDOW]**, after which we
may delete it in line with the retention periods in our Privacy Policy.

## 10. Disclaimers

The Service assists with cryptographic inventory and compliance assessment. **It
does not guarantee that your estate is secure, complete or compliant.** Findings
depend on what the Service can observe and on the policies you configure.
Decisions you take on the basis of its output remain yours.

Except as expressly stated, and to the extent the law permits, the Service is
provided "as is" without warranties of any kind.

## 11. Limitation of liability

To the extent the law permits, neither party is liable for indirect, incidental,
special or consequential loss, or for lost profits, revenue or data. Each
party's total liability arising from these Terms is limited to **[CAP]**.

Nothing here limits liability that cannot lawfully be limited — including for
death or personal injury caused by negligence, or for fraud.

## 12. Indemnity

You will defend and indemnify us against third-party claims arising from your
use of the Service in breach of these Terms, including any claim that you
assessed a system without authorization.

## 13. Changes

We may update these Terms. We will publish the new version here and, where the
change is material, ask you to accept it before continuing to use the Service.

## 14. Governing law

These Terms are governed by the laws of **[JURISDICTION]**, and the courts of
**[VENUE]** have exclusive jurisdiction, without regard to conflict-of-laws
rules.

## 15. Contact

**[YOUR LEGAL ENTITY]**
**[YOUR ADDRESS]**
**[YOUR CONTACT]**
$tos$),
    ('privacy_policy',   1, 'Privacy Policy',   $priv$# Privacy Policy

_Last updated: [DATE]_

> **This is a template, not legal advice.** Vista Platform is self-hosted:
> **you**, the organization running this deployment, are the data controller —
> the software author neither operates this instance nor receives data from it.
> Replace every `[BRACKETED]` value and have counsel review it against the law
> that applies to you (GDPR, UK GDPR, CCPA/CPRA, or otherwise) before publishing.
> Edit and publish at **Settings → Legal**.

## 1. Who is responsible

**[YOUR LEGAL ENTITY]**, **[YOUR ADDRESS]**, is the controller for personal data
processed by the Vista Platform deployment at **[YOUR SERVICE URL]**.
[IF REQUIRED: name your Data Protection Officer and contact details.]

Contact us about privacy at **[YOUR PRIVACY CONTACT]**.

## 2. Where your data lives

This is a self-hosted deployment. Your data resides in infrastructure **you**
control and is not transmitted to the authors of the software. There is no
telemetry, no phone-home and no vendor-side copy of your inventory.

## 3. What we process

**Account data** — name, email address, hashed password, role, organization,
and identity-provider identifiers if you sign in through SSO.

**Usage data** — sign-in times, IP addresses, browser/user-agent, audit records
of actions taken in the platform.

**Discovery data** — the substance of the Service. Certificates, keys, hostnames,
IP addresses, service banners, protocol and cipher configurations, and device
metadata gathered from systems you direct the platform to observe or interrogate.

> Discovery data is mostly about *systems*, but some of it can identify people —
> a certificate subject or an SSH key comment may carry a name or email address.
> Treat it as potentially personal data, and say so here if that is the case in
> your environment.

**Credentials you supply** for interrogating devices and cloud accounts. These
are encrypted at rest (AES-256-GCM) and used only to perform the assessments you
configure.

## 4. Why we process it, and on what basis

| Purpose | Basis (GDPR Art. 6) |
|---|---|
| Providing the Service and your account | Performance of a contract |
| Securing the Service; audit and abuse prevention | Legitimate interests |
| Cryptographic inventory and compliance assessment | Legitimate interests, or legal obligation where a regulation requires it |
| Service communications | Performance of a contract |
| Marketing, if any | Consent |

[Adjust to the basis you actually rely on. If your jurisdiction does not use
this framework, replace the table.]

## 5. Sharing

We do not sell personal data. We share it only with:

- **Service providers** who host or support this deployment, under contract and
  only as needed. [LIST YOUR SUB-PROCESSORS, OR STATE THAT THERE ARE NONE.]
- **Authorities**, where the law requires it — and where we are permitted to,
  we will tell you first.
- **AI assistants, if anyone connects one.** The Service exposes a read-only
  Model Context Protocol (MCP) endpoint that an AI assistant can query for
  inventory, compliance and CBOM data. Nothing reaches it until a user in your
  organization creates an API token and authorizes a client; from that point,
  what the assistant reads leaves this deployment and is processed by whichever
  AI provider that user chose, under **that provider's** terms — not ours.
  [STATE WHETHER YOU PERMIT THIS AND WHICH PROVIDERS, OR SAY YOU HAVE DISABLED
  IT.]

If you have configured integrations (SIEM forwarding, CMDB sync, ticketing,
notifications), data flows to those systems because you told it to. **You**
control those destinations.

## 6. Retention

| Data | Retained |
|---|---|
| Account data | While the account is active, then **[PERIOD]** |
| Audit logs | **[PERIOD]** |
| Discovery data and inventory | Until you delete it, or **[PERIOD]** after account closure |
| Backups | **[PERIOD]** |

Retention for several of these is configurable in the platform; set the values
above to match how you have configured yours, rather than to an aspiration.

## 7. Security

Access is role-controlled and tenant-isolated at the database level. Traffic is
encrypted in transit, credentials and other sensitive fields are encrypted at
rest, and administrative actions are audit-logged. No system is perfectly
secure, and we do not claim otherwise.

Report a suspected vulnerability to **[YOUR SECURITY CONTACT]**.

## 8. Your rights

Depending on where you live, you may have the right to access, correct, delete,
port, restrict or object to processing of your personal data, and to withdraw
consent where we rely on it. Exercise any of these at **[YOUR PRIVACY CONTACT]**;
we respond within **[PERIOD]**.

You may also complain to your data protection authority. [NAME YOURS.]

## 9. Cookies

The Service sets cookies strictly necessary to operate: a session cookie holding
your authentication token, and a paired CSRF token. It does not use advertising
or cross-site tracking cookies. [AMEND IF YOU ADD ANALYTICS.]

## 10. International transfers

[IF YOU TRANSFER PERSONAL DATA ACROSS BORDERS: name the destinations and the
safeguard you rely on — adequacy decision, Standard Contractual Clauses, or
another mechanism. IF NOT: say the data stays within [REGION].]

## 11. Children

The Service is for organizational use and is not directed at children under
**[AGE]**. We do not knowingly collect their personal data.

## 12. Changes

We will post any update here and revise the date above. Where a change is
material we will ask you to review it before you continue using the Service.

## 13. Contact

**[YOUR LEGAL ENTITY]**
**[YOUR ADDRESS]**
**[YOUR PRIVACY CONTACT]**
$priv$)
) AS d(doc_type, version, title, body)
ON CONFLICT (doc_type, version) DO NOTHING;

-- =================================================================
-- Platform notification default pack (first install only)
-- =================================================================
-- The platform track had no equivalent of the tenant default pack
-- (auth-service seedDefaultNotificationPack), so a fresh install had ZERO
-- platform_notification_channels and ZERO platform_notification_rules. The
-- platform detectors fire correctly — service_down forms an alert in `alerts`,
-- the alert engine publishes the notification — and then the rule engine
-- matches nothing and the notification is written to notification_history with
-- an empty channels_used. Nobody is told a platform service is down until an
-- operator manually configures delivery. This closes that.
--
-- Mirrors the tenant pack's design, including the one insight that makes a
-- seeded email channel possible at all: the channel stores NO address. It
-- names a ROLE, and delivery_service resolves the role's active members at
-- send time — here the platform-admin equivalent (platform_users JOIN
-- platform_roles), so the pack works before any operator has entered an
-- address, and tracks admin membership as it changes.
--
--   'Platform in-app'          in_app  → platform_in_app_notifications (operator bell)
--   'Platform admin email'     email   → recipient_role 'super_admin', resolved at send time
--   'Default platform critical alerts'  all sources, critical+high  → in-app + email
--   'Default platform activity feed'    all sources, medium+low+info → in-app
--
-- Severity coverage is exhaustive ON PURPOSE. NormalizeSeverity
-- (notification-service) maps every producer severity onto exactly five values
-- — critical / high / medium / low / info — and its `default:` branch degrades
-- ANY unrecognized or empty severity to 'info'. The tenant pack originally
-- omitted 'info' and silently dropped every notification that landed there,
-- including everything the default branch degrades. The two rules here union
-- to all five bands, so no platform notification can fall through the rules.
--
-- Platform severities this covers: service_down (critical, rule 1),
-- tenant_health_degraded (medium, rule 2), metric_threshold (from-threshold:
-- the evaluator emits 'critical' on the critical arm and 'high' on the warning
-- arm — both rule 1).
--
-- FIRST-INSTALL-ONLY, deliberately. The seed Job re-runs on every helm upgrade,
-- so a per-name ON CONFLICT DO NOTHING would resurrect a default the operator
-- deliberately DELETED, every upgrade, forever. Guarding on "the operator has
-- configured no platform delivery at all" means we seed the empty case and
-- never touch a configured one — an operator who has edited, disabled, renamed
-- or deleted any of this keeps exactly what they have.
DO $$
DECLARE
    v_in_app_id uuid;
    v_email_id  uuid;
BEGIN
    IF EXISTS (SELECT 1 FROM platform_notification_channels)
       OR EXISTS (SELECT 1 FROM platform_notification_rules) THEN
        RETURN;  -- operator-configured: leave it exactly as it is
    END IF;

    INSERT INTO platform_notification_channels (channel_name, channel_type, config, enabled, description)
    VALUES ('Platform in-app', 'in_app', '{}'::jsonb, true,
            'Default platform in-app notifications (operator bell). Seeded on first install.')
    RETURNING id INTO v_in_app_id;

    INSERT INTO platform_notification_channels (channel_name, channel_type, config, enabled, description)
    VALUES ('Platform admin email', 'email',
            '{"recipients": [], "recipient_role": "super_admin"}'::jsonb, true,
            'Emails all active super_admin platform users (resolved at send time). Seeded on first install.')
    RETURNING id INTO v_email_id;

    INSERT INTO platform_notification_rules
        (rule_name, alert_source, channel_ids, severity_filter, frequency, enabled, priority)
    VALUES
        ('Default platform critical alerts', 'all', ARRAY[v_in_app_id, v_email_id],
         ARRAY['critical','high']::varchar[], 'immediate', true, 100),
        ('Default platform activity feed', 'all', ARRAY[v_in_app_id],
         ARRAY['medium','low','info']::varchar[], 'immediate', true, 50);
END $$;

-- =================================================================
-- Default monitoring alert thresholds (first install only)
-- =================================================================
-- metric_threshold is a `status: live` platform alert type whose detector
-- (monitoring-service alert_evaluator) evaluates monitoring_alert_thresholds.
-- That table shipped EMPTY, so the detector had nothing to breach and the
-- alert type could not fire on a fresh install however healthy or unhealthy
-- the platform was.
--
-- Shape constraints, all learned from the evaluator and the snapshot schema —
-- get any of them wrong and the row is silently inert:
--
--  * service_name MUST be set. GetServiceMetrics filters
--    `service_name = $1` exactly, so a NULL service_name asks for metrics of
--    the service named '' and matches nothing, forever.
--  * The name must match a key of monitoring-service's health-check config
--    (the aggregator writes snapshots under exactly those names).
--  * Only response_time / error_rate / throughput are evaluated.
--    cpu_usage and memory_usage hit an explicit `return nil` — seeding those
--    would look like coverage and provide none.
--  * response_time is compared against latency_p95 in MILLISECONDS, which the
--    aggregator derives as (health-check round-trip ms x 1.5).
--  * The evaluator reads the 60-SECOND snapshot window and uses the single
--    latest sample. duration_minutes is stored but NOT honored — one bad
--    sample fires. That is precisely why the values below are set well above
--    any plausible healthy reading rather than at a tight SLO.
--
-- Values: warning 1000 ms p95, critical 2500 ms p95.
--   1000 ms p95 == a ~667 ms raw /health round-trip. /health does no query
--   work, and an in-cluster round-trip to a healthy Go service is single-digit
--   milliseconds, so two-thirds of a second means the process is saturated,
--   GC-thrashing, or the network path is degraded. It is ~100x the healthy
--   reading, so ordinary jitter cannot reach it: a default that cries wolf
--   gets muted, which is worse than no default.
--   2500 ms p95 == a ~1.7 s raw round-trip, still below the 5 s
--   SERVICE_TIMEOUT at which the probe fails outright and the service is
--   recorded down (service_down's job). So the ladder warns while the service
--   is merely sick and hands off cleanly before it is dead.
--
-- Only three services, not all nineteen. These are the ones whose latency a
-- user feels directly (every request authenticates; inventory is the primary
-- data path) plus the datastore that is the usual root cause. Nineteen
-- default thresholds would be nineteen chances to cry wolf; operators extend
-- the set from admin-ui → System → Alerts.
--
-- Deliberately NOT seeded: an error_rate threshold. The aggregator does not
-- measure a real request error rate — it synthesizes 1.0 when a service is
-- down and 0.1 when degraded. Any error_rate threshold low enough to catch
-- 'degraded' also fires on every outage, double-alerting alongside
-- service_down for the same condition. Flagged for the owner rather than
-- guessed at.
--
-- First-install-only for the same reason as the notification pack above: the
-- seed Job re-runs on every upgrade, and a per-name guard would resurrect a
-- threshold the operator deleted.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM monitoring_alert_thresholds) THEN
        RETURN;  -- operator-configured: leave it exactly as it is
    END IF;

    -- notify_* are stored for the admin UI's benefit; actual fan-out is
    -- governed by platform_notification_rules (seeded above), not by these.
    INSERT INTO monitoring_alert_thresholds
        (threshold_name, metric_type, service_name, warning_threshold, critical_threshold,
         severity, enabled, comparison_operator, duration_minutes,
         notify_in_app, notify_email, notify_slack, notify_webhook, description)
    VALUES
        ('auth-service response time', 'response_time', 'auth-service', 1000, 2500,
         'high', true, 'gt', 5, true, false, false, false,
         'Authentication is on every request path; p95 health latency above 1s means sign-in is already painful.'),
        ('inventory-service response time', 'response_time', 'inventory-service', 1000, 2500,
         'high', true, 'gt', 5, true, false, false, false,
         'The primary tenant data path. Slow here is slow everywhere in the product.'),
        ('postgres response time', 'response_time', 'postgres', 1000, 2500,
         'high', true, 'gt', 5, true, false, false, false,
         'The datastore every service depends on — usually the root cause when several services slow at once.');
END $$;

-- =================================================================
-- Edition-gate correction (idempotent, must run on every seed)
-- =================================================================
--
-- Invariant: NO subscription tier may grant an edition-gated capability.
--
-- The tier_entitlements insert above uses ON CONFLICT DO NOTHING, so flipping
-- the seeded values alone would only fix FRESH databases. Every deployment
-- seeded before this change keeps its old rows forever — including any that
-- granted paid capability from the enterprise tier, which is exactly the hole
-- this closes. Hence a corrective UPDATE rather than a value change alone.
--
-- Why it is safe to run every time: edition-gated capability is granted by an
-- entitlement TOKEN, which writes tenant_entitlements overrides
-- (admin-service/ee/edition/seeder.go). Overrides outrank tiers in the
-- resolver, so a licensed deployment is unaffected by what the tier says. The
-- only thing this can take away is capability nobody was entitled to.
--
-- Keep this list in sync with editionByItem in shared/entitlements/editions.go.
-- `make audit` enforces the partition; a key added there and missed here would
-- leave a tier able to self-grant it.
UPDATE tier_entitlements te
SET    included_value = '{"enabled": false}'::jsonb,
       updated_at     = now()
FROM   billable_items bi
WHERE  bi.id = te.item_id
  AND  bi.key IN (
         'custom_policies', 'threshold_overrides',
         'ot_active_probing', 'ot_primary_lens',
         'cbom_signing', 'sso_saml', 'custom_branding',
         'cmdb_sync', 'siem_export', 'billing_portal'
       )
  AND  te.included_value IS DISTINCT FROM '{"enabled": false}'::jsonb;


-- =================================================================
-- Built-in service-identification rules (port heuristic)
-- =================================================================
-- inventory-service's ServiceIdentificationService.GetPortHeuristic is the only
-- reader of service_identification_rules, and until this block nothing ever
-- wrote a row: the built-ins were data statements inside schema.sql and a
-- `pg_dump --schema-only` regeneration of that file dropped them. The table has
-- been empty on every install since. Symptom, with nothing logged anywhere: a
-- passively discovered TLS asset is labelled the literal "TLS Service", and
-- every third-party external connection and every EnrichAllAssets backfill
-- (both call IdentifyService with rawData=nil, so only the port heuristic can
-- fire) leaves service_name / service_version / service_confidence /
-- service_identification_method NULL — the asset drawer's Service row is blank.
--
-- They live in seed.sql, not schema.sql, precisely because schema.sql is the
-- file that gets regenerated from a live database; these are data rows and
-- belong with the other reference data (algorithms, measurement_types, tiers).
-- The chart's seed-data Job runs post-install AND post-upgrade, so existing
-- deployments pick the rules up on their next upgrade.
--
-- SHAPE. Columns are exactly (port, protocol, service_name, service_category,
-- is_builtin, tenant_id) — there is no confidence column. Confidence is decided
-- by the CONSUMER: a match here is always reported as `low` with method
-- `port_heuristic`, while a parsed SSH/SMTP/FTP banner is reported `high`. So a
-- rule can never overclaim in the UI; what a rule can do is put a WRONG name on
-- an asset, and a confidently wrong service label is worse than a generic one.
-- That is the whole selection criterion below, and it is why several rows from
-- the pre-regeneration set are deliberately NOT restored:
--   * 3000 "Node/Dev", 5000 "Flask/Dev", 8888 "Jupyter" — framework guesses.
--     3000 is Grafana as often as node; 5000 is AirPlay/registry; 8888 is a
--     generic alternate HTTP port.
--   * 9090 — DELIBERATELY UNNAMED, decided rather than overlooked; do not
--     re-litigate. The original "Prometheus" row was dropped because Prometheus
--     serves plain HTTP by default, so a TLS listener on 9090 is more often
--     Cockpit (which serves HTTPS there). Cockpit was NOT added in its place,
--     because that argument stopped holding: Prometheus has shipped native TLS
--     via --web.config.file since 2.24, and enabling it is exactly what a
--     hardened estate — the kind that runs this product — does. TLS on 9090 is
--     therefore genuinely ambiguous between at least two common services, and
--     by this block's own selection rule a confidently wrong label is worse
--     than none. 9090 falls through to a blank Service row, the same honest
--     answer any unrecognised port gets. If it is ever named, it needs a
--     stronger signal than the port — a banner or a JA3S match, not a guess.
--   * 992 "Telnet-over-TLS" — effectively extinct; a TLS listener there today
--     is more likely something else entirely.
--   * 990 "FTPS-data" — simply wrong. 990 is the implicit-FTPS CONTROL port;
--     989 is its data channel. Corrected below.
--
-- PROTOCOL VALUES ARE UPPERCASE on purpose. The lookup matches the caller's raw
-- protocol OR its normalized form, and the normalized form is
-- strings.ToUpper(protocol) for anything outside the TLS/SSH alias map — so an
-- uppercase row matches "Modbus", "modbus" and "MODBUS" alike.
--
-- SCOPE. A rule only fires once the protocol is already known, so its job is to
-- name the APPLICATION riding on that protocol. For TLS that is genuinely
-- informative (TLS says nothing about the service). For SSH/SMB/OT the protocol
-- already names the service, so only the ports the platform itself probes get a
-- row — see the curated map in shared/discovery/sweep.go. OT protocols the
-- platform does not port-probe (DNP3, S7/MMS, HART-IP) are named by the
-- sensor's own protocol classification and are deliberately absent here rather
-- than guessed at from a port.
--
-- Idempotent: ON CONFLICT targets the partial unique index over the built-in
-- (tenant_id IS NULL) rows, so re-running the seed on every upgrade is a no-op
-- and a tenant's own override row for the same port is untouched.
INSERT INTO service_identification_rules (port, protocol, service_name, service_category, is_builtin, tenant_id) VALUES
    -- Web. 443 is as close to certain as a port gets. The alternates are
    -- named "HTTPS (alternate)" rather than guessing at a product, because
    -- 8443/9443/10443/8080 host every admin console ever written.
    (443,   'TLS', 'HTTPS',                     'web',           true, NULL),
    (8443,  'TLS', 'HTTPS (alternate)',         'web',           true, NULL),
    (9443,  'TLS', 'HTTPS (alternate)',         'web',           true, NULL),
    (10443, 'TLS', 'HTTPS (alternate)',         'web',           true, NULL),
    (8080,  'TLS', 'HTTPS (alternate)',         'web',           true, NULL),

    -- Directory. 636 and 3269 are LDAP-only; 3269 is the AD Global Catalog.
    (636,   'TLS', 'LDAPS',                     'directory',     true, NULL),
    (3269,  'TLS', 'LDAPS (Global Catalog)',    'directory',     true, NULL),

    -- Mail. 465 is implicit-TLS submission (RFC 8314), 587 is the STARTTLS
    -- submission port; both are mail-only.
    (465,   'TLS', 'SMTPS',                     'mail',          true, NULL),
    (587,   'TLS', 'SMTP Submission',           'mail',          true, NULL),
    (993,   'TLS', 'IMAPS',                     'mail',          true, NULL),
    (995,   'TLS', 'POP3S',                     'mail',          true, NULL),
    -- STARTTLS on the cleartext mail ports. TLS observed on 25/143/110 can only
    -- be the STARTTLS upgrade of that port's own protocol — these ports serve
    -- nothing else — which makes them a SAFER inference than the 8080 rule
    -- above, where "HTTPS (alternate)" is a guess about an arbitrary admin
    -- console. Named for the upgrade so the drawer says what was observed.
    (25,    'TLS', 'SMTP (STARTTLS)',           'mail',          true, NULL),
    (143,   'TLS', 'IMAP (STARTTLS)',           'mail',          true, NULL),
    (110,   'TLS', 'POP3 (STARTTLS)',           'mail',          true, NULL),

    -- File transfer. 990 = implicit FTPS control; TLS seen on 21 is explicit
    -- FTPS (AUTH TLS) — the only way TLS appears on the FTP control port.
    (990,   'TLS', 'FTPS (implicit)',           'file',          true, NULL),
    (21,    'TLS', 'FTPS (explicit)',           'file',          true, NULL),

    -- Network services. Each of these ports exists only for the TLS-wrapped
    -- form of its protocol. The second 853 row covers callers that report the
    -- protocol as "DoT" rather than "TLS".
    (853,   'TLS', 'DNS over TLS',              'network',       true, NULL),
    (853,   'DOT', 'DNS over TLS',              'network',       true, NULL),
    (5061,  'TLS', 'SIP over TLS',              'voice',         true, NULL),
    (2083,  'TLS', 'RADIUS over TLS (RadSec)',  'network',       true, NULL),
    (6514,  'TLS', 'Syslog over TLS',           'logging',       true, NULL),

    -- Remote access and management.
    (3389,  'TLS', 'RDP',                       'remote_access', true, NULL),
    (5986,  'TLS', 'WinRM over HTTPS',          'management',    true, NULL),
    (2376,  'TLS', 'Docker daemon (TLS)',       'container',     true, NULL),
    (6443,  'TLS', 'Kubernetes API',            'container',     true, NULL),

    -- Datastores. Labelled by WIRE PROTOCOL, not product, where a fork shares
    -- the port: 3306 is MariaDB as often as MySQL, 9200 is OpenSearch as often
    -- as Elasticsearch, and 6379 carries Valkey/KeyDB as well as Redis.
    (5432,  'TLS', 'PostgreSQL',                'database',      true, NULL),
    (3306,  'TLS', 'MySQL/MariaDB',             'database',      true, NULL),
    (1433,  'TLS', 'Microsoft SQL Server',      'database',      true, NULL),
    (2484,  'TLS', 'Oracle Database (TCPS)',    'database',      true, NULL),
    (27017, 'TLS', 'MongoDB',                   'database',      true, NULL),
    (6379,  'TLS', 'Redis',                     'cache',         true, NULL),
    (9200,  'TLS', 'Elasticsearch/OpenSearch',  'search',        true, NULL),

    -- Messaging.
    (5671,  'TLS', 'AMQPS',                     'messaging',     true, NULL),
    (8883,  'TLS', 'MQTTS',                     'messaging',     true, NULL),

    -- SSH. 2222 is the conventional alternate and is named as such rather than
    -- being attributed to a particular appliance.
    (22,    'SSH', 'SSH',                       'remote_access', true, NULL),
    (2222,  'SSH', 'SSH (alternate)',           'remote_access', true, NULL),

    -- SMB (probed by shared/discovery/sweep.go).
    (445,   'SMB', 'SMB',                       'file',          true, NULL),
    (139,   'SMB', 'SMB over NetBIOS',          'file',          true, NULL),

    -- OT / ICS — exactly the OT ports shared/discovery/sweep.go probes.
    (502,   'MODBUS',      'Modbus/TCP',        'ot',            true, NULL),
    (4840,  'OPC_UA',      'OPC UA',            'ot',            true, NULL),
    (44818, 'ETHERNET_IP', 'EtherNet/IP',       'ot',            true, NULL),
    (47808, 'BACNET',      'BACnet/IP',         'ot',            true, NULL)
ON CONFLICT (port, protocol) WHERE tenant_id IS NULL DO NOTHING;
