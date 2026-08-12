# Database Seeding Architecture

This document describes the two-tier database seeding system for the Crypto Inventory Platform.

## Overview

The platform uses a **two-tier seeding architecture** to separate core system data from optional demo/test data:

| Tier | Contents | Environments | Auto-Loaded |
|------|----------|--------------|-------------|
| **Tier 1** | Core system data (roles, frameworks, platform admin) | All (dev, smoke, prod) | Yes |
| **Tier 2** | Demo tenant, users, and test data | Optional (manual or QA Platform) | No |

**Tier 2 is optional.** Session-init and Tier 1 deployment validation do not assume any tenant exists. Tenant data is expected via the QA Platform (`tools/qa-platform/run.sh`) or `./scripts/database/load-demo-data.sh`.

## Quick Start

### Fresh Dev Deployment

For a **fresh development database**, use the main session starter. All database initialization is done by the schema and seed scripts; no migration scripts are run at init:

1. **Clean slate (optional):** `./scripts/cleanup-docker.sh --dev` to remove volumes.
2. **Start:** `./start-session.sh`

PostgreSQL runs only: `01-schema.sql` (schema.sql) and `02-seed.sql` (seed.sql). Then session-init runs `apply_core_seed.sh` and `04-ensure-licenses.sql`. Tier 2 (demo tenant) is **not** auto-loaded—use the QA Platform (`tools/qa-platform/run.sh`) or `./scripts/database/load-demo-data.sh` to add tenant data. See [Shutdown and Fresh Deployment](../../docsv4/development/workflows/shutdown-and-fresh-deployment.md) and [Fresh Development Deployment](../../docsv4/development/workflows/fresh-dev-deployment.md) for details.

**Existing databases:** All schema and Tier 1 seed are consolidated in `schema.sql` and `seed.sql`. For an existing DB, apply `schema.sql` (or the specific one-off script if documented). One-off scripts (e.g. `apply-source-ip-migration.sql`, `migrate-to-unified-notifications.sql`) are for repair or data migration only; with no customers, fresh init needs only schema + seed. (RBAC repair needs no separate script: re-running `seed.sql` reconciles the platform admin user and tenant roles/permissions idempotently.)

### Development Environment

```bash
# Start development session (Tier 1 only; add tenant data via QA Platform or load-demo-data.sh)
./start-session.sh
```

### Smoke Environment

```bash
# Deploy to smoke (prompts for demo data)
./scripts/deploy-smoke.sh

# Deploy with demo data (no prompt)
./scripts/deploy-smoke.sh --with-demo

# Deploy without demo data (no prompt)
./scripts/deploy-smoke.sh --no-demo
```

### Manual Demo Data Loading

```bash
# Load demo data after deployment
./scripts/database/load-demo-data.sh
```

## File Structure

```
scripts/database/
├── schema.sql                              # Single source for DB init (01-schema.sql): full DDL + built-in data + permission reconciliation
├── seed.sql                                # Tier 1: Core system data + RBAC init (02-seed.sql). Only 01 and 02 run at Docker init.
├── critical-tables.sql                     # Legacy fallback (content in schema.sql); used by database-validation repair only
├── 04-ensure-licenses.sql                  # Best Practices licenses for all tenants; run by session-init (not at Docker init)
├── migrations/README.md                    # Notes: migrations consolidated into schema.sql; no migration scripts at init
├── apply-source-ip-migration.sql           # One-off for existing DBs only (source_ip already in schema.sql)
├── migrate-to-unified-notifications.sql   # One-off data migration for existing DBs (no customers = not needed for fresh init)
├── seed_demo.sql                           # Tier 2: Demo tenant + users
├── seed_democorp_assets.sql                # Tier 2: Demo assets (265+ assets)
├── seed_democorp_crypto_implementations.sql# Tier 2: Crypto implementations
├── seed_democorp_compliance.sql            # Tier 2: Compliance framework configuration
├── seed_democorp_compliance_violations.sql # Tier 2: Assets/certificates with violations
├── trigger-compliance-evaluation.go        # Go CLI tool to trigger evaluation events
├── trigger-compliance-evaluation.sh        # Bash wrapper for the Go tool
├── load-demo-data.sh                       # Script to load Tier 2 data (canonical)
├── validate-deployment.sh                  # Validation script
├── archive/                                # Archived migrations and scripts (for reference only)
└── README.md                               # This file
```

## Tier 1: Core System Data

**File:** `seed.sql` (single consolidated file: templates, frameworks, and RBAC init)

Contains essential data required for the platform to function:

- **Platform Roles** (`platform_roles`): `super_admin`, `platform_admin`, `support_agent`
- **Platform Users** (`platform_users`): `su_admin@vistaplatform.invalid` (super_admin), `admin@vistaplatform.invalid` (platform_admin)
- **Subscription Tiers** (`subscription_tiers`): `free`, `professional`, `enterprise`
- **Tenant Permissions** (`tenant_permissions`): All permission definitions
- **Measurement Types** (`measurement_types`): TLS, certificate, encryption types
- **Measurement Templates** (`measurement_templates`): Compliance rule templates
- **Platform Frameworks** (`platform_frameworks`): SOC2, PCI-DSS, NIST, ISO27001, Best Practices
- **Asset Lifecycle Policies**: Default policies for tenants
- **RBAC initialization**: Platform admin user ensure and tenant roles/permissions for all tenants (consolidated from ensure-rbac-initialization.sql)

**Important:** Tier 1 does NOT include:
- Any tenants
- Any tenant-specific roles (created dynamically when tenants are onboarded)
- Any tenant users

## Tier 2: Demo Data

**Files:** `seed_demo.sql`, `seed_democorp_assets.sql`

Contains optional demo/test data:

- **Demo Tenant**: Demo Corporation (`demo-corp`)
- **Tenant Roles**: 6 roles for demo-corp (billing_admin, tenant_admin, etc.)
- **Role Permissions**: Permission mappings for each role
- **Demo Users** (all passwords: `Password123!`):
  - `owner@democorp.com` - Billing Admin
  - `admin@democorp.com` - Tenant Admin  
  - `security@democorp.com` - Security Admin
  - `analyst@democorp.com` - Viewer (analyst role retired, #219)
  - `viewer@democorp.com` - Viewer
  - `api@democorp.com` - API User
- **User Role Assignments**: Each user assigned their respective role
- **Demo Assets**: 265+ network assets with complete data:
  - Production: 104 assets (web servers, databases, APIs, firewalls, load balancers, cache servers)
  - Staging: 63 assets (web servers, databases, APIs, test servers)
  - Development: 73 assets (workstations, servers, services, databases)
  - Test: 25 assets (test servers, endpoints)
  - Legacy: 10 assets (legacy servers)
  - Cloud: 15 assets (cloud services)
  - Network: 10 assets (network appliances)
  - All assets include proper `asset_status` and `asset_ownership` values
  - Mix of `first_party` and `third_party` ownership
  - Mix of `monitoring` and `pending_approval` status
- **Compliance Configuration**: Tenant framework setup for demo tenant:
  - Tenant framework copy of Best Practices framework (10 controls)
  - All controls and measurements copied from platform framework
  - Framework automatically selected in tenant settings
  - Enables compliance evaluation and reporting
- **Compliance Violations**: Assets and certificates with actual violations:
  - Seeded via `seed_democorp_compliance_violations.sql`
  - Violations match NIST CSF controls (PR.DS-1, PR.DS-2, PR.DS-3)
  - Findings generated through event-driven evaluation (see below)

## Environment Behavior

### Development (`DEPLOY_ENV=development` or unset)

1. `./start-session.sh` starts infrastructure
2. `schema.sql` applied by Docker entrypoint
3. `seed.sql` applied (Tier 1 - includes templates and frameworks)
4. Session-init runs `apply_core_seed.sh` and `04-ensure-licenses.sql`. **Tier 2 is not auto-loaded.**

To add tenant data:
- **QA Platform:** Run `tools/qa-platform/run.sh`, add a connection to the platform, then run a simulation (direct_import or full_pipeline) to create tenants and seed inventory via the API.
- **Legacy demo:** Run `./scripts/database/load-demo-data.sh` to load the demo-corp tenant, users, assets, compliance config, and violations (as in the Tier 2 file list below).

**Result:** Platform ready with core data; tenant data added on demand via QA Platform or manual load-demo-data.sh.

### Smoke (`DEPLOY_ENV=smoke`)

1. `./scripts/deploy-smoke.sh` starts infrastructure
2. Schema and Tier 1 data applied
3. **Interactive prompt** asks if demo data should be loaded
4. Services started

**Result:** Platform ready for smoke testing, optionally with demo data.

### Production

1. Tier 1 data only
2. No demo data
3. Real tenants onboarded through the application

## Tenant Role Creation

When a new tenant is onboarded (not from seed), the `auth-service` automatically creates standard roles:

```go
// From auth-service/internal/auth/service.go
defaultRoles := []struct {
    name        string
    displayName string
    description string
}{
    {"billing_admin", "Billing Admin", "Full tenant control"},
    {"tenant_admin", "Tenant Administrator", "Tenant management"},
    {"security_admin", "Security Administrator", "Security settings"},
    {"viewer", "Viewer", "Read-only access"},
    {"api_user", "API User", "API-only access"},
}
```

This means:
- Tier 1 does NOT need tenant roles (no tenants exist yet)
- Demo tenant (Tier 2) includes roles because it bypasses normal onboarding

## Event-Driven Compliance Findings

### Overview

Compliance findings are generated through an **event-driven evaluation system** rather than being directly inserted into the database. This ensures findings:

1. **Persist through re-evaluation** - Findings match actual asset violations
2. **Update automatically** - When assets change, findings are re-evaluated
3. **Match real violations** - Only findings for actual detected violations are created

### How It Works

1. **Violation Seeding** (`seed_democorp_compliance_violations.sql`):
   - Creates assets and certificates with actual violations
   - Examples:
     - **PR.DS-1**: Certificate with 1024-bit RSA key (< 2048 bit threshold)
     - **PR.DS-2**: Network asset with TLS 1.0 (weak TLS version)
     - **PR.DS-3**: Certificate expiring in 15 days (< 30 day threshold)

2. **Event Triggering** (`trigger-compliance-evaluation.sh`):
   - Publishes `AssetChangedEvent` events for all demo tenant assets
   - Events are published via NATS to the compliance engine
   - Uses bulk publishing for efficiency when many assets exist

3. **Evaluation** (compliance-engine service):
   - Receives `AssetChangedEvent` events
   - Evaluates controls against asset measurements
   - Generates findings for detected violations
   - Marks findings as `ACTIVE` or `INACTIVE` based on current state

### Environment Behavior

- **Development** (`DEPLOY_ENV=development`): Violations seeded and events triggered automatically
- **Smoke** (`DEPLOY_ENV=smoke`): Only if `--with-demo` flag is used
- **Production** (`DEPLOY_ENV=production`): Demo findings generation is skipped

### Manual Triggering

To manually trigger compliance evaluation after seeding:

```bash
# Trigger evaluation for demo-corp tenant
./scripts/database/trigger-compliance-evaluation.sh

# Or with custom tenant
./scripts/database/trigger-compliance-evaluation.sh -tenant my-tenant-slug
```

### Troubleshooting

**No findings generated after seeding:**

1. Check that violations were seeded:
   ```bash
   docker exec crypto-postgres psql -U crypto_user -d crypto_inventory -c "
     SELECT hostname, tags->>'compliance_violation' as violation
     FROM network_assets
     WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'demo-corp')
     AND tags->>'compliance_violation' IS NOT NULL;
   "
   ```

2. Check that NATS is running:
   ```bash
   docker ps | grep nats
   ```

3. Check compliance-engine logs for evaluation errors:
   ```bash
   docker logs crypto-compliance-engine
   ```

4. Manually trigger evaluation:
   ```bash
   ./scripts/database/trigger-compliance-evaluation.sh
   ```

**Findings marked as INACTIVE:**

This is expected if the asset no longer has the violation. The evaluation system automatically marks findings as `INACTIVE` when violations are resolved. To ensure findings remain `ACTIVE`, the seeded violations must match actual asset data.

## Validation

```bash
# Validate Tier 1 only
./scripts/database/validate-deployment.sh

# Validate Tier 1 + Tier 2 (demo data)
./scripts/database/validate-deployment.sh --demo
```

Expected Tier 1 counts:
- Platform Roles: >= 3
- Platform Users: >= 1
- Subscription Tiers: >= 3
- Tenant Permissions: >= 10
- Published Frameworks: >= 5
- Measurement Types: >= 5
- Measurement Templates: >= 5

Expected Tier 2 counts (if demo loaded):
- Demo Tenant: 1
- Demo Tenant Roles: 6
- Demo Users: 6
- Demo Role Assignments: 6

## Troubleshooting

### No frameworks after seeding

Frameworks require `measurement_types` to exist first. Ensure `schema.sql` was fully applied.

```bash
# Check measurement types
docker exec crypto-postgres psql -U crypto_user -d crypto_inventory -c \
  "SELECT code FROM measurement_types ORDER BY code;"
```

### Demo users can't login

Ensure tenant roles and role assignments exist:

```bash
docker exec crypto-postgres psql -U crypto_user -d crypto_inventory -c "
  SELECT u.email, tr.name as role
  FROM users u
  JOIN user_tenant_roles utr ON u.id = utr.user_id
  JOIN tenant_roles tr ON utr.role_id = tr.id
  WHERE u.email LIKE '%@democorp.com';
"
```

### Platform admin can't login

Check platform users:

```bash
docker exec crypto-postgres psql -U crypto_user -d crypto_inventory -c "
  SELECT pu.email, pr.name as role, pu.is_active
  FROM platform_users pu
  JOIN platform_roles pr ON pu.role_id = pr.id;
"
```

## Related Files

- `scripts/session-init.sh` - Development environment startup
- `scripts/deploy-smoke.sh` - Smoke environment deployment
- `scripts/apply_core_seed.sh` - Applies seed.sql with validation (includes templates and frameworks)
- `scripts/database-validation.sh` - Database validation helpers
