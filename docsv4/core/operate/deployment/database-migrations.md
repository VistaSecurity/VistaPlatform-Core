---
render_macros: false
---

# Database Migration Guide

## Overview

This guide explains how database schema is managed for the crypto inventory platform across different deployment environments, including Docker Compose, EC2, EKS, and RDS.

## Schema & Seed Management Pattern

**Single Source of Truth Approach:**

All database schema and seed data is maintained in two files:

- **`scripts/database/schema.sql`** – Consolidated schema file (manually maintained)
  - Contains all schema definitions: extensions, types, tables, indexes, functions, RLS policies, etc.
  - **Manually maintained** – edit this file directly when schema changes are needed
  - Used for new database initialization in all environments
  - Idempotent – safe to run on existing databases (uses `CREATE TABLE IF NOT EXISTS`, etc.)

- **`scripts/database/seed.sql`** – Core platform seed data (manually maintained)
  - Contains platform admin users (`platform_users`), subscription tiers, measurement templates, and the free compliance frameworks (`platform_frameworks`, `platform_framework_controls`, `control_measurements`)
  - **Manually maintained** – edit this file when core configuration changes are needed
  - Applied automatically by Postgres's own init mechanism, immediately after `schema.sql`, in every environment

For re-seeding an *existing* database idempotently (e.g. after a partial apply), `scripts/apply_core_seed.sh` re-runs `seed.sql` via `docker exec` with dependency checks.

**Archived Files:**

Individual per-feature migration files have been consolidated into `schema.sql` and removed — there is no directory of historical migration files to consult. All schema changes should now be made directly to `schema.sql`.

### Schema File Structure

The consolidated `schema.sql` includes (in order):
1. **Database initialization** - Extensions, types, functions (`init.sql`)
2. **Authentication schema** - Tenants, users (`001_auth_schema.sql`)
3. **Core platform** - Assets, certificates, implementations (`migrations.sql`)
4. **RBAC system** - Roles and permissions (`05-rbac-migration.sql`)
5. **Feature schemas** - Discovery, sensors, artifacts, integrations, etc.
6. **Compliance frameworks** - Frameworks, controls, measurements, templates
   - Framework management (`27-compliance-framework-management.sql`)
   - Measurement templates (`28-measurement-templates.sql`)
   - Enhanced measurement types (`30-enhance-measurement-types.sql`)
7. **Security** - Row Level Security policies (`24-rls-policies.sql`)
8. **Scalability** - Table partitioning (`25-table-partitioning.sql`)

### Seed Data

Seed data is split into **core** and **demo** layers:

- **Core seed (`seed.sql`)**:
  - Platform admins, measurement templates, and platform frameworks
  - Required in **all** environments (dev, smoke, prod)
  - Applied explicitly using `psql` in session/deployment scripts

- **Demo seed (Tier 2)**:
  - Demo tenants, demo users, bulk asset data, compliance violations
  - Optional and **dev-only** – used to provide a rich demo dataset for local development
  - Never applied automatically in production; smoke environments may choose not to run it at all
  - Includes event-driven compliance findings generation (see below)

### Demo Data Seeding and Event-Driven Findings

Demo data seeding uses an **event-driven approach** to generate compliance findings:

1. **Violation Seeding** (`seed_democorp_compliance_violations.sql`):
   - Creates assets and certificates with actual violations matching NIST CSF controls
   - Examples:
     - **PR.DS-1**: Certificate with 1024-bit RSA key (violates < 2048 bit threshold)
     - **PR.DS-2**: Network asset with TLS 1.0 (violates weak TLS version pattern)
     - **PR.DS-3**: Certificate expiring in 15 days (violates < 30 day threshold)

2. **Event Triggering** (`trigger-compliance-evaluation.sh`):
   - Publishes `AssetChangedEvent` events via NATS for all demo tenant assets
   - Triggers compliance engine evaluation
   - Generates findings naturally through the normal evaluation flow

3. **Benefits**:
   - Findings persist through re-evaluation (not marked INACTIVE)
   - Findings match actual asset violations
   - Automatic updates when assets change

**Environment Behavior:**
- **Development** (`DEPLOY_ENV=development`): Violations seeded and events triggered automatically
- **Smoke** (`DEPLOY_ENV=smoke`): Only if `--with-demo` flag is used
- **Production** (`DEPLOY_ENV=production`): Demo findings generation is skipped

For more details, see `scripts/database/README.md` and `docsv4/development/data-seeding.md`.

## Deployment Environments

### Docker Compose (Development/Testing)

**New Databases (Automatic + Script-Driven Seed):**

- On first startup, schema is automatically applied via `schema.sql` mount:

  ```yaml
  volumes:
    - ./scripts/database/schema.sql:/docker-entrypoint-initdb.d/01-schema.sql
    - ./scripts/database/seed.sql:/docker-entrypoint-initdb.d/02-seed.sql
  ```

- Both files are applied automatically by Postgres's own init mechanism on first
  startup — the container runs every `.sql` file it finds under
  `docker-entrypoint-initdb.d/` in filename order, so `01-schema.sql` runs before
  `02-seed.sql`. No script drives this; nothing else runs at startup.

The consolidated `schema.sql` file contains all schema definitions and is applied automatically when PostgreSQL initializes a new database. Platform admin users, subscription tiers, measurement templates and the free compliance frameworks are then loaded from `seed.sql`.

**Existing Databases (Manual):**

For existing databases, apply the consolidated schema (idempotent):

```bash
# Apply the full consolidated schema (will skip existing objects)
docker exec crypto-postgres psql -U crypto_user -d crypto_inventory \
  -f scripts/database/schema.sql
```

**Note:** The consolidated schema uses `CREATE TABLE IF NOT EXISTS` and similar idempotent statements, so it's safe to run on existing databases. All schema changes should be made to `schema.sql` directly.

### EC2-Smoke / Production (Docker Compose)

**New Databases (Automatic):**

Schema is automatically applied via the consolidated `schema.sql` file:

```yaml
volumes:
  - ./scripts/database/schema.sql:/docker-entrypoint-initdb.d/01-schema.sql
```

**Existing Deployments (Manual):**

For existing production databases, apply the consolidated schema:

```bash
# Apply full schema (idempotent - safe for existing databases)
docker compose -f docker-compose.prod.yml exec -T postgres \
  psql -U crypto_user -d crypto_inventory \
  -f scripts/database/schema.sql
```

### RDS (AWS Managed PostgreSQL)

For RDS deployments, migrations must be applied manually via `psql` or AWS RDS Query Editor.

#### Prerequisites
1. RDS instance accessible from your local machine or bastion host
2. Database credentials
3. Security group allows connections from your IP

#### Apply Schema

**Apply schema.sql directly** — there is no bundled RDS migration script in this repository; apply the schema with `psql` as shown below.

```bash
# Set connection details
export RDS_HOST=your-rds-instance.region.rds.amazonaws.com
export RDS_DB=crypto_inventory
export RDS_USER=crypto_user
export PGPASSWORD=your-password

# Apply consolidated schema (idempotent - safe for existing databases)
psql -h $RDS_HOST -U $RDS_USER -d $RDS_DB -f scripts/database/schema.sql
```

#### Using AWS RDS Query Editor

1. Navigate to RDS Console → Your Database → Query Editor
2. Copy contents of `scripts/database/schema.sql`
3. Paste and execute (may need to run in chunks if very large)

#### Using AWS Systems Manager Session Manager (Recommended for Production)

```bash
# Connect to bastion host via SSM
aws ssm start-session --target i-xxxxx

# From bastion, connect to RDS
psql -h $RDS_HOST -U $RDS_USER -d $RDS_DB -f /path/to/schema.sql
```

### EKS (Kubernetes)

For EKS deployments with RDS, apply migrations using a Kubernetes Job or directly via `kubectl exec`.

#### Option 1: Kubernetes Job (Recommended)

Create a migration job:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: db-migration-rls
  namespace: crypto-inventory
spec:
  template:
    spec:
      containers:
      - name: postgres-client
        image: postgres:17-alpine
        command:
        - /bin/sh
        - -c
        - |
          psql -h $RDS_HOST -U $RDS_USER -d $RDS_DB -f /migrations/schema.sql
        env:
        - name: RDS_HOST
          valueFrom:
            secretKeyRef:
              name: crypto-inventory-secrets
              key: rds-host
        - name: RDS_USER
          valueFrom:
            secretKeyRef:
              name: crypto-inventory-secrets
              key: rds-user
        - name: PGPASSWORD
          valueFrom:
            secretKeyRef:
              name: crypto-inventory-secrets
              key: rds-password
        volumeMounts:
        - name: migrations
          mountPath: /migrations
      volumes:
      - name: migrations
        configMap:
          name: db-migrations
      restartPolicy: Never
  backoffLimit: 3
```

Create ConfigMap with migration files:

```bash
kubectl create configmap db-migrations \
  --from-file=schema.sql=scripts/database/schema.sql \
  -n crypto-inventory
```

Apply the job:

```bash
kubectl apply -f migration-job.yaml
kubectl wait --for=condition=complete --timeout=300s job/db-migration-rls -n crypto-inventory
```

#### Option 2: kubectl exec (Quick)

If you have a pod with postgres client:

```bash
# Copy schema file to pod
kubectl cp scripts/database/schema.sql crypto-inventory/some-pod:/tmp/

# Execute schema
kubectl exec -n crypto-inventory some-pod -- \
  psql -h $RDS_HOST -U $RDS_USER -d $RDS_DB -f /tmp/schema.sql
```

## Making Schema Changes

### Editing schema.sql

When you need to make schema changes:

1. **Edit `scripts/database/schema.sql` directly**
   - Add new tables, columns, indexes, functions, etc.
   - Maintain proper dependency order (tables before foreign keys, etc.)
   - Use idempotent statements (`CREATE TABLE IF NOT EXISTS`, `CREATE OR REPLACE FUNCTION`, etc.)

2. **Test the changes**
   ```bash
   # Test with fresh database
   docker compose down -v
   docker compose up -d postgres
   # Verify schema applied correctly
   ```

3. **Apply to existing databases**
   - The schema is idempotent, so you can run it on existing databases with `psql -f scripts/database/schema.sql` (see the RDS section above for connecting to a managed Postgres instance)

### Schema Structure (for reference)

The consolidated schema applies migrations in this order:

1. **Database initialization** - Extensions, types, functions
2. **Authentication** - Tenants, users, platform users
3. **Core platform** - Assets, certificates, implementations
4. **RBAC** - Roles and permissions
5. **Features** - Discovery, sensors, artifacts, integrations, monitoring
6. **Security** - Row Level Security policies (REQUIRED for production)
7. **Scalability** - Table partitioning (optional, for high scale)

**Note:** For existing databases, you may need to apply individual migrations incrementally rather than the full consolidated schema.

## Verification

After applying migrations, verify they were successful:

### Check RLS is Enabled

```sql
-- Check if RLS is enabled on sensors table
SELECT tablename, rowsecurity 
FROM pg_tables 
WHERE schemaname = 'public' 
AND tablename IN ('sensors', 'pending_sensors', 'sensor_discoveries', 'network_assets', 'crypto_implementations');

-- Should show rowsecurity = true
```

### Check RLS Policies Exist

```sql
-- List all RLS policies
SELECT schemaname, tablename, policyname, permissive, roles, cmd, qual 
FROM pg_policies 
WHERE schemaname = 'public' 
AND tablename IN ('sensors', 'pending_sensors', 'sensor_discoveries', 'network_assets', 'crypto_implementations');

-- Should show policies for each table
```

### Check Security Functions Exist

```sql
-- Check if security functions exist
SELECT proname, proargtypes 
FROM pg_proc 
WHERE proname IN ('set_tenant_context', 'clear_tenant_context');

-- Should return 2 rows
```

### Test RLS (Development Only)

```sql
-- Set tenant context
SELECT set_tenant_context('your-tenant-uuid-here'::uuid);

-- Try to query sensors (should only see your tenant's sensors)
SELECT id, name, tenant_id FROM sensors;

-- Clear context
SELECT clear_tenant_context();
```

## Rollback Procedures

### RLS Policies Rollback

RLS policies can be disabled if needed (not recommended):

```sql
-- Disable RLS on a table (emergency only)
ALTER TABLE sensors DISABLE ROW LEVEL SECURITY;

-- Drop policies (if needed)
DROP POLICY IF EXISTS sensors_tenant_isolation ON sensors;
```

**Warning**: Disabling RLS removes database-level tenant isolation. Only do this in emergencies and re-enable immediately.

### Partitioning Rollback

Partitioning migration creates new tables but doesn't rename existing ones. To rollback:

1. Don't activate partitioned tables (keep using original tables)
2. Drop partitioned tables if created:

```sql
DROP TABLE IF EXISTS sensor_discoveries_partitioned CASCADE;
DROP TABLE IF EXISTS network_assets_partitioned CASCADE;
DROP TABLE IF EXISTS crypto_implementations_partitioned CASCADE;
```

## Pre-Deployment Checklist

Before deploying updated sensor-manager service with RLS support:

- [ ] RLS policies migration (`24-rls-policies.sql`) applied to database
- [ ] RLS policies verified (see Verification section)
- [ ] Security functions (`set_tenant_context`, `clear_tenant_context`) exist
- [ ] Application code updated (sensor-manager with RLS middleware)
- [ ] Tested in staging environment
- [ ] Backup database before production deployment

## Post-Deployment Verification

After deploying updated services:

1. **Check service logs** for RLS context errors:
   ```bash
   docker logs crypto-sensor-manager | grep -i "rls\|tenant"
   ```

2. **Test tenant isolation**:
   - Create test data for different tenants
   - Verify each tenant only sees their own data
   - Verify cross-tenant queries are blocked

3. **Monitor performance**:
   - Check query performance hasn't degraded
   - Monitor connection pool usage
   - Check for any RLS-related errors

## Troubleshooting

### RLS Blocking All Queries

If RLS is blocking all queries (including system queries):

```sql
-- Temporarily allow empty tenant context (development only)
-- Check if policies allow empty string
SELECT qual FROM pg_policies WHERE policyname LIKE '%tenant_isolation%';

-- Policies should include: OR current_setting('app.tenant_id', true) = ''
```

### Migration Fails with Permission Error

Ensure database user has necessary permissions:

```sql
-- Grant required permissions
GRANT EXECUTE ON FUNCTION set_tenant_context(UUID) TO crypto_user;
GRANT EXECUTE ON FUNCTION clear_tenant_context() TO crypto_user;
```

### Application Can't Set Tenant Context

Check middleware is setting context:

```sql
-- Check if context is being set (from application logs)
-- Should see: SELECT set_tenant_context(...) before queries
```

## Related Documentation

- [Production Checklist](./production-checklist.md) - Production deployment checklist
