---
render_macros: false
---

# Deployment Migration Checklist

This checklist ensures the new security and scalability improvements are properly deployed across all environments.

## Pre-Deployment

### Code Changes
- [x] RLS policies migration created (`24-rls-policies.sql`)
- [x] Table partitioning migration created (`25-table-partitioning.sql`)
- [x] RLS context middleware implemented
- [x] Query validation middleware implemented
- [x] Registration key validation strengthened
- [x] Development bypass security improved
- [x] Docker Compose files updated with new migrations
- [x] CI/CD pipeline updated to include new migrations

### Documentation
- [x] Architecture improvements documented (`ARCHITECTURE_IMPROVEMENTS.md`)
- [x] Database migration guide created (`docsv4/operations/deployment/database-migrations.md`)
- [x] RDS migration script created (`scripts/apply-rds-migrations.sh`)

## Deployment by Environment

### Development (Docker Compose)

- [ ] **For existing databases**: Apply RLS migration manually
  ```bash
  docker exec crypto-postgres psql -U crypto_user -d crypto_inventory \
    -f /docker-entrypoint-initdb.d/24-rls-policies.sql
  ```

- [ ] **For new databases**: Migrations auto-apply on startup (already configured)

- [ ] Verify RLS is enabled:
  ```bash
  docker exec crypto-postgres psql -U crypto_user -d crypto_inventory -c \
    "SELECT tablename, rowsecurity FROM pg_tables WHERE tablename IN ('sensors', 'pending_sensors');"
  ```

- [ ] Deploy updated sensor-manager service
- [ ] Test tenant isolation works correctly
- [ ] Verify no RLS-related errors in logs

### EC2-Smoke

- [ ] **Apply RLS migration** (REQUIRED before deploying updated service):
  ```bash
  docker compose -f docker-compose.ec2-smoke.yml exec -T postgres \
    psql -U crypto_user -d crypto_inventory \
    -f /docker-entrypoint-initdb.d/24-rls-policies.sql
  ```

- [ ] Verify migration success (see verification section below)
- [ ] Deploy updated sensor-manager service
- [ ] Run smoke tests
- [ ] Verify tenant isolation
- [ ] Monitor logs for errors

### Production (Docker Compose)

- [ ] **Backup database** before applying migrations
- [ ] **Apply RLS migration** (REQUIRED):
  ```bash
  docker compose -f docker-compose.prod.yml exec -T postgres \
    psql -U crypto_user -d crypto_inventory \
    -f /docker-entrypoint-initdb.d/24-rls-policies.sql
  ```

- [ ] Verify migration success
- [ ] Deploy updated sensor-manager service (rolling deployment recommended)
- [ ] Monitor service health and logs
- [ ] Verify tenant isolation in production
- [ ] Check performance metrics

### RDS (AWS Managed PostgreSQL)

- [ ] **Backup RDS instance** (automated backups should be enabled)
- [ ] **Apply RLS migration** using one of these methods:

  **Option A: Using migration script (Recommended)**
  ```bash
  ./scripts/apply-rds-migrations.sh prod
  ```

  **Option B: Manual psql connection**
  ```bash
  export PGPASSWORD=your-password
  psql -h your-rds-instance.region.rds.amazonaws.com \
    -U crypto_user -d crypto_inventory \
    -f scripts/database/24-rls-policies.sql
  ```

  **Option C: AWS RDS Query Editor**
  - Copy contents of `scripts/database/24-rls-policies.sql`
  - Paste into RDS Query Editor
  - Execute

- [ ] Verify migration success (see verification section)
- [ ] Update application connection strings if needed
- [ ] Deploy updated sensor-manager service
- [ ] Monitor CloudWatch logs for RLS-related errors
- [ ] Verify tenant isolation

### EKS (Kubernetes with RDS)

- [ ] **Backup RDS instance**
- [ ] **Create ConfigMap with migration files**:
  ```bash
  kubectl create configmap db-migrations \
    --from-file=24-rls-policies.sql=scripts/database/24-rls-policies.sql \
    -n crypto-inventory
  ```

- [ ] **Apply migration using Kubernetes Job** (see `DATABASE_MIGRATION_GUIDE.md`)
- [ ] Verify migration success
- [ ] Update sensor-manager deployment with new image
- [ ] Monitor pod logs for RLS context errors
- [ ] Verify tenant isolation

## Verification Steps

### 1. Check RLS is Enabled

```sql
SELECT tablename, rowsecurity 
FROM pg_tables 
WHERE schemaname = 'public' 
AND tablename IN ('sensors', 'pending_sensors', 'sensor_discoveries', 
                  'network_assets', 'crypto_implementations');
```

**Expected**: All tables should show `rowsecurity = true`

### 2. Check RLS Policies Exist

```sql
SELECT tablename, policyname 
FROM pg_policies 
WHERE schemaname = 'public' 
AND tablename IN ('sensors', 'pending_sensors', 'sensor_discoveries', 
                  'network_assets', 'crypto_implementations');
```

**Expected**: At least one policy per table (e.g., `sensors_tenant_isolation`)

### 3. Check Security Functions

```sql
SELECT proname 
FROM pg_proc 
WHERE proname IN ('set_tenant_context', 'clear_tenant_context');
```

**Expected**: Both functions should exist

### 4. Test Tenant Isolation (Development/Staging Only)

```sql
-- Set tenant context
SELECT set_tenant_context('test-tenant-uuid'::uuid);

-- Query should only return data for that tenant
SELECT id, name, tenant_id FROM sensors LIMIT 10;

-- Clear context
SELECT clear_tenant_context();
```

### 5. Application Logs

Check sensor-manager logs for:
- No RLS-related errors
- Successful tenant context setting
- Normal query execution

```bash
# Docker Compose
docker logs crypto-sensor-manager | grep -i "rls\|tenant\|error"

# Kubernetes
kubectl logs -n crypto-inventory deployment/sensor-manager | grep -i "rls\|tenant\|error"
```

## Rollback Plan

If issues occur after deployment:

### Immediate Rollback (Emergency)

1. **Revert service deployment** to previous version
2. **RLS can remain enabled** - it won't break old code (old code just won't use it)
3. **Investigate issues** in staging before re-deploying

### Full Rollback (If Needed)

```sql
-- Disable RLS on specific table (emergency only)
ALTER TABLE sensors DISABLE ROW LEVEL SECURITY;

-- Drop policies (if needed)
DROP POLICY IF EXISTS sensors_tenant_isolation ON sensors;
```

**Warning**: Only disable RLS in emergencies. Re-enable immediately after fixing issues.

## Post-Deployment Monitoring

### First 24 Hours

- [ ] Monitor application logs for RLS errors
- [ ] Check query performance (should be unchanged)
- [ ] Verify tenant isolation is working
- [ ] Monitor database connection pool usage
- [ ] Check for any authentication/authorization issues

### First Week

- [ ] Review query performance metrics
- [ ] Check for any tenant data leakage (security audit)
- [ ] Verify all tenants can access their data correctly
- [ ] Monitor database resource usage

## Optional: Table Partitioning

Table partitioning (`25-table-partitioning.sql`) is **optional** and can be applied later when scaling needs arise (1000+ tenants).

### When to Apply Partitioning

- Database size > 100GB
- Query performance degrading
- Planning for 1000+ tenants
- Need for tenant-level maintenance operations

### How to Apply

See `DATABASE_MIGRATION_GUIDE.md` for detailed instructions. Partitioning requires:
1. Creating partitioned tables
2. Migrating data
3. Creating views or renaming tables
4. Testing thoroughly

## Support and Troubleshooting

### Common Issues

1. **"permission denied for function set_tenant_context"**
   - Solution: Grant execute permission (migration should handle this)

2. **"RLS blocking all queries"**
   - Check: Tenant context is being set by middleware
   - Check: Policies allow empty string for system operations

3. **"Migration fails with syntax error"**
   - Check: PostgreSQL version (requires 12+)
   - Check: Migration file is complete

### Getting Help

- Review `ARCHITECTURE_IMPROVEMENTS.md` for architecture details
- Review `DATABASE_MIGRATION_GUIDE.md` for migration procedures
- Check application logs for specific error messages
- Test in development environment first

## Sign-Off

After completing deployment:

- [ ] All environments migrated
- [ ] RLS verified in all environments
- [ ] Services deployed and healthy
- [ ] Tenant isolation verified
- [ ] Performance acceptable
- [ ] Documentation updated
- [ ] Team notified of changes

**Deployment Date**: _______________
**Deployed By**: _______________
**Verified By**: _______________
