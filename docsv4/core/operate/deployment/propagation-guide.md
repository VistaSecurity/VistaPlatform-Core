---
render_macros: false
---

# Deployment Propagation Guide

## Will Changes Propagate Automatically?

### ✅ YES - Automatic Propagation

These changes will **automatically propagate** when you:

1. **Build new Docker images** - Code changes are in the repository
2. **Deploy new containers** - Updated sensor-manager service includes RLS middleware
3. **Create new databases** - Migrations auto-apply via Docker Compose volume mounts

**Environments with automatic propagation:**
- ✅ New Docker Compose deployments (dev, smoke, prod)
- ✅ CI/CD test databases
- ✅ Fresh database initializations

### ⚠️ NO - Manual Steps Required

These require **manual migration** for existing databases:

1. **Existing Docker Compose databases** - Must apply RLS migration manually
2. **RDS (AWS Managed PostgreSQL)** - Must apply migrations via psql or AWS tools
3. **EKS with RDS** - Must apply migrations via Kubernetes Job or kubectl exec
4. **Any existing production database** - Must apply `24-rls-policies.sql` before deploying updated service

## What Needs to Be Updated?

### 1. Docker Compose Files ✅ DONE

All Docker Compose files updated with new migration volumes:
- ✅ `docker-compose.yml` (development)
- ✅ `docker-compose.prod.yml` (production)
- ✅ `docker-compose.ec2-smoke.yml` (smoke testing)
- ✅ `docker-compose.test.yml` (CI testing)

**What this means:**
- New databases: Migrations auto-apply on first startup
- Existing databases: Need manual migration (see below)

### 2. CI/CD Pipeline ✅ DONE

- ✅ `.github/workflows/ci.yml` - Updated to include RLS migration in test setup

**What this means:**
- CI tests will run with RLS enabled
- Test databases get RLS policies automatically

### 3. Deployment Scripts ✅ DONE

- ✅ `scripts/apply-rds-migrations.sh` - NEW script for RDS migrations

**What this means:**
- Easy migration for RDS deployments
- Supports dev, smoke, and prod environments

### 4. Documentation ✅ DONE

All documentation updated:
- ✅ `ARCHITECTURE_IMPROVEMENTS.md` - Architecture review summary
- ✅ `docsv4/operations/deployment/database-migrations.md` - Comprehensive migration guide
- ✅ `DEPLOYMENT_MIGRATION_CHECKLIST.md` - Step-by-step checklist
- ✅ `MIGRATION_DEPLOYMENT_SUMMARY.md` - Summary of all changes
- ✅ `QUICK_START_MIGRATIONS.md` - Quick reference
- ✅ `DEPLOYMENT_PROPAGATION_GUIDE.md` - This file
- ✅ `PRODUCTION_DEPLOYMENT_CHECKLIST.md` - Updated with RLS migration
- ✅ `docsv4/operations/deployment/production-checklist.md` - Updated with migration note

## Deployment by Environment

### Development (Docker Compose)

**Status**: ✅ Ready
- Migrations included in `docker-compose.yml`
- Auto-applies on new database initialization

**For existing database:**
```bash
docker exec crypto-postgres psql -U crypto_user -d crypto_inventory \
  -f /docker-entrypoint-initdb.d/24-rls-policies.sql
```

### EC2-Smoke

**Status**: ✅ Ready
- Migrations included in `docker-compose.ec2-smoke.yml`
- Auto-applies on new deployments

**For existing deployment:**
```bash
docker compose -f docker-compose.ec2-smoke.yml exec -T postgres \
  psql -U crypto_user -d crypto_inventory \
  -f /docker-entrypoint-initdb.d/24-rls-policies.sql
```

### Production (Docker Compose)

**Status**: ✅ Ready
- Migrations included in `docker-compose.prod.yml`
- Auto-applies on new deployments

**For existing deployment:**
```bash
# BACKUP FIRST!
docker compose -f docker-compose.prod.yml exec -T postgres \
  psql -U crypto_user -d crypto_inventory \
  -f /docker-entrypoint-initdb.d/24-rls-policies.sql
```

### RDS (AWS Managed PostgreSQL)

**Status**: ⚠️ Manual Migration Required
- RDS doesn't support Docker volume mounts
- Must apply migrations manually

**Options:**
1. **Migration script** (recommended):
   ```bash
   ./scripts/apply-rds-migrations.sh prod
   ```

2. **Manual psql**:
   ```bash
   export PGPASSWORD=your-password
   psql -h your-rds-host.region.rds.amazonaws.com \
     -U crypto_user -d crypto_inventory \
     -f scripts/database/24-rls-policies.sql
   ```

3. **AWS RDS Query Editor**:
   - Copy contents of `scripts/database/24-rls-policies.sql`
   - Paste into RDS Query Editor
   - Execute

4. **AWS Systems Manager Session Manager**:
   - Connect to bastion host
   - Run psql from bastion

### EKS (Kubernetes with RDS)

**Status**: ⚠️ Manual Migration Required
- Migrations must be applied to RDS
- Can use Kubernetes Job or kubectl exec

**Options:**
1. **Kubernetes Job** (recommended - see `DATABASE_MIGRATION_GUIDE.md`)
2. **kubectl exec** with postgres client pod

## Critical Deployment Order

**IMPORTANT**: For existing deployments, follow this order:

1. ✅ **Backup Database** (production/staging)
2. ✅ **Apply RLS Migration** (`24-rls-policies.sql`)
3. ✅ **Verify Migration** (check RLS enabled, policies exist)
4. ✅ **Deploy Updated sensor-manager Service**
5. ✅ **Verify Tenant Isolation**
6. ✅ **Monitor Logs**

**DO NOT** deploy updated sensor-manager before applying RLS migration to existing databases.

## Scripts Updated

### New Scripts
- ✅ `scripts/apply-rds-migrations.sh` - Applies migrations to RDS

### Existing Scripts (No Changes Needed)
- ✅ `scripts/deploy-ec2-smoke.sh` - Works as-is (migrations in docker-compose)
- ✅ `scripts/deploy-aws.sh` - Works as-is
- ✅ `scripts/deploy-with-ecr.sh` - Works as-is
- ✅ `Makefile` - No changes needed (uses docker-compose)

## Documentation Structure

```
Root Directory:
├── ARCHITECTURE_IMPROVEMENTS.md          # Architecture review summary
├── DEPLOYMENT_MIGRATION_CHECKLIST.md     # Step-by-step deployment
├── MIGRATION_DEPLOYMENT_SUMMARY.md        # Summary of all changes
├── QUICK_START_MIGRATIONS.md             # Quick reference
└── DEPLOYMENT_PROPAGATION_GUIDE.md       # This file

docsv4/operations/deployment/:
└── database-migrations.md                # Comprehensive migration guide

scripts/:
└── apply-rds-migrations.sh               # RDS migration script
```

## Testing

### CI/CD
- ✅ Tests will run with RLS enabled
- ✅ Migration included in test database setup

### Local Testing
```bash
# Reset database (applies all migrations including RLS)
make db-reset

# Or manually apply
docker exec crypto-postgres psql -U crypto_user -d crypto_inventory \
  -f /docker-entrypoint-initdb.d/24-rls-policies.sql
```

## Rollback

If issues occur:

1. **Revert sensor-manager service** to previous version
2. **RLS can remain enabled** - old code won't break
3. **Investigate** in staging
4. **Re-deploy** after fixes

**Emergency**: Can disable RLS if needed (not recommended):
```sql
ALTER TABLE sensors DISABLE ROW LEVEL SECURITY;
```

## Summary

### What Propagates Automatically?
- ✅ Code changes (in repository, deployed via images)
- ✅ New database initializations (via Docker Compose)
- ✅ CI/CD test databases

### What Requires Manual Steps?
- ⚠️ Existing databases (Docker Compose, RDS, EKS)
- ⚠️ RDS migrations (must apply manually)
- ⚠️ EKS with RDS (must apply via Job or kubectl)

### What's Updated?
- ✅ All Docker Compose files
- ✅ CI/CD pipeline
- ✅ All documentation
- ✅ New RDS migration script

### Next Steps
1. Review `DEPLOYMENT_MIGRATION_CHECKLIST.md`
2. Apply RLS migration to existing databases
3. Deploy updated sensor-manager service
4. Verify tenant isolation

## Quick Reference

**For existing Docker Compose:**
```bash
docker exec crypto-postgres psql -U crypto_user -d crypto_inventory \
  -f /docker-entrypoint-initdb.d/24-rls-policies.sql
```

**For RDS:**
```bash
./scripts/apply-rds-migrations.sh prod
```

**For EKS:**
See `database-migrations.md` for Kubernetes Job example.

**Verify:**
```sql
SELECT tablename, rowsecurity FROM pg_tables 
WHERE tablename IN ('sensors', 'pending_sensors');
-- Should show rowsecurity = true
```
