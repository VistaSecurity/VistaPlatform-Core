---
render_macros: false
---

# Database Deployment Readiness - Sensor Management Enhancements

## Status: ✅ READY FOR DEPLOYMENT

All database changes have been consolidated into `schema.sql` and `seed.sql` - **NO MIGRATIONS REQUIRED**.

## Summary

Since there are no production customers and we're rebuilding dev/smoke environments from scratch, all database changes have been integrated directly into the base schema and seed files.

## Database Changes Included

### 1. Schema Changes (scripts/database/schema.sql)

#### New Column: `sensors.ip_address`
```sql
-- Line 3529 in schema.sql
ip_address VARCHAR(45),
```

**Purpose**: Track the IP address sensors are connecting from  
**Index**: `idx_sensors_ip_address` (line 3599)  
**Type**: VARCHAR(45) to support both IPv4 and IPv6 addresses

#### New Table: `sensor_health_metrics`
```sql
-- Lines 3571-3581 in schema.sql
CREATE TABLE IF NOT EXISTS sensor_health_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sensor_id UUID NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    uptime_seconds BIGINT NOT NULL,
    memory_usage_bytes BIGINT NOT NULL,
    cpu_usage_percent DECIMAL(5,2) NOT NULL,
    packets_captured BIGINT NOT NULL DEFAULT 0,
    discoveries_made BIGINT NOT NULL DEFAULT 0,
    errors_count INTEGER NOT NULL DEFAULT 0,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

**Purpose**: Store historical health metrics for sensors  
**Indexes**:
- `idx_sensor_health_metrics_sensor_id` (line 3611) - Fast lookups by sensor
- `idx_sensor_health_metrics_recorded_at` (line 3612) - Time-series queries

**Features**:
- Foreign key to sensors table with CASCADE delete
- Stores comprehensive health data (CPU, memory, uptime, cache stats)
- Timestamp for time-series analysis
- Optimized for historical queries

### 2. Seed Data (scripts/database/seed.sql)

Platform sensors are automatically created for all tenants:

**Platform Discovery Sensor**
- ID: `550e8400-e29b-41d4-a716-446655440001`
- Lines 118-145

**Platform Device Interrogation Agent**
- ID: `550e8400-e29b-41d4-a716-446655440002`
- Lines 154-180

## Deployment Process

### Automatic Initialization

The database will be initialized automatically when deploying to dev/smoke:

1. **Docker Compose**: 
   - `schema.sql` is mounted to `/docker-entrypoint-initdb.d/01-schema.sql`
   - Postgres automatically runs scripts in this directory on first startup
   - All tables, indexes, and constraints are created

2. **Seed Data**:
   - Applied by deployment scripts (`deploy-smoke.sh`, `deploy-ec2-smoke.sh`)
   - Creates platform sensors, default roles, and base configuration

### Deployment Steps

For **dev** or **smoke** environments:

```bash
# 1. Tear down existing environment
docker compose down -v  # -v removes volumes (clean slate)

# 2. Deploy fresh environment
./scripts/deploy-smoke.sh
# OR
./scripts/deploy-ec2-smoke.sh
```

The deployment script will:
1. Start PostgreSQL container
2. Automatically apply `schema.sql` (via Docker init)
3. Apply `seed.sql` (via deployment script)
4. Start all services with new images

## Verification

After deployment, verify the changes:

```bash
# Connect to database
docker exec -it crypto-inventory-postgres psql -U crypto_user -d crypto_inventory

# Verify ip_address column
\d sensors

# Verify sensor_health_metrics table
\d sensor_health_metrics

# Check indexes
\di idx_sensors_ip_address
\di idx_sensor_health_metrics_sensor_id
\di idx_sensor_health_metrics_recorded_at

# Verify platform sensors exist
SELECT id, name, sensor_type FROM sensors 
WHERE sensor_type = 'platform-discovery' OR sensor_type = 'platform-device-agent';
```

Expected results:
- `sensors` table has `ip_address` column
- `sensor_health_metrics` table exists with all columns
- All indexes are created
- Two platform sensors exist for the default tenant

## Migration Status

**No Migrations Required**

- ✅ All changes are in `schema.sql` (base schema)
- ✅ `migrations/` directory is empty (no pending migrations)
- ✅ Archive migrations are not applied (in `archive/` directory only)
- ✅ Fresh database deployments get everything automatically

## Rollback Plan

Since we're rebuilding from scratch:
- **Rollback**: Redeploy with previous Docker images (tag: previous release)
- **No database migration rollback needed** - just use old images with old schema
- **Full rollback**: Use git to checkout previous commit and redeploy

## Docker Images

New images are available in ECR:
- **Tag**: `cf84d90-1769567820` (latest commit)
- **Tag**: `latest` (always points to newest build)
- **Registry**: `<account-id>.dkr.ecr.<region>.amazonaws.com/`

All 18 service images include the sensor management enhancements:
- sensor-manager (backend service with new endpoints)
- web-ui (frontend with enhanced UI)
- admin-ui (admin interface)
- All other services (updated dependencies)

## Files Modified

### Database Files (Consolidated)
- ✅ `scripts/database/schema.sql` - All schema changes integrated
- ✅ `scripts/database/seed.sql` - Platform sensors seeded

### Application Code
- ✅ `sensor/` - Enhanced sensor with cache, metrics, commands
- ✅ `services/sensor-manager/` - Backend API with health history
- ✅ `web-ui/` - Frontend UI enhancements
- ✅ All built and pushed to ECR

## Deployment Checklist

- [x] Schema changes consolidated in schema.sql
- [x] Seed data updated in seed.sql
- [x] Migrations directory empty (no migrations to apply)
- [x] Docker images built and pushed to ECR
- [x] Sensor binary built and placed in artifacts
- [x] Documentation updated
- [x] Git committed and pushed
- [ ] Deploy to smoke environment
- [ ] Verify database schema
- [ ] Verify platform sensors created
- [ ] Verify sensor health metrics recording
- [ ] Test UI enhancements
- [ ] Test command execution

## Next Steps

1. **Deploy to Smoke**:
   ```bash
   ./scripts/deploy-smoke.sh
   ```

2. **Verify Deployment**:
   - Check database schema
   - Verify platform sensors
   - Test sensor registration
   - Test health metrics collection
   - Test command execution

3. **Test Features**:
   - Connection deduplication cache
   - Health metrics recording
   - IP address tracking
   - Command execution (all 7 types)
   - UI enhancements (Overview, Health, Commands, Certificates tabs)

4. **Deploy to Dev** (if smoke tests pass)

## Support

If issues arise during deployment:

1. **Check Logs**:
   ```bash
   docker compose logs -f sensor-manager
   docker compose logs -f postgres
   ```

2. **Verify Schema**:
   ```bash
   docker exec -it crypto-inventory-postgres psql -U crypto_user -d crypto_inventory -c "\d sensors"
   docker exec -it crypto-inventory-postgres psql -U crypto_user -d crypto_inventory -c "\d sensor_health_metrics"
   ```

3. **Check Service Health**:
   ```bash
   curl http://localhost:8080/health
   ```

---

**Status**: Ready for deployment  
**Environment**: dev, smoke (fresh rebuild)  
**Migration Required**: No  
**Risk Level**: Low (fresh deployment, no data loss risk)  
**Rollback**: Simple (redeploy previous images)
