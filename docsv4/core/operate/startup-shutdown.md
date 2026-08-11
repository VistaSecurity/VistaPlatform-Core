---
render_macros: false
---

# Service Startup and Shutdown Procedures

This document describes the startup and shutdown procedures for all environments (development, smoke, production).

## Overview

The platform uses Docker Compose for service orchestration. Services are defined in the service registry (`standards/service-registry.yaml`) and generated into `docker-compose.yml` files.

## Service Registry

All services are registered in `standards/service-registry.yaml`. The registry is the **single source of truth** for service configuration.

**⚠️ CRITICAL**: Never edit `docker-compose.yml` or `docker-compose.prod.yml` directly. Always edit the service registry and run `make registry-first` to regenerate.

## Development Environment

### Startup

**Full Session Startup:**
```bash
./start-session.sh
```

This script:
1. Generates `.env` if missing
2. Runs session initialization
3. Starts all services via `scripts/start-all-services.sh`

**Manual Startup:**
```bash
# 1. Start infrastructure
docker compose up -d postgres redis nats influxdb

# 2. Wait for infrastructure (10-30 seconds)
sleep 10

# 3. Start backend services
docker compose up -d auth-service inventory-service compliance-engine \
  cbom-service sensor-manager admin-service cluster-sensor-service \
  monitoring-service resource-tracker-service tenant-health-service \
  device-interrogation-service audit-service notification-service \
  discovery-processor-service

# 4. Start API gateway (before frontend so UIs can reach the API)
docker compose up -d api-gateway
# The API gateway serves both v1 and v2; Traefik config is generated from the registry per environment (dev, ec2-smoke, prod).

# 5. Start frontend
docker compose up -d web-ui admin-ui
```

**Service Order:**
1. Infrastructure (postgres, redis, nats, influxdb)
2. Backend services (all can start in parallel after infrastructure)
3. API Gateway
4. Frontend applications

### Shutdown

**Graceful Shutdown:**
```bash
./scripts/stop-all-services.sh
```

**Complete Cleanup (removes all data):**
```bash
./scripts/cleanup-docker.sh --dev
```

**Manual Shutdown:**
```bash
docker compose down
```

### Service Validation

After startup, validate all services:
```bash
./scripts/validate-services.sh
```

This checks:
- Infrastructure health
- Backend service health endpoints
- Frontend accessibility
- API Gateway functionality

## Smoke Test Environment

### Startup

**Using Deployment Script:**
```bash
./scripts/deploy-smoke.sh
```

**Manual Startup:**
```bash
# 1. Generate environment
./scripts/generate-ec2-smoke-env.sh

# 2. Start infrastructure
docker compose -f docker-compose.ec2-smoke.yml --env-file .env.ec2-smoke up -d postgres redis nats

# 3. Wait for database
sleep 15

# 4. Start all services
docker compose -f docker-compose.ec2-smoke.yml --env-file .env.ec2-smoke up -d
```

### Shutdown

```bash
docker compose -f docker-compose.ec2-smoke.yml --env-file .env.ec2-smoke down
```

### Service Validation

```bash
# Check service health
docker compose -f docker-compose.ec2-smoke.yml ps

# Check logs
docker compose -f docker-compose.ec2-smoke.yml logs notification-service
```

## Production Environment

### Startup

**Using EC2 Services Script:**
```bash
./scripts/ec2-services.sh start
```

**Manual Startup:**
```bash
# 1. Load environment
source .env.prod

# 2. Start infrastructure
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d postgres redis nats

# 3. Wait for database
sleep 15

# 4. Start all services
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d
```

### Shutdown

**Graceful Shutdown:**
```bash
./scripts/ec2-services.sh stop
```

**Manual Shutdown:**
```bash
docker compose -f docker-compose.prod.yml --env-file .env.prod down
```

**Emergency Shutdown:**
```bash
./scripts/ec2-services.sh emergency
```

### Service Validation

```bash
# Check all services
./scripts/ec2-services.sh status

# Check health
./scripts/ec2-services.sh health

# View logs
./scripts/ec2-services.sh logs notification-service
```

## Service Dependencies

### Infrastructure Services

All services depend on:
- **PostgreSQL**: Database (required by all backend services)
- **Redis**: Caching and sessions (required by auth-service, cbom-service)
- **NATS**: Message queue (required by inventory-service, compliance-engine, cbom-service, sensor-manager)
- **InfluxDB**: Time-series data (required by inventory-service, cbom-service, sensor-manager, monitoring-service)

### Backend Service Dependencies

- **auth-service**: postgres, redis
- **inventory-service**: postgres, influxdb, nats
- **compliance-engine**: postgres, nats
- **cbom-service**: postgres, redis, influxdb, nats
- **sensor-manager**: postgres, influxdb, nats
- **admin-service**: postgres, redis
- **cluster-sensor-service**: postgres
  - Requires `CLUSTER_SENSOR_SERVICE_TOKEN` for auto-registration
  - Auto-registers platform discovery sensor for all tenants on startup
- **monitoring-service**: postgres, redis, influxdb
- **resource-tracker-service**: postgres
- **tenant-health-service**: postgres
- **device-interrogation-service**: postgres
  - Requires `DEVICE_INTERROGATION_SERVICE_TOKEN` for auto-registration
  - Auto-registers platform device interrogation agent for all tenants on startup
- **audit-service**: postgres
- **notification-service**: postgres

### Service-to-Service Dependencies

- **monitoring-service** → **notification-service** (for alerts)
- **cluster-sensor-service** → **notification-service** (for discovery alerts)
- **audit-service** → **notification-service** (for security alerts)

## Notification Service Configuration

### Environment Variables

**Required:**
- `DATABASE_URL`: PostgreSQL connection string
- `JWT_SECRET`: JWT signing secret
- `ENCRYPTION_MASTER_KEY`: For decrypting email configuration

**Optional:**
- `PORT`: Service port (default: 8080)
- `ENV`: Environment (development, smoke, production)
- `LOG_LEVEL`: Logging level (debug, info, warn, error)
- `NOTIFICATION_SERVICE_URL`: URL for other services to call (default: http://notification-service:8080)

### Service Startup Order

Notification service should start after:
1. PostgreSQL (database)
2. Other services that send notifications (monitoring, discovery, audit)

Notification service can start in parallel with other backend services.

### Health Check

```bash
# Check notification service health
curl http://localhost:8097/health

# Expected response:
# {"status":"healthy","service":"notification-service"}
```

## Troubleshooting

### Service Won't Start

1. **Check logs:**
   ```bash
   docker compose logs notification-service
   ```

2. **Check database connectivity:**
   ```bash
   docker compose exec postgres psql -U crypto_user -d crypto_inventory -c "SELECT 1;"
   ```

3. **Check environment variables:**
   ```bash
   docker compose exec notification-service env | grep -E "(DATABASE|JWT|ENCRYPTION)"
   ```

4. **Check port availability:**
   ```bash
   netstat -tuln | grep 8097
   ```

### Service Starts But Crashes

1. **Check database schema:**
   ```bash
   docker compose exec postgres psql -U crypto_user -d crypto_inventory -c "\dt tenant_notification*"
   ```

2. **Check the schema is applied** (there is no migration runner — the schema is loaded from `scripts/database/schema.sql`, so there is no `schema_migrations` version table; verify expected tables exist instead):
   ```bash
   docker compose exec postgres psql -U crypto_user -d crypto_inventory -c "\dt" | head -20
   ```

3. **Check service logs for errors:**
   ```bash
   docker compose logs --tail=100 notification-service
   ```

### Notifications Not Sending

1. **Check notification service is running:**
   ```bash
   docker compose ps notification-service
   ```

2. **Check notification history:**
   ```sql
   SELECT * FROM notification_history ORDER BY created_at DESC LIMIT 10;
   ```

3. **Check channel configuration:**
   ```sql
   SELECT * FROM tenant_notification_channels WHERE enabled = true;
   ```

4. **Test channel connectivity:**
   - Use UI: Settings → Notifications → Channels → Test
   - Or API: `POST /api/v1/notification-service/tenant/channels/:id/test`

## Related Documentation

- [Service Validation](../../../scripts/validate-services.sh) - Validation script
- [Notification Provider Integration Guide](operations/notification-providers.md) - Third-party integration setup
