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

## Development / Local Evaluation (Docker Compose)

### Startup

**Quickstart:**
```bash
./scripts/bootstrap-env.sh
docker compose up -d
```

`docker compose` automatically loads `docker-compose.override.yml` alongside
`docker-compose.yml`, which is what makes this a single command — see
[INSTALL.md](https://github.com/VistaSecurity/VistaPlatform-Core/blob/main/INSTALL.md)
for the full walkthrough.

**Manual, staged Startup** (useful when debugging a specific service):
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
# The API gateway serves both v1 and v2; Traefik config is generated from the registry.

# 5. Start frontend
docker compose up -d web-ui admin-ui
```

**Service Order:**
1. Infrastructure (postgres, redis, nats, influxdb)
2. Backend services (all can start in parallel after infrastructure)
3. API Gateway
4. Frontend applications

### Shutdown

**Manual Shutdown:**
```bash
docker compose down
```

**Complete Cleanup (removes all data):**
```bash
docker compose down -v
# or, if you need the volumes' host-side artifacts cleaned too:
./scripts/clean-all-volumes.sh
```

### Service Validation

After startup, validate all services — there is no bundled validation script:
```bash
docker compose ps
curl -sf http://localhost:8080/api/v1/auth-service/health
curl -sf http://localhost:3000  # web UI
curl -sf http://localhost:3006  # admin UI
```

This checks:
- All containers report `Up`/`healthy` in `docker compose ps`
- API Gateway routes through to a backend health endpoint
- Frontend accessibility (web UI and admin UI)

## Production Environment (Kubernetes)

There is no `docker-compose.prod.yml` or EC2-based production path in this
repository — production installs use the Helm chart
(`charts/vistaplatform/`) against any Kubernetes cluster. See
[INSTALL.md](https://github.com/VistaSecurity/VistaPlatform-Core/blob/main/INSTALL.md#run-it)
("Run it") for the quick path, or [Service-mesh mTLS](./security/service-mesh-mtls.md)
for staging internal mTLS on an existing production cluster.

### Startup / Shutdown

```bash
helm install vista oci://ghcr.io/vistasecurity/vistaplatform \
  --namespace vista --create-namespace --wait

helm uninstall vista --namespace vista
```

### Service Validation

```bash
kubectl -n vista get pods
kubectl -n vista logs deployment/notification-service
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

- [Service Validation](#service-validation) - manual validation commands above (there is no bundled validation script)
- [Notification Provider Integration Guide](operations/notification-providers.md) - Third-party integration setup
