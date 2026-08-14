---
render_macros: false
---

# Production Deployment Checklist

Comprehensive checklist for deploying the Crypto Inventory Platform to production.

## Pre-Deployment

### Environment Setup

- [ ] Generate a `.env` with real secrets: `./scripts/bootstrap-env.sh` (see [INSTALL.md](https://github.com/VistaSecurity/VistaPlatform-Core/blob/main/INSTALL.md) — the environment generators referenced by older revisions of this checklist, `generate-prod-env.mjs` and `generate-ec2-smoke-env.mjs`, are internal tooling and are not part of this repository)
- [ ] Review and update the environment file with production values
- [ ] Verify all secrets are secure and randomized
- [ ] Verify `JWT_SECRET` is NOT the dev default (`dev-secret-key-change-in-production`) — auth-service will refuse to start
- [ ] Verify `INTERNAL_AUTH_SECRET` is NOT the dev default — required for HMAC-signed service-to-service authentication
- [ ] Verify `ENCRYPTION_MASTER_KEY` is set — certificate generation scripts will fail without it
- [ ] Set `ENV=production` so runtime secret validation is enforced
- [ ] Configure domain names (api.example.com, app.example.com, admin.example.com)
- [ ] Set up DNS records pointing to EC2 instance or ALB

> **Secrets Configuration**: All secrets are now externalized into `.env` (see `env.example` at the repository root for the full list of required variables). `INTERNAL_AUTH_SECRET` is required for HMAC-signed service-to-service authentication and must be a strong, randomly generated value. Docker Compose uses `${VAR:?error}` syntax to fail fast if required secrets are missing -- if a service fails to start, check that all variables listed in `env.example` are defined in your `.env` file.

### Infrastructure

- [ ] Provision EC2 instance (recommended: t3.large or larger)
- [ ] Configure Security Groups (ports 80, 443, 22)
- [ ] Set up Application Load Balancer (ALB) with ACM certificate
- [ ] Configure Route 53 DNS
- [ ] Set up S3 bucket for artifact storage (optional)
- [ ] Configure IAM roles for AWS services (if using AWS integrations)

### Database

- [ ] Provision PostgreSQL database (RDS or self-hosted)
- [ ] Configure database backups
- [ ] Set up database connection pooling
- [ ] Verify database schema is up to date
  ```bash
  # Schema is automatically applied on new databases via schema.sql
  # For existing databases, apply schema updates:
  docker compose -f docker-compose.prod.yml exec -T postgres \
    psql -U crypto_user -d crypto_inventory -f scripts/database/schema.sql
  ```
- [ ] Verify RLS is active — schema.sql enables RLS on all tenant-scoped tables. Services must call `set_tenant_context()` before tenant queries
- [ ] Configure `DATABASE_URL` with `sslmode=require` or `sslmode=verify-full` for encrypted connections
- [ ] Verify seed.sql admin passwords have been changed from defaults
- [ ] Generate bootstrap certificates for platform services
  ```bash
  # Generate platform bootstrap CA (one-time, if not exists)
  ./scripts/generate-bootstrap-ca.sh
  
  # Generate bootstrap certificates for platform services
  ./scripts/generate-bootstrap-certificates.sh
  
  # Certificates are stored in ./bootstrap-certs/ directory
  # Ensure certificates are mounted in docker-compose.prod.yml
  # See docsv4/operations/security/bootstrap-certificates.md for details
  ```

### SSL/TLS

- [ ] Configure ACM certificate in ALB (recommended)
- [ ] Or configure Let's Encrypt on EC2
- [ ] Verify HTTPS redirect works
- [ ] Test SSL certificate validity

## Deployment Steps

### 1. Build Production Images

```bash
# Build all services
docker compose -f docker-compose.prod.yml build

# Or build specific service
docker compose -f docker-compose.prod.yml build auth-service
```

### 2. Start Infrastructure

```bash
# Start database, Redis, NATS
docker compose -f docker-compose.prod.yml up -d postgres redis nats
```

### 3. Verify Database Schema

```bash
# For new databases: Schema auto-applies via schema.sql on first startup
# For existing databases: Apply schema updates (idempotent)
docker compose -f docker-compose.prod.yml exec -T postgres \
  psql -U crypto_user -d crypto_inventory -f scripts/database/schema.sql
```

### 4. Start Services

```bash
# Start all services (includes notification-service)
docker compose -f docker-compose.prod.yml up -d

# Or start specific services
docker compose -f docker-compose.prod.yml up -d auth-service inventory-service notification-service
```

**Note:** The `notification-service` is included in the service registry and will be started automatically. Ensure it has access to:
- PostgreSQL database
- `ENCRYPTION_MASTER_KEY` environment variable (for email config decryption)
- `NOTIFICATION_SERVICE_URL` environment variable (for other services to call it)

### 5. Start API Gateway

```bash
# Start Traefik gateway
docker compose -f docker-compose.prod.yml up -d api-gateway
```

### 6. Start Frontend

```bash
# Start web-ui and admin-ui
docker compose -f docker-compose.prod.yml up -d web-ui admin-ui
```

## Post-Deployment

### Verification

- [ ] Verify all services are healthy (including notification-service on port 8097)
  ```bash
  curl https://api.example.com/health
  curl http://localhost:8097/health  # Notification service
  ```
- [ ] Test API Gateway routing (v1 and v2; v2 available at `/api/v2/inventory-service/`, `/api/v2/health`, and v2 pass-through for other services)
- [ ] Verify frontend applications load
- [ ] Test authentication flow
- [ ] Verify database connections
- [ ] Check service logs for errors
- [ ] Test notification channels (Slack, Email, Webhook, PagerDuty)
- [ ] Verify notification service can receive alerts from other services
- [ ] Check notification history is being recorded
- [ ] Verify the MCP service is healthy (port 8100) and requires `INTERNAL_AUTH_SECRET`
  ```bash
  curl http://localhost:8100/health  # MCP service (read-only AI integration)
  ```
  The MCP endpoint (`/api/v1/mcp-service/mcp`) requires a tenant API token; an
  unauthenticated request must return `401`. See
  MCP Service architecture.

### Monitoring

- [ ] Set up monitoring alerts
- [ ] Configure log aggregation
- [ ] Set up uptime monitoring
- [ ] Configure error tracking

### Security

- [ ] Verify HTTPS is enforced
- [ ] Test authentication and authorization
- [ ] Verify CORS configuration
- [ ] Check security headers
- [ ] Review access logs

## Common Issues

### Services Not Starting

- Check Docker logs: `docker compose -f docker-compose.prod.yml logs <service>`
- Verify environment variables are set
- Check database connectivity
- Verify port availability

### Database Connection Errors

- Verify `DATABASE_URL` is correct
- Check database is accessible from EC2
- Verify database user permissions
- Check firewall rules

### Frontend Not Loading

- Verify API Gateway URL is correct
- Check CORS configuration
- Verify frontend build completed successfully
- Check browser console for errors

## Rollback Procedure

1. Stop services: `docker compose -f docker-compose.prod.yml down`
2. Restore database backup if needed
3. Revert to previous image versions
4. Restart services with previous configuration

## Related Documentation

- [Database Migrations](./database-migrations.md) - Migration procedures
- [Startup and Shutdown Procedures](../startup-shutdown.md) - Service lifecycle management
- [Notification Provider Integration Guide](../operations/notification-providers.md) - Third-party integration setup
