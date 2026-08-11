---
render_macros: false
---

# Deployment Documentation

Deployment guides and checklists for the Crypto Inventory Platform.

## Deployment Guides

- [Production Checklist](./production-checklist.md) - Comprehensive production deployment checklist
- [Database Migrations](./database-migrations.md) - Database migration procedures

## Migration Guides

- [Migration Checklist](./migration-checklist.md) - Deployment migration checklist
- [Propagation Guide](./propagation-guide.md) - Deployment propagation procedures

## Quick Start

### Development Deployment

```bash
# Start development environment
make session-init
```

### Production Deployment

1. Review [Production Checklist](./production-checklist.md)
2. Generate environment: `node ./scripts/generate-prod-env.mjs`
3. Deploy: `docker compose -f docker-compose.prod.yml up -d`

## Deployment Environments

- **Development**: Local Docker Compose (`docker-compose.yml`)
- **Smoke Test**: Single EC2 instance (`docker-compose.ec2-smoke.yml`)
- **Production**: AWS EC2 with ALB (`docker-compose.prod.yml`)
- **Staging**: Similar to production (optional)

## Related Documentation

- [Operations Monitoring](../monitoring/setup.md) - Monitoring setup
