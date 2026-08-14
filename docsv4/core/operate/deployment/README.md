---
render_macros: false
---

# Deployment Documentation

Deployment guides and checklists for Vista Platform.

## Deployment Guides

- [Production Checklist](./production-checklist.md) - Comprehensive production deployment checklist
- [Database Migrations](./database-migrations.md) - Database migration procedures
- [Service-mesh mTLS](../security/service-mesh-mtls.md) - Staging internal mTLS across upgrades, managed-Postgres/NATS notes

## Quick Start

### Try it (Docker Compose, local)

```bash
./scripts/bootstrap-env.sh
docker compose up -d
```

See [INSTALL.md](https://github.com/VistaSecurity/VistaPlatform-Core/blob/main/INSTALL.md) in the repository root for the full walkthrough, including the single-VM Kubernetes path ("Evaluate it") and a production cluster install with your own certificates ("Run it").

### Production Deployment

Production installs use the Helm chart, not Docker Compose — there is no
`docker-compose.prod.yml` in this repository. See:

1. [Production Checklist](./production-checklist.md)
2. `helm install vista oci://ghcr.io/vistasecurity/vistaplatform` directly against any Kubernetes cluster — see [INSTALL.md](https://github.com/VistaSecurity/VistaPlatform-Core/blob/main/INSTALL.md#run-it) ("Run it") and, if you're staging internal service-mesh mTLS on an existing cluster, [Service-mesh mTLS](../security/service-mesh-mtls.md).

## Deployment Environments

- **Local evaluation**: Docker Compose (`docker-compose.yml` + `docker-compose.override.yml`) — see [INSTALL.md](https://github.com/VistaSecurity/VistaPlatform-Core/blob/main/INSTALL.md)
- **Production**: the Helm chart (`charts/vistaplatform/`), on any Kubernetes cluster

## Related Documentation

- [Operations Monitoring](../monitoring/setup.md) - Monitoring setup
