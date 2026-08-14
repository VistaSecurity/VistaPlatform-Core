---
render_macros: false
---

# Operating VistaPlatform

Documentation for deploying and running VistaPlatform — solutions engineers,
platform operators, and anyone standing up the platform for their own
organization.

## Quick Start

| I want to… | Start here |
|------------|-----------|
| Try it, evaluate it, or deploy it for real | **`INSTALL.md`** at the repository root — three paths (laptop, single VM, production cluster), plus how to verify the images |
| Stage internal service-mesh mTLS on a production cluster | [Service-mesh mTLS](./security/service-mesh-mtls.md) |
| Run a production pre-flight | [Production Checklist](./deployment/production-checklist.md) |
| Operate the platform day-to-day | [Platform Admin Guide](./platform-admin-guide.md) |
| Monitor and alert | [Monitoring Setup](./monitoring/setup.md) |
| Troubleshoot issues | [Common Issues](./troubleshooting/common-issues.md) |

## Contents

### Deployment
- **`INSTALL.md`** at the repository root — Try it / Evaluate it / Run it, and image verification
- [Production Checklist](./deployment/production-checklist.md)
- [Service-mesh mTLS](./security/service-mesh-mtls.md) — staging internal mTLS across upgrades, managed-Postgres/NATS notes
- [Database Migrations](./deployment/database-migrations.md)
- [Device Agent Deployment](./deployment/device-agent-deployment.md)
- [Managed vs In-Cluster Postgres/Redis](./deployment/managed-vs-in-cluster.md)

### Operations
- [Platform Admin Guide](./platform-admin-guide.md) — Complete operations reference
- [Releases](./releases.md) — Release process, versioning, upgrade path
- [Startup & Shutdown](./startup-shutdown.md) — Service lifecycle management
- [Container Runtime Images](./container-runtime-images.md) — Source of truth for all runtime images
- [Notification Providers](./operations/notification-providers.md) — Slack, Email, Webhook, PagerDuty

### Monitoring
- [Monitoring Setup](./monitoring/setup.md)
- [Log Management](./monitoring/log-management.md)
- [Compliance Engine Alerts](./monitoring/compliance-engine-alerts.md)

### Security
- [Security Architecture](./security/architecture.md)
- [Certificate Management](./security/certificates.md)
- [Secrets Management](./security/secrets-management.md)
- [Bootstrap Certificates](./security/bootstrap-certificates.md)

### Configuration
- [Platform Integrations](./configuration/platform-integrations.md) — AWS, Azure, GCP, SaaS CMDB integrations

### Troubleshooting
- [Common Issues](./troubleshooting/common-issues.md)
- [Asset Approval Workflow Issues](./troubleshooting/asset-approval-workflow-issues.md)
- [Runbooks](troubleshooting/runbooks/) — Recovery and gateway runbooks
