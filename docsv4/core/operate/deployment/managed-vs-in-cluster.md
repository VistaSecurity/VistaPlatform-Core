---
render_macros: false
---

# Managed vs In-Cluster Data Services (EKS)

For the EKS deployment, we use the following choices. This document records the decision and rationale.

## Summary

| Service | Choice | Rationale |
|---------|--------|-----------|
| **PostgreSQL** | **Managed (RDS)** | Durability, backups, patching; Terraform in `infrastructure/terraform/` provisions RDS. |
| **Redis** | **Managed (ElastiCache)** | Durability, encryption, no in-cluster persistence; Terraform provisions ElastiCache. |
| **NATS** | **In-cluster** | No AWS-managed NATS; run NATS (and JetStream if needed) as a Deployment in the same EKS cluster. |
| **InfluxDB** | **Optional / in-cluster** | Not required for minimal deploy; if needed, run in-cluster or use a managed time-series DB later. |

## PostgreSQL (RDS)

- **Provisioned by:** `infrastructure/terraform/rds.tf`
- **Connection:** Applications use `DATABASE_URL` (or separate host/port/user/password) from Secrets. RDS endpoint is in private subnets; EKS nodes reach it via security groups.
- **Schema:** Apply `scripts/database/schema.sql` once after RDS is created (e.g. via a one-off Job or from a bastion).

## Redis (ElastiCache)

- **Provisioned by:** `infrastructure/terraform/elasticache.tf`
- **Connection:** Applications use `REDIS_URL` (e.g. `rediss://...` with TLS). ElastiCache is in private subnets; EKS nodes reach it via security groups.
- **Auth:** ElastiCache can use AUTH token; if enabled, include it in `REDIS_URL` or a separate secret.

## NATS (in-cluster)

- **No AWS-managed option.** NATS runs inside the cluster.
- **Deployment:** Run NATS as a Kubernetes Deployment (and optionally a StatefulSet for JetStream). Store connection URL in a ConfigMap or Secret (e.g. `nats://nats.crypto-inventory.svc.cluster.local:4222`).
- **Persistence:** For JetStream, use a PersistentVolumeClaim for the NATS data directory.
- **In this repo:** Kubernetes manifests in `k8s/eks/` include (or will include) a NATS Deployment and Service so application services can use `NATS_URL` pointing at that Service.

## InfluxDB (optional)

- **Not required** for minimal EKS deploy. If you need metrics storage:
  - Run InfluxDB as a Deployment + PVC in the cluster, or
  - Use a managed time-series service (e.g. Amazon Timestream) and adapt the app config later.

## References

- Terraform: `infrastructure/terraform/`
- EKS walkthrough: eks-deployment-walkthrough.md
- Service registry: `standards/service-registry.yaml`
