---
render_macros: false
---

# Container runtime images (source of truth)

**Purpose:** Single reference for **which container images run** when the platform is up, for security reviews, supply-chain questions, and Chainguard or registry planning.

**Last updated:** 2026-06-09

## How to read this

- **Runtime image** = what actually executes in a long-running container (the effective `image:` after build, or the final stage of a multi-stage Dockerfile).
- **First-party images** = built from this repository (Go services, UIs, `ai-analysis-service`). They are published to your registry (for example ECR) in production; locally they are built by Docker from `Dockerfile.dev` / `Dockerfile.prod`.
- **Third-party images** = pulled from a public or vendor registry as-is.

**Default registry:** References without a host (for example `postgres:17-alpine`) resolve to **Docker Hub** (`docker.io`). Override only if your org uses mirrors or pull-through caches.

**Maintenance:** When you add a service, change a `FROM`, or change a compose `image:`, update this file. Compose files are partly generated from `standards/service-registry.yaml` (`make generate`); infrastructure exceptions stay in root `docker-compose*.yml`.

---

## First-party runtime images (application workloads)

These images contain Vista code. **Production** references below use `${ECR_REGISTRY}crypto-inventory/<name>:${IMAGE_TAG}` from `docker-compose.prod.yml` (substitute your registry and tag). **Local development** builds the same logical services from `Dockerfile.dev` via `docker-compose.yml`.

| Service | Dockerfile (prod) | Final runtime base (inside the built image) |
|---------|-------------------|---------------------------------------------|
| auth-service | `services/auth-service/Dockerfile.prod` | `alpine:3.24.1` + static Go binary |
| inventory-service | `services/inventory-service/Dockerfile.prod` | `alpine:3.24.1` |
| compliance-engine | `services/compliance-engine/Dockerfile.prod` | `alpine:3.24.1` |
| sensor-manager | `services/sensor-manager/Dockerfile.prod` | `alpine:3.24.1` |
| cbom-service | `services/cbom-service/Dockerfile.prod` | `alpine:3.24.1` |
| resource-tracker-service | `services/resource-tracker-service/Dockerfile.prod` | `alpine:3.24.1` |
| tenant-health-service | `services/tenant-health-service/Dockerfile.prod` | `alpine:3.24.1` |
| device-interrogation-service | `services/device-interrogation-service/Dockerfile.prod` | `alpine:3.24.1` |
| audit-service | `services/audit-service/Dockerfile.prod` | `alpine:3.24.1` |
| cluster-sensor-service | `services/cluster-sensor-service/Dockerfile.prod` | `alpine:3.24.1` |
| monitoring-service | `services/monitoring-service/Dockerfile.prod` | `alpine:3.24.1` |
| admin-service | `services/admin-service/Dockerfile.prod` | `alpine:3.24.1` |
| notification-service | `services/notification-service/Dockerfile.prod` | `alpine:3.24.1` |
| discovery-processor-service | `services/discovery-processor-service/Dockerfile.prod` | `alpine:3.24.1` |
| ai-analysis-service | `services/ai-analysis-service/Dockerfile.prod` | `python:3.11-slim` |
| web-ui | `web-ui/Dockerfile.prod` | `caddy:2-alpine` (static assets; build stage uses `node:24-alpine`) |
| admin-ui | `admin-ui/Dockerfile.prod` | `caddy:2-alpine` (build stage uses `node:24-alpine`) |

**Local development (UI only):** `web-ui/Dockerfile.dev` and `admin-ui/Dockerfile.dev` run on **`node:24-alpine`** (Vite dev server), not Caddy.

**Build-time bases (not the running container for Go services):** All Go services above use **`golang:1.26-alpine`** as the compile stage; the shipped runtime remains **`alpine:3.24.1`**.

---

## Third-party runtime images (pulled directly)

### `docker-compose.prod.yml` (production-style stack)

| Service | Image reference |
|---------|-----------------|
| postgres | `postgres:17-alpine` |
| redis | `redis:7-alpine` |
| influxdb | `influxdb:2.7-alpine` |
| nats | `nats:2.10-alpine` |
| api-gateway | `traefik:v3.3` |
| otel-collector | `otel/opentelemetry-collector-contrib:0.114.0` |
| jaeger | `jaegertracing/all-in-one:1.64.0` |
| grafana | `grafana/grafana:11.3.0` |

**Not in `docker-compose.prod.yml` today:** `notification-service`, `discovery-processor-service` (they appear in local dev compose and in sample EKS manifests).

### `docker-compose.yml` (local full stack) — extra / different

Same third-party set as prod, **plus:**

| Service | Image reference |
|---------|-----------------|
| adminer | `adminer:latest` |

**Local stack note:** `docker-compose.yml` does **not** include `ai-analysis-service`; `docker-compose.prod.yml` does.

### Sample Kubernetes (`k8s/eks/`)

- **Application images:** `*.dkr.ecr.us-east-1.amazonaws.com/crypto-inventory/<service>:latest` (see `04-deployments-backend.yaml`, `06-deployments-frontend.yaml`). Includes **notification-service** and **discovery-processor-service**.
- **api-gateway:** `traefik:v3.3`
- **nats:** `nats:2.9-alpine` (different patch stream than compose’s `2.10-alpine`; align intentionally if both are used).

Postgres/Redis/Influx in real EKS deployments are often **managed services** rather than images in this repo; treat those as environment-specific.

### Other template (`k8s/production-balanced/deployments.yaml`)

Placeholder **`gcr.io/PROJECT_ID/...`** images for a subset of services (GCP-oriented sample).

---

## Deduplicated third-party catalog (compose-based product)

Unique public images referenced by **`docker-compose.prod.yml`** and **`docker-compose.yml`** for a full local run:

| Image | Used by (representative) |
|-------|---------------------------|
| `postgres:17-alpine` | postgres |
| `redis:7-alpine` | redis |
| `influxdb:2.7-alpine` | influxdb |
| `nats:2.10-alpine` | nats |
| `traefik:v3.3` | api-gateway |
| `caddy:2-alpine` | final stage of prod UIs (web-ui, admin-ui) |
| `otel/opentelemetry-collector-contrib:0.114.0` | otel-collector |
| `jaegertracing/all-in-one:1.64.0` | jaeger |
| `grafana/grafana:11.3.0` | grafana |
| `adminer:latest` | adminer (**local dev only**) |

**Additional bases inside first-party images** (not separate compose services): `alpine:3.24.1`, `golang:1.26-alpine` (build), `node:24-alpine` (UI build or dev runtime), `caddy:2-alpine` (UI prod runtime), `python:3.11-slim` (`ai-analysis-service`).

---

## Environment summary

| Concern | `docker-compose.yml` (dev) | `docker-compose.prod.yml` |
|--------|----------------------------|---------------------------|
| ai-analysis-service | Not defined | ECR first-party image |
| notification-service, discovery-processor-service | Built locally | Not defined |
| adminer | Pulled (`adminer:latest`) | Not defined |

For compliance answers, state **which compose file or cluster** defines the deployment; the sets are not identical.
