---
render_macros: false
---

# Container runtime images (source of truth)

**Purpose:** Single reference for **which container images run** when the
platform is up, for security reviews, supply-chain questions, and registry
planning.

**Last updated:** 2026-09-16

## How to read this

- **Runtime image** = what actually executes in a long-running container (the
  effective `image:` after build, or the final stage of a multi-stage
  Dockerfile).
- **First-party images** = built from this repository (16 Go backend services
  plus the two frontends). Locally they're built by Docker from
  `Dockerfile.dev` / `Dockerfile.prod`; in production the Helm chart pulls
  pre-built, cosign-signed images.
- **Third-party images** = pulled from a public or vendor registry as-is.

**Default registry:** References without a host (for example
`postgres:17-alpine`) resolve to **Docker Hub** (`docker.io`).

**Maintenance:** When you add a service, change a `FROM`/`ARG`, or change a
compose `image:`, update this file. Compose files are partly generated from
`standards/service-registry.yaml` (`make generate`); infrastructure exceptions
stay in root `docker-compose*.yml`.

---

## First-party runtime images (application workloads)

These images contain Vista code. **16 backend services**, all Go, all built the
same way:

| Service | Port | Dockerfile (prod) |
|---------|------|-------------------|
| auth-service | 8081 | `services/auth-service/Dockerfile.prod` |
| inventory-service | 8082 | `services/inventory-service/Dockerfile.prod` |
| compliance-engine | 8083 | `services/compliance-engine/Dockerfile.prod` |
| cbom-service | 8084 | `services/cbom-service/Dockerfile.prod` |
| sensor-manager | 8085 | `services/sensor-manager/Dockerfile.prod` |
| cluster-sensor-service | 8088 | `services/cluster-sensor-service/Dockerfile.prod` |
| admin-service | 8089 | `services/admin-service/Dockerfile.prod` |
| monitoring-service | 8091 | `services/monitoring-service/Dockerfile.prod` |
| resource-tracker-service | 8092 | `services/resource-tracker-service/Dockerfile.prod` |
| tenant-health-service | 8093 | `services/tenant-health-service/Dockerfile.prod` |
| device-interrogation-service | 8095 | `services/device-interrogation-service/Dockerfile.prod` |
| audit-service | 8096 | `services/audit-service/Dockerfile.prod` |
| notification-service | 8097 | `services/notification-service/Dockerfile.prod` |
| pcap-processor | 8098 | `services/pcap-processor/Dockerfile.prod` |
| discovery-processor-service | 8090 | `services/discovery-processor-service/Dockerfile.prod` |
| mcp-service | 8100 | `services/mcp-service/Dockerfile.prod` |

**Build/runtime bases (all 16, `pcap-processor` noted separately):**

- Compile stage: `golang:1.26.6-alpine` (`ARG GO_BUILDER_IMAGE`)
- Runtime: `alpine:3.24.1` + a static Go binary (`ARG RUNTIME_IMAGE`)
- **`pcap-processor` is the one exception.** It needs CGO and libpcap (packet
  capture is not pure Go), so its build stage adds `gcc musl-dev libpcap-dev`
  and its runtime stage adds the `libpcap` runtime package on top of the same
  `alpine:3.24.1` base. This is also why `pcap-processor` has no
  `Dockerfile.licensed`/`.dist` variant in the commercial pipeline — a
  CGO-linked binary can't be obfuscated the way the pure-Go services are.

**Frontends** — Vite/React apps, built with Caddy as the runtime web server:

| Service | Port | Dockerfile (prod) |
|---------|------|-------------------|
| web-ui | 3000 | `frontend-v2/Dockerfile.prod` |
| admin-ui | 3006 | `admin-ui-v2/Dockerfile.prod` |

- Build stage: `dhi.io/node:24-alpine3.22-dev` (Docker Hardened Images —
  free and open source; needs a Docker Hub account, not a paid plan)
- Runtime: `caddy:2-alpine`, pinned by digest
- **`admin-ui-v2` has no `Dockerfile.dev`.** Local development for the admin
  console runs the Vite dev server directly (`npm run dev`) rather than through
  Docker; `admin-ui-v2/Dockerfile.prod` is the only Dockerfile the package
  ships. `frontend-v2/Dockerfile.dev` exists and runs on **`node:24-alpine`**
  (Vite dev server, not Caddy) — that's what `docker compose up` builds locally
  for `web-ui`. `docker-compose.yml`'s `admin-ui` service in fact builds
  `admin-ui-v2/Dockerfile.prod` directly, since there's no dev variant to
  build instead.

### Where the running images actually come from

**Local development (`docker compose up -d`):** Docker builds all 18 images
from source on your machine, from the `Dockerfile.dev`/`Dockerfile.prod`
variants above.

**Production (Helm chart):** the chart does **not** build anything — it pulls
pre-built images. `image.registry`/`image.repoPrefix` in `values.yaml` default
to the commercial line (`docker.io/vistasecurity/*`); the **Core** chart
published at `oci://ghcr.io/vistasecurity/vistaplatform` rewrites those to
`ghcr.io/vistasecurity/*` and digest-pins every backend to the image built
from *this* public source by `.github/workflows/release-core.yml` — no
`-tags ee`, no obfuscation. Every image and the chart itself are cosign-signed;
see [Verifying what you're running](https://github.com/VistaSecurity/VistaPlatform-Core/blob/main/INSTALL.md#verifying-what-youre-running)
in `INSTALL.md`.

---

## Third-party runtime images

### `docker-compose.yml` (local full stack)

| Service | Image reference |
|---------|-----------------|
| postgres | `postgres:17-alpine` |
| redis | `redis:8-alpine` |
| influxdb | `influxdb:2.8-alpine` |
| nats | `nats:2.14-alpine` |
| api-gateway | `traefik:v3.6.12` |
| otel-collector | `otel/opentelemetry-collector-contrib:0.151.0` |
| jaeger | `jaegertracing/jaeger:2.17.0` |
| prometheus | `prom/prometheus:v3.11.3` |
| grafana | `grafana/grafana:13.1.0-25351545110` |
| adminer | `adminer:latest` (local dev only — a Postgres admin UI) |

`api-gateway` (Traefik) exists only in the Docker Compose topology. There is no
in-cluster gateway pod in the Helm chart — the chart's Traefik `IngressRoute`/
`Middleware` resources route the cluster's own Traefik directly to backend
Services.

### Helm chart (`charts/vistaplatform/values.yaml`) — in-cluster datastores

The chart pins its own datastore image versions, which are **not always the
same as `docker-compose.yml`'s** — always state which one you mean when
answering a supply-chain question, the sets are not identical:

| Datastore | Image reference | vs. `docker-compose.yml` |
|-----------|-----------------|---------------------------|
| postgres | `postgres:17-alpine` | same |
| redis | `redis:7-alpine` | dev compose runs `8-alpine` |
| influxdb | `influxdb:2.8-alpine` | same |
| nats | `nats:2.10-alpine` | dev compose runs `2.14-alpine` |

Any of the four in-cluster datastores can be swapped for a managed/external
instance instead (`datastores.<name>.enabled: false` plus the corresponding
`*-url` secret key) — see the comments above the `datastores:` block in
`values.yaml`.

---

## Environment summary

| Concern | `docker-compose.yml` (local dev) | Helm chart (production) |
|--------|----------------------------|---------------------------|
| Builds images from source | Yes, all 18 | No — pulls pre-built, signed images |
| API gateway (Traefik pod) | Yes (`api-gateway` service) | No — cluster's own Traefik routes directly |
| Observability stack (otel-collector, jaeger, prometheus, grafana) | Bundled for local exploration | Not installed by the chart — bring your own |
| adminer | Bundled | Not applicable |

For compliance answers, state **which environment** defines the deployment
you're describing — a laptop `docker compose up -d` and a production Helm
install run different image sets, at different versions, from different
registries.
