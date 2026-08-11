---
render_macros: false
---

# Vista Security Overview — RKE2 v1

Audience: customer security / GRC teams reviewing Vista before approving deployment to production.

---

## 1. Executive summary

Vista is delivered as a Helm chart that installs into a customer-managed RKE2 Kubernetes cluster. All workloads, data, and credentials remain inside the customer's cluster. Vista's only required external dependency is image registry access — Docker Hub (`docker.io/vistasecurity/`, the VistaSecurity organization's URL namespace) for standard deliveries, or AWS ECR for contracts that specifically require it. Either way, the registry is read-only and authenticated with a long-lived access token (Docker Hub) or short-lived AWS IAM credentials (ECR).

The chart enforces a defense-in-depth security posture by default:

- All pods run **non-root**, with **read-only root filesystems**, **all capabilities dropped**, and the **RuntimeDefault seccomp profile**.
- A **default-deny `NetworkPolicy`** is applied to the namespace; only required east-west flows are explicitly allowed.
- **Datastores require authentication** (Postgres password, Redis `requirepass`, NATS authorization token, InfluxDB admin password). Each is generated independently at install time and stored in a chart-managed Secret.
- **TLS terminates at the ingress** with a customer-supplied certificate. HTTP is redirected to HTTPS by a Traefik middleware; HSTS is set on responses.
- **License token (JWT) is mounted as a file**, not an env var, reducing exposure via `/proc/<pid>/environ`, child-process inheritance, and crash dumps.
- **Container images and the Helm chart are signed with cosign keyless OIDC**; signatures are verifiable end-to-end against VistaSecurity's GitHub Actions identity.

---

## 2. Architecture and trust boundaries

```
                  ┌─ trust boundary: customer infrastructure ─────────────────┐
                  │                                                            │
   internet ──────┤  customer ingress LB / DNS                                 │
                  │           │                                                │
                  │   ┌───────▼────────┐                                       │
                  │   │ Cluster ingress│  Traefik (installed per §3.5 of       │
                  │   │ TLS terminates │  the deployment guide)                │
                  │   └───────┬────────┘                                       │
                  │           │ HTTP within cluster                            │
                  │   ┌───────▼────────────────────┐                           │
                  │   │ namespace: vistaplatform      │                           │
                  │   │  ┌──────────────────────┐  │                           │
                  │   │  │ default-deny NetPol  │  │                           │
                  │   │  └──────────────────────┘  │                           │
                  │   │  ┌─────────┐   ┌────────┐  │                           │
                  │   │  │api-gw   │──▶│backends│  │                           │
                  │   │  └─────────┘   └───┬────┘  │                           │
                  │   │                    │       │                           │
                  │   │  ┌────┐ ┌───┐ ┌────▼┐ ┌──┐ │                           │
                  │   │  │PG  │ │RDS│ │NATS │ │IX│ │   in-cluster only         │
                  │   │  └────┘ └───┘ └─────┘ └──┘ │                           │
                  │   └────────────────────────────┘                           │
                  │                                                            │
                  └────────────────────────────────────────────────────────────┘
                              │
                              │ outbound: image pulls only
                              ▼
                  ┌─ trust boundary: VistaSecurity (vendor) ──────┐
                  │  Docker Hub (or ECR for ECR contracts)     │
                  │  ─ container images (signed)               │
                  │  ─ Helm chart artifact (signed)            │
                  │  Read-only via access token / IAM          │
                  └────────────────────────────────────────────┘
```

**No customer data leaves the cluster.** Vista services do not phone home, do not transmit telemetry to VistaSecurity-controlled endpoints, and do not call external SaaS by default. Optional integrations (Stripe billing, OpenTelemetry export to a customer-controlled collector) exist but are off by default.

---

## 3. Network flows

### Inbound (external → cluster)

| Path | Port | Termination | Authentication |
|---|---|---|---|
| Tenant browser → `https://<dnsName>/` | 443 | Ingress | TLS + cookie session (httpOnly, Secure, SameSite=Lax) |
| Tenant browser → `https://<dnsName>/admin` | 443 | Ingress | TLS + cookie session, role check at admin-ui |
| Tenant API client → `https://<dnsName>/api/v1/*` | 443 | Ingress | TLS + JWT bearer token |

The chart redirects all `:80` traffic to `:443` via a Traefik `redirectScheme` middleware.

### East-west (within the cluster)

Every flow below is explicitly allowed by a NetworkPolicy. All other flows are denied.

| From | To | Port | Auth |
|---|---|---|---|
| ingress controller pod | api-gateway | 80 | none (in-cluster) |
| api-gateway | any backend service | 8080 | HMAC-SHA256 signed inter-service token |
| backend service | postgres | 5432 | password (chart-generated) + sslmode=require |
| backend service | redis | 6379 | requirepass (chart-generated) |
| backend service | nats | 4222 | authorization token (chart-generated) |
| schema-migration Job | postgres | 5432 | same as backends |

Backends only reach datastores they actually need. The `backends:` map in `values.yaml` declares each service's `needs` for postgres / redis / nats, and the NetworkPolicy emits exactly those rules. There is no service-to-service shortcut that bypasses the api-gateway.

### Outbound (cluster → external)

| Destination | Required | Purpose | How to disable |
|---|---|---|---|
| Docker Hub (`registry-1.docker.io`, `auth.docker.io`) | yes | container image + Helm chart pulls | not possible — needed at install + on every pod restart |
| AWS ECR (`*.dkr.ecr.<region>.amazonaws.com`) | yes (ECR contracts only) | container image + Helm chart pulls | not possible — needed at install + on every pod restart |
| ACME directory (Let's Encrypt etc.) | conditional | TLS certificate issuance via cert-manager | use `tls.mode: existingSecret` and supply your own cert |
| Stripe (`api.stripe.com`) | no, off by default | billing in admin-ui | leave `stripe_secret_key` unset |
| OpenTelemetry collector | no, off by default | trace/metric export | leave `OTEL_ENABLED=false` |
| Customer-configured webhooks | conditional | tenant-defined notification webhooks | tenant admins control these from web-ui |

License validation is **fully offline** — JWT signature verification against an embedded ECDSA P-256 public key. No license-server callout.

---

## 4. Secret inventory

| Secret | Lives in | Created by | Rotation |
|---|---|---|---|
| `vistaplatform-license` | K8s Secret | Customer applies, JWT minted by VistaSecurity | Customer re-applies the Secret + rolling restart of backend Deployments |
| `vistaplatform-platform` | K8s Secret | Customer applies (or chart templates from values.yaml) | Customer re-applies Secret + rolling restart |
| `vistaplatform-generated` | K8s Secret | Chart auto-generates on first install via `lookup` + `randAlphaNum` | Manual `kubectl edit secret` + restart of datastores AND consumers |
| TLS certificate | K8s Secret | cert-manager (or customer-supplied) | cert-manager auto-renews; customer-supplied: customer rotates |

**`vistaplatform-generated`** carries the datastore credentials (postgres, redis, influxdb admin, influxdb token, nats token) and is annotated `helm.sh/resource-policy: keep`. This means `helm uninstall` does **not** delete it, ensuring credentials persist if the chart is reinstalled and the data PVCs are still around.

**Secrets in flight inside the pod**:
- `LICENSE_TOKEN_FILE` — path to a file mount of the license JWT. The JWT itself never appears as an env var, never enters `/proc/<pid>/environ`, never gets inherited by exec'd children.
- `JWT_SECRET`, `INTERNAL_AUTH_SECRET`, `ENCRYPTION_MASTER_KEY` — currently sourced as env vars from the platform Secret. **Roadmap item:** convert these to file mounts in a future release alongside the rest of the deployment profiles. The file-mount loader is already in place; only the chart wiring needs updating.

**No secret is logged.** Vista services do not log credential values. Audit logs include user identifiers and operation types but never bearer tokens.

---

## 5. Hardening posture

### Pod / container security

- `automountServiceAccountToken: false` on **every** workload in the chart. None of the Vista services interact with the Kubernetes API. The default ServiceAccount is unused.
- `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, all capabilities dropped, RuntimeDefault seccomp on every backend, frontend, gateway, and (where the upstream image supports it) datastore pod.
- All workloads have CPU and memory `requests` and `limits` set, preventing resource-starvation DoS within the namespace.
- `PodDisruptionBudgets` engage in HA mode preventing both replicas of a service being evicted simultaneously during node drains.
- The release Namespace is labeled `pod-security.kubernetes.io/enforce: baseline` (audit + warn at `restricted`) when the chart manages namespace creation. If you `--create-namespace` separately, apply these labels yourself.

### Network

- Default-deny ingress on the namespace. Eight named NetworkPolicies provide the minimum-required allow set.
- No service is exposed via NodePort or LoadBalancer by default. The gateway is `ClusterIP`; external access goes through the cluster's ingress controller.
- The NATS monitoring port (8222) is bound to the headless Service for in-cluster liveness probes only and is not reachable from outside the StatefulSet pods.

### Supply chain

- Container images and the chart artifact are signed with **cosign keyless OIDC** via GitHub Actions. The signing identity is the workflow path; you can verify with one command (see deployment guide §8).
- **SBOMs** (CycloneDX, generated by syft) are attached as cosign attestations to every image and the chart.
- **In-toto attestation** lists every artifact digest in a release; one signed manifest covers the whole release.
- All third-party GitHub Actions in the release pipeline are pinned by commit SHA, not by version tag.
- Container images are pinned by `sha256:` digest in the chart's `values.yaml` at release time. Tags are immutable in VistaSecurity's published registries.
- **Customer-distributed binaries are obfuscated.** Backend service images shipped to customers are built with [garble](https://github.com/mvdan/garble): symbol names replaced with deterministic hashes, string literals scrambled to runtime, file paths and build IDs stripped. This is a separate build from the development binaries used by the VistaSecurity team internally — distinct Dockerfiles, distinct license signing keys. Exception: `pcap-processor` uses CGO + libpcap and cannot run through garble; it ships with `-ldflags="-w -s"` (strip symbols and DWARF) only.

### Cluster

- The deployment guide documents the RKE2 CIS profile (`profile: cis`), audit logging, and `write-kubeconfig-mode: 0600` as required cluster-level baseline. These are customer responsibilities; the chart cannot enforce them.

---

## 6. Threat model summary

What this v1 deployment defends against, and what it does not.

### Defends against

- **Compromised pod** trying to read other services' files or escalate to host: read-only root FS, dropped capabilities, no host paths, no privileged mode, no service account token mounted.
- **Compromised pod** scanning the namespace: NetworkPolicies block lateral movement to datastores or peer services that don't explicitly allow it.
- **MITM on ingress traffic:** TLS-only, HSTS, secure cookies, valid certificate via cert-manager.
- **Stolen kubeconfig** (cluster-wide): mode 0600 on the master makes copy-by-local-user harder; CIS profile + audit log makes detection feasible.
- **Compromised image registry tag:** images are pulled by digest after release, and cosign signatures verify against a workflow-pinned identity. A tag-mover attack does not affect already-deployed pods.
- **License evasion via stripped binaries:** every backend validates the license JWT independently at startup, against a public key embedded in the binary.

### Does NOT defend against

- **Cluster admin compromise.** Anyone with cluster-admin can read the chart-managed Secrets and platform Secret. This is unchanged from any K8s deployment.
- **Datastore node loss in HA mode.** Postgres / Redis / InfluxDB / NATS are single-replica in v1; a node failure causes a brief outage on those services. See deployment guide §12 for the v1.x roadmap.
- **Inter-tenant data isolation through bugs in the application layer.** Vista uses Postgres Row-Level Security plus per-tenant scoping in service code; vulnerabilities in either could permit cross-tenant access. This is a software-quality concern, not a chart-level one. Report security findings to VistaSecurity per §9.
- **Side-channel attacks between co-tenanted pods.** Kubernetes is not a hard multi-tenant boundary; it is appropriate for trusted-application multi-tenancy (multiple tenants of one trusted product), not multiple distrusting tenants sharing a cluster. The chart does not change this.

---

## 7. Logging, audit, and monitoring

- **K8s audit log** enabled on the master per the deployment guide, written to `/var/lib/rancher/rke2/server/logs/audit.log`. Customer is responsible for shipping these to a SIEM.
- **Application audit log** — Vista's audit-service records authentication events, RBAC decisions, configuration changes, and tenant-administrative actions. Stored in Postgres; customer can query via the admin-ui or directly via SQL.
- **Application access logs** — Traefik api-gateway logs every request with method, path, status, latency, and tenant identifier (when authenticated). Available via `kubectl logs deploy/api-gateway`.
- **No log shipping is configured by default.** Customer can deploy fluentbit / loki / vector against the namespace to forward.
- **OpenTelemetry export** is supported but off by default. Set `OTEL_ENABLED=true` and `OTEL_COLLECTOR_URL=...` (in a values override) to enable. Traces include request IDs but no token values.

---

## 8. Compliance posture

- **CIS Kubernetes Benchmark:** the customer-side cluster install (RKE2 with `profile: cis` + audit policy + kubeconfig mode 0600) satisfies the cluster-level controls. The chart's pod hardening covers the workload-level controls (non-root, read-only FS, dropped capabilities, etc.).
- **NIST 800-53 / SOC 2:** Vista itself produces compliance evidence as a feature (audit log, immutable findings, framework-based reporting). For controls related to Vista's own deployment, contact VistaSecurity Sales for current attestation status.
- **FIPS 140-3:** the chart does not currently enforce a FIPS-validated cryptographic library. If your environment requires FIPS-mode binaries, contact VistaSecurity for a FIPS-targeted build of the images.

---

## 9. Reporting security issues

**Do not open a public issue.** Report privately through either channel:

- **GitHub Security Advisories** — [open a draft advisory](https://github.com/VistaSecurity/VistaPlatform-Core/security/advisories/new). Preferred: it keeps the report, the fix and the CVE in one place.
- **Email** — `product@vistasecurity.io`. If you want to encrypt the report, ask for a key in a first message with no details in it.

Acknowledgement within 3 business days, initial assessment within 10, and we ask for 90 days before public disclosure. The full policy — including what is in and out of scope — is [SECURITY.md](https://github.com/VistaSecurity/VistaPlatform-Core/blob/main/SECURITY.md), which is the authoritative version if this page ever drifts from it.

---

## 10. Configuration knobs that affect security posture

The defaults are secure. These are the values you might want to confirm or override in your `values-customer.yaml`:

| Value | Default | Security impact |
|---|---|---|
| `tls.mode` | `certManager` | Set to `existingSecret` if you bring your own certificate. `none` is gated behind `tls.allowNone: true` and intended for dev only. |
| `networkPolicy.enabled` | `true` | Do not disable in production. |
| `networkPolicy.ingressControllerNamespace` | `kube-system` | Override if your ingress runs elsewhere; otherwise the gateway will be unreachable. |
| `enableSpreadAcrossNodes` | `false` (true in `values-ha.yaml`) | Affects availability, not direct security. |
| `image.pullSecrets` | `[]` | If you use the ECR imagePullSecret path (§6B Option B2 of the deployment guide), ensure the Secret is rotated before the 12-hour ECR token expires. |

No values weaken the default hardening. The chart fails to render if `tls.mode=none` is set without explicitly setting `tls.allowNone: true`.
