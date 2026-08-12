---
render_macros: false
---

# Vista Deployment Guide — RKE2 v1

Audience: platform engineers / SRE deploying Vista into a customer-managed RKE2 cluster.

This guide is self-contained. You do not need access to the Vista source repository.

Vista container images and the Helm chart are delivered through the **VistaSecurity Docker Hub organization** at `docker.io/vistasecurity/` (display name "Vista Platform"; URL namespace `vistasecurity`). Your license package includes a Docker Hub access token scoped to that organization, plus the chart version and image tag for your release. cosign signatures (chart and images) are also published to Docker Hub.

AWS ECR delivery is available as an alternative for contracts that specifically require it; if that applies to you, your VistaSecurity contact will provide the ECR account, region, and IAM instructions, and the ECR-specific notes throughout this guide tell you what to substitute. **Otherwise, follow the Docker Hub path everywhere.**

> **Before you open §1:** Complete the [Pre-Flight Checklist](./pre-flight-checklist.md) first. It lists everything Vista delivers to you before the install and confirms your cluster and workstation are ready. Starting the guide without all checklist items in hand will cause the install to fail partway through.

---

## 1. Overview

Vista is a multi-tenant cryptographic asset inventory and compliance platform delivered as a Helm chart. A single `helm install` deploys:

- **16 Go backend services** (auth, inventory, compliance, etc.)
- **2 React frontends** (web-ui for tenants, admin-ui for platform admins)
- **Traefik `IngressRoute` + `Middleware` CRDs** consumed by the cluster's own Traefik. The chart does **not** ship an in-cluster gateway pod — the cluster's existing Traefik (kube-system on RKE2) handles TLS termination and per-service routing directly.
- **4 in-cluster datastores** (Postgres, Redis, InfluxDB, NATS JetStream)
- **NetworkPolicies, PodDisruptionBudgets, hardened pod security contexts** by default
- **Schema migration Job** that runs idempotently on every install/upgrade

### Architecture at a glance

```
  vistaplatform.example.com         admin.vistaplatform.example.com
  (tenant host)                  (admin host)
         │                              │
         └──────────────┬───────────────┘
                       ▼
            ┌─────────────────────────────┐
            │  RKE2 ingress (Traefik)     │  TLS terminates here (one cert,
            │  reads IngressRoute CRDs    │  two SANs). Routes by Host header:
            │  + Middleware CRDs from     │   tenant host → web-ui + /api/*
            │  the vistaplatform namespace   │   admin host  → admin-ui
            └─────────────┬───────────────┘
                ┌─────────────────┼─────────────────┐
                │                 │                 │
        ┌───────▼──────┐  ┌───────▼──────┐  ┌──────▼──────┐
        │ 16 Go        │  │ web-ui       │  │ admin-ui    │
        │ services     │  │ (replicas:2) │  │ (replicas:2)│
        │ (replicas:2) │  └──────────────┘  └─────────────┘
        └──┬───┬───┬──┘
           │   │   │
   ┌───────▼┐ ┌▼──┐ ┌─▼─────┐ ┌────────┐
   │Postgres│ │Rds│ │ NATS  │ │InfluxDB│   single replica each
   │ (PVC)  │ │   │ │  JS   │ │  (PVC) │   in v1 — see HA caveats
   └────────┘ └───┘ └───────┘ └────────┘
```

Per-service routing rules (path prefixes, rate limits, circuit breakers, CORS, security headers, `/api/v1/<svc>/health → /health` rewrites, `/api/v2 → /api/v1` rewrites) are emitted as Traefik `IngressRoute` and `Middleware` CRDs in the release namespace and read by cluster Traefik. They are generated from `standards/service-registry.yaml` and shipped inside the chart; customers do not edit them.

### Two install profiles

The chart ships two reference values overlays:

- **`values-ha.yaml`** — recommended for the customer's 3-node cluster. All stateless workloads run `replicas: 2` with `podAntiAffinity` to spread across worker nodes, and PodDisruptionBudgets engage. Datastores remain single-replica (true datastore HA is a v1.x roadmap item).
- **`values-minimal.yaml`** — single-replica everything. For lab / single-worker / minimal-footprint deployments.

You apply one of these alongside your `values-customer.yaml`.

### Before you begin — cluster assumptions

> **This guide assumes you already have a freshly installed RKE2 cluster with no existing production workloads running on it.**
>
> If you need to provision a new RKE2 cluster from scratch, Vista provides a helper script (`scripts/install-rke2-server.sh`) and a reference cluster config (`config/rke2/cluster-config.yaml.example`) that stand up a CIS-hardened single-node cluster in minutes. A full walkthrough is available in the [RKE2 Cluster Provisioning Guide](./cluster-provisioning-guide.md) — request it from your VistaSecurity contact or start there if you don't have an existing cluster.
>
> If you have an existing RKE2 cluster with running workloads, read §3 carefully before proceeding. Applying the CIS hardening profile to a live cluster requires a maintenance window and may affect existing applications.

---

## 2. Prerequisites

### Tested-against versions

Vista v2.4 has been validated end-to-end against the dependency versions below. Customers may deviate at their own risk; these are the floor of what we test on every release.

| Dependency | Tested version | Where it appears |
|---|---|---|
| RKE2 | `v1.35.4+rke2r1` | §3 |
| Traefik (Helm chart) | `32.1.1` | §3.5 |
| Longhorn (Helm chart) | `1.11.2` | §2 (storage class) |
| MetalLB (Helm chart) | `0.14.x` | §4B |
| cert-manager | `v1.16.x` | §5B / §5C / **§5E (required — mesh mTLS is on by default)** |
| Stakater Reloader | latest | **§5E (required — mesh mTLS is on by default)** |

Newer major versions of these charts may introduce breaking value-schema changes. Traefik v40, for example, removed several v32-era keys and is **not** drop-in compatible. Pin to the tested versions until you have a maintenance window to test an upgrade.

### Cluster

- **RKE2 1.28 or later** (1.30+ recommended). Three nodes: 1 master + 2 workers.
- **CIS profile enabled** on the master (instructions in §3).
- **Audit logging enabled** on the master (instructions in §3).
- **Worker VM size:** 6 vCPU / 16 GiB RAM / 100 GiB disk per worker recommended. Minimum 4 vCPU / 8 GiB.
- **Master VM size:** 2 vCPU / 4 GiB / 50 GiB disk is sufficient.
- **Storage class** — the chart defaults to `local-path` (acceptable for single-node lab installs only). For production we recommend Longhorn (install instructions below) or an existing CSI driver. Override the class via `datastores.storageClassName` in your values file.

### Network

- **Two DNS records** pointing at the cluster's ingress endpoint (or the load balancer in front of it). Both records resolve to the same IP — Traefik routes by `Host` header.

  | Record | Used for | Example |
  |---|---|---|
  | Tenant host (`tls.dnsName`) | web-UI + REST API + WebSocket + uploads | `vistaplatform.example.com` |
  | Admin host (`tls.adminDnsName`) | admin-UI (platform administration) | `admin.vistaplatform.example.com` |

  The admin-UI is served at the root of the admin host (not as a path under the tenant host). This matches the deployment convention used in every other Vista delivery and avoids an asset-path bug that would block admin-UI rendering if it ran under a sub-path.

  If you do not configure the admin host, the platform admin-UI will not be reachable externally — `kubectl port-forward svc/admin-ui` remains an emergency path. Both UIs share the same TLS certificate (single cert with both SANs); see §5 below.

  > **Cookie domain constraint — required, not optional.**
  > Vista issues authentication cookies with `Domain=.{tls.dnsName}` (a wildcard scoped to the tenant hostname and all its subdomains). The admin-UI frontend makes its API calls to that same host, so the browser only sends those cookies when the admin hostname is **within the same registered domain** as the tenant hostname.
  >
  > - **Supported:** `vistaplatform.example.com` + `admin.vistaplatform.example.com` — the admin host is a subdomain of the tenant host. ✓
  > - **Supported:** `api.example.com` + `admin.example.com` — both under `example.com`; API calls go to `api.example.com` and the cookie domain `.api.example.com` covers those requests. ✓
  > - **Not supported:** `vistaplatform.company-a.com` + `admin.company-b.com` — different registered domains. The browser will not send auth cookies for API calls that cross eTLD+1 boundaries with `SameSite=Strict`, breaking admin login.
  >
  > The examples throughout this guide use the subdomain pattern (`admin.vistaplatform.example.com`) because it is unambiguously safe. If your organization's naming policy requires a different structure, verify that both hostnames share the same eTLD+1 before proceeding.

- **Outbound connectivity from cluster nodes** to the following hosts. If your environment uses an egress proxy or strict allowlist firewall, open these before starting:

  | Host(s) | Purpose | Required for |
  |---|---|---|
  | `registry-1.docker.io`, `auth.docker.io`, `production.cloudflare.docker.com` | Vista container images + Helm chart | always (Docker Hub delivery) |
  | `*.dkr.ecr.<your-region>.amazonaws.com`, `api.ecr.<your-region>.amazonaws.com` | Vista container images + Helm chart | only if your contract delivers via ECR |
  | `get.rke2.io`, `update.rke2.io`, `rpm.rancher.io` (RHEL/Rocky) | RKE2 installer + add-on container images | §3 |
  | `helm.traefik.io`, `traefik.github.io` | Traefik Helm chart + images | §3.5 |
  | `charts.longhorn.io`, `longhornio` containers on Docker Hub | Longhorn Helm chart + images | §2 (if installing Longhorn) |
  | `metallb.github.io`, MetalLB images on quay.io | MetalLB Helm chart + images | §4B (if using MetalLB) |
  | `charts.jetstack.io`, cert-manager images on quay.io | cert-manager Helm chart + images | §5B / §5C only |
  | `acme-v02.api.letsencrypt.org` (or your ACME server) | ACME HTTP-01 / DNS-01 challenge | §5B only |

- **Outbound connectivity from your operator workstation** to `registry-1.docker.io` (and `<your-account>.dkr.ecr.<region>.amazonaws.com` for ECR customers) for `helm pull` and `cosign verify`.

- No outbound connectivity required for license validation — licenses are JWTs verified against a public key embedded in the binaries.

### Required cluster add-ons

- **cert-manager** v1.16 or later — **required by default**. Service-mesh mTLS (§5E) is **on by default** (#965) and cert-manager issues its Platform CA + per-service certs; a stock install **fails fast** if its CRDs are absent. It is *also* used by the §5B / §5C edge-cert paths. Earlier versions accepted a now-removed `apiVersion` field on `issuerRef`; v1.16+ enforces strict decoding and the chart's `Certificate` template uses the `group` field instead. cert-manager is **only** skippable if you both bring your own edge TLS Secret (§5A self-signed or §5D PKI-team-provided, `tls.mode: existingSecret`) **and** opt out of mesh mTLS (§5E — set all three internal-transport toggles to `false`).
- **Stakater Reloader** — **required by default** (see §5E). Restarts pods when their auto-rotated mesh cert Secret changes. The install does not fail without it, but the first cert renewal (~60 days in) silently breaks mTLS if Reloader is absent. Not needed only if you opt out of mesh mTLS (§5E).
- **CNI** that enforces NetworkPolicies. RKE2's default Canal does. **Cilium is recommended** for security-conscious deployments — it provides DNS-based egress policies, L7 HTTP/gRPC enforcement, and Hubble observability beyond what standard NetworkPolicy can express. If you've replaced the default CNI, confirm your CNI implements NetworkPolicy v1.
- **Storage class** with dynamic provisioning supporting `ReadWriteOnce` and at least 60 GB available across nodes. **Longhorn is recommended** for customers without existing storage infrastructure (see "Storage class — Longhorn install" below). Customers with existing CSI drivers (NetApp, Pure, Rook-Ceph, EBS, Persistent Disk, etc.) point Vista at their class with `--set datastores.storageClassName=<their-class>`.

### Storage class — Longhorn install (recommended)

Skip this section if you already have a CSI-based storage class your cluster uses. Otherwise:

**Per-node host packages.** On every cluster node:

```bash
sudo apt install -y open-iscsi nfs-common
sudo systemctl enable --now iscsid
```

(Other distros: install the equivalents — `iscsi-initiator-utils` and `nfs-utils` on RHEL/Rocky/Alma, etc.)

Verify each node can load the iSCSI kernel module and that multipathd isn't going to interfere:

```bash
sudo modprobe iscsi_tcp && echo "iscsi_tcp ok"
sudo systemctl is-active multipathd 2>&1 | grep -q inactive && echo "multipathd ok (inactive)" \
  || echo "multipathd active — see Longhorn docs for configuration to ignore Longhorn devices"
```

**Pre-create the `longhorn-system` namespace with `privileged` Pod Security labels.** Longhorn's manager and CSI pods require host paths, the `NET_ADMIN` capability, and the ability to run as root — all of which the cluster-default `restricted` enforcement (applied via `profile: cis`) blocks. `helm install --create-namespace` inherits the cluster default; you must label the namespace before installing or the speaker/manager DaemonSets will fail admission with `PodSecurity "restricted:latest"` violations.

```bash
kubectl create namespace longhorn-system
kubectl label namespace longhorn-system \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/audit=privileged \
  pod-security.kubernetes.io/warn=privileged
```

**Install Longhorn via Helm:**

```bash
helm repo add longhorn https://charts.longhorn.io
helm repo update
helm install longhorn longhorn/longhorn \
  --namespace longhorn-system \
  --version 1.11.2 \
  --set defaultSettings.defaultReplicaCount=3 \
  --wait --timeout 10m
```

(Set `defaultReplicaCount=1` for single-node clusters; `=3` for 3+ node production. Increase later via the Longhorn UI as the cluster grows.)

> The same pattern (`kubectl label namespace … pod-security.kubernetes.io/enforce=privileged`) applies to any other privileged infrastructure component you add later — Reloader, OpenEBS, cert-manager's CAInjector in some configurations, etc. The Vista application namespace itself runs at `restricted` and does **not** need privileged labels.

**Verify the storage class exists and Longhorn is healthy:**

```bash
kubectl get storageclass longhorn
kubectl -n longhorn-system get pods | grep -v Running | grep -v Completed | grep -v "0/0"
# expect: only the header line (no non-Running pods)
```

**Set Longhorn as the default storage class** (optional but recommended):

```bash
kubectl patch storageclass longhorn -p \
  '{"metadata": {"annotations": {"storageclass.kubernetes.io/is-default-class": "true"}}}'
```

For single-node lab evaluations without storage infrastructure or appetite for Longhorn's overhead, RKE2 ships the `local-path` StorageClass by default — no extra setup required, just leave the chart's `datastores.storageClassName` at its `local-path` default. **Not recommended for customer-facing deployments** — `local-path` pins each PVC to one node, so any worker loss takes its datastores down until the node returns.

### Tools on the operator's workstation

- `kubectl` — must reach the cluster's API server with admin credentials.
- `helm` v3.13 or later.
- `cosign` v2.x (only required for verifying chart and image signatures).
- `aws` CLI v2 — only required if your contract delivers via ECR and you generate pull secrets manually instead of using a node IAM role. Most customers can skip this.

### From Vista (delivered out of band)

Your Vista license package is delivered via a password-manager share or encrypted email. It contains everything you need to complete this guide:

| Item | What it is | Used in |
|---|---|---|
| **License token (JWT)** | Signed token that authorizes your deployment | §7 |
| **Docker Hub org URL namespace** | The org's URL namespace (`vistasecurity`) — what appears in `docker.io/<namespace>/...` paths. Display name on Docker Hub is "Vista Platform". | §6, §9 |
| **Docker Hub access token** | Credentials to pull images from Docker Hub | §6 |
| **Chart version + image tag** | The specific chart and image tag versions to deploy (e.g. chart `2.5.2` / image `v2.5.2`; chart and image share the same release number — the chart version is bare semver, the image tag has a `v` prefix) | §8, §9 |
| **ECR account ID + region + IAM instructions** | _Only if your contract delivers via ECR_ | "Alternative: AWS ECR" subsection in §6 |

Keep this package secure — it contains credentials. Do not commit it to source control.

---

## 3. Install RKE2 with CIS profile and audit logging

### Why CIS hardening is required

The CIS Kubernetes Benchmark is a security standard published by the Center for Internet Security. RKE2 has built-in support for it via `profile: cis`. Enabling it enforces API server hardening, kubeconfig file permissions, and audit logging — controls that Vista's own compliance reporting assumes are present at the cluster level.

> **Can I skip this?** Vista will install and run on a non-CIS-hardened cluster. The chart enforces its own pod-level security controls (non-root containers, NetworkPolicies, default-deny ingress) regardless of cluster profile. If your organization has compensating controls or policy constraints that prevent applying the CIS profile, you may skip §3 and proceed to §4. Document your compensating controls — auditors will ask.

Choose the path that matches your situation:

- **§3A — Fresh RKE2 install** — RKE2 is not yet installed. Bake CIS in from the start.
- **§3B — Retrofit onto existing cluster** — RKE2 is already running. Apply the profile to a live cluster.

---

### §3A — Fresh install (CIS baked in from the start)

If you are using the Vista cluster provisioning helper script, the reference config (`config/rke2/cluster-config.yaml.example`) already includes the CIS profile. See the [RKE2 Cluster Provisioning Guide](./cluster-provisioning-guide.md) for the full walkthrough.

If you are configuring manually, create the following files **before** running the RKE2 installer:

**Step 1 — Create required system users.** Run this **on every node** (master and workers) for symmetry and future-promotion to multi-master. The `etcd` user is only strictly required on nodes that run etcd (master nodes), but creating it everywhere costs nothing and keeps the procedure uniform:

```bash
sudo useradd -r -c "kube-apiserver user" -s /sbin/nologin -M kube-apiserver
sudo useradd -r -c "etcd user" -s /sbin/nologin -M etcd
```

**Step 2 — Create `/etc/rancher/rke2/audit-policy.yaml` (master only):**
```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
    omitStages: ["RequestReceived"]
```

**Step 3 — Create `/etc/rancher/rke2/config.yaml` on the master.**

> ⚠️ **REPLACE the `tls-san` placeholder below with your actual hostname before saving the file.** The angle-bracket form `<master-hostname-or-IP>` is a literal — RKE2 will happily bake it into the API server certificate as a SAN if you leave it in place, and you'll later get TLS errors when you try to reach the API server by its real hostname. Substitute the real DNS name (e.g. `master-1.example.com`) or IP. If your cluster will be reached by multiple names, list them all — one per `- "..."` line.

```yaml
profile: cis
write-kubeconfig-mode: "0600"
tls-san:
  - "REPLACE_WITH_YOUR_HOSTNAME"   # e.g. master-1.example.com — DO NOT leave the placeholder

# Disable RKE2's bundled ingress. v1.30+ ships nginx by default; Vista
# requires Traefik (the chart uses Traefik-only IngressRoute CRDs). We install
# Traefik explicitly in §3.5 below.
disable:
  - rke2-ingress-nginx

kube-apiserver-arg:
  - audit-log-path=/var/lib/rancher/rke2/server/logs/audit.log
  - audit-log-maxage=30
  - audit-log-maxbackup=10
  - audit-log-maxsize=100
  - audit-policy-file=/etc/rancher/rke2/audit-policy.yaml

# Optional: prevent app workloads from scheduling on the master node.
node-taint:
  - "node-role.kubernetes.io/control-plane=true:NoSchedule"
```

After saving, sanity-check that you replaced the placeholder:

```bash
# Should print your real hostname, NOT "REPLACE_WITH_YOUR_HOSTNAME":
sudo grep -A1 tls-san /etc/rancher/rke2/config.yaml
```

**Step 4 — Create `/etc/rancher/rke2/config.yaml` on each worker:**
```yaml
profile: cis
server: https://<master-IP>:9345
token: <node-join-token-from-master>
```

**Step 5 — Install RKE2 and start it.**

On the master:
```bash
# Install the RKE2 server binary (pinned to the tested version):
curl -sfL https://get.rke2.io | \
  sudo INSTALL_RKE2_VERSION=v1.35.4+rke2r1 INSTALL_RKE2_TYPE=server sh -

# Enable and start the service:
sudo systemctl enable --now rke2-server.service

# Wait ~60–90 seconds for first-boot, then confirm:
sudo systemctl is-active rke2-server   # expected: active
```

The node-join token is generated on first boot. Retrieve it from the master and use it in each worker's `config.yaml` (Step 4):
```bash
sudo cat /var/lib/rancher/rke2/server/node-token
```

On each worker (substitute `INSTALL_RKE2_TYPE=agent`):
```bash
curl -sfL https://get.rke2.io | \
  sudo INSTALL_RKE2_VERSION=v1.35.4+rke2r1 INSTALL_RKE2_TYPE=agent sh -

sudo systemctl enable --now rke2-agent.service
sudo systemctl is-active rke2-agent    # expected: active
```

Then skip to §3 Verify below.

---

### §3B — Retrofit CIS onto an existing cluster

> **Warning:** This procedure restarts the RKE2 API server on the master node. The restart takes approximately 30–60 seconds during which `kubectl` commands will be unavailable. **Running workloads on worker nodes are not affected** — existing pods keep running. However, once the server comes back up with `profile: cis` active, pods that violate CIS pod security requirements may fail to reschedule if they crash or their node reboots. Perform this in a maintenance window on clusters with existing workloads.

**Step 1 — Create required system users** (on the master):
```bash
sudo useradd -r -c "kube-apiserver user" -s /sbin/nologin -M kube-apiserver
sudo useradd -r -c "etcd user" -s /sbin/nologin -M etcd
```

**Step 2 — Create the audit policy file** (on the master):
```bash
sudo tee /etc/rancher/rke2/audit-policy.yaml <<'EOF'
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
    omitStages: ["RequestReceived"]
EOF
```

**Step 3 — Update `/etc/rancher/rke2/config.yaml`** on the master.

First, check what is currently in your config so you don't lose anything:
```bash
sudo cat /etc/rancher/rke2/config.yaml
```

Note any `tls-san` entries — these are the hostnames and IPs the API server TLS certificate is valid for. If you remove them when rewriting the file, `kubectl` connections that use those names will fail with a TLS error. If your current config has no `tls-san` block, omit it from the new config below.

```bash
sudo tee /etc/rancher/rke2/config.yaml <<'EOF'
profile: cis
write-kubeconfig-mode: "0600"

# IMPORTANT: re-add any tls-san entries from your previous config here.
# If your cluster had none, remove this block entirely.
# tls-san:
#   - "<hostname-or-IP>"

# Disable RKE2's bundled ingress. Vista requires Traefik
# (the chart uses Traefik-only IngressRoute CRDs). If your existing cluster
# is already running rke2-ingress-nginx with other workloads on it, see the
# note below before adding this line.
disable:
  - rke2-ingress-nginx

kube-apiserver-arg:
  - audit-log-path=/var/lib/rancher/rke2/server/logs/audit.log
  - audit-log-maxage=30
  - audit-log-maxbackup=10
  - audit-log-maxsize=100
  - audit-policy-file=/etc/rancher/rke2/audit-policy.yaml
EOF
```

> **Existing cluster already running nginx?** If your cluster has `rke2-ingress-nginx` actively serving other workloads, do **not** simply add the `disable:` line — the next `rke2-server` restart will tear it down. Either (a) install Traefik alongside nginx and have Vista use Traefik's IngressClass while other apps continue using nginx, or (b) migrate the other workloads off nginx first. Skip the `disable:` block above and use option (a); see §3.5.

**Step 4 — Update each worker's config** (`/etc/rancher/rke2/config.yaml`), add `profile: cis`, then restart the agent:
```bash
# On each worker — add profile line if not present:
echo 'profile: cis' | sudo tee -a /etc/rancher/rke2/config.yaml
sudo systemctl restart rke2-agent
```

**Step 5 — Restart the server** (on the master):
```bash
sudo systemctl restart rke2-server
```

**Step 6 — Restart the Canal CNI DaemonSet** (from your operator workstation):

Restarting rke2-server can leave the Canal/Flannel VXLAN forwarding database (FDB) empty on worker nodes. Without FDB entries, cross-node pod-to-pod traffic silently drops even though the VXLAN port (UDP 8472) is open. Always restart Canal after a server restart to force it to repopulate the FDB:

```bash
kubectl -n kube-system rollout restart daemonset rke2-canal
kubectl -n kube-system rollout status daemonset rke2-canal --timeout=120s
```

Verify cross-node pod networking is working:
```bash
# Get a pod IP from one worker:
kubectl get pods -A -o wide | grep -v <master-node-name> | head -5

# From the other worker, ping that pod IP:
ssh <worker-node> "ping -c3 <pod-IP>"
# Expect 0% packet loss. If you see 100% loss, re-run the Canal restart above.
```

---

### Verify

Run these after the Canal restart:

```bash
# All nodes still Ready:
sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get nodes

# Audit log is being written:
sudo tail -1 /var/lib/rancher/rke2/server/logs/audit.log
```

### Copy kubeconfig to your operator workstation

```bash
scp <master>:/etc/rancher/rke2/rke2.yaml ~/.kube/vistaplatform-config
sed -i 's/127.0.0.1/<master-hostname-or-IP>/' ~/.kube/vistaplatform-config
chmod 600 ~/.kube/vistaplatform-config
export KUBECONFIG=~/.kube/vistaplatform-config
```

---

## 3.5 Install Traefik ingress controller

**Why this section exists.** RKE2 v1.30 and later default their bundled ingress to `rke2-ingress-nginx`, not Traefik. The Vista chart emits Traefik `IngressRoute` CRDs and `Middleware` resources — nginx does not understand these, so the routes silently never get registered and external traffic dead-ends at HTTP 404. The §3 config disables nginx; this section installs Traefik in its place.

> **Already have Traefik on your cluster?** Verify it's at v3 (chart 32.x) and that its `IngressRoute`/`Middleware` CRDs are installed: `kubectl get crd ingressroutes.traefik.io middlewares.traefik.io`. If both exist and Traefik is reachable as a `LoadBalancer` Service, skip this section.

From your operator workstation:

```bash
helm repo add traefik https://helm.traefik.io/traefik
helm repo update

helm install traefik traefik/traefik \
  --namespace kube-system \
  --version 32.1.1 \
  --set service.type=LoadBalancer \
  --set providers.kubernetesCRD.enabled=true \
  --set providers.kubernetesIngress.enabled=true \
  --set ingressClass.enabled=true \
  --set ingressClass.isDefaultClass=true \
  --wait --timeout 5m
```

> **Version pin matters.** Traefik chart v40+ rewrote several value keys (TLS, providers, ports) and is **not** drop-in compatible with v32. The chart values above target v32.x. If you must use a newer Traefik, validate the Vista install against it in a non-production cluster first.

Verify Traefik came up and got an EXTERNAL-IP (this happens after §4 — at this stage `EXTERNAL-IP` will show `<pending>` if no MetalLB / external LB is in place yet, which is expected):

```bash
kubectl -n kube-system get svc traefik
kubectl -n kube-system get pods -l app.kubernetes.io/name=traefik
```

The Service should be `TYPE: LoadBalancer`. The pod(s) should be `Running`.

> **Required if your cluster was installed with `profile: cis` (§3).** RKE2's CIS profile auto-creates a `default-network-policy` (default-deny ingress) in `kube-system`, plus a `default-network-traefik-policy` that's supposed to whitelist ingress to Traefik on ports 80 and 443. The auto-created allow-policy targets pods labeled `app.kubernetes.io/name=rke2-traefik` — the bundled chart's label, **not** the upstream `traefik/traefik` chart's label (`app.kubernetes.io/name=traefik`). Without an explicit allow-policy matching the upstream label, **nothing outside `kube-system` can reach Traefik** — cert-manager ACME solvers fail self-checks, in-cluster probes time out, etc.
>
> Apply this patch immediately after Traefik comes up. Skip it if you did NOT install RKE2 with `profile: cis`.
>
> ```bash
> kubectl apply -f - <<'YAML'
> apiVersion: networking.k8s.io/v1
> kind: NetworkPolicy
> metadata:
>   name: allow-ingress-to-upstream-traefik
>   namespace: kube-system
> spec:
>   podSelector:
>     matchLabels:
>       app.kubernetes.io/name: traefik
>   policyTypes:
>   - Ingress
>   ingress:
>   - ports:
>     - port: web
>       protocol: TCP
>     - port: websecure
>       protocol: TCP
> YAML
> ```

Continue to §4 for IP assignment.

---

## 3.6 Bring-your-own ingress contract (`ingress.controller: none`)

The chart's default is `ingress.controller: traefik`, which renders the Traefik `IngressRoute` + `Middleware` CRDs you saw above. **Skip this section** if you run Traefik.

If you run **nginx-ingress, Istio Gateway API, an external ALB/NLB, or any non-Traefik ingress**, set `ingress.controller: none` in `values-customer.yaml`. The chart then renders **no ingress resources**, and your platform team authors them.

The chart still emits the right NetworkPolicies for your controller's namespace — make sure `networkPolicy.ingressControllerNamespace` matches where your ingress runs (defaults to `kube-system`).

### What your ingress must route

All paths are matched on the **tenant host** (`tls.dnsName` in values) unless noted as **admin host** (`tls.adminDnsName`).

| Path / pattern | Backend Service | Service port | Notes |
|---|---|---|---|
| `/` (tenant host) | `web-ui` | 80 | Catch-all for tenant UI |
| `/` (admin host) | `admin-ui` | 80 | Only if `tls.adminDnsName` is set |
| `/api/v1/<service>/health` | `<service>` | 8080 | **Rewrite to `/health`** before forwarding (backends only expose `/health` at root) |
| `/api/v1/<service>/*` | `<service>` | 8080 | Per-service path prefix — see route table below |
| `/api/v2/<service>/*` | `<service>` | 8080 | Same as v1 for `inventory-service` (native v2). For every other service, **rewrite `/api/v2/<svc>/*` → `/api/v1/<svc>/*`** (services don't have native v2 handlers yet). |
| `/ws/*` | `inventory-service` | 8080 | WebSocket upgrade — your ingress must allow `Upgrade: websocket` |
| `/uploads/platform-branding/*` | `admin-service` | 8080 | Platform-admin asset uploads |
| `/uploads/branding/*` | `auth-service` | 8080 | Tenant branding |
| `/uploads/avatars/*` | `auth-service` | 8080 | User avatars |

#### Service prefix → Service name mapping

| Path prefix | Service name | Purpose |
|---|---|---|
| `/api/v1/auth-service/` | `auth-service` | Login, JWT issuance, SSO |
| `/api/v1/inventory-service/` | `inventory-service` | Asset / CMDB CRUD |
| `/api/v1/compliance-engine/` | `compliance-engine` | Framework evaluation |
| `/api/v1/cbom-service/` | `cbom-service` | Reports, CBOM artifacts, attestations |
| `/api/v1/report-generator/*` | `cbom-service` | **Legacy alias.** Renamed in v2.4; the chart installs an IngressRoute redirect so existing callers and bookmarks keep working. New integrations should use `/api/v1/cbom-service/`. |
| `/api/v1/sensor-manager/` | `sensor-manager` | Sensor deployment + jobs |
| `/api/v1/cluster-sensor-service/` | `cluster-sensor-service` | Discovery job processing |
| `/api/v1/admin-service/` | `admin-service` | Platform admin |
| `/api/v1/monitoring-service/` | `monitoring-service` | System health |
| `/api/v1/resource-tracker-service/` | `resource-tracker-service` | Resource usage |
| `/api/v1/tenant-health-service/` | `tenant-health-service` | Tenant health scoring |
| `/api/v1/device-interrogation-service/` | `device-interrogation-service` | Network/cloud device interrogation |
| `/api/v1/audit-service/` | `audit-service` | Audit log |
| `/api/v1/notification-service/` | `notification-service` | Notifications |
| `/api/v1/pcap-processor/` | `pcap-processor` | PCAP file processing |
| `/api/v1/discovery/jobs/<id>/import` | `inventory-service` | **Higher priority than `/api/v1/discovery/`** — see special routes |

#### Special routes (priority overrides)

These rules apply per-path, not per-service prefix. Match them with higher priority than the catch-all `/api/v1/<svc>/*` routes above:

| Path / pattern | Backend Service | Why |
|---|---|---|
| `/api/v1/auth-service/auth/sso/providers` (exact) | `auth-service` | Login screen polls this before authenticating — **must bypass auth rate limit** (see "Rate limiting" below) |
| `/api/v2/auth-service/auth/sso/providers` (exact) | `auth-service` | Same; for v2 callers |
| `/api/v1/discovery/jobs/<id>/import` (regex: `^/api/v1/discovery/jobs/[^/]+/import$`) | `inventory-service` | Cluster sensor uploads land here; everything else under `/api/v1/discovery/` goes to `cluster-sensor-service` |
| `/api/v1/discovery/*` (after the import exception above) | `cluster-sensor-service` | |
| `/api/v1/admin-service/status/*` | `monitoring-service` | Status endpoints live in monitoring-service, but historically appear under the admin-service prefix |
| `/api/v2/admin-service/status/*` | `monitoring-service` | Same; rewrite `/api/v2/admin-service/status/*` → `/api/v1/admin-service/status/*` |

### Required edge behaviors

| Behavior | Recommended value | Why |
|---|---|---|
| **TLS termination** | Cert from `tls.existingSecretName` or your ACME issuer | Backends do not speak TLS themselves; `tls.adminDnsName` must be a SAN on the same cert if set |
| **HSTS** | `max-age=31536000; includeSubDomains; preload` when TLS is on; omit entirely when off | Don't poison HSTS caches for dev/eval clusters |
| **HTTP→HTTPS redirect** | 301 to `https://` on both hosts | Anything else lets a logged-in cookie leak over plaintext if a user types `http://` |
| **CORS — Allow-Origin** | `https://<tls.dnsName>` plus `https://<tls.adminDnsName>` if set, plus any `gateway.extraCorsOrigins` | Single source of truth for CORS — backends emit CORS headers in dev but the ingress should overwrite them in prod |
| **CORS — Allow-Methods** | `GET, POST, PUT, PATCH, DELETE, OPTIONS` | |
| **CORS — Allow-Headers** | `Authorization, Content-Type, X-Requested-With, X-Impersonate-Tenant, X-Tenant-ID, X-User-ID, X-CSRF-Token` | |
| **CORS — Allow-Credentials** | `true` | The app uses cookie-based auth |
| **Security headers** | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, CSP per below | Standard hardening; match Traefik mode for parity |
| **Content-Security-Policy** | `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'none';` | The UI loads Poppins + Inconsolata from Google Fonts at HTML-render time |
| **Body size limit** | 100 MiB | Bulk asset import (sensor manager); larger bodies should go via signed upload URLs |
| **Compression** | gzip on responses ≥ 1 KiB | |
| **Retry** | 3 attempts on 502 / 503 / 504 with 100 ms backoff | Backends roll on `helm upgrade`; without retry, in-flight requests will 502 |
| **Rate limit — `/api/v1/auth-service/*`** | 200 RPS average, 400 RPS burst, **per source IP** | Brute-force resistance on login + token endpoints |
| **Rate limit — `/api/v1/auth-service/auth/sso/providers`** | **None** | Login UI polls this from logged-out state — counting against the auth bucket would lock users out before they could sign in |
| **Rate limit — all other `/api/*`** | 1000 RPS average, 2000 RPS burst, **per source IP** | |
| **Circuit breaker (recommended)** | Per backend Service: open at >30% 5xx over a 10 s window; half-open after 60 s | nginx-ingress has no native equivalent — implement via service mesh (Istio `DestinationRule`) if your platform requires it, or skip (the app survives without it) |

If you need the exact values, the Traefik-mode renderings live at `charts/vistaplatform/templates/ingress/middlewares.yaml` and `charts/vistaplatform/templates/ingress/ingressroutes.yaml` after running `make generate-k8s-ingress`. They're the canonical reference — your ingress objects just need to express equivalent behavior in your controller's syntax.

### NetworkPolicies still apply

With `ingress.controller: none`, the chart still emits:

- `allow-ingress-to-backends` — your ingress namespace → backend Services on 8080
- `allow-ingress-to-frontends` — your ingress namespace → web-ui/admin-ui on 80
- `default-deny-ingress` — everything else is denied by default

Make sure `networkPolicy.ingressControllerNamespace` (default `kube-system`) matches the namespace your ingress controller actually runs in, or these allow rules won't match its pods and your ingress will get 0 traffic.

---

## 4. Load balancer setup

RKE2's built-in Traefik ingress controller needs an external IP before DNS can point at it. How you provide that IP depends on your environment:

- **§4A — External load balancer** — you already have a hardware LB, cloud NLB, or proxy (HAProxy, pfSense, etc.) in front of the cluster. Skip MetalLB entirely.
- **§4B — Bare metal / no external LB** — install MetalLB to give Traefik a stable virtual IP from your local network. Recommended for on-premises and home-lab deployments.

---

### §4A — External load balancer

```
  Internet / LAN
       │
  ┌────▼─────────────┐
  │  External LB     │  (hardware LB, cloud NLB, HAProxy, etc.)
  │  VIP: <lb-ip>    │  forwards :80 and :443
  └────┬─────────────┘
       │            │
  ┌────▼────┐  ┌────▼────┐
  │worker-1 │  │worker-2 │  worker nodes — Traefik DaemonSet
  └─────────┘  └─────────┘
```

1. Configure your load balancer to forward TCP ports 80 and 443 to **all worker node IPs**.
2. Create your DNS A record pointing your chosen hostname at the LB's VIP.
3. No changes needed to RKE2 or the Vista Helm values — Traefik is already listening on every worker node. Skip to §5.

---

### §4B — MetalLB (bare-metal virtual IP)

MetalLB runs inside the cluster and responds to ARP requests for a reserved IP range on your local network, giving Traefik a stable VIP that floats between worker nodes.

```
  LAN
   │
   │  ARP: who has 192.168.1.230?  →  MetalLB answers
   │
  ┌▼──────────────────────────────┐
  │  VIP: 192.168.1.230           │  MetalLB L2 advertisement
  │  (floats between worker nodes)│
  └───────┬───────────────────────┘
          │            │
     ┌────▼────┐  ┌────▼────┐
     │worker-1 │  │worker-2 │  worker nodes — Traefik DaemonSet
     └─────────┘  └─────────┘
```

#### 4B.1 Reserve the IP pool in your network

Reserve a contiguous address range in your DHCP server so those addresses are never handed out dynamically. Example range used in this guide: `192.168.1.230–192.168.1.240` (11 addresses — Traefik uses the first available one, the rest are available for future services).

#### 4B.2 Install MetalLB

MetalLB's speaker pods require host network access and elevated Linux capabilities (`NET_ADMIN`, `NET_RAW`) to send ARP announcements. The CIS `restricted` pod security policy blocks these by default. You must create the namespace and label it `privileged` **before** installing MetalLB, otherwise the speaker DaemonSet will fail to schedule.

```bash
helm repo add metallb https://metallb.github.io/metallb
helm repo update

# Create namespace and exempt it from the restricted pod security policy.
# MetalLB's speaker is a legitimate system-level workload that requires
# host network access — this exemption is expected and safe.
kubectl create namespace metallb-system
kubectl label namespace metallb-system \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/audit=privileged \
  pod-security.kubernetes.io/warn=privileged

helm install metallb metallb/metallb \
  --namespace metallb-system \
  --wait --timeout 5m
```

#### 4B.3 Configure the address pool

Replace the address range below with the range you reserved:

```yaml
# metallb-config.yaml
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: vistaplatform-pool
  namespace: metallb-system
spec:
  addresses:
    - 192.168.1.230-192.168.1.240   # replace with your reserved range
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: vistaplatform-l2
  namespace: metallb-system
spec:
  ipAddressPools:
    - vistaplatform-pool
```

```bash
kubectl apply -f metallb-config.yaml
```

#### 4B.4 Verify Traefik gets an IP

```bash
kubectl -n kube-system get svc traefik
```

Check the `TYPE` column. RKE2's bundled Traefik may be installed as `NodePort` rather than `LoadBalancer` depending on how the cluster was provisioned. MetalLB only assigns IPs to `LoadBalancer` services — if you see `NodePort` and `<none>` for EXTERNAL-IP, patch it:

```bash
kubectl -n kube-system patch svc traefik \
  -p '{"spec": {"type": "LoadBalancer"}}'
```

Re-run the get command — within a few seconds MetalLB will assign the first address from your pool:

```bash
kubectl -n kube-system get svc traefik
# TYPE should be LoadBalancer
# EXTERNAL-IP should show an address from your reserved range (e.g. 192.168.1.230)
```

Note the `EXTERNAL-IP` — this is the IP your DNS A record should point to.

---

## 5. TLS certificate setup

> **Two independent TLS layers — don't conflate them.** Vista has two
> separate certificate concerns, with separate trust requirements:
>
> | Layer | What it secures | Who must trust it | Configured by |
> |---|---|---|---|
> | **Edge / UI cert** | The browser-facing HTTPS endpoint (`dnsName` / `adminDnsName`) and the REST API | **Your users' browsers** — so it must be issued by a CA they already trust (a public CA, or your corporate root that's on managed endpoints) | The `tls.*` block — **this section (§5)** |
> | **Service-mesh mTLS** *(on by default)* | In-cluster service-to-service traffic, plus Postgres and NATS | **Only Vista's own pods** — nobody's browser ever sees it | The `serviceMtls.*` block — **§5E**, **ON by default** (requires cert-manager + Reloader) |
> | **Agent / sensor mTLS** *(optional)* | The agent↔platform control channel (job-poll, result submission, heartbeat), terminated at the backend via edge **passthrough** | **Each tenant's agents/sensors and the backend** — per-tenant client certs verified against the tenant CA | The `agentMtls.*` block — **§5F**, off by default, requires §5E |
>
> The mesh layer uses a **self-signed Platform CA** the chart generates
> internally. That is intentional and correct: a private, fully-controlled CA
> is the right trust anchor for a service mesh, and burdening a public or
> corporate CA with dozens of short-lived internal certs is unnecessary. A
> self-signed *mesh* CA does **not** mean your *UI* cert is self-signed — the
> two are chosen independently. This section (§5) is only about the
> browser-facing cert; for the mesh see §5E.

Choose the option that matches your environment:

| Option | When to use | cert-manager required? |
|---|---|---|
| **§5A — Self-signed cert** | Lab, evaluation, private network, no public DNS | No — skip cert-manager entirely |
| **§5B — cert-manager + Let's Encrypt** | Production with a public domain | Yes |
| **§5C — cert-manager + internal CA** | Production with a corporate CA | Yes |
| **§5D — Existing TLS secret** | You already have a cert (e.g. from your PKI team) | No |
| **§5E — Service-mesh mTLS** *(on by default)* | Encrypt + authenticate all in-cluster traffic — the shipped posture; opt out only if the cluster can't provide the prereqs | **Yes — required** (+ Reloader) |
| **§5F — Agent / sensor mTLS** *(optional)* | Fail-closed mutual auth on the agent↔platform control channel | Requires §5E (so yes, + Reloader) |

---

### §5A — Self-signed certificate (lab / evaluation)

Use this when your hostname is not publicly resolvable or you just want to get Vista running quickly. You will see a browser security warning the first time you visit — click through it. Everything works correctly over HTTPS.

```bash
# Generate a single self-signed cert covering BOTH hostnames (tenant + admin):
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout tls.key -out tls.crt \
  -subj "/CN=<tenant-hostname>" \
  -addext "subjectAltName=DNS:<tenant-hostname>,DNS:<admin-hostname>"

# Load it into the cluster (create + label the namespace if it doesn't exist):
kubectl create namespace vistaplatform --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace vistaplatform \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted \
  --overwrite
kubectl create secret tls vistaplatform-tls \
  -n vistaplatform --cert=tls.crt --key=tls.key
```

In your `values-customer.yaml`:
```yaml
tls:
  mode: existingSecret
  dnsName: <tenant-hostname>          # e.g. vistaplatform.example.com
  adminDnsName: <admin-hostname>      # e.g. admin.vistaplatform.example.com
  existingSecretName: vistaplatform-tls
```

Skip to §6 — cert-manager is not needed.

---

### §5B — cert-manager + Let's Encrypt (production, public domain)

Requires your hostname to be publicly resolvable and port 80 reachable from the internet for the HTTP-01 ACME challenge.

```bash
helm repo add jetstack https://charts.jetstack.io
helm repo update
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace \
  --version v1.16.1 \
  --set crds.enabled=true
```

```yaml
# letsencrypt-issuer.yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: ops@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
      - http01:
          ingress:
            class: traefik
```

```bash
kubectl apply -f letsencrypt-issuer.yaml
kubectl get clusterissuer letsencrypt-prod
```

In your `values-customer.yaml`:
```yaml
tls:
  mode: certManager
  dnsName: <tenant-hostname>          # e.g. vistaplatform.example.com
  adminDnsName: <admin-hostname>      # e.g. admin.vistaplatform.example.com
  issuerRef:
    group: cert-manager.io
    kind: ClusterIssuer
    name: letsencrypt-prod
```

When `adminDnsName` is set, the chart's `Certificate` resource lists both names under `dnsNames` so cert-manager issues one cert covering both SANs.

---

### §5C — cert-manager + internal CA (production, corporate PKI)

Install cert-manager as in §5B, then create a CA-backed issuer instead of an ACME issuer. See the [cert-manager CA issuer docs](https://cert-manager.io/docs/configuration/ca/) — you reference an existing Secret holding your CA cert and key. Set both `dnsName` and `adminDnsName` in your values; the chart-managed `Certificate` covers both SANs automatically.

---

### §5D — Existing TLS secret (cert provided by PKI team)

If your organization's PKI team has provided a certificate and key file:

> **The certificate must cover BOTH hostnames as SANs** (tenant + admin). When you request the cert from your PKI team, tell them both DNS names. A single-SAN cert will leave admin-UI unreachable.

```bash
# Sanity check before loading — both names must appear in the SAN list:
openssl x509 -in <path-to-cert.crt> -noout -ext subjectAltName

kubectl create namespace vistaplatform --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace vistaplatform \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted \
  --overwrite
kubectl create secret tls vistaplatform-tls \
  -n vistaplatform --cert=<path-to-cert.crt> --key=<path-to-key.key>
```

In your `values-customer.yaml`:
```yaml
tls:
  mode: existingSecret
  dnsName: <tenant-hostname>          # e.g. vistaplatform.example.com
  adminDnsName: <admin-hostname>      # e.g. admin.vistaplatform.example.com
  existingSecretName: vistaplatform-tls
```

Skip to §6 — cert-manager is not needed.

---

### §5E — Service-mesh mTLS (ON by default)

This is **separate from and independent of** your edge/UI cert above (§5A–§5D).
It encrypts and mutually authenticates traffic *inside* the cluster — every
service-to-service call, plus the connections to Postgres and NATS — so that a
compromised pod or a network tap inside the cluster cannot read or impersonate
Vista's internal traffic.

**This is ON by default (#965)** — a stock `helm install` ships encrypted
internal transport. That means the two prerequisites below are **required**,
not optional. The chart validates cert-manager's presence and **fails the
install fast** with a clear message if its CRDs are absent, rather than failing
mysteriously mid-apply.

> **Opting out** (only for a cluster that genuinely cannot provide the
> prerequisites): set **all three** toggles to `false` —
> `serviceMtls.enabled`, `datastores.postgres.tls.enabled`, and
> `datastores.nats.tls.enabled`. The two datastore toggles **require**
> `serviceMtls.enabled`, so a partial opt-out (e.g. serviceMtls off but a
> datastore toggle left on) is rejected at render time. With all three off,
> the chart needs neither cert-manager nor Reloader for the mesh.

**Prerequisites (cluster infrastructure — the chart does not install these):**

1. **cert-manager** (same install as §5B) — issues the per-service certs.
2. **Stakater Reloader** — restarts pods when their auto-rotated cert Secret
   changes, so a renewal doesn't require a manual rollout:
   ```bash
   helm repo add stakater https://stakater.github.io/stakater-charts
   helm install reloader stakater/reloader \
     --namespace reloader --create-namespace
   ```
   > **If your cluster enforces the `restricted` Pod Security Standard**, the
   > Reloader chart's default container securityContext is rejected and its pod
   > never starts (`FailedCreate` / 0 replicas). Add the two required fields:
   > ```bash
   > helm install reloader stakater/reloader \
   >   --namespace reloader --create-namespace \
   >   --set reloader.deployment.containerSecurityContext.allowPrivilegeEscalation=false \
   >   --set "reloader.deployment.containerSecurityContext.capabilities.drop={ALL}"
   > ```
   > Verify Reloader is actually `1/1 Running` before enabling mTLS — if it
   > isn't, certs rotate but pods never restart and mTLS breaks at the ~60-day
   > renewal boundary.

**How the trust works.** By default the chart provisions a self-signed
**Platform CA** (a cert-manager `Issuer` + a 10-year CA cert) and issues every
service a 90-day cert from it (`rotationPolicy: Always`, renewed 30 days out).
This CA is private to the mesh — see the trust-domains note at the top of §5.
The three data-plane toggles are decoupled so you can roll them out in stages:

```yaml
serviceMtls:
  enabled: true            # HTTP service-to-service mTLS (gateway → backends, and S2S)

datastores:
  postgres:
    tls:
      enabled: true        # Postgres requires TLS; backends connect sslmode=verify-full
  nats:
    tls:
      enabled: true        # NATS requires a client cert (the shared token is retired)
```

> **Order of rollout — a fresh install gets all three at once.** A brand-new
> `helm install` with the defaults brings up serviceMtls + Postgres TLS + NATS
> TLS together cleanly (there's no running datastore to migrate). The staging
> rule below matters for **existing releases**, not fresh installs.
>
> **Upgrading an existing release that ran with all three OFF (staged, not
> all-at-once).** Do **not** flip all three in a single `helm upgrade`. Enable
> `serviceMtls.enabled` first (one upgrade — it provisions the Platform CA and
> the per-service certs the Postgres and NATS layers reuse), let the HTTP layer
> go healthy, then enable `datastores.postgres.tls.enabled` and
> `datastores.nats.tls.enabled` in a **later** upgrade. Each datastore toggle
> **requires** `serviceMtls.enabled` — they draw their certs and the in-pod
> `ca.crt` from it.
>
> Toggling `postgres.tls` on a live release changes the `schema-migration` Job
> pod template. Historically that hit `Job spec.template is immutable` (#421)
> and required manually deleting the Job before the upgrade. That is **fixed by
> #983**, which hashes the Job name on its pod template so a template change
> creates a fresh Job instead of colliding with the immutable existing one — no
> manual delete needed on chart versions that include #983.

**Advanced: chain the mesh off your own root.** If your security policy forbids
*any* self-signed CA, even an internal one, point the Platform CA at an
intermediate issued from your corporate root instead of the chart's self-signed
bootstrap. Provide a Secret containing `tls.crt` + `tls.key` + `ca.crt`:

```yaml
serviceMtls:
  enabled: true
  platformCa:
    externalCaSecretName: vistaplatform-platform-ca   # your intermediate CA
```

The entire mesh then chains to your root. This is a power-user option; the
default self-signed Platform CA is appropriate for the large majority of
deployments.

> **Bring-your-own Postgres/NATS (managed services).** When
> `datastores.postgres.enabled: false` (e.g. RDS) the chart can't mint the
> Postgres server cert. Point `serviceMtls.postgres.caSecretName` /
> `clientCertSecretName` at your provider's CA and your client cert, and set
> `serviceMtls.postgres.mode` to match what the managed service enforces
> (`require` / `verify-ca` / `verify-full`).

> **Single-node clusters: avoid the rolling-upgrade CPU deadlock.** On a
> one-node cluster, a `helm upgrade` that rolls every service at once briefly
> runs old + new pods together, doubling CPU *requests* (the scheduler packs by
> requests, not usage). If that exceeds the node's allocatable CPU, the
> recreated `postgres-0` can't schedule, the schema migration can't connect, and
> the upgrade hangs until it times out. Either size the node for ~2× steady-state
> CPU requests before upgrading, or set `strategy: Recreate` on the backends so
> pods replace in place without surging (brief per-service downtime). If an
> upgrade does wedge, `helm rollback` restores the previous release.
>
> This applies to **config-only upgrades too**, not just version bumps: the pod
> templates carry a `checksum/config` hash of the app ConfigMap, so changing any
> value that lands there (`tls.dnsName`, `appConfig.*`, …) deliberately rolls
> every backend — env vars are injected at pod start only, and without the roll
> the running pods would silently keep the old config.

---

### §5F — Agent / sensor mTLS (edge passthrough, optional)

This secures the **agent↔platform control channel** — the job-poll, result-submission,
and heartbeat calls that discovery agents make to **device-interrogation-service** and
that sensors make to **sensor-manager**. It is **off by default** and is an **add-on to
§5E**: `agentMtls.enabled` **requires `serviceMtls.enabled`** (the agent-mTLS listener
reuses the per-service mesh cert), and `helm` refuses to render the chart otherwise.

Unlike the edge/UI cert (§5A–§5D), this traffic is **not** terminated at the edge. The
agent/sensor presents a **per-tenant client certificate**, and that cert must reach the
backend intact so the backend can **fail closed** — verify the cert against the tenant's
CA, bind identity to the cert CN, and derive the tenant from it. So the cluster ingress is
configured to **pass the TLS connection through** to the backend rather than terminate it.

> **Three trust domains, not two.** The edge cert (§5), the mesh Platform CA (§5E), and
> this agent layer are independent. The edge cert is for browsers; the mesh CA is for
> in-cluster pod-to-pod; the agent layer uses **per-tenant** client certs verified at the
> backend. Don't reuse one host or one CA across them.

**What the chart renders when `agentMtls.enabled: true`:**

- On **device-interrogation-service** and **sensor-manager** only: a dedicated mTLS
  listener on container + Service **port 8444**, and the env var
  **`AGENT_MTLS_REQUIRED=true`** so the auth middleware fails closed — a verified client
  cert is mandatory, and a call without one gets `401` before any database lookup. No
  other backend is touched.
- One **`IngressRouteTCP` per backend** with **`tls.passthrough: true`**, matching
  `HostSNI(<dnsName>)` and routing to that backend's port 8444 on the agent-mTLS
  entrypoint. A single entrypoint fans out to both backends — HostSNI disambiguates them.

Enable it in `values-customer.yaml`:

```yaml
serviceMtls:
  enabled: true                 # REQUIRED — agentMtls reuses the per-service mesh cert

agentMtls:
  enabled: true
  port: 8444                    # container + Service port, and the passthrough entrypoint port
  entryPoint: agent-mtls        # name of the cluster-Traefik entrypoint (see prerequisites)
  backends:
    device-interrogation-service:
      dnsName: agents.example.com     # HostSNI the discovery agents connect to
    sensor-manager:
      dnsName: sensors.example.com    # HostSNI the sensors connect to
```

**Prerequisites (cluster infrastructure — the chart does NOT install these):**

1. **A TLS-passthrough entrypoint on the cluster ingress.** The chart's `IngressRouteTCP`
   references an entrypoint by the name in `agentMtls.entryPoint` (default `agent-mtls`)
   but cannot create one — entrypoints are cluster-Traefik static configuration. Add a
   plain TCP entrypoint on `agentMtls.port` and publish it on the Traefik LoadBalancer.
   TLS passthrough is set **per-route by the chart**, so the entrypoint itself stays plain
   TCP. With the upstream `traefik/traefik` chart:
   ```yaml
   # Cluster Traefik values — NOT the Vista chart.
   ports:
     agent-mtls:
       port: 8444
       exposedPort: 8444
       protocol: TCP
       expose:
         default: true     # publish on the Traefik LoadBalancer so agents can reach it
   ```
   Confirm your LoadBalancer and any firewall / security-group rules allow inbound `8444`
   from wherever your agents and sensors run.

2. **New DNS names — one per backend — distinct from `tls.dnsName`.** Each
   `agentMtls.backends.<svc>.dnsName` is the SNI host the agent/sensor dials and the
   `HostSNI` the route matches. Create a DNS record for each (for example
   `agents.<domain>` and `sensors.<domain>`) resolving to the **cluster Traefik
   LoadBalancer** address. This is the same LB as the edge host, but these names are
   **passed through** to the backend, whereas `tls.dnsName` / `adminDnsName` are
   **edge-terminated** — so they must be **separate hostnames**. You cannot reuse the edge
   host, because that host's TLS is terminated at the edge and the client cert would be
   lost.

**How end-to-end enablement works.** Agents and sensors **register on the
edge-terminated public host** (`tls.dnsName`) using a registration key — at that
point they hold no client certificate, and the passthrough listener requires one
at the TLS handshake. The registration response hands them a client certificate,
the platform CA as server trust anchor, and the **advertised passthrough URL**
(derived from `agentMtls.backends.<svc>.dnsName` + `agentMtls.port`); they switch
to it, persist it, and use it for all subsequent traffic. No agent-side
configuration is needed beyond the normal install command.

> ⚠️ **Enabling `agentMtls` on an environment with already-enrolled agents.**
> Agents and sensors enrolled *before* the flip keep calling the edge host, where
> the proxy terminates TLS and strips their client certificate — fail-closed
> enforcement will reject them with 401. After enabling, **re-register fielded
> agents** (fresh registration key) or update each agent's configured platform
> URL to the passthrough hostname and restart it. Plan this as part of the
> enablement change window.

---

### §5H — JWT signing keys and closing the migration window

Session tokens used to be signed **and** verified with one shared HS256 secret
(`platform.jwtSecret`) held by every service. That is a symmetric key in ~17
pods: any one of them — or any log line, env dump or core file that touched it —
could mint a token for any user, any tenant, any role. There was no key id, so
rotation was all-or-nothing.

`jwtSigning.enabled` (**on by default**) generates one ECDSA P-256 key into a
Secret and mounts it **only** into the two services that issue tokens:
`auth-service` (tenant sessions) and `admin-service` (platform sessions). Every
other service verifies with the public half, polled from
`http://auth-service:8080/.well-known/jwks.json`. A leak from a verifier grants
nothing.

> The JWKS endpoint sits on the **plaintext** listener beside `/health`, even
> with `serviceMtls` on. That is deliberate: the mTLS listener would demand a
> client certificate, and requiring a client cert to fetch the keys you need in
> order to authenticate is a circularity with no security value. The document is
> public key material. It is also published at the edge
> (`https://<tls.dnsName>/.well-known/jwks.json`) so an external verifier can
> validate our tokens without being handed a secret.

**Enabling is not the finish line.** Until you complete step 3 the shared secret
is *still* a forgery key — you have only reduced the number of pods holding it
from ~17 to 2.

**1. Upgrade.** Nothing else to do; `jwtSigning.enabled` defaults to true. New
sessions are ES256 with a `kid`; sessions minted before the upgrade stay valid
for their full lifetime because verifiers accept both. Nobody is logged out.

Confirm the issuer is actually signing asymmetrically:

```bash
kubectl -n vistaplatform logs deploy/auth-service | grep "signing JWTs"
```

`signing JWTs with ES256, kid=…` is what you want. `signing JWTs with the legacy
shared HS256 secret` means no key was mounted — check the Secret exists.

And that the keys are being served:

```bash
kubectl -n vistaplatform exec deploy/inventory-service -- \
  wget -qO- http://auth-service:8080/.well-known/jwks.json
```

**2. Wait one refresh-token lifetime** — 7 days by default. That is how long the
oldest still-valid HS256 session can live. Closing the window early logs those
users out; it does not break anything else.

**3. Close the window.** This is the step that actually retires the shared
secret:

```yaml
jwtSigning:
  acceptLegacyHmac: false
```

After this upgrade `JWT_SECRET` is no longer injected into any pod except the
two issuers, and an HS256 token is rejected outright. Verify:

```bash
kubectl -n vistaplatform get deploy inventory-service \
  -o jsonpath='{.spec.template.spec.containers[0].env[*].name}' | tr ' ' '\n' | grep JWT_SECRET
```

No output is success. If `JWT_SECRET` is still there, the upgrade did not take —
remember that `envFrom`/`env` values are injected at **pod start**, so confirm
the pods actually restarted rather than trusting a green `helm upgrade`.

#### Rotating the signing key

Keys are ordered in one PEM file: the **first** block signs, later blocks stay
published so sessions minted before the rotation keep working.

1. Generate a new key and **prepend** it:
   ```bash
   openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out new.pem
   kubectl -n vistaplatform get secret vista-jwt-signing \
     -o jsonpath='{.data.signing-key\.pem}' | base64 -d > old.pem
   cat new.pem old.pem | kubectl -n vistaplatform create secret generic vista-jwt-signing \
     --from-file=signing-key.pem=/dev/stdin --dry-run=client -o yaml | kubectl apply -f -
   ```
2. Restart `auth-service` and `admin-service`. They now publish **both** public
   keys and sign with the new one.
3. **Wait one `jwksRefreshSeconds` interval (5 min default) before trusting the
   new tokens platform-wide.** A verifier that has not refreshed yet sees an
   unknown `kid` and correctly rejects the token. Rotating faster than the
   refresh interval produces exactly that failure.
4. After one max-token-TTL, drop the old block from the PEM and restart again.
   The old key stops verifying — which is also how you **revoke** a key you
   believe is compromised, except that then you do it immediately and accept
   that sessions signed with it are terminated.

Delete `new.pem` and `old.pem` afterwards; they are private key material.

---

### §5G — Admin-plane isolation (do this before you go live)

The admin console at `tls.adminDnsName` is not just a different UI — it is the
front door to the **cross-tenant** platform-admin API. A caller who reaches those
endpoints with a valid platform-admin session can read and change data belonging
to **every tenant** in the deployment. Their role check is the only thing in the
way, so *where they can be reached from* is part of the control, not a detail.

Two independent settings, and you want both.

**1. Keep the platform-admin API off the public host** — `adminPlane.restrictToAdminHost`,
**on by default**, active as soon as `tls.adminDnsName` is set.

With it on, Traefik serves the platform-admin API on the admin host only and
returns `404` for it on the tenant host. The route set is generated from
`admin_plane:` in `standards/service-registry.yaml` — read that block if you need
the authoritative list of what moves.

One documented hole stays open on the tenant host: the inbound **billing-provider
webhook** (`/api/v1/admin-service/admin/billing/webhook/*`). The provider posts
from its own infrastructure and can never come from your admin network; the
payload is authenticated by the provider's signature, not by network position.

Nothing changes if `tls.adminDnsName` is unset — with a single host there is
nowhere else to serve the console from, so the split is skipped and `helm install`
tells you the plane is unisolated.

**2. Restrict the admin host to your operator networks** — `adminPlane.ipAllowList`,
**off by default**, because the chart cannot guess your CIDRs and a wrong guess
locks you out of your own platform.

```yaml
adminPlane:
  ipAllowList:
    enabled: true
    sourceRange:
      - 203.0.113.0/24      # office egress
      - 10.20.0.0/16        # operator VPN
    ipStrategy:
      depth: 0
```

> **`ipStrategy.depth` decides whether this works at all.** Traefik allow-lists the
> address it sees *on the connection*. Behind a load balancer that is the **load
> balancer**, not your operator. Set `depth` to the number of trusted proxies in
> front of Traefik so the client IP is read from `X-Forwarded-For` instead:
>
> | Topology | `depth` |
> |---|---|
> | MetalLB with `externalTrafficPolicy: Local` (real client IP preserved) | `0` |
> | AWS ALB in front of Traefik (`ingress.alb.enabled`) | `1` |
> | ALB behind CloudFront or another proxy | `2` |
>
> Get it wrong one way and every operator is locked out — obvious, quickly fixed.
> Get it wrong the other way and the allow-list matches the **balancer's own
> address**, which admits everyone while looking exactly like a working control.

**Verify from outside the range.** An allow-list you have only tested from inside
it has not been tested:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  https://admin.vistaplatform.example.com/api/v1/admin-service/admin/auth/me
```

- from **outside** `sourceRange` → `403`
- from **inside** `sourceRange` → `401` (reached the service, no session)

And confirm the split, from anywhere:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  https://vistaplatform.example.com/api/v1/admin-service/admin/auth/me   # expect 404
```

A `401` there means the split is not in effect — check that `tls.adminDnsName` is
set and `adminPlane.restrictToAdminHost` is `true`.

**Stronger options, if your environment supports them.** An IP allow-list at
Traefik is the portable control this chart can ship. If you can put the admin host
on an internal-only load balancer, a separate ingress entrypoint bound to a
management VLAN, or behind your own SSO proxy, do that as well — the two compose.

---

## 6. Configure registry access

Create an `imagePullSecret` in the `vistaplatform` namespace so the chart can pull images from Docker Hub during `helm install`. Your license package includes a Docker Hub access token scoped to the `vistaplatform` organization.

> **ECR customers:** skip to the "Alternative: AWS ECR" subsection at the end of §6. Otherwise, follow the Docker Hub instructions below — they are the standard path.

### Docker Hub imagePullSecret

Your license package includes a Docker Hub access token scoped to the `vistaplatform` organization. Create an imagePullSecret from it:

```bash
kubectl create secret docker-registry vistaplatform-registry \
  -n vistaplatform \
  --docker-server=docker.io \
  --docker-username=<docker-hub-username> \
  --docker-password=<docker-hub-access-token>
```

Docker Hub access tokens do not expire automatically, but you should rotate them periodically. If you ever need to rotate: delete and recreate the secret, then do a rolling restart of the deployments — no `helm upgrade` required.

Note the secret name (`vistaplatform-registry`) — you will reference it in your `values-customer.yaml` when you assemble it in §9.

### Verify Docker Hub pull works

This step confirms two things independently:
1. The image exists at the expected path and tag on Docker Hub
2. Your worker nodes have outbound internet access to Docker Hub

> **Important:** `crictl pull` tests anonymous or containerd-level access — it does **not** use the Kubernetes `vistaplatform-registry` secret you just created. That secret is used by the Kubernetes scheduler when it pulls images for pods. The two are separate. A successful `crictl pull` confirms the image exists and is reachable; the Kubernetes secret is what authorizes pods to pull it during `helm install`.

RKE2 uses containerd at a non-standard socket path. SSH to any worker node and run:

```bash
# Substitute your org name and tag from your license package:
sudo /var/lib/rancher/rke2/bin/crictl \
  --runtime-endpoint unix:///run/k3s/containerd/containerd.sock \
  pull docker.io/vistasecurity/auth-service:<image-tag>
```

Expected output: `Image is up to date for sha256:...` or a download progress bar.

If you see `not found` — the org name or tag is wrong. Double-check your license package.
If you see `unauthorized` — the image is private and `crictl` can't pull it anonymously. This is normal for private repos. Proceed to §7 and let the Helm install confirm credentials via the Kubernetes secret.
If you see a network timeout — your worker nodes can't reach Docker Hub. Check outbound internet access.

---

### Alternative: AWS ECR

> **Skip this subsection unless your contract specifically delivers via ECR.** The standard Vista delivery is Docker Hub (above). Replace `<your-ecr-account>` and `<your-region>` everywhere below with the values your VistaSecurity contact provided.

#### Option B1 — Node IAM role (recommended for AWS-hosted clusters)

If your worker nodes run on AWS EC2 with an instance profile, attach an IAM policy granting:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetAuthorizationToken"
    ],
    "Resource": "*"
  }]
}
```

Enable the ECR credential provider on each node by adding to `/etc/rancher/rke2/config.yaml`:

```yaml
kubelet-arg:
  - image-credential-provider-config=/etc/rancher/rke2/credential-providers.yaml
  - image-credential-provider-bin-dir=/var/lib/rancher/rke2/bin
```

See the [Kubernetes credential provider docs](https://kubernetes.io/docs/tasks/administer-cluster/kubelet-credential-provider/). RKE2 ships `ecr-credential-provider` in `/var/lib/rancher/rke2/bin/`. Restart RKE2 after making these changes.

#### Option B2 — imagePullSecret (non-AWS or manual rotation)

**ECR tokens expire every 12 hours.** For short-lived testing this is fine; for production set up a refresh CronJob.

```bash
kubectl create secret docker-registry vistaplatform-registry \
  -n vistaplatform \
  --docker-server=<your-ecr-account>.dkr.ecr.<your-region>.amazonaws.com \
  --docker-username=AWS \
  --docker-password="$(aws ecr get-login-password --region <your-region>)"
```

Note the secret name (`vistaplatform-registry`) — you will reference it in your `values-customer.yaml` when you assemble it in §9.

For long-running deployments, set up a refresh CronJob — see §11 troubleshooting.

### Verify ECR pull works

```bash
sudo /var/lib/rancher/rke2/bin/crictl \
  --runtime-endpoint unix:///run/k3s/containerd/containerd.sock \
  pull <your-ecr-account>.dkr.ecr.<your-region>.amazonaws.com/vistaplatform/auth-service:<image-tag>
```

If this fails, fix registry access before continuing — the chart install will time out with `ImagePullBackOff` otherwise.

---

## 7. Apply the license and platform secrets

The chart never templates secret values. Apply them as standalone Secrets that the chart references by name. This section creates two Secrets: one holding your license token, and one holding the cryptographic keys the platform generates and uses internally.

---

### 7.1 — Create the namespace

Pre-create the namespace with explicit Pod Security Admission labels at `restricted`. The Vista chart's pods all satisfy the `restricted` profile (non-root, no host paths, dropped capabilities, etc.), and labeling explicitly is auditor-defensible — it documents intent rather than relying on whatever the cluster default happens to be.

```bash
kubectl create namespace vistaplatform --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace vistaplatform \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted \
  --overwrite
```

If you already ran the namespace creation in §5A or §5D, this is a no-op — `--overwrite` makes the label command idempotent.

---

### 7.2 — Apply the license token

Your license token (a JWT string) was delivered to you out-of-band by your VistaSecurity contact. Substitute it below exactly as provided — no line breaks, no extra spaces, no surrounding quotes added by your terminal.

```bash
kubectl create secret generic vistaplatform-license \
  -n vistaplatform \
  --from-literal=token='<JWT-FROM-VISTAPLATFORM>'
```

---

### 7.3 — Generate and save the platform secrets

> ⚠️ **Read this entire section before running any commands.**

Vista uses three secret values internally:

| Key | Purpose |
|---|---|
| `jwt-secret` | Signs and verifies all user session tokens. If this changes, every active user session is immediately invalidated. |
| `internal-auth-secret` | Signs HMAC tokens used for service-to-service authentication inside the cluster. If this changes, all inter-service calls will fail until every pod is restarted with the new value. |
| `encryption-master-key` | Encrypts sensitive data stored in the database (API keys, credentials, secrets held on behalf of tenants). **This is the most critical value.** If this key is lost or changed, any data encrypted with the original key becomes permanently unrecoverable — there is no fallback and no recovery path. |

**These values are generated once and must never change for the life of this deployment.** They are not stored anywhere by the platform — once you create the Kubernetes Secret, the only copies of these values are inside that Secret and wherever you save them yourself.

**Before running the commands below:**
- Open your secret manager (your password manager, Vault, AWS Secrets Manager, etc.)
- Have it ready to receive three values
- Do not close your terminal between generating and saving

The commands below generate the values, print them clearly so you can copy them, and then create the Secret. **Do not skip the save step.** If you ever need to recreate this Secret — after a namespace wipe, a cluster rebuild, or a disaster recovery restore — you will need these exact values. Without them, all encrypted data in the database is lost permanently.

```bash
# Step 1 — Generate the values and display them.
# COPY THESE TO YOUR SECRET MANAGER BEFORE PROCEEDING.
QVIEW_JWT_SECRET=$(openssl rand -hex 32)
QVIEW_INTERNAL_AUTH=$(openssl rand -hex 32)
QVIEW_ENC_KEY=$(openssl rand -hex 32)

echo ""
echo "========================================="
echo "  SAVE THESE VALUES TO YOUR SECRET MANAGER NOW"
echo "========================================="
echo "  jwt-secret:            $QVIEW_JWT_SECRET"
echo "  internal-auth-secret:  $QVIEW_INTERNAL_AUTH"
echo "  encryption-master-key: $QVIEW_ENC_KEY"
echo "========================================="
echo ""

# Step 2 — Once saved, create the Kubernetes Secret.
kubectl create secret generic vistaplatform-platform \
  -n vistaplatform \
  --from-literal=jwt-secret="$QVIEW_JWT_SECRET" \
  --from-literal=internal-auth-secret="$QVIEW_INTERNAL_AUTH" \
  --from-literal=encryption-master-key="$QVIEW_ENC_KEY"
```

> ⚠️ **After the Secret is created, clear your terminal history** if you are on a shared or recorded workstation: `history -c`. The values are now safely inside Kubernetes and in your secret manager — they do not need to remain in your shell history.

> ⚠️ **If you lose the `encryption-master-key`**, do not attempt to recreate it with a new random value. Doing so will not restore access to encrypted data — it will make the situation worse. Contact VistaSecurity support immediately.

---

## 8. Verify chart and image signatures

Vista signs every release artifact with cosign keyless OIDC. Always verify before installing.

Substitute `<IMAGE_TAG>` with the tag provided in your license package (e.g. `v1.2.3`).

```bash
# Pull the chart locally. --untar also extracts it into a `vistaplatform/`
# directory next to the .tgz; you'll copy the example values file out of
# that directory in §9.1.
helm pull oci://registry-1.docker.io/vistasecurity/vistaplatform \
  --version <CHART_VERSION> \
  --untar

# Verify the chart artifact (cosign verifies the OCI ref, not the local .tgz;
# it rejects an oci:// scheme on the ref — omit it here even though `helm pull`
# above requires it):
cosign verify registry-1.docker.io/vistasecurity/vistaplatform:<CHART_VERSION> \
  --certificate-identity-regexp '<SIGNING_IDENTITY>' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Verify a representative image:
cosign verify docker.io/vistasecurity/auth-service:<IMAGE_TAG> \
  --certificate-identity-regexp '<SIGNING_IDENTITY>' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Each `cosign verify` must report `Verified OK`. If any verification fails, **stop** — do not install — and contact VistaSecurity support.

> **`<SIGNING_IDENTITY>` and the registry are edition-specific.** Signing is keyless, so the
> signing identity *is* the release workflow that built the artifact — which differs between the
> Core and commercial lines, as does the registry (`ghcr.io` vs `docker.io`). `helm install`
> prints the exact command for the artifact you have; copy the identity from there. For Core it is
> `https://github.com/VistaSecurity/VistaPlatform-Core/.github/workflows/release-core.yml@.*`. The OIDC
> issuer (`token.actions.githubusercontent.com`) is the same either way.

You can also fetch the in-toto attestation listing every artifact digest in the release:

```bash
cosign verify-attestation \
  oci://registry-1.docker.io/vistasecurity/vistaplatform:<CHART_VERSION> \
  --certificate-identity-regexp '<SIGNING_IDENTITY>' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --type slsaprovenance
```

---

## 9. Install Vista

### 9.1 Assemble your values-customer.yaml

> **Where to run these commands:** Everything in §9 runs on your **operator workstation** (the machine where `kubectl` and `helm` are installed and configured). You do not need to copy any files to your cluster nodes — `helm` communicates with the cluster over your kubeconfig the same way `kubectl` does.

The chart you pulled with `--untar` in §8 extracted into a `vistaplatform/` directory alongside the `.tgz`. Three files inside that directory matter for this step:

- `vistaplatform/examples/values-customer.yaml.example` — the configuration template you will fill in
- `vistaplatform/values-minimal.yaml` — resource profile for lab / evaluation installs
- `vistaplatform/values-ha.yaml` — resource profile for production HA installs

Copy the example out of the extracted chart directory to create your working file:

```bash
cp vistaplatform/examples/values-customer.yaml.example values-customer.yaml
```

(`values-minimal.yaml` and `values-ha.yaml` stay where they are — you'll reference them as `vistaplatform/values-{minimal,ha}.yaml` in §9.3.)

Open `values-customer.yaml` and make the following changes. **This file is YAML — use spaces, not tabs, and pay close attention to indentation.** A misaligned key will either cause `helm` to fail with a parse error or, worse, be silently ignored.

**TLS section** — change `mode` to match whichever §5 path you followed, set both hostnames, and uncomment the appropriate line (`existingSecretName` or `issuerRef`):

```yaml
tls:
  mode: existingSecret           # existingSecret | certManager | none
  dnsName: <tenant-hostname>     # web-UI + API; must match the tenant DNS record exactly
  adminDnsName: <admin-hostname> # admin-UI (separate hostname); must be a SAN on the cert
  existingSecretName: vistaplatform-tls   # uncomment this line for §5A or §5D
  # issuerRef:                         # uncomment this block for §5B or §5C
  #   group: cert-manager.io
  #   kind: ClusterIssuer
  #   name: letsencrypt-prod
```

**License and platform sections** — these are already correct in the template if you followed §7. Verify the secret names match what you created:

```yaml
license:
  existingSecretName: vistaplatform-license

platform:
  existingSecretName: vistaplatform-platform
```

**Image section** — near the bottom of the file you will see the image block already in place. Fill in `<image-tag>` with the tag delivered by your VistaSecurity contact (the same value referenced in the pre-flight checklist). The block is preconfigured for Docker Hub. ECR customers: comment out the Docker Hub block and uncomment the ECR block immediately below it, substituting your ECR account and region.

If you are using `local-path` storage (RKE2 default) and your worker disks are adequate, no storage overrides are needed.

**Recommended optional sections** — the example file ships a few additional blocks commented out. Two are worth a look for production installs:

- **`ingress.controller`** (default `traefik`, alternative `none`). Leave on `traefik` if you run cluster Traefik v3+ (RKE2 default). Set to `none` if you use nginx-ingress, Istio, Gateway API, or an external ALB and want to author your own ingress objects — the chart then renders no Ingress/IngressRoute resources, but still emits the right NetworkPolicies. See §3.6 for the full Ingress contract (host headers, paths, required CORS / HSTS / rate-limit behaviors).

- **`monitoring.syntheticChecks`** (default empty). When set, the `monitoring-service` runs HTTP probes against your customer-facing URL every ~30 s and surfaces the result as `synthetic-<name>` in the admin status dashboard. Recommended for production because it catches the failure class per-service probes miss: malformed IngressRoute / Middleware CRDs, expired TLS cert, NetworkPolicy regressions, ingress-controller misbehaviour. A minimal example:

  ```yaml
  monitoring:
    syntheticChecks:
      - name: edge-tenant
        url: https://<your-tls.dnsName>/api/v1/auth-service/health
  ```

  Set `insecureSkipVerify: true` only in lab clusters where the edge cert is signed by an internal CA the `monitoring-service` pod doesn't trust; production deployments with publicly-trusted certs should leave it off.

- **`networkPolicy.egressEnabled`** (default `false`; new in v2.4). When `true`, the chart adds a default-deny **egress** policy alongside the default-deny ingress and emits allow-rules for everything pods legitimately need to reach: kube-DNS, the four datastores (Postgres / Redis / NATS / InfluxDB), backend-to-backend HTTP on 8080, and Internet egress for the four services that intentionally call out (`sensor-manager`, `cluster-sensor-service`, `device-interrogation-service`, `notification-service`). Recommended for production: it limits the blast radius of a compromised backend pod (data exfil, SSRF amplification, attacker C2). Stay on the default while you bring the cluster up; flip it on as a follow-up once everything is green. On EKS with VPC CNI or GKE with NetworkPolicy v2 you may need vendor-specific tweaks — validate in a staging cluster first.

### 9.2 Add the Helm registry

Log in to Docker Hub so `helm` can pull the Vista chart:

```bash
helm registry login registry-1.docker.io \
  --username <your-dockerhub-username> \
  --password <your-dockerhub-token>
```

> **ECR customers** instead run:
> ```bash
> aws ecr get-login-password --region <your-region> | \
>   helm registry login --username AWS --password-stdin \
>   <your-ecr-account>.dkr.ecr.<your-region>.amazonaws.com
> ```

### 9.3 Run helm install

Substitute `<CHART_VERSION>` with the chart version your VistaSecurity contact provided — the same value you used in `helm pull --version <CHART_VERSION>` in §8. Choose the profile that matches your cluster:

**Minimal profile** — for lab, evaluation, or single-node installs with limited resources:

```bash
helm install vistaplatform \
  oci://registry-1.docker.io/vistasecurity/vistaplatform \
  --version <CHART_VERSION> \
  -f vistaplatform/values-minimal.yaml \
  -f values-customer.yaml \
  -n vistaplatform \
  --create-namespace \
  --wait --timeout 10m
```

**HA profile** — for production installs with multiple workers and adequate resources:

```bash
helm install vistaplatform \
  oci://registry-1.docker.io/vistasecurity/vistaplatform \
  --version <CHART_VERSION> \
  -f vistaplatform/values-ha.yaml \
  -f values-customer.yaml \
  -n vistaplatform \
  --create-namespace \
  --wait --timeout 10m
```

> **ECR customers:** replace `oci://registry-1.docker.io/vistasecurity/vistaplatform` with `oci://<your-ecr-account>.dkr.ecr.<your-region>.amazonaws.com/charts/vistaplatform` in the command above.

The `--wait` flag holds the command open until every Deployment, StatefulSet, and Job completes or the timeout is reached. On a healthy cluster with images already cached this typically finishes in 4–6 minutes; allow up to 10 minutes on first install when images need to be pulled.

---

## 10. Verify the install

```bash
# All pods Running:
kubectl -n vistaplatform get pods
# (Expect 16 backend Deployments, 2 frontends, 4 datastores. Routing CRDs
#  (IngressRoute + Middleware) are not pods. In HA mode you'll see 2
#  replicas of every backend except sensor-manager and pcap-processor.)

# Schema migration Job completed successfully:
kubectl -n vistaplatform get jobs
# vistaplatform-schema-migration-<hash>   1/1   <duration>   <age>
# (The <hash> suffix is a short SHA256 of the schema content, so successive
#  upgrades with different schema versions get uniquely-named Jobs.)

# NetworkPolicies are in place:
kubectl -n vistaplatform get networkpolicies
# Expect 7 policies including default-deny-ingress.

# Run the smoke test:
helm test vistaplatform -n vistaplatform
# Expect "Phase: Succeeded".

# Hit the public endpoint (auth-service health, routed through cluster
# Traefik with a /api/v1/<svc>/health → /health rewrite middleware):
curl -fsS https://vistaplatform.example.com/api/v1/auth-service/health
# Expect HTTP 200 and a JSON body like {"service":"auth-service","status":"healthy",...}.

# Browser:
#   https://vistaplatform.example.com           — tenant web-ui
#   https://admin.vistaplatform.example.com     — platform admin-ui (separate host)
```

If any pod is stuck in `ImagePullBackOff`, registry access is misconfigured (return to §6). Confirm the `vistaplatform-registry` Secret exists in the `vistaplatform` namespace and the values-file `image.registry` / `image.repoPrefix` / `image.tag` match the path you can pull with `crictl`.
If any pod is `CrashLoopBackOff`, check `kubectl logs` and §11 troubleshooting.

### Confirm component versions match — About page

Sign in to the tenant web-UI as any user and open the **About** page from the profile dropdown (new in v2.4). It renders the chart version, the image tag of every backend, and the build SHA of each frontend, then compares them against what was stamped into the bundle at release time. A green badge means every layer is on the expected release; a red badge surfaces a version skew — usually a stuck pod still running the previous tag after a partial upgrade, a values file pinning `image.tag` to an older release, or a mixed-replica rollout that hasn't finished yet. Run this check after every install and upgrade.

---

## 11. Day-2 operations

### Upgrade

```bash
helm upgrade vistaplatform \
  oci://registry-1.docker.io/vistasecurity/vistaplatform \
  --version <new-version> \
  -f vistaplatform/values-ha.yaml \
  -f values-customer.yaml \
  -n vistaplatform \
  --wait --timeout 10m
```

> **ECR customers:** replace the OCI URL with `oci://<your-ecr-account>.dkr.ecr.<your-region>.amazonaws.com/charts/vistaplatform` and re-run `aws ecr get-login-password ... | helm registry login ...` first if your previous helm registry login has expired.

> **Upgrading from chart 2.2.x:** if you skip the `-f` flags above and use `--reuse-values` instead, append `--reset-then-reuse-values` (helm 3.13+). 2.3.x reworked the gateway architecture (removed the in-cluster api-gateway pod, added `tls.adminDnsName`, added Traefik IngressRoute + Middleware CRDs); plain `--reuse-values` re-applies your old overrides on top of the **previous** chart's default values and would miss those changes.
>
> **One-time migration for chart 2.2.x → 2.3.x — `ENCRYPTION_MASTER_KEY` env shape:** 2.2.x embedded `ENCRYPTION_MASTER_KEY` as a literal `value:` in the container env of eight backend Deployments. 2.3.x reads it from the `vistaplatform-platform` Secret via `valueFrom: secretKeyRef`. Kubernetes strategic-merge-patch merges env arrays by `name` and cannot replace the storage shape, so the patched manifest ends up with both `value:` and `valueFrom:` set on the same env var, which the API rejects with `may not be specified when 'value' is not empty`. Workaround — before running `helm upgrade`, delete the affected Deployments so helm creates them fresh from the new template instead of patching:
>
> ```
> kubectl delete deploy \
>   auth-service admin-service monitoring-service sensor-manager \
>   cluster-sensor-service resource-tracker-service \
>   device-interrogation-service notification-service \
>   -n vistaplatform
> ```
>
> ~30s downtime per service while the new pods come up. Operators on 2.3.0 or later can skip this step entirely — the env shape is stable from 2.3.x onward.

> **Behavior change in chart 2.4.x — `device-interrogation-service` defaults to TLS verification.** Before 2.4, the device interrogator (used to fetch configurations from F5, Palo Alto, Cisco, Fortinet, etc. via vendor management APIs) silently skipped TLS verification for every device. From 2.4 onward, TLS verification is **on by default**, and the per-device `tls_insecure_skip_verify` field must be set explicitly for any device that presents a self-signed or internal-CA certificate. After upgrade, expect any device whose management endpoint uses a cert that isn't in the platform pod's trust store to start failing interrogation with a TLS verify error — flip the per-device opt-in in the admin UI (or via the device API) for those devices, or add the internal CA to the platform's trust bundle if it's a standard internal PKI.

The schema migration Job is created as a regular release resource (not a Helm hook). Each backend Deployment has an init container that polls Postgres for the `public.tenants` sentinel table and blocks the main container until the schema is applied, so `helm upgrade --wait` correctly observes the Deployments becoming Ready only after migration completes. The Job's name embeds a short SHA256 of the schema content, so each upgrade that changes the schema gets a uniquely-named Job. The chart-managed `vistaplatform-generated` Secret survives via `helm.sh/resource-policy: keep`, so datastore credentials remain stable across upgrades.

### Rollback

```bash
helm history vistaplatform -n vistaplatform
helm rollback vistaplatform <revision> -n vistaplatform --wait
```

Caveats: rollback re-runs the schema migration Job against the older schema. The Vista schema is forward-compatible (additive only — `CREATE TABLE IF NOT EXISTS`), so this is safe in nearly all cases. If you need to roll back across a destructive schema change, contact VistaSecurity support before doing so.

### License rotation

```bash
kubectl create secret generic vistaplatform-license \
  -n vistaplatform \
  --from-literal=token='<NEW-JWT>' \
  --dry-run=client -o yaml | kubectl apply -f -

# Roll the backend pods so they pick up the new file:
kubectl -n vistaplatform rollout restart deployment
```

No `helm upgrade` required.

### Backup

The customer is responsible for backing up the persistent volumes. Recommended:

- **Postgres:** `pg_dump` from inside the postgres pod, or volume-snapshot via your CSI driver.
- **InfluxDB:** the `influx backup` CLI run inside the influxdb pod.
- **Redis:** AOF persistence is enabled; the PVC contains the AOF file. For a clean snapshot, `redis-cli BGSAVE` then snapshot the volume.
- **NATS JetStream:** snapshot the `nats-data-*` PVC.

Out of scope for v1: automated backup operators. Roadmap.

### Support bundle

When opening a support ticket, run this and attach the output:

```bash
{
  echo "=== helm status ==="
  helm status vistaplatform -n vistaplatform
  echo "=== pods ==="
  kubectl -n vistaplatform get pods -o wide
  echo "=== events ==="
  kubectl -n vistaplatform get events --sort-by=.lastTimestamp
  echo "=== describe failing pods ==="
  kubectl -n vistaplatform get pods --field-selector=status.phase!=Running -o name | \
    xargs -r -I{} kubectl -n vistaplatform describe {}
  echo "=== networkpolicies ==="
  kubectl -n vistaplatform get networkpolicies -o yaml
  echo "=== chart values ==="
  helm get values vistaplatform -n vistaplatform
} > vistaplatform-support-bundle.txt
```

The bundle does **not** include logs by default (they may contain customer data). If support asks for logs of a specific service, run `kubectl -n vistaplatform logs deploy/<service-name>` separately and review before sending.

### Common issues

| Symptom | Likely cause | Fix |
|---|---|---|
| Pods stuck `ImagePullBackOff` | Registry credentials missing or expired | Refresh the image pull Secret (see §6) |
| `Certificate not yet ready` after install | cert-manager Issuer can't reach ACME / CA | Check cert-manager logs and Issuer status |
| Schema migration Job failing | Postgres unreachable or wrong password | `kubectl logs job/vistaplatform-schema-migration -n vistaplatform`; usually a NetworkPolicy or storage-class issue |
| `helm install --wait` times out with "Deployment/cbom-service not ready" (or "Deployment/report-generator not ready" on pre-v2.4 charts); backends in `CrashLoopBackOff` with "relation does not exist" Postgres errors; **no** schema-migration Job in `kubectl get jobs` | **Chart v0.1.1 only.** Schema migration was a `post-install` Helm hook; `--wait` blocks on the main resources reaching Ready before running post-install hooks, but the backends can never reach Ready without the schema, so the hook never runs. Chicken-and-egg. Fixed in **chart v0.2.0** (schema migration is now a regular release resource gated by an init container on each backend). | **Upgrade to chart v0.2.0+** before re-installing. If you must recover an existing v0.1.1 install: apply the schema manually, then restart the backends. <br><br>`kubectl -n vistaplatform cp <path>/schema.sql postgres-0:/tmp/schema.sql` <br>`kubectl -n vistaplatform exec postgres-0 -- psql -U crypto_user -d crypto_inventory -f /tmp/schema.sql` <br>`kubectl -n vistaplatform rollout restart deployment` <br>then `helm test vistaplatform -n vistaplatform`. Contact VistaSecurity support for the `schema.sql` file matching your chart version. |
| `pcap-processor` pod Pending after node loss | The shared `pcap-uploads` PVC is `ReadWriteOnce` and pinned to the failed node | When the node recovers, the pod will reschedule. To force, delete the PV's `nodeAffinity` (data may be lost). v1.x roadmap: object-storage-backed PCAP handoff. |
| `vistaplatform-generated` Secret missing on reinstall | You ran `helm uninstall` without `--keep-history`, or removed the `helm.sh/resource-policy: keep` annotation | Recover datastore passwords from your backup or recreate the Secret manually before reinstalling — see support |
| Cross-node pod traffic silently dropping (pods on different workers can't communicate) | Canal/Flannel VXLAN forwarding database (FDB) is empty after an rke2-server restart | Restart the Canal DaemonSet: `kubectl -n kube-system rollout restart daemonset rke2-canal`. Verify with `bridge fdb show dev flannel.1` on a worker — should show one entry per remote node. |
| MetalLB VIP unreachable even though Traefik pod is Running | MetalLB advertising VIP from a worker whose kube-proxy can't route cross-node (same FDB issue as above) | Same fix — restart Canal DaemonSet, then confirm `nc -zv <vip> 80` succeeds. |
| Traefik service stuck as `NodePort` / `EXTERNAL-IP: <pending>` after MetalLB install | RKE2 deployed Traefik as NodePort type; MetalLB only assigns IPs to LoadBalancer services | Patch: `kubectl -n kube-system patch svc traefik -p '{"spec":{"type":"LoadBalancer"}}'` |
| MetalLB speaker pods fail to schedule with `violates PodSecurity "restricted:latest"` | CIS profile enforces `restricted` pod security on all namespaces; MetalLB speaker requires host network and elevated capabilities | Label the namespace before installing: `kubectl label ns metallb-system pod-security.kubernetes.io/enforce=privileged` |

---

## 12. HA limitations and roadmap

This v1 chart provides:

- **Stateless tier HA** in `values-ha.yaml` mode. Backends and frontends run with `replicas: 2` and `podAntiAffinity` spreading them across worker nodes. Loss of any single worker keeps the application available. Routing rides on the cluster's own Traefik IngressController — scale that per your cluster's standard practice.
- **PodDisruptionBudgets** that prevent both replicas of a service from being drained simultaneously during planned maintenance.
- **NetworkPolicies** enforcing a default-deny ingress posture with named allows generated from the same backend definitions.

This v1 chart does **not** provide:

- **Datastore HA.** Postgres, Redis, InfluxDB, and NATS run as single replicas. Loss of the worker hosting a datastore takes that datastore down until rescheduling completes (and PVC reattaches). Roadmap items for v1.x:
  - Postgres → CloudNativePG operator or external managed Postgres
  - Redis → Sentinel mode or external managed
  - InfluxDB → upgrade to 3.x with native clustering, or external managed
  - NATS → 3-replica JetStream cluster (requires either 3 worker nodes or scheduling on the master)
- **PCAP upload HA.** sensor-manager and pcap-processor share a `ReadWriteOnce` PVC and are pinned to `replicas: 1`. Loss of the worker hosting them temporarily disables PCAP upload. Roadmap: object-storage-backed handoff (S3 or in-cluster MinIO) so both services can scale independently.
- **Geographic replication / multi-cluster.** Out of scope for v1.

If your security or business requirements need any of the above sooner than the v1.x roadmap, contact VistaSecurity to discuss a custom engagement.

---

## 13. Uninstall

```bash
helm uninstall vistaplatform -n vistaplatform
kubectl delete namespace vistaplatform
```

Note: persistent volumes (`postgres-data-*`, `redis-data-*`, `influxdb-data-*`, `nats-data-*`, `pcap-uploads`) are **not** automatically deleted because the chart annotates them with `helm.sh/resource-policy: keep`. This is deliberate: an accidental `helm uninstall` does not destroy customer data. To fully reclaim storage, delete the PVCs manually after confirming you don't need the data:

```bash
kubectl -n vistaplatform delete pvc --all
```

---

## Appendix A — Inventory of resources the chart creates

| Kind | Count (HA) | Count (minimal) | Notes |
|---|---|---|---|
| Deployment | 18 | 18 | 16 backends + web-ui + admin-ui (no in-cluster gateway pod) |
| StatefulSet | 4 | 4 | postgres, redis, influxdb, nats |
| Service | 23 | 23 | one per workload + nats-headless |
| IngressRoute (Traefik CRD) | 3–4 | 3–4 | tenant API + tenant web-ui + HTTP→HTTPS redirect, plus admin-ui when `tls.adminDnsName` is set |
| Middleware (Traefik CRD) | 56 | 56 | shared (CORS, security headers, rate limit, retry, body-size, compress, redirect) + per-service (16 circuit-breakers + 16 health-rewrites + 15 v2→v1 rewrites) |
| PodDisruptionBudget | 14 | 0 | engages only when replicas > 1 |
| NetworkPolicy | 8 | 8 | default-deny-ingress + 7 named allows (postgres, redis, nats client + monitor, influxdb, ingress→frontends, ingress→backends, frontends-from-gateway) |
| ConfigMap | 6 | 6 | app config, ui runtime configs (2), schema, seed-data, nats config |
| Secret (chart-managed) | 1 | 1 | `<release>-vistaplatform-generated` (datastore passwords). `vistaplatform-platform` is BYO unless you set inline values |
| Certificate (cert-manager) | 1 | 1 | only when `tls.mode=certManager`; lists both `dnsName` and `adminDnsName` as SANs |
| Job | 2 | 2 | schema-migration + seed-data (both idempotent across upgrades) |
| PersistentVolumeClaim | 1 | 1 | `pcap-uploads` (datastore PVCs come from StatefulSet `volumeClaimTemplates`) |
| Pod (helm-test only) | 1 | 1 | `<release>-vistaplatform-smoke-test`, created by `helm test`, deleted on success |

Plus customer-applied: `vistaplatform-license`, `vistaplatform-platform` (when not using inline values), and the `vistaplatform-registry` imagePullSecret you created in §6.
