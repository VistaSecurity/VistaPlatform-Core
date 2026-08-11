---
render_macros: false
---

# Vista RKE2 Deployment — Pre-Flight Checklist

**Complete this checklist before opening the deployment guide.** Every item on this list is required. Do not begin the install until you can check every box — missing any one of them will cause the install to fail partway through, which is harder to recover from than waiting until you have everything ready.

Your VistaSecurity contact is responsible for delivering items 1–4. Items 5–6 are your responsibility.

---

## From Vista (delivered before you begin)

- [ ] **License token** — A JWT string starting with `eyJ...`. Delivered securely (password-manager share link, encrypted email, or secure file transfer). This is time-limited — check the expiry date with your contact. You will need this for §7 of the deployment guide.

- [ ] **Docker Hub access token + username** — A personal access token (PAT) scoped to the VistaSecurity Docker Hub organization (URL namespace `vistasecurity`; images live under `docker.io/vistasecurity/`), plus the username it was issued for. Used to pull Vista container images and the Helm chart onto your cluster nodes. Treat this like a password — do not share it or commit it to source control. You will need both values for §6 of the deployment guide.

  > If your contract specifies AWS ECR delivery instead of Docker Hub, you will receive an ECR account ID, region, and IAM instructions in place of the Docker Hub token. ECR delivery is the exception, not the norm.

- [ ] **Chart version + image tag** — The specific version for your licensed release (e.g. chart `2.4.0` / image `v2.4.0`). Chart and image share the same release number; the only difference is the `v` prefix on image tags (OCI chart versions are bare semver). Delivered alongside the Docker Hub token. You will use the chart version in `helm pull --version` (§8) and the image tag in your `values-customer.yaml` (§9.1).

  There is **no separate install package**. The chart you pull in §8 includes everything you need:

  - `examples/values-customer.yaml.example` — the configuration template you will fill in
  - `values-minimal.yaml` — resource profile for lab / evaluation installs
  - `values-ha.yaml` — resource profile for production HA installs

  `helm pull --untar` (used in §8) extracts these into a `vistaplatform/` directory alongside the `.tgz`. §9.1 walks through copying the example out.

- [ ] **Link to this documentation** — The URL to the full deployment guide and supporting docs. If you are reading this, you already have it.

---

## Your responsibility (before you begin)

- [ ] **RKE2 cluster is up and meets prerequisites** — See §2 of the deployment guide for minimum cluster requirements. Verify with `kubectl get nodes` — all nodes should show `Ready`.

- [ ] **Operator workstation is configured** — the following CLIs are installed and `kubectl` is pointed at your cluster:
  - `kubectl` — `kubectl get nodes` returns all nodes `Ready`
  - `helm` v3.13 or later (`helm version`)
  - `cosign` v2.x (`cosign version`) — used in §8 of the deployment guide to verify chart and image signatures
  - `openssl` — used in §5A (self-signed cert) and §7.3 (generating platform secrets)
  - `aws` CLI v2 — only required if your contract delivers via ECR; most customers can skip this

- [ ] **Ingress controller decision is made** — RKE2 v1.30+ ships `rke2-ingress-nginx` by default, but Vista requires Traefik. §3 of the deployment guide walks you through disabling nginx and installing Traefik. If you already have a Traefik v3 install on the cluster, confirm the `IngressRoute` and `Middleware` CRDs are present (`kubectl get crd ingressroutes.traefik.io middlewares.traefik.io`).

- [ ] **Storage class is identified** — either an existing CSI-backed storage class with `ReadWriteOnce` support (60+ GB available across nodes), or readiness to install Longhorn per §2 of the deployment guide.

- [ ] **Two DNS records are created** pointing at the cluster's ingress LB:
  - Tenant host — e.g. `vistaplatform.example.com` (web-UI + REST API)
  - Admin host — e.g. `admin.vistaplatform.example.com` (platform admin-UI, served at root of this hostname)

  Both resolve to the same ingress IP — Traefik routes by `Host` header. Skipping the admin record will leave the platform admin-UI unreachable externally.

  > **Both hostnames must share the same registered domain (eTLD+1).** Auth cookies are scoped to `.{tenant-host}` — if the admin hostname is on a different registered domain (e.g., `admin.company-b.com` when the tenant host is `vistaplatform.company-a.com`), admin login will silently fail. The subdomain pattern shown above (`admin.vistaplatform.example.com`) is always safe. See deployment guide §2 for the full explanation.

---

## Quick reference — where each item is used

| Item | Used in |
|---|---|
| License token | §7 — Apply the license and platform secrets |
| Docker Hub access token + username | §6 — Configure registry access |
| Chart version | §8 — Pull and verify the chart |
| Image tag | §9.1 — Assemble your values-customer.yaml |
| Cluster ready | §2 — Prerequisites |
| Two DNS records (tenant + admin) | §2 — Prerequisites, §5 — TLS |

---

Once every box above is checked, open the deployment guide and start at §1.
