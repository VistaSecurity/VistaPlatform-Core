# Installing Vista Platform

Three ways in, depending on what you're trying to find out. Start at the top —
each takes longer and looks more like production than the one above it.

| | What you get | Needs | Time |
|---|---|---|---|
| [Try it](#try-it) | The whole product on your laptop | Docker | ~5 min |
| [Evaluate it](#evaluate-it) | A real Kubernetes deployment on one VM | A VM, root | ~15 min |
| [Run it](#run-it) | Your cluster, your certificates | A cluster | — |

Everything is free under [FSL-1.1-ALv2](LICENSE.md). No licence key, no
registration, no phone-home.

> **Beta software, provided "AS IS", used at your own risk.** Before you deploy
> a sensor or agent, read [DISCLAIMER.md](DISCLAIMER.md) — in particular
> [authorized use](DISCLAIMER.md#authorized-use-only), which covers scanning
> only what you own and the caution around probing OT/ICS networks.

---

## Try it

```bash
git clone https://github.com/VistaSecurity/VistaPlatform-Core.git
cd VistaPlatform-Core
./scripts/bootstrap-env.sh
docker compose up -d
```

Then open **http://localhost:3000** and sign up. The first account you create
becomes the administrator of a new organization.

The first run builds ~18 images and applies the database schema, so give it a
few minutes. `docker compose ps` will show 29 containers when it's ready.

**Don't skip `bootstrap-env.sh`.** `env.example` ships readable placeholders so
the file is easy to follow — and those placeholders are published in this
repository. A deployment that keeps them has a JWT signing key and a
service-auth secret anyone can look up. The script replaces each with a random
value.

**If a container dies with `address already in use`**, something on the host
already owns that port. Every published port has an override in `.env` — set it
to a free number and `docker compose up -d` again. The three the instructions
above name (`API_GATEWAY_HOST_PORT` 8080, `WEB_UI_HOST_PORT` 3000,
`ADMIN_UI_HOST_PORT` 3006) are the likeliest to clash, since `bootstrap-env.sh`
deliberately leaves them on their documented values; everything else is already
moved into the 4xxxx range.

Compose is fine for looking around. It is not how you should run this for real:
there is no HA, no rolling upgrade, and everything shares one host.

### Signing in to the admin console

Signing up at the tenant UI makes you an administrator of *an organization*. The
**platform** admin console — tenants, plans, platform-wide settings — is a
separate UI with separate accounts, at **http://localhost:3006** under compose
(`tls.adminDnsName` on Kubernetes).

Every install seeds two platform administrators, both with the same password:

| Email | Role |
|---|---|
| `su_admin@vistaplatform.invalid` | super admin |
| `admin@vistaplatform.invalid` | platform admin |

Password: `PlatformAdm!n2026`

**These are published defaults — every install on earth starts with them, and
they are only good for one thing.** Both accounts are seeded "must change
password": signing in with the default yields a session that can set a new
password and nothing else. The services reject every other request until you
rotate, and that is enforced server-side, not just by the UI.

The `.invalid` domain is deliberate — [RFC 6761][rfc6761] reserves it so the
address can never resolve to a real mailbox. That also means **password-reset
mail to a seeded admin goes nowhere.** Rotate on first sign-in, then create your
own platform admin under a real address (**Staff & Access → Staff**) and use that
one day to day. Don't rename the seeded rows: the seed re-applies on every upgrade
and will rename them back.

[rfc6761]: https://www.rfc-editor.org/rfc/rfc6761#section-6.4

---

## Evaluate it

A real Kubernetes deployment on a single machine — same charts, same manifests,
same upgrade path as a production install, just one node.

On a fresh VM (2 vCPU / 8 GB is comfortable):

```bash
# 1. A single-node Kubernetes
curl -sfL https://get.k3s.io | sh -
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
```

```bash
# 2. The two prerequisites the chart does not install
helm repo add jetstack https://charts.jetstack.io
helm repo add stakater https://stakater.github.io/stakater-charts
helm repo update
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace --set crds.enabled=true --wait
helm install reloader stakater/reloader \
  --namespace reloader --create-namespace --wait
```

```bash
# 3. Vista Platform
helm install vista oci://ghcr.io/vistasecurity/vistaplatform \
  --namespace vista --create-namespace --wait
```

**Why step 2.** Internal traffic — service-to-service, and the connections to
PostgreSQL and NATS — is mTLS-encrypted by default. cert-manager issues those
per-service certificates from a private CA the chart provisions, and Reloader
restarts pods when one rotates. k3s ships neither, so without this step step 3
stops immediately with an error naming what is missing. That is the chart
refusing to come up in a weaker configuration than you asked for, not a
failure to install.

If you would rather not run those two, you can turn encrypted internal
transport off instead — but then it stays off, so this is only sensible for a
throwaway look:

```bash
helm install vista oci://ghcr.io/vistasecurity/vistaplatform \
  --namespace vista --create-namespace --wait \
  --set serviceMtls.enabled=false \
  --set datastores.postgres.tls.enabled=false \
  --set datastores.nats.tls.enabled=false
```

Either way there is no values file. The chart generates its own secrets and a
self-signed certificate on first install, so it comes up without being told
anything else. Expect a minute or two: `--wait` returns when every pod is
ready.

Routing is by hostname, and with no values the hostname is `vista.local`. So
point that name at the ingress controller — on k3s, its bundled Traefik:

```bash
kubectl -n kube-system get svc traefik -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
```

Add that IP to `/etc/hosts` (on whichever machine runs the browser) as
`vista.local`, then open **https://vista.local**.

The platform's own Services are all ClusterIP — there is nothing to reach in the
`vista` namespace directly. Traffic arrives through the ingress controller, and
the chart's `IngressRoute` matches on `Host(vista.local)`, so a request sent to
the bare IP gets a 404 rather than the UI.

Your browser will warn about the certificate. That warning is accurate — it's
self-signed. [Run it](#run-it) below covers getting a real one.

The admin UI is not routed until you give it a hostname (`tls.adminDnsName`);
the evaluation install exposes the tenant UI only.

---

## Run it

```bash
helm install vista oci://ghcr.io/vistasecurity/vistaplatform \
  --namespace vista --create-namespace \
  --values values.yaml
```

A minimal production `values.yaml`:

```yaml
tls:
  mode: certManager           # a real certificate, renewed automatically
  dnsName: vista.example.com  # where users reach the web UI and API
  adminDnsName: admin.vista.example.com
  issuerRef:
    name: letsencrypt-prod    # a cert-manager ClusterIssuer you already have
    kind: ClusterIssuer

platform:
  # Recommended: create this Secret yourself, out of band, and name it here.
  # Otherwise the chart generates these on first install and keeps them.
  existingSecretName: vista-platform-secrets
```

### Prerequisites the chart does not install

- **cert-manager** — required by default. It issues the per-service
  certificates for encrypted internal transport (`serviceMtls`, on by
  default), and it is also what `tls.mode: certManager` uses for the
  browser-facing certificate. The install stops with a clear error if its CRDs
  are absent. Only optional if you turn all three of `serviceMtls.enabled`,
  `datastores.postgres.tls.enabled` and `datastores.nats.tls.enabled` off.
- **Stakater Reloader** — required whenever `serviceMtls` is on, so by default.
  It restarts pods when a certificate rotates. Nothing fails at install time
  without it; internal mTLS quietly breaks at the first renewal, ~60 days in.
- **Traefik**, with its CRDs. The chart creates `IngressRoute` and `Middleware`
  *resources*; it does not install the controller or the CRDs that define them.
  (k3s ships Traefik by default, which is why "Evaluate it" installs only the
  two above.)
- **A StorageClass** for the PostgreSQL, InfluxDB and upload volumes.

Full detail on the internal-mTLS options — what each toggle covers, how to
stage them across upgrades, and how to run against a managed PostgreSQL — is in
§5E of
[`docsv4/core/operate/deployment/rke2-v1/deployment-guide.md`](docsv4/core/operate/deployment/rke2-v1/deployment-guide.md).

### One thing worth knowing before you upgrade

`ENCRYPTION_MASTER_KEY` encrypts stored integration credentials. If it changes,
those become permanently undecryptable. The chart therefore reads the existing
Secret back on upgrade and reuses it rather than generating a new one — but if
you manage that Secret yourself, treat it the way you'd treat a database
encryption key.

---

## Verifying what you're running

Every Core image and the chart are built from this repository by
[`.github/workflows/release-core.yml`](.github/workflows/release-core.yml) and
signed with cosign. There's no key to trust — the signing identity *is* the
workflow:

```bash
# any service image
cosign verify ghcr.io/vistasecurity/auth-service:<version> \
  --certificate-identity-regexp 'https://github.com/VistaSecurity/VistaPlatform-Core/.github/workflows/release-core.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# and the chart itself
cosign verify ghcr.io/vistasecurity/vistaplatform:<chart-version> \
  --certificate-identity-regexp 'https://github.com/VistaSecurity/VistaPlatform-Core/.github/workflows/release-core.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

A successful verification prints the workflow, the tag it ran on, and the
commit — check that the tag matches what you meant to install. The chart also
prints this command, filled in for the version you have, at the end of
`helm install`.

Because these images are built from the public source with no obfuscation, you
can also just rebuild a tag yourself and compare. That is the point of shipping
them this way.

---

## After it's up

1. **Sign up** at the web UI — the first account creates the organization.
2. **Deploy a sensor** so there's something to inventory. Sensors are standalone
   Go binaries you run inside your own network — see
   [`docsv4/core/features/SENSOR_REGISTRATION.md`](docsv4/core/features/SENSOR_REGISTRATION.md).
3. **Look at Inventory → Certificates** once discovery has run.
4. **Generate a CBOM** from Risk & Compliance.

## Before anyone else uses it

**Replace the Terms of Service and Privacy Policy.** The deployment ships with
**templates** — real structure with `[BRACKETED]` blanks, and a banner saying
they are not legally binding. Every user is asked to accept them at sign-up, so
until you replace them your users are accepting placeholder text.

This is not an oversight on our part that you can wait for us to fix. VistaPlatform
is self-hosted: **you** are the service provider and the data controller. Those
are *your* terms with *your* users, and only you can write them — the software
authors neither operate your instance nor receive any data from it.

Edit and publish at **Settings → Legal** in the admin console. Publishing a new
version asks existing users to re-accept, and each acceptance is recorded against
the version and its content hash, so you can show who agreed to what and when.

Have counsel review before you publish. The templates are a starting point, not
legal advice.

## When something doesn't come up

```bash
kubectl -n vista get pods
kubectl -n vista logs deploy/auth-service
```

Deployments are named after the service (`auth-service`, `web-ui`), not prefixed
with the release name. The Jobs and ConfigMaps are release-prefixed; the
workloads are not.

Common first-install problems:

- **`helm install` fails immediately with "cert-manager is not installed in
  this cluster"** — encrypted internal transport is on by default and needs
  cert-manager (and Reloader). Install both, or turn the three toggles off;
  step 2 of [Evaluate it](#evaluate-it) shows each.
- **The UI 404s** — you reached the ingress controller but not by the name it
  routes on. Check `kubectl -n vista get ingressroute -o yaml | grep match:` and
  use that hostname.
- **Pods `Pending`** — no StorageClass, or the node is too small. `kubectl -n
  vista describe pod <name>` says which.
- **`schema-migration` fails** — Postgres wasn't ready. It's a Job; delete it and
  re-run `helm upgrade`. Its name carries a hash of the pod template, so find it
  with `kubectl -n vista get job -l app.kubernetes.io/component=schema-migration`
  rather than guessing.
- **Signup succeeds but login says "Email not verified"** — you have `SMTP_HOST`
  set but mail isn't actually being delivered. Either fix delivery or unset it;
  with no SMTP configured, verification isn't required.
