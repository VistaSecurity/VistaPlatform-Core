---
render_macros: false
---

# Production Deployment Checklist

Vista Platform ships as a **Helm chart** — production installs run on Kubernetes,
against the chart at `oci://ghcr.io/vistasecurity/vistaplatform`. This checklist
covers the pre-flight, the install itself, and post-install verification for a
real deployment. Docker Compose (the top-level `docker compose up -d` path) is
for trying the product on a laptop, not for running it — see
[Try it](https://github.com/VistaSecurity/VistaPlatform-Core/blob/main/INSTALL.md#try-it)
in `INSTALL.md`. There is no `docker-compose.prod.yml` in the public
distribution; it isn't part of how anyone is meant to run this in production.

For a smaller, single-VM run-through of the same chart (useful for evaluation or
staging before a real cluster), see
[Evaluate it](https://github.com/VistaSecurity/VistaPlatform-Core/blob/main/INSTALL.md#evaluate-it)
in `INSTALL.md`.

## Pre-Deployment

### Cluster prerequisites the chart does not install

- **cert-manager** — required by default. It issues the per-service certificates
  for encrypted internal transport (`serviceMtls`, on by default) and, with
  `tls.mode: certManager`, the browser-facing certificate too. The install stops
  with a clear error if its CRDs are absent. Only optional if you turn all four
  of `serviceMtls.enabled`, `datastores.postgres.tls.enabled`,
  `datastores.nats.tls.enabled` and `agentMtls.enabled` off (`agentMtls` is on by
  default and requires `serviceMtls`) — not recommended for a real deployment.
- **Stakater Reloader** — required whenever `serviceMtls` is on (the default). It
  restarts pods when a certificate rotates. Nothing fails at install time
  without it; internal mTLS quietly breaks at the first renewal, ~60 days in.
- **Traefik**, with its CRDs. The chart creates `IngressRoute` and `Middleware`
  *resources*; it does not install the controller or the CRDs that define them.
  **Traefik v3.4 or newer** is required when `serviceMtls` is on: the chart's
  `ServersTransport` uses the `rootCAs` field, which older releases do not know.
- **A StorageClass** for the PostgreSQL, Redis, NATS and upload volumes. The
  chart defaults to `datastores.storageClassName: ""`, which omits
  `storageClassName` so your cluster's **default** StorageClass is used; check
  that `kubectl get storageclass` shows one marked `(default)`. If there is no
  default (or you want a specific class), set `datastores.storageClassName`
  (or a per-datastore `datastores.<store>.storageClassName`, which wins) to a
  class that exists; otherwise the PersistentVolumeClaims stay `Pending`.

  **Upgrading an existing release: pin its class first.** Earlier chart
  versions defaulted this value to `longhorn`, and StatefulSet
  `volumeClaimTemplates` are immutable, so `helm upgrade` with the new empty
  default fails with a `Forbidden` error. Before upgrading, read the class off
  your existing volumes (`kubectl -n <ns> get pvc`) and pass
  `--set datastores.storageClassName=<class>` (or put it in your values file).

Full detail on the internal-mTLS options — what each toggle covers, how to stage
them across upgrades, and how to run against a managed PostgreSQL — is in
[Service-mesh mTLS](../security/service-mesh-mtls.md). If your edge certificate
comes from an internal or corporate CA rather than a public issuer, see
[Running with an internal CA](../security/internal-ca.md) for the supported way
to make in-cluster callers trust it.

### `values.yaml`

- [ ] Set `tls.dnsName` and `tls.adminDnsName` — where users reach the web UI/API
      and the admin console.
- [ ] Set `tls.issuerRef` to a cert-manager `ClusterIssuer` you already have (for
      `tls.mode: certManager`), or configure your own certificate path.
- [ ] If you use `tls.mode: certManager` with an **HTTP-01** issuer, the chart
      already allows the cert-manager solver pod (label
      `acme.cert-manager.io/http01-solver`, port 8089) through its default-deny
      ingress NetworkPolicy, from `networkPolicy.ingressControllerNamespace`
      (default `kube-system`; set it to the namespace your ingress controller
      runs in). Your issuer must still be able to reach your ingress from the
      Internet on port 80. A **DNS-01** issuer creates no solver pod and needs
      nothing extra from the NetworkPolicy.
- [ ] If you turn on `networkPolicy.egressEnabled` **and** use an external
      PostgreSQL or Redis (`datastores.postgres.enabled: false` /
      `datastores.redis.enabled: false`), list the database's address range in
      `networkPolicy.externalDatastoreCIDRs` (for example `["10.20.30.0/24"]`).
      The chart then allows egress to those CIDRs on TCP 5432 (PostgreSQL) and
      6379 (Redis); without it the default egress deny blocks every backend and
      Job from reaching the database, so the chart refuses to render with an
      empty list.
- [ ] Create `platform.existingSecretName` yourself, out of band, and name it in
      values — otherwise the chart generates platform secrets on first install
      and keeps them. Either way, treat `ENCRYPTION_MASTER_KEY` the way you'd
      treat a database encryption key: if it changes, every stored integration
      credential encrypted under the old key becomes permanently undecryptable.
      The chart reads the existing Secret back on upgrade rather than
      regenerating it, but only if you haven't overridden that behavior.
- [ ] **External PostgreSQL or Redis** (`datastores.postgres.enabled=false` /
      `datastores.redis.enabled=false`) **requires** `platform.existingSecretName`.
      The chart-generated Secret cannot carry your connection strings, so the
      render stops with an error unless you supply a Secret that also holds
      `database-url` (external Postgres) and/or `redis-url` (external Redis),
      alongside `jwt-secret`, `internal-auth-secret` and `encryption-master-key`.
- [ ] **External NATS is not supported.** `datastores.nats.enabled=false` is
      refused at render time; keep the bundled NATS.
- [ ] If you apply the schema yourself (`schemaMigration.enabled=false`) and keep
      `serviceRls.enabled` on (the default), your schema must create the
      `crypto_app` (NOLOGIN NOBYPASSRLS) and `crypto_bypass` (NOLOGIN BYPASSRLS)
      roles with the grants from `schema.sql`. The `rls-roles` Job still runs and
      waits for them, then grants LOGIN; backends stay in `Init` until it does.
- [ ] The chart creates the namespace only with `createNamespace=true`; that
      namespace is kept on `helm uninstall` (with its PVCs and Secrets). Delete
      it yourself when you mean to destroy the data.
- [ ] Size the node(s) for roughly double your steady-state CPU **request**
      during upgrades if you're running a single-node cluster — see
      "Single-node clusters" below.

### Optional prerequisites

- [ ] **A model provider**, if you want AI-assisted seams (finding
      explanations, remediation drafting, EOL gap-filling proposals) to use a
      real model instead of the rule-based default every one of them falls
      back to. See [Connecting a model provider](../configuration/ai-provider.md)
      — nothing here blocks an install; every AI capability works without it.
- [ ] **The offline End-of-life/Vulnerability bundle**, for an air-gapped
      install with no route to endoflife.date/NVD/OSV. See
      [Air-gapped installs: the offline bundle](../catalogs.md#air-gapped-installs-the-offline-bundle).


### Legal documents

- [ ] Replace the Terms of Service and Privacy Policy templates. The chart
      ships **templates** — real structure with `[BRACKETED]` blanks and a
      banner saying they are not legally binding — and every user is asked to
      accept them at sign-up. See [Legal documents for operators](../legal/README.md).

## Deployment

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

agentMtls:
  # Required by default: sensors and discovery agents authenticate with client
  # certificates over a TLS-passthrough listener, one hostname per service.
  # Each must differ from the other and from tls.dnsName, and resolve to a
  # Traefik passthrough entrypoint (agentMtls.entryPoint, port 8444) you provide.
  backends:
    sensor-manager:
      dnsName: sensors.vista.example.com
    device-interrogation-service:
      dnsName: agents.vista.example.com
```

The install **fails** without the two `agentMtls` hostnames (or an explicit
`agentMtls.enabled: false`) — see
[Agent and sensor mTLS](../security/service-mesh-mtls.md#agent-and-sensor-mtls-agentmtls--on-by-default-and-a-breaking-upgrade).

There is no separate "start infrastructure, then services, then gateway"
sequence to run by hand — `helm install` reconciles everything (Postgres,
Redis, NATS, every backend, both frontends, and the schema-migration
and seed-data Jobs) in dependency order, and `--wait` returns once every pod is
ready. Give the first install a few minutes: it's applying the schema, seeding
reference data, and pulling ~18 images.

## Post-Deployment

### Verification

- [ ] All pods are ready:
      ```bash
      kubectl -n vista get pods
      ```
- [ ] The web UI and admin UI load at `tls.dnsName` / `tls.adminDnsName`
- [ ] Sign in with a seeded platform administrator and complete the mandatory
      password rotation (see the [Platform Admin Guide](../platform-admin-guide.md#first-sign-in-mandatory-password-rotation))
- [ ] A backend answers on its plaintext health port (used for probes; mTLS is
      not required against it even when `serviceMtls.enabled` is on):
      ```bash
      kubectl -n vista exec deploy/auth-service -- wget -qO- http://localhost:8080/health
      ```
- [ ] The MCP service is healthy and requires `INTERNAL_AUTH_SECRET`/a tenant
      API token — an unauthenticated request to `/api/v1/mcp-service/mcp` must
      return `401`.
- [ ] Test your configured notification channels (Settings → Notification
      Delivery) and confirm delivery history records the attempt.
- [ ] **Take a backup and prove it.** Admin console → Maintenance → Backups →
      Create backup, download it, and keep a copy outside the cluster. If you
      tick "Include encryption keys and install secrets", store the passphrase in
      your password manager: it is not recoverable. Walk through the Restore
      procedure in [Maintenance](../maintenance.md#restore) on a scratch
      cluster before you need it.
- [ ] **Decide on update checks.** `maintenance.updateCheck.enabled` is `true` by
      default and makes one outbound registry call a day. On an air-gapped site
      set it to `false` (and point `image.registry` / `maintenance.chartSource`
      at your mirror); see [Maintenance](../maintenance.md#where-latest-comes-from).

### Verify what you're running

Every Core image and the chart are cosign-signed with the signing identity
*being* the release workflow — see
[Verifying what you're running](https://github.com/VistaSecurity/VistaPlatform-Core/blob/main/INSTALL.md#verifying-what-youre-running)
in `INSTALL.md` for the `cosign verify` commands. `helm install` prints the
verify command for the chart version you installed at the end of its run.

### Monitoring

- [ ] Configure monitoring alert thresholds and notification channels — see
      [Monitoring Setup](../monitoring/setup.md)
- [ ] Set up log aggregation for your cluster's logging stack
- [ ] Set up uptime monitoring against the public hostname

### Security

- [ ] Verify HTTPS is enforced end to end (browser → ingress)
- [ ] Test authentication and authorization
- [ ] Review the [Security & Trust → Dashboard](../platform-admin-guide.md#security--trust) posture view

## GitOps (Argo CD / Flux)

By default the chart generates its passwords and keys with `lookup`, which
reads the Secret back on `helm install` / `helm upgrade`. A template-only render
(Argo CD, Flux's dry runs, `helm template | kubectl apply`) cannot `lookup`, so
every sync would write **new** random values: a new database password against the
old volume, and a new `encryption-master-key` that makes every stored
integration credential undecryptable. For these tools, set
`platform.generateSecrets: false` and create the Secrets yourself (Sealed
Secrets, SOPS, External Secrets, or `kubectl create secret`). The render then
contains no generated Secret at all, and fails, listing the keys, if you have not
named them.

```yaml
platform:
  generateSecrets: false
  existingSecretName: vista-platform          # jwt-secret, internal-auth-secret, encryption-master-key
  existingDatastoreSecretName: vista-datastores   # postgres-password, redis-password, nats-token
install:
  existingSecretName: vista-install           # install-id, signing-key.pem
  # ...or pin BOTH install.id and install.signingKeyPEM instead (from an encrypted values file)
jwtSigning:
  existingSecretName: vista-jwt-signing       # signing-key.pem (skip if jwtSigning.enabled: false)
cbomSigning:
  existingSecretName: vista-cbom-signing      # signing-key.pem (or pin cbomSigning.keyPEM)
tls:
  mode: certManager                           # or existingSecret; selfSigned is refused (it generates a cert)
```

| Secret | Keys | Value |
|---|---|---|
| `platform.existingSecretName` | `jwt-secret`, `internal-auth-secret`, `encryption-master-key` | 64 random alphanumeric characters each. Add `database-url` / `redis-url` only for an external database or Redis. |
| `platform.existingDatastoreSecretName` | `postgres-password`, `redis-password`, `nats-token` | 32 random alphanumeric characters each. |
| `install.existingSecretName` | `install-id`, `signing-key.pem` | A UUID, and an ECDSA P-256 private key in PEM. On an existing install copy both from the current `<release>-install` Secret. |
| `jwtSigning.existingSecretName` | `signing-key.pem` | An ECDSA P-256 private key in PEM. On an existing install copy it from `<release>-jwt-signing` so live sessions survive. |
| `cbomSigning.existingSecretName` | `signing-key.pem` | An Ed25519 private key as a PKCS#8 PEM. On an existing install copy it from `<release>-cbom-signing` so artifact signatures keep their key id. |

To adopt an existing release, copy the values out of the Secrets the chart
created (`kubectl get secret <release>-generated -o yaml`, and the `-platform`,
`-install`, `-jwt-signing` siblings) into your own Secrets **before** switching
the flag; the chart-created Secrets carry `helm.sh/resource-policy: keep`, so
they are not deleted when they leave the render.

Keep `generateSecrets: true` for plain `helm install` / `helm upgrade`.

**Migration Jobs.** The `schema-migration` and `rls-roles` Jobs have no
`ttlSecondsAfterFinished`, so a controller never sees them disappear and
re-apply them. Their names embed a hash of the rendered pod template: the same
chart and values render the same Job, and a schema or chart change renders a new
one. At most one finished Job of each kind is kept; the next change renames it
and Helm (or Argo CD / Flux with pruning enabled) deletes the superseded one.
The `seed-data` Job is a Helm hook (post-install/post-upgrade) and is cleaned up
as one.

## Upgrading

**From the admin console.** The usual way to back up and update is the console's
**Maintenance** section: **Backups → Create backup** first, then
**About & Updates → Update**. See
[Maintenance in the admin console](../maintenance.md). Installs managed by
Argo CD or Flux are updated from the values repository instead (the console says
so), and the manual Helm procedure below always works and is the fallback.

`ENCRYPTION_MASTER_KEY` encrypts stored integration credentials — see
[Secrets Management](../security/secrets-management.md). The chart reads the
existing Secret back on upgrade rather than generating a new one.

**Use `--reset-then-reuse-values` for a cross-version upgrade, not
`--reuse-values`.** `--reuse-values` carries every previous release's
user-supplied value forward verbatim — including any per-service
`backends.<svc>.image.tag` override you set for a one-off hotfix — which then
silently pins that service to the OLD image even though the chart version (and
every other service) moved forward. `helm upgrade` reports success either way.
`--reset-then-reuse-values` resets to the new chart's defaults first, then
reapplies only the values you still have set in your `-f`/`--set` flags, which
is what you want when moving to a new chart version. Reserve plain
`--reuse-values` for a same-version re-run (e.g. rolling a single service's tag
by hand). The chart's `NOTES.txt` repeats this on every `helm upgrade`.

**Back up before every upgrade.** The chart re-applies `scripts/database/schema.sql`
on every `helm upgrade`; `NOTES.txt` reminds you of this on every run. Use
**Maintenance → Backups → Create backup** in the admin console, or `pg_dump`
yourself; the console's update takes a backup automatically as its first step.

### The cache server changed from Redis to Valkey

Releases up to 5.0.0 shipped Redis (`redis:7-alpine` in the chart). Later releases ship
**Valkey 8** (`valkey/valkey`, BSD-3-Clause), a Redis-protocol drop-in. The values key
(`datastores.redis`), the `redis` Service, the `redis-password` / `redis-url` secret keys
and the `REDIS_URL` variable are unchanged, so your values file needs no edit.

Valkey cannot read the files Redis 7.4 wrote (RDB format 12; it stops with
`Can't handle RDB format version 12`). So the chart gives Valkey its own files on the
same volume (`valkey-dump.rdb`, `valkey-appendonlydir/`) and **the cache starts empty on
the first upgrade**. The Redis files stay where they are, untouched, so a
`helm rollback` to the previous chart finds them again.

Redis holds caches and short-lived state, not records — inventory, users, sessions'
refresh tokens and jobs are all in PostgreSQL. After the upgrade:

- pending password-reset and email-verification links stop working (request new ones),
  and SSO or login flows in progress must be restarted;
- rate-limit and login-throttle counters start from zero (account lockout lives in
  PostgreSQL and still applies);
- **token revocations from the last access-token lifetime are forgotten.** Logging out,
  changing or resetting a password, revoking a session, deactivating or erasing a user,
  and ending an impersonation all revoke access tokens in the cache. A token revoked in
  the hour before the upgrade (`JWT_EXPIRY`, default `1h`) is accepted again until it
  expires. Refresh tokens are revoked in PostgreSQL and stay revoked, so no new access
  token can be minted. If this matters, upgrade at least one access-token lifetime after
  the last such action.

`--reuse-values` keeps the previous chart's defaults, so it would leave you on
`redis:7-alpine`: use `--reset-then-reuse-values` (above). If you set
`datastores.redis.image` yourself (a mirror, for example), point it at a Valkey 8 image.
An external Redis-protocol server (`datastores.redis.enabled: false`) is not affected.

### Single-node clusters

A default `helm upgrade` rolls every backend with a rolling-update strategy, so
old and new pods briefly coexist — on a one-node cluster that can surge pod CPU
*requests* past what the node has to give, which can leave a recreated
`postgres-0` unable to schedule and every backend's init container hanging
waiting on it. Size the node for roughly double your steady-state CPU request
during upgrades, or set `strategy: Recreate` on the backends you can afford
brief downtime on (the chart already does this for `pcap-processor`). A wedged
upgrade recovers with `helm rollback`.

**Switching a backend that is already deployed to `Recreate` needs one extra
step under Helm's server-side apply** (the default in Helm 4). Kubernetes filled
in `rollingUpdate: {maxSurge: 25%, maxUnavailable: 25%}` when the Deployment was
created; server-side apply leaves a field it never set in place, so the
upgrade that sets `strategy: Recreate` fails with
`spec.strategy.rollingUpdate: Forbidden: may not be specified when strategy
type is 'Recreate'` — and the whole upgrade stops there. Clear the field
first, once per backend, then run the upgrade:

```bash
kubectl -n <namespace> patch deployment <backend> --type=merge \
  -p '{"spec":{"strategy":{"type":"Recreate","rollingUpdate":null}}}'
```

The patch does not restart anything, since the strategy is not part of the pod
template. Helm 3's client-side apply clears the field without the patch. It is
only needed when you move a live backend to `Recreate`, not on a fresh install.

## Common Issues

### Pods not starting

- Check logs: `kubectl -n vista logs deployment/<service>`
- Verify the chart's prerequisites (cert-manager, Reloader, a StorageClass) are
  actually installed and healthy
- Check `kubectl -n vista get pvc` for volumes stuck `Pending`

### Database connection errors

- Verify `kubectl -n vista get pods` shows `postgres-0` `Running`/`Ready`
- Check `datastores.postgres.tls.enabled` matches whether `serviceMtls.enabled`
  is on — the datastore TLS toggles require the mesh toggle
- Check firewall/security-group rules if using a managed PostgreSQL instead of
  the chart's in-cluster instance — set `datastores.postgres.enabled: false`
  and provide a `database-url` key in your platform secret, per the comments
  above the `datastores:` block in `values.yaml`

### PostgreSQL JIT (your own or a managed PostgreSQL)

PostgreSQL's just-in-time (JIT) compiler speeds up long analytical queries and
slows down short ones. Vista Platform's tables are split into partitions, so
even a simple lookup builds a large query plan, and with JIT on the compile time
can dwarf the work itself (the same query went from tens of seconds to about a
tenth of a second with JIT off). The platform therefore asks for `jit=off` on
every connection it opens. Nothing needs to be configured for this, and your
other databases and applications on the same server are not affected.

- To keep your server's own JIT setting instead, set `appConfig.dbJit: true` in
  your values. It is one value for every backend service (the chart passes it
  to them as the `DB_JIT` environment variable), and the backends restart on
  the upgrade that changes it. A `DB_JIT` entry under `backends.<service>.extraEnv` overrides it for that
  one service.
- If a connection pooler such as PgBouncer sits between the platform and
  PostgreSQL and rejects the connection with `unsupported startup parameter:
  jit`, either add `jit` to the pooler's `ignore_startup_parameters` setting, or
  set `appConfig.dbJit: true` and set `jit = off` for the platform's database or
  role on the PostgreSQL side (`ALTER DATABASE crypto_inventory SET jit = off;`).
  Running behind a pooler or a managed database proxy is described here but is
  not something the project tests.

### Frontend not loading

- Verify `tls.dnsName` / `tls.adminDnsName` resolve to your ingress controller
- Check the Traefik `IngressRoute`/`Middleware` resources the chart created:
  `kubectl -n vista get ingressroute,middleware`
- Check browser console for CORS or certificate errors

## Rollback

```bash
helm rollback vista --namespace vista
```

Restore your `pg_dump` backup if the upgrade already wrote schema changes you
need to undo — `helm rollback` reverts the release's Kubernetes objects, not
data already written to the database.

Restore a whole dump (schema and data) into an empty database. If you restore
**data only** into a database that already has the schema, pass
`pg_restore --data-only --disable-triggers`: without it, the triggers that
tell shipped catalogue content from your own mark every restored shipped
framework, control and rule as **Custom**, and upgrades stop keeping them
current (see [Shipped content and upgrades](../catalogs.md#shipped-content-and-upgrades)).

## Related Documentation

- [Database Migrations](./database-migrations.md) — the schema-apply model (no migration runner)
- [Startup and Shutdown Procedures](../startup-shutdown.md) — service lifecycle management
- [Notification Provider Integration Guide](../operations/notification-providers.md) — third-party integration setup
- [Container Runtime Images](../container-runtime-images.md) — every image this deployment runs
