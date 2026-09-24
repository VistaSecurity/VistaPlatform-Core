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
  with a clear error if its CRDs are absent. Only optional if you turn all three
  of `serviceMtls.enabled`, `datastores.postgres.tls.enabled` and
  `datastores.nats.tls.enabled` off — not recommended for a real deployment.
- **Stakater Reloader** — required whenever `serviceMtls` is on (the default). It
  restarts pods when a certificate rotates. Nothing fails at install time
  without it; internal mTLS quietly breaks at the first renewal, ~60 days in.
- **Traefik**, with its CRDs. The chart creates `IngressRoute` and `Middleware`
  *resources*; it does not install the controller or the CRDs that define them.
- **A StorageClass** for the PostgreSQL, InfluxDB, and upload volumes.

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
- [ ] Create `platform.existingSecretName` yourself, out of band, and name it in
      values — otherwise the chart generates platform secrets on first install
      and keeps them. Either way, treat `ENCRYPTION_MASTER_KEY` the way you'd
      treat a database encryption key: if it changes, every stored integration
      credential encrypted under the old key becomes permanently undecryptable.
      The chart reads the existing Secret back on upgrade rather than
      regenerating it, but only if you haven't overridden that behavior.
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
```

There is no separate "start infrastructure, then services, then gateway"
sequence to run by hand — `helm install` reconciles everything (Postgres,
Redis, NATS, InfluxDB, every backend, both frontends, and the schema-migration
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

## Upgrading

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

**`pg_dump` before every upgrade.** The chart re-applies `scripts/database/schema.sql`
on every `helm upgrade`; `NOTES.txt` reminds you of this on every run. There is
no backup tooling shipped with the chart.

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
