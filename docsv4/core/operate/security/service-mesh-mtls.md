---
render_macros: false
---

# Service-mesh mTLS

This covers the chart's in-cluster (service-mesh) mTLS — separate from and
independent of your edge/browser-facing TLS certificate (`tls.mode`,
`tls.dnsName`; see [INSTALL.md](https://github.com/VistaSecurity/VistaPlatform-Core/blob/main/INSTALL.md#run-it)).
It encrypts and mutually authenticates traffic *inside* the cluster — every
service-to-service call, plus the connections to Postgres and NATS — so that a
compromised pod or a network tap inside the cluster cannot read or impersonate
the platform's internal traffic.

If your edge certificate itself is issued by an internal/corporate CA (rather
than a public one), that's a different gap — a pod calling *back out* to your
edge hostname won't trust it either, since pods don't inherit the node's OS
trust store. See [Running with an internal CA](internal-ca.md) for that case.

**This is ON by default.** A stock `helm install` ships encrypted internal
transport. That means the two prerequisites below are **required**, not
optional. The chart validates cert-manager's presence and **fails the install
fast** with a clear message if its CRDs are absent, rather than failing
mysteriously mid-apply.

> **Opting out** (only for a cluster that genuinely cannot provide the
> prerequisites): set **all three** toggles to `false` —
> `serviceMtls.enabled`, `datastores.postgres.tls.enabled`, and
> `datastores.nats.tls.enabled`. The two datastore toggles **require**
> `serviceMtls.enabled`, so a partial opt-out (e.g. serviceMtls off but a
> datastore toggle left on) is rejected at render time. With all three off,
> the chart needs neither cert-manager nor Reloader for the mesh.

## Prerequisites (cluster infrastructure — the chart does not install these)

1. **cert-manager** — issues the per-service certs. See the "Evaluate it" /
   "Run it" prerequisites in
   [INSTALL.md](https://github.com/VistaSecurity/VistaPlatform-Core/blob/main/INSTALL.md).
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

## How the trust works

By default the chart provisions a self-signed **Platform CA** (a cert-manager
`Issuer` + a 10-year CA cert) and issues every service a 90-day cert from it
(`rotationPolicy: Always`, renewed 30 days out). This CA is private to the mesh
— it is unrelated to your edge/browser certificate. The three data-plane
toggles are decoupled so you can roll them out in stages:

```yaml
serviceMtls:
  enabled: true            # HTTP service-to-service mTLS (gateway → backends, and S2S)

datastores:
  postgres:
    tls:
      enabled: true        # Postgres requires TLS; backends connect sslmode=verify-full
  nats:
    tls:
      enabled: true         # NATS requires a client cert (the shared token is retired)
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
> pod template. The `schema-migration` and `rls-roles` Job names embed a hash
> of the rendered pod template, so any pod-template change (TLS toggles, chart
> version bumps) creates a fresh Job instead of colliding with an immutable
> existing one — no manual Job deletion needed.

## Advanced: chain the mesh off your own root

If your security policy forbids *any* self-signed CA, even an internal one,
point the Platform CA at an intermediate issued from your corporate root
instead of the chart's self-signed bootstrap. Provide a Secret containing
`tls.crt` + `tls.key` + `ca.crt`:

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
> `datastores.postgres.enabled: false` (e.g. a managed Postgres) the chart
> can't mint the Postgres server cert. Point
> `serviceMtls.postgres.caSecretName` / `clientCertSecretName` at your
> provider's CA and your client cert, and set `serviceMtls.postgres.mode` to
> match what the managed service enforces (`require` / `verify-ca` /
> `verify-full`).

## Agent and sensor mTLS (`agentMtls`) — ON by default, and a breaking upgrade

This is a **separate** toggle from `serviceMtls`, covering the *outbound* calls
device agents and sensors make into the platform: job polling, result
submission, heartbeats, discovery submission, command polling and certificate
rotation.

With `agentMtls.enabled: false` those routes tolerate a missing client
certificate: the agent/sensor UUID in the URL is the entire credential, so any
caller on the pod network that knows (or guesses from a leaked log line) a UUID
can poll that agent's jobs, submit results in its name, or submit discoveries.
**It now defaults to `true`**, and the backends fail closed: the certificate
issued at registration must reach the service intact, its CN must be the
agent/sensor id, it must chain to that tenant's CA, and it must be that
identity's *current* certificate.

> **Certificate rotation requires the current certificate in every mode**, even
> with `agentMtls.enabled: false`. Rotation mints a new, legitimately CA-signed
> certificate and supersedes the old one, so a path UUID must never be enough to
> obtain it. An agent or sensor that has lost its certificate cannot rotate —
> re-enroll it with a registration key.

### Prerequisites (cluster infrastructure — the chart does not install these)

1. `serviceMtls.enabled: true` (the default). The agent listener reuses the
   per-service mesh certificate as its *server* certificate.
2. A cluster-Traefik **TLS-passthrough** entrypoint on `agentMtls.port`
   (default `8444`). The edge must **not** terminate this traffic, or the
   client certificate never reaches the backend. The chart owns only the
   `IngressRouteTCP`, not Traefik's static entrypoint configuration.
3. A DNS name per backend resolving to that entrypoint, set in values:

   ```yaml
   agentMtls:
     enabled: true
     backends:
       sensor-manager:
         dnsName: sensors.example.com
       device-interrogation-service:
         dnsName: agents.example.com
   ```

   **Both backends need their own hostname.** They share one passthrough
   entrypoint and are told apart by `HostSNI`, so a single name cannot serve
   both. Keep them **distinct from each other** and **distinct from
   `tls.dnsName`** — that host is terminated at the edge.

   The chart **fails the install** rather than open a listener nothing can
   reach. It fails if either hostname is missing, and also if a backend entry
   is **deleted** — removing a key does not opt a service out. The deployment
   template keys `AGENT_MTLS_REQUIRED` off the presence of that entry, so a
   missing key emits no value and the service falls back to its built-in
   default of `true`, demanding a client certificate that no route can
   deliver. To opt out, set `agentMtls.enabled: false`.

   **Dev installs need no DNS entries at all.** The docker-compose path sets
   `AGENT_MTLS_REQUIRED=false` for both services explicitly, so a compose
   developer never provisions a passthrough host or a certificate.

### Migrating an existing install (do this before upgrading)

Agents and sensors enrolled while `agentMtls` was off call the edge host and
hold no usable transport for their certificate. After the upgrade they are
rejected with `401` until migrated.

1. **Inventory what is enrolled.** Discovery → Sensors & Agents lists every
   agent and sensor with its last check-in.
2. **Provision the passthrough entrypoint and DNS** (prerequisites 2 and 3
   above) *before* the upgrade, and verify the host resolves and accepts TCP on
   the port.
3. **Upgrade with the dnsNames set.** Every backend restarts.
4. **Re-point or re-enroll each agent/sensor.** Re-registering with a
   registration key is the reliable path: the registration response hands back
   the client certificate, the Platform CA as server trust anchor, and the
   passthrough URL, which the agent persists and uses from then on.
5. **Confirm.** Each agent/sensor returns to a healthy last-check-in; a failure
   shows as `401` in the `sensor-manager` / `device-interrogation-service` logs
   naming the missing or mismatched certificate.

Staging the upgrade in two steps (mesh first, agents second) keeps the blast
radius small, exactly as with the datastore toggles above.

### Opting out deliberately

```
--set agentMtls.enabled=false
```

This restores the previous, **unauthenticated** agent/sensor surface. The chart
prints a warning in `NOTES.txt` on every install and upgrade while it is off, so
the choice stays visible. Certificate rotation remains refused in this mode.

## Single-node clusters: avoid the rolling-upgrade CPU deadlock

On a one-node cluster, a `helm upgrade` that rolls every service at once
briefly runs old + new pods together, doubling CPU *requests* (the scheduler
packs by requests, not usage). If that exceeds the node's allocatable CPU, the
recreated `postgres-0` can't schedule, the schema migration can't connect, and
the upgrade hangs until it times out. Either size the node for ~2× steady-state
CPU requests before upgrading, or set `strategy: Recreate` on the backends so
pods replace in place without surging (brief per-service downtime). If an
upgrade does wedge, `helm rollback` restores the previous release.

This applies to **config-only upgrades too**, not just version bumps: the pod
templates carry a `checksum/config` hash of the app ConfigMap, so changing any
value that lands there (`tls.dnsName`, `appConfig.*`, …) deliberately rolls
every backend — env vars are injected at pod start only, and without the roll
the running pods would silently keep the old config.
