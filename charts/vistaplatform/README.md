# vistaplatform

Vista cryptographic asset inventory and compliance platform — Helm chart for RKE2 / Kubernetes.

This chart is delivered to Core users as a signed OCI artifact at `oci://ghcr.io/vistasecurity/vistaplatform` (commercial customers pull the same chart shape from `oci://docker.io/vistasecurity/vistaplatform`). The customer-facing install walkthrough is `INSTALL.md` at the repository root; internal service-mesh mTLS staging detail is at `docsv4/core/operate/security/service-mesh-mtls.md`. **If you're installing this chart, start there**, not here.

## Quick install

```bash
helm install vistaplatform \
  oci://docker.io/vistasecurity/vistaplatform \
  --version <version> \
  -f values-ha.yaml \
  -f values-customer.yaml \
  -n vistaplatform --create-namespace --wait
```

Replace `<version>` with the release tag (e.g. `2.4.1`). Cosign-verify before installing — see "Verifying chart authenticity" below.

## Profile overlays

| File | Use |
|---|---|
| `values.yaml` | Sensible defaults; do not edit. |
| `values-ha.yaml` | Recommended overlay for multi-worker clusters. `replicas: 2` on stateless workloads, `podAntiAffinity` to spread across nodes, PDBs engaged. |
| `values-minimal.yaml` | Single-replica everything. For lab / single-worker clusters. |

Apply one of the two overlays alongside your customer values:

```bash
helm install ... -f values-ha.yaml -f values-customer.yaml
```

## Required customer values

All required fields are validated by `values.schema.json` at parse time. Minimum:

- `tls.dnsName` — external hostname for the install
- `tls.issuerRef.name` — cert-manager Issuer / ClusterIssuer (when `tls.mode: certManager`, the default)
- `license.existingSecretName` — Secret holding the JWT (default `vistaplatform-license`). Optional: without it the install runs as Core.

The chart also creates `<fullname>-install` (for release `vista`,
`vista-vistaplatform-install`), a Secret holding this install's identity
(`install-id`, a UUID generated once and kept across upgrades and uninstalls).
admin-service records it in the database on first boot, and from then on the
database copy is authoritative — it logs the id in use at every start
(`[edition] this install's id: …`). An MSP licence is issued for that id.
**GitOps (ArgoCD, Flux, `helm template`) users must set `install.id`**: those
renders cannot `lookup` the existing Secret and would otherwise write a new id
on every sync (admin-service keeps the database id and warns). When set,
`install.id` is used verbatim.
The same Secret holds `signing-key.pem`, the install's ECDSA P-256 signing
key: on an MSP licence admin-service signs every licence usage report with it,
and Vista Security's receiver pins the first key it sees, so it is generated
once and kept exactly like the id. GitOps users set `install.signingKeyPEM`
too (from an encrypted values file). **MSP installs: set `licensing.reports.persistence.enabled=true`** to
write a copy of each report to a `<fullname>-license-reports` PVC (off by
default, since only an MSP licence produces reports and the chart cannot know
the edition; 1Gi, ReadWriteOnce — which makes admin-service single-replica
with a no-surge rolling update, `maxSurge: 0` / `maxUnavailable: 1`; use
ReadWriteMany for more replicas). Off, reports live in the database only.
**Automatic report delivery** is off until you set
`licensing.reporting.endpoint` to the https:// receiver URL Vista Security
gives you: admin-service then POSTs each complete monthly report to
`<endpoint>/v1/usage-reports` (checking every `licensing.reporting.intervalMinutes`,
default 60; failures back off from 1h to 24h per report). It uses the system
trust store and honours `HTTPS_PROXY` / `NO_PROXY`; behind an egress proxy,
give admin-service those through `backends.admin-service.extraEnv` (and, if
the proxy re-signs TLS, mount a CA bundle with `extraVolumes`/`extraVolumeMounts`
and point `SSL_CERT_FILE` at it — the bundle replaces the system one, so
include the public roots). Air-gapped installs leave the endpoint empty and
upload the downloaded report instead.
- Either `platform.existingSecretName` OR all three of `platform.{jwtSecret,internalAuthSecret,encryptionMasterKey}`

See `examples/values-customer.yaml.example` (bundled with this chart) for the full annotated starter. After `helm pull --untar`, copy it into your own infrastructure repo, edit, and apply with `-f`.

## What the chart deploys

- 16 Go backend services (auth, inventory, compliance, etc.)
- 2 React frontends (web-ui for tenants, admin-ui for platform admins)
- Traefik `IngressRoute` + `Middleware` CRDs consumed by the cluster's own
  Traefik (kube-system on RKE2, ALB+Traefik on EKS). No in-cluster gateway pod.
- 4 datastores (Postgres, Redis, InfluxDB, NATS JetStream)
- NetworkPolicies, schema-migration Job, helm-test smoke check
- Hardened pod security defaults (non-root, read-only FS, dropped caps, RuntimeDefault seccomp, no SA token mount)

Resource counts by HA / minimal profile — see `values-ha.yaml` / `values-minimal.yaml` in this directory.

## v1 limitations to flag with customers

- **Datastores are single-replica** even in HA mode. True datastore HA needs operators (CloudNativePG, NATS clustering) or external managed services. v1.x roadmap.
- **`pcap-processor` and `sensor-manager` are pinned to `replicas: 1`** even in HA mode. They share a `ReadWriteOnce` PVC for PCAP file handoff between sensor-manager (writer) and pcap-processor (reader). Scaling either to 2 results in a `MultiAttach` error and the new pod stays Pending. Roadmap: object-storage-backed handoff (S3 or in-cluster MinIO) so both services can scale independently.
- **No air-gap support in v1.** All image pulls go through AWS ECR. If a customer needs offline install, that's a separate engagement.

## Verifying chart authenticity (customer instructions)

Every release is keyless-signed with cosign via GitHub OIDC + Fulcio + Rekor.
Verify before installing — copy-pasteable against any published release:

Because signing is keyless, the identity *is* the release workflow — so both
the registry and the identity differ between the Core and commercial lines.
`helm install` prints the correct command for the artifact you actually have
(NOTES.txt renders it from `image.registry`, `image.repoPrefix` and
`verification.certificateIdentityRegexp`). Prefer that over copying from here.

The Core form:

```bash
# Verify the Helm chart itself
cosign verify ghcr.io/vistasecurity/vistaplatform:<version> \
  --certificate-identity-regexp 'https://github.com/VistaSecurity/VistaPlatform-Core/.github/workflows/release-core.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Verify an individual service image (same identity, different repo)
cosign verify ghcr.io/vistasecurity/auth-service:<version> \
  --certificate-identity-regexp 'https://github.com/VistaSecurity/VistaPlatform-Core/.github/workflows/release-core.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Replace `<version>` with the release tag (e.g. `v0.2.0`). Substitute any of the
published images for `auth-service` — the same identity regex matches all of
them because every image is signed by the same release workflow. Commercial
builds are signed by a different workflow and published to `docker.io`; take
that command from the `helm install` output.

## For chart maintainers (internal)

- `templates/_helpers.tpl` — common labels, securityContext, image helper, podAntiAffinity helper, TLS validator.
- `templates/backend/_deployment.tpl` — single named template that produces every backend Deployment + Service + PDB. The `backends:` map in values.yaml is the source of truth — adding/removing a service is a values edit, not a template edit.
- `templates/networkpolicy/allow-rules.yaml` — emits egress rules from the same `backends.<name>.needs` map. If you change a service's datastore deps, edit values, not the policy template.
- `templates/secrets-generated.yaml` — `lookup` + `randAlphaNum` with `helm.sh/resource-policy: keep`. Deliberately not a Helm hook (hooks aren't visible to `lookup` on subsequent upgrades).
- `templates/ingress/{middlewares,ingressroutes}.yaml` — generated from `standards/service-registry.yaml` by `make generate-k8s-ingress` (also wired into `make generate`). **Re-run before tagging a release** if the registry has changed.
- `files/schema/schema.sql` — copied from `scripts/database/schema.sql` at chart-package time. The release workflow handles this; if you `helm package` manually, copy it first.

To validate locally:

```bash
docker run --rm -v "$PWD/charts:/charts:ro" alpine/helm:3.16.3 \
  template t /charts/vistaplatform \
    -f /charts/vistaplatform/values-ha.yaml \
    --set tls.dnsName=test.example.com \
    --set tls.issuerRef.name=test-issuer \
    --set platform.jwtSecret=j --set platform.internalAuthSecret=i --set platform.encryptionMasterKey=e
```

`helm lint` should pass with only the cosmetic icon-recommended info note.
