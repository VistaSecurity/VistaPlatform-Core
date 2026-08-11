---
render_macros: false
---

# Vista RKE2 v1 — Customer Documentation

This bundle accompanies a v1 Vista release for deployment on a customer-managed RKE2 cluster.

## What's in this bundle

| File | Audience | Purpose |
|---|---|---|
| [`pre-flight-checklist.md`](./pre-flight-checklist.md) | Whoever is running the install | Confirms you have every item delivered by VistaSecurity and every workstation/cluster prereq in place before you start |
| [`deployment-guide.md`](./deployment-guide.md) | Platform engineers / SRE | Step-by-step install: prereqs, RKE2 + Traefik + cert-manager prep, registry access, license, helm install, day-2 ops |
| [`cluster-provisioning-guide.md`](./cluster-provisioning-guide.md) | Platform engineers without an existing cluster | Optional helper path for standing up a CIS-hardened RKE2 cluster from scratch before running the deployment guide |
| [`security-overview.md`](./security-overview.md) | Security / GRC team | Architecture, trust boundaries, network flows, secret inventory, hardening posture, threat model |
| [`support-bundle.md`](./support-bundle.md) | Operators | Script + instructions for collecting cluster state to attach to an issue or support request |
| [`values-customer.yaml.example`](../../../../../charts/vistaplatform/examples/values-customer.yaml.example) | Whoever runs `helm install` | Starter values file with annotated required fields |

## Recommended reading order

1. **`security-overview.md`** — get sign-off from your security team before scheduling the install.
2. **`pre-flight-checklist.md`** — confirm every box is checked before you start the install. Items missing here will cause the install to fail mid-way.
3. **`cluster-provisioning-guide.md`** — only if you do not yet have an RKE2 cluster.
4. **`deployment-guide.md`** — work through it in order; nothing in it is optional except where explicitly marked.
5. Keep **`support-bundle.md`** handy for any troubleshooting.
6. Copy **`values-customer.yaml.example`** to `values-customer.yaml`, fill in the marked fields.

## Versions in this bundle

**Latest:** `2.5.2` — released 2026-05-21

| Version | Chart           | Image tag | Released   |
|---------|-----------------|-----------|------------|
| 2.5.2   | vistaplatform-2.5.2 | v2.5.2    | 2026-05-21 |
| 2.4.3   | vistaplatform-2.4.3 | v2.4.3    | 2026-05-17 |
| 2.4.1   | vistaplatform-2.4.1 | v2.4.1    | 2026-05-15 |

The chart version and image tag share the same number for each release — the chart version is bare semver, the image tag has a `v` prefix. Do not mix chart and app versions across a release.

## Support

- General questions: open a [GitHub issue](https://github.com/VistaSecurity/VistaPlatform-Core/issues)
- Email: `product@vistasecurity.io`
- **Security issues — do not open a public issue.** See
  [SECURITY.md](https://github.com/VistaSecurity/VistaPlatform-Core/blob/main/SECURITY.md)
  for the reporting process and response times.

Commercial support with contracted response times is part of the Enterprise and
MSP editions.

When reporting a problem, run the script in `support-bundle.md` and attach the resulting tarball — after reading it, since it comes from a system holding your cryptographic inventory.
