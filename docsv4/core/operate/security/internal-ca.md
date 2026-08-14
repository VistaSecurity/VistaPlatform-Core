---
render_macros: false
---

# Running with an internal CA

If your edge certificate (`tls.dnsName` / `tls.adminDnsName`) is issued by a
private or corporate CA rather than a public one, anything **inside** the
cluster that calls the edge hostname over HTTPS fails TLS verification. A pod
carries only the base image's public CA bundle — it does not inherit the
node's OS trust store, so the fact that your laptop or a cluster node already
trusts that CA proves nothing about what a pod trusts.

This is separate from [service-mesh mTLS](service-mesh-mtls.md), which already
handles service-to-service, Postgres, and NATS traffic with its own
cert-manager-provisioned Platform CA. The gap this page covers is narrower:
anything that calls back out to your **edge** hostname from inside the
cluster.

## Where this actually bites

Today the one place is `monitoring.syntheticChecks` (see
[INSTALL.md](https://github.com/VistaSecurity/VistaPlatform-Core/blob/main/INSTALL.md#run-it)
and the `monitoring:` block in `values.yaml`). Each check is a real HTTPS GET
that monitoring-service issues against your customer-facing URL — DNS,
ingress, TLS, and every middleware in between, the same way a browser would.
Against an internal-CA edge cert, that GET fails certificate verification,
and the only toggle offered for it in `values.yaml` is
`insecureSkipVerify: true` — which turns the check off rather than fixing
what it's checking. For a product built around certificate hygiene, "turn
verification off" cannot be the only documented answer, so here is the
supported one.

## The supported fix: mount your CA into the pod

The chart supports arbitrary extra volumes, mounts, and environment variables
per backend (`values.yaml` → `backends.<service>.extraVolumes` /
`extraVolumeMounts` / `extraEnv`). Combine that with `SSL_CERT_FILE`, which
Go's standard library honors on Linux, and a backend can trust your CA
without any image change.

**1. Build a combined bundle.** Go's cert loader does not merge
`SSL_CERT_FILE` with the image's default trust store — setting it replaces
the default list outright. If you hand it only your internal CA, the pod
loses the ability to verify anything signed by a public CA too (an SMTP
relay, a webhook target, an update check). Concatenate both:

```bash
# The Core runtime images are Alpine-based with ca-certificates installed,
# so their default bundle is /etc/ssl/certs/ca-certificates.crt. Grab a copy
# from any Alpine box (or `docker run --rm <runtime-image> cat
# /etc/ssl/certs/ca-certificates.crt`) and append your CA to it:
cat ca-certificates.crt your-internal-ca.pem > ca-bundle.pem
```

**2. Put it in a ConfigMap in the release namespace:**

```bash
kubectl create configmap internal-ca-bundle \
  --namespace vista \
  --from-file=ca-bundle.pem=./ca-bundle.pem
```

**3. Mount it and point the backend at it**, in your `values.yaml`. Today
that's `monitoring-service`, since that's the only backend calling the edge
by hostname out of the box:

```yaml
backends:
  monitoring-service:
    extraVolumes:
      - name: internal-ca-bundle
        configMap:
          name: internal-ca-bundle
    extraVolumeMounts:
      - name: internal-ca-bundle
        mountPath: /etc/ssl/internal
        readOnly: true
    extraEnv:
      - name: SSL_CERT_FILE
        value: /etc/ssl/internal/ca-bundle.pem
```

**4.** `helm upgrade` with that values file. No `insecureSkipVerify` needed —
the check now verifies your edge cert against a trust store that actually
includes the CA that issued it.

This has been verified against the chart with `helm template`: the volume,
the mount, and `SSL_CERT_FILE` all render correctly onto the
`monitoring-service` Deployment with the overlay above. It has not been
verified against a live install — a real internal CA and a syntheticChecks
target were not available to test end to end, so treat "the config is
correct" as proven and "the probe goes green against your CA" as expected but
unconfirmed until you try it.

## What `insecureSkipVerify` is actually for

`monitoring.syntheticChecks[].insecureSkipVerify` skips TLS verification for
that one probe only. It predates the CA-mount option above and exists because
a throwaway cluster needs *something* that works without a CA-provisioning
step.

- **Acceptable**: a lab or evaluation cluster where you already click through
  the browser's certificate warning yourself, and the synthetic check exists
  only to keep the dashboard from showing a spurious "down."
- **Not acceptable** on anything you'd call real: it silently disables the
  one check in the product whose entire job is to catch a broken or
  misconfigured edge — which is exactly the failure class an internal-CA
  mismatch is. Use the CA mount instead.

## If you add another backend that calls your own edge hostname

The same recipe applies to any backend, integration, or webhook target that
calls back into your edge hostname from inside the cluster: mount the CA via
that backend's `extraVolumes` / `extraVolumeMounts`, and point it at the
bundle with `SSL_CERT_FILE` via `extraEnv`. `SSL_CERT_FILE` is a Go/OpenSSL
convention honored by every Go service in this chart on Linux — it is not a
chart-specific mechanism, so the same variable works for anything you add
that also happens to be a Go binary.
