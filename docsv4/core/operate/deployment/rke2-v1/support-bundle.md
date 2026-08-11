---
render_macros: false
---

# Vista Support Bundle

When opening a support ticket with VistaSecurity, attaching a support bundle saves a round-trip. The bundle captures cluster state without including application logs (which may contain customer data); attach logs separately if support requests them.

## Quick collection

Save this script as `vistaplatform-support.sh` on your operator workstation:

```bash
#!/usr/bin/env bash
set -e
NS="${1:-vistaplatform}"
OUT="vistaplatform-support-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

echo "Collecting cluster context..."
kubectl version > "$OUT/kubectl-version.txt" 2>&1 || true
kubectl get nodes -o wide > "$OUT/nodes.txt" 2>&1
kubectl get nodes -o yaml > "$OUT/nodes.yaml" 2>&1

echo "Collecting helm state..."
helm version > "$OUT/helm-version.txt" 2>&1 || true
helm list -n "$NS" -a > "$OUT/helm-list.txt" 2>&1
helm status vistaplatform -n "$NS" > "$OUT/helm-status.txt" 2>&1 || true
helm history vistaplatform -n "$NS" > "$OUT/helm-history.txt" 2>&1 || true
helm get values vistaplatform -n "$NS" > "$OUT/helm-values.txt" 2>&1 || true
helm get manifest vistaplatform -n "$NS" > "$OUT/helm-manifest.yaml" 2>&1 || true

echo "Collecting workload state in namespace $NS..."
kubectl -n "$NS" get all,pvc,secret,configmap,networkpolicy,ingress,ingressroute -o wide \
  > "$OUT/all-resources.txt" 2>&1 || true
kubectl -n "$NS" get pods -o wide > "$OUT/pods.txt" 2>&1
kubectl -n "$NS" get pods -o yaml > "$OUT/pods.yaml" 2>&1
kubectl -n "$NS" get events --sort-by=.lastTimestamp > "$OUT/events.txt" 2>&1
kubectl -n "$NS" get networkpolicies -o yaml > "$OUT/networkpolicies.yaml" 2>&1

echo "Describing failing pods..."
mkdir -p "$OUT/failing-pods"
kubectl -n "$NS" get pods --field-selector=status.phase!=Running -o name 2>&1 | \
  while read -r pod; do
    name="${pod#pod/}"
    kubectl -n "$NS" describe "$pod" > "$OUT/failing-pods/${name}-describe.txt" 2>&1 || true
  done

echo "Collecting cert-manager state..."
kubectl get clusterissuers -o yaml > "$OUT/clusterissuers.yaml" 2>&1 || true
kubectl -n "$NS" get certificate,certificaterequest,order,challenge -o yaml \
  > "$OUT/cert-manager-resources.yaml" 2>&1 || true

# Redact known sensitive keys from helm-values
sed -i 's/\(jwtSecret\|internalAuthSecret\|encryptionMasterKey\): .*/\1: REDACTED/g' \
  "$OUT/helm-values.txt" 2>/dev/null || true

tar czf "${OUT}.tar.gz" "$OUT" && rm -rf "$OUT"
echo "Bundle: ${OUT}.tar.gz"
echo "Note: this bundle does NOT include pod logs. If support requests logs,"
echo "run kubectl logs separately and review for sensitive content first."
```

```bash
chmod +x vistaplatform-support.sh
./vistaplatform-support.sh vistaplatform
```

## What the bundle contains

- Cluster + helm versions
- Node list and full node spec (helps support match Kubernetes / RKE2 versions)
- Full helm release state: status, history, manifest, values (with platform secrets redacted)
- All workload resources in the Vista namespace
- Recent K8s events (sorted oldest-first within the recent window)
- `describe` output for any pod not in `Running` phase
- cert-manager Issuer / Certificate / Challenge state (frequent source of "TLS not ready" tickets)

## What the bundle does NOT contain

- **Application logs.** They may contain customer data. If support asks for logs, collect them with `kubectl -n vistaplatform logs deploy/<service> --previous` (or without `--previous` for current pod), review the output, and attach separately.
- **The license JWT.** It's mounted into pods as a file but not captured by `kubectl describe`.
- **Platform secret values.** Redacted from `helm-values.txt`.
- **Datastore contents.** No `pg_dump`, no Redis state, no InfluxDB data. If a ticket needs data, support will guide you on dump-and-share.

## Sending the bundle

A support bundle contains configuration and logs from your deployment. **Read it
before you send it anywhere** — it is drawn from a system holding your
cryptographic inventory, and what is safe to share depends on your environment,
not on ours.

For a Core deployment there is no support ticket queue: attach the bundle to a
[GitHub issue](https://github.com/VistaSecurity/VistaPlatform-Core/issues) only if you
are satisfied it carries nothing sensitive. If the bundle is relevant to a
security report, follow
[SECURITY.md](https://github.com/VistaSecurity/VistaPlatform-Core/blob/main/SECURITY.md)
instead and ask for an encryption key in a first message containing no details.

Enterprise and MSP customers send bundles through their support channel.
