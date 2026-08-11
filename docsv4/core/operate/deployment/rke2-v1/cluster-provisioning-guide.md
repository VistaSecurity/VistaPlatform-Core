---
render_macros: false
---

# Vista — RKE2 Cluster Provisioning Guide

Audience: platform engineers who need to stand up a new RKE2 cluster before installing Vista.

> **Status: stub — full walkthrough coming soon.**
> Contact your VistaSecurity representative to request the current version of this guide or access to the provisioning helper script.

---

## Overview

If you do not already have an RKE2 cluster, Vista provides two resources to help you provision one:

| Resource | Purpose |
|---|---|
| `scripts/install-rke2-server.sh` | Helper script — provisions a CIS-hardened RKE2 server on the local Linux node in a single command |
| `config/rke2/cluster-config.yaml.example` | Reference cluster config — includes the CIS profile, audit logging, and Vista-required settings pre-configured |

These are included in the Vista delivery package. Request them from your VistaSecurity contact if they were not included in your license bundle.

---

## What the helper script does

`scripts/install-rke2-server.sh` automates the following steps:

1. Copies `config/rke2/cluster-config.yaml.example` → `/etc/rancher/rke2/config.yaml` (only if no existing config is present)
2. Runs the official RKE2 install script from `https://get.rke2.io`
3. Enables and starts `rke2-server`
4. Symlinks the RKE2-bundled `kubectl` into `/usr/local/bin`
5. Configures `KUBECONFIG` for the invoking user

The reference config includes `profile: cis`, audit logging, `disable: [rke2-ingress-nginx]`, and correct kubeconfig permissions out of the box — no manual CIS retrofit required after install. You still need to install Traefik separately (see deployment-guide §3.5) since the reference config disables RKE2's bundled nginx ingress.

### Prerequisites

- Linux node (Ubuntu 20.04+, Debian 11+, or RHEL/Rocky 8+)
- `sudo` access
- Outbound internet access (to pull RKE2 installer and container images)
- The required CIS system users created before running the script:

```bash
sudo useradd -r -c "kube-apiserver user" -s /sbin/nologin -M kube-apiserver
sudo useradd -r -c "etcd user" -s /sbin/nologin -M etcd
```

### Usage

```bash
# From the Vista delivery package root:
./scripts/install-rke2-server.sh
```

---

## After provisioning

Once the script completes and all nodes are `Ready`, return to the main [RKE2 Deployment Guide](./deployment-guide.md) and start at **§3.5 Install Traefik ingress controller**. The CIS profile, audit logging, and nginx-disable covered in §3 are already configured by the provisioning script. You **must** still run §3.5 — the reference config disables RKE2's bundled ingress, so the cluster has no ingress controller until you install Traefik.

---

## TODO — Full walkthrough (coming soon)

- [ ] Multi-node cluster setup (master + worker join procedure)
- [ ] Customising `cluster-config.yaml.example` for your environment (TLS SANs, CNI selection, node taints)
- [ ] Air-gapped / offline install path
- [ ] Verifying CIS compliance after install (`kube-bench`)
- [ ] Adding worker nodes to an existing cluster
