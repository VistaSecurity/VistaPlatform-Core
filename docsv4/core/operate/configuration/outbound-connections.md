---
render_macros: false
---

# Outbound connections: proxies, egress policy and private endpoints

Several Vista Platform services call systems **outside the cluster** that a
tenant or an operator configured: webhook, Slack and PagerDuty receivers, mail
relays, vendor and cloud APIs, and — in Enterprise — a tenant's NetBox, CMDB or
SIEM collector, and the model provider. This page covers the four things an operator decides about
that traffic:

1. whether it goes through an **egress proxy** (`HTTPS_PROXY`);
2. whether a **NetworkPolicy** restricts it (`networkPolicy.egressEnabled`);
3. whether a connection may reach a **private address** on your own network;
4. which **certificate authorities** a connection trusts.

## Which services dial out

| Service | What it reaches |
|---|---|
| `notification-service` | Webhook, Slack, PagerDuty and SMTP delivery |
| `monitoring-service`, `auth-service`, `admin-service` | SMTP; `admin-service` also fetches the catalogue feeds and delivers licence reports |
| `device-interrogation-service`, `sensor-manager`, `cluster-sensor-service` | Device management APIs and active probes on your networks |
| `inventory-service` | Enterprise: the tenant's CMDB connectors |
| `audit-service` | S3 archival of expired audit logs, when configured |
| `compliance-engine`, `cbom-service` | Enterprise: the configured [model provider](ai-provider.md) — framework authoring and remediation drafts, and the CBOM comparison narrative. `inventory-service` and `admin-service`, the other two AI callers, reach it too. |


This is the chart's `networkPolicy.externalEgressBackends` list. Every one of
these opens its connection **from its own pod** — there is no central egress
pod — so proxy settings and policy exceptions have to apply to each service
that needs them.

## Behind an egress proxy

The services honour the standard `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY`
variables. Set them per service with `extraEnv`:

```yaml
backends:
  inventory-service:
    extraEnv:
      - name: HTTPS_PROXY
        value: http://proxy.corp.example:3128
      - name: NO_PROXY
        value: localhost,127.0.0.1,.svc,.cluster.local,10.42.0.0/16,10.43.0.0/16
```

**`NO_PROXY` must cover everything inside the cluster**: the `.svc` /
`.cluster.local` names and your pod and Service CIDRs (the same ranges as
`networkPolicy.clusterInternalCIDRs`). Service-to-service calls use the same
environment, and without those entries they are sent to the proxy.

### How the SSRF guard behaves behind a proxy

Every outbound client that reaches a tenant-configured destination is guarded:
it refuses loopback, link-local (which includes the cloud metadata endpoint
`169.254.169.254`), the platform's own cluster ranges, and — unless the
connection has opted in — private addresses.

With a proxy in the path, the socket the service opens is to the **proxy**, so
the guard judges the **destination of each request** instead: the host in the
URL, resolved by the service. The proxy address itself is trusted, because you
configured it. Redirects are judged again at every hop.

What the service cannot see is what the **proxy** resolves a name to. Two
consequences, stated plainly:

- A name that resolves differently for the proxy than for the service
  (split-horizon DNS, or a record that changes between the two lookups) is
  outside what the platform can check.
- If the service **cannot resolve** a name at all — normal in a cluster where
  only the proxy has external DNS — the request is handed to the proxy rather
  than refused. IP literals, and names such as `localhost`,
  `metadata.google.internal` and `*.svc.cluster.local`, are refused without
  any lookup.

So **configure your proxy to refuse internal destinations** as well: loopback,
`169.254.0.0/16`, your cluster's pod and Service CIDRs, and any network the
platform should never reach. That ACL is the control that closes the gap above.

### A proxy that re-signs TLS

If the proxy intercepts TLS, the services must trust the proxy's CA for every
destination. Mount a bundle and point `SSL_CERT_FILE` at it, per
[Running with an internal CA](../security/internal-ca.md). `SSL_CERT_FILE`
**replaces** the image's trust store, so the bundle must include the public
roots too. (This is a platform-wide setting; the per-connection CA bundles
below are for one receiver and are added to the trust store, not substituted.)

## Restricting egress with NetworkPolicy

With `networkPolicy.egressEnabled: true` the chart denies egress by default and
lets only the services in `externalEgressBackends` leave the cluster, to any
address **except** `networkPolicy.clusterInternalCIDRs` and link-local. Set
`clusterInternalCIDRs` to your cluster's pod and Service CIDRs first — the
chart refuses to render without them. See the comments on `networkPolicy` in
the chart's `values.yaml` for the port list and per-distribution defaults.

If your **proxy runs inside the cluster**, it sits in one of those excepted
ranges, so the chart's rule does not reach it. NetworkPolicies are additive:
add one of your own that lets the dialling services reach the proxy.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-to-proxy
  namespace: vista            # your release namespace
spec:
  podSelector:
    matchExpressions:
      - key: app.kubernetes.io/component
        operator: In
        values: [notification-service, inventory-service, audit-service]
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: egress-proxy }
      ports:
        - { protocol: TCP, port: 3128 }
```

## Private endpoints

A connector whose target is on-premises by nature may be allowed to reach a
private address (RFC 1918, `100.64.0.0/10`, IPv6 ULA) — a per-connection
setting the tenant turns on, recorded in the audit log.

That setting never opens:

- loopback, the unspecified address, link-local and the cloud metadata
  endpoints, and multicast;
- the platform's own cluster ranges. The chart passes
  `networkPolicy.clusterInternalCIDRs` as `VISTA_PLATFORM_INTERNAL_CIDRS` to
  the services that dial private targets — `device-interrogation-service`
  and `inventory-service` (CMDB connectors), and any backend whose
  values entry sets `privateNetworkDialer: true` — whether or not
  `egressEnabled` is on, and refuses to render if you try to override it with
  `extraEnv`. A malformed value makes those services refuse every outbound
  connection rather than ignore it. So set `clusterInternalCIDRs` to your
  cluster's real ranges even if you never enable the egress NetworkPolicy.

An operator can forbid private targets for the whole deployment with
`CONNECTOR_ALLOW_PRIVATE_ENDPOINTS=false` (via `extraEnv` on the services
concerned). The operator's setting wins over the tenant's.

## Certificate authorities for integrations

Outbound connections verify TLS against the image's trust store. A receiver
whose certificate your **own CA** issued — an on-premises NetBox, CMDB or SIEM
collector — would fail that check, so a connection can carry a **custom CA
bundle**: one or more PEM `CERTIFICATE` blocks that are **added** to the trust
store for that connection only.

- It is checked when the connection is saved: text that is not PEM, text after
  the last certificate, or anything other than a certificate is refused with a
  message saying which. A **private key** pasted by mistake is refused
  outright; it would otherwise be stored in a non-secret field.
- A CA certificate is public, so it is shown again on the edit form.

**There is no "skip certificate verification" option, deliberately.** The only
legitimate reason to want one is a receiver signed by a CA the platform does
not trust, and a CA bundle fixes exactly that while keeping verification on. A
connection that verifies nothing sends its API token, or a stream of audit
events, to whoever is in the network path.


Webhook, Slack and PagerDuty delivery reach public endpoints only and use the
image's trust store. All of these outbound clients honour the egress proxy.
