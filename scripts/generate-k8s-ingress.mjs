#!/usr/bin/env node
// Generate Kubernetes Traefik CRDs (Middleware + IngressRoute) for the
// VistaPlatform Helm chart from standards/service-registry.yaml.
//
// Replaces the bundled api-gateway Traefik (charts/vistaplatform/files/gateway/)
// and the hand-written charts/vistaplatform/templates/gateway/ingressroute.yaml.
// In k8s deployments the cluster's own Traefik (kube-system on RKE2, ALB +
// Traefik on EKS, etc.) does all routing — no inner gateway pod.
//
// Outputs:
//   charts/vistaplatform/templates/ingress/middlewares.yaml
//   charts/vistaplatform/templates/ingress/ingressroutes.yaml
//
// Both files are Helm templates: hostname, TLS secret, labels, and the
// release namespace are interpolated at install time via `.Values` / Helm
// built-ins. Everything else (routes, route prefixes, rate-limit thresholds,
// circuit-breaker expressions) is baked in from the registry at generate
// time and is committed to git.

import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ─── Constants tuned for k8s deployments ───────────────────────────────
// These mirror the production tier in scripts/generate-traefik-config.mjs.
// k8s deployments are always "production-like" — no dev port-forwarding via
// the chart, no relaxed thresholds. Local development still uses Docker
// Compose + scripts/generate-traefik-config.mjs DEPLOY_ENV=development.
const RATE_LIMIT_API = { average: 1000, burst: 2000 };
const RATE_LIMIT_AUTH = { average: 200, burst: 400 };
const CIRCUIT_BREAKER = {
  expression: 'ResponseCodeRatio(500, 600, 0, 600) > 0.30',
  checkPeriod: '10s',
  fallbackDuration: '30s',
  recoveryDuration: '60s',
};
const BODY_SIZE_LIMIT_BYTES = 104857600; // 100MB

// Hostname placeholders. Replaced verbatim by Helm at install time —
// `.Values.tls.dnsName` for the tenant host (web-UI + API) and
// `.Values.tls.adminDnsName` for the admin-UI host. Keeping the placeholders
// readable makes the committed YAML easier to grep.
const HOST_TOKEN = '__DNS_NAME__';
const ADMIN_HOST_TOKEN = '__ADMIN_DNS_NAME__';
// API routes match BOTH the tenant host and the admin host (when set), so the
// admin console (admin-ui, same-origin relative /api) can reach the backends
// on its own host — not just the tenant host. Expands to a `$apiHost` helm var
// (see HEADER). The UI catch-all routes keep their single-host match.
//
// The platform-admin (cross-tenant) subset of that surface is carved back out
// by the admin-plane routes below: it is ALLOWed on the admin host only and
// DENIed on the tenant host. See registry `admin_plane:` and.
const API_HOST_TOKEN = '__API_HOST__';
// Tenant-host-only and admin-host-only match tokens, used by the admin-plane
// deny/allow pair. `$dnsName`/`$adminDnsName` are bare hostnames; these expand
// to full Host(`…`) matchers.
const PUBLIC_ONLY_TOKEN = '__PUBLIC_HOST_ONLY__';
const ADMIN_ONLY_TOKEN = '__ADMIN_HOST_ONLY__';

// Admin-plane routes sit above every other priority in this file (max 300), so
// they win against the per-service PathPrefix catch-alls regardless of rule
// length. Public exceptions must in turn outrank the deny.
const PRIORITY_ADMIN_PLANE = 900;
const PRIORITY_ADMIN_PLANE_EXCEPTION = 950;

async function main() {
  const root = path.resolve(__dirname, '..');
  const registryPath = path.resolve(root, 'standards', 'service-registry.yaml');
  const outDir = path.resolve(root, 'charts', 'vistaplatform', 'templates', 'ingress');

  const registry = yaml.parse(await fs.readFile(registryPath, 'utf8'));
  const services = (registry.services || []).filter((s) => s.status !== 'optional');
  const adminPlane = registry.admin_plane || { prefixes: [], public_exceptions: [] };

  await fs.ensureDir(outDir);

  await writeMiddlewares(services, path.join(outDir, 'middlewares.yaml'));
  await writeIngressRoutes(services, adminPlane, path.join(outDir, 'ingressroutes.yaml'));

  console.log(`Generated ${path.relative(root, path.join(outDir, 'middlewares.yaml'))}`);
  console.log(`Generated ${path.relative(root, path.join(outDir, 'ingressroutes.yaml'))}`);
}

// ─── Middlewares ────────────────────────────────────────────────────────

function buildMiddlewares(services) {
  const docs = [];

  // CORS — origins are computed in the Helm template from .Values.tls.dnsName
  // so a customer's actual host appears in Access-Control-Allow-Origin.
  // We emit a __CORS_ORIGINS__ placeholder that the Helm wrapper replaces
  // with a rendered list at install time.
  docs.push({
    apiVersion: 'traefik.io/v1alpha1',
    kind: 'Middleware',
    metadata: { name: 'cors-headers' },
    spec: {
      headers: {
        accessControlAllowOriginList: '__CORS_ORIGINS__',
        accessControlAllowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        accessControlAllowHeaders: [
          'Authorization', 'Content-Type', 'X-Requested-With',
          'X-Impersonate-Tenant', 'X-Tenant-ID', 'X-User-ID', 'X-CSRF-Token',
        ],
        accessControlAllowCredentials: true,
        accessControlMaxAge: 86400,
        addVaryHeader: true,
      },
    },
  });

  // Security headers — HSTS rendered conditionally by the Helm wrapper
  // (omitted when tls.mode=none so it doesn't poison HSTS caches).
  docs.push({
    apiVersion: 'traefik.io/v1alpha1',
    kind: 'Middleware',
    metadata: { name: 'security-headers' },
    spec: {
      headers: {
        frameDeny: true,
        contentTypeNosniff: true,
        browserXssFilter: true,
        referrerPolicy: 'strict-origin-when-cross-origin',
        contentSecurityPolicy:
          "default-src 'self'; script-src 'self'; " +
          // admin-UI and web-UI import Poppins + Inconsolata from Google Fonts
          // at HTML-render time (link rel=stylesheet to fonts.googleapis.com,
          // which in turn loads woff2 files from fonts.gstatic.com).
          "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
          "font-src 'self' data: https://fonts.gstatic.com; " +
          "img-src 'self' data: https:; " +
          "connect-src 'self' https:; frame-ancestors 'none';",
        // Permissions-Policy parity with the Gin service middleware
        // (shared/middleware/security_headers.go): API responses already carry
        // it, but UI static responses (nginx behind Traefik) only get what
        // this middleware sets.
        customResponseHeaders: {
          'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
        },
        '__HSTS__': '__HSTS__',
      },
    },
  });

  // Strip duplicate CORS headers coming back from backends (services set
  // their own CORS in dev; Traefik wins in k8s).
  docs.push({
    apiVersion: 'traefik.io/v1alpha1',
    kind: 'Middleware',
    metadata: { name: 'strip-backend-cors' },
    spec: {
      headers: {
        customResponseHeaders: {
          'Access-Control-Allow-Origin': '',
          'Access-Control-Allow-Methods': '',
          'Access-Control-Allow-Headers': '',
          'Access-Control-Allow-Credentials': '',
          'Access-Control-Max-Age': '',
        },
      },
    },
  });

  docs.push({
    apiVersion: 'traefik.io/v1alpha1',
    kind: 'Middleware',
    metadata: { name: 'rate-limit-api' },
    spec: { rateLimit: RATE_LIMIT_API },
  });

  docs.push({
    apiVersion: 'traefik.io/v1alpha1',
    kind: 'Middleware',
    metadata: { name: 'rate-limit-auth' },
    spec: { rateLimit: RATE_LIMIT_AUTH },
  });

  docs.push({
    apiVersion: 'traefik.io/v1alpha1',
    kind: 'Middleware',
    metadata: { name: 'compress' },
    spec: { compress: { minResponseBodyBytes: 1024 } },
  });

  docs.push({
    apiVersion: 'traefik.io/v1alpha1',
    kind: 'Middleware',
    metadata: { name: 'body-size-limit' },
    spec: { buffering: { maxRequestBodyBytes: BODY_SIZE_LIMIT_BYTES } },
  });

  docs.push({
    apiVersion: 'traefik.io/v1alpha1',
    kind: 'Middleware',
    metadata: { name: 'retry' },
    spec: { retry: { attempts: 3, initialInterval: '100ms' } },
  });

  // ── Admin plane ────────────────────────────────────────────────
  //
  // deny-admin-plane: the DENY half of the admin-plane split. Traefik has no
  // "reject" middleware, so the idiomatic deny is an allow-list that nothing
  // can satisfy: 192.0.2.0/24 is TEST-NET-1 (RFC 5737), reserved for
  // documentation and guaranteed never to be a real client source address.
  // Routes carrying this middleware 404 before a backend is ever selected.
  //
  // 404 rather than 403 so the public host does not confirm that the
  // platform-admin API exists. rejectStatusCode needs Traefik >= 3.1; on
  // older CRDs the field is pruned by the API server and the deny falls back
  // to 403 — still a deny, just chattier.
  docs.push({
    apiVersion: 'traefik.io/v1alpha1',
    kind: 'Middleware',
    metadata: { name: 'deny-admin-plane' },
    spec: {
      ipAllowList: {
        sourceRange: ['192.0.2.0/24'],
        rejectStatusCode: 404,
      },
    },
  });

  // deny-internal-plane: same mechanism as deny-admin-plane, kept as a separate
  // object so that a denied request is attributable in Traefik's dashboard and
  // access log without decoding the rule. The two planes are denied for
  // different reasons and may diverge later.
  docs.push({
    apiVersion: 'traefik.io/v1alpha1',
    kind: 'Middleware',
    metadata: { name: 'deny-internal-plane' },
    spec: {
      ipAllowList: {
        sourceRange: ['192.0.2.0/24'],
        rejectStatusCode: 404,
      },
    },
  });

  // admin-plane-allowlist: the operator's own network control on the admin
  // host. Rendered only when adminPlane.ipAllowList.enabled — the chart cannot
  // guess a customer's admin CIDR, so the default is off and NOTES.txt says so.
  //
  // ipStrategy matters as much as sourceRange: Traefik sees the *connecting*
  // address, which behind an ALB/NLB/MetalLB is the load balancer, not the
  // operator. Set adminPlane.ipAllowList.ipStrategy.depth to the number of
  // trusted proxies in front of Traefik (ALB => 1) so the real client IP is
  // taken from X-Forwarded-For. Leaving depth at 0 with a proxy in front will
  // lock everyone out — or, worse, let everyone in if the LB's own address is
  // inside sourceRange.
  docs.push({
    apiVersion: 'traefik.io/v1alpha1',
    kind: 'Middleware',
    metadata: { name: 'admin-plane-allowlist', annotations: { '__ALLOWLIST_GATE__': 'true' } },
    spec: { ipAllowList: '__ADMIN_ALLOWLIST__' },
  });

  // Redirect HTTP → HTTPS (rendered only when TLS is on).
  docs.push({
    apiVersion: 'traefik.io/v1alpha1',
    kind: 'Middleware',
    metadata: { name: 'redirect-https' },
    spec: { redirectScheme: { scheme: 'https', permanent: true } },
  });

  // Per-service circuit breakers — one per service to isolate failures.
  for (const svc of services) {
    docs.push({
      apiVersion: 'traefik.io/v1alpha1',
      kind: 'Middleware',
      metadata: { name: `circuit-breaker-${svc.name}` },
      spec: { circuitBreaker: CIRCUIT_BREAKER },
    });
  }

  // Per-service /api/v1/<svc>/health → /health rewrite. Backends only
  // expose /health at the root, not under the registry route prefix.
  for (const svc of services) {
    docs.push({
      apiVersion: 'traefik.io/v1alpha1',
      kind: 'Middleware',
      metadata: { name: `rewrite-${svc.name}-health` },
      spec: { replacePath: { path: '/health' } },
    });
  }

  // Per-service /api/v2/<svc>/* → /api/v1/<svc>/* rewrite for v1
  // passthrough. inventory-service has native v2 handlers and is skipped.
  for (const svc of services) {
    if (svc.name === 'inventory-service') continue;
    docs.push({
      apiVersion: 'traefik.io/v1alpha1',
      kind: 'Middleware',
      metadata: { name: `v2-to-v1-${svc.name}` },
      spec: {
        replacePathRegex: {
          regex: `^/api/v2${svc.route_prefix}/(.*)`,
          replacement: `/api/v1${svc.route_prefix}/$1`,
        },
      },
    });
  }

  return docs;
}

// ─── IngressRoutes ──────────────────────────────────────────────────────

// Standard middleware chains, mirroring the file-provider generator.
const apiChain = (svcName) => [
  'cors-headers',
  `circuit-breaker-${svcName}`,
  'strip-backend-cors',
  'security-headers',
  'rate-limit-api',
  'compress',
  'body-size-limit',
  'retry',
];

const authChain = (svcName) => [
  'cors-headers',
  `circuit-breaker-${svcName}`,
  'strip-backend-cors',
  'security-headers',
  'rate-limit-auth',
  'compress',
  'body-size-limit',
  'retry',
];

// SSO providers route: no rate limit (auth flows initiate from logged-out
// pages and would otherwise count against the global auth budget).
const noRateLimitChain = (svcName) => [
  'cors-headers',
  `circuit-breaker-${svcName}`,
  'strip-backend-cors',
  'security-headers',
  'compress',
  'body-size-limit',
  'retry',
];

const brandingChain = (svcName) => [
  'cors-headers',
  `circuit-breaker-${svcName}`,
  'strip-backend-cors',
  'security-headers',
  'compress',
  'retry',
];

// Each route becomes one entry in IngressRoute.spec.routes.
//
// `priority` matters because Traefik scores rules by length when not given
// an explicit value, and our exact-path health/SSO routes are roughly the
// same length as the PathPrefix catch-all — so the catch-all wins ties and
// the rewrite middlewares never fire. Match these priorities to the
// original file-provider generator:
//
//   100  main v1 / v2 PathPrefix
//   110  cluster-sensor /api/v1/discovery PathPrefix
//   120  branding / WebSocket
//   150  exact-path /api/v1/<svc>/health
//   200  exact-path /api/v[12]/auth-service/auth/sso/providers
//        discovery import PathRegexp
//   300  admin-service status (cross-service to monitoring)
function makeRoute(match, svcName, middlewareNames, opts = {}) {
  const port = opts.port || 8080;
  const route = {
    match: `${API_HOST_TOKEN} && (${match})`,
    kind: 'Rule',
    services: [{ name: svcName, port }],
    middlewares: middlewareNames.map((name) => ({ name })),
  };
  if (opts.priority) route.priority = opts.priority;
  return route;
}

function buildApiRoutes(services) {
  const routes = [];

  for (const svc of services) {
    const isAuth = svc.name === 'auth-service';
    const base = isAuth ? authChain(svc.name) : apiChain(svc.name);

    // v1 health (priority 150 to beat v1 main's 100; same string length
    // would otherwise tie and let the catch-all win).
    routes.push(
      makeRoute(
        `Path(\`/api/v1${svc.route_prefix}/health\`)`,
        svc.name,
        [`rewrite-${svc.name}-health`, 'retry'],
        { priority: 150 }
      )
    );

    // Auth: SSO providers (exact path, no rate limit), v1 and v2.
    // Auth: /.well-known/oauth-authorization-server (RFC 8414 metadata, no rate limit).
    if (isAuth) {
      routes.push(
        makeRoute(
          `Path(\`/api/v1${svc.route_prefix}/auth/sso/providers\`)`,
          svc.name,
          noRateLimitChain(svc.name),
          { priority: 200 }
        )
      );
      routes.push(
        makeRoute(
          `Path(\`/api/v2${svc.route_prefix}/auth/sso/providers\`)`,
          svc.name,
          [...noRateLimitChain(svc.name), `v2-to-v1-${svc.name}`],
          { priority: 200 }
        )
      );
      routes.push(
        makeRoute(
          'Path(`/.well-known/oauth-authorization-server`)',
          svc.name,
          noRateLimitChain(svc.name),
          { priority: 200 }
        )
      );
      // JWKS. Public and unauthenticated by design — it holds only
      // public keys, and a verifier has to fetch it before it can authenticate
      // anything. Exposed at the edge so an external verifier (a customer's
      // API gateway, an SIEM correlating tokens) can validate our tokens
      // without us handing them a secret. No rate limit: this is polled on a
      // schedule by every verifier, and 429-ing it would break authentication
      // across the platform rather than protect anything.
      routes.push(
        makeRoute(
          'Path(`/.well-known/jwks.json`)',
          svc.name,
          noRateLimitChain(svc.name),
          { priority: 200 }
        )
      );
    }

    // Cluster-sensor-service: split /api/v1/discovery/* between
    // inventory-service (the import endpoint) and itself (everything else).
    if (svc.name === 'cluster-sensor-service') {
      routes.push({
        match:
          `${API_HOST_TOKEN} && PathPrefix(\`/api/v1/discovery/jobs/\`) && ` +
          'PathRegexp(`^/api/v1/discovery/jobs/[^/]+/import$`)',
        kind: 'Rule',
        priority: 200,
        services: [{ name: 'inventory-service', port: 8080 }],
        middlewares: apiChain('inventory-service').map((name) => ({ name })),
      });
      routes.push(
        makeRoute('PathPrefix(`/api/v1/discovery/`)', svc.name, apiChain(svc.name),
          { priority: 110 })
      );
    }

    // Inventory: discovery import on v1 + v2 with the same logic. v2 is
    // native (no path rewrite); v1 passthrough.
    if (svc.name === 'inventory-service') {
      routes.push({
        match:
          `${API_HOST_TOKEN} && PathPrefix(\`/api/v1/inventory-service/discovery/jobs/\`) && ` +
          'PathRegexp(`^/api/v1/inventory-service/discovery/jobs/[^/]+/import$`)',
        kind: 'Rule',
        priority: 200,
        services: [{ name: 'inventory-service', port: 8080 }],
        middlewares: apiChain('inventory-service').map((name) => ({ name })),
      });
      routes.push({
        match:
          `${API_HOST_TOKEN} && PathPrefix(\`/api/v2/inventory-service/discovery/jobs/\`) && ` +
          'PathRegexp(`^/api/v2/inventory-service/discovery/jobs/[^/]+/import$`)',
        kind: 'Rule',
        priority: 200,
        services: [{ name: 'inventory-service', port: 8080 }],
        middlewares: apiChain('inventory-service').map((name) => ({ name })),
      });
    }

    // monitoring-service handles /api/v1/admin-service/status/* historically.
    // The broad admin-service v1 route would otherwise swallow these.
    if (svc.name === 'monitoring-service') {
      routes.push(
        makeRoute(
          'PathPrefix(`/api/v1/admin-service/status/`)',
          svc.name,
          apiChain(svc.name),
          { priority: 300 }
        )
      );
      routes.push(
        makeRoute(
          'PathPrefix(`/api/v2/admin-service/status/`)',
          svc.name,
          [...apiChain(svc.name), 'v2-to-v1-admin-service'],
          { priority: 300 }
        )
      );
    }

    // v1 main route — catches everything else under /api/v1/<svc>/.
    routes.push(
      makeRoute(`PathPrefix(\`/api/v1${svc.route_prefix}/\`)`, svc.name, base,
        { priority: 100 })
    );

    // v2 main route — native for inventory, rewrite-to-v1 for everything else.
    if (svc.name === 'inventory-service') {
      routes.push(
        makeRoute(`PathPrefix(\`/api/v2${svc.route_prefix}/\`)`, svc.name, base,
          { priority: 100 })
      );
    } else {
      routes.push(
        makeRoute(
          `PathPrefix(\`/api/v2${svc.route_prefix}/\`)`,
          svc.name,
          [...base, `v2-to-v1-${svc.name}`],
          { priority: 100 }
        )
      );
    }
  }

  return routes;
}

// ─── Admin plane ─────────────────────────────────────────────────
//
// For every prefix declared in the registry's `admin_plane:` block, emit a
// matched pair at priority 900:
//
//   ALLOW  Host(admin)  && PathPrefix(v1|v2 prefix)  → owning backend
//   DENY   Host(tenant) && PathPrefix(v1|v2 prefix)  → deny-admin-plane
//
// and, at 950, an ALLOW on the tenant host for each declared public exception
// (the billing-provider webhook), so a deny prefix can carry a documented hole
// without weakening the rest of it.
//
// Both halves render only when tls.adminDnsName is set. On a single-host
// install there is nowhere else to serve the admin console from, so denying it
// on the only host would lock the operator out of their own platform; the
// chart says so in NOTES.txt rather than silently doing either thing.

// URL segment → route_prefix owner. `/admin-service/admin/` → `admin-service`.
function urlSegmentOf(prefix) {
  return prefix.replace(/^\//, '').split('/')[0];
}

function adminPlaneBackend(prefix, adminPlane) {
  const overrides = (adminPlane && adminPlane.service_overrides) || {};
  return overrides[prefix] || urlSegmentOf(prefix);
}

// The v2→v1 rewrite is keyed off the URL prefix, not the backend: a request to
// /api/v2/admin-service/status/** is rewritten by v2-to-v1-admin-service even
// though monitoring-service answers it.
function v2RewriteFor(prefix) {
  const segment = urlSegmentOf(prefix);
  return segment === 'inventory-service' ? null : `v2-to-v1-${segment}`;
}

// Traefik's PathPrefix is a literal string prefix, so `PathPrefix(/x/y/)` does
// NOT match `/x/y`. Several gated groups register a handler on the group root
// itself (gin's `logs.GET("", …)` → `/api/v1/monitoring-service/logs`), which
// would slip past a trailing-slash-only rule and stay on the public host. This
// was found by curling the live cluster, not by reading the generated YAML —
// the rules looked correct.
//
// So a prefix ending in "/" gets both forms: the prefix, and the exact bare
// path. Dropping the trailing slash from the prefix instead would be wrong in
// the other direction — `PathPrefix(/…/logs)` also matches `/…/logs-public`.
function pathMatcher(fullPath) {
  const prefixExpr = `PathPrefix(\`${fullPath}\`)`;
  if (!fullPath.endsWith('/')) return prefixExpr;
  return `(${prefixExpr} || Path(\`${fullPath.slice(0, -1)}\`))`;
}

function buildAdminPlaneRoutes(adminPlane) {
  const routes = [];
  const prefixes = adminPlane.prefixes || [];
  const exceptions = adminPlane.public_exceptions || [];

  // Public exceptions first (higher priority): a request matching one of these
  // must reach its backend on the tenant host even though the enclosing
  // admin-plane prefix is denied there.
  for (const ex of exceptions) {
    const backend = adminPlaneBackend(ex, adminPlane);
    const rewrite = v2RewriteFor(ex);
    routes.push({
      match: `${PUBLIC_ONLY_TOKEN} && ${pathMatcher(`/api/v1${ex}`)}`,
      kind: 'Rule',
      priority: PRIORITY_ADMIN_PLANE_EXCEPTION,
      services: [{ name: backend, port: 8080 }],
      middlewares: apiChain(backend).map((name) => ({ name })),
    });
    routes.push({
      match: `${PUBLIC_ONLY_TOKEN} && ${pathMatcher(`/api/v2${ex}`)}`,
      kind: 'Rule',
      priority: PRIORITY_ADMIN_PLANE_EXCEPTION,
      services: [{ name: backend, port: 8080 }],
      middlewares: [...apiChain(backend), ...(rewrite ? [rewrite] : [])].map((name) => ({ name })),
    });
  }

  for (const prefix of prefixes) {
    const backend = adminPlaneBackend(prefix, adminPlane);
    const rewrite = v2RewriteFor(prefix);
    // Platform-admin login is a credential endpoint on the crown-jewel API and
    // gets the auth rate limit (200/s) rather than the general API one
    // (1000/s), matching how tenant login is treated on auth-service.
    const chain = prefix === '/admin-service/auth/' ? authChain(backend) : apiChain(backend);

    for (const version of ['v1', 'v2']) {
      const mw = version === 'v2' && rewrite ? [...chain, rewrite] : chain;
      routes.push({
        match: `${ADMIN_ONLY_TOKEN} && ${pathMatcher(`/api/${version}${prefix}`)}`,
        kind: 'Rule',
        priority: PRIORITY_ADMIN_PLANE,
        services: [{ name: backend, port: 8080 }],
        // The operator's IP allow-list, when configured, is prepended by the
        // renderer so it runs before anything else on the chain.
        middlewares: mw.map((name) => ({ name })),
        adminAllowList: true,
      });
      routes.push({
        match: `${PUBLIC_ONLY_TOKEN} && ${pathMatcher(`/api/${version}${prefix}`)}`,
        kind: 'Rule',
        priority: PRIORITY_ADMIN_PLANE,
        // Never reached: deny-admin-plane rejects before the service is
        // selected. A service is still required — IngressRoute rejects a route
        // without one — so name the real backend rather than a fictional one.
        services: [{ name: backend, port: 8080 }],
        middlewares: [{ name: 'deny-admin-plane' }],
      });
    }
  }

  return routes;
}

// Internal plane. Unlike the admin plane there is no host these belong
// on, so the deny matches the API host expression — both the tenant host and
// the admin host when one is configured. Rendered unconditionally: it needs no
// second host to move anything to, so there is no single-host caveat.
function buildInternalPlaneRoutes(adminPlane) {
  const routes = [];
  for (const prefix of adminPlane.internal_prefixes || []) {
    const backend = urlSegmentOf(prefix);
    for (const version of ['v1', 'v2']) {
      routes.push({
        match: `${API_HOST_TOKEN} && ${pathMatcher(`/api/${version}${prefix}`)}`,
        kind: 'Rule',
        priority: PRIORITY_ADMIN_PLANE,
        // Never reached — deny-internal-plane rejects before a service is
        // selected — but IngressRoute requires one, so name the real backend
        // rather than inventing a fictional Service.
        services: [{ name: backend, port: 8080 }],
        middlewares: [{ name: 'deny-internal-plane' }],
      });
    }
  }
  return routes;
}

function buildUploadRoutes() {
  return [
    makeRoute(
      'PathPrefix(`/uploads/platform-branding/`)',
      'admin-service',
      brandingChain('admin-service'),
      { priority: 120 }
    ),
    makeRoute(
      'PathPrefix(`/uploads/branding/`)',
      'auth-service',
      brandingChain('auth-service'),
      { priority: 120 }
    ),
    makeRoute(
      'PathPrefix(`/uploads/avatars/`)',
      'auth-service',
      brandingChain('auth-service'),
      { priority: 120 }
    ),
  ];
}

function buildWebSocketRoute() {
  // /ws/ → inventory-service. Traefik handles the HTTP→WebSocket upgrade
  // transparently; no extra middleware required.
  return makeRoute('PathPrefix(`/ws/`)', 'inventory-service', ['retry'],
    { priority: 120 });
}

function buildIngressRoutes(services, adminPlane) {
  const docs = [];

  // Admin-plane IngressRoute. Kept in its own object rather than folded
  // into `-api` because the whole set is gated on tls.adminDnsName, and because
  // an auditor asking "what is the platform-admin API surface and where is it
  // reachable from?" should be able to read one object and get the answer.
  //
  // Traefik compares priorities across routers globally within an entrypoint,
  // so these 900/950 rules outrank the catch-alls in `-api` even though they
  // live in a different IngressRoute.
  docs.push({
    apiVersion: 'traefik.io/v1alpha1',
    kind: 'IngressRoute',
    metadata: {
      name: '__FULLNAME__-admin-plane',
      annotations: { '__ADMIN_PLANE_GATE__': 'true' },
    },
    spec: {
      entryPoints: '__ENTRY_POINTS__',
      routes: buildAdminPlaneRoutes(adminPlane),
      tls: '__TLS__',
    },
  });

  // Internal-plane denies. Its own object, always rendered, so "what is
  // refused at the edge and why" is answerable by reading one manifest.
  docs.push({
    apiVersion: 'traefik.io/v1alpha1',
    kind: 'IngressRoute',
    metadata: { name: '__FULLNAME__-internal-plane' },
    spec: {
      entryPoints: '__ENTRY_POINTS__',
      routes: buildInternalPlaneRoutes(adminPlane),
      tls: '__TLS__',
    },
  });

  // API IngressRoute: everything under /api/* and /ws/* and /uploads/*.
  docs.push({
    apiVersion: 'traefik.io/v1alpha1',
    kind: 'IngressRoute',
    metadata: { name: '__FULLNAME__-api' },
    spec: {
      entryPoints: '__ENTRY_POINTS__',
      routes: [
        ...buildApiRoutes(services),
        ...buildUploadRoutes(),
        buildWebSocketRoute(),
      ],
      tls: '__TLS__',
    },
  });

  // Tenant UI IngressRoute: / → web-ui at the tenant host.
  docs.push({
    apiVersion: 'traefik.io/v1alpha1',
    kind: 'IngressRoute',
    metadata: { name: '__FULLNAME__-app' },
    spec: {
      entryPoints: '__ENTRY_POINTS__',
      routes: [
        {
          match: `Host(\`${HOST_TOKEN}\`)`,
          kind: 'Rule',
          services: [{ name: 'web-ui', port: 80 }],
          middlewares: [{ name: 'security-headers' }],
        },
      ],
      tls: '__TLS__',
    },
  });

  // Admin UI IngressRoute: served on a separate host (e.g.
  // admin.vistaplatform.example) so vite's default root-relative asset URLs
  // resolve correctly without a path-prefix shim. Rendered only when
  // tls.adminDnsName is set. As of the v3 cutover the admin host is
  // served by admin-ui ("VISTA Operations"); v1 admin-ui is retired from running.
  docs.push({
    apiVersion: 'traefik.io/v1alpha1',
    kind: 'IngressRoute',
    metadata: { name: '__FULLNAME__-admin', annotations: { '__ADMIN_GATE__': 'true' } },
    spec: {
      entryPoints: '__ENTRY_POINTS__',
      routes: [
        {
          match: `Host(\`${ADMIN_HOST_TOKEN}\`)`,
          kind: 'Rule',
          services: [{ name: 'admin-ui', port: 80 }],
          middlewares: [{ name: 'security-headers' }],
        },
      ],
      tls: '__TLS__',
    },
  });

  // HTTP → HTTPS redirect on both hosts (rendered only when TLS is on).
  docs.push({
    apiVersion: 'traefik.io/v1alpha1',
    kind: 'IngressRoute',
    metadata: { name: '__FULLNAME__-redirect', annotations: { '__TLS_GATE__': 'true' } },
    spec: {
      entryPoints: ['web'],
      routes: [
        {
          match: `Host(\`${HOST_TOKEN}\`) || Host(\`${ADMIN_HOST_TOKEN}\`)`,
          kind: 'Rule',
          services: [{ name: 'web-ui', port: 80 }],
          middlewares: [{ name: 'redirect-https' }],
        },
      ],
    },
  });

  return docs;
}

// ─── Render to Helm-templated YAML ──────────────────────────────────────

const HEADER = [
  '{{/*',
  '  GENERATED FILE. DO NOT EDIT.',
  '  Source: standards/service-registry.yaml',
  '  Generator: scripts/generate-k8s-ingress.mjs',
  '  Regenerate with: make generate-k8s-ingress',
  '*/}}',
  '{{/*',
  '  Gated on .Values.ingress.controller: this entire file emits nothing',
  '  when the operator selected an ingress controller other than Traefik',
  '  (e.g. "none" — bring-your-own-ingress, nginx-ingress, Istio, Gateway',
  '  API). See values.yaml `ingress:` block for the supported values.',
  '*/}}',
  '{{- if eq (.Values.ingress.controller | default "traefik") "traefik" }}',
  '{{- include "vistaplatform.validateTLS" . -}}',
  '{{- $tlsMode := .Values.tls.mode -}}',
  '{{- $fullname := include "vistaplatform.fullname" . -}}',
  '{{- $namespace := .Release.Namespace -}}',
  '{{- $dnsName := include "vistaplatform.publicHost" . -}}',
  '{{- $adminDnsName := .Values.tls.adminDnsName | default "" -}}',
  // API host match: the tenant host alone, or (tenant || admin) when an admin
  // host is set — so admin-ui (same-origin /api on the admin host) reaches
  // the backends. The UI catch-all routes keep their single-host match.
  '{{- $apiHost := printf "Host(`%s`)" $dnsName -}}',
  '{{- if $adminDnsName }}{{- $apiHost = printf "(Host(`%s`) || Host(`%s`))" $dnsName $adminDnsName -}}{{- end -}}',
  '{{- $entryPoints := list "websecure" -}}',
  '{{- $tlsSecret := "" -}}',
  '{{- if or (eq $tlsMode "certManager") (eq $tlsMode "selfSigned") -}}{{- $tlsSecret = printf "%s-tls" $fullname -}}{{- end -}}',
  '{{- if eq $tlsMode "existingSecret" -}}{{- $tlsSecret = .Values.tls.existingSecretName -}}{{- end -}}',
  '{{- if eq $tlsMode "none" -}}{{- $entryPoints = list "web" -}}{{- end -}}',
  // Admin plane.
  //
  // $adminPlaneSplit — render the deny/allow pair that keeps the
  // platform-admin API off the public host. Requires an admin host to move it
  // TO; on a single-host install there is nowhere else to serve the console
  // from, so the split is skipped and NOTES.txt says the plane is unisolated.
  //
  // NOTE the absence of `| default true`: in Go templates `false | default true`
  // evaluates to TRUE, because `default` fires on any empty value and false is
  // empty. Using it here would make `restrictToAdminHost: false` silently
  // ignored — the same class of bug as jq's `//` swallowing an explicit false.
  // values.yaml carries the default instead.
  '{{- $adminPlaneSplit := and $adminDnsName .Values.adminPlane.restrictToAdminHost -}}',
  // $adminAllowList — the operator's IP allow-list, or empty when not
  // configured. Only meaningful alongside the split, since without it the same
  // API is reachable on the tenant host anyway.
  '{{- $adminAllowList := "" -}}',
  '{{- if and $adminPlaneSplit .Values.adminPlane.ipAllowList.enabled -}}',
  '{{- if not .Values.adminPlane.ipAllowList.sourceRange -}}',
  '{{- fail "adminPlane.ipAllowList.enabled is true but adminPlane.ipAllowList.sourceRange is empty — an allow-list with no entries would lock every operator out of the admin console" -}}',
  '{{- end -}}',
  '{{- $adminAllowList = .Values.adminPlane.ipAllowList -}}',
  '{{- end -}}',
  '',
].join('\n');

const FOOTER = '{{- end }}\n';

async function writeMiddlewares(services, outPath) {
  const docs = buildMiddlewares(services);
  const lines = [HEADER];

  for (const doc of docs) {
    const isRedirect = doc.metadata.name === 'redirect-https';
    const isAllowlist = doc.metadata.annotations && doc.metadata.annotations.__ALLOWLIST_GATE__;
    if (isRedirect) {
      lines.push('{{- if ne $tlsMode "none" }}');
    }
    if (isAllowlist) {
      lines.push('{{- if $adminAllowList }}');
    }
    lines.push('---');
    lines.push(`apiVersion: ${doc.apiVersion}`);
    lines.push(`kind: ${doc.kind}`);
    lines.push('metadata:');
    lines.push(`  name: ${doc.metadata.name}`);
    lines.push('  labels:');
    lines.push('    {{- include "vistaplatform.labels" . | nindent 4 }}');
    lines.push('spec:');
    if (isAllowlist) {
      // Rendered straight from values so the operator's CIDRs and ipStrategy
      // land verbatim; nothing here is baked in at generate time.
      lines.push('  ipAllowList:');
      lines.push('    sourceRange:');
      lines.push('      {{- range $adminAllowList.sourceRange }}');
      lines.push('      - {{ . | quote }}');
      lines.push('      {{- end }}');
      // ipStrategy is emitted only when it carries something. The default
      // (depth: 0, excludedIPs: []) is a non-empty MAP, so a bare `with` would
      // fire and leave `ipStrategy:` with no children — i.e. an explicit null
      // in the CRD, which is not the same as omitting the field.
      lines.push('    {{- with $adminAllowList.ipStrategy }}');
      lines.push('    {{- if or .depth .excludedIPs }}');
      lines.push('    ipStrategy:');
      lines.push('      {{- if .depth }}');
      lines.push('      depth: {{ .depth }}');
      lines.push('      {{- end }}');
      lines.push('      {{- with .excludedIPs }}');
      lines.push('      excludedIPs:');
      lines.push('        {{- range . }}');
      lines.push('        - {{ . | quote }}');
      lines.push('        {{- end }}');
      lines.push('      {{- end }}');
      lines.push('    {{- end }}');
      lines.push('    {{- end }}');
    } else {
      lines.push(indent(renderSpec(doc.spec), 2));
    }
    if (isAllowlist) {
      lines.push('{{- end }}');
    }
    if (isRedirect) {
      lines.push('{{- end }}');
    }
  }

  await fs.writeFile(outPath, lines.join('\n') + '\n' + FOOTER);
}

async function writeIngressRoutes(services, adminPlane, outPath) {
  const docs = buildIngressRoutes(services, adminPlane);
  const lines = [HEADER];

  for (const doc of docs) {
    const isRedirect = doc.metadata.annotations && doc.metadata.annotations.__TLS_GATE__;
    const isAdmin = doc.metadata.annotations && doc.metadata.annotations.__ADMIN_GATE__;
    const isAdminPlane = doc.metadata.annotations && doc.metadata.annotations.__ADMIN_PLANE_GATE__;
    if (isRedirect) {
      lines.push('{{- if ne $tlsMode "none" }}');
    }
    if (isAdmin) {
      lines.push('{{- if $adminDnsName }}');
    }
    if (isAdminPlane) {
      lines.push('{{- if $adminPlaneSplit }}');
    }

    const nameTpl = doc.metadata.name.replace('__FULLNAME__', '{{ $fullname }}');

    lines.push('---');
    lines.push(`apiVersion: ${doc.apiVersion}`);
    lines.push(`kind: ${doc.kind}`);
    lines.push('metadata:');
    lines.push(`  name: ${nameTpl}`);
    lines.push('  labels:');
    lines.push('    {{- include "vistaplatform.labels" . | nindent 4 }}');
    lines.push('spec:');

    if (doc.spec.entryPoints === '__ENTRY_POINTS__') {
      lines.push('  entryPoints: {{ $entryPoints | toJson }}');
    } else {
      lines.push(`  entryPoints: ${JSON.stringify(doc.spec.entryPoints)}`);
    }

    lines.push('  routes:');
    for (const route of doc.spec.routes) {
      const matchExpr = route.match
        .replaceAll(API_HOST_TOKEN, '{{ $apiHost }}')
        .replaceAll(PUBLIC_ONLY_TOKEN, 'Host(`{{ $dnsName }}`)')
        .replaceAll(ADMIN_ONLY_TOKEN, 'Host(`{{ $adminDnsName }}`)')
        .replaceAll(HOST_TOKEN, '{{ $dnsName }}')
        .replaceAll(ADMIN_HOST_TOKEN, '{{ $adminDnsName }}');
      lines.push(`    - match: ${matchExpr}`);
      lines.push(`      kind: ${route.kind}`);
      if (route.priority) {
        lines.push(`      priority: ${route.priority}`);
      }
      lines.push('      services:');
      for (const s of route.services) {
        lines.push(`        - name: ${s.name}`);
        if (s.port === 8080) {
          // Backend Go service (dual-listener). When serviceMtls is on, its real
          // API moves to the mTLS listener (8443) and :8080 becomes health-only —
          // so the gateway MUST call 8443 over HTTPS using the api-gateway client
          // cert (the backends-mtls ServersTransport in templates/mtls/). Without
          // this, external API calls hit the health-only :8080 and 404. The
          // ServersTransport resolves in the IngressRoute's own (release) namespace.
          lines.push('          {{- if $.Values.serviceMtls.enabled }}');
          lines.push('          port: 8443');
          lines.push('          scheme: https');
          lines.push('          serversTransport: backends-mtls');
          lines.push('          {{- else }}');
          lines.push(`          port: ${s.port}`);
          lines.push('          {{- end }}');
        } else {
          // Frontends (web-ui / admin-ui, nginx on :80) are not mTLS backends.
          lines.push(`          port: ${s.port}`);
        }
      }
      lines.push('      middlewares:');
      if (route.adminAllowList) {
        // Prepended, so the network control is evaluated before CORS, rate
        // limiting, or anything else that could produce a response.
        lines.push('        {{- if $adminAllowList }}');
        lines.push('        - name: admin-plane-allowlist');
        lines.push('        {{- end }}');
      }
      for (const m of route.middlewares) {
        lines.push(`        - name: ${m.name}`);
      }
    }

    if (doc.spec.tls === '__TLS__') {
      lines.push('  {{- if $tlsSecret }}');
      lines.push('  tls:');
      lines.push('    secretName: {{ $tlsSecret }}');
      // Pin min TLS version + cipher allowlist via the chart's TLSOption CRD
      // (templates/ingress/tlsoptions.yaml). Namespace is included because
      // Traefik resolves a bare options.name in the IngressRoute's own
      // namespace; being explicit keeps it correct if the release namespace
      // ever differs from where Traefik looks.
      lines.push('    options:');
      lines.push('      name: {{ $fullname }}-tls-options');
      lines.push('      namespace: {{ $namespace }}');
      lines.push('  {{- end }}');
    }

    if (isAdminPlane) {
      lines.push('{{- end }}');
    }
    if (isAdmin) {
      lines.push('{{- end }}');
    }
    if (isRedirect) {
      lines.push('{{- end }}');
    }
  }

  await fs.writeFile(outPath, lines.join('\n') + '\n' + FOOTER);
}

// Render a spec subtree to YAML, replacing our placeholders with Helm
// template expressions. Done as a post-processing step over yaml.stringify
// so we control exactly what lands in the file.
function renderSpec(spec) {
  let text = yaml.stringify(spec, { lineWidth: 120 });

  // CORS origins: replace the single placeholder string with a Helm range
  // that emits ["https://<public host>"] and any extras from .Values.gateway.extraCorsOrigins.
  // Indentation: after yaml.stringify, the placeholder sits inside `headers:`
  // at column 2. The whole spec gets a +2 indent by the caller, so list items
  // here at column 4 land at column 6 in the final file — matching the
  // surrounding `accessControlAllowMethods` etc.
  text = text.replace(
    /accessControlAllowOriginList: __CORS_ORIGINS__\s*\n/,
    [
      'accessControlAllowOriginList:',
      '    - "https://{{ $dnsName }}"',
      '    {{- if .Values.tls.adminDnsName }}',
      '    - "https://{{ .Values.tls.adminDnsName }}"',
      '    {{- end }}',
      '    {{- range .Values.gateway.extraCorsOrigins | default list }}',
      '    - {{ . | quote }}',
      '    {{- end }}',
      '',
    ].join('\n')
  );

  // HSTS gate: omit the three HSTS keys when TLS is off.
  text = text.replace(
    /\s*__HSTS__: __HSTS__\s*\n/,
    [
      '',
      '  {{- if ne .Values.tls.mode "none" }}',
      '  stsSeconds: 31536000',
      '  stsIncludeSubdomains: true',
      '  stsPreload: true',
      '  {{- end }}',
      '',
    ].join('\n')
  );

  return text.trimEnd();
}

function indent(text, n) {
  const pad = ' '.repeat(n);
  return text
    .split('\n')
    .map((line) => (line.length ? pad + line : line))
    .join('\n');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
