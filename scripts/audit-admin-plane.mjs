#!/usr/bin/env node
/**
 * Admin-plane drift audit.
 *
 * The platform-admin control plane is cross-tenant: a caller who reaches those
 * endpoints with a valid platform session can read and change data belonging to
 * every tenant in the deployment. The chart keeps them off the public host by
 * generating a deny/allow pair from `admin_plane:` in the service registry.
 *
 * That only holds while the registry list matches reality. Two ways it rots:
 *
 *   1. Someone mounts a NEW platform-admin-gated route group in a Go service
 *      and does not add its path to the registry. The route then rides the
 *      per-service PathPrefix catch-all straight onto the public host, with no
 *      error anywhere.
 *   2. Someone hand-edits the generated ingressroutes.yaml, or the generator
 *      changes, and a declared prefix silently stops producing its deny/allow
 *      pair.
 *
 * This audit fails on either. Run strict from `make audit`.
 *
 *   node scripts/audit-admin-plane.mjs [--strict]
 *
 * Both halves are meant to be mutation-tested: delete a prefix from the
 * registry and check B fails; add a RequirePlatformAdmin group with an
 * unlisted path and check A fails. If neither happens, this file is decoration.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const STRICT = process.argv.includes('--strict');

const problems = [];
const notes = [];

// ─── Registry ──────────────────────────────────────────────────────────────

const registry = yaml.parse(
  fs.readFileSync(path.join(ROOT, 'standards', 'service-registry.yaml'), 'utf8')
);
const adminPlane = registry.admin_plane;
if (!adminPlane || !Array.isArray(adminPlane.prefixes) || adminPlane.prefixes.length === 0) {
  console.error('FAIL: standards/service-registry.yaml has no admin_plane.prefixes block.');
  process.exit(1);
}
const PREFIXES = adminPlane.prefixes;
const EXCEPTIONS = adminPlane.public_exceptions || [];
// Anonymous-public routes that are denied on the tenant host BY DESIGN
// (session-establishment endpoints served from the admin host). The inverse
// check treats these as declared intent, not swallowed routes.
const ADMIN_HOST_PUBLIC = adminPlane.admin_host_public || [];
// Gated route groups that host-based splitting cannot express, each with the
// reason. Anything here is knowingly still reachable on the public host.
const UNSPLITTABLE = adminPlane.unsplittable || {};
// Service-to-service prefixes: denied on EVERY host, not split.
const INTERNAL = adminPlane.internal_prefixes || [];
const deployments = registry.deployments || {};
const apiSubdomain = registry.metadata?.gateway?.api_host_subdomain || 'api';
const adminSubdomain = registry.ui?.admin?.host_subdomain || 'admin';

// ─── Check A: the Go services ──────────────────────────────────────────────
//
// Find every gin route group that installs a platform-admin gate, resolve its
// full URL path, and require that the registry covers it.

const PLATFORM_GATES =
  /RequirePlatformAuth|RequirePlatformAdmin|RequirePlatformPermission|RequireAnyPlatformPermission/;
// A group gated ONLY by the shared internal HMAC is service-to-service: no
// browser and no customer integration calls it, so it must be denied at the
// edge rather than merely moved to another host. RequireInternalOnly is
// auth-service's spelling of the same gate — its absence here is how
// /auth-service/internal/api-tokens/exchange stayed off internal_prefixes.
const INTERNAL_GATES = /RequireInternalHMAC|RequireInternalOnly/;

// ANY authentication middleware, platform or tenant. Used by the inverse
// check: a route whose chain carries none of these is anonymous-public, and
// an anonymous-public route under a denied prefix is either a declared
// public_exception or a route that silently 404s on every install where the
// deny renders — which is how platform branding (/platform/config) and ee
// social signup (/platform/sso-providers) broke on Kubernetes.
const ANY_AUTH_GATES =
  /RequireAuth|RequireJWTAuth|AuthMiddleware|RequirePlatformAuth|RequirePlatformAdmin|RequirePlatformPermission|RequireAnyPlatformPermission|RequireInternalHMAC|RequireInternalOnly/;

// `name := expr.Group("/literal"` — captures the variable, its parent
// expression, and the literal path segment. Only string literals are matched;
// a computed path is reported rather than guessed at.
const GROUP_DECL = /^\s*(\w+)\s*:?=\s*([\w.]+)\.Group\(\s*"([^"]*)"/;
// A gate passed inline as a later argument of the same .Group(...) call.
const GROUP_INLINE_GATE = /\.Group\(\s*"[^"]*"\s*,(.*)$/;
// `name.Use(...)`
const USE_CALL = /^\s*(\w+)\.Use\(/;
// A route registered DIRECTLY on a group variable — `g.GET("/path", …)`. The
// group-only parser above never sees these, which is how a public route under
// a denied prefix (and a direct HMAC-gated internal route) evaded this audit.
const ROUTE_REG = /^\s*(\w+)\.(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Any|Handle)\(\s*"([^"]*)"/;

function goFiles(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'vendor' || entry.name === 'node_modules') continue;
      goFiles(p, out);
    } else if (entry.name.endsWith('.go') && !entry.name.endsWith('_test.go')) {
      out.push(p);
    }
  }
  return out;
}

// Resolve a group variable to its full URL path by walking the parent chain.
//
// Returns null when the chain does not bottom out at a router root — e.g. the
// ee/ packages hang their groups off a *gin.RouterGroup handed in through
// EditionHooks, whose own path is not visible in that file. Truncating to the
// visible suffix there would produce a confident wrong path, so those are
// reported as unresolved instead. admin-service (the whole of ee/) is covered
// by a stronger guard: internal/api/admin_plane_test.go builds the real router
// and classifies every mounted route.
function resolvePath(varName, groups, seen = new Set()) {
  if (seen.has(varName)) return null; // cycle guard
  seen.add(varName);
  const g = groups.get(varName);
  if (!g) return null;
  if (g.parent === null) return g.path; // reached a router root
  const parent = resolvePath(g.parent, groups, seen);
  return parent === null ? null : parent + g.path;
}

// A gated path is covered when some registry prefix is a prefix of it, OR when
// the path is an ancestor of a registry prefix. The second case matters for
// mixed groups: /sensor-manager/admin is a gated *ancestor* of the listed
// /sensor-manager/admin/sensors, and the registry deliberately lists the
// narrower path because sibling routes under /admin are tenant-facing.
function coveredByRegistry(urlPath) {
  return PREFIXES.some((p) => urlPath.startsWith(p) || p.startsWith(urlPath));
}

const gatedFindings = [];
const internalFindings = [];
const publicUnderDeny = [];
const unresolved = [];

// True when any group on the variable's parent chain carries a middleware in
// `set` (via .Use or an inline .Group argument).
function chainHas(varName, groups, set, seen = new Set()) {
  if (seen.has(varName)) return false;
  seen.add(varName);
  if (set.has(varName)) return true;
  const g = groups.get(varName);
  if (!g || g.parent === null) return false;
  return chainHas(g.parent, groups, set, seen);
}

// A public exception covers a route when it names it exactly or is a declared
// prefix of it.
function coveredByException(urlPath) {
  return [...EXCEPTIONS, ...ADMIN_HOST_PUBLIC].some(
    (ex) => urlPath === ex || urlPath.startsWith(ex.endsWith('/') ? ex : ex + '/')
  );
}

function underDeniedPrefix(urlPath) {
  return PREFIXES.some((p) => urlPath.startsWith(p) || urlPath + '/' === p);
}

for (const file of goFiles(path.join(ROOT, 'services'))) {
  const src = fs.readFileSync(file, 'utf8');
  // No skip on gate regexes here: the inverse check below must see files that
  // contain no gate at all — an entirely-public router file can still mount a
  // route under a denied prefix.

  const lines = src.split('\n');
  const groups = new Map(); // var -> {parent, path}
  const gated = new Set();
  const internalGated = new Set();
  const authed = new Set(); // ANY auth middleware, tenant or platform
  const routes = []; // direct registrations: {name, seg, ctx}

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const decl = GROUP_DECL.exec(line);
    if (decl) {
      const [, name, parentExpr, seg] = decl;
      // Router roots (s.router, router, r, engine) contribute no path.
      const parent = /^(s\.)?(router|engine|r)$/.test(parentExpr) ? null : parentExpr;
      groups.set(name, { parent, path: seg });
      const inline = GROUP_INLINE_GATE.exec(line);
      if (inline && PLATFORM_GATES.test(inline[1])) gated.add(name);
      if (inline && INTERNAL_GATES.test(inline[1])) internalGated.add(name);
      if (inline && ANY_AUTH_GATES.test(inline[1])) authed.add(name);
      continue;
    }
    const use = USE_CALL.exec(line);
    if (use && PLATFORM_GATES.test(line)) gated.add(use[1]);
    if (use && INTERNAL_GATES.test(line)) internalGated.add(use[1]);
    if (use && ANY_AUTH_GATES.test(line)) authed.add(use[1]);
    const reg = ROUTE_REG.exec(line);
    if (reg) {
      // Per-route middleware may sit in later arguments, possibly on
      // continuation lines — keep a small context window for gate matching.
      routes.push({ name: reg[1], seg: reg[3], ctx: lines.slice(i, i + 3).join('\n') });
    }
  }

  // Direct registrations: feed internal-gated ones into the same registry
  // coverage check as internal-gated groups, and run the inverse check on the
  // anonymous-public ones.
  for (const r of routes) {
    const base = resolvePath(r.name, groups);
    if (base === null) continue; // unresolvable parents are handled by the real-router tests
    const full = base + (r.seg === '/' ? '' : r.seg);
    const urlPath = full.replace(/^\/api\/v[12]/, '');
    if (!urlPath.startsWith('/')) continue;

    const inlineInternal = INTERNAL_GATES.test(r.ctx);
    if (inlineInternal || chainHas(r.name, groups, internalGated)) {
      internalFindings.push({ file: path.relative(ROOT, file), name: r.name, urlPath });
      continue;
    }
    const hasAnyAuth = ANY_AUTH_GATES.test(r.ctx) || chainHas(r.name, groups, authed);
    if (!hasAnyAuth && underDeniedPrefix(urlPath) && !coveredByException(urlPath)) {
      publicUnderDeny.push({ file: path.relative(ROOT, file), name: r.name, urlPath });
    }
  }

  for (const name of internalGated) {
    const full = resolvePath(name, groups);
    if (full === null) {
      unresolved.push({ file: path.relative(ROOT, file), name });
      continue;
    }
    const urlPath = full.replace(/^\/api\/v[12]/, '');
    if (!urlPath.startsWith('/')) continue;
    internalFindings.push({ file: path.relative(ROOT, file), name, urlPath });
  }

  for (const name of gated) {
    const full = resolvePath(name, groups);
    const rel = path.relative(ROOT, file);
    if (full === null) {
      unresolved.push({ file: rel, name });
      continue;
    }
    // Strip the API version so it compares against registry prefixes, which
    // are version-agnostic (/api/v1/foo and /api/v2/foo both generated).
    const urlPath = full.replace(/^\/api\/v[12]/, '');
    if (!urlPath.startsWith('/')) continue; // not an API route
    gatedFindings.push({ file: rel, name, urlPath });
  }
}

const uncovered = gatedFindings.filter(
  (f) => !coveredByRegistry(f.urlPath) && !UNSPLITTABLE[f.urlPath]
);

if (uncovered.length) {
  problems.push(
    'Platform-admin-gated route groups NOT declared in registry admin_plane.prefixes.\n' +
      'These ride the per-service catch-all onto the PUBLIC host, where their role\n' +
      'check is the only control. Add each path to admin_plane.prefixes and re-run\n' +
      '`make generate-k8s-ingress`, or record it under admin_plane.unsplittable with\n' +
      'a reason if host-based splitting genuinely cannot express it:\n' +
      uncovered.map((f) => `  ${f.urlPath}   (${f.file}, group "${f.name}")`).join('\n')
  );
}

const uncoveredInternal = internalFindings.filter(
  (f) => !INTERNAL.some((p) => f.urlPath.startsWith(p) || p.startsWith(f.urlPath))
);
if (uncoveredInternal.length) {
  problems.push(
    'HMAC-gated service-to-service route groups NOT declared in\n' +
      'registry admin_plane.internal_prefixes. These are published on the public\n' +
      'ingress, where a leaked INTERNAL_AUTH_SECRET is the only thing between an\n' +
      'anonymous caller and the handler. Add each to internal_prefixes and re-run\n' +
      '`make generate-k8s-ingress`:\n' +
      uncoveredInternal.map((f) => `  ${f.urlPath}   (${f.file}, group "${f.name}")`).join('\n')
  );
}

// ─── Check A2 (inverse): no anonymous-public route under a denied prefix ───
//
// Check A asks "is every gated route denied?". This asks the reverse: "does
// the deny swallow anything that was meant to be public?". A route with NO
// auth middleware anywhere on its chain is anonymous-public — something a
// login/signup page reads before any session exists. If it sits under a
// denied admin-plane prefix and is not a declared public_exception, it 404s
// on every install where the deny renders, and nothing anywhere errors.
// That is precisely how GET /auth-service/platform/config (platform branding)
// served the frontend fallback wordmark on Kubernetes while working on
// Docker Compose.
if (publicUnderDeny.length) {
  problems.push(
    'Anonymous-public route(s) mounted under a DENIED admin-plane prefix and not\n' +
      'declared in admin_plane.public_exceptions. These are unreachable on the\n' +
      'tenant host — the deny answers before the backend — so whichever page reads\n' +
      'them gets a 404 and falls back silently. Either add each to\n' +
      'public_exceptions (with a justification) and re-run `make generate`, or\n' +
      'move the route out from under the denied prefix:\n' +
      publicUnderDeny.map((f) => `  ${f.urlPath}   (${f.file}, on "${f.name}")`).join('\n')
  );
}

// ─── Check B: the generated chart ──────────────────────────────────────────
//
// Every declared prefix must produce, for BOTH API versions, an allow route on
// the admin host and a deny route on the tenant host. Text assertions against
// the generated template: the file is a Helm template, so the host matchers are
// still `{{ $dnsName }}` / `{{ $adminDnsName }}` placeholders here.

const ingressPath = path.join(
  ROOT, 'charts', 'vistaplatform', 'templates', 'ingress', 'ingressroutes.yaml'
);
const ingress = fs.readFileSync(ingressPath, 'utf8');
const ingressLines = ingress.split('\n');

const ADMIN_HOST = 'Host(`{{ $adminDnsName }}`)';
const TENANT_HOST = 'Host(`{{ $dnsName }}`)';

// Index every route by its match line so the middlewares that follow it can be
// inspected. A route block ends at the next `- match:`.
const routeBlocks = [];
for (let i = 0; i < ingressLines.length; i++) {
  const m = /^\s*- match: (.+)$/.exec(ingressLines[i]);
  if (!m) continue;
  const body = [];
  for (let j = i + 1; j < ingressLines.length && !/^\s*- match: /.test(ingressLines[j]); j++) {
    body.push(ingressLines[j]);
  }
  routeBlocks.push({ match: m[1], body: body.join('\n') });
}

function findRoute(match) {
  return routeBlocks.find((r) => r.match === match);
}

// `- name:` appears under both `services:` and `middlewares:`; only the latter
// is wanted. Take everything after the `middlewares:` key.
function middlewaresOf(body) {
  const idx = body.indexOf('middlewares:');
  if (idx === -1) return [];
  return [...body.slice(idx).matchAll(/^\s*- name: (\S+)$/gm)].map((m) => m[1]);
}

// Mirrors pathMatcher() in generate-k8s-ingress.mjs: a trailing-slash prefix
// must ALSO match the bare group path, because Traefik's PathPrefix(`/x/y/`)
// does not match `/x/y` and several gated groups register a handler there.
function pathMatcher(fullPath) {
  const prefixExpr = `PathPrefix(\`${fullPath}\`)`;
  if (!fullPath.endsWith('/')) return prefixExpr;
  return `(${prefixExpr} || Path(\`${fullPath.slice(0, -1)}\`))`;
}

for (const prefix of PREFIXES) {
  for (const version of ['v1', 'v2']) {
    const pathExpr = pathMatcher(`/api/${version}${prefix}`);

    const allow = findRoute(`${ADMIN_HOST} && ${pathExpr}`);
    if (!allow) {
      problems.push(`Missing admin-host ALLOW route for /api/${version}${prefix} in ${path.relative(ROOT, ingressPath)}`);
    } else if (!/priority: 900/.test(allow.body)) {
      problems.push(`Admin-host route for /api/${version}${prefix} is not at priority 900 — the per-service catch-all may outrank it`);
    } else if (!/name: admin-plane-allowlist/.test(allow.body)) {
      problems.push(`Admin-host route for /api/${version}${prefix} does not carry the optional admin-plane-allowlist middleware`);
    }

    const deny = findRoute(`${TENANT_HOST} && ${pathExpr}`);
    if (!deny) {
      problems.push(
        `Missing tenant-host DENY route for /api/${version}${prefix}. Without it the ` +
          `per-service catch-all serves this platform-admin path on the public host.`
      );
    } else {
      const mws = middlewaresOf(deny.body);
      if (mws.length !== 1 || mws[0] !== 'deny-admin-plane') {
        problems.push(
          `Tenant-host route for /api/${version}${prefix} should carry exactly ` +
            `[deny-admin-plane]; found [${mws.join(', ')}]. Any other middleware ` +
            `means the request can still reach a backend.`
        );
      }
    }
  }
}

for (const ex of EXCEPTIONS) {
  for (const version of ['v1', 'v2']) {
    const pathExpr = pathMatcher(`/api/${version}${ex}`);
    const route = findRoute(`${TENANT_HOST} && ${pathExpr}`);
    if (!route) {
      problems.push(`Missing tenant-host ALLOW route for declared public exception /api/${version}${ex}`);
    } else if (!/priority: 950/.test(route.body)) {
      problems.push(`Public exception /api/${version}${ex} must outrank the deny (priority 950)`);
    } else if (/deny-admin-plane/.test(route.body)) {
      problems.push(`Public exception /api/${version}${ex} carries deny-admin-plane — it would be denied, not excepted`);
    }
  }
}

for (const prefix of INTERNAL) {
  for (const version of ['v1', 'v2']) {
    const pathExpr = pathMatcher(`/api/${version}${prefix}`);
    const route = findRoute(`{{ $apiHost }} && ${pathExpr}`);
    if (!route) {
      problems.push(
        `Missing edge DENY for the internal route /api/${version}${prefix}. ` +
          `Without it the per-service catch-all publishes a service-to-service ` +
          `endpoint on the public internet.`
      );
      continue;
    }
    const mws = middlewaresOf(route.body);
    if (mws.length !== 1 || mws[0] !== 'deny-internal-plane') {
      problems.push(
        `Internal route /api/${version}${prefix} should carry exactly ` +
          `[deny-internal-plane]; found [${mws.join(', ')}].`
      );
    }
  }
}

// The deny middlewares themselves must exist and must actually deny.
const middlewares = fs.readFileSync(
  path.join(ROOT, 'charts', 'vistaplatform', 'templates', 'ingress', 'middlewares.yaml'), 'utf8'
);
if (!/name: deny-internal-plane/.test(middlewares)) {
  problems.push('middlewares.yaml has no deny-internal-plane Middleware — every internal deny route is inert.');
}
if (!/name: deny-admin-plane/.test(middlewares)) {
  problems.push('middlewares.yaml has no deny-admin-plane Middleware — every deny route is inert.');
} else if (!/sourceRange:\n\s*- 192\.0\.2\.0\/24/.test(middlewares)) {
  problems.push(
    'deny-admin-plane no longer allow-lists only the RFC 5737 documentation range. ' +
      'If its sourceRange can match a real client, the deny admits traffic.'
  );
}

// ─── Check C: generated compose/EC2 Traefik config ─────────────────────────
//
// The chart generator is not the only edge. Docker Compose / EC2-smoke use the
// file-provider config from generate-traefik-config.mjs, so the same registry
// prefixes must be represented there too. Internal routes are denied in every
// topology; admin-plane host splitting is enforced where the gateway owns both
// API and admin hosts (gateway_routes_ui=true).

function readDynamicConfig(env) {
  const p = path.join(ROOT, 'config', 'traefik', `dynamic-${env}.yaml`);
  return {
    path: p,
    rel: path.relative(ROOT, p),
    // These are trusted, committed generator outputs that intentionally use
    // anchors for repeated middleware chains. The default alias cap is for
    // untrusted input and trips before the audit can inspect the file.
    doc: yaml.parse(fs.readFileSync(p, 'utf8'), { maxAliasCount: -1 }),
  };
}

function routeEntries(dynamic) {
  return Object.entries(dynamic.doc?.http?.routers || {}).map(([name, route]) => ({ name, route }));
}

function routeMiddlewares(route) {
  return route.middlewares || [];
}

function findDynamicRoute(dynamic, rule) {
  return routeEntries(dynamic).find(({ route }) => route.rule === rule);
}

function assertDenyMiddleware(dynamic, name) {
  const mw = dynamic.doc?.http?.middlewares?.[name];
  const ranges = mw?.ipAllowList?.sourceRange || [];
  if (!ranges.includes('192.0.2.0/24')) {
    problems.push(`${dynamic.rel} middleware ${name} is missing the TEST-NET-1 deny allow-list.`);
  }
}

for (const env of Object.keys(deployments)) {
  const dynamic = readDynamicConfig(env);
  assertDenyMiddleware(dynamic, 'deny-internal-plane');

  const multiHost = deployments[env]?.gateway_routes_ui === true;
  const apiHost = `${apiSubdomain}.example.com`;
  const adminHost = `${adminSubdomain}.example.com`;

  for (const prefix of INTERNAL) {
    for (const version of ['v1', 'v2']) {
      const pathExpr = pathMatcher(`/api/${version}${prefix}`);
      const rule = multiHost
        ? `(Host(\`${apiHost}\`) || Host(\`${adminHost}\`)) && (${pathExpr})`
        : pathExpr;
      const route = findDynamicRoute(dynamic, rule);
      if (!route) {
        problems.push(`${dynamic.rel} is missing edge DENY for internal route /api/${version}${prefix}.`);
        continue;
      }
      const mws = routeMiddlewares(route.route);
      if (mws.length !== 1 || mws[0] !== 'deny-internal-plane') {
        problems.push(
          `${dynamic.rel} internal route /api/${version}${prefix} should carry exactly ` +
            `[deny-internal-plane]; found [${mws.join(', ')}].`
        );
      }
    }
  }

  if (!multiHost) continue;

  assertDenyMiddleware(dynamic, 'deny-admin-plane');

  for (const prefix of PREFIXES) {
    for (const version of ['v1', 'v2']) {
      const pathExpr = pathMatcher(`/api/${version}${prefix}`);
      const allow = findDynamicRoute(dynamic, `Host(\`${adminHost}\`) && (${pathExpr})`);
      if (!allow) {
        problems.push(`${dynamic.rel} is missing admin-host ALLOW for /api/${version}${prefix}.`);
      } else if (allow.route.priority !== 900) {
        problems.push(`${dynamic.rel} admin-host ALLOW for /api/${version}${prefix} must be priority 900.`);
      } else if (routeMiddlewares(allow.route).includes('deny-admin-plane')) {
        problems.push(`${dynamic.rel} admin-host ALLOW for /api/${version}${prefix} carries deny-admin-plane.`);
      }

      const deny = findDynamicRoute(dynamic, `Host(\`${apiHost}\`) && (${pathExpr})`);
      if (!deny) {
        problems.push(`${dynamic.rel} is missing public-host DENY for /api/${version}${prefix}.`);
      } else {
        const mws = routeMiddlewares(deny.route);
        if (mws.length !== 1 || mws[0] !== 'deny-admin-plane') {
          problems.push(
            `${dynamic.rel} public-host route /api/${version}${prefix} should carry exactly ` +
              `[deny-admin-plane]; found [${mws.join(', ')}].`
          );
        }
      }
    }
  }

  for (const ex of EXCEPTIONS) {
    for (const version of ['v1', 'v2']) {
      const pathExpr = pathMatcher(`/api/${version}${ex}`);
      const route = findDynamicRoute(dynamic, `Host(\`${apiHost}\`) && (${pathExpr})`);
      if (!route) {
        problems.push(`${dynamic.rel} is missing public-host ALLOW for exception /api/${version}${ex}.`);
      } else if (route.route.priority !== 950) {
        problems.push(`${dynamic.rel} public exception /api/${version}${ex} must be priority 950.`);
      } else if (routeMiddlewares(route.route).includes('deny-admin-plane')) {
        problems.push(`${dynamic.rel} public exception /api/${version}${ex} carries deny-admin-plane.`);
      }
    }
  }
}

// ─── Report ────────────────────────────────────────────────────────────────

console.log(`Admin plane: ${PREFIXES.length} declared prefixes, ${EXCEPTIONS.length} public exception(s)`);
console.log(`Internal plane: ${INTERNAL.length} declared prefixes, ${internalFindings.length} HMAC-gated group(s) found`);
console.log(`  ${gatedFindings.length} platform-admin-gated route group(s) found in services/`);
if (Object.keys(UNSPLITTABLE).length) {
  console.log('  knowingly still on the public host (admin_plane.unsplittable):');
  for (const [p, why] of Object.entries(UNSPLITTABLE)) console.log(`    ${p} — ${why}`);
}
if (unresolved.length) {
  // Grouped by file: every one of these is a gated group whose parent
  // *gin.RouterGroup arrives through EditionHooks, so its path is not visible
  // in this file. They are covered instead by the real-router classification in
  // services/admin-service/internal/api/admin_plane_test.go.
  const byFile = new Map();
  for (const u of unresolved) {
    if (!byFile.has(u.file)) byFile.set(u.file, []);
    byFile.get(u.file).push(u.name);
  }
  console.log('  path not statically resolvable (covered by the real-router test instead):');
  for (const [f, names] of byFile) console.log(`    ${f}: ${names.join(', ')}`);
}
for (const n of notes) console.log(n);

if (problems.length) {
  console.error('\n' + problems.map((p) => `FAIL: ${p}`).join('\n\n'));
  process.exit(STRICT ? 1 : 0);
}
console.log('OK: admin plane declared, generated, and denied on the public host.');
