#!/usr/bin/env node
/**
 * Regression tests for the admin/internal plane edge audit.
 *
 * The bug class is subtle: Traefik PathPrefix(`/x/y/`) does not match `/x/y`.
 * The deny routes that protect platform-admin and service-to-service APIs must
 * include both the slash-prefixed subtree and the bare group path.
 */

import { spawnSync } from 'node:child_process';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

const adminPrefix = '/admin-service/logs/';
const exceptionPrefix = '/admin-service/auth/';
const internalPrefix = '/monitoring-service/logs/';

let failures = 0;

function check(desc, ok, detail = '') {
  if (ok) {
    console.log(`  PASS ${desc}`);
    return;
  }
  failures++;
  console.error(`  FAIL ${desc}${detail ? `\n       ${detail}` : ''}`);
}

function pathMatcher(fullPath, includeBarePath = true) {
  const prefixExpr = `PathPrefix(\`${fullPath}\`)`;
  if (!includeBarePath || !fullPath.endsWith('/')) return prefixExpr;
  return `(${prefixExpr} || Path(\`${fullPath.slice(0, -1)}\`))`;
}

function chartRule(hostMatcher, fullPath, includeBarePath = true) {
  return `${hostMatcher} && ${pathMatcher(fullPath, includeBarePath)}`;
}

function dynamicHostRule(host, fullPath, includeBarePath = true) {
  return `Host(\`${host}\`) && (${pathMatcher(fullPath, includeBarePath)})`;
}

function dynamicInternalRule(fullPath, includeBarePath = true) {
  return `(Host(\`api.example.com\`) || Host(\`admin.example.com\`)) && (${pathMatcher(fullPath, includeBarePath)})`;
}

function routeBlock(match, middleware, priority) {
  return `    - match: ${match}
      priority: ${priority}
      services:
        - name: blackhole
          port: 8080
      middlewares:
        - name: ${middleware}
`;
}

function dynamicRouter(name, rule, middleware, priority) {
  return `    ${name}:
      rule: ${JSON.stringify(rule)}
      entryPoints:
        - web
      service: blackhole
      middlewares:
        - ${middleware}
      priority: ${priority}
`;
}

function writeFixture(dir, options = {}) {
  const {
    chartAdminDenyIncludesBarePath = true,
    dynamicInternalDenyIncludesBarePath = true,
    goRouterSource = null,
    adminHostPublic = [],
  } = options;

  mkdirSync(path.join(dir, 'scripts'), { recursive: true });
  copyFileSync(
    path.join(root, 'scripts', 'audit-admin-plane.mjs'),
    path.join(dir, 'scripts', 'audit-admin-plane.mjs'),
  );

  const scriptNodeModules = path.join(root, 'scripts', 'node_modules');
  if (!existsSync(scriptNodeModules)) {
    throw new Error('scripts/node_modules is missing; run `cd scripts && npm install` first');
  }
  symlinkSync(scriptNodeModules, path.join(dir, 'scripts', 'node_modules'), 'dir');

  mkdirSync(path.join(dir, 'standards'), { recursive: true });
  mkdirSync(path.join(dir, 'services'), { recursive: true });
  mkdirSync(path.join(dir, 'config', 'traefik'), { recursive: true });
  mkdirSync(path.join(dir, 'charts', 'vistaplatform', 'templates', 'ingress'), { recursive: true });

  writeFileSync(path.join(dir, 'standards', 'service-registry.yaml'), `
metadata:
  gateway:
    api_host_subdomain: api
ui:
  admin:
    host_subdomain: admin
deployments:
  ec2-smoke:
    gateway_routes_ui: true
admin_plane:
  prefixes:
    - ${adminPrefix}
  public_exceptions:
    - ${exceptionPrefix}
${adminHostPublic.length ? `  admin_host_public:\n${adminHostPublic.map((p) => `    - ${p}`).join('\n')}\n` : ''}  internal_prefixes:
    - ${internalPrefix}
services: []
`);

  if (goRouterSource) {
    mkdirSync(path.join(dir, 'services', 'testsvc', 'internal', 'api'), { recursive: true });
    writeFileSync(path.join(dir, 'services', 'testsvc', 'internal', 'api', 'router.go'), goRouterSource);
  }

  const chartRoutes = [];
  for (const version of ['v1', 'v2']) {
    chartRoutes.push(routeBlock(
      chartRule('Host(`{{ $adminDnsName }}`)', `/api/${version}${adminPrefix}`),
      'admin-plane-allowlist',
      900,
    ));
    chartRoutes.push(routeBlock(
      chartRule('Host(`{{ $dnsName }}`)', `/api/${version}${adminPrefix}`, chartAdminDenyIncludesBarePath),
      'deny-admin-plane',
      900,
    ));
    chartRoutes.push(routeBlock(
      chartRule('Host(`{{ $dnsName }}`)', `/api/${version}${exceptionPrefix}`),
      'cors-headers',
      950,
    ));
    chartRoutes.push(routeBlock(
      chartRule('{{ $apiHost }}', `/api/${version}${internalPrefix}`),
      'deny-internal-plane',
      900,
    ));
  }

  writeFileSync(
    path.join(dir, 'charts', 'vistaplatform', 'templates', 'ingress', 'ingressroutes.yaml'),
    `routes:\n${chartRoutes.join('')}`,
  );

  writeFileSync(
    path.join(dir, 'charts', 'vistaplatform', 'templates', 'ingress', 'middlewares.yaml'),
    `
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: deny-admin-plane
spec:
  ipAllowList:
    sourceRange:
      - 192.0.2.0/24
---
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: deny-internal-plane
spec:
  ipAllowList:
    sourceRange:
      - 192.0.2.0/24
`,
  );

  const dynamicRouters = [];
  for (const version of ['v1', 'v2']) {
    dynamicRouters.push(dynamicRouter(
      `allow_admin_plane_${version}`,
      dynamicHostRule('admin.example.com', `/api/${version}${adminPrefix}`),
      'cors-headers',
      900,
    ));
    dynamicRouters.push(dynamicRouter(
      `deny_admin_plane_${version}`,
      dynamicHostRule('api.example.com', `/api/${version}${adminPrefix}`),
      'deny-admin-plane',
      900,
    ));
    dynamicRouters.push(dynamicRouter(
      `allow_admin_exception_${version}`,
      dynamicHostRule('api.example.com', `/api/${version}${exceptionPrefix}`),
      'cors-headers',
      950,
    ));
    dynamicRouters.push(dynamicRouter(
      `deny_internal_${version}`,
      dynamicInternalRule(`/api/${version}${internalPrefix}`, dynamicInternalDenyIncludesBarePath),
      'deny-internal-plane',
      900,
    ));
  }

  writeFileSync(path.join(dir, 'config', 'traefik', 'dynamic-ec2-smoke.yaml'), `
http:
  middlewares:
    cors-headers:
      headers: {}
    deny-admin-plane:
      ipAllowList:
        sourceRange:
          - 192.0.2.0/24
        rejectStatusCode: 404
    deny-internal-plane:
      ipAllowList:
        sourceRange:
          - 192.0.2.0/24
        rejectStatusCode: 404
  routers:
${dynamicRouters.join('')}
`);
}

function runAudit(options = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), 'admin-plane-audit-test-'));
  try {
    writeFixture(dir, options);
    const result = spawnSync(
      process.execPath,
      [path.join(dir, 'scripts', 'audit-admin-plane.mjs'), '--strict'],
      { cwd: dir, encoding: 'utf8' },
    );
    return {
      status: result.status,
      output: `${result.stdout}${result.stderr}`,
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function expectAudit(desc, options, expectedStatus, expectedText = '') {
  const result = runAudit(options);
  check(
    desc,
    result.status === expectedStatus && (!expectedText || result.output.includes(expectedText)),
    `expected status ${expectedStatus}${expectedText ? ` and output containing ${JSON.stringify(expectedText)}` : ''}, ` +
      `got status ${result.status}\n${result.output}`,
  );
}

console.log('Admin/internal plane audit regression tests');

expectAudit(
  'accepts admin and internal deny routes that also match the bare group path',
  {},
  0,
  'OK: admin plane declared, generated, and denied on the public host.',
);

expectAudit(
  'fails when a chart tenant-host admin deny route omits the bare group path',
  { chartAdminDenyIncludesBarePath: false },
  1,
  'Missing tenant-host DENY route for /api/v1/admin-service/logs/',
);

expectAudit(
  'fails when compose/EC2 internal deny routes omit the bare group path',
  { dynamicInternalDenyIncludesBarePath: false },
  1,
  'dynamic-ec2-smoke.yaml is missing edge DENY for internal route /api/v1/monitoring-service/logs/',
);

// ─── Inverse check (A2) + direct-registration parsing polarities ───────────

// A public route (no auth middleware anywhere on the chain) mounted under the
// denied admin prefix and not excepted — the platform-branding bug shape.
const publicUnderDenySource = `package api

func Setup() {
	api := router.Group("/api")
	v1 := api.Group("/v1")
	svc := v1.Group("/admin-service")
	logs := svc.Group("/logs")
	logs.GET("/branding", brandingHandler)
}
`;

expectAudit(
  'fails when an anonymous-public route is mounted under a denied prefix',
  { goRouterSource: publicUnderDenySource },
  1,
  'Anonymous-public route(s) mounted under a DENIED admin-plane prefix',
);

expectAudit(
  'accepts a public route under a denied prefix when declared admin_host_public',
  { goRouterSource: publicUnderDenySource, adminHostPublic: ['/admin-service/logs/branding'] },
  0,
  'OK: admin plane declared, generated, and denied on the public host.',
);

expectAudit(
  'accepts an authenticated route under a denied prefix (the deny is its shield)',
  {
    goRouterSource: `package api

func Setup() {
	api := router.Group("/api")
	v1 := api.Group("/v1")
	svc := v1.Group("/admin-service")
	logs := svc.Group("/logs")
	logs.Use(middleware.RequirePlatformAuth(cfg))
	logs.GET("/feed", feedHandler)
}
`,
  },
  0,
  'OK: admin plane declared, generated, and denied on the public host.',
);

// A DIRECT registration carrying the internal HMAC gate inline, on a path the
// registry does not cover — the /auth-service/internal/api-tokens/exchange
// shape, which the group-only parser used to miss entirely.
expectAudit(
  'fails when a direct internal-HMAC route is not covered by internal_prefixes',
  {
    goRouterSource: `package api

func Setup() {
	api := router.Group("/api")
	v1 := api.Group("/v1")
	svc := v1.Group("/monitoring-service")
	svc.POST("/private/exchange",
		middleware.RequireInternalOnly(cfg),
		exchangeHandler)
}
`,
  },
  1,
  'internal_prefixes',
);

if (failures) {
  console.error(`\n${failures} admin/internal plane audit regression check(s) failed`);
  process.exit(1);
}

console.log('Admin/internal plane audit catches the expected route matcher regressions');
