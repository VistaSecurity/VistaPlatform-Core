#!/usr/bin/env node
// GENERATED CONFIG SCRIPT: Produces Traefik v3 static + dynamic config from service-registry.yaml
// Replaces scripts/generate-nginx-config.mjs for the NGINX -> Traefik migration.
//
// Usage:
//   DEPLOY_ENV=development node scripts/generate-traefik-config.mjs
//   DEPLOY_ENV=ec2-smoke USE_MTLS=true node scripts/generate-traefik-config.mjs
//   DEPLOY_ENV=production USE_MTLS=false node scripts/generate-traefik-config.mjs
//
// Outputs:
//   config/traefik/traefik-{environment}.yaml   (static config)
//   config/traefik/dynamic-{environment}.yaml    (dynamic config: routers, services, middlewares)
//   config/generated/traefik-{environment}.yaml  (copy of dynamic config for CI validation)

import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function main() {
  const root = path.resolve(__dirname, '..');
  const registryPath = path.resolve(root, 'standards', 'service-registry.yaml');

  if (!(await fs.pathExists(registryPath))) {
    console.error(`Registry not found: ${registryPath}`);
    process.exit(1);
  }

  const content = await fs.readFile(registryPath, 'utf8');
  const registry = yaml.parse(content);

  await fs.ensureDir(path.resolve(root, 'config', 'traefik'));
  await fs.ensureDir(path.resolve(root, 'config', 'generated'));

  const services = registry.services || [];
  const deployEnv = (process.env.DEPLOY_ENV || '').toLowerCase();
  const isProd = deployEnv === 'production' || process.env.NODE_ENV === 'production';
  const isEc2Smoke = deployEnv === 'ec2-smoke';
  const environment = isEc2Smoke ? 'ec2-smoke' : (isProd ? 'production' : 'development');

  // Per-deployment topology flags (defined under top-level `deployments:` in the registry).
  // gateway_routes_ui=true means Traefik must front BOTH /api/* AND the web-ui/admin-ui
  // by Host() (single-host topologies behind a multi-host ALB or DNS round-robin).
  // gateway_routes_ui=false means an upstream layer (Vite dev server, k8s IngressRoute)
  // already does the host split, so Traefik handles only /api/* on any host.
  const deploymentCfg = (registry.deployments && registry.deployments[environment]) || {};
  const gatewayRoutesUI = deploymentCfg.gateway_routes_ui === true;

  // Multi-host routing inputs (only meaningful when gatewayRoutesUI is true).
  const domain = process.env.DOMAIN || 'example.com';
  const apiSubdomain = (registry.metadata && registry.metadata.gateway && registry.metadata.gateway.api_host_subdomain) || 'api';
  const tenantUI = (registry.ui && registry.ui.tenant) || {};
  const adminUI = (registry.ui && registry.ui.admin) || {};
  const tenantSubdomain = tenantUI.host_subdomain || 'app';
  const adminSubdomain = adminUI.host_subdomain || 'admin';
  const apiHost = `${apiSubdomain}.${domain}`;
  const tenantHost = `${tenantSubdomain}.${domain}`;
  const adminHost = `${adminSubdomain}.${domain}`;

  // Filter out optional services (Traefik fails if it can't reach an upstream)
  const activeServices = services.filter(s => s.status !== 'optional');
  const adminPlane = registry.admin_plane || { prefixes: [], public_exceptions: [], internal_prefixes: [] };

  // mTLS: default true for production, false for dev unless USE_MTLS is set
  const useMTLS = process.env.USE_MTLS === 'true' || (isProd && process.env.USE_MTLS !== 'false');

  // TLS termination with Let's Encrypt (ACME): for EC2/bare-metal deployments
  // In EKS, the ALB terminates TLS so this should be false (USE_TLS=false)
  // In EC2-smoke/production without ALB, defaults to true
  // Development defaults to false unless USE_TLS=true is explicitly set
  const useTLS = process.env.USE_TLS === 'true' || (isProd && process.env.USE_TLS !== 'false');

  // Environment-specific rate limiting
  // Production/smoke values are high because these are DDoS-protection ceilings,
  // not per-tenant limits. Per-tenant rate limiting is enforced at the service level
  // (auth-service Redis-based middleware). Keep dev values moderate for local testing.
  const apiRateAverage = environment === 'development' ? 100 : 1000;
  const apiRateBurst = environment === 'development' ? 200 : 2000;
  const authRateAverage = environment === 'development' ? 20 : 200;
  const authRateBurst = environment === 'development' ? 50 : 400;

  // Environment-specific CORS origins
  let corsOrigins = (isProd || isEc2Smoke)
    ? [
        'https://example.com', 'https://app.example.com', 'https://admin.example.com',
        'https://demoapi.example.com', 'https://demoapp.example.com', 'https://demoadmin.example.com',
      ]
    : [
        'http://localhost:3000', 'http://localhost:3005', 'http://localhost:3006',
        'http://localhost:5173', 'http://localhost:5174',
      ];

  // Development CORS: default to allow any browser origin via regex (reflects Origin header;
  // required for credentialed requests — wildcard '*' is forbidden with credentials).
  // Set DEV_CORS_ALLOW_ANY=0 to use an explicit allowlist instead (localhost + extras below).
  const devCorsAllowAny = !isProd && !isEc2Smoke && process.env.DEV_CORS_ALLOW_ANY !== '0';

  // Explicit extras when DEV_CORS_ALLOW_ANY=0 (e.g. http://192.168.x.x:3000).
  // Example: TRAEFIK_DEV_EXTRA_CORS_ORIGINS=http://10.0.0.12:3000,http://10.0.0.12:3006 make generate-gateway
  if (!isProd && !isEc2Smoke && !devCorsAllowAny) {
    const extra = (process.env.TRAEFIK_DEV_EXTRA_CORS_ORIGINS || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    if (extra.length) {
      corsOrigins = [...corsOrigins, ...extra];
    }
  }

  // ─── Static Config ──────────────────────────────────────────────────
  const staticConfig = {
    // Metadata
    global: {
      checkNewVersion: false,
      sendAnonymousUsage: false,
    },
    // Entry points
    entryPoints: {
      web: {
        address: ':80',
        // In TLS environments, redirect HTTP to HTTPS
        ...(useTLS ? {
          http: {
            redirections: {
              entryPoint: {
                to: 'websecure',
                scheme: 'https',
              },
            },
          },
        } : {}),
      },
      metrics: {
        address: ':8099',
      },
      // HTTPS entrypoint for TLS-terminating environments
      ...(useTLS ? {
        websecure: {
          address: ':443',
        },
      } : {}),
    },
    // Health/ping endpoint (Traefik-native, replaces /health)
    ping: {
      entryPoint: 'web',
    },
    // Prometheus metrics endpoint
    metrics: {
      prometheus: {
        entryPoint: 'metrics',
        addEntryPointsLabels: true,
        addRoutersLabels: true,
        addServicesLabels: true,
      },
    },
    // OpenTelemetry tracing
    tracing: {
      otlp: {
        grpc: {
          endpoint: 'otel-collector:4317',
          insecure: true,
        },
      },
    },
    // ACME / Let's Encrypt for non-EKS environments with TLS
    ...(useTLS ? {
      certificatesResolvers: {
        letsencrypt: {
          acme: {
            email: process.env.ACME_EMAIL || 'admin@example.com',
            storage: '/etc/traefik/acme.json',
            httpChallenge: {
              entryPoint: 'web',
            },
          },
        },
      },
    } : {}),
    // Access log with timing info (mirrors NGINX log_format)
    accessLog: {
      format: 'common',
      fields: {
        headers: {
          defaultMode: 'drop',
          names: {
            'X-Forwarded-For': 'keep',
            'X-Real-Ip': 'keep',
            'User-Agent': 'keep',
            Origin: 'keep',
          },
        },
      },
    },
    log: {
      level: environment === 'development' ? 'DEBUG' : 'WARN',
    },
    // File provider for dynamic config
    providers: {
      file: {
        filename: '/etc/traefik/dynamic.yaml',
        watch: true,
      },
    },
    // API dashboard (insecure in dev only; API endpoints available in all environments for metrics)
    api: environment === 'development'
      ? { dashboard: true, insecure: true }
      : { dashboard: false },
  };

  // For mTLS environments, Traefik needs serversTransport TLS config
  // The certificates are mounted at /etc/traefik/certs/
  const certBasePath = '/etc/traefik/certs';

  // ─── Dynamic Config ─────────────────────────────────────────────────

  // -- Middlewares --
  const middlewares = {};

  // CORS + security headers middleware
  const corsHeaderConfig = devCorsAllowAny
    ? {
        // Any http(s) origin — Traefik echoes the matching Origin (works with credentials).
        accessControlAllowOriginListRegex: ['^https?://.+$'],
      }
    : {
        accessControlAllowOriginList: corsOrigins,
      };

  middlewares['cors-headers'] = {
    headers: {
      ...corsHeaderConfig,
      accessControlAllowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      accessControlAllowHeaders: [
        'Authorization', 'Content-Type', 'X-Requested-With',
        'X-Impersonate-Tenant', 'X-Tenant-ID', 'X-User-ID', 'X-CSRF-Token',
      ],
      accessControlAllowCredentials: true,
      accessControlMaxAge: 86400,
      addVaryHeader: true,
    },
  };

  // Security headers middleware (mirrors ssl.conf)
  // HSTS is only included for TLS environments to avoid poisoning browser HSTS
  // caches on localhost/HTTP in development.
  const securityHeaders = {
    frameDeny: true,
    contentTypeNosniff: true,
    browserXssFilter: true,
    referrerPolicy: 'strict-origin-when-cross-origin',
    contentSecurityPolicy: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'${isProd ? '' : ' http:'} https:; frame-ancestors 'none';`,
    // Permissions-Policy parity with the Gin service middleware — UI responses
    // routed through the gateway only get what this middleware sets.
    customResponseHeaders: {
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    },
  };
  if (isProd || isEc2Smoke) {
    securityHeaders.stsSeconds = 31536000;
    securityHeaders.stsIncludeSubdomains = true;
  }
  middlewares['security-headers'] = { headers: securityHeaders };

  // Strip duplicate CORS headers from backend responses
  middlewares['strip-backend-cors'] = {
    headers: {
      customResponseHeaders: {
        'Access-Control-Allow-Origin': '',
        'Access-Control-Allow-Methods': '',
        'Access-Control-Allow-Headers': '',
        'Access-Control-Allow-Credentials': '',
        'Access-Control-Max-Age': '',
      },
    },
  };

  // Rate limiting: API tier
  middlewares['rate-limit-api'] = {
    rateLimit: {
      average: apiRateAverage,
      burst: apiRateBurst,
    },
  };

  // Rate limiting: Auth tier (stricter)
  middlewares['rate-limit-auth'] = {
    rateLimit: {
      average: authRateAverage,
      burst: authRateBurst,
    },
  };

  // Gzip compression (min 1024 bytes)
  middlewares['compress'] = {
    compress: {
      minResponseBodyBytes: 1024,
    },
  };

  // Request body size limit (100MB, mirrors client_max_body_size)
  middlewares['body-size-limit'] = {
    buffering: {
      maxRequestBodyBytes: 104857600,
    },
  };

  // Extended timeout placeholder for discovery import
  // Traefik doesn't have per-route timeout middleware; we handle this via
  // serversTransport responseForwardingFlushInterval and service-level settings.
  // For extended-timeout routes, we define a separate service with longer timeouts.

  // Retry middleware (mirrors proxy_next_upstream error timeout http_502 http_503 http_504)
  middlewares['retry'] = {
    retry: {
      attempts: 3,
      initialInterval: '100ms',
    },
  };

  // Deny middlewares for edge-only control planes. Traefik has no explicit
  // "return 404" middleware in file config, so deny with an allow-list that
  // cannot match a real client: TEST-NET-1 is reserved for documentation.
  const denyMiddleware = {
    ipAllowList: {
      sourceRange: ['192.0.2.0/24'],
      rejectStatusCode: 404,
    },
  };
  middlewares['deny-admin-plane'] = denyMiddleware;
  middlewares['deny-internal-plane'] = denyMiddleware;

  // -- Services (backends) --
  const traefikServices = {};

  // Standard middleware chain for API routes
  const standardApiMiddlewares = [
    'cors-headers', 'strip-backend-cors', 'security-headers',
    'rate-limit-api', 'compress', 'body-size-limit', 'retry',
  ];
  const authApiMiddlewares = [
    'cors-headers', 'strip-backend-cors', 'security-headers',
    'rate-limit-auth', 'compress', 'body-size-limit', 'retry',
  ];
  // No rate limit (for auth SSO providers)
  const noRateLimitMiddlewares = [
    'cors-headers', 'strip-backend-cors', 'security-headers',
    'compress', 'body-size-limit', 'retry',
  ];
  // Health check passthrough (minimal middlewares)
  const healthMiddlewares = ['retry'];

  // Gateway circuit breakers: off for local development (iterative debugging, flaky backends).
  // Production and ec2-smoke always use breakers. To re-enable in dev: ENABLE_GATEWAY_CIRCUIT_BREAKER=true make generate-gateway
  const useGatewayCircuitBreaker =
    environment !== 'development' || process.env.ENABLE_GATEWAY_CIRCUIT_BREAKER === 'true';

  // Build a middleware chain that puts cors-headers as the outermost wrapper (first in list),
  // then optionally the circuit breaker, then the remaining middlewares. When the breaker is on,
  // CORS wraps it so 503 breaker responses still get CORS headers.
  const corsFirstWithCB = (svcName, baseMw) => {
    const [corsMw, ...restBaseMw] = baseMw;
    if (!useGatewayCircuitBreaker) {
      return [corsMw, ...restBaseMw];
    }
    return [corsMw, `circuit-breaker-${svcName}`, ...restBaseMw];
  };

  // Circuit breaker: production/ec2-smoke use the strict baseline below.
  // Development (when ENABLE_GATEWAY_CIRCUIT_BREAKER=true) uses relaxed thresholds.
  const circuitBreakerStrict = {
    expression: 'ResponseCodeRatio(500, 600, 0, 600) > 0.30',
    checkPeriod: '10s',
    fallbackDuration: '30s',
    recoveryDuration: '60s',
  };
  const circuitBreakerDevelopment = {
    expression: 'ResponseCodeRatio(500, 600, 0, 600) > 0.90',
    checkPeriod: '30s',
    fallbackDuration: '90s',
    recoveryDuration: '180s',
  };
  const circuitBreakerFor = () =>
    environment === 'development' ? circuitBreakerDevelopment : circuitBreakerStrict;

  // Branding/uploads middlewares (CORS + basic)
  const brandingMiddlewares = [
    'cors-headers', 'strip-backend-cors', 'security-headers',
    'compress', 'retry',
  ];

  // -- serversTransports for mTLS --
  const serversTransports = {};

  for (const svc of activeServices) {
    const svcKey = svc.name.replace(/-/g, '_');
    const scheme = useMTLS ? 'https' : 'http';
    const port = useMTLS ? 8443 : 8080;
    const timeout = svc.gateway_timeout || '15s';

    // Standard service (per-service timeout from registry)
    traefikServices[`${svcKey}`] = {
      loadBalancer: {
        servers: [{ url: `${scheme}://${svc.name}:${port}` }],
        passHostHeader: true,
        responseForwarding: {
          flushInterval: '100ms',
        },
        healthCheck: {
          path: '/health',
          interval: '10s',
          timeout: '3s',
          scheme: 'http',
          port: 8080,
        },
        ...(useMTLS ? { serversTransport: `${svcKey}_mtls` } : {}),
      },
    };

    // Circuit breaker middleware per service (omitted entirely in local dev unless ENABLE_GATEWAY_CIRCUIT_BREAKER=true).
    if (useGatewayCircuitBreaker) {
      middlewares[`circuit-breaker-${svc.name}`] = {
        circuitBreaker: circuitBreakerFor(),
      };
    }

    // Health service (always HTTP port 8080, no mTLS)
    traefikServices[`${svcKey}_health`] = {
      loadBalancer: {
        servers: [{ url: `http://${svc.name}:8080` }],
        passHostHeader: true,
      },
    };

    // mTLS serversTransport for this service
    if (useMTLS) {
      serversTransports[`${svcKey}_mtls`] = {
        serverName: svc.name,
        certificates: [{
          certFile: `${certBasePath}/api-gateway-client-cert.pem`,
          keyFile: `${certBasePath}/api-gateway-client-key.pem`,
        }],
        rootCAs: [`${certBasePath}/platform-ca-cert.pem`],
      };
    }
  }

  // Extended-timeout service for discovery import (inventory-service)
  const inventoryService = activeServices.find(s => s.name === 'inventory-service');
  if (inventoryService) {
    const scheme = useMTLS ? 'https' : 'http';
    const port = useMTLS ? 8443 : 8080;
    traefikServices['inventory_service_extended'] = {
      loadBalancer: {
        servers: [{ url: `${scheme}://inventory-service:${port}` }],
        passHostHeader: true,
        responseForwarding: {
          flushInterval: '1s',
        },
        ...(useMTLS ? { serversTransport: 'inventory_service_mtls' } : {}),
      },
    };
  }

  // -- Routers --
  const routers = {};
  let routerPriority = 100; // Base priority; higher = more specific
  const adminPlanePriority = 900;
  const adminPlaneExceptionPriority = 950;

  // TLS-aware entrypoints and router TLS config
  const routerEntryPoints = useTLS ? ['web', 'websecure'] : ['web'];
  const routerTLS = useTLS ? { tls: { certResolver: 'letsencrypt' } } : {};

  // Gateway health endpoints (Traefik-local, no upstream needed)
  // /ping is handled natively by Traefik's ping entrypoint
  // But we also need /health, /api/health, /api/v1/health, /api/v2/health for compatibility
  // We use a simple service that returns from Traefik itself — but Traefik doesn't have
  // a built-in "return 200" equivalent. Instead, we route these to the ping endpoint
  // via a custom middleware or we define them as routers with no backend.
  //
  // For health endpoints we'll use a dedicated health-responder approach:
  // The Traefik ping endpoint at /ping returns "OK". For backwards-compatible /health,
  // /api/health, /api/v1/health, /api/v2/health, we add path-rewriting routers that
  // map to the internal ping service.

  // Health check routers - route to Traefik's internal ping
  const healthPaths = ['/health', '/api/health', '/api/v1/health', '/api/v2/health'];
  for (const hp of healthPaths) {
    const routerName = `health-${hp.replace(/\//g, '-').replace(/^-/, '')}`;
    routers[routerName] = {
      rule: `Path(\`${hp}\`)`,
      entryPoints: routerEntryPoints,
      service: 'ping@internal',
      priority: 9999, // Highest priority - health checks always win
      middlewares: hp.startsWith('/api/') ? ['cors-headers'] : [],
    };
  }

  // Service API routers
  for (const svc of activeServices) {
    const svcKey = svc.name.replace(/-/g, '_');
    const isAuth = svc.name === 'auth-service';
    const baseMw = isAuth ? authApiMiddlewares : standardApiMiddlewares;
    const mw = corsFirstWithCB(svc.name, baseMw);

    // v1 main route
    routers[`${svcKey}_v1`] = {
      rule: `PathPrefix(\`/api/v1${svc.route_prefix}/\`)`,
      entryPoints: routerEntryPoints,
      service: svcKey,
      middlewares: mw,
      priority: routerPriority,
    };

    // Health passthrough: backends only serve GET /health at the root, not under
    // /api/v1/{service}/health. Rewrite so Traefik health URLs match the app.
    const healthRewriteName = `rewrite-${svc.name}-api-v1-health`;
    middlewares[healthRewriteName] = {
      replacePath: {
        path: '/health',
      },
    };

    // Health passthrough (proxies to service /health endpoint)
    routers[`${svcKey}_health`] = {
      rule: `Path(\`/api/v1${svc.route_prefix}/health\`)`,
      entryPoints: routerEntryPoints,
      service: `${svcKey}_health`,
      middlewares: [healthRewriteName, ...healthMiddlewares],
      priority: routerPriority + 50, // Higher than general route
    };

    // -- Special cases --

    // Auth SSO providers (no rate limiting)
    if (isAuth) {
      routers['auth_sso_providers_v1'] = {
        rule: `Path(\`/api/v1${svc.route_prefix}/auth/sso/providers\`)`,
        entryPoints: routerEntryPoints,
        service: svcKey,
        middlewares: noRateLimitMiddlewares,
        priority: routerPriority + 100, // Exact path > prefix
      };
      // OAuth 2.0 well-known metadata endpoint. RFC 8414 requires this at
      // the issuer root — no /api/v1/ prefix. Priority 9000 keeps it below health
      // checks (9999) but above all API routes (100–200).
      routers['auth_oauth_well_known'] = {
        rule: `Path(\`/.well-known/oauth-authorization-server\`)`,
        entryPoints: routerEntryPoints,
        service: svcKey,
        middlewares: noRateLimitMiddlewares,
        priority: 9000,
      };
    }

    // Inventory-service: discovery import with extended timeout
    if (svc.name === 'inventory-service') {
      routers['inventory_discovery_import_v1'] = {
        rule: `PathPrefix(\`/api/v1/inventory-service/discovery/jobs/\`) && PathRegexp(\`^/api/v1/inventory-service/discovery/jobs/[^/]+/import$\`)`,
        entryPoints: routerEntryPoints,
        service: 'inventory_service_extended',
        middlewares: standardApiMiddlewares,
        priority: routerPriority + 100,
      };
    }

    // Cluster-sensor-service: /api/v1/discovery/ routes
    if (svc.name === 'cluster-sensor-service') {
      // Discovery import goes to inventory-service (extended timeout)
      routers['discovery_import_v1'] = {
        rule: `PathPrefix(\`/api/v1/discovery/jobs/\`) && PathRegexp(\`^/api/v1/discovery/jobs/[^/]+/import$\`)`,
        entryPoints: routerEntryPoints,
        service: 'inventory_service_extended',
        middlewares: standardApiMiddlewares,
        priority: routerPriority + 100,
      };
      // General discovery routes go to cluster-sensor-service
      routers['discovery_v1'] = {
        rule: `PathPrefix(\`/api/v1/discovery/\`)`,
        entryPoints: routerEntryPoints,
        service: svcKey,
        middlewares: standardApiMiddlewares,
        priority: routerPriority + 10,
      };
    }
  }

  // API v2 routes
  // inventory-service has native v2 endpoints (proxy to backend /api/v2/)
  // All other services: v2 -> v1 passthrough (proxy /api/v2/svc/ to backend /api/v1/svc/)
  if (inventoryService) {
    const invKey = 'inventory_service';

    // v2 discovery import (extended timeout)
      routers['inventory_discovery_import_v2'] = {
      rule: `PathPrefix(\`/api/v2/inventory-service/discovery/jobs/\`) && PathRegexp(\`^/api/v2/inventory-service/discovery/jobs/[^/]+/import$\`)`,
      entryPoints: routerEntryPoints,
      service: 'inventory_service_extended',
      middlewares: corsFirstWithCB('inventory-service', standardApiMiddlewares),
      priority: routerPriority + 100,
    };

    // v2 main route (native v2 - no rewrite needed, backend handles /api/v2/)
    routers[`${invKey}_v2`] = {
      rule: `PathPrefix(\`/api/v2/inventory-service/\`)`,
      entryPoints: routerEntryPoints,
      service: invKey,
      middlewares: corsFirstWithCB('inventory-service', standardApiMiddlewares),
      priority: routerPriority,
    };
  }

  // v2 -> v1 passthrough for other services (rewrite /api/v2/svc/ to /api/v1/svc/)
  for (const svc of activeServices) {
    if (svc.name === 'inventory-service') continue; // Handled above (native v2)
    const svcKey = svc.name.replace(/-/g, '_');
    const isAuth = svc.name === 'auth-service';
    const baseMw = isAuth ? authApiMiddlewares : standardApiMiddlewares;
    const mw = corsFirstWithCB(svc.name, baseMw);

    // Define a replacePath middleware for this service's v2->v1 rewrite
    const rewriteName = `v2-to-v1-${svc.name}`;
    middlewares[rewriteName] = {
      replacePathRegex: {
        regex: `^/api/v2${svc.route_prefix}/(.*)`,
        replacement: `/api/v1${svc.route_prefix}/$1`,
      },
    };

    routers[`${svcKey}_v2`] = {
      rule: `PathPrefix(\`/api/v2${svc.route_prefix}/\`)`,
      entryPoints: routerEntryPoints,
      service: svcKey,
      middlewares: [...mw, rewriteName],
      priority: routerPriority,
    };

    // Auth SSO providers v2 (no rate limit, exact path, v2->v1 rewrite)
    if (isAuth) {
      routers['auth_sso_providers_v2'] = {
        rule: `Path(\`/api/v2${svc.route_prefix}/auth/sso/providers\`)`,
        entryPoints: routerEntryPoints,
        service: svcKey,
        middlewares: [...noRateLimitMiddlewares, rewriteName],
        priority: routerPriority + 100,
      };
    }
  }

  // monitoring-service registers admin platform status at /api/v1/admin-service/status/*
  // (historical path). The broad admin-service router would send those requests to
  // admin-service, which has no handlers — admin-ui would see empty service lists.
  const monitoringForStatus = activeServices.find(s => s.name === 'monitoring-service');
  if (monitoringForStatus) {
    const monitoringKey = 'monitoring_service';
    const monitoringMw = corsFirstWithCB('monitoring-service', standardApiMiddlewares);
    routers['admin_service_status_v1'] = {
      rule: 'PathPrefix(`/api/v1/admin-service/status/`)',
      entryPoints: routerEntryPoints,
      service: monitoringKey,
      middlewares: monitoringMw,
      priority: routerPriority + 200,
    };
    routers['admin_service_status_v2'] = {
      rule: 'PathPrefix(`/api/v2/admin-service/status/`)',
      entryPoints: routerEntryPoints,
      service: monitoringKey,
      middlewares: [...monitoringMw, 'v2-to-v1-admin-service'],
      priority: routerPriority + 200,
    };
  }

  // Branding/upload routes
  const brandingRoutes = [
    { path: '/uploads/platform-branding/', service: 'admin_service', name: 'platform-branding' },
    { path: '/uploads/branding/', service: 'auth_service', name: 'tenant-branding' },
    { path: '/uploads/avatars/', service: 'auth_service', name: 'avatars' },
  ];
  for (const br of brandingRoutes) {
    routers[`branding_${br.name.replace(/-/g, '_')}`] = {
      rule: `PathPrefix(\`${br.path}\`)`,
      entryPoints: routerEntryPoints,
      service: br.service,
      middlewares: brandingMiddlewares,
      priority: routerPriority + 20,
    };
  }

  // WebSocket route for inventory service
  routers['websocket'] = {
    rule: `PathPrefix(\`/ws/\`)`,
    entryPoints: ['web'],
    service: 'inventory_service',
    middlewares: ['retry'],
    priority: routerPriority + 20,
  };

  // ─── Multi-host gateway: constrain existing routers to the API host and add UI routers ──
  // When gateway_routes_ui=true (ec2-smoke today), this Traefik instance fronts the
  // entire deployment: the API on api.${DOMAIN}, the tenant UI on app.${DOMAIN}, and
  // the admin UI on admin.${DOMAIN}. We therefore:
  //   1. Prefix every existing API/health/branding/websocket router with Host(`api.${DOMAIN}`)
  //      so non-API hosts cannot accidentally hit `/api/*`.
  //   2. Add `web_ui` and `admin_ui` services + Host()-matched routers for the UIs.
  // When gateway_routes_ui=false (development, k8s production), this block is a no-op:
  //   - dev: Vite serves the UIs directly on their own ports
  //   - k8s: the cluster IngressRoute splits hosts before traffic reaches api-gateway
  if (gatewayRoutesUI) {
    for (const router of Object.values(routers)) {
      // Health endpoints stay accessible on every host so ALB/Route53 health checks
      // and curl smoke tests work regardless of which Host header they send.
      if (router.service === 'ping@internal') continue;
      router.rule = `Host(\`${apiHost}\`) && (${router.rule})`;
    }

    // UI backends. internal_port comes from the registry (web-ui:3001, admin-ui:3003)
    // and matches the container ports exposed by docker-compose.ec2-smoke.yml.
    if (tenantUI.name && tenantUI.internal_port) {
      traefikServices['web_ui'] = {
        loadBalancer: {
          servers: [{ url: `http://${tenantUI.name}:${tenantUI.internal_port}` }],
          passHostHeader: true,
          responseForwarding: { flushInterval: '100ms' },
        },
      };
      routers['web_ui_host'] = {
        rule: `Host(\`${tenantHost}\`)`,
        entryPoints: routerEntryPoints,
        service: 'web_ui',
        priority: 1,
        middlewares: [],
      };
    }
    if (adminUI.name && adminUI.internal_port) {
      traefikServices['admin_ui'] = {
        loadBalancer: {
          servers: [{ url: `http://${adminUI.name}:${adminUI.internal_port}` }],
          passHostHeader: true,
          responseForwarding: { flushInterval: '100ms' },
        },
      };
      routers['admin_ui_host'] = {
        rule: `Host(\`${adminHost}\`)`,
        entryPoints: routerEntryPoints,
        service: 'admin_ui',
        priority: 1,
        middlewares: [],
      };
    }
  }

  const urlSegmentOf = (prefix) => prefix.replace(/^\//, '').split('/')[0];
  const adminPlaneBackend = (prefix) => {
    const overrides = adminPlane.service_overrides || {};
    return overrides[prefix] || urlSegmentOf(prefix);
  };
  const v2RewriteFor = (prefix) => {
    const segment = urlSegmentOf(prefix);
    return segment === 'inventory-service' ? null : `v2-to-v1-${segment}`;
  };
  const pathMatcher = (fullPath) => {
    const prefixExpr = `PathPrefix(\`${fullPath}\`)`;
    if (!fullPath.endsWith('/')) return prefixExpr;
    return `(${prefixExpr} || Path(\`${fullPath.slice(0, -1)}\`))`;
  };
  const hostScopedRule = (host, matcher) => `Host(\`${host}\`) && (${matcher})`;
  const adminChainFor = (prefix, backend) => {
    const base = prefix === '/admin-service/auth/' ? authApiMiddlewares : standardApiMiddlewares;
    return corsFirstWithCB(backend, base);
  };

  // Internal plane: service-to-service HMAC endpoints have no browser
  // or customer caller and should never transit the edge. Deny them in every
  // Traefik topology; in multi-host mode match both API and admin hosts.
  const internalHostRule = gatewayRoutesUI
    ? (matcher) => `(Host(\`${apiHost}\`) || Host(\`${adminHost}\`)) && (${matcher})`
    : (matcher) => matcher;
  for (const prefix of adminPlane.internal_prefixes || []) {
    const backendKey = urlSegmentOf(prefix).replace(/-/g, '_');
    for (const version of ['v1', 'v2']) {
      routers[`deny_internal_${version}_${prefix.replace(/[^a-zA-Z0-9]+/g, '_').replace(/^_|_$/g, '')}`] = {
        rule: internalHostRule(pathMatcher(`/api/${version}${prefix}`)),
        entryPoints: routerEntryPoints,
        service: backendKey,
        middlewares: ['deny-internal-plane'],
        priority: adminPlanePriority,
      };
    }
  }

  // Admin plane: only the multi-host compose topology has an admin host
  // where the platform-admin API can live. Single-host dev/production gateway
  // configs keep existing behavior; the chart generator enforces the split for
  // Kubernetes installs.
  if (gatewayRoutesUI) {
    for (const ex of adminPlane.public_exceptions || []) {
      const backend = adminPlaneBackend(ex);
      const backendKey = backend.replace(/-/g, '_');
      const rewrite = v2RewriteFor(ex);
      for (const version of ['v1', 'v2']) {
        routers[`allow_admin_exception_${version}_${ex.replace(/[^a-zA-Z0-9]+/g, '_').replace(/^_|_$/g, '')}`] = {
          rule: hostScopedRule(apiHost, pathMatcher(`/api/${version}${ex}`)),
          entryPoints: routerEntryPoints,
          service: backendKey,
          middlewares: version === 'v2' && rewrite
            ? [...adminChainFor(ex, backend), rewrite]
            : adminChainFor(ex, backend),
          priority: adminPlaneExceptionPriority,
        };
      }
    }

    for (const prefix of adminPlane.prefixes || []) {
      const backend = adminPlaneBackend(prefix);
      const backendKey = backend.replace(/-/g, '_');
      const rewrite = v2RewriteFor(prefix);
      for (const version of ['v1', 'v2']) {
        const matcher = pathMatcher(`/api/${version}${prefix}`);
        routers[`allow_admin_plane_${version}_${prefix.replace(/[^a-zA-Z0-9]+/g, '_').replace(/^_|_$/g, '')}`] = {
          rule: hostScopedRule(adminHost, matcher),
          entryPoints: routerEntryPoints,
          service: backendKey,
          middlewares: version === 'v2' && rewrite
            ? [...adminChainFor(prefix, backend), rewrite]
            : adminChainFor(prefix, backend),
          priority: adminPlanePriority,
        };
        routers[`deny_admin_plane_${version}_${prefix.replace(/[^a-zA-Z0-9]+/g, '_').replace(/^_|_$/g, '')}`] = {
          rule: hostScopedRule(apiHost, matcher),
          entryPoints: routerEntryPoints,
          service: backendKey,
          middlewares: ['deny-admin-plane'],
          priority: adminPlanePriority,
        };
      }
    }
  }

  // ─── Apply TLS config to all service routers ──────────────────────
  if (useTLS) {
    for (const [name, router] of Object.entries(routers)) {
      // Health check routers use ping@internal and don't need TLS cert resolver
      if (router.service !== 'ping@internal') {
        router.tls = { certResolver: 'letsencrypt' };
      }
    }
  }

  // ─── Assemble dynamic config ────────────────────────────────────────
  const dynamicConfig = {
    http: {
      routers,
      services: traefikServices,
      middlewares,
      ...(useMTLS && Object.keys(serversTransports).length > 0
        ? { serversTransports }
        : {}),
    },
  };

  // ─── Write output files ─────────────────────────────────────────────
  const header = `# GENERATED: DO NOT EDIT. Source: standards/service-registry.yaml\n# Generated for ${environment} environment (mTLS: ${useMTLS}, TLS: ${useTLS})\n`;

  const staticYaml = header + yaml.stringify(staticConfig, { lineWidth: 120 });
  const dynamicYaml = header + yaml.stringify(dynamicConfig, { lineWidth: 120 });

  // When set (e.g. RKE2 api-gateway ConfigMap build), write only under this directory
  // so USE_MTLS=false runs do not clobber committed config/traefik/*-production.yaml.
  const stagingDir = process.env.TRAEFIK_CONFIG_STAGING_DIR
    ? path.resolve(process.env.TRAEFIK_CONFIG_STAGING_DIR)
    : null;
  const traefikDir = stagingDir || path.resolve(root, 'config', 'traefik');
  await fs.ensureDir(traefikDir);

  const staticPath = path.join(traefikDir, `traefik-${environment}.yaml`);
  const dynamicPath = path.join(traefikDir, `dynamic-${environment}.yaml`);
  const generatedPath = stagingDir
    ? path.join(traefikDir, `traefik-${environment}.generated.yaml`)
    : path.resolve(root, 'config', 'generated', `traefik-${environment}.yaml`);

  await fs.writeFile(staticPath, staticYaml);
  await fs.writeFile(dynamicPath, dynamicYaml);
  await fs.writeFile(generatedPath, dynamicYaml);

  console.log(`Generated Traefik static config: ${staticPath}`);
  console.log(`Generated Traefik dynamic config: ${dynamicPath}`);
  console.log(`Generated copy for CI validation: ${generatedPath}`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
