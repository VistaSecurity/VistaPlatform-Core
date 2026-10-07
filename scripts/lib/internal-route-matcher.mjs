/**
 * Edge matchers for `admin_plane.internal_routes` (standards/service-registry.yaml).
 *
 * `internal_prefixes` denies a whole subtree. That cannot express a
 * service-to-service route that shares its path with a tenant-facing one (for
 * instance audit-service's HMAC-only `POST /activity-logs` next to the tenant's
 * `GET /activity-logs`), so these entries are one METHOD plus one EXACT path.
 *
 * Both Traefik generators (the chart's IngressRoutes and the compose
 * file-provider config) and the audit that checks their output call this one
 * module, so the three cannot disagree about what "denied" means. The behaviour
 * itself is pinned independently by scripts/test-edge-hmac-deny.mjs, which
 * evaluates the GENERATED rules against concrete requests.
 */

const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
const SEGMENT = /^(?:[a-z0-9][a-z0-9._-]*|:[A-Za-z_][A-Za-z0-9_]*)$/;

/** Throws on an entry the matcher cannot express faithfully. */
export function validateInternalRoute(entry) {
  const where = `admin_plane.internal_routes entry ${JSON.stringify(entry)}`;
  if (!entry || typeof entry !== 'object') throw new Error(`${where} is not an object`);
  if (!METHODS.has(entry.method)) {
    throw new Error(`${where}: method must be one of ${[...METHODS].join(', ')} (upper case)`);
  }
  const p = entry.path;
  if (typeof p !== 'string' || !p.startsWith('/') || p.endsWith('/') || p.includes('//')) {
    throw new Error(`${where}: path must start with "/" and must not end with "/" (both slash forms are always denied)`);
  }
  for (const seg of p.slice(1).split('/')) {
    if (!SEGMENT.test(seg)) {
      throw new Error(`${where}: segment "${seg}" must be a lower-case literal or a whole-segment :param`);
    }
  }
}

const hasParam = (p) => p.split('/').some((s) => s.startsWith(':'));

// Escape a literal path segment for a Go regexp. Literal segments are limited
// by validateInternalRoute to [a-z0-9._-], so only "." needs it.
const reLiteral = (s) => s.replace(/[.]/g, '\\.');

/**
 * The Traefik matcher (no host clause) for one internal route at one API
 * version. `:param` is exactly one non-empty path segment. Both the bare and the
 * trailing-slash form are matched: gin redirects `POST /x/` to `/x`, and a deny
 * that only knew one of them would leave the other reaching the backend.
 */
export function internalRouteMatcher(version, entry) {
  validateInternalRoute(entry);
  const full = `/api/${version}${entry.path}`;
  const method = `Method(\`${entry.method}\`)`;
  if (!hasParam(entry.path)) {
    return `${method} && (Path(\`${full}\`) || Path(\`${full}/\`))`;
  }
  const re = full
    .slice(1)
    .split('/')
    .map((s) => (s.startsWith(':') ? '[^/]+' : reLiteral(s)))
    .join('/');
  return `${method} && PathRegexp(\`^/${re}/?$\`)`;
}

/** Stable identifier for router names: `post_audit_service_activity_logs`. */
export function internalRouteSlug(entry) {
  return `${entry.method}_${entry.path}`
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_|_$/g, '');
}

/** The service URL segment that owns the route (`/audit-service/x` → `audit-service`). */
export function internalRouteService(entry) {
  return entry.path.replace(/^\//, '').split('/')[0];
}
