#!/usr/bin/env node
// Audit parity between the permissions the web-ui REFERENCES and the
// permissions the database SEEDS into `tenant_permissions`.
//
// Background: in May 2026 we shipped device-interrogation UI gated by
// <PermissionGate permission="discovery.manage"> in 18 places, but the
// `discovery.read` / `discovery.manage` rows were never added to the
// tenant_permissions INSERT in scripts/database/seed.sql. Result: the
// permission could not be granted to any role, so the "Add Network
// Device" button was hidden for every user on every tenant — silently —
// including on the first EKS production deployment. PCAP upload had
// the same shape (pcap.upload, pcap.delete used but never seeded).
//
// This audit makes that class of drift surface as a CI failure instead
// of a customer-install incident.
//
// What it checks:
//   1. DECLARED — every value inside the TENANT_PERMISSIONS object literal
//      in packages/primitives/src/rbac/constants.ts (@vistasecurity/primitives).
//   2. USED — every TENANT_PERMISSIONS.<resource>.<action> reference and
//      every `permission="X"` / `permission='X'` JSX attr in
//      frontend-v2/src/**/*.{ts,tsx}.
//   3. SEEDED — every row in the `INSERT INTO tenant_permissions ... VALUES`
//      block of scripts/database/seed.sql.
//   4. GRANTED — every permission referenced (directly or via a filter
//      that selects it) in a `tenant_role_permissions` grant statement in
//      seed.sql. This is the "any role will ever receive it" set, computed
//      by re-evaluating each grant's WHERE clause against SEEDED.
//   5. ENFORCED — every permission that at least one Go service hands to
//      `RequireTenantPermission(...)` or `RequirePermission(...)`. If a
//      permission is not in this set, the UI is the sole barrier — a
//      direct API call bypasses any check.
//
// Failures (strict):
//   - USED ∉ SEEDED          — runtime gate that can never pass
//   - DECLARED ∉ SEEDED      — a declared constant that won't work
//
// Warnings (always printed; not failures even in strict):
//   - USED ∉ DECLARED        — string-literal usage that should be a constant
//   - SEEDED ∉ (USED ∪ DECLARED)
//                            — orphan permission row (dead seed data); the
//                              "permission granted but no UI uses it" report
//   - SEEDED ∉ GRANTED       — permission exists in tenant_permissions but
//                              no role grants it; effectively unreachable
//   - SEEDED ∉ ENFORCED      — no backend service enforces this permission;
//                              UI is the sole barrier. Direct API calls
//                              bypass any check. Security-relevant.
//
// Exit codes:
//   0  no failures
//   0  failures present but --strict not set (warnings printed)
//   1  failures present with --strict (CI, `make audit`, pre-commit hook)
//
// Wired into `make audit` (strict) and the pre-commit hook (transitively).

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

const STRICT = process.argv.includes('--strict');
const MATRIX = process.argv.includes('--matrix');

const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';

// The declared-permission source of truth is @vistasecurity/primitives
// (TENANT_PERMISSIONS), shared by both live UIs. Gate usage is scanned in
// frontend-v2 (the tenant UI — the surface tenant_permissions gates).
const CONSTS_PATH = path.join(root, 'packages', 'primitives', 'src', 'rbac', 'constants.ts');
const SEED_PATH = path.join(root, 'scripts', 'database', 'seed.sql');
const WEBUI_SRC = path.join(root, 'frontend-v2', 'src');
const SERVICES_DIR = path.join(root, 'services');
const SHARED_RBAC_CONSTS = path.join(root, 'shared', 'rbac', 'permissions.go');

// Permission key shape: `<resource>.<action>` where resource and action
// are lowercase identifiers (letters, digits, underscore). Matches every
// permission currently in use across the codebase.
const PERM_RE = /^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/;

// ----------------------------------------------------------------------------
// ENFORCEMENT ALLOWLIST
//
// Permissions that are intentionally NOT enforced by backend middleware.
// The "SEEDED but no backend service enforces it" warning is suppressed
// for these. Every entry must carry a reason — drop a permission off the
// list and the warning comes back.
//
// Three legitimate categories:
//
// frontend-only: The permission is used solely by web-ui to gate
//   navigation or button visibility. Writes that actually mutate state
//   on the backend are gated by a different (finer-grained) permission.
//   Example: settings.manage gates the org-settings sub-pages and
//   sidebar nav. The actual write endpoints use settings.update.
//
// jwt-scoped: Read permission whose data is already scoped to the
//   caller's tenant by the JWT middleware + WHERE tenant_id = $X
//   queries. Adding an explicit permission gate is defense-in-depth, not
//   a security requirement, because there is no way to read another
//   tenant's data even without the check. Worth revisiting if we ever
//   want a role that can sign in but cannot read a specific resource
//   family — today no such role exists in the matrix.
//
// pending-feature: A permission for a feature that exists in the DB
//   model but doesn't yet have backend handlers. The permission is
//   reserved so it can be granted to the right roles when the handlers
//   land. REMOVE the permission from this list when its handlers ship.
//
// If you find yourself adding a write permission here, stop and write
// the middleware instead.
const ENFORCEMENT_ALLOWLIST = {
  // Frontend-only — web-ui uses these for navigation/visibility; the
  // actual mutations go through .update permissions.
  'compliance.manage': 'frontend-only',
  'settings.manage':   'frontend-only',
  'reports.read':      'frontend-only',
  'reports.manage':    'frontend-only',

  // JWT-scoped reads — tenant_id baked into every query; cross-tenant
  // reads are impossible regardless of permission.
  'assets.read':     'jwt-scoped',
  'compliance.read': 'jwt-scoped',
  // discovery.read is now enforced per-route by device-interrogation-service
  // (read endpoints for devices, jobs, schedules, agents, integrations).
  'sensors.read':    'jwt-scoped',
  // Alert reads are deliberately open to all tenant members (RLS-scoped);
  // only lifecycle mutations are gated (alerts.manage, enforced by
  // compliance-engine). alerts.read exists for viewer/api_user role shaping.
  'alerts.read':     'jwt-scoped',
};

// ----------------------------------------------------------------------------
// DECLARED — pull values from the TENANT_PERMISSIONS object literal.
// We don't parse TS; we just scan for quoted dotted strings inside the
// `export const TENANT_PERMISSIONS = { ... } as const;` block. The strings
// are the source of truth — the keys around them are irrelevant.
// ----------------------------------------------------------------------------
function loadDeclared() {
  const src = fs.readFileSync(CONSTS_PATH, 'utf8');
  const start = src.indexOf('TENANT_PERMISSIONS');
  if (start < 0) {
    throw new Error(
      `Could not find TENANT_PERMISSIONS in ${CONSTS_PATH}. ` +
      `If this constant was renamed, update audit-permissions.mjs.`
    );
  }
  // Walk braces from the first `{` after TENANT_PERMISSIONS until the
  // matching close.
  const objStart = src.indexOf('{', start);
  let depth = 0;
  let objEnd = -1;
  for (let i = objStart; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') {
      depth--;
      if (depth === 0) { objEnd = i; break; }
    }
  }
  if (objEnd < 0) throw new Error('Unterminated TENANT_PERMISSIONS object literal.');
  const body = src.slice(objStart, objEnd + 1);
  const found = new Set();
  for (const m of body.matchAll(/['"]([a-z][a-z0-9_]*\.[a-z][a-z0-9_]*)['"]/g)) {
    found.add(m[1]);
  }
  return found;
}

// ----------------------------------------------------------------------------
// USED — scan web-ui/src for `permission="X"` and `permission='X'`. Also
// matches `permission={'X'}` and `permission={"X"}` since react permits both.
// Skips test files and __tests__ directories so test fixtures don't pollute.
// ----------------------------------------------------------------------------
function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '__tests__') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (/\.(ts|tsx)$/.test(entry.name) && !/\.test\.(ts|tsx)$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

function loadUsed() {
  const found = new Map(); // perm -> Set(relative file paths)
  for (const file of walk(WEBUI_SRC)) {
    const src = fs.readFileSync(file, 'utf8');
    // Constant references — the idiomatic frontend-v2 form:
    //   <PermissionGate permission={TENANT_PERMISSIONS.alerts.manage}>
    //   hasPermission(TENANT_PERMISSIONS.pcap.upload)
    // The registry keys mirror the permission strings 1:1, so the member
    // path IS the permission name.
    const constRe = /TENANT_PERMISSIONS\.([a-z][a-z0-9_]*)\.([a-z][a-z0-9_]*)/g;
    for (const m of src.matchAll(constRe)) {
      const perm = `${m[1]}.${m[2]}`;
      if (!found.has(perm)) found.set(perm, new Set());
      found.get(perm).add(path.relative(root, file));
    }
    // String-literal form: permission="X" | 'X' | {"X"} | {'X'}. Kept so
    // hardcoded strings still count as used (and surface in the
    // USED ∉ DECLARED "should be a constant" warning).
    const litRe = /permission=\{?['"]([a-z][a-z0-9_]*\.[a-z][a-z0-9_]*)['"]\}?/g;
    for (const m of src.matchAll(litRe)) {
      if (!found.has(m[1])) found.set(m[1], new Set());
      found.get(m[1]).add(path.relative(root, file));
    }
  }
  return found;
}

// ----------------------------------------------------------------------------
// SEEDED — parse the `INSERT INTO tenant_permissions (name, resource,
// action, scope, description) VALUES (...)` block in seed.sql. Returns a
// Map keyed by permission name so callers can also see resource/action
// for the role-grant evaluator below.
// ----------------------------------------------------------------------------
function loadSeeded() {
  const sql = fs.readFileSync(SEED_PATH, 'utf8');
  // Find the INSERT INTO tenant_permissions ... VALUES block. Terminate at
  // the trailing `ON CONFLICT` or `;` that closes the statement.
  const re = /INSERT\s+INTO\s+tenant_permissions[^;]*?VALUES\s+([\s\S]*?)(?:ON\s+CONFLICT|;)/i;
  const m = sql.match(re);
  if (!m) {
    throw new Error(
      `Could not find an INSERT INTO tenant_permissions ... VALUES block in ${SEED_PATH}.`
    );
  }
  const body = m[1];
  // Pull all 4 expected columns: name, resource, action, scope.
  const rowRe = /\(\s*'([^']+)'\s*,\s*'([^']+)'\s*,\s*'([^']+)'\s*,\s*'([^']+)'/g;
  const found = new Map();
  for (const r of body.matchAll(rowRe)) {
    const [, name, resource, action] = r;
    if (!PERM_RE.test(name)) continue;
    found.set(name, { name, resource, action });
  }
  return found;
}

// ----------------------------------------------------------------------------
// SEEDED-platform — parse the `INSERT INTO platform_permissions (name,
// resource, action, description) VALUES (...)` block in seed.sql. The
// permission name is the first column of each `('name', ...)` row. Returns a
// Map keyed by permission name (carrying resource/action) so the platform
// failure report can group by resource, mirroring loadSeeded() above.
//
// Background: platform-permission rows are a separate table from
// tenant_permissions and a separate INSERT block. We hit the same drift bug
// class here three times in one week — routes gated by RequirePlatformPermission
// using a permission (platform_users.manage, platform_roles.manage,
// platform.notifications.manage, platform.impersonate) that was never added to
// this INSERT, so the permission could be granted to no role → 403 for every
// platform admin, invisible to the contract tests (which stub auth).
// ----------------------------------------------------------------------------
function loadSeededPlatform() {
  const sql = fs.readFileSync(SEED_PATH, 'utf8');
  const re = /INSERT\s+INTO\s+platform_permissions[^;]*?VALUES\s+([\s\S]*?)(?:ON\s+CONFLICT|;)/i;
  const m = sql.match(re);
  if (!m) {
    throw new Error(
      `Could not find an INSERT INTO platform_permissions ... VALUES block in ${SEED_PATH}.`
    );
  }
  const body = m[1];
  // Pull name, resource, action (first three quoted columns of each row).
  const rowRe = /\(\s*'([^']+)'\s*,\s*'([^']+)'\s*,\s*'([^']+)'/g;
  const found = new Map();
  for (const r of body.matchAll(rowRe)) {
    const [, name, resource, action] = r;
    found.set(name, { name, resource, action });
  }
  return found;
}

// ----------------------------------------------------------------------------
// GRANTED-platform — parse the `INSERT INTO platform_role_permissions ...`
// grant blocks in seed.sql. Two grant shapes appear:
//   1. super_admin cross-join with no `p.name IN (...)` filter → grants ALL
//      seeded platform permissions.
//   2. role-scoped grants with an `AND p.name IN ( 'a','b',... )` filter →
//      grants exactly the listed names.
// Returns the union of every permission name some role grants. Used only for a
// non-fatal "seeded but ungranted" warning, mirroring the tenant GRANTED set.
// ----------------------------------------------------------------------------
function loadGrantedPlatform(seededPlatform) {
  const sql = fs.readFileSync(SEED_PATH, 'utf8');
  const granted = new Set();
  // Each grant statement runs from `INSERT INTO platform_role_permissions`
  // up to the closing `;`.
  const stmtRe = /INSERT\s+INTO\s+platform_role_permissions[\s\S]*?;/gi;
  for (const m of sql.matchAll(stmtRe)) {
    const stmt = m[0];
    const inMatch = stmt.match(/p\.name\s+IN\s*\(([\s\S]*?)\)/i);
    if (inMatch) {
      // Role-scoped: grant exactly the listed names.
      for (const nm of inMatch[1].matchAll(/'([^']+)'/g)) granted.add(nm[1]);
    } else {
      // No name filter (super_admin cross-join) → grants ALL seeded perms.
      for (const name of seededPlatform.keys()) granted.add(name);
    }
  }
  return granted;
}

// ----------------------------------------------------------------------------
// ENFORCED-platform — find every permission string handed to
// `RequirePlatformPermission(...)` by any Go service. Three call shapes:
//
//   sharedrbac.RequirePlatformPermission(db, rbac.PermissionPlatformHealth)   // 2-arg
//   middleware.RequirePlatformPermission(rbacService, "platform.settings")    // 2-arg literal
//   rbacMiddleware.RequirePlatformPermission(rbac.PermissionTenantsRead)      // 1-arg (admin-service)
//
// The permission is always the LAST argument; the optional leading arg (db /
// rbacService) is matched non-greedily. `rbac.PermissionX` / `sharedrbac.PermissionX`
// constants resolve to their string via shared/rbac/permissions.go.
// ----------------------------------------------------------------------------
function loadEnforcedPlatform() {
  const consts = loadGoPermissionConsts();
  const enforced = new Map(); // perm -> Set(relative file paths)
  if (!fs.existsSync(SERVICES_DIR)) return enforced;

  const callRe =
    /RequirePlatformPermission\s*\(\s*(?:[^,()]+?\s*,\s*)?(?:"([^"]+)"|[a-zA-Z_]+\.Permission([A-Za-z0-9_]+))\s*\)/g;

  for (const file of walkGo(SERVICES_DIR)) {
    const src = fs.readFileSync(file, 'utf8');
    for (const m of src.matchAll(callRe)) {
      let perm;
      if (m[1]) perm = m[1];
      else if (m[2]) perm = consts.get(m[2]);
      if (!perm) continue;
      if (!enforced.has(perm)) enforced.set(perm, new Set());
      enforced.get(perm).add(path.relative(root, file));
    }
  }
  return enforced;
}

// ----------------------------------------------------------------------------
// Role grant predicates. These MUST mirror the filter expressions in:
//   - scripts/database/seed.sql        (post-migration DO block)
//   - services/auth-service/internal/auth/service.go (assignRolePermissions)
//
// When you change a role's grant filter, update all three. The audit will
// expose drift in the chart it emits — if a permission appears under a
// role in this JS but not in the live DB, the SQL drifted from the JS;
// vice-versa means the JS lags.
//
// Each predicate takes the parsed { name, resource, action } row and
// returns true iff that role gets the permission.
// ----------------------------------------------------------------------------
const ROLE_GRANTS = [
  {
    role: 'billing_admin',
    displayName: 'Billing Admin',
    description: 'Billing + visibility into who has access',
    grants: (p) => p.resource === 'billing' || ['settings.read', 'users.read'].includes(p.name),
  },
  {
    role: 'tenant_admin',
    displayName: 'Tenant Administrator',
    description: 'Everything except billing.update',
    grants: (p) => p.name !== 'billing.update',
  },
  {
    role: 'security_admin',
    displayName: 'Security Administrator',
    description: 'Operational/security scope + read users/settings',
    grants: (p) =>
      ['assets', 'sensors', 'reports', 'compliance', 'pcap', 'discovery', 'alerts'].includes(p.resource) ||
      ['users.read', 'settings.read'].includes(p.name),
  },
  {
    role: 'viewer',
    displayName: 'Viewer',
    description: 'Read-only non-billing',
    grants: (p) => p.action === 'read' && p.resource !== 'billing',
  },
  {
    role: 'api_user',
    displayName: 'API User',
    description: 'Read-only integration scope',
    grants: (p) =>
      p.action === 'read' &&
      ['assets', 'sensors', 'reports', 'compliance', 'discovery', 'pcap'].includes(p.resource),
  },
];

// ----------------------------------------------------------------------------
// ENFORCED — find every permission string that at least one Go service
// hands to `RequireTenantPermission(...)`. Two call shapes are matched:
//
//   sharedrbac.RequireTenantPermission(db, rbac.PermissionFoo)
//   middleware.RequirePermission(rbacService, "X")
//
// The first form requires resolving `rbac.PermissionFoo` → "foo.bar" via
// the constants in shared/rbac/permissions.go. The second form is a string
// literal we can read directly.
//
// This audit only knows whether ANY route in the service uses the
// permission — it does not verify every route that should be gated is.
// That's a deeper AST-level audit and out of scope here. But this catches
// the more dangerous case: a permission that no backend service enforces
// at all, leaving the UI as the sole barrier.
// ----------------------------------------------------------------------------
function loadGoPermissionConsts() {
  // Parse `Permission<Name> = "tenant_perm.string"` lines from
  // shared/rbac/permissions.go.
  if (!fs.existsSync(SHARED_RBAC_CONSTS)) return new Map();
  const src = fs.readFileSync(SHARED_RBAC_CONSTS, 'utf8');
  const consts = new Map();
  for (const m of src.matchAll(/Permission([A-Za-z0-9_]+)\s*=\s*"([^"]+)"/g)) {
    consts.set(m[1], m[2]);
  }
  return consts;
}

function walkGo(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === 'vendor' ||
        entry.name === 'testdata' || entry.name === '__tests__') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walkGo(full, out);
    else if (entry.name.endsWith('.go') && !entry.name.endsWith('_test.go')) {
      out.push(full);
    }
  }
  return out;
}

function loadEnforced(seededMap) {
  const consts = loadGoPermissionConsts();
  const enforced = new Map(); // perm -> Set(relative file paths)
  if (!fs.existsSync(SERVICES_DIR)) return enforced;

  // Match these call shapes — both pass the permission as the LAST argument:
  //   RequireTenantPermission(<anything>, "perm.name")
  //   RequireTenantPermission(<anything>, rbac.PermissionX)
  //   RequirePermission(<anything>, "perm.name")
  //   RequirePermission(<anything>, rbac.PermissionX)
  // We use a loose regex that captures the trailing arg up to the closing `)`.
  const callRe =
    /Require(?:Tenant)?Permission\s*\(\s*[^,()]+?\s*,\s*(?:"([^"]+)"|[a-zA-Z_]+\.Permission([A-Za-z0-9_]+))\s*\)/g;

  for (const file of walkGo(SERVICES_DIR)) {
    const src = fs.readFileSync(file, 'utf8');
    for (const m of src.matchAll(callRe)) {
      let perm;
      if (m[1]) perm = m[1];
      else if (m[2]) perm = consts.get(m[2]);
      if (!perm || !PERM_RE.test(perm)) continue;
      // Only count permissions that are actually tenant-seeded; platform
      // permissions don't live in tenant_permissions and aren't audited here.
      if (!seededMap.has(perm)) continue;
      if (!enforced.has(perm)) enforced.set(perm, new Set());
      enforced.get(perm).add(path.relative(root, file));
    }
  }
  return enforced;
}

function computeMatrix(seeded) {
  // Returns rows: [{ name, resource, action, roles: Set<role> }]
  const rows = [];
  for (const p of [...seeded.values()].sort(byResourceThenAction)) {
    const roles = new Set();
    for (const r of ROLE_GRANTS) {
      if (r.grants(p)) roles.add(r.role);
    }
    rows.push({ ...p, roles });
  }
  return rows;
}

function byResourceThenAction(a, b) {
  if (a.resource !== b.resource) return a.resource.localeCompare(b.resource);
  return a.action.localeCompare(b.action);
}

// ----------------------------------------------------------------------------

function fmtList(set, indent = '    ') {
  return [...set].sort().map((p) => `${indent}${p}`).join('\n');
}

function renderMatrix(rows) {
  const cols = ROLE_GRANTS.map((r) => r.role);
  // Compute column widths.
  const header = ['permission', ...cols];
  const data = rows.map((r) => [r.name, ...cols.map((c) => (r.roles.has(c) ? '✓' : '·'))]);
  const widths = header.map((h, i) => Math.max(h.length, ...data.map((d) => d[i].length)));
  const fmt = (cells) => cells.map((c, i) => c.padEnd(widths[i])).join('  ');
  const out = [];
  out.push(`\n${BLUE}Permission × Role matrix (computed from seed.sql filter rules)${RESET}`);
  out.push(`${DIM}  ✓ = granted by the role's filter; · = not granted${RESET}`);
  out.push(`${DIM}  This is the design intent. The live DB may differ if SQL drift exists.${RESET}\n`);
  out.push(fmt(header));
  out.push(widths.map((w) => '─'.repeat(w)).join('  '));
  let prevResource = null;
  for (const [i, row] of data.entries()) {
    const p = rows[i];
    if (prevResource && prevResource !== p.resource) out.push('');
    prevResource = p.resource;
    out.push(fmt(row));
  }
  out.push('');
  out.push(`${DIM}Role legend:${RESET}`);
  for (const r of ROLE_GRANTS) {
    out.push(`  ${r.role.padEnd(16)} ${DIM}${r.displayName} — ${r.description}${RESET}`);
  }
  return out.join('\n');
}

function main() {
  const declared = loadDeclared();
  const used = loadUsed();
  const seeded = loadSeeded();

  const seededNames = new Set(seeded.keys());
  const usedSet = new Set(used.keys());
  const union = new Set([...declared, ...usedSet]);

  const usedNotSeeded = [...usedSet].filter((p) => !seededNames.has(p)).sort();
  const declaredNotSeeded = [...declared].filter((p) => !seededNames.has(p)).sort();
  const usedNotDeclared = [...usedSet].filter((p) => !declared.has(p)).sort();
  // "Granted but no UI gates it" — exactly what was asked for. Compared
  // against USED (actual <PermissionGate> consumers), not DECLARED, since
  // a permission having a constant in permissions.ts doesn't mean any
  // page actually checks it.
  const seededNotUsed = [...seededNames].filter((p) => !usedSet.has(p)).sort();
  // Truly orphan: not used AND not even declared as a constant. Strong
  // candidate for removal from seed.
  const seededFullyOrphan = [...seededNames].filter((p) => !union.has(p)).sort();

  // GRANTED: permissions that at least one role's filter would select.
  const matrix = computeMatrix(seeded);
  const grantedNames = new Set(matrix.filter((r) => r.roles.size > 0).map((r) => r.name));
  const seededButUngranted = [...seededNames].filter((p) => !grantedNames.has(p)).sort();

  // ENFORCED: permissions that at least one Go service hands to the
  // RequireTenantPermission / RequirePermission middleware.
  const enforced = loadEnforced(seeded);
  const enforcedNames = new Set(enforced.keys());
  // Suppress the warning for permissions on the documented allowlist.
  // The audit still reports them once at the top so the allowlist
  // doesn't become a quiet way to ship un-gated writes.
  const seededNotEnforcedRaw = [...seededNames].filter((p) => !enforcedNames.has(p)).sort();
  const seededNotEnforced = seededNotEnforcedRaw.filter((p) => !(p in ENFORCEMENT_ALLOWLIST));
  const allowlisted = seededNotEnforcedRaw.filter((p) => p in ENFORCEMENT_ALLOWLIST);
  // Spot the case where a permission is on the allowlist but ALSO gets
  // backend enforcement — usually means someone added a gate without
  // removing the allowlist entry. Worth surfacing.
  const allowlistOverEnforced = [...enforcedNames].filter((p) => p in ENFORCEMENT_ALLOWLIST).sort();

  // --------------------------------------------------------------------------
  // PLATFORM parity — same drift class for platform_permissions / the
  // RequirePlatformPermission gates. Independent of the tenant logic above.
  // --------------------------------------------------------------------------
  const seededPlatform = loadSeededPlatform();
  const seededPlatformNames = new Set(seededPlatform.keys());
  const enforcedPlatform = loadEnforcedPlatform();
  const enforcedPlatformNames = new Set(enforcedPlatform.keys());
  const grantedPlatform = loadGrantedPlatform(seededPlatform);

  // FAIL (strict): a route gated by RequirePlatformPermission uses a
  // permission that platform_permissions never seeds → 403 for everyone.
  const enforcedPlatformNotSeeded =
    [...enforcedPlatformNames].filter((p) => !seededPlatformNames.has(p)).sort();
  // Warning: seeded but no role grants it → unreachable.
  const seededPlatformNotGranted =
    [...seededPlatformNames].filter((p) => !grantedPlatform.has(p)).sort();

  const failures = new Set([
    ...usedNotSeeded,
    ...declaredNotSeeded,
    ...enforcedPlatformNotSeeded.map((p) => `platform:${p}`),
  ]);

  console.log(`\n${BLUE}Permission parity audit (web-ui ↔ seed.sql ↔ services)${RESET}`);
  console.log(`${DIM}  declared in packages/primitives (TENANT_PERMISSIONS)   : ${declared.size}${RESET}`);
  console.log(`${DIM}  used as <PermissionGate permission="...">       : ${usedSet.size}${RESET}`);
  console.log(`${DIM}  seeded into tenant_permissions in seed.sql      : ${seededNames.size}${RESET}`);
  console.log(`${DIM}  granted to ≥1 role by seed.sql filter rules     : ${grantedNames.size}${RESET}`);
  console.log(`${DIM}  enforced by ≥1 service's middleware call        : ${enforcedNames.size}${RESET}`);

  if (usedNotSeeded.length) {
    console.log(`\n${RED}✖ USED but NOT SEEDED — these permission gates can never evaluate true${RESET}`);
    console.log(`${DIM}  (this is the bug class that hid the device-registration UI on EKS prod)${RESET}`);
    for (const p of usedNotSeeded) {
      const refs = [...used.get(p)].sort();
      console.log(`  ${RED}${p}${RESET}`);
      for (const r of refs.slice(0, 5)) console.log(`    ${DIM}↳ ${r}${RESET}`);
      if (refs.length > 5) console.log(`    ${DIM}↳ … +${refs.length - 5} more${RESET}`);
    }
    console.log(
      `  ${DIM}Fix: add the missing row(s) to the INSERT INTO tenant_permissions${RESET}\n` +
      `  ${DIM}     block in scripts/database/seed.sql.${RESET}`
    );
  }

  if (declaredNotSeeded.length) {
    console.log(`\n${RED}✖ DECLARED but NOT SEEDED — constant is dead at runtime${RESET}`);
    console.log(fmtList(declaredNotSeeded));
  }

  if (usedNotDeclared.length) {
    console.log(`\n${YELLOW}⚠ USED but NOT DECLARED — string literal should move to TENANT_PERMISSIONS${RESET}`);
    for (const p of usedNotDeclared) {
      const refs = [...used.get(p)].sort();
      console.log(`  ${YELLOW}${p}${RESET}`);
      for (const r of refs.slice(0, 3)) console.log(`    ${DIM}↳ ${r}${RESET}`);
      if (refs.length > 3) console.log(`    ${DIM}↳ … +${refs.length - 3} more${RESET}`);
    }
  }

  if (seededNotUsed.length) {
    console.log(`\n${YELLOW}⚠ GRANTED but no UI gates it — permission is in tenant_permissions and${RESET}`);
    console.log(`${YELLOW}  granted to ≥1 role, but no <PermissionGate>/route in web-ui consumes it.${RESET}`);
    console.log(`${DIM}  Either remove from seed (dead permission) or build the UI that needs it.${RESET}`);
    console.log(`${DIM}  ↳ Listed permissions, the roles that receive them, and whether the constant exists:${RESET}\n`);
    const labelW = Math.max(...seededNotUsed.map((p) => p.length));
    for (const p of seededNotUsed) {
      const row = matrix.find((r) => r.name === p);
      const roles = row ? [...row.roles].sort().join(',') : '(none)';
      const declaredTag = declared.has(p) ? '' : `  ${DIM}[also not declared in permissions.ts]${RESET}`;
      console.log(`  ${YELLOW}${p.padEnd(labelW)}${RESET}  ${DIM}→ ${roles}${RESET}${declaredTag}`);
    }
  }

  if (seededFullyOrphan.length && seededFullyOrphan.length !== seededNotUsed.length) {
    console.log(`\n${YELLOW}⚠ SEEDED but neither used nor declared — strong candidates for removal${RESET}`);
    console.log(fmtList(seededFullyOrphan));
  }

  if (seededButUngranted.length) {
    console.log(`\n${YELLOW}⚠ SEEDED but no role grants it — permission exists in tenant_permissions${RESET}`);
    console.log(`${YELLOW}  but no role's filter rule selects it. Effectively unreachable.${RESET}`);
    console.log(fmtList(seededButUngranted));
  }

  if (allowlisted.length) {
    console.log(`\n${BLUE}ⓘ ${allowlisted.length} permission(s) intentionally not backend-enforced${RESET}`);
    console.log(`${DIM}  Suppressed from the warning below. See ENFORCEMENT_ALLOWLIST in this script.${RESET}`);
    // Group by allowlist reason so the user can see the categories at a glance.
    const byReason = new Map();
    for (const p of allowlisted) {
      const r = ENFORCEMENT_ALLOWLIST[p];
      if (!byReason.has(r)) byReason.set(r, []);
      byReason.get(r).push(p);
    }
    for (const [reason, perms] of [...byReason.entries()].sort()) {
      console.log(`  ${DIM}${reason}:${RESET} ${perms.join(', ')}`);
    }
  }

  if (allowlistOverEnforced.length) {
    console.log(`\n${YELLOW}⚠ Allowlist drift — these permissions ARE enforced by a service but are${RESET}`);
    console.log(`${YELLOW}  still in ENFORCEMENT_ALLOWLIST. Drop them from the allowlist.${RESET}`);
    console.log(fmtList(allowlistOverEnforced));
  }

  if (seededNotEnforced.length) {
    console.log(`\n${RED}⚠ SEEDED but NO BACKEND SERVICE ENFORCES IT — UI is the sole barrier.${RESET}`);
    console.log(`${YELLOW}  A direct API call bypasses every check on routes covered by this permission.${RESET}`);
    console.log(`${DIM}  Fix by adding sharedrbac.RequireTenantPermission(db, "<perm>") to the route(s)${RESET}`);
    console.log(`${DIM}  that implement this action. See services/sensor-manager/cmd/main.go for an example.${RESET}`);
    console.log(`${DIM}  If the permission is intentionally not enforced (frontend-only, JWT-scoped,${RESET}`);
    console.log(`${DIM}  or pending-feature), add it to ENFORCEMENT_ALLOWLIST with a reason.${RESET}\n`);
    // Group by resource so the user sees the family-level pattern.
    const byResource = new Map();
    for (const p of seededNotEnforced) {
      const r = seeded.get(p)?.resource ?? '?';
      if (!byResource.has(r)) byResource.set(r, []);
      byResource.get(r).push(p);
    }
    for (const [resource, perms] of [...byResource.entries()].sort()) {
      console.log(`  ${YELLOW}${resource}${RESET}  ${DIM}(${perms.length})${RESET}`);
      for (const p of perms) console.log(`    ${RED}${p}${RESET}`);
    }
  }

  // --------------------------------------------------------------------------
  // PLATFORM report
  // --------------------------------------------------------------------------
  console.log(`\n${BLUE}Platform-permission parity audit (seed.sql ↔ services)${RESET}`);
  console.log(`${DIM}  seeded into platform_permissions in seed.sql        : ${seededPlatformNames.size}${RESET}`);
  console.log(`${DIM}  granted to ≥1 platform role by seed.sql             : ${grantedPlatform.size}${RESET}`);
  console.log(`${DIM}  enforced by ≥1 RequirePlatformPermission(...) call  : ${enforcedPlatformNames.size}${RESET}`);

  if (enforcedPlatformNotSeeded.length) {
    console.log(`\n${RED}✖ ENFORCED but NOT SEEDED — RequirePlatformPermission gate that can never pass${RESET}`);
    console.log(`${DIM}  (this is the bug class that 403'd every platform admin three times this week:${RESET}`);
    console.log(`${DIM}   platform_users.manage, platform_roles.manage, platform.notifications.manage,${RESET}`);
    console.log(`${DIM}   platform.impersonate — all gated but never seeded into platform_permissions)${RESET}`);
    for (const p of enforcedPlatformNotSeeded) {
      const refs = [...enforcedPlatform.get(p)].sort();
      console.log(`  ${RED}${p}${RESET}`);
      for (const r of refs.slice(0, 5)) console.log(`    ${DIM}↳ ${r}${RESET}`);
      if (refs.length > 5) console.log(`    ${DIM}↳ … +${refs.length - 5} more${RESET}`);
    }
    console.log(
      `  ${DIM}Fix: add the missing row(s) to the INSERT INTO platform_permissions${RESET}\n` +
      `  ${DIM}     block in scripts/database/seed.sql (and grant them to the right role).${RESET}`
    );
  }

  if (seededPlatformNotGranted.length) {
    console.log(`\n${YELLOW}⚠ SEEDED but no platform role grants it — exists in platform_permissions but${RESET}`);
    console.log(`${YELLOW}  no role's grant block selects it. Effectively unreachable.${RESET}`);
    console.log(fmtList(seededPlatformNotGranted));
  }

  if (MATRIX) {
    console.log(renderMatrix(matrix));
  }

  if (failures.size === 0) {
    console.log(`\n${GREEN}✓ permission parity ok${RESET}`);
    if (!MATRIX) {
      console.log(`${DIM}  Run with --matrix to print the permission × role chart.${RESET}`);
    }
    console.log('');
    return 0;
  }

  if (STRICT) {
    console.log(`\n${RED}✖ permission parity audit FAILED (${failures.size} issue${failures.size === 1 ? '' : 's'})${RESET}\n`);
    return 1;
  }
  console.log(`\n${YELLOW}⚠ permission parity audit found ${failures.size} issue${failures.size === 1 ? '' : 's'} (non-strict — not failing build)${RESET}\n`);
  return 0;
}

process.exit(main());
