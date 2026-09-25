// Permission-gating guard for the operator navigation (RC-3, admin-ui data
// review): the nav gate of every section and sub-view must equal the gate its
// backend enforces, and the three seeded roles must see what their grants
// actually let them use.
//
// Pure functions over the REAL SECTIONS registry, and the seeded role grants
// are read out of scripts/database/seed.sql rather than copied here, so a seed
// change that moves what a role can reach is reflected without editing a
// fixture.
import { describe, expect, it } from 'vitest';
import { SECTIONS, SECTION_BY_ID, gateAllows, visibleSections, type NavItem } from './nav';
import type { EditionCapabilities } from '../lib/edition';
// Vite `?raw` rather than node:fs — this app has no @types/node.
import SEED from '../../../scripts/database/seed.sql?raw';

const MSP: EditionCapabilities = { msp: true, billing: true };

// ── the route gates ─────────────────────────────────────────────────────────
// The permission each surface's backend requires to READ. One line per
// sub-view whose backend is gated differently from its section, plus the
// sections whose own gate was wrong. Each names the enforcing route so a
// reviewer can check it against the Go.
const ROUTE_GATES: Record<string, string | string[]> = {
  // tenant-health-service health_handlers.go: RequirePlatformPermission(platform.health)
  'support/health': 'platform.health',
  // device-interrogation router.go: /admin observe group → platform.health
  'support/repair': 'platform.health',
  jobs: 'platform.health',
  // device-interrogation /admin/agents + sensor-manager /admin/sensors → platform.health
  fleet: 'platform.health',
  // compliance-engine /admin/alerts + monitoring-service → platform.health
  system: 'platform.health',
  // admin-service server.go: /tiers and /billable-items → platform.settings
  plans: 'platform.settings',
  // admin-service /admin/security → platform.security
  'security/dashboard': 'platform.security',
  // audit-service RequirePermission(audit.read) → platform.audit for operators
  'security/activity': 'platform.audit',
  // audit-service RequirePermission(audit.read) → platform.audit for operators
  'security/retention': 'platform.audit',
  'security/siem': 'platform.audit',
  // admin-service GET /admin/settings → platform.settings
  'security/policy': 'platform.settings',
  // compliance-engine /admin frameworks → catalogs.manage
  'catalog/frameworks': 'catalogs.manage',
  // admin-service /admin/catalogs/** → catalogs.manage
  'catalog/eol': 'catalogs.manage',
  'catalog/vulnerabilities': 'catalogs.manage',
  'catalog/classification-rules': 'catalogs.manage',
  // notification-service /platform/** → platform.notifications.manage
  'settings/notifications': 'platform.notifications.manage',
  // admin-service /admin/roles + /admin/permissions compose both read gates
  'staff/roles': ['platform_roles.read', 'platform_permissions.read'],
};

/** The gate the nav applies to a section or `section/child` path. */
function navGate(path: string): string | string[] | undefined {
  const [sid, cid] = path.split('/');
  const section = SECTION_BY_ID[sid];
  if (!section) throw new Error(`no section ${sid}`);
  const child = cid ? section.children?.find((c) => c.id === cid) : undefined;
  if (cid && !child) throw new Error(`no sub-view ${path}`);
  const entry = child && (child.permission || child.anyOf?.length || child.allOf?.length) ? child : section;
  return entry.permission ?? entry.anyOf ?? entry.allOf;
}

describe('nav gate equals route gate', () => {
  it.each(Object.entries(ROUTE_GATES))('%s', (path, want) => {
    expect(navGate(path)).toEqual(want);
  });

  // A section whose every sub-view is gated is visible exactly when one of
  // them is: its own gate is the union of theirs. Otherwise the rail shows a
  // section heading with nothing under it, or hides one with a usable page.
  it.each(['support', 'security'])('%s is gated on the union of its sub-views', (id) => {
    const s = SECTION_BY_ID[id];
    const union = new Set<string>();
    for (const c of s.children ?? []) {
      if (!c.permission && !c.anyOf?.length && !c.allOf?.length) throw new Error(`${id}/${c.id} is ungated`);
      for (const p of c.permission ? [c.permission] : c.anyOf ?? c.allOf!) union.add(p);
    }
    expect(new Set(s.permission ? [s.permission] : s.anyOf)).toEqual(union);
  });
});

// ── the seeded roles ────────────────────────────────────────────────────────
function seededGrants(role: string): Set<string> {
  const re = new RegExp(`WHERE r\\.name = '${role}'\\s+AND p\\.name IN \\(([\\s\\S]*?)\\)`);
  const m = SEED.match(re);
  if (!m) throw new Error(`seed.sql has no grant list for ${role}`);
  return new Set([...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]));
}

function visibleTree(has: (p: string) => boolean): string[] {
  return visibleSections(has, MSP, SECTIONS, 'msp').flatMap((s: NavItem) => [
    s.id,
    ...(s.children ?? []).map((c) => `${s.id}/${c.id}`),
  ]);
}

const EVERYTHING = SECTIONS.flatMap((s) => [s.id, ...(s.children ?? []).map((c) => `${s.id}/${c.id}`)]);

describe('seeded roles', () => {
  it('reads the seed (premise)', () => {
    expect(seededGrants('platform_admin').has('platform.settings')).toBe(true);
    expect(seededGrants('support_agent').has('platform.health')).toBe(true);
  });

  // super_admin holds every permission (seed.sql grants it the whole table).
  it('super_admin sees every section and sub-view, as before', () => {
    expect(visibleTree(() => true)).toEqual(EVERYTHING);
  });

  // platform_admin saw every entry before this change and must still: it holds
  // every permission the nav gates on.
  it('platform_admin sees every section and sub-view, as before', () => {
    const pa = seededGrants('platform_admin');
    expect(visibleTree((p) => pa.has(p))).toEqual(EVERYTHING);
  });

  // support_agent used to be shown Support ▸ Impersonation, Security ▸ Dashboard
  // and Security ▸ Policy, every call on which 403'd (it holds none of
  // platform.impersonate, platform.security, platform.settings). They are
  // hidden now. Everything it still sees, its grants let it use — Retention
  // and SIEM included, which audit-service now resolves from platform.audit.
  it('support_agent sees exactly what its grants open', () => {
    const sa = seededGrants('support_agent');
    expect(visibleTree((p) => sa.has(p))).toEqual([
      'overview',
      'tenants',
      'support', 'support/health', 'support/repair',
      'fleet',
      'jobs',
      'system', 'system/services', 'system/gateway', 'system/alerts',
      'staff', 'staff/staff',
      'security', 'security/activity', 'security/retention', 'security/siem',
    ]);
  });
});

describe('custom roles', () => {
  const only = (...perms: string[]) => visibleTree((p) => perms.includes(p));

  // plans-billing-13: billing alone used to show a Plans & Pricing section that
  // 403'd on every call; settings alone could manage tiers over the API but not
  // reach the page.
  it('platform.billing alone does not open Plans & Pricing', () => {
    expect(only('platform.billing')).not.toContain('plans');
  });
  it('platform.settings alone opens Plans & Pricing', () => {
    expect(only('platform.settings')).toContain('plans');
  });

  // Owner decision 10 (RC-21): the Impersonation sub-view is gone — it listed
  // an audit trail nothing could write. platform.impersonate alone therefore
  // opens nothing in Support.
  it('platform.impersonate alone opens no Support entry', () => {
    expect(only('platform.impersonate').filter((e) => e.startsWith('support'))).toEqual([]);
  });

  it('a sub-view gate hides only that sub-view', () => {
    const settingsOnly = only('platform.settings');
    expect(settingsOnly).toContain('settings/email');
    expect(settingsOnly).not.toContain('settings/notifications');
  });

  it('gateAllows passes an ungated entry', () => {
    expect(gateAllows({}, () => false)).toBe(true);
  });

  it('gateAllows requires every allOf permission', () => {
    const gate = { allOf: ['platform_roles.read', 'platform_permissions.read'] };
    expect(gateAllows(gate, (p) => p === 'platform_roles.read')).toBe(false);
    expect(gateAllows(gate, () => true)).toBe(true);
  });
});
