// Dashboard navigation parity — the reachability check, made mechanical.
//
// Four registries describe the Dashboard section: the dashboard catalogue
// (`dashboards.ts`), the rail (`nav.ts`), the router (`App.tsx`) and ⌘K
// (`command-palette.tsx`). They can drift in every direction, and none of the
// drifts shows up in a typecheck or a build:
//
//   · a dashboard with no rail entry is a page nobody can reach without typing
//     a URL — "a route with no named entry point is dead code";
//   · a rail entry with no route is a link to the app's Not Found page;
//   · a route with no dashboard entry is an orphaned component.
//
// This is the same guard shape `inventory-nav.test.ts` puts on the Inventory
// section, for the same reason: the feature framework's Reachability check is a
// merge gate, and a gate a human has to remember to run is not a gate.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { SECTIONS } from './nav';
import { DASHBOARD_NAV_ITEMS, NAV_ITEMS } from './command-palette';
import { DASHBOARDS, findDashboard, subDashboards } from '../sections/dashboard/dashboards';

const dashboard = SECTIONS.find((s) => s.id === 'dashboard')!;
const railItems = (dashboard.groups ?? []).flatMap((g) => g.items);

/**
 * The `/dashboard*` paths App.tsx actually serves, read from the source.
 *
 * Read as TEXT rather than by importing App: importing it pulls the whole route
 * tree and every page's module graph into a jsdom-less test. The regex is
 * anchored on the literal `<Route path="…">` form the file uses throughout, and
 * the "finds something at all" assertion below is what stops a scan that
 * silently matches nothing from passing every case vacuously.
 */
function routedDashboardPaths(): string[] {
  const src = readFileSync(new URL('../App.tsx', import.meta.url), 'utf8');
  return [...src.matchAll(/<Route\s+path="(\/dashboard[^"]*)"/g)].map((m) => m[1]);
}

describe('the dashboard registry', () => {
  it('keeps Overview on the bare /dashboard path', () => {
    // `/` redirects here, the settings drawer falls back here, and every
    // bookmark in existence points here. Moving it costs all three and buys
    // nothing.
    expect(findDashboard('overview')!.path).toBe('/dashboard');
  });

  it('lists the dashboards, Overview first', () => {
    expect(DASHBOARDS.map((d) => d.key)).toEqual(['overview', 'assets', 'compliance', 'pqc', 'overview-next']);
  });

  it('gives every non-Overview dashboard a /dashboard/<key> path', () => {
    for (const d of subDashboards()) expect(d.path).toBe(`/dashboard/${d.key}`);
  });

  it('gives every entry a unique key and path', () => {
    expect(new Set(DASHBOARDS.map((d) => d.key)).size).toBe(DASHBOARDS.length);
    expect(new Set(DASHBOARDS.map((d) => d.path)).size).toBe(DASHBOARDS.length);
  });

  it('gives every entry a sublabel that says what the page answers', () => {
    // The palette matches on sublabel as well as label, so an empty one makes
    // the page findable only by its exact name.
    for (const d of DASHBOARDS) expect(d.sublabel.length).toBeGreaterThan(15);
  });
});

describe('registry ↔ rail', () => {
  it('gives the Dashboard section a sub-nav group at all', () => {
    // Before this work the section had no `groups`, so the three focused pages
    // would have been URL-only.
    expect(dashboard.groups?.length).toBe(1);
    expect(railItems.length).toBeGreaterThan(0);
  });

  it('gives EVERY dashboard a rail entry', () => {
    const railPaths = railItems.map((i) => i.path);
    const orphans = DASHBOARDS.filter((d) => !railPaths.includes(d.path)).map((d) => d.key);
    expect(orphans).toEqual([]);
  });

  it('points every rail entry at a dashboard that exists', () => {
    const paths = DASHBOARDS.map((d) => d.path);
    expect(railItems.filter((i) => !paths.includes(i.path)).map((i) => i.path)).toEqual([]);
  });

  it('labels each rail entry with the registry label, in registry order', () => {
    expect(railItems.map((i) => i.label)).toEqual(DASHBOARDS.map((d) => d.label));
  });

  it('marks none of them a cross-link', () => {
    // `crossLink` renders an arrow meaning "this leaves the section". All four
    // of these ARE the section.
    for (const item of railItems) expect(item.crossLink).toBeUndefined();
  });
});

describe('registry ↔ router', () => {
  const routed = routedDashboardPaths();

  it('finds the dashboard routes in App.tsx at all', () => {
    // A scan that matches nothing must fail, or every assertion below passes
    // vacuously — the "a check that cannot fail is worse than no check" rule.
    expect(routed.length).toBeGreaterThanOrEqual(DASHBOARDS.length);
  });

  it('serves a route for EVERY dashboard', () => {
    const missing = DASHBOARDS.filter((d) => !routed.includes(d.path)).map((d) => d.path);
    expect(missing).toEqual([]);
  });

  it('serves no /dashboard route that is not in the registry', () => {
    const extra = routed.filter((p) => !DASHBOARDS.some((d) => d.path === p));
    expect(extra).toEqual([]);
  });
});

describe('registry ↔ command palette', () => {
  it('offers EVERY dashboard', () => {
    const offered = DASHBOARD_NAV_ITEMS.map((i) => i.to);
    for (const d of DASHBOARDS) {
      expect(offered, `⌘K does not offer ${d.path}`).toContain(d.path);
    }
  });

  it('is actually wired into the palette list, not just exported', () => {
    // The failure this catches: defining DASHBOARD_NAV_ITEMS and forgetting to
    // spread it into NAV_ITEMS. Everything above still passes; the palette
    // shows nothing.
    const navTargets = NAV_ITEMS.map((i) => i.to);
    for (const d of DASHBOARDS) expect(navTargets).toContain(d.path);
  });

  it('keeps the plain "Dashboard" label for Overview', () => {
    const overview = DASHBOARD_NAV_ITEMS.find((i) => i.to === '/dashboard')!;
    expect(overview.label).toBe('Dashboard');
  });

  it('prefixes the focused dashboards with the section, as the rail reads', () => {
    for (const d of subDashboards()) {
      const entry = DASHBOARD_NAV_ITEMS.find((i) => i.to === d.path)!;
      expect(entry.label).toBe(`Dashboard · ${d.label}`);
    }
  });

  it('gives every entry a unique id across the WHOLE palette', () => {
    const ids = NAV_ITEMS.map((i) => i.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('finds the PQC dashboard by the words a person would actually type', () => {
    // "PQC" is a label nobody searches for cold. The sublabel is what makes
    // "quantum" and "migration" land on this page.
    const pqc = DASHBOARD_NAV_ITEMS.find((i) => i.to === '/dashboard/pqc')!;
    const haystack = `${pqc.label} ${pqc.sublabel ?? ''}`.toLowerCase();
    for (const term of ['pqc', 'quantum', 'migration']) {
      expect(haystack, `typing “${term}” finds nothing`).toContain(term);
    }
  });
});
