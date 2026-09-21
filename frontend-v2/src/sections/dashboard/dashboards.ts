// The Dashboard section's registry — the four dashboards, in rail order.
//
// One list, three consumers: the rail (`app/nav.ts`), the router (`App.tsx`) and
// ⌘K (`app/command-palette.tsx`). The Inventory section learned this the hard
// way — its nav registry and its lens catalogue drifted in both directions, and
// neither a typecheck nor a build says anything when they do. `dashboard-nav.test.ts`
// joins this registry against all three consumers so a dashboard cannot exist
// without a rail entry, and a rail entry cannot point at a route nobody serves.
//
// Why four pages rather than four tabs on one: the Dashboard section previously
// had no sub-nav at all, and the v2 UI pattern puts sub-navigation in the left
// rail rather than in in-page chrome (see the Findings lenses and the Posture
// views, both of which hang off the rail). Distinct pathnames also mean the
// generic `s.groups` block in app-shell renders this section with no special
// case — unlike Inventory, whose items differ only by `?lens=` and therefore
// needed a block of its own.

export interface DashboardEntry {
  /** Stable key — the palette id suffix and the test's join column. */
  key: string;
  /** Rail label. */
  label: string;
  /** Route path. `/dashboard` for the overview, `/dashboard/<key>` for the rest. */
  path: string;
  /** ⌘K sublabel: what question this page answers. Also the customer-doc blurb. */
  sublabel: string;
}

/**
 * Overview keeps the bare `/dashboard` path.
 *
 * It is the app's index redirect target, the ⌘K "Dashboard" entry and the
 * fallback the settings drawer returns to — moving it to `/dashboard/overview`
 * would break all three plus every bookmark, and buy nothing.
 */
export const DASHBOARDS: DashboardEntry[] = [
  {
    key: 'overview',
    label: 'Overview',
    path: '/dashboard',
    sublabel: 'Health overview across every section',
  },
  {
    key: 'assets',
    label: 'Assets',
    path: '/dashboard/assets',
    sublabel: 'Configuration items — composition, lifecycle and data quality',
  },
  {
    key: 'compliance',
    label: 'Compliance',
    path: '/dashboard/compliance',
    sublabel: 'Framework scores, findings and remediation standing',
  },
  {
    key: 'pqc',
    label: 'PQC',
    path: '/dashboard/pqc',
    sublabel: 'Post-quantum readiness and the migration worklist',
  },
];

/** The three pages added by the multi-dashboard work, i.e. everything but Overview. */
export function subDashboards(): DashboardEntry[] {
  return DASHBOARDS.filter((d) => d.key !== 'overview');
}

export function findDashboard(key: string): DashboardEntry | undefined {
  return DASHBOARDS.find((d) => d.key === key);
}
