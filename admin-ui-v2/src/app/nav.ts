// VISTA Operations primary navigation — the 10-section operator IA from the
// design kit (ops-shell.jsx `NAV`). This is the redesigned information
// architecture (the design team's keep/cut/redesign pass), not the v1 admin-ui
// mirror. Three groups: ungrouped, Platform, Governance. `source` notes the v1
// admin-ui surface(s) each section supersedes (Migration Ledger key).
//
// ── Core vs MSP/Enterprise (admin-service carve) ────────────────────────────
// admin-service is split: a Core build ships a barebones single-organization
// operator console and does NOT mount the MSP management plane
// (/admin/tenants/**, /admin/stats/**, /admin/dashboard/**, /admin/costs/**,
// /admin/announcements, /admin/maintenance-windows, /admin/support-tickets,
// /admin/legal/acceptances, /admin/monitoring/metrics) or the Enterprise
// billing surface (/admin/billing/**). Those routes 404 in a Core deployment —
// they are absent, not forbidden, so no permission check can stand in for this.
//
// The partition, verified route-by-route against the running Core deployment
// (Core routes answer 401 unauthenticated; absent ones answer 404):
//   Core        support · fleet · jobs · plans · system · catalog · settings ·
//               staff · security
//   MSP-only    tenants · comms
//   Enterprise  billing (its finops child reads /admin/costs, which is MSP)
//   Partial     overview (revenue hero = billing, tenant roster = MSP; the
//               service-health tiles are Core) ·
//               settings → legal (authoring is Core, the acceptance ledger is
//               MSP)
//
// `edition` below marks the sections/children a build must actually ship for
// the entry to appear. It is resolved at runtime from
// GET /api/v1/admin-service/admin/platform/edition (src/lib/edition.ts) and
// applied by `visibleSections`, which the shell renders and App.tsx guards.
// The partial cases are gated inside their own pages — a section is only listed
// here when the WHOLE section is absent.
//
// Not covered here: SIEM Export under Security & Trust lives in
// audit-service/ee/siemexport, a different binary this read-out cannot speak
// for. It keeps its own response probe (sections/security/audit-queries.ts,
// via packages/primitives/src/features/edition.ts) and renders an edition
// notice rather than an error.
import { PLATFORM_PERMISSIONS } from '@vistasecurity/primitives/platform-auth';
import type { EditionCapabilities, EditionCapability } from '../lib/edition';

/**
 * A sub-section. Sub-navigation in the v2 UI lives in the LEFT rail, indented
 * under its parent section — NOT as in-page/data-view tabs (that was the v1
 * pattern). Each child is its own route at /<parent>/<id>; the first child is
 * the section's default (index) view. The section component is a layout that
 * renders an internal <Routes> mapping each child id to a sub-page; see
 * sections/security/security-page.tsx for the reference implementation.
 */
export interface NavChild {
  /** sub-route segment: /<parent>/<id>. */
  id: string;
  label: string;
  /** topbar title when this child is active. */
  title: string;
  /** topbar subtitle when this child is active. */
  subtitle: string;
  /**
   * Optional grandchildren, rendered indented one level deeper under this child
   * in the left rail. Their route is /<section>/<child>/<grandchild>. Used when a
   * sub-view has its own drill-in.
   */
  children?: NavChild[];
  /**
   * Admin-service capability this sub-view's backend needs. Absent in the
   * running build ⇒ the rail entry is hidden and the route renders an
   * edition notice instead of a page whose calls 404.
   */
  edition?: EditionCapability;
}

export interface NavItem {
  /** route id (also the path: /<id>, or /<id>/* when it has children). */
  id: string;
  label: string;
  /** lucide-react icon name (see ICONS map in app-shell). */
  icon: string;
  /** group header this item sits under (null = the top, ungrouped block). */
  group: 'Platform' | 'Governance' | null;
  /** topbar title + subtitle for the section (TITLES map in the prototype). */
  title: string;
  subtitle: string;
  /** left-nav sub-items, rendered indented under this section when active. */
  children?: NavChild[];
  /** v1 admin-ui page(s) this supersedes. */
  source?: string;
  /**
   * Platform permission required to VIEW this section — drives both the nav
   * filter (app-shell) and the route guard (RequirePlatformPermission in App.tsx).
   * Omit for sections every authenticated operator may see (e.g. Mission Control).
   * Write actions inside a section gate separately with PlatformPermissionGate on
   * the corresponding `.manage`/`.update`/`.delete` permission.
   */
  permission?: string;
  /** Any-of variant of `permission`: visible if the operator holds at least one. */
  anyOf?: string[];
  /**
   * Admin-service capability this section's backend needs ('msp' | 'billing').
   * Absent in the running build ⇒ the section is hidden from the rail and its
   * route renders an edition notice. RBAC is NOT a substitute: a Core operator
   * legitimately holds `tenants.read`, so permission gating alone still shows
   * a Tenants tab that 404s.
   */
  edition?: EditionCapability;
}

const P = PLATFORM_PERMISSIONS;

/** True if the operator may see this section, given a permission predicate. */
export function sectionVisible(s: NavItem, has: (p: string) => boolean): boolean {
  if (s.permission) return has(s.permission);
  if (s.anyOf?.length) return s.anyOf.some(has);
  return true;
}

/**
 * True if this build actually ships the backend an entry needs.
 *
 * Unmarked entries are Core and always pass — same default as the Go side
 * (shared/entitlements: unmapped keys are Core), so adding a nav entry never
 * accidentally hides it.
 */
export function editionAllows(
  entry: { edition?: EditionCapability },
  capabilities: EditionCapabilities,
): boolean {
  return !entry.edition || capabilities[entry.edition] !== false;
}

/**
 * SECTIONS filtered by BOTH gates — permission (who you are) and edition (what
 * this build ships) — with children and grandchildren filtered by edition too,
 * and any section left with no children dropped.
 *
 * Pure: the shell passes in the resolved predicate and capability map. Keeping
 * it here rather than inline in app-shell.tsx means the rule is unit-testable
 * and the shell's diff stays to one call.
 */
export function visibleSections(
  has: (p: string) => boolean,
  capabilities: EditionCapabilities,
  sections: NavItem[] = SECTIONS,
): NavItem[] {
  return sections
    .filter((s) => sectionVisible(s, has) && editionAllows(s, capabilities))
    .map((s) => {
      if (!s.children?.length) return s;
      const children = s.children
        .filter((c) => editionAllows(c, capabilities))
        .map((c) =>
          c.children?.length
            ? { ...c, children: c.children.filter((g) => editionAllows(g, capabilities)) }
            : c,
        );
      return { ...s, children };
    })
    .filter((s) => !s.children || s.children.length > 0);
}

export const SECTIONS: NavItem[] = [
  { id: 'overview', label: 'Mission Control', icon: 'Gauge', group: null,
    title: 'Mission Control', subtitle: 'Platform health, revenue, fleet, and what needs you', source: 'dashboard-page' },
  // Tenants — the MSP management plane's front door. EVERY data call in this
  // section (directory, detail, stats, lifecycle, per-tenant entitlements)
  // comes from ee/msp, so a Core build has nothing to show: tenants reach a
  // Core deployment through self-service signup, and there is no console path
  // to create or manage them.
  { id: 'tenants', label: 'Tenants', icon: 'Building2', group: null,
    title: 'Tenants', subtitle: 'Every customer organization', source: 'tenants-page (+ detail/sso/billing/entitlements)', permission: P.tenants.read,
    edition: 'msp' },
  // Support — the customer-success operator cockpit. Three read/repair sub-views,
  // all on the typed contract (tenant-health, auth impersonation audit, device
  // interrogation job repair).
  { id: 'support', label: 'Support', icon: 'LifeBuoy', group: null,
    title: 'Support', subtitle: 'Tenant health, impersonation, and job repair', source: '(new — CS cockpit)', permission: P.tenants.read,
    children: [
      { id: 'health', label: 'Tenant Health', title: 'Tenant Health', subtitle: 'Per-tenant health scores and alerts' },
      { id: 'impersonation', label: 'Impersonation', title: 'Impersonation', subtitle: 'Support impersonation sessions and history' },
      { id: 'repair', label: 'Job Repair', title: 'Job Repair', subtitle: 'Retry or cancel stuck discovery jobs' },
    ] },
  { id: 'fleet', label: 'Fleet', icon: 'Radar', group: null,
    title: 'Fleet', subtitle: 'Every discovery sensor and agent across all tenants', source: 'platform-devices-page', permission: P.platform.health },
  { id: 'jobs', label: 'Jobs & Queues', icon: 'Workflow', group: null,
    title: 'Jobs & Queues', subtitle: 'Discovery runs and platform pipelines', source: 'jobs-page', permission: P.platform.health },
  // Billing & Revenue — RevOps only (ADR-0004 / Slice 5). Tiers + Billable
  // Items moved to Plans & Pricing; the remaining money views are left-rail
  // sub-routes (no more in-page tabs).
  { id: 'billing', label: 'Billing & Revenue', icon: 'Wallet', group: null,
    title: 'Billing & Revenue', subtitle: 'MRR, invoices, coupons, trials, dunning',
    source: 'billing-analytics/invoices/coupons/trials/payment-recovery/cost-monitoring (Revenue area)', permission: P.platform.billing,
    // Whole section is ee/billingapi (Stripe, invoices, coupons, trials,
    // dunning, revenue analytics). Core ships no monetization code at all.
    edition: 'billing',
    children: [
      { id: 'overview', label: 'Overview', title: 'Billing Overview', subtitle: 'MRR, ARR, revenue by plan, and invoices' },
      { id: 'coupons', label: 'Coupons', title: 'Coupons', subtitle: 'Discount codes and redemptions' },
      { id: 'trials', label: 'Trials', title: 'Trials', subtitle: 'Trial-conversion analytics' },
      { id: 'dunning', label: 'Dunning', title: 'Payment Recovery', subtitle: 'Past-due invoices and recovery' },
      // FinOps reads /admin/costs, which is MSP rather than billing — marked
      // separately so the two stay independent if the editions ever diverge.
      { id: 'finops', label: 'FinOps', title: 'Platform Cost', subtitle: 'Infrastructure cost by service and tenant', edition: 'msp' },
    ] },
  // Plans & Pricing — the packaging area (ADR-0004). Entitlements = the lever
  // catalog (billable_items; absorbs the retired Feature Flags section); Tiers
  // and Add-ons land in later slices of.
  { id: 'plans', label: 'Plans & Pricing', icon: 'Layers', group: null,
    title: 'Plans & Pricing', subtitle: 'Entitlements, tiers, and add-ons — what we sell and how it’s composed',
    source: 'feature-flags registry + billing-analytics/billable-items + subscription-tiers', permission: P.platform.billing,
    children: [
      { id: 'entitlements', label: 'Entitlements', title: 'Entitlements', subtitle: 'The lever catalog: capability gates, capacity caps, metered meters, support' },
      { id: 'tiers', label: 'Tiers', title: 'Tiers', subtitle: 'Compose entitlements into plans, price, and publish' },
      { id: 'addons', label: 'Add-ons', title: 'Add-ons', subtitle: 'Flat à-la-carte lever packs' },
    ] },

  { id: 'system', label: 'System Health', icon: 'Activity', group: 'Platform',
    title: 'System Health', subtitle: 'Services, uptime, incidents', source: 'platform-services-status/platform-overview/gateway', permission: P.platform.health,
    children: [
      { id: 'services', label: 'Services', title: 'Service Health', subtitle: 'Backend service status and latency' },
      { id: 'gateway', label: 'Gateway', title: 'API Gateway', subtitle: 'Routers, services, and routing health' },
      { id: 'alerts', label: 'Alerts', title: 'System Alerts', subtitle: 'Alert history and thresholds' },
    ] },
  { id: 'comms', label: 'Comms', icon: 'Megaphone', group: 'Platform',
    title: 'Comms', subtitle: 'Customer announcements and maintenance windows',
    source: 'announcements + maintenance-windows', permission: P.platform.notificationsManage,
    // Both children are ee/msp: announcing to, and scheduling downtime for,
    // OTHER organizations is the management plane's job.
    edition: 'msp',
    children: [
      { id: 'announcements', label: 'Announcements', title: 'Announcements', subtitle: 'Platform-wide announcements' },
      { id: 'maintenance', label: 'Maintenance', title: 'Maintenance Windows', subtitle: 'Scheduled maintenance windows' },
    ] },
  { id: 'catalog', label: 'Catalog', icon: 'Library', group: 'Platform',
    title: 'Catalog', subtitle: 'Algorithm source of truth and framework catalog', source: 'measurement-templates/compliance-frameworks', permission: P.algorithms.manage,
    children: [
      { id: 'ratings', label: 'Algorithms', title: 'Algorithms', subtitle: 'Crypto-assessment source of truth' },
      { id: 'frameworks', label: 'Frameworks', title: 'Framework Catalog', subtitle: 'Compliance framework authoring' },
    ] },
  { id: 'settings', label: 'Settings', icon: 'Settings2', group: 'Platform',
    title: 'Settings', subtitle: 'Platform configuration — email, branding, and notification delivery', source: 'settings-page', permission: P.platform.settings,
    children: [
      { id: 'email', label: 'Email', title: 'Email Delivery', subtitle: 'SMTP for invitations, resets, onboarding' },
      { id: 'access', label: 'Access & Sign-up', title: 'Access & Sign-up', subtitle: 'Self-service sign-up and email-verification gates' },
      { id: 'branding', label: 'Branding', title: 'Branding', subtitle: 'White-label the platform — product name, logos, and favicon' },
      { id: 'legal', label: 'Legal', title: 'Legal Documents', subtitle: 'Terms of Service and Privacy Policy — authoring, versioning, and acceptance audit' },
      { id: 'identity-providers', label: 'Identity Providers', title: 'Identity Providers', subtitle: "Vista's Google / Microsoft OAuth apps for social sign-up" },
      { id: 'notifications', label: 'Notification Delivery', title: 'Notification Delivery', subtitle: 'Channels, routing rules, and delivery history' },
    ] },

  { id: 'staff', label: 'Staff & Access', icon: 'UsersRound', group: 'Governance',
    title: 'Staff & Access', subtitle: 'VISTA internal users and roles', source: 'users-page/roles-page', permission: P.platformUsers.read,
    children: [
      { id: 'staff', label: 'Staff', title: 'Staff', subtitle: 'VISTA internal users' },
      { id: 'roles', label: 'Roles', title: 'Roles & Permissions', subtitle: 'Platform roles and their permissions' },
    ] },
  // Security & Trust — the consolidated "are we trustworthy" home (Governance). It
  // absorbed the dissolved Audit section (): Activity Log + Retention + SIEM
  // Export moved in alongside the existing Dashboard + Policy. The cut Audit sub-views
  // (Alerts, Alert Rules, Compliance Reports) were dropped. There is no standalone Audit
  // section anymore — its one daily-visited surface (the activity trail) lives here.
  { id: 'security', label: 'Security & Trust', icon: 'ShieldAlert', group: 'Governance',
    title: 'Security & Trust', subtitle: 'Posture, policy, and the platform activity trail',
    source: 'security-dashboard-page/security-settings-page/audit-page/impersonation-log-page', anyOf: [P.platform.security, P.platform.audit],
    children: [
      { id: 'dashboard', label: 'Dashboard', title: 'Security Dashboard', subtitle: 'Security events, anomalies, and posture' },
      { id: 'activity', label: 'Activity Log', title: 'Activity Log', subtitle: 'Platform-wide staff and tenant activity trail' },
      { id: 'retention', label: 'Retention', title: 'Retention Policies', subtitle: 'Log retention and archival' },
      { id: 'siem', label: 'SIEM Export', title: 'SIEM Integrations', subtitle: 'Outbound SIEM forwarding' },
      { id: 'policy', label: 'Policy', title: 'Security Policy', subtitle: 'Platform security and authentication settings' },
    ] },
];

/** Lookup by route id (for the topbar title/subtitle). */
export const SECTION_BY_ID: Record<string, NavItem> = Object.fromEntries(SECTIONS.map((s) => [s.id, s]));

/**
 * Resolve the active section + child from a pathname (e.g. "/security/siem").
 * `child` falls back to the section's first child when the sub-segment is absent
 * or unknown (so /<section> shows the default sub-view). `title`/`subtitle` are
 * the child's when a child is active, otherwise the section's.
 */
export function resolveActive(pathname: string): {
  sectionId: string;
  section?: NavItem;
  child?: NavChild;
  grandchild?: NavChild;
  title: string;
  subtitle: string;
} {
  const [, seg1, seg2, seg3] = pathname.split('/');
  const sectionId = seg1 || 'overview';
  const section = SECTION_BY_ID[sectionId];
  let child: NavChild | undefined;
  let grandchild: NavChild | undefined;
  if (section?.children?.length) {
    child = section.children.find((c) => c.id === seg2) ?? section.children[0];
    if (child?.children?.length && seg3) {
      grandchild = child.children.find((g) => g.id === seg3);
    }
  }
  // The active "leaf" (grandchild if on a /<section>/<child>/<grandchild> path,
  // else the child) drives the topbar title/subtitle.
  const leaf = grandchild ?? child;
  return {
    sectionId,
    section,
    child,
    grandchild,
    title: leaf?.title ?? section?.title ?? 'VISTA Operations',
    subtitle: leaf?.subtitle ?? section?.subtitle ?? '',
  };
}
