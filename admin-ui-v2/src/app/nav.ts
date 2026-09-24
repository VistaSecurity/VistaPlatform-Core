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
// /admin/announcements, /admin/support-tickets,
// /admin/legal/acceptances, /admin/monitoring/metrics) or the Enterprise
// billing surface (/admin/billing/**). Those routes 404 in a Core deployment —
// they are absent, not forbidden, so no permission check can stand in for this.
//
// The partition, verified route-by-route against the running Core deployment
// (Core routes answer 401 unauthenticated; absent ones answer 404):
//   Core        support · fleet · jobs · plans · system · catalog · settings ·
//               staff · security
//   MSP-only    tenants
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
import type { EditionCapabilities, EditionCapability, LicenseState } from '../lib/edition';

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
  /**
   * Platform permission this sub-view's backend requires to READ, when it is
   * not the section's own gate. It hides the rail entry AND guards the
   * sub-route (RequireChildPermission in section-child.tsx reads this same
   * field), so the nav gate and the route gate cannot differ. Omit when the
   * section's gate already covers the sub-view.
   */
  permission?: string;
  /** Any-of variant of `permission`. */
  anyOf?: string[];
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
   * Licence-edition gate, independent of `edition` (which is about the BUILD):
   *   'msp' — shown only when the licence is MSP. Billing & Revenue and Plans &
   *           Pricing: billing, plans and pricing are how a service provider
   *           sells to its own customers (edition-licensing spec §1). Enterprise
   *           has no plans, and Core is a single organisation with nobody to
   * sell to, so both are hidden there (owner decision.
   */
  license?: LicenseGate;
  /**
   * Admin-service capability this section's backend needs ('msp' | 'billing').
   * Absent in the running build ⇒ the section is hidden from the rail and its
   * route renders an edition notice. RBAC is NOT a substitute: a Core operator
   * legitimately holds `tenants.read`, so permission gating alone still shows
   * a Tenants tab that 404s.
   */
  edition?: EditionCapability;
}

export type LicenseGate = 'msp';

const P = PLATFORM_PERMISSIONS;

/**
 * True if the install's licence allows this entry. `pending` hides gated
 * entries (the nav grows, never shrinks, as the answer lands); `unknown` fails
 * open, like CAPABILITIES_UNKNOWN, so a read failure never blanks a paying MSP
 * console. Ungated entries always pass.
 */
export function licenseAllows(entry: { license?: LicenseGate }, license: LicenseState): boolean {
  if (!entry.license || license === 'unknown') return true;
  if (license === 'pending') return false;
  return license === 'msp';
}

/**
 * True if the operator passes an entry's permission gate. Ungated entries
 * pass — a child without a gate inherits its section's.
 */
export function gateAllows(entry: { permission?: string; anyOf?: string[] }, has: (p: string) => boolean): boolean {
  if (entry.permission) return has(entry.permission);
  if (entry.anyOf?.length) return entry.anyOf.some(has);
  return true;
}

/** True if the operator may see this section, given a permission predicate. */
export function sectionVisible(s: NavItem, has: (p: string) => boolean): boolean {
  return gateAllows(s, has);
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
 * this build ships) — with children and grandchildren filtered by both too,
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
  license: LicenseState = 'unknown',
): NavItem[] {
  return sections
    .filter((s) => sectionVisible(s, has) && editionAllows(s, capabilities) && licenseAllows(s, license))
    .map((s) => {
      if (!s.children?.length) return s;
      const children = s.children
        .filter((c) => editionAllows(c, capabilities) && gateAllows(c, has))
        .map((c) =>
          c.children?.length
            ? { ...c, children: c.children.filter((g) => editionAllows(g, capabilities) && gateAllows(g, has)) }
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
  // Support — the customer-success operator cockpit. Two read/repair sub-views,
  // both on the typed contract (tenant-health, device interrogation job
  // repair), and both read with platform.health:
  //   health        tenant-health-service /tenants/**      platform.health
  //   repair        device-interrogation /admin/jobs        platform.health
  //                 (retry/cancel additionally need tenants.manage; the page
  //                 gates those buttons)
  // It used to gate the whole section on tenants.read, which none of these
  // backends checks — a support_agent saw pages that all 403'd.
  //
  // There is no Impersonation sub-view. It listed an audit trail that nothing
  // could ever write — no start/stop flow exists — so it was always empty
  // (owner decision 10, RC-21). Impersonation is seeded as a feature
  // (break-glass, audited, time-boxed) in the feature index; the page comes
  // back with that flow, not before.
  { id: 'support', label: 'Support', icon: 'LifeBuoy', group: null,
    title: 'Support', subtitle: 'Tenant health and job repair', source: '(new — CS cockpit)',
    permission: P.platform.health,
    children: [
      { id: 'health', label: 'Tenant Health', title: 'Tenant Health', subtitle: 'Per-tenant health scores and alerts', permission: P.platform.health },
      { id: 'repair', label: 'Job Repair', title: 'Job Repair', subtitle: 'Retry or cancel stuck discovery jobs', permission: P.platform.health },
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
    // And billing is MSP-only by LICENCE: an Enterprise company has nobody
    // to bill, so the section is hidden unless the licence is MSP.
    license: 'msp',
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
  //
  // platform.settings, because that is what every route it calls requires
  // (admin-service /admin/tiers/** and /admin/billable-items/**, which the
  // Tenants drawer also reads). It was platform.billing, so a role holding
  // billing alone saw a section that 403'd on every call and a role holding
  // settings alone could manage tiers over the API but not reach the page.
  { id: 'plans', label: 'Plans & Pricing', icon: 'Layers', group: null,
    title: 'Plans & Pricing', subtitle: 'Entitlements, tiers, and add-ons — what we sell and how it’s composed',
    source: 'feature-flags registry + billing-analytics/billable-items + subscription-tiers', permission: P.platform.settings,
    // MSP only. Enterprise has no plans (every tenant gets the licence, minus
    // per-tenant switches in the tenant drawer), and Core is one organisation
    // with nobody to sell plans to. The tier ROUTES stay mounted on Core —
    // shared/entitlements still resolves against the seeded tiers — only the
    // authoring area is hidden.
    license: 'msp',
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
  // There is no Comms section (owner decision 9, RC-20). Its two sub-views
  // are gone:
  //   Maintenance   wrote public.maintenance_windows, which nothing read.
  //                 Alert suppression reads platform_maintenance_windows, whose
  //                 form is System → Alerts; that is the one store now.
  //                 /comms/maintenance redirects there (App.tsx).
  //   Announcements saved announcements nothing delivered to any tenant. It is
  //                 hidden until tenant delivery exists (seeded in the feature
  //                 index); admin-service /admin/announcements stays mounted
  //                 for that work to build on.
  // Catalog — the platform's curated reference data. Crypto is ONE catalogue
  // among several (ADR-0006 D7), which is why End-of-life and Vulnerability feed
  // sit here beside Algorithms and Frameworks rather than in a section of their
  // own. All four are platform-scoped: no tenant_id, every tenant evaluated
  // against the same rows.
  //
  // `anyOf` rather than a single permission: the two new catalogues are gated on
  // `catalogs.manage` server-side, because curating crypto ratings and
  // re-pointing the platform at a vulnerability source are different trust
  // decisions. Both are granted to super_admin and platform_admin today, so
  // nothing changes in practice until someone splits them.
  { id: 'catalog', label: 'Catalog', icon: 'Library', group: 'Platform',
    title: 'Catalog', subtitle: 'Algorithms, frameworks, end-of-life and vulnerability data', source: 'measurement-templates/compliance-frameworks',
    anyOf: [P.algorithms.manage, P.catalogs.manage],
    children: [
      { id: 'ratings', label: 'Algorithms', title: 'Algorithms', subtitle: 'Crypto-assessment source of truth' },
      // compliance-engine /admin/frameworks/** — catalogs.manage for reads too.
      { id: 'frameworks', label: 'Frameworks', title: 'Framework Catalog', subtitle: 'Compliance framework authoring', permission: P.catalogs.manage },
      // Three views of one catalogue (ADR-0008 workstream 4.5b). Sub-navigation
      // in this console lives in the LEFT rail — see the NavChild doc comment —
      // so Proposals and Gaps are grandchildren with their own routes, not
      // in-page tabs. They are Core: a Core deployment has the lookup, the gap
      // list and the review queue, and an empty queue.
      { id: 'eol', label: 'End-of-life', title: 'End-of-life Catalogue', subtitle: 'Release cycles and their support dates, mirrored from endoflife.date',
        permission: P.catalogs.manage,
        children: [
          { id: 'catalogue', label: 'Catalogue', title: 'End-of-life Catalogue', subtitle: 'Release cycles and their support dates, mirrored from endoflife.date' },
          { id: 'proposals', label: 'Proposals', title: 'End-of-life Proposals', subtitle: 'AI-proposed catalogue rows awaiting review — nothing here is in the catalogue yet' },
          { id: 'gaps', label: 'Gaps', title: 'End-of-life Gaps', subtitle: 'Products the catalogue could not answer for, ordered by how often they were asked about' },
        ] },
      { id: 'vulnerabilities', label: 'Vulnerability feed', title: 'Vulnerability Catalogue', subtitle: 'CVEs mirrored from NVD and OSV, and the health of both feeds', permission: P.catalogs.manage },
      { id: 'classification-rules', label: 'Classification rules', title: 'Classification Rules', subtitle: 'The fingerprint rules behind every class proposal — OUI, sysObjectID, cloud type, banner, model, platform', permission: P.catalogs.manage },
    ] },
  { id: 'settings', label: 'Settings', icon: 'Settings2', group: 'Platform',
    title: 'Settings', subtitle: 'Platform configuration — email, branding, and notification delivery', source: 'settings-page', permission: P.platform.settings,
    children: [
      { id: 'email', label: 'Email', title: 'Email Delivery', subtitle: 'SMTP for invitations, resets, onboarding' },
      { id: 'access', label: 'Access & Sign-up', title: 'Access & Sign-up', subtitle: 'Self-service sign-up and email-verification gates' },
      { id: 'branding', label: 'Branding', title: 'Branding', subtitle: 'White-label the platform — product name, logos, and favicon' },
      { id: 'legal', label: 'Legal', title: 'Legal Documents', subtitle: 'Terms of Service and Privacy Policy — authoring, versioning, and acceptance audit' },
      { id: 'identity-providers', label: 'Identity Providers', title: 'Identity Providers', subtitle: "Vista's Google / Microsoft OAuth apps for social sign-up" },
      // notification-service /platform/** — platform.notifications.manage.
      { id: 'notifications', label: 'Notification Delivery', title: 'Notification Delivery', subtitle: 'Channels, routing rules, and delivery history', permission: P.platform.notificationsManage },
      // Core: a Core build answers "no licence installed", which is this
      // page's Core state (GET /admin/license is Core code).
      { id: 'license', label: 'License & Usage', title: 'License & Usage', subtitle: 'The licence this install runs under, and the data-retention cap' },
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
  //
  // Each sub-view carries the permission its backend reads with; the section is
  // visible to anyone holding one of them:
  //   dashboard  admin-service /admin/security/**          platform.security
  //   activity   audit-service /activity-logs (no permission gate for a
  //              platform token) — kept on the section's historic pair
  //   retention  audit-service /retention-policies        platform.audit
  //   siem       audit-service /siem/integrations          platform.audit
  //              (both pages gate their writes on platform.audit.manage)
  //   policy     admin-service GET /admin/settings        platform.settings
  //              (editing needs platform.security.manage, enforced server-side
  // per key since; the page renders read-only without it)
  { id: 'security', label: 'Security & Trust', icon: 'ShieldAlert', group: 'Governance',
    title: 'Security & Trust', subtitle: 'Posture, policy, and the platform activity trail',
    source: 'security-dashboard-page/security-settings-page/audit-page/impersonation-log-page',
    anyOf: [P.platform.security, P.platform.audit, P.platform.settings],
    children: [
      { id: 'dashboard', label: 'Dashboard', title: 'Security Dashboard', subtitle: 'Security events, anomalies, and posture', permission: P.platform.security },
      { id: 'activity', label: 'Activity Log', title: 'Activity Log', subtitle: 'Platform-wide staff and tenant activity trail', anyOf: [P.platform.security, P.platform.audit] },
      { id: 'retention', label: 'Retention', title: 'Retention Policies', subtitle: 'Log retention and archival', permission: P.platform.audit },
      { id: 'siem', label: 'SIEM Export', title: 'SIEM Integrations', subtitle: 'Outbound SIEM forwarding', permission: P.platform.audit },
      { id: 'policy', label: 'Policy', title: 'Security Policy', subtitle: 'Platform security and authentication settings', permission: P.platform.settings },
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
    if (child?.children?.length) {
      // Same fallback as the line above, one level down: /<section>/<child>
      // with no third segment shows the child's DEFAULT sub-view, so the rail
      // highlights it and the topbar names it. Without this, the bare URL
      // rendered a page whose rail entry looked unselected.
      grandchild = (seg3 ? child.children.find((g) => g.id === seg3) : undefined) ?? child.children[0];
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
