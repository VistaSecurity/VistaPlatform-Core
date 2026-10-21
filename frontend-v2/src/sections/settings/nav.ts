// Settings & My Profile navigation registries — ported from the mock's
// Shell.jsx SETTINGS_NAV and settings/profile.jsx PROFILE_NAV. `built` marks
// pages wired to live data in this build; the rest render the mock's
// "Spec'd — design pending" panel. `permission` (optional) gates the page via
// the RBAC primitives — viewers without it get an access notice, not the data.
// `feature` (optional) gates the page on EDITION/entitlement — a Core build
// does not mount the Enterprise routes these pages call, so the entry is hidden
// entirely and a deep link gets an upgrade card (never a 404-ing page).
//
// RBAC-hiding is not edition-hiding: a Tenant Admin has `settings.read` on a
// Core install too, so `permission` alone leaves Enterprise pages reachable.
import { TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import type { FeatureName, FeaturesMap } from '@vistasecurity/primitives/features';

export interface SettingsNavItem {
  key: string;
  label: string;
  /** kebab-case lucide icon name (components/ui Icon) */
  icon: string;
  /** one-line "job statement" shown under the page title (from the mock) */
  job: string;
  built?: boolean;
  permission?: string;
  danger?: boolean;
  /**
   * This page began life in the Settings drawer but is an operational tenant
   * workspace.  When present the Settings entry is hidden and the legacy
   * `/settings/:key` route redirects here, preserving bookmarks without
   * keeping two homes for the same object.
   */
  workspacePath?: string;
  /**
   * Entitlement key that must be on for this page to exist. Off ⇒ the rail
   * entry is hidden and the route renders `lock` instead of the page body.
   */
  feature?: FeatureName;
  /** Upgrade-card copy shown when `feature` is off. Required alongside it. */
  lock?: { title: string; message: string };
  /**
   * Interim, edition-INDEPENDENT kill-switch: the page still mounts (entitled
   * tenants keep read access to whatever they already have), but the page is
   * expected to hide every create/edit/delete affordance and show this notice
   * instead — a known-broken capability, not an entitlement gate. Distinct
   * from `lock`, which replaces the whole page body when the tenant simply
   * isn't entitled. Unlike `lock`, nothing here is edition-conditional.
   */
  authoringDisabled?: { title: string; message: string };
}
export interface SettingsNavSection {
  section: string;
  items: SettingsNavItem[];
}

export const SETTINGS_NAV: SettingsNavSection[] = [
  { section: 'Organization', items: [
    { key: 'org-overview', label: 'Overview', icon: 'building-2', built: true, job: "Edit core organization metadata — name, domain, billing email — and glance at the frameworks you're licensed for." },
    // dcim.read: the page reads /dcim/business-units; the write controls inside
    // it are behind business_units.manage (tenant admin only).
    { key: 'business-units', label: 'Business Units', icon: 'building-2', built: true, permission: TENANT_PERMISSIONS.dcim.read, workspacePath: '/inventory/manage/business-units', job: 'Define the parties assets belong to - departments, customers, cost centres - as a tree, and reassign their assets when one goes away.' },
    // DCIM row 2.1: the Region › Site group › Site › Location tree. Replaces the
    // 4.x Settings → Locations page, whose single typed tree it splits apart.
    { key: 'sites', label: 'Sites', icon: 'map-pin', built: true, permission: TENANT_PERMISSIONS.dcim.read, workspacePath: '/inventory/manage/sites', job: 'Maintain the regions, site groups and sites your assets live in, and the halls, cages and rows inside each site.' },
    // DCIM row 5.4: the page reads /dcim/saved-filters (assets.read). Editing a
    // shared filter needs settings.update, which the page checks from the list.
    { key: 'saved-filters', label: 'Saved Filters', icon: 'bookmark', built: true, permission: TENANT_PERMISSIONS.assets.read, workspacePath: '/inventory/manage/saved-filters', job: 'Review the query filters you and your organization have saved, and edit or delete them. Filters are saved from the Filters menu on a lens.' },
    // DCIM row 2.3: racks, their reservations and utilisation. Row 2.5 adds the
    // Inventory → Racks lens and the drawn elevation.
    { key: 'racks', label: 'Racks', icon: 'server', built: true, permission: TENANT_PERMISSIONS.dcim.read, workspacePath: '/inventory/manage/racks', job: 'Maintain the racks in each site, their height and role, and the units reserved in them; place assets from their Placement card.' },
    // DCIM row 2.4: the module-type catalogue (2.2 left it API-only). Folds
    // into Settings → Device Types as a tab once that page is on main.
    { key: 'module-types', label: 'Module Types', icon: 'blocks', built: true, permission: TENANT_PERMISSIONS.dcim.read, workspacePath: '/inventory/manage/module-types', job: 'Browse the module types — line cards, network modules, power supplies — that can be installed in an asset\'s module bays, and add your own.' },
    { key: 'org-branding', label: 'Branding', icon: 'palette', built: true, permission: TENANT_PERMISSIONS.settings.read, job: 'Upload your logo and favicon and set the display name to white-label the console.' },
  ] },
  { section: 'Account', items: [
    // NOT feature-gated (edition-licensing spec §6): every tenant sees what it
    // is on — "Vista Platform Core", "Vista Platform Enterprise, provided by
    // <licensee>", or its MSP plan. Only the billing CONTROLS inside the page
    // (subscription, invoices, payment portal) follow `billing_portal`, which
    // resolves on only on an MSP install whose plan includes it.
    {
      key: 'billing', label: 'Billing account', icon: 'credit-card', built: true,
      permission: TENANT_PERMISSIONS.billing.read,
      job: 'See what your organization is on and, where your provider bills you here, manage the subscription, invoices and payment methods.',
    },
    // NOT gated: Usage & Limits reads auth-service /billing/usage/current, which
    // is Core. Consumption-against-limits is meaningful on a free install too.
    { key: 'usage', label: 'Usage & Limits', icon: 'chart-column', built: true, permission: TENANT_PERMISSIONS.billing.read, job: 'Monitor consumption against your limits.' },
  ] },
  { section: 'People & Access', items: [
    { key: 'members', label: 'Members', icon: 'users', built: true, permission: TENANT_PERMISSIONS.users.read, job: 'Invite users, assign roles, and manage the organization roster.' },
    // users.manage, not users.read: the whole /tenant/:id/roles route group in
    // auth-service requires users.manage, so gating the entry on users.read
    // advertised the page to security_admin and viewer, who then hit the page's
    // "Couldn't load roles" error banner instead of a proper access notice.
    { key: 'roles', label: 'Roles & Permissions', icon: 'shield-half', built: true, permission: TENANT_PERMISSIONS.users.manage, job: 'Define roles and the permissions each one grants.' },
    {
      key: 'security-sso', label: 'Security & SSO', icon: 'fingerprint', built: true,
      // settings.update, not settings.read: auth-service gates the WHOLE
      // /tenant/sso group at settings.update, reads included (ee/sso/routes.go),
      // so a settings.read-only role could reach the page and get a load error
      // instead of an access notice. Same shape as the `roles` entry above.
      permission: TENANT_PERMISSIONS.settings.update,
      job: 'Configure identity-provider connections (OAuth / SAML / LDAP), the org authentication policy, and SSO-group → role mapping.',
      feature: 'sso_saml',
      lock: {
        title: 'An Enterprise feature',
        message: 'Federated sign-in lets your members authenticate through your own identity provider (OIDC / SAML), with group-to-role mapping and an org-wide authentication policy. Local users, invitations, and roles are included in every edition. Upgrade to Enterprise to enable SSO.',
      },
    },
  ] },
  { section: 'Integrations', items: [
    { key: 'integrations', label: 'Integrations', icon: 'plug', built: true, permission: TENANT_PERMISSIONS.settings.read, job: 'Connect the platform to any 3rd-party system — SIEM, CMDB/ITSM, messaging channels, storage — and monitor those connections in one hub.' },
    // Deliberately NO `feature`. The page is Core and it EXPLAINS the edition:
    // a Core tenant opening it sees every generative capability marked
    // Enterprise beside the rule-based behaviour that answers instead, plus the
    // two switches they own in every edition. An upgrade card here would hide
    // the settings a Core tenant genuinely has (ADR-0008 — AI-native, never
    // AI-dependent).
    //
    // settings.update, not settings.read, and for the reason the Security & SSO
    // entry gives: the page exists to change two switches, and PUT /tenant/ai
    // requires settings.update — a settings.read-only role (security_admin,
    // billing_admin) reaching it would get a page whose only controls fail.
    //
    // GET /tenant/ai is deliberately looser (authentication only), so that any
    // OTHER surface can explain why a generative capability is absent without
    // needing an administrator. That is the endpoint's gating, not this entry's.
    { key: 'ai-assistant', label: 'AI assistant', icon: 'sparkles', built: true, permission: TENANT_PERMISSIONS.settings.update, job: 'See which AI capabilities this deployment has turned on, what answers without them, and control whether your organization uses them at all.' },
  ] },
  { section: 'Notifications & Alerts', items: [
    { key: 'routing', label: 'Routing Rules', icon: 'route', built: true, permission: TENANT_PERMISSIONS.settings.read, job: 'Match events to configured delivery channels, with severity/category filters and digest frequency.' },
    { key: 'alert-rules', label: 'Alert Rules', icon: 'bell-ring', built: true, permission: TENANT_PERMISSIONS.settings.read, job: 'See which alert types the platform raises, how their severity escalates, and turn individual alert types on or off.' },
    { key: 'notification-history', label: 'Delivery History', icon: 'mail', built: true, permission: TENANT_PERMISSIONS.settings.read, workspacePath: '/remediation/delivery', job: 'Review every notification the platform sent — or silently dropped — with the channels, status, and rule-match outcome for each.' },
  ] },
  { section: 'Policies', items: [
    { key: 'frameworks', label: 'Compliance Frameworks', icon: 'scroll-text', built: true, permission: TENANT_PERMISSIONS.compliance.read, job: 'Activate and manage compliance frameworks and set the default.' },
    {
      key: 'custom-policies', label: 'Custom Policies', icon: 'sliders-horizontal', built: true,
      permission: TENANT_PERMISSIONS.compliance.read,
      job: 'Author your own compliance frameworks — controls and measurement rules (Enterprise).',
      feature: 'custom_policies',
      lock: {
        title: 'An Enterprise feature',
        message: 'Custom policies let you author your own compliance frameworks — controls and measurement rules evaluated against your inventory, alongside the platform frameworks. Upgrade to Enterprise to enable them.',
      },
      // NOTE: the boolean half of this interim lives in Go, as
      // `authoringDisabledInterim` in
      // services/auth-service/internal/api/ai_settings.go, because Settings →
      // AI assistant reports it too. The COPY below is the single source for
      // both pages. When is fixed, flip that constant and delete this
      // entry — either one alone leaves the product saying two different things.
      //
      // Interim mitigation for audit finding B-05, NOT the fix:
      // custom policies (`tenant_frameworks`) are never evaluated today — no
      // finding, no score, for any tenant, regardless of this entitlement.
      // compliance-engine's reconcile engine hardcodes "platform" at every
      // call site and has no "tenant" path, and tenant_framework_scores has
      // no row shape a custom-policy score could occupy. Rather than let a
      // tenant believe a policy they wrote is doing something, authoring is
      // disabled here until the real fix lands. Existing policies are NOT
      // deleted or hidden — see pages-custom-policies.tsx for what stays
      // visible. Tracking:
      authoringDisabled: {
        title: 'Authoring is temporarily disabled',
        message: 'Custom policies are not evaluated yet — they produce no finding and no score for any tenant. Authoring (new policies, controls, and measurement rules) is disabled until that is fixed. Anything you already authored stays here and has not been deleted. Tracking: issue #1439.',
      },
    },
    { key: 'ratings', label: 'Severity Ratings', icon: 'gauge', job: 'The source-of-truth registry that rates every cryptographic value consistently over time.' },
    { key: 'asset-lifecycle', label: 'Asset Lifecycle', icon: 'recycle', built: true, permission: TENANT_PERMISSIONS.settings.read, job: 'Set staleness thresholds, auto-archive behavior, and the drift baseline window assets are compared against.' },
    // No 'retention' entry, deliberately (SECURITY C4, v1.0.0 audit).
    // audit.retention_policies is platform-GLOBAL config — one row set governs
    // every tenant's audit history, the table has no tenant_id column, and the
    // sweep it drives deletes from audit.activity_logs with no tenant
    // predicate. Its routes now require a platform identity, so a tenant-facing
    // entry could only lead to a 403, and a dead button is a bug. The surface
    // lives in admin-ui-v2 -> Security -> Retention. Do not re-add it here
    // unless the table is first given a tenant_id and the feature genuinely
    // re-scoped per tenant.
    { key: 'scopes', label: 'Scopes', icon: 'crop', built: true, workspacePath: '/risk-compliance/scopes', job: 'Define named, versioned asset boundaries used by CBOM.' },
    // ADR-0006 D7. Both read the GENERATED class registry, not an endpoint —
    // the taxonomy is fixed and the client already ships it. `assets.read`
    // rather than `settings.read`: these pages explain how the inventory is
    // decided, so anyone who can see the inventory should be able to see the
    // rules behind it, and neither page calls a settings route.
    { key: 'classes', label: 'Classes', icon: 'shapes', built: true, permission: TENANT_PERMISSIONS.assets.read, workspacePath: '/inventory/manage/classes', job: 'Browse the asset class taxonomy and the attributes each class carries.' },
    { key: 'identification-rules', label: 'Identification rules', icon: 'fingerprint', built: true, permission: TENANT_PERMISSIONS.assets.read, job: 'See how a discovered thing is matched to an existing asset, and decide whether a high enough match may be accepted without you.' },
    //. `assets.read` for the same reason as the two entries above: the
    // page explains how the inventory's trust column is decided, so anyone who
    // can see a certificate's trust status can see the decisions behind it.
    // Changing them is `certificates.trust`, enforced on the write controls
    // inside the page (and by the server) — NOT here, or a viewer would get an
    // access notice in place of the rules their inventory is judged by.
    { key: 'trusted-cas', label: 'Trusted CAs', icon: 'badge-check', built: true, permission: TENANT_PERMISSIONS.assets.read, job: 'Decide which certificate authorities your organisation trusts or distrusts, on top of the public roots trusted by default.' },
  ] },
  { section: 'Audit', items: [
    // audit.read, not settings.read: the audit trail is its own permission
    // family now that audit-service resolves grants from
    // tenant_role_permissions instead of a hardcoded role switch.
    // Never weaker than the routes the page calls (GET /activity-logs is
    // ungated; the by-user / by-resource drill-downs require audit.read), and
    // it stops advertising the trail to billing_admin, which holds
    // settings.read but has no operational scope.
    { key: 'audit', label: 'Audit Log', icon: 'history', built: true, permission: TENANT_PERMISSIONS.audit.read, workspacePath: '/risk-compliance/audit', job: 'Search, view, and export the full audit trail — who did what, when.' },
  ] },
  { section: 'Infrastructure', items: [
    // Was spec'd as "Sensor Configuration". It is not about sensors: it decides
    // whether the PLATFORM probes the tenant's own network without being asked,
    // and a tenant admin looking for that would not click a page named after a
    // piece of hardware. The key stays `sensor-config` because the route is the
    // key and a rename would break anyone's bookmark for nothing.
    { key: 'sensor-config', label: 'Active Scanning', icon: 'radar', built: true, permission: TENANT_PERMISSIONS.settings.read, job: 'Decide whether the platform scans your internal hosts on its own — when one is first seen, and how often after that.' },
    { key: 'ipam', label: 'IPAM', icon: 'network', built: true, permission: TENANT_PERMISSIONS.ipam.read, workspacePath: '/inventory/manage/ipam', job: 'Maintain the VRFs, aggregates, registries, prefix roles and AS numbers the Networks view builds on.' },
    { key: 'cluster-types', label: 'Cluster Types & Groups', icon: 'boxes', built: true, permission: TENANT_PERMISSIONS.virtualization.read, workspacePath: '/inventory/manage/cluster-types', job: 'Maintain the cluster types and groups the Clusters view builds on.' },
    // DCIM row 4.3: the IKE / IPsec proposals, policies and profiles tunnels
    // are built from, each algorithm with its catalogue assessment.
    { key: 'vpn-policies', label: 'VPN Policies', icon: 'shield', built: true, permission: TENANT_PERMISSIONS.vpn.read, workspacePath: '/inventory/manage/vpn-policies', job: 'Maintain the IKE and IPsec proposals, policies and profiles your tunnels use, each algorithm scored by the catalogue.' },
    { key: 'wireless', label: 'Wireless', icon: 'wifi', built: true, permission: TENANT_PERMISSIONS.wireless.read, workspacePath: '/inventory/manage/wireless', job: 'See the wireless LANs your access points broadcast, how each authenticates and how the catalogue rates its cipher; keep LAN groups and links.' },
    { key: 'contacts', label: 'Contacts', icon: 'users', built: true, permission: TENANT_PERMISSIONS.dcim.read, workspacePath: '/inventory/manage/contacts', job: 'Maintain the people and teams — NOC, on-call, owners — you assign to sites, racks and assets, and the roles they hold.' },
    { key: 'config-contexts', label: 'Config Contexts', icon: 'braces', built: true, permission: TENANT_PERMISSIONS.dcim.read, workspacePath: '/inventory/manage/config-contexts', job: 'Define the JSON — NTP servers, syslog targets, banners — that is merged by weight into every asset it applies to.' },
    // DCIM row 5.5. dcim.read opens the page; its write controls are behind dcim.manage.
    { key: 'export-templates', label: 'Export Templates', icon: 'file-code', built: true, permission: TENANT_PERMISSIONS.dcim.read, job: 'Define the text formats — a hosts file, a config snippet, an XML feed — that any list can be exported through, beside CSV.' },
    // DCIM row 2.7. dcim.read opens the page (the kinds list and the template are
    // behind it); the Apply button inside is gated by each kind's own manage
    // permission, so a reader can check a file but not write it.
    { key: 'import', label: 'Import', icon: 'file-up', built: true, permission: TENANT_PERMISSIONS.dcim.read, workspacePath: '/inventory/manage/import', job: 'Bring objects in from a CSV — check every row first, then apply. Business units, locations, assets, interfaces, the device catalogue and IPAM.' },
    // DCIM gap 8. dcim.read opens the page; its write controls are behind dcim.manage.
    { key: 'spares', label: 'Spares & RMA', icon: 'package', built: true, permission: TENANT_PERMISSIONS.dcim.read, workspacePath: '/inventory/manage/spares', job: 'Keep the spare parts on your shelves — quantities, stock locations, reservations — install them into assets, and follow each unit out for RMA until its replacement is back in stock.' },
    // DCIM row 4.1. circuits.read: the page reads /circuits/*; its write
    // controls are behind circuits.manage.
    { key: 'circuit-providers', label: 'Circuit Providers', icon: 'globe', built: true, permission: TENANT_PERMISSIONS.circuits.read, workspacePath: '/inventory/manage/circuit-providers', job: 'Maintain the circuit providers, their accounts and networks, and the circuit types and groups the Circuits view builds on.' },
    // DCIM row 5.1. dcim.read: every DCIM detail renders the definitions; the
    // write controls inside are behind custom_fields.manage.
    { key: 'custom-fields', label: 'Custom Fields', icon: 'list-checks', built: true, permission: TENANT_PERMISSIONS.dcim.read, job: 'Add your own fields to assets, interfaces, prefixes, VLANs, circuits and the rest — typed, validated on every save, editable on each object and queryable as cf.<name>.' },
    // The device catalogue (DCIM row 2.2): dcim.read to see it, dcim.manage
    // (inside the pages) to write. Built-in rows are read-only to everyone.
    { key: 'device-types', label: 'Device Types', icon: 'server', built: true, permission: TENANT_PERMISSIONS.dcim.read, workspacePath: '/inventory/manage/device-types', job: 'Browse the hardware catalogue, import models from the device-type library, and define the interfaces and ports each model has.' },
    { key: 'manufacturers', label: 'Manufacturers', icon: 'factory', built: true, permission: TENANT_PERMISSIONS.dcim.read, workspacePath: '/inventory/manage/manufacturers', job: 'The makers your device types belong to.' },
    { key: 'device-roles', label: 'Device Roles', icon: 'tag', built: true, permission: TENANT_PERMISSIONS.dcim.read, workspacePath: '/inventory/manage/device-roles', job: 'What each device does in your estate — one ships per hardware and virtual asset class.' },
    { key: 'platforms', label: 'Platforms (OS)', icon: 'cpu', built: true, permission: TENANT_PERMISSIONS.dcim.read, workspacePath: '/inventory/manage/platforms', job: 'The operating system or firmware families your devices run.' },
  ] },
];

export const PROFILE_NAV: SettingsNavItem[] = [
  { key: 'personal', label: 'Personal', icon: 'user', built: true, job: 'Edit your identity — name, avatar, timezone — and change your email via a verified flow.' },
  { key: 'preferences', label: 'Preferences', icon: 'sliders-horizontal', job: 'Personal app behavior — theme, language, formats, default landing, and your framework default.' },
  { key: 'security', label: 'Security', icon: 'shield-check', built: true, job: 'Password, multi-factor authentication, and account status.' },
  { key: 'notifications', label: 'Notifications', icon: 'bell', built: true, job: "Choose which notifications you receive and how — bound to the org's configured channels." },
  { key: 'sessions', label: 'Sessions & Devices', icon: 'monitor-smartphone', built: true, job: 'See and revoke active sessions, and review your login history.' },
  { key: 'connected', label: 'Connected Accounts', icon: 'link-2', built: true, job: 'Link, unlink, and set your primary SSO providers.' },
  { key: 'api-tokens', label: 'API Tokens', icon: 'key-round', built: true, job: 'Create, scope, and revoke your personal API tokens.' },
  { key: 'accessibility', label: 'Accessibility', icon: 'accessibility', job: 'Reduced motion, high contrast, font scale, and keyboard-navigation hints.' },
  { key: 'account-privacy', label: 'Account & Privacy', icon: 'shield-alert', danger: true, job: 'Export your personal data, or deactivate / delete your account.' },
];

/**
 * The Settings drawer is deliberately organised by tenant-wide behaviour,
 * not by the service which owns an endpoint.  SETTINGS_NAV remains the full
 * page registry (including redirect metadata for pages moved to the tenant
 * workspace); this smaller map is the information architecture users see.
 */
const SETTINGS_DRAWER_GROUPS: ReadonlyArray<{ section: string; keys: readonly string[] }> = [
  { section: 'Organization', keys: ['org-overview', 'org-branding'] },
  { section: 'Plan & Usage', keys: ['billing', 'usage'] },
  { section: 'People & Access', keys: ['members', 'roles', 'security-sso'] },
  { section: 'Integrations', keys: ['integrations', 'ai-assistant'] },
  { section: 'Notifications', keys: ['routing', 'alert-rules'] },
  { section: 'Discovery & Reconciliation', keys: ['sensor-config', 'identification-rules'] },
  { section: 'Policies & Trust', keys: ['frameworks', 'custom-policies', 'ratings', 'asset-lifecycle', 'trusted-cas'] },
  { section: 'Data & Schema', keys: ['custom-fields', 'export-templates'] },
];

const allSettingsItems = () => SETTINGS_NAV.flatMap((section) => section.items);

export function workspacePageMeta(key: string): (SettingsNavItem & { section?: string }) | undefined {
  const item = allSettingsItems().find((candidate) => candidate.key === key && candidate.workspacePath);
  if (!item) return undefined;
  const section = item.workspacePath!.startsWith('/risk-compliance/')
    ? 'Risk & Compliance'
    : item.workspacePath!.startsWith('/remediation/')
      ? 'Remediation'
      : 'Infrastructure';
  return { ...item, section };
}

/**
 * SETTINGS_NAV with edition-gated AND not-yet-built entries removed, and any
 * section left empty by that removal dropped too. Pure — the rail passes the
 * resolved flag map in.
 *
 * Hiding the entry matters as much as gating the page: a rail link to a locked
 * (or unbuilt) page is worse than no link at all. The entry and its `built`
 * flag stay in the registry either way — this only affects what's rendered,
 * so the page returns to the rail the moment it flips `built: true`. The
 * route stays mounted (SettingsPage's `default:` case still renders
 * SpecPendingPage), so a deep link to an unbuilt page never 404s or crashes —
 * it's just not advertised in the nav.
 */
export function visibleSettingsNav(
  features: FeaturesMap,
  /** Omit to skip permission filtering (callers with no RBAC context). */
  hasPermission?: (p: string) => boolean,
): SettingsNavSection[] {
  const items = allSettingsItems();
  return SETTINGS_DRAWER_GROUPS
    .map((group) => ({
      section: group.section,
      items: group.keys
        .map((key) => items.find((item) => item.key === key))
        .filter((item): item is SettingsNavItem => !!item)
        .filter((item) =>
          item.built
          && !item.workspacePath
          && (!item.feature || features[item.feature])
          && (!item.permission || !hasPermission || hasPermission(item.permission))),
    }))
    .filter((sec) => sec.items.length > 0);
}

/**
 * PROFILE_NAV with not-yet-built entries removed. Same rationale as
 * visibleSettingsNav: the entry (and `built` flag) stays in the registry, the
 * route stays mounted for deep links — only the rail listing is filtered.
 */
export function visibleProfileNav(): SettingsNavItem[] {
  return PROFILE_NAV.filter((it) => it.built);
}

const EMPTY: SettingsNavItem = { key: '', label: 'Settings', icon: 'settings', job: '' };

export function settingsPageMeta(key: string): SettingsNavItem & { section?: string } {
  const visibleSection = SETTINGS_DRAWER_GROUPS.find((group) => group.keys.includes(key));
  for (const sec of SETTINGS_NAV) {
    const it = sec.items.find((i) => i.key === key);
    if (it) return { ...it, section: visibleSection?.section ?? sec.section };
  }
  return EMPTY;
}

export function profilePageMeta(key: string): SettingsNavItem {
  return PROFILE_NAV.find((p) => p.key === key) ?? { ...EMPTY, label: 'Profile' };
}
