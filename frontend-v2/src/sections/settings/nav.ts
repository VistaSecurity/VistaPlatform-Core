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
   * Entitlement key that must be on for this page to exist. Off ⇒ the rail
   * entry is hidden and the route renders `lock` instead of the page body.
   */
  feature?: FeatureName;
  /** Upgrade-card copy shown when `feature` is off. Required alongside it. */
  lock?: { title: string; message: string };
}
export interface SettingsNavSection {
  section: string;
  items: SettingsNavItem[];
}

export const SETTINGS_NAV: SettingsNavSection[] = [
  { section: 'Organization', items: [
    { key: 'org-overview', label: 'Overview', icon: 'building-2', built: true, job: "Edit core organization metadata — name, domain, billing email — and glance at the frameworks you're licensed for." },
    { key: 'org-branding', label: 'Branding', icon: 'palette', built: true, permission: TENANT_PERMISSIONS.settings.read, job: 'Upload your logo and favicon and set the display name to white-label the console.' },
  ] },
  { section: 'Account', items: [
    {
      key: 'billing', label: 'Billing', icon: 'credit-card', built: true,
      permission: TENANT_PERMISSIONS.billing.read,
      job: 'Manage the subscription — plan, invoices, and payment methods.',
      feature: 'billing_portal',
      lock: {
        title: 'Not part of this edition',
        message: 'Self-service billing — subscription, invoices, plan changes and the payment portal — belongs to the commercial editions, which are sold and provisioned by our team. A Core deployment has no subscription to manage; it is free to run for any purpose, with no plan, no invoices and no payment provider. Usage & Limits still shows your consumption against the tier you are on.',
      },
    },
    // NOT gated: Usage & Limits reads auth-service /billing/usage/current, which
    // is Core. Consumption-against-limits is meaningful on a free install too.
    { key: 'usage', label: 'Usage & Limits', icon: 'chart-column', built: true, permission: TENANT_PERMISSIONS.billing.read, job: 'Monitor consumption against plan limits and see when to upgrade.' },
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
  ] },
  { section: 'Notifications & Alerts', items: [
    { key: 'routing', label: 'Routing Rules', icon: 'route', built: true, permission: TENANT_PERMISSIONS.settings.read, job: 'Match events to configured delivery channels, with severity/category filters and digest frequency.' },
    { key: 'alert-rules', label: 'Alert Rules', icon: 'bell-ring', built: true, permission: TENANT_PERMISSIONS.settings.read, job: 'Define event-based alerts — thresholds, severity, and the actions they trigger.' },
    { key: 'notification-history', label: 'Delivery History', icon: 'mail', built: true, permission: TENANT_PERMISSIONS.settings.read, job: 'Review every notification the platform sent — or silently dropped — with the channels, status, and rule-match outcome for each.' },
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
    },
    { key: 'ratings', label: 'Severity Ratings', icon: 'gauge', job: 'The source-of-truth registry that rates every cryptographic value consistently over time.' },
    { key: 'asset-lifecycle', label: 'Asset Lifecycle', icon: 'recycle', built: true, permission: TENANT_PERMISSIONS.settings.read, job: 'Set staleness thresholds and auto-archive behavior for assets.' },
    // Stays settings.read: the page's only load call, GET /retention-policies,
    // is ungated in audit-service, so the entry is not weaker than its route
    // and nobody reaches an error banner. Its WRITE affordances are gated on
    // audit.manage inside the page — the create/edit routes' real
    // requirement.
    { key: 'retention', label: 'Retention Policies', icon: 'archive', built: true, permission: TENANT_PERMISSIONS.settings.read, job: 'Define data-retention schedules for audit and event logs.' },
    { key: 'scopes', label: 'Scopes', icon: 'crop', built: true, job: 'Define named, versioned asset boundaries used by CBOM.' },
  ] },
  { section: 'Audit', items: [
    // audit.read, not settings.read: the audit trail is its own permission
    // family now that audit-service resolves grants from
    // tenant_role_permissions instead of a hardcoded role switch.
    // Never weaker than the routes the page calls (GET /activity-logs is
    // ungated; the by-user / by-resource drill-downs require audit.read), and
    // it stops advertising the trail to billing_admin, which holds
    // settings.read but has no operational scope.
    { key: 'audit', label: 'Audit', icon: 'history', built: true, permission: TENANT_PERMISSIONS.audit.read, job: 'Search, view, and export the full audit trail — who did what, when.' },
  ] },
  { section: 'Infrastructure', items: [
    { key: 'sensor-config', label: 'Sensor Configuration', icon: 'radar', job: 'Set global discovery-engine behavior — Active Scanning Policy and Observation Rest Period.' },
    { key: 'locations', label: 'Locations', icon: 'map-pin', built: true, permission: TENANT_PERMISSIONS.settings.read, job: 'Maintain the hierarchical physical/cloud location registry used by Inventory and Discovery.' },
    { key: 'segments', label: 'Network Segments', icon: 'network', built: true, permission: TENANT_PERMISSIONS.settings.read, job: 'Define network boundaries (CIDR / range / domain / VPC) that Discovery scopes scans against.' },
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
export function visibleSettingsNav(features: FeaturesMap): SettingsNavSection[] {
  return SETTINGS_NAV
    .map((sec) => ({ ...sec, items: sec.items.filter((it) => it.built && (!it.feature || features[it.feature])) }))
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
  for (const sec of SETTINGS_NAV) {
    const it = sec.items.find((i) => i.key === key);
    if (it) return { ...it, section: sec.section };
  }
  return EMPTY;
}

export function profilePageMeta(key: string): SettingsNavItem {
  return PROFILE_NAV.find((p) => p.key === key) ?? { ...EMPTY, label: 'Profile' };
}
