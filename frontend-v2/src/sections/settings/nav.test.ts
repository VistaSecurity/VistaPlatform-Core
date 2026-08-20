// Settings-nav edition gating.
//
// Hiding the rail entry matters as much as gating the page body: a link to a
// locked page is worse than no link, and RBAC-hiding is NOT edition-hiding — a
// Tenant Admin holds `settings.read` on a Core install too, so `permission`
// alone leaves Enterprise-only pages advertised and reachable.
import { describe, it, expect } from 'vitest';
import { defaultFeatures, type FeaturesMap } from '@vistasecurity/primitives/features';
import { PROFILE_NAV, SETTINGS_NAV, settingsPageMeta, visibleProfileNav, visibleSettingsNav } from './nav';

// Every registered flag on, derived from defaultFeatures so a newly registered
// key is covered automatically instead of silently defaulting to off here.
const allOn: FeaturesMap = Object.fromEntries(
  Object.keys(defaultFeatures).map((k) => [k, true]),
) as unknown as FeaturesMap;

const keysOf = (sections: ReturnType<typeof visibleSettingsNav>) =>
  sections.flatMap((s) => s.items.map((i) => i.key));

describe('visibleSettingsNav', () => {
  it('hides Enterprise-only entries on a Core deployment (all flags off)', () => {
    const keys = keysOf(visibleSettingsNav(defaultFeatures));
    expect(keys).not.toContain('custom-policies'); // compliance-engine/ee/policyauthoring
    expect(keys).not.toContain('security-sso');    // auth-service/ee/sso
    expect(keys).not.toContain('billing');         // admin-service/ee/billingapi
  });

  it('shows them once the entitlements resolve on', () => {
    const keys = keysOf(visibleSettingsNav(allOn));
    expect(keys).toContain('custom-policies');
    expect(keys).toContain('security-sso');
    expect(keys).toContain('billing');
  });

  it('keeps Usage & Limits on Core — its route (auth-service) is not carved', () => {
    // Billing and Usage sit in the same Account section and share the same
    // `billing.read` permission, but only ONE of them is Enterprise. Gating the
    // section rather than the entry would take consumption-against-limits away
    // from every free install.
    const sections = visibleSettingsNav(defaultFeatures);
    const account = sections.find((s) => s.section === 'Account');
    expect(account, 'the Account section must survive with Billing removed').toBeTruthy();
    expect(account!.items.map((i) => i.key)).toEqual(['usage']);
  });

  it('keeps every Core entry visible with all flags off', () => {
    const keys = keysOf(visibleSettingsNav(defaultFeatures));
    // Integrations hosts Core notification channels alongside the gated CMDB and
    // SIEM sections, so the PAGE stays — only those sections lock.
    expect(keys).toContain('integrations');
    // Branding keeps the palette (Core); only the white-label marks are gated,
    // in-page. Hiding the whole page would take colours away from Core.
    expect(keys).toContain('org-branding');
    expect(keys).toContain('members');
    expect(keys).toContain('roles');
    expect(keys).toContain('frameworks');
    expect(keys).toContain('audit');
  });

  it('drops a section left empty by gating, rather than showing a bare header', () => {
    const sections = visibleSettingsNav(defaultFeatures);
    expect(sections.every((s) => s.items.length > 0)).toBe(true);
  });

  it('never gates on a key outside the registered FeatureName union', () => {
    // A key that isn't in the resolved map would read `undefined` → falsy →
    // the entry would vanish on EVERY deployment, Enterprise included.
    const registered = new Set(Object.keys(defaultFeatures));
    for (const sec of SETTINGS_NAV) {
      for (const item of sec.items) {
        if (item.feature) expect(registered.has(item.feature)).toBe(true);
      }
    }
  });

  it('gives every gated entry upgrade copy for its deep-link lock', () => {
    for (const sec of SETTINGS_NAV) {
      for (const item of sec.items) {
        if (!item.feature) continue;
        expect(item.lock, `${item.key} is feature-gated but has no lock copy`).toBeTruthy();
        expect(item.lock!.message.length).toBeGreaterThan(40);
      }
    }
  });

  // FE-2: five "Spec'd — build pending" pages were advertised in the rail
  // with nothing behind them (Settings: Severity Ratings, Sensor
  // Configuration; Profile: Preferences, Accessibility, Account & Privacy).
  // The registry entry (and its `built` flag) stays — SettingsPage's
  // `default:` case still renders SpecPendingPage for a deep link — only the
  // nav listing is filtered, so the item reappears automatically once
  // `built: true` is set.
  it('filters unbuilt entries out of the rendered rail', () => {
    const keys = keysOf(visibleSettingsNav(allOn));
    expect(keys).not.toContain('ratings');       // Severity Ratings
    expect(keys).not.toContain('sensor-config'); // Sensor Configuration
  });

  it('still carries the unbuilt entries in the source registry, for deep-link routing', () => {
    const allKeys = SETTINGS_NAV.flatMap((s) => s.items.map((i) => i.key));
    expect(allKeys).toContain('ratings');
    expect(allKeys).toContain('sensor-config');
    expect(SETTINGS_NAV.flatMap((s) => s.items).find((i) => i.key === 'ratings')?.built).toBeFalsy();
    expect(SETTINGS_NAV.flatMap((s) => s.items).find((i) => i.key === 'sensor-config')?.built).toBeFalsy();
  });
});

describe('visibleProfileNav', () => {
  it('filters the three unbuilt profile pages out of the rail', () => {
    const keys = visibleProfileNav().map((i) => i.key);
    expect(keys).not.toContain('preferences');
    expect(keys).not.toContain('accessibility');
    expect(keys).not.toContain('account-privacy');
  });

  it('keeps the built profile pages', () => {
    const keys = visibleProfileNav().map((i) => i.key);
    expect(keys).toContain('personal');
    expect(keys).toContain('security');
    expect(keys).toContain('notifications');
    expect(keys).toContain('sessions');
    expect(keys).toContain('connected');
    expect(keys).toContain('api-tokens');
  });

  it('still carries the unbuilt entries in PROFILE_NAV, for deep-link routing', () => {
    const allKeys = PROFILE_NAV.map((i) => i.key);
    expect(allKeys).toContain('preferences');
    expect(allKeys).toContain('accessibility');
    expect(allKeys).toContain('account-privacy');
  });
});

describe('settingsPageMeta', () => {
  it('carries the feature + lock through to the page router (deep-link gate)', () => {
    const meta = settingsPageMeta('custom-policies');
    expect(meta.feature).toBe('custom_policies');
    expect(meta.lock?.title).toBeTruthy();
    expect(meta.section).toBe('Policies');
  });

  it('gates the Billing deep link, so /settings/billing cannot bypass the rail', () => {
    // The rail is only half the gate. `SettingsPage` reads this same meta and
    // renders the lock instead of <BillingPage/>, so a bookmark from an
    // Enterprise deployment lands on an upgrade card rather than a page whose
    // every call 404s.
    const meta = settingsPageMeta('billing');
    expect(meta.feature).toBe('billing_portal');
    expect(meta.lock?.title).toBeTruthy();
    expect(meta.section).toBe('Account');
  });

  it('gates Roles & Permissions on users.manage, matching the backend route', () => {
    // auth-service's /tenant/:tenantId/roles group requires users.manage. Gating
    // the entry on the weaker users.read let security_admin and viewer reach a
    // page whose every call 403s — an error banner where an access notice
    // belongs. The nav permission must never be weaker than the route's.
    expect(settingsPageMeta('roles').permission).toBe('users.manage');
    expect(settingsPageMeta('members').permission).toBe('users.read');
  });

  it('gates Security & SSO on settings.update, matching the backend route', () => {
    // auth-service gates the whole /tenant/sso group at settings.update — the
    // provider list and auth-policy GETs included — so settings.read would put
    // the same error banner where the access notice belongs.
    expect(settingsPageMeta('security-sso').permission).toBe('settings.update');
  });

  it('gates the Audit page on audit.read, its own permission family', () => {
    // audit-service resolves grants from tenant_role_permissions now instead of
    // a hardcoded switch on the role name, so the audit trail has real
    // permissions: audit.read and audit.manage. The Audit entry names the read
    // one — never weaker than the routes the page calls (GET /activity-logs is
    // ungated; the by-user / by-resource drill-downs require audit.read).
    expect(settingsPageMeta('audit').permission).toBe('audit.read');
    // Retention stays on settings.read: its only load call, GET
    // /retention-policies, is ungated, so nobody reaches an error banner. The
    // page's WRITE affordances are gated on audit.manage inline instead.
    expect(settingsPageMeta('retention').permission).toBe('settings.read');
  });

  it('leaves ungated pages ungated', () => {
    expect(settingsPageMeta('members').feature).toBeUndefined();
    expect(settingsPageMeta('integrations').feature).toBeUndefined();
    // Usage reads a Core route — gating it would be wrong, not merely cautious.
    expect(settingsPageMeta('usage').feature).toBeUndefined();
  });

  // B-05 interim mitigation: custom policies are never evaluated —
  // no finding, no score, for any tenant — so authoring must stay disabled
  // independent of the `custom_policies` entitlement, even once a tenant is
  // Enterprise-licensed. This pins the registry flag the page consults
  // (pages-custom-policies.tsx reads `meta.authoringDisabled`); it does not
  // by itself prove the page hides its buttons — see that file's comments.
  // Mutation check: deleting `authoringDisabled` from the nav.ts entry (or
  // its message) turns this red.
  it('keeps Custom Policy authoring disabled regardless of entitlement, pending #1439', () => {
    const meta = settingsPageMeta('custom-policies');
    expect(meta.feature).toBe('custom_policies'); // entitlement gate unchanged
    expect(meta.authoringDisabled, 'custom-policies must carry an authoringDisabled notice').toBeTruthy();
    expect(meta.authoringDisabled!.message).toMatch(/1439/);
    expect(meta.authoringDisabled!.message.length).toBeGreaterThan(40);
  });
});
