// Tenants ▸ (a tenant) ▸ Entitlements, and the Enterprise presentation of the
// tenant list/drawer (edition-licensing spec PR 2).
//
// Enterprise: every licensed feature with an on/off switch — loading, error,
// empty (no licence), default and read-only states. MSP: the plan's
// composition from the tenant's REAL tier id (RC-10) plus Plan Exceptions.
// Plus the pure helpers the list and drawer use to keep tier and trial words
// off an Enterprise console.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { Tenant, TenantFeatures } from './queries';

type Q<T> = { data?: T; isLoading: boolean; isError: boolean; refetch: () => void };

const state: {
  license: string;
  features: Q<TenantFeatures>;
  tierEnts: { data?: unknown[]; isLoading: boolean; isError: boolean };
  tierAskedFor: (string | null)[];
  canManage: boolean;
} = vi.hoisted(() => ({
  license: 'enterprise',
  features: { isLoading: true, isError: false, refetch: () => {} },
  tierEnts: { isLoading: false, isError: false },
  tierAskedFor: [],
  canManage: true,
}));

vi.mock('../../lib/edition', () => ({
  usePlatformEdition: () => ({ license: state.license, isMsp: state.license === 'msp', has: () => true }),
}));
vi.mock('./queries', async (orig) => {
  const real = await orig<typeof import('./queries')>();
  return {
    ...real,
    useTenantFeatures: () => state.features,
    useSetTenantFeature: () => ({ mutate: vi.fn(), isPending: false }),
    useTierEntitlements: (id: string | null) => { state.tierAskedFor.push(id); return state.tierEnts; },
  };
});
vi.mock('./plan-exceptions', () => ({ PlanExceptionsPanel: () => createElement('div', null, 'PLAN-EXCEPTIONS-PANEL') }));
vi.mock('@vistasecurity/primitives/platform-auth', () => ({
  PLATFORM_PERMISSIONS: { tenants: { manage: 'tenants.manage' } },
  usePlatformPermissions: () => ({ hasPermission: () => state.canManage }),
}));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));

const { TenantEntitlementsTab } = await import('./tenant-entitlements-tab');
const { planLabel, tierIdOf } = await import('./queries');
const { statusFilters } = await import('./tenants-page');
const { drawerTabs } = await import('./tenant-drawer');

const TIER = '22222222-2222-4222-8222-222222222222';
const tenant = {
  id: '11111111-1111-4111-8111-111111111111', name: 'Acme', slug: 'acme', domain: null,
  subscription_tier_id: TIER, billing_email: '', payment_status: 'active', stripe_customer_id: null,
  sso_enabled: false, is_active: true, custom_branding: null, ui_config: null, settings: null,
  created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', deleted_at: null,
  plan: { edition: 'enterprise', display_name: 'Vista Platform Enterprise', licensee: 'Acme Corp', expires_at: '2027-01-01T00:00:00Z' },
} as unknown as Tenant;

const features = (over: Partial<TenantFeatures> = {}): Q<TenantFeatures> => ({
  isLoading: false, isError: false, refetch: () => {},
  data: {
    tenant_id: tenant.id, edition: 'enterprise', switchable: true,
    features: [
      { key: 'sso_saml', display_name: 'SSO / SAML', description: null, enabled: false, source: 'override', switched_off: true, reason: 'contractor tenant' },
      { key: 'custom_policies', display_name: 'Custom Compliance Policies', description: null, enabled: true, source: 'edition', switched_off: false, reason: null },
    ],
    ...over,
  },
});

const render = () => renderToStaticMarkup(createElement(TenantEntitlementsTab, { tenant }));

beforeEach(() => {
  state.license = 'enterprise';
  state.features = features();
  state.tierEnts = { data: undefined, isLoading: false, isError: false };
  state.tierAskedFor = [];
  state.canManage = true;
});

describe('Enterprise: per-tenant feature switches', () => {
  it('default: every licensed feature, the switched-off one with its reason', () => {
    const html = render();
    expect(html).toContain('Licensed features');
    expect(html).toContain('SSO / SAML');
    expect(html).toContain('Switched off — contractor tenant');
    expect(html).toContain('Custom Compliance Policies');
    expect(html).toContain('On (licence)');
    expect(html).toContain('aria-label="Switch SSO / SAML on"');
    expect(html).toContain('aria-label="Switch Custom Compliance Policies off"');
    // No plan composition on Enterprise — plans do not exist there.
    expect(html).not.toContain('PLAN-EXCEPTIONS-PANEL');
    expect(state.tierAskedFor).toEqual([]);
  });

  it('loading', () => {
    state.features = { isLoading: true, isError: false, refetch: () => {} };
    expect(render()).toContain('data-testid="features-loading"');
  });

  it('error: inline, with a retry', () => {
    state.features = { isLoading: false, isError: true, refetch: () => {} };
    const html = render();
    expect(html).toContain("Couldn&#x27;t load this tenant&#x27;s features");
    expect(html).toContain('Retry');
  });

  it('empty: no licence, nothing to switch', () => {
    state.features = features({ edition: 'core', switchable: false, features: [] });
    expect(render()).toContain('this install has no licence');
  });

  it('read-only without tenants.manage: values, no switches', () => {
    state.canManage = false;
    const html = render();
    expect(html).not.toContain('aria-label="Switch');
    expect(html).toContain('needs the tenants.manage permission');
  });

  it('a feature off by another writer\'s override is shown, not offered as a switch', () => {
    state.features = features({ features: [
      { key: 'cmdb_sync', display_name: 'CMDB / ITSM Sync', description: null, enabled: false, source: 'override', switched_off: false, reason: null },
    ] });
    const html = render();
    expect(html).toContain('Off for this tenant by an override set outside this switch');
    expect(html).not.toContain('aria-label="Switch CMDB');
  });

  it('never says "community" or "trial"', () => {
    const html = render().toLowerCase();
    expect(html).not.toContain('community');
    expect(html).not.toContain('trial');
  });
});

describe('MSP: plan composition + exceptions', () => {
  beforeEach(() => { state.license = 'msp'; });

  it('reads the plan from the tenant\'s real tier id (RC-10)', () => {
    state.tierEnts = { data: [{ item_id: 'x', item_display_name: 'Sensors', included_value: { quantity: 25 }, item_unit: 'sensors' }], isLoading: false, isError: false };
    const html = renderToStaticMarkup(createElement(TenantEntitlementsTab, { tenant: { ...tenant, plan: { edition: 'msp', display_name: 'Premium', licensee: null, expires_at: null } } }));
    expect(state.tierAskedFor).toContain(TIER);
    expect(html).toContain('Plan — Premium');
    expect(html).toContain('25 sensors');
    expect(html).toContain('PLAN-EXCEPTIONS-PANEL');
  });

  it('never queries tier 0000… for a tenant without a tier', () => {
    renderToStaticMarkup(createElement(TenantEntitlementsTab, { tenant: { ...tenant, subscription_tier_id: '00000000-0000-0000-0000-000000000000' } }));
    expect(state.tierAskedFor).toEqual([null]);
  });
});

describe('list and drawer helpers', () => {
  it('planLabel reads the plan block, never the old "Trial" fallback', () => {
    expect(planLabel(tenant)).toBe('Vista Platform Enterprise');
    expect(planLabel({ plan: undefined, subscription_tier: 'Pro' })).toBe('Pro');
    expect(planLabel({ plan: undefined, subscription_tier: undefined })).toBe('—');
  });
  it('tierIdOf drops the nil uuid', () => {
    expect(tierIdOf({ subscription_tier_id: TIER })).toBe(TIER);
    expect(tierIdOf({ subscription_tier_id: '00000000-0000-0000-0000-000000000000' })).toBeNull();
  });
  it('status chips: trial and billing states only on MSP', () => {
    expect(statusFilters(false).map(([k]) => k)).toEqual(['all', 'active', 'suspended']);
    expect(statusFilters(true).map(([k]) => k)).toContain('trial');
  });
  it('the Billing tab only when billing applies', () => {
    expect(drawerTabs(false)).not.toContain('Billing');
    expect(drawerTabs(true)).toContain('Billing');
    expect(drawerTabs(false)).toContain('Entitlements');
  });
});
