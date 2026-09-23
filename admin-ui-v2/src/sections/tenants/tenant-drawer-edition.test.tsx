// The Tenants list and the tenant drawer RENDERED on each licence — the wiring
// test for the edition gating that tenant-entitlements-tab.test.tsx checks only
// through its helpers (drawerTabs, statusFilters). Those helpers can be right
// while the call site passes the wrong argument: `drawerTabs(true)` puts the
// Billing tab (ee/billingapi, which the Enterprise binary still mounts) back on
// an Enterprise console, and `{true && <Row label="Billing status">}` or a
// Trial-ends row keyed on the raw `trial_ends_at` puts billing and trial words
// back in the drawer. Each of those mutations fails a case below; the MSP
// cases are the other polarity, so the Enterprise assertions cannot pass by
// the elements simply never rendering.
//
// The Enterprise tenant fixture deliberately still carries `trial_ends_at`, as
// a row the backend had not normalised would: the drawer must key the trial
// row on the resolved plan block, never on the raw column.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { Tenant } from './queries';

type Q<T> = { data?: T; isLoading: boolean; isError: boolean; refetch: () => void };

const state: { license: string; tenants: Q<Tenant[]> } = vi.hoisted(() => ({
  license: 'enterprise',
  tenants: { isLoading: false, isError: false, refetch: () => {} },
}));

vi.mock('../../lib/edition', () => ({
  usePlatformEdition: () => ({ license: state.license, isMsp: state.license === 'msp', has: () => true }),
}));
vi.mock('../../app/scope', () => ({ useScope: () => ({ scopeId: null }) }));
vi.mock('./queries', async (orig) => {
  const real = await orig<typeof import('./queries')>();
  const idle = { mutate: vi.fn(), isPending: false };
  const none = { data: undefined, isLoading: false, isError: false };
  return {
    ...real,
    useTenants: () => state.tenants,
    useTenantHealthMap: () => none,
    useTenantStats: () => none,
    useTenantCost: () => none,
    useTenantCoupons: () => none,
    useAdminTiers: () => none,
    useTenantStatusMutation: () => idle,
    useTenantReevaluateMutation: () => idle,
    useDeleteTenant: () => idle,
    useAdminChangePlan: () => idle,
  };
});
vi.mock('./tenant-entitlements-tab', () => ({ TenantEntitlementsTab: () => null }));
vi.mock('./tenant-settings-tab', () => ({ TenantSettingsPanel: () => null }));
vi.mock('./tenant-form-modal', () => ({ TenantFormModal: () => null }));
// The MSP operator-tenant control reads the licence cap and platform
// permissions; it has its own tests (tenants-page-operator.jsdom.test.tsx).
vi.mock('./operator-tenant-control', () => ({ OperatorTenantControl: () => null }));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn() }) }));

const { TenantDrawer } = await import('./tenant-drawer');
const { TenantsPage } = await import('./tenants-page');

const base = {
  id: '11111111-1111-4111-8111-111111111111', name: 'Acme', slug: 'acme', domain: null,
  subscription_tier_id: '22222222-2222-4222-8222-222222222222', billing_email: 'billing@acme.example',
  stripe_customer_id: null, sso_enabled: false, is_active: true, is_operator: false, custom_branding: null, ui_config: null,
  settings: null, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', deleted_at: null,
};

const enterpriseTenant = {
  ...base,
  payment_status: 'active',
  trial_ends_at: '2026-10-23T00:00:00Z', // an un-normalised row: must not surface
  plan: { edition: 'enterprise', display_name: 'Vista Platform Enterprise', licensee: 'Acme Corp', expires_at: '2027-01-01T00:00:00Z' },
} as unknown as Tenant;

const mspTrialTenant = {
  ...base,
  payment_status: 'trial',
  subscription_tier: 'Premium',
  trial_ends_at: '2026-10-23T00:00:00Z',
  plan: { edition: 'msp', display_name: 'Premium', licensee: null, expires_at: null, trial: { ends_at: '2026-10-23T00:00:00Z' } },
} as unknown as Tenant;

const drawer = (tenant: Tenant) =>
  renderToStaticMarkup(createElement(TenantDrawer, { tenant, onClose: () => {} }));
const page = () => renderToStaticMarkup(createElement(TenantsPage));

/** The tab strip's chips, by their label. */
const tabChips = (html: string) => Array.from(html.matchAll(/class="op-chip[^"]*">([^<]+)<\/button>/g), (m) => m[1]);

beforeEach(() => {
  state.license = 'enterprise';
  state.tenants = { data: [enterpriseTenant], isLoading: false, isError: false, refetch: () => {} };
});

describe('tenant drawer, rendered', () => {
  it('Enterprise: no Billing tab, no billing rows, no trial date, plan display name in the header', () => {
    const html = drawer(enterpriseTenant);
    const tabs = tabChips(html);
    expect(tabs).toEqual(['Overview', 'Entitlements', 'Settings', 'SSO', 'Activity']);
    expect(html).not.toContain('Billing status');
    expect(html).not.toContain('Billing email');
    expect(html).not.toContain('Trial ends');
    expect(html.toLowerCase()).not.toContain('trial');
    expect(html).toContain('Vista Platform Enterprise');
  });

  it('Core: the same — no billing, no trial', () => {
    state.license = 'core';
    const html = drawer(enterpriseTenant);
    expect(tabChips(html)).not.toContain('Billing');
    expect(html).not.toContain('Billing status');
    expect(html).not.toContain('Trial ends');
  });

  it('MSP (the other polarity): Billing tab, billing rows and the plan\'s trial date', () => {
    state.license = 'msp';
    const html = drawer(mspTrialTenant);
    expect(tabChips(html)).toContain('Billing');
    expect(html).toContain('Billing status');
    expect(html).toContain('Billing email');
    expect(html).toContain('Trial ends');
    expect(html).toContain('Premium');
  });

  it('MSP without a plan trial: no trial row even though the raw column is set', () => {
    state.license = 'msp';
    const html = drawer({ ...mspTrialTenant, plan: { ...mspTrialTenant.plan, trial: undefined } } as unknown as Tenant);
    expect(html).not.toContain('Trial ends');
  });
});

describe('tenants list, rendered', () => {
  const chipLabels = (html: string) =>
    Array.from(html.matchAll(/class="op-chip[^"]*">([A-Za-z ]+)<span/g), (m) => m[1]);

  it('Enterprise: status chips are All/Active/Suspended, no MRR column, plan display name', () => {
    const html = page();
    expect(chipLabels(html)).toEqual(['All', 'Active', 'Suspended']);
    expect(html).not.toContain('>MRR<');
    expect(html.toLowerCase()).not.toContain('trial');
    expect(html).toContain('Vista Platform Enterprise');
  });

  it('MSP (the other polarity): trial and billing chips, MRR column', () => {
    state.license = 'msp';
    state.tenants = { data: [mspTrialTenant], isLoading: false, isError: false, refetch: () => {} };
    const html = page();
    expect(chipLabels(html)).toEqual(['All', 'Active', 'Trial', 'Past due', 'Suspended', 'Canceled']);
    expect(html).toContain('>MRR<');
  });

  it('loading, error and empty states', () => {
    state.tenants = { isLoading: true, isError: false, refetch: () => {} };
    expect(page()).toContain('Loading tenants…');
    state.tenants = { isLoading: false, isError: true, refetch: () => {} };
    expect(page()).toContain('Couldn&#x27;t load tenants.');
    state.tenants = { data: [], isLoading: false, isError: false, refetch: () => {} };
    expect(page()).toContain('No tenants match these filters.');
  });
});
