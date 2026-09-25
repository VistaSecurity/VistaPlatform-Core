// @vitest-environment jsdom
//
// Tenants ▸ drawer ▸ Billing ▸ Change plan (support), MOUNTED (admin-UI data
// review RC-25). The panel changes the tenant's Stripe subscription, so it is
// offered only to a tenant with a live one; it used to be shown to every
// tenant and always fail for the rest with a generic message. Without one the
// drawer points at Plans & Pricing → Assign to tenant (owner decision 7).
//
// Mutations run (each red, then restored green): rendering the form
// regardless of the subscription; treating a cancelled subscription as live.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Tenant } from './queries';

const state = vi.hoisted(() => ({
  billing: { data: undefined as unknown, isLoading: false, isError: false },
}));

vi.mock('../../lib/edition', () => ({
  usePlatformEdition: () => ({ license: 'msp', isMsp: true, has: () => true }),
}));
vi.mock('../../app/scope', () => ({ useScope: () => ({ scopeId: null }) }));
vi.mock('./queries', async (orig) => {
  const real = await orig<typeof import('./queries')>();
  const idle = { mutate: vi.fn(), mutateAsync: vi.fn(), isPending: false };
  const none = { data: undefined, isLoading: false, isError: false };
  return {
    ...real,
    useTenantHealthMap: () => none,
    useTenantStats: () => none,
    useTenantCost: () => none,
    useTenantCoupons: () => none,
    useAdminTiers: () => ({ data: [], isLoading: false }),
    useTenantStatusMutation: () => idle,
    useTenantReevaluateMutation: () => idle,
    useDeleteTenant: () => idle,
    useAdminChangePlan: () => idle,
    useTenantBillingRecords: () => state.billing,
  };
});
vi.mock('./tenant-entitlements-tab', () => ({ TenantEntitlementsTab: () => null }));
vi.mock('./tenant-settings-tab', () => ({ TenantSettingsPanel: () => null }));
vi.mock('./tenant-form-modal', () => ({ TenantFormModal: () => null }));
vi.mock('./operator-tenant-control', () => ({ OperatorTenantControl: () => null }));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn() }) }));

const { TenantDrawer } = await import('./tenant-drawer');
const real = await vi.importActual<typeof import('./queries')>('./queries');

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const tenant: Tenant = {
  id: '11111111-1111-4111-8111-111111111111', name: 'Acme', slug: 'acme', domain: null,
  subscription_tier: null, subscription_tier_id: '22222222-2222-4222-8222-222222222222', trial_ends_at: null,
  billing_email: '', payment_status: 'active', stripe_customer_id: null, sso_enabled: false, is_active: true,
  is_operator: false, custom_branding: null, ui_config: null, settings: null,
  created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', deleted_at: null,
} as unknown as Tenant;

let root: Root | null = null;
let host: HTMLDivElement;
afterEach(() => {
  act(() => root?.unmount());
  root = null;
  host?.remove();
});

function openBillingTab() {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => root!.render(<TenantDrawer tenant={tenant} onClose={() => {}} />));
  const tab = Array.from(host.querySelectorAll('button')).find((b) => b.textContent === 'Billing');
  if (!tab) throw new Error('no Billing tab');
  act(() => tab.click());
}
const applyButton = () => Array.from(host.querySelectorAll('button')).find((b) => /Apply plan change/.test(b.textContent ?? ''));

describe('Change plan (support)', () => {
  it('is not offered to a tenant with no Stripe subscription', () => {
    state.billing = { data: { subscriptions: [], hasLiveStripeSubscription: false }, isLoading: false, isError: false };
    openBillingTab();
    expect(applyButton()).toBeUndefined();
    expect(host.querySelector('[data-testid="plan-change-unavailable"]')?.textContent).toContain('Assign to tenant');
  });

  it('is offered to a tenant with a live Stripe subscription', () => {
    state.billing = { data: { subscriptions: [], hasLiveStripeSubscription: true }, isLoading: false, isError: false };
    openBillingTab();
    expect(applyButton()).toBeDefined();
    expect(host.querySelector('[data-testid="plan-change-unavailable"]')).toBeNull();
  });
});

describe('hasLiveStripeSubscription', () => {
  it('counts a Stripe subscription Stripe still bills, and nothing else', () => {
    expect(real.hasLiveStripeSubscription([{ provider: 'stripe', status: 'active', subscription_id: 'sub_1' }])).toBe(true);
    expect(real.hasLiveStripeSubscription([{ provider: 'stripe', status: 'past_due', subscription_id: 'sub_1' }])).toBe(true);
    expect(real.hasLiveStripeSubscription([{ provider: 'stripe', status: 'trialing', subscription_id: 'sub_1' }])).toBe(true);
    expect(real.hasLiveStripeSubscription([{ provider: 'stripe', status: 'canceled', subscription_id: 'sub_1' }])).toBe(false);
    expect(real.hasLiveStripeSubscription([{ provider: 'stripe', status: 'incomplete_expired', subscription_id: 'sub_1' }])).toBe(false);
    expect(real.hasLiveStripeSubscription([{ provider: 'manual', status: 'active', subscription_id: 'invoice:x' }])).toBe(false);
    // The support billing edit's placeholder: no Stripe subscription behind it.
    expect(real.hasLiveStripeSubscription([{ provider: 'stripe', status: 'incomplete', subscription_id: 'pending' }])).toBe(false);
    expect(real.hasLiveStripeSubscription([{ provider: 'stripe', status: 'incomplete', subscription_id: 'sub_1' }])).toBe(true);
    expect(real.hasLiveStripeSubscription([])).toBe(false);
  });
});

describe('serverError', () => {
  it("prefers admin-service's own message", () => {
    expect(real.serverError({ error: 'tenant has no Stripe subscription — change the tier via tier assignment instead' }, 'x'))
      .toBe('tenant has no Stripe subscription — change the tier via tier assignment instead');
    expect(real.serverError(undefined, 'fallback')).toBe('fallback');
    expect(real.serverError({ error: '  ' }, 'fallback')).toBe('fallback');
  });
});
