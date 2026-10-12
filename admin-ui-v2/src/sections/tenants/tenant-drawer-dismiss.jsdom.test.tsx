// @vitest-environment jsdom
//
// Tenants ▸ drawer, MOUNTED: an accessible dialog whose scrim click / Esc must
// not throw away a half-written support plan change.
//
// Mutations run (each red, then restored green): not passing `dirty` from the
// plan-change form up to the drawer.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Tenant } from './queries';

vi.mock('../../lib/edition', () => ({ usePlatformEdition: () => ({ license: 'msp', isMsp: true, has: () => true }) }));
vi.mock('../../app/scope', () => ({ useScope: () => ({ scopeId: null }) }));
vi.mock('./queries', async (orig) => {
  const real = await orig<typeof import('./queries')>();
  const idle = { mutate: vi.fn(), mutateAsync: vi.fn(), isPending: false };
  const none = { data: undefined, isLoading: false, isError: false };
  return {
    ...real,
    useTenantHealthMap: () => none, useTenantStats: () => none, useTenantCost: () => none, useTenantCoupons: () => none,
    useAdminTiers: () => ({ data: [], isLoading: false }),
    useTenantStatusMutation: () => idle, useTenantReevaluateMutation: () => idle, useDeleteTenant: () => idle, useAdminChangePlan: () => idle,
    useTenantBillingRecords: () => ({ data: { subscriptions: [], hasLiveStripeSubscription: true }, isLoading: false, isError: false }),
  };
});
vi.mock('./tenant-entitlements-tab', () => ({ TenantEntitlementsTab: () => null }));
vi.mock('./tenant-settings-tab', () => ({ TenantSettingsPanel: () => null }));
vi.mock('./tenant-form-modal', () => ({ TenantFormModal: () => null }));
vi.mock('./operator-tenant-control', () => ({ OperatorTenantControl: () => null }));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn() }) }));

const { TenantDrawer } = await import('./tenant-drawer');

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const tenant = {
  id: '11111111-1111-4111-8111-111111111111', name: 'Acme', slug: 'acme', domain: null,
  subscription_tier: null, subscription_tier_id: null, trial_ends_at: null, billing_email: '', payment_status: 'active',
  stripe_customer_id: null, sso_enabled: false, is_active: true, is_operator: false, custom_branding: null, ui_config: null,
  settings: null, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', deleted_at: null,
} as unknown as Tenant;

let root: Root | null = null;
let host: HTMLDivElement;
afterEach(() => { act(() => root?.unmount()); root = null; host?.remove(); });

function open(onClose: () => void) {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => root!.render(<TenantDrawer tenant={tenant} onClose={onClose} />));
}
function typeReason() {
  const tab = Array.from(host.querySelectorAll('button')).find((b) => b.textContent === 'Billing')!;
  act(() => tab.click());
  const ta = host.querySelector('textarea') as HTMLTextAreaElement;
  const set = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')!.set!;
  act(() => { set.call(ta, 'customer asked'); ta.dispatchEvent(new Event('input', { bubbles: true })); });
}
const scrim = () => host.querySelector('[data-dialog-scrim]') as HTMLElement;

describe('tenant drawer dialog', () => {
  it('is a labelled modal dialog with a named close button and Edit button', () => {
    open(() => {});
    const d = host.querySelector('[role="dialog"]')!;
    expect(d.getAttribute('aria-modal')).toBe('true');
    expect(document.getElementById(d.getAttribute('aria-labelledby')!)?.textContent).toBe('Acme');
    expect(d.querySelector('button[aria-label="Close"]')).not.toBeNull();
    expect(d.querySelector('button[aria-label="Edit tenant"]')).not.toBeNull();
  });

  it('closes on a scrim click while clean', () => {
    const onClose = vi.fn();
    open(onClose);
    act(() => scrim().click());
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('keeps a drawer with typed input open on a scrim click, and asks first', () => {
    const onClose = vi.fn();
    open(onClose);
    typeReason();
    act(() => scrim().click());
    expect(onClose).not.toHaveBeenCalled();
    expect(host.textContent).toContain('Discard changes?');
  });
});
