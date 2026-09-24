// @vitest-environment jsdom
//
// Tenants ▸ drawer ▸ Scope, and the scope bar, MOUNTED (owner decision 10,
// RC-21).
//
// "Scope" used to raise a toast saying it would be wired with the
// impersonation flow, although global scope (useScope) already existed; it now
// sets that scope. "Open in Console" — in the drawer and on the scope bar —
// promised an impersonation flow that does not exist and is removed.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Tenant } from './queries';

const state = vi.hoisted(() => ({
  setScope: vi.fn(),
  clear: vi.fn(),
  scopeId: null as string | null,
  scopeName: null as string | null,
  onClose: vi.fn(),
}));

vi.mock('../../lib/edition', () => ({
  usePlatformEdition: () => ({ license: 'msp', isMsp: true, has: () => true }),
}));
vi.mock('../../app/scope', () => ({
  useScope: () => ({ scopeId: state.scopeId, scopeName: state.scopeName, setScope: state.setScope, clear: state.clear }),
}));
vi.mock('./queries', async (orig) => {
  const real = await orig<typeof import('./queries')>();
  const idle = { mutate: vi.fn(), isPending: false };
  const none = { data: undefined, isLoading: false, isError: false };
  return {
    ...real,
    useTenants: () => none,
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
vi.mock('./operator-tenant-control', () => ({ OperatorTenantControl: () => null }));
const toastMock = vi.hoisted(() => Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn() }));
vi.mock('react-hot-toast', () => ({ default: toastMock }));

const { TenantDrawer } = await import('./tenant-drawer');
const { ScopeBar } = await import('../../app/tenant-switcher');

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const tenant: Tenant = {
  id: '11111111-1111-4111-8111-111111111111', name: 'Acme', slug: 'acme', domain: null,
  subscription_tier: null, subscription_tier_id: '22222222-2222-4222-8222-222222222222', trial_ends_at: null,
  billing_email: '', payment_status: 'active', stripe_customer_id: null, sso_enabled: false, is_active: true,
  is_operator: false, custom_branding: null, ui_config: null, settings: null,
  created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', deleted_at: null,
};

let root: Root | null = null;
let host: HTMLDivElement;

function mount(node: React.ReactNode) {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => root!.render(node));
}
const buttons = () => Array.from(host.querySelectorAll('button')).map((b) => (b.textContent ?? '').trim());

beforeEach(() => {
  state.setScope.mockReset();
  state.clear.mockReset();
  state.onClose.mockReset();
  state.scopeId = null;
  state.scopeName = null;
  toastMock.mockReset();
});
afterEach(() => {
  act(() => root?.unmount());
  root = null;
  host?.remove();
});

describe('tenant drawer Scope', () => {
  it('sets the global scope to this tenant instead of raising a toast', () => {
    mount(<TenantDrawer tenant={tenant} onClose={state.onClose} />);
    const scope = Array.from(host.querySelectorAll('button')).find((b) => (b.textContent ?? '').trim() === 'Scope');
    if (!scope) throw new Error('no Scope button');
    act(() => scope.click());
    expect(state.setScope).toHaveBeenCalledWith(tenant.id, tenant.name);
    expect(state.onClose).toHaveBeenCalled();
    // The old stub: a bare toast() naming the impersonation flow.
    expect(toastMock).not.toHaveBeenCalled();
  });

  it('offers no "Open in Console" — no impersonation flow exists', () => {
    mount(<TenantDrawer tenant={tenant} onClose={state.onClose} />);
    expect(buttons()).not.toContain('Open in Console');
    expect(host.textContent ?? '').not.toMatch(/imperson/i);
  });
});

describe('scope bar', () => {
  it('offers Clear scope but no "Open in Console"', () => {
    state.scopeId = tenant.id;
    state.scopeName = tenant.name;
    mount(<ScopeBar />);
    expect(buttons()).toContain('Clear scope');
    expect(buttons()).not.toContain('Open in Console');
  });
});
