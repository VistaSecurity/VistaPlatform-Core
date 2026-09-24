// @vitest-environment jsdom
//
// Tenants ▸ drawer ▸ Suspend / Reactivate / Delete — the confirmation copy,
// MOUNTED (RC-4).
//
// Suspension and deletion are now enforced (sessions end, sign-in and agents
// are refused), and there is no restore for a deleted tenant. The old Delete
// prompt promised the tenant was "recoverable", which was never true. These
// cases click the real buttons and read what window.confirm is asked, so
// reverting the copy fails here; declining the prompt must send nothing.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Tenant } from './queries';

const state = vi.hoisted(() => ({
  statusMutate: vi.fn(),
  deleteMutate: vi.fn(),
}));

vi.mock('../../lib/edition', () => ({
  usePlatformEdition: () => ({ license: 'msp', isMsp: true, has: () => true }),
}));
vi.mock('../../app/scope', () => ({ useScope: () => ({ scopeId: null }) }));
vi.mock('./queries', async (orig) => {
  const real = await orig<typeof import('./queries')>();
  const idle = { mutate: vi.fn(), isPending: false };
  const none = { data: undefined, isLoading: false, isError: false };
  return {
    ...real,
    useTenantHealthMap: () => none,
    useTenantStats: () => none,
    useTenantCost: () => none,
    useTenantCoupons: () => none,
    useAdminTiers: () => none,
    useTenantStatusMutation: () => ({ mutate: state.statusMutate, isPending: false }),
    useTenantReevaluateMutation: () => idle,
    useDeleteTenant: () => ({ mutate: state.deleteMutate, isPending: false }),
    useAdminChangePlan: () => idle,
  };
});
vi.mock('./tenant-entitlements-tab', () => ({ TenantEntitlementsTab: () => null }));
vi.mock('./tenant-settings-tab', () => ({ TenantSettingsPanel: () => null }));
vi.mock('./tenant-form-modal', () => ({ TenantFormModal: () => null }));
vi.mock('./operator-tenant-control', () => ({ OperatorTenantControl: () => null }));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn() }) }));

const { TenantDrawer } = await import('./tenant-drawer');

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const tenant = (over: Partial<Tenant> = {}): Tenant => ({
  id: '11111111-1111-4111-8111-111111111111', name: 'Acme', slug: 'acme', domain: null,
  subscription_tier: null, subscription_tier_id: '22222222-2222-4222-8222-222222222222', trial_ends_at: null,
  billing_email: '', payment_status: 'active', stripe_customer_id: null, sso_enabled: false, is_active: true,
  is_operator: false, custom_branding: null, ui_config: null, settings: null,
  created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', deleted_at: null,
  ...over,
});

let root: Root | null = null;
let host: HTMLDivElement;
const confirmSpy = vi.fn<(msg?: string) => boolean>();

function mount(t: Tenant) {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => root!.render(<TenantDrawer tenant={t} onClose={() => {}} />));
}
function click(label: RegExp) {
  const btn = Array.from(host.querySelectorAll('button')).find((b) => label.test(b.textContent ?? ''));
  if (!btn) throw new Error(`no button matching ${label}`);
  act(() => btn.click());
}

beforeEach(() => {
  state.statusMutate.mockReset();
  state.deleteMutate.mockReset();
  confirmSpy.mockReset();
  confirmSpy.mockReturnValue(true);
  vi.stubGlobal('confirm', confirmSpy);
});
afterEach(() => {
  act(() => root?.unmount());
  root = null;
  host?.remove();
  vi.unstubAllGlobals();
});

describe('tenant drawer lifecycle confirmations', () => {
  it('Delete no longer promises the tenant is recoverable, and says what deletion does', () => {
    mount(tenant());
    click(/^Delete$/);
    const msg = confirmSpy.mock.calls[0]?.[0] ?? '';
    expect(msg.toLowerCase()).not.toContain('recoverable');
    expect(msg).toContain('cannot be restored');
    expect(msg).toContain('signed out');
    expect(state.deleteMutate).toHaveBeenCalledTimes(1);
  });

  it('Suspend says users are signed out and refused until reactivation', () => {
    mount(tenant());
    click(/Suspend/);
    const msg = confirmSpy.mock.calls[0]?.[0] ?? '';
    expect(msg).toContain('signed out and cannot sign in');
    expect(state.statusMutate).toHaveBeenCalledWith({ id: tenant().id, action: 'suspend' }, expect.anything());
  });

  it('Reactivate says the previous status is restored', () => {
    mount(tenant({ payment_status: 'suspended', is_active: false }));
    click(/Reactivate/);
    const msg = confirmSpy.mock.calls[0]?.[0] ?? '';
    expect(msg).toContain('status it had before the suspension is restored');
    expect(state.statusMutate).toHaveBeenCalledWith({ id: tenant().id, action: 'activate' }, expect.anything());
  });

  it('declining the prompt sends nothing', () => {
    confirmSpy.mockReturnValue(false);
    mount(tenant());
    click(/^Delete$/);
    click(/Suspend/);
    expect(state.deleteMutate).not.toHaveBeenCalled();
    expect(state.statusMutate).not.toHaveBeenCalled();
  });
});
