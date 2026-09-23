// @vitest-environment jsdom
//
// Tenants ▸ drawer ▸ "Your own tenant" (MSP soft cap), MOUNTED.
//
//   - rendered only on an MSP licence (the licensed-tenant read's edition);
//     hidden while that read is loading, after it failed, on Core and on
//     Enterprise;
//   - reflects is_operator, is read-only without tenants.manage;
//   - a confirmed toggle sends the new value; a declined one sends nothing;
//   - the server's message (e.g. its 409) is surfaced as the error toast.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { LicenseCap } from '../../lib/license-cap';
import type { Tenant } from './queries';

type MutateOpts = { onSuccess?: () => void; onError?: (e: unknown) => void };
const state = vi.hoisted(() => ({
  cap: { data: undefined as LicenseCap | undefined },
  perms: new Set<string>(['tenants.manage']),
  mutate: vi.fn<(vars: { id: string; isOperator: boolean }, opts: MutateOpts) => void>(),
  isPending: false,
  toastSuccess: vi.fn(),
  toastError: vi.fn(),
}));

vi.mock('../../lib/license-cap', () => ({ useLicenseCap: () => state.cap }));
vi.mock('./queries', () => ({
  useSetTenantOperator: () => ({ mutate: state.mutate, isPending: state.isPending }),
}));
vi.mock('@vistasecurity/primitives/platform-auth', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, usePlatformPermissions: () => ({ hasPermission: (p: string) => state.perms.has(p) }) };
});
vi.mock('react-hot-toast', () => ({ default: { success: state.toastSuccess, error: state.toastError } }));

import { OperatorTenantControl } from './operator-tenant-control';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const tenant = (over: Partial<Tenant> = {}): Tenant => ({
  id: '22222222-2222-4222-8222-222222222222', name: 'Acme', slug: 'acme', domain: null,
  subscription_tier: null, subscription_tier_id: '00000000-0000-0000-0000-000000000000', trial_ends_at: null,
  billing_email: '', payment_status: 'active', stripe_customer_id: null, sso_enabled: false, is_active: true,
  is_operator: false, custom_branding: null, ui_config: null, settings: null,
  created_at: '2026-09-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z', deleted_at: null,
  ...over,
});
const mspCap: LicenseCap = {
  edition: 'msp', licensed: 10, current: 4, operator: 0,
  grace_started_at: null, grace_days: 30, grace_ends_at: null, state: 'under',
};

let root: Root | null = null;
let host: HTMLDivElement;
function mount(t: Tenant) {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => root!.render(<OperatorTenantControl tenant={t} />));
}
const checkbox = () => host.querySelector<HTMLInputElement>('[data-testid="operator-tenant-control"] input');

beforeEach(() => {
  state.cap = { data: mspCap };
  state.perms = new Set(['tenants.manage']);
  state.mutate.mockReset();
  state.isPending = false;
  state.toastSuccess.mockReset();
  state.toastError.mockReset();
  vi.stubGlobal('confirm', vi.fn(() => true));
});
afterEach(() => {
  act(() => root?.unmount());
  root = null;
  host.remove();
  vi.unstubAllGlobals();
});

describe('who sees it', () => {
  it('is hidden while the licence read is loading or failed (no data)', () => {
    state.cap = { data: undefined };
    mount(tenant());
    expect(checkbox()).toBeNull();
  });

  it('is hidden on Core and Enterprise', () => {
    state.cap = { data: { ...mspCap, edition: 'enterprise', licensed: null, grace_days: null, state: 'uncapped' } };
    mount(tenant());
    expect(checkbox()).toBeNull();
    act(() => root?.unmount());
    host.remove();
    state.cap = { data: { ...mspCap, edition: 'core', licensed: null, grace_days: null, state: 'uncapped' } };
    mount(tenant());
    expect(checkbox()).toBeNull();
  });

  it('shows the current value and the count on MSP', () => {
    mount(tenant({ is_operator: true }));
    expect(checkbox()?.checked).toBe(true);
    expect(host.textContent).toContain('4 of 10 in use');
  });

  it('is read-only without tenants.manage', () => {
    state.perms = new Set();
    mount(tenant());
    expect(checkbox()?.disabled).toBe(true);
  });

  it('is disabled while a change is saving', () => {
    state.isPending = true;
    mount(tenant());
    expect(checkbox()?.disabled).toBe(true);
  });
});

describe('changing it', () => {
  it('sends the new value after confirmation and toasts success', () => {
    state.mutate.mockImplementation((_v, opts) => opts.onSuccess?.());
    mount(tenant());
    act(() => checkbox()!.click());
    expect(state.mutate).toHaveBeenCalledWith({ id: tenant().id, isOperator: true }, expect.anything());
    expect(state.toastSuccess).toHaveBeenCalledWith('Acme is marked as your own tenant');
  });

  it('sends nothing when the confirmation is declined', () => {
    vi.stubGlobal('confirm', vi.fn(() => false));
    mount(tenant());
    act(() => checkbox()!.click());
    expect(state.mutate).not.toHaveBeenCalled();
  });

  it("surfaces the server's message on error", () => {
    state.mutate.mockImplementation((_v, opts) => opts.onError?.(new Error('Marking the operator\'s own tenant applies to MSP licences only')));
    mount(tenant({ is_operator: true }));
    act(() => checkbox()!.click());
    expect(state.mutate).toHaveBeenCalledWith({ id: tenant().id, isOperator: false }, expect.anything());
    expect(state.toastError).toHaveBeenCalledWith("Marking the operator's own tenant applies to MSP licences only");
  });
});
