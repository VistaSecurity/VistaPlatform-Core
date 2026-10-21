// @vitest-environment jsdom
// The Hardware tab's Lifecycle card (DCIM gap 4): its five states (loading,
// error, empty, recorded, after a save), the honest "not recorded" words, the
// badges' tones, the device type's dates with their sources, Edit behind
// dcim.manage, the PATCH body (only what changed, "" clears, currency
// upper-cased) and the client-side refusals.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  LifecycleCard, NOT_RECORDED, commercialChanges, costText, draftOfCommercial, eosBadge, eosSourceText, warrantyBadge,
} from './lifecycle-card';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() }));
vi.mock('../../../lib/clients', () => ({ clients: { inventory: api } }));

const BASE = {
  asset_id: 'a1', class_key: 'switch', is_hardware: true, device_type: null, manufacturer: null, device_role: null, platform: null,
  serial: null, asset_tag: null, template_counts: {},
  commercial: NOT_RECORDED, device_type_eos: null, platform_eos: null,
  lifecycle: { warranty_state: 'unknown', eos_state: 'unknown', effective_end_of_support: null, source: 'none', subject: null },
};
const RECORDED = {
  ...BASE,
  device_type: { id: 'dt', name: 'AX-48', slug: 'ax-48' },
  commercial: { ...NOT_RECORDED, purchase_date: '2024-03-01', warranty_end: '2026-11-15', purchase_cost: 4200.5, purchase_currency: 'EUR', vendor: 'Acme Resale' },
  device_type_eos: {
    end_of_sale: { date: '2024-12-31', source: 'declared' },
    end_of_support: { date: '2025-06-30', source: 'catalogue' },
    end_of_life: { date: null, source: 'none' },
    eol_catalogue: { id: 'e1', product_kind: 'hardware', vendor: 'Acme', product: 'AX-48', cycle: '1', eol_date: '2025-06-30', extended_support_date: null },
  },
  lifecycle: { warranty_state: 'expiring_90', eos_state: 'past_eos', effective_end_of_support: '2025-06-30', source: 'catalogue', subject: 'device_type' },
};

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function render(perms: string[], canManage = perms.includes('dcim.manage')) {
  cache.setQueryData(['user-permissions'], perms);
  await act(async () => {
    root.render(<QueryClientProvider client={cache}><PermissionProvider><LifecycleCard assetId="a1" canManage={canManage} /></PermissionProvider></QueryClientProvider>);
  });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
}
const byTest = (id: string) => host.querySelector(`[data-testid="${id}"]`);
const input = (label: string) => host.querySelector<HTMLInputElement>(`[aria-label="${label}"]`)!;
function type(el: HTMLInputElement, value: string) {
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(el, value);
  el.dispatchEvent(new Event('input', { bubbles: true }));
}
const click = async (el: Element | null) => { await act(async () => { (el as HTMLButtonElement).click(); }); };

describe('<LifecycleCard> states', () => {
  it('loading', async () => {
    api.GET.mockReturnValue(new Promise(() => {}));
    await render(['dcim.read']);
    expect(host.textContent).toContain('Loading the lifecycle');
  });

  it('error', async () => {
    api.GET.mockResolvedValue({ data: undefined, error: { error: { message: 'inventory down' } } });
    await render(['dcim.read']);
    expect(byTest('substrate-error')?.textContent).toContain('inventory down');
  });

  it('empty: nothing recorded says so, and both states are "not recorded", never healthy', async () => {
    api.GET.mockResolvedValue({ data: { data: BASE } });
    await render(['dcim.read']);
    expect(host.textContent).toContain('No lifecycle recorded');
    expect(byTest('warranty-badge')?.textContent).toBe('Warranty not recorded');
    expect(byTest('eos-badge')?.textContent).toBe('End of support not recorded');
    expect(byTest('warranty-badge')?.getAttribute('data-tone')).toBe('muted');
    expect(host.textContent).not.toMatch(/Under warranty|Supported/);
  });

  it('an older server with no lifecycle fields reads as not recorded', async () => {
    const { commercial: _c, lifecycle: _l, device_type_eos: _d, platform_eos: _p, ...old } = BASE;
    api.GET.mockResolvedValue({ data: { data: old } });
    await render(['dcim.read']);
    expect(byTest('eos-badge')?.textContent).toBe('End of support not recorded');
  });

  it('default: the recorded fields, "Not recorded" for the rest, the badges and the device type dates with sources', async () => {
    api.GET.mockResolvedValue({ data: { data: RECORDED } });
    await render(['dcim.read']);
    const rows = byTest('lifecycle-rows')!;
    expect(rows.textContent).toContain('2024-03-01');
    expect(rows.textContent).toContain('Acme Resale');
    expect(rows.textContent).toMatch(/4,200\.50|4200\.50|4\.200,50/);
    expect(rows.textContent).toContain('Not recorded'); // purchase order, contract, …
    expect(byTest('warranty-badge')?.textContent).toBe('Warranty ends within 90 days');
    expect(byTest('eos-badge')?.textContent).toBe('Past end of support');
    expect(byTest('eos-badge')?.getAttribute('data-tone')).toBe('danger');
    expect(byTest('eos-source')?.textContent).toContain('2025-06-30 — the device type, the end-of-life catalogue');
    const dt = byTest('eos-device-type')?.textContent ?? '';
    expect(dt).toContain('2024-12-31');
    expect(dt).toContain('declared');
    expect(dt).toContain('from the end-of-life catalogue');
    expect(byTest('eos-platform')).toBeNull();
    expect(byTest('lifecycle-edit')).toBeNull(); // a reader gets no Edit
  });

  it('success: Edit, change two fields, Save sends only those (currency upper-cased) and shows the server answer', async () => {
    api.GET.mockResolvedValue({ data: { data: RECORDED } });
    const after = { ...RECORDED, commercial: { ...RECORDED.commercial, vendor: null, purchase_currency: 'USD' } };
    api.PATCH.mockResolvedValue({ data: { data: after } });
    await render(['dcim.read', 'dcim.manage']);
    await click(byTest('lifecycle-edit'));
    expect(byTest('lifecycle-form')).not.toBeNull();
    expect(input('Purchase cost').value).toBe('4200.50');
    await act(async () => { type(input('Vendor (seller)'), ''); type(input('Currency'), 'usd'); });
    await click(byTest('lifecycle-save'));
    await vi.waitFor(() => expect(api.PATCH).toHaveBeenCalledTimes(1));
    expect(api.PATCH.mock.calls[0][0]).toBe('/dcim/assets/{id}/hardware');
    expect(api.PATCH.mock.calls[0][1]).toEqual({ params: { path: { id: 'a1' } }, body: { vendor: null, purchase_currency: 'USD' } });
    await vi.waitFor(() => expect(byTest('lifecycle-form')).toBeNull());
    expect(byTest('lifecycle-rows')?.textContent).not.toContain('Acme Resale');
  });

  it('a refusal from the server is shown and the form stays open', async () => {
    api.GET.mockResolvedValue({ data: { data: RECORDED } });
    api.PATCH.mockResolvedValue({ data: undefined, error: { error: { message: 'purchase_order is longer than 200 characters' } } });
    await render(['dcim.read', 'dcim.manage']);
    await click(byTest('lifecycle-edit'));
    await act(async () => { type(input('Purchase order'), 'PO-1'); });
    await click(byTest('lifecycle-save'));
    await vi.waitFor(() => expect(byTest('lifecycle-error')?.textContent).toContain('longer than 200'));
    expect(byTest('lifecycle-form')).not.toBeNull();
  });

  it('a warranty ending before it starts is refused before any request', async () => {
    api.GET.mockResolvedValue({ data: { data: RECORDED } });
    await render(['dcim.read', 'dcim.manage']);
    await click(byTest('lifecycle-edit'));
    await act(async () => { type(input('Warranty start'), '2027-01-01'); });
    await click(byTest('lifecycle-save'));
    expect(byTest('lifecycle-error')?.textContent).toContain('cannot end before it starts');
    expect(api.PATCH).not.toHaveBeenCalled();
  });

  it('no Edit when the tab says the asset cannot be managed (archived), even with dcim.manage', async () => {
    api.GET.mockResolvedValue({ data: { data: RECORDED } });
    await render(['dcim.read', 'dcim.manage'], false);
    expect(byTest('lifecycle-edit')).toBeNull();
  });
});

describe('lifecycle words', () => {
  it('badges never default to healthy', () => {
    expect(warrantyBadge('unknown').tone).toBe('muted');
    expect(eosBadge('unknown').tone).toBe('muted');
    expect(warrantyBadge('active').tone).toBe('ok');
    expect(eosBadge('eos_within_12m').tone).toBe('warn');
  });
  it('the source line names the platform and a declared date', () => {
    expect(eosSourceText({ warranty_state: 'unknown', eos_state: 'supported', effective_end_of_support: '2031-01-01', source: 'declared', subject: 'platform' }))
      .toBe('2031-01-01 — the platform (OS), declared');
    expect(eosSourceText({ warranty_state: 'unknown', eos_state: 'unknown', effective_end_of_support: null, source: 'none', subject: null })).toBeNull();
  });
  it('a cost without a currency says so', () => {
    expect(costText(12, null)).toBe('12.00 (no currency recorded)');
    expect(costText(null, 'USD')).toBeNull();
  });
  it('commercialChanges sends only what moved and refuses a bad cost or currency', () => {
    const base = draftOfCommercial({ ...NOT_RECORDED, vendor: 'A' });
    expect(commercialChanges(base, base)).toEqual({ body: null, error: null });
    expect(commercialChanges(base, { ...base, vendor: '', purchase_cost: '10' }).body).toEqual({ vendor: null, purchase_cost: '10' });
    expect(commercialChanges(base, { ...base, purchase_cost: '1.234' }).error).toContain('two decimals');
    expect(commercialChanges(base, { ...base, purchase_currency: 'EURO' }).error).toContain('ISO 4217');
    expect(commercialChanges(base, { ...base, installed_at: '2026-02-01', decommissioned_at: '2026-01-01' }).error).toContain('decommissioned before');
  });
});
