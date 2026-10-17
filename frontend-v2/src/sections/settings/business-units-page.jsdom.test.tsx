// @vitest-environment jsdom
// Settings -> Business Units: the five states, the tree, and the write
// controls behind business_units.manage. The REAL PermissionProvider decides
// what renders, seeded through its own query, so a dropped gate turns a test red.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { BusinessUnitsPage } from './business-units-page';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn(), DELETE: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));

const unit = (id: string, name: string, parent_id: string | null, asset_count = 0) => ({
  id, tenant_id: 't', name, slug: name.toLowerCase(), parent_id, description: null, external_ids: {}, source_kind: 'declared',
  custom_fields: {}, created_at: '', updated_at: '', asset_count,
});
const LIST = [unit('f', 'Finance', 'c', 2), unit('c', 'Corporate', null), unit('r', 'Retail', null)];

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function render(perms: string[]) {
  cache.setQueryData(['user-permissions'], perms);
  const meta = { key: 'business-units', label: 'Business Units', icon: 'building-2', job: 'Units' };
  await act(async () => {
    root.render(<QueryClientProvider client={cache}><PermissionProvider><BusinessUnitsPage meta={meta} /></PermissionProvider></QueryClientProvider>);
  });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
}
const btn = (re: RegExp) => [...host.querySelectorAll('button')].find((b) => re.test(b.textContent ?? '') || re.test(b.getAttribute('aria-label') ?? ''));
const names = () => [...host.querySelectorAll('[data-testid="bu-name"]')].map((e) => e.textContent ?? '');

it('loading', async () => {
  api.GET.mockReturnValue(new Promise(() => {}));
  await render(['dcim.read']);
  expect(host.textContent).toContain('Loading business units');
});

it('error', async () => {
  api.GET.mockResolvedValue({ data: undefined, error: { error: 'x' } });
  await render(['dcim.read']);
  expect(host.textContent).toContain("Couldn't load business units");
});

it('empty', async () => {
  api.GET.mockResolvedValue({ data: { business_units: [], total: 0 } });
  await render(['dcim.read', 'business_units.manage']);
  expect(host.textContent).toContain('No business units');
});

it('default: the tree, parents above children, and no write controls for a reader', async () => {
  api.GET.mockResolvedValue({ data: { business_units: LIST, total: 3 } });
  await render(['dcim.read']);
  expect(api.GET).toHaveBeenCalledWith('/dcim/business-units', {});
  expect(names().map((n) => n.replace('↳', '').trim())).toEqual(['Corporate', 'Finance', 'Retail']);
  expect(btn(/New business unit/)).toBeUndefined();
  expect(btn(/Edit Finance/)).toBeUndefined();
});

it('success: a manager creates a unit under a parent', async () => {
  api.GET.mockResolvedValue({ data: { business_units: LIST, total: 3 } });
  api.POST.mockResolvedValue({ data: unit('n', 'Payroll', 'f'), response: { ok: true, status: 201 } });
  await render(['dcim.read', 'business_units.manage']);
  await act(async () => { btn(/New business unit/)!.click(); });
  const set = (el: Element, v: string, proto: typeof HTMLInputElement | typeof HTMLSelectElement) =>
    act(async () => {
      Object.getOwnPropertyDescriptor(proto.prototype, 'value')!.set!.call(el, v);
      el.dispatchEvent(new Event(proto === HTMLInputElement ? 'input' : 'change', { bubbles: true }));
    });
  await set(document.querySelector('input[aria-label="Name"]')!, 'Payroll', HTMLInputElement);
  await set(document.querySelector('select[aria-label="Parent business unit"]')!, 'f', HTMLSelectElement);
  await act(async () => { btn(/^Create business unit$/)!.click(); });
  await vi.waitFor(() => expect(api.POST).toHaveBeenCalledTimes(1));
  expect(api.POST.mock.calls[0][0]).toBe('/dcim/business-units');
  expect((api.POST.mock.calls[0][1] as { body: unknown }).body).toMatchObject({ name: 'Payroll', parent_id: 'f' });
});

it('delete: a unit with assets must name where they go, and sends reassign_to', async () => {
  api.GET.mockResolvedValue({ data: { business_units: LIST, total: 3 } });
  api.DELETE.mockResolvedValue({ response: { ok: true, status: 204 } });
  await render(['dcim.read', 'business_units.manage']);
  await act(async () => { btn(/Delete Finance/)!.click(); });
  const del = btn(/^Delete$/)!;
  expect(del.disabled).toBe(true);
  const pick = document.querySelector('select[aria-label="Move its assets to"]') as HTMLSelectElement;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')!.set!.call(pick, 'r');
    pick.dispatchEvent(new Event('change', { bubbles: true }));
  });
  expect(btn(/^Delete$/)!.disabled).toBe(false);
  await act(async () => { btn(/^Delete$/)!.click(); });
  await vi.waitFor(() => expect(api.DELETE).toHaveBeenCalledTimes(1));
  expect((api.DELETE.mock.calls[0][1] as { params: unknown }).params).toEqual({ path: { id: 'f' }, query: { reassign_to: 'r' } });
});

it('edit: the drawer carries the unit\'s Changes and Journal panels', async () => {
  api.GET.mockImplementation(async (path: string) => path === '/dcim/business-units'
    ? { data: { business_units: LIST, total: 3 } }
    : { data: { changes: [], journal_entries: [], entries: [], total: 0 } });
  await render(['dcim.read', 'business_units.manage']);
  await act(async () => { btn(/Edit Finance/)!.click(); });
  expect(document.querySelector('[data-testid="bu-history"]')).not.toBeNull();
  await vi.waitFor(() => expect(api.GET.mock.calls.some((c) => String(c[0]).includes('/dcim/changes'))).toBe(true));
});
