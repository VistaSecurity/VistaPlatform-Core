// @vitest-environment jsdom
// Settings -> Device Types (DCIM 2.2): the five states, built-in rows read-only,
// the detail view's template tabs, and "Import from library". The REAL
// PermissionProvider decides what renders, so a dropped gate turns a test red.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { DeviceTypesPage } from './device-types-page';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));

const MFR = { id: 'm1', tenant_id: null, name: 'Cisco', slug: 'cisco' };
const dt = (id: string, model: string, tenant_id: string | null) => ({
  id, tenant_id, manufacturer_id: 'm1', model, slug: model.toLowerCase(), part_number: model, u_height: 1,
  is_full_depth: true, airflow: 'front-to-rear', external_ids: { library: { path: `Cisco/${model}.yaml` } },
  manufacturer: { id: 'm1', name: 'Cisco', slug: 'cisco' }, interface_template_count: 2,
});
const TYPES = [dt('d1', 'C9300-48P', null), dt('d2', 'Lab-Switch', 't')];

function routes(types: unknown[] = TYPES) {
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/dcim/device-types') return { data: { data: types, pagination: { total: types.length } } };
    if (path === '/dcim/manufacturers') return { data: { data: [MFR], pagination: { total: 1 } } };
    if (path === '/dcim/device-types/{id}/interface-templates') {
      return { data: { data: [{ id: 'i1', name: 'GigabitEthernet1/0/1', type: '1000base-t', label: null }, { id: 'i2', name: 'GigabitEthernet1/0/2', type: '1000base-t', label: null }] } };
    }
    return { data: { data: [] } };
  });
}

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); document.body.innerHTML = ''; });

async function render(perms: string[]) {
  cache.setQueryData(['user-permissions'], perms);
  const meta = { key: 'device-types', label: 'Device Types', icon: 'server', job: 'Catalogue' };
  await act(async () => {
    root.render(<QueryClientProvider client={cache}><PermissionProvider><DeviceTypesPage meta={meta} /></PermissionProvider></QueryClientProvider>);
  });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
}
const btn = (re: RegExp) => [...document.querySelectorAll('button')].find((b) => re.test(b.textContent ?? '') || re.test(b.getAttribute('aria-label') ?? ''));
const flush = () => act(async () => { await new Promise((r) => setTimeout(r, 0)); });

it('loading', async () => {
  api.GET.mockReturnValue(new Promise(() => {}));
  await render(['dcim.read']);
  expect(host.textContent).toContain('Loading device types');
});

it('error', async () => {
  api.GET.mockResolvedValue({ data: undefined, error: { error: { message: 'boom' } } });
  await render(['dcim.read']);
  expect(host.querySelector('[data-testid="substrate-error"]')?.textContent).toContain('boom');
});

it('empty', async () => {
  routes([]);
  await render(['dcim.read', 'dcim.manage']);
  expect(host.textContent).toContain('No device types');
});

it('default: built-in types are read-only, the tenant’s own are editable — and a reader edits nothing', async () => {
  routes();
  await render(['dcim.read']);
  const models = [...host.querySelectorAll('[data-testid="device-type-model"]')].map((e) => e.textContent);
  expect(models).toEqual(['C9300-48P', 'Lab-Switch']);
  expect(host.textContent).toContain('Built in');
  expect(btn(/Import from library/)).toBeUndefined();
  expect(btn(/Edit Lab-Switch/)).toBeUndefined();

  act(() => root.unmount()); root = createRoot(host);
  await render(['dcim.read', 'dcim.manage']);
  expect(btn(/Import from library/)).toBeDefined();
  expect(btn(/Edit Lab-Switch/)).toBeDefined();
  expect(btn(/Edit C9300-48P/)).toBeUndefined();
});

it('detail: a type opens with its interface templates', async () => {
  routes();
  await render(['dcim.read', 'dcim.manage']);
  const row = [...host.querySelectorAll('[data-testid="device-type-model"]')].find((e) => e.textContent === 'C9300-48P')!;
  await act(async () => { (row.closest('[role="row"], div') as HTMLElement).click(); });
  await flush();
  expect(document.querySelector('[data-testid="device-type-detail"]')).not.toBeNull();
  await vi.waitFor(() => expect(document.querySelectorAll('[data-testid="template-name"]').length).toBe(2));
  expect(api.GET.mock.calls.some((c) => c[0] === '/dcim/device-types/{id}/interface-templates'
    && (c[1] as { params: { path: { id: string } } }).params.path.id === 'd1')).toBe(true);
  // A built-in type's templates cannot be changed.
  expect(btn(/Edit GigabitEthernet1\/0\/1/)).toBeUndefined();
});

it('success: import from library sends the YAML and shows what each document did', async () => {
  routes();
  api.POST.mockResolvedValue({ data: { data: [
    { manufacturer: 'Panduit', model: 'CPA24BLY', status: 'created', device_type_id: 'n1', manufacturer_created: true, templates: 48, warnings: [] },
    { manufacturer: 'Cisco', model: 'Catalyst 9300-48P', status: 'exists', device_type_id: 'd1', manufacturer_created: false, templates: 0, warnings: [] },
  ] } });
  await render(['dcim.read', 'dcim.manage']);
  await act(async () => { btn(/Import from library/)!.click(); });
  const ta = document.querySelector('textarea[aria-label="Library YAML"]') as HTMLTextAreaElement;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')!.set!.call(ta, 'manufacturer: Panduit\nmodel: CPA24BLY\n');
    ta.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await act(async () => { (document.querySelector('[data-testid="import-submit"]') as HTMLButtonElement).click(); });
  await vi.waitFor(() => expect(api.POST).toHaveBeenCalledTimes(1));
  expect(api.POST.mock.calls[0][0]).toBe('/dcim/device-types/import');
  expect((api.POST.mock.calls[0][1] as { body: unknown }).body).toEqual({ yaml: 'manufacturer: Panduit\nmodel: CPA24BLY\n' });
  await vi.waitFor(() => expect(document.querySelector('[data-testid="import-result"]')).not.toBeNull());
  const result = document.querySelector('[data-testid="import-result"]')!.textContent ?? '';
  expect(result).toContain('Imported · 48 templates');
  expect(result).toContain('Already in the catalogue');
});
