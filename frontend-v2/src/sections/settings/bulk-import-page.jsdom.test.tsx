// @vitest-environment jsdom
// Settings -> Import: the five states (default, loading, error, empty, success),
// the dry-run plan with per-row reasons, and the Apply button behind the kind's
// own manage permission. The REAL PermissionProvider decides what renders.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { BulkImportPage } from './bulk-import-page';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));

const KINDS = [
  { kind: 'vlan', label: 'VLAN', plural: 'VLANs', permission: 'ipam.manage', read_permission: 'ipam.read', preview: false,
    columns: [{ name: 'vid', required: true, example: '100' }, { name: 'name', required: true, example: 'Users' }] },
  { kind: 'business_unit', label: 'Business unit', plural: 'Business units', permission: 'business_units.manage', read_permission: 'dcim.read', preview: true,
    columns: [{ name: 'name', required: true, example: 'Finance' }] },
];
const row = (r: number, action: string, extra: object = {}) => ({ row: r, action, key: `k${r}`, ...extra });
const plan = (rows: object[], summary: object, extra: object = {}) => ({
  data: { data: { kind: 'vlan', mode: 'dry_run', applied: false, preview: false, columns: ['vid', 'name'], rows,
    summary: { total: rows.length, create: 0, update: 0, unchanged: 0, error: 0, ...summary }, ...extra } },
});

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function render(perms: string[]) {
  cache.setQueryData(['user-permissions'], perms);
  const meta = { key: 'import', label: 'Import', icon: 'file-up', job: 'Import objects' };
  await act(async () => {
    root.render(<QueryClientProvider client={cache}><PermissionProvider><BulkImportPage meta={meta} /></PermissionProvider></QueryClientProvider>);
  });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
}
async function chooseFile(text = 'vid,name\n10,A\n') {
  const input = host.querySelector('[data-testid="import-file"]') as HTMLInputElement;
  const file = new File([text], 'vlans.csv', { type: 'text/csv' });
  Object.defineProperty(input, 'files', { value: [file], configurable: true });
  await act(async () => { input.dispatchEvent(new Event('change', { bubbles: true })); });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
}
const btn = (re: RegExp) => [...host.querySelectorAll('button')].find((b) => re.test(b.textContent ?? ''));

it('loading: the kinds are being fetched', async () => {
  api.GET.mockReturnValue(new Promise(() => {}));
  await render(['dcim.read']);
  expect(host.textContent).toContain('Loading');
});

it('error: the kinds list failed', async () => {
  api.GET.mockResolvedValue({ data: undefined, error: { error: { message: 'boom' } } });
  await render(['dcim.read']);
  expect(host.textContent).toContain("Couldn't load the importable kinds");
});

it('default: kinds, columns with the required ones marked, and no plan yet', async () => {
  api.GET.mockResolvedValue({ data: { data: KINDS } });
  await render(['dcim.read']);
  const sel = host.querySelector('[data-testid="import-kind"]') as HTMLSelectElement;
  expect([...sel.options].map((o) => o.textContent)).toEqual(['VLANs', 'Business units']);
  expect(host.textContent).toContain('vid*');
  expect(host.querySelector('[data-testid="import-plan"]')).toBeNull();
});

it('success: a dry run lists each row with its reason, and Apply sends mode=apply for the valid rows', async () => {
  api.GET.mockResolvedValue({ data: { data: KINDS } });
  api.POST.mockResolvedValueOnce(plan(
    [row(2, 'create'), row(3, 'error', { reason: 'group: no vlan group named "Nowhere"' }), row(4, 'update', { changed: ['name'] })],
    { create: 1, update: 1, error: 1 }));
  await render(['dcim.read', 'ipam.manage']);
  await chooseFile();
  expect(api.POST.mock.calls[0][0]).toBe('/dcim/import');
  expect(api.POST.mock.calls[0][1]).toMatchObject({ params: { query: { kind: 'vlan', mode: 'dry_run' } } });
  expect(host.querySelector('[data-testid="import-summary"]')!.textContent).toContain('1 to create · 1 to update · 0 unchanged · 1 error');
  expect([...host.querySelectorAll('[data-testid="import-row-reason"]')].map((e) => e.textContent)).toEqual(['group: no vlan group named "Nowhere"']);
  expect(btn(/Apply 2 valid rows \(skip 1\)/)).toBeTruthy();

  api.POST.mockResolvedValueOnce(plan([row(2, 'create', { id: 'x' }), row(4, 'update')], { create: 1, update: 1 }, { applied: true, mode: 'apply' }));
  await act(async () => { btn(/Apply 2 valid rows/)!.click(); });
  await vi.waitFor(() => expect(api.POST).toHaveBeenCalledTimes(2));
  expect(api.POST.mock.calls[1][1]).toMatchObject({ params: { query: { kind: 'vlan', mode: 'apply' } } });
  await vi.waitFor(() => expect(host.textContent).toContain('1 created · 1 updated'));
  expect(btn(/^Apply/)).toBeUndefined();
});

it('gate: a reader can check a file but has no Apply button, and is told the permission', async () => {
  api.GET.mockResolvedValue({ data: { data: KINDS } });
  api.POST.mockResolvedValue(plan([row(2, 'create')], { create: 1 }));
  await render(['dcim.read']);
  await chooseFile();
  expect(btn(/^Apply/)).toBeUndefined();
  expect(host.querySelector('[data-testid="import-no-permission"]')!.textContent).toContain('ipam.manage');
});

it('empty: a file that already matches says there is nothing to change', async () => {
  api.GET.mockResolvedValue({ data: { data: KINDS } });
  api.POST.mockResolvedValue(plan([row(2, 'unchanged')], { unchanged: 1 }));
  await render(['dcim.read', 'ipam.manage']);
  await chooseFile();
  expect(host.textContent).toContain('Nothing to change');
});

it('error: a rejected file shows the server reason', async () => {
  api.GET.mockResolvedValue({ data: { data: KINDS } });
  api.POST.mockResolvedValue({ data: undefined, error: { error: { message: 'missing required column(s): vid' } } });
  await render(['dcim.read', 'ipam.manage']);
  await chooseFile('name\nA\n');
  expect(host.textContent).toContain('The file was not accepted');
  expect(host.textContent).toContain('missing required column(s): vid');
});

it('loading: the file is being checked', async () => {
  api.GET.mockResolvedValue({ data: { data: KINDS } });
  api.POST.mockReturnValue(new Promise(() => {}));
  await render(['dcim.read', 'ipam.manage']);
  await chooseFile();
  expect(host.textContent).toContain('Checking the file');
});
