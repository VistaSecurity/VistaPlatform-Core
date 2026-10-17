// @vitest-environment jsdom
// Settings -> Manufacturers / Device Roles / Platforms (DCIM 2.2): the five
// states of the shared table, built-in rows read-only, and a manager's create.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { DeviceRolesPage, ManufacturersPage, PlatformsPage } from './device-catalogue-pages';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));

const mfr = (id: string, name: string, tenant_id: string | null) => ({ id, tenant_id, name, slug: name.toLowerCase(), description: null });
const MFRS = [mfr('m1', 'Cisco', null), mfr('m2', 'Acme', 't')];

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); document.body.innerHTML = ''; });

async function render(perms: string[], Page = ManufacturersPage) {
  cache.setQueryData(['user-permissions'], perms);
  const meta = { key: 'x', label: 'X', icon: 'factory', job: 'Job' };
  await act(async () => {
    root.render(<QueryClientProvider client={cache}><PermissionProvider><Page meta={meta} /></PermissionProvider></QueryClientProvider>);
  });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
}
const btn = (re: RegExp) => [...document.querySelectorAll('button')].find((b) => re.test(b.textContent ?? '') || re.test(b.getAttribute('aria-label') ?? ''));

it('loading', async () => {
  api.GET.mockReturnValue(new Promise(() => {}));
  await render(['dcim.read']);
  expect(host.textContent).toContain('Loading manufacturers');
});

it('error', async () => {
  api.GET.mockResolvedValue({ data: undefined, error: { error: { message: 'nope' } } });
  await render(['dcim.read']);
  expect(host.querySelector('[data-testid="substrate-error"]')?.textContent).toContain('nope');
});

it('empty', async () => {
  api.GET.mockResolvedValue({ data: { data: [], pagination: { total: 0 } } });
  await render(['dcim.read'], DeviceRolesPage);
  expect(host.textContent).toContain('No device roles yet');
});

it('default: built-in rows are tagged and never editable; a reader gets no controls', async () => {
  api.GET.mockResolvedValue({ data: { data: MFRS, pagination: { total: 2 } } });
  await render(['dcim.read']);
  expect(host.textContent).toContain('Cisco');
  expect(host.textContent).toContain('Built in');
  expect(btn(/Add manufacturer/)).toBeUndefined();
  expect(btn(/Edit Acme/)).toBeUndefined();
  act(() => root.unmount()); root = createRoot(host);
  await render(['dcim.read', 'dcim.manage']);
  expect(btn(/Edit Acme/)).toBeDefined();
  expect(btn(/Edit Cisco/)).toBeUndefined();
});

it('success: a manager adds a platform naming its manufacturer', async () => {
  api.GET.mockImplementation(async (path: string) => path === '/dcim/manufacturers'
    ? { data: { data: MFRS, pagination: { total: 2 } } }
    : { data: { data: [], pagination: { total: 0 } } });
  api.POST.mockResolvedValue({ data: { data: { id: 'p1', name: 'IOS-XE' } } });
  await render(['dcim.read', 'dcim.manage'], PlatformsPage);
  await act(async () => { btn(/Add platform/)!.click(); });
  const name = document.querySelector('input[aria-label="Name"]') as HTMLInputElement;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(name, 'IOS-XE');
    name.dispatchEvent(new Event('input', { bubbles: true }));
  });
  const sel = document.querySelector('select[aria-label="Manufacturer"]') as HTMLSelectElement;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')!.set!.call(sel, 'm1');
    sel.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await act(async () => { (document.querySelector('[data-testid="catalogue-save"]') as HTMLButtonElement).click(); });
  await vi.waitFor(() => expect(api.POST).toHaveBeenCalledTimes(1));
  expect(api.POST.mock.calls[0][0]).toBe('/dcim/platforms');
  expect((api.POST.mock.calls[0][1] as { body: unknown }).body).toMatchObject({ name: 'IOS-XE', manufacturer_id: 'm1' });
});
