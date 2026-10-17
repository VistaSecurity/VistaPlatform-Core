// @vitest-environment jsdom
// The asset page's Placement card (DCIM row 2.3): the five states, the write
// controls behind dcim.manage, placing an asset with the cascading selects,
// the half-U stepper and the face toggle, and a refusal that names (and links
// to) the asset in the way.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { PlacementCard } from './placement-card';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() }));
vi.mock('../../../lib/clients', () => ({ clients: { inventory: api } }));

const ASSET = 'a1';
const unplaced = { asset_id: ASSET, site: null, location: null, rack: null, position: null, face: null, u_height: 2, is_full_depth: true, has_device_type: true, is_child: false };
const placed = { ...unplaced, site: { id: 'ams', name: 'AMS-1' }, location: { id: 'row3', name: 'Row 3', path: 'AMS-1 / Row 3' }, rack: { id: 'r12', name: 'R12' }, position: 40, face: 'front' };
const rack = (id: string, name: string, location_id: string | null) => ({ id, name, site_id: 'ams', location_id, u_height: 42, starting_unit: 1 });
const DATA: Record<string, unknown> = {
  '/dcim/sites': { sites: [{ id: 'ams', name: 'AMS-1' }, { id: 'nyc', name: 'NYC-1' }], total: 2 },
  '/dcim/locations': { locations: [{ id: 'row3', site_id: 'ams', parent_id: null, name: 'Row 3' }], total: 1 },
  '/dcim/racks': { data: [rack('r12', 'R12', 'row3'), rack('r13', 'R13', null)], pagination: {} },
};
const serve = (placement: unknown) => api.GET.mockImplementation(async (path: string) => {
  if (path === '/dcim/assets/{id}/placement') return { data: { data: placement } };
  return path in DATA ? { data: DATA[path] } : { data: {} };
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
  await act(async () => {
    root.render(<MemoryRouter><QueryClientProvider client={cache}><PermissionProvider><PlacementCard assetId={ASSET} /></PermissionProvider></QueryClientProvider></MemoryRouter>);
  });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
}
const btn = (re: RegExp) => [...document.querySelectorAll('button')].find((b) => re.test(b.textContent ?? '') || re.test(b.getAttribute('aria-label') ?? ''));
const set = (el: Element, v: string) => act(async () => {
  Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')!.set!.call(el, v);
  el.dispatchEvent(new Event('change', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 0));
});

it('loading', async () => {
  api.GET.mockReturnValue(new Promise(() => {}));
  await render(['dcim.read']);
  expect(host.querySelector('[data-testid="placement-loading"]')).not.toBeNull();
});

it('error', async () => {
  api.GET.mockResolvedValue({ data: undefined, error: { error: { code: 'x' } } });
  await render(['dcim.read']);
  expect(host.querySelector('[data-testid="placement-error"]')).not.toBeNull();
});

it('empty: not in a rack, and a manager may place it', async () => {
  serve(unplaced);
  await render(['dcim.read', 'dcim.manage']);
  expect(host.querySelector('[data-testid="placement-empty"]')?.textContent).toContain('Not in a rack');
  expect(btn(/Place in a rack/)).toBeDefined();
});

it('default: Site › Location › Rack › U · Face, and no write controls for a reader', async () => {
  serve(placed);
  await render(['dcim.read']);
  expect(host.querySelector('[data-testid="placement-placed"]')?.textContent).toContain('AMS-1 › Row 3 › R12 › U40 · Front');
  expect(btn(/Edit placement/)).toBeUndefined();
  expect(btn(/Remove from rack/)).toBeUndefined();
});

it('placed: "Open rack" opens the rack page with this device highlighted (row 2.5)', async () => {
  serve(placed);
  await render(['dcim.read']);
  expect(host.querySelector('[data-testid="placement-open-rack"]')?.getAttribute('href')).toBe('/inventory/racks/r12?asset=a1');
});

it('unplaced: no "Open rack" link', async () => {
  serve(unplaced);
  await render(['dcim.read']);
  expect(host.querySelector('[data-testid="placement-open-rack"]')).toBeNull();
});

it('without dcim.read the card says why instead of calling the API', async () => {
  serve(placed);
  await render([]);
  expect(host.textContent).toContain('needs the data-centre read permission');
  expect(api.GET).not.toHaveBeenCalled();
});

it('success: a manager places the asset — site, location, rack, half-U position, rear face', async () => {
  serve(unplaced);
  api.PUT.mockResolvedValue({ data: { data: placed }, response: { ok: true, status: 200 } });
  await render(['dcim.read', 'dcim.manage']);
  await act(async () => { btn(/Place in a rack/)!.click(); });
  await vi.waitFor(() => expect(document.querySelector('select[aria-label="Site"] option[value="ams"]')).not.toBeNull());
  await set(document.querySelector('select[aria-label="Site"]')!, 'ams');
  await vi.waitFor(() => expect(document.querySelector('select[aria-label="Location"] option[value="row3"]')).not.toBeNull());
  await set(document.querySelector('select[aria-label="Location"]')!, 'row3');
  // The location narrows the racks: R13 (no location) is not offered.
  const rackOptions = () => [...document.querySelectorAll('select[aria-label="Rack"] option')].map((o) => o.textContent);
  await vi.waitFor(() => expect(rackOptions()).toEqual(['Choose a rack…', 'R12 (42U)']));
  await set(document.querySelector('select[aria-label="Rack"]')!, 'r12');
  expect(btn(/Lower position/)!.disabled).toBe(true); // already at U1
  for (let i = 0; i < 3; i++) await act(async () => { btn(/Raise position/)!.click(); });
  expect(document.querySelector('[data-testid="placement-position"]')!.textContent).toBe('U2.5');
  await act(async () => { btn(/^Rear$/)!.click(); });
  await act(async () => { btn(/Save placement/)!.click(); });
  await vi.waitFor(() => expect(api.PUT).toHaveBeenCalledTimes(1));
  expect(api.PUT.mock.calls[0][0]).toBe('/dcim/assets/{id}/placement');
  expect(api.PUT.mock.calls[0][1]).toMatchObject({ params: { path: { id: ASSET } }, body: { rack_id: 'r12', position: 2.5, face: 'rear' } });
});

it('conflict: a refused placement names the blocking asset and links to it', async () => {
  serve(placed);
  api.PUT.mockResolvedValue({ error: { error: { code: 'placement_conflict', message: 'occupied', blocking_asset: { id: 'sw9', name: 'core-sw-9', position: 40, face: 'front', u_height: 1 } } }, response: { ok: false, status: 409 } });
  await render(['dcim.read', 'dcim.manage']);
  await act(async () => { btn(/Edit placement/)!.click(); });
  await vi.waitFor(() => expect((document.querySelector('select[aria-label="Rack"]') as HTMLSelectElement).value).toBe('r12'));
  await act(async () => { btn(/Save placement/)!.click(); });
  await vi.waitFor(() => expect(document.querySelector('[data-testid="placement-conflict"]')).not.toBeNull());
  const link = document.querySelector('[data-testid="placement-conflict-asset"]') as HTMLAnchorElement;
  expect(link.textContent).toBe('core-sw-9');
  expect(link.getAttribute('href')).toBe('/inventory/assets/sw9');
  expect(document.querySelector('[data-testid="placement-conflict"]')!.textContent).toContain('U40, front, 1U');
});

it('a manager removes the asset from its rack', async () => {
  serve(placed);
  api.DELETE.mockResolvedValue({ data: { data: unplaced }, response: { ok: true, status: 200 } });
  await render(['dcim.read', 'dcim.manage']);
  await act(async () => { btn(/Remove from rack/)!.click(); });
  await vi.waitFor(() => expect(api.DELETE).toHaveBeenCalledWith('/dcim/assets/{id}/placement', { params: { path: { id: ASSET } } }));
});
