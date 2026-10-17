// @vitest-environment jsdom
// The asset form's Site and Location selects (DCIM row 2.1): the location list
// is the chosen site's only, choosing another site clears the location, and
// what each choice sends.
import { act, useState } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { SiteLocationSelect, placementFields, type Placement } from './site-location-select';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn() }));
vi.mock('../../../lib/clients', () => ({ clients: { inventory: api } }));

const site = (id: string, name: string) => ({ id, name });
const loc = (id: string, site_id: string, name: string) => ({ id, site_id, name, parent_id: null });

let host: HTMLDivElement; let root: Root; let cache: QueryClient; let latest: Placement = { siteId: '', locationId: '' };
function Harness() {
  const [v, setV] = useState<Placement>({ siteId: '', locationId: '' });
  const onChange = (next: Placement) => { latest = next; setV(next); };
  return <SiteLocationSelect value={v} onChange={onChange} />;
}
beforeEach(() => {
  api.GET.mockReset().mockImplementation(async (path: string, opts?: { params?: { query?: { site_id?: string } } }) => {
    if (path === '/dcim/sites') return { data: { sites: [site('ams', 'AMS-1'), site('nyc', 'NYC-1')], total: 2 } };
    const id = opts?.params?.query?.site_id;
    const all = [loc('h2', 'ams', 'Hall 2'), loc('c1', 'nyc', 'Cage 1')];
    return { data: { locations: all.filter((l) => !id || l.site_id === id), total: 1 } };
  });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function mount() {
  await act(async () => { root.render(<QueryClientProvider client={cache}><Harness /></QueryClientProvider>); });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
}
const sel = (label: string) => host.querySelector(`select[aria-label="${label}"]`) as HTMLSelectElement;
const choose = (label: string, v: string) => act(async () => {
  Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')!.set!.call(sel(label), v);
  sel(label).dispatchEvent(new Event('change', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 0));
});
const options = (label: string) => [...sel(label).options].map((o) => o.textContent);

it('the location select is disabled until a site is chosen', async () => {
  await mount();
  expect(options('Site')).toEqual(['None', 'AMS-1', 'NYC-1']);
  expect(sel('Location').disabled).toBe(true);
});

it('lists only the chosen site\'s locations, and a new site clears the location', async () => {
  await mount();
  await choose('Site', 'ams');
  await vi.waitFor(() => expect(options('Location')).toEqual(['None', 'Hall 2']));
  expect(api.GET).toHaveBeenCalledWith('/dcim/locations', { params: { query: { site_id: 'ams' } } });
  await choose('Location', 'h2');
  expect(latest).toEqual({ siteId: 'ams', locationId: 'h2' });
  await choose('Site', 'nyc');
  expect(latest).toEqual({ siteId: 'nyc', locationId: '' });
  await vi.waitFor(() => expect(options('Location')).toEqual(['None', 'Cage 1']));
});

it('sends ids; an edit choosing none clears, a create omits', () => {
  expect(placementFields({ siteId: 'ams', locationId: 'h2' }, true)).toEqual({ site_id: 'ams', location_id: 'h2' });
  expect(placementFields({ siteId: 'ams', locationId: '' }, true)).toEqual({ site_id: 'ams', location_id: '' });
  expect(placementFields({ siteId: '', locationId: '' }, true)).toEqual({ site_id: '' });
  expect(placementFields({ siteId: '', locationId: '' }, false)).toEqual({});
});
