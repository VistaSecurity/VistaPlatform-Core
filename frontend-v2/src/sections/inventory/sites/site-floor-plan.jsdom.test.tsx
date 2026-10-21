// @vitest-environment jsdom
// The site page's Floor plan tab (DCIM gap 9): its states (loading, error,
// empty, no plan, default), the colour toggle, a click opening the rack page,
// and the manager's writes — set up a plan, drag a rack, drag past the edge
// (refused before any write), arrow-key nudge, R to turn, Place from the tray
// and a server refusal shown as such. A reader gets no write at all.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter, Route, Routes } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';
import { SiteFloorPlan } from './site-floor-plan';
import { SitePage } from './site-page';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
type ApiCall = (path: string, opts?: unknown) => Promise<unknown>;
const api = vi.hoisted(() => ({ GET: vi.fn<ApiCall>(), PATCH: vi.fn<ApiCall>(), PUT: vi.fn<ApiCall>() }));
vi.mock('../../../lib/clients', () => ({ clients: { inventory: api } }));

const LOC = (id: string, name: string, plan: [number, number, 'm' | 'ft'] | null) => ({
  id, tenant_id: 't', site_id: 'ams', parent_id: null, name, slug: id, operational_status: 'active', facility: null, business_unit_id: null,
  source_kind: 'declared', custom_fields: {}, created_at: '', updated_at: '', path: name, asset_count: 0,
  floor_plan_width: plan?.[0] ?? null, floor_plan_depth: plan?.[1] ?? null, floor_plan_unit: plan?.[2] ?? null,
});
const RACK = (id: string, name: string, place: [number, number, number] | null, util: number | null, power: number | null, dflt = false) => ({
  id, name, operational_status: 'active', floor_x: place?.[0] ?? null, floor_y: place?.[1] ?? null, floor_rotation: place?.[2] ?? null,
  outer_width: dflt ? null : 600, outer_depth: dflt ? null : 1200, outer_unit: dflt ? null : 'mm',
  footprint_width: dflt ? 0.6 : 0.6, footprint_depth: dflt ? 1 : 1.2, footprint_default: dflt,
  utilization: util, used_units: util == null ? null : 10, total_units: util == null ? null : 42, power_utilization: power, device_count: 3,
});
const PLAN = (loc: ReturnType<typeof LOC>, racks: ReturnType<typeof RACK>[]) => ({
  location: { id: loc.id, site_id: 'ams', name: loc.name, path: loc.name, floor_plan_width: loc.floor_plan_width, floor_plan_depth: loc.floor_plan_depth, floor_plan_unit: loc.floor_plan_unit },
  default_footprint: { width: 600, depth: 1000, unit: 'mm' },
  racks,
});

const HALL = LOC('hall', 'Hall 2', [10, 8, 'm']);
const CAGE = LOC('cage', 'Cage 7', null);
// planScale(10 x 8) = 65 px per metre; the plan's corner sits at PAD = 28 px.
const px = (m: number) => 28 + m * 65;

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  api.GET.mockReset(); api.PATCH.mockReset(); api.PUT.mockReset();
  api.PATCH.mockResolvedValue({ data: { data: {} }, response: { ok: true, status: 200 } });
  api.PUT.mockResolvedValue({ data: {}, response: { ok: true, status: 200 } });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

function serve(locations: ReturnType<typeof LOC>[], plans: Record<string, ReturnType<typeof PLAN>>) {
  api.GET.mockImplementation(async (path: string, opts?: unknown) => {
    if (path === '/dcim/locations') return { data: { locations, total: locations.length } };
    if (path === '/dcim/locations/{id}/floor-plan') {
      const id = (opts as { params: { path: { id: string } } }).params.path.id;
      return plans[id] ? { data: plans[id] } : { error: { error: 'x' } };
    }
    return { data: {} };
  });
}

async function flush() { await act(async () => { await new Promise((r) => setTimeout(r, 0)); }); }

async function render(permissions: string[] = ['dcim.read', 'dcim.manage']) {
  cache.setQueryData(['user-permissions'], permissions);
  await act(async () => {
    root.render(<QueryClientProvider client={cache}><PermissionProvider><MemoryRouter initialEntries={['/inventory/sites/ams']}>
      <Routes>
        <Route path="/inventory/sites/:id" element={<SiteFloorPlan siteId="ams" />} />
        <Route path="/inventory/racks/:id" element={<div data-testid="rack-page-stub">rack page</div>} />
      </Routes>
    </MemoryRouter></PermissionProvider></QueryClientProvider>);
  });
  await flush(); await flush();
}

const q = (sel: string) => host.querySelector(sel);
const rackEl = (id: string) => q(`[data-testid="floor-plan-rack"][data-rack="${id}"]`) as SVGGElement;
async function fire(target: EventTarget, type: string, x: number, y: number) {
  await act(async () => { target.dispatchEvent(new MouseEvent(type, { bubbles: true, clientX: x, clientY: y, button: 0 })); });
}
async function key(target: Element, k: string, shift = false) {
  await act(async () => { target.dispatchEvent(new KeyboardEvent('keydown', { key: k, shiftKey: shift, bubbles: true })); });
}
const patchBody = (i = 0) => (api.PATCH.mock.calls[i][1] as { body: unknown }).body;

it('loading', async () => {
  api.GET.mockReturnValue(new Promise(() => {}));
  await render();
  expect(host.textContent).toContain('Loading locations');
});

it('error', async () => {
  api.GET.mockResolvedValue({ error: { error: 'x' } });
  await render();
  expect(q('[data-testid="substrate-error"]')!.textContent).toContain("Couldn't load the site's locations.");
});

it('empty: a site without locations says where a plan comes from', async () => {
  serve([], {});
  await render();
  expect(host.textContent).toContain('No locations yet');
  expect(q('[data-testid="floor-plan-canvas"]')).toBeNull();
});

it('the floor plan read failing is an error, not an empty plan', async () => {
  serve([HALL], {});
  await render();
  expect(host.textContent).toContain("Couldn't load the floor plan.");
});

it('default: the first location with a plan, racks drawn where they stand, coloured by utilisation, the tray below', async () => {
  serve([CAGE, HALL], { hall: PLAN(HALL, [RACK('r1', 'R1', [5, 4, 0], 90, 20), RACK('r2', 'R2', [2, 2, 90], null, null), RACK('r3', 'R3', null, 5, null, true)]) });
  await render();
  expect((q('[data-testid="floor-plan-location"]') as HTMLSelectElement).value).toBe('hall');
  expect(q('[data-testid="floor-plan-location"]')!.textContent).toContain('Cage 7 (no plan)');
  expect(q('[data-testid="floor-plan-canvas"]')!.getAttribute('aria-label')).toContain('10 × 8 m');
  const r1 = rackEl('r1');
  expect([r1.dataset.x, r1.dataset.y, r1.dataset.rotation, r1.dataset.colour]).toEqual(['5', '4', '0', 'value']);
  expect(r1.querySelector('rect')!.getAttribute('stroke')).toBe('var(--warn-strong)');
  expect(r1.querySelector('g')!.getAttribute('transform')).toBe(`translate(${px(5)} ${px(4)}) rotate(0)`);
  // Not recorded is drawn dashed and says so — never 0 %.
  const r2 = rackEl('r2');
  expect(r2.dataset.colour).toBe('unrecorded');
  expect(r2.getAttribute('aria-label')).toContain('Utilisation not recorded');
  expect(r2.querySelector('g')!.getAttribute('transform')).toContain('rotate(90)');
  // The unplaced rack is in the tray, flagged as drawn at the default footprint.
  const tray = q('[data-testid="floor-plan-tray"]')!;
  expect(tray.textContent).toContain('R3 *');
  expect(host.textContent).toContain('default 600 × 1000 mm');
  expect(rackEl('r3')).toBeNull();
});

it('the toggle colours by power instead', async () => {
  serve([HALL], { hall: PLAN(HALL, [RACK('r1', 'R1', [5, 4, 0], 10, 97)]) });
  await render();
  expect(rackEl('r1').querySelector('rect')!.getAttribute('stroke')).toBe('var(--accent)');
  const power = [...host.querySelectorAll('button')].find((b) => b.textContent === 'Power')!;
  await act(async () => { power.click(); });
  expect(power.getAttribute('aria-pressed')).toBe('true');
  expect(rackEl('r1').querySelector('rect')!.getAttribute('stroke')).toBe('var(--danger-text)');
  expect(rackEl('r1').getAttribute('aria-label')).toContain('97% of available power allocated');
});

it('a click on a rack opens its rack page', async () => {
  serve([HALL], { hall: PLAN(HALL, [RACK('r1', 'R1', [5, 4, 0], 10, null)]) });
  await render();
  await fire(rackEl('r1'), 'pointerdown', px(5), px(4));
  await fire(window, 'pointerup', px(5), px(4));
  await flush();
  expect(q('[data-testid="rack-page-stub"]')).not.toBeNull();
  expect(api.PATCH).not.toHaveBeenCalled();
});

it('success: dragging a rack writes its new place through the rack PATCH', async () => {
  serve([HALL], { hall: PLAN(HALL, [RACK('r1', 'R1', [5, 4, 0], 10, null)]) });
  await render();
  await fire(rackEl('r1'), 'pointerdown', px(5), px(4));
  await fire(window, 'pointermove', px(6), px(2.5));
  expect(q('[data-testid="floor-plan-ghost"]')!.getAttribute('data-fits')).toBe('true');
  await fire(window, 'pointerup', px(6), px(2.5));
  await flush();
  expect(api.PATCH).toHaveBeenCalledTimes(1);
  expect(api.PATCH.mock.calls[0][0]).toBe('/dcim/racks/{id}');
  expect(api.PATCH.mock.calls[0][1]).toMatchObject({ params: { path: { id: 'r1' } } });
  expect(patchBody()).toEqual({ floor_x: 6, floor_y: 2.5, floor_rotation: 0 });
  expect(q('[data-testid="floor-plan-message"]')!.textContent).toContain('R1 placed at 6, 2.5 m');
});

it('a drag past the edge shows red and writes nothing', async () => {
  serve([HALL], { hall: PLAN(HALL, [RACK('r1', 'R1', [5, 4, 0], 10, null)]) });
  await render();
  await fire(rackEl('r1'), 'pointerdown', px(5), px(4));
  await fire(window, 'pointermove', px(9.9), px(4));
  const ghost = q('[data-testid="floor-plan-ghost"]')!;
  expect(ghost.getAttribute('data-fits')).toBe('false');
  expect(ghost.textContent).toContain('Outside the plan');
  await fire(window, 'pointerup', px(9.9), px(4));
  await flush();
  expect(api.PATCH).not.toHaveBeenCalled();
  expect(q('[data-testid="floor-plan-message"]')!.textContent).toContain('would run past the edge');
});

it('arrow keys nudge the focused rack and R turns it', async () => {
  serve([HALL], { hall: PLAN(HALL, [RACK('r1', 'R1', [5, 4, 0], 10, null)]) });
  await render();
  await key(rackEl('r1'), 'ArrowRight');
  await flush();
  expect(patchBody(0)).toEqual({ floor_x: 5.1, floor_y: 4, floor_rotation: 0 });
  await key(rackEl('r1'), 'ArrowUp', true);
  await flush();
  expect(patchBody(1)).toEqual({ floor_x: 5, floor_y: 3, floor_rotation: 0 });
  await key(rackEl('r1'), 'r');
  await flush();
  expect(patchBody(2)).toEqual({ floor_x: 5, floor_y: 4, floor_rotation: 90 });
});

it('Place puts a tray rack at the middle of the plan; Take off sends nulls', async () => {
  serve([HALL], { hall: PLAN(HALL, [RACK('r1', 'R1', [5, 4, 0], 10, null), RACK('r3', 'R3', null, 5, null, true)]) });
  await render();
  const place = [...q('[data-testid="floor-plan-tray"]')!.querySelectorAll('button')].find((b) => b.textContent === 'Place')!;
  await act(async () => { place.click(); });
  await flush();
  expect(api.PATCH.mock.calls[0][1]).toMatchObject({ params: { path: { id: 'r3' } }, body: { floor_x: 5, floor_y: 4, floor_rotation: 0 } });
  const off = host.querySelector('button[aria-label="Take R1 off the plan"]') as HTMLButtonElement;
  await act(async () => { off.click(); });
  await flush();
  expect(patchBody(1)).toEqual({ floor_x: null, floor_y: null, floor_rotation: null });
});

it('dragging a tray rack onto the plan places it where it is dropped', async () => {
  serve([HALL], { hall: PLAN(HALL, [RACK('r3', 'R3', null, 5, null, true)]) });
  await render();
  const handle = q('[data-testid="floor-plan-unplaced"] span')!;
  await fire(handle, 'pointerdown', 900, 900);
  await fire(window, 'pointermove', px(2), px(3));
  await fire(window, 'pointerup', px(2), px(3));
  await flush();
  expect(api.PATCH.mock.calls[0][1]).toMatchObject({ params: { path: { id: 'r3' } }, body: { floor_x: 2, floor_y: 3, floor_rotation: 0 } });
});

it('a refusal from the server is shown as its message', async () => {
  serve([HALL], { hall: PLAN(HALL, [RACK('r1', 'R1', [5, 4, 0], 10, null)]) });
  api.PATCH.mockResolvedValue({ error: { error: { code: 'invalid', message: 'the rack does not fit the floor plan of Hall 2' } }, response: { ok: false, status: 400 } });
  await render();
  await key(rackEl('r1'), 'ArrowLeft');
  await flush();
  expect(q('[data-testid="floor-plan-message"]')!.textContent).toContain('does not fit the floor plan of Hall 2');
  expect(rackEl('r1').dataset.x).toBe('5');
});

it('a location without a plan: a manager sets one up', async () => {
  serve([CAGE], { cage: PLAN(CAGE, [RACK('r9', 'R9', null, null, null)]) });
  await render();
  expect(host.textContent).toContain('Cage 7 has no floor plan yet · 1 rack in it');
  const form = q('[data-testid="floor-plan-size-form"]') as HTMLFormElement;
  expect(form.textContent).toContain('Set up a plan');
  const set = (label: string, v: string) => {
    const el = form.querySelector(`[aria-label="${label}"]`) as HTMLInputElement | HTMLSelectElement;
    const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, 'value')!.set!.call(el, v);
    el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? 'change' : 'input', { bubbles: true }));
  };
  await act(async () => { set('Plan width', '12.5'); set('Plan depth', '9'); set('Plan unit', 'ft'); });
  await act(async () => { form.querySelector('button[type="submit"]')!.dispatchEvent(new MouseEvent('click', { bubbles: true })); });
  await flush();
  expect(api.PUT).toHaveBeenCalledTimes(1);
  expect(api.PUT.mock.calls[0][0]).toBe('/dcim/locations/{id}');
  expect(api.PUT.mock.calls[0][1]).toMatchObject({ params: { path: { id: 'cage' } }, body: { floor_plan_width: 12.5, floor_plan_depth: 9, floor_plan_unit: 'ft' } });
});

it('a reader sees no plan form, and a drag writes nothing', async () => {
  serve([CAGE, HALL], { cage: PLAN(CAGE, []), hall: PLAN(HALL, [RACK('r1', 'R1', [5, 4, 0], 10, null), RACK('r3', 'R3', null, 5, null)]) });
  await render(['dcim.read']);
  expect(q('button[aria-label="Take R1 off the plan"]')).toBeNull();
  expect([...host.querySelectorAll('button')].some((b) => b.textContent === 'Place')).toBe(false);
  await fire(rackEl('r1'), 'pointerdown', px(5), px(4));
  await fire(window, 'pointermove', px(7), px(4));
  expect(q('[data-testid="floor-plan-ghost"]')).toBeNull();
  await fire(window, 'pointerup', px(7), px(4));
  await key(rackEl('r1') ?? host, 'ArrowRight');
  await flush();
  expect(api.PATCH).not.toHaveBeenCalled();
});

it('a reader on a location without a plan is told so, without a form', async () => {
  serve([CAGE], { cage: PLAN(CAGE, []) });
  await render(['dcim.read']);
  expect(host.textContent).toContain('Cage 7 has no floor plan yet.');
  expect(q('[data-testid="floor-plan-size-form"]')).toBeNull();
});

it('is reachable: the site page has a Floor plan tab that mounts it', async () => {
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/dcim/sites/{id}') {
      return { data: { id: 'ams', name: 'AMS-1', operational_status: 'active', asns: [], asset_count: 0, counts: { assets: 0, locations: 1, racks: 0, prefixes: 0, vlans: 0 } }, response: { status: 200 } };
    }
    if (path === '/dcim/locations') return { data: { locations: [HALL], total: 1 } };
    if (path === '/dcim/locations/{id}/floor-plan') return { data: PLAN(HALL, []) };
    return { data: { changes: [], journal_entries: [], entries: [], environments: [], total: 0, data: [] } };
  });
  cache.setQueryData(['user-permissions'], ['dcim.read']);
  await act(async () => {
    root.render(<QueryClientProvider client={cache}><PermissionProvider><MemoryRouter initialEntries={['/inventory/sites/ams']}>
      <Routes><Route path="/inventory/sites/:id" element={<SitePage />} /></Routes>
    </MemoryRouter></PermissionProvider></QueryClientProvider>);
  });
  await flush();
  const tab = [...host.querySelectorAll('[role="tab"]')].find((b) => b.textContent === 'Floor plan') as HTMLButtonElement;
  expect(tab).toBeTruthy();
  await act(async () => { tab.click(); });
  await flush(); await flush();
  expect(q('[data-testid="floor-plan-canvas"]')).not.toBeNull();
});
