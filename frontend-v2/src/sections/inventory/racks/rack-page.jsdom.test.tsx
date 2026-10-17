// @vitest-environment jsdom
// The rack page (DCIM row 2.5): its five states; the drawn front and rear
// elevation (full depth on both faces, reservations hatched); the crypto
// overlay's colours from the ratings bands, its lock and certificate badge;
// drag-to-place sending PUT placement with the new position and face, and a
// 409 snapping the block back with the reason; click-through to the asset's
// findings; Add device; the ?asset= highlight; the SVG export; and that the
// page is reachable (route registered, lens has a nav home).
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter, Route, Routes } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { LEVEL_COLOR } from '../../../components/ui/risk';
import { INVENTORY_LENSES } from '../lenses';
import { SECTIONS } from '../../../app/nav';
import { RackPage } from './rack-page';
import { UNIT_PX, spanY } from './rack-geometry';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
type ApiCall = (path: string, opts?: { params?: { path?: Record<string, string>; query?: Record<string, unknown> }; body?: unknown }) => Promise<unknown>;
const api = vi.hoisted(() => ({ GET: vi.fn<ApiCall>(), POST: vi.fn<ApiCall>(), PUT: vi.fn<ApiCall>(), PATCH: vi.fn<ApiCall>(), DELETE: vi.fn<ApiCall>() }));
vi.mock('../../../lib/clients', () => ({ clients: { inventory: api } }));

const RACK = {
  id: 'r12', tenant_id: 't', name: 'R12', facility_id: null, site_id: 'ams', location_id: 'row3', business_unit_id: null, role_id: 'net',
  rack_type_id: null, operational_status: 'active', serial: null, asset_tag: null, form_factor: null, width: 19, u_height: 42, starting_unit: 1,
  desc_units: false, outer_width: null, outer_depth: null, outer_unit: null, mounting_depth: null, weight: null, max_weight: null, weight_unit: null,
  airflow: null, external_ids: {}, description: null, comments: null, source_kind: 'declared', source_ref: null, custom_fields: {},
  created_at: '', updated_at: '', created_by: null,
  site: { id: 'ams', name: 'AMS-1', slug: 'ams-1' }, location: { id: 'row3', name: 'Row 3', path: 'AMS-1 / Row 3' }, role: { id: 'net', name: 'Network', slug: 'network' },
};
const soon = new Date(Date.now() + 12 * 86_400_000 + 3_600_000).toISOString();
const SW = {
  asset_id: 'sw', name: 'core-sw-1', class_key: 'switch', position: 40, face: 'front', u_height: 1, is_full_depth: true, child_count: 0, serial: 'FOC1234',
  device_type: { id: 'dt', model: 'C9300-48P', slug: 'c9300-48p', front_image_ref: null, rear_image_ref: null },
  posture: { assessed: true, open_findings: 2, weak_protocol: true, cert_expires_at: soon, top_finding: { id: 'f1', producer: 'crypto', kind: 'weak_configuration', severity: 'high', score: 80, summary: 'TLS 1.0 negotiated on 443' } },
};
const SRV = {
  asset_id: 'srv', name: 'db-1', class_key: 'server', position: 30, face: 'rear', u_height: 2, is_full_depth: false, child_count: 0, serial: null,
  device_type: null, posture: { assessed: false, open_findings: 0, weak_protocol: false, cert_expires_at: null, top_finding: null },
};
const RES = { id: 'res1', units: [39], description: 'Future PDU', user_id: null };
const elevation = (over: Record<string, unknown> = {}) => ({
  rack: RACK, devices: [SW, SRV], units: [], reservations: [RES], non_racked: 0,
  utilization: { used_units: 3, total_units: 42, utilization: 7.1, refreshed_at: '' }, ...over,
});

function serve(el: unknown, extra: Record<string, unknown> = {}) {
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/dcim/racks/{id}/elevation') return { data: { data: el }, response: { status: 200 } };
    if (path in extra) return { data: extra[path], response: { status: 200 } };
    return { data: { data: [], changes: [], journal_entries: [], entries: [], total: 0, pagination: {} }, response: { status: 200 } };
  });
}

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

const flush = () => act(async () => { await new Promise((r) => setTimeout(r, 0)); });
async function render(perms: string[] = ['dcim.read', 'dcim.manage'], url = '/inventory/racks/r12') {
  cache.setQueryData(['user-permissions'], perms);
  await act(async () => {
    root.render(<QueryClientProvider client={cache}><PermissionProvider><MemoryRouter initialEntries={[url]}>
      <Routes>
        <Route path="/inventory/racks/:id" element={<RackPage />} />
        <Route path="/inventory/assets/:id/:tab?" element={<div data-testid="asset-page-stub" />} />
      </Routes>
    </MemoryRouter></PermissionProvider></QueryClientProvider>);
  });
  await flush(); await flush();
}
const blocks = (asset: string) => [...host.querySelectorAll(`[data-testid="rack-block"][data-asset="${asset}"]`)];
const block = (asset: string, face: string) => host.querySelector(`[data-testid="rack-block"][data-asset="${asset}"][data-face="${face}"]`)!;
const fire = (target: EventTarget, type: string, x: number, y: number) => act(async () => {
  target.dispatchEvent(new MouseEvent(type, { bubbles: true, clientX: x, clientY: y, button: 0 }));
});
const FRONT_X = 100; // inside the front face's grid (jsdom has no layout: 1 client px = 1 drawing px)

describe('states', () => {
  it('loading', async () => {
    api.GET.mockReturnValue(new Promise(() => {}));
    await render();
    expect(host.textContent).toContain('Loading rack');
  });
  it('error', async () => {
    api.GET.mockResolvedValue({ data: undefined, error: { error: 'x' }, response: { status: 500 } });
    await render();
    expect(host.textContent).toContain('Failed to load the rack');
  });
  it('not found is its own state', async () => {
    api.GET.mockResolvedValue({ data: undefined, error: { error: 'x' }, response: { status: 404 } });
    await render();
    expect(host.textContent).toContain('Rack not found');
  });
  it('empty: an empty rack still draws its grid and says how to fill it', async () => {
    serve(elevation({ devices: [], reservations: [], utilization: { used_units: 0, total_units: 42, utilization: 0, refreshed_at: '' } }));
    await render();
    expect(host.querySelector('[data-testid="rack-empty"]')?.textContent).toContain('No devices in this rack yet');
    expect(host.querySelectorAll('[data-testid="rack-unit-label"]')).toHaveLength(42);
    // A real 0 %, not a blank.
    expect(host.querySelector('[data-testid="rack-utilisation"]')?.textContent).toContain('0 / 42U · 0%');
  });
  it('default: header, both faces, reservations, the devices table', async () => {
    serve(elevation());
    await render();
    expect(host.querySelector('[data-testid="rack-page"]')).not.toBeNull();
    expect(host.querySelector('h1')?.textContent).toContain('R12');
    expect(host.querySelector('[data-testid="rack-breadcrumb"]')?.textContent).toContain('AMS-1 › Row 3');
    expect(host.textContent).toContain('Network');
    // Full depth: on both faces, mirrored on the rear.
    expect(blocks('sw').map((b) => [b.getAttribute('data-face'), b.getAttribute('data-mirrored')])).toEqual([['front', 'false'], ['rear', 'true']]);
    // Half depth: its own face only.
    expect(blocks('srv').map((b) => b.getAttribute('data-face'))).toEqual(['rear']);
    expect(Number(block('srv', 'rear').getAttribute('data-y'))).toBe(spanY(RACK, 30, 2).y);
    expect(Number(block('srv', 'rear').getAttribute('data-h'))).toBe(2 * UNIT_PX);
    // The reservation is hatched on both faces with its description.
    const res = [...host.querySelectorAll('[data-testid="rack-reservation"]')];
    expect(res.map((r) => r.getAttribute('data-face'))).toEqual(['front', 'rear']);
    expect(res[0].getAttribute('data-from')).toBe('39');
    expect(res[0].querySelector('rect')?.getAttribute('fill')).toMatch(/^url\(#rack-hatch-/);
    expect(res[0].textContent).toContain('Future PDU');
    const rows = [...host.querySelectorAll('[data-testid="rack-device-row"]')];
    expect(rows.map((r) => r.textContent)).toEqual([expect.stringContaining('core-sw-1'), expect.stringContaining('db-1')]);
    expect(rows[0].textContent).toContain('FOC1234');
    expect(rows[0].textContent).toContain('C9300-48P');
    expect(host.querySelector('[data-testid="reservation-row"]')?.textContent).toContain('Future PDU');
    expect(host.querySelector('[data-testid="rack-contacts"]')).not.toBeNull();
    expect(host.querySelector('[data-testid="rack-images"]')).not.toBeNull();
  });
});

describe('crypto overlay', () => {
  it('tints by the worst open finding through the ratings bands, with lock and certificate badges', async () => {
    serve(elevation());
    await render();
    expect(block('sw', 'front').getAttribute('data-overlay-color')).toBe(LEVEL_COLOR.High);
    expect(block('sw', 'front').querySelector('[data-testid="rack-overlay-tint"]')?.getAttribute('fill')).toBe(LEVEL_COLOR.High);
    expect(block('sw', 'front').querySelector('[data-testid="rack-weak-protocol"]')).not.toBeNull();
    expect(block('sw', 'front').querySelector('[data-testid="rack-cert-badge"]')?.textContent).toContain('12d');
    expect(block('sw', 'front').querySelector('title')?.textContent).toContain('Top finding: TLS 1.0 negotiated on 443');
    // Never assessed is not clean.
    expect(block('srv', 'rear').getAttribute('data-overlay-kind')).toBe('unassessed');
    expect(host.querySelector('[data-testid="overlay-legend"]')).not.toBeNull();
  });
  it('the header toggle turns it off', async () => {
    serve(elevation());
    await render();
    const toggle = host.querySelector('[data-testid="overlay-toggle"] input') as HTMLInputElement;
    await act(async () => { toggle.click(); });
    expect(block('sw', 'front').getAttribute('data-overlay-color')).toBe('');
    expect(block('sw', 'front').querySelector('[data-testid="rack-weak-protocol"]')).toBeNull();
    expect(host.querySelector('[data-testid="overlay-legend"]')).toBeNull();
  });
  it('asks the elevation for posture', async () => {
    serve(elevation());
    await render();
    const call = api.GET.mock.calls.find((c) => c[0] === '/dcim/racks/{id}/elevation')!;
    expect(call[1]?.params).toEqual({ path: { id: 'r12' }, query: { include: 'posture' } });
  });
});

describe('drag to place', () => {
  it('dragging a block two units down sends PUT placement with the new position and face', async () => {
    serve(elevation());
    api.PUT.mockResolvedValue({ data: { data: {} }, response: { ok: true, status: 200 } });
    await render();
    await fire(block('sw', 'front'), 'pointerdown', FRONT_X, 50);
    await fire(window, 'pointermove', FRONT_X, 50 + 2 * UNIT_PX);
    expect(host.querySelector('[data-testid="rack-drag-ghost"]')?.getAttribute('data-position')).toBe('38');
    await fire(window, 'pointerup', FRONT_X, 50 + 2 * UNIT_PX);
    await flush();
    expect(api.PUT).toHaveBeenCalledTimes(1);
    const [path, opts] = api.PUT.mock.calls[0];
    expect(path).toBe('/dcim/assets/{id}/placement');
    expect(opts?.params).toEqual({ path: { id: 'sw' } });
    expect(opts?.body).toEqual({ rack_id: 'r12', position: 38, face: 'front' });
  });
  it('dragging across to the rear face changes the face', async () => {
    serve(elevation());
    api.PUT.mockResolvedValue({ data: { data: {} }, response: { ok: true, status: 200 } });
    await render();
    await fire(block('srv', 'rear'), 'pointerdown', 400, 300);
    await fire(window, 'pointermove', FRONT_X, 300);
    await fire(window, 'pointerup', FRONT_X, 300);
    await flush();
    expect(api.PUT.mock.calls[0][1]?.body).toEqual({ rack_id: 'r12', position: 30, face: 'front' });
  });
  it('a 409 snaps the block back and names what holds the units', async () => {
    serve(elevation());
    api.PUT.mockResolvedValue({ data: undefined, error: { error: { code: 'placement_conflict', message: 'U39 is reserved', blocking_reservation: { id: 'res1', description: 'Future PDU', units: [39] } } }, response: { ok: false, status: 409 } });
    await render();
    const origY = block('sw', 'front').getAttribute('data-y');
    await fire(block('sw', 'front'), 'pointerdown', FRONT_X, 50);
    await fire(window, 'pointermove', FRONT_X, 50 + UNIT_PX);
    await fire(window, 'pointerup', FRONT_X, 50 + UNIT_PX);
    await flush(); await flush();
    expect(api.PUT.mock.calls[0][1]?.body).toEqual({ rack_id: 'r12', position: 39, face: 'front' });
    expect(host.querySelector('[data-testid="move-refused"]')?.textContent).toContain('reserved: Future PDU');
    expect(block('sw', 'front').getAttribute('data-y')).toBe(origY);
  });
  it('a click (no movement) opens the asset — its findings when the overlay shows some', async () => {
    serve(elevation());
    await render();
    await fire(block('sw', 'front'), 'pointerdown', FRONT_X, 50);
    await fire(window, 'pointerup', FRONT_X, 50);
    await flush();
    expect(api.PUT).not.toHaveBeenCalled();
    expect(host.querySelector('[data-testid="asset-page-stub"]')).not.toBeNull();
  });
  it('a reader cannot move devices: no PUT, no Add device, no empty-unit targets', async () => {
    serve(elevation());
    await render(['dcim.read']);
    expect(host.querySelector('[data-testid="add-device"]')).toBeNull();
    expect(host.querySelector('[data-testid="rack-empty-unit"]')).toBeNull();
    expect(host.querySelector('[data-testid="unrack"]')).toBeNull();
    await fire(block('sw', 'front'), 'pointerdown', FRONT_X, 50);
    await fire(window, 'pointermove', FRONT_X, 50 + 2 * UNIT_PX);
    await fire(window, 'pointerup', FRONT_X, 50 + 2 * UNIT_PX);
    await flush();
    expect(api.PUT).not.toHaveBeenCalled();
  });
});

describe('manage', () => {
  it('Add device: picks an unracked asset of the site and places it', async () => {
    serve(elevation(), {
      '/infrastructure-assets': { assets: [{ id: 'fw', hostname: 'edge-fw-1', display_name: 'edge-fw-1', class_key: 'firewall', rack: null }], pagination: { total: 1, page: 1, page_size: 50 } },
    });
    api.PUT.mockResolvedValue({ data: { data: {} }, response: { ok: true, status: 200 } });
    await render();
    // An empty unit opens the picker at that unit.
    const empty = host.querySelector('[data-testid="rack-empty-unit"][data-unit="20"][data-face="rear"]')!;
    await act(async () => { empty.dispatchEvent(new MouseEvent('click', { bubbles: true })); });
    await flush();
    const q = api.GET.mock.calls.find((c) => c[0] === '/infrastructure-assets')!;
    expect(q[1]?.params?.query?.query).toBe('site.id = "ams" and not exists(rack.id)');
    await act(async () => { (document.querySelector('[data-testid="add-device-option"]') as HTMLButtonElement).click(); });
    await act(async () => { (document.querySelector('[data-testid="add-device-save"]') as HTMLButtonElement).click(); });
    await flush();
    expect(api.PUT.mock.calls[0][1]).toEqual({ params: { path: { id: 'fw' } }, body: { rack_id: 'r12', position: 20, face: 'rear' } });
  });
  it('Unrack takes the device out of the rack', async () => {
    serve(elevation());
    api.DELETE.mockResolvedValue({ data: { data: {} }, response: { ok: true, status: 200 } });
    await render();
    await act(async () => { (host.querySelector('[data-testid="unrack"]') as HTMLButtonElement).click(); });
    await flush();
    expect(api.DELETE).toHaveBeenCalledWith('/dcim/assets/{id}/placement', { params: { path: { id: 'sw' } } });
  });
  it('?asset= highlights the device', async () => {
    serve(elevation());
    await render(undefined, '/inventory/racks/r12?asset=srv');
    expect(block('srv', 'rear').querySelector('[data-testid="rack-block-highlight"]')).not.toBeNull();
    expect(block('sw', 'front').querySelector('[data-testid="rack-block-highlight"]')).toBeNull();
  });
});

describe('export', () => {
  it('downloads a standalone SVG with no unresolved CSS variables', async () => {
    serve(elevation());
    await render();
    const blobs: Blob[] = [];
    const create = vi.fn((b: Blob) => { blobs.push(b); return 'blob:x'; });
    Object.assign(URL, { createObjectURL: create, revokeObjectURL: vi.fn() });
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    await act(async () => { (host.querySelector('[data-testid="export-svg"]') as HTMLButtonElement).click(); });
    expect(click).toHaveBeenCalled();
    const text = await blobs[0].text();
    expect(text).toContain('<svg');
    expect(text).toContain('core-sw-1');
    expect(text).not.toContain('var(');
    expect(text).not.toContain('rack-empty-unit');
    click.mockRestore();
  });
});

describe('reachability', () => {
  it('the route is registered and the Racks lens is in the Assets group', () => {
    const app = readFileSync(resolve(__dirname, '../../../App.tsx'), 'utf8');
    expect(app).toMatch(/<Route path="\/inventory\/racks\/:id" element={<RackPage \/>} \/>/);
    const lens = INVENTORY_LENSES.find((l) => l.key === 'racks');
    expect(lens).toMatchObject({ label: 'Racks', icon: 'server', group: 'assets', live: true });
    const inventory = SECTIONS.find((s) => s.id === 'inventory')!;
    expect(inventory.groups!.flatMap((g) => g.items).some((i) => i.lens === 'racks' && i.path === '/inventory?lens=racks')).toBe(true);
    const page = readFileSync(resolve(__dirname, '../inventory-page.tsx'), 'utf8');
    expect(page).toMatch(/if \(lens === 'racks'\) \{\s*return <RacksLens \/>;/);
  });
});

it('render budget: a 48U rack with 40 devices (informative)', async () => {
  const devices = Array.from({ length: 40 }, (_, i) => ({
    ...SW, asset_id: `d${i}`, name: `dev-${i}`, position: i + 1, face: i % 2 ? 'rear' : 'front', is_full_depth: i % 3 === 0,
    posture: { ...SW.posture, weak_protocol: i % 4 === 0 },
  }));
  serve(elevation({ rack: { ...RACK, u_height: 48 }, devices, reservations: [{ ...RES, units: [45, 46] }] }));
  const t0 = performance.now();
  await render();
  const ms = performance.now() - t0;
  console.info(`rack elevation render (48U, 40 devices, jsdom, incl. data load): ${ms.toFixed(1)} ms (budget 100 ms in a browser)`);
  expect(host.querySelectorAll('[data-testid="rack-block"]').length).toBeGreaterThanOrEqual(40);
  expect(ms).toBeLessThan(2000);
});
