// @vitest-environment jsdom
//
// Inventory → Cabling (DCIM row 3.4): registered as a lens in the Assets group
// with a nav entry, dispatched by the Inventory page (the wiring, read from
// source like the other lens reachability tests), and the lens itself — the
// table (A/B ends, type, status with Proposed distinct, length, colour swatch,
// site/rack), the filters reaching the server, the five states, the drawer's
// edit PATCH (only changed fields), Trace from an end, and the CSV export.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn(), patch: vi.fn(), del: vi.fn() }));
vi.mock('../../../lib/clients', () => ({
  clients: new Proxy({}, { get: () => ({ GET: mocks.get, POST: vi.fn(), PATCH: mocks.patch, DELETE: mocks.del }) }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { INVENTORY_LENSES, findLens, lensesInGroup } from '../lenses';
import { SECTIONS } from '../../../app/nav';
import { CablingLens, patchOf, draftOf } from './cabling-lens';
import { cablesCsv, statusFilter } from './cabling-model';
import { ASSET_ID, FAR_ID, MANAGE, READ, byLabel, byTest, cable, mountUi, page, ref, routeGets, setValue, text, tick, unmount, type Mounted } from './cabling-test-kit';

let m: Mounted | null = null;
beforeEach(() => { for (const f of Object.values(mocks)) f.mockReset(); });
afterEach(() => { unmount(m); m = null; });

const A = ref({ termination_id: 'gi1', name: 'Gi1/0/1', site_id: 's1', site_name: 'DC-East', rack_id: 'r1', rack_name: 'R12' });
const B = ref({ termination_id: 'eth0', asset_id: FAR_ID, asset_name: 'srv-9', name: 'eth0' });
const C1 = cable({ id: 'c1', label: 'P-1', color: '2f6fdb', length: 2.5, length_unit: 'm', a_terminations: [A], b_terminations: [B] });
const C2 = cable({ id: 'c2', label: 'L-7', status: 'pending', type: null, a_terminations: [ref({ termination_id: 'gi2', name: 'Gi1/0/2' })], b_terminations: [ref({ termination_id: 'ap', asset_id: FAR_ID, asset_name: 'ap-3', name: 'eth0' })] });

describe('lens registration', () => {
  it('Cabling is a live Assets-group lens with a nav entry and a dispatch on the Inventory page', () => {
    const lens = findLens('cabling');
    expect(lens.key).toBe('cabling');
    expect(lens).toMatchObject({ label: 'Cabling', group: 'assets', live: true, anchor: 'cable' });
    expect(lensesInGroup('assets').map((l) => l.key)).toContain('cabling');
    expect(INVENTORY_LENSES.filter((l) => l.key === 'cabling')).toHaveLength(1);
    const inventory = SECTIONS.find((s) => s.id === 'inventory')!;
    const items = (inventory.groups ?? []).flatMap((g) => g.items);
    expect(items.find((i) => i.lens === 'cabling')?.path).toBe('/inventory?lens=cabling');
    const page = readFileSync(resolve(__dirname, '../inventory-page.tsx'), 'utf8');
    expect(page).toMatch(/if \(lens === 'cabling'\) \{\s*return <CablingLens \/>;/);
  });
});

describe('<CablingLens>', () => {
  it('default: the table — ends, type, status (Proposed distinct), length, colour swatch, site / rack', async () => {
    routeGets(mocks.get, { '/dcim/cables': () => page([C1, C2]) });
    m = await mountUi(<CablingLens />, READ, '/inventory?lens=cabling');
    await tick();
    const rows = byTest('cable-row');
    expect(rows).toHaveLength(2);
    expect(rows[0].textContent).toContain('sw-1:Gi1/0/1');
    expect(rows[0].textContent).toContain('srv-9:eth0');
    expect(rows[0].textContent).toContain('CAT6');
    expect(rows[0].textContent).toContain('2.5');
    expect(rows[0].textContent).toContain('DC-East / R12');
    expect(rows[0].querySelector('[data-testid="cable-swatch"]')?.getAttribute('title')).toBe('#2f6fdb');
    expect(rows[1].dataset.status).toBe('pending');
    expect(rows[1].textContent).toContain('Proposed');
    expect(rows[1].style.borderLeft).toContain('dashed');
    expect(rows[0].querySelector('a')?.getAttribute('href')).toBe(`/inventory/assets/${ASSET_ID}/ports`);
    expect(text()).toContain('2 cables');
  });

  it('filters reach the server: site, rack, type, status (proposed is the lifecycle filter), port kind', async () => {
    routeGets(mocks.get, {
      '/dcim/cables': () => page([]),
      '/dcim/sites': () => ({ data: { sites: [{ id: 's1', name: 'DC-East' }] } }),
      '/dcim/racks': () => page([{ id: 'r1', name: 'R12' }]),
    });
    m = await mountUi(<CablingLens />, READ, '/inventory?lens=cabling');
    await tick();
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Site')!, 's1'); });
    await tick();
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Rack')!, 'r1'); });
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Cable type')!, 'smf'); });
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Status')!, 'pending'); });
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Port kind')!, 'front_port'); });
    await tick();
    const last = (mocks.get.mock.calls as [string, { params: { query: unknown } }][]).filter(([p]) => p === '/dcim/cables').pop()!;
    expect(last[1].params.query).toEqual({ limit: 200, offset: 0, site_id: 's1', rack_id: 'r1', type: 'smf', termination_kind: 'front_port', status: 'pending' });
    expect(statusFilter('connected')).toEqual({ operational_status: 'connected' });
    expect(text()).toContain('No cables match');
  });

  it('empty, loading and error', async () => {
    routeGets(mocks.get, { '/dcim/cables': () => page([]) });
    m = await mountUi(<CablingLens />, READ);
    await tick();
    expect(text()).toContain('No cables yet');
    unmount(m);
    mocks.get.mockImplementation(() => new Promise(() => {}));
    m = await mountUi(<CablingLens />, READ);
    expect(byTest('substrate-loading')).toHaveLength(1);
    unmount(m);
    routeGets(mocks.get, { '/dcim/cables': () => ({ error: { error: { message: 'cable store down' } } }) });
    m = await mountUi(<CablingLens />, READ);
    await tick();
    expect(byTest('substrate-error')[0].textContent).toContain('cable store down');
  });

  it('success: the drawer edits only what changed, traces from an end, and shows the changes', async () => {
    routeGets(mocks.get, {
      '/dcim/cables': () => page([C1]),
      '/dcim/cables/{id}': () => ({ data: { data: C1 } }),
      '/dcim/interfaces/{id}/trace': () => ({ data: { data: { object: { kind: 'interface', id: 'gi1', name: 'Gi1/0/1', asset_id: ASSET_ID, asset_name: 'sw-1', circuit_id: null }, paths: [] } } }),
    });
    mocks.patch.mockResolvedValue({ data: { data: { ...C1, label: 'P-2' } } });
    m = await mountUi(<CablingLens />, MANAGE, '/inventory?lens=cabling&cable=c1');
    await tick();
    await tick();
    expect(byTest('cable-drawer')).toHaveLength(1);
    expect(byTest('cable-end-A')[0].textContent).toContain('DC-East / R12');
    expect(mocks.get).toHaveBeenCalledWith('/dcim/interfaces/{id}/trace', { params: { path: { id: 'gi1' } } });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Cable label')!, 'P-2'); });
    await act(async () => { byTest('cable-save')[0].click(); });
    await tick();
    expect(mocks.patch).toHaveBeenCalledWith('/dcim/cables/{id}', { params: { path: { id: 'c1' } }, body: { label: 'P-2' } });
  });

  it('a reader sees the drawer read-only', async () => {
    routeGets(mocks.get, {
      '/dcim/cables': () => page([C1]), '/dcim/cables/{id}': () => ({ data: { data: C1 } }),
      '/dcim/interfaces/{id}/trace': () => ({ data: { data: { object: { kind: 'interface', id: 'gi1', name: 'Gi1/0/1', asset_id: ASSET_ID, asset_name: 'sw-1', circuit_id: null }, paths: [] } } }),
    });
    m = await mountUi(<CablingLens />, READ, '/inventory?lens=cabling&cable=c1');
    await tick();
    expect(byLabel<HTMLInputElement>('Cable label')!.disabled).toBe(true);
    expect(byTest('cable-save')).toHaveLength(0);
    expect(byTest('cable-disconnect')).toHaveLength(0);
  });
});

describe('cable drafts and CSV', () => {
  it('patchOf sends only changed fields; clearing the length clears its unit', () => {
    const d = draftOf(C1);
    expect(patchOf(C1, d)).toEqual({});
    expect(patchOf(C1, { ...d, color: '#FF0000' })).toEqual({ color: 'ff0000' });
    expect(patchOf(C1, { ...d, length: '' })).toEqual({ length: null, length_unit: null });
    expect(patchOf(C1, { ...d, length_unit: 'ft' })).toEqual({ length: 2.5, length_unit: 'ft' });
  });

  it('cablesCsv: a header and one escaped row per cable', () => {
    const csv = cablesCsv([C1, { ...C2, label: 'has, comma' }]);
    const lines = csv.trim().split('\n');
    expect(lines[0]).toBe('Label,A end,B end,Type,Status,Length,Length unit,Colour,Site / rack,ID');
    expect(lines[1]).toBe('P-1,sw-1:Gi1/0/1,srv-9:eth0,cat6,Connected,2.5,m,2f6fdb,DC-East / R12,c1');
    expect(lines[2].startsWith('"has, comma",sw-1:Gi1/0/2,ap-3:eth0,,Proposed')).toBe(true);
  });
});
