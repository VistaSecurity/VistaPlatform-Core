// @vitest-environment jsdom
//
// The bulk cable editor (DCIM row 3.4): spreadsheet paste parsing (tabs, a
// header row, commas as a fallback), per-row validation (unknown port, already
// cabled, unknown far asset / port, the compatibility matrix, cable type,
// duplicates), and — through the faceplate's "Edit cables as table" — a paste
// into a cell filling the grid, Check rows resolving names, and Apply creating
// the valid rows one after another with per-row results (a refused row does
// not stop the next).
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }));
vi.mock('../../../lib/clients', () => ({
  clients: new Proxy({}, { get: () => ({ GET: mocks.get, POST: mocks.post, PATCH: vi.fn(), DELETE: vi.fn() }) }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { checkRows, normaliseCableType, parseCablePaste, pasteInto, emptyRow, type FarAssetMatch, type FarPortChoice } from './bulk-cable-model';
import type { FacePort } from './faceplate-model';
import { PortsTab } from '../dcim/ports-tab';
import { ASSET, FAR_ID, MANAGE, byLabel, byTest, cable, iface, mountUi, page, ref, routeGets, tick, unmount, type Mounted } from './cabling-test-kit';

let m: Mounted | null = null;
beforeEach(() => { mocks.get.mockReset(); mocks.post.mockReset(); });
afterEach(() => { unmount(m); m = null; });

const port = (id: string, name: string, over: Partial<FacePort> = {}): FacePort => ({
  kind: 'interface', id, name, label: null, type: '', state: 'up', cableId: null, markConnected: false, ...over,
});

describe('parseCablePaste', () => {
  it('splits tab-separated rows, drops a header and blank lines', () => {
    const t = 'Local port\tFar asset\tFar port\tCable type\tLabel\nGi1/0/1\tsrv-1\teth0\tcat6\tP-1\r\n\nGi1/0/2\tsrv-2\teth0\n';
    expect(parseCablePaste(t)).toEqual([
      { local: 'Gi1/0/1', farAsset: 'srv-1', farPort: 'eth0', type: 'cat6', label: 'P-1' },
      { local: 'Gi1/0/2', farAsset: 'srv-2', farPort: 'eth0', type: '', label: '' },
    ]);
  });

  it('falls back to commas when no line has a tab; quoted cells are unwrapped', () => {
    expect(parseCablePaste('Gi1/0/1,"srv 1",eth0,CAT6a,')).toEqual([{ local: 'Gi1/0/1', farAsset: 'srv 1', farPort: 'eth0', type: 'CAT6a', label: '' }]);
  });

  it('pastes into the grid from the row it lands on, growing it', () => {
    const g = pasteInto([emptyRow(), emptyRow()], 1, parseCablePaste('a\tb\tc\nd\te\tf'));
    expect(g.map((r) => r.local)).toEqual(['', 'a', 'd']);
  });

  it('reads a cable type by key or label, any case', () => {
    expect(normaliseCableType('CAT6a')).toBe('cat6a');
    expect(normaliseCableType('Singlemode Fiber (OS2)')).toBe('smf-os2');
    expect(normaliseCableType('')).toBe('');
    expect(normaliseCableType('string')).toBeNull();
  });
});

describe('checkRows', () => {
  const local = [port('gi1', 'Gi1/0/1'), port('gi2', 'Gi1/0/2', { cableId: 'c9' }), port('con', 'con 0', { kind: 'console_port' })];
  const assets = new Map<string, FarAssetMatch>([
    ['srv-1', { status: 'found', id: 'a1', name: 'srv-1' }], ['ghost', { status: 'missing' }], ['twin', { status: 'ambiguous', count: 2 }],
  ]);
  const ports = new Map<string, FarPortChoice[]>([['a1', [
    { kind: 'interface', id: 'e0', name: 'eth0', cabled: false }, { kind: 'interface', id: 'e1', name: 'eth1', cabled: true },
  ]]]);
  const ctx = { localPorts: local, cables: undefined, farAssets: assets, farPorts: ports };
  const row = (l: string, a: string, p: string, type = '') => ({ local: l, farAsset: a, farPort: p, type, label: '' });

  it('passes a good row and names each problem on a bad one', () => {
    const r = checkRows([
      row('Gi1/0/1', 'srv-1', 'eth0', 'cat6'),
      row('Gi9', 'srv-1', 'eth0'),
      row('Gi1/0/2', 'ghost', 'eth0'),
      row('Gi1/0/1', 'twin', 'eth0'),
      row('con 0', 'srv-1', 'eth0'),
      row('Gi1/0/1', 'srv-1', 'eth1', 'string'),
      emptyRow(),
    ], ctx);
    expect(r).toHaveLength(6);
    expect(r[0].problems).toEqual(['This local port appears on more than one row.', 'This far port appears on more than one row.']);
    expect(r[1].problems[0]).toContain('No port named “Gi9”');
    expect(r[2].problems).toEqual(['Gi1/0/2 already has a cable.', 'No asset named “ghost”.']);
    expect(r[3].problems[0]).toContain('2 assets are named “twin”');
    expect(r[4].problems[0]).toContain('cable compatibility matrix');
    expect(r[5].problems).toContain('eth1 on srv-1 already has a cable.');
    expect(r[5].problems).toContain('“string” is not a cable type.');
  });

  it('a lone good row is ready', () => {
    const [c] = checkRows([row('Gi1/0/1', 'SRV-1', 'eth0', 'cat6')], ctx);
    expect(c.problems).toEqual([]);
    expect(c.far?.id).toBe('e0');
    expect(c.type).toBe('cat6');
  });
});

describe('<BulkCableEditor> from the faceplate', () => {
  it('paste → check → apply: per-row results, a refused row does not stop the others', async () => {
    routeGets(mocks.get, {
      '/dcim/assets/{id}/interfaces': (o) => (o?.params?.path?.id === FAR_ID
        ? page([iface({ id: 'f0', asset_id: FAR_ID, name: 'eth0' }), iface({ id: 'f1', asset_id: FAR_ID, name: 'eth1' }), iface({ id: 'f2', asset_id: FAR_ID, name: 'eth2' })])
        : page([iface({ id: 'gi1', name: 'Gi1/0/1' }), iface({ id: 'gi2', name: 'Gi1/0/2' }), iface({ id: 'gi3', name: 'Gi1/0/3' })])),
      '/dcim/cables': () => page([]),
      '/infrastructure-assets': () => ({ data: { assets: [{ id: FAR_ID, hostname: 'srv-1', display_name: 'srv-1' }], pagination: { total: 1, page: 1, page_size: 50 } } }),
    });
    mocks.post
      .mockResolvedValueOnce({ data: { data: cable({ id: 'n1' }) } })
      .mockResolvedValueOnce({ error: { error: { code: 'conflict', message: 'interface f1 is already on cable x' } } })
      .mockResolvedValueOnce({ data: { data: cable({ id: 'n3', a_terminations: [ref({})] }) } });
    m = await mountUi(<PortsTab asset={ASSET as never} />, MANAGE);
    await tick();
    await act(async () => { byTest('bulk-cables-open')[0].click(); });
    expect(byTest('bulk-cable-editor')).toHaveLength(1);
    const first = byLabel<HTMLInputElement>('Row 1 local port')!;
    const pasted = 'Gi1/0/1\tsrv-1\teth0\tcat6\tP-1\nGi1/0/2\tsrv-1\teth1\nGi1/0/3\tsrv-1\teth2\tsmf\nGi1/0/9\tsrv-1\teth5';
    const data = { getData: (t: string) => (t === 'text' ? pasted : '') };
    await act(async () => {
      const ev = new Event('paste', { bubbles: true, cancelable: true });
      Object.defineProperty(ev, 'clipboardData', { value: data });
      first.dispatchEvent(ev);
    });
    expect(byTest('bulk-row')).toHaveLength(4);
    expect(byLabel<HTMLInputElement>('Row 3 far port')!.value).toBe('eth2');
    await act(async () => { byTest('bulk-check')[0].click(); });
    await tick();
    const results = () => byTest('bulk-row-result').map((r) => r.textContent ?? '');
    expect(results()[0]).toContain('Ready');
    expect(results()[3]).toContain('No port named “Gi1/0/9”');
    expect(byTest('bulk-apply')[0].textContent).toBe('Apply 3 cables');
    await act(async () => { byTest('bulk-apply')[0].click(); });
    await tick();
    expect(mocks.post).toHaveBeenCalledTimes(3);
    expect((mocks.post.mock.calls as [string, { body: unknown }][]).map((c) => c[1].body)).toEqual([
      { a_terminations: [{ termination_kind: 'interface', termination_id: 'gi1' }], b_terminations: [{ termination_kind: 'interface', termination_id: 'f0' }], operational_status: 'connected', type: 'cat6', label: 'P-1' },
      { a_terminations: [{ termination_kind: 'interface', termination_id: 'gi2' }], b_terminations: [{ termination_kind: 'interface', termination_id: 'f1' }], operational_status: 'connected' },
      { a_terminations: [{ termination_kind: 'interface', termination_id: 'gi3' }], b_terminations: [{ termination_kind: 'interface', termination_id: 'f2' }], operational_status: 'connected', type: 'smf' },
    ]);
    expect(results()[0]).toContain('Connected');
    expect(results()[1]).toContain('already on cable');
    expect(results()[2]).toContain('Connected');
    expect(byTest('bulk-summary')[0].textContent).toBe('2 of 3 connected');
  });
});
