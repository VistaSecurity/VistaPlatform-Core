// @vitest-environment jsdom
//
// The cable trace view (DCIM row 3.4) over a fixture through a patch panel:
// the diagram runs switch port → cable → panel front port, front → rear, panel
// rear port → cable → server port, the far end is highlighted, each asset
// links through, a planned cable is drawn dashed, the hop list and "Copy as
// text" say the same; plus loading, error and not-cabled states.
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock('../../../lib/clients', () => ({
  clients: new Proxy({}, { get: () => ({ GET: mocks.get, POST: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() }) }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { TraceBody } from './trace-view';
import { pathHops, traceText } from './trace-model';
import { ASSET_ID, FAR_ID, PANEL_ID, READ, byTest, mountUi, node, patchPanelPath, text, tick, unmount, type Mounted } from './cabling-test-kit';

let m: Mounted | null = null;
beforeEach(() => { mocks.get.mockReset(); });
afterEach(() => { unmount(m); m = null; });

const origin = node({ id: 'gi1', name: 'Gi1/0/1', asset_id: ASSET_ID, asset_name: 'sw-1' });

describe('pathHops', () => {
  it('reads a patch-panel path left to right with the in-device hop between the cables', () => {
    const hops = pathHops(patchPanelPath());
    expect(hops.map((h) => (h.type === 'ports' ? h.nodes.map((n) => n.name).join() : h.type === 'cable' ? `~${h.nodes[0].name}~` : `[${h.label}]`)))
      .toEqual(['Gi1/0/1', '~P-1~', 'Front1', '[front → rear]', 'Rear1', '~T-1~', 'eth0']);
    expect(hops.filter((h) => h.type === 'ports' && h.far)).toHaveLength(1);
    expect(hops[hops.length - 1]).toMatchObject({ type: 'ports', far: true });
  });

  it('copies as text: every hop, the far end, and the path state', () => {
    const t = traceText({ object: origin, paths: [patchPanelPath()] });
    expect(t).toContain('Path 1 from sw-1:Gi1/0/1 (complete · not every cable is connected)');
    expect(t).toContain('pp-1:Front1 [front port]');
    expect(t).toContain('↓ front → rear');
    expect(t).toContain('cable T-1 (smf, planned)');
    expect(t).toContain('→ far end: srv-9:eth0');
    expect(traceText({ object: origin, paths: [] })).toBe('sw-1:Gi1/0/1: not cabled');
  });
});

describe('<TraceBody>', () => {
  it('success: the diagram through the patch panel, far end highlighted, assets linked, planned cable dashed', async () => {
    mocks.get.mockResolvedValue({ data: { data: { object: origin, paths: [patchPanelPath()] } } });
    m = await mountUi(<TraceBody kind="interface" id="gi1" />, READ);
    await tick();
    expect(mocks.get).toHaveBeenCalledWith('/dcim/interfaces/{id}/trace', { params: { path: { id: 'gi1' } } });
    const nodes = byTest('trace-node');
    expect(nodes.map((n) => n.textContent)).toEqual([
      'interfaceGi1/0/1sw-1', 'front portFront1pp-1', 'rear portRear1pp-1', 'interfaceeth0srv-9',
    ]);
    const far = nodes.filter((n) => n.dataset.far);
    expect(far).toHaveLength(1);
    expect(far[0].textContent).toContain('srv-9');
    expect(nodes.map((n) => n.getAttribute('href'))).toEqual([
      `/inventory/assets/${ASSET_ID}/ports`, `/inventory/assets/${PANEL_ID}/ports`, `/inventory/assets/${PANEL_ID}/ports`, `/inventory/assets/${FAR_ID}/ports`,
    ]);
    expect(byTest('trace-through')[0].textContent).toContain('front → rear');
    const lines = byTest('trace-cable').map((c) => (c.querySelector('span[aria-hidden]') as HTMLElement).style.borderTop);
    expect(lines[0]).toContain('solid');
    expect(lines[1]).toContain('dashed');
    expect(byTest('trace-hops')[0].textContent).toContain('srv-9:eth0 (interface, far end)');
  });

  it('copy as text writes the trace to the clipboard', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    mocks.get.mockResolvedValue({ data: { data: { object: origin, paths: [patchPanelPath()] } } });
    m = await mountUi(<TraceBody kind="interface" id="gi1" />, READ);
    await tick();
    await act(async () => { byTest('trace-copy')[0].click(); });
    expect(writeText).toHaveBeenCalledWith(expect.stringContaining('far end: srv-9:eth0'));
    expect(text()).toContain('Copied');
  });

  it('a front port uses its own trace route', async () => {
    mocks.get.mockResolvedValue({ data: { data: { object: node({ kind: 'front_port', id: 'f1', name: 'Front1' }), paths: [patchPanelPath()] } } });
    m = await mountUi(<TraceBody kind="front_port" id="f1" />, READ);
    await tick();
    expect(mocks.get).toHaveBeenCalledWith('/dcim/front-ports/{id}/trace', { params: { path: { id: 'f1' } } });
  });

  it('empty: an uncabled port says it is not cabled, with no diagram', async () => {
    mocks.get.mockResolvedValue({ data: { data: { object: origin, paths: [] } } });
    m = await mountUi(<TraceBody kind="interface" id="gi1" />, READ);
    await tick();
    expect(text()).toContain('Not cabled');
    expect(byTest('trace-diagram')).toHaveLength(0);
  });

  it('loading and error', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    m = await mountUi(<TraceBody kind="interface" id="gi1" />, READ);
    expect(byTest('substrate-loading')).toHaveLength(1);
    unmount(m);
    mocks.get.mockResolvedValue({ error: { error: { message: 'trace store down' } } });
    m = await mountUi(<TraceBody kind="interface" id="gi1" />, READ);
    await tick();
    expect(byTest('substrate-error')).toHaveLength(1);
    expect(text()).toContain('trace store down');
  });
});
