// @vitest-environment jsdom
//
// The asset faceplate (DCIM row 3.4), mounted through the REAL Ports tab so
// dropping it from the tab fails here: ports in the device type's template
// order (then natural order), a 48-port switch wrapping to two rows of 24,
// link-state colours, the cabled dot and the dashed proposed cable, the crypto
// overlay's tints asserted against the generated ratings module (not a copied
// threshold), the lock on a weak protocol, the overlay toggle, the port panel
// with Trace, arrow-key movement, and the loading / error / empty states.
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { riskLevelFromScore } from '@vistasecurity/primitives/ratings';
import { LEVEL_COLOR } from '../../../components/ui/risk';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }));
vi.mock('../../../lib/clients', () => ({
  clients: new Proxy({}, { get: () => ({ GET: mocks.get, POST: mocks.post, PATCH: vi.fn(), DELETE: vi.fn() }) }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { PortsTab } from '../dcim/ports-tab';
import { InterfacesTab } from '../dcim/interfaces-tab';
import { naturalCompare, orderPorts, faceplateRows, interfaceState, PORT_STATE_COLOR } from './faceplate-model';
import { portOverlay, UNASSESSED_COLOR } from './port-overlay';
import type { InterfacePosture } from './cabling-queries';
import {
  ASSET, ASSET_ID, FAR_ID, MANAGE, READ, button, byLabel, byTest, cable, iface, mountUi, page, ref, routeGets, text, tick, unmount, type Mounted,
} from './cabling-test-kit';

let m: Mounted | null = null;
beforeEach(() => { mocks.get.mockReset(); mocks.post.mockReset(); });
afterEach(() => { unmount(m); m = null; });

// 48 copper ports reported out of order, plus two SFP uplinks the template
// lists FIRST, plus a VLAN interface that is not a socket.
const GI = Array.from({ length: 48 }, (_, i) => iface({ id: `gi${i + 1}`, name: `Gi1/0/${i + 1}`, operational_status: i % 2 ? 'down' : 'up' }))
  .map((x) => (x.id === 'gi5' ? { ...x, enabled: false } : x))
  .reverse();
const UPLINKS = [iface({ id: 'te2', name: 'Te1/1/2', type: '10gbase-x-sfpp' }), iface({ id: 'te1', name: 'Te1/1/1', type: '10gbase-x-sfpp' })];
const VLAN = iface({ id: 'v10', name: 'Vlan10', type: 'virtual', type_label: 'Virtual' });
const TEMPLATES = ['Te1/1/1', 'Te1/1/2', ...Array.from({ length: 48 }, (_, i) => `Gi1/0/${i + 1}`)];

const CABLED = cable({ id: 'c1', a_terminations: [ref({ termination_id: 'gi1', name: 'Gi1/0/1' })], b_terminations: [ref({ termination_id: 'srv', asset_id: FAR_ID, asset_name: 'srv-9', name: 'eth0' })] });
const PROPOSED = cable({ id: 'c2', status: 'pending', a_terminations: [ref({ termination_id: 'gi2', name: 'Gi1/0/2' })], b_terminations: [ref({ termination_id: 'ap', asset_id: FAR_ID, asset_name: 'ap-3', name: 'eth0' })] });

const posture = (id: string, over: Partial<InterfacePosture>): InterfacePosture => ({
  interface_id: id, configurations: 1, assessed: false, worst_score: null, weakest_strength: null, weak_protocol: false, worst_configuration: null, ...over,
});
const POSTURE = {
  asset_id: ASSET_ID, open_findings: 1,
  top_finding: { id: 'f', producer: 'crypto', kind: 'weak_configuration', severity: 'high', score: 80, summary: 'TLS 1.0 offered' },
  interfaces: [
    posture('gi1', { assessed: true, worst_score: 95, weakest_strength: 'weak', weak_protocol: true,
      worst_configuration: { id: 'cfg-1', protocol: 'TLS', protocol_version: 'TLS1.0', cipher_suite: 'TLS_RSA_WITH_RC4_128_SHA', port: 443, risk_score: 95, risk_score_assessed: true, strength: 'weak' } }),
    posture('gi2', { weakest_strength: 'recommended' }),
    posture('gi3', { assessed: true, worst_score: 45 }),
    posture('gi4', { configurations: 0 }),
  ],
};

function standardRoutes(over: Record<string, () => unknown> = {}) {
  routeGets(mocks.get, {
    '/dcim/assets/{id}/interfaces': () => page([...GI, ...UPLINKS, VLAN]),
    '/dcim/assets/{id}/console-ports': () => page([{ id: 'con0', name: 'con 0', label: null, type: 'rj-45', cable_id: null, mark_connected: false }]),
    '/dcim/assets/{id}/hardware': () => ({ data: { data: { asset_id: ASSET_ID, device_type: { id: 'dt1', name: 'C9300-48T' } } } }),
    '/dcim/device-types/{id}/interface-templates': () => page(TEMPLATES.map((name) => ({ name }))),
    '/dcim/cables': () => page([CABLED, PROPOSED]),
    '/dcim/assets/{id}/interface-posture': () => ({ data: { data: POSTURE } }),
    ...over,
  });
}

const tile = (id: string) => document.body.querySelector<HTMLButtonElement>(`[data-testid="face-port"][data-port-id="${id}"]`)!;
const interfaceTiles = () => [...document.body.querySelectorAll<HTMLButtonElement>('[data-testid="face-group-interface"] [data-testid="face-port"]')];

describe('faceplate model', () => {
  it('orders by template, then naturally (Gi1/0/2 before Gi1/0/10)', () => {
    expect(naturalCompare('Gi1/0/2', 'Gi1/0/10')).toBeLessThan(0);
    const ports = ['Gi1/0/10', 'x9', 'Gi1/0/2', 'Te1/1/1'].map((name) => ({ name }));
    expect(orderPorts(ports, ['Te1/1/1', 'Gi1/0/10']).map((p) => p.name)).toEqual(['Te1/1/1', 'Gi1/0/10', 'Gi1/0/2', 'x9']);
    expect(orderPorts(ports, null).map((p) => p.name)).toEqual(['Gi1/0/2', 'Gi1/0/10', 'Te1/1/1', 'x9']);
  });

  it('wraps at 24 per row; a declared-disabled port is disabled whatever was measured', () => {
    expect(faceplateRows(Array.from({ length: 50 }, (_, i) => i)).map((r) => r.length)).toEqual([24, 24, 2]);
    expect(interfaceState({ enabled: false, operational_status: 'up' })).toBe('disabled');
    expect(interfaceState({ enabled: true, operational_status: null })).toBe('unknown');
  });

  it('overlay: certified scores band through the ratings module; uncertified is grey, never clean; nothing observed is untinted', () => {
    for (const score of [0, 1, 39, 40, 69, 70, 89, 90, 100]) {
      const o = portOverlay(posture('p', { assessed: true, worst_score: score }));
      expect(o.color).toBe(LEVEL_COLOR[riskLevelFromScore(score)]);
    }
    expect(portOverlay(posture('p', { assessed: false, worst_score: null }) as never)).toMatchObject({ kind: 'unassessed', color: UNASSESSED_COLOR });
    expect(portOverlay(posture('p', { configurations: 0 }) as never)).toMatchObject({ kind: 'none', color: null });
  });
});

describe('<Faceplate> on the Ports tab', () => {
  it('draws ports in template order, 48 copper ports as two rows, states and cable marks', async () => {
    standardRoutes();
    m = await mountUi(<PortsTab asset={ASSET as never} />, MANAGE);
    await tick();
    await tick();
    expect(byTest('faceplate')).toHaveLength(1);
    const names = interfaceTiles().map((t) => t.getAttribute('aria-label')!.split(',')[0]);
    expect(names.slice(0, 4)).toEqual(['Te1/1/1', 'Te1/1/2', 'Gi1/0/1', 'Gi1/0/2']);
    expect(names).toHaveLength(50);
    expect(names).not.toContain('Vlan10');
    expect(text()).toContain('1 virtual or wireless interface not drawn');
    // 50 ports → rows of 24, 24, 2: the 48-port block wraps.
    const rows = [...document.body.querySelectorAll('[data-testid="face-group-interface"] [data-testid="face-row"]')].map((r) => r.children.length);
    expect(rows).toEqual([24, 24, 2]);
    expect(tile('gi1').dataset.state).toBe('up');
    expect(tile('gi2').dataset.state).toBe('down');
    expect(tile('gi5').dataset.state).toBe('disabled');
    expect(tile('gi1').style.border).toContain(PORT_STATE_COLOR.up.replace(/ /g, ''));
    expect(tile('gi1').dataset.mark).toBe('cabled');
    expect(tile('gi2').dataset.mark).toBe('pending');
    expect(tile('gi2').style.border).toContain('dashed');
    expect(tile('gi3').dataset.mark).toBe('none');
    expect(tile('gi1').getAttribute('aria-label')).toContain('cabled to srv-9:eth0');
    // Console ports in their own row group.
    expect(byTest('face-group-console_port')).toHaveLength(1);
    // Template order came from the asset's device type.
    const tpl = (mocks.get.mock.calls as [string, { params: { path: { id: string } } }][]).find(([p]) => p === '/dcim/device-types/{id}/interface-templates');
    expect(tpl?.[1].params.path.id).toBe('dt1');
  });

  it('crypto overlay (default on): tints from the ratings module, a lock on a weak protocol; toggling it off removes the tint', async () => {
    standardRoutes();
    m = await mountUi(<PortsTab asset={ASSET as never} />, READ);
    await tick();
    await tick();
    expect(byLabel<HTMLInputElement>('Crypto overlay')!.checked).toBe(true);
    expect(tile('gi1').dataset.tint).toBe(LEVEL_COLOR[riskLevelFromScore(95)]);
    expect(tile('gi1').dataset.weak).toBe('true');
    expect(tile('gi1').getAttribute('title')).toContain('TLS1.0 · TLS_RSA_WITH_RC4_128_SHA on port 443');
    expect(tile('gi3').dataset.tint).toBe(LEVEL_COLOR[riskLevelFromScore(45)]);
    expect(tile('gi2').dataset.tint).toBe(UNASSESSED_COLOR);
    expect(tile('gi4').dataset.tint).toBe('');
    expect(tile('gi4').dataset.weak).toBeUndefined();
    expect(byTest('asset-top-finding')[0]?.textContent).toContain('TLS 1.0 offered');
    await act(async () => { byLabel<HTMLInputElement>('Crypto overlay')!.click(); });
    expect(tile('gi1').dataset.tint).toBe('');
    expect(tile('gi1').dataset.weak).toBeUndefined();
  });

  it('a failed overlay read says so instead of drawing ports clean', async () => {
    standardRoutes({ '/dcim/assets/{id}/interface-posture': () => ({ error: { error: { message: 'down' } } }) });
    m = await mountUi(<PortsTab asset={ASSET as never} />, READ);
    await tick();
    await tick();
    expect(byTest('overlay-error')).toHaveLength(1);
    expect(tile('gi1').dataset.tint).toBe('');
  });

  it('click a port → its panel with the far end and Trace; arrow keys move between ports', async () => {
    standardRoutes({
      '/dcim/interfaces/{id}/trace': () => ({ data: { data: { object: { kind: 'interface', id: 'gi1', name: 'Gi1/0/1', asset_id: ASSET_ID, asset_name: 'sw-1', circuit_id: null }, paths: [] } } }),
    });
    m = await mountUi(<PortsTab asset={ASSET as never} />, MANAGE);
    await tick();
    await tick();
    await act(async () => { tile('gi1').click(); });
    const panel = byTest('port-panel')[0];
    expect(panel.getAttribute('aria-label')).toBe('Port Gi1/0/1');
    expect(panel.textContent).toContain('srv-9:eth0');
    expect(byLabel('Disconnect Gi1/0/1')).not.toBeNull();
    expect(byTest('port-crypto')[0].textContent).toContain('Critical');
    await act(async () => { byTest('port-trace')[0].click(); });
    await tick();
    expect(mocks.get).toHaveBeenCalledWith('/dcim/interfaces/{id}/trace', { params: { path: { id: 'gi1' } } });
    expect(text()).toContain('Trace Gi1/0/1');
    // An uncabled port offers Connect from the panel.
    await act(async () => { button('Close').click(); });
    await act(async () => { tile('gi3').click(); });
    expect(byLabel('Connect Gi1/0/3')).not.toBeNull();
    // Keyboard: ArrowRight from Gi1/0/3 focuses Gi1/0/4.
    tile('gi3').focus();
    await act(async () => { tile('gi3').dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true })); });
    expect(document.activeElement).toBe(tile('gi4'));
  });

  it('loading, error and empty', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    m = await mountUi(<PortsTab asset={ASSET as never} />, READ);
    expect(byTest('faceplate')[0].querySelector('[data-testid="substrate-loading"]')).not.toBeNull();
    unmount(m);
    standardRoutes({ '/dcim/assets/{id}/interfaces': () => ({ error: { error: { message: 'iface store down' } } }) });
    m = await mountUi(<PortsTab asset={ASSET as never} />, READ);
    await tick();
    expect(byTest('faceplate')[0].querySelector('[data-testid="substrate-error"]')?.textContent).toContain('iface store down');
    unmount(m);
    routeGets(mocks.get, { '/dcim/assets/{id}/interfaces': () => page([VLAN]) });
    m = await mountUi(<PortsTab asset={ASSET as never} />, MANAGE);
    await tick();
    expect(byTest('faceplate')[0].textContent).toContain('No ports to draw');
    expect(byTest('bulk-cables-open')).toHaveLength(0);
  });

  it('the Interfaces tab header links to the faceplate', async () => {
    routeGets(mocks.get, { '/dcim/assets/{id}/interfaces': () => page([GI[0]]) });
    m = await mountUi(<InterfacesTab asset={ASSET as never} />, READ);
    await tick();
    expect(byTest('open-faceplate')[0].getAttribute('href')).toBe(`/inventory/assets/${ASSET_ID}/ports#faceplate`);
  });
});
