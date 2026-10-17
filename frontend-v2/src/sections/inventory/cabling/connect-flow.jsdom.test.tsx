// @vitest-environment jsdom
//
// The upgraded Connect flow (DCIM row 3.4): the compatibility matrix shown
// inline (a console port cannot take an interface: the reason is shown and
// Connect stays disabled), the far end picked by site › rack › asset with the
// rack listing its assets without a search term, a circuit's termination as
// the far end, and the Trace button on a cabled port.
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }));
vi.mock('../../../lib/clients', () => ({
  clients: new Proxy({}, { get: () => ({ GET: mocks.get, POST: mocks.post, PATCH: vi.fn(), DELETE: vi.fn() }) }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { ConnectCableModal, connectProblem, farAssetQuery, type CablePort } from '../dcim/cable-column';
import { InterfacesTab } from '../dcim/interfaces-tab';
import { ASSET, ASSET_ID, FAR_ID, MANAGE, button, byLabel, byTest, cable, iface, mountUi, page, ref, routeGets, setValue, text, tick, unmount, type Mounted } from './cabling-test-kit';

let m: Mounted | null = null;
beforeEach(() => { mocks.get.mockReset(); mocks.post.mockReset(); });
afterEach(() => { unmount(m); m = null; });

const CONSOLE: CablePort = { kind: 'console_port', id: 'con0', name: 'con 0', cableId: null, markConnected: false };
const ETH: CablePort = { kind: 'interface', id: 'gi2', name: 'Gi1/0/2', cableId: null, markConnected: false };

describe('connectProblem (the compatibility matrix)', () => {
  it('refuses incompatible kinds and an in-use far port; accepts a compatible free one', () => {
    expect(connectProblem('console_port', 'interface')).toContain('A console port cannot be cabled to an interface');
    expect(connectProblem('interface', 'console_port')).toContain('compatibility matrix');
    expect(connectProblem('interface', 'front_port')).toBeNull();
    expect(connectProblem('interface', 'circuit_termination')).toBeNull();
    expect(connectProblem('interface', 'interface', { id: 'x', name: 'eth1', cabled: true })).toContain('already cabled');
  });

  it('builds the far-asset search from rack, else site, and the typed text', () => {
    expect(farAssetQuery('srv', '', '')).toBe('"srv"');
    expect(farAssetQuery('srv', 's1', '')).toBe('site.id:s1 and "srv"');
    expect(farAssetQuery('', 's1', 'r1')).toBe('rack.id:r1');
  });
});

describe('<ConnectCableModal>', () => {
  it('shows the matrix inline: a console port picking an interface cannot connect', async () => {
    routeGets(mocks.get, {});
    m = await mountUi(<ConnectCableModal port={CONSOLE} onClose={() => {}} />, MANAGE);
    await tick();
    const kind = byLabel<HTMLSelectElement>('Far port kind')!;
    // Default is the first compatible kind; incompatible ones are labelled.
    expect(kind.value).toBe('front_port');
    expect([...kind.options].find((o) => o.value === 'interface')?.textContent).toContain('(not compatible)');
    expect(byTest('connect-problem')).toHaveLength(0);
    await act(async () => { setValue(kind, 'interface'); });
    expect(byTest('connect-problem')[0].textContent).toContain('A console port cannot be cabled to an interface');
    expect(button('Connect cable').disabled).toBe(true);
  });

  it('site › rack lists the rack\'s assets with no search term; picking one and a port posts the cable', async () => {
    routeGets(mocks.get, {
      '/dcim/sites': () => ({ data: { sites: [{ id: 'site-1', name: 'DC1' }] } }),
      '/dcim/racks': () => page([{ id: 'rack-7', name: 'R7' }]),
      '/infrastructure-assets': () => ({ data: { assets: [{ id: FAR_ID, hostname: 'srv-1', display_name: 'srv-1', class_key: 'server' }], pagination: { total: 1, page: 1, page_size: 50 } } }),
      '/dcim/assets/{id}/interfaces': () => page([iface({ id: 'far-eth0', asset_id: FAR_ID, name: 'eth0' })]),
    });
    mocks.post.mockResolvedValue({ data: { data: cable({}) } });
    const onClose = vi.fn();
    m = await mountUi(<ConnectCableModal port={ETH} onClose={onClose} />, MANAGE);
    await tick();
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Site')!, 'site-1'); });
    await tick();
    expect(mocks.get).toHaveBeenCalledWith('/dcim/racks', { params: { query: { limit: 1000, site_id: 'site-1' } } });
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Rack')!, 'rack-7'); });
    await tick(350);
    await tick();
    const search = (mocks.get.mock.calls as [string, { params: { query: { query: string } } }][]).filter(([p]) => p === '/infrastructure-assets').pop();
    expect(search?.[1].params.query.query).toBe('rack.id:rack-7');
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Far port kind')!, 'interface'); });
    await act(async () => { button('srv-1').click(); });
    await tick();
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Far port')!, 'far-eth0'); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Cable colour')!, '#2F6FDB'); });
    await act(async () => { button('Connect cable').click(); });
    await tick();
    expect(mocks.post).toHaveBeenCalledWith('/dcim/cables', {
      body: {
        a_terminations: [{ termination_kind: 'interface', termination_id: 'gi2' }],
        b_terminations: [{ termination_kind: 'interface', termination_id: 'far-eth0' }],
        operational_status: 'connected', type: 'cat6', color: '2f6fdb',
      },
    });
    expect(onClose).toHaveBeenCalled();
  });

  it('a circuit termination as the far end: search the circuit, pick its side', async () => {
    routeGets(mocks.get, {
      '/circuits/circuits': () => page([{ id: 'cir-1', cid: 'MPLS-0042' }]),
      '/circuits/circuit-terminations': () => page([{ id: 'ct-a', term_side: 'A', cable_id: null, mark_connected: false }, { id: 'ct-z', term_side: 'Z', cable_id: 'x', mark_connected: false }]),
    });
    mocks.post.mockResolvedValue({ data: { data: cable({}) } });
    m = await mountUi(<ConnectCableModal port={ETH} onClose={() => {}} />, MANAGE);
    await tick();
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Far port kind')!, 'circuit_termination'); });
    expect(byLabel('Site')).toBeNull();
    await act(async () => { setValue(byLabel<HTMLInputElement>('Search for the circuit')!, 'MPLS'); });
    await tick(350);
    await tick();
    await act(async () => { button('MPLS-0042').click(); });
    await tick();
    const sides = [...byLabel<HTMLSelectElement>('Far port')!.options].map((o) => [o.textContent, o.disabled]);
    expect(sides).toContainEqual(['Side A', false]);
    expect(sides).toContainEqual(['Side Z (in use)', true]);
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Far port')!, 'ct-a'); });
    await act(async () => { button('Connect cable').click(); });
    await tick();
    expect((mocks.post.mock.calls as [string, { body: { b_terminations: unknown } }][])[0][1].body.b_terminations).toEqual([{ termination_kind: 'circuit_termination', termination_id: 'ct-a' }]);
  });
});

describe('Trace from the Cable column', () => {
  it('a cabled interface offers Trace, which opens the trace view; a proposed cable says so', async () => {
    const c = cable({ status: 'pending', a_terminations: [ref({ termination_id: 'gi1', name: 'Gi1/0/1' })], b_terminations: [ref({ termination_id: 'x', asset_id: FAR_ID, asset_name: 'srv-9', name: 'eth9' })] });
    routeGets(mocks.get, {
      '/dcim/assets/{id}/interfaces': () => page([iface({ id: 'gi1', name: 'Gi1/0/1', cable_id: 'cab1' })]),
      '/dcim/cables': () => page([c]),
      '/dcim/interfaces/{id}/trace': () => ({ data: { data: { object: { kind: 'interface', id: 'gi1', name: 'Gi1/0/1', asset_id: ASSET_ID, asset_name: 'sw-1', circuit_id: null }, paths: [] } } }),
    });
    m = await mountUi(<InterfacesTab asset={ASSET as never} />, MANAGE);
    await tick();
    expect(byTest('cable-pending')).toHaveLength(1);
    await act(async () => { button('Trace Gi1/0/1').click(); });
    await tick();
    expect(text()).toContain('Trace Gi1/0/1');
    expect(text()).toContain('Not cabled');
  });
});
