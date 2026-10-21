// @vitest-environment jsdom
//
// The asset page's Ports tab (DCIM BUILD_PLAN row 3.1): its five states per
// section, the front-to-rear mapping controls, the add flow's request bodies,
// the permission gates, Apply templates reporting every component kind, and the
// tab's registration on the asset page (mounted through the REAL AssetPage
// route, so removing the tab from the registry or the page's switch fails here).
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), patch: vi.fn(), del: vi.fn() }));
vi.mock('../../../lib/clients', () => ({
  clients: new Proxy({}, {
    get: () => ({ GET: mocks.get, POST: mocks.post, PUT: vi.fn(), PATCH: mocks.patch, DELETE: mocks.del }),
  }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { AssetPage } from '../asset-page';
import { ASSET_TABS } from '../asset-tabs';
import { PortsTab, bodyOf, draftOf, draftProblem } from './ports-tab';
import type { ConsolePort, DeviceBay, FrontPort, RearPort } from './component-queries';

const ASSET_ID = '11111111-1111-4111-8111-111111111111';
const DT_ID = '22222222-2222-4222-8222-222222222222';
const NOW = new Date().toISOString();
const ASSET = { id: ASSET_ID, hostname: 'pp-1.example.test', display_name: 'pp-1.example.test', class_key: 'switch', asset_status: 'monitoring', risk_score: 0, deleted_at: null };

const base = {
  tenant_id: 't', asset_id: ASSET_ID, module_id: null, label: null, mark_connected: false, cable_id: null, cable_end: null,
  source_kind: 'declared', source_ref: null, custom_fields: {}, external_ids: {}, description: null, comments: null,
  status: 'active', first_seen_at: NOW, last_seen_at: NOW, observation_count: 0, approved_by: null, approved_at: null,
  created_at: NOW, updated_at: NOW, created_by: null,
};
const CON: ConsolePort = { ...base, id: 'c1', name: 'con 0', type: 'rj-45', speed: 9600 };
const REAR: RearPort = { ...base, id: 'r1', name: 'Rear1', type: 'lc', color: null, positions: 12 };
const FRONT: FrontPort = { ...base, id: 'f1', name: 'Front3', type: 'lc', color: null, rear_port_id: 'r1', rear_port_position: 3 };
const BAY: DeviceBay = { ...base, id: 'b1', name: 'Bay1', installed_asset_id: '99999999-9999-4999-8999-999999999999' };

const page = (rows: unknown[]) => ({ data: { data: rows, pagination: { total: rows.length, limit: 1000, offset: 0, next_offset: null } } });

let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  for (const m of Object.values(mocks)) m.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root.unmount());
  host.remove();
  document.body.innerHTML = '';
});

type RouteMap = Record<string, (opts?: { params?: { query?: Record<string, unknown> } }) => unknown>;
const ALL_EMPTY: RouteMap = Object.fromEntries(
  ['console-ports', 'console-server-ports', 'front-ports', 'rear-ports', 'device-bays'].map((k) => [`/dcim/assets/{id}/${k}`, () => page([])]),
);
function answer(routes: RouteMap) {
  const all = { ...ALL_EMPTY, ...routes };
  mocks.get.mockImplementation(async (path: string, opts?: { params?: { query?: Record<string, unknown> } }) => {
    const fn = all[path];
    return fn ? fn(opts) : { data: {} };
  });
}

async function mount(ui: React.ReactNode, permissions: string[], path = '/') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(['user-permissions'], permissions);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <PermissionProvider>
          <MemoryRouter initialEntries={[path]}>
            <Routes>
              <Route path="/" element={ui} />
              <Route path="/inventory/assets/:id/:tab?" element={<AssetPage />} />
            </Routes>
          </MemoryRouter>
        </PermissionProvider>
      </QueryClientProvider>,
    );
  });
}

const READ = ['dcim.read'];
const MANAGE = ['dcim.read', 'dcim.manage'];
const text = () => document.body.textContent ?? '';
const byTest = (id: string) => document.body.querySelectorAll(`[data-testid="${id}"]`);
const byLabel = <T extends Element>(label: string) => document.body.querySelector<T>(`[aria-label="${label}"]`);

function setValue(el: HTMLInputElement | HTMLSelectElement, value: string) {
  const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value')!.set!.call(el, value);
  el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? 'change' : 'input', { bubbles: true }));
}

function button(label: string): HTMLButtonElement {
  const b = [...document.body.querySelectorAll('button')].find((x) => x.textContent?.trim() === label || x.getAttribute('aria-label') === label);
  if (!b) throw new Error(`no button "${label}" in: ${text()}`);
  return b;
}
const section = async (label: string) => { await act(async () => { button(label).click(); }); };
const sectionButton = (label: string) => [...document.body.querySelectorAll('[role="tab"]')].find((t) => t.textContent?.startsWith(label)) as HTMLButtonElement;

describe('<PortsTab> states', () => {
  it('default: section strip with counts, and a row per console port', async () => {
    answer({
      '/dcim/assets/{id}/console-ports': () => page([CON]),
      '/dcim/assets/{id}/rear-ports': () => page([REAR]),
      '/dcim/assets/{id}/front-ports': () => page([FRONT]),
    });
    await mount(<PortsTab asset={ASSET as never} />, READ);
    await vi.waitFor(() => expect(byTest('port-row')).toHaveLength(1));
    expect(text()).toContain('con 0');
    expect(text()).toContain('RJ-45');
    expect(text()).toContain('9600 baud');
    expect(byTest('count-console-ports')[0].textContent).toBe('1');
    expect(byTest('count-device-bays')[0].textContent).toBe('0');
    expect(mocks.get).toHaveBeenCalledWith('/dcim/assets/{id}/console-ports', { params: { path: { id: ASSET_ID }, query: { limit: 1000 } } });
  });

  it('front ports name their rear port and position; rear ports count what is mapped', async () => {
    answer({ '/dcim/assets/{id}/rear-ports': () => page([REAR]), '/dcim/assets/{id}/front-ports': () => page([FRONT]) });
    await mount(<PortsTab asset={ASSET as never} />, READ);
    await vi.waitFor(() => expect(byTest('count-front-ports')[0]?.textContent).toBe('1'));
    await section('Front ports1');
    expect(text()).toContain('Front3');
    expect(text()).toContain('Rear1');
    expect(byTest('port-row')[0].textContent).toContain('3');
    await section('Rear ports1');
    expect(byTest('port-row')[0].textContent).toContain('1 of 12');
  });

  it('device bays link to the installed asset, or say Empty', async () => {
    answer({ '/dcim/assets/{id}/device-bays': () => page([BAY, { ...BAY, id: 'b2', name: 'Bay2', installed_asset_id: null }]) });
    await mount(<PortsTab asset={ASSET as never} />, READ);
    await vi.waitFor(() => expect(byTest('count-device-bays')[0]?.textContent).toBe('2'));
    await section('Device bays2');
    expect(document.body.querySelector('a[href="/inventory/assets/99999999-9999-4999-8999-999999999999"]')).not.toBeNull();
    expect(text()).toContain('Empty');
  });

  it('empty: says nothing is declared, not that the asset has none', async () => {
    answer({});
    await mount(<PortsTab asset={ASSET as never} />, READ);
    await vi.waitFor(() => expect(text()).toContain('No console ports yet'));
    expect(text()).toContain('says nothing about whether it has any');
    expect(text()).not.toMatch(/has no console ports/i);
  });

  it('loading: a skeleton while the request is in flight', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    await mount(<PortsTab asset={ASSET as never} />, READ);
    // The faceplate (row 3.4) above the sections has its own loading state.
    expect([...byTest('substrate-loading')].filter((e) => !e.closest('[data-testid="faceplate"]'))).toHaveLength(1);
  });

  it('error: the server reason and a retry', async () => {
    answer({ '/dcim/assets/{id}/console-ports': () => ({ error: { error: { code: 'internal_error', message: 'database unavailable' } } }) });
    await mount(<PortsTab asset={ASSET as never} />, READ);
    await vi.waitFor(() => expect([...byTest('substrate-error')].filter((e) => !e.closest('[data-testid="faceplate"]'))).toHaveLength(1));
    expect(text()).toContain('database unavailable');
    expect(text()).toContain('Retry');
  });

  it('read-only: dcim.read sees the lists but no add, delete or Apply templates', async () => {
    answer({ '/dcim/assets/{id}/console-ports': () => page([CON]) });
    await mount(<PortsTab asset={ASSET as never} />, READ);
    await vi.waitFor(() => expect(byTest('port-row')).toHaveLength(1));
    expect(text()).not.toContain('Add console port');
    expect(text()).not.toContain('Apply templates');
    expect(byLabel('Delete con 0')).toBeNull();
  });

  it('without dcim.read: the permission explanation and no request', async () => {
    answer({});
    await mount(<PortsTab asset={ASSET as never} />, ['assets.read']);
    expect(text()).toContain("You can't view ports");
    expect(mocks.get).not.toHaveBeenCalled();
  });
});

describe('add / edit / delete', () => {
  it('adds a front port mapped to a rear port position', async () => {
    answer({ '/dcim/assets/{id}/rear-ports': () => page([REAR]) });
    mocks.post.mockResolvedValue({ data: { data: FRONT } });
    await mount(<PortsTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(byTest('count-rear-ports')[0]?.textContent).toBe('1'));
    await section('Front ports0');
    await act(async () => { button('Add front port').click(); });
    await act(async () => {
      setValue(byLabel<HTMLInputElement>('Name')!, 'Front3');
      setValue(byLabel<HTMLSelectElement>('Type')!, 'lc');
      setValue(byLabel<HTMLSelectElement>('Rear port')!, 'r1');
      setValue(byLabel<HTMLInputElement>('Position')!, '3');
    });
    expect(button('Add front port').disabled).toBe(false);
    await act(async () => { [...document.body.querySelectorAll('button')].filter((b) => b.textContent === 'Add front port').pop()!.click(); });
    expect(mocks.post).toHaveBeenCalledWith('/dcim/assets/{id}/front-ports', {
      params: { path: { id: ASSET_ID } },
      body: { name: 'Front3', label: null, description: null, type: 'lc', color: null, rear_port_id: 'r1', rear_port_position: 3, asset_id: ASSET_ID },
    });
  });

  it('refuses a position beyond the rear port before asking the server', async () => {
    expect(draftProblem('front-ports', { ...draftOf('front-ports', null), name: 'F', type: 'lc', rear_port_id: 'r1', rear_port_position: '13' }, [REAR]))
      .toBe('Rear1 has 12 positions.');
    expect(draftProblem('front-ports', { ...draftOf('front-ports', null), name: 'F', type: 'lc', rear_port_id: 'r1', rear_port_position: '12' }, [REAR])).toBeNull();
    expect(draftProblem('front-ports', { ...draftOf('front-ports', null), name: 'F', type: 'lc' }, [REAR])).toBe('Choose the rear port this maps to.');
    expect(draftProblem('rear-ports', { ...draftOf('rear-ports', null), name: 'R', type: 'lc', positions: '0' }, [])).toContain('Positions');
    expect(draftProblem('console-ports', { ...draftOf('console-ports', null), name: '' }, [])).toBe('A name is required.');
  });

  it('bodies are per kind', () => {
    expect(bodyOf('console-ports', { ...draftOf('console-ports', null), name: ' con 0 ', speed: '9600' })).toMatchObject({ name: 'con 0', speed: 9600, type: null });
    expect(bodyOf('rear-ports', { ...draftOf('rear-ports', null), name: 'R', type: 'lc', positions: '12' })).toMatchObject({ positions: 12, type: 'lc' });
    expect(bodyOf('device-bays', { ...draftOf('device-bays', null), name: 'B' })).toEqual({ name: 'B', label: null, description: null, installed_asset_id: null });
  });

  it('shows the server reason when a save is refused', async () => {
    answer({ '/dcim/assets/{id}/console-ports': () => page([]) });
    mocks.post.mockResolvedValue({ error: { error: { message: 'an object with the same identity already exists' } } });
    await mount(<PortsTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(text()).toContain('No console ports yet'));
    await act(async () => { button('Add console port').click(); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Name')!, 'con 0'); });
    await act(async () => { [...document.body.querySelectorAll('button')].filter((b) => b.textContent === 'Add console port').pop()!.click(); });
    await vi.waitFor(() => expect(byTest('port-form-error')[0]?.textContent).toContain('same identity'));
  });

  it('deleting a rear port warns that its front ports go with it', async () => {
    answer({ '/dcim/assets/{id}/rear-ports': () => page([REAR]) });
    mocks.del.mockResolvedValue({});
    await mount(<PortsTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(byTest('count-rear-ports')[0]?.textContent).toBe('1'));
    await section('Rear ports1');
    await act(async () => { button('Delete Rear1').click(); });
    expect(text()).toContain('front ports mapped to this rear port are deleted with it');
    await act(async () => { button('Delete').click(); });
    expect(mocks.del).toHaveBeenCalledWith('/dcim/rear-ports/{id}', { params: { path: { id: 'r1' } } });
  });
});

describe('Apply templates', () => {
  const HW = (dt: unknown) => ({ data: { data: { asset_id: ASSET_ID, class_key: 'switch', is_hardware: true, device_type: dt, manufacturer: null, device_role: null, platform: null, serial: null, asset_tag: null, template_counts: {} } } });
  const RESULT = {
    device_type_id: DT_ID,
    interfaces: { created: 48, updated: 0, unchanged: 0, removed: 0, skipped: [] },
    components: {
      'rear-ports': { created: 2, updated: 0, unchanged: 0, removed: 0, skipped: [] },
      'front-ports': { created: 4, updated: 0, unchanged: 0, removed: 0, skipped: [] },
      'console-ports': { created: 1, updated: 0, unchanged: 0, removed: 0, skipped: ['con {module}: placed when a module is installed'] },
      'power-ports': { created: 0, updated: 0, unchanged: 0, removed: 0, skipped: [] },
    },
    not_instantiated: { 'module-bay-templates': 2 },
    hardware: { device_type: { id: DT_ID, name: 'Catalyst 9300-48P', slug: 'c9300' } },
  };

  it('posts the asset\'s device type and reports every kind it created or skipped', async () => {
    answer({ '/dcim/assets/{id}/hardware': () => HW({ id: DT_ID, name: 'Catalyst 9300-48P', slug: 'c9300' }) });
    mocks.post.mockResolvedValue({ data: { data: RESULT } });
    await mount(<PortsTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(button('Apply templates').disabled).toBe(false));
    await act(async () => { button('Apply templates').click(); });
    await vi.waitFor(() => expect(byTest('apply-result')).toHaveLength(1));
    expect(mocks.post).toHaveBeenCalledWith('/dcim/assets/{id}/device-type', { params: { path: { id: ASSET_ID } }, body: { device_type_id: DT_ID } });
    const rows = [...byTest('apply-row')].map((r) => r.textContent ?? '');
    expect(rows.some((r) => r.startsWith('Interfaces') && r.includes('48 created'))).toBe(true);
    expect(rows.some((r) => r.startsWith('Rear ports') && r.includes('2 created'))).toBe(true);
    expect(rows.some((r) => r.startsWith('Front ports') && r.includes('4 created'))).toBe(true);
    expect(rows.some((r) => r.startsWith('Console ports') && r.includes('placed when a module is installed'))).toBe(true);
    expect(rows.some((r) => r.startsWith('Power ports'))).toBe(false); // nothing happened: not listed
    expect(text()).toContain('2 module bay templates');
  });

  it('is disabled, with the reason, when the asset has no device type', async () => {
    answer({ '/dcim/assets/{id}/hardware': () => HW(null) });
    await mount(<PortsTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(button('Apply templates').title).toContain('no device type'));
    expect(button('Apply templates').disabled).toBe(true);
  });

  it('shows the server reason when the apply fails', async () => {
    answer({ '/dcim/assets/{id}/hardware': () => HW({ id: DT_ID, name: 'x', slug: 'x' }) });
    mocks.post.mockResolvedValue({ error: { error: { message: 'no such device type' } } });
    await mount(<PortsTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(button('Apply templates').disabled).toBe(false));
    await act(async () => { button('Apply templates').click(); });
    await vi.waitFor(() => expect(byTest('apply-error')[0]?.textContent).toContain('no such device type'));
  });
});

describe('asset page wiring', () => {
  it('Ports is in the tab registry, right after Interfaces and IP Addresses', () => {
    const keys = ASSET_TABS.map((t) => t.key);
    expect(keys.indexOf('ports')).toBe(keys.indexOf('ip-addresses') + 1);
    expect(keys.indexOf('ip-addresses')).toBe(keys.indexOf('interfaces') + 1);
    expect(ASSET_TABS.find((t) => t.key === 'ports')?.placeholder).toBeUndefined();
  });

  it('the tab is registered on the real asset page and lists the asset\'s ports', async () => {
    answer({
      '/infrastructure-assets/{id}': () => ({ data: { asset: ASSET } }),
      '/dcim/assets/{id}/console-ports': () => page([CON]),
      '/dcim/objects/{kind}/{id}/tags': () => ({ data: { data: [] } }),
    });
    await mount(null, MANAGE, `/inventory/assets/${ASSET_ID}/ports`);
    await vi.waitFor(() => expect(byTest('port-row')).toHaveLength(1));
    expect(sectionButton('Console ports')).toBeDefined();
    expect([...document.body.querySelectorAll('[role="tab"]')].some((t) => t.textContent === 'Ports' && t.getAttribute('aria-selected') === 'true')).toBe(true);
  });
});
