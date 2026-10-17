// @vitest-environment jsdom
//
// Wireless (DCIM BUILD_PLAN row 4.4): Settings → Infrastructure → Wireless and
// the asset page's Wireless LANs panel, mounted through the REAL SettingsPage
// and InterfacesTab over a faked inventory client and the REAL permission gate.
// Five states each (default, empty, loading, error, success), the catalogue's
// risk colour, the write controls hidden from a read-only role, and the rule
// the feature rests on: no control can send a pre-shared key.
//
// Mutations (each red, then restored green):
//   - drop the `wireless` entry from SETTINGS_NAV (nav.ts) -> "is registered in
//     the Settings nav" fails;
//   - drop the `wireless` case from SettingsPage -> the spec-pending page renders;
//   - drop <WirelessLansPanel> from InterfacesTab -> "an access point shows its
//     SSIDs" fails;
//   - draw an unscored LAN as a banded chip (AuthRisk) -> "not assessed" fails.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), patch: vi.fn(), del: vi.fn() }));
vi.mock('../../lib/clients', () => ({
  clients: new Proxy({}, {
    get: () => ({ GET: mocks.get, POST: mocks.post, PUT: vi.fn(), PATCH: mocks.patch, DELETE: mocks.del }),
  }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { WorkspacePage } from './settings-page';
import { SETTINGS_NAV } from './nav';
import { InterfacesTab } from '../inventory/dcim/interfaces-tab';

const NOW = new Date().toISOString();
const T = '00000000-0000-4000-8000-00000000000a';
const ASSET_ID = '11111111-1111-4111-8111-111111111111';
const base = {
  tenant_id: T, description: null, comments: null, source_kind: 'measured', source_ref: null,
  custom_fields: {}, external_ids: {}, created_at: NOW, updated_at: NOW, created_by: null,
};
const lifecycle = { status: 'active', first_seen_at: null, last_seen_at: null, observation_count: 1, approved_by: null, approved_at: null };
const lan = (id: string, ssid: string, extra: Record<string, unknown> = {}) => ({
  ...base, ...lifecycle, id, ssid, group_id: null, operational_status: 'active', vlan_id: null, business_unit_id: null,
  auth_type: 'wpa-personal', auth_cipher: 'aes', auth_psk_present: true, algorithm_id: 'alg-ccmp', algorithm_code: 'WIFI-CCMP',
  algorithm_strength: 'acceptable', algorithm_risk_score: 30, interface_count: 2, ...extra,
});
const CORP = lan('l1', 'Corp');
const LEGACY = lan('l2', 'Legacy', { auth_cipher: 'tkip', algorithm_code: 'WIFI-TKIP', algorithm_strength: 'weak', algorithm_risk_score: 90 });
const AUTO = lan('l3', 'Negotiated', { auth_cipher: 'auto', algorithm_id: null, algorithm_code: null, algorithm_strength: null, algorithm_risk_score: null, auth_psk_present: false });
const OPEN = lan('l4', 'Lobby', { auth_type: 'open', auth_cipher: null, algorithm_code: 'WIFI-OPEN', algorithm_strength: 'weak', algorithm_risk_score: 90, auth_psk_present: false, status: 'pending' });
const GROUP = { ...base, source_kind: 'declared', id: 'g1', name: 'HQ Campus', slug: 'hq-campus', parent_id: null };
const LINK = {
  ...base, ...lifecycle, id: 'k1', interface_a_id: 'aaaaaaaa-0000-4000-8000-000000000001', interface_b_id: 'bbbbbbbb-0000-4000-8000-000000000002',
  ssid: 'Mesh', operational_status: 'connected', auth_type: 'wpa-personal', auth_cipher: 'aes', auth_psk_present: true, algorithm_id: null,
  distance: null, distance_unit: null, algorithm_code: 'WIFI-CCMP', algorithm_strength: 'acceptable', algorithm_risk_score: 30,
  interface_a_name: 'ra0', interface_a_asset_id: ASSET_ID, interface_b_name: 'sta0', interface_b_asset_id: null,
};
const page = (rows: unknown[]) => ({ data: { data: rows, pagination: { total: rows.length, limit: 200, offset: 0, next_offset: null } } });

type Routes = Record<string, (init?: unknown) => unknown>;
function answer(routes: Routes) {
  mocks.get.mockImplementation(async (path: string, init?: unknown) => {
    const fn = routes[path];
    return fn ? fn(init) : page([]);
  });
}
const happy: Routes = {
  '/wireless/wireless-lans': () => page([CORP, LEGACY, AUTO, OPEN]),
  '/wireless/wireless-lan-groups': () => page([GROUP]),
  '/wireless/wireless-links': () => page([LINK]),
};

let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  for (const m of Object.values(mocks)) m.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); document.body.innerHTML = ''; });

const flush = () => act(async () => { await new Promise((r) => setTimeout(r, 20)); });
const READ = ['wireless.read'];
const MANAGE = ['wireless.read', 'wireless.manage'];

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
              <Route path="/inventory/manage/:page" element={<WorkspacePage />} />
            </Routes>
          </MemoryRouter>
        </PermissionProvider>
      </QueryClientProvider>,
    );
  });
  await flush();
}
const q = (sel: string) => host.querySelector(sel);
const all = (sel: string) => Array.from(host.querySelectorAll(sel));
const body = () => document.body;
const click = (el: Element | null) => act(async () => { (el as HTMLElement).click(); });

describe('Settings → Wireless', () => {
  it('is registered in the Settings nav behind wireless.read', () => {
    const item = SETTINGS_NAV.flatMap((s) => s.items).find((i) => i.key === 'wireless');
    expect(item).toMatchObject({ label: 'Wireless', built: true, permission: 'wireless.read' });
  });

  it('is reached through the real page and lists LANs with auth, key and catalogue risk (success)', async () => {
    answer(happy);
    await mount(null, MANAGE, '/inventory/manage/wireless');
    expect(q('[data-testid="wireless-settings"]')).not.toBeNull();
    const rows = all('[data-testid="wireless-section-wireless-lans"] [role="row"], [data-testid="wireless-section-wireless-lans"] > div > div');
    const text = q('[data-testid="wireless-section-wireless-lans"]')?.textContent ?? '';
    expect(rows.length).toBeGreaterThan(0);
    for (const s of ['Corp', 'Legacy', 'Negotiated', 'Lobby']) expect(text).toContain(s);
    expect(text).toContain('WPA Personal (shared key) · AES (CCMP)');
    expect(text).toContain('WPA Personal (shared key) · TKIP');
    expect(text).toContain('Open (no encryption)');
    expect(text).toContain('Key set');
    expect(text).toContain('Pending');
    expect(q('[data-testid="wireless-section-wireless-lan-groups"]')?.textContent).toContain('HQ Campus');
    expect(q('[data-testid="wireless-section-wireless-links"]')?.textContent).toContain('ra0');
    expect(q('[data-testid="wireless-section-wireless-links"]')?.textContent).toContain('sta0');
  });

  it('colours the cipher by the catalogue score, and says "not assessed" for an unscored LAN', async () => {
    answer(happy);
    await mount(null, READ, '/inventory/manage/wireless');
    const risks = all('[data-testid="wireless-section-wireless-lans"] [data-testid="auth-risk"]');
    const byLevel = risks.map((r) => `${r.getAttribute('data-assessed')}:${r.getAttribute('data-level')}`);
    // Corp 30 -> Low; Legacy 90 -> Critical; Negotiated null -> not assessed; Lobby (open) 90 -> Critical.
    expect(byLevel).toEqual(['true:Low', 'true:Critical', 'false:null', 'true:Critical']);
    expect(risks[2].textContent).toContain('Not assessed');
  });

  it('shows loading, error and empty states (loading, error, empty)', async () => {
    answer({ ...happy, '/wireless/wireless-lans': () => new Promise(() => {}) });
    await mount(null, READ, '/inventory/manage/wireless');
    expect(q('[data-testid="wireless-section-wireless-lans"] [data-testid="substrate-loading"]')).not.toBeNull();

    act(() => root.unmount());
    root = createRoot(host);
    answer({ ...happy, '/wireless/wireless-lans': () => ({ error: { error: { message: 'boom' } } }) });
    await mount(null, READ, '/inventory/manage/wireless');
    expect(q('[data-testid="wireless-section-wireless-lans"] [data-testid="substrate-error"]')?.textContent).toContain('boom');

    act(() => root.unmount());
    root = createRoot(host);
    answer({ '/wireless/wireless-lans': () => page([]) });
    await mount(null, READ, '/inventory/manage/wireless');
    expect(q('[data-testid="wireless-section-wireless-lans"] [data-testid="substrate-empty"]')?.textContent).toContain('No wireless lans yet');
  });

  it('hides every write control from a read-only role', async () => {
    answer(happy);
    await mount(null, READ, '/inventory/manage/wireless');
    expect(q('[data-testid="add-wireless-lans"]')).toBeNull();
    expect(q('[data-testid="add-wireless-lan-groups"]')).toBeNull();
    expect(body().querySelector('[aria-label="Delete Corp"]')).toBeNull();
    expect(body().querySelector('[aria-label="Edit Corp"]')).toBeNull();
  });

  it('adds a LAN with a key-present checkbox and no way to send a key', async () => {
    answer(happy);
    mocks.post.mockResolvedValue({ data: { data: CORP } });
    await mount(null, MANAGE, '/inventory/manage/wireless');
    await click(q('[data-testid="add-wireless-lans"]'));
    const dialog = document.body.querySelector('[role="dialog"]') ?? document.body;
    const labels = Array.from(dialog.querySelectorAll('input,select,textarea')).map((e) => (e.getAttribute('aria-label') ?? '').toLowerCase());
    expect(labels).toContain('a pre-shared key is configured');
    expect(labels.some((l) => /passphrase|password|secret/.test(l) || l === 'key' || l === 'psk')).toBe(false);
    // The only key-related control is the checkbox.
    const keyed = Array.from(dialog.querySelectorAll('input')).filter((e) => /key/i.test(e.getAttribute('aria-label') ?? ''));
    expect(keyed.map((e) => e.type)).toEqual(['checkbox']);
    const ssid = dialog.querySelector<HTMLInputElement>('[aria-label="SSID"]')!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(ssid, 'Staff');
      ssid.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await click(keyed[0]);
    await click(document.body.querySelector('[data-testid="ipam-save"]'));
    await flush();
    const [path, init] = mocks.post.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(path).toBe('/wireless/wireless-lans');
    expect(init.body).toMatchObject({ ssid: 'Staff', auth_psk_present: true });
    expect(Object.keys(init.body).some((k) => /psk$|passphrase|secret/.test(k) && k !== 'auth_psk_present')).toBe(false);
  });
});

const ASSET = { id: ASSET_ID, hostname: 'ap-1.example.test', display_name: 'ap-1', class_key: 'switch', asset_status: 'monitoring', risk_score: 0, deleted_at: null };
const radio = {
  id: 'i1', asset_id: ASSET_ID, name: 'ra0', type: 'ieee802.11n', type_label: 'IEEE 802.11n', status: 'active', enabled: true,
  mgmt_only: false, mac_addresses: [], tagged_vlan_ids: [], vdcs: [], custom_fields: {}, source_kind: 'measured',
};
const wired = { ...radio, id: 'i2', name: 'Port 1', type: '1000base-t', type_label: '1000BASE-T' };
const ifaces = (rows: unknown[]) => ({ data: { data: rows, pagination: { total: rows.length, limit: 1000, offset: 0, next_offset: null } } });

describe('Asset page → Wireless LANs panel', () => {
  const READ_BOTH = ['dcim.read', 'wireless.read'];

  it('an access point shows its SSIDs with authentication and catalogue risk (success)', async () => {
    answer({
      '/dcim/assets/{id}/interfaces': () => ifaces([radio, wired]),
      '/wireless/wireless-lans': (init) => {
        expect((init as { params: { query: Record<string, unknown> } }).params.query).toMatchObject({ asset_id: ASSET_ID });
        return page([CORP, LEGACY]);
      },
    });
    await mount(<InterfacesTab asset={ASSET as never} />, READ_BOTH);
    await vi.waitFor(() => expect(body().querySelectorAll('[data-testid="wireless-lan-row"]')).toHaveLength(2));
    const panel = body().querySelector('[data-testid="wireless-panel"]')!;
    expect(panel.textContent).toContain('Legacy');
    expect(panel.textContent).toContain('TKIP');
    expect(panel.querySelectorAll('[data-testid="auth-risk"][data-level="Critical"]')).toHaveLength(1);
  });

  it('a switch has no wireless panel', async () => {
    answer({ '/dcim/assets/{id}/interfaces': () => ifaces([wired]) });
    await mount(<InterfacesTab asset={ASSET as never} />, READ_BOTH);
    await vi.waitFor(() => expect(body().querySelectorAll('[data-testid="interface-row"]')).toHaveLength(1));
    expect(body().querySelector('[data-testid="wireless-panel"]')).toBeNull();
  });

  it('loading, error, empty and permission states', async () => {
    answer({ '/dcim/assets/{id}/interfaces': () => ifaces([radio]), '/wireless/wireless-lans': () => new Promise(() => {}) });
    await mount(<InterfacesTab asset={ASSET as never} />, READ_BOTH);
    await vi.waitFor(() => expect(body().querySelector('[data-testid="wireless-panel"] [data-testid="substrate-loading"]')).not.toBeNull());

    act(() => root.unmount());
    root = createRoot(host);
    answer({ '/dcim/assets/{id}/interfaces': () => ifaces([radio]), '/wireless/wireless-lans': () => ({ error: { error: { message: 'nope' } } }) });
    await mount(<InterfacesTab asset={ASSET as never} />, READ_BOTH);
    await vi.waitFor(() => expect(body().querySelector('[data-testid="wireless-panel"] [data-testid="substrate-error"]')?.textContent).toContain('nope'));

    act(() => root.unmount());
    root = createRoot(host);
    answer({ '/dcim/assets/{id}/interfaces': () => ifaces([radio]), '/wireless/wireless-lans': () => page([]) });
    await mount(<InterfacesTab asset={ASSET as never} />, READ_BOTH);
    await vi.waitFor(() => expect(body().querySelector('[data-testid="wireless-panel"]')?.textContent).toContain('No wireless LANs reported'));

    act(() => root.unmount());
    root = createRoot(host);
    mocks.get.mockClear();
    answer({ '/dcim/assets/{id}/interfaces': () => ifaces([radio]) });
    await mount(<InterfacesTab asset={ASSET as never} />, ['dcim.read']);
    await vi.waitFor(() => expect(body().querySelector('[data-testid="wireless-panel"]')?.textContent).toContain("You can't view wireless LANs"));
    expect(mocks.get.mock.calls.some((c) => c[0] === '/wireless/wireless-lans')).toBe(false);
  });
});
