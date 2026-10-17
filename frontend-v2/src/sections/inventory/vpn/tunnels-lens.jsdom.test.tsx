// @vitest-environment jsdom
//
// Inventory → Tunnels and Settings → VPN Policies (DCIM BUILD_PLAN row 4.3),
// mounted through the REAL InventoryPage / SettingsPage over a faked inventory
// client and the REAL permission gate, in the five states (default, empty,
// loading, error, success): the tunnel row's weakest component banded by the
// one risk ladder and its PQC class, the drawer's proposals with their
// catalogue assessments, and write controls hidden from a read-only role.
//
// Mutation: drop the `tunnels` lens from lenses.ts or its branch from
// InventoryPage, or the `vpn-policies` case from SettingsPage → the
// "reached through the real page" tests fail.
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

import { InventoryPage } from '../inventory-page';
import { WorkspacePage } from '../../settings/settings-page';
import { INVENTORY_LENSES, lensesInGroup } from '../lenses';

const NOW = new Date().toISOString();
const T = '00000000-0000-4000-8000-00000000000a';
const base = {
  tenant_id: T, description: null, comments: null, source_kind: 'measured', source_ref: 'interrogation:fw', custom_fields: {},
  created_at: NOW, updated_at: NOW, created_by: null,
};
const assess = (code: string, strength: string, risk: number | null, primitive = 'key-agree') =>
  ({ code, name: code, strength, deprecation_status: 'current', risk_score: risk, is_pqc: false, primitive });
const TUNNEL = {
  ...base, id: 't1', name: 'to-branch', group_id: null, operational_status: 'active', encapsulation: 'ipsec-tunnel',
  ipsec_profile_id: 'prof1', business_unit_id: null, tunnel_id: null, external_ids: {}, status: 'active',
  observed_peer_addresses: ['203.0.113.9/32'], first_seen_at: NOW, last_seen_at: NOW, observation_count: 2, approved_by: null, approved_at: null,
  ike_version: 1, pfs_group: 14,
  terminations: [{ id: 'tt1', role: 'peer', interface_id: 'if1', interface: 'to-branch', asset_id: 'a1', asset_name: 'fw-edge', outside_ip: null }],
  weakest_component: { code: 'AUTH-HMAC-SHA1-96', phase: 'ike', role: 'hash', risk_score: 68, strength: 'weak', deprecation_status: 'deprecated' },
  pqc_status: 'needs_migration',
};
const PROFILE = { ...base, id: 'prof1', name: 'to-branch', mode: 'esp', ike_policy_id: 'ikp1', ipsec_policy_id: 'esp1', external_ids: {} };
const IKE_POLICY = { ...base, id: 'ikp1', name: 'to-branch IKE', version: 1, mode: 'main', preshared_key_present: true, external_ids: {}, proposals: ['ike1'] };
const IKE_PROPOSAL = {
  ...base, id: 'ike1', name: 'IKE aes-256-cbc / hmac-sha1 / group 14', authentication_method: 'preshared-keys',
  encryption_algorithm: 'aes-256-cbc', authentication_algorithm: 'hmac-sha1', group: 14, sa_lifetime_seconds: 86400, external_ids: {},
  encryption_algorithm_id: 'al1', authentication_algorithm_id: 'al2', group_algorithm_id: 'al3',
  encryption_assessment: assess('ENCR-AES-CBC-256', 'strong', 25, 'block-cipher'),
  authentication_assessment: assess('AUTH-HMAC-SHA1-96', 'weak', 68, 'mac'),
  group_assessment: assess('DH-MODP-2048', 'acceptable', 35),
};
const ESP_POLICY = { ...base, id: 'esp1', name: 'to-branch IPsec', pfs_group: 14, pfs_group_algorithm_id: 'al3', external_ids: {}, proposals: [], pfs_group_assessment: assess('DH-MODP-2048', 'acceptable', 35) };

const page = (rows: unknown[]) => ({ data: { data: rows, pagination: { total: rows.length, limit: 200, offset: 0, next_offset: null } } });
type RoutesMap = Record<string, () => unknown>;
function answer(routes: RoutesMap) {
  mocks.get.mockImplementation(async (path: string) => {
    const fn = routes[path];
    return fn ? fn() : page([]);
  });
}
const happy: RoutesMap = {
  '/vpn/tunnels': () => page([TUNNEL]),
  '/vpn/ipsec-profiles': () => page([PROFILE]),
  '/vpn/ike-policies': () => page([IKE_POLICY]),
  '/vpn/ike-proposals': () => page([IKE_PROPOSAL]),
  '/vpn/ipsec-policies': () => page([ESP_POLICY]),
};

let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  for (const m of Object.values(mocks)) m.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

const flush = () => act(async () => { await new Promise((r) => setTimeout(r, 20)); });
const MANAGE = ['vpn.read', 'vpn.manage'];
const READ = ['vpn.read'];

async function mount(path: string, permissions: string[]) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(['user-permissions'], permissions);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <PermissionProvider>
          <MemoryRouter initialEntries={[path]}>
            <Routes>
              <Route path="/inventory" element={<InventoryPage />} />
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

describe('the Tunnels lens registration', () => {
  it('is one live lens in the cryptography group', () => {
    const lens = INVENTORY_LENSES.filter((l) => l.key === 'tunnels');
    expect(lens).toHaveLength(1);
    expect(lens[0]).toMatchObject({ group: 'cryptography', live: true, anchor: 'vpn' });
    expect(lensesInGroup('cryptography').map((l) => l.key)).toContain('tunnels');
  });
});

describe('Inventory → Tunnels', () => {
  it('is reached through the real page with posture columns (success)', async () => {
    answer(happy);
    await mount('/inventory?lens=tunnels', MANAGE);
    expect(q('[data-testid="tunnels-lens"]')).not.toBeNull();
    const rows = all('[data-testid="tunnel-row"]');
    expect(rows).toHaveLength(1);
    const text = rows[0].textContent ?? '';
    expect(text).toContain('to-branch');
    expect(text).toContain('IPsec (tunnel)');
    expect(text).toContain('fw-edge to-branch');
    expect(text).toContain('203.0.113.9');
    expect(text).toContain('v1');
    // 68 is Medium on the one CVSS-anchored ladder (40-69).
    expect(q('[data-testid="weakest-component"]')?.textContent).toContain('Medium');
    expect(q('[data-testid="weakest-component"]')?.textContent).toContain('AUTH-HMAC-SHA1-96');
    expect(q('[data-testid="pqc-status"]')?.textContent).toBe('Needs PQC migration');
    expect(q('[data-testid="add-tunnel"]')).not.toBeNull();
  });

  it('opens a tunnel with its proposals and their catalogue assessments (default → drawer)', async () => {
    answer(happy);
    await mount('/inventory?lens=tunnels&tunnel=t1', MANAGE);
    const panel = q('[data-testid="tunnel-panel"]');
    expect(panel).not.toBeNull();
    const ike = q('[data-testid="ike-proposal"]')?.textContent ?? '';
    expect(ike).toContain('aes-256-cbc');
    expect(ike).toContain('hmac-sha1');
    expect(ike).toContain('weak');
    expect(ike).toContain('group 14');
    expect(panel?.textContent).toContain('pre-shared key configured (never collected)');
  });

  it('says when nothing scored a tunnel instead of rendering a clean band', async () => {
    answer({ ...happy, '/vpn/tunnels': () => page([{ ...TUNNEL, weakest_component: null, pqc_status: 'unclassified' }]) });
    await mount('/inventory?lens=tunnels', MANAGE);
    expect(q('[data-testid="tunnel-row"]')?.textContent).toContain('Not assessed');
    expect(q('[data-testid="pqc-status"]')?.textContent).toBe('Not classified');
  });

  it('shows an empty inventory as empty (empty)', async () => {
    answer({ ...happy, '/vpn/tunnels': () => page([]) });
    await mount('/inventory?lens=tunnels', MANAGE);
    expect(q('[data-testid="substrate-empty"]')?.textContent).toContain('No tunnels yet');
  });

  it('shows loading while the list is on its way (loading)', async () => {
    answer({ ...happy, '/vpn/tunnels': () => new Promise(() => {}) });
    await mount('/inventory?lens=tunnels', MANAGE);
    expect(q('[data-testid="substrate-loading"]')).not.toBeNull();
  });

  it('shows the server refusal (error)', async () => {
    answer({ ...happy, '/vpn/tunnels': () => ({ error: { error: { code: 'forbidden', message: 'vpn.read required' } } }) });
    await mount('/inventory?lens=tunnels', MANAGE);
    expect(host.textContent).toContain('vpn.read required');
  });

  it('hides write controls from a read-only role', async () => {
    answer(happy);
    await mount('/inventory?lens=tunnels', READ);
    expect(q('[data-testid="add-tunnel"]')).toBeNull();
  });
});

describe('Settings → VPN Policies', () => {
  it('is reached through the real settings page and shows assessed proposals', async () => {
    answer(happy);
    await mount('/inventory/manage/vpn-policies', MANAGE);
    expect(q('[data-testid="vpn-policies-settings"]')).not.toBeNull();
    const proposals = q('[data-testid="vpn-catalog-ike-proposals"]')?.textContent ?? '';
    expect(proposals).toContain('aes-256-cbc');
    expect(proposals).toContain('weak');
    expect(q('[data-testid="vpn-catalog-ike-policies"]')?.textContent).toContain('IKE aes-256-cbc / hmac-sha1 / group 14');
    expect(q('[data-testid="add-ike-proposals"]')).not.toBeNull();
  });

  it('hides write controls from a read-only role', async () => {
    answer(happy);
    await mount('/inventory/manage/vpn-policies', READ);
    expect(q('[data-testid="vpn-policies-settings"]')).not.toBeNull();
    expect(q('[data-testid="add-ike-proposals"]')).toBeNull();
  });
});
