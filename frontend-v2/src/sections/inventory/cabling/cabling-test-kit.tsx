// Shared jsdom scaffolding for the Cabling tests (DCIM row 3.4): a mounted
// tree with React Query, permissions and a router, and the fixtures the tests
// share. Imported by *.jsdom.test.tsx only.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';
import type { Cable, CableTerminationRef } from '../dcim/cable-queries';
import type { Interface } from '../dcim/interface-queries';
import type { CablePath, CablePathNode } from './cabling-queries';

export const NOW = new Date().toISOString();
export const ASSET_ID = '11111111-1111-4111-8111-111111111111';
export const FAR_ID = '22222222-2222-4222-8222-222222222222';
export const PANEL_ID = '33333333-3333-4333-8333-333333333333';
export const ASSET = { id: ASSET_ID, hostname: 'sw-1', display_name: 'sw-1', class_key: 'switch', asset_status: 'monitoring', risk_score: 0, deleted_at: null };

export function iface(over: Partial<Interface>): Interface {
  return {
    id: 'x', asset_id: ASSET_ID, module_id: null, name: 'eth0', label: null,
    type: '1000base-t', type_label: '1000BASE-T (1GE)', enabled: true, mgmt_only: false, mtu: null, mac_address: null,
    mac_addresses: [], speed_kbps: null, duplex: null, mode: null, untagged_vlan_id: null, tagged_vlan_ids: [],
    vrf_id: null, parent_id: null, bridge_id: null, lag_id: null, rf_role: null, rf_channel: null,
    rf_channel_frequency: null, rf_channel_width: null, tx_power: null, poe_mode: null, poe_type: null, wwn: null,
    operational_status: null, admin_status: null, vdcs: [], virtual_device_contexts: [], virtual_device_context_ids: [], mark_connected: false, cable_id: null, cable_end: null,
    source_kind: 'declared', source_ref: null, custom_fields: {}, description: null, comments: null, status: 'active',
    first_seen_at: NOW, last_seen_at: NOW, observation_count: 0, approved_by: null, approved_at: null,
    created_at: NOW, updated_at: NOW, created_by: null, vlan_translation_policy_id: null,
    ...over,
  };
}

export function ref(over: Partial<CableTerminationRef>): CableTerminationRef {
  return { termination_kind: 'interface', termination_id: 't', asset_id: ASSET_ID, asset_name: 'sw-1', circuit_id: null, name: 'eth0', ...over };
}

export function cable(over: Partial<Cable>): Cable {
  return {
    id: 'cab1', tenant_id: 't', type: 'cat6', operational_status: 'connected', label: null, color: null, length: null,
    length_unit: null, business_unit_id: null, source_kind: 'declared', source_ref: null, custom_fields: {}, external_ids: {},
    description: null, comments: null, status: 'active', first_seen_at: NOW, last_seen_at: NOW, observation_count: 0, lldp_confirmed_at: null,
    approved_by: null, approved_at: null, created_at: NOW, updated_at: NOW, created_by: null,
    a_terminations: [], b_terminations: [],
    ...over,
  };
}

export function node(over: Partial<CablePathNode>): CablePathNode {
  return { kind: 'interface', id: 'n', name: 'eth0', asset_id: null, asset_name: null, circuit_id: null, ...over };
}

/** sw-1:Gi1/0/1 → cable P-1 → panel Front1, front → rear, panel Rear1 → cable T-1 → srv-9:eth0. */
export function patchPanelPath(): CablePath {
  const gi = node({ id: 'gi1', name: 'Gi1/0/1', asset_id: ASSET_ID, asset_name: 'sw-1' });
  const front = node({ kind: 'front_port', id: 'f1', name: 'Front1', asset_id: PANEL_ID, asset_name: 'pp-1' });
  const rear = node({ kind: 'rear_port', id: 'r1', name: 'Rear1', asset_id: PANEL_ID, asset_name: 'pp-1' });
  const far = node({ id: 'srv-eth0', name: 'eth0', asset_id: FAR_ID, asset_name: 'srv-9' });
  return {
    origin: gi,
    steps: [
      { near_end: [gi], cables: [node({ kind: 'cable', id: 'c1', name: 'P-1', type: 'cat6', operational_status: 'connected', color: '2f6fdb' })], far_end: [front] },
      { near_end: [rear], cables: [node({ kind: 'cable', id: 'c2', name: 'T-1', type: 'smf', operational_status: 'planned', color: null })], far_end: [far] },
    ],
    destination: far,
    is_complete: true,
    is_active: false,
    is_split: false,
  };
}

export const page = (rows: unknown[]) => ({ data: { data: rows, pagination: { total: rows.length, limit: 1000, offset: 0, next_offset: null } } });

export type Handler = (opts?: { params?: { path?: { id?: string }; query?: Record<string, unknown> }; body?: unknown }) => unknown;

/** Routes a mocked GET by its spec path. Unknown paths answer an empty page. */
export function routeGets(get: { mockImplementation: (fn: (path: string, opts?: Parameters<Handler>[0]) => Promise<unknown>) => unknown }, routes: Record<string, Handler>) {
  get.mockImplementation((path: string, opts?: Parameters<Handler>[0]) => {
    const fn = routes[path];
    return Promise.resolve(fn ? fn(opts) : page([]));
  });
}

export interface Mounted { root: Root; host: HTMLDivElement; qc: QueryClient }

export async function mountUi(ui: React.ReactNode, permissions: string[], url = '/'): Promise<Mounted> {
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(['user-permissions'], permissions);
  await act(async () => {
    await Promise.resolve();
    root.render(
      <QueryClientProvider client={qc}>
        <PermissionProvider>
          <MemoryRouter initialEntries={[url]}>{ui}</MemoryRouter>
        </PermissionProvider>
      </QueryClientProvider>,
    );
  });
  return { root, host, qc };
}

export function unmount(m: Mounted | null) {
  if (!m) return;
  act(() => m.root.unmount());
  m.host.remove();
  document.body.innerHTML = '';
}

export const READ = ['dcim.read'];
export const MANAGE = ['dcim.read', 'dcim.manage'];
export const text = () => document.body.textContent ?? '';
export const byTest = (id: string) => [...document.body.querySelectorAll<HTMLElement>(`[data-testid="${id}"]`)];
export const byLabel = <T extends Element>(label: string) => document.body.querySelector<T>(`[aria-label="${label}"]`);
export const tick = (ms = 0) => act(async () => { await new Promise((r) => setTimeout(r, ms)); });

export function setValue(el: HTMLInputElement | HTMLSelectElement, value: string) {
  const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value')!.set!.call(el, value);
  el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? 'change' : 'input', { bubbles: true }));
}

export function button(label: string): HTMLButtonElement {
  const b = [...document.body.querySelectorAll('button')].find((x) => x.textContent?.trim() === label || x.getAttribute('aria-label') === label);
  if (!b) throw new Error(`no button "${label}" in: ${text()}`);
  return b;
}
