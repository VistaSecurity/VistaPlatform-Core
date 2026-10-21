// @vitest-environment jsdom
//
// A row in the VLANs, Circuits and Cabling lenses opens the object's own page
// (DCIM gap 7), carrying the lens URL in router state so Back returns to the
// lens with its query.
//
// Mutation: put `set('circuit', c.id)` back in the Circuits row handler → the
// circuit case fails (the location stays on the lens).
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock('../../../lib/clients', () => ({
  clients: new Proxy({}, { get: () => ({ GET: mocks.get, POST: vi.fn(), PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() }) }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { VlansLens } from '../ipam/vlans-lens';
import { CircuitsLens } from '../circuits/circuits-lens';
import { CablingLens } from '../cabling/cabling-lens';
import { cable, ref } from '../cabling/cabling-test-kit';

const NOW = new Date().toISOString();
const base = { tenant_id: 't', description: null, comments: null, source_kind: 'declared', source_ref: null, custom_fields: {}, external_ids: {}, created_at: NOW, updated_at: NOW, created_by: null };
const page = (rows: unknown[]) => ({ data: { data: rows, pagination: { total: rows.length, limit: 200, offset: 0, next_offset: null } } });
const ROWS: Record<string, unknown[]> = {
  '/ipam/vlans': [{ ...base, id: 'v10', vid: 10, name: 'voice', group_id: null, site_id: null, business_unit_id: null, operational_status: 'active', status: 'active', prefixes: [] }],
  '/circuits/circuits': [{ ...base, id: 'c1', cid: 'CKT-1', provider_id: 'p', type_id: 't', operational_status: 'active', commit_rate_kbps: null, terminations: [] }],
  '/dcim/cables': [cable({ id: 'cab1', label: 'P-1', a_terminations: [ref({})], b_terminations: [ref({ termination_id: 'u' })] })],
};

function Where() {
  const l = useLocation();
  return <div data-testid="where">{l.pathname}{l.search}|{JSON.stringify(l.state)}</div>;
}

let host: HTMLDivElement; let root: Root;
beforeEach(() => {
  mocks.get.mockReset();
  mocks.get.mockImplementation(async (path: string) => page(ROWS[path] ?? []));
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

describe.each([
  ['VLANs', '/inventory?lens=vlans&group=g9', VlansLens, 'vlan-row', '/inventory/vlans/v10'],
  ['Circuits', '/inventory?lens=circuits&status=active', CircuitsLens, 'circuit-row', '/inventory/circuits/c1'],
  ['Cabling', '/inventory?lens=cabling&site=s1', CablingLens, 'cable-row', '/inventory/cables/cab1'],
] as const)('%s lens', (_n, start, Lens, rowId, target) => {
  it('a row opens the object page and remembers the lens query', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    qc.setQueryData(['user-permissions'], ['ipam.read', 'circuits.read', 'dcim.read']);
    await act(async () => {
      root.render(
        <QueryClientProvider client={qc}><PermissionProvider><MemoryRouter initialEntries={[start]}>
          <Routes>
            <Route path="/inventory" element={<Lens />} />
            <Route path="*" element={<Where />} />
          </Routes>
        </MemoryRouter></PermissionProvider></QueryClientProvider>,
      );
    });
    await act(async () => { await new Promise((r) => setTimeout(r, 30)); });
    const row = host.querySelector(`[data-testid="${rowId}"]`) as HTMLElement;
    expect(row).not.toBeNull();
    await act(async () => { row.click(); });
    const where = host.querySelector('[data-testid="where"]')?.textContent ?? '';
    expect(where.startsWith(target + '|')).toBe(true);
    expect(where).toContain(JSON.stringify({ from: start }));
  });
});

describe.each([
  ['VLANs', '/inventory?lens=vlans&vlan=v10', VlansLens, 'vlan-open-page', '/inventory/vlans/v10'],
  ['Circuits', '/inventory?lens=circuits&circuit=c1', CircuitsLens, 'circuit-open-page', '/inventory/circuits/c1'],
  ['Cabling', '/inventory?lens=cabling&cable=cab1', CablingLens, 'cable-open-page', '/inventory/cables/cab1'],
] as const)('%s quick look', (_n, start, Lens, linkId, target) => {
  it('its title links to the object page', async () => {
    mocks.get.mockImplementation(async (path: string) => (path.endsWith('/trace') ? { data: { data: { object: { kind: 'interface', id: 'i', name: 'e' }, paths: [] } } } : path === '/dcim/cables/{id}' ? { data: { data: ROWS['/dcim/cables'][0] } } : page(ROWS[path] ?? [])));
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    qc.setQueryData(['user-permissions'], ['ipam.read', 'circuits.read', 'dcim.read']);
    await act(async () => {
      root.render(
        <QueryClientProvider client={qc}><PermissionProvider><MemoryRouter initialEntries={[start]}>
          <Routes><Route path="/inventory" element={<Lens />} /></Routes>
        </MemoryRouter></PermissionProvider></QueryClientProvider>,
      );
    });
    await act(async () => { await new Promise((r) => setTimeout(r, 30)); });
    expect(host.querySelector(`[data-testid="${linkId}"]`)!.getAttribute('href')).toBe(target);
  });
});
