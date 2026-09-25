// @vitest-environment jsdom
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { NetworkSegmentsPage } from './pages-infra';

// The WIRING test for learned-segment provenance: the helper is pinned by
// segment-provenance.test.ts, and this pins that the Network Segments page
// actually renders it — replacing the name cell with a plain name must fail.
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));
vi.mock('@vistasecurity/primitives/rbac', () => ({
  TENANT_PERMISSIONS: { settings: { update: 'settings.update' } },
  PermissionGate: ({ fallback }: { children: ReactNode; fallback?: ReactNode }) => fallback ?? null,
}));

const base = {
  tenant_id: 't', segment_type: 'cidr', environment: 'production', location_id: null, is_active: true,
  auto_approve_discoveries: false, tags: null, created_at: '2026-09-24T00:00:00Z', updated_at: '2026-09-24T00:00:00Z',
};
const segments = [
  { ...base, id: 'learned', name: 'port1.100', value: '10.20.30.0/24', network_type: 'private',
    metadata: { source: 'interrogation', source_device_type: 'fortinet', source_asset_id: 'a1', dhcp: 'unknown' } },
  { ...base, id: 'legacy', name: 'LAN', value: '192.168.10.0/24', network_type: 'private',
    metadata: { source: 'unifi', dynamic: true } },
  { ...base, id: 'declared', name: 'Operator DMZ', value: '198.51.100.0/24', network_type: 'public',
    metadata: { operator: 'keep', dynamic: true } },
];

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  api.GET.mockReset().mockResolvedValue({ data: { network_segments: segments }, response: { ok: true } });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function render() {
  const meta = { key: 'network-segments', label: 'Network Segments', icon: 'network', job: 'Segments' };
  await act(async () => { root.render(<QueryClientProvider client={cache}><NetworkSegmentsPage meta={meta} /></QueryClientProvider>); });
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); });
}

function rowText(name: string): string {
  const cell = [...host.querySelectorAll('span')].find((s) => s.textContent === name);
  expect(cell, `no row named ${name}`).toBeTruthy();
  return cell!.parentElement!.textContent ?? '';
}

it('labels a learned segment with its device and an unknown DHCP posture', async () => {
  await render();
  expect(rowText('port1.100')).toContain('Learned from Fortinet · DHCP unknown');
  expect(rowText('LAN')).toContain('Learned from UniFi · DHCP on');
});

it('shows no provenance line for a declared segment', async () => {
  await render();
  expect(rowText('Operator DMZ')).not.toContain('Learned');
  expect(host.textContent?.match(/Learned from/g)?.length).toBe(2);
});
