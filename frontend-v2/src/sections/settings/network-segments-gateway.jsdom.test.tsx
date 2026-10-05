// @vitest-environment jsdom
//
// slice C: Settings → Network Segments gains a Gateway column and a
// Coverage column. Drives the REAL page; the decisions are pinned in
// `inventory/segment-gateway.test.ts`.
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { NetworkSegmentsPage } from './pages-infra';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));
vi.mock('@vistasecurity/primitives/rbac', () => ({
  TENANT_PERMISSIONS: { settings: { update: 'settings.update' } },
  PermissionGate: ({ fallback }: { children: ReactNode; fallback?: ReactNode }) => fallback ?? null,
}));

const ROUTER = '00000000-0000-4000-8000-0000000000a1';
const base = {
  tenant_id: 't', segment_type: 'cidr', environment: 'production', location_id: null, is_active: true,
  auto_approve_discoveries: false, tags: null, metadata: {}, network_type: 'private', dynamic: null, dynamic_source: null,
  created_at: '2026-10-03T00:00:00Z', updated_at: '2026-10-03T00:00:00Z',
};
const gateway = { asset_id: ROUTER, display_name: 'edge-router', address: '192.0.2.1', observed_at: '2026-10-03T00:00:00Z' };
const segments = [
  { ...base, id: 'covered', name: 'Office LAN', value: '192.0.2.0/24', gateway,
    coverage: { sensor_id: '00000000-0000-4000-8000-0000000000d1', sensor_name: 'office-sensor' } },
  { ...base, id: 'dark', name: 'Cameras', value: '198.51.100.0/24', gateway: { ...gateway, address: '198.51.100.1' }, coverage: null },
  { ...base, id: 'v6', name: 'Lab v6', value: '2001:db8:10::/64',
    gateway: { ...gateway, address: '2001:db8:10::1/128' }, coverage: null },
  // No device has reported it — or the device that did was deleted, which the
  // server reports the same way.
  { ...base, id: 'orphan', name: 'Declared DMZ', value: '203.0.113.0/24', gateway: null, coverage: null },
  { ...base, id: 'range', name: 'Printers', segment_type: 'ip_range', value: '192.0.2.100-192.0.2.150', gateway: null, coverage: null },
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
  await act(async () => {
    root.render(
      <QueryClientProvider client={cache}>
        <MemoryRouter><NetworkSegmentsPage meta={meta} /></MemoryRouter>
      </QueryClientProvider>,
    );
  });
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); });
}

/** The row element that holds a segment named `name`. */
function row(name: string): Element {
  const cell = [...host.querySelectorAll('span')].find((s) => s.textContent === name);
  expect(cell, `no row named ${name}`).toBeTruthy();
  let el: Element | null = cell!;
  while (el && !el.querySelector('[data-testid="coverage-note"]')) el = el.parentElement;
  expect(el, `no row element for ${name}`).toBeTruthy();
  return el!;
}

it('has Gateway and Coverage columns', async () => {
  await render();
  expect(host.textContent).toContain('Gateway');
  expect(host.textContent).toContain('Coverage');
});

it('names the gateway with its address, linking to its asset page', async () => {
  await render();
  const link = row('Office LAN').querySelector('[data-testid="gateway-link"]');
  expect(link?.textContent).toContain('edge-router');
  expect(link?.textContent).toContain('(192.0.2.1)');
  expect(link?.querySelector('a')?.getAttribute('href')).toBe(`/inventory/assets/${ROUTER}`);
  // When it was reported is one hover away.
  expect(link?.querySelector('a')?.getAttribute('title')).toMatch(/Reported by an interrogation .+ ago/);
});

it('shows an IPv6 gateway address without its host mask', async () => {
  await render();
  const text = row('Lab v6').querySelector('[data-testid="gateway-link"]')?.textContent ?? '';
  expect(text).toContain('2001:db8:10::1');
  expect(text).not.toContain('/128');
});

it('shows a dash with the reason when no gateway is recorded', async () => {
  await render();
  const r = row('Declared DMZ');
  expect(r.querySelector('[data-testid="gateway-link"]')).toBeNull();
  const missing = r.querySelector('[data-testid="segment-gateway-missing"]');
  expect(missing?.textContent).toBe('—');
  expect(missing?.getAttribute('title')).toMatch(/No device has reported being this network's gateway/);
});

it('names the sensor that reaches a network, and says so plainly when none does', async () => {
  await render();
  expect(row('Office LAN').querySelector('[data-testid="coverage-note"]')?.textContent).toBe('Sensor: office-sensor');
  const dark = row('Cameras').querySelector('[data-testid="coverage-note"]');
  expect(dark?.getAttribute('data-coverage')).toBe('none');
  expect(dark?.textContent).toBe('No sensor on this network');
});

it('does not call a non-CIDR segment uncovered', async () => {
  await render();
  const note = row('Printers').querySelector('[data-testid="coverage-note"]');
  expect(note?.getAttribute('data-coverage')).toBe('not-applicable');
  expect(note?.textContent).toBe('—');
  expect(host.textContent?.match(/No sensor on this network/g)).toHaveLength(3);
});
