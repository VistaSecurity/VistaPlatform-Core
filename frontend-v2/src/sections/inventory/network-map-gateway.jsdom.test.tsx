// @vitest-environment jsdom
//
// slice C: Inventory → Map → Network shows each network's REAL gateway,
// and "gateway not recorded" only where the API says null. Driven through the
// real map shell, in both layouts that draw a network row (Funnel and Circuit).
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { groupSites, type NetworkMap, type NetworkMapAsset } from './network-map-model';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
vi.setConfig({ testTimeout: 15_000 });

class StubResizeObserver {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}
vi.stubGlobal('ResizeObserver', StubResizeObserver);

const ROUTED = '00000000-0000-4000-8000-0000000000aa';
const UNROUTED = '00000000-0000-4000-8000-0000000000bb';
const ROUTER = '00000000-0000-4000-8000-000000000001';
const LONG_NAME = 'core-gateway-building-4-east-wing-primary-ha-member-a';

const quiet = { components: [], pqc: { needs_migration: 0, pqc_ready: 0, symmetric_safe: 0, unclassified: 0 }, certs_expiring_90d: 0 };
function device(id: string, name: string, segment: string | undefined, address: string): NetworkMapAsset {
  return {
    asset_id: id, display_name: name, class_key: 'server', address, asset_status: 'monitoring', site: 'Head office',
    segment_id: segment, risk_score: 0, risk_assessed: false, service_count: 0, crypto_service_count: 0, crypto: quiet,
  };
}

const MAP: NetworkMap = {
  segments: [
    {
      segment_id: ROUTED, name: 'Lab v6', value: '2001:db8:10::/64', segment_type: 'cidr',
      gateway: { asset_id: ROUTER, display_name: LONG_NAME, address: '2001:db8:10::1/128', observed_at: '2026-10-03T00:00:00Z' },
    },
    { segment_id: UNROUTED, name: 'Guest', value: '198.51.100.0/24', segment_type: 'cidr', gateway: null },
  ],
  assets: [
    device(ROUTER, LONG_NAME, ROUTED, '2001:db8:10::1'),
    device('00000000-0000-4000-8000-000000000002', 'guest-laptop', UNROUTED, '198.51.100.20'),
    device('00000000-0000-4000-8000-000000000003', 'loose-device', undefined, '192.0.2.50'),
  ],
  total_assets: 3,
  truncated: false,
  asset_cap: 5000,
};

vi.mock('./relationship-queries', () => ({
  useNetworkMap: () => ({ data: MAP, isLoading: false, isError: false, error: null, refetch: () => {} }),
  useAssetNeighbourhood: () => ({ data: undefined, isLoading: true, isError: false, error: null, refetch: () => {} }),
  useAssetImpact: () => ({ data: undefined, isLoading: false, isError: false, error: null }),
  useAssetTopology: () => ({ data: undefined, isLoading: true, isError: false, error: null }),
}));
vi.mock('./asset-queries', async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useAssetsQuery: () => ({ data: { assets: [] }, isLoading: false, isError: false, error: null }),
}));

let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  try { window.localStorage.clear(); } catch { /* not needed */ }
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root.unmount());
  host.remove();
});

async function settle(until: () => boolean, ms = 8000): Promise<void> {
  const end = Date.now() + ms;
  while (!until() && Date.now() < end) {
    await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
  }
}

async function render(): Promise<void> {
  const { MapShell } = await import('./map-shell');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root.render(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={['/inventory?lens=map']}><MapShell /></MemoryRouter>
      </QueryClientProvider>,
    );
  });
  await settle(() => host.querySelectorAll('[data-testid="network-map-tray"]').length > 0);
}

function trayText(name: string): Element {
  const tray = [...host.querySelectorAll('[data-testid="network-map-tray"]')].find((t) => t.textContent?.includes(name));
  expect(tray, `no tray named ${name}`).toBeTruthy();
  return tray!;
}

function assertGatewayLabels() {
  const routed = trayText('Lab v6');
  const label = routed.querySelector('[data-testid="network-map-gateway"]');
  expect(label?.textContent).toContain(LONG_NAME);
  // The address without its host mask.
  expect(label?.textContent).toContain('(2001:db8:10::1)');
  expect(label?.querySelector('a')?.getAttribute('href')).toBe(`/inventory/assets/${ROUTER}`);
  expect(routed.textContent).not.toContain('gateway not recorded');

  const unrouted = trayText('Guest');
  expect(unrouted.querySelector('[data-testid="network-map-gateway"]')).toBeNull();
  expect(unrouted.querySelector('[data-testid="network-map-gateway-missing"]')?.textContent).toContain('gateway not recorded');

  // A tray that is not a network says nothing about a gateway at all.
  const loose = trayText('Unsegmented');
  expect(loose.querySelector('[data-testid="network-map-gateway"], [data-testid="network-map-gateway-missing"]')).toBeNull();
}

it('labels a network with its recorded gateway and an unrouted one honestly (Funnel)', async () => {
  await render();
  assertGatewayLabels();
});

it('labels the network rows the same way in the Circuit layout', async () => {
  await render();
  const btn = [...(host.querySelector('[data-testid="network-map-view-select"]')?.querySelectorAll('button') ?? [])].find((b) => b.textContent === 'Circuit')!;
  await act(async () => { btn.click(); });
  const circuit = host.querySelector('[data-testid="network-map-circuit"]')!;
  expect(circuit).not.toBeNull();
  const labels = [...circuit.querySelectorAll('[data-testid="network-map-gateway"]')];
  expect(labels).toHaveLength(1);
  expect(labels[0].textContent).toContain(LONG_NAME);
  expect(circuit.querySelectorAll('[data-testid="network-map-gateway-missing"]')).toHaveLength(1);
});

it('carries each network\'s gateway onto its tray, and none onto a non-network tray', () => {
  const trays = groupSites(MAP, MAP.assets ?? []).flatMap((s) => s.trays);
  expect(trays.find((t) => t.segmentId === ROUTED)?.gateway?.asset_id).toBe(ROUTER);
  expect(trays.find((t) => t.segmentId === UNROUTED)?.gateway).toBeNull();
  expect(trays.find((t) => t.segmentId === null)?.gateway).toBeNull();
});
