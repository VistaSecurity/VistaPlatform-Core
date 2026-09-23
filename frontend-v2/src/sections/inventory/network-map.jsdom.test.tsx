// @vitest-environment jsdom
//
// The WIRING for the Network view.
//
// `network-map-model.test.ts` pins the decisions. This drives the REAL map
// shell through the real lazy import, so deleting the tab, the lazy mount, the
// tile's click handler or the exploded view's data path turns something here
// red — the "helper with perfect tests and no call site" trap CLAUDE.md names.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { NetworkMap } from './network-map-model';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

// Above `settle`'s deadline, so a slow runner fails on the assertion that
// explains itself rather than on a bare timeout.
vi.setConfig({ testTimeout: 15_000 });

class StubResizeObserver {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}
vi.stubGlobal('ResizeObserver', StubResizeObserver);

const SEG = '00000000-0000-4000-8000-0000000000aa';
const ROUTER = '00000000-0000-4000-8000-000000000001';
const QUIET = '00000000-0000-4000-8000-000000000002';
const ENDPOINT = '00000000-0000-4000-8000-0000000000e1';
const CONFIG = '00000000-0000-4000-8000-0000000000c1';
const CERT = '00000000-0000-4000-8000-0000000000f1';

const noPqc = { needs_migration: 1, pqc_ready: 0, symmetric_safe: 0, unclassified: 0 };

const MAP: NetworkMap = {
  segments: [{ segment_id: SEG, name: 'Office LAN', value: '10.0.0.0/24', segment_type: 'cidr' }],
  assets: [
    {
      asset_id: ROUTER, display_name: 'edge-router', class_key: 'router', address: '10.0.0.1',
      asset_status: 'monitoring', site: 'Head office', segment_id: SEG,
      risk_score: 72, risk_assessed: true, service_count: 2, crypto_service_count: 1,
      crypto: {
        components: [
          { algorithm_type: 'signature', name: 'ssh-rsa (SHA-1)', strength: 'weak', is_pqc: false, observed: true },
          { algorithm_type: 'key_exchange', name: 'ecdhe', strength: 'strong', is_pqc: false, observed: true },
        ],
        pqc: noPqc,
        certs_expiring_90d: 0,
      },
    },
    {
      asset_id: QUIET, display_name: 'printer', class_key: 'printer', address: '10.0.0.9',
      asset_status: 'pending_approval', site: 'Head office', segment_id: SEG,
      risk_score: 0, risk_assessed: false, service_count: 0, crypto_service_count: 0,
      crypto: { components: [], pqc: { needs_migration: 0, pqc_ready: 0, symmetric_safe: 0, unclassified: 0 }, certs_expiring_90d: 0 },
    },
  ],
  total_assets: 2,
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
  useAssetEndpoints: () => ({
    data: [
      { id: ENDPOINT, port: 443, protocol: 'TLS', transport: 'tcp', service_name: 'HTTPS' },
      { id: 'ep-plain', port: 161, protocol: 'SNMP', transport: 'udp', service_name: 'snmp' },
    ],
    isLoading: false, isError: false, refetch: () => {},
  }),
  useAssetConfigs: () => ({
    data: [{ id: CONFIG, endpoint_id: ENDPOINT, certificate_id: CERT, key_size: 2048 }],
    isLoading: false, isError: false, refetch: () => {},
  }),
}));

vi.mock('../../lib/clients', () => ({
  clients: {
    inventory: {
      GET: async (path: string) => {
        if (path === '/crypto-configurations/{id}/components') {
          return {
            data: {
              components: [
                { algorithm_type: 'signature', name: 'ssh-rsa (SHA-1)', strength: 'weak', is_pqc: false, is_inferred: false },
                { algorithm_type: 'hash', name: 'hmac-sha1', strength: 'weak', is_pqc: false, is_inferred: true },
                { algorithm_type: 'hash', name: 'umac-128', strength: 'strong', is_pqc: false, is_inferred: true },
              ],
            },
          };
        }
        if (path === '/certificates/{id}') {
          return { data: { certificate: { id: CERT, common_name: 'edge.example', not_after: '2099-01-01T00:00:00Z' } } };
        }
        return { data: undefined, error: { error: 'unexpected' } };
      },
    },
  },
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

// Waits on a DEADLINE, not a try count: the first test pays for the lazy
// import of the view, which took 2.4s on a loaded CI runner while a 40×5ms
// loop gave up after ~200ms.
async function settle(until: () => boolean, ms = 8000): Promise<void> {
  const end = Date.now() + ms;
  while (!until() && Date.now() < end) {
    await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
  }
}

async function render(url: string): Promise<void> {
  const { MapShell } = await import('./map-shell');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root.render(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={[url]}>
          <MapShell />
        </MemoryRouter>
      </QueryClientProvider>,
    );
  });
}

const $ = (sel: string) => host.querySelector(sel);
const $$ = (sel: string) => [...host.querySelectorAll(sel)];

it('opens the map lens on the Network view, with a tab for it', async () => {
  await render('/inventory?lens=map');
  await settle(() => !!$('[data-testid="network-map-view"]'));
  expect($('[data-testid="map-view-network"]')?.getAttribute('aria-selected')).toBe('true');
  expect($('[data-testid="network-map-view"]')).not.toBeNull();
  // A small estate opens on every device (D1).
  expect($$('[data-testid="network-map-tile"]')).toHaveLength(2);
});

it('keeps an old focus= link out of the Network view', async () => {
  await render(`/inventory?lens=map&focus=${ROUTER}`);
  await settle(() => !!$('[data-testid="map-view-neighbourhood"][aria-selected="true"]'));
  expect($('[data-testid="map-view-neighbourhood"]')?.getAttribute('aria-selected')).toBe('true');
  expect($('[data-testid="network-map-view"]')).toBeNull();
});

it('badges devices by the server\'s assessment, not by a guess', async () => {
  await render('/inventory?lens=map');
  await settle(() => $$('[data-testid="network-map-tile"]').length > 0);
  const tones: Record<string, string | null> = Object.fromEntries($$('[data-testid="network-map-tile"]').map((t) => [t.getAttribute('aria-label')?.split(',')[0] ?? '', t.getAttribute('data-tone')]));
  expect(tones['edge-router']).toBe('high');
  // No services and no assessment: nothing to badge, not a zero.
  expect(tones.printer).toBe('none');
});

it('explodes a clicked device into its services and catalogue-assessed crypto', async () => {
  await render('/inventory?lens=map');
  await settle(() => $$('[data-testid="network-map-tile"]').length > 0);
  const tile = $$('[data-testid="network-map-tile"]').find((t) => t.getAttribute('aria-label')?.startsWith('edge-router'))!;
  await act(async () => { (tile as HTMLButtonElement).click(); });
  await settle(() => (($('[data-testid="exploded-service"]')?.textContent ?? '').includes('edge.example')));

  expect($('[data-testid="network-map-exploded"]')).not.toBeNull();
  const service = $('[data-testid="exploded-service"]')?.textContent ?? '';
  expect(service).toContain('443');
  expect(service).toContain('ssh-rsa (SHA-1)');
  // A weak option the server only OFFERS is shown, in different words.
  expect(service).toContain('also offers hmac-sha1');
  // A strong option it only offers is noise, and is not.
  expect(service).not.toContain('umac-128');
  expect(service).toContain('2048-bit key');
  expect(service).toContain('edge.example');
  // The endpoint with no crypto is collapsed, not dropped.
  expect($('[data-testid="exploded-plain"]')?.textContent).toContain('161');
});

it('groups devices by shared crypto, weakest first, in the By-crypto view', async () => {
  await render('/inventory?lens=map');
  await settle(() => !!$('[data-testid="network-map-view-select"]'));
  const btn = [...($('[data-testid="network-map-view-select"]')?.querySelectorAll('button') ?? [])].find((b) => b.textContent === 'By crypto')!;
  await act(async () => { btn.click(); });
  const rows = $$('[data-testid="network-map-trait"]').map((r) => r.textContent ?? '');
  expect(rows[0]).toContain('ssh-rsa (SHA-1)');
  // The strong, non-PQC component waits behind "show all".
  expect(rows.some((r) => r.includes('ecdhe'))).toBe(false);
});

it('summarises sites at the Sites zoom and focuses one on click', async () => {
  await render('/inventory?lens=map');
  await settle(() => !!$('[data-testid="network-map-zoom"]'));
  const sitesBtn = [...($('[data-testid="network-map-zoom"]')?.querySelectorAll('button') ?? [])].find((b) => b.textContent === 'Sites')!;
  await act(async () => { sitesBtn.click(); });
  const card = $('[data-testid="network-map-site-card"]') as HTMLButtonElement;
  expect(card.textContent).toContain('Head office');
  expect(card.textContent).toContain('2 devices');
  await act(async () => { card.click(); });
  expect($('[data-testid="network-map-crumbs"]')?.textContent).toContain('All sites');
  expect($('[data-testid="network-map-crumbs"]')?.textContent).toContain('Head office');
  // Focusing from the summary drops into the devices.
  expect($$('[data-testid="network-map-tile"]').length).toBe(2);
});
