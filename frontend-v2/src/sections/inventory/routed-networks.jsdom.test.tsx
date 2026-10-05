// @vitest-environment jsdom
//
// slice C: the asset page's "Networks routed" card and the host's
// "via <gateway>" line, driven through the REAL AssetPage (Overview tab).
//
// `segment-gateway.test.ts` pins the decisions; this pins that the page renders
// them — deleting the card, its null check or the via line turns this red.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Asset } from '@vistasecurity/api-contract';
import { AssetPage } from './asset-page';
import type { RoutedSegment, SegmentGateway } from './segment-gateway';

// The page renders the Active Scan button, which reads the query client; none of
// these tests reads a query through it.
const queryClient = new QueryClient();

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const state = vi.hoisted(() => ({ asset: {} as Asset }));
vi.mock('./asset-queries', async (importOriginal) => ({
  ...await importOriginal<typeof import('./asset-queries')>(),
  useAsset: () => ({ data: state.asset }),
  useAssetIdentifiers: () => ({ data: state.asset.identifiers }),
}));
vi.mock('../findings/queries', async (importOriginal) => ({
  ...await importOriginal<typeof import('../findings/queries')>(),
  useAssetFindings: () => ({ data: [] }),
}));
vi.mock('@vistasecurity/primitives/rbac', async (importOriginal) => ({
  ...await importOriginal<typeof import('@vistasecurity/primitives/rbac')>(),
  PermissionGate: () => null,
}));

const ROUTER = '00000000-0000-4000-8000-0000000000a1';
const HOST = '00000000-0000-4000-8000-0000000000b1';
const SEG_V4 = '00000000-0000-4000-8000-0000000000c1';
const SEG_V6 = '00000000-0000-4000-8000-0000000000c2';
const SEG_RANGE = '00000000-0000-4000-8000-0000000000c3';
const LONG_NAME = 'Building 4 east wing laboratory instrumentation network (isolated)';

const v4: RoutedSegment = {
  segment_id: SEG_V4, name: 'Office LAN', value: '192.0.2.0/24', segment_type: 'cidr', address: '192.0.2.1',
  observed_at: '2026-10-03T00:00:00Z', vlan_id: 10, dynamic: true, host_count: 1234,
  coverage: { sensor_id: '00000000-0000-4000-8000-0000000000d1', sensor_name: 'office-sensor' },
};
const v6: RoutedSegment = {
  segment_id: SEG_V6, name: LONG_NAME, value: '2001:db8:10::/64', segment_type: 'cidr', address: '2001:db8:10::1/128',
  observed_at: '2026-10-03T00:00:00Z', vlan_id: null, dynamic: null, host_count: 3, coverage: null,
};
const range: RoutedSegment = {
  segment_id: SEG_RANGE, name: 'Printers', value: '198.51.100.10-198.51.100.40', segment_type: 'ip_range', address: '198.51.100.1',
  observed_at: '2026-10-03T00:00:00Z', vlan_id: 30, dynamic: false, host_count: 0, coverage: null,
};

const gw: SegmentGateway = { asset_id: ROUTER, display_name: 'edge-router', address: '192.0.2.1', observed_at: '2026-10-03T00:00:00Z' };

let container: HTMLDivElement;
let root: Root;
beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

function render(asset: Partial<Asset>) {
  state.asset = { class_key: 'router', ...asset } as Asset;
  act(() => {
    root.render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={[`/inventory/assets/${asset.id}`]}>
          <Routes><Route path="/inventory/assets/:id" element={<AssetPage />} /></Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
  });
}

const $ = (sel: string) => container.querySelector(sel);
const $$ = (sel: string) => [...container.querySelectorAll(sel)];

describe('Networks routed card', () => {
  it('lists every network the asset routes, with each column the spec names', () => {
    render({ id: ROUTER, routed_segments: [v4, v6, range] });
    const card = $('[data-testid="routed-networks"]');
    expect(card).not.toBeNull();
    expect(card?.textContent).toContain('Networks routed (3)');
    const rows = $$('[data-testid="routed-network-row"]');
    expect(rows).toHaveLength(3);

    const office = rows[0].textContent ?? '';
    expect(office).toContain('Office LAN');
    expect(office).toContain('192.0.2.0/24');
    expect(office).toContain('192.0.2.1');
    expect(office).toContain('10');
    expect(office).toContain('DHCP');
    expect(office).toContain('1,234');
    expect(office).toContain('Sensor: office-sensor');
    expect($('[data-testid="routed-networks-error"]')).toBeNull();
  });

  it('links each host count to the existing segment_id: Inventory query', () => {
    render({ id: ROUTER, routed_segments: [v4] });
    const link = $$('[data-testid="routed-network-row"] a').find((a) => a.textContent === '1,234');
    expect(link?.getAttribute('href')).toBe(`/inventory?lens=assets&query=${encodeURIComponent(`segment_id:${SEG_V4}`)}`);
  });

  it('handles an IPv6 network, a long name, no VLAN tag, unknown DHCP and no sensor', () => {
    render({ id: ROUTER, routed_segments: [v6] });
    const row = $('[data-testid="routed-network-row"]')!;
    // The full name is one hover away even when the cell ellipsizes it.
    expect(row.querySelector(`[title="${LONG_NAME}"]`)).not.toBeNull();
    // The host mask is not shown on a gateway's own address.
    expect(row.textContent).toContain('2001:db8:10::1');
    expect(row.textContent).not.toContain('/128');
    expect(row.textContent).toContain('Untagged');
    expect(row.textContent).toContain('Unknown');
    const note = row.querySelector('[data-testid="coverage-note"]');
    expect(note?.getAttribute('data-coverage')).toBe('none');
    expect(note?.textContent).toBe('No sensor on this network');
  });

  it('does not call a non-CIDR network uncovered', () => {
    render({ id: ROUTER, routed_segments: [range] });
    const note = $('[data-testid="routed-network-row"] [data-testid="coverage-note"]');
    expect(note?.getAttribute('data-coverage')).toBe('not-applicable');
    expect($('[data-testid="routed-network-row"]')?.textContent).not.toContain('No sensor');
    expect($('[data-testid="routed-network-row"]')?.textContent).toContain('Static');
  });

  it('is not rendered at all for an asset that routes nothing', () => {
    render({ id: HOST, class_key: 'workstation', routed_segments: [] });
    expect($('[data-testid="routed-networks"]')).toBeNull();
    expect(container.textContent).not.toContain('Networks routed');
  });

  it('says it could not load when the field is ABSENT, rather than showing an empty card', () => {
    render({ id: ROUTER });
    expect($('[data-testid="routed-networks"]')).not.toBeNull();
    expect($('[data-testid="routed-networks-error"]')?.textContent).toContain("Couldn't load routed networks");
    expect($$('[data-testid="routed-network-row"]')).toHaveLength(0);
    // The rest of the Overview is still there.
    expect(container.textContent).toContain('Identity');
  });
});

describe('"via <gateway>" on a host', () => {
  it('shows the gateway beside the host\'s network, linking to the gateway', () => {
    render({ id: HOST, class_key: 'workstation', network_segment_name: 'Office LAN', segment_gateway: gw, routed_segments: [] });
    const line = $('[data-testid="network-segment-via"]');
    expect(line?.textContent).toContain('Office LAN');
    expect(line?.textContent).toContain('via');
    expect(line?.textContent).toContain('edge-router');
    expect(line?.textContent).toContain('(192.0.2.1)');
    expect(line?.querySelector('a')?.getAttribute('href')).toBe(`/inventory/assets/${ROUTER}`);
  });

  it('is absent when the host\'s network has no recorded gateway', () => {
    render({ id: HOST, class_key: 'workstation', network_segment_name: 'Office LAN', routed_segments: [] });
    expect($('[data-testid="network-segment-via"]')).toBeNull();
    expect(container.textContent).toContain('Office LAN');
    expect(container.textContent).not.toContain('via edge-router');
  });

  it('is absent on the gateway itself, even if the server named it', () => {
    render({ id: ROUTER, network_segment_name: 'Office LAN', segment_gateway: gw, routed_segments: [v4] });
    expect($('[data-testid="network-segment-via"]')).toBeNull();
  });
});
