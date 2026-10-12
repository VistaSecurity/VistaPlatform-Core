// @vitest-environment jsdom
//
// Selecting a device rewrites the URL, which re-renders NetworkMapView. Tiles
// are memoised and fed a stable `onSelect`, so only the previously and newly
// selected tile may re-render — not every tile on the map. Each Tile renders
// exactly one 16px class Icon (nothing else in this view uses that size), so
// counting those counts Tile renders.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { NetworkMap } from './network-map-model';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
vi.setConfig({ testTimeout: 15_000 });

const tileRenders = vi.hoisted(() => ({ n: 0 }));

vi.mock('../../components/ui', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../components/ui')>();
  const React = await import('react');
  return {
    ...real,
    Icon: (props: React.ComponentProps<typeof real.Icon>) => {
      if (props.size === 16) tileRenders.n += 1;
      return React.createElement(real.Icon, props);
    },
  };
});

vi.mock('./network-map-exploded', () => ({ ExplodedDevice: () => null }));

const COUNT = 80;
const SEG = '00000000-0000-4000-8000-0000000000aa';
const id = (i: number): string => `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`;
const noPqc = { needs_migration: 0, pqc_ready: 0, symmetric_safe: 0, unclassified: 0 };

const MAP: NetworkMap = {
  segments: [{ segment_id: SEG, name: 'Office LAN', value: '10.0.0.0/24', segment_type: 'cidr', gateway: null }],
  assets: Array.from({ length: COUNT }, (_, i) => ({
    asset_id: id(i + 1), display_name: `host-${i}`, class_key: 'server', address: `10.0.0.${i + 1}`,
    asset_status: 'monitoring', site: 'Head office', segment_id: SEG,
    risk_score: 0, risk_assessed: false, service_count: 0, crypto_service_count: 0,
    crypto: { components: [], pqc: noPqc, certs_expiring_90d: 0 },
  })),
  total_assets: COUNT,
  truncated: false,
  asset_cap: 5000,
};

vi.mock('./relationship-queries', () => ({
  useNetworkMap: () => ({ data: MAP, isLoading: false, isError: false, error: null, refetch: () => {} }),
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

it('re-renders only the tiles whose selection changed', async () => {
  const { NetworkMapView } = await import('./network-map-view');
  await act(async () => {
    root.render(<MemoryRouter><NetworkMapView /></MemoryRouter>);
  });
  const tiles = () => [...host.querySelectorAll<HTMLButtonElement>('[data-testid="network-map-tile"]')];
  expect(tiles()).toHaveLength(COUNT);
  expect(tileRenders.n).toBeGreaterThanOrEqual(COUNT);

  let before = tileRenders.n;
  await act(async () => { tiles()[3].click(); });
  expect(tiles()[3].getAttribute('aria-pressed')).toBe('true');
  expect(tileRenders.n - before).toBeLessThanOrEqual(2);

  before = tileRenders.n;
  await act(async () => { tiles()[7].click(); });
  expect(tiles()[7].getAttribute('aria-pressed')).toBe('true');
  expect(tiles()[3].getAttribute('aria-pressed')).toBe('false');
  const moved = tileRenders.n - before;
  expect(moved).toBeGreaterThanOrEqual(2);
  expect(moved).toBeLessThanOrEqual(2);
});
