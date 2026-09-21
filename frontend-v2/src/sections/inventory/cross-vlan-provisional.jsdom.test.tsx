// @vitest-environment jsdom
//
// The cross-VLAN provisional journey ( §1), driven through the REAL pages.
//
// Every layer of this feature has tests of its own and none of them would have
// noticed the thing that makes it a feature: that the row you see in Inventory,
// the panel you read on the asset page, and the observation you open from
// Discovery are all about the SAME item, before and after a second sensor
// corroborates it. That is the promise — "no duplicate and no lost history" —
// and it is a promise about identity across three pages, so it is tested across
// three pages.
//
// Two phases, one asset id, one fixture that flips between them:
//
//   phase 1 — a sensor on VLAN A repeated an advert about a device on VLAN B.
//             Nothing can reach VLAN B. The item is provisional.
//   phase 2 — a sensor on VLAN B saw the device. The SAME id is established,
//             both sensors' observations are on it, and the first-seen time is
//             still the moment the advert was heard.
//
// The assertion that the asset id never changes is the one that would catch a
// re-implementation that "promotes" by creating a new row, which is exactly
// what a projection-based design would have had to do.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter, Route, Routes } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { inventoryComponents } from '@vistasecurity/api-contract';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

type Observation = inventoryComponents['schemas']['IdentityObservation'];

const ASSET_ID = '3f2a6c1e-0000-4000-8000-00000000abcd';
const ADVERT_SEEN = '2026-09-20T14:02:00Z';

const phase = vi.hoisted(() => ({ provisional: true }));

const asset = () => ({
  id: ASSET_ID,
  tenant_id: 'tenant',
  class_key: 'printer',
  class_path: 'hardware.peripheral.printer',
  class_source_kind: 'measured',
  display_name: 'crossvlan-printer.local',
  hostname: 'crossvlan-printer.local',
  primary_address: '198.51.100.7',
  asset_status: 'pending_approval',
  identity_status: phase.provisional ? 'provisional' : 'established',
  attributes: {},
  identifiers: [{ kind: 'hostname', value: 'crossvlan-printer.local', source_kind: 'measured' }],
  tags: {},
  first_discovered_at: ADVERT_SEEN,
  last_seen_at: ADVERT_SEEN,
});

const advert: Observation = {
  id: 'obs-advert',
  source_kind: 'measured',
  source_ref: 'sensor:aaaaaaaa-0000-4000-8000-000000000001',
  collector_version: 'rc.13',
  network_scope: '198.51.100.0/24',
  evidence: { admission: { relayed: true }, identifiers: [{ kind: 'hostname', value: 'crossvlan-printer.local' }] },
  admission_reasons: ['unverified_relayed_advertisement'],
  state: 'unresolved',
  asset_id: ASSET_ID,
  proposal_id: null,
  first_seen_at: ADVERT_SEEN,
  last_seen_at: ADVERT_SEEN,
  occurrence_count: 4,
  enrichment_state: 'blocked',
  enrichment_reason: 'no_eligible_collector_in_target_network',
  last_attempt_at: null,
  next_attempt_at: null,
  collector: {
    observer: { sensor_id: 'aaaaaaaa-0000-4000-8000-000000000001', name: 'crossvlan-sensor-a', reachable: false, reason: 'collector_has_no_interface_in_target_network' },
    executor: null,
    reason: 'no_eligible_collector_in_target_network',
  },
};

// Phase 2: the advert is now linked (it backs an established asset) and the
// direct sighting from Sensor B sits beside it. The advert's `first_seen_at` is
// UNCHANGED — corroboration touches an asset, it does not restart its history.
const direct: Observation = {
  ...advert,
  id: 'obs-direct',
  source_ref: 'sensor:bbbbbbbb-0000-4000-8000-000000000002',
  evidence: { admission: { direct: true }, identifiers: [{ kind: 'hostname', value: 'crossvlan-printer.local' }] },
  admission_reasons: [],
  state: 'linked',
  first_seen_at: '2026-09-20T16:40:00Z',
  last_seen_at: '2026-09-20T16:40:00Z',
  enrichment_state: 'completed',
  enrichment_reason: '',
  collector: {
    observer: { sensor_id: 'bbbbbbbb-0000-4000-8000-000000000002', name: 'crossvlan-sensor-b', reachable: true, reason: '' },
    executor: { sensor_id: 'bbbbbbbb-0000-4000-8000-000000000002', name: 'crossvlan-sensor-b' },
    reason: '',
  },
};

function observations(): Observation[] {
  return phase.provisional ? [advert] : [{ ...advert, state: 'linked' }, direct];
}

const summary = () => ({
  established: phase.provisional ? 0 : 1,
  operator_confirmed: 0,
  legacy: 0,
  unresolved: phase.provisional ? 1 : 0,
  conflicted: 0,
  provisional: phase.provisional ? 1 : 0,
  admission_mode: 'enforce',
});

// One dispatcher, used by every page in the journey. Anything not named here
// answers an empty-but-valid shape, so a page that grew a new call does not
// silently fail this test with a network error that looks like a UI bug.
const inventoryGet = vi.hoisted(() => vi.fn());
const complianceGet = vi.hoisted(() => vi.fn());
vi.mock('../../lib/clients', () => ({
  clients: {
    inventory: { GET: inventoryGet, POST: vi.fn(), PUT: vi.fn(), DELETE: vi.fn() },
    compliance: { GET: complianceGet },
  },
}));
vi.mock('@vistasecurity/primitives/rbac', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@vistasecurity/primitives/rbac')>()),
  PermissionGate: () => null,
  usePermissions: () => ({ hasPermission: () => false, hasAnyPermission: () => false, permissions: [] }),
}));

import { InventoryPage } from './inventory-page';
import { AssetPage } from './asset-page';
import { ObservationsPage } from '../discovery/observations-page';

function ok(data: unknown) {
  return { data, error: undefined, response: { ok: true, status: 200 } };
}

beforeEach(() => {
  phase.provisional = true;
  complianceGet.mockReset().mockResolvedValue(ok({ findings: [] }));
  inventoryGet.mockReset().mockImplementation(async (path: string, init?: { params?: { path?: { id?: string } } }) => {
    switch (path) {
      case '/identity/summary': return ok(summary());
      case '/infrastructure-assets':
        return ok({ assets: [asset()], pagination: { total: 1, page: 1, page_size: 50 } });
      case '/infrastructure-assets/{id}':
        return init?.params?.path?.id === ASSET_ID
          ? ok({ asset: asset() })
          : { data: undefined, error: { error: 'not found' }, response: { ok: false, status: 404 } };
      case '/infrastructure-assets/{id}/identifiers': return ok({ identifiers: asset().identifiers });
      case '/infrastructure-assets/{id}/endpoints': return ok({ endpoints: [] });
      case '/infrastructure-assets/facets': return ok({ facets: {} });
      case '/saved-views': return ok({ saved_views: [] });
      case '/discovery/observations': return ok({ observations: observations(), total: observations().length, page: 1, page_size: 50 });
      case '/discovery/observations/{id}': {
        const id = init?.params?.path?.id;
        const found = observations().find((o) => o.id === id);
        return found ? ok(found) : { data: undefined, error: { error: 'not found' }, response: { ok: false, status: 404 } };
      }
      default:
        return ok({ assets: [], observations: [], items: [], total: 0, pagination: { total: 0, page: 1, page_size: 50 } });
    }
  });
});

let host: HTMLDivElement;
let root: Root;
let cache: QueryClient;
beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function show(entry: string) {
  cache.clear();
  await act(async () => {
    // `key={entry}` remounts the router. `initialEntries` is read once, on
    // mount: without the key, re-rendering the same root with a new entry
    // leaves the router on the previous page and every assertion below would
    // be made against the page we navigated AWAY from.
    root.render(<MemoryRouter key={entry} initialEntries={[entry]}>
      <QueryClientProvider client={cache}>
        <Routes>
          <Route path="/inventory" element={<InventoryPage />} />
          <Route path="/inventory/assets/:id" element={<AssetPage />} />
          <Route path="/inventory/assets/:id/:tab" element={<AssetPage />} />
          <Route path="/discovery/observations" element={<ObservationsPage />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>);
  });
  for (let i = 0; i < 6; i++) await act(async () => { await new Promise((r) => setTimeout(r, 10)); });
  return host.textContent ?? '';
}

function links(): { href: string; text: string }[] {
  return [...host.querySelectorAll('a')].map((a) => ({ href: a.getAttribute('href') ?? '', text: a.textContent ?? '' }));
}

it('phase 1: the advertised device is inventory, labelled as unverified, and says what would settle it', async () => {
  // Inventory → All assets. The row is an ordinary asset row; the label is the
  // only thing that says it is hearsay.
  const list = await show('/inventory?lens=assets');
  expect(list).toContain('crossvlan-printer.local');
  expect(list).toContain('Provisional identity — unverified');
  expect(host.querySelector('[data-identity="provisional"]')).not.toBeNull();

  // The asset page explains itself: who said so, who cannot check, what to do.
  const page = await show(`/inventory/assets/${ASSET_ID}`);
  expect(page).toContain('This item was created from an advertisement that no collector has verified directly.');
  expect(page).toContain('Advertised by crossvlan-sensor-a (reflected mDNS,');
  expect(page).toContain('No collector currently reaches this network. Deploy a sensor on the observed network to continue.');
  const evidence = links().find((l) => l.text === 'Inspect discovery evidence');
  expect(evidence?.href).toBe('/discovery/observations?observation_id=obs-advert');

  // …and the evidence leads back to the SAME item, by id.
  const obs = await show('/discovery/observations?observation_id=obs-advert');
  expect(obs).toContain('Provisional inventory item:');
  const back = links().find((l) => l.text === 'Open provisional item');
  expect(back?.href).toBe(`/inventory/assets/${ASSET_ID}`);
});

it('phase 2: a sensor on the device’s own VLAN establishes the SAME item, keeping its history', async () => {
  phase.provisional = false;

  const page = await show(`/inventory/assets/${ASSET_ID}`);
  expect(page).toContain('Identity established');
  expect(page).not.toContain('Provisional identity — unverified');
  // The panel is gone, not merely re-worded: an established item has no
  // provisional explanation to give.
  expect(page).not.toContain('This item was created from an advertisement');
  expect(page).not.toContain('Deploy a sensor on the observed network');

  const list = await show('/inventory?lens=assets');
  expect(list).toContain('Identity established');
  expect(host.querySelector('[data-identity="provisional"]')).toBeNull();

  // Both sensors' observations are on the item, and the advert still carries
  // the time it was first heard — corroboration adds evidence, it does not
  // restart the record.
  const obs = await show(`/discovery/observations?asset_id=${ASSET_ID}`);
  expect(obs).toContain('sensor:aaaaaaaa-0000-4000-8000-000000000001');
  expect(obs).toContain('sensor:bbbbbbbb-0000-4000-8000-000000000002');
  expect(obs).toContain(new Date(ADVERT_SEEN).toLocaleString());
  expect(obs).toContain('Open linked asset');
  expect(obs).not.toContain('Provisional inventory item');
  for (const l of links().filter((x) => x.href.startsWith('/inventory/assets/'))) {
    expect(l.href, 'every asset link on the evidence page points at the one item').toBe(`/inventory/assets/${ASSET_ID}`);
  }
});
