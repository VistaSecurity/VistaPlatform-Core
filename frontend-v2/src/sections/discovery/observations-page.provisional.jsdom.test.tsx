// @vitest-environment jsdom
//
// Discovery → Observations, for the two shapes introduced.
//
// The link is the load-bearing part. An `unresolved` observation that already
// carries an `asset_id` is not "unlinked evidence" — it is the evidence a
// provisional inventory item was built from, and the observation stays
// unresolved on purpose so enrichment keeps working on it. Calling that "Open
// linked asset" would have said the identity question was settled; showing both
// links would have said it twice, differently.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { ObservationsPage } from './observations-page';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));
vi.mock('./observation-actions', () => ({ ObservationActions: () => null }));

type Observation = inventoryComponents['schemas']['IdentityObservation'];

const observation: Observation = {
  id: 'obs-1',
  source_kind: 'measured',
  source_ref: 'sensor:aaaa',
  collector_version: 'rc.13',
  network_scope: '198.51.100.0/24',
  evidence: { admission: { relayed: true }, identifiers: [{ kind: 'hostname', value: 'crossvlan-printer.local' }] },
  admission_reasons: ['unverified_relayed_advertisement'],
  state: 'unresolved',
  asset_id: 'asset-1',
  proposal_id: null,
  first_seen_at: '2026-09-20T14:02:00Z',
  last_seen_at: '2026-09-20T14:02:00Z',
  occurrence_count: 2,
  enrichment_state: 'blocked',
  enrichment_reason: 'no_eligible_collector_in_target_network',
  last_attempt_at: null,
  next_attempt_at: null,
  collector: {
    observer: { sensor_id: 'aaaa', name: 'sensor-a', reachable: false, reason: 'collector_has_no_interface_in_target_network' },
    executor: null,
    reason: 'no_eligible_collector_in_target_network',
  },
};

const summary = { established: 1, operator_confirmed: 0, legacy: 0, unresolved: 1, conflicted: 0, provisional: 1, admission_mode: 'enforce' };

let host: HTMLDivElement;
let root: Root;
let cache: QueryClient;
beforeEach(() => {
  api.GET.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function render(observations: Observation[]) {
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/identity/summary') return { response: { ok: true }, data: summary };
    return { response: { ok: true }, data: { observations, total: observations.length, page: 1, page_size: 50 } };
  });
  await act(async () => {
    root.render(<MemoryRouter initialEntries={['/discovery/observations']}>
      <QueryClientProvider client={cache}><ObservationsPage /></QueryClientProvider>
    </MemoryRouter>);
  });
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 10)); });
}

function hrefs(): string[] {
  return [...host.querySelectorAll('a')].map((a) => a.getAttribute('href') ?? '');
}

it('leads an unresolved observation to the provisional item it produced', async () => {
  await render([observation]);
  expect(host.textContent).toContain('Provisional inventory item:');
  const link = [...host.querySelectorAll('a')].find((a) => a.textContent === 'Open provisional item');
  expect(link?.getAttribute('href')).toBe('/inventory/assets/asset-1');
  // Exactly one asset link, and it is not the settled-identity wording.
  expect(host.textContent).not.toContain('Open linked asset');
  expect(hrefs().filter((h) => h === '/inventory/assets/asset-1')).toHaveLength(1);
});

it('keeps the settled wording for an observation whose identity IS settled', async () => {
  await render([{ ...observation, state: 'linked' }]);
  expect(host.textContent).toContain('Open linked asset');
  expect(host.textContent).not.toContain('Provisional inventory item');
});

it('does not promise an item for an unresolved observation that produced none', async () => {
  await render([{ ...observation, asset_id: null }]);
  expect(host.textContent).not.toContain('Provisional inventory item');
  expect(hrefs().some((h) => h.startsWith('/inventory/assets/'))).toBe(false);
});

it('shows collector reachability on the card, for every observation that has one', async () => {
  await render([observation]);
  expect(host.querySelector('[aria-label="Collector reachability"]')).not.toBeNull();
  expect(host.textContent).toContain('Observed bysensor-a — cannot reach this network');
  expect(host.textContent).toContain('Enrichment executorNone available');
});

it('omits the block entirely when the observation has no resolvable network', async () => {
  await render([{ ...observation, collector: null }]);
  expect(host.querySelector('[aria-label="Collector reachability"]')).toBeNull();
});

it('explains an exhausted allowance as a promotion refusal, not a dropped sighting', async () => {
  await render([{ ...observation, admission_reasons: ['asset_allowance_exhausted'] }]);
  expect(host.textContent).toContain('Direct evidence was found, but the asset allowance is exhausted; the item stays provisional.');
  expect(host.textContent).not.toContain('asset allowance exhausted');
});

it('counts provisional items in the coverage strip and filters Inventory to them', async () => {
  await render([observation]);
  const link = [...host.querySelectorAll('a')].find((a) => a.textContent === '1 provisional items');
  expect(link, 'the coverage strip names the provisional count').toBeTruthy();
  // `?query=` is the inventory page's ONE filter. The predicate names the
  // statuses as well as the identity, because the list endpoint defaults to
  // monitoring-only when nothing constrains status — and a provisional item is
  // pending approval by construction, so the count would lead to an empty list.
  const href = link!.getAttribute('href')!;
  expect(decodeURIComponent(href)).toBe('/inventory?query=(status:pending_approval or status:monitoring) and identity_status:provisional');
});
