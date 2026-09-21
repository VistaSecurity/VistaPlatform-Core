// @vitest-environment jsdom
//
// The provisional panel, MOUNTED, in every state it can be in.
//
// The two assertions that matter most are negative ones. When no collector can
// reach the device's network the panel must say what to DO about it — a person
// looking at a row that will never improve on its own needs the instruction,
// not a status. And when a collector CAN reach it, the panel must not print
// that instruction: telling someone to deploy a sensor they already have is how
// a UI trains its reader to ignore it.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { ProvisionalIdentityPanel } from './provisional-identity-panel';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));

type Observation = inventoryComponents['schemas']['IdentityObservation'];

const base: Observation = {
  id: 'obs-1',
  source_kind: 'measured',
  source_ref: 'sensor:11111111-1111-1111-1111-111111111111',
  collector_version: 'rc.13',
  network_scope: '198.51.100.0/24',
  evidence: { admission: { relayed: true }, identifiers: [{ kind: 'hostname', value: 'crossvlan-printer.local' }] },
  admission_reasons: ['unverified_relayed_advertisement'],
  state: 'unresolved',
  asset_id: 'asset-1',
  proposal_id: null,
  first_seen_at: '2026-09-20T14:02:00Z',
  last_seen_at: '2026-09-20T14:02:00Z',
  occurrence_count: 3,
  enrichment_state: 'blocked',
  enrichment_reason: 'no_eligible_collector_in_target_network',
  last_attempt_at: null,
  next_attempt_at: '2026-09-21T10:00:00Z',
  collector: {
    observer: { sensor_id: '11111111-1111-1111-1111-111111111111', name: 'xps16-sensor-1', reachable: false, reason: 'collector_has_no_interface_in_target_network' },
    executor: null,
    reason: 'no_eligible_collector_in_target_network',
  },
};

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

async function mount() {
  await act(async () => {
    root.render(<MemoryRouter><QueryClientProvider client={cache}><ProvisionalIdentityPanel assetID="asset-1" /></QueryClientProvider></MemoryRouter>);
  });
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 10)); });
}

function answer(observations: Observation[]) {
  api.GET.mockResolvedValue({ response: { ok: true }, data: { observations, total: observations.length, page: 1, page_size: 5 } });
}

it('asks only for the unresolved observations of this asset', async () => {
  answer([base]);
  await mount();
  expect(api.GET).toHaveBeenCalledWith('/discovery/observations', {
    params: { query: { asset_id: 'asset-1', state: 'unresolved', page: 1, page_size: 5 } },
  });
});

it('announces loading and offers a retry when the evidence cannot be read', async () => {
  let resolve!: (v: unknown) => void;
  api.GET.mockReturnValue(new Promise((r) => { resolve = r; }));
  await act(async () => {
    root.render(<MemoryRouter><QueryClientProvider client={cache}><ProvisionalIdentityPanel assetID="asset-1" /></QueryClientProvider></MemoryRouter>);
  });
  expect(host.querySelector('[role="status"]')?.textContent).toContain('Loading the evidence');
  await act(async () => { resolve({ response: { ok: false }, data: undefined }); await new Promise((r) => setTimeout(r, 10)); });
  expect(host.querySelector('[role="alert"]')?.textContent).toContain('could not be loaded');
  expect([...host.querySelectorAll('button')].some((b) => b.textContent === 'Retry')).toBe(true);
});

it('says so honestly when nothing is linked, rather than inventing a collector', async () => {
  answer([]);
  await mount();
  expect(host.textContent).toContain('No observation is currently linked to this provisional item.');
  expect(host.textContent).toContain('This item was created from an advertisement that no collector has verified directly.');
  expect(host.textContent).not.toContain('Deploy a sensor');
});

it('names the advertising sensor, why it cannot check, and what to do about it', async () => {
  answer([base]);
  await mount();
  expect(host.textContent).toContain('This item was created from an advertisement that no collector has verified directly.');
  expect(host.textContent).toContain('Advertised by xps16-sensor-1 (reflected mDNS,');
  expect(host.textContent).toContain('The observing collector has no interface on the observed network.');
  // The whole point of the panel: an instruction, not a status.
  expect(host.textContent).toContain('No collector currently reaches this network. Deploy a sensor on the observed network to continue.');
  expect(host.textContent).toContain('Approving this item monitors it; its identity stays provisional until a collector on its network corroborates it or you confirm it.');
  const link = host.querySelector('a');
  expect(link?.getAttribute('href')).toBe('/discovery/observations?observation_id=obs-1');
  expect(link?.textContent).toBe('Inspect discovery evidence');
});

it('stops telling the tenant to deploy a sensor once one can run the work', async () => {
  answer([{ ...base, collector: { ...base.collector!, executor: { sensor_id: '22222222-2222-2222-2222-222222222222', name: 'vlan-b-sensor' }, reason: '' } }]);
  await mount();
  expect(host.textContent).toContain('Enrichment can run through vlan-b-sensor.');
  expect(host.textContent).not.toContain('Deploy a sensor');
  // The OBSERVER is still the one that heard it, and still cannot reach it.
  // Provenance and capability are different facts and both stay on screen.
  expect(host.textContent).toContain('Advertised by xps16-sensor-1');
  expect(host.textContent).toContain('The observing collector has no interface on the observed network.');
});

it('describes a non-relayed sensor observation as what it was', async () => {
  answer([{ ...base, evidence: { admission: { direct: false } } }]);
  await mount();
  expect(host.textContent).toContain('(passive observation,');
  expect(host.textContent).not.toContain('reflected mDNS');
});

it('says when the next attempt is, and says "Not scheduled" rather than a fake date', async () => {
  answer([base]);
  await mount();
  expect(host.textContent).toContain('Next attempt:');
  expect(host.textContent).not.toContain('Next attempt: Not scheduled');
  answer([{ ...base, next_attempt_at: null }]);
  cache.clear();
  await mount();
  expect(host.textContent).toContain('Next attempt: Not scheduled');
});

it('explains an exhausted allowance as a promotion refusal, not a lost sighting', async () => {
  answer([{ ...base, admission_reasons: ['asset_allowance_exhausted'] }]);
  await mount();
  expect(host.textContent).toContain('Direct evidence was found, but this item cannot be established because the asset allowance is exhausted.');
});

it('does not claim a network it could not resolve', async () => {
  answer([{ ...base, collector: null }]);
  await mount();
  expect(host.textContent).toContain('This item was created from an advertisement that no collector has verified directly.');
  expect(host.textContent).toContain('Network placement could not be resolved for this observation.');
  expect(host.textContent).not.toContain('Deploy a sensor');
  expect(host.textContent).not.toContain('Advertised by');
  expect(host.querySelector('a')?.getAttribute('href')).toBe('/discovery/observations?observation_id=obs-1');
});
