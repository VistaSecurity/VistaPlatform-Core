// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, it } from 'vitest';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { CollectorReachability, ObservationDetails } from './observation-details';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let host: HTMLDivElement; let root: Root;
beforeEach(() => { host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host); });
afterEach(() => { act(() => root.unmount()); host.remove(); });
const observation: inventoryComponents['schemas']['IdentityObservation'] = {
  id: 'observation', source_kind: 'measured', source_ref: 'sensor:one', collector_version: 'rc.11', network_scope: 'segment',
  evidence: {}, admission_reasons: ['insufficient_identity_evidence'], state: 'unresolved', asset_id: null, proposal_id: null,
  first_seen_at: '2026-09-18T10:00:00Z', last_seen_at: '2026-09-18T10:00:00Z', occurrence_count: 1,
  enrichment_state: 'blocked', enrichment_reason: 'collector_capability_missing', last_attempt_at: null, next_attempt_at: null,
  enrichment_jobs: [{ id: 'job', action: 'dns', executor_scope: 'sensor:one', state: 'blocked', reason: 'collector_capability_missing', attempts: 0, last_attempt_at: null, next_attempt_at: '2026-09-19T10:00:00Z' }],
  retained_evidence: { total: 51, limit: 50, has_more: true, items: [{
    kind: 'crypto', scope: 'source_context', source_ref: 'sensor:one', observed_at: null, collector_version: 'rc.11', materialization_state: 'pending',
    facts_count: 2, software_count: 0, endpoints_count: 2, relationships_count: 1, protocols: ['TLS', 'SSH'], certificates_count: 2,
    certificates: [{ sha256_fingerprint: 'a'.repeat(64), expired: true, self_signed: true }], keys_count: 1, crypto_configurations_count: 2,
  }] },
};
it('shows retained security evidence without treating source context as established device facts', () => {
  act(() => root.render(<ObservationDetails observation={observation} />));
  expect(host.textContent).toContain('Retained — awaiting identity or approval');
  expect(host.textContent).toContain('not all attributable to this device');
  expect(host.textContent).toContain('TLS, SSH');
  expect(host.textContent).toContain('expired · self-signed');
  expect(host.textContent).toContain('Showing 1 certificate examples');
  expect(host.textContent).toContain('of 51 retained receipts');
  expect(host.textContent).toContain('ObservedNot recorded');
  expect(host.textContent).toContain('rc.11');
});
it('explains unsupported collectors and separates next attempts from actual observation times', () => {
  act(() => root.render(<ObservationDetails observation={observation} />));
  expect(host.textContent).toContain('Update it or use a suitable collector in the same network');
  expect(host.textContent).toContain('Scoped name resolution · blocked');
  expect(host.textContent).toContain('Last attemptNot recorded');
  expect(host.textContent).toContain('Next eligible attempt');
});
it('distinguishes no retained details from unavailable server summaries', () => {
  act(() => root.render(<ObservationDetails observation={{ ...observation, retained_evidence: undefined, enrichment_jobs: [] }} />));
  expect(host.textContent).toContain('unavailable from this server');
  expect(host.textContent).toContain('No enrichment attempts');
  act(() => root.render(<ObservationDetails observation={{ ...observation, retained_evidence: { items: [], total: 0, limit: 50, has_more: false } }} />));
  expect(host.textContent).toContain('No additional inventory or security details');
});
it('distinguishes an online collector outside the target network from an offline collector', () => {
  const job = observation.enrichment_jobs![0];
  act(() => root.render(<ObservationDetails observation={{ ...observation, enrichment_jobs: [{ ...job, reason: 'collector_has_no_interface_in_target_network' }] }} />));
  expect(host.textContent).toContain('collector is online');
  expect(host.textContent).toContain('Reflected advertisements');
  act(() => root.render(<ObservationDetails observation={{ ...observation, enrichment_jobs: [{ ...job, reason: 'observing_collector_offline' }] }} />));
  expect(host.textContent).toContain('offline or its heartbeat is stale');
});

// ---- collector reachability ( D7/D8) ---------------------------------
//
// Observer and executor are DIFFERENT collectors and the block exists to stop
// them being read as one. Before the only collector on screen was the
// source ref, which a reader naturally took to mean "the thing that can go and
// check" — and for a reflected advertisement it is exactly the thing that
// cannot.
const collector = { observer: { sensor_id: 'observer-id', name: 'sensor-a', reachable: false, reason: 'collector_has_no_interface_in_target_network' }, executor: null, reason: 'no_eligible_collector_in_target_network' };

it('separates who heard the evidence from who can act on it', () => {
  act(() => root.render(<CollectorReachability collector={{ ...collector, executor: { sensor_id: 'executor-id', name: 'sensor-b' }, reason: '' }} />));
  expect(host.textContent).toContain('Observed bysensor-a — cannot reach this network');
  expect(host.textContent).toContain('The observing collector has no interface on the observed network.');
  expect(host.textContent).toContain('Enrichment executorsensor-b');
  // An executor exists, so there is nothing in the way and the block says
  // nothing about it rather than repeating the observer's problem as a block.
  expect(host.textContent).not.toContain('Why no collector can act');
});

it('names the missing executor and the action that supplies one', () => {
  act(() => root.render(<CollectorReachability collector={collector} />));
  expect(host.textContent).toContain('Enrichment executorNone available');
  expect(host.textContent).toContain('Why no collector can act');
  expect(host.textContent).toContain('No collector currently reaches this network. Deploy a sensor on the observed network to continue.');
});

it('says a reachable observer is reachable, without a reason it does not have', () => {
  act(() => root.render(<CollectorReachability collector={{ observer: { sensor_id: 'observer-id', name: 'sensor-a', reachable: true, reason: '' }, executor: { sensor_id: 'observer-id', name: 'sensor-a' }, reason: '' }} />));
  expect(host.textContent).toContain('Observed bysensor-a — reachable');
  expect(host.textContent).not.toContain('cannot reach');
});

it('keeps the long-form enrichment guidance separate from the short block phrase', () => {
  // Same reason, two audiences. The job list explains what an operator can DO
  // about a blocked attempt; the block answers "what is true of this collector".
  // Collapsing them would have deleted the only place the interface advice
  // appears.
  const job = observation.enrichment_jobs![0];
  act(() => root.render(<ObservationDetails observation={{ ...observation, enrichment_jobs: [{ ...job, reason: 'collector_has_no_interface_in_target_network' }] }} />));
  expect(host.textContent).toContain('review its interface configuration');
  act(() => root.render(<CollectorReachability collector={collector} />));
  expect(host.textContent).not.toContain('review its interface configuration');
});
