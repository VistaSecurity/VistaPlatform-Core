// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, it } from 'vitest';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { ObservationDetails } from './observation-details';

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
