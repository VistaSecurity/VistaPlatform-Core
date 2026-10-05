import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  BULK_FAILURE_COPY, CHIPS, DEFAULT_CHIP, EXPLANATIONS, MAX_BULK, MAX_REASON, NEEDS_LABEL, batchReason, bulkFailureMessage,
  canBulkConfirm, canBulkDismiss, canBulkLink, hostLabel, linkLabel, loadView, needsLabel, networkLabel, nextNonEmptyChip, proposedReason,
  saveView, serviceChips, stableIdentifierNote, type Observation,
} from './observation-review';

const ready = { state: 'unresolved', needs: 'ready_to_confirm', suggested_action: 'confirm' } as const;
const network = { state: 'unresolved', needs: 'needs_network', suggested_action: 'add_network' } as const;

describe('bulk rules (D4)', () => {
  it('offers Confirm only for an all-ready selection', () => {
    expect(canBulkConfirm([ready, ready])).toBe(true);
    expect(canBulkConfirm([ready, network])).toBe(false);
    expect(canBulkConfirm([network])).toBe(false);
    expect(canBulkConfirm([])).toBe(false);
    // Ready by needs but no longer unresolved: not confirmable.
    expect(canBulkConfirm([{ ...ready, state: 'linked' }])).toBe(false);
  });
  it('offers Dismiss for any selection, within the ceiling', () => {
    expect(canBulkDismiss([ready, network])).toBe(true);
    expect(canBulkDismiss([])).toBe(false);
    expect(canBulkDismiss(Array.from({ length: MAX_BULK }, () => network))).toBe(true);
    expect(canBulkDismiss(Array.from({ length: MAX_BULK + 1 }, () => network))).toBe(false);
    expect(canBulkConfirm(Array.from({ length: MAX_BULK + 1 }, () => ready))).toBe(false);
  });
});

describe('bulk Link (#2205)', () => {
  const link = { state: 'unresolved', needs: 'link_existing', suggested_action: 'link', link_asset: { id: 'x', name: 'dream-router', linkable: true } } as const;
  it('is offered only for an all-link-suggestion selection that carries its owner', () => {
    expect(canBulkLink([link, link])).toBe(true);
    expect(canBulkLink([link, { ...ready, link_asset: null }])).toBe(false);
    expect(canBulkLink([{ ...link, link_asset: null }])).toBe(false);
    expect(canBulkLink([{ ...link, state: 'linked' }])).toBe(false);
    expect(canBulkLink([])).toBe(false);
    expect(canBulkLink(Array.from({ length: MAX_BULK + 1 }, () => link))).toBe(false);
    // And a link suggestion is never bulk-confirmable.
    expect(canBulkConfirm([{ ...link }])).toBe(false);
  });
  it('names the owner, or says "the existing asset" rather than an id', () => {
    expect(linkLabel(link)).toBe('Link to dream-router');
    expect(linkLabel({ link_asset: { id: 'x', name: ' ', linkable: true } })).toBe('Link to the existing asset');
    expect(linkLabel({ link_asset: null })).toBe('Link to the existing asset');
  });
  it('re-words a link sentence for another decision and drops its "— why" clause', () => {
    const o = { suggested_reason: 'Linked from Observations: SSH 22 seen at 192.0.2.4 — already belongs to dream-router.' };
    expect(proposedReason(o, 'link')).toBe(o.suggested_reason);
    expect(proposedReason(o, 'dismiss')).toBe('Dismissed from Observations: SSH 22 seen at 192.0.2.4.');
    expect(proposedReason(o, 'confirm')).toBe('Confirmed from Observations: SSH 22 seen at 192.0.2.4.');
  });
});

describe('plain words', () => {
  it('has a sentence for every explanation code and a label for every needs value', () => {
    // The Records are total over the contract's enums, so a new code fails
    // typecheck; this pins that no entry is an empty placeholder.
    for (const [code, e] of Object.entries(EXPLANATIONS)) {
      expect(e.why, code).toMatch(/\w/);
      if (code !== 'not_awaiting_review') expect(e.fix, code).toMatch(/\w/);
    }
    for (const label of Object.values(NEEDS_LABEL)) expect(label).toMatch(/\w/);
    expect(CHIPS[0].key).toBe(DEFAULT_CHIP);
    expect(DEFAULT_CHIP).toBe('ready_to_confirm');
  });
  it('labels a decided row by its state, an unresolved one by its need', () => {
    expect(needsLabel({ state: 'unresolved', needs: 'needs_sensor' })).toBe('Needs a sensor');
    expect(needsLabel({ state: 'linked', needs: 'none' })).toBe('Linked');
  });
  it('maps every failure code to its own words, and an unknown one to a generic sentence', () => {
    expect(bulkFailureMessage({ code: 'asset_allowance_reached', status: 402 })).toContain('asset allowance has been reached');
    expect(bulkFailureMessage({ code: 'observation_changed', status: 409 })).toBe('This changed since you looked — review it.');
    expect(bulkFailureMessage({ code: 'provisional_item_requires_merge_review', status: 409 })).toContain('merge review');
    expect(bulkFailureMessage({ code: 'not_ready_to_confirm', status: 422 })).toContain('review it on its own');
    expect(bulkFailureMessage({ code: 'not_found', status: 404 })).toContain('gone');
    expect(bulkFailureMessage({ code: undefined, status: 500 })).toBe('The decision could not be saved. Try again.');
    expect(new Set(Object.values(BULK_FAILURE_COPY)).size).toBe(Object.keys(BULK_FAILURE_COPY).length);
  });
  it('names a stable identifier only when the evidence carries one', () => {
    expect(stableIdentifierNote({ summary: [{ kind: 'ssh_host_key_fingerprint', label: 'SSH host key', value: 'SHA256:abc…xyz' }] }))
      .toBe('Its ssh host key (SHA256:abc…xyz) will recognise it next time.');
    expect(stableIdentifierNote({ summary: [{ kind: 'ip_address', label: 'IP address', value: '192.0.2.4' }] })).toBeNull();
  });
});

describe('names, never ids', () => {
  it('shows a neutral label for an unnamed network instead of its scope', () => {
    expect(networkLabel({ network_name: null })).toBe('No configured network');
    expect(networkLabel({ network_name: '  ' })).toBe('No configured network');
    expect(networkLabel({ network_name: 'Office LAN' })).toBe('Office LAN');
  });
  it('calls a host by its name, else its address, reading raw evidence when the summary is empty', () => {
    const summary: Observation['summary'] = [];
    expect(hostLabel({ summary, evidence: { identifiers: [{ kind: 'hostname', value: 'printer.local' }, { kind: 'ip_address', value: '192.0.2.9' }] } }))
      .toEqual({ primary: 'printer.local', secondary: '192.0.2.9' });
    expect(hostLabel({ summary, evidence: { endpoints: [{ address: '192.0.2.10', port: 22, protocol: 'ssh' }] } }))
      .toEqual({ primary: '192.0.2.10', secondary: '' });
    expect(hostLabel({ summary, evidence: {} }).primary).toBe('Unnamed device');
  });
  it('labels services the way the server sentence does', () => {
    expect(serviceChips({ evidence: { endpoints: [{ port: 22, protocol: 'ssh' }, { port: 8443, protocol: 'tls' }, { port: 161, transport: 'udp' }, { port: 22, protocol: 'ssh' }] } }))
      .toEqual(['SSH 22', 'TLS 8443', 'UDP 161']);
  });
});

describe('reasons (D1)', () => {
  const confirmable = { suggested_reason: 'Confirmed from Observations: SSH 22 seen at 192.0.2.4 on Office LAN (sensor-a).', explanation_code: 'dynamic_address_answered' } as const;
  const relayed = { suggested_reason: 'Dismissed from Observations: A device seen as tv.local (sensor-a) — advertised by another device; nothing here saw the device itself.', explanation_code: 'relayed_advertisement' } as const;
  it('uses the server sentence for the decision it was proposed for', () => {
    expect(proposedReason(confirmable, 'confirm')).toBe(confirmable.suggested_reason);
    expect(proposedReason(relayed, 'dismiss')).toBe(relayed.suggested_reason);
  });
  it('keeps what was seen and changes the verb for another decision', () => {
    expect(proposedReason(confirmable, 'dismiss')).toBe('Dismissed from Observations: SSH 22 seen at 192.0.2.4 on Office LAN (sensor-a).');
    // The "— why" clause argues for dismissing; it does not survive a confirm.
    expect(proposedReason(relayed, 'confirm')).toBe('Confirmed from Observations: A device seen as tv.local (sensor-a).');
    expect(proposedReason(relayed, 'link')).toBe('Linked from Observations: A device seen as tv.local (sensor-a).');
    expect(proposedReason({ suggested_reason: '' }, 'dismiss')).toBe('');
  });
  it('summarises a batch in one reason under the endpoint limit', () => {
    expect(batchReason([confirmable], 'confirm')).toBe(confirmable.suggested_reason);
    expect(batchReason([confirmable, confirmable, confirmable], 'confirm'))
      .toBe('Confirmed from Observations: SSH 22 seen at 192.0.2.4 on Office LAN (sensor-a), and 2 more like it.');
    expect(batchReason([confirmable, relayed], 'dismiss'))
      .toBe('Dismissed from Observations: SSH 22 seen at 192.0.2.4 on Office LAN (sensor-a), and 1 more.');
    const long = { ...confirmable, suggested_reason: `Confirmed from Observations: ${'x'.repeat(3000)}.` };
    const r = batchReason([long, long], 'confirm');
    expect(r.length).toBeLessThanOrEqual(MAX_REASON);
    expect(r.endsWith(', and 1 more like it.')).toBe(true);
    expect(batchReason([], 'confirm')).toBe('');
  });
});

describe('the next chip an empty view suggests', () => {
  const counts = { ready_to_confirm: 0, link_existing: 0, needs_review: 0, needs_network: 0, needs_sensor: 3, likely_noise: 5, all: 9 };
  it('picks the first other chip with rows', () => {
    expect(nextNonEmptyChip('ready_to_confirm', counts)).toBe('needs_sensor');
    expect(nextNonEmptyChip('needs_sensor', counts)).toBe('likely_noise');
    expect(nextNonEmptyChip('ready_to_confirm', { ...counts, needs_sensor: 0, likely_noise: 0 })).toBe('all');
    expect(nextNonEmptyChip('ready_to_confirm', { ready_to_confirm: 0, link_existing: 0, needs_review: 0, needs_network: 0, needs_sensor: 0, likely_noise: 0, all: 0 })).toBeNull();
    expect(nextNonEmptyChip('ready_to_confirm', undefined)).toBeNull();
  });
});

describe('the remembered view', () => {
  afterEach(() => { vi.unstubAllGlobals(); });
  it('falls back to Ready to confirm when storage throws, and saving never throws', () => {
    vi.stubGlobal('window', { localStorage: { getItem: () => { throw new Error('blocked'); }, setItem: () => { throw new Error('blocked'); } } });
    expect(loadView()).toEqual({ chip: 'ready_to_confirm', pageSize: 50 });
    expect(() => saveView({ chip: 'likely_noise', pageSize: 25 })).not.toThrow();
    vi.unstubAllGlobals();
  });
  it('ignores a stored value it does not recognise', () => {
    const store: Record<string, string> = { 'vista.observations.view': JSON.stringify({ chip: 'bogus', pageSize: 7 }) };
    vi.stubGlobal('window', { localStorage: { getItem: (k: string) => store[k] ?? null, setItem: (k: string, v: string) => { store[k] = v; } } });
    expect(loadView()).toEqual({ chip: 'ready_to_confirm', pageSize: 50 });
    saveView({ chip: 'needs_sensor', pageSize: 100 });
    expect(loadView()).toEqual({ chip: 'needs_sensor', pageSize: 100 });
    vi.unstubAllGlobals();
  });
});
