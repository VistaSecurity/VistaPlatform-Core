// Editing an asset's identifiers, now that the server honours them.
//
// The form has always sent an `identifiers` array; until gate1 B6 the server
// dropped it on the floor, so the edit was a silent no-op that reported
// "saved". With the write path live, the form's side of the contract matters:
// what it shows, what it sends, and what it says when the server keeps
// something the save asked to remove.
import { describe, expect, it } from 'vitest';
import type { Asset } from '@vistasecurity/api-contract';
import { identifiersToRows, identifierUpdateError, keptIdentifiersMessage } from './asset-form-modal';
import { identifierLockReason, isEditableIdentifier } from './class-picker';

const asset = {
  id: 'a1',
  identifiers: [
    { kind: 'hostname', value: 'web-01', source_kind: 'declared', scope: 'seg-1', confidence: 1, first_seen_at: '', last_seen_at: '' },
    { kind: 'ip_address', value: '10.0.0.1', source_kind: 'measured', scope: 'seg-1', confidence: 1, first_seen_at: '', last_seen_at: '' },
    { kind: 'agent_id', value: 'agt-77', source_kind: 'measured', confidence: 1, first_seen_at: '', last_seen_at: '' },
    { kind: 'cloud_resource_id', value: 'arn:aws:s3:::payments', source_kind: 'measured', confidence: 1, first_seen_at: '', last_seen_at: '' },
  ],
} as unknown as Asset;

describe('identifiersToRows (gate1 C3)', () => {
  it('shows EVERY identifier, collector-minted ones included', () => {
    // They used to be filtered out entirely, so the asset looked like it had
    // fewer ways of being known than it has — and an agent id the form never
    // mentioned still decides every future match.
    expect(identifiersToRows(asset).map((r) => r.kind)).toEqual([
      'hostname', 'ip_address', 'agent_id', 'cloud_resource_id',
    ]);
  });

  it('carries each identifier’s source and scope, which is what decides editability', () => {
    const rows = identifiersToRows(asset);
    expect(rows[0]).toEqual({ kind: 'hostname', value: 'web-01', sourceKind: 'declared', scope: 'seg-1' });
    expect(rows[2].sourceKind).toBe('measured');
  });

  it('copes with an asset that has no identifiers at all', () => {
    expect(identifiersToRows(null)).toEqual([]);
    expect(identifiersToRows({ id: 'x' } as unknown as Asset)).toEqual([]);
  });
});

describe('isEditableIdentifier (gate1 C3)', () => {
  it('lets a person edit what a person declared', () => {
    expect(isEditableIdentifier({ kind: 'hostname', value: 'web-01', sourceKind: 'declared' })).toBe(true);
  });

  it('locks a collector-minted kind whatever its source says', () => {
    // The server applies exactly this rule, and reports what it KEPT. A remove
    // button here would produce a click that reads as saved and changes nothing.
    expect(isEditableIdentifier({ kind: 'agent_id', value: 'agt-77', sourceKind: 'declared' })).toBe(false);
    expect(isEditableIdentifier({ kind: 'cloud_resource_id', value: 'arn:…', sourceKind: 'declared' })).toBe(false);
  });

  it('locks anything measured, imported or inferred', () => {
    for (const src of ['measured', 'imported', 'inferred']) {
      expect(isEditableIdentifier({ kind: 'ip_address', value: '10.0.0.1', sourceKind: src })).toBe(false);
    }
  });

  it('treats a brand-new row — no source yet — as the person’s own', () => {
    expect(isEditableIdentifier({ kind: 'serial_number', value: 'J7K2QX1' })).toBe(true);
  });

  it('says why a row is locked, in the same terms the server uses', () => {
    expect(identifierLockReason({ kind: 'agent_id', value: 'x', sourceKind: 'measured' }))
      .toMatch(/issued by a collector/i);
    expect(identifierLockReason({ kind: 'ip_address', value: 'x', sourceKind: 'measured' }))
      .toMatch(/measured collection/i);
  });
});

describe('keptIdentifiersMessage (gate1 C3)', () => {
  it('names what was kept and repeats the server’s reason', () => {
    const msg = keptIdentifiersMessage([
      { kind: 'agent_id', value: 'agt-77', reason: 'issued by a collector, not by a person' },
    ]);
    expect(msg).toContain('agent_id agt-77');
    expect(msg).toContain('issued by a collector');
  });

  it('says how many when there are several, without listing them all', () => {
    const msg = keptIdentifiersMessage([
      { kind: 'agent_id', value: 'a' }, { kind: 'ip_address', value: 'b' },
      { kind: 'fqdn', value: 'c' }, { kind: 'mac_address', value: 'd' },
    ]);
    expect(msg).toContain('Kept 4 identifiers');
    expect(msg).toContain('and 1 more');
  });

  it('is empty when the server kept nothing, so nothing is shown', () => {
    expect(keptIdentifiersMessage([])).toBe('');
  });
});

describe('identifierUpdateError (gate1 C3)', () => {
  it('sends the operator to Approvals when the refusal opened a merge proposal', () => {
    const msg = identifierUpdateError({
      message: 'identifier hostname="web-01" already belongs to asset b2; merge proposal p9 was opened for review',
      merge_proposal_id: 'p9',
    });
    expect(msg).toContain('Approvals');
    expect(msg).toContain('nothing was merged');
  });

  it('does not invent a proposal when there is none', () => {
    expect(identifierUpdateError({ message: 'class_key is not a known class' }))
      .toBe('class_key is not a known class');
  });

  it('has something to say about an error with no message at all', () => {
    expect(identifierUpdateError(undefined)).toBe('Failed to update asset');
  });
});
