import { readFileSync } from 'node:fs';
import { describe, it, expect } from 'vitest';
import { describeMaterialization, findingsLabel, observationsNotice } from './discover-summary';

// The wizard used to end on an "Import N findings" button: it fetched the job's
// results into the browser and posted them back, choosing the approval status
// client-side. Findings now flow into inventory server-side, so the results step
// is terminal and its only job is to say honestly where they went.

const texts = (count: number, m?: Parameters<typeof describeMaterialization>[1]) =>
  describeMaterialization(count, m).parts.map((p) => p.text);

describe('describeMaterialization', () => {
  it('reports the split the spec asks for: found · auto-approved · awaiting approval', () => {
    expect(texts(5, { findings: 5, queued: 5, auto_approved: 3, pending_approval: 2, awaiting_processing: 0 }))
      .toEqual(['Found 5 findings', '3 auto-approved', '2 awaiting approval']);
  });

  it('says "still processing" rather than reporting an unfinished pipeline as zero', () => {
    const s = describeMaterialization(4, {
      findings: 4, queued: 4, auto_approved: 1, pending_approval: 0, awaiting_processing: 3,
    });
    expect(s.parts.map((p) => p.text)).toContain('3 still processing');
    expect(s.settling).toBe(true);
  });

  it('states an explicit zero when findings reached inventory but nothing landed', () => {
    const s = describeMaterialization(6, {
      findings: 6, queued: 0, auto_approved: 0, pending_approval: 0, awaiting_processing: 0,
    });
    // The find count survives — it is the job's own record and answers a
    // different question from "what is in my inventory".
    expect(s.parts[0].text).toBe('Found 6 findings');
    expect(s.parts.map((p) => p.text)).toContain('0 added to inventory');
    // …and the gap is explained rather than left as a silent contradiction.
    expect(s.note).toContain('6 findings did not become an inventory asset');
    expect(s.settling).toBe(false);
  });

  it('never renders unknown as zero', () => {
    const s = describeMaterialization(3, undefined);
    expect(s.parts.map((p) => p.text)).toEqual(['Found 3 findings']);
    expect(s.parts.map((p) => p.text)).not.toContain('0 added to inventory');
    expect(s.note).toContain('unavailable');
  });

  it('always states the one auto-approval rule', () => {
    const s = describeMaterialization(1, { findings: 1, queued: 1, auto_approved: 1, pending_approval: 0, awaiting_processing: 0 });
    expect(s.note).toContain('network segments with auto-approve enabled');
  });

  // Suppressed rows matched an asset the tenant already archived or denied —
  // nothing was added, and nothing is awaiting a decision either, so this must
  // read as neither "added to inventory" nor "awaiting approval".
  it('states suppressed findings separately from added or awaiting', () => {
    const s = describeMaterialization(4, {
      findings: 4, queued: 4, auto_approved: 1, pending_approval: 0, awaiting_processing: 0, suppressed: 3,
    });
    expect(texts(4, {
      findings: 4, queued: 4, auto_approved: 1, pending_approval: 0, awaiting_processing: 0, suppressed: 3,
    })).toContain('3 findings on denied or archived assets — not shown in Approvals');
    // Not the "0 added to inventory" fallback — 1 auto-approved is real.
    expect(s.parts.map((p) => p.text)).not.toContain('0 added to inventory');
  });

  it('a purely suppressed job does not fall back to "0 added to inventory"', () => {
    const s = describeMaterialization(2, {
      findings: 2, queued: 2, auto_approved: 0, pending_approval: 0, awaiting_processing: 0, suppressed: 2,
    });
    expect(s.parts.map((p) => p.text)).toContain('2 findings on denied or archived assets — not shown in Approvals');
    expect(s.parts.map((p) => p.text)).not.toContain('0 added to inventory');
  });
});

//: "Found 15" read as fifteen new assets; it was fifteen open ports on
// ten hosts, none of which became an asset (each was kept as an observation),
// and nothing said where they went.
describe('a finding count says what it counts', () => {
  it('open ports on hosts when the host count is known; plain findings otherwise', () => {
    expect(findingsLabel(15, 10)).toBe('15 open ports on 10 hosts');
    expect(findingsLabel(1, 1)).toBe('1 open port on 1 host');
    expect(findingsLabel(15, undefined)).toBe('15 findings');
    expect(texts(15, { findings: 15, finding_hosts: 10, queued: 15, auto_approved: 0, pending_approval: 0, awaiting_processing: 0, observed: 15 })[0])
      .toBe('Found 15 open ports on 10 hosts');
  });

  it('states the observations next to "0 added to inventory" — both are true', () => {
    expect(texts(15, { findings: 15, queued: 15, auto_approved: 0, pending_approval: 0, awaiting_processing: 0, observed: 15 }))
      .toEqual(['Found 15 findings', '15 kept as observations', '0 added to inventory']);
  });
});

describe('observationsNotice', () => {
  it('names how many findings on how many hosts, with DHCP only as an example, and points at Observations', () => {
    const n = observationsNotice({ findings: 15, queued: 15, observed: 15, observed_hosts: 10 });
    expect(n?.href).toBe('/discovery/observations');
    expect(n?.text).toBe(
      '15 findings on 10 hosts were kept as observations — they could not be tied to an asset yet (for example, on a network that uses DHCP an address alone does not identify a device).',
    );
    expect(n?.review).toBe('Review them in');
  });

  it('singular, and without the host count when the server did not send one', () => {
    const n = observationsNotice({ findings: 1, queued: 1, observed: 1 });
    expect(n?.text).toMatch(/^1 finding was kept as observations — it could not be tied/);
    expect(n?.review).toBe('Review it in');
  });

  it('nothing at zero, and nothing when the count is unknown (never a zero)', () => {
    expect(observationsNotice({ findings: 3, queued: 3, observed: 0 })).toBeUndefined();
    expect(observationsNotice({ findings: 3, queued: 3 })).toBeUndefined();
    expect(observationsNotice(undefined)).toBeUndefined();
  });
});

describe('the Discover wizard has no import step', () => {
  const source = readFileSync(new URL('./discover-modal.tsx', import.meta.url), 'utf8');

  it('does not call the import endpoint', () => {
    expect(source).not.toContain('/import');
  });

  it('does not send an approval status from the browser', () => {
    expect(source).not.toContain('asset_status');
    expect(source).not.toContain('auto_approve:');
  });

  it('has no "imported" phase — the results step is terminal', () => {
    expect(source).not.toContain("'imported'");
  });
});
