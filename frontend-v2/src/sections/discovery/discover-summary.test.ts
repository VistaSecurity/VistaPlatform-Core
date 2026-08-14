import { readFileSync } from 'node:fs';
import { describe, it, expect } from 'vitest';
import { describeMaterialization } from './discover-summary';

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
