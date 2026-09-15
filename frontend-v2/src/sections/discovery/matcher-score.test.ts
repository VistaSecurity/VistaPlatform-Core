// The learned matcher's UI surfaces (workstream 4.6): the score, its reasons,
// the auto-merged record, and the threshold control's wording.
//
// The wording tests are not decoration. The one thing this feature can get
// catastrophically wrong is telling a tenant that "0" is the LOOSEST setting
// when it is the strictest — a number that reads as a confidence floor rather
// than as OFF — so the sentence each value produces is pinned here.
import { describe, expect, it } from 'vitest';
import { factorDirection, scoreLabel, topReasons, TOP_REASONS_SHOWN } from './merge-proposal-row';
import { acceptedCandidate, isReviewed, remainingCandidates } from './auto-merged-section';
import {
  thresholdLabel, thresholdSummary, THRESHOLD_SCOPE_NOTE, THRESHOLD_STEPS,
} from '../settings/auto-accept-card';
import type { MergeCandidate, MergeProposal, MergeScoreFactor } from '../inventory/asset-queries';

const factor = (feature: string, contribution: number): MergeScoreFactor => ({
  feature, label: `${feature} label`, value: 1, weight: contribution, contribution,
});

const candidate = (id: string, over: Partial<MergeCandidate> = {}): MergeCandidate => ({
  asset_id: id, deleted: false, matched_identifiers: [], score: 0, ...over,
});

const proposal = (over: Partial<MergeProposal> = {}): MergeProposal => ({
  id: 'p1', tenant_id: 't1', status: 'pending', source: 'sensor',
  proposed_at: '2026-09-11T10:00:00Z', candidates: [], ...over,
});

// --- the score bar ---------------------------------------------------------

describe('scoreLabel', () => {
  it('renders a score as a percentage', () => {
    expect(scoreLabel(0.93)).toBe('93%');
  });

  it('shows an UNSCORED candidate as an absence, not as 0%', () => {
    // "Zero means unscored, not certainly wrong" — a 0% bar reads as a
    // confident rejection, which is the opposite of "nothing scored this".
    expect(scoreLabel(0)).toBeNull();
    expect(scoreLabel(Number.NaN)).toBeNull();
  });
});

// --- the reasons -----------------------------------------------------------

describe('topReasons', () => {
  it('takes the front of the server order rather than re-sorting', () => {
    // The server orders by absolute contribution. Re-deriving that here would
    // be a second opinion about which signal mattered most, and only the
    // model's own ordering is actually true of the score.
    const c = candidate('a', {
      score: 0.9,
      explanation: [factor('first', 3), factor('second', -2), factor('third', 1), factor('fourth', 0.5)],
    });
    expect(topReasons(c).map((f) => f.feature)).toEqual(['first', 'second', 'third']);
    expect(topReasons(c)).toHaveLength(TOP_REASONS_SHOWN);
  });

  it('keeps the reasons that count AGAINST the match', () => {
    // A proposal is a question. Filtering the evidence against would make the
    // panel a case for merging rather than a summary of what was weighed.
    const c = candidate('a', { score: 0.6, explanation: [factor('against', -4), factor('for', 1)] });
    const reasons = topReasons(c);
    expect(reasons.map(factorDirection)).toEqual(['against', 'for']);
  });

  it('is empty for a candidate nothing scored', () => {
    expect(topReasons(candidate('a'))).toEqual([]);
  });
});

// --- the auto-merged record ------------------------------------------------

describe('the auto-merged record', () => {
  it('names the candidate the matcher merged into', () => {
    const p = proposal({
      auto_accepted: true,
      accepted_asset_id: 'b',
      candidates: [candidate('a'), candidate('b'), candidate('c')],
    });
    expect(acceptedCandidate(p)?.asset_id).toBe('b');
  });

  it('keeps the OTHER candidates visible', () => {
    // An auto-accept settles where the sighting went, not whether the remaining
    // candidates are the same thing — those are still a person's decision, and
    // a row showing only the winner reads as if the whole question were closed.
    const p = proposal({
      auto_accepted: true,
      accepted_asset_id: 'b',
      candidates: [candidate('a'), candidate('b'), candidate('c')],
    });
    expect(remainingCandidates(p).map((c) => c.asset_id)).toEqual(['a', 'c']);
  });

  it('has no accepted candidate when the winner is gone', () => {
    const p = proposal({ auto_accepted: true, accepted_asset_id: 'gone', candidates: [candidate('a')] });
    expect(acceptedCandidate(p)).toBeUndefined();
  });

  it('distinguishes a merge a person has since reviewed from one they have not', () => {
    expect(isReviewed(proposal({ status: 'pending' }))).toBe(false);
    expect(isReviewed(proposal({ status: 'merged' }))).toBe(true);
    expect(isReviewed(proposal({ status: 'kept_separate' }))).toBe(true);
  });
});

// --- the threshold control -------------------------------------------------

describe('the auto-accept threshold wording', () => {
  it('calls zero "Never", not "0%"', () => {
    // The inversion this guards against: a control reading "0%" invites
    // "0% confidence required", i.e. merge everything — the exact opposite of
    // what zero means.
    expect(thresholdLabel(0)).toBe('Never');
    expect(thresholdLabel(90)).toBe('90%');
  });

  it('describes zero as OFF and says what happens instead', () => {
    const summary = thresholdSummary(0);
    expect(summary).toMatch(/off/i);
    expect(summary).toMatch(/waits for a person/i);
    expect(summary).not.toMatch(/0%/);
  });

  it('states the rule for a threshold that is on, both halves', () => {
    const summary = thresholdSummary(90);
    expect(summary).toContain('90%');
    expect(summary).toMatch(/without asking/i);
    // The other half: what does NOT get auto-accepted. A sentence that only
    // said what the setting permits would read as a description of the whole
    // behaviour.
    expect(summary).toMatch(/below waits for a person/i);
  });

  it('states which intakes the threshold governs: all of them', () => {
    // Until BUILD_PLAN 4.6a this note carved out an exception —
    // device-interrogation-service ran its own identification engines and did
    // not read the setting, so interrogation and cloud-collector observations
    // were never auto-accepted whatever a tenant set. 4.6a wired those engines
    // to the same threshold, and the note became a WIDER claim than it was.
    //
    // A wider claim needs more pinning, not less: the named paths are the ones
    // a tenant would otherwise have to guess about, and the old carve-out must
    // not creep back as a sentence while the code says otherwise.
    expect(THRESHOLD_SCOPE_NOTE).toMatch(/every sighting/i);
    expect(THRESHOLD_SCOPE_NOTE).toMatch(/device interrogation/i);
    expect(THRESHOLD_SCOPE_NOTE).toMatch(/cloud collectors/i);
    expect(THRESHOLD_SCOPE_NOTE).not.toMatch(/always reviewed by a person/i);
  });

  it('offers Never first, so the safe setting is the one nearest the label', () => {
    expect(THRESHOLD_STEPS[0]).toBe(0);
    expect([...THRESHOLD_STEPS].every((s, i, a) => i === 0 || s > a[i - 1])).toBe(true);
    expect(THRESHOLD_STEPS.every((s) => s >= 0 && s <= 100)).toBe(true);
  });
});
