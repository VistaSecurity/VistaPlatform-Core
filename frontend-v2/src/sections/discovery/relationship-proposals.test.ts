// Relationship proposals as the third row kind on Approvals (ADR-0006 D6).
//
// "No second queue anywhere. Every AI or rule proposal is a row here." Adding a
// row kind is easy to do halfway — the rows render, and the queue's counts and
// its empty state quietly keep describing two of three kinds. Those are the
// failures pinned here, because each one looks like a working page.
import { describe, expect, it } from 'vitest';
import {
  APPROVAL_SOURCES, countBySource, matchesSourceFilter, sourceOfRelationshipProposal,
} from './approval-sources';
import { confidencePct } from './relationship-proposal-row';
import { queryNoteKind, type QueryState } from './kit';

const ok: QueryState = { isLoading: false, isError: false };
const loading: QueryState = { isLoading: true, isError: false };
const failed: QueryState = { isLoading: false, isError: true, error: new Error('boom') };

describe('sourceOfRelationshipProposal', () => {
  it('reads the producer out of source_ref', () => {
    expect(sourceOfRelationshipProposal({ source_ref: 'assistant:gpt' })).toBe('assistant');
    expect(sourceOfRelationshipProposal({ source_ref: 'classifier:v2' })).toBe('classifier');
    expect(sourceOfRelationshipProposal({ source_ref: 'cmdb:servicenow-prod' })).toBe('cmdb');
  });

  it('treats a collector reference as discovered', () => {
    for (const ref of ['sensor:abc', 'interrogation:job-1', 'cloud:aws-prod']) {
      expect(sourceOfRelationshipProposal({ source_ref: ref })).toBe('discovered');
    }
  });

  it('falls back to matcher, NOT to discovered', () => {
    // A relationship proposal is by construction something nothing will promote
    // on its own, so an unattributed one was drawn by an inference engine.
    // Calling it "discovered" would tell a reviewer a sensor saw it.
    expect(sourceOfRelationshipProposal({})).toBe('matcher');
    expect(sourceOfRelationshipProposal({ source_kind: 'inferred' })).toBe('matcher');
  });

  it('uses source_kind when there is no ref to read', () => {
    expect(sourceOfRelationshipProposal({ source_kind: 'imported' })).toBe('imported');
    expect(sourceOfRelationshipProposal({ source_kind: 'measured' })).toBe('discovered');
  });

  it('only ever returns a source the facet can show', () => {
    for (const p of [{}, { source_ref: 'weird:thing' }, { source_kind: 'declared' }]) {
      expect(APPROVAL_SOURCES).toContain(sourceOfRelationshipProposal(p));
    }
  });
});

describe('countBySource with three row kinds', () => {
  it('counts relationship proposals into the facet', () => {
    // The chips claim to describe the queue. A row kind missing from them makes
    // the numbers under-report the work waiting.
    const counts = countBySource(
      [],
      [],
      [{ source_ref: 'matcher' }, { source_ref: 'assistant:gpt' }],
    );
    expect(counts.matcher).toBe(1);
    expect(counts.assistant).toBe(1);
  });

  it('adds them to the other kinds rather than replacing them', () => {
    const counts = countBySource(
      [{ class_source_kind: 'measured' }],
      [{ source: 'matcher' }],
      [{ source_ref: 'matcher' }],
    );
    expect(counts.discovered).toBe(1);
    expect(counts.matcher).toBe(2);
    const total = APPROVAL_SOURCES.reduce((n, s) => n + counts[s], 0);
    expect(total).toBe(3);
  });

  it('stays backwards compatible when no third argument is given', () => {
    // The signature grew an optional parameter; an existing caller must keep
    // producing the same numbers rather than throwing on `undefined.length`.
    const counts = countBySource([{ class_source_kind: 'measured' }], [{ source: 'matcher' }]);
    expect(counts.discovered).toBe(1);
    expect(counts.matcher).toBe(1);
  });

  it('seeds every source at zero so the facet teaches what the queue can hold', () => {
    const counts = countBySource([], [], []);
    for (const s of APPROVAL_SOURCES) expect(counts[s]).toBe(0);
  });
});

describe('the source filter applies to relationship proposals too', () => {
  it('keeps a proposal whose source is selected', () => {
    expect(matchesSourceFilter(sourceOfRelationshipProposal({ source_ref: 'matcher' }), ['matcher'])).toBe(true);
  });

  it('hides one whose source is not', () => {
    expect(matchesSourceFilter(sourceOfRelationshipProposal({ source_ref: 'matcher' }), ['cmdb'])).toBe(false);
  });

  it('treats an empty selection as "all", not "none"', () => {
    expect(matchesSourceFilter(sourceOfRelationshipProposal({}), [])).toBe(true);
  });
});

// The reason this file exists. The queue's empty state is a claim about EVERY
// read that feeds it, and the Approvals page now has three.
describe('the empty state accounts for all three reads', () => {
  it('says "empty" only when all three succeeded and there is nothing', () => {
    expect(queryNoteKind([ok, ok, ok], true)).toBe('empty');
  });

  it('does NOT say "empty" when the relationship read failed', () => {
    // This is the regression. A failed relationship read is an unknown number of
    // proposals a person still has to decide; rendering it as "Nothing awaiting
    // review" sends them away from work they have. The merge read had exactly
    // this bug, and adding a third kind without adding it to the guard would
    // reintroduce it.
    expect(queryNoteKind([ok, ok, failed], true)).toBe('error');
  });

  it('does not say "empty" when the relationship read is still in flight', () => {
    expect(queryNoteKind([ok, ok, loading], true)).toBe('loading');
  });

  it('reports an error even when there ARE rows from the other reads', () => {
    // An error anywhere outranks a non-empty everywhere: the page is showing a
    // partial queue and has to say so.
    expect(queryNoteKind([ok, ok, failed], false)).toBe('error');
  });

  it('is null when everything loaded and there is something to show', () => {
    expect(queryNoteKind([ok, ok, ok], false)).toBeNull();
  });
});

describe('confidencePct', () => {
  it('renders a fraction as a percentage', () => {
    expect(confidencePct(0.82)).toBe('82%');
  });

  it('passes a value already in percent through', () => {
    expect(confidencePct(82)).toBe('82%');
  });

  it('treats zero as UNSCORED rather than as certainty of wrongness', () => {
    // Same rule the merge row follows: a 0% bar reads as a confident rejection,
    // which is a different claim from "nobody scored this".
    expect(confidencePct(0)).toBeNull();
  });

  it('copes with a missing or non-finite confidence', () => {
    expect(confidencePct(undefined)).toBeNull();
    expect(confidencePct(Number.NaN)).toBeNull();
  });
});
