// Class proposals as the fourth row kind on Approvals (ADR-0006 D6,
// workstream 2.10b).
//
// "No second queue anywhere. Every AI or rule proposal is a row here." Adding a
// row kind is easy to do halfway — the rows render, and the queue's counts and
// its empty state quietly keep describing three of four kinds. Those are the
// failures pinned here, because each one looks like a working page.
import { describe, expect, it } from 'vitest';
import {
  APPROVAL_SOURCES, countBySource, matchesSourceFilter, sourceOfClassProposal,
} from './approval-sources';
import { readClassProposalPage, CLASS_PROPOSALS_PAGE_SIZE } from './class-proposal-queries';
import { queryNoteKind, type QueryState } from './kit';

const ok: QueryState = { isLoading: false, isError: false };
const loading: QueryState = { isLoading: true, isError: false };
const failed: QueryState = { isLoading: false, isError: true, error: new Error('boom') };

describe('sourceOfClassProposal', () => {
  it('is the classifier by default', () => {
    expect(sourceOfClassProposal({})).toBe('classifier');
    expect(sourceOfClassProposal({ source: 'classifier:rules' })).toBe('classifier');
  });

  it('reads a different producer when one says so', () => {
    // Workstream 4.2's learned classifier and the assistant will write their
    // own refs. The chip follows the producer rather than this function.
    expect(sourceOfClassProposal({ source: 'assistant:gpt' })).toBe('assistant');
  });

  it('never falls back to "discovered"', () => {
    // A class proposal is by construction something a RULE argued, never
    // something a sensor observed. Calling an unattributed one "discovered"
    // would tell a reviewer the network said so.
    expect(sourceOfClassProposal({ source: 'something-else' })).not.toBe('discovered');
  });

  it('only ever returns a source the facet can show', () => {
    for (const p of [{}, { source: 'weird:thing' }, { source: '' }]) {
      expect(APPROVAL_SOURCES).toContain(sourceOfClassProposal(p));
    }
  });
});

describe('countBySource with four row kinds', () => {
  it('counts class proposals into the facet', () => {
    const counts = countBySource([], [], [], [{ source: 'classifier:rules' }, { source: 'assistant:gpt' }]);
    expect(counts.classifier).toBe(1);
    expect(counts.assistant).toBe(1);
  });

  it('adds them to the other kinds rather than replacing them', () => {
    const counts = countBySource(
      [{ class_source_kind: 'measured' }],
      [{ source: 'matcher' }],
      [{ source_ref: 'matcher' }],
      [{ source: 'classifier:rules' }],
    );
    expect(counts.discovered).toBe(1);
    expect(counts.matcher).toBe(2);
    expect(counts.classifier).toBe(1);
    const total = APPROVAL_SOURCES.reduce((n, s) => n + counts[s], 0);
    expect(total).toBe(4);
  });

  it('stays backwards compatible when no fourth argument is given', () => {
    // The signature grew another optional parameter; an existing caller must
    // keep producing the same numbers rather than throwing on
    // `undefined.length`.
    const counts = countBySource([{ class_source_kind: 'measured' }], [{ source: 'matcher' }], [{ source_ref: 'matcher' }]);
    expect(counts.discovered).toBe(1);
    expect(counts.matcher).toBe(2);
    expect(counts.classifier).toBe(0);
  });
});

// ── the learned classifier's proposals (workstream 4.2) ─────────────────────
//
// A second producer writes class proposals now: the model that speaks where the
// curated rules could not decide. The facet, the counts and the row all have to
// account for it, and each of these is a way of NOT accounting for it that
// leaves a page looking like it works.
describe('a model-derived class proposal', () => {
  it('is still the classifier on the source facet', () => {
    // Both producers write a `classifier:` source, so the chip groups them
    // together — the reviewer's question there is "who is asking me this", and
    // the answer for both is the classifier. The ROW is where the two are told
    // apart, because that is where the difference changes what a reviewer does.
    expect(sourceOfClassProposal({ source: 'classifier:model' })).toBe('classifier');
  });

  it('is counted into the queue rather than dropped', () => {
    // A row kind the counts do not see makes the chips under-report the work
    // waiting, which is the same lie the merge total told before it was read
    // off `total`.
    const counts = countBySource([], [], [], [
      { source: 'classifier:rules' },
      { source: 'classifier:model' },
    ]);
    expect(counts.classifier).toBe(2);
  });

  it('passes the classifier source filter like any other', () => {
    expect(matchesSourceFilter(sourceOfClassProposal({ source: 'classifier:model' }), ['classifier'])).toBe(true);
    expect(matchesSourceFilter(sourceOfClassProposal({ source: 'classifier:model' }), ['matcher'])).toBe(false);
  });
});

describe('the source filter applies to class proposals too', () => {
  it('keeps a proposal whose source is selected', () => {
    expect(matchesSourceFilter(sourceOfClassProposal({ source: 'classifier:rules' }), ['classifier'])).toBe(true);
  });

  it('hides one whose source is not', () => {
    expect(matchesSourceFilter(sourceOfClassProposal({ source: 'classifier:rules' }), ['cmdb'])).toBe(false);
  });

  it('treats an empty selection as "all", not "none"', () => {
    expect(matchesSourceFilter(sourceOfClassProposal({}), [])).toBe(true);
  });
});

// The queue's empty state is a claim about EVERY read that feeds it, and the
// Approvals page now has four.
describe('the empty state accounts for all four reads', () => {
  it('says "empty" only when all four succeeded and there is nothing', () => {
    expect(queryNoteKind([ok, ok, ok, ok], true)).toBe('empty');
  });

  it('does NOT say "empty" when the class read failed', () => {
    // The regression this file guards. A failed class read is an unknown number
    // of proposals a person still has to decide; rendering it as "Nothing
    // awaiting review" sends them away from work they have. The merge read had
    // exactly this bug, the relationship read inherited the guard, and a fourth
    // kind added without it would reintroduce it.
    expect(queryNoteKind([ok, ok, ok, failed], true)).toBe('error');
  });

  it('does not say "empty" when the class read is still in flight', () => {
    expect(queryNoteKind([ok, ok, ok, loading], true)).toBe('loading');
  });
});

describe('readClassProposalPage', () => {
  it('reads the tenant-wide total, not the page length', () => {
    // The array stops at the page size. Reading its length as the count is how
    // the merge queue once told a tenant with 132 proposals that it had 50.
    const page = readClassProposalPage({ class_proposals: [], total: 132, limit: 50, offset: 0 });
    expect(page.total).toBe(132);
  });

  it('treats a missing body as an empty page rather than throwing', () => {
    const page = readClassProposalPage(undefined);
    expect(page.proposals).toEqual([]);
    expect(page.total).toBe(0);
    expect(page.limit).toBe(CLASS_PROPOSALS_PAGE_SIZE);
  });

  it('falls back to the array length only when the server sent no total', () => {
    const page = readClassProposalPage({ class_proposals: [{ id: 'a' }, { id: 'b' }] as never });
    expect(page.total).toBe(2);
  });
});
