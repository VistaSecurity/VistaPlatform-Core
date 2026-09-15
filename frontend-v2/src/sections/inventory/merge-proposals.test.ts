// The merge-proposal queue's COUNT and its page are two different numbers.
//
// The list endpoint caps at 50 whether or not anyone asks for a limit, and the
// UI used `merge_proposals.length` as the count — on the Approvals header and
// in the "awaiting review" banner on Inventory. A tenant with 132 proposals was
// told it had 50, and the other 82 were not merely unpaged, they were invisible
// and uncounted.
import { describe, expect, it } from 'vitest';
import {
  MERGE_PROPOSALS_PAGE_SIZE, mergeProposalRangeLabel, readMergeProposalPage,
} from './asset-queries';

/** `n` proposal-shaped rows — only the length matters here. */
const rows = (n: number) => Array.from({ length: n }, (_, i) => ({ id: `p${i}` })) as never[];

describe('readMergeProposalPage (gate1 C6)', () => {
  it('reports the tenant total, not the page length', () => {
    const page = readMergeProposalPage({ merge_proposals: rows(50), total: 132, limit: 50, offset: 0 });
    expect(page.total).toBe(132);
    expect(page.proposals).toHaveLength(50);
  });

  it('does not mistake a real zero for a missing total', () => {
    // `??` and not `||`: an empty queue answers 0, and 0 is an answer.
    const page = readMergeProposalPage({ merge_proposals: [], total: 0, limit: 50, offset: 0 });
    expect(page.total).toBe(0);
  });

  it('falls back to the page length only when the envelope carries no total', () => {
    const page = readMergeProposalPage({ merge_proposals: rows(3) });
    expect(page.total).toBe(3);
    expect(page.limit).toBe(MERGE_PROPOSALS_PAGE_SIZE);
    expect(page.offset).toBe(0);
  });

  it('copes with no envelope at all', () => {
    expect(readMergeProposalPage(undefined)).toEqual({
      proposals: [], total: 0, limit: MERGE_PROPOSALS_PAGE_SIZE, offset: 0,
    });
  });
});

describe('mergeProposalRangeLabel (gate1 C6)', () => {
  it('says which slice of the queue is on screen', () => {
    expect(mergeProposalRangeLabel(readMergeProposalPage({ merge_proposals: rows(50), total: 132, offset: 50 })))
      .toBe('51–100 of 132');
  });

  it('counts the last, short page correctly', () => {
    expect(mergeProposalRangeLabel(readMergeProposalPage({ merge_proposals: rows(32), total: 132, offset: 100 })))
      .toBe('101–132 of 132');
  });

  it('says nothing when the whole queue fits on one page', () => {
    expect(mergeProposalRangeLabel(readMergeProposalPage({ merge_proposals: rows(7), total: 7, offset: 0 })))
      .toBe('');
  });
});
