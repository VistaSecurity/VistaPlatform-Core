// A page's "nothing here" is a claim about every read that feeds its list.
//
// Approvals asks for two things — pending assets and merge proposals — and
// judged its empty state on the first alone. A failed merge-proposal read
// therefore rendered as "Nothing awaiting review" over an unknown number of
// merges still waiting for a person, which is the worst possible reading: the
// reviewer closes the tab.
import { describe, expect, it } from 'vitest';
import { queryNoteKind } from './kit';

const ok = { isLoading: false, isError: false };
const loading = { isLoading: true, isError: false };
const failed = { isLoading: false, isError: true, error: new Error('boom') };

describe('queryNoteKind (gate1 C5)', () => {
  it('reports an error when ANY of the queries failed, even with the others empty', () => {
    expect(queryNoteKind([ok, failed], true)).toBe('error');
    expect(queryNoteKind([failed, ok], true)).toBe('error');
  });

  it('does not report "empty" while a second read is still failing', () => {
    expect(queryNoteKind([ok, failed], true)).not.toBe('empty');
  });

  it('still reports "empty" when every read succeeded and there is nothing (the other polarity)', () => {
    expect(queryNoteKind([ok, ok], true)).toBe('empty');
  });

  it('reports loading while any read is in flight', () => {
    expect(queryNoteKind([ok, loading], true)).toBe('loading');
  });

  it('prefers the error over the loading when both are true of different reads', () => {
    // An in-flight retry must not hide a failure that is already known.
    expect(queryNoteKind([loading, failed], false)).toBe('error');
  });

  it('returns null when the reads succeeded and there is something to show', () => {
    expect(queryNoteKind([ok, ok], false)).toBeNull();
  });

  it('still accepts a single query, which is how every other page calls it', () => {
    expect(queryNoteKind(failed, false)).toBe('error');
    expect(queryNoteKind(ok, true)).toBe('empty');
  });
});
