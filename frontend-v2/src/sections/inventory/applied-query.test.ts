// The canonical-query echo (ADR-0008 D4.4).
//
// `GET /assets` returns `query`: the predicate that actually selected the rows,
// which is the caller's own AND the read path's default scope
// (`status:monitoring`, unless the query names a status itself). It is almost
// never the string that was sent, and the gap is the whole reason the field
// exists — a user who types `class:server`, gets fewer rows than they expect
// and is shown only their own query has no way to find out why.
//
// The hook must not paper over an absent echo either: `query` is optional on
// the envelope precisely because an empty predicate has nothing to show, and
// turning that into the caller's typed text would invent an answer.
import { describe, expect, it } from 'vitest';
import { appliedQueryOf } from './asset-queries';

describe('appliedQueryOf', () => {
  it('takes the server’s echo', () => {
    expect(appliedQueryOf({ query: 'class:server and status:monitoring' }))
      .toBe('class:server and status:monitoring');
  });

  it('is EMPTY when the server ran no predicate, never the caller’s text', () => {
    // The field is absent when the predicate was empty. Substituting the typed
    // query here would claim the server ran something it did not.
    expect(appliedQueryOf({})).toBe('');
    expect(appliedQueryOf({ query: undefined })).toBe('');
  });

  it('ignores a non-string echo rather than rendering "[object Object]"', () => {
    expect(appliedQueryOf({ query: 42 as unknown as string })).toBe('');
  });
});
