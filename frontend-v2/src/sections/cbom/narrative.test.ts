// The comparison narrative panel has to say two things a reader cannot get
// from the prose itself: WHO wrote it, and WHICH row each claim rests on.
//
// Both matter because the same panel can hold two very different artefacts. A
// rule-written summary is arithmetic over the rows and is identical on every
// recomputation. A model-written one came from a named model and is kept only
// because every sentence cited a change the model was actually shown. Rendering
// them identically would leave a reader unable to tell which they are looking
// at — which is the shape this codebase keeps finding: "did not check" rendered
// as "passed".
import { describe, it, expect } from 'vitest';
import { narrativeLabel, narrativeSegments, diffRowAnchor } from './kit';

describe('narrativeLabel', () => {
  it('names the rule narrator', () => {
    expect(narrativeLabel({ source: 'rules', model_id: '' })).toBe('Summarised by rules');
  });

  it('names the model that wrote it, not just "AI"', () => {
    expect(narrativeLabel({ source: 'model', model_id: 'some-model-1' }))
      .toBe('Summarised by some-model-1');
  });

  it('falls back to an unnamed model rather than claiming rules wrote it', () => {
    expect(narrativeLabel({ source: 'model', model_id: '' })).toBe('Summarised by a model');
  });

  it('says nothing when the server sent no detail', () => {
    // A server predating the seam. Inventing an attribution would be worse
    // than showing none.
    expect(narrativeLabel(undefined)).toBeNull();
    expect(narrativeLabel(null)).toBeNull();
    expect(narrativeLabel({})).toBeNull();
  });
});

describe('narrativeSegments', () => {
  it('splits prose into runs and citation markers, in place', () => {
    const segs = narrativeSegments('Net improvement: 2 improvements [row:r1][row:r4] and 1 regression [row:r7].');
    expect(segs.filter((s) => s.cite).map((s) => s.cite)).toEqual(['r1', 'r4', 'r7']);
    // The prose either side of a marker survives, so the citation stays
    // attached to the clause it supports.
    expect(segs.map((s) => (s.cite ? '' : s.text)).join(''))
      .toBe('Net improvement: 2 improvements  and 1 regression .');
  });

  it('returns plain prose untouched when there are no citations', () => {
    const segs = narrativeSegments('No material changes between two snapshots.');
    expect(segs).toEqual([{ text: 'No material changes between two snapshots.' }]);
  });

  it('does not treat a markdown link as a citation', () => {
    // The grammar is deliberately not markdown: a model writing a link must not
    // be able to produce something the UI renders as a row reference.
    const segs = narrativeSegments('See [the docs](https://example.test) for detail.');
    expect(segs.some((s) => s.cite)).toBe(false);
  });

  it('is re-runnable — the shared regex keeps no state between calls', () => {
    const text = 'One [row:r1] two [row:r2].';
    const first = narrativeSegments(text);
    const second = narrativeSegments(text);
    expect(second).toEqual(first);
    expect(first.filter((s) => s.cite)).toHaveLength(2);
  });
});

describe('diffRowAnchor', () => {
  it('is the single definition the row id and the link both use', () => {
    expect(diffRowAnchor('r12')).toBe('diff-row-r12');
  });
});
