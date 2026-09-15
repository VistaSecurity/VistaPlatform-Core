import { describe, expect, it } from 'vitest';
import {
  acceptedCount,
  citedSegments,
  draftingOffered,
  dropReasonLabel,
  initialReviewState,
  measurementSummary,
  parseCitationRef,
  pendingCount,
  reviewReducer,
  sourceRefFor,
  type ControlDraft,
  type DraftControlsResponse,
  type ReviewState,
} from './drafts';

const standard = '4.2.1 Use strong cryptography.\n4.2.2 Certificates expire within 90 days.';

function draft(over: Partial<ControlDraft> = {}): ControlDraft {
  return {
    source_kind: 'inferred',
    source_ref: 'author:model',
    confidence: 0,
    model_id: 'test-model',
    title: 'Strong cryptography',
    published: false,
    citations: [{ kind: 'standard_span', ref: '0-31', text: '4.2.1 Use strong cryptography.\n' }],
    ...over,
  } as ControlDraft;
}

function response(over: Partial<DraftControlsResponse> = {}): DraftControlsResponse {
  return {
    source: 'model',
    model_id: 'test-model',
    drafts: [draft()],
    dropped: { count: 0, reasons: [] },
    ...over,
  } as DraftControlsResponse;
}

function ran(text = standard): ReviewState {
  return reviewReducer({ ...initialReviewState, text }, { type: 'run' });
}

describe('review state machine', () => {
  it('starts idle with an empty paste', () => {
    expect(initialReviewState.phase).toBe('idle');
    expect(initialReviewState.text).toBe('');
  });

  it('moves idle → running → review', () => {
    const running = ran();
    expect(running.phase).toBe('running');
    const reviewing = reviewReducer(running, { type: 'succeeded', response: response() });
    expect(reviewing.phase).toBe('review');
    if (reviewing.phase !== 'review') return;
    expect(reviewing.items).toHaveLength(1);
    expect(reviewing.items[0].status).toBe('pending');
    expect(reviewing.modelId).toBe('test-model');
  });

  it('moves running → error and keeps the paste so the user can retry', () => {
    const failed = reviewReducer(ran(), { type: 'failed', message: 'no provider' });
    expect(failed.phase).toBe('error');
    expect(failed.text).toBe(standard);
    if (failed.phase === 'error') expect(failed.message).toBe('no provider');
  });

  it('keeps the pasted text on the review state, because citations index into it', () => {
    const reviewing = reviewReducer(ran(), { type: 'succeeded', response: response() });
    expect(reviewing.text).toBe(standard);
  });

  // The empty result is a real answer and must be a real state: a review panel
  // saying "the model drafted nothing from this text" is honest, and falling
  // back to `idle` would look like the button had not been pressed.
  it('renders an empty result as a review with no items', () => {
    const reviewing = reviewReducer(ran(), {
      type: 'succeeded',
      response: response({ drafts: [] }),
    });
    expect(reviewing.phase).toBe('review');
    if (reviewing.phase !== 'review') return;
    expect(reviewing.items).toHaveLength(0);
  });

  it('carries the drop report, the run notes and the truncation flag through', () => {
    const reviewing = reviewReducer(ran(), {
      type: 'succeeded',
      response: response({
        dropped: { count: 2, reasons: [{ reason: 'no_citation', scope: 'control' }, { reason: 'over_limit', scope: 'control' }] },
        notes: ['partial reading'],
        truncated: true,
      }),
    });
    if (reviewing.phase !== 'review') throw new Error('expected review');
    expect(reviewing.dropped).toHaveLength(2);
    expect(reviewing.notes).toEqual(['partial reading']);
    expect(reviewing.truncated).toBe(true);
  });

  // Editing the paste after a run abandons the drafts on purpose: they cite
  // byte offsets into the OLD text, so keeping them would highlight passages
  // they did not come from.
  it('drops the drafts when the paste is edited', () => {
    const reviewing = reviewReducer(ran(), { type: 'succeeded', response: response() });
    const edited = reviewReducer(reviewing, { type: 'edit', text: 'something else' });
    expect(edited.phase).toBe('idle');
    expect(edited.text).toBe('something else');
  });
});

describe('accept / discard', () => {
  const reviewing = reviewReducer(ran(), {
    type: 'succeeded',
    response: response({ drafts: [draft({ title: 'A' }), draft({ title: 'B' })] }),
  });

  it('marks one draft accepted and leaves the other alone', () => {
    const after = reviewReducer(reviewing, { type: 'accepted', key: 'draft-0' });
    if (after.phase !== 'review') throw new Error('expected review');
    expect(after.items[0].status).toBe('accepted');
    expect(after.items[1].status).toBe('pending');
  });

  it('shows the in-flight state while accepting', () => {
    const after = reviewReducer(reviewing, { type: 'accepting', key: 'draft-0' });
    if (after.phase !== 'review') throw new Error('expected review');
    expect(after.items[0].status).toBe('accepting');
  });

  // The accept call created a row. Offering the button again would create a
  // second one, and a duplicated control in a published framework is a
  // duplicated finding for every tenant.
  it('refuses to re-arm an accepted draft', () => {
    const accepted = reviewReducer(reviewing, { type: 'accepted', key: 'draft-0' });
    const again = reviewReducer(accepted, { type: 'accepting', key: 'draft-0' });
    if (again.phase !== 'review') throw new Error('expected review');
    expect(again.items[0].status).toBe('accepted');
  });

  it('refuses to re-arm a discarded draft', () => {
    const discarded = reviewReducer(reviewing, { type: 'discarded', key: 'draft-1' });
    const again = reviewReducer(discarded, { type: 'accepted', key: 'draft-1' });
    if (again.phase !== 'review') throw new Error('expected review');
    expect(again.items[1].status).toBe('discarded');
  });

  // A failed accept is retryable, but only deliberately: it lands on `failed`,
  // not back on `pending`, so the user sees what went wrong before trying again.
  it('records the failure message and does not silently re-arm', () => {
    const failed = reviewReducer(reviewing, { type: 'acceptFailed', key: 'draft-0', message: 'duplicate control id' });
    if (failed.phase !== 'review') throw new Error('expected review');
    expect(failed.items[0].status).toBe('failed');
    expect(failed.items[0].error).toBe('duplicate control id');
  });

  it('counts what is left to review and what landed', () => {
    let s = reviewing;
    expect(pendingCount(s)).toBe(2);
    s = reviewReducer(s, { type: 'accepted', key: 'draft-0' });
    expect(pendingCount(s)).toBe(1);
    expect(acceptedCount(s)).toBe(1);
    s = reviewReducer(s, { type: 'discarded', key: 'draft-1' });
    expect(pendingCount(s)).toBe(0);
    expect(acceptedCount(s)).toBe(1);
  });

  it('counts a failed draft as still needing a decision', () => {
    const s = reviewReducer(reviewing, { type: 'acceptFailed', key: 'draft-0', message: 'x' });
    expect(pendingCount(s)).toBe(2);
  });

  it('ignores accept/discard outside the review phase', () => {
    expect(reviewReducer(ran(), { type: 'accepted', key: 'draft-0' }).phase).toBe('running');
  });
});

describe('citation highlighting', () => {
  it('parses a well-formed ref', () => {
    expect(parseCitationRef('0-31')).toEqual({ start: 0, end: 31 });
    expect(parseCitationRef(' 31-72 ')).toEqual({ start: 31, end: 72 });
  });

  it('rejects a ref it cannot trust', () => {
    for (const bad of ['', 'abc', '31-31', '40-10', '[src:0-31]', '0', '-5-9']) {
      expect(parseCitationRef(bad), bad).toBeNull();
    }
  });

  it('splits the text into cited and uncited segments', () => {
    const segments = citedSegments(standard, [{ kind: 'standard_span', ref: '0-31' }]);
    expect(segments).toEqual([
      { text: '4.2.1 Use strong cryptography.\n', cited: true },
      { text: '4.2.2 Certificates expire within 90 days.', cited: false },
    ]);
  });

  it('merges overlapping and out-of-order citations', () => {
    const segments = citedSegments(standard, [
      { kind: 'standard_span', ref: '31-72' },
      { kind: 'standard_span', ref: '0-31' },
    ]);
    expect(segments).toHaveLength(1);
    expect(segments[0].cited).toBe(true);
    expect(segments[0].text).toBe(standard);
  });

  // A highlight is a claim about where a draft came from. A wrong one is worse
  // than none, so a range past the end of the text is dropped rather than
  // clamped to something that looks plausible.
  it('drops a citation that runs past the end', () => {
    const segments = citedSegments(standard, [{ kind: 'standard_span', ref: '0-99999' }]);
    expect(segments).toEqual([{ text: standard, cited: false }]);
  });

  // The offsets are BYTE offsets into UTF-8; JavaScript strings are UTF-16.
  // Slicing the string directly would land in the wrong place on any document
  // with a non-ASCII character in it — and standards are full of § and —.
  it('slices by byte offset, not by UTF-16 code unit', () => {
    const text = '§ 4.2.1 Übergang.\nsecond line';
    const firstLineBytes = new TextEncoder().encode('§ 4.2.1 Übergang.\n').length;
    const segments = citedSegments(text, [{ kind: 'standard_span', ref: `0-${firstLineBytes}` }]);
    expect(segments[0]).toEqual({ text: '§ 4.2.1 Übergang.\n', cited: true });
    expect(segments[1]).toEqual({ text: 'second line', cited: false });
  });

  it('returns the whole text uncited when there are no citations', () => {
    expect(citedSegments(standard, [])).toEqual([{ text: standard, cited: false }]);
    expect(citedSegments(standard, undefined)).toEqual([{ text: standard, cited: false }]);
    expect(citedSegments('', [])).toEqual([]);
  });
});

describe('presentation helpers', () => {
  it('turns every drop reason into a sentence', () => {
    for (const reason of ['no_citation', 'unresolvable_citation', 'missing_title', 'unknown_measurement_type', 'invalid_predicate', 'over_limit']) {
      expect(dropReasonLabel(reason)).not.toBe(reason);
      expect(dropReasonLabel(reason).length).toBeGreaterThan(10);
    }
  });

  // A reason the server grows later must be visible, not swallowed into
  // "unknown" — the drop report exists to say what happened.
  it('shows an unrecognised reason rather than hiding it', () => {
    expect(dropReasonLabel('some_new_reason')).toBe('some_new_reason');
  });

  it('summarises each rule type', () => {
    expect(measurementSummary({ measurement_type_code: 'cert_expiration_days', rule_type: 'threshold', predicate: { operator: '<=', value: 90 } }))
      .toBe('cert_expiration_days <= 90');
    expect(measurementSummary({ measurement_type_code: 'pfs_support', rule_type: 'presence', predicate: { required: true } }))
      .toBe('pfs_support present');
    expect(measurementSummary({ measurement_type_code: 'tls_version', rule_type: 'pattern', predicate: { pattern: '^TLS1\\.0$', flags: 'i' } }))
      .toBe('tls_version matches /^TLS1\\.0$/i');
    expect(measurementSummary({ measurement_type_code: 'key_size', rule_type: 'range', predicate: { min: 2048 } }))
      .toBe('key_size in [2048, ∞]');
  });

  it('builds the source_ref an accepted draft is stored under', () => {
    expect(sourceRefFor('claude-opus-4')).toBe('author:claude-opus-4');
    expect(sourceRefFor('')).toBe('author:model');
  });
});

describe('availability gating', () => {
  it('offers the action only when the server says it can answer', () => {
    expect(draftingOffered({ available: true, provider: 'anthropic' })).toBe(true);
    expect(draftingOffered({ available: false, reason: 'edition' })).toBe(false);
    expect(draftingOffered({ available: false, reason: 'no_provider' })).toBe(false);
  });

  // Not yet answered, or the query failed. Offering a capability before it is
  // known to exist is offering a button that errors.
  it('does not offer it while the answer is unknown', () => {
    expect(draftingOffered(undefined)).toBe(false);
  });
});
