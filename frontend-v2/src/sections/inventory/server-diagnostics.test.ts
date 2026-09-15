// Server query diagnostics: byte spans, and the tombstone pointer.
//
// Two facts about the API that a client gets wrong silently.
//
// `QueryDiagnostic.span` is "a byte span into the submitted text" — Go counts
// UTF-8 bytes and a JavaScript string counts UTF-16 code units. They agree on
// ASCII and on nothing else, so a highlight built from a raw server span is
// right in every test written in English and wrong on the first accented
// hostname, with the message still correct and the caret under an innocent
// word. Nothing throws; it just teaches the user something false about their
// own query.
//
// `merged_into` is the pointer a merge leaves on the losing record. Without it
// the archived asset's page — which every link ever sent to it still resolves
// to — reads as an ordinary empty asset rather than as a redirect.
import { describe, expect, it } from 'vitest';
import { byteSpanToStringSpan, serverDiagnosticsForDisplay } from './query-editor';
import { queryDiagnostics } from './asset-queries';
import { mergedIntoId } from './asset-page';

/** What Go would report: the byte offset of a substring in the UTF-8 encoding. */
function byteOffsetOf(source: string, needle: string): { start: number; end: number } {
  const enc = new TextEncoder();
  const at = source.indexOf(needle);
  if (at < 0) throw new Error(`no ${needle} in ${source}`);
  const start = enc.encode(source.slice(0, at)).length;
  return { start, end: start + enc.encode(needle).length };
}

describe('byteSpanToStringSpan', () => {
  it('is the identity on ASCII, where the two index spaces coincide', () => {
    const q = 'environment:production and hostnaem:web-1';
    const span = byteOffsetOf(q, 'hostnaem');
    expect(byteSpanToStringSpan(q, span)).toEqual(span);
    expect(q.slice(span.start, span.end)).toBe('hostnaem');
  });

  it('finds the right word after a two-byte character', () => {
    // "Zürich" is 7 bytes and 6 code units, so every byte offset after it is
    // one too far right. Using the raw span underlines "hostnaem" shifted by
    // one — a caret under "ostnaem:" and a message about "hostnaem".
    const q = 'site:Zürich and hostnaem:web-1';
    const span = byteOffsetOf(q, 'hostnaem');
    expect(q.slice(span.start, span.end)).not.toBe('hostnaem');
    const fixed = byteSpanToStringSpan(q, span);
    expect(q.slice(fixed.start, fixed.end)).toBe('hostnaem');
  });

  it('copes with three-byte characters', () => {
    const q = 'business_unit:"決済" and hostnaem:web-1';
    const fixed = byteSpanToStringSpan(q, byteOffsetOf(q, 'hostnaem'));
    expect(q.slice(fixed.start, fixed.end)).toBe('hostnaem');
  });

  it('copes with a surrogate pair, which is 4 bytes and TWO code units', () => {
    // The one case where a naive "one character per byte-run" conversion also
    // fails: an astral code point advances the string index by 2, not 1.
    const q = 'tag:"🚀" and hostnaem:web-1';
    const fixed = byteSpanToStringSpan(q, byteOffsetOf(q, 'hostnaem'));
    expect(q.slice(fixed.start, fixed.end)).toBe('hostnaem');
  });

  it('lands exactly on a multi-byte value that IS the offending span', () => {
    const q = 'environment:Ünknown';
    const fixed = byteSpanToStringSpan(q, byteOffsetOf(q, 'Ünknown'));
    expect(q.slice(fixed.start, fixed.end)).toBe('Ünknown');
  });

  it('clamps rather than throwing on a span past the end', () => {
    const q = 'class:server';
    expect(byteSpanToStringSpan(q, { start: 900, end: 1000 })).toEqual({ start: q.length, end: q.length });
  });

  it('clamps a negative start and never returns an inverted span', () => {
    const q = 'class:server';
    const out = byteSpanToStringSpan(q, { start: -5, end: -1 });
    expect(out.start).toBe(0);
    expect(out.end).toBeGreaterThanOrEqual(out.start);
  });

  it('is a no-op on an empty source', () => {
    expect(byteSpanToStringSpan('', { start: 0, end: 4 })).toEqual({ start: 0, end: 0 });
  });
});

describe('serverDiagnosticsForDisplay', () => {
  it('converts every diagnostic and keeps the rest of it untouched', () => {
    const q = 'site:Zürich and hostnaem:web-1';
    const span = byteOffsetOf(q, 'hostnaem');
    const [out] = serverDiagnosticsForDisplay(q, [
      { code: 'unknown_field', message: 'no field "hostnaem" on assets', span, suggestion: 'did you mean "hostname"?' },
    ]);
    expect(q.slice(out.span.start, out.span.end)).toBe('hostnaem');
    expect(out.code).toBe('unknown_field');
    expect(out.suggestion).toBe('did you mean "hostname"?');
  });
});

describe('queryDiagnostics', () => {
  const envelope = {
    error: 'invalid query',
    query: 'class:servr',
    errors: [{ code: 'unknown_value', message: 'no class "servr"', span: { start: 6, end: 11 }, suggestion: 'server' }],
  };

  it('reads the structured envelope', () => {
    const out = queryDiagnostics(envelope);
    expect(out?.query).toBe('class:servr');
    expect(out?.errors).toHaveLength(1);
    expect(out?.errors[0].suggestion).toBe('server');
  });

  it('is null for the legacy single-message error shape', () => {
    // The 400 is `oneOf: [QueryError, LegacyError]`. Rendering an empty
    // diagnostics panel for the second would replace a usable message with
    // nothing at all.
    expect(queryDiagnostics({ error: 'invalid page size' })).toBeNull();
    expect(queryDiagnostics(new Error('boom'))).toBeNull();
    expect(queryDiagnostics(null)).toBeNull();
  });

  it('drops an entry with no usable span rather than rendering a caret at 0', () => {
    expect(queryDiagnostics({ query: 'x', errors: [{ code: 'c', message: 'm' }] })).toBeNull();
    expect(queryDiagnostics({ query: 'x', errors: ['nonsense'] })).toBeNull();
  });

  it('defaults a missing code rather than dropping a real message', () => {
    const out = queryDiagnostics({ query: 'x', errors: [{ message: 'm', span: { start: 0, end: 1 } }] });
    expect(out?.errors[0].code).toBe('invalid_query');
  });
});

describe('mergedIntoId', () => {
  it('reads the contract’s first-class field', () => {
    expect(mergedIntoId({ merged_into: 'aaaa-bbbb' })).toBe('aaaa-bbbb');
  });

  it('falls back to the metadata pointer for a row an older build archived', () => {
    // The merge service wrote `metadata.merged_into` before the column was
    // projected onto the Asset schema, so rows archived by an older build carry
    // it there and nowhere else. Those are exactly the stale links the banner
    // exists for.
    expect(mergedIntoId({ metadata: { merged_into: 'aaaa-bbbb' } })).toBe('aaaa-bbbb');
  });

  it('prefers the field over the fallback', () => {
    expect(mergedIntoId({ merged_into: 'field', metadata: { merged_into: 'meta' } })).toBe('field');
  });

  it('is null for an asset that was never merged', () => {
    // "Present ONLY on an asset a merge archived" — absent is the normal case
    // and must not render a banner pointing at nothing.
    expect(mergedIntoId({})).toBeNull();
    expect(mergedIntoId({ merged_into: null })).toBeNull();
    expect(mergedIntoId({ metadata: {} })).toBeNull();
    expect(mergedIntoId({ metadata: { discovery_source: 'sensor' } })).toBeNull();
  });

  it('is null for a blank or non-string pointer, never an empty link', () => {
    expect(mergedIntoId({ merged_into: '   ' })).toBeNull();
    expect(mergedIntoId({ metadata: { merged_into: '   ' } })).toBeNull();
    expect(mergedIntoId({ metadata: { merged_into: 42 } })).toBeNull();
    expect(mergedIntoId({ metadata: 'not an object' as unknown })).toBeNull();
  });
});
