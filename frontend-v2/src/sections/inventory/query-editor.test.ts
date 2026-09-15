// The query editor's two contracts: what it accepts, and what it says when it
// does not.
//
// There is no DOM harness in this project (vitest runs in `node`), so the tests
// are over the two pure functions the component is built out of — which is where
// the behaviour actually lives. `checkAssetQuery` decides the red border and
// whether Run is enabled; `suggestAssetQuery` decides the completion list. The
// component is the thin part.
//
// The rule the completions are held to is the package's own, and it is the one
// worth pinning here: an editor may only ever offer what the validator would
// accept. Suggesting a field the server then rejects teaches the user something
// false about the language, which is worse than suggesting nothing.
import { describe, expect, it } from 'vitest';
import { checkAssetQuery, splitFieldSpans, suggestAssetQuery } from './query-editor';

describe('checkAssetQuery', () => {
  it('accepts the empty query — which is "everything", not an error', () => {
    const out = checkAssetQuery('');
    expect(out.ok).toBe(true);
    expect(out.canonical).toBe('');
    expect(out.errors).toEqual([]);
  });

  it('accepts a query over the real asset vocabulary and returns CANONICAL text', () => {
    const out = checkAssetQuery('environment:production AND risk >= high');
    expect(out.ok).toBe(true);
    // Lowercased keywords, one space around operators (§10). This is the text a
    // saved view stores, so two spellings of one predicate become one string.
    expect(out.canonical).toBe('environment:production and risk >= high');
  });

  it('resolves a class attribute through the generated schemas', () => {
    // `attr.<name>` had an EMPTY vocabulary before workstream 0.8e, so every
    // attribute reported unknown_field. This is the guard that it does not
    // regress to that.
    expect(checkAssetQuery('attr.operating_system:Ubuntu').ok).toBe(true);
  });

  it('rejects an unknown field, names the span, and suggests the near miss', () => {
    const out = checkAssetQuery('environment:production and hostnaem:web-1');
    expect(out.ok).toBe(false);
    const [err] = out.errors;
    expect(err.code).toBe('unknown_field');
    // The SPAN is what the editor underlines. A message that names the field is
    // useful; one that points at it in what the user typed is the difference
    // between reading an error and seeing one.
    expect('environment:production and hostnaem:web-1'.slice(err.span.start, err.span.end)).toBe('hostnaem');
    expect(`${err.message} ${err.suggestion ?? ''}`).toContain('hostname');
  });

  it('rejects a band compared as a number, and says what to write instead', () => {
    const out = checkAssetQuery('risk >= 70');
    expect(out.ok).toBe(false);
    expect(out.errors[0].code).toBe('type_mismatch');
    expect(`${out.errors[0].message} ${out.errors[0].suggestion ?? ''}`).toContain('risk_score');
  });

  it('rejects a syntax error rather than guessing', () => {
    expect(checkAssetQuery('class:(((').ok).toBe(false);
  });

  it('reports EVERY error, not just the first', () => {
    // The editor renders one line per error. Stopping at the first would make a
    // user fix a query one round trip at a time.
    const out = checkAssetQuery('hostnaem:a and enviroment:b');
    expect(out.ok).toBe(false);
    expect(out.errors.length).toBeGreaterThanOrEqual(2);
  });

  it('gives every error a span inside the source text', () => {
    // A span outside the text would render the highlight over nothing.
    const source = 'class:server and hostnaem:web-1';
    const out = checkAssetQuery(source);
    expect(out.ok).toBe(false);
    for (const e of out.errors) {
      expect(e.span.start).toBeGreaterThanOrEqual(0);
      expect(e.span.end).toBeLessThanOrEqual(source.length);
      expect(e.span.end).toBeGreaterThan(e.span.start);
    }
  });
});

describe('suggestAssetQuery', () => {
  it('offers asset fields at the head of a term', () => {
    const out = suggestAssetQuery('env', 3);
    expect(out.completions.map((c) => c.text)).toContain('environment');
  });

  it('offers a field’s closed value set after its colon', () => {
    const out = suggestAssetQuery('environment:', 12);
    expect(out.completions.map((c) => c.text)).toContain('production');
  });

  it('offers class keys after class:', () => {
    const out = suggestAssetQuery('class:', 6);
    const texts = out.completions.map((c) => c.text);
    expect(texts).toContain('server');
  });

  it('offers not_assessed after risk: but NOT after risk >=', () => {
    // `not_assessed` is the ABSENCE of a score, not a rung of the ladder
    // (§13 A2). Offering it after `>=` would suggest a query the validator
    // rejects — the exact thing the completion rule forbids.
    expect(suggestAssetQuery('risk:', 5).completions.map((c) => c.text)).toContain('not_assessed');
    expect(suggestAssetQuery('risk >= ', 8).completions.map((c) => c.text)).not.toContain('not_assessed');
  });

  it('only ever offers completions the VALIDATOR would accept', () => {
    // The package's own rule, re-checked here against the production catalogue:
    // substitute each completion back into the query and validate the result.
    for (const prefix of ['', 'class:server and ', 'environment:']) {
      const out = suggestAssetQuery(prefix, prefix.length);
      expect(out.completions.length).toBeGreaterThan(0);
      for (const c of out.completions.slice(0, 12)) {
        const substituted = prefix.slice(0, out.span.start) + c.text + prefix.slice(out.span.end);
        const checked = checkAssetQuery(substituted);
        // A completion may leave the query INCOMPLETE ("environment:" alone is
        // a partial term), so the bar is that it must not be a *semantic*
        // error — an unknown field or value the server would reject.
        if (!checked.ok) {
          expect(checked.errors.map((e) => e.code)).not.toContain('unknown_field');
          expect(checked.errors.map((e) => e.code)).not.toContain('unknown_value');
        }
      }
    }
  });

  it('reports the span it would replace, so the editor can splice correctly', () => {
    const out = suggestAssetQuery('class:ser', 9);
    expect(out.span.end).toBe(9);
    expect('class:ser'.slice(out.span.start, out.span.end)).toBe('ser');
  });
});

// The read-only rendering, used on the scope row and anywhere a stored query is
// shown rather than edited.
describe('splitFieldSpans — what QueryChip highlights', () => {
  it('splits a query into field runs and the rest, losing nothing', () => {
    const q = 'environment:production and risk >= high';
    const parts = splitFieldSpans(q);
    expect(parts.map((p) => p.text).join('')).toBe(q);
    expect(parts.filter((p) => p.field).map((p) => p.text)).toEqual(['environment', 'risk']);
  });

  it('does NOT highlight a value that merely looks like a field name', () => {
    // The highlighting comes from the parser's resolved field spans, not from a
    // regex over the text, so it cannot disagree with what the query means.
    const parts = splitFieldSpans('hostname:"environment"');
    expect(parts.filter((p) => p.field).map((p) => p.text)).toEqual(['hostname']);
  });

  it('highlights a namespaced field as one run', () => {
    expect(splitFieldSpans('attr.operating_system:Ubuntu').filter((p) => p.field).map((p) => p.text))
      .toEqual(['attr.operating_system']);
  });

  it('leaves a query that does not parse as ONE unhighlighted run', () => {
    // Highlighting a guess at a broken query would invent structure that is not
    // there.
    expect(splitFieldSpans('class:(((')).toEqual([{ text: 'class:(((', field: false }]);
  });

  it('returns nothing for an empty query', () => {
    expect(splitFieldSpans('')).toEqual([]);
  });

  it('never loses or reorders text, for every shape the rail writes', () => {
    for (const q of [
      'class:server',
      'class:server and status:monitoring',
      'environment:production or environment:staging',
      'tag.tier:gold',
      'not finding:(detection_state:ACTIVE)',
      'endpoint:(port:443 and protocol:tls)',
    ]) {
      expect(splitFieldSpans(q).map((p) => p.text).join('')).toBe(q);
    }
  });
});
