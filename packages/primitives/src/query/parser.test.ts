// The grammar (§2, §3), where the conformance file does not reach.
//
// The 228 shared fixtures are the contract; these are the lexical corners a
// hand-written scanner gets wrong on its own — the mode switch, the quoted head
// segment, the keyword-shaped value, and the depth ceiling that exists because
// recursive descent recurses.

import { describe, expect, it } from 'vitest';

import { toJSON } from './json';
import { MAX_DEPTH, parse } from './parser';
import { format } from './format';

function tree(src: string): unknown {
  const out = parse(src);
  expect(out.ok, `parse ${JSON.stringify(src)}`).toBe(true);
  if (!out.ok) return null;
  return toJSON(out.value.root);
}

function errorsOf(src: string): string[] {
  const out = parse(src);
  return out.ok ? [] : out.errors.map((e) => e.code);
}

describe('the value mode (§2)', () => {
  // The whole reason the scanner is mode-driven: after a field separator, `:`
  // and `/` are ordinary characters inside a value, so `id.mac:aa:bb:*` is a
  // field, a separator and ONE value — not five tokens.
  it('lets a bare value carry : and /', () => {
    expect(tree('id.mac:aa:bb:cc:dd:ee:ff')).toEqual({
      cmp: { f: 'id.mac', op: ':', v: 'aa:bb:cc:dd:ee:ff' },
    });
    expect(tree('primary_address:198.51.100.0/24')).toEqual({
      cmp: { f: 'primary_address', op: ':', v: '198.51.100.0/24' },
    });
  });

  it('reads a keyword-shaped value as a keyword, and says how to quote it', () => {
    expect(errorsOf('environment:and')).toEqual(['syntax_error']);
    expect(tree('environment:"and"')).toEqual({ cmp: { f: 'environment', op: ':', v: 'and' } });
    const out = parse('environment:and');
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.errors[0].suggestion).toContain('quote it');
  });

  // `status:in` is someone using the keyword as a value, not an empty list. The
  // parser rewinds so the diagnostic names the keyword rather than a
  // parenthesis the user never meant to write.
  it('does not mistake a bare `in` for a list', () => {
    const out = parse('status:in');
    expect(out.ok).toBe(false);
    if (!out.ok) {
      expect(out.errors[0].code).toBe('syntax_error');
      expect(out.errors[0].message).toContain('keyword');
    }
  });
});

describe('field paths (§3)', () => {
  // §3's `segment = identifier | string` holds at the HEAD of a path too.
  // Without that, `"hostname":web1` silently became two free-text terms — no
  // error, just a different query.
  it('takes a quoted head segment', () => {
    expect(tree('"hostname":web1')).toEqual({ cmp: { f: 'hostname', op: ':', v: 'web1' } });
    expect(tree('tag."cost center":eng')).toEqual({
      cmp: { f: 'tag."cost center"', op: ':', v: 'eng' },
    });
  });

  it('leaves a quoted term with no operator as free text', () => {
    expect(tree('"just text"')).toEqual({ text: 'just text' });
  });

  // `web.01` is not a field path — a digit does not start an identifier — so
  // the term was free text all along. Only the PATH parse is retried: an error
  // after the operator is a real error and must not be swallowed.
  it('falls back to free text for a dotted name that is not a path', () => {
    expect(tree('web.01')).toEqual({ text: 'web.01' });
    expect(errorsOf('hostname ~ notquoted')).toEqual(['syntax_error']);
  });

  it('lowercases an unquoted segment and keeps a quoted one', () => {
    expect(tree('Environment:Production')).toEqual({
      cmp: { f: 'environment', op: ':', v: 'Production' },
    });
    expect(tree('tag."Cost Center":x')).toEqual({
      cmp: { f: 'tag."Cost Center"', op: ':', v: 'x' },
    });
  });

  // `"not":foo` unquoted is `not:foo`, which reparses as a negation of the free
  // text ":foo" — so a keyword in HEAD position keeps its quotes.
  it('keeps quotes on a keyword head segment', () => {
    const out = parse('"not":foo');
    expect(out.ok).toBe(true);
    if (out.ok) expect(format(out.value.root)).toBe('"not":foo');
  });
});

describe('value groups (§13 A3)', () => {
  // The group grammar's `not` binds ONE value, exactly as the outer grammar's
  // `unary` binds one term. Before the amendment this query was a syntax error
  // whose suggestion told the user to quote "not" — advice that would have
  // searched for the literal string.
  it('binds `not` to one value', () => {
    expect(tree('environment:(not production and not staging)')).toEqual({
      and: [
        { not: { cmp: { f: 'environment', op: ':', v: 'production' } } },
        { not: { cmp: { f: 'environment', op: ':', v: 'staging' } } },
      ],
    });
  });

  it('desugars into the same field, with no group node', () => {
    expect(tree('environment:(a or b)')).toEqual({
      or: [
        { cmp: { f: 'environment', op: ':', v: 'a' } },
        { cmp: { f: 'environment', op: ':', v: 'b' } },
      ],
    });
  });

  // A misspelled relationship is syntactically a value group over a field of
  // that name, so the bare failure ("expected \")\"") hides the real mistake.
  // This one fails inside the group because `=` may appear in a predicate and
  // never in a value; the near-miss suggestion is what says what went wrong.
  it('suggests the relationship when a misspelled one fails to parse as a group', () => {
    const out = parse('depand_on:(class=server)');
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.errors[0].suggestion).toContain('depends_on');
  });

  // When the group DOES parse, the mistake is a field name and the validator
  // owns it — which is why the fixture for `depands_on:(class:server)` records
  // unknown_field rather than a syntax error.
  it('parses a misspelled relationship as a value group when it can', () => {
    expect(tree('depands_on:(class:server)')).toEqual({
      cmp: { f: 'depands_on', op: ':', v: 'class:server' },
    });
  });
});

describe('negation and juxtaposition', () => {
  it('reads two adjacent terms as an implicit and (§2)', () => {
    expect(tree('a:1 b:2')).toEqual(tree('a:1 and b:2'));
  });

  it('reads `-term` as `not term`', () => {
    expect(tree('-class:hardware')).toEqual(tree('not class:hardware'));
  });
});

describe('the depth ceiling', () => {
  // Recursive descent recurses, and in Go a stack overflow is a runtime FATAL
  // error that recover() cannot catch — so the parser refuses absurd nesting
  // itself rather than leaving it to the validator, which cannot run until the
  // tree exists. A query arrives from a URL, a saved view, a stored rule and an
  // AI, so this is a denial of service, not a tidiness problem.
  it('refuses nesting past MAX_DEPTH with too_many_clauses', () => {
    const deep = '('.repeat(MAX_DEPTH + 10) + 'class:server' + ')'.repeat(MAX_DEPTH + 10);
    expect(errorsOf(deep)).toEqual(['too_many_clauses']);
  });

  it('still accepts nesting just inside it', () => {
    // Each parenthesis costs two levels (parseOr, then the group), so this is
    // comfortably legal and proves the ceiling is not merely always-on.
    const shallow = '('.repeat(8) + 'class:server' + ')'.repeat(8);
    expect(errorsOf(shallow)).toEqual([]);
  });

  it('counts a unary chain, which has no parenthesis to count', () => {
    expect(errorsOf('not '.repeat(MAX_DEPTH + 10) + 'class:server')).toEqual(['too_many_clauses']);
  });

  it('does not overflow the stack on a pathological input', () => {
    // The shape the ceiling exists for: if it were missing this would take the
    // process down rather than return a diagnostic.
    expect(errorsOf('('.repeat(200000))).toEqual(['too_many_clauses']);
  });
});

describe('strings (§2)', () => {
  it('decodes the documented escapes', () => {
    expect(tree('display_name:"a\\nb"')).toEqual({ cmp: { f: 'display_name', op: ':', v: 'a\nb' } });
    expect(tree('display_name:"\\u0041"')).toEqual({ cmp: { f: 'display_name', op: ':', v: 'A' } });
    expect(tree("display_name:'single'")).toEqual({
      cmp: { f: 'display_name', op: ':', v: 'single' },
    });
  });

  it('rejects an unknown escape and an unterminated string', () => {
    expect(errorsOf('hostname ~ "^web\\d"')).toEqual(['syntax_error']);
    expect(errorsOf('display_name:"web')).toEqual(['syntax_error']);
  });

  // A lone surrogate is half of a UTF-16 pair and is not a character. Go's
  // WriteRune would substitute U+FFFD, so \ud800 and \udfff would decode to the
  // SAME value — two different queries, one stored predicate. JavaScript would
  // instead keep the lone surrogate, which is a different wrong answer for the
  // same reason. Both sides refuse it.
  it('refuses an unpaired surrogate escape', () => {
    expect(errorsOf('display_name:"\\ud800"')).toEqual(['syntax_error']);
    expect(errorsOf('display_name:"\\udfff"')).toEqual(['syntax_error']);
  });
});

describe('the empty query', () => {
  it('parses to nothing, which matches everything under RLS (§8)', () => {
    const out = parse('');
    expect(out.ok).toBe(true);
    if (out.ok) {
      expect(out.value.root).toBeNull();
      expect(format(out.value.root)).toBe('');
    }
    expect(parse('   ').ok).toBe(true);
  });
});
