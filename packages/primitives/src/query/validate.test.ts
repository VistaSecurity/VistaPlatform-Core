// §6's rules, in both polarities.
//
// "The validator is mutation-tested in both polarities: each rule must reject
// the thing it names AND accept the nearest legal query, because an over-strict
// guard is the same bug pointed the other way." (§6.) The conformance file
// carries a twin for every failing case; these add the ones a port can get
// wrong on its own — chiefly the caps whose units differ, and the suggestions,
// which the fixture deliberately does not pin so wording can improve.

import { describe, expect, it } from 'vitest';

import { check } from './index';
import type { QueryError } from './errors';
import { parse } from './parser';
import { LADDER, newTestCatalog } from './test-catalog';
import { defaultOptions, validate, withLadder } from './validate';
import type { Options } from './validate';

const cat = newTestCatalog();

function opts(over: Partial<Options> = {}): Options {
  return { ...withLadder(defaultOptions(), LADDER), ...over };
}

function codes(src: string, target = 'asset', over: Partial<Options> = {}): string[] {
  const out = check(src, target, cat, opts(over));
  return out.ok ? [] : out.errors.map((e) => e.code);
}

function firstError(src: string, target = 'asset', over: Partial<Options> = {}): QueryError {
  const out = check(src, target, cat, opts(over));
  if (out.ok) throw new Error(`expected ${JSON.stringify(src)} to fail`);
  return out.errors[0];
}

/** Every rule, with the nearest query that must still be accepted. */
const BOTH_POLARITIES: { rule: string; bad: string; code: string; ok: string; over?: Partial<Options> }[] = [
  { rule: 'unknown_field', bad: 'hostnaem:web-1', code: 'unknown_field', ok: 'hostname:web-1' },
  {
    rule: 'unknown_field (namespace key)',
    bad: 'attr.not_registered:1',
    code: 'unknown_field',
    ok: 'attr.os_version:1',
  },
  {
    rule: 'operator_not_allowed',
    bad: 'environment < production',
    code: 'operator_not_allowed',
    ok: 'environment:production',
  },
  { rule: 'type_mismatch', bad: 'risk >= 70', code: 'type_mismatch', ok: 'risk_score >= 70' },
  { rule: 'unknown_value', bad: 'status:monitorng', code: 'unknown_value', ok: 'status:monitoring' },
  {
    rule: 'unknown_value (class)',
    bad: 'class:serverr',
    code: 'unknown_value',
    ok: 'class:server',
  },
  {
    rule: 'depth_exceeded',
    bad: 'depends_on(4):(class:server)',
    code: 'depth_exceeded',
    ok: 'depends_on(3):(class:server)',
  },
  {
    rule: 'regex_invalid',
    bad: 'hostname ~ "\\\\bweb"',
    code: 'regex_invalid',
    ok: 'hostname ~ "^web"',
  },
  {
    rule: 'query_too_long',
    bad: 'environment:production and class:server',
    code: 'query_too_long',
    ok: 'class:server',
    over: { maxBytes: 20 },
  },
  {
    rule: 'too_many_clauses',
    bad: 'class:server and environment:production and status:monitoring',
    code: 'too_many_clauses',
    ok: 'class:server and environment:production',
    over: { maxLeaves: 2 },
  },
  {
    rule: 'untranslatable (free text off-target)',
    bad: 'payroll',
    code: 'untranslatable',
    ok: 'subject_dn:payroll',
  },
];

describe('§6, in both polarities', () => {
  for (const c of BOTH_POLARITIES) {
    it(`${c.rule}: rejects the thing it names`, () => {
      const target = c.rule.includes('off-target') ? 'certificate' : 'asset';
      expect(codes(c.bad, target, c.over)).toContain(c.code);
    });
    it(`${c.rule}: accepts the nearest legal query`, () => {
      const target = c.rule.includes('off-target') ? 'certificate' : 'asset';
      expect(codes(c.ok, target, c.over)).toEqual([]);
    });
  }
});

describe('the caps, and the units they are measured in', () => {
  // The fixture file is pure ASCII, so it cannot tell a byte cap from a
  // character cap. §6 says the query cap is BYTES and the regex cap is
  // CHARACTERS, "on purpose" — a port that used `String.length` for both would
  // pass all 228 fixtures and then disagree with the server on the first
  // accented hostname.
  it('measures the query cap in bytes, not code units', () => {
    // 10 accented characters: 10 code units, 20 UTF-8 bytes.
    const q = 'display_name:"' + 'é'.repeat(10) + '"';
    expect(q.length).toBe(25);
    expect(codes(q, 'asset', { maxBytes: 30 })).toEqual(['query_too_long']);
    expect(codes(q, 'asset', { maxBytes: 40 })).toEqual([]);
  });

  it('measures the regex cap in code points, not bytes', () => {
    // Eight accented characters is eight CHARACTERS and sixteen bytes.
    const q = 'hostname ~ "' + 'é'.repeat(8) + '"';
    expect(codes(q, 'asset', { maxRegexLen: 8 })).toEqual([]);
    expect(codes(q, 'asset', { maxRegexLen: 7 })).toEqual(['regex_invalid']);
  });

  it('caps the values in one list', () => {
    // `business_unit`, not `environment`: the latter is a closed set since
    // §12 A1, and arbitrary values there would fail for a second, unrelated
    // reason — which would make this test pass for the wrong one.
    expect(codes('business_unit in (a, b, c)', 'asset', { maxInValues: 2 })).toEqual([
      'too_many_clauses',
    ]);
    expect(codes('business_unit in (a, b)', 'asset', { maxInValues: 2 })).toEqual([]);
  });

  it('caps parenthesis nesting on what was WRITTEN, not what survives formatting', () => {
    // Canonical form drops redundant parentheses, so the AST no longer shows
    // what the user typed; the depth is measured at parse time for that reason.
    expect(codes('(((class:server)))', 'asset', { maxParenDepth: 2 })).toEqual([
      'too_many_clauses',
    ]);
    expect(codes('((class:server))', 'asset', { maxParenDepth: 2 })).toEqual([]);
  });

  it('applies the hard traversal maximum over any configured budget (§5.6)', () => {
    expect(codes('depends_on(7):(class:server)', 'asset', { traversalBudget: 10 })).toEqual([
      'depth_exceeded',
    ]);
    expect(codes('depends_on(6):(class:server)', 'asset', { traversalBudget: 10 })).toEqual([]);
  });

  it('sums declared depths along the deepest nested path', () => {
    // 2 + 1 = 3 is exactly the default budget; 2 + 2 is not.
    expect(codes('depends_on(2):(hosted_on:(class:hypervisor))')).toEqual([]);
    expect(codes('depends_on(2):(hosted_on(2):(class:hypervisor))')).toEqual(['depth_exceeded']);
  });
});

describe('the regex dialect (§13 A6)', () => {
  // Each of these is inside RE2 and outside what Postgres does with it, or the
  // other way round. `\b` is the one that matters most: it compiles as RE2,
  // validates, reaches Postgres — where it is a BACKSPACE — and returns the
  // wrong rows with no error anywhere.
  const outside = [
    ['\\\\bweb\\\\b', 'word boundary is a backspace in ARE'],
    ['web(?i)01', '(?i) is a prefix-only flag'],
    ['(?<name>x)', 'named groups'],
    ['x\\\\z', 'anchors outside the subset'],
    ['\\\\p{L}', 'unicode classes'],
    ['a+?', 'non-greedy quantifiers mean different things'],
    ['[[:alpha:]]', 'POSIX classes inside a class'],
    ['a{256}', 'past Postgres DUPMAX'],
  ];
  for (const [pattern, why] of outside) {
    it(`rejects ${pattern} — ${why}`, () => {
      expect(codes(`hostname ~ "${pattern}"`)).toEqual(['regex_invalid']);
    });
  }

  const inside = ['^web[0-9]{2}$', '(?i)web', 'a{255}', '(a|b)+', '\\\\d+\\\\.\\\\d+', '[^a-z]'];
  for (const pattern of inside) {
    it(`accepts ${pattern}`, () => {
      expect(codes(`hostname ~ "${pattern}"`)).toEqual([]);
    });
  }

  it('caps the repetition PRODUCT across nesting, separately from a single count', () => {
    // Each bound is legal on its own; Postgres calls their product "too
    // complex", which reaches a user as a 500 rather than a diagnostic.
    expect(codes('hostname ~ "(a{100}){100}"')).toEqual(['regex_invalid']);
    expect(codes('hostname ~ "(a{10}){100}"')).toEqual([]);
  });
});

describe('three-valued logic, as the validator can see it (§5.2)', () => {
  // `not_assessed` is the absence of a score, not a rung of the ladder. Before
  // §13 A2, `risk < not_assessed` validated and then returned every unassessed
  // asset, and `risk:[not_assessed to high]` validated and then failed
  // `untranslatable` — a code §6 reserves for a parser bug.
  it('allows not_assessed only with : = and !=', () => {
    expect(codes('risk:not_assessed')).toEqual([]);
    expect(codes('risk != not_assessed')).toEqual([]);
    expect(codes('risk < not_assessed')).toEqual(['operator_not_allowed']);
    expect(codes('risk:[not_assessed to high]')).toEqual(['operator_not_allowed']);
  });

  it('refuses not_assessed on a band that records no coverage', () => {
    // `finding.severity` has no assessedBy column, so "nobody assessed it" is
    // not a question that field can answer.
    expect(codes('severity:not_assessed', 'finding')).toEqual(['unknown_value']);
    expect(codes('severity:critical', 'finding')).toEqual([]);
  });

  it('refuses a version field with no normalised sort key', () => {
    // §5.5 forbids a lexical fallback outright, so a version field whose
    // accessor names no sort column is untranslatable rather than compared as
    // a string. Every version field in the catalogue HAS one, which is what the
    // passing half proves.
    expect(codes('version:3.0', 'software_install')).toEqual([]);
    const res = parse('version:3.0');
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    const stripped = {
      ...cat,
      targets: () => cat.targets(),
      fields: (t: string) => cat.fields(t),
      relationshipNames: () => cat.relationshipNames(),
      classExists: (k: string) => cat.classExists(k),
      enumValues: () => null,
      resolve: (t: string, p: string[]) => {
        const out = cat.resolve(t, p);
        if (!out.ok) return out;
        return { ok: true as const, field: { ...out.field, accessor: { ...out.field.accessor, sortColumn: '' } } };
      },
    };
    const out = validate(res.value, 'software_install', stripped, opts());
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.errors.map((e) => e.code)).toEqual(['untranslatable']);
  });

  it('refuses a band field when no ladder was supplied', () => {
    // Without a ladder a band is untranslatable — refused, not guessed at.
    const noLadder = defaultOptions();
    expect(check('risk:high', 'asset', cat, noLadder)).toMatchObject({
      ok: false,
      errors: [{ code: 'untranslatable' }],
    });
    expect(check('risk_score >= 70', 'asset', cat, noLadder).ok).toBe(true);
  });
});

describe('reachability of a target (§5.1, §5.6)', () => {
  it('refuses a collection the target cannot reach, and names the ones it can', () => {
    const e = firstError('finding:(kind:stale)', 'endpoint');
    expect(e.code).toBe('untranslatable');
    expect(e.suggestion).toContain('asset');
    expect(codes('asset:(class:server)', 'endpoint')).toEqual([]);
  });

  it('refuses traversal off an asset, and says how to wrap it', () => {
    const e = firstError('depends_on:(class:server)', 'certificate');
    expect(e.code).toBe('untranslatable');
    expect(e.suggestion).toContain('asset:(depends_on:(…))');
    expect(codes('asset:(depends_on:(class:server))', 'certificate')).toEqual([]);
  });

  it('refuses a reverse label in the explicit rel() form and offers both spellings', () => {
    const e = firstError('rel(used_by, out):(class:server)');
    expect(e.code).toBe('unknown_value');
    expect(e.suggestion).toContain('rel(depends_on, in, …)');
    expect(e.suggestion).toContain('used_by:(…)');
    expect(codes('used_by:(class:server)')).toEqual([]);
  });
});

describe('the suggestions §10 asks for', () => {
  it('names the closest field within edit distance 2', () => {
    expect(firstError('hostnaem:web-1').suggestion).toBe('did you mean "hostname"?');
  });

  it('points a bare namespace at its key form', () => {
    const e = firstError('attr:1');
    expect(e.code).toBe('unknown_field');
    expect(e.suggestion).toContain('attr.<key>');
  });

  it('names where the other namespaces live when nothing is close', () => {
    const e = firstError('completely_unrelated:1');
    expect(e.suggestion).toContain('attr.<name>');
    expect(e.suggestion).toContain('fact.<key>');
  });

  it('sends a numeric band comparison to the numeric twin', () => {
    // §10's worked example. The twin is found through the catalogue — the field
    // sharing the band's column — not hard-coded as a pair.
    expect(firstError('risk >= 70').suggestion).toBe('for the numeric score use "risk_score >= 70"');
  });

  it('sends the retired any-kind identifier spelling to id.any (§13 A1)', () => {
    const e = firstError('id:"aa:bb:cc:dd:ee:ff"');
    expect(e.code).toBe('type_mismatch');
    expect(e.suggestion).toContain('id.any');
    expect(codes('id.any:"aa:bb:cc:dd:ee:ff"')).toEqual([]);
  });

  it('offers the longer enum value a short one is a prefix of', () => {
    // §12 contradiction 2: §9 example 12 writes `status:pending` and the
    // vocabulary is `pending_approval`. Edit distance alone would not find it.
    expect(firstError('status:pending').suggestion).toBe('did you mean "pending_approval"?');
  });
});

describe('errors are ordered and complete', () => {
  it('reports every problem at once, sorted by span', () => {
    const out = check('hostnaem:a and stauts:b', 'asset', cat, opts());
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.errors.map((e) => e.code)).toEqual(['unknown_field', 'unknown_field']);
    expect(out.errors[0].span.start).toBeLessThan(out.errors[1].span.start);
  });

  it('underlines the offending span', () => {
    const e = firstError('environment:production and hostnaem:web-1');
    expect('environment:production and hostnaem:web-1'.slice(e.span.start, e.span.end)).toBe(
      'hostnaem',
    );
  });
});
