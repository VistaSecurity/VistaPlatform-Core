// Canonical form (§10) as a property, not only as a table.
//
// The conformance file pins the canonical text of 222 specific queries. What it
// cannot show is that the two properties hold for queries nobody wrote down:
//
//   format(format(q)) === format(q)          — it is a normal form
//   parse(format(q))  ≡  parse(q)            — it is a normalisation, not a rewrite
//
// The second is the one that matters. A formatter that quietly changes what a
// query means while still producing text that parses is the worst shape this
// code can take — it would rewrite a stored scope into a different predicate
// and nothing would report an error.

import { describe, expect, it } from 'vitest';

import { format } from './format';
import { toJSON } from './json';
import { parse } from './parser';

function canonical(src: string): string {
  const out = parse(src);
  expect(out.ok, `parse ${JSON.stringify(src)}`).toBe(true);
  if (!out.ok) return '';
  return format(out.value.root);
}

/** A small grammar of query fragments, combined below into whole queries. */
const TERMS = [
  'environment:production',
  'hostname="Web01"',
  'hostname:=Web01',
  'risk_score >= 70',
  'risk >= high',
  'risk:not_assessed',
  'last_seen < now-24h',
  'last_seen < now-14d',
  'not_after < now+30d',
  'environment in (production, staging)',
  'environment not in (production, staging)',
  'risk_score:[40 to 69]',
  'hostname ~ "^web[0-9]{2}\\\\."',
  'exists(owner_email)',
  'owner_email:*',
  'payroll',
  '"has space"',
  '"now-24h"',
  'display_name:"five*"',
  'tag.env:prod',
  'tag:env',
  'id.mac:aa:bb:*',
  'id=550e8400-e29b-41d4-a716-446655440000',
  'class:hardware.computer.server',
  'class=server',
  'environment:(production or prod)',
  'environment:(not production and not staging)',
  'endpoint:(port:443 and protocol:tls)',
  'exists(cert)',
  'depends_on:(class=database_instance)',
  'depends_on(3):(display_name:"Payroll")',
  'depends_on(1):(class:server)',
  'used_by:(class:application)',
  'any_rel:(class:hardware)',
  'rel(connects_to, in, 2):(display_name:"core-sw-1")',
  'rel(connects_to, any):(class:server)',
  '-class:hardware',
  'not exists(owner_email)',
];

/** Combinators that must not change what the operands mean. */
function combinations(): string[] {
  const out: string[] = [...TERMS];
  for (let i = 0; i < TERMS.length; i++) {
    const a = TERMS[i];
    const b = TERMS[(i + 7) % TERMS.length];
    const c = TERMS[(i + 13) % TERMS.length];
    out.push(
      `${a} and ${b}`,
      `${a} or ${b}`,
      `${a} ${b}`, // juxtaposition is an implicit and (§2)
      `not (${a} or ${b})`,
      `not (${a} and ${b})`,
      `(${a} or ${b}) and ${c}`,
      `${a} or (${b} or ${c})`,
      `${a} and (${b} and ${c})`,
      `((${a}))`,
      `${a} and not ${b} or ${c}`,
    );
  }
  return out;
}

const QUERIES = combinations();

describe('canonical form is a normal form (§10)', () => {
  it('is idempotent for every generated query', () => {
    const notIdempotent: string[] = [];
    for (const q of QUERIES) {
      const once = canonical(q);
      const twice = canonical(once);
      if (once !== twice) notIdempotent.push(`${q}\n  once:  ${once}\n  twice: ${twice}`);
    }
    expect(notIdempotent).toEqual([]);
  });

  it('reparses to an identical tree for every generated query', () => {
    const changed: string[] = [];
    for (const q of QUERIES) {
      const before = parse(q);
      const after = parse(canonical(q));
      if (!before.ok || !after.ok) {
        changed.push(`${q}: canonical form does not parse`);
        continue;
      }
      const a = JSON.stringify(toJSON(before.value.root));
      const b = JSON.stringify(toJSON(after.value.root));
      if (a !== b) changed.push(`${q}\n  before: ${a}\n  after:  ${b}`);
    }
    expect(changed).toEqual([]);
  });

  it('covers a meaningful number of shapes', () => {
    // A property test over an empty corpus is the cheapest way to have a guard
    // that cannot fail.
    expect(QUERIES.length).toBeGreaterThan(300);
  });
});

describe('what canonical form normalises', () => {
  it('writes the implicit and, the dash negation and the := alias', () => {
    expect(canonical('environment:production class:server')).toBe(
      'environment:production and class:server',
    );
    expect(canonical('-class:hardware')).toBe('not class:hardware');
    expect(canonical('hostname:="Web01"')).toBe('hostname=Web01');
  });

  it('lowercases field names and keywords, and leaves values alone', () => {
    expect(canonical('Environment:Production AND Class:server')).toBe(
      'environment:Production and class:server',
    );
  });

  it('drops a redundant parenthesis and keeps a load-bearing one', () => {
    expect(canonical('(class:server)')).toBe('class:server');
    expect(canonical('(a:1 or b:2) and c:3')).toBe('(a:1 or b:2) and c:3');
    // An Or inside an Or would flatten into a different tree, so its
    // parentheses stay even though precedence does not require them.
    expect(canonical('a:1 or (b:2 or c:3)')).toBe('a:1 or (b:2 or c:3)');
  });

  it('writes a duration in the largest exact unit', () => {
    expect(canonical('last_seen < now-24h')).toBe('last_seen < now-1d');
    expect(canonical('last_seen < now-14d')).toBe('last_seen < now-2w');
    expect(canonical('last_seen < now-90d')).toBe('last_seen < now-90d');
    expect(canonical('last_seen < now-6months')).toBe('last_seen < now-6mo');
  });

  it('drops the default hop count and keeps any other', () => {
    expect(canonical('depends_on(1):(class:server)')).toBe('depends_on:(class:server)');
    expect(canonical('depends_on(3):(class:server)')).toBe('depends_on(3):(class:server)');
  });
});

describe('what canonical form deliberately does NOT do', () => {
  // §10: "Formatting is syntactic normalisation, not algebraic rewriting."
  it('preserves clause order', () => {
    expect(canonical('risk_score <= 10 and risk_score >= 1')).toBe(
      'risk_score <= 10 and risk_score >= 1',
    );
  });

  it('does not fold two comparisons into a range', () => {
    expect(canonical('risk_score >= 1 and risk_score <= 10')).toBe(
      'risk_score >= 1 and risk_score <= 10',
    );
  });

  it('does not rewrite a quoted value that looks like a date', () => {
    // The formatter is type-free: it cannot tell a date from a string that
    // looks like one, and `hostname="now-24h"` is a hostname. Rewriting it to
    // `hostname=now-1d` would change the stored predicate into a different one
    // that still parses (§13 S7).
    expect(canonical('hostname="now-24h"')).toBe('hostname="now-24h"');
    // Free text is a substring search and can never be an instant, so there the
    // quotes are lexical and come off — without the value changing.
    expect(canonical('"now-24h"')).toBe('now-24h');
  });
});
