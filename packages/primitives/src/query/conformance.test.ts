// The cross-language contract.
//
// `shared/query/testdata/conformance.json` is the file Go's
// `shared/query/conformance_test.go` runs, and this test runs the same file
// against the TypeScript port. Every case must pass; a case this port cannot
// pass is a bug in the port, not a reason to skip.
//
// Three of the file's five assertions apply here. `canonical`, `ast` and
// `errors` are the language; `sql` and `sql_errors` are the server's
// translator, which this side deliberately does not have — so a case whose only
// expectation is an `sql_errors` entry is, from here, a case that must validate
// cleanly, and it is checked as one.
//
// The fixture is read from the Go tree rather than copied. A copy is a fixture
// that can go stale without anything failing, which is the whole hazard the
// file exists to remove.

/// <reference types="node" />
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { toJSON } from './json';
import type { JSONValue } from './json';
import { format } from './format';
import { parse } from './parser';
import { newTestCatalog, LADDER } from './test-catalog';
import { defaultOptions, validate, withLadder } from './validate';
import type { Options } from './validate';

/** One conformance case, exactly as the file records it. */
interface Case {
  name: string;
  query: string;
  target?: string;
  twin?: string;
  note?: string;
  options?: CaseOptions;
  canonical?: string;
  ast?: JSONValue;
  errors?: { code: string }[];
  sql?: { where: string; arg_count: number; args?: JSONValue };
  sql_errors?: { code: string }[];
}

interface CaseOptions {
  max_bytes?: number;
  max_leaves?: number;
  max_subs?: number;
  max_paren_depth?: number;
  max_in_values?: number;
  max_regex_len?: number;
  max_repetition?: number;
  traversal_budget?: number;
}

const FIXTURE_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  '../../../../shared/query/testdata/conformance.json',
);

const CASES: Case[] = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as Case[];

/** What this port produced for a case: the three fields it owns. */
interface Ran {
  canonical: string;
  /** undefined when the text did not parse, mirroring the fixture's omission. */
  ast: JSONValue | undefined;
  errors: { code: string }[] | undefined;
}

function run(c: Case): Ran {
  const target = c.target === undefined || c.target === '' ? 'asset' : c.target;
  const cat = newTestCatalog();

  const parsed = parse(c.query);
  if (!parsed.ok) {
    return { canonical: '', ast: undefined, errors: parsed.errors.map((e) => ({ code: e.code })) };
  }
  const canonical = format(parsed.value.root);
  const ast = toJSON(parsed.value.root);

  const outcome = validate(parsed.value, target, cat, caseOptions(c));
  if (!outcome.ok) {
    return { canonical, ast, errors: outcome.errors.map((e) => ({ code: e.code })) };
  }
  return { canonical, ast, errors: undefined };
}

function caseOptions(c: Case): Options {
  const opts = withLadder(defaultOptions(), LADDER);
  const o = c.options;
  if (o === undefined) return opts;
  // A zero in the file means "not overridden", exactly as Go's `omitempty`
  // encoding of the struct means.
  if (o.max_bytes) opts.maxBytes = o.max_bytes;
  if (o.max_leaves) opts.maxLeaves = o.max_leaves;
  if (o.max_subs) opts.maxSubs = o.max_subs;
  if (o.max_paren_depth) opts.maxParenDepth = o.max_paren_depth;
  if (o.max_in_values) opts.maxInValues = o.max_in_values;
  if (o.max_regex_len) opts.maxRegexLen = o.max_regex_len;
  if (o.max_repetition) opts.maxRepetition = o.max_repetition;
  if (o.traversal_budget) opts.traversalBudget = o.traversal_budget;
  return opts;
}

describe('conformance', () => {
  it('the fixture file is present and non-empty', () => {
    expect(CASES.length).toBeGreaterThan(0);
  });

  it('has no duplicate case names', () => {
    const seen = new Set<string>();
    const duplicates: string[] = [];
    for (const c of CASES) {
      if (seen.has(c.name)) duplicates.push(c.name);
      seen.add(c.name);
    }
    expect(duplicates).toEqual([]);
  });

  for (const c of CASES) {
    it(c.name, () => {
      const got = run(c);
      expect(got.canonical).toBe(c.canonical ?? '');
      expect(got.ast).toEqual('ast' in c ? c.ast : undefined);
      expect(got.errors).toEqual(c.errors);
    });
  }
});

describe('conformance — the properties, not the table', () => {
  // §10: canonical text reparses to the same tree, and formatting is
  // idempotent. Go asserts both; they are the reason canonical form can be what
  // a scope stores.
  for (const c of CASES) {
    if (c.canonical === undefined || c.canonical === '') continue;
    it(`round-trips: ${c.name}`, () => {
      const first = parse(c.query);
      expect(first.ok).toBe(true);
      if (!first.ok) return;
      const again = parse(c.canonical as string);
      expect(again.ok).toBe(true);
      if (!again.ok) return;
      expect(toJSON(again.value.root)).toEqual(toJSON(first.value.root));
      expect(format(again.value.root)).toBe(c.canonical);
    });
  }

  // A case whose only expectation is an `sql_errors` entry validates cleanly on
  // this side — the failure is the server's translator having no shape for it,
  // which is a statement about SQL, not about the language. Asserting that
  // explicitly stops those four cases from being silently "not checked here".
  it('every sql-only failure still validates', () => {
    const sqlOnly = CASES.filter(
      (c) => (c.sql_errors ?? []).length > 0 && (c.errors ?? []).length === 0,
    );
    expect(sqlOnly.length).toBeGreaterThan(0);
    for (const c of sqlOnly) {
      expect(run(c).errors, c.name).toBeUndefined();
    }
  });

  // §6's closing paragraph, and the half of it that is easy to lose: a rule
  // must reject the thing it names AND accept the nearest legal query. The Go
  // suite enforces the twin convention over the file; this one checks that the
  // port actually produces both polarities, which is the part a port can get
  // wrong on its own.
  it('every failing case has a passing twin, and the port agrees about both', () => {
    const byName = new Map(CASES.map((c) => [c.name, c]));
    const fails = (c: Case): boolean =>
      (c.errors ?? []).length > 0 || (c.sql_errors ?? []).length > 0;

    for (const c of CASES) {
      if (!fails(c)) continue;
      const twin =
        c.twin !== undefined && c.twin !== ''
          ? c.twin
          : c.name.endsWith('-bad')
            ? c.name.slice(0, -'-bad'.length) + '-ok'
            : null;
      expect(twin, `${c.name} names no nearest-passing twin`).not.toBeNull();
      const pair = byName.get(twin as string);
      expect(pair, `${c.name} has no twin ${String(twin)}`).toBeDefined();
      if (pair === undefined) continue;
      expect(run(pair).errors, `${pair.name} is meant to pass`).toBeUndefined();
      if ((c.errors ?? []).length > 0) {
        expect(run(c).errors, `${c.name} is meant to fail`).toBeDefined();
      }
    }
  });

  // §6's code vocabulary, from this side: every code the file exercises through
  // parse or validation is one the port can actually produce. A code the port
  // silently never emits would show up as a fixture mismatch case by case, but
  // this says it in one line.
  it('produces every validation code the fixture exercises', () => {
    const expected = new Set<string>();
    for (const c of CASES) for (const e of c.errors ?? []) expected.add(e.code);
    const produced = new Set<string>();
    for (const c of CASES) for (const e of run(c).errors ?? []) produced.add(e.code);
    expect([...produced].sort()).toEqual([...expected].sort());
  });
});
