// Autocomplete.
//
// The rule this is held to: autocomplete may only ever offer what the validator
// would accept. Nothing about it crosses the wire, so there is no fixture — but
// an editor that suggests a field the server then rejects has taught the user
// something false about the language, which is worse than suggesting nothing.
// The last block below substitutes every completion it produces back into a
// query and validates it.

import { describe, expect, it } from 'vitest';

import { COLLECTION_TARGET } from './catalog';
import { check } from './index';
import { CVSS_LADDER, newRegistryCatalog } from './registry-catalog';
import { lookupRelationship } from './vocabulary';
import { suggest } from './suggest';
import type { Completion, SuggestOptions } from './suggest';
import { LADDER, newTestCatalog } from './test-catalog';
import { defaultOptions, withLadder } from './validate';

const cat = newTestCatalog();
/** limit 0, so these assert what is offered rather than what survives the cap. */
const opts: SuggestOptions = { ladder: LADDER, limit: 0 };

function at(text: string, over: SuggestOptions = {}): Completion[] {
  return suggest(text, text.length, cat, { ...opts, ...over }).completions;
}

function texts(text: string, over: SuggestOptions = {}): string[] {
  return at(text, over).map((c) => c.text);
}

function span(text: string): { start: number; end: number } {
  return suggest(text, text.length, cat, opts).span;
}

function detailOf(text: string, completion: string): string | undefined {
  return at(text).find((c) => c.text === completion)?.detail;
}

describe('at the head of a term', () => {
  it('offers fields matching what has been typed', () => {
    expect(texts('host')).toContain('hostname');
    expect(texts('risk')).toEqual(expect.arrayContaining(['risk', 'risk_score', 'risk_assessed_by']));
  });

  it('ranks a prefix match above a substring match', () => {
    const out = at('name');
    const display = out.findIndex((c) => c.text === 'display_name');
    expect(display).toBeGreaterThanOrEqual(0);
    // `display_name` only contains "name"; `hostname` does too. Both are
    // substring matches, and neither outranks a prefix match that is not here.
    const prefixed = at('ris').findIndex((c) => c.text === 'risk');
    expect(prefixed).toBe(0);
  });

  it('offers the namespace prefixes, so attr. and fact. are discoverable', () => {
    expect(texts('at')).toContain('attr.');
    expect(texts('fa')).toContain('fact.');
    expect(texts('')).toContain('tag.');
  });

  it('offers no namespace the target does not carry', () => {
    // §4.2: only an asset-shaped row carries attributes, facts, identifiers and
    // tags.
    expect(texts('', { target: 'certificate' })).not.toContain('attr.');
    expect(texts('', { target: 'measurement' })).toContain('fact.');
    expect(texts('', { target: 'measurement' })).not.toContain('tag.');
  });

  it('offers the collections the target can reach, ready to open', () => {
    expect(texts('endp')).toContain('endpoint:(');
    // A certificate reaches only `asset`, so `endpoint` is not offered there.
    expect(texts('endp', { target: 'certificate' })).not.toContain('endpoint:(');
    expect(texts('as', { target: 'certificate' })).toContain('asset:(');
  });

  it('offers relationships only where traversal is available', () => {
    expect(texts('depend')).toContain('depends_on:(');
    expect(texts('any_')).toContain('any_rel:(');
    // §5.6: edges join assets, so traversal is not offered off one.
    expect(texts('depend', { target: 'certificate' })).not.toContain('depends_on:(');
  });

  it('offers the keywords', () => {
    expect(texts('ex')).toContain('exists(');
    expect(texts('no')).toContain('not');
    expect(texts('environment:production a')).toContain('and');
  });

  it('replaces the token being typed, not the whole query', () => {
    expect(span('environment:production and host')).toEqual({ start: 27, end: 31 });
    expect(span('environment:production and ')).toEqual({ start: 27, end: 27 });
  });

  it('applies the default cap, and lifts it on request', () => {
    expect(suggest('', 0, cat, { ladder: LADDER }).completions.length).toBe(50);
    expect(suggest('', 0, cat, { ladder: LADDER, limit: 0 }).completions.length).toBeGreaterThan(50);
  });
});

describe('after a field name', () => {
  it('offers the operators §4.4 allows for the type, and no others', () => {
    expect(texts('hostname ')).toEqual(expect.arrayContaining([':', '=', '!=', 'in', '~']));
    expect(texts('hostname ')).not.toContain('>=');
    expect(texts('risk_score ')).toEqual(expect.arrayContaining([':', '<', '>=', '[a to b]']));
    expect(texts('risk_score ')).not.toContain('~');
    // class takes ":" (subtree) and "=" (exact) and deliberately not "!=":
    // "not exactly this class" is better written with `not`, where the
    // three-valued rule is visible in the text.
    expect(texts('class ')).toEqual(expect.arrayContaining([':', '=', 'in']));
    expect(texts('class ')).not.toContain('!=');
    // keyword[] is the same shape: `:` contains, `=` contains, no `!=`.
    expect(texts('risk_assessed_by ')).not.toContain('!=');
  });

  it('moves on to the value as soon as the operator is complete', () => {
    // `:` could still become `:=` and `>` could become `>=`, but the value is
    // what a user is reaching for; the operators were offered one keystroke
    // earlier, after the field and a space.
    expect(texts('risk >')).toEqual(expect.arrayContaining(['critical', 'high']));
    expect(span('risk >')).toEqual({ start: 6, end: 6 });
  });

  it('offers `and` and `or` only where there is a term to join', () => {
    expect(texts('')).not.toContain('and');
    expect(texts('environment:production ')).toContain('and');
    expect(texts('environment:production and ')).not.toContain('and');
    expect(texts('endpoint:(')).not.toContain('and');
    expect(texts('endpoint:(port:443 ')).toContain('and');
    expect(texts('endpoint:(port:443) ')).toContain('and');
    // `not` needs nothing to its left and is always offered.
    expect(texts('')).toContain('not');
  });

  it('says what ":" means for this type, since it is not one thing', () => {
    expect(detailOf('hostname ', ':')).toContain('contains');
    expect(detailOf('class ', ':')).toContain('under it');
    expect(detailOf('primary_address ', ':')).toContain('CIDR');
    expect(detailOf('risk_assessed_by ', ':')).toContain('contains');
    expect(detailOf('environment ', ':')).toContain('equal');
  });
});

describe('in a value position', () => {
  it('offers the enum values of a closed set', () => {
    expect(texts('status:')).toEqual(
      expect.arrayContaining(['pending_approval', 'monitoring', 'denied', 'archived']),
    );
    expect(texts('status:mon')).toContain('monitoring');
  });

  it('works with the operator spelled with spaces', () => {
    // The reason the analysis scans forward: `risk >= ` read backwards is three
    // words, and the value position is invisible.
    expect(texts('risk >= ')).toEqual(expect.arrayContaining(['critical', 'high', 'medium']));
    expect(texts('status != ')).toContain('monitoring');
    expect(texts('risk_score >= ')).toEqual([]);
  });

  it('offers band rungs', () => {
    expect(texts('risk:')).toEqual(
      expect.arrayContaining(['critical', 'high', 'medium', 'low', 'informational']),
    );
  });

  // §13 A2: not_assessed is the absence of a score, not a rung of the ladder,
  // so it is legal with : = and != and nothing else.
  it('offers not_assessed only where the operator accepts it', () => {
    expect(texts('risk:')).toContain('not_assessed');
    expect(texts('risk != ')).toContain('not_assessed');
    expect(texts('risk >= ')).not.toContain('not_assessed');
    expect(texts('risk < ')).not.toContain('not_assessed');
  });

  it('does not offer not_assessed on a band that records no coverage', () => {
    const out = texts('severity:', { target: 'finding' });
    expect(out).toContain('critical');
    expect(out).not.toContain('not_assessed');
  });

  it('offers booleans and relative dates', () => {
    expect(texts('self_signed:', { target: 'certificate' })).toEqual(
      expect.arrayContaining(['true', 'false']),
    );
    expect(texts('not_after < ', { target: 'certificate' })).toEqual(
      expect.arrayContaining(['now', 'now-30d', 'now+30d']),
    );
  });

  it('offers the present-at-all star, but only after ":"', () => {
    expect(texts('owner_email:')).toContain('*');
    expect(texts('hostname=')).not.toContain('*');
  });

  it('offers class keys with the subtree they stand for', () => {
    // The static catalogue publishes no class keys — deliberately, so it stays
    // a faithful port of Go's testcatalog — so the production one answers this.
    const registry = newRegistryCatalog();
    const out = suggest('class:serv', 10, registry, { ladder: CVSS_LADDER, limit: 0 });
    const server = out.completions.find((c) => c.text === 'server');
    expect(server?.detail).toContain('hardware.computer.server');
    expect(server?.detail).toContain('under it');
    // With "=" the subtree is not what is matched, so the detail does not claim
    // it is.
    const exact = suggest('class=serv', 10, registry, { ladder: CVSS_LADDER, limit: 0 });
    expect(exact.completions.find((c) => c.text === 'server')?.detail).not.toContain('under it');
  });

  it('replaces only the value being typed', () => {
    expect(span('status:mon')).toEqual({ start: 7, end: 10 });
    // `:` is legal inside a bare value, so the field ends at the FIRST operator
    // and everything after it is one value.
    expect(span('id.mac:aa:bb:')).toEqual({ start: 7, end: 13 });
    expect(span('risk >= hi')).toEqual({ start: 8, end: 10 });
  });

  it('keeps the field across a list, a group and a range', () => {
    expect(texts('status in (monitoring, ')).toContain('pending_approval');
    expect(texts('status:(monitoring or ')).toContain('pending_approval');
    expect(texts('status not in (')).toContain('monitoring');
    expect(texts('risk:[low to ')).toContain('high');
  });
});

describe('inside a sub-predicate or a traversal', () => {
  it('resolves against the collection’s target, not the outer one', () => {
    expect(texts('endpoint:(po')).toContain('port');
    // `port` is an endpoint column and not an asset one.
    expect(texts('po')).not.toContain('port');
  });

  it('resolves against assets inside a traversal, because edges join assets', () => {
    expect(texts('depends_on:(host')).toContain('hostname');
    expect(texts('depends_on(3):(host')).toContain('hostname');
    expect(texts('rel(connects_to, in, 2):(host')).toContain('hostname');
    expect(texts('any_rel:(host')).toContain('hostname');
  });

  it('returns to the outer target after the predicate closes', () => {
    expect(texts('endpoint:(port:443) and host')).toContain('hostname');
    expect(texts('endpoint:(port:443) and po')).not.toContain('port');
  });

  it('is not confused by a parenthesis inside a string', () => {
    expect(texts('display_name:"a (b" and host')).toContain('hostname');
  });

  it('keeps the outer target inside a value group and an in-list', () => {
    expect(texts('environment:(prod')).not.toContain('port');
    expect(texts('environment in (prod')).not.toContain('port');
  });

  it('completes a field name inside exists()', () => {
    expect(texts('exists(owner')).toContain('owner_email');
    expect(texts('endpoint:(exists(serv')).toContain('service_name');
  });

  it('nests two levels deep', () => {
    expect(texts('depends_on:(endpoint:(po')).toContain('port');
    expect(texts('depends_on:(endpoint:(port:443) and host')).toContain('hostname');
  });
});

describe('every completion it offers is one the validator accepts', () => {
  // The property that makes autocomplete safe to trust.
  const prefixes: { text: string; target?: string }[] = [
    { text: '' },
    { text: 'ho' },
    { text: 'status:' },
    { text: 'risk:' },
    { text: 'risk >= ' },
    { text: 'risk:[low to ' },
    { text: 'environment:production and ' },
    { text: 'endpoint:(' },
    { text: 'depends_on:(' },
    { text: 'exists(' },
    { text: 'severity:', target: 'finding' },
    { text: 'transport:', target: 'endpoint' },
    { text: 'certificate_state:', target: 'certificate' },
    { text: '', target: 'observation' },
  ];

  for (const p of prefixes) {
    it(`${JSON.stringify(p.text)}${p.target === undefined ? '' : ` (${p.target})`} → every completion validates`, () => {
      const target = p.target ?? 'asset';
      const out = suggest(p.text, p.text.length, cat, { ...opts, target });
      expect(out.completions.length).toBeGreaterThan(0);
      const rejected: string[] = [];
      for (const c of out.completions) {
        const query = completeQuery(
          p.text.slice(0, out.span.start) + c.text,
          c,
          p.text,
          out.target,
        );
        if (query === null) continue;
        const res = check(query, target, cat, withLadder(defaultOptions(), LADDER));
        if (!res.ok) rejected.push(`${c.kind} ${c.text} → ${query}: ${res.errors[0].code}`);
      }
      expect(rejected).toEqual([]);
    });
  }
});

/**
 * A term that is valid on any target: its first catalogued field, present at
 * all. There is no ONE universal filler — `id` is the row's uuid on most
 * targets but `observation` has no such column, which this test found by
 * rejecting it.
 */
function filler(target: string): string {
  const first = cat.fields(target)[0];
  return `${first.name}:*`;
}

/**
 * Turns a completion into a whole query, or null when it is a fragment whose
 * completion is the user's next keystroke rather than this test's business.
 */
function completeQuery(
  base: string,
  c: Completion,
  prefix: string,
  target: string,
): string | null {
  if (c.kind === 'operator' || c.kind === 'namespace') return null;
  if (c.text.endsWith('(') && !c.text.endsWith(':(') && c.text !== 'exists(') return null;

  // Inside `exists(…)` the field IS the whole term, so it takes no operator.
  const insideExists = /exists\($/.test(prefix);

  let text = base;
  if (c.kind === 'keyword') {
    text =
      c.text === 'exists('
        ? text + cat.fields(target)[0].name + ')'
        : text + ' ' + filler(target);
  } else if (c.text.endsWith(':(')) {
    // The predicate inside is over the collection's own target, or over assets
    // when it is a traversal (§5.6).
    const name = c.text.slice(0, -2);
    const inner = lookupRelationship(name) !== null || name === 'any_rel'
      ? 'asset'
      : (COLLECTION_TARGET[name] ?? target);
    text += filler(inner);
  } else if (c.kind === 'field' && !insideExists) {
    text += ':*';
  }
  return text + closers(text);
}

/** The brackets left open in text, innermost last, ignoring quoted ones. */
function closers(text: string): string {
  const open: string[] = [];
  let quote: string | null = null;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quote !== null) {
      if (ch === '\\') i++;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") quote = ch;
    else if (ch === '(') open.push(')');
    else if (ch === '[') open.push(']');
    else if (ch === ')' || ch === ']') open.pop();
  }
  return open.reverse().join('');
}
