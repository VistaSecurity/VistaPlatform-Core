// The facet rail ↔ query string round trip.
//
// The rail is a BUILDER over one query string, not a parallel filter model, and
// the property that makes that safe is round-tripping: what the rail writes, the
// rail must read back, and what it cannot read back it must carry forward
// untouched. Both halves are tested here, and the second half is the one that
// would have been easy to skip and expensive to get wrong — a reader that
// silently dropped a term the rail could not show would delete the user's work
// on their next checkbox click.
import { describe, expect, it } from 'vitest';
import { check, defaultOptions, newRegistryCatalog, CVSS_LADDER, withLadder } from '@vistasecurity/primitives/query';
import { OPEN_FINDINGS_QUERY } from '@vistasecurity/primitives/findings';
import {
  applyFacetChange, cycleFindings, emptyFacets, facetCount, facetsEmpty, facetsToQuery,
  FACET_LABEL, OPEN_FINDINGS, queryToFacets, quoteValue, setFacetClass, toggleFacetValue,
  type FacetState,
} from './facet-query';

const CATALOG = newRegistryCatalog();
const OPTIONS = withLadder(defaultOptions(), CVSS_LADDER);

/** Every query the rail produces must be one the SERVER would accept. A rail
 *  that writes a query the validator rejects has made the page unusable with a
 *  click, which is worse than not offering the filter. */
function assertValid(query: string) {
  if (query === '') return;
  const out = check(query, 'asset', CATALOG, OPTIONS);
  if (!out.ok) {
    throw new Error(`rail produced an invalid query: ${query}\n${out.errors.map((e) => `${e.code}: ${e.message}`).join('\n')}`);
  }
}

function facets(over: Partial<FacetState> = {}): FacetState {
  return { ...emptyFacets(), ...over };
}

describe('facetsToQuery', () => {
  it('is the empty string when nothing is selected — which matches everything under RLS', () => {
    expect(facetsToQuery(emptyFacets())).toBe('');
    expect(facetsEmpty(emptyFacets())).toBe(true);
  });

  it('writes a class facet as a SUBTREE match', () => {
    // `class:hardware` selects every hardware descendant. That is what lets one
    // faceted list replace the lens-per-class the ADR rejected.
    const q = facetsToQuery(facets({ class: 'hardware' }));
    expect(q).toBe('class:hardware');
    assertValid(q);
  });

  it('writes one value as field:value and several as a field:(a or b) group', () => {
    expect(facetsToQuery(facets({ environment: ['production'] }))).toBe('environment:production');
    // The stored text is the CANONICAL form (§10), which expands the group into
    // an explicit disjunction and drops parentheses precedence does not need.
    // That is the point of storing canonical text: the shape a user typed and
    // the shape a checkbox produced become one string.
    const many = facetsToQuery(facets({ environment: ['production', 'staging'] }));
    expect(many).toBe('environment:production or environment:staging');
    assertValid(many);
  });

  it('ANDs across facets and ORs within one', () => {
    const q = facetsToQuery(facets({ class: 'server', environment: ['production', 'staging'], status: ['monitoring'] }));
    expect(q).toBe('class:server and status:monitoring and (environment:production or environment:staging)');
    assertValid(q);
  });

  it('writes the risk facet by BAND NAME, including not_assessed', () => {
    // `not_assessed` is the absence of a score, not a rung of the ladder — it is
    // written `risk:not_assessed` and never `risk >= not_assessed` (§13 A2).
    const q = facetsToQuery(facets({ risk: ['high', 'not_assessed'] }));
    expect(q).toBe('risk:high or risk:not_assessed');
    assertValid(q);
  });

  it('writes a bare tag key as tag:key and a key=value as tag.key:value', () => {
    expect(facetsToQuery(facets({ tag: ['pci'] }))).toBe('tag:pci');
    const kv = facetsToQuery(facets({ tag: ['tier=gold'] }));
    expect(kv).toBe('tag.tier:gold');
    assertValid(kv);
  });

  it('quotes a value that is not a safe bareword', () => {
    expect(quoteValue('Payments EU')).toBe('"Payments EU"');
    expect(quoteValue('simple-value_1')).toBe('simple-value_1');
    // A keyword as a bare value would reparse as syntax.
    expect(quoteValue('and')).toBe('"and"');
    const q = facetsToQuery(facets({ business_unit: ['Payments EU'] }));
    expect(q).toBe('business_unit:"Payments EU"');
    assertValid(q);
  });

  it('emits CANONICAL text, which is what a saved view stores', () => {
    // The rail joins with explicit `and`, and `format` is idempotent — so the
    // same selection always produces byte-identical text, and two spellings of
    // one predicate become one cache key.
    const q = facetsToQuery(facets({ class: 'server', environment: ['production'] }));
    const reparsed = check(q, 'asset', CATALOG, OPTIONS);
    expect(reparsed.ok).toBe(true);
    if (reparsed.ok) expect(reparsed.value.canonical).toBe(q);
  });

  it('appends terms the rail cannot express, unchanged', () => {
    const q = facetsToQuery(facets({ class: 'server' }), ['depends_on:(class=database_instance)']);
    expect(q).toContain('class:server');
    expect(q).toContain('depends_on:(class=database_instance)');
    assertValid(q);
  });
});

describe('queryToFacets', () => {
  it('reads an empty query as no facets', () => {
    const out = queryToFacets('');
    expect(out.facets).toEqual(emptyFacets());
    expect(out.extra).toEqual([]);
    expect(out.unparsed).toBe(false);
  });

  it('reads back every facet the rail writes', () => {
    const source = facets({
      class: 'server',
      status: ['monitoring'],
      environment: ['production', 'staging'],
      site: ['dc-1'],
      segment: ['aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'],
      owner: ['ops@example.com'],
      business_unit: ['Payments'],
      tag: ['pci', 'tier=gold'],
      risk: ['high', 'not_assessed'],
      provenance: ['measured'],
    });
    const query = facetsToQuery(source);
    assertValid(query);
    const back = queryToFacets(query);
    expect(back.unparsed).toBe(false);
    expect(back.extra).toEqual([]);
    expect(back.facets).toEqual(source);
  });

  it('round-trips through the query and back to the SAME query', () => {
    // The property that matters: reading and rewriting must be a fixed point,
    // or a user's filters would drift every time they touched a checkbox.
    const source = facets({ class: 'network_device', environment: ['production'], risk: ['critical'] });
    const once = facetsToQuery(source);
    const twice = facetsToQuery(queryToFacets(once).facets, queryToFacets(once).extra);
    expect(twice).toBe(once);
  });

  it('keeps a term the rail has no control for, rather than dropping it', () => {
    // A hand-written traversal cannot be a checkbox. Dropping it on the next
    // click would silently delete the user's work.
    const out = queryToFacets('class:server and depends_on:(class = database_instance)');
    expect(out.facets.class).toBe('server');
    expect(out.extra).toHaveLength(1);
    expect(out.extra[0]).toContain('depends_on');
  });

  it('carries an unrepresentable term back out when the rail rewrites the query', () => {
    const read = queryToFacets('class:server and depends_on:(class = database_instance)');
    const next = facetsToQuery(toggleFacetValue(read.facets, 'environment', 'production'), read.extra);
    expect(next).toContain('environment:production');
    expect(next).toContain('depends_on');
    assertValid(next);
  });

  it('does NOT swallow a cross-field disjunction into a single facet', () => {
    // `environment:prod or risk:high` means something the rail cannot express;
    // reading it as "environment = prod" would change what the query MEANS.
    const out = queryToFacets('environment:production or risk:high');
    expect(out.facets.environment).toEqual([]);
    expect(out.facets.risk).toEqual([]);
    expect(out.extra).toHaveLength(1);
  });

  it('reads free text as free text', () => {
    const out = queryToFacets('payroll');
    expect(out.facets.text).toEqual(['payroll']);
  });

  it('reports an unparsable query rather than guessing at it', () => {
    const out = queryToFacets('class:(((');
    expect(out.unparsed).toBe(true);
    expect(out.facets).toEqual(emptyFacets());
  });

  it('reads a hand-written in-list as extra, since the rail writes the group form', () => {
    // Deliberate: only the shapes `facetsToQuery` writes are recognised. A
    // looser reader is how a facet starts changing a query it did not author.
    const out = queryToFacets('environment in (production, staging)');
    expect(out.facets.environment).toEqual([]);
    expect(out.extra).toHaveLength(1);
  });
});

describe('toggles', () => {
  it('adds and removes a value from a multi-select', () => {
    const one = toggleFacetValue(emptyFacets(), 'environment', 'production');
    expect(one.environment).toEqual(['production']);
    expect(toggleFacetValue(one, 'environment', 'production').environment).toEqual([]);
  });

  it('treats the class facet as SINGLE-select — the taxonomy is a tree', () => {
    const picked = setFacetClass(emptyFacets(), 'server');
    expect(picked.class).toBe('server');
    // Picking another replaces, rather than accumulating into nonsense.
    expect(setFacetClass(picked, 'switch').class).toBe('switch');
    // Clicking the active one clears it.
    expect(setFacetClass(picked, 'server').class).toBeUndefined();
  });

  it('counts every selection for the badge', () => {
    expect(facetCount(emptyFacets())).toBe(0);
    expect(facetCount(facets({ class: 'server', environment: ['a', 'b'] }))).toBe(3);
  });
});

describe('the findings facet', () => {
  // Restored at workstream 3.1. It was withdrawn because the control wrote
  // `finding:(…)` over the unified `findings` table while the number beside it
  // came from a server facet level counting `compliance_findings` — one
  // question, two tables. There is one table now, and the server produces the
  // count by COMPILING this very string, so the control and its number are the
  // same predicate rather than two attempts at it.
  //
  // The string is the GENERATED one, not a copy: a test that restated the
  // predicate would keep passing after someone changed the registry, which is
  // the failure it exists to catch.
  it('writes the generated open-findings predicate, not a restatement of it', () => {
    expect(OPEN_FINDINGS).toBe(OPEN_FINDINGS_QUERY);
    // Both halves of "open" are present. Either one alone is a different
    // question: detection_state alone counts findings a person already signed
    // off; workflow_status alone counts findings that have since been fixed.
    expect(OPEN_FINDINGS).toContain('detection_state:ACTIVE');
    expect(OPEN_FINDINGS).toContain('RESOLVED');
    expect(OPEN_FINDINGS).toContain('SUPPRESSED');
  });

  it('offers a findings control', () => {
    expect(Object.keys(FACET_LABEL)).toContain('findings');
  });

  it('writes no findings term when the facet is off', () => {
    const everything = facets({
      class: 'server', status: ['monitoring'], environment: ['production'],
      site: ['dc-1'], owner: ['ops@example.com'], business_unit: ['Payments'],
      tag: ['pci'], risk: ['high'], provenance: ['measured'], text: ['payroll'],
    });
    expect(facetsToQuery(everything)).not.toContain('finding:');
  });

  it('round-trips the `has open findings` arm', () => {
    const out = facetsToQuery(facets({ findings: true }));
    assertValid(out);
    expect(queryToFacets(out).facets.findings).toBe(true);
    // And it is a FACET, not an unrepresentable term — the rail must show it as
    // a control rather than as "1 term only the query editor can edit".
    expect(queryToFacets(out).extra).toHaveLength(0);
  });

  it('round-trips the `no open findings` arm, which is a different question from `not assessed`', () => {
    const out = facetsToQuery(facets({ findings: false }));
    assertValid(out);
    expect(out).toContain('not ');
    const read = queryToFacets(out);
    expect(read.facets.findings).toBe(false);
    expect(read.extra).toHaveLength(0);
  });

  it('cycles off → has open → none → off', () => {
    let f = emptyFacets();
    f = cycleFindings(f);
    expect(f.findings).toBe(true);
    f = cycleFindings(f);
    expect(f.findings).toBe(false);
    f = cycleFindings(f);
    expect(f.findings).toBeUndefined();
  });

  it('counts as one active filter, and an empty rail has it unset', () => {
    expect(facetsEmpty(facets({ findings: false }))).toBe(false);
    expect(facetCount(facets({ findings: true }))).toBe(1);
    expect(facetsEmpty(emptyFacets())).toBe(true);
  });

  it('carries a DIFFERENT hand-written finding term through as an unrepresentable term', () => {
    // Only the exact open-findings predicate is a facet. Anything else the user
    // typed keeps meaning what it said and is carried forward untouched — the
    // rail is a builder over their query, not a replacement for it.
    const out = queryToFacets('class:server and finding:(producer:eol and severity >= high)');
    expect(out.unparsed).toBe(false);
    expect(out.facets.class).toBe('server');
    expect(out.facets.findings).toBeUndefined();
    expect(out.extra).toHaveLength(1);
    expect(out.extra[0]).toContain('finding:');
  });

  it('writes that term back unchanged when a facet is clicked', () => {
    const read = queryToFacets('class:server and finding:(producer:eol and severity >= high)');
    const out = facetsToQuery(setFacetClass(read.facets, 'switch'), read.extra);
    expect(out).toContain('class:switch');
    expect(out).toContain('producer:eol');
    assertValid(out);
  });
});

describe('a facet click over an unparsable query (gate1 C2)', () => {
  // `queryToFacets` returns `extra: []` for text it could not parse — it has no
  // tree to walk, so there is nothing to carry the user's words in. Writing the
  // rail's state over the top therefore DELETED what they typed, on the first
  // checkbox click, with no warning. The rail refuses and says so instead.
  it('refuses to write, rather than replacing the text it could not read', () => {
    const read = queryToFacets('class:(((');
    expect(read.unparsed).toBe(true);
    expect(applyFacetChange(read, setFacetClass(read.facets, 'server'))).toBeNull();
  });

  it('still writes the query when the text DID parse (the other polarity)', () => {
    const read = queryToFacets('environment:production');
    expect(read.unparsed).toBe(false);
    const out = applyFacetChange(read, setFacetClass(read.facets, 'server'));
    expect(out).not.toBeNull();
    expect(out).toContain('class:server');
    expect(out).toContain('environment:production');
  });

  it('still carries terms the rail cannot show, which is the case it must not be confused with', () => {
    // An unrepresentable-but-VALID term is kept in `extra` and written back; only
    // text that does not parse at all disables the rail.
    const read = queryToFacets('environment:production or risk:high');
    expect(read.unparsed).toBe(false);
    const out = applyFacetChange(read, setFacetClass(read.facets, 'server'));
    expect(out).toContain('risk:high');
  });
});
