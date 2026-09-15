// The Inventory health hero's arithmetic (ADR-0006 D5, workstream 3.8).
//
// Three things can be wrong here in ways that look right on screen, and each
// gets its own polarity test:
//
//   1. summing the class facet counts most of the estate two or three times,
//      because the facet is HIERARCHICAL by design;
//   2. a facet level that FAILED returns no buckets, which reads identically to
//      a tenant that genuinely has none — and a reassuring zero is what a
//      person takes at face value;
//   3. a hygiene score of null is "not assessed", not 100 and not 0.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parse } from '@vistasecurity/primitives/query';
import {
  HERO_CLASS_LIMIT, HERO_PENDING_HREF, HERO_STALE_QUERY, HYGIENE_FRAMEWORK_CODE,
  bucketCount, classSlices, hygieneScore, inventoryQueryHref, totalFromClasses,
} from './inventory-health';
import type { FacetData } from '../inventory/asset-queries';

// The shape the `class` facet really returns: EVERY ancestor of every class,
// which is what makes picking "Hardware" in the rail show the whole branch.
const HIERARCHICAL_CLASS_BUCKETS = [
  { value: 'hardware', count: 40, label: 'Hardware' },
  { value: 'hardware.computer', count: 35, label: 'Computer' },
  { value: 'hardware.computer.server', count: 30, label: 'Server' },
  { value: 'hardware.network_device', count: 5, label: 'Network device' },
  { value: 'service', count: 12, label: 'Service' },
  { value: 'service.data.managed_database', count: 12, label: 'Managed database' },
  { value: 'cloud_resource', count: 7, label: 'Cloud resource' },
];

describe('the class breakdown', () => {
  it('takes ROOT classes only, so the rows do not double-count', () => {
    // Summing every bucket here gives 141 for an estate of 59. The two biggest
    // rows would be `hardware` and its own child `hardware.computer`.
    const slices = classSlices(HIERARCHICAL_CLASS_BUCKETS);
    expect(slices.map((s) => s.path)).toEqual(['hardware', 'service', 'cloud_resource']);
    expect(totalFromClasses(HIERARCHICAL_CLASS_BUCKETS)).toBe(59);
  });

  it('sorts biggest-first', () => {
    expect(classSlices(HIERARCHICAL_CLASS_BUCKETS).map((s) => s.count)).toEqual([40, 12, 7]);
  });

  it('rolls the tail into a single "Other" row past the limit', () => {
    const many = Array.from({ length: HERO_CLASS_LIMIT + 3 }, (_, i) => ({
      value: `root${i}`, count: 10 - i, label: `Root ${i}`,
    }));
    const slices = classSlices(many);
    expect(slices).toHaveLength(HERO_CLASS_LIMIT + 1);
    const other = slices[slices.length - 1];
    expect(other.label).toBe('Other');
    expect(other.other).toBe(true);
    // It is a REMAINDER, so it has to equal what was cut.
    expect(other.count).toBe(many.slice(HERO_CLASS_LIMIT).reduce((n, r) => n + r.count, 0));
  });

  it('omits an empty "Other" rather than drawing a zero row', () => {
    const exactly = Array.from({ length: HERO_CLASS_LIMIT }, (_, i) => ({ value: `r${i}`, count: 3, label: `R${i}` }));
    expect(classSlices(exactly).some((s) => s.other)).toBe(false);
  });

  it('handles no data without inventing any', () => {
    expect(classSlices(undefined)).toEqual([]);
    expect(totalFromClasses(undefined)).toBe(0);
  });

  it('falls back to the raw path when the server sent no label', () => {
    // A tenant subclass is not in the generated registry, so its own key is the
    // honest label — better than a blank row.
    expect(classSlices([{ value: 'bespoke', count: 1 }])[0].label).toBe('bespoke');
  });
});

describe('a facet count', () => {
  const facets = (over: Partial<FacetData> = {}): FacetData => ({
    buckets: {
      status: [
        { value: 'monitoring', count: 50 },
        { value: 'pending_approval', count: 4 },
      ],
      stale_status: [{ value: 'active', count: 54 }],
    },
    failed: [],
    ...over,
  });

  it('reads the bucket', () => {
    expect(bucketCount(facets(), 'status', 'pending_approval')).toBe(4);
  });

  it('is 0 when the level answered and the bucket is genuinely absent', () => {
    // "We looked and there are none" is a real answer and must stay a number.
    expect(bucketCount(facets(), 'stale_status', 'stale')).toBe(0);
  });

  it('is NULL when the level FAILED — never 0', () => {
    // The facet hook records the failure rather than flattening it into empty
    // buckets, precisely so this distinction survives. A hero tile reading "0
    // stale" off a 500 is an assertion about the tenant's data made on the
    // strength of a failed request.
    expect(bucketCount(facets({ failed: ['stale_status'] }), 'stale_status', 'stale')).toBeNull();
  });

  it('is NULL before anything has loaded', () => {
    expect(bucketCount(undefined, 'status', 'pending_approval')).toBeNull();
  });

  it('is NULL for a level nothing answered for at all', () => {
    expect(bucketCount(facets(), 'site', 'DC-East')).toBeNull();
  });
});

describe('the hygiene score', () => {
  const row = (over: Record<string, unknown> = {}) => [{
    platform_framework: { code: HYGIENE_FRAMEWORK_CODE },
    is_licensed: true,
    preview_score: 82,
    controls_passing: 9,
    controls_failing: 2,
    controls_not_assessed: 1,
    ...over,
  }] as Parameters<typeof hygieneScore>[0];

  it('reads the Core Inventory Hygiene framework', () => {
    const h = hygieneScore(row());
    expect(h.score).toBe(82);
    expect(h.passing).toBe(9);
    expect(h.failing).toBe(2);
    expect(h.notAssessed).toBe(1);
    expect(h.activated).toBe(true);
    expect(h.present).toBe(true);
  });

  it('is NOT ASSESSED when the engine has produced no rollup', () => {
    // Null, not 0 and not 100. The engine has not looked yet — or it has and no
    // control could be assessed — and either rendered as a number is
    // the three-valued collapse this platform keeps paying for.
    expect(hygieneScore(row({ preview_score: null })).score).toBeNull();
    expect(hygieneScore(row({ preview_score: undefined })).score).toBeNull();
  });

  it('keeps a real 0 as 0', () => {
    // The other polarity: a genuine score of zero must not be mistaken for
    // absence by a truthiness check.
    expect(hygieneScore(row({ preview_score: 0 })).score).toBe(0);
  });

  it('reports the framework as ABSENT rather than scoring 0 when it is missing', () => {
    const h = hygieneScore([{ platform_framework: { code: 'pqc-readiness' }, is_licensed: true, preview_score: 40 }]);
    expect(h.present).toBe(false);
    expect(h.score).toBeNull();
  });

  it('reports not-activated separately from not-scored', () => {
    const h = hygieneScore(row({ is_licensed: false, preview_score: null }));
    expect(h.activated).toBe(false);
    expect(h.score).toBeNull();
  });

  it('survives no data', () => {
    expect(hygieneScore(undefined).present).toBe(false);
  });
});

describe('where the hero links', () => {
  it('sends Pending to the ONE approvals queue, not to a second list of it', () => {
    // ADR-0006 D1/D6: assets are accepted or denied in exactly one place. A
    // second surface listing them invites a second way to act on them.
    expect(HERO_PENDING_HREF).toBe('/discovery/approvals');
  });

  it('writes the stale filter in the query language the rail also writes', () => {
    // The Inventory page parses the query back into its rail; a second
    // vocabulary would land there as an opaque "extra" the checkboxes cannot
    // show.
    expect(HERO_STALE_QUERY).toBe('stale_status:stale');
    const href = inventoryQueryHref(HERO_STALE_QUERY);
    expect(decodeURIComponent(new URL(href, 'https://x').searchParams.get('query')!)).toBe('stale_status:stale');
  });

  it('drops the query parameter entirely when there is no predicate', () => {
    expect(inventoryQueryHref('')).toBe('/inventory?lens=assets');
  });

  it('writes queries the REAL parser accepts', () => {
    // A string comparison pins a format; only the parser pins a behaviour. A
    // hero tile that linked to a query the language cannot read would show a
    // number beside a link that opens a parse error, and nothing on the
    // dashboard would say so.
    for (const q of [HERO_STALE_QUERY, 'class:hardware', 'class:cloud_resource']) {
      const res = parse(q);
      expect(res.ok, `${q} did not parse: ${JSON.stringify(res.ok ? null : res.errors)}`).toBe(true);
    }
  });

  it('links a class bar with the SUBTREE operator, which is what its bar counted', () => {
    // The opposite choice from the topology's class chips, deliberately. These
    // bars come from the hierarchical `class` facet, whose root bucket counts
    // every asset beneath the root — so `class:` (subtree) is the form that
    // selects the rows the bar counted, and `class=` would select only the
    // assets classified at the root itself. The tooltip on the bar says
    // "and everything beneath it in the taxonomy" for the same reason.
    const hero = readFileSync(new URL('./inventory-health-hero.tsx', import.meta.url), 'utf8');
    expect(hero).toContain('inventoryQueryHref(`class:${slice.path}`)');
  });
});
