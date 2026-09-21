import { describe, expect, it } from 'vitest';
import {
  attributeCoverage, bucketRows, drillThrough, facetBucketCount,
  inventoryQueryHref, rootClassBuckets, totalAssets,
} from './assets-dashboard-metrics';
import type { FacetData } from '../inventory/asset-queries';

const bucket = (value: string, count: number, label?: string) => ({ value, count, label });

function facets(buckets: Record<string, { value: string; count: number; label?: string }[]>, failed: string[] = []): FacetData {
  return { buckets, failed };
}

describe('the class facet is hierarchical', () => {
  // A `hardware.computer.server` asset counts under all three of its ancestors,
  // so the facet's buckets do NOT partition the estate. Summing them counts
  // most assets several times — the bug this filter exists to prevent.
  const hierarchical = [
    bucket('hardware', 10), bucket('hardware.computer', 8), bucket('hardware.computer.server', 6),
    bucket('software', 4), bucket('software.application', 4),
  ];

  it('keeps only the root buckets', () => {
    expect(rootClassBuckets(hierarchical).map((b) => b.value)).toEqual(['hardware', 'software']);
  });

  it('totals the ROOTS, not every bucket', () => {
    // 10 + 4, not 10+8+6+4+4 = 32.
    expect(totalAssets(hierarchical)).toBe(14);
  });

  it('draws class bars against the root sum, so no bar can exceed 100%', () => {
    const { rows, total } = bucketRows('class', hierarchical);
    expect(total).toBe(14);
    for (const r of rows) expect(r.count).toBeLessThanOrEqual(total);
  });

  it('treats a non-class level as a flat partition', () => {
    // The dotted-value filter must NOT apply to other levels: an environment
    // legitimately called "eu.prod" would vanish from its own panel.
    const { rows, total } = bucketRows('environment', [bucket('eu.prod', 3), bucket('dev', 2)]);
    expect(rows.map((r) => r.value)).toEqual(['eu.prod', 'dev']);
    expect(total).toBe(5);
  });
});

describe('bucket rows', () => {
  it('ranks biggest first, then by value for a stable tie-break', () => {
    const { rows } = bucketRows('environment', [bucket('b', 2), bucket('a', 5), bucket('c', 2)]);
    expect(rows.map((r) => r.value)).toEqual(['a', 'b', 'c']);
  });

  it('falls back to the value when the server omits the label', () => {
    const { rows } = bucketRows('environment', [bucket('prod', 1)]);
    expect(rows[0].label).toBe('prod');
  });

  it('falls back to the value when the label is EMPTY, not just absent', () => {
    // `||` rather than `??`: an empty label is not a label, and a blank row is
    // worse than one showing the raw key.
    const { rows } = bucketRows('environment', [bucket('prod', 1, '')]);
    expect(rows[0].label).toBe('prod');
  });

  it('rolls the tail into a non-clickable Other row', () => {
    const many = Array.from({ length: 9 }, (_, i) => bucket(`e${i}`, 9 - i));
    const { rows } = bucketRows('environment', many, 3);
    const other = rows[rows.length - 1];
    expect(other.other).toBe(true);
    expect(other.href).toBeNull();
    // 6+5+4+3+2+1 — everything past the first three.
    expect(other.count).toBe(21);
  });

  it('omits an empty Other row', () => {
    const { rows } = bucketRows('environment', [bucket('a', 1), bucket('b', 1), bucket('c', 0)], 2);
    expect(rows.some((r) => r.other)).toBe(false);
  });
});

describe('drill-through', () => {
  it('writes the canonical rail query for a level the rail can represent', () => {
    expect(drillThrough('environment', 'production')).toBe(inventoryQueryHref('environment:production'));
  });

  it('writes the class PATH, which is what `class:` prefix-matches', () => {
    const href = drillThrough('class', 'hardware.computer.server')!;
    expect(decodeURIComponent(href)).toContain('class:hardware.computer.server');
  });

  it('turns the Unknown bucket into `not exists(...)`, not the literal string', () => {
    // The bug this pins: `owner_email:Unknown` matched the literal word and so
    // returned none of the rows the facet had counted, and on a closed enum
    // (`environment:Unknown`) the server answered 400.
    const href = decodeURIComponent(drillThrough('business_unit', 'Unknown')!);
    expect(href).toContain('not exists(business_unit)');
    expect(href).not.toContain('business_unit:Unknown');
  });

  it('also matches the empty string on columns that fold "" into Unknown', () => {
    // Spelled without spaces because `format` owns the canonical form and
    // normalizes the comparison; asserting the pretty form would pin the test
    // to a spacing the writer does not produce.
    expect(decodeURIComponent(drillThrough('business_unit', 'Unknown')!)).toContain('business_unit=""');
  });

  it('serves levels the rail has no checkbox for, via the same term writer', () => {
    expect(decodeURIComponent(drillThrough('stale_status', 'stale')!)).toContain('stale_status:stale');
    expect(decodeURIComponent(drillThrough('ownership', 'managed')!)).toContain('ownership:managed');
  });

  it('applies the Unknown rule on those levels too, not just the rail ones', () => {
    // The assertions above pass just as well against a hand-written
    // `${field}:${value}`, because an ordinary value renders identically either
    // way. The Unknown bucket is the whole reason `facetFieldTerm` is exported
    // rather than reimplemented here, and this is the branch that uses it: the
    // rail levels take the `RAIL_FACET` path above and never reach it.
    //
    // `support_group` is in EMPTY_IS_UNSET, so its unset form is the two-part
    // one; `ownership` is not, so it is the bare `not exists`. Both were
    // silently unpinned until a mutation replaced the call and 26 tests stayed
    // green.
    //
    // Spelled WITH spaces, unlike the rail assertion above: that one is
    // normalized by `format` on its way through `facetsToQuery`, and this path
    // returns the writer's own output untouched.
    const supportGroup = decodeURIComponent(drillThrough('support_group', 'Unknown')!);
    expect(supportGroup).toContain('not exists(support_group)');
    expect(supportGroup).toContain('support_group = ""');
    expect(supportGroup).not.toContain('support_group:Unknown');

    const ownership = decodeURIComponent(drillThrough('ownership', 'Unknown')!);
    expect(ownership).toContain('not exists(ownership)');
    expect(ownership).not.toContain('ownership:Unknown');
  });

  it('returns NULL for a level with no query field at all', () => {
    // These levels the server counts but the asset query language has no field
    // for. A best-effort link degrades to the unfiltered asset list — a row
    // reading "12" that opens every asset in the tenant, with nothing saying
    // which twelve were meant. A non-clickable row is the honest rendering.
    expect(drillThrough('operating_system', 'Ubuntu 24.04')).toBeNull();
    expect(drillThrough('has_endpoints', 'false')).toBeNull();
    expect(drillThrough('has_findings', 'true')).toBeNull();
  });

  it('marks unlinkable bucket rows null rather than pointing them somewhere wrong', () => {
    const { rows } = bucketRows('has_endpoints', [bucket('true', 3), bucket('false', 7)]);
    expect(rows.every((r) => r.href === null)).toBe(true);
  });

  it('encodes the query exactly once', () => {
    const href = drillThrough('environment', 'pre prod')!;
    expect(href.startsWith('/inventory?lens=assets&query=')).toBe(true);
    // Decoding once must yield the raw term; a double-encode would leave %20.
    expect(decodeURIComponent(href.split('query=')[1])).not.toContain('%');
  });
});

describe('three-valued counts', () => {
  const data = facets({ status: [bucket('active', 5), bucket('pending_approval', 2)] });

  it('reads a present bucket', () => {
    expect(facetBucketCount(data, 'status', 'pending_approval')).toBe(2);
  });

  it('reads an absent bucket in an answered level as a real zero', () => {
    expect(facetBucketCount(data, 'status', 'retired')).toBe(0);
  });

  it('returns NULL for a level that FAILED, not zero', () => {
    // "No pending assets" and "we could not ask" are different facts, and a
    // hero tile is the worst place to guess: a reassuring zero is exactly what
    // a reader takes at face value.
    const broken = facets({ status: [] }, ['status']);
    expect(facetBucketCount(broken, 'status', 'pending_approval')).toBeNull();
  });

  it('returns NULL when the caller already knows the whole fan-out failed', () => {
    expect(facetBucketCount(data, 'status', 'pending_approval', true)).toBeNull();
  });

  it('returns NULL when there are no facets at all', () => {
    expect(facetBucketCount(undefined, 'status', 'pending_approval')).toBeNull();
  });
});

describe('attribute coverage', () => {
  it('counts everything outside the Unknown bucket as recorded', () => {
    const data = facets({ business_unit: [bucket('Unknown', 30), bucket('Finance', 50), bucket('IT', 20)] });
    expect(attributeCoverage(data, 'business_unit')).toEqual({ known: 70, total: 100, percent: 70 });
  });

  it('reports 100% when nothing is Unknown', () => {
    const data = facets({ environment: [bucket('prod', 4)] });
    expect(attributeCoverage(data, 'environment')!.percent).toBe(100);
  });

  it('returns null for a FAILED level rather than 0% recorded', () => {
    expect(attributeCoverage(facets({ site: [] }, ['site']), 'site')).toBeNull();
  });

  it('returns null for a level with no assets at all, rather than dividing by zero', () => {
    expect(attributeCoverage(facets({ site: [] }), 'site')).toBeNull();
  });
});
