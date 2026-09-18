// The facet rail's two pieces of arithmetic, both of which are about the gap
// between what the SERVER counts and what the rail shows.
//
// Neither would fail loudly if it were wrong: a class tree of zeroes and a facet
// section that is permanently empty both look like a tenant with no data, which
// is exactly the reading they must not produce.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { ASSET_CLASSES, CLASS_TREE, type AssetClassKey } from '@vistasecurity/primitives/assets';
import { FACET_LEVELS, FACET_LEVEL_FOR, ancestorsOf, bucketFacetView, levelFailed, subtreeCount } from './facet-rail';
import { FACET_LABEL, type FacetKey } from './facet-query';

/** The tree node for a class key. */
function node(key: AssetClassKey) {
  const find = (nodes: readonly { key: string; children: readonly never[] }[] | typeof CLASS_TREE): typeof CLASS_TREE[number] | undefined => {
    for (const n of nodes as typeof CLASS_TREE) {
      if (n.key === key) return n;
      const hit = find(n.children);
      if (hit) return hit;
    }
    return undefined;
  };
  const found = find(CLASS_TREE);
  if (!found) throw new Error(`no such class in the tree: ${key}`);
  return found;
}

/**
 * A `level=class` response, as `classFacets` actually builds it: every row's
 * `class_path` expanded into each of its own ancestors, so a parent bucket is
 * already the subtree total. Tests state the assets they mean and this shapes
 * the payload, which is the whole point — a fixture written as leaf-only counts
 * describes a response the endpoint has never sent.
 */
function serverBuckets(assets: { classKey: AssetClassKey; n: number }[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const { classKey, n } of assets) {
    const segments = ASSET_CLASSES[classKey].path.split('.');
    for (let i = 1; i <= segments.length; i += 1) {
      const path = segments.slice(0, i).join('.');
      out[path] = (out[path] ?? 0) + n;
    }
  }
  return out;
}

describe('subtreeCount', () => {
  it('keys buckets by the class PATH, not the class key', () => {
    // The facet's `value` is what a QUERY TERM matches on, and `class:` compares
    // a prefix of `class_path`. Looking buckets up by key would find nothing for
    // every class below the top level and show a tree of zeroes — which reads
    // as "you have no servers", not as "this code is wrong".
    const counts = { [ASSET_CLASSES.server.path]: 40 };
    expect(subtreeCount(node('server'), counts)).toBe(40);
    // And the key form must NOT work, or the test above would pass either way.
    expect(subtreeCount(node('server'), { server: 40 })).toBe(0);
  });

  it('shows the SERVER’s subtree total, without re-summing it', () => {
    // `classFacets` already expands each row into every ancestor of its class,
    // so `hardware` arrives holding the whole branch. Adding the children again
    // here counted every asset once per level of its path: 40 servers rendered
    // as "Hardware 120 / Computer 80 / Server 40".
    const counts = serverBuckets([{ classKey: 'server', n: 40 }, { classKey: 'switch', n: 3 }]);
    expect(subtreeCount(node('server'), counts)).toBe(40);
    expect(subtreeCount(node('computer'), counts)).toBe(40);
    expect(subtreeCount(node('network_device'), counts)).toBe(3);
    expect(subtreeCount(node('hardware'), counts)).toBe(43);
  });

  it('counts an asset classed AT a parent once, in every bucket it belongs to', () => {
    // An asset can be classed at a parent — `hardware` with nothing more
    // specific known — and it must appear on its own row without being counted
    // a second time into the same row by way of its children.
    const counts = serverBuckets([{ classKey: 'hardware', n: 5 }, { classKey: 'server', n: 2 }]);
    expect(subtreeCount(node('hardware'), counts)).toBe(7);
    expect(subtreeCount(node('computer'), counts)).toBe(2);
    expect(subtreeCount(node('server'), counts)).toBe(2);
  });

  it('does not invent a parent count the server did not send', () => {
    // The negative polarity of the rule above: given ONLY a leaf bucket — the
    // shape a rolling-up client would need — the parent reads 0 rather than
    // quietly synthesising a total the endpoint never computed.
    const leafOnly = { [ASSET_CLASSES.server.path]: 40 };
    expect(subtreeCount(node('hardware'), leafOnly)).toBe(0);
    expect(subtreeCount(node('computer'), leafOnly)).toBe(0);
  });

  it('is zero, not NaN, for a class with no bucket', () => {
    expect(subtreeCount(node('hardware'), {})).toBe(0);
  });
});

describe('ancestorsOf', () => {
  it('gives the chain a selected class needs expanded to be visible', () => {
    expect(ancestorsOf('server')).toEqual(['hardware', 'computer']);
    expect(ancestorsOf('hardware')).toEqual([]);
  });

  it('returns nothing for an unknown class rather than throwing', () => {
    expect(ancestorsOf('tenant_custom_thing')).toEqual([]);
  });
});

describe('FACET_LEVEL_FOR', () => {
  it('maps the rail’s names onto the SERVER’s', () => {
    // The rail says "owner" and "provenance" because that is what a person calls
    // them; the API says `owner_email` and `source` because that is what the
    // columns are. Asking for the rail's name would return an empty bucket list
    // and render a permanently empty facet section.
    expect(FACET_LEVEL_FOR.owner).toBe('owner_email');
    expect(FACET_LEVEL_FOR.provenance).toBe('source');
  });

  it('covers every facet the rail asks the server to count', () => {
    const asked: FacetKey[] = ['class', 'status', 'environment', 'site', 'segment', 'owner', 'business_unit', 'tag', 'risk', 'provenance', 'findings'];
    for (const key of asked) {
      expect(FACET_LEVEL_FOR[key], `no server level for the ${key} facet`).toBeTruthy();
      expect(FACET_LABEL[key]).toBeTruthy();
    }
  });

  it('requests one level per facet, with no duplicates', () => {
    expect(FACET_LEVELS.length).toBe(Object.keys(FACET_LEVEL_FOR).length);
    expect(new Set(FACET_LEVELS).size).toBe(FACET_LEVELS.length);
  });

  it('names only levels the endpoint documents', () => {
    // From getAssetFacets' own `level` description. A typo here is a silently
    // empty facet, not an error.
    //
    // `has_findings` is back at workstream 3.1: one findings table answers both
    // the count and the term the rail's click writes.
    const supported = new Set([
      'class', 'risk', 'tag', 'has_findings', 'has_endpoints', 'status', 'environment',
      'ownership', 'stale_status', 'site', 'region', 'zone', 'segment', 'owner_email',
      'business_unit', 'support_group', 'operating_system', 'source', 'proposed_by',
    ]);
    for (const level of FACET_LEVELS) expect(supported).toContain(level);
  });

  it('asks the server for the findings level, under the server\'s name for it', () => {
    // The rail calls it `findings` and the endpoint calls it `has_findings`.
    // Asking for a level the endpoint does not serve renders as a permanently
    // empty facet section rather than an error, so the mapping is pinned.
    expect(Object.keys(FACET_LEVEL_FOR)).toContain('findings');
    expect(FACET_LEVEL_FOR.findings).toBe('has_findings');
    expect(FACET_LEVELS).toContain('has_findings');
  });
});

describe('a facet level that did not answer (gate1 C4)', () => {
  // "No sites recorded." is a sentence about the tenant's data. A failed
  // request is not evidence for it, and the rail used to say it anyway —
  // every per-level error was flattened into an empty bucket list.
  const empty = 'No sites recorded.';

  it('says it could not load, instead of asserting the tenant has none', () => {
    const view = bucketFacetView([], [], true, empty);
    expect(view.kind).toBe('failed');
    expect(JSON.stringify(view)).not.toContain(empty);
  });

  it('still says "none recorded" when the level answered with no buckets', () => {
    // The other polarity: a level that genuinely returned nothing must keep
    // saying so, or the fix would replace one lie with another.
    const view = bucketFacetView([], [], false, empty);
    expect(view).toEqual({ kind: 'empty', message: empty });
  });

  it('keeps a selected value listed while the level is failing, so the filter can be cleared', () => {
    const view = bucketFacetView([], ['dc-west'], true, empty);
    expect(view.kind).toBe('failed');
    expect(view.kind !== 'empty' && view.values.map((v) => v.value)).toEqual(['dc-west']);
  });

  it('shows NO count for a selected value while the level is failing, rather than 0', () => {
    const view = bucketFacetView([], ['dc-west'], true, empty);
    expect(view.kind !== 'empty' && view.values[0].count).toBeUndefined();
    // …and 0 is still the right answer when the level DID answer: the value is
    // selected and the server counted none of it under the current query.
    const ok = bucketFacetView([], ['dc-west'], false, empty);
    expect(ok.kind !== 'empty' && ok.values[0].count).toBe(0);
  });

  it('renders the buckets it did get, failure or not', () => {
    const view = bucketFacetView([{ value: 'dc-east', count: 4 }], [], false, empty);
    expect(view).toEqual({ kind: 'values', values: [{ value: 'dc-east', count: 4 }] });
  });

  it('maps a failed SERVER level back onto the rail’s own facet name', () => {
    // The rail asks about `owner`; the failure comes back as `owner_email`.
    expect(levelFailed({ buckets: {}, failed: ['owner_email'] }, 'owner')).toBe(true);
    expect(levelFailed({ buckets: {}, failed: ['owner_email'] }, 'site')).toBe(false);
    expect(levelFailed(undefined, 'owner')).toBe(false);
  });
});

describe('the rail starts collapsed', () => {
  const src = readFileSync(new URL('./facet-rail.tsx', import.meta.url), 'utf8');

  it('filter sections are closed until a value is selected', () => {
    expect(src).toMatch(/useState\(\(\) => \(count \?\? 0\) > 0\)/);
    expect(src).not.toMatch(/useState\(true\)/);
  });

  it('the class tree is closed, not pre-expanded to every top-level node', () => {
    expect(src).toMatch(/useState<Set<string>>\(\(\) => new Set\(\)\)/);
    expect(src).not.toMatch(/new Set\(CLASS_TREE\.map/);
  });
});
