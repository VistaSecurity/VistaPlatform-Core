// The shared asset fetch must skip every lens that renders without it.
//
// `InventoryPage` holds one `useAssets(page, search, usesAssetDataset, …)` for
// the crypto-anchored lenses, and three asset-anchored lenses return BEFORE its
// result is ever read: `assets` (AssetsLens holds its own query), `software`
// (product-anchored) and `map` (the neighbourhood graph). Each has to be named
// in the `usesAssetDataset` clause, or the page fetches and discards a page of
// fifty assets on every visit to one of them.
//
// This is a regression guard with a history. The clause used to rely on
// `!def.placeholder` to cover `map` — which was true only while the map WAS a
// placeholder, and stopped being true the moment workstream 2.9 made it live,
// silently. Nothing failed when that happened, and nothing failed when the
// clause was repaired either: removing `lens !== 'map'` again left all 971
// tests of the day green. A fix that no test can see is a fix that comes back.
//
// inventory-page.tsx has no JSX/DOM harness in this repo (no jsdom), so the
// guard is structural — the same shape as inventory-page.ownership-filter.test.ts.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const src = readFileSync(fileURLToPath(new URL('./inventory-page.tsx', import.meta.url)), 'utf8');
const lines = src.split('\n');

/**
 * The lenses that return early from the component body.
 *
 * Anchored on exactly two spaces of indentation, which is what separates a
 * branch of the COMPONENT from the `if (lens === 'stale')` inside the nested
 * row renderer. The "found what we expected" assertion below is what stops that
 * anchor from silently matching nothing after a reformat.
 */
const earlyReturnLenses = lines
  .map((line, i) => ({ line, i }))
  .filter(({ line }) => /^ {2}if \(lens === '[a-z_-]+'\) \{$/.test(line))
  // ...and it really does return, rather than merely branching.
  .filter(({ i }) => lines.slice(i, i + 25).some((l) => /^\s{4}return[ (]/.test(l)))
  .map(({ line }) => /'([a-z_-]+)'/.exec(line)![1]);

/** The `usesAssetDataset` expression, as one line. */
const clause = (() => {
  const start = lines.findIndex((l) => l.includes('const usesAssetDataset ='));
  expect(start, 'usesAssetDataset not found in inventory-page.tsx').toBeGreaterThan(-1);
  const end = lines.findIndex((l, i) => i >= start && l.trimEnd().endsWith(';'));
  return lines.slice(start, end + 1).join(' ').replace(/\s+/g, ' ');
})();

describe('the shared asset dataset', () => {
  it('finds the early-returning lenses at all', () => {
    // Without this the two assertions below pass vacuously over an empty list,
    // which is exactly the failure mode they exist to catch.
    expect(earlyReturnLenses).toContain('assets');
    expect(earlyReturnLenses).toContain('software');
    expect(earlyReturnLenses).toContain('map');
  });

  it('is disabled for EVERY lens that returns before the result is read', () => {
    for (const lens of earlyReturnLenses) {
      expect(
        clause,
        `\`${lens}\` returns early but is not excluded from usesAssetDataset — `
        + 'the page will fetch a page of assets on every visit to it and throw it away',
      ).toContain(`lens !== '${lens}'`);
    }
  });

  it('is still ENABLED for a lens that reads it — the other polarity', () => {
    // A clause that excluded everything would pass the test above and break the
    // page. `stale` is asset-anchored and renders FROM this result.
    expect(clause).not.toContain("lens !== 'stale'");
    expect(clause).toContain("def.anchor === 'asset'");
    expect(clause).toContain('!def.placeholder');
  });

  it('passes the flag to useAssets rather than computing a second opinion', () => {
    expect(src).toMatch(/useAssets\(page, search, usesAssetDataset,/);
  });
});
