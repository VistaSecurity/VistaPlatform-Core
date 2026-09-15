// Inventory navigation parity (ADR-0006 D1).
//
// Two registries describe the Inventory section — the nav registry (`nav.ts`,
// what the rail shows) and the lens catalogue (`lenses.ts`, what the page
// renders) — and they can disagree in both directions. A lens with no nav entry
// is a page nobody can reach without typing a URL; a nav entry with no lens is a
// link to a page that renders the default lens under someone else's label.
//
// Both are exactly the "orphaned layer" failure the feature framework exists to
// prevent, and neither shows up in a typecheck, so this is the guard.
import { describe, expect, it } from 'vitest';
import { SECTIONS } from './nav';
import {
  DEFAULT_LENS, INVENTORY_LENSES, LENS_ALIASES, findLens, lensesInGroup, resolveLensAlias,
} from '../sections/inventory/lenses';

const inventory = SECTIONS.find((s) => s.id === 'inventory')!;
const navLensKeys = (inventory.groups ?? [])
  .flatMap((g) => g.items)
  .filter((i) => i.lens)
  .map((i) => i.lens!);

describe('the Inventory nav registry', () => {
  it('has the three ADR-0006 D1 groups, in order', () => {
    expect((inventory.groups ?? []).map((g) => g.label)).toEqual(['Assets', 'Cryptography', 'Lifecycle']);
  });

  it('opens with the Assets group: All assets, Map, Software', () => {
    expect(inventory.groups![0].items.map((i) => i.label)).toEqual(['All assets', 'Map', 'Software']);
  });

  it('keeps every crypto lens, grouped under one label', () => {
    // "The existing lenses, unchanged in behaviour, grouped under one label so
    // crypto reads as a module" — losing one here would quietly delete a page.
    const crypto = inventory.groups!.find((g) => g.label === 'Cryptography')!.items.map((i) => i.lens);
    expect(crypto).toEqual(['certificate', 'keys', 'configuration', 'tls', 'ssh', 'data-protection', 'connections']);
  });

  it('links Pending OUT to Discovery → Approvals rather than repeating the queue', () => {
    // "Pending is a cross-link, not a second queue." A second inbox is how half
    // the proposals in a product end up unread.
    const pending = inventory.groups!.find((g) => g.label === 'Lifecycle')!.items.find((i) => i.label === 'Pending')!;
    expect(pending.path).toBe('/discovery/approvals');
    expect(pending.crossLink).toBe(true);
    expect(pending.lens).toBeUndefined();
  });
});

describe('nav ↔ lens registry parity', () => {
  it('gives EVERY lens a nav home', () => {
    // The reachability rule: no page without a nav entry.
    const orphans = INVENTORY_LENSES.filter((l) => !navLensKeys.includes(l.key)).map((l) => l.key);
    expect(orphans).toEqual([]);
  });

  it('points every nav lens entry at a REAL lens', () => {
    const dangling = navLensKeys.filter((k) => !INVENTORY_LENSES.some((l) => l.key === k));
    expect(dangling).toEqual([]);
  });

  it('lists each lens exactly once', () => {
    expect(new Set(navLensKeys).size).toBe(navLensKeys.length);
  });

  it('builds each path from the lens key it declares', () => {
    for (const item of (inventory.groups ?? []).flatMap((g) => g.items)) {
      if (item.lens) expect(item.path).toBe(`/inventory?lens=${item.lens}`);
    }
  });

  it('puts each lens in the nav group its registry entry declares', () => {
    const groupOf: Record<string, string> = { Assets: 'assets', Cryptography: 'cryptography', Lifecycle: 'lifecycle' };
    for (const g of inventory.groups ?? []) {
      for (const item of g.items) {
        if (!item.lens) continue;
        expect(findLens(item.lens).group).toBe(groupOf[g.label!]);
      }
    }
  });

  it('has at least one lens in every group', () => {
    for (const group of ['assets', 'cryptography', 'lifecycle'] as const) {
      expect(lensesInGroup(group).length).toBeGreaterThan(0);
    }
  });
});

describe('the default lens and its aliases', () => {
  it('defaults to the class-faceted list', () => {
    // ADR-0006 D2: "All assets" replaces Infrastructure as the default.
    expect(DEFAULT_LENS).toBe('assets');
    expect(findLens(null).key).toBe('assets');
    expect(findLens('nonsense').key).toBe('assets');
  });

  it('redirects the retired keys rather than 404ing or silently rendering something else', () => {
    // `?lens=infrastructure` was the default for the whole of the previous UI,
    // so those bookmarks are real.
    expect(resolveLensAlias('infrastructure')).toEqual({ lens: 'assets' });
    expect(resolveLensAlias('network')).toEqual({ lens: 'assets' });
  });

  it('does NOT treat a live lens as an alias', () => {
    for (const lens of INVENTORY_LENSES) {
      expect(resolveLensAlias(lens.key)).toBeNull();
    }
  });

  it('points every alias at a lens that exists', () => {
    for (const [from, to] of Object.entries(LENS_ALIASES)) {
      expect(INVENTORY_LENSES.some((l) => l.key === to.lens)).toBe(true);
      // An alias must not shadow a live lens key, or the redirect would fire
      // on a page that works.
      expect(INVENTORY_LENSES.some((l) => l.key === from)).toBe(false);
    }
  });
});

describe('placeholder lenses', () => {
  it('still describes any lens that is NOT built yet, rather than showing an empty table', () => {
    // A placeholder lens is SHOWN — the shape of the inventory is part of what
    // the nav communicates — but its body has to say when it arrives rather
    // than rendering an empty table that reads as "you have none of these".
    //
    // There are none left as of workstream 2.9 (`map` was the last), so this
    // walks whatever is marked rather than naming a key: the rule has to
    // survive the next lens that lands as a placeholder, and a hard-coded list
    // would have to be remembered.
    for (const lens of INVENTORY_LENSES) {
      if (!lens.placeholder) continue;
      expect(lens.live).toBe(false);
      expect(lens.placeholder.phase).toMatch(/phase [23]/);
      expect(lens.placeholder.message.length).toBeGreaterThan(40);
    }
  });

  it('has software and map LIVE, with no placeholder left behind', () => {
    // Both shipped from a placeholder — `software` in 2.6b, `map` in 2.9 — and
    // both are asserted here rather than dropped from the list, so demoting
    // either back to "arrives in phase 2" without a reason fails.
    for (const key of ['software', 'map']) {
      const lens = findLens(key);
      expect(lens.key).toBe(key);
      expect(lens.live).toBe(true);
      expect(lens.placeholder).toBeUndefined();
    }
  });

  it('marks every other lens live', () => {
    for (const lens of INVENTORY_LENSES) {
      if (lens.placeholder) continue;
      expect(lens.live).toBe(true);
    }
  });

  it('never leaves a lens both live and a placeholder', () => {
    for (const lens of INVENTORY_LENSES) {
      expect(lens.live && !!lens.placeholder).toBe(false);
    }
  });
});
