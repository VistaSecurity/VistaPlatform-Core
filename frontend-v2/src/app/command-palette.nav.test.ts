// ⌘K's quick-navigation list is a map of the product, and a map drawn by hand
// goes stale the first time a room is added or removed — silently, because
// nothing fails when it does.
//
// It advertised `infrastructure` and `network`, two retired lens keys that only
// redirect, and offered none of the lenses added since: All assets, Map,
// Software, Data Protection, Stale. The inventory entries are now DERIVED from
// the lens registry and this file guards the join in both directions.
import { describe, expect, it } from 'vitest';
import { LENS_NAV_ITEMS, NAV_ITEMS } from './command-palette';
import { INVENTORY_LENSES, LENS_ALIASES } from '../sections/inventory/lenses';
import { SECTIONS } from './nav';
import { SETTINGS_NAV } from '../sections/settings/nav';

/** The `lens` a quick-nav target opens, or null when it is not a lens link. */
function lensOf(to: string): string | null {
  const qs = to.split('?')[1];
  if (!qs) return null;
  return new URLSearchParams(qs).get('lens');
}

describe('palette ↔ lens registry parity (gate1 C8)', () => {
  it('offers every primary lens', () => {
    const offered = LENS_NAV_ITEMS.map((i) => lensOf(i.to));
    for (const lens of INVENTORY_LENSES.filter((l) => l.primary)) {
      expect(offered, `⌘K does not offer the ${lens.key} lens`).toContain(lens.key);
    }
  });

  it('offers ONLY lenses that exist — no retired key, no alias', () => {
    // The polarity that was failing: `infrastructure` and `network` are in
    // LENS_ALIASES, not INVENTORY_LENSES.
    for (const item of NAV_ITEMS) {
      const lens = lensOf(item.to);
      if (lens === null) continue;
      expect(INVENTORY_LENSES.some((l) => l.key === lens), `⌘K offers “${lens}”, which is not a lens`).toBe(true);
      expect(Object.keys(LENS_ALIASES), `⌘K offers the retired key “${lens}”`).not.toContain(lens);
    }
  });

  it('does not offer the protocol sub-lenses as places of their own', () => {
    const offered = LENS_NAV_ITEMS.map((i) => lensOf(i.to));
    for (const lens of INVENTORY_LENSES.filter((l) => !l.primary)) {
      expect(offered).not.toContain(lens.key);
    }
  });

  it('labels each lens entry with the registry’s own label', () => {
    for (const item of LENS_NAV_ITEMS) {
      const lens = INVENTORY_LENSES.find((l) => l.key === lensOf(item.to))!;
      expect(item.label).toBe(`Inventory · ${lens.label}`);
    }
  });

  it('says so when a lens is a placeholder, rather than sending someone to an empty page', () => {
    for (const item of LENS_NAV_ITEMS) {
      const lens = INVENTORY_LENSES.find((l) => l.key === lensOf(item.to))!;
      if (lens.placeholder) expect(item.sublabel).toContain(lens.placeholder.phase);
      else expect(item.sublabel ?? '').not.toMatch(/not built/);
    }
  });

  it('gives every entry a unique id', () => {
    const ids = NAV_ITEMS.map((i) => i.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe('palette ↔ settings registry parity (gate1 C8)', () => {
  const settingsKeys = SETTINGS_NAV.flatMap((s) => s.items.map((i) => i.key));

  it('offers the two pages that explain how the inventory is decided', () => {
    const targets = NAV_ITEMS.map((i) => i.to);
    expect(targets).toContain('/settings/classes');
    expect(targets).toContain('/settings/identification-rules');
  });

  it('points every settings entry at a page the settings rail actually has', () => {
    for (const item of NAV_ITEMS) {
      const m = /^\/settings\/([^?]+)$/.exec(item.to);
      if (!m) continue;
      expect(settingsKeys, `⌘K offers /settings/${m[1]}, which is not a settings page`).toContain(m[1]);
    }
  });
});

describe('palette ↔ Bills of Materials (ADR-0005 D6)', () => {
  const railLabel = SECTIONS
    .flatMap((sec) => sec.groups ?? [])
    .flatMap((g) => g.items)
    .find((i) => i.path === '/risk-compliance/cbom')?.label;

  const entry = NAV_ITEMS.find((i) => i.to === '/risk-compliance/cbom');

  it('calls the page what the left rail calls it', () => {
    // The rename left the palette saying "CBOM" while the rail said "Bills of
    // Materials". Two names for one page is worse than either: someone who saw
    // it in the rail cannot find it here, and the whole reason for the rename
    // was that a user wanting an SBOM would never look under "CBOM".
    //
    // Scoped to this page on purpose. Several palette entries use a deliberate
    // shorthand for a longer rail label ("Discovery · Sensors" for "Sensors &
    // Agents"), so a blanket label-equality rule across the palette would fail
    // on entries that are fine — and renaming those is not this change's
    // business. `endsWith` because the palette prefixes the section and the
    // rail, being inside it already, does not.
    expect(railLabel, 'the left rail has no /risk-compliance/cbom item').toBeTruthy();
    expect(entry, 'the Bills of Materials page is not in the palette at all').toBeTruthy();
    expect(
      entry!.label.endsWith(railLabel!),
      `⌘K calls it “${entry!.label}”; the left rail calls it “${railLabel!}”`,
    ).toBe(true);
  });

  it('is found by every kind a user might type', () => {
    // The palette matches on label AND sublabel, so the four kinds have to be
    // written down in the entry or the search that matters most — for a word
    // that is not in the page title — returns nothing.
    const haystack = `${entry!.label} ${entry!.sublabel ?? ''}`.toLowerCase();
    for (const term of ['cbom', 'sbom', 'hbom', 'inventory']) {
      expect(haystack, `typing “${term}” finds nothing`).toContain(term);
    }
  });
});
