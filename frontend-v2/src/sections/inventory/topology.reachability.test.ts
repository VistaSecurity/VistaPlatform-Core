// Reachability for the topology view (ADR-0006 D4 second half, workstream 3.8),
// in BOTH polarities.
//
// The feature framework's rule is that no layer ships without its consumer, and
// this feature has four: a backend endpoint, a view component, the `?view=`
// switch on the Map lens, and a link to it from the dashboard hero. Each can
// fail in two opposite directions — it can be MISSING (built and unreachable),
// or it can be PRESENT while the thing it points at is still a placeholder
// (reachable and lying about being live). The map lens spent two phases in the
// second state, which is why both directions are asserted here.
//
// The tests read the REAL registries and the REAL source: a nav entry this test
// invented would prove nothing about what the app serves.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { SECTIONS } from '../../app/nav';
import { LENS_NAV_ITEMS } from '../../app/command-palette';
import { INVENTORY_LENSES, findLens } from './lenses';
import { DEFAULT_MAP_VIEW, MAP_VIEWS, readMapView } from './topology-model';

const here = new URL('.', import.meta.url).pathname;
const read = (rel: string) => readFileSync(join(here, rel), 'utf8');

describe('the Map lens still gets a person to the map', () => {
  it('is in the registry, LIVE, and in the Assets group', () => {
    const lens = findLens('map');
    expect(lens.live).toBe(true);
    expect(lens.group).toBe('assets');
  });

  it('carries no leftover placeholder', () => {
    expect(INVENTORY_LENSES.find((l) => l.key === 'map')!.placeholder).toBeUndefined();
  });

  it('has a nav entry and a ⌘K entry, unchanged by the second view', () => {
    // Adding a view must not move the front door. A user who has always reached
    // the map from the sidebar keeps reaching it the same way.
    const inventory = SECTIONS.find((s) => s.id === 'inventory')!;
    const entry = (inventory.groups ?? []).flatMap((g) => g.items).find((i) => i.lens === 'map');
    expect(entry?.path).toBe('/inventory?lens=map');
    expect(LENS_NAV_ITEMS.find((i) => i.to === '/inventory?lens=map')).toBeDefined();
  });
});

describe('the view switch', () => {
  const shell = read('map-shell.tsx');

  it('derives its controls from the REGISTRY, so no declared view can lack one', () => {
    // Asserted as "it maps over MAP_VIEWS" rather than "it contains two
    // buttons": a view added to the registry must get a control without an edit
    // here, and two hand-written buttons would silently not.
    expect(shell).toContain('MAP_VIEWS.map(');
    expect(shell).toContain('data-testid={`map-view-${key}`}');
    // VIEW_META is typed `Record<MapView, …>`, so a view with no label is a
    // compile error rather than a button reading "undefined". Pinned here
    // because a widened type would make that guarantee vanish silently.
    expect(shell).toContain('Readonly<Record<MapView,');
    expect(MAP_VIEWS.length).toBeGreaterThan(1);
  });

  it('actually mounts the topology component, not a placeholder card', () => {
    // The other polarity, and the state the map lens shipped in twice: a switch
    // that is present, clickable, and leads to "arrives in phase 3".
    expect(shell).toContain("import('./topology-view')");
    expect(shell).not.toMatch(/arrives in phase/i);
  });

  it('mounts BOTH halves lazily, so neither ships to someone who opens the other', () => {
    expect(shell).toContain("import('./map-lens')");
    expect(shell).toMatch(/lazy\(/);
  });

  it('keeps an old focus= link on the neighbourhood while the estate is the default', () => {
    expect(readMapView(null)).toBe(DEFAULT_MAP_VIEW);
    expect(DEFAULT_MAP_VIEW).toBe('network');
    // The shell must pass the focus through, or every pre- map link
    // would open the estate instead of the asset it names.
    expect(shell).toContain("readMapView(params.get('view'), params.has('focus'))");
  });

  it('mounts the network view lazily too', () => {
    expect(shell).toContain("import('./network-map-view')");
  });

  it('leaves the implied view OUT of the URL rather than writing it in', () => {
    // Writing `?view=` on every tab switch would churn every shared link.
    expect(shell).toContain("p.delete('view')");
  });
});
