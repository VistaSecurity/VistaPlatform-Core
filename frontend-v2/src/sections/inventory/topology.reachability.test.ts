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

  it('keeps the neighbourhood as the default, so an old bookmark still lands there', () => {
    expect(readMapView(null)).toBe(DEFAULT_MAP_VIEW);
    expect(DEFAULT_MAP_VIEW).toBe('neighbourhood');
  });

  it('leaves the default OUT of the URL rather than writing it in', () => {
    // `/inventory?lens=map` has always meant the neighbourhood. Writing
    // `?view=neighbourhood` on every visit would churn every shared link.
    expect(shell).toContain("p.delete('view')");
  });
});

describe('the Inventory page reaches the switch', () => {
  it('routes the map lens through MapShell rather than straight at one renderer', () => {
    const page = read('inventory-page.tsx');
    expect(page).toContain('<MapShell />');
    // The other polarity: if the page still mounted AssetMapLens directly, the
    // switch would exist and never render.
    expect(page).not.toContain('<AssetMapLens />');
  });
});

describe('the topology view is wired to a real endpoint', () => {
  it('reads GET /infrastructure-assets/topology through the generated client', () => {
    // A component with no caller is a gap; so is a hook nothing calls. Both
    // halves are asserted, in the source, because there is no router to drive.
    expect(read('relationship-queries.ts')).toContain("'/infrastructure-assets/topology'");
    expect(read('topology-view.tsx')).toContain('useAssetTopology');
  });

  it('drills through to the asset list rather than dead-ending', () => {
    const view = read('topology-view.tsx');
    expect(view).toContain('classDrillThroughQuery');
    expect(view).toContain('segmentDrillThroughQuery');
    expect(view).toContain('topologyAssetsHref');
  });
});

describe('the dashboard hero offers the topology', () => {
  it('links at it by its deep-linkable URL', () => {
    // The hero is where an ops persona starts, and "where is everything" is the
    // question the topology answers. A view reachable only by finding a segmented
    // control on another page is a view most people never see.
    const hero = readFileSync(join(here, '..', 'dashboard', 'inventory-health-hero.tsx'), 'utf8');
    expect(hero).toContain('/inventory?lens=map&view=topology');
  });

  it('is mounted on the dashboard, not on a page of its own', () => {
    // ADR-0006 D5 is explicit: "No new dashboard." Both personas read one page.
    const page = readFileSync(join(here, '..', 'dashboard', 'dashboard-page.tsx'), 'utf8');
    expect(page).toContain('<InventoryHealthHero />');
  });
});
