// Reachability for the map (workstream 2.9), in BOTH polarities.
//
// The feature framework's rule is that no layer ships without its consumer, and
// this feature has four: a lens registry entry, a nav item, a ⌘K entry and a
// full-screen route. Each can fail in two opposite directions — it can be
// MISSING (built and unreachable), or it can be PRESENT while still declaring
// itself a placeholder (reachable and lying about being live). The map spent
// two phases in the second state: the lens was in the registry, the nav showed
// it, ⌘K offered it, and all three led to a card saying "arrives in phase 2".
// A test that only checked for presence would have passed throughout.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { isValidElement, type ReactElement } from 'react';
import { Routes, createRoutesFromElements, matchRoutes } from 'react-router';
import App from '../../App';
import { SECTIONS } from '../../app/nav';
import { PUBLIC_PATHS } from '../../app/public-routes';
import { LENS_NAV_ITEMS } from '../../app/command-palette';
import { ICON_NAMES } from '../../components/ui';
import { INVENTORY_LENSES, findLens } from './lenses';

// --------------------------------------------- the real route table again --
// Same technique as app/routing.contract.test.tsx: App is a plain, hook-free
// component, so it can be invoked directly and its <Routes> read. Asserting
// against the REAL table is the point — a route this test invented would prove
// nothing about what the app serves.
function findRoutesElement(node: unknown): ReactElement | null {
  if (Array.isArray(node)) {
    for (const child of node) {
      const found = findRoutesElement(child);
      if (found) return found;
    }
    return null;
  }
  if (!isValidElement(node)) return null;
  if (node.type === Routes) return node;
  const children = (node.props as { children?: unknown }).children;
  return children === undefined ? null : findRoutesElement(children);
}

const routesEl = findRoutesElement((App as () => unknown)());
if (!routesEl) throw new Error('could not locate <Routes> in App() — the test needs updating');
const routes = createRoutesFromElements((routesEl.props as { children: ReactElement }).children);

const resolve = (url: string): string => {
  const matches = matchRoutes(routes, url);
  return matches ? matches.map((m) => m.route.path ?? (m.route.index ? 'index' : '~layout')).join(' > ') : '(no match)';
};

const paramsFor = (url: string): Record<string, string | undefined> => {
  const matches = matchRoutes(routes, url);
  return matches ? matches[matches.length - 1].params : {};
};

// ------------------------------------------------------------- the lens ---

describe('the Inventory map lens', () => {
  it('is in the registry, LIVE, and in the Assets group', () => {
    const lens = findLens('map');
    expect(lens.key).toBe('map');
    expect(lens.live).toBe(true);
    expect(lens.group).toBe('assets');
    expect(lens.primary).toBe(true);
  });

  it('carries no leftover placeholder', () => {
    // The other polarity, and the state this workstream started in.
    const lens = INVENTORY_LENSES.find((l) => l.key === 'map')!;
    expect(lens.placeholder).toBeUndefined();
  });

  it('is exactly one lens — the registry has no duplicate', () => {
    expect(INVENTORY_LENSES.filter((l) => l.key === 'map')).toHaveLength(1);
  });

  it('names an icon the Icon component can actually draw', () => {
    // `waypoints` was named by the registry while missing from the icon map, so
    // the lens's own nav glyph was the unknown-name placeholder. The failure is
    // silent by design in production, which is why it needs asserting here.
    expect(ICON_NAMES).toContain(findLens('map').icon);
  });

  it('...and so does every other lens', () => {
    // Widened deliberately: the map's icon was not specially broken, it was one
    // instance of a registry naming icons as bare strings with nothing checking
    // them.
    const unknown = INVENTORY_LENSES.filter((l) => !ICON_NAMES.includes(l.icon)).map((l) => `${l.key}: ${l.icon}`);
    expect(unknown).toEqual([]);
  });
});

// -------------------------------------------------------------- the nav ---

describe('the nav entry', () => {
  it('exists, and points at the lens URL', () => {
    // A lens with no nav home is a page nobody reaches without typing a URL.
    const inventory = SECTIONS.find((s) => s.id === 'inventory')!;
    const entry = (inventory.groups ?? []).flatMap((g) => g.items).find((i) => i.lens === 'map');
    expect(entry).toBeDefined();
    expect(entry!.path).toBe('/inventory?lens=map');
    expect(entry!.label).toBe('Map');
  });

  it('sits in the Assets group beside the list it is an alternative view of', () => {
    const inventory = SECTIONS.find((s) => s.id === 'inventory')!;
    const assets = (inventory.groups ?? []).find((g) => g.label === 'Assets')!;
    expect(assets.items.map((i) => i.lens)).toContain('map');
  });
});

// ------------------------------------------------------ the ⌘K palette ----

describe('the command palette', () => {
  it('offers the map', () => {
    const item = LENS_NAV_ITEMS.find((i) => i.to === '/inventory?lens=map');
    expect(item).toBeDefined();
    expect(item!.label).toBe('Inventory · Map');
  });

  it('no longer warns that it is not built yet', () => {
    // The other polarity. The palette derives its sublabel from the lens's
    // placeholder, so a live lens must carry no "phase 2 — not built yet"
    // caption — which would send people away from a page that works.
    const item = LENS_NAV_ITEMS.find((i) => i.to === '/inventory?lens=map')!;
    expect(item.sublabel).toBeUndefined();
  });

  it('stays in parity with the lens registry — every primary lens, and nothing else', () => {
    const offered = LENS_NAV_ITEMS.map((i) => new URL(i.to, 'https://x').searchParams.get('lens'));
    const expected = INVENTORY_LENSES.filter((l) => l.primary).map((l) => l.key);
    expect(offered.sort()).toEqual(expected.sort());
  });
});

// ------------------------------------------------- the full-screen route --

describe('the full-screen map route', () => {
  it('resolves and captures the asset id', () => {
    expect(resolve('/inventory/map/a1b2c3')).not.toBe('(no match)');
    expect(paramsFor('/inventory/map/a1b2c3')).toEqual({ assetId: 'a1b2c3' });
  });

  it('is behind the auth gate but OUTSIDE the app shell', () => {
    // Exactly one pathless layout ancestor (RequireAuth), not two: the whole
    // point of the full-screen mode is that the rail is not competing with the
    // canvas. Two would mean it kept the shell; zero would mean it escaped the
    // auth gate.
    expect(resolve('/inventory/map/a1b2c3')).toBe('~layout > /inventory/map/:assetId');
  });

  it('is NOT a public path', () => {
    // The routing contract asserts that every route declared outside
    // RequireAuth appears in PUBLIC_PATHS. This is the same rule read the other
    // way: a gated route must not be listed there, or an expired session would
    // stop bouncing to /login on it.
    expect(PUBLIC_PATHS).not.toContain('/inventory/map/:assetId');
  });

  it('does not fall through to the catch-all', () => {
    expect(resolve('/inventory/map/a1b2c3')).not.toContain('*');
  });

  it('does not swallow the asset page or the lens', () => {
    // The reverse direction: a route added under /inventory must not shadow the
    // ones that were there. `/inventory/map/:assetId` and
    // `/inventory/assets/:id` differ only in one static segment.
    expect(resolve('/inventory')).toBe('~layout > ~layout > /inventory');
    expect(resolve('/inventory?lens=map')).toBe('~layout > ~layout > /inventory');
    expect(resolve('/inventory/assets/a1b2c3')).toBe('~layout > ~layout > /inventory/assets/:id');
    expect(resolve('/inventory/assets/a1b2c3/relationships')).toBe('~layout > ~layout > /inventory/assets/:id/:tab');
  });

  it('renders a page, not a redirect', () => {
    // A nav target that resolves to a <Navigate> is a page that does not exist.
    const matches = matchRoutes(routes, '/inventory/map/a1b2c3')!;
    const el = matches[matches.length - 1].route.element as ReactElement<{ to?: string }>;
    expect(el.props.to).toBeUndefined();
  });
});

// ------------------------------------------------- the seeds-part-3 wiring --
//
// `map-layout.test.ts` and `map-export.test.ts` pin the pure functions. Neither
// can fail if the COMPONENT stops calling them — the offsets could be computed
// and thrown away, and the dismissal rules could be exported and never bound to
// a listener, with both suites green. That is the "test the wiring, not the
// helper" rule, so this reads the component.
describe('the map lens wires its geometry and its menu', () => {
  const lens = readFileSync(join(new URL('.', import.meta.url).pathname, 'map-lens.tsx'), 'utf8');

  it('spreads parallel edges and hands each edge its offset', () => {
    // Without all three, an application that both `runs_on` and `connects_to`
    // its host is one visible line again, with the second edge's provenance and
    // confidence unreachable.
    expect(lens).toContain('parallelEdgeOffsets(graph.edges)');
    expect(lens).toContain("type: 'offset'");
    expect(lens).toContain('edgeTypes={EDGE_TYPES}');
  });

  it('binds BOTH dismissal rules to real listeners', () => {
    expect(lens).toContain('closesOnKey(e.key)');
    expect(lens).toContain('closesOnOutsidePointer(e.target');
    expect(lens).toContain("addEventListener('keydown'");
    expect(lens).toContain("addEventListener('mousedown'");
  });

  it('no longer relies on mouseleave, which no keyboard or touch user produces', () => {
    // The other polarity: re-adding it would let the menu close itself out from
    // under a pointer travelling to an item, which is the bug the rules replace.
    expect(lens).not.toContain('onMouseLeave');
  });

  it('tells assistive tech the button opens a menu, and whether it is open', () => {
    expect(lens).toContain('aria-haspopup="menu"');
    expect(lens).toContain('aria-expanded={open && !disabled}');
    expect(lens).toContain('role="menu"');
  });
});
