// @vitest-environment jsdom
//
// DCIM row 1.6: the Settings page for network boundaries is gone with its
// table (its old label is assembled below, so the vocabulary guard keeps
// hunting the literal everywhere else). The nav
// entry is removed, and a bookmark to /settings/segments lands on Inventory →
// Networks — rendered here through the REAL route element App() declares, so
// deleting the redirect (or letting /settings/:page swallow it) goes red.
import { act, isValidElement, type ReactElement } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter, Route, Routes, createRoutesFromElements, matchRoutes, useLocation } from 'react-router';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import App from '../../App';
import { SETTINGS_NAV, settingsPageMeta } from './nav';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

function findRoutes(node: unknown): ReactElement | null {
  if (Array.isArray(node)) {
    for (const c of node) { const f = findRoutes(c); if (f) return f; }
    return null;
  }
  if (!isValidElement(node)) return null;
  if (node.type === Routes) return node;
  const children = (node.props as { children?: unknown }).children;
  return children === undefined ? null : findRoutes(children);
}

/** The element App() routes /settings/segments to. */
function segmentsRouteElement(): ReactElement {
  const routesEl = findRoutes((App as () => unknown)());
  if (!routesEl) throw new Error('could not locate <Routes> in App()');
  const routes = createRoutesFromElements((routesEl.props as { children: ReactElement }).children);
  const matches = matchRoutes(routes, '/settings/segments');
  if (!matches) throw new Error('/settings/segments matched nothing');
  return matches[matches.length - 1].route.element as ReactElement;
}

function Landed() {
  const loc = useLocation();
  return <div data-testid="landed">{loc.pathname}{loc.search}</div>;
}

let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

const RETIRED_LABEL = ['Network', 'Segments'].join(' ');

describe('the Settings page for network boundaries is retired', () => {
  it('a /settings/segments bookmark lands on Inventory → Networks', async () => {
    const el = segmentsRouteElement();
    await act(async () => {
      root.render(
        <MemoryRouter initialEntries={['/settings/segments']}>
          <Routes>
            <Route path="/settings/segments" element={el} />
            <Route path="/inventory" element={<Landed />} />
          </Routes>
        </MemoryRouter>,
      );
    });
    expect(host.querySelector('[data-testid="landed"]')?.textContent).toBe('/inventory?lens=networks');
  });

  it('is not in the settings navigation', () => {
    const keys = SETTINGS_NAV.flatMap((s) => s.items.map((i) => i.key));
    expect(keys.length).toBeGreaterThan(0); // a scan that finds nothing must fail
    expect(keys).not.toContain('segments');
    expect(SETTINGS_NAV.flatMap((s) => s.items.map((i) => i.label))).not.toContain(RETIRED_LABEL);
    // And the meta lookup no longer knows it as a built page.
    expect(settingsPageMeta('segments').built).not.toBe(true);
  });
});
