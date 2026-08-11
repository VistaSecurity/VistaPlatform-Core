// Routing contract for the platform-admin console.
//
// Added with the react-router v6 → v7 upgrade (open-redirect advisories
// GHSA-jjmj-jmhj-qwj2 et al. have no patched 6.x — v7 is the only remedy).
// A passing `tsc -b && vite build` only proves the imports resolve; it says
// nothing about whether URLs still resolve to the pages they used to.
//
// This console is the more exposed of the two UIs under the upgrade, because
// it is the one that uses the pattern v7 changed the semantics around: every
// section with left-rail children mounts on a SPLAT path (`/<id>/*`, App.tsx)
// and owns a DESCENDANT `<Routes>` whose child paths are RELATIVE
// (`path="email"`, `<Route index>`). React Router v7 turns on the old
// `v7_relativeSplatPath` future flag by default, which is exactly about how
// paths resolve underneath a splat. So the two-level resolution is exercised
// here for real, through react-router itself.
//
// The route SHAPES come from the real source: the top-level table is read out
// of `App()` and each section's descendant table out of that section's real
// component (all of them are thin, hook-free `<Routes>` wrappers). Only the
// LEAF ELEMENTS are replaced with markers, so no page component, query client
// or network call is involved.
//
// Carried through the v7 → v8 upgrade unchanged apart from the import rename
// (`react-router-dom` has no 8.x) and the version floor at the bottom. Every
// splat/descendant case below resolved identically on both majors, which is
// the evidence that the major bump did not move any operator-clickable URL.
import { describe, expect, it } from 'vitest';
import { Fragment, createElement, isValidElement, type ReactElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter, Navigate, Outlet, Route, Routes } from 'react-router';
import pkg from '../../package.json' with { type: 'json' };
import App from '../App';
import { SECTIONS } from './nav';
import { SupportPage } from '../sections/support/support-page';
import { BillingPage } from '../sections/billing/billing-page';
import { PlansPage } from '../sections/plans/plans-page';
import { SystemPage } from '../sections/system/system-page';
import { CommsPage } from '../sections/comms/comms-page';
import { CatalogPage } from '../sections/catalog/catalog-page';
import { SettingsPage } from '../sections/settings/settings-page';
import { StaffPage } from '../sections/staff/staff-page';
import { SecurityPage } from '../sections/security/security-page';

/** The real section components that own a descendant <Routes>, by section id. */
const SECTION_COMPONENTS: Record<string, () => unknown> = {
  support: SupportPage,
  billing: BillingPage,
  plans: PlansPage,
  system: SystemPage,
  comms: CommsPage,
  catalog: CatalogPage,
  settings: SettingsPage,
  staff: StaffPage,
  security: SecurityPage,
};

type RouteDef = { index?: boolean; path?: string; element: ReactElement; children?: unknown };

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

/** The direct <Route> children of a <Routes> (or of another <Route>). */
function childDefs(children: unknown): RouteDef[] {
  const list = (Array.isArray(children) ? children : [children]).flat(Infinity);
  return list.filter(isValidElement).map((el) => el.props as RouteDef);
}

function routeDefs(routesEl: ReactElement): RouteDef[] {
  return childDefs((routesEl.props as { children: unknown }).children);
}

// Every one of these is a plain, hook-free component, so it can be invoked
// directly to get at its element tree without mounting anything.
function defsOf(component: () => unknown, label: string): RouteDef[] {
  const routesEl = findRoutesElement(component());
  if (!routesEl) throw new Error(`no <Routes> found in ${label} — the test needs updating`);
  return routeDefs(routesEl);
}

const topDefs = defsOf(App as () => unknown, 'App');

/**
 * Rebuild the real route shape with marker leaves and render it at `url`.
 * The marker text is the leaf's own declared path (or `index` / `*`), so the
 * rendered output names exactly which <Route> react-router chose.
 */
function renderAt(url: string): string {
  const marker = (name: string) => createElement('i', null, name);
  const nameOf = (d: RouteDef) => (d.index ? 'index' : d.path ?? '?');

  const stubSection = (sectionId: string) => {
    const defs = defsOf(SECTION_COMPONENTS[sectionId], `${sectionId} section`);
    return function StubSection() {
      return createElement(
        Routes,
        null,
        defs.map((d, i) =>
          createElement(Route, {
            key: i,
            index: d.index,
            path: d.path,
            element: marker(`${sectionId}:${nameOf(d)}`),
          }),
        ),
      );
    };
  };

  // Rebuild the real (nested) <Route> tree, keeping every `path` / `index` /
  // nesting level and swapping only the elements: pathless layout routes
  // (RequireAuth, AppShell) become a bare <Outlet>, splat-mounted sections
  // become their real descendant table with marker leaves, everything else
  // becomes a marker naming its own path.
  const rebuild = (defs: RouteDef[]): ReactElement[] =>
    defs.map((d, i) => {
      const kids = d.children === undefined ? [] : childDefs(d.children);
      if (kids.length) {
        return createElement(
          Route,
          { key: i, index: d.index, path: d.path, element: createElement(Outlet) },
          ...rebuild(kids),
        );
      }
      // `/<id>/*` → this section owns a descendant <Routes>; stub it.
      const splat = typeof d.path === 'string' ? /^\/([^/]+)\/\*$/.exec(d.path) : null;
      const element =
        splat && SECTION_COMPONENTS[splat[1]]
          ? createElement(stubSection(splat[1]))
          : marker(nameOf(d));
      return createElement(Route, { key: i, index: d.index, path: d.path, element });
    });

  const tree = createElement(
    MemoryRouter,
    { initialEntries: [url] },
    createElement(Routes, null, ...rebuild(topDefs)),
  );
  return renderToStaticMarkup(createElement(Fragment, null, tree));
}

const leaf = (url: string) => renderAt(url).replace(/^<i>|<\/i>$/g, '');

describe('admin console route table (react-router v8)', () => {
  it.each([
    ['/login', 'login'],
    ['/reset-password', 'reset-password'],
    ['/forgot-password', 'forgot-password'],
  ])('public %s stays outside the auth gate', (url, expected) => {
    expect(leaf(url)).toBe(`/${expected}`);
  });

  it('the app index (inside the auth gate + shell) redirects to Mission Control', () => {
    const findIndex = (defs: RouteDef[]): RouteDef | undefined => {
      for (const d of defs) {
        if (d.index === true) return d;
        if (d.children !== undefined) {
          const nested = findIndex(childDefs(d.children));
          if (nested) return nested;
        }
      }
      return undefined;
    };
    const indexDef = findIndex(topDefs);
    expect(indexDef, 'App has no index route').toBeDefined();
    const el = indexDef!.element as ReactElement<{ to: string; replace?: boolean }>;
    expect(el.type).toBe(Navigate);
    expect(el.props.to).toBe('/overview');
    expect(el.props.replace).toBe(true);
  });

  // Childless sections mount on an exact path.
  it.each(SECTIONS.filter((s) => !s.children?.length).map((s) => s.id))(
    'childless section /%s resolves to its own route',
    (id) => {
      expect(leaf(`/${id}`)).toBe(`/${id}`);
    },
  );

  it('every section with left-rail children is covered by this test', () => {
    // Guards the guard: a new sub-navved section that is not listed in
    // SECTION_COMPONENTS would otherwise be stubbed as a plain leaf and its
    // descendant routing would go unchecked.
    const missing = SECTIONS.filter((s) => s.children?.length && !SECTION_COMPONENTS[s.id]).map(
      (s) => s.id,
    );
    expect(missing, 'add these to SECTION_COMPONENTS').toEqual([]);
  });

  // THE case this upgrade could have broken: a section mounted on `/<id>/*`
  // whose descendant <Routes> declares RELATIVE child paths. Every left-rail
  // URL an operator can click must still land on its own sub-route.
  const withChildren = SECTIONS.filter((s) => s.children?.length);
  it.each(withChildren.map((s) => [s.id, s.children!.map((c) => c.id)] as const))(
    'splat section /%s/* resolves every left-rail child',
    (id, childIds) => {
      // Bare /<id> → the section's index route.
      expect(leaf(`/${id}`)).toBe(`${id}:index`);
      for (const child of childIds) {
        // Every entry an operator can click in the left rail must land on its
        // own sub-route. Landing on `<id>:*` means it fell through to the
        // section catch-all — i.e. the rail entry is dead.
        expect(leaf(`/${id}/${child}`), `left-rail entry /${id}/${child} does not route`).toBe(
          `${id}:${child}`,
        );
      }
    },
  );

  it('a multi-segment child under a splat still resolves', () => {
    // A two-segment RELATIVE path inside the descendant <Routes> of a
    // splat-mounted section is the exact shape `v7_relativeSplatPath` changed.
    // No live section declares one right now (the last of them, Catalog →
    // Artifacts → Tenant Overrides, went with artifact-service), so the shape
    // is exercised synthetically rather than dropped: the hazard is a property
    // of react-router, and the next grandchild sub-view must land on it safely.
    const Section = () =>
      createElement(
        Routes,
        null,
        createElement(Route, { path: 'a', element: createElement('i', null, 'a') }),
        createElement(Route, { path: 'a/b', element: createElement('i', null, 'a/b') }),
      );
    const renderSynthetic = (url: string) =>
      renderToStaticMarkup(
        createElement(
          MemoryRouter,
          { initialEntries: [url] },
          createElement(
            Routes,
            null,
            createElement(Route, { path: '/sec/*', element: createElement(Section) }),
          ),
        ),
      ).replace(/<\/?i>/g, '');

    expect(renderSynthetic('/sec/a')).toBe('a');
    expect(renderSynthetic('/sec/a/b')).toBe('a/b');
  });

  it('an unknown sub-path inside a section hits that section catch-all, not the app one', () => {
    expect(leaf('/settings/not-a-real-subpage')).toBe('settings:*');
    expect(leaf('/security/not-a-real-subpage')).toBe('security:*');
  });

  it('each section catch-all redirects back to that section root', () => {
    for (const id of Object.keys(SECTION_COMPONENTS)) {
      const catchAll = defsOf(SECTION_COMPONENTS[id], id).find((d) => d.path === '*');
      expect(catchAll, `${id} has no catch-all`).toBeDefined();
      const el = catchAll!.element as ReactElement<{ to: string; replace?: boolean }>;
      expect(el.type).toBe(Navigate);
      expect(el.props.to).toBe(`/${id}`);
      expect(el.props.replace).toBe(true);
    }
  });

  it('an unknown top-level URL hits the app catch-all', () => {
    expect(leaf('/definitely-not-a-section')).toBe('*');
  });

  it('a query string does not change which route matches', () => {
    expect(leaf('/settings/email?foo=bar')).toBe('settings:email');
    expect(leaf('/security/activity?page=2')).toBe('security:activity');
  });
});

describe('react-router version floor', () => {
  // Two advisories stack here, and each one's fix is the next major:
  //
  //   GHSA-jjmj-jmhj-qwj2  open redirect → XSS via `<Link>` / `useNavigate`
  //                        >=6.0.0 <7.18.0. No patched 6.x exists (6.30.4 is
  //                        the last 6.x), so v7 was the only remedy.
  //   GHSA-qwww-vcr4-c8h2  RSC-mode CSRF, HIGH. >=7.12.0 <8.3.0 — i.e. the
  //                        v7 fix for the first one landed INSIDE the window
  //                        of the second. Patched only in 8.3.0.
  //
  // So 8.3.0 is the first version clear of both, and there is no lower
  // release to fall back to. Pin the floor here rather than relying on
  // someone reading `npm audit`.
  //
  // The package name is part of the assertion, not incidental: `react-router-dom`
  // was a thin re-export of `react-router` through 7.x and DOES NOT EXIST at
  // 8.x (7.18.2 is its last release). Reading a `react-router-dom` range would
  // therefore silently read `undefined` and the version check would throw
  // rather than fail meaningfully.
  it('is declared on react-router (not react-router-dom) at >= 8.3.0', () => {
    const deps = (pkg as { dependencies: Record<string, string> }).dependencies;
    expect(deps['react-router-dom'], 'react-router-dom has no 8.x — do not reintroduce it').toBeUndefined();
    const range = deps['react-router'];
    expect(range, 'react-router is not a declared dependency').toBeDefined();
    const [major, minor] = range.replace(/^[^0-9]*/, '').split('.').map(Number);
    expect(major).toBeGreaterThanOrEqual(8);
    if (major === 8) expect(minor).toBeGreaterThanOrEqual(3);
  });

  // React 19 is not a free-standing choice — react-router@8 declares
  // `react: >=19.2.7`. If someone rolls React back to 18 to unstick a build,
  // the router silently drops below its own supported floor.
  it('pins React at the >= 19.2.7 floor react-router@8 requires', () => {
    const range = (pkg as { dependencies: Record<string, string> }).dependencies['react'];
    const [major, minor, patch] = range.replace(/^[^0-9]*/, '').split('.').map(Number);
    expect(major).toBeGreaterThanOrEqual(19);
    if (major === 19) {
      expect(minor).toBeGreaterThanOrEqual(2);
      if (minor === 2) expect(patch).toBeGreaterThanOrEqual(7);
    }
  });
});
