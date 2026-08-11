// Routing contract for the tenant console.
//
// Added with the react-router v6 → v7 upgrade (open-redirect advisories
// GHSA-jjmj-jmhj-qwj2 et al. have no patched 6.x — v7 is the only remedy).
// A passing `tsc -b && vite build` only proves the imports resolve; it says
// nothing about whether URLs still resolve to the pages they used to. This
// file pins that separately.
//
// It reads the REAL route table out of `App()` (which is a plain, hook-free
// component, so it can be called directly) and drives it through react-router's
// real matcher. No DOM, no providers, no network — pure route resolution.
//
// Carried through the v7 → v8 upgrade unchanged apart from the import rename
// (`react-router-dom` has no 8.x) and the version floor at the bottom. It
// resolved identically on both majors, which is the evidence that the rename
// and the major bump did not move any URL.
import { describe, expect, it } from 'vitest';
import { isValidElement, type ReactElement } from 'react';
import { Routes, createRoutesFromElements, matchRoutes } from 'react-router';
import pkg from '../../package.json' with { type: 'json' };
import App from '../App';

/** Pull the real <Routes> element out of App()'s rendered tree. */
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

// App is a plain, hook-free component, so it can be invoked directly to get at
// its element tree without mounting anything.
const routesEl = findRoutesElement((App as () => unknown)());
if (!routesEl) throw new Error('could not locate <Routes> in App() — the test needs updating');
const routes = createRoutesFromElements((routesEl.props as { children: ReactElement }).children);

/**
 * Resolve a URL against the real route table and render the matched chain as a
 * readable string: each ancestor contributes its `path`, or `~layout` for a
 * pathless layout route (RequireAuth / AppShell), or `index` for an index route.
 */
function resolve(url: string): string {
  const matches = matchRoutes(routes, url);
  if (!matches) return '(no match)';
  return matches.map((m) => m.route.path ?? (m.route.index ? 'index' : '~layout')).join(' > ');
}

function paramsFor(url: string): Record<string, string | undefined> {
  const matches = matchRoutes(routes, url);
  return matches ? matches[matches.length - 1].params : {};
}

describe('tenant console route table (react-router v8)', () => {
  // Public routes — reachable while signed out. A regression here locks users
  // out of sign-in / signup / the emailed reset+invite landings.
  it.each([
    ['/login', '/login'],
    ['/signup', '/signup'],
    ['/verify-email', '/verify-email'],
    ['/reset-password', '/reset-password'],
    ['/accept-invite', '/accept-invite'],
    ['/auth/sso/callback', '/auth/sso/callback'],
    ['/register/complete', '/register/complete'],
    ['/register/complete-profile', '/register/complete-profile'],
    ['/legal/terms', '/legal/terms'],
    ['/legal/privacy', '/legal/privacy'],
  ])('public %s resolves outside the auth gate', (url, expected) => {
    expect(resolve(url)).toBe(expected);
  });

  // Authenticated routes sit under two pathless layout routes: RequireAuth
  // (the gate) then AppShell (the chrome). Both must stay in the chain — losing
  // either would either unguard the route or drop the nav.
  it.each([
    ['/', '~layout > ~layout > index'],
    ['/dashboard', '~layout > ~layout > /dashboard'],
    ['/about', '~layout > ~layout > /about'],
    ['/inventory', '~layout > ~layout > /inventory'],
    ['/discovery', '~layout > ~layout > /discovery'],
    ['/discovery/sensors', '~layout > ~layout > /discovery/sensors'],
    ['/discovery/active-scan', '~layout > ~layout > /discovery/active-scan'],
    ['/risk-compliance/posture', '~layout > ~layout > /risk-compliance/posture'],
    ['/risk-compliance/findings', '~layout > ~layout > /risk-compliance/findings'],
    ['/risk-compliance/cbom', '~layout > ~layout > /risk-compliance/cbom'],
    ['/risk-compliance/cbom/compare', '~layout > ~layout > /risk-compliance/cbom/compare'],
    ['/remediation/alerts', '~layout > ~layout > /remediation/alerts'],
    ['/remediation/triage', '~layout > ~layout > /remediation/triage'],
    ['/getting-started', '~layout > ~layout > /getting-started'],
    ['/settings', '~layout > ~layout > /settings'],
    ['/profile', '~layout > ~layout > /profile'],
  ])('gated %s resolves through RequireAuth + AppShell', (url, expected) => {
    expect(resolve(url)).toBe(expected);
  });

  it('dynamic settings/profile sub-pages still capture :page', () => {
    expect(resolve('/settings/org-overview')).toBe('~layout > ~layout > /settings/:page');
    expect(paramsFor('/settings/org-overview')).toEqual({ page: 'org-overview' });
    expect(resolve('/profile/personal')).toBe('~layout > ~layout > /profile/:page');
    expect(paramsFor('/profile/personal')).toEqual({ page: 'personal' });
  });

  it('a query string does not change which route matches', () => {
    // Inventory lenses, findings lenses and posture tabs are all ?param-driven
    // (useSearchParams), so the route must match on pathname alone.
    expect(resolve('/inventory?lens=keys')).toBe('~layout > ~layout > /inventory');
    expect(resolve('/risk-compliance/findings?lens=crypto')).toBe('~layout > ~layout > /risk-compliance/findings');
    expect(resolve('/risk-compliance/posture?tab=frameworks')).toBe('~layout > ~layout > /risk-compliance/posture');
  });

  it('unknown gated URLs fall through to the catch-all, not off the table', () => {
    expect(resolve('/definitely-not-a-page')).toBe('~layout > ~layout > *');
    expect(resolve('/discovery/not-a-thing')).toBe('~layout > ~layout > *');
  });

  it('the documented /cbom deep links still redirect into risk-compliance', () => {
    expect(resolve('/cbom')).toBe('~layout > ~layout > /cbom');
    expect(resolve('/cbom/compare')).toBe('~layout > ~layout > /cbom/compare');
    // ...and the element they render is the redirect, with the right target.
    for (const [url, target] of [
      ['/cbom', '/risk-compliance/cbom'],
      ['/cbom/compare', '/risk-compliance/cbom/compare'],
    ] as const) {
      const matches = matchRoutes(routes, url)!;
      const el = matches[matches.length - 1].route.element as ReactElement<{ to: string; replace?: boolean }>;
      expect(el.props.to).toBe(target);
      expect(el.props.replace).toBe(true);
    }
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
