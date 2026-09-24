// Owner decisions 9 and 10 (ADMIN_UI_DATA_REVIEW_2026-09, RC-20 / RC-21):
// stubs and duplicate stores removed from the operator console.
//
//   - Comms is gone from the rail and the route table. Its Maintenance form
//     wrote a table nothing read; the one maintenance-window store is the one
//     alert suppression reads, whose form is System → Alerts, so the old URL
//     redirects there. Announcements are hidden until they can be delivered.
//   - Support → Impersonation is gone from the rail and the route table: it
//     listed an audit trail nothing could write.
//
// Read from the REAL nav registry and the REAL App / SupportPage route tables
// (the same technique routing.contract.test.tsx uses), so re-adding either
// entry or either route fails here.
import { describe, expect, it } from 'vitest';
import { isValidElement, type ReactElement } from 'react';
import { Navigate, Routes } from 'react-router';
import App from '../App';
import { SECTIONS, SECTION_BY_ID, visibleSections } from './nav';
import { SupportPage } from '../sections/support/support-page';

type RouteDef = { index?: boolean; path?: string; element: ReactElement; children?: unknown };

function findRoutes(node: unknown): ReactElement | null {
  if (Array.isArray(node)) {
    for (const c of node) {
      const f = findRoutes(c);
      if (f) return f;
    }
    return null;
  }
  if (!isValidElement(node)) return null;
  if (node.type === Routes) return node;
  const children = (node.props as { children?: unknown }).children;
  return children === undefined ? null : findRoutes(children);
}

function defs(children: unknown): RouteDef[] {
  return (Array.isArray(children) ? children : [children])
    .flat(Infinity)
    .filter(isValidElement)
    .map((el) => el.props as RouteDef);
}

/** Every <Route> in a component's <Routes>, flattened through nesting. */
function allRoutes(component: () => unknown): RouteDef[] {
  const routes = findRoutes(component());
  if (!routes) throw new Error('no <Routes> found');
  const walk = (ds: RouteDef[]): RouteDef[] =>
    ds.flatMap((d) => [d, ...(d.children === undefined ? [] : walk(defs(d.children)))]);
  return walk(defs((routes.props as { children: unknown }).children));
}

const appRoutes = allRoutes(App as () => unknown);
const everything = () => true;
const allCapabilities = { msp: true, billing: true };

function redirectOf(path: string): { to: string; replace?: boolean } | undefined {
  const d = appRoutes.find((r) => r.path === path);
  if (!d) return undefined;
  expect(d.element.type, `${path} must be a redirect`).toBe(Navigate);
  return d.element.props as { to: string; replace?: boolean };
}

describe('Comms is retired (decision 9)', () => {
  it('is not in the nav registry, even for an operator holding everything on MSP', () => {
    expect(SECTION_BY_ID.comms).toBeUndefined();
    expect(visibleSections(everything, allCapabilities, SECTIONS, 'msp').map((s) => s.id)).not.toContain('comms');
  });

  it('mounts no Comms section route', () => {
    expect(appRoutes.map((r) => r.path)).not.toContain('/comms');
    // The only /comms routes left are the two redirects below.
    const comms = appRoutes.filter((r) => r.path?.startsWith('/comms'));
    expect(comms.map((r) => r.element.type)).toEqual([Navigate, Navigate]);
  });

  it('sends the old Maintenance URL to the one maintenance-window store (System → Alerts)', () => {
    expect(redirectOf('/comms/maintenance')).toEqual({ to: '/system/alerts', replace: true });
    // …and that target is a real rail entry, not a dead link.
    expect(SECTION_BY_ID.system.children?.map((c) => c.id)).toContain('alerts');
  });

  it('sends every other /comms URL (Announcements included) away rather than to a page', () => {
    expect(redirectOf('/comms/*')).toEqual({ to: '/overview', replace: true });
  });
});

describe('Support → Impersonation is removed (decision 10)', () => {
  it('is not a rail entry', () => {
    const support = SECTION_BY_ID.support;
    expect(support.children?.map((c) => c.id)).toEqual(['health', 'repair']);
    // No entry anywhere in the rail offers it. (`source` is exempt: it is the
    // Migration Ledger key naming the v1 pages a section superseded.)
    const shown = SECTIONS.flatMap((s) => [s, ...(s.children ?? [])]).map((e) =>
      [e.id, e.label, e.title, e.subtitle].join(' '),
    );
    expect(shown.filter((text) => /imperson/i.test(text))).toEqual([]);
  });

  it('has no route in the Support section', () => {
    const paths = allRoutes(SupportPage as () => unknown).map((r) => r.path);
    expect(paths).not.toContain('impersonation');
    expect(paths).toEqual(expect.arrayContaining(['health', 'repair']));
  });

  it('platform.impersonate alone no longer reveals the Support section', () => {
    const only = (p: string) => p === 'platform.impersonate';
    expect(visibleSections(only, allCapabilities, SECTIONS, 'msp').map((s) => s.id)).not.toContain('support');
  });
});
