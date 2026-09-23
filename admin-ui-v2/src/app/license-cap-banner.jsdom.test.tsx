// @vitest-environment jsdom
//
// The shell's licensed-tenant banner, MOUNTED — and mounted inside the REAL
// AppShell, so deleting <LicenseCapBanner /> from the shell turns this red, not
// just a change to the component.
//
// Screen states (spec §1 "Soft-cap banner"): hidden while loading, on error,
// under the licence and when uncapped; shown in grace (days left) and after
// grace (new tenants blocked).
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter, Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { LicenseCap } from '../lib/license-cap';

type CapQuery = { data?: LicenseCap; isLoading: boolean; isError: boolean };
const state = vi.hoisted(() => ({ cap: { isLoading: true, isError: false } as CapQuery }));

vi.mock('../lib/license-cap', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/license-cap')>();
  return { ...actual, useLicenseCap: () => state.cap };
});

// The shell's other data-dependent children are stubbed: this test is about
// the banner's placement and states, not theirs.
vi.mock('@vistasecurity/primitives/platform-auth', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    usePlatformAuth: () => ({ user: { first_name: 'Op', last_name: 'Erator', email: 'op@example.test', role: 'platform_admin' }, logout: vi.fn() }),
    usePlatformPermissions: () => ({ hasPermission: () => true }),
  };
});
vi.mock('../lib/edition', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/edition')>();
  return { ...actual, usePlatformEdition: () => ({ capabilities: { msp: true, billing: true }, edition: 'enterprise', has: () => true, resolved: true }) };
});
vi.mock('./platform-branding', () => ({ usePlatformBranding: () => ({ name: 'Vista', logoUrl: null }), BrandLogo: () => null }));
vi.mock('./command-palette', () => ({ CommandPalette: () => null }));
vi.mock('./tenant-switcher', () => ({ TenantSwitcher: () => null, ScopeBar: () => null }));
vi.mock('./notification-bell', () => ({ NotificationBell: () => null }));

import { AppShell } from './app-shell';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let root: Root | null = null;
let host: HTMLDivElement;

function mount() {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => {
    root!.render(
      <MemoryRouter initialEntries={['/overview']}>
        <Routes>
          <Route element={<AppShell />}>
            <Route path="/overview" element={<div>page body</div>} />
          </Route>
        </Routes>
      </MemoryRouter>,
    );
  });
}

const banner = () => host.querySelector('[data-testid="license-cap-banner"]');

const cap = (over: Partial<LicenseCap>): LicenseCap => ({
  edition: 'msp', licensed: 10, current: 4, operator: 1,
  grace_started_at: null, grace_days: 30, grace_ends_at: null, state: 'under',
  ...over,
});

beforeEach(() => {
  state.cap = { isLoading: true, isError: false };
});
afterEach(() => {
  act(() => root?.unmount());
  root = null;
  host.remove();
});

describe('licensed-tenant banner in the app shell', () => {
  it('renders the page with no banner while loading', () => {
    mount();
    expect(host.textContent).toContain('page body');
    expect(banner()).toBeNull();
  });

  it('stays hidden when the read failed', () => {
    state.cap = { isLoading: false, isError: true };
    mount();
    expect(banner()).toBeNull();
  });

  it('stays hidden under the licence and when uncapped', () => {
    state.cap = { isLoading: false, isError: false, data: cap({ current: 10, state: 'under' }) };
    mount();
    expect(banner()).toBeNull();
    act(() => root?.unmount());
    host.remove();

    state.cap = { isLoading: false, isError: false, data: cap({ edition: 'enterprise', licensed: null, grace_days: null, state: 'uncapped' }) };
    mount();
    expect(banner()).toBeNull();
  });

  it('warns with the grace days left', () => {
    const ends = new Date(Date.now() + 5 * 24 * 60 * 60 * 1000 - 60 * 1000).toISOString();
    state.cap = { isLoading: false, isError: false, data: cap({ current: 11, state: 'grace', grace_ends_at: ends }) };
    mount();
    expect(banner()?.getAttribute('role')).toBe('status');
    expect(banner()?.textContent).toContain('11 of 10 licensed tenants — 5 days of grace left');
  });

  it('states that new tenants are blocked after grace', () => {
    state.cap = { isLoading: false, isError: false, data: cap({ current: 12, state: 'blocked', grace_ends_at: '2026-01-01T00:00:00Z' }) };
    mount();
    expect(banner()?.getAttribute('role')).toBe('alert');
    expect(banner()?.textContent).toContain('grace period ended, new tenants are blocked');
    expect(host.textContent).toContain('page body'); // the page still renders
  });
});
