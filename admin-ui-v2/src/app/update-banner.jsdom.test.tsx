// @vitest-environment jsdom
//
// The shell's update-available banner, MOUNTED inside the REAL AppShell so
// deleting <UpdateBanner /> from the shell turns this red, not just a change to
// the component. Screen states (spec §1): hidden when current, while loading,
// on error and when the Maintenance section is absent (status 404); shown with
// the version and two links; dismissed per version, back for a newer one.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { UpdateStatus } from '../sections/maintenance/maintenance-queries';

type UpdateQuery = { data?: UpdateStatus; isLoading: boolean; isError: boolean };
const state = vi.hoisted(() => {
  const initial: { update: UpdateQuery; availability: 'pending' | 'available' | 'absent'; canRead: boolean; enabledArg: boolean | undefined } = {
    update: { isLoading: true, isError: false },
    availability: 'available',
    canRead: true,
    enabledArg: undefined,
  };
  return initial;
});

vi.mock('../sections/maintenance/maintenance-queries', () => ({
  useMaintenanceAvailability: () => state.availability,
  useUpdateStatus: (opts: { enabled?: boolean } = {}) => {
    state.enabledArg = opts.enabled;
    return state.update;
  },
}));
vi.mock('../lib/license-cap', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/license-cap')>();
  return { ...actual, useLicenseCap: () => ({ data: undefined, isLoading: false, isError: false }) };
});
vi.mock('@vistasecurity/primitives/platform-auth', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    usePlatformAuth: () => ({ user: { first_name: 'Op', last_name: 'Erator', email: 'op@example.test', role: 'platform_admin' }, logout: vi.fn() }),
    usePlatformPermissions: () => ({ hasPermission: () => state.canRead }),
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
import { UPDATE_BANNER_DISMISSED_KEY } from './update-banner';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let root: Root | null = null;
let host: HTMLDivElement;
const visited = vi.fn<(path: string) => void>();

function Where() {
  visited(useLocation().pathname);
  return null;
}

function mount() {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => {
    root!.render(
      <MemoryRouter initialEntries={['/overview']}>
        <Where />
        <Routes>
          <Route element={<AppShell />}>
            <Route path="/overview" element={<div>page body</div>} />
            <Route path="/maintenance/about" element={<div>about page</div>} />
          </Route>
        </Routes>
      </MemoryRouter>,
    );
  });
}

const banner = () => host.querySelector('[data-testid="update-banner"]');
const available = (version: string, over: Partial<UpdateStatus> = {}): UpdateStatus => ({
  checked_at: '2026-10-14T00:00:00Z',
  source: 'oci://ghcr.io/vistasecurity/vistaplatform',
  current_version: '4.5.0',
  latest_version: version,
  notes_url: `https://github.com/VistaSecurity/VistaPlatform-Core/releases/tag/v${version}`,
  error: null,
  prereleases_seen: [],
  update_available: true,
  check_enabled: true,
  ...over,
});

beforeEach(() => {
  state.update = { isLoading: true, isError: false };
  state.availability = 'available';
  state.canRead = true;
  state.enabledArg = undefined;
  window.localStorage.clear();
});
afterEach(() => {
  act(() => root?.unmount());
  root = null;
  host.remove();
  vi.restoreAllMocks();
});

describe('update banner in the app shell', () => {
  it('is hidden while loading, and the page still renders', () => {
    mount();
    expect(host.textContent).toContain('page body');
    expect(banner()).toBeNull();
  });

  it('is hidden when the install is current', () => {
    state.update = { isLoading: false, isError: false, data: available('4.5.0', { update_available: false, latest_version: null, notes_url: null }) };
    mount();
    expect(banner()).toBeNull();
  });

  it('is hidden when the status read failed', () => {
    state.update = { isLoading: false, isError: true };
    mount();
    expect(banner()).toBeNull();
  });

  it('is hidden when the Maintenance section is absent (status 404) or still pending', () => {
    state.update = { isLoading: false, isError: false, data: available('4.6.0') };
    for (const availability of ['absent', 'pending'] as const) {
      state.availability = availability;
      mount();
      expect(banner(), availability).toBeNull();
      act(() => root?.unmount());
      host.remove();
    }
  });

  it('does not even ask for the status without platform.health, and shows nothing', () => {
    state.canRead = false;
    state.update = { isLoading: false, isError: false, data: available('4.6.0') };
    mount();
    expect(state.enabledArg).toBe(false);
    expect(banner()).toBeNull();
  });

  it('shows the version, a What’s new link in a new tab, and a See details link', () => {
    state.update = { isLoading: false, isError: false, data: available('4.6.0') };
    mount();
    expect(banner()?.textContent).toContain('Vista Platform 4.6.0 is available');
    const notes = host.querySelector('[data-testid="update-banner-notes"]') as HTMLAnchorElement;
    expect(notes.getAttribute('href')).toBe('https://github.com/VistaSecurity/VistaPlatform-Core/releases/tag/v4.6.0');
    expect(notes.getAttribute('target')).toBe('_blank');
    expect(notes.getAttribute('rel')).toContain('noopener');
    expect(state.enabledArg).toBe(true);
  });

  it('See details navigates to Maintenance → About & Updates', () => {
    state.update = { isLoading: false, isError: false, data: available('4.6.0') };
    mount();
    act(() => (host.querySelector('[data-testid="update-banner-details"]') as HTMLAnchorElement).click());
    expect(visited).toHaveBeenLastCalledWith('/maintenance/about');
  });

  it('omits What’s new when there is no notes URL', () => {
    state.update = { isLoading: false, isError: false, data: available('4.6.0', { notes_url: null }) };
    mount();
    expect(banner()).not.toBeNull();
    expect(host.querySelector('[data-testid="update-banner-notes"]')).toBeNull();
  });

  it('dismiss hides it and remembers THIS version', () => {
    state.update = { isLoading: false, isError: false, data: available('4.6.0') };
    mount();
    act(() => (host.querySelector('[data-testid="update-banner-dismiss"]') as HTMLButtonElement).click());
    expect(banner()).toBeNull();
    expect(window.localStorage.getItem(UPDATE_BANNER_DISMISSED_KEY)).toBe('4.6.0');
    expect(UPDATE_BANNER_DISMISSED_KEY).toBe('maintenance.update-banner.dismissed');
    // A fresh page view of the same version stays dismissed.
    act(() => root?.unmount());
    host.remove();
    mount();
    expect(banner()).toBeNull();
  });

  it('reappears for a newer version than the one dismissed', () => {
    window.localStorage.setItem(UPDATE_BANNER_DISMISSED_KEY, '4.6.0');
    state.update = { isLoading: false, isError: false, data: available('4.6.1') };
    mount();
    expect(banner()?.textContent).toContain('Vista Platform 4.6.1 is available');
  });

  it('works when localStorage throws: shows, dismisses for the page view, never crashes', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('blocked'); });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('blocked'); });
    state.update = { isLoading: false, isError: false, data: available('4.6.0') };
    mount();
    expect(banner()).not.toBeNull();
    act(() => (host.querySelector('[data-testid="update-banner-dismiss"]') as HTMLButtonElement).click());
    expect(banner()).toBeNull();
  });

  it('uses the product name, never the squashed identifier', () => {
    state.update = { isLoading: false, isError: false, data: available('4.6.0') };
    mount();
    expect(banner()?.textContent).not.toMatch(/VistaPlatform/);
  });
});
