// @vitest-environment jsdom
//
// The Settings / My Profile rail drawer, MOUNTED.
//
// This layer used to be a full swap: `Sidebar` returned `<SettingsRail/>` for
// any /settings or /profile route, which took the brand block and the profile
// chip off screen with it — the one control telling you who you are vanished
// exactly when you went to manage who you are. It is now a drawer that covers
// the nav list only.
//
// What replaced the swap is state, not markup: an open layer can come from the
// route (a bookmark to /settings/members) or from the toggle (which opens the
// nav WITHOUT navigating), closing returns you to the console page you came
// from, and a hand-opened layer expires when you land somewhere else. None of
// that lives in a helper that could be unit-tested — it is the component. So
// this drives the real AppShell through a real router and asserts on the real
// pathname, per the repo's "test the WIRING, not just the helper" rule: delete
// any one of those rules and something here goes red.
//
// Follows `command-palette.jsdom.test.tsx`: jsdom + React's own `act`, no
// testing-library, and the docblock above opts this file in so the node-env
// suites are untouched.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Routes, Route, useLocation } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Everything the shell reads that is not the drawer. Each is stubbed at the
// module boundary: what is under test is the rail's state machine, and a real
// fetch would make these assertions depend on unrelated endpoint shapes.
vi.mock('@vistasecurity/primitives/auth', () => ({
  useAuth: () => ({
    user: { first_name: 'Dana', last_name: 'Reyes', email: 'dana@example.test', role: 'tenant_admin' },
    logout: vi.fn(async () => undefined),
  }),
}));
vi.mock('@vistasecurity/primitives/rbac', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@vistasecurity/primitives/rbac')>()),
  usePermissions: () => ({ hasAnyPermission: () => false }),
}));
vi.mock('@vistasecurity/primitives/features', () => ({ useFeatures: () => ({ features: {} }) }));
vi.mock('../sections/onboarding/queries', () => ({ useOnboardingStatus: () => ({ data: undefined }) }));
vi.mock('../sections/onboarding/onboarding-nudge', () => ({ OnboardingNudge: () => null }));
vi.mock('./notification-bell', () => ({ NotificationBell: () => null }));
vi.mock('./command-palette', () => ({ CommandPalette: () => null }));
vi.mock('./platform-branding', () => ({
  usePlatformBranding: () => ({ name: 'Vista', logoUrl: null }),
  BrandLogo: () => null,
}));

import { AppShell } from './app-shell';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let container: HTMLDivElement;
let root: Root;

function Probe() {
  const { pathname } = useLocation();
  return <span id="loc">{pathname}</span>;
}

async function mount(at: string): Promise<void> {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={[at]}>
          <Probe />
          <Routes>
            <Route element={<AppShell />}>
              <Route path="/dashboard" element={<div>console: dashboard</div>} />
              <Route path="/inventory" element={<div>console: inventory</div>} />
              <Route path="/about" element={<div>console: about</div>} />
              <Route path="/settings" element={<div>settings landing</div>} />
              <Route path="/settings/:page" element={<div>settings page</div>} />
              <Route path="/profile" element={<div>profile landing</div>} />
              <Route path="/profile/:page" element={<div>profile page</div>} />
            </Route>
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
  });
}

afterEach(() => {
  act(() => root.unmount());
  container.remove();
});
beforeEach(() => { vi.clearAllMocks(); });

const at = (): string => container.querySelector('#loc')?.textContent ?? '';
const drawer = (): HTMLElement => {
  const el = container.querySelector('.rail-drawer');
  if (!el) throw new Error('the rail rendered no drawer');
  return el as HTMLElement;
};
// The drawer stays MOUNTED when closed (it slides, so it has to animate both
// ways) — "open" is the class, never mere presence in the DOM. A test that
// asserted on presence would pass against a drawer that never opens.
const isOpen = (): boolean => drawer().classList.contains('open');
/** The drawer's own title — "Settings" or "My Profile". */
const drawerHeading = (): string => {
  const el = [...drawer().querySelectorAll('span')].find((s) => ['Settings', 'My Profile'].includes((s.textContent ?? '').trim()));
  return (el?.textContent ?? '').trim();
};

// Both the Settings toggle and the profile chip are disclosures now, so they
// are told apart by their label rather than by `aria-expanded` alone.
const disclosures = (): HTMLButtonElement[] =>
  [...container.querySelectorAll('button[aria-expanded]')] as HTMLButtonElement[];

function settingsToggle(): HTMLButtonElement {
  const el = disclosures().find((b) => (b.textContent ?? '').includes('Settings'));
  if (!el) throw new Error('the rail rendered no Settings toggle');
  return el;
}
function profileChip(): HTMLButtonElement {
  const el = disclosures().find((b) => (b.textContent ?? '').includes('Dana Reyes'));
  if (!el) throw new Error('the rail rendered no profile chip');
  return el;
}
function link(href: string): HTMLAnchorElement {
  const el = container.querySelector(`a[href="${href}"]`);
  if (!el) throw new Error(`no link to ${href}`);
  return el as HTMLAnchorElement;
}
async function click(el: Element): Promise<void> {
  await act(async () => {
    el.dispatchEvent(new window.MouseEvent('click', { bubbles: true, cancelable: true, button: 0 }));
  });
}
async function press(key: string): Promise<void> {
  await act(async () => { window.dispatchEvent(new window.KeyboardEvent('keydown', { key, bubbles: true })); });
}
/** The profile chip renders the signed-in name; it is the thing the old swap
 *  hid, so "is it still on screen" is the regression this change exists for. */
const profileChipVisible = (): boolean => (container.textContent ?? '').includes('Dana Reyes');

/** Open the profile chip's popover and click one of its entries. The chip stays
 *  reachable while the drawer is up, which is exactly what makes it usable as
 *  the "navigate away with the layer open" path below. */
async function chipMenu(label: string): Promise<void> {
  await click(profileChip());
  const entry = [...container.querySelectorAll('button')].find((b) => (b.textContent ?? '').trim() === label);
  if (!entry) throw new Error(`no "${label}" entry in the chip menu`);
  await click(entry);
}

describe('rail drawer — the Settings toggle', () => {
  it('opens the layer without navigating anywhere', async () => {
    await mount('/dashboard');
    expect(isOpen()).toBe(false);

    await click(settingsToggle());

    expect(isOpen()).toBe(true);
    // Asking for the nav must not also drop you on a page you did not pick.
    expect(at()).toBe('/dashboard');
    expect(settingsToggle().getAttribute('aria-expanded')).toBe('true');
  });

  it('closes the layer again from the same button, still without navigating', async () => {
    await mount('/dashboard');
    await click(settingsToggle());
    await click(settingsToggle());

    expect(isOpen()).toBe(false);
    expect(at()).toBe('/dashboard');
  });

  it('keeps the profile chip on screen while the layer is open', async () => {
    await mount('/dashboard');
    expect(profileChipVisible()).toBe(true);

    await click(settingsToggle());

    // The whole point of the drawer over the swap.
    expect(isOpen()).toBe(true);
    expect(profileChipVisible()).toBe(true);
    expect(settingsToggle()).toBeTruthy();
  });

  it('stays open across a jump between settings pages', async () => {
    await mount('/dashboard');
    await click(settingsToggle());
    await click(link('/settings/members'));

    expect(at()).toBe('/settings/members');
    expect(isOpen()).toBe(true);
    expect(profileChipVisible()).toBe(true);
  });
});

describe('rail drawer — closing returns you where you were', () => {
  it('goes back to the console page the layer was opened from', async () => {
    await mount('/inventory');
    await click(settingsToggle());
    await click(link('/settings/members'));
    expect(at()).toBe('/settings/members');

    await click(settingsToggle());

    // Not /dashboard, and not left stranded on the settings page.
    expect(at()).toBe('/inventory');
    expect(isOpen()).toBe(false);
  });

  it('falls back to the dashboard when the layer was deep-linked into', async () => {
    await mount('/settings/members');
    // A bookmark lands with the layer already open — the route opens it.
    expect(isOpen()).toBe(true);

    await click(settingsToggle());

    expect(at()).toBe('/dashboard');
    expect(isOpen()).toBe(false);
  });

  it('closes on Escape', async () => {
    await mount('/dashboard');
    await click(settingsToggle());
    expect(isOpen()).toBe(true);

    await press('Escape');

    expect(isOpen()).toBe(false);
  });
});

describe('rail drawer — a hand-opened layer expires on navigation', () => {
  it('closes when you land on a different console page', async () => {
    await mount('/dashboard');
    await click(settingsToggle());
    expect(isOpen()).toBe(true);

    // The chip menu's About entry — reachable precisely because the drawer
    // leaves the chip on screen, and the concrete case that used to strand the
    // settings nav over a console page.
    await chipMenu('About');

    expect(at()).toBe('/about');
    // Otherwise the settings nav sits over a console page.
    expect(isOpen()).toBe(false);
  });
});

describe('rail drawer — the profile chip is the profile layer\'s toggle', () => {
  // The chip's own trigger ("My Profile") lives in a popover that closes the
  // instant you use it, so without this the profile layer had no toggle at all
  // and behaved differently from the Settings layer right above it.
  it('closes the layer it opened, from the chip itself', async () => {
    await mount('/dashboard');
    await chipMenu('My Profile');
    expect(isOpen()).toBe(true);

    await click(profileChip());

    expect(isOpen()).toBe(false);
    expect(at()).toBe('/dashboard');
  });

  it('returns you where you were when closed from a profile page', async () => {
    await mount('/inventory');
    await chipMenu('My Profile');
    await click(link('/profile/personal'));
    expect(at()).toBe('/profile/personal');

    await click(profileChip());

    expect(at()).toBe('/inventory');
    expect(isOpen()).toBe(false);
  });

  it('marks itself expanded while the layer is up', async () => {
    await mount('/dashboard');
    expect(profileChip().getAttribute('aria-expanded')).toBe('false');

    await chipMenu('My Profile');

    expect(profileChip().getAttribute('aria-expanded')).toBe('true');
  });

  // The drawer slides out over 220ms, so it is still on screen for a beat after
  // `open` goes false. If its content reverted to the default layer on close,
  // you would watch the profile nav turn into the settings nav on the way down.
  it('keeps showing the layer it is closing while it slides out', async () => {
    await mount('/dashboard');
    await chipMenu('My Profile');
    expect(drawerHeading()).toBe('My Profile');

    await click(profileChip());

    expect(isOpen()).toBe(false);
    expect(drawerHeading()).toBe('My Profile');
  });

  // Same rule for a layer the ROUTE opened. Leaving a deep-linked /profile page
  // by any route that is not the chip — browser Back, a command-palette jump —
  // slides the drawer out, and it must not turn into the settings nav on the way.
  it('keeps a deep-linked profile layer on screen when you navigate away from it', async () => {
    await mount('/profile/personal');
    expect(isOpen()).toBe(true);
    expect(drawerHeading()).toBe('My Profile');

    await click(link('/dashboard'));

    expect(at()).toBe('/dashboard');
    expect(isOpen()).toBe(false);
    expect(drawerHeading()).toBe('My Profile');
  });

  it('still opens its MENU while the settings layer is up, rather than closing anything', async () => {
    await mount('/dashboard');
    await click(settingsToggle());
    expect(isOpen()).toBe(true);

    await click(profileChip());

    // The chip only doubles as a close control for its OWN layer; with Settings
    // up it stays a menu, which is how you reach My Profile from there at all.
    expect(isOpen()).toBe(true);
    expect([...container.querySelectorAll('button')].some((b) => (b.textContent ?? '').trim() === 'Sign out')).toBe(true);
  });
});

describe('rail drawer — My Profile shares the mechanism', () => {
  it('opens the profile layer from the chip menu without navigating', async () => {
    await mount('/dashboard');
    await chipMenu('My Profile');

    expect(isOpen()).toBe(true);
    expect(at()).toBe('/dashboard');
    // The profile nav, not the settings nav — and the Settings toggle is NOT
    // the one lit, since a different layer is up.
    expect(link('/profile/personal')).toBeTruthy();
    expect(settingsToggle().getAttribute('aria-expanded')).toBe('false');
  });

  it('lands on the profile when switched to from a settings page', async () => {
    await mount('/settings/members');
    await chipMenu('My Profile');

    // Switching layers while the OTHER layer's page is on screen would leave
    // the nav and the content disagreeing.
    expect(at()).toBe('/profile');
    expect(isOpen()).toBe(true);
  });
});
