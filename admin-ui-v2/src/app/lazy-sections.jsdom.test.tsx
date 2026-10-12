// @vitest-environment jsdom
//
// Route-level code splitting: App.tsx must not import a section's module until
// that section's route is visited, so the first paint ships the shell rather
// than the whole console. Section modules are mocked with an evaluation
// counter; the gates and the shell are replaced by pass-throughs (the real
// App route table is what is under test). Making a section import eager again
// evaluates its module at App import time and turns the "not evaluated" case
// red.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { Outlet, MemoryRouter } from 'react-router';
import { afterEach, describe, expect, it, vi } from 'vitest';

const evaluated = vi.hoisted(() => ({ overview: 0, tenants: 0 }));

vi.mock('./require-auth', () => ({ RequireAuth: () => <Outlet /> }));
vi.mock('./app-shell', () => ({
  AppShell: () => (
    <div>
      <nav data-testid="shell">shell</nav>
      <Outlet />
    </div>
  ),
}));
vi.mock('./platform-branding', () => ({ PlatformBrandingEffects: () => null }));
vi.mock('./require-permission', () => ({
  RequirePlatformPermission: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));
vi.mock('./require-edition', () => ({
  RequirePlatformEdition: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  RequireLicenseEdition: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));
vi.mock('../sections/overview/overview-page', () => {
  evaluated.overview += 1;
  return { OverviewPage: () => <div>overview body</div> };
});
vi.mock('../sections/tenants/tenants-page', () => {
  evaluated.tenants += 1;
  return { TenantsPage: () => <div>tenants body</div> };
});

import App from '../App';

let root: Root | undefined;
let host: HTMLElement | undefined;

async function mountAt(url: string) {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  await act(async () => {
    root!.render(
      <MemoryRouter initialEntries={[url]}>
        <App />
      </MemoryRouter>,
    );
  });
}

async function until(pred: () => boolean) {
  for (let i = 0; i < 50 && !pred(); i++) {
    await act(async () => {
      await new Promise((r) => setTimeout(r, 10));
    });
  }
}

afterEach(() => {
  act(() => root?.unmount());
  host?.remove();
});

describe('admin console route-level code splitting', () => {
  it('importing App evaluates no section module', () => {
    expect(evaluated).toEqual({ overview: 0, tenants: 0 });
  });

  it('the initial route loads only its own section; the shell stays mounted', async () => {
    await mountAt('/overview');
    await until(() => (host?.textContent ?? '').includes('overview body'));
    expect(host?.textContent).toContain('overview body');
    expect(host?.querySelector('[data-testid="shell"]')).not.toBeNull();
    expect(evaluated.overview).toBe(1);
    expect(evaluated.tenants).toBe(0);
  });

  it('a section is evaluated when its route is visited', async () => {
    await mountAt('/tenants');
    await until(() => (host?.textContent ?? '').includes('tenants body'));
    expect(host?.textContent).toContain('tenants body');
    expect(evaluated.tenants).toBe(1);
  });

  it('the bare index still redirects to Mission Control', async () => {
    await mountAt('/');
    await until(() => (host?.textContent ?? '').includes('overview body'));
    expect(host?.textContent).toContain('overview body');
  });
});
