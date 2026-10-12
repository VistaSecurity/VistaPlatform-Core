// @vitest-environment jsdom
//
// ⌘K palette, MOUNTED: it is a second door into the sections the rail shows, so
// it must apply the rail's permission gate (not only edition/licence), and a
// tenant hit must carry the tenant id so the Tenants page can open its drawer.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const state = vi.hoisted(() => ({ perms: new Set<string>() }));

vi.mock('@vistasecurity/primitives/platform-auth', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, usePlatformPermissions: () => ({ hasPermission: (p: string) => state.perms.has(p) }) };
});
vi.mock('../lib/edition', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/edition')>();
  return { ...actual, usePlatformEdition: () => ({ capabilities: { msp: true, billing: true }, license: 'msp', edition: 'msp', has: () => true, resolved: true }) };
});
vi.mock('../sections/tenants/queries', () => ({
  useTenants: () => ({ data: [{ id: 'tenant-1', name: 'Acme Corp', slug: 'acme' }] }),
  planLabel: () => 'Pro',
}));

import { CommandPalette } from './command-palette';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let root: Root | null = null;
let host: HTMLDivElement;

function Where() {
  const l = useLocation();
  return <div data-testid="where">{l.pathname + l.search}</div>;
}

function mount() {
  act(() => {
    root!.render(
      <MemoryRouter initialEntries={['/start']}>
        <CommandPalette open onClose={() => {}} />
        <Routes><Route path="*" element={<Where />} /></Routes>
      </MemoryRouter>,
    );
  });
}

beforeEach(() => {
  state.perms = new Set();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root?.unmount());
  host.remove();
  root = null;
});

const labels = () => Array.from(host.querySelectorAll('button')).map((b) => b.textContent ?? '');

describe('command palette', () => {
  it('offers only sections the operator holds the permission for', () => {
    state.perms = new Set(['platform.health']);
    mount();
    const all = labels().join('|');
    expect(all).toContain('Fleet');
    expect(all).not.toContain('Billing & Revenue');
    expect(all).not.toContain('Plans & Pricing');
  });

  it('opens the chosen tenant by id', () => {
    state.perms = new Set(['tenants.read']);
    mount();
    const hit = Array.from(host.querySelectorAll('button')).find((b) => b.textContent?.includes('Acme Corp'))!;
    act(() => hit.dispatchEvent(new MouseEvent('click', { bubbles: true })));
    expect(host.querySelector('[data-testid="where"]')!.textContent).toBe('/tenants?open=tenant-1');
  });
});
