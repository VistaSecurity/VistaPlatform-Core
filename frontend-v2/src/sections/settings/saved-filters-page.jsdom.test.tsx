// @vitest-environment jsdom
//
// Settings -> Saved Filters (DCIM BUILD_PLAN row 5.4): the five states, and the
// rule that a shared filter's controls are locked for someone who cannot manage
// shared filters while a personal filter's are not.
// Mutation: change `!f.shared || canShare` to `true` -> the locked test goes red.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn(), del: vi.fn() }));
vi.mock('../../lib/clients', () => ({
  clients: new Proxy({}, { get: () => ({ GET: mocks.get, POST: vi.fn(), PUT: mocks.put, PATCH: vi.fn(), DELETE: mocks.del }) }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { SavedFiltersPage } from './saved-filters-page';
import { SETTINGS_NAV } from './nav';

const meta = SETTINGS_NAV.flatMap((s) => s.items).find((i) => i.key === 'saved-filters')!;
const f = (over: Record<string, unknown>) => ({
  id: 'id-' + String(over.name), slug: 's', description: null, object_kinds: ['asset'], user_id: null, shared: false, weight: 100,
  created_at: '2026-10-16T00:00:00Z', updated_at: '2026-10-16T00:00:00Z', ...over,
});
let host: HTMLDivElement;
let root: Root;
beforeEach(() => { host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host); mocks.put.mockReset(); mocks.del.mockReset(); });
afterEach(() => { act(() => root.unmount()); host.remove(); });

async function render(get: () => unknown) {
  mocks.get.mockReset().mockImplementation(async () => get());
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => { root.render(<QueryClientProvider client={qc}><SavedFiltersPage meta={meta} /></QueryClientProvider>); });
  // Let the list query settle (the pending case never does, and has its own text).
  await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
}
const text = () => host.textContent ?? '';

describe('Settings -> Saved Filters', () => {
  it('is in the Settings nav', () => {
    expect(meta.built).toBe(true);
  });
  it('loading', async () => {
    await render(() => new Promise(() => {}));
    expect(text()).toContain('Loading saved filters');
  });
  it('error', async () => {
    await render(() => ({ data: undefined, error: { error: { message: 'boom' } } }));
    expect(text()).toContain("Couldn't load saved filters");
    expect(text()).toContain('boom');
  });
  it('empty', async () => {
    await render(() => ({ data: { data: [], can_share: false } }));
    expect(text()).toContain('No saved filters');
  });
  it('lists filters with their scope and locks a shared one the caller cannot manage', async () => {
    await render(() => ({ data: { data: [f({ name: 'Prod web', query: 'hostname:web*', shared: true }), f({ name: 'Mine', query: 'risk >= high' })], can_share: false } }));
    expect(text()).toContain('Prod web');
    expect(text()).toContain('Shared');
    expect(text()).toContain('Personal');
    expect(host.querySelectorAll('[data-testid="sf-locked"]')).toHaveLength(1);
    expect(host.querySelector('[aria-label="Edit Mine"]')).not.toBeNull();
    expect(host.querySelector('[aria-label="Edit Prod web"]')).toBeNull();
  });
  it('unlocks the shared one for someone who can manage shared filters', async () => {
    await render(() => ({ data: { data: [f({ name: 'Prod web', query: 'hostname:web*', shared: true })], can_share: true } }));
    expect(host.querySelector('[aria-label="Edit Prod web"]')).not.toBeNull();
    expect(host.querySelector('[data-testid="sf-locked"]')).toBeNull();
  });
  it('delete confirms, then calls DELETE', async () => {
    mocks.del.mockResolvedValue({ error: undefined });
    await render(() => ({ data: { data: [f({ name: 'Mine', query: 'risk >= high' })], can_share: false } }));
    await act(async () => { (host.querySelector('[aria-label="Delete Mine"]') as HTMLButtonElement).click(); });
    const confirm = [...document.body.querySelectorAll('button')].find((b) => b.textContent === 'Delete filter')!;
    await act(async () => { confirm.click(); });
    expect(mocks.del).toHaveBeenCalledWith('/dcim/saved-filters/{id}', { params: { path: { id: 'id-Mine' } } });
  });
});
