// @vitest-environment jsdom
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { expect, it, vi } from 'vitest';
import { IdentityCoverage } from './observations-page';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));

it.each([
  ['disabled', 'Identity assessment is not activated.'],
  ['observe', 'Identity assessment is observing evidence'],
  ['paused', 'Identity assessment and enrichment are paused.'],
  ['enforce', null],
  [undefined, null],
])('explains the actual identity policy: %s', async (mode, note) => {
  api.GET.mockResolvedValue({ response: { ok: true }, data: { established: 2, operator_confirmed: 0, legacy: 25, unresolved: 4, conflicted: 3, provisional: 6, admission_mode: mode } });
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const host = document.createElement('div'); const root = createRoot(host);
  try {
    await act(async () => { root.render(<MemoryRouter><QueryClientProvider client={cache}><IdentityCoverage /></QueryClientProvider></MemoryRouter>); });
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 10)); });
    expect(host.textContent).toContain('25 not evaluated');
    expect(host.textContent).toContain('4 unresolved observations');
    expect(host.textContent).toContain('3 assets with identity conflicts');
    // Provisional items are NOT part of "Monitored inventory" — they are pending
    // approval by construction ( D1) — so they get their own entry rather
    // than inflating the three counts beside the heading.
    expect(host.textContent).toContain('6 provisional items');
    const provisionalHref = [...host.querySelectorAll('a')].find((a) => a.textContent === '6 provisional items')?.getAttribute('href') ?? '';
    expect(decodeURIComponent(provisionalHref)).toContain('identity_status:provisional');
    // The list endpoint defaults to monitoring-only, and a provisional item is
    // pending approval: without a status term the count would link to nothing.
    expect(decodeURIComponent(provisionalHref)).toContain('status:pending_approval');
    expect(host.textContent).not.toContain('legacy');
    if (note) expect(host.textContent).toContain(note);
    else expect(host.textContent).not.toContain('Identity assessment');
    if (mode === 'disabled') expect(host.querySelector('a[href="/settings/sensor-config"]')).not.toBeNull();
  } finally { act(() => root.unmount()); cache.clear(); }
});
