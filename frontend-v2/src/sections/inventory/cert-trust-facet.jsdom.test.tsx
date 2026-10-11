// @vitest-environment jsdom
//
// Inventory → All assets → facet "Certificate trust" ( slice 3), through
// the REAL InventoryPage: the rail must ask the server for the `cert_trust`
// level, show its counts beside the values when it answers, show the values
// WITHOUT numbers (and without a failure note) while the server does not serve
// the level yet, and a tick must write the facet's query into the URL.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';
import { certTrustCounts } from './facet-rail';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn(), serveTrust: true }));
vi.mock('../../lib/clients', () => ({
  clients: new Proxy({}, {
    get: () => ({ GET: mocks.get, POST: vi.fn(), PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() }),
  }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { InventoryPage } from './inventory-page';

function LocationProbe() {
  const loc = useLocation();
  return <div data-testid="location">{loc.search}</div>;
}

const levelsAsked: string[] = [];
let host: HTMLDivElement; let root: Root;
beforeEach(() => {
  levelsAsked.length = 0;
  mocks.get.mockReset().mockImplementation(async (path: string, init?: { params?: { query?: { level?: string } } }) => {
    if (path === '/infrastructure-assets') return { data: { assets: [], pagination: { total: 0, page: 1, page_size: 50 } } };
    if (path === '/infrastructure-assets/facets') {
      const level = init?.params?.query?.level ?? '';
      levelsAsked.push(level);
      if (level === 'cert_trust') {
        return mocks.serveTrust
          ? { data: { level, buckets: [{ value: 'untrusted', count: 4 }, { value: 'public', count: 11 }] }, response: { ok: true, status: 200 } }
          : { error: { error: 'unknown level' }, response: { ok: false, status: 400 } };
      }
      return { data: { level, buckets: [] }, response: { ok: true, status: 200 } };
    }
    return { data: {} };
  });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

async function renderLens() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(['user-permissions'], []);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <PermissionProvider>
          <MemoryRouter initialEntries={['/inventory?lens=assets']}>
            <Routes><Route path="/inventory" element={<><InventoryPage /><LocationProbe /></>} /></Routes>
          </MemoryRouter>
        </PermissionProvider>
      </QueryClientProvider>,
    );
  });
  for (let i = 0; i < 6; i++) await act(async () => { await new Promise((r) => setTimeout(r, 10)); });
}

function section(): HTMLElement {
  const head = [...host.querySelectorAll('button')].find((b) => b.textContent?.includes('Certificate trust'));
  if (!head) throw new Error('no Certificate trust section in the rail');
  return head.parentElement as HTMLElement;
}
async function openSection() {
  await act(async () => { [...host.querySelectorAll('button')].find((b) => b.textContent?.includes('Certificate trust'))!.click(); });
}
const rowText = (label: string) => section().querySelector(`input[aria-label="${label}"]`)?.closest('label')?.textContent ?? '';

describe('Assets lens · Certificate trust facet', () => {
  it('asks for the cert_trust level and shows its counts, with an unlisted value as a real zero', async () => {
    mocks.serveTrust = true;
    await renderLens();
    expect(levelsAsked).toContain('cert_trust');
    await openSection();
    expect(rowText('Untrusted CA')).toContain('4');
    expect(rowText('Public CA')).toContain('11');
    expect(rowText('Distrusted CA')).toContain('0');
    expect(rowText('Not yet evaluated')).toContain('0');
  });

  it('renders the values without numbers — and without a failure note — while the server does not serve the level', async () => {
    mocks.serveTrust = false;
    await renderLens();
    await openSection();
    expect(rowText('Untrusted CA')).toBe('Untrusted CA');
    expect(section().querySelector('[data-testid="facet-level-failed"]')).toBeNull();
  });

  it('a tick writes the facet query into the URL', async () => {
    mocks.serveTrust = true;
    await renderLens();
    await openSection();
    await act(async () => { section().querySelector<HTMLInputElement>('input[aria-label="Untrusted CA"]')!.click(); });
    const search = new URLSearchParams(host.querySelector('[data-testid="location"]')!.textContent ?? '');
    expect(search.get('query')).toBe('cert:(trust_status:untrusted)');
  });
});

describe('certTrustCounts', () => {
  it('is null when the level did not answer, and fills absent values with zero when it did', () => {
    expect(certTrustCounts(null)).toBeNull();
    expect(certTrustCounts(undefined)).toBeNull();
    expect(certTrustCounts([{ value: 'self_signed', count: 2 }])).toMatchObject({ self_signed: 2, untrusted: 0, unevaluated: 0 });
  });
});
