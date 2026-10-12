// @vitest-environment jsdom
//
// Narrowing the Findings filter forms groups that did not exist a moment ago;
// those groups must open. The open-set effect used to re-run only on the
// fetches' first success (and the lens), so on the By Asset lens, where the
// first five bands start open, a filter that dropped one asset let a sixth
// asset into the top five COLLAPSED, under a count that said it had rows.
//
// MUTATION (recorded in the PR): put the effect back to
// `setOpen(new Set(groupKeys))` with the deps
// `[lens, risksQ.isSuccess, batchQ.isSuccess, listQ.isSuccess, producerF]`:
// the test fails, because asset 6's band is collapsed after the filter and its
// row is never rendered.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api, compliance: api } }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));
vi.mock('@vistasecurity/primitives/auth', () => ({ useAuth: () => ({ user: { id: 'u1' } }) }));
vi.mock('@vistasecurity/primitives/rbac', () => ({
  PermissionGate: ({ children }: { children: React.ReactNode }) => children,
  TENANT_PERMISSIONS: new Proxy({}, { get: () => new Proxy({}, { get: (_t, k) => String(k) }) }),
  usePermissions: () => ({ can: () => true }),
}));

const { FindingsPage } = await import('./findings-page');

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let host: HTMLDivElement; let root: Root; let qc: QueryClient;
beforeEach(() => {
  api.GET.mockReset();
  qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); qc.clear(); });

// Asset i has (7 - i) risks, so the bands sort a1 .. a6 and the first five open.
function risks() {
  const out: Record<string, unknown>[] = [];
  for (let i = 1; i <= 6; i++) {
    for (let n = 0; n < 7 - i; n++) {
      out.push({
        id: `r${i}-${n}`, asset_id: `asset-${i}`, asset_hostname: `host-${i}`, severity: 'high',
        issue_type: 'weak_cipher', category: 'protocol', description: 'd',
        protocol: `PROTO-A${i}`, current_value: i === 1 ? 'alpha' : 'beta', detected_at: '2026-01-01',
      });
    }
  }
  return out;
}

describe('Findings groups on a narrowed filter', () => {
  it('opens the band a narrowing filter pulls into the first five', async () => {
    api.GET.mockImplementation(async (path: string) => {
      if (path === '/crypto-risks') {
        const r = risks();
        return { data: { risks: r, total: r.length, total_pages: 1 } };
      }
      return { data: {} };
    });
    await act(async () => {
      root.render(
        <MemoryRouter initialEntries={['/findings?lens=asset']}>
          <QueryClientProvider client={qc}><FindingsPage /></QueryClientProvider>
        </MemoryRouter>,
      );
    });
    await act(async () => { await new Promise((r) => setTimeout(r, 30)); });
    expect(host.textContent).toContain('PROTO-A5');
    expect(host.textContent).not.toContain('PROTO-A6');

    const input = host.querySelector('input[placeholder="Filter findings…"]') as HTMLInputElement;
    const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
    await act(async () => {
      setValue.call(input, 'beta');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await act(async () => { await new Promise((r) => setTimeout(r, 30)); });

    expect(host.textContent).not.toContain('PROTO-A1');
    expect(host.textContent).toContain('PROTO-A6');
  });
});
