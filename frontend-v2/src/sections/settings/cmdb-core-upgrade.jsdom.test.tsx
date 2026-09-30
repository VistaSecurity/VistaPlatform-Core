// @vitest-environment jsdom
//
// Settings · Integrations, as a CORE install renders it (platform ADR-0002 M3).
//
// CMDB / ITSM sync runs in an Enterprise-only service, which a Core install
// does not have: there is no CMDB route to ask, and the Core tree carries
// neither the section that would ask nor the client it would ask with. What a
// Core tenant must still see is the shape of the product — the CMDB section
// with its upgrade card, and the CMDB platforms in the connector catalogue
// marked "Included in Enterprise" — without a single failed request.
//
// The Enterprise slots are emptied here exactly as the public-tree export
// empties them (enterprise-slots.ts's fenced lines stripped), and the clients
// module offers no integration client, as in Core. MUTATION: render the CMDB
// section unconditionally, drop the CmdbUpgradeSection fallback, or call the
// profiles endpoint from the page again, and this goes red.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const api = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn(), POST: vi.fn(), DELETE: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api, notifications: api } }));
vi.mock('./enterprise-slots', () => ({ enterpriseSettings: {} }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));
vi.mock('@vistasecurity/primitives/features', async (orig) => ({
  ...(await orig<typeof import('@vistasecurity/primitives/features')>()),
  // Core never grants a paid capability.
  useFeature: () => false,
  editionAwareRetry: () => false,
}));
vi.mock('@vistasecurity/primitives/rbac', async (orig) => ({
  ...(await orig<typeof import('@vistasecurity/primitives/rbac')>()),
  PermissionGate: ({ children }: { children: unknown }) => children,
}));

const { IntegrationsPage } = await import('./pages-integrations');

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let host: HTMLDivElement; let root: Root;
beforeEach(() => {
  for (const fn of Object.values(api)) fn.mockReset();
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); vi.restoreAllMocks(); });

const servicenowEntry = {
  key: 'servicenow', label: 'ServiceNow', kind: 'cmdb', direction: 'both', status: 'live',
  description: 'IT service management CMDB', feature: 'cmdb_sync', edition: 'enterprise',
  entitled: false, addable: false, unavailable_reason: 'upgrade',
};

it('shows the CMDB upgrade card and the catalogue entry, and asks nothing about CMDB profiles', async () => {
  const consoleError = vi.spyOn(console, 'error');
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/connectors') {
      return { data: { groups: [{ kind: 'cmdb', connectors: [servicenowEntry] }] }, response: { ok: true, status: 200 } };
    }
    return { data: [], response: { ok: true, status: 200 } };
  });
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <IntegrationsPage meta={{ key: 'integrations', label: 'Integrations', icon: 'plug', job: '' }} />
      </QueryClientProvider>,
    );
  });
  for (let i = 0; i < 40 && !document.body.textContent?.includes('Included in Enterprise'); i++) {
    await act(async () => { await new Promise((r) => setTimeout(r, 5)); });
  }
  const text = document.body.textContent ?? '';

  // The section is there, with its upgrade card — not an error, not missing.
  expect(text).toContain('CMDB / ITSM sync');
  expect(text).toContain('Upgrade to Enterprise to connect an external CMDB');
  expect(text).not.toContain("Couldn't load CMDB profiles");
  // The catalogue still lists ServiceNow, as an upgrade, with nothing to click.
  expect(text).toContain('Included in Enterprise');
  expect([...document.querySelectorAll('button')].some((b) => b.textContent === 'Add CMDB sync')).toBe(false);
  // Nor the mapping editor (W21a): no Mapping button, no editor.
  expect(document.querySelector('button[title="Field mapping"]')).toBeNull();
  expect(text).not.toContain('Field mapping');
  // Nor dry run, run changes or undo (W21b).
  expect([...document.querySelectorAll('button')].some((b) => b.textContent === 'Dry run')).toBe(false);
  expect(text).not.toContain('Not synced yet');

  // Not one CMDB request, from any client.
  const paths = api.GET.mock.calls.map((c) => String(c[0]))
    .concat(api.POST.mock.calls.map((c) => String(c[0])))
    .concat(api.PUT.mock.calls.map((c) => String(c[0])));
  expect(paths.filter((p) => p.includes('cmdb'))).toEqual([]);
  // In particular none of the mapping editor's (W21a): mapping, schema,
  // preview, vocabulary.
  expect(paths.filter((p) => p.includes('mapping'))).toEqual([]);
  expect(paths.filter((p) => p.includes('dry-run') || p.includes('undo') || p.includes('/items'))).toEqual([]);
  expect(consoleError).not.toHaveBeenCalled();
});
