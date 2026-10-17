// @vitest-environment jsdom
//
// A cloud account asset's Relationships tab (asset-inventory ADR-0009 D1):
// every resource discovered in the account points at it with a stored
// `hosted_on` edge, so the account's page lists them, read from the account's
// side — "hosts <resource>". Driven through the REAL RelationshipsTab; only
// the queries are stubbed.
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const ACCOUNT_ASSET = 'aaaaaaaa-0000-4000-8000-0000000000a1';
const BUCKET = 'aaaaaaaa-0000-4000-8000-0000000000b1';
const INSTANCE = 'aaaaaaaa-0000-4000-8000-0000000000c1';

const hosted = (id: string, from: string, name: string, cls: string, status: string) => ({
  id, tenant_id: 't', from_asset_id: from, to_asset_id: ACCOUNT_ASSET, type: 'hosted_on',
  source_kind: 'measured', source_ref: 'cloud:aws', confidence: 1, status,
  first_seen_at: '2026-10-15T00:00:00Z', last_seen_at: '2026-10-15T00:00:00Z', observation_count: 1,
  peer: { asset_id: from, display_name: name, class_key: cls, asset_status: status === 'active' ? 'monitoring' : 'pending_approval', deleted: false },
});

const rel = vi.hoisted((): { data: unknown } => ({ data: undefined }));
vi.mock('./relationship-queries', () => ({
  useAssetRelationships: () => ({ data: rel.data, isLoading: false, isError: false, error: null, refetch: () => {} }),
  useAssetNeighbourhood: () => ({ data: undefined, isLoading: false, isError: false }),
  useAssetImpact: () => ({ data: undefined, isLoading: false, isError: false }),
  useCreateRelationship: () => ({ mutate: vi.fn(), isPending: false }),
  useDeleteRelationship: () => ({ mutate: vi.fn(), isPending: false }),
  useDecideRelationshipProposal: () => ({ mutate: vi.fn(), isPending: false }),
}));
vi.mock('./asset-queries', async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useAssetsQuery: () => ({ data: { assets: [] }, isLoading: false, isError: false }),
}));
vi.mock('@vistasecurity/primitives/rbac', async (importOriginal) => ({
  ...await importOriginal<typeof import('@vistasecurity/primitives/rbac')>(),
  PermissionGate: ({ children }: { children: ReactNode }) => <>{children}</>,
  usePermissions: () => ({ hasPermission: () => false }),
}));

const { RelationshipsTab } = await import('./relationships-tab');

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let host: HTMLDivElement; let root: Root;
beforeEach(() => { host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host); });
afterEach(() => { act(() => root.unmount()); host.remove(); });

it('lists the resources a cloud account hosts, from the account side', async () => {
  rel.data = {
    relationships: [
      hosted('h1', BUCKET, 'assets-bucket', 'object_storage', 'active'),
      hosted('h2', INSTANCE, 'web-01', 'compute_instance', 'pending'),
    ],
    total: 2,
  };
  const asset = { id: ACCOUNT_ASSET, class_key: 'cloud_account', display_name: 'AWS account 210987654321', asset_status: 'monitoring' };
  await act(async () => {
    root.render(
      <QueryClientProvider client={new QueryClient()}>
        <MemoryRouter><RelationshipsTab asset={asset as never} /></MemoryRouter>
      </QueryClientProvider>,
    );
  });
  const rows = [...host.querySelectorAll('[data-testid="relationship-row"]')];
  expect(rows).toHaveLength(2);
  for (const r of rows) expect(r.textContent).toMatch(/^hosts/);
  const links = rows.map((r) => r.querySelector('a')?.getAttribute('href'));
  expect(links).toEqual(expect.arrayContaining([`/inventory/assets/${BUCKET}`, `/inventory/assets/${INSTANCE}`]));
  // The pending resource's edge says it is pending, rather than reading as fact.
  expect(host.querySelector('[data-edge-id="h2"] [data-testid="status-chip"]')?.textContent).toBe('pending');
});
