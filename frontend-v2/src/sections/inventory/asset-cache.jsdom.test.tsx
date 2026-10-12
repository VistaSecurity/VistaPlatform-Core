// @vitest-environment jsdom
// Cache behaviour of the asset read hooks: the Endpoints/Identifiers tabs follow
// a refetched asset, a merge invalidates asset/inventory keys but not the
// session, and the "awaiting review" banner asks the server for a count only.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { useAsset, useAssetEndpoints, useAssetIdentifiers, useMergeAsIs, useMergeProposalCount } from './asset-queries';
import { useRelationshipProposalCount } from './relationship-queries';
import { useClassProposalCount } from '../discovery/class-proposal-queries';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const get = vi.hoisted(() => vi.fn());
const post = vi.hoisted(() => vi.fn());
vi.mock('../../lib/clients', () => ({ clients: { inventory: { GET: get, POST: post } } }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  get.mockReset(); post.mockReset();
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });
async function render(node: React.ReactNode) {
  await act(async () => root.render(<QueryClientProvider client={cache}>{node}</QueryClientProvider>));
  await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
}

const asset = (address: string, ident: string) => ({
  id: 'a1', endpoints: [{ id: 'e', address }], identifiers: [{ id: 'i', value: ident }],
});

function Tabs() {
  const q = useAsset('a1');
  const endpoints = useAssetEndpoints('a1', q.data?.endpoints);
  const identifiers = useAssetIdentifiers('a1', q.data?.identifiers);
  return <p>{JSON.stringify([endpoints.data, identifiers.data])}</p>;
}

it('endpoints and identifiers follow a refetched asset read', async () => {
  // Like the real server, the dedicated paths answer with their own envelope.
  get.mockImplementation(async (path: string) => path === '/infrastructure-assets/{id}'
    ? { data: { asset: asset('10.0.0.1', 'first-id') } }
    : { data: { endpoints: [], identifiers: [] } });
  await render(<Tabs />);
  expect(host.textContent).toContain('10.0.0.1');
  expect(host.textContent).toContain('first-id');

  await act(async () => { cache.setQueryData(['asset-detail', 'a1'], asset('10.0.0.2', 'second-id')); await new Promise((r) => setTimeout(r, 20)); });
  expect(host.textContent).toContain('10.0.0.2');
  expect(host.textContent).toContain('second-id');
  expect(host.textContent).not.toContain('10.0.0.1');
});

it('a merge invalidates inventory and asset keys but not the session', async () => {
  post.mockImplementation(async (path: string) => path.endsWith('/preview')
    ? { data: { preview: { conflicts: [], revision: 'r' } }, response: { ok: true, status: 200 } }
    : { data: {}, response: { ok: true, status: 200 } });
  const keys = [['auth', 'me'], ['settings', 'branding'], ['inventory', 'assets'], ['asset-detail', 'a1'], ['asset-endpoints', 'a1'], ['findings', 'x'], ['dashboard', 'x']];
  for (const k of keys) cache.setQueryData(k, 1);
  const spy = vi.spyOn(cache, 'invalidateQueries');
  const handle: { run?: () => Promise<unknown> } = {};
  function Merge() { const m = useMergeAsIs(); handle.run = () => m.mutateAsync({ proposalID: 'p', selection: {} as never }); return null; }
  await render(<Merge />);
  await act(async () => { await handle.run!(); });

  expect(spy).toHaveBeenCalled();
  const invalidated = (k: string[]) => cache.getQueryState(k)!.isInvalidated;
  expect(invalidated(['auth', 'me'])).toBe(false);
  expect(invalidated(['settings', 'branding'])).toBe(false);
  for (const k of keys.slice(2)) expect(invalidated(k)).toBe(true);
});

it('the awaiting-review banner counts with limit 1', async () => {
  get.mockResolvedValue({ data: { total: 132, merge_proposals: [], relationship_proposals: [], class_proposals: [] } });
  function Counts() {
    const m = useMergeProposalCount(); const r = useRelationshipProposalCount(); const c = useClassProposalCount();
    return <p>{[m.data, r.data, c.data].join(',')}</p>;
  }
  await render(<Counts />);
  expect(host.textContent).toBe('132,132,132');
  expect(get).toHaveBeenCalledTimes(3);
  for (const call of get.mock.calls) expect(call[1].params.query.limit).toBe(1);
});
