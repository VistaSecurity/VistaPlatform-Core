// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AssetMergeModal, mergeChoices } from './asset-merge-modal';
import type { MergeProposal } from '../inventory/asset-queries';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const post = vi.hoisted(() => vi.fn());
vi.mock('../../lib/clients', () => ({ clients: { inventory: { POST: post } } }));
vi.mock('../inventory/asset-queries', async (original) => ({
  ...await original<typeof import('../inventory/asset-queries')>(),
  useAssetsQuery: () => ({ data: { assets: [{ id: 'bravo', display_name: 'bravo', asset_status: 'monitoring', class_key: 'server' }], total: 1, pageSize: 50 }, isPending: false, isError: false }),
}));
const proposal: MergeProposal = {
  id: 'proposal', tenant_id: 'tenant', status: 'pending', source: 'matcher', proposed_at: '2026-09-18T00:00:00Z',
  candidates: ['alpha', 'bravo', 'charlie'].map((id) => ({ asset_id: id, display_name: id, deleted: false, score: 0.9, matched_identifiers: [] })),
};
const preview = {
  revision: 'revision1', source_asset_ids: ['bravo'], survivor_asset_id: 'alpha', assets: [],
  conflicts: [], selected_fields: { display_name: 'alpha' }, children: [{ table: 'certificates', count: 2 }], evidence: [],
};
let host: HTMLDivElement; let root: Root; let cache: QueryClient;
const close = vi.fn();
beforeEach(async () => {
  post.mockReset().mockResolvedValue({ data: { preview }, response: { ok: true, status: 200 } }); close.mockReset();
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await act(async () => root.render(<QueryClientProvider client={cache}><AssetMergeModal proposal={proposal} onClose={close} /></QueryClientProvider>));
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });
function button(label: string) { const found = [...host.querySelectorAll('button')].find((b) => b.textContent === label); expect(found).toBeTruthy(); return found!; }
async function click(label: string) { await act(async () => button(label).click()); }
async function select(label: string, value: string) {
  await act(async () => { const el = host.querySelector<HTMLSelectElement>(`select[aria-label="${label}"]`)!; el.value = value; el.dispatchEvent(new Event('change', { bubbles: true })); });
}
async function choose() {
  await select('Surviving asset', 'alpha');
  await act(async () => host.querySelector<HTMLInputElement>('input[aria-label="Merge bravo"]')!.click());
}
async function reason() {
  await act(async () => { const el = host.querySelector('textarea')!; Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')!.set!.call(el, 'Verified controller serial'); el.dispatchEvent(new Event('input', { bubbles: true })); });
}
it('requires explicit sources and survivor, preview and reason; never selects the whole candidate group', async () => {
  expect(button('Preview selected merge').disabled).toBe(true);
  expect(host.querySelectorAll('input:checked')).toHaveLength(0);
  await choose(); await click('Preview selected merge');
  expect(post).toHaveBeenLastCalledWith('/approvals/merge-proposals/{id}/preview', { params: { path: { id: 'proposal' } }, body: { source_asset_ids: ['bravo'], survivor_asset_id: 'alpha', field_resolutions: {} } });
  expect(button('Merge selected assets').disabled).toBe(true);
  await reason(); await click('Merge selected assets');
  expect(post).toHaveBeenLastCalledWith('/approvals/merge-proposals/{id}/merge', { params: { path: { id: 'proposal' } }, body: { source_asset_ids: ['bravo'], survivor_asset_id: 'alpha', field_resolutions: {}, revision: 'revision1', reason: 'Verified controller serial' } });
  expect(close).toHaveBeenCalledOnce();
});
it('requires a refreshed revision after resolving a declared field', async () => {
  post.mockResolvedValue({ data: { preview: { ...preview, conflicts: [{ field: 'display_name', requires_resolution: true, values: [{ asset_id: 'alpha', value: 'alpha', declared: true }, { asset_id: 'bravo', value: 'bravo', declared: true }] }] } }, response: { status: 200 } });
  await choose(); await click('Preview selected merge'); await reason();
  expect(button('Merge selected assets').disabled).toBe(true);
  await select('Resolve display name', 'bravo');
  expect(button('Merge selected assets').disabled).toBe(true);
  await click('Refresh preview');
  expect(post).toHaveBeenLastCalledWith('/approvals/merge-proposals/{id}/preview', expect.objectContaining({ body: expect.objectContaining({ field_resolutions: { display_name: 'bravo' } }) }));
  expect(button('Merge selected assets').disabled).toBe(false);
});
it('preserves choices and reason on stale preview and requires explicit refresh', async () => {
  await choose(); await click('Preview selected merge'); await reason();
  post.mockResolvedValueOnce({ error: { message: 'changed' }, response: { status: 409 } });
  await click('Merge selected assets');
  expect(host.querySelector('[role="alert"]')?.textContent).toContain('Refresh the preview');
  expect(close).not.toHaveBeenCalled();
  expect(host.querySelector('textarea')?.value).toBe('Verified controller serial');
  expect(button('Merge selected assets').disabled).toBe(true);
  await click('Refresh preview');
  expect(button('Merge selected assets').disabled).toBe(false);
});

it('supports directly selected inventory records using the same preview checks', async () => {
  await act(async () => root.render(<QueryClientProvider client={cache}><AssetMergeModal key="direct" initialAssets={[proposal.candidates[0]]} onClose={close} /></QueryClientProvider>));
  await select('Asset to add', 'bravo'); await click('Add record');
  await choose(); await click('Preview selected merge'); await reason();
  expect(post).toHaveBeenLastCalledWith('/infrastructure-assets/merge/preview', { body: { source_asset_ids: ['bravo'], survivor_asset_id: 'alpha', field_resolutions: {} } });
  await click('Merge selected assets');
  expect(post).toHaveBeenLastCalledWith('/infrastructure-assets/merge', { body: { source_asset_ids: ['bravo'], survivor_asset_id: 'alpha', field_resolutions: {}, revision: 'revision1', reason: 'Verified controller serial' } });
});

it('excludes archived, denied and deleted candidates from explicit selection', () => {
  expect(mergeChoices({ ...proposal, candidates: [proposal.candidates[0], { ...proposal.candidates[1], asset_status: 'archived' }, { ...proposal.candidates[2], asset_status: 'denied' }] }).map((a) => a.asset_id)).toEqual(['alpha']);
});
