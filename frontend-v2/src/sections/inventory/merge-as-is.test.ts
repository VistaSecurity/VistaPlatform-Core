// "Merge as is" is preview-then-merge on the recommended selection, with no
// reason. The one thing it hands back to a person is a field with two
// declared values, which the server would refuse to merge unresolved anyway.
import { beforeEach, expect, it, vi } from 'vitest';
import { mergeAsIs } from './asset-queries';

const post = vi.hoisted(() => vi.fn());
vi.mock('../../lib/clients', () => ({ clients: { inventory: { POST: post } } }));
vi.mock('../../lib/toast', () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

const selection = { survivor_asset_id: 'alpha', source_asset_ids: ['bravo'], field_resolutions: {} };
const preview = { revision: 'r'.repeat(64), ...selection, assets: [], conflicts: [], selected_fields: {}, children: [], evidence: [] };
beforeEach(() => post.mockReset());

it('previews, then merges on the preview revision with no reason', async () => {
  post.mockResolvedValueOnce({ data: { preview }, response: { status: 200 } })
    .mockResolvedValueOnce({ data: { merge: {} }, response: { status: 200 } });
  await expect(mergeAsIs('p', selection)).resolves.toEqual({ outcome: 'merged' });
  expect(post).toHaveBeenNthCalledWith(1, '/approvals/merge-proposals/{id}/preview', { params: { path: { id: 'p' } }, body: selection });
  expect(post).toHaveBeenNthCalledWith(2, '/approvals/merge-proposals/{id}/merge', { params: { path: { id: 'p' } }, body: { ...selection, revision: preview.revision, reason: '' } });
});

it('stops before merging when a field needs a person, naming the field', async () => {
  post.mockResolvedValueOnce({ data: { preview: { ...preview, conflicts: [
    { field: 'display_name', requires_resolution: true, values: [] },
    { field: 'environment', requires_resolution: false, values: [] },
  ] } }, response: { status: 200 } });
  await expect(mergeAsIs('p', selection)).resolves.toEqual({ outcome: 'needs-review', note: 'Both records declare a different display name. Choose which to keep, then merge.' });
  expect(post).toHaveBeenCalledTimes(1);
});

it('surfaces a preview failure and a stale revision as errors, not as merges', async () => {
  post.mockResolvedValueOnce({ error: { message: 'nope' }, response: { status: 500 } });
  await expect(mergeAsIs('p', selection)).rejects.toThrow('nope');
  post.mockReset();
  post.mockResolvedValueOnce({ data: { preview }, response: { status: 200 } })
    .mockResolvedValueOnce({ error: { message: 'changed' }, response: { status: 409 } });
  await expect(mergeAsIs('p', selection)).rejects.toThrow(/changed while merging/);
});
