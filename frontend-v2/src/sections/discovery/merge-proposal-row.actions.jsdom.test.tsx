// @vitest-environment jsdom
//
// The three answers on a merge proposal: Merge as is (the recommendation, one
// click), Review merge (the recommendation, adjustable), Keep separate. Each
// button calls its own handler and nothing else's.
import type { ReactNode } from 'react';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { MergeCandidate, MergeProposal } from '../inventory/asset-queries';
import { MergeProposalRow } from './merge-proposal-row';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
vi.mock('@vistasecurity/primitives/rbac', () => ({
  PermissionGate: ({ children }: { children: ReactNode }) => children,
  TENANT_PERMISSIONS: { assets: { update: 'assets.update' } },
}));

function candidate(id: string, score: number, extra: Partial<MergeCandidate> = {}): MergeCandidate {
  return { asset_id: id, display_name: id, deleted: false, asset_status: 'monitoring', matched_identifiers: [], score, ...extra };
}
const proposal: MergeProposal = {
  id: 'p', tenant_id: 't', status: 'pending', source: 'sensor', proposed_at: '2026-10-07T10:00:00Z',
  candidates: [candidate('a', 0.8), candidate('b', 0.5)],
};

let host: HTMLDivElement; let root: Root;
const onMergeAsIs = vi.fn(); const onAccept = vi.fn(); const onKeepSeparate = vi.fn();
beforeEach(() => { host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host); vi.clearAllMocks(); });
afterEach(() => { act(() => root.unmount()); host.remove(); });
async function render(p: MergeProposal) {
  await act(async () => root.render(<MemoryRouter><MergeProposalRow proposal={p} onMergeAsIs={onMergeAsIs} onAccept={onAccept} onKeepSeparate={onKeepSeparate} /></MemoryRouter>));
}
function button(label: string) { const b = [...host.querySelectorAll('button')].find((x) => x.textContent === label); expect(b, label).toBeTruthy(); return b!; }

it('offers Merge as is, Review merge and Keep separate, each wired to its own handler', async () => {
  await render(proposal);
  expect([...host.querySelectorAll('button')].map((b) => b.textContent)).toEqual(['Merge as is', 'Review merge', 'Keep separate']);
  await act(async () => button('Merge as is').click());
  expect(onMergeAsIs).toHaveBeenCalledOnce(); expect(onAccept).not.toHaveBeenCalled(); expect(onKeepSeparate).not.toHaveBeenCalled();
  await act(async () => button('Review merge').click());
  expect(onAccept).toHaveBeenCalledOnce();
  await act(async () => button('Keep separate').click());
  expect(onKeepSeparate).toHaveBeenCalledOnce();
});

it('disables both merge buttons, but not Keep separate, when fewer than two records remain', async () => {
  await render({ ...proposal, candidates: [candidate('a', 0.8), candidate('b', 0.5, { deleted: true })] });
  expect(button('Merge as is').disabled).toBe(true);
  expect(button('Review merge').disabled).toBe(true);
  expect(button('Keep separate').disabled).toBe(false);
});
