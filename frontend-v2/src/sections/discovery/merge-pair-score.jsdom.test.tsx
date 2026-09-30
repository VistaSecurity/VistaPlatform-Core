// @vitest-environment jsdom
//
// Phase 5: the Approvals merge-proposal card says what the matcher makes
// of the two RECORDS compared with each other — "the two records themselves
// score N%" — beside each candidate's own score against the sighting.
import type { ReactNode } from 'react';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { MergeCandidate, MergeProposal } from '../inventory/asset-queries';
import { MergeProposalRow } from './merge-proposal-row';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

vi.mock('@vistasecurity/primitives/rbac', () => ({
  PermissionGate: ({ children }: { children: ReactNode }) => children,
  TENANT_PERMISSIONS: { assets: { update: 'assets.update' } },
}));

const A = '00000000-0000-4000-8000-00000000000a';
const B = '00000000-0000-4000-8000-00000000000b';
const C = '00000000-0000-4000-8000-00000000000c';

function candidate(id: string, name: string, score: number): MergeCandidate {
  return {
    asset_id: id, display_name: name, deleted: false, asset_status: 'monitoring',
    matched_identifiers: [{ kind: 'mac_address', value: `0a:00:00:00:00:0${id.slice(-1)}` }], score,
  };
}

function proposal(overrides: Partial<MergeProposal>): MergeProposal {
  return {
    id: 'p', tenant_id: 't', status: 'pending', source: 'sensor', proposed_at: '2026-09-29T10:00:00Z',
    candidates: [candidate(A, 'print-lobby', 0.81), candidate(B, 'lobby-printer', 0.44)],
    ...overrides,
  };
}

let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root.unmount());
  host.remove();
});

async function render(p: MergeProposal) {
  await act(async () => root.render(
    <MemoryRouter><MergeProposalRow proposal={p} onAccept={vi.fn()} onKeepSeparate={vi.fn()} /></MemoryRouter>,
  ));
  return host.querySelector('[data-testid="merge-pair-score"]');
}

describe('the pair score on a merge proposal', () => {
  it('says what the two records score against each other, with the model\'s reason', async () => {
    const line = await render(proposal({ pair_score: 0.62, pair_asset_ids: [A, B], pair_reason: 'a tenant-unique identifier matches (SSH host key, MAC or FQDN), and 3 other signals' }));
    expect(line?.textContent).toContain('The two records themselves score 62%');
    expect(line?.textContent).toContain('a tenant-unique identifier matches');
    // Each candidate still shows its OWN score against the sighting.
    expect(host.textContent).toContain('81%');
    expect(host.textContent).toContain('44%');
  });

  it('names the two records when the proposal has more than two candidates', async () => {
    const line = await render(proposal({
      candidates: [candidate(A, 'print-lobby', 0.81), candidate(B, 'lobby-printer', 0.44), candidate(C, 'spare', 0.1)],
      pair_score: 0.05, pair_asset_ids: [A, B],
    }));
    expect(line?.textContent).toContain('print-lobby and lobby-printer themselves score 5%');
  });

  it('shows nothing when the pair is unscored — zero is the matcher\'s "no score", not 0%', async () => {
    expect(await render(proposal({ pair_score: 0, pair_asset_ids: [A, B] }))).toBeNull();
    expect(await render(proposal({}))).toBeNull();
  });

  it('shows nothing when the records it names are not both on the card', async () => {
    expect(await render(proposal({ pair_score: 0.7, pair_asset_ids: [A, C] }))).toBeNull();
    expect(await render(proposal({ pair_score: 0.7, pair_asset_ids: [A] }))).toBeNull();
  });
});
