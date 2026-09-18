import type { ReactNode } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router';
import type { MergeCandidate, MergeProposal } from '../inventory/asset-queries';
import { MergeProposalRow } from './merge-proposal-row';
import { AutoMergedSection } from './auto-merged-section';

vi.mock('@vistasecurity/primitives/rbac', () => ({
  PermissionGate: ({ children }: { children: ReactNode }) => children,
  TENANT_PERMISSIONS: { assets: { update: 'assets.update' } },
}));

function candidate(assetId: string, name: string, score: number): MergeCandidate {
  return {
    asset_id: assetId,
    display_name: name,
    hostname: null,
    class_key: 'hardware.computer.server',
    class_label: 'Server',
    asset_status: 'monitoring',
    deleted: false,
    matched_identifiers: [{ kind: 'serial_number', value: `serial-${name}` }],
    score,
    explanation: [],
  };
}

function proposal(overrides: Partial<MergeProposal> = {}): MergeProposal {
  return {
    id: 'proposal-1',
    tenant_id: 'tenant-1',
    status: 'pending',
    source: 'matcher',
    proposed_at: '2026-09-17T12:00:00Z',
    candidates: [],
    ...overrides,
  };
}

describe('identity confidence component wiring', () => {
  it('reads candidate.score as 0..1 and keeps matcher zero unscored', () => {
    const html = renderToStaticMarkup(
      <MemoryRouter>
        <MergeProposalRow
          proposal={proposal({ candidates: [
            candidate('asset-0', 'Zero candidate', 0),
            candidate('asset-1', 'One percent candidate', 0.01),
            candidate('asset-2', 'Certain candidate', 1),
          ] })}
          onAccept={vi.fn()}
          onKeepSeparate={vi.fn()}
        />
      </MemoryRouter>,
    );
    expect(html).toContain('One percent candidate');
    expect(html).toContain('>1%</span>');
    expect(html).toContain('>100%</span>');
    expect(html).not.toContain('>0%</span>');
  });

  it('reads accepted_score on auto-merged history with the same zero-as-unscored contract', () => {
    const winner = candidate('asset-1', 'Winner', 0.9);
    const scored = renderToStaticMarkup(
      <MemoryRouter><AutoMergedSection merges={[proposal({
        status: 'merged', candidates: [winner], accepted_asset_id: winner.asset_id,
        accepted_score: 0.01, auto_accepted: true,
      })]} windowDays={30} /></MemoryRouter>,
    );
    expect(scored).toContain('Merged into Winner');
    expect(scored).toContain('>1%</span>');

    const unscored = renderToStaticMarkup(
      <MemoryRouter><AutoMergedSection merges={[proposal({
        status: 'merged', candidates: [winner], accepted_asset_id: winner.asset_id,
        accepted_score: 0, auto_accepted: true,
      })]} windowDays={30} /></MemoryRouter>,
    );
    expect(unscored).not.toContain('>0%</span>');
  });
});

describe('merge source eligibility', () => {
  it.each([undefined, '', 'source-asset'])('requires an observation asset (%s)', (observationId) => {
    const html = renderToStaticMarkup(
      <MemoryRouter>
        <MergeProposalRow
          proposal={proposal({
            observation_asset_id: observationId,
            candidates: [candidate('survivor', 'Survivor', 0.8)],
          })}
          onAccept={vi.fn()}
          onKeepSeparate={vi.fn()}
        />
      </MemoryRouter>,
    );
    const mergeButton = html.match(/<button[^>]*>.*?Merge<\/button>/)?.[0];
    expect(mergeButton).toBeDefined();
    expect(mergeButton?.includes('disabled')).toBe(!observationId);
    expect(html.includes('This sighting has no separate asset to merge.')).toBe(!observationId);
  });
});
