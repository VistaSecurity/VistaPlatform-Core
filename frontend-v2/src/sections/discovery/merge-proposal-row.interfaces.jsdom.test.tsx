// @vitest-environment jsdom
//
// DCIM row 1.4: a contested candidate's card lists, beside each matched MAC
// and address, the candidate's interface that holds it — "00:00:5e:00:88:02
// on eth1" — so the evidence names where on the device the match is.
import type { ReactNode } from 'react';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { MergeCandidate, MergeProposal } from '../inventory/asset-queries';
import { MergeProposalRow, interfaceNote, readIdentifier } from './merge-proposal-row';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
vi.mock('@vistasecurity/primitives/rbac', () => ({
  PermissionGate: ({ children }: { children: ReactNode }) => children,
  TENANT_PERMISSIONS: { assets: { update: 'assets.update' } },
}));

function candidate(id: string, matched: Array<Record<string, unknown>>): MergeCandidate {
  return { asset_id: id, display_name: id, deleted: false, asset_status: 'monitoring', matched_identifiers: matched, score: 0.6 };
}

let host: HTMLDivElement; let root: Root;
beforeEach(() => { host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host); });
afterEach(() => { act(() => root.unmount()); host.remove(); });
async function render(p: MergeProposal) {
  await act(async () => root.render(<MemoryRouter><MergeProposalRow proposal={p} onMergeAsIs={vi.fn()} onAccept={vi.fn()} onKeepSeparate={vi.fn()} /></MemoryRouter>));
}

it('names the interface beside a matched MAC and address', async () => {
  await render({
    id: 'p', tenant_id: 't', status: 'pending', source: 'sensor', proposed_at: '2026-10-15T10:00:00Z',
    candidates: [
      candidate('host', [
        { kind: 'mac_address', value: '00:00:5e:00:88:02', interface: 'eth1' },
        { kind: 'ip_address', value: '10.88.1.1', scope: 'tenant', interface: 'eth1' },
        { kind: 'hostname', value: 'it-contested', scope: 'tenant' },
      ]),
      candidate('other', [{ kind: 'mac_address', value: '00:00:5e:00:88:09' }]),
    ],
  });
  const notes = [...host.querySelectorAll('[data-testid="matched-interface"]')].map((n) => n.textContent);
  expect(notes).toEqual(['on eth1', 'on eth1']);
  // A matched value with no interface (a MAC on no interface, an older
  // proposal) says nothing rather than inventing one.
  expect(host.querySelectorAll('[data-testid="matched-identifier"]')).toHaveLength(4);
});

it('reads the interface only for MACs and addresses', () => {
  expect(interfaceNote(readIdentifier({ kind: 'ip_address', value: '10.0.0.1', interface: 'Gi0/1' }))).toBe('on Gi0/1');
  expect(interfaceNote(readIdentifier({ kind: 'hostname', value: 'h', interface: 'eth0' }))).toBeNull();
  expect(interfaceNote(readIdentifier({ kind: 'mac_address', value: 'aa', interface: '' }))).toBeNull();
  expect(interfaceNote(readIdentifier(null))).toBeNull();
});
