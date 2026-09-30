// @vitest-environment jsdom
//
// Discovery → Approvals → "Merged automatically (last 30 days)" ( Phase 4).
//
// The real page over the real hooks with only the client mocked, so the states
// in the spec's table are the states seen here: rows of BOTH kinds, the empty
// line, the skeleton, and the retry banner.
//
// MUTATIONS (recorded in the PR):
//   - render the section on a FAILED read (drop the isError branch): the error
//     test fails, because "Nothing has been merged" would answer a question the
//     read never answered;
//   - hide the section when empty (the old behaviour): the empty test fails;
//   - label every row "Auto-accepted by the matcher": the rule-row tests fail;
//   - read the survivor from `accepted_asset_id` instead of `merged_into`: the
//     survivor-link test fails.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));
vi.mock('@vistasecurity/primitives/rbac', () => ({
  PermissionGate: ({ children }: { children: React.ReactNode }) => children,
  TENANT_PERMISSIONS: { assets: { update: 'assets.update' }, settings: { update: 'settings.update' } },
}));

const { ApprovalsPage } = await import('./approvals-page');
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const ok = (data: unknown) => ({ data, response: { ok: true, status: 200 } });
const failed = { data: undefined, error: { error: 'boom' }, response: { ok: false, status: 500 } };

const SURVIVOR = '11111111-1111-4111-8111-111111111111';
const ABSORBED = '22222222-2222-4222-8222-222222222222';
const WINNER = '33333333-3333-4333-8333-333333333333';

const candidate = (id: string, name: string, score = 0) => ({
  asset_id: id, display_name: name, hostname: null, class_key: 'hardware.computer.server', class_label: 'Server',
  asset_status: 'monitoring', deleted: false, matched_identifiers: [{ kind: 'mac_address', value: '00:00:5e:00:53:01' }], score,
});

const ruleRow = {
  id: 'rule-row', tenant_id: 't', status: 'merged', source: 'sensor', proposed_at: '2026-09-29T10:00:00Z',
  resolved_at: '2026-09-29T10:01:00Z', merged_into: SURVIVOR, decided_by: 'rule',
  rule_evidence: ['same MAC 00:00:5e:00:53:01 seen directly by a sensor', 'same network segment'],
  candidates: [candidate(SURVIVOR, 'declared-router'), candidate(ABSORBED, 'discovered-router')],
};
const matcherRow = {
  id: 'matcher-row', tenant_id: 't', status: 'pending', source: 'sensor', proposed_at: '2026-09-29T09:00:00Z',
  auto_accepted: true, decided_by: 'matcher', accepted_asset_id: WINNER, accepted_score: 0.93, accepted_model_id: 'matcher-logreg-v1',
  candidates: [candidate(WINNER, 'matcher-winner', 0.93)],
};

let autoAccepted: () => unknown;
let host: HTMLDivElement; let root: Root; let qc: QueryClient;
beforeEach(() => {
  autoAccepted = () => ok({ merges: [], window_days: 30 });
  api.GET.mockReset().mockImplementation(async (path: string) => {
    switch (path) {
      case '/infrastructure-assets': return ok({ assets: [] });
      case '/approvals/merge-proposals': return ok({ merge_proposals: [], total: 0 });
      case '/approvals/relationships': return ok({ relationship_proposals: [], total: 0 });
      case '/approvals/classes': return ok({ class_proposals: [], total: 0 });
      case '/approvals/merge-proposals/auto-accepted': return autoAccepted();
      default: throw new Error(`unmocked GET ${path}`);
    }
  });
  qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); qc.clear(); });

async function render() {
  await act(async () => {
    root.render(<MemoryRouter><QueryClientProvider client={qc}><ApprovalsPage /></QueryClientProvider></MemoryRouter>);
  });
  await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
}
const section = () => host.querySelector('[data-testid="auto-merged-section"]');
const rows = () => [...host.querySelectorAll('[data-testid="auto-merged-row"]')];
const autoAcceptedCalls = () => api.GET.mock.calls.filter((c) => c[0] === '/approvals/merge-proposals/auto-accepted').length;

it('lists rule merges beside matcher auto-accepts, newest first, each labelled by who decided', async () => {
  autoAccepted = () => ok({ merges: [ruleRow, matcherRow], window_days: 30 });
  await render();

  expect(section()!.textContent).toContain('Merged automatically (last 30 days) (2)');
  expect(host.textContent, 'the old section title must be gone').not.toContain('Auto-merged by the matcher');

  const [rule, matcher] = rows();
  expect(rows()).toHaveLength(2);
  expect(rule.getAttribute('data-decided-by')).toBe('rule');
  expect(rule.querySelector('[data-testid="decided-by"]')!.textContent).toBe('Merged by rule');
  expect(matcher.getAttribute('data-decided-by')).toBe('matcher');
  expect(matcher.querySelector('[data-testid="decided-by"]')!.textContent).toBe('Auto-accepted by the matcher');
});

it('a rule row shows the evidence line and a link to the survivor — from merged_into', async () => {
  autoAccepted = () => ok({ merges: [ruleRow], window_days: 30 });
  await render();

  const [rule] = rows();
  expect(rule.textContent).toContain('Merged into declared-router');
  const evidence = [...rule.querySelectorAll('[data-testid="rule-evidence"] li')].map((li) => li.textContent);
  expect(evidence).toEqual([
    'same MAC 00:00:5e:00:53:01 seen directly by a sensor',
    'same network segment',
  ]);
  expect(rule.querySelector<HTMLAnchorElement>('[data-testid="survivor-link"]')!.getAttribute('href'))
    .toBe(`/inventory/assets/${SURVIVOR}`);
  // No score, no model, no "other candidates still waiting": a rule has none of
  // those, and an empty bar would read as "scored zero".
  expect(rule.textContent).not.toContain('decided by matcher');
  expect(rule.textContent).not.toContain('other candidate');
  expect(rule.querySelector('[data-testid="auto-merged-reasons"]')).toBeNull();
});

it('a matcher row still shows its score, its model and its link', async () => {
  autoAccepted = () => ok({ merges: [matcherRow], window_days: 30 });
  await render();

  const [matcher] = rows();
  expect(matcher.textContent).toContain('Merged into matcher-winner');
  expect(matcher.textContent).toContain('93%');
  expect(matcher.textContent).toContain('decided by matcher-logreg-v1');
  expect(matcher.querySelector('[data-testid="rule-evidence"]')).toBeNull();
});

it('says so when nothing has been merged — the section is not hidden', async () => {
  await render();
  expect(section(), 'an empty section that vanishes cannot tell "nothing merged" from "not reported"').not.toBeNull();
  expect(host.querySelector('[data-testid="auto-merged-empty"]')!.textContent)
    .toBe('Nothing has been merged automatically in the last 30 days.');
  expect(section()!.textContent).toContain('Merged automatically (last 30 days)');
  expect(rows()).toHaveLength(0);
});

it('shows skeleton rows while loading, and neither the empty line nor a false zero', async () => {
  autoAccepted = () => new Promise(() => {});
  await render();
  expect(host.querySelector('[data-testid="auto-merged-skeleton"]')).not.toBeNull();
  expect(host.querySelector('[data-testid="auto-merged-empty"]')).toBeNull();
  expect(rows()).toHaveLength(0);
});

it('a failed read shows the retry banner and NOT the empty line', async () => {
  autoAccepted = () => failed;
  await render();

  const banner = host.querySelector('[data-testid="auto-merged-error"]');
  expect(banner).not.toBeNull();
  expect(banner!.textContent).toContain('does not mean nothing was merged');
  expect(section(), 'a section over a failed read would tell the reviewer nothing was merged').toBeNull();
  expect(host.textContent).not.toContain('Nothing has been merged automatically');
});

it('Retry re-reads, and the rows appear when the second read succeeds', async () => {
  autoAccepted = () => failed;
  await render();
  const before = autoAcceptedCalls();

  autoAccepted = () => ok({ merges: [ruleRow], window_days: 30 });
  const retry = [...host.querySelectorAll('[data-testid="auto-merged-error"] button')].find((b) => b.textContent === 'Retry');
  await act(async () => { (retry as HTMLElement).click(); });
  await act(async () => { await new Promise((r) => setTimeout(r, 20)); });

  expect(autoAcceptedCalls()).toBeGreaterThan(before);
  expect(host.querySelector('[data-testid="auto-merged-error"]')).toBeNull();
  expect(rows()).toHaveLength(1);
});

it('uses the window the server counted over, so the heading cannot disagree with the query', async () => {
  autoAccepted = () => ok({ merges: [], window_days: 14 });
  await render();
  expect(section()!.textContent).toContain('Merged automatically (last 14 days)');
  expect(host.querySelector('[data-testid="auto-merged-empty"]')!.textContent)
    .toBe('Nothing has been merged automatically in the last 14 days.');
});
