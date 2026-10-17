// @vitest-environment jsdom
//
// Discovery → Cloud's per-integration account panel (ADR-0009 D1, D5): the
// account asset link, the auto-approve switch (which PERSISTS through
// PUT /integrations/{id}), and the last run's per-type outcomes — in all five
// states (default, empty, loading, error, success). Driven through the REAL
// CloudPage, so deleting <CloudAccountPanel/> from the card turns these red.
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

type Q = { data: unknown; isLoading: boolean; isError: boolean };
const mocks = vi.hoisted(() => ({
  integrations: vi.fn(),
  jobs: vi.fn(),
  results: vi.fn(),
  put: vi.fn(),
}));
vi.mock('./queries', () => ({
  useIntegrations: (): Q => mocks.integrations() as Q,
  useJobs: (): Q => mocks.jobs() as Q,
  useJobResults: (id?: string | null): Q => mocks.results(id) as Q,
}));
vi.mock('../../lib/clients', () => ({ clients: { devices: { PUT: mocks.put, GET: vi.fn(), POST: vi.fn(), DELETE: vi.fn() } } }));
vi.mock('react-router', () => ({
  Link: ({ to, children, ...rest }: { to: string; children: ReactNode }) => <a href={to} {...rest}>{children}</a>,
}));
vi.mock('@vistasecurity/primitives/rbac', async (importOriginal) => ({
  ...await importOriginal<typeof import('@vistasecurity/primitives/rbac')>(),
  PermissionGate: ({ children }: { children: ReactNode }) => <>{children}</>,
}));
// The write modals are out of scope here and need router/form context.
vi.mock('./cloud-modals', () => ({
  CloudIntegrationFormModal: () => null,
  CloudIntegrationDeleteModal: () => null,
  CloudIntegrationTestModal: () => null,
  CloudIntegrationDiscoverModal: () => null,
}));

const { CloudPage } = await import('./cloud-page');
const { AUTO_APPROVE_COPY } = await import('./cloud-account-panel');

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const integ = {
  id: 'i-1', tenant_id: 't', integration_type: 'aws', integration_name: 'prod aws', provider: 'cloud', config: {},
  account_id: '210987654321', account_asset_id: 'acct-asset-1', auto_approve_resources: true,
  is_enabled: true, status: 'connected', created_at: '2026-10-15T00:00:00Z', updated_at: '2026-10-15T00:00:00Z',
};
const run = { id: 'job-9', integration_id: 'i-1', job_type: 'cloud_discovery', status: 'completed', created_at: '2026-10-15T10:00:00Z', completed_at: '2026-10-15T10:05:00Z' };
const ok = (data: unknown): Q => ({ data, isLoading: false, isError: false });

let host: HTMLDivElement; let root: Root; let qc: QueryClient;
beforeEach(() => {
  mocks.integrations.mockReset().mockReturnValue(ok([integ]));
  mocks.jobs.mockReset().mockReturnValue(ok({ jobs: [run] }));
  mocks.results.mockReset().mockImplementation((id?: string | null) => (id ? ok({
    resource_types: [
      { resource_type: 's3', status: 'succeeded', found: 4, scopes_succeeded: 1, scopes_attempted: 1 },
      { resource_type: 'kms', status: 'failed', found: 0, scopes_succeeded: 0, scopes_attempted: 1, failures: [{ reason: 'access_denied' }] },
    ],
  }) : ok(undefined)));
  mocks.put.mockReset().mockResolvedValue({ data: { message: 'ok' }, response: { ok: true, status: 200 } });
  qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

async function render() {
  await act(async () => {
    root.render(<QueryClientProvider client={qc}><CloudPage /></QueryClientProvider>);
  });
}
const sw = () => document.body.querySelector<HTMLInputElement>('input[role="switch"][aria-label="Auto-approve resources"]');
const panel = () => document.body.querySelector('[data-testid="cloud-account-i-1"]');

it('default + success: links the account asset, shows the switch with its copy, and the last run per type', async () => {
  await render();
  const link = panel()!.querySelector('a');
  expect(link?.getAttribute('href')).toBe('/inventory/assets/acct-asset-1');
  expect(link?.textContent).toContain('210987654321');
  expect(sw()?.checked).toBe(true);
  expect(panel()!.textContent).toContain(AUTO_APPROVE_COPY);
  const outcomes = panel()!.querySelector('[data-testid="cloud-last-run-outcomes"]')!.textContent ?? '';
  expect(outcomes).toContain('S3 buckets');
  expect(outcomes).toContain('4 found');
  expect(outcomes).toContain('Could not collect'); // "could not look" is not "none"
});

it('persists the switch through PUT /integrations/{id}', async () => {
  await render();
  await act(async () => { sw()!.click(); });
  expect(mocks.put).toHaveBeenCalledTimes(1);
  expect(mocks.put.mock.calls[0][0]).toBe('/integrations/{id}');
  expect(mocks.put.mock.calls[0][1]).toMatchObject({ params: { path: { id: 'i-1' } }, body: { auto_approve_resources: false } });
  expect(sw()?.checked).toBe(false);
});

it('error: a failed save reverts the switch and says so', async () => {
  mocks.put.mockResolvedValue({ data: undefined, error: { error: 'nope' }, response: { ok: false, status: 500 } });
  await render();
  await act(async () => { sw()!.click(); });
  expect(sw()?.checked).toBe(true);
  expect(panel()!.querySelector('[role="alert"]')).not.toBeNull();
});

it('empty: no account asset yet, and never run', async () => {
  mocks.integrations.mockReturnValue(ok([{ ...integ, account_id: undefined, account_asset_id: undefined }]));
  mocks.jobs.mockReturnValue(ok({ jobs: [] }));
  await render();
  expect(panel()!.textContent).toContain('Account not known yet');
  expect(panel()!.textContent).toContain('Not run yet');
});

it('loading and error of the last run are distinct from an empty one', async () => {
  mocks.results.mockImplementation((id?: string | null) => (id ? { data: undefined, isLoading: true, isError: false } : ok(undefined)));
  await render();
  expect(panel()!.textContent).toContain('Loading the last run');

  mocks.results.mockImplementation((id?: string | null) => (id ? { data: undefined, isLoading: false, isError: true } : ok(undefined)));
  await render();
  expect(panel()!.querySelector('[role="alert"]')?.textContent).toContain('could not be loaded');
});
