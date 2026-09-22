// @vitest-environment jsdom
//
// The consumer half of slice E. A recorded outcome that nothing renders
// is not done (CLAUDE.md's reachability rule), and these drive the REAL modal:
// deleting the <ResourceTypes/> block from job-detail-modal.tsx turns them red.
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { JobDetailModal } from './job-detail-modal';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

// Typed at the seam: vi.fn() is `any`, and returning it straight out of the
// mocked hook makes every downstream read unchecked.
type JobResultsQuery = { data: unknown; isLoading: boolean; isError: boolean };
const mocks = vi.hoisted(() => ({ results: vi.fn() }));
vi.mock('./queries', () => ({ useJobResults: (): JobResultsQuery => mocks.results() as JobResultsQuery }));
vi.mock('../../components/ui', () => ({
  Modal: ({ children }: { children: ReactNode }) => <div>{children}</div>,
}));

const job = {
  id: '11111111-2222-3333-4444-555555555555',
  tenant_id: '99999999-8888-7777-6666-555555555555',
  job_type: 'cloud_discovery',
  status: 'completed',
  integration_name: 'aws-prod',
  cloud_provider: 'aws',
  executor: 'Platform Agent',
  created_at: '2026-09-21T10:00:00Z',
  updated_at: '2026-09-21T10:05:00Z',
} as unknown as Parameters<typeof JobDetailModal>[0]['job'];

// The demo-host run from the spec's evidence, with KMS denied.
const cloudResults = {
  job_id: job!.id,
  status: 'completed',
  success: false,
  assets: [],
  summary: { total_assets: 0, with_crypto: 0, with_certificates: 0 },
  outcome: 'partial',
  resource_types: [
    { resource_type: 's3', status: 'succeeded', found: 4, scopes_succeeded: 1, scopes_attempted: 1 },
    { resource_type: 'rds', status: 'succeeded', found: 0, scopes_succeeded: 1, scopes_attempted: 1 },
    {
      resource_type: 'kms',
      status: 'failed',
      found: 0,
      scopes_succeeded: 0,
      scopes_attempted: 1,
      failures: [
        {
          scope: 'us-east-1',
          reason: 'access_denied',
          code: 'AccessDeniedException',
          message: 'User: arn:aws:iam::123456789012:user/discovery is not authorized to perform: kms:ListKeys',
        },
      ],
    },
  ],
};

let host: HTMLDivElement;
let root: Root;
let cache: QueryClient;

beforeEach(() => {
  mocks.results.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});
afterEach(() => {
  act(() => root.unmount());
  cache.clear();
  host.remove();
});

async function render(data: unknown) {
  mocks.results.mockReturnValue({ data, isLoading: false, isError: false });
  await act(async () => {
    root.render(
      <QueryClientProvider client={cache}>
        <JobDetailModal job={job} onClose={() => {}} />
      </QueryClientProvider>,
    );
  });
  return host.textContent ?? '';
}

it('shows a denied resource type as not measured, and an empty one as none', async () => {
  const text = await render(cloudResults);

  // The type that was read and found nothing.
  expect(text).toContain('RDS instances');
  expect(text).toContain('None in this account');

  // The type that could not be read — and it must NOT read as a zero.
  expect(text).toContain('KMS keys');
  expect(text).toContain('Could not collect');
  expect(text).toContain('Not measured');

  // The provider's own words, so the user knows which permission is missing.
  expect(text).toContain('AccessDeniedException');
  expect(text).toContain('kms:ListKeys');
  expect(text).toContain('us-east-1');

  // And what to do about it.
  expect(text).toMatch(/grant the missing read permission/i);

  // The run verdict, not a bare "completed".
  expect(text).toContain('Collected in part');
});

it('renders nothing about resource types for a job that reported none', async () => {
  const text = await render({
    job_id: job!.id,
    status: 'completed',
    success: true,
    assets: [],
    summary: { total_assets: 0, with_crypto: 0, with_certificates: 0 },
  });
  // Absent means "not reported" — the modal must not invent a verdict.
  expect(text).not.toContain('Resource types');
  expect(text).not.toContain('Everything requested was collected');
});

it('surfaces why account enumeration did not run', async () => {
  const text = await render({
    ...cloudResults,
    enumeration_skipped: 'enumerate_compute is off for this integration',
  });
  expect(text).toContain('enumerate_compute is off for this integration');
});

it('says a zero is a real zero when every type was collected', async () => {
  const text = await render({
    ...cloudResults,
    success: true,
    outcome: 'complete',
    resource_types: [{ resource_type: 'kms', status: 'succeeded', found: 0, scopes_succeeded: 1, scopes_attempted: 1 }],
  });
  expect(text).toMatch(/genuinely has none/i);
  expect(text).toContain('None in this account');
  expect(text).not.toContain('Could not collect');
});
