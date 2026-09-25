// @vitest-environment jsdom
//
// The consumer half of W0.1: collection warnings recorded on a job must be
// visible in its detail. These drive the REAL modal, so deleting either
// <CollectionWarnings/> render in job-detail-modal.tsx turns them red.
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { JobDetailModal } from './job-detail-modal';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

type JobResultsQuery = { data: unknown; isLoading: boolean; isError: boolean };
const mocks = vi.hoisted(() => ({ results: vi.fn() }));
vi.mock('./queries', () => ({ useJobResults: (): JobResultsQuery => mocks.results() as JobResultsQuery }));
vi.mock('../../components/ui', () => ({
  Modal: ({ children }: { children: ReactNode }) => <div>{children}</div>,
}));

const job = {
  id: '11111111-2222-3333-4444-555555555555',
  tenant_id: '99999999-8888-7777-6666-555555555555',
  job_type: 'device_interrogation',
  status: 'completed',
  device_name: 'fw-branch-01',
  device_type: 'fortigate',
  executor: 'Platform Agent',
  created_at: '2026-09-21T10:00:00Z',
  updated_at: '2026-09-21T10:05:00Z',
} as unknown as Parameters<typeof JobDetailModal>[0]['job'];

const results = (extra: Record<string, unknown>) => ({
  job_id: job!.id,
  status: 'completed',
  success: true,
  assets: [],
  summary: { total_assets: 0, with_crypto: 0, with_certificates: 0, materialized: 0 },
  processing: { assets_received: 0, findings_created: 0, discoveries_written: 0, fully_materialized: true },
  ...extra,
});

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

async function render(query: JobResultsQuery) {
  mocks.results.mockReturnValue(query);
  await act(async () => {
    root.render(
      <QueryClientProvider client={cache}>
        <JobDetailModal job={job} onClose={() => {}} />
      </QueryClientProvider>,
    );
  });
  return host.textContent ?? '';
}

it('lists each warning: the endpoint or command, the reason, and what is missing', async () => {
  const text = await render({
    data: results({
      collection_warnings: [
        {
          collector: 'fortinet',
          endpoint: '/api/v2/cmdb/system/interface',
          reason: 'permission_denied',
          effect: 'Configured interfaces and VLANs not collected',
          detail: 'API returned status 403',
        },
        {
          collector: 'cisco',
          endpoint: 'show ip arp',
          reason: 'truncated',
          effect: 'Output cut at 262144 bytes; the facts derived from it are partial',
        },
      ],
    }),
    isLoading: false,
    isError: false,
  });

  expect(text).toContain('Collection warnings');
  expect(host.querySelectorAll('[aria-label="Collection warnings"] [role="listitem"]')).toHaveLength(2);
  expect(text).toContain('/api/v2/cmdb/system/interface');
  expect(text).toContain('Permission denied');
  expect(text).toContain('Configured interfaces and VLANs not collected');
  expect(text).toContain('show ip arp');
  expect(text).toContain('Truncated');
  // The raw reason key is a label, not the text a user reads.
  expect(text).not.toContain('permission_denied');
});

// Past the platform's cap the list ends with one entry counting the rest, so a
// capped list never reads as the whole one.
it('shows the overflow entry that counts warnings past the cap', async () => {
  const text = await render({
    data: results({
      collection_warnings: [
        { collector: 'cisco', endpoint: 'show vlan brief', reason: 'error', effect: 'VLANs not collected' },
        { collector: 'cisco', endpoint: '(further warnings)', reason: 'truncated', effect: '12 more warnings not shown' },
      ],
    }),
    isLoading: false,
    isError: false,
  });
  expect(host.querySelectorAll('[aria-label="Collection warnings"] [role="listitem"]')).toHaveLength(2);
  expect(text).toContain('12 more warnings not shown');
});

it('shows no warnings section for a run that raised none', async () => {
  const text = await render({ data: results({}), isLoading: false, isError: false });
  expect(text).toContain('Pipeline'); // the processing area rendered…
  expect(text).not.toContain('Collection warnings'); // …without a warnings section
});

it('inherits the job detail loading state rather than claiming there are none', async () => {
  const text = await render({ data: undefined, isLoading: true, isError: false });
  expect(text).toContain('Loading results');
  expect(text).not.toContain('Collection warnings');
});

it('says the warnings could not be loaded when the results failed', async () => {
  const text = await render({ data: undefined, isLoading: false, isError: true });
  expect(text).toContain('Collection warnings');
  expect(text).toContain('Warnings could not be loaded');
});

it('says the warnings could not be loaded when the stored list was unreadable', async () => {
  const text = await render({ data: results({ collection_warnings_unreadable: true }), isLoading: false, isError: false });
  expect(text).toContain('Warnings could not be loaded');
});
