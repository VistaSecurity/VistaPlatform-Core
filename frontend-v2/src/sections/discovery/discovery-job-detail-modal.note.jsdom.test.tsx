// @vitest-environment jsdom
//
// A scan job's `note` (why nothing was probed, which targets were dropped) is
// visible in the detail dialog and carried onto the jobs-list row. Drives the
// REAL modal: deleting the Note row turns it red.
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { DiscoveryJobDetailModal } from './discovery-job-detail-modal';
import { discoveryRow } from './unified-jobs';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

vi.mock('../../lib/clients', () => ({ clients: { inventory: { POST: vi.fn() } } }));
// The job's own read (useScanJob, which the modal polls while the job runs)
// returns nothing here: the row's snapshot is what the dialog shows.
vi.mock('./queries', () => ({
  useDiscoveryJobResults: () => ({ data: undefined, isLoading: false, isError: false }),
  useScanJob: () => ({ data: undefined, isLoading: false, isError: false }),
}));
vi.mock('@vistasecurity/primitives/rbac', () => ({
  PermissionGate: ({ children }: { children: ReactNode }) => <>{children}</>,
  TENANT_PERMISSIONS: { discovery: { update: 'discovery.update' } },
}));
vi.mock('../../components/ui', () => ({
  Modal: ({ children, secondary, footerNote }: { children: ReactNode; secondary?: ReactNode; footerNote?: ReactNode }) => (
    <div>
      {children}
      <footer>{secondary}{footerNote}</footer>
    </div>
  ),
}));

const NOTE = 'no active scanning requested; nothing probed';
const job = {
  id: '11111111-2222-3333-4444-555555555555',
  status: 'completed',
  execution_mode: 'async',
  targets: ['198.51.100.0/24'],
  created_at: '2026-10-01T10:00:00Z',
  note: NOTE,
} as unknown as NonNullable<Parameters<typeof DiscoveryJobDetailModal>[0]['job']>;

let host: HTMLDivElement;
let root: Root;
let cache: QueryClient;

beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  cache = new QueryClient();
});
afterEach(() => {
  act(() => root.unmount());
  cache.clear();
  host.remove();
});

async function renderModal(j: typeof job) {
  await act(async () => {
    root.render(
      <QueryClientProvider client={cache}>
        <DiscoveryJobDetailModal job={j} onClose={() => {}} />
      </QueryClientProvider>,
    );
  });
}

it('shows the job note in the Execution section', async () => {
  await renderModal(job);
  expect(host.textContent).toContain('Note');
  expect(host.textContent).toContain(NOTE);
});

it('shows no Note row when the job has none', async () => {
  await renderModal({ ...job, note: undefined } as typeof job);
  expect(host.textContent).not.toContain('Note');
});

it('carries the note onto the jobs-list row', () => {
  expect(discoveryRow(job).note).toBe(NOTE);
  expect(discoveryRow({ ...job, note: '' } as typeof job).note).toBeUndefined();
});
