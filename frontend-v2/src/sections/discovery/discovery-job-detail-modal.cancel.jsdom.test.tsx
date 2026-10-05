// @vitest-environment jsdom
//
// A refused Cancel says why. inventory-service now answers 409
// `job_not_cancellable` with the reason when the job already ended; this dialog
// used to swallow every failure silently. Drives the REAL modal, so deleting the
// footerNote render — or the jobActionError call — turns it red.
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { DiscoveryJobDetailModal } from './discovery-job-detail-modal';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ post: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: { POST: mocks.post } } }));
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

const job = {
  id: '11111111-2222-3333-4444-555555555555',
  status: 'running',
  execution_mode: 'async',
  targets: ['198.51.100.0/24'],
  created_at: '2026-10-01T10:00:00Z',
} as unknown as Parameters<typeof DiscoveryJobDetailModal>[0]['job'];

let host: HTMLDivElement;
let root: Root;
let cache: QueryClient;

beforeEach(() => {
  mocks.post.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
});
afterEach(() => {
  act(() => root.unmount());
  cache.clear();
  host.remove();
});

async function renderAndCancel() {
  await act(async () => {
    root.render(
      <QueryClientProvider client={cache}>
        <DiscoveryJobDetailModal job={job} onClose={() => {}} />
      </QueryClientProvider>,
    );
  });
  const cancel = Array.from(host.querySelectorAll('button')).find((b) => b.textContent === 'Cancel');
  expect(cancel).toBeTruthy();
  await act(async () => {
    cancel!.click();
  });
}

it("shows the server's reason when the cancel is refused, not a silent no-op", async () => {
  mocks.post.mockResolvedValue({ data: undefined, error: { error: 'job_not_cancellable', details: 'job already completed' } });
  await renderAndCancel();

  expect(mocks.post).toHaveBeenCalledWith('/discovery/jobs/{id}/cancel', { params: { path: { id: job!.id } } });
  // The mutation settles on a later tick than the click.
  await vi.waitFor(() => expect(host.querySelector('[role="alert"]')?.textContent).toBe('job already completed'));
});

it('shows no error when the cancel took effect', async () => {
  mocks.post.mockResolvedValue({ data: { message: 'Job cancelled' }, error: undefined });
  await renderAndCancel();
  await vi.waitFor(() => expect(mocks.post).toHaveBeenCalledTimes(1));
  await act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });

  expect(host.querySelector('[role="alert"]')).toBeNull();
});
