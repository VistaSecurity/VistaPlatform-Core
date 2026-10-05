// @vitest-environment jsdom
//
// Discovery → Discovery Jobs list ( WP4b), driven through the REAL page,
// query hooks and design-system Modal; only the HTTP client is a fake.
//
//   - a running scan-plan job's row shows a real progress bar and live line,
//     its executor and its depth; a legacy row shows none of that;
//   - a refused Cancel says why, in the server's words (it was silent);
//   - Resume scan is offered on a failed or queued scan only, explains what it
//     does, re-queues through the rerun route, and shows a 409/403 refusal;
//   - ?job=<id> opens that job's detail.
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { JobsPage } from './jobs-page';
import { RESUME_TOOLTIP } from './resume-scan-dialog';
import type { ScanJob } from './scan-job-state';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ invGet: vi.fn(), invPost: vi.fn(), devGet: vi.fn(), devPost: vi.fn() }));
vi.mock('../../lib/clients', () => ({
  clients: { inventory: { GET: mocks.invGet, POST: mocks.invPost }, devices: { GET: mocks.devGet, POST: mocks.devPost } },
}));
vi.mock('@vistasecurity/primitives/rbac', () => ({
  PermissionGate: ({ children }: { children: ReactNode }) => <>{children}</>,
  TENANT_PERMISSIONS: { discovery: { update: 'discovery.update', create: 'discovery.create' } },
}));

const PLAN = {
  depth: 'standard', pace: 'normal', tcp_ports: '1-1000', udp_ports: '', tcp_port_count: 1000, udp_port_count: 0,
  run_from_requested: 'auto', executor_resolved: 'platform', executor_reason: 'no sensor observes these targets', depth_adjustments: [],
  targets: [{ target: '10.0.0.0/24', class: 'private', depth: 'standard', addresses: 254, tcp_ports: '1-1000', udp_ports: '', tcp_port_count: 1000, udp_port_count: 0, estimated_probes: 254000 }],
  estimated_probes: 254000, probe_limit: 25000000,
} as NonNullable<ScanJob['plan']>;

const RUNNING = 'aaaaaaaa-0000-0000-0000-000000000001';
const FAILED = 'aaaaaaaa-0000-0000-0000-000000000002';
const DONE = 'aaaaaaaa-0000-0000-0000-000000000003';

const JOBS: ScanJob[] = [
  {
    id: RUNNING, status: 'running', execution_mode: 'async', executor: 'platform', created_at: '2026-10-02T10:04:00Z', plan: PLAN, progress: 44,
    coverage: {
      hosts_total: 254, hosts_responded: 31, hosts_no_answer: 81, hosts_undetermined: 0, hosts_failed: 0, hosts_pending: 142, hosts_cancelled: 0,
      ports_requested: 112000, ports_open: 9, ports_closed: 4120, ports_filtered: 61, ports_local_errors: 0, ports_not_probed: 0,
      tarpit_hosts: 0, ot_suspect_hosts: 0, udp_answered: 0, warnings: [],
    },
  },
  { id: FAILED, status: 'failed', execution_mode: 'async', executor: 'platform', created_at: '2026-10-02T10:03:00Z', plan: PLAN, progress: 0,
    error_message: 'scan stopped responding; no heartbeat since 2026-10-02T10:00:00Z — retry to resume' },
  { id: DONE, status: 'completed', execution_mode: 'async', executor: 'platform', created_at: '2026-10-02T10:02:00Z', plan: PLAN, progress: 0 },
  { id: 'aaaaaaaa-0000-0000-0000-000000000004', status: 'running', execution_mode: 'async', executor: 'platform', created_at: '2026-10-02T10:01:00Z', targets: ['10.9.9.9'], progress: 0 },
];

let host: HTMLDivElement;
let root: Root;
let cache: QueryClient;

beforeEach(() => {
  for (const m of Object.values(mocks)) m.mockReset();
  mocks.devGet.mockResolvedValue({ data: { jobs: [] }, error: undefined });
  mocks.invGet.mockImplementation((path: string, init: { params: { path?: { id: string } } }) => {
    if (path === '/discovery/jobs') return Promise.resolve({ data: { jobs: JOBS, total: JOBS.length, page: 1, page_size: 100 }, error: undefined });
    if (path === '/discovery/jobs/{id}') return Promise.resolve({ data: JOBS.find((j) => j.id === init.params.path?.id), error: undefined });
    if (path === '/discovery/jobs/{id}/results') return Promise.resolve({ data: { findings: [], hosts: [], total_hosts: 0 }, error: undefined });
    return Promise.resolve({ data: undefined, error: { error: 'unexpected' } });
  });
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

async function render(url = '/discovery/jobs') {
  await act(async () => {
    root.render(
      <MemoryRouter initialEntries={[url]}>
        <QueryClientProvider client={cache}>
          <JobsPage />
        </QueryClientProvider>
      </MemoryRouter>,
    );
  });
  await act(async () => {
    await new Promise((r) => setTimeout(r, 0));
  });
}

const buttonIn = (el: Element, label: string) => Array.from(el.querySelectorAll('button')).find((b) => b.getAttribute('aria-label') === label || b.textContent === label);

describe('rows', () => {
  it('a running scan shows a real progress bar, the live line, executor and depth', async () => {
    await render();
    const bar = host.querySelector(`[role="progressbar"]`)!;
    expect(bar.getAttribute('aria-valuenow')).toBe('44');
    expect(bar.textContent).toContain('44%');
    expect(bar.textContent).toContain('112 of 254 hosts · 31 responded · 9 open ports');
    const row = bar.closest('.row-hover')!;
    expect(row.textContent).toContain('Platform sensor');
    expect(row.textContent).toContain('Standard depth');
    expect(row.textContent).toContain('10.0.0.0/24');
    expect(row.textContent).toContain('Running');
  });

  it('only the running plan job has a bar; the legacy row reads as before', async () => {
    await render();
    expect(host.querySelectorAll('[role="progressbar"]')).toHaveLength(1);
    const legacy = Array.from(host.querySelectorAll('.row-hover')).find((r) => r.textContent?.includes('10.9.9.9'))!;
    expect(legacy.textContent).not.toContain('depth');
    expect(legacy.textContent).toContain('Running');
  });

  it("a failed scan says so in plain words, with the server's reason", async () => {
    await render();
    const failed = Array.from(host.querySelectorAll('.row-hover')).find((r) => r.textContent?.includes('Failed — stopped responding'))!;
    expect(failed.textContent).toContain('scan stopped responding; no heartbeat since 2026-10-02T10:00:00Z — retry to resume');
    const done = Array.from(host.querySelectorAll('.row-hover')).filter((r) => r.textContent?.includes('Finished'));
    expect(done).toHaveLength(1);
  });
});

describe('cancel', () => {
  it("shows the server's reason when the cancel is refused", async () => {
    mocks.invPost.mockResolvedValue({ data: undefined, error: { error: 'job_not_cancellable', details: 'job already completed' } });
    await render();
    const row = host.querySelector('[role="progressbar"]')!.closest('.row-hover')!;
    await act(async () => buttonIn(row, 'Cancel job')!.click());
    await vi.waitFor(() => expect(host.querySelector('[role="alert"]')?.textContent).toContain('job already completed'));
    expect(host.querySelector('[role="alert"]')!.textContent).toContain('Could not cancel job aaaaaaaa');
    expect(mocks.invPost).toHaveBeenCalledWith('/discovery/jobs/{id}/cancel', { params: { path: { id: RUNNING } } });
  });

  it('a cancel that worked shows no error and re-reads the list', async () => {
    mocks.invPost.mockResolvedValue({ data: { message: 'Job cancelled' }, error: undefined });
    await render();
    const listReads = mocks.invGet.mock.calls.filter(([p]) => p === '/discovery/jobs').length;
    const row = host.querySelector('[role="progressbar"]')!.closest('.row-hover')!;
    await act(async () => buttonIn(row, 'Cancel job')!.click());
    await vi.waitFor(() => expect(mocks.invGet.mock.calls.filter(([p]) => p === '/discovery/jobs').length).toBeGreaterThan(listReads));
    expect(host.querySelector('[role="alert"]')).toBeNull();
  });
});

describe('resume', () => {
  const resumeButtons = () => Array.from(host.querySelectorAll('button')).filter((b) => b.getAttribute('aria-label') === RESUME_TOOLTIP);

  it('is offered on the failed scan only — not on a finished or running one', async () => {
    await render();
    const buttons = resumeButtons();
    expect(buttons).toHaveLength(1);
    expect(buttons[0].closest('.row-hover')!.textContent).toContain('Failed — stopped responding');
    expect(buttons[0].title).toContain('finished hosts and their results are kept');
  });

  async function confirmResume() {
    await render();
    await act(async () => resumeButtons()[0].click());
    const dialog = host.querySelector('[role="dialog"][aria-label="Resume this scan?"]')!;
    expect(dialog.textContent).toContain('Only the hosts it had not finished are scanned again; hosts already finished, and what they found, are kept.');
    await act(async () => buttonIn(dialog, 'Resume scan')!.click());
    return dialog;
  }

  it('re-queues through the rerun route and closes', async () => {
    mocks.invPost.mockResolvedValue({ data: { message: 'Job rerun initiated' }, error: undefined });
    await confirmResume();
    expect(mocks.invPost).toHaveBeenCalledWith('/discovery/jobs/{id}/rerun', { params: { path: { id: FAILED } } });
    await vi.waitFor(() => expect(host.querySelector('[role="dialog"][aria-label="Resume this scan?"]')).toBeNull());
  });

  it.each([
    [409, { error: 'job_not_rerunnable', details: 'job can only be retried if status is queued or failed' }, 'job can only be retried if status is queued or failed'],
    [403, { error: 'forbidden', details: 'insufficient permissions: discovery.update required' }, 'insufficient permissions: discovery.update required'],
  ])('a %s refusal is shown in the server\'s words and the dialog stays open', async (_status, body, want) => {
    mocks.invPost.mockResolvedValue({ data: undefined, error: body });
    const dialog = await confirmResume();
    await vi.waitFor(() => expect(dialog.querySelector('[role="alert"]')?.textContent).toBe(want));
    expect(host.querySelector('[role="dialog"][aria-label="Resume this scan?"]')).not.toBeNull();
  });
});

describe('deep link', () => {
  it('?job=<id> opens that job\'s detail', async () => {
    await render(`/discovery/jobs?job=${FAILED}`);
    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });
    const dialog = host.querySelector('[role="dialog"]');
    expect(dialog?.textContent).toContain(`Job ${FAILED.slice(0, 8)}`);
    expect(dialog?.textContent).toContain('What this scan does');
  });
});

describe('list refresh', () => {
  const listReads = () => mocks.invGet.mock.calls.filter(([p]) => p === '/discovery/jobs').length;

  it('re-reads every 5 s while a job is unfinished, and not at all once every job has ended', async () => {
    vi.useFakeTimers();
    try {
      await act(async () => {
        root.render(
          <MemoryRouter initialEntries={['/discovery/jobs']}>
            <QueryClientProvider client={cache}>
              <JobsPage />
            </QueryClientProvider>
          </MemoryRouter>,
        );
      });
      await act(async () => { await vi.advanceTimersByTimeAsync(100); });
      const first = listReads();
      await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
      expect(listReads()).toBe(first + 1);

      // Everything settles: the next read shows it, and the polling stops.
      const ended = JOBS.map((j) => ({ ...j, status: 'completed' }));
      mocks.invGet.mockImplementation((path: string) =>
        Promise.resolve(path === '/discovery/jobs' ? { data: { jobs: ended, total: ended.length, page: 1, page_size: 100 }, error: undefined } : { data: undefined, error: { error: 'unexpected' } }),
      );
      await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
      const settled = listReads();
      await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
      expect(listReads()).toBe(settled);
    } finally {
      vi.useRealTimers();
    }
  });
});
