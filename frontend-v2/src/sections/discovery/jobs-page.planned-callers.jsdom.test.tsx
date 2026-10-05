// @vitest-environment jsdom
//
// Discovery → Discovery Jobs list ( WP4): automatic scans and identity
// checks now arrive as PLANNED jobs (a custom-depth plan on their ports, often
// run from a tenant sensor). Their rows render through the real page and
// hooks — only the HTTP client is a fake — with the plan's executor, depth and
// a progress bar while running, and the automatic one keeps its kind.
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { JobsPage } from './jobs-page';
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

const plan = (target: string) => ({
  depth: 'custom', pace: 'normal', tcp_ports: '22,443', udp_ports: '', tcp_port_count: 2, udp_port_count: 0,
  run_from_requested: 'sensor', executor_resolved: 'sensor', executor_reason: 'the sensor you chose', sensor_id: 'edge', depth_adjustments: [],
  targets: [{ target, class: 'private', depth: 'custom', addresses: 1, tcp_ports: '22,443', udp_ports: '', tcp_port_count: 2, udp_port_count: 0, estimated_probes: 2 }],
  estimated_probes: 2, probe_limit: 25000000,
}) as NonNullable<ScanJob['plan']>;

const coverage = {
  hosts_total: 1, hosts_responded: 0, hosts_no_answer: 0, hosts_undetermined: 0, hosts_failed: 0, hosts_pending: 1, hosts_cancelled: 0,
  ports_requested: 2, ports_open: 0, ports_closed: 0, ports_filtered: 0, ports_local_errors: 0, ports_not_probed: 0,
  tarpit_hosts: 0, ot_suspect_hosts: 0, udp_answered: 0, warnings: [],
};

const JOBS: ScanJob[] = [
  { id: 'bbbbbbbb-0000-0000-0000-000000000001', origin: 'auto_scan', status: 'running', execution_mode: 'sensors', executor: 'sensor', assigned_sensor_name: 'edge-sensor',
    created_at: '2026-10-04T10:04:00Z', plan: plan('10.0.0.41'), progress: 10, coverage },
  { id: 'bbbbbbbb-0000-0000-0000-000000000002', origin: 'identity_enrichment', status: 'completed', execution_mode: 'sensors', executor: 'sensor', assigned_sensor_name: 'edge-sensor',
    created_at: '2026-10-04T10:03:00Z', plan: plan('10.0.0.42'), progress: 100 },
];

let host: HTMLDivElement;
let root: Root;
let cache: QueryClient;

beforeEach(() => {
  for (const m of Object.values(mocks)) m.mockReset();
  mocks.devGet.mockResolvedValue({ data: { jobs: [] }, error: undefined });
  mocks.invGet.mockImplementation((path: string) => {
    if (path === '/discovery/jobs') return Promise.resolve({ data: { jobs: JOBS, total: JOBS.length, page: 1, page_size: 100 }, error: undefined });
    return Promise.resolve({ data: { findings: [], hosts: [], total_hosts: 0 }, error: undefined });
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

async function render() {
  await act(async () => {
    root.render(
      <MemoryRouter initialEntries={['/discovery/jobs']}>
        <QueryClientProvider client={cache}>
          <JobsPage />
        </QueryClientProvider>
      </MemoryRouter>,
    );
  });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
}

describe('planned automatic and identity jobs in the list', () => {
  it('renders both rows with their executor, and a bar for the running one', async () => {
    await render();
    const rows = Array.from(host.querySelectorAll('.row-hover'));
    const auto = rows.find((r) => r.textContent?.includes('10.0.0.41'));
    const identity = rows.find((r) => r.textContent?.includes('10.0.0.42'));
    expect(auto, 'the automatic scan row').toBeTruthy();
    expect(identity, 'the identity check row').toBeTruthy();
    expect(auto!.textContent).toContain('edge-sensor');
    expect(auto!.querySelector('[role="progressbar"]')).toBeTruthy();
    expect(identity!.textContent).toContain('Custom depth');
    expect(identity!.textContent).toContain('Finished');
  });
});
