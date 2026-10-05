// @vitest-environment jsdom
//
// The Discovery Jobs detail for a scan-plan job ( WP4b), driven through
// the REAL modal, the REAL query hooks and the REAL design-system Modal — only
// the HTTP client is a fake. Each test is one row of the spec's screen-state
// table ("Job detail — coverage", "Job detail — results") or one honesty rule:
// "no answer" is never "down", nothing-answered gives reachability guidance, an
// early stop says why, an unidentified port is shown, a tarpit host is one
// line, results page by host, polling stops when the job ends, and a legacy
// job keeps its old sections.
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DiscoveryJobDetailModal } from './discovery-job-detail-modal';
import type { ScanJob } from './scan-job-state';
import type { JobCoverage, ScanHost } from './scan-plan-view';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: { GET: mocks.get, POST: mocks.post } } }));
vi.mock('@vistasecurity/primitives/rbac', () => ({
  PermissionGate: ({ children }: { children: ReactNode }) => <>{children}</>,
  TENANT_PERMISSIONS: { discovery: { update: 'discovery.update', create: 'discovery.create' } },
}));

const JOB_ID = '11111111-2222-3333-4444-555555555555';

const PLAN = {
  depth: 'thorough',
  pace: 'normal',
  tcp_ports: '1-65535',
  udp_ports: '53,123,161',
  tcp_port_count: 65535,
  udp_port_count: 3,
  run_from_requested: 'auto',
  executor_resolved: 'platform',
  executor_reason: 'no sensor observes these targets',
  depth_adjustments: [
    { target: '203.0.113.5', requested: 'thorough', applied: 'standard', reason: 'outside your registered networks: Standard is the deepest scan allowed; register the range if it is yours' },
    { target: '203.0.113.9', requested: 'thorough', applied: 'standard', reason: 'outside your registered networks: Standard is the deepest scan allowed; register the range if it is yours' },
  ],
  targets: [{ target: '10.0.0.0/24', class: 'private', depth: 'thorough', addresses: 254, tcp_ports: '1-65535', udp_ports: '53,123,161', tcp_port_count: 65535, udp_port_count: 3, estimated_probes: 1 }],
  estimated_probes: 1,
  probe_limit: 25000000,
} as NonNullable<ScanJob['plan']>;

function cov(over: Partial<JobCoverage> = {}): JobCoverage {
  return {
    hosts_total: 254, hosts_responded: 31, hosts_no_answer: 81, hosts_undetermined: 0, hosts_failed: 0, hosts_pending: 142, hosts_cancelled: 0,
    ports_requested: 1000, ports_open: 9, ports_closed: 4120, ports_filtered: 61, ports_local_errors: 0, ports_not_probed: 0,
    tarpit_hosts: 1, ot_suspect_hosts: 0, udp_answered: 2, warnings: [], ...over,
  };
}

const HOSTS: ScanHost[] = [
  {
    address: '10.0.0.5',
    hostname: 'mail.example.internal',
    unit: { status: 'done', liveness_state: 'up', ports_requested: 65535, open_count: 3, closed_count: 1, filtered_count: 0, not_probed_count: 0, responds_on_all_ports: false, ot_suspect: false },
    ports: [
      { finding_id: 'f1', port: 25, protocol: 'tcp', transport: 'tcp', identified: false, service_hint: 'smtp', confidence_score: 0.5, data: { transport: 'tcp', unidentified: true, service_hint: 'smtp', banner_len: 40 } },
      { finding_id: 'f2', port: 443, protocol: 'TLS', transport: 'tcp', identified: true, confidence_score: 0.9, data: { transport: 'tcp', version: 'TLS 1.3', cipher_suite: 'TLS_AES_128_GCM_SHA256', certificates: [{ subject: 'CN=mail', chain_order: 0 }] } },
      { finding_id: 'f3', port: 53, protocol: 'DNS', transport: 'udp', identified: true, confidence_score: 0.9, data: { transport: 'udp' } },
      { finding_id: 'f4', port: 9999, protocol: 'tcp', transport: 'tcp', identified: false, confidence_score: 0.5, data: { transport: 'tcp', unidentified: true } },
    ],
  },
  {
    address: '10.0.0.9',
    unit: { status: 'done', liveness_state: 'up', ports_requested: 65535, open_count: 60000, closed_count: 0, filtered_count: 0, not_probed_count: 0, responds_on_all_ports: true, ot_suspect: false },
    ports: [{ finding_id: 'f9', port: 1, protocol: 'tcp', transport: 'tcp', identified: false, confidence_score: 0.5, data: { transport: 'tcp', responds_on_all_ports: true, open_sample: Array.from({ length: 32 }, (_, i) => 1000 + i), open_count: 60000 } }],
  },
];

interface Server {
  job: ScanJob;
  hosts?: ScanHost[];
  /** Hosts per page, by page number — overrides `hosts` when set. */
  pages?: Record<number, ScanHost[]>;
  materialization?: Record<string, number>;
  totalHosts?: number;
  hostsError?: boolean;
  hostsPending?: boolean;
}

let server: Server;

function install() {
  mocks.get.mockImplementation((path: string, init: { params: { query?: { group?: string; page?: number } } }) => {
    if (path === '/discovery/jobs/{id}') return Promise.resolve({ data: server.job, error: undefined });
    if (path === '/discovery/jobs/{id}/results' && init.params.query?.group === 'host') {
      if (server.hostsPending) return new Promise(() => {});
      if (server.hostsError) return Promise.resolve({ data: undefined, error: { error: 'failed to read results' } });
      const page = init.params.query.page ?? 1;
      const hosts = server.pages ? (server.pages[page] ?? []) : (server.hosts ?? []);
      return Promise.resolve({ data: { job_id: JOB_ID, group: 'host', hosts, total_hosts: server.totalHosts ?? hosts.length, page, page_size: 25 }, error: undefined });
    }
    if (path === '/discovery/jobs/{id}/results') {
      const materialization = server.materialization ?? { findings: 7, queued: 7, auto_approved: 2, pending_approval: 5, awaiting_processing: 0 };
      return Promise.resolve({ data: { findings: [], materialization }, error: undefined });
    }
    return Promise.resolve({ data: undefined, error: { error: 'unexpected' } });
  });
}

function planJob(over: Partial<ScanJob> = {}): ScanJob {
  return { id: JOB_ID, status: 'running', execution_mode: 'async', executor: 'platform', created_at: '2026-10-02T10:00:00Z', plan: PLAN, progress: 44, coverage: cov(), ...over };
}

let host: HTMLDivElement;
let root: Root;
let cache: QueryClient;

beforeEach(() => {
  mocks.get.mockReset();
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
  vi.useRealTimers();
});

async function open(listed: ScanJob, s: Partial<Server> = {}) {
  server = { job: listed, hosts: HOSTS, ...s };
  install();
  await act(async () => {
    root.render(
      <MemoryRouter>
        <QueryClientProvider client={cache}>
          <DiscoveryJobDetailModal job={listed} onClose={() => {}} />
        </QueryClientProvider>
      </MemoryRouter>,
    );
  });
  await settle();
}

async function settle() {
  await act(async () => {
    await new Promise((r) => setTimeout(r, 0));
  });
  await act(async () => {
    await new Promise((r) => setTimeout(r, 0));
  });
}

const text = () => document.body.textContent ?? '';
const section = (title: string) => Array.from(document.querySelectorAll('section')).find((s) => s.querySelector('h3')?.textContent === title);
const hostCalls = () => mocks.get.mock.calls.filter(([p, i]) => p === '/discovery/jobs/{id}/results' && (i as { params: { query?: { group?: string } } }).params.query?.group === 'host');
const jobCalls = () => mocks.get.mock.calls.filter(([p]) => p === '/discovery/jobs/{id}');

describe('plan summary', () => {
  it('shows progress, depth, pace, targets, where it ran and why, and every depth adjustment', async () => {
    await open(planJob());
    const bar = document.querySelector('[role="progressbar"][aria-label="Scan progress"]');
    expect(bar?.getAttribute('aria-valuenow')).toBe('44');
    expect(bar?.textContent).toContain('44% · 112 of 254 hosts');
    const plan = section('What this scan does')!;
    expect(plan.textContent).toContain('Thorough · Normal pace');
    expect(plan.textContent).toContain('Platform sensor — you chose Auto; no sensor observes these targets');
    expect(plan.textContent).toContain('10.0.0.0/24');
    expect(plan.textContent).toContain(
      '2 targets were scanned at Standard depth instead of Thorough — outside your registered networks: Standard is the deepest scan allowed; register the range if it is yours',
    );
    expect(plan.textContent).toContain('203.0.113.5, 203.0.113.9');
  });
});

describe('coverage', () => {
  it('reports responded and no answer — never "down" or "empty"', async () => {
    await open(planJob());
    const c = section('Coverage')!;
    expect(c.textContent).toContain('254 addresses · 31 responded · 81 no answer · 142 still to scan');
    expect(c.textContent).toContain('Ports: 9 open · 4,120 closed · 61 filtered');
    expect(c.textContent).toContain('UDP services answered: 2');
    expect(c.textContent).toContain('Hosts answering on every port: 1');
    expect(c.textContent).not.toMatch(/\bdown\b|\bempty\b/i);
  });

  it('nothing answered → reachability guidance with the run-from facts, and the server line is not repeated', async () => {
    const silent = cov({ hosts_responded: 0, hosts_no_answer: 254, hosts_pending: 0, ports_open: 0, tarpit_hosts: 0, udp_answered: 0,
      warnings: ['0 of 254 scanned addresses responded — the platform sensor may not be able to reach this network; run the scan from a sensor on that network'] });
    await open(planJob({ status: 'completed', progress: 100, coverage: silent }), { hosts: [] });
    const c = section('Coverage')!;
    expect(c.textContent).toContain(
      'Nothing answered. The Platform sensor may not be able to reach this network — run the scan from a sensor on that network, or check that the addresses are right.',
    );
    expect(c.textContent).toContain('Ran from Platform sensor (you chose Auto) — no sensor observes these targets.');
    expect(c.textContent).not.toContain('0 of 254 scanned addresses responded');
    expect(section('Results by host')!.textContent).toContain('No host answered.');
  });

  it('a partial run says where it stopped and why', async () => {
    const stopped = cov({ hosts_pending: 0, hosts_cancelled: 142, warnings: ['stopped at 112 of 254 hosts: the scan was cancelled', 'scanner resource limits were hit'] });
    await open(planJob({ status: 'cancelled', coverage: stopped }));
    const c = section('Coverage')!;
    expect(c.textContent).toContain('Stopped at 112 of 254 hosts — the scan was cancelled.');
    expect(c.textContent).not.toContain('stopped at 112 of 254 hosts: the scan was cancelled');
    expect(c.querySelector('[aria-label="Scan warnings"]')?.textContent).toContain('scanner resource limits were hit');
  });

  it("a failed scan shows the server's failure text", async () => {
    const msg = 'scan stopped responding; no heartbeat since 2026-10-02T10:00:00Z — retry to resume';
    await open(planJob({ status: 'failed', error_message: msg, coverage: cov({ hosts_pending: 142 }) }));
    expect(text()).toContain(msg);
    expect(text()).toContain('Failed — stopped responding');
    expect(section('Coverage')!.textContent).toContain('Stopped at 112 of 254 hosts — the scan stopped responding');
  });

  it('loading: a skeleton until the job read lands; then the numbers', async () => {
    server = { job: planJob(), hosts: HOSTS };
    install();
    let release: (v: unknown) => void = () => {};
    mocks.get.mockImplementationOnce(() => new Promise((r) => { release = r; }));
    await act(async () => {
      root.render(
        <MemoryRouter>
          <QueryClientProvider client={cache}>
            <DiscoveryJobDetailModal job={planJob({ coverage: undefined })} onClose={() => {}} />
          </QueryClientProvider>
        </MemoryRouter>,
      );
    });
    expect(section('Coverage')!.querySelector('[aria-busy="true"][aria-label="Loading coverage"]')).not.toBeNull();
    await act(async () => release({ data: planJob(), error: undefined }));
    await settle();
    expect(section('Coverage')!.textContent).toContain('254 addresses');
  });

  it('a scan run on a tenant sensor says coverage by host is not reported for it', async () => {
    const sensorPlan = { ...PLAN, executor_resolved: 'sensor' as const, sensor_name: 'edge-a' };
    await open(planJob({ plan: sensorPlan, coverage: undefined, executor: 'sensor' }));
    expect(section('Coverage')!.textContent).toContain('this one runs on edge-a');
  });
});

describe('results by host', () => {
  it('lists hosts collapsed; expanding shows ports with the unidentified label, its hint and the UDP row', async () => {
    await open(planJob());
    const r = section('Results by host')!;
    expect(r.textContent).toContain('2 hosts so far');
    const toggle = Array.from(r.querySelectorAll('button[aria-expanded]')).find((b) => b.textContent?.includes('10.0.0.5'))!;
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    expect(toggle.textContent).toContain('4 open ports');
    expect(toggle.textContent).toContain('Answered');
    expect(r.querySelector('table')).toBeNull();

    await act(async () => (toggle as HTMLButtonElement).click());
    expect(toggle.getAttribute('aria-expanded')).toBe('true');
    const rows = Array.from(r.querySelectorAll('tbody tr')).map((tr) => tr.textContent);
    expect(rows).toContain('25TCPopen, unidentified (looks like smtp)');
    expect(rows).toContain('9999TCPopen, unidentified');
    expect(rows.some((t) => t?.startsWith('53UDPDNS'))).toBe(true);
    expect(rows.some((t) => t?.startsWith('443TCPTLS'))).toBe(true);

    // The TLS port's certificate/cipher detail is the Discover wizard's.
    const detail = Array.from(r.querySelectorAll('tbody button')).find((b) => b.textContent === 'Detail')!;
    await act(async () => (detail as HTMLButtonElement).click());
    expect(r.textContent).toContain('TLS_AES_128_GCM_SHA256');

    await act(async () => (toggle as HTMLButtonElement).click());
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    expect(r.querySelector('table')).toBeNull();
  });

  it('a host that answers on every port is one line with a bounded sample, not a port per row', async () => {
    await open(planJob());
    const tarpit = document.querySelector('[data-testid="tarpit-host"]')!;
    expect(tarpit.textContent).toContain('10.0.0.9 — answers on every port — probably a firewall or proxy; showing 8 sample ports: 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007');
    expect(tarpit.textContent).not.toContain('1008');
    expect(tarpit.querySelector('button, table')).toBeNull();
  });

  it('pages by host with a pager, never loading every row', async () => {
    await open(planJob(), { totalHosts: 60 });
    const r = section('Results by host')!;
    expect(r.textContent).toContain('Hosts 1–2 of 60');
    expect(hostCalls()[0][1]).toMatchObject({ params: { query: { group: 'host', page: 1, page_size: 25 } } });
    const next = Array.from(r.querySelectorAll('button')).find((b) => b.textContent === 'Next')!;
    const prev = Array.from(r.querySelectorAll('button')).find((b) => b.textContent === 'Previous')!;
    expect(prev.disabled).toBe(true);
    await act(async () => next.click());
    await settle();
    expect(hostCalls().some(([, i]) => (i as { params: { query: { page: number } } }).params.query.page === 2)).toBe(true);
  });

  //: a /24 answered "25 responded" and the list showed 10 — the 15
  // hosts that refused every port were only a grey count, and the person read
  // the pager as broken. Every responder is listed now; a quiet one is one
  // secondary line, in address order among the others.
  it('lists a host that answered with nothing open as one line, among the others, with no separate note', async () => {
    const quiet: ScanHost = {
      address: '10.0.0.7', nothing_open: true, ports: [],
      unit: { status: 'done', liveness_state: 'up', liveness_evidence: 'tcp-refused:22', ports_requested: 78, open_count: 0, closed_count: 78, filtered_count: 0, not_probed_count: 0, responds_on_all_ports: false, ot_suspect: false },
    };
    await open(planJob({ coverage: cov({ hosts_responded: 3 }) }), { hosts: [HOSTS[0], quiet, HOSTS[1]] });
    const r = section('Results by host')!;
    expect(r.textContent).toContain('3 hosts so far');
    const items = Array.from(r.querySelectorAll('ul[aria-label="Hosts that answered"] > li'));
    expect(items).toHaveLength(3);
    expect(items[1].textContent).toBe('10.0.0.7 — answered, nothing open (78 ports scanned: all refused)');
    expect(items[1].getAttribute('data-testid')).toBe('quiet-host');
    expect(items[1].querySelector('button, table')).toBeNull();
    expect(r.textContent).not.toMatch(/counted under Coverage|not listed here/);
    expect(r.textContent).not.toMatch(/\bdown\b/i);
  });

  it('25 responders — 10 with open ports, 15 quiet — fill one page of 25 and the pager says so', async () => {
    const withPorts = Array.from({ length: 10 }, (_, i): ScanHost => ({ ...HOSTS[0], address: `10.0.0.${i * 2 + 1}`, hostname: undefined }));
    const quiet = Array.from({ length: 15 }, (_, i): ScanHost => ({ address: `10.0.0.${100 + i}`, nothing_open: true, ports: [] }));
    await open(planJob({ status: 'completed', progress: 100, coverage: cov({ hosts_pending: 0, hosts_responded: 25 }) }), { hosts: [...withPorts, ...quiet] });
    const r = section('Results by host')!;
    expect(r.textContent).toContain('25 hosts');
    expect(r.textContent).toContain('Hosts 1–25 of 25');
    expect(r.querySelectorAll('[data-testid="quiet-host"]')).toHaveLength(15);
    expect(r.querySelectorAll('li > button[aria-expanded]')).toHaveLength(10);
    expect((Array.from(r.querySelectorAll('button')).find((b) => b.textContent === 'Next') as HTMLButtonElement).disabled).toBe(true);
  });

  it('pages a responder list longer than one page, quiet hosts included', async () => {
    const page1 = Array.from({ length: 25 }, (_, i): ScanHost => (i % 2 ? { address: `10.0.1.${i + 1}`, nothing_open: true, ports: [] } : { ...HOSTS[0], address: `10.0.1.${i + 1}`, hostname: undefined }));
    const page2 = Array.from({ length: 5 }, (_, i): ScanHost => ({ address: `10.0.1.${26 + i}`, nothing_open: true, ports: [] }));
    await open(planJob({ status: 'completed', progress: 100, coverage: cov({ hosts_pending: 0, hosts_responded: 30 }) }), { pages: { 1: page1, 2: page2 }, totalHosts: 30 });
    const r = () => section('Results by host')!;
    expect(r().textContent).toContain('Hosts 1–25 of 30');
    const button = (label: string) => Array.from(r().querySelectorAll('button')).find((b) => b.textContent === label) as HTMLButtonElement;
    expect(button('Next').disabled).toBe(false);
    await act(async () => button('Next').click());
    await settle();
    expect(r().textContent).toContain('Hosts 26–30 of 30');
    expect(r().querySelectorAll('[data-testid="quiet-host"]')).toHaveLength(5);
    expect(button('Next').disabled).toBe(true);
    expect(button('Previous').disabled).toBe(false);
  });

  it('empty while running vs empty when finished', async () => {
    await open(planJob(), { hosts: [] });
    expect(section('Results by host')!.textContent).toContain('No host has answered yet');
    act(() => root.unmount());
    root = createRoot(host);
    cache.clear();
    await open(planJob({ status: 'completed', progress: 100, coverage: cov({ hosts_pending: 0, hosts_no_answer: 223 }) }), { hosts: [] });
    expect(section('Results by host')!.textContent).toContain('No listening ports were found on the hosts that answered.');
  });

  it('loading shows a skeleton; an error offers Retry, which reads again', async () => {
    await open(planJob(), { hostsPending: true });
    expect(section('Results by host')!.querySelector('[aria-busy="true"][aria-label="Loading results"]')).not.toBeNull();
    act(() => root.unmount());
    root = createRoot(host);
    cache.clear();

    await open(planJob({ status: 'completed' }), { hostsError: true });
    const r = section('Results by host')!;
    expect(r.querySelector('[role="alert"]')?.textContent).toContain("Could not load this scan's results.");
    const before = hostCalls().length;
    server.hostsError = false;
    await act(async () => (Array.from(r.querySelectorAll('button')).find((b) => b.textContent === 'Retry') as HTMLButtonElement).click());
    await settle();
    expect(hostCalls().length).toBe(before + 1);
    expect(section('Results by host')!.textContent).toContain('10.0.0.5');
  });
});

describe('findings summary', () => {
  it('keeps where the findings went, with the way to Approvals', async () => {
    await open(planJob({ status: 'completed' }));
    const link = Array.from(document.querySelectorAll('a')).find((a) => a.textContent === 'Approvals');
    expect(link?.getAttribute('href')).toBe('/discovery/approvals');
    expect(text()).toContain('2 auto-approved');
    expect(text()).toContain('5 awaiting approval');
  });

  //: "Found 15" read as fifteen new assets. The count is open ports,
  // and says on how many hosts; the tiles beside it count findings too.
  const OWNER_SCAN = { findings: 15, finding_hosts: 10, queued: 15, auto_approved: 0, pending_approval: 0, awaiting_processing: 0, suppressed: 0, observed: 15, observed_hosts: 10 };
  const tile = (label: string) => Array.from(document.querySelectorAll('.panel')).find((p) => p.firstElementChild?.textContent === label);

  it('labels the finding count as open ports on hosts, and the other tiles as findings', async () => {
    await open(planJob({ status: 'completed' }), { materialization: OWNER_SCAN });
    expect(tile('Found')).toBeUndefined();
    expect(tile('Open ports found')?.textContent).toBe('Open ports found15on 10 hosts');
    expect(tile('Pending approval')?.textContent).toBe('Pending approval0findings');
    expect(tile('Auto-approved')?.textContent).toBe('Auto-approved0findings');
    expect(text()).toContain('Found 15 open ports on 10 hosts');
  });

  it('says where the findings that became no asset went, with the way to Observations', async () => {
    await open(planJob({ status: 'completed' }), { materialization: OWNER_SCAN });
    const note = document.querySelector('[role="note"][aria-label="Kept as observations"]');
    expect(note?.textContent).toBe(
      '15 findings on 10 hosts were kept as observations — they could not be tied to an asset yet (for example, on a network that uses DHCP an address alone does not identify a device). Review them in Discovery → Observations.',
    );
    const link = note?.querySelector('a');
    expect(link?.textContent).toBe('Discovery → Observations');
    expect(link?.getAttribute('href')).toBe('/discovery/observations');
    expect(text()).toContain('15 kept as observations');
  });

  it('shows no observations notice when none were kept, or when the count is unknown', async () => {
    await open(planJob({ status: 'completed' }), { materialization: { ...OWNER_SCAN, observed: 0, observed_hosts: 0, pending_approval: 15 } });
    expect(document.querySelector('[aria-label="Kept as observations"]')).toBeNull();
    expect(text()).not.toContain('kept as observations');
    act(() => root.unmount());
    root = createRoot(host);
    cache.clear();
    const { observed: _o, observed_hosts: _h, ...unknown } = OWNER_SCAN;
    await open(planJob({ status: 'completed' }), { materialization: unknown });
    expect(document.querySelector('[aria-label="Kept as observations"]')).toBeNull();
  });
});

describe('live refresh', () => {
  it('re-reads every 5 s while the job runs and stops once it has ended', async () => {
    vi.useFakeTimers();
    server = { job: planJob(), hosts: HOSTS };
    install();
    await act(async () => {
      root.render(
        <MemoryRouter>
          <QueryClientProvider client={cache}>
            <DiscoveryJobDetailModal job={planJob()} onClose={() => {}} />
          </QueryClientProvider>
        </MemoryRouter>,
      );
    });
    await act(async () => { await vi.advanceTimersByTimeAsync(100); });
    expect(jobCalls()).toHaveLength(1);
    const hostsAtStart = hostCalls().length;

    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(jobCalls()).toHaveLength(2);
    expect(hostCalls().length).toBeGreaterThan(hostsAtStart);

    // The job ends: one more read shows it, then the polling stops.
    server.job = planJob({ status: 'completed', progress: 100, coverage: cov({ hosts_pending: 0, hosts_no_answer: 223 }) });
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    const jobsAtEnd = jobCalls().length;
    await act(async () => { await vi.advanceTimersByTimeAsync(100); });
    const hostsAtEnd = hostCalls().length;
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
    expect(jobCalls()).toHaveLength(jobsAtEnd);
    expect(hostCalls()).toHaveLength(hostsAtEnd);
    expect(text()).toContain('Finished');
  });
});

describe('legacy job', () => {
  it('keeps its sections: no plan summary, coverage or results by host', async () => {
    const legacy: ScanJob = { id: JOB_ID, status: 'completed', execution_mode: 'async', executor: 'platform', targets: ['10.0.0.1'], created_at: '2026-10-02T10:00:00Z' };
    await open(legacy);
    expect(section('What this scan does')).toBeUndefined();
    expect(section('Coverage')).toBeUndefined();
    expect(section('Results by host')).toBeUndefined();
    expect(hostCalls()).toHaveLength(0);
    expect(text()).toContain('Completed');
    expect(text()).toContain('Dispatch timeline');
    expect(text()).toContain('Auto-approved');
  });
});

// Since WP4 automatic scans, identity checks and Active Scans are planned
// jobs too: a custom-depth plan on their ports, often run from a tenant sensor.
// Their detail renders the same plan and coverage blocks without error.
describe('automatic, identity and Active Scan jobs as planned jobs', () => {
  const customPlan = {
    ...PLAN, depth: 'custom', tcp_ports: '22,443,8443', udp_ports: '', tcp_port_count: 3, udp_port_count: 0,
    run_from_requested: 'sensor', executor_resolved: 'sensor', executor_reason: 'the sensor you chose',
    depth_adjustments: [],
    targets: [{ target: '10.0.0.5', class: 'private', depth: 'custom', addresses: 1, tcp_ports: '22,443,8443', udp_ports: '', tcp_port_count: 3, udp_port_count: 0, estimated_probes: 3 }],
  } as NonNullable<ScanJob['plan']>;

  for (const origin of ['auto_scan', 'identity_enrichment', undefined]) {
    it(`renders a ${origin ?? 'Active Scan'} job run from a tenant sensor`, async () => {
      await open(planJob({
        origin, plan: customPlan, status: 'awaiting_sensor', execution_mode: 'sensors', executor: 'sensor',
        assigned_sensor_name: 'edge-sensor', coverage: cov({ hosts_total: 1, hosts_responded: 0, hosts_no_answer: 0, hosts_pending: 1, tarpit_hosts: 0, udp_answered: 0 }),
      }), { hosts: [] });
      const plan = section('What this scan does')!;
      expect(plan).toBeTruthy();
      expect(plan.textContent).toContain('Custom');
      expect(plan.textContent).toContain('10.0.0.5');
      expect(text()).toContain('edge-sensor');
    });
  }
});
