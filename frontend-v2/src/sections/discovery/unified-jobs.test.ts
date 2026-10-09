import { describe, expect, it } from 'vitest';
import {
  discoveryJobKind,
  discoveryRow,
  distinctExecutors,
  filterRows,
  interrogationRow,
  kindLabel,
  matchesFilters,
  mergeJobs,
  statusBucket,
  type InterrogationJob,
} from './unified-jobs';
import type { ScanJob } from './scan-job-state';

// The unified Discovery → Discovery Jobs page (morning-notes decision 7b)
// merges two job sources that used to have separate (or, for discovery_jobs,
// no) listing surfaces. These pin the merge/label/filter rules as table
// tests, mirroring kit.ts and scan-job-state.ts's own pattern next door.

function interrogation(overrides: Partial<InterrogationJob> = {}): InterrogationJob {
  return {
    id: 'ij-1',
    tenant_id: 't1',
    job_type: 'device_interrogation',
    status: 'completed',
    created_at: '2026-09-17T10:00:00Z',
    updated_at: '2026-09-17T10:05:00Z',
    executor: 'platform',
    ...overrides,
  };
}

function discovery(overrides: Partial<ScanJob> = {}): ScanJob {
  return {
    id: 'dj-1',
    status: 'completed',
    execution_mode: 'async',
    executor: 'platform',
    created_at: '2026-09-17T09:00:00Z',
    ...overrides,
  };
}

describe('discoveryJobKind', () => {
  it('is "automatic" only when origin carries the #1814 sweep marker', () => {
    expect(discoveryJobKind({ origin: 'auto_scan' })).toBe('automatic');
    expect(discoveryJobKind({ origin: '' })).toBe('discovery');
    expect(discoveryJobKind({ origin: undefined })).toBe('discovery');
  });
});

describe('kindLabel', () => {
  it('names all three kinds', () => {
    expect(kindLabel('interrogation')).toBe('Interrogation');
    expect(kindLabel('discovery')).toBe('Discovery');
    expect(kindLabel('automatic')).toBe('Automatic scan');
  });
});

describe('statusBucket', () => {
  it('buckets both job vocabularies onto one set', () => {
    expect(statusBucket('queued')).toBe('queued');
    expect(statusBucket('pending')).toBe('queued');
    expect(statusBucket('awaiting_sensor')).toBe('awaiting_sensor');
    expect(statusBucket('running')).toBe('running');
    expect(statusBucket('in_progress')).toBe('running');
    expect(statusBucket('completed')).toBe('completed');
    expect(statusBucket('success')).toBe('completed');
    expect(statusBucket('failed')).toBe('failed');
    expect(statusBucket('error')).toBe('failed');
    expect(statusBucket('cancelled')).toBe('cancelled');
  });
});

describe('mergeJobs', () => {
  it('includes rows from BOTH sources — losing either half is the regression this exists to prevent', () => {
    const rows = mergeJobs([interrogation({ id: 'a' })], [discovery({ id: 'b' })]);
    const kinds = rows.map((r) => r.kind).sort();
    expect(kinds).toEqual(['discovery', 'interrogation']);
    expect(rows.map((r) => r.id).sort()).toEqual(['a', 'b']);
  });

  it('sorts newest first across both sources by their own timestamp', () => {
    const older = discovery({ id: 'old', created_at: '2026-09-01T00:00:00Z' });
    const newer = interrogation({ id: 'new', created_at: '2026-09-17T00:00:00Z', started_at: '2026-09-17T00:00:00Z' });
    const rows = mergeJobs([newer], [older]);
    expect(rows.map((r) => r.id)).toEqual(['new', 'old']);
  });

  it('marks an automatic-scan job distinctly from an operator-started discovery job', () => {
    const rows = mergeJobs([], [
      discovery({ id: 'sweep', origin: 'auto_scan' }),
      discovery({ id: 'manual' }),
    ]);
    const byId = Object.fromEntries(rows.map((r) => [r.id, r.kind]));
    expect(byId.sweep).toBe('automatic');
    expect(byId.manual).toBe('discovery');
  });

  it('empty on both sources yields an empty list, not a crash', () => {
    expect(mergeJobs([], [])).toEqual([]);
  });
});

describe('interrogationRow / discoveryRow', () => {
  it('projects a device-interrogation job with its device/integration target', () => {
    const row = interrogationRow(interrogation({ device_name: 'F5-lb-01', assets_discovered: 4, duration_seconds: 62 }));
    expect(row.kind).toBe('interrogation');
    expect(row.target).toBe('F5-lb-01');
    expect(row.found).toBe(4);
    expect(row.durationSec).toBe(62);
  });

  it('projects a discovery job with its target list, truncated past two', () => {
    const row = discoveryRow(discovery({ targets: ['10.0.0.1', '10.0.0.2', '10.0.0.3'] }));
    expect(row.target).toBe('10.0.0.1, 10.0.0.2 +1');
    expect(row.targetCount).toBe(3);
  });

  it('a discovery row has no per-row findings count (found is a dash, not a fabricated number)', () => {
    const row = discoveryRow(discovery());
    expect(row.found).toBe('—');
  });
});

describe('filters', () => {
  it('kind filter isolates exactly one kind', () => {
    const rows = mergeJobs(
      [interrogation({ id: 'i' })],
      [discovery({ id: 'd' }), discovery({ id: 'a', origin: 'auto_scan' })],
    );
    expect(filterRows(rows, { kind: 'automatic', status: 'all', executor: 'all' }).map((r) => r.id)).toEqual(['a']);
    expect(filterRows(rows, { kind: 'discovery', status: 'all', executor: 'all' }).map((r) => r.id)).toEqual(['d']);
    expect(filterRows(rows, { kind: 'interrogation', status: 'all', executor: 'all' }).map((r) => r.id)).toEqual(['i']);
  });

  it('status filter reads the bucketed status, not the raw string', () => {
    const rows = mergeJobs([], [discovery({ id: 'run', status: 'in_progress' }), discovery({ id: 'done', status: 'completed' })]);
    expect(filterRows(rows, { kind: 'all', status: 'running', executor: 'all' }).map((r) => r.id)).toEqual(['run']);
  });

  it('executor filter matches the derived executor label, not the raw executor field', () => {
    const row = discoveryRow(discovery({ executor: 'sensor', execution_mode: 'sensors', assigned_sensor_name: 'xps16-sensor' }));
    expect(matchesFilters(row, { kind: 'all', status: 'all', executor: 'xps16-sensor' })).toBe(true);
    expect(matchesFilters(row, { kind: 'all', status: 'all', executor: 'Platform sensor' })).toBe(false);
  });

  it('"all" never excludes a row on that axis', () => {
    const row = interrogationRow(interrogation());
    expect(matchesFilters(row, { kind: 'all', status: 'all', executor: 'all' })).toBe(true);
  });
});

describe('distinctExecutors', () => {
  it('lists each executor once, sorted, excluding the placeholder dash', () => {
    const rows = mergeJobs(
      [interrogation({ id: 'i1', executor: 'agent-42' }), interrogation({ id: 'i2', executor: '' })],
      [discovery({ id: 'd1', executor: 'sensor', execution_mode: 'sensors', assigned_sensor_name: 'xps16-sensor' })],
    );
    expect(distinctExecutors(rows)).toEqual(['agent-42', 'xps16-sensor']);
  });
});

// A scan-plan job ( WP4b) carries its depth and, while it runs, its
// progress on the row; a legacy job's row is exactly what it was.
describe('discoveryRow — scan-plan jobs', () => {
  const plan = {
    depth: 'standard',
    pace: 'normal',
    tcp_ports: '1-1000',
    udp_ports: '',
    tcp_port_count: 1000,
    udp_port_count: 0,
    run_from_requested: 'auto',
    executor_resolved: 'platform',
    executor_reason: 'no sensor observes these targets',
    depth_adjustments: [],
    targets: [{ target: '10.0.0.0/24', class: 'private', depth: 'standard', addresses: 254, tcp_ports: '1-1000', udp_ports: '', tcp_port_count: 1000, udp_port_count: 0, estimated_probes: 254000 }],
    estimated_probes: 254000,
    probe_limit: 25000000,
  } as NonNullable<ScanJob['plan']>;
  const cov = {
    hosts_total: 254, hosts_responded: 31, hosts_no_answer: 81, hosts_undetermined: 0, hosts_failed: 0, hosts_pending: 142, hosts_cancelled: 0,
    ports_requested: 112000, ports_open: 9, ports_closed: 4120, ports_filtered: 61, ports_local_errors: 0, ports_not_probed: 0,
    tarpit_hosts: 0, ot_suspect_hosts: 0, udp_answered: 0, warnings: [],
  };

  it('a running plan job shows its progress, live line, depth and target', () => {
    const row = discoveryRow(discovery({ status: 'running', targets: undefined, plan, progress: 44, coverage: cov }));
    expect(row.progress).toEqual({ pct: 44, line: '112 of 254 hosts · 31 responded · 9 open ports' });
    expect(row.depth).toBe('Standard');
    expect(row.statusLabel).toBe('Running');
    expect(row.target).toBe('10.0.0.0/24');
    expect(row.executor).toBe('Platform sensor');
  });

  it('a queued or finished plan job has no progress bar; a finished one reads "Finished"', () => {
    expect(discoveryRow(discovery({ status: 'queued', plan })).progress).toBeUndefined();
    const done = discoveryRow(discovery({ status: 'completed', plan, progress: 0 }));
    expect(done.progress).toBeUndefined();
    expect(done.statusLabel).toBe('Finished');
  });

  it('a legacy job row is unchanged — no depth, no progress, the old wording', () => {
    const row = discoveryRow(discovery({ status: 'completed', progress: 100 }));
    expect(row.depth).toBeUndefined();
    expect(row.progress).toBeUndefined();
    expect(row.statusLabel).toBe('Completed');
    expect(discoveryRow(discovery({ status: 'running', progress: 50 })).progress).toBeUndefined();
  });
});

// Job Logs was folded into this table. What only its line said (the run's
// outcome and a failure's own error) must survive on the interrogation row.
describe('interrogationRow carries what Job Logs used to show', () => {
  it('puts a cloud run\'s enumeration under the status', () => {
    const row = interrogationRow(interrogation({ enumeration: { instances: 12, networks: 0, subnets: 3, security_groups: 0 } }));
    expect(row.statusDetail).toBe('12 instances, 3 subnets');
  });

  it('says a host inventory failed rather than listing its counts', () => {
    const row = interrogationRow(interrogation({ host_inventory: { failed: 'identity conflict' } as InterrogationJob['host_inventory'] }));
    expect(row.statusDetail).toBe('host inventory NOT materialised — identity conflict');
  });

  it('shows a failed run\'s error, and only for a failed run', () => {
    expect(interrogationRow(interrogation({ status: 'failed', error_message: 'connection refused' })).errorDetail).toBe('connection refused');
    expect(interrogationRow(interrogation({ status: 'error', error_message: 'timeout' })).errorDetail).toBe('timeout');
    expect(interrogationRow(interrogation({ status: 'completed', error_message: 'stale' })).errorDetail).toBeUndefined();
  });

  it('adds no detail line for a run that reports nothing extra', () => {
    expect(interrogationRow(interrogation()).statusDetail).toBeUndefined();
  });
});
