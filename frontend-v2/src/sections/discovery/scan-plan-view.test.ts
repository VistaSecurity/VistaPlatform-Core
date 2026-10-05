// The wording rules of a scan-plan job on Discovery → Discovery Jobs (
// WP4b). Each test is one honesty rule from the spec's screen-state table.
import { describe, expect, it } from 'vitest';
import {
  coverageHostsLine,
  coveragePortsLine,
  depthAdjustmentGroups,
  hostsFinished,
  isJobLive,
  isQuietHost,
  isResumable,
  isTarpitHost,
  nothingAnswered,
  partialStop,
  planJobState,
  portServiceLabel,
  portTransportLabel,
  progressLine,
  progressPercent,
  quietHostLine,
  remainingWarnings,
  tarpitSummary,
  TARPIT_SAMPLE_SHOWN,
  zeroResponderGuidance,
  type JobCoverage,
  type ScanHost,
} from './scan-plan-view';
import type { ScanJob } from './scan-job-state';

function coverage(over: Partial<JobCoverage> = {}): JobCoverage {
  return {
    hosts_total: 254,
    hosts_responded: 31,
    hosts_no_answer: 223,
    hosts_undetermined: 0,
    hosts_failed: 0,
    hosts_pending: 0,
    hosts_cancelled: 0,
    ports_requested: 4190,
    ports_open: 9,
    ports_closed: 4120,
    ports_filtered: 61,
    ports_local_errors: 0,
    ports_not_probed: 0,
    tarpit_hosts: 0,
    ot_suspect_hosts: 0,
    udp_answered: 0,
    warnings: [],
    ...over,
  };
}

const job = (over: Partial<ScanJob>): ScanJob => ({ id: 'j1', status: 'running', ...over });

describe('progress', () => {
  it.each([
    [25, 25],
    [33.4, 33],
    [99.6, 100],
    [140, 100],
    [-5, 0],
    [undefined, 0],
    [Number.NaN, 0],
  ])('progressPercent(%s) = %s', (input, want) => {
    expect(progressPercent(input)).toBe(want);
  });

  it('counts finished hosts as total minus pending minus never-reached', () => {
    expect(hostsFinished(coverage({ hosts_pending: 142 }))).toBe(112);
    expect(hostsFinished(coverage({ hosts_pending: 100, hosts_cancelled: 42 }))).toBe(112);
  });

  it('the live line says how far, how many answered and what is open', () => {
    expect(progressLine(coverage({ hosts_pending: 142 }))).toBe('112 of 254 hosts · 31 responded · 9 open ports');
    expect(progressLine(coverage({ ports_open: 1 }))).toBe('254 of 254 hosts · 31 responded · 1 open port');
    expect(progressLine(coverage({ ports_open: 0 }))).toBe('254 of 254 hosts · 31 responded');
    expect(progressLine(undefined)).toBeUndefined();
    expect(progressLine(coverage({ hosts_total: 0 }))).toBeUndefined();
  });
});

describe('coverage wording', () => {
  it('states addresses, responded and no answer', () => {
    expect(coverageHostsLine(coverage())).toBe('254 addresses · 31 responded · 223 no answer');
    expect(coveragePortsLine(coverage())).toBe('9 open · 4,120 closed · 61 filtered');
  });

  it('never calls an address that gave no answer "down" or "empty"', () => {
    for (const c of [coverage(), coverage({ hosts_responded: 0, hosts_no_answer: 254 }), coverage({ hosts_undetermined: 3, hosts_failed: 2, hosts_pending: 5 })]) {
      const text = `${coverageHostsLine(c)} ${coveragePortsLine(c)} ${progressLine(c) ?? ''}`.toLowerCase();
      expect(text).not.toMatch(/\bdown\b|\bempty\b|\boffline\b|\bdead\b/);
      expect(text).toContain('no answer');
    }
  });

  it('accounts for every other host it did not get a verdict on', () => {
    expect(coverageHostsLine(coverage({ hosts_no_answer: 213, hosts_undetermined: 3, hosts_failed: 2, hosts_pending: 4, hosts_cancelled: 1 }))).toBe(
      '254 addresses · 31 responded · 213 no answer · 3 could not be checked · 2 not scanned · 4 still to scan · 1 not reached',
    );
    expect(coveragePortsLine(coverage({ ports_not_probed: 12, ports_local_errors: 1500 }))).toBe(
      "9 open · 4,120 closed · 61 filtered · 12 not probed · 1,500 failed on the scanner's side",
    );
  });
});

describe('nothing answered', () => {
  const silent = coverage({ hosts_responded: 0, hosts_no_answer: 254, ports_open: 0, ports_closed: 0 });

  it('is recognised only once every host is done', () => {
    expect(nothingAnswered(silent)).toBe(true);
    expect(nothingAnswered({ ...silent, hosts_pending: 10, hosts_no_answer: 244 })).toBe(false);
    expect(nothingAnswered(coverage())).toBe(false);
  });

  it('gives reachability guidance, not "empty network"', () => {
    expect(zeroResponderGuidance({ executor_resolved: 'platform' })).toBe(
      'Nothing answered. The Platform sensor may not be able to reach this network — run the scan from a sensor on that network, or check that the addresses are right.',
    );
    expect(zeroResponderGuidance({ executor_resolved: 'sensor', sensor_name: 'edge-a' })).toMatch(/^Nothing answered\. edge-a may not be able to reach this network/);
  });
});

describe('a scan that stopped early says where and why', () => {
  const stopped = coverage({ hosts_pending: 0, hosts_cancelled: 142 });
  it.each([
    ['cancelled', null, 'Stopped at 112 of 254 hosts — the scan was cancelled.'],
    ['failed', 'scan stopped responding; no heartbeat since 2026-10-02T10:00:00Z — retry to resume', 'Stopped at 112 of 254 hosts — the scan stopped responding; Resume scan in the Jobs list runs the hosts it had not finished.'],
    ['failed', 'sensor edge-a went offline; nothing was scanned', 'Stopped at 112 of 254 hosts — the sensor went offline.'],
    ['failed', 'job exceeded its deadline', 'Stopped at 112 of 254 hosts — it ran out of time.'],
    ['failed', 'boom', 'Stopped at 112 of 254 hosts — the scan failed.'],
  ])('%s / %s', (status, err, want) => {
    expect(partialStop({ status, error_message: err }, stopped)).toBe(want);
  });

  it('says nothing while running or when every host was finished', () => {
    expect(partialStop({ status: 'running' }, coverage({ hosts_pending: 100 }))).toBeUndefined();
    expect(partialStop({ status: 'completed' }, coverage())).toBeUndefined();
    expect(partialStop({ status: 'cancelled' }, undefined)).toBeUndefined();
  });

  it('a failed job with pending hosts counts them as not finished', () => {
    expect(partialStop({ status: 'failed', error_message: 'scan stopped responding' }, coverage({ hosts_pending: 142 }))).toMatch(/^Stopped at 112 of 254 hosts/);
  });
});

describe('server warnings', () => {
  const w = ['0 of 254 scanned addresses responded — the platform sensor may not be able to reach this network', 'stopped at 112 of 254 hosts: the scan was cancelled', 'scanner resource limits were hit'];
  it('drops only the ones the page restates, and only when it restates them', () => {
    expect(remainingWarnings(coverage({ warnings: w }), { zeroResponder: true, partial: true })).toEqual(['scanner resource limits were hit']);
    expect(remainingWarnings(coverage({ warnings: w }), { zeroResponder: false, partial: false })).toEqual(w);
  });
});

describe('depth adjustments', () => {
  it('explains each one in plain words and drops none', () => {
    const reason = 'outside your registered networks: Standard is the deepest scan allowed; register the range if it is yours';
    const groups = depthAdjustmentGroups([
      { target: '203.0.113.5', requested: 'thorough', applied: 'standard', reason },
      { target: '198.51.100.0/30', requested: 'thorough', applied: 'standard', reason },
      { target: 'host.example', requested: 'custom', applied: 'quick', reason: 'other' },
    ]);
    expect(groups).toEqual([
      { text: `2 targets were scanned at Standard depth instead of Thorough — ${reason}`, targets: ['203.0.113.5', '198.51.100.0/30'] },
      { text: '1 target was scanned at Quick depth instead of Custom — other', targets: ['host.example'] },
    ]);
    expect(depthAdjustmentGroups([])).toEqual([]);
  });
});

describe('status in plain words', () => {
  it.each([
    [{ status: 'queued' }, 'Queued'],
    [{ status: 'awaiting_sensor', executor: 'sensor' as const, assigned_sensor_name: 'edge-a' }, 'Waiting for sensor'],
    [{ status: 'awaiting_sensor', executor: 'sensor' as const, assigned_sensor_name: 'edge-a', picked_up_at: '2026-10-02T10:00:00Z' }, 'Running on edge-a'],
    [{ status: 'running' }, 'Running'],
    [{ status: 'completed' }, 'Finished'],
    [{ status: 'cancelled' }, 'Cancelled'],
    [{ status: 'failed', error_message: 'scan stopped responding; no heartbeat since 2026-10-02T10:00:00Z — retry to resume' }, 'Failed — stopped responding'],
    [{ status: 'failed', error_message: 'boom' }, 'Failed'],
  ])('%o → %s', (over, label) => {
    expect(planJobState(job(over)).label).toBe(label);
  });

  it("shows the server's failure text verbatim as the detail", () => {
    const msg = 'scan stopped responding; no heartbeat since 2026-10-02T10:00:00Z — retry to resume';
    expect(planJobState(job({ status: 'failed', error_message: msg })).detail).toBe(msg);
  });

  it('only a queued or failed job can be resumed; only an unfinished one is polled', () => {
    expect(['failed', 'queued', 'error', 'pending'].every(isResumable)).toBe(true);
    expect(['completed', 'running', 'cancelled', 'awaiting_sensor', ''].some(isResumable)).toBe(false);
    expect(['queued', 'running', 'awaiting_sensor'].every(isJobLive)).toBe(true);
    expect(['completed', 'failed', 'cancelled', '', undefined].some(isJobLive)).toBe(false);
  });
});

describe('results by host', () => {
  const port = (over: Record<string, unknown>) => ({ finding_id: 'f', port: 25, protocol: 'tcp', identified: false, confidence_score: 0.5, data: {}, ...over });

  it('an unidentified open port is labelled, never hidden', () => {
    expect(portServiceLabel(port({}))).toBe('open, unidentified');
    expect(portServiceLabel(port({ service_hint: 'smtp' }))).toBe('open, unidentified (looks like smtp)');
    expect(portServiceLabel(port({ identified: true, protocol: 'TLS' }))).toBe('TLS');
    expect(portServiceLabel(port({ identified: true, protocol: 'TLS', data: { identification_note: 'tls-handshake-refused' } }))).toBe(
      'TLS, handshake refused',
    );
    expect(portTransportLabel(port({ transport: 'udp' }))).toBe('UDP');
    expect(portTransportLabel(port({ data: {} }))).toBe('TCP');
  });

  it('a host that answers on every port is one line with a bounded sample', () => {
    const sample = Array.from({ length: 32 }, (_, i) => i + 1);
    const host: ScanHost = { address: '10.0.0.9', ports: [port({ port: 1, data: { responds_on_all_ports: true, open_sample: sample } })] };
    expect(isTarpitHost(host)).toBe(true);
    const t = tarpitSummary(host);
    expect(t.ports).toHaveLength(TARPIT_SAMPLE_SHOWN);
    expect(t.line).toBe(`answers on every port — probably a firewall or proxy; showing ${TARPIT_SAMPLE_SHOWN} sample ports`);
    expect(isTarpitHost({ address: '10.0.0.8', ports: [port({})] })).toBe(false);
  });

  //: every host that answered is listed; one with nothing open is a
  // single line saying how its ports answered — refused or filtered, never
  // "down".
  const unit = (over: Partial<NonNullable<ScanHost['unit']>> = {}): NonNullable<ScanHost['unit']> => ({
    status: 'done', liveness_state: 'up', ports_requested: 78, open_count: 0, closed_count: 78, filtered_count: 0, not_probed_count: 0,
    responds_on_all_ports: false, ot_suspect: false, ...over,
  });

  it('a host that answered with nothing open is a quiet host; one with ports, or a tarpit, is not', () => {
    expect(isQuietHost({ address: '10.0.0.5', ports: [], nothing_open: true, unit: unit() })).toBe(true);
    expect(isQuietHost({ address: '10.0.0.5', ports: [], unit: unit() })).toBe(true);
    expect(isQuietHost({ address: '10.0.0.6', ports: [port({})], unit: unit({ open_count: 1, closed_count: 77 }) })).toBe(false);
    expect(isQuietHost({ address: '10.0.0.9', ports: [], unit: unit({ responds_on_all_ports: true }) })).toBe(false);
  });

  it('says how the ports of a quiet host answered', () => {
    const line = (u?: Partial<NonNullable<ScanHost['unit']>>) => quietHostLine({ address: '10.0.0.5', ports: [], nothing_open: true, unit: u ? unit(u) : undefined });
    expect(line({})).toBe('answered, nothing open (78 ports scanned: all refused)');
    expect(line({ closed_count: 0, filtered_count: 78, liveness_evidence: 'tcp-refused:22' })).toBe('answered, nothing open (78 ports scanned: all filtered)');
    expect(line({ closed_count: 70, filtered_count: 6, not_probed_count: 2 })).toBe('answered, nothing open (78 ports scanned: 70 refused, 6 filtered, 2 not probed)');
    expect(line({ ports_requested: 1, closed_count: 1 })).toBe('answered, nothing open (1 port scanned: all refused)');
    expect(line({ ports_requested: 0, closed_count: 0, udp_answered_count: 1 })).toBe('answered, nothing open on the ports scanned');
    expect(line()).toBe('answered, nothing open on the ports scanned');
    for (const u of [{}, { closed_count: 0, filtered_count: 78 }, { closed_count: 70, filtered_count: 8 }]) {
      expect(line(u)).not.toMatch(/\bdown\b|\bempty\b|no answer/i);
    }
  });
});
