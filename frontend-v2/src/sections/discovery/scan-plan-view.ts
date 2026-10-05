// How a scan-plan job reads on Discovery → Discovery Jobs: its status
// in plain words, its progress, its coverage, why it stopped, what it did to
// the depth asked for, and its results grouped by host.
//
// Out of the components so every wording rule is a table test. The rules that
// matter most are about honesty:
//
//   - "no answer" is never "down" or "empty": a firewall that drops everything
//     looks exactly like an address with nothing on it;
//   - a scan that answered nothing says the scanner may not be able to reach
//     the network, rather than reading as an empty network (H11);
//   - a scan that stopped early says where and why;
//   - an open port nothing could name is shown as "open, unidentified", never
//     hidden (H13);
//   - a host that answers on every port is one line, not 65,535 rows (H14).
//
// A legacy (protocols × ports) job has no `plan` and is not described here —
// it keeps scan-job-state.ts's wording exactly.
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { relTime } from './kit';
import { DANGER, INFO, MUTED, OK, WARN, executorLabel, type ScanJob, type ScanJobState } from './scan-job-state';

export type ScanPlan = inventoryComponents['schemas']['DiscoveryScanPlan'];
export type JobCoverage = inventoryComponents['schemas']['DiscoveryJobCoverage'];
export type DepthAdjustment = inventoryComponents['schemas']['DiscoveryDepthAdjustment'];
export type ScanHost = inventoryComponents['schemas']['DiscoveryHost'];
export type ScanHostPort = inventoryComponents['schemas']['DiscoveryHostPort'];

const SETTLED = new Set(['completed', 'success', 'failed', 'error', 'cancelled', 'canceled']);

/** True while the job has not ended — the detail and the list poll only then. */
export function isJobLive(status?: string | null): boolean {
  const s = (status ?? '').toLowerCase();
  return s !== '' && !SETTLED.has(s);
}

/** Queued or failed: what the rerun endpoint accepts (409 otherwise). */
export function isResumable(status?: string | null): boolean {
  const s = (status ?? '').toLowerCase();
  return s === 'failed' || s === 'error' || s === 'queued' || s === 'pending';
}

export const fmtCount = (n: number | undefined | null): string => (n ?? 0).toLocaleString('en-US');
const plural = (n: number, one: string, many = `${one}s`) => `${fmtCount(n)} ${n === 1 ? one : many}`;

const DEPTH_LABEL: Record<string, string> = { quick: 'Quick', standard: 'Standard', thorough: 'Thorough', custom: 'Custom' };
const PACE_LABEL: Record<string, string> = { polite: 'Polite', normal: 'Normal', fast: 'Fast' };

/** The label for a known value, the value itself for an unknown one, and a dash for none. */
function labelOf(labels: Record<string, string>, v?: string | null): string {
  if (!v) return '—';
  return labels[v] ?? v;
}

export function depthLabel(depth?: string | null): string {
  return labelOf(DEPTH_LABEL, depth);
}

export function paceLabel(pace?: string | null): string {
  return labelOf(PACE_LABEL, pace);
}

/** Where the plan said the scan runs: the Platform sensor or the named tenant sensor. */
export function planExecutorLabel(plan: Pick<ScanPlan, 'executor_resolved' | 'sensor_name'>): string {
  if (plan.executor_resolved !== 'sensor') return 'Platform sensor';
  if (!plan.sensor_name) return 'Tenant sensor';
  return plan.sensor_name;
}

/** What the person asked for under "Run from". */
export function runFromLabel(requested?: string | null): string {
  switch (requested) {
    case 'auto':
      return 'Auto';
    case 'platform':
      return 'Platform sensor';
    case 'sensor':
      return 'A sensor you chose';
    default:
      if (!requested) return '—';
      return requested;
  }
}

function stoppedResponding(msg?: string | null): boolean {
  return /stopped responding|no heartbeat/i.test(msg ?? '');
}

function sensorOffline(msg?: string | null): boolean {
  return /sensor .*offline|offline; nothing was scanned/i.test(msg ?? '');
}

function ranOutOfTime(msg?: string | null): boolean {
  return /deadline|time limit|timed out|timeout/i.test(msg ?? '');
}

/**
 * A scan-plan job's status chip, in plain words. The server's failure text
 * (e.g. "scan stopped responding; no heartbeat since … — retry to resume") is
 * the detail line, verbatim: it is written for a person.
 */
export function planJobState(job: ScanJob): ScanJobState {
  const status = (job.status ?? '').toLowerCase();
  const err = job.error_message ?? undefined;
  switch (status) {
    case 'queued':
    case 'pending':
      return { label: 'Queued', color: WARN };
    case 'awaiting_sensor':
      if (job.picked_up_at) return { label: `Running on ${executorLabel(job)}`, color: INFO };
      return { label: 'Waiting for sensor', color: WARN, detail: job.dispatched_at ? `sent to ${executorLabel(job)} ${relTime(job.dispatched_at)}` : undefined };
    case 'running':
    case 'in_progress':
    case 'processing':
      return { label: 'Running', color: INFO };
    case 'completed':
    case 'success':
      return { label: 'Finished', color: OK };
    case 'failed':
    case 'error':
      if (stoppedResponding(err)) return { label: 'Failed — stopped responding', color: DANGER, detail: err };
      if (sensorOffline(err)) {
        const beat = job.assigned_sensor_last_heartbeat ? ` (last heartbeat ${relTime(job.assigned_sensor_last_heartbeat)})` : '';
        return { label: 'Failed — sensor offline', color: DANGER, detail: `${err ?? ''}${beat}`.trim() };
      }
      return { label: 'Failed', color: DANGER, detail: err };
    case 'cancelled':
    case 'canceled':
      return { label: 'Cancelled', color: MUTED };
    default:
      return { label: job.status || 'Unknown', color: MUTED };
  }
}

/** The server's `progress`, as a whole percent the bar can draw. */
export function progressPercent(progress?: number | null): number {
  if (typeof progress !== 'number' || !Number.isFinite(progress)) return 0;
  return Math.max(0, Math.min(100, Math.round(progress)));
}

/** Hosts the scanner is finished with — scanned, or refused with a reason. A host never reached because the job was cancelled is not finished. */
export function hostsFinished(c: JobCoverage): number {
  return Math.max(0, c.hosts_total - c.hosts_pending - c.hosts_cancelled);
}

/** The row's live line: "112 of 254 hosts · 31 responded · 9 open ports". */
export function progressLine(c?: JobCoverage | null): string | undefined {
  if (!c || c.hosts_total <= 0) return undefined;
  const parts = [`${fmtCount(hostsFinished(c))} of ${plural(c.hosts_total, 'host')}`, `${fmtCount(c.hosts_responded)} responded`];
  if (c.ports_open > 0) parts.push(plural(c.ports_open, 'open port'));
  return parts.join(' · ');
}

/**
 * "254 addresses · 31 responded · 223 no answer", plus whatever else is not
 * accounted for. "No answer" is the honest word: it is never "down".
 */
export function coverageHostsLine(c: JobCoverage): string {
  const parts = [plural(c.hosts_total, 'address', 'addresses'), `${fmtCount(c.hosts_responded)} responded`, `${fmtCount(c.hosts_no_answer)} no answer`];
  if (c.hosts_undetermined > 0) parts.push(`${fmtCount(c.hosts_undetermined)} could not be checked`);
  if (c.hosts_failed > 0) parts.push(`${fmtCount(c.hosts_failed)} not scanned`);
  if (c.hosts_pending > 0) parts.push(`${fmtCount(c.hosts_pending)} still to scan`);
  if (c.hosts_cancelled > 0) parts.push(`${fmtCount(c.hosts_cancelled)} not reached`);
  return parts.join(' · ');
}

/** "9 open · 4,120 closed · 61 filtered" over the ports of the hosts scanned. */
export function coveragePortsLine(c: JobCoverage): string {
  const parts = [`${fmtCount(c.ports_open)} open`, `${fmtCount(c.ports_closed)} closed`, `${fmtCount(c.ports_filtered)} filtered`];
  if (c.ports_not_probed > 0) parts.push(`${fmtCount(c.ports_not_probed)} not probed`);
  if (c.ports_local_errors > 0) parts.push(`${fmtCount(c.ports_local_errors)} failed on the scanner's side`);
  return parts.join(' · ');
}

/** Every scanned address was silent — the network may simply be out of the scanner's reach. Same rule as the server's warning. */
export function nothingAnswered(c: JobCoverage): boolean {
  const scanned = c.hosts_responded + c.hosts_no_answer + c.hosts_undetermined;
  return c.hosts_pending === 0 && scanned > 0 && c.hosts_responded === 0;
}

/** Reachability guidance for a scan nothing answered (H11). */
export function zeroResponderGuidance(plan?: Pick<ScanPlan, 'executor_resolved' | 'sensor_name'> | null): string {
  if (plan?.executor_resolved === 'sensor') {
    return `Nothing answered. ${planExecutorLabel(plan)} may not be able to reach this network — check that it can, or that the addresses are right.`;
  }
  return 'Nothing answered. The Platform sensor may not be able to reach this network — run the scan from a sensor on that network, or check that the addresses are right.';
}

/**
 * Why a scan that has ended did not cover every host: "Stopped at 112 of 254
 * hosts — the scan was cancelled." Undefined while it runs, or when it
 * finished every host.
 */
export function partialStop(job: Pick<ScanJob, 'status' | 'error_message'>, c?: JobCoverage | null): string | undefined {
  if (!c || isJobLive(job.status)) return undefined;
  const unreached = c.hosts_pending + c.hosts_cancelled;
  if (unreached <= 0) return undefined;
  const status = (job.status ?? '').toLowerCase();
  const err = job.error_message;
  let why: string;
  if (status === 'cancelled' || status === 'canceled') why = 'the scan was cancelled';
  else if (stoppedResponding(err)) why = 'the scan stopped responding; Resume scan in the Jobs list runs the hosts it had not finished';
  else if (sensorOffline(err)) why = 'the sensor went offline';
  else if (ranOutOfTime(err)) why = 'it ran out of time';
  else if (status === 'failed' || status === 'error') why = 'the scan failed';
  else why = 'it ended early';
  return `Stopped at ${fmtCount(hostsFinished(c))} of ${plural(c.hosts_total, 'host')} — ${why}.`;
}

/**
 * The server's warnings minus the two this page already restates in its own
 * words (the zero-responder guidance and the partial-run line), so the person
 * does not read the same thing twice. Matching is on the server's sentence
 * opening; if that wording changes, both are shown — never neither.
 */
export function remainingWarnings(c: JobCoverage, shown: { zeroResponder: boolean; partial: boolean }): string[] {
  return (c.warnings ?? []).filter((w) => {
    if (shown.zeroResponder && /^0 of [\d,]+ scanned addresses responded/i.test(w)) return false;
    if (shown.partial && /^stopped at [\d,]+ of [\d,]+ hosts/i.test(w)) return false;
    return true;
  });
}

export interface DepthAdjustmentGroup {
  text: string;
  targets: string[];
}

/**
 * Every depth adjustment, grouped by what was done and why: "2 targets were
 * scanned at Standard depth instead of Thorough — <the server's reason>".
 * Nothing is dropped: each target appears in exactly one group.
 */
export function depthAdjustmentGroups(adjustments?: DepthAdjustment[] | null): DepthAdjustmentGroup[] {
  const groups = new Map<string, { a: DepthAdjustment; targets: string[] }>();
  for (const a of adjustments ?? []) {
    const key = `${a.requested}|${a.applied}|${a.reason}`;
    const g = groups.get(key);
    if (g) g.targets.push(a.target);
    else groups.set(key, { a, targets: [a.target] });
  }
  return Array.from(groups.values()).map(({ a, targets }) => {
    const n = targets.length;
    const reason = a.reason ? ` — ${a.reason}` : '';
    return {
      text: `${plural(n, 'target')} ${n === 1 ? 'was' : 'were'} scanned at ${depthLabel(a.applied)} depth instead of ${depthLabel(a.requested)}${reason}`,
      targets,
    };
  });
}

const CLASS_LABEL: Record<string, string> = {
  private: 'private network',
  registered_segment: 'your registered network',
  external: 'outside your registered networks',
};

export function targetClassLabel(cls?: string | null): string {
  return cls ? (CLASS_LABEL[cls] ?? cls) : '';
}

// ─── Results grouped by host ─────────────────────────────────────────────────

/** How many sample ports a tarpit host's one line lists. The server keeps a bounded sample; this is the display cap. */
export const TARPIT_SAMPLE_SHOWN = 8;

export function isTarpitHost(host: ScanHost): boolean {
  if (host.unit?.responds_on_all_ports) return true;
  return host.ports.some((p) => p.data?.responds_on_all_ports === true);
}

function tarpitSample(host: ScanHost): number[] {
  for (const p of host.ports) {
    const sample = p.data?.open_sample;
    if (Array.isArray(sample)) return sample.filter((n): n is number => typeof n === 'number');
  }
  return host.ports.map((p) => p.port);
}

/** A tarpit host's single line, and the sample ports it lists (never every one). */
export function tarpitSummary(host: ScanHost): { line: string; ports: number[] } {
  const ports = tarpitSample(host).slice(0, TARPIT_SAMPLE_SHOWN);
  return {
    line: `answers on every port — probably a firewall or proxy; showing ${plural(ports.length, 'sample port')}`,
    ports,
  };
}

/** Open ports the host has listed (a UDP service that replied counts). */
export function hostOpenCount(host: ScanHost): number {
  return host.ports.length;
}

/** The evidence the host is there at all. */
export function livenessLabel(state?: string | null): string {
  switch (state) {
    case 'up':
      return 'Answered';
    case 'assumed_up':
      return 'Assumed up (not checked)';
    case 'no_answer':
      return 'No answer to the liveness check';
    case 'undetermined':
      return 'Could not be checked';
    default:
      return '';
  }
}

/**
 * The service column: the protocol, or "open, unidentified" (with the greeting's hint when there was one).
 * A TLS port that answered the handshake with an alert says so: it is TLS, and nothing was negotiated
 * (usually the server needs a name, and the scan had only an address).
 */
export function portServiceLabel(port: Pick<ScanHostPort, 'identified' | 'protocol' | 'service_hint' | 'data'>): string {
  if (port.identified) {
    return port.data?.identification_note === 'tls-handshake-refused' ? `${port.protocol}, handshake refused` : port.protocol;
  }
  return port.service_hint ? `open, unidentified (looks like ${port.service_hint})` : 'open, unidentified';
}

export function portTransportLabel(port: Pick<ScanHostPort, 'transport' | 'data'>): string {
  const t = port.transport ?? (typeof port.data?.transport === 'string' ? port.data.transport : 'tcp');
  return t.toUpperCase();
}

/** Identified ports whose finding carries crypto detail the certificate/cipher view can show. */
export function portHasDetail(port: ScanHostPort): boolean {
  if (!port.identified) return false;
  const d = port.data ?? {};
  return Array.isArray(d.certificates) || typeof d.cipher_suite === 'string';
}

/**
 * A host listed because it answered, with nothing open on the ports scanned
 * (the server marks it `nothing_open` and sends no ports). It is shown as one
 * secondary line, not an expandable row with an empty table.
 */
export function isQuietHost(host: ScanHost): boolean {
  if (host.nothing_open) return true;
  return host.ports.length === 0 && !isTarpitHost(host);
}

/**
 * A quiet host's line: "answered, nothing open (78 ports scanned: all
 * refused)". Refused and filtered are said as they were measured — never
 * "down", never "closed for good" — and a host whose every port was filtered
 * is still a host that answered (its liveness probe was refused).
 */
export function quietHostLine(host: ScanHost): string {
  const u = host.unit;
  if (!u || u.ports_requested <= 0) return 'answered, nothing open on the ports scanned';
  const requested = u.ports_requested;
  let breakdown: string;
  if (u.closed_count === requested) breakdown = 'all refused';
  else if (u.filtered_count === requested) breakdown = 'all filtered';
  else {
    const parts: string[] = [];
    if (u.closed_count > 0) parts.push(`${fmtCount(u.closed_count)} refused`);
    if (u.filtered_count > 0) parts.push(`${fmtCount(u.filtered_count)} filtered`);
    if (u.not_probed_count > 0) parts.push(`${fmtCount(u.not_probed_count)} not probed`);
    breakdown = parts.join(', ');
  }
  const scanned = `${plural(requested, 'port')} scanned`;
  return `answered, nothing open (${breakdown ? `${scanned}: ${breakdown}` : scanned})`;
}
