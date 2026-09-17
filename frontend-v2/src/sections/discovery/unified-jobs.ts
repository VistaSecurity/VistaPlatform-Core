// Discovery → Discovery Jobs — merging two job sources into one table
// (morning-notes decision 7b).
//
// Before this, `discovery_jobs` (Active Scan, the Discover wizard, and the
// automatic-scan sweep) had NO listing page anywhere: this page listed
// only device-interrogation jobs (`device_jobs`, device-interrogation-service).
// A scan sent to a tenant sensor was visible only as a feedback panel on the
// page that started it, or a stub run list on Settings → Active Scanning.
//
// Out of the component so every merge/label/filter rule is a table test —
// the same pattern kit.ts and scan-job-state.ts already use here.
import type { deviceInterrogationComponents } from '@vistasecurity/api-contract';
import { jobMeta, jobTypeLabel, relTime, durationFmt } from './kit';
import { type ScanJob, dispatchTimeline, executorLabel, scanJobState, type TimelineStep } from './scan-job-state';

export type InterrogationJob = deviceInterrogationComponents['schemas']['InterrogationJob'];

export type JobKind = 'interrogation' | 'discovery' | 'automatic';

export function kindLabel(kind: JobKind): string {
  switch (kind) {
    case 'interrogation':
      return 'Interrogation';
    case 'automatic':
      return 'Automatic scan';
    case 'discovery':
      return 'Discovery';
  }
}

/**
 * A `discovery_jobs` row's kind. `origin` is the sweep's marker
 * (`metadata.options.origin`, surfaced by cluster-sensor-service's GetJob/
 * GetJobs as a read-only field) — everything else that reaches
 * cluster-sensor-service (Active Scan, the Discover wizard) is "discovery".
 */
export function discoveryJobKind(job: Pick<ScanJob, 'origin'>): 'discovery' | 'automatic' {
  return job.origin === 'auto_scan' ? 'automatic' : 'discovery';
}

/** Coarse status bucket shared across both job vocabularies, for the Status filter. */
export type StatusBucket = 'queued' | 'awaiting_sensor' | 'running' | 'completed' | 'failed' | 'cancelled';

export function statusBucket(status?: string | null): StatusBucket {
  const s = (status ?? '').toLowerCase();
  if (s === 'awaiting_sensor') return 'awaiting_sensor';
  if (s === 'running' || s === 'in_progress' || s === 'processing') return 'running';
  if (s === 'completed' || s === 'success') return 'completed';
  if (s === 'failed' || s === 'error') return 'failed';
  if (s === 'cancelled' || s === 'canceled') return 'cancelled';
  return 'queued';
}

export const STATUS_BUCKET_LABELS: Record<StatusBucket, string> = {
  queued: 'Queued',
  awaiting_sensor: 'Awaiting sensor',
  running: 'Running',
  completed: 'Completed',
  failed: 'Failed',
  cancelled: 'Cancelled',
};

export interface UnifiedJobRow {
  kind: JobKind;
  id: string;
  /** Row title — the job type (interrogation) or "Discovery"/"Automatic scan". */
  label: string;
  /** Target text for the row, already truncated for display. */
  target: string;
  targetCount?: number;
  executor: string;
  statusLabel: string;
  statusColor: string;
  statusDetail?: string;
  bucket: StatusBucket;
  /** Device/integration name (interrogation) or the kind label (discovery/automatic) — the Source column. */
  source: string;
  /** Assets found. Discovery/automatic rows show '—': the list endpoint does
   *  not carry a findings count (per-row would mean an N+1 fetch); see the
   *  count in the detail panel instead. */
  found: number | string;
  startedAt?: string | null;
  durationSec?: number | null;
  sortKey: number;
  raw: { source: 'interrogation'; job: InterrogationJob } | { source: 'discovery'; job: ScanJob };
}

function sortKeyOf(iso?: string | null): number {
  if (!iso) return 0;
  const t = new Date(iso).getTime();
  return Number.isFinite(t) ? t : 0;
}

function interrogationTarget(job: InterrogationJob): string {
  return job.device_name || job.integration_name || '—';
}

export function interrogationRow(job: InterrogationJob): UnifiedJobRow {
  const m = jobMeta(job.status);
  return {
    kind: 'interrogation',
    id: job.id,
    label: jobTypeLabel(job.job_type) ?? job.job_type ?? 'Job',
    target: interrogationTarget(job),
    executor: job.executor || '—',
    statusLabel: m.l,
    statusColor: m.c,
    bucket: statusBucket(job.status),
    source: job.cloud_provider || job.device_type || (job.integration_name ? 'cloud' : '—'),
    found: job.assets_discovered ?? '—',
    startedAt: job.started_at || job.created_at,
    durationSec: job.duration_seconds,
    sortKey: sortKeyOf(job.started_at || job.created_at),
    raw: { source: 'interrogation', job },
  };
}

function discoveryTarget(job: ScanJob): string {
  const targets = job.targets ?? [];
  if (targets.length === 0) return '—';
  return targets.length <= 2 ? targets.join(', ') : `${targets.slice(0, 2).join(', ')} +${targets.length - 2}`;
}

export function discoveryRow(job: ScanJob): UnifiedJobRow {
  const kind = discoveryJobKind(job);
  const state = scanJobState(job);
  return {
    kind,
    id: job.id,
    label: kindLabel(kind),
    target: discoveryTarget(job),
    targetCount: job.targets?.length,
    executor: executorLabel(job),
    statusLabel: state.label,
    statusColor: state.color,
    statusDetail: state.detail,
    bucket: statusBucket(job.status),
    source: kindLabel(kind),
    found: '—',
    startedAt: job.dispatched_at ?? job.started_at ?? job.created_at,
    durationSec: undefined,
    sortKey: sortKeyOf(job.created_at),
    raw: { source: 'discovery', job },
  };
}

/** Both sources, newest first. Neither list is dropped — losing either half
 * is exactly the regression the reachability test guards against. */
export function mergeJobs(deviceJobs: InterrogationJob[], discoveryJobs: ScanJob[]): UnifiedJobRow[] {
  const rows = [...deviceJobs.map(interrogationRow), ...discoveryJobs.map(discoveryRow)];
  return rows.sort((a, b) => b.sortKey - a.sortKey);
}

export interface JobFilters {
  kind: 'all' | JobKind;
  status: 'all' | StatusBucket;
  /** An executor label from `distinctExecutors`, or the sentinel `'all'`. */
  executor: string;
}

export const DEFAULT_FILTERS: JobFilters = { kind: 'all', status: 'all', executor: 'all' };

export function matchesFilters(row: UnifiedJobRow, filters: JobFilters): boolean {
  if (filters.kind !== 'all' && row.kind !== filters.kind) return false;
  if (filters.status !== 'all' && row.bucket !== filters.status) return false;
  if (filters.executor !== 'all' && row.executor !== filters.executor) return false;
  return true;
}

export function filterRows(rows: UnifiedJobRow[], filters: JobFilters): UnifiedJobRow[] {
  return rows.filter((r) => matchesFilters(r, filters));
}

/** Distinct executor names present, for the Executor filter's option list. */
export function distinctExecutors(rows: UnifiedJobRow[]): string[] {
  const seen = new Set<string>();
  for (const r of rows) {
    if (r.executor && r.executor !== '—') seen.add(r.executor);
  }
  return Array.from(seen).sort((a, b) => a.localeCompare(b));
}

/** Re-exported so the detail panel does not need its own import of scan-job-state. */
export function discoveryJobTimeline(job: ScanJob): TimelineStep[] {
  return dispatchTimeline(job);
}

export function durationLabel(sec?: number | null): string {
  return durationFmt(sec);
}

export function relTimeLabel(iso?: string | null): string {
  return relTime(iso);
}
