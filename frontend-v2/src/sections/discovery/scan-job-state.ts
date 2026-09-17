// How a discovery job (a scan) reads where scans are visible: the
// Active Scan page's own job feedback for scans started there, and the Active
// Scanning settings run list for automatic ones. Who is running it, what state
// it is in, and the dispatch timeline when a tenant sensor is involved.
//
// Out of the component so every state in the spec table is a table test:
// queued · awaiting sensor · running · completed · failed: sensor offline.
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { relTime } from './kit';

export type ScanJob = inventoryComponents['schemas']['DiscoveryJob'];
export type RecentAutoScan = inventoryComponents['schemas']['AutoScanRecentJob'];

/** The settings run list's row shape, folded onto the job shape so one state rule serves both surfaces. */
export function scanJobFromRecent(job: RecentAutoScan): ScanJob {
  return {
    id: job.id,
    status: job.status,
    executor: job.executor,
    execution_mode: job.executor === 'sensor' ? 'sensors' : 'async',
    assigned_sensor_name: job.executor_name,
    assigned_sensor_last_heartbeat: job.executor_last_heartbeat,
    dispatched_at: job.dispatched_at,
    picked_up_at: job.picked_up_at,
    completed_at: job.completed_at,
    error_message: job.error_message,
    created_at: job.created_at,
  };
}

export interface ScanJobState {
  /** Short chip text. */
  label: string;
  /** CSS colour token. */
  color: string;
  /** One line under the chip — e.g. the failure reason. */
  detail?: string;
}

export const OK = 'var(--ok)';
export const INFO = 'var(--info)';
export const WARN = 'var(--warn)';
export const DANGER = 'var(--danger)';
export const MUTED = 'var(--app-t3)';

/** "Platform sensor" or the tenant sensor's name; a sensor job with no name yet still says it is a sensor's. */
export function executorLabel(job: Pick<ScanJob, 'executor' | 'assigned_sensor_name' | 'execution_mode'>): string {
  const sensorJob = job.executor === 'sensor' || (job.execution_mode ?? '').toLowerCase() === 'sensors';
  if (!sensorJob) return 'Platform sensor';
  return job.assigned_sensor_name ?? 'Tenant sensor';
}

function isSensorOffline(msg?: string | null): boolean {
  return /sensor .*offline|offline; nothing was scanned/i.test(msg ?? '');
}

/**
 * The state chip. `awaiting_sensor` splits in two by whether the sensor has
 * collected the command yet: waiting on a heartbeat is not the same as
 * scanning, and the operator watching the page needs to know which.
 */
export function scanJobState(job: ScanJob): ScanJobState {
  const status = (job.status ?? '').toLowerCase();
  const err = job.error_message ?? undefined;
  switch (status) {
    case 'queued':
    case 'pending':
      return { label: 'Queued', color: WARN };
    case 'awaiting_sensor':
      if (job.picked_up_at) return { label: `Running on ${executorLabel(job)}`, color: INFO };
      return { label: `Awaiting ${executorLabel(job)}`, color: WARN, detail: job.dispatched_at ? `dispatched ${relTime(job.dispatched_at)}` : undefined };
    case 'running':
    case 'in_progress':
    case 'processing':
      return { label: 'Running', color: INFO };
    case 'completed':
    case 'success':
      return { label: 'Completed', color: OK };
    case 'failed':
    case 'error':
      if (isSensorOffline(err)) {
        const beat = job.assigned_sensor_last_heartbeat ? ` (last heartbeat ${relTime(job.assigned_sensor_last_heartbeat)})` : '';
        return { label: 'Failed: sensor offline', color: DANGER, detail: `${err ?? ''}${beat}`.trim() };
      }
      return { label: 'Failed', color: DANGER, detail: err };
    case 'cancelled':
      return { label: 'Cancelled', color: MUTED };
    default:
      return { label: job.status || 'Unknown', color: MUTED };
  }
}

export interface TimelineStep {
  label: string;
  at?: string | null;
  /** done · current · pending · failed */
  state: 'done' | 'current' | 'pending' | 'failed';
}

/**
 * queued → dispatched to X → picked up → completed, for a job on a tenant
 * sensor; queued → started → completed for a platform job. A failure marks the
 * step it happened at.
 */
export function dispatchTimeline(job: ScanJob): TimelineStep[] {
  const status = (job.status ?? '').toLowerCase();
  const failed = status === 'failed' || status === 'error';
  const done = status === 'completed' || status === 'success';
  const sensor = job.executor === 'sensor' || (job.execution_mode ?? '').toLowerCase() === 'sensors';

  const steps: TimelineStep[] = [{ label: 'Queued', at: job.created_at, state: 'done' }];
  if (sensor) {
    const name = executorLabel(job);
    steps.push({ label: `Dispatched to ${name}`, at: job.dispatched_at, state: job.dispatched_at ? 'done' : 'pending' });
    steps.push({ label: `Picked up by ${name}`, at: job.picked_up_at, state: job.picked_up_at ? 'done' : 'pending' });
  } else {
    steps.push({ label: 'Started', at: job.started_at, state: job.started_at ? 'done' : 'pending' });
  }
  steps.push({ label: done ? 'Completed' : failed ? 'Failed' : 'Completed', at: job.completed_at, state: done ? 'done' : failed ? 'failed' : 'pending' });

  if (failed) {
    // The failure lands on the first step that did not happen.
    const firstPending = steps.findIndex((s) => s.state === 'pending');
    if (firstPending >= 0) {
      steps[firstPending] = { ...steps[firstPending], state: 'failed', at: job.completed_at ?? steps[firstPending].at };
      for (let i = firstPending + 1; i < steps.length; i++) steps[i] = { ...steps[i], state: 'pending' };
    }
  } else if (!done) {
    const firstPending = steps.findIndex((s) => s.state === 'pending');
    if (firstPending >= 0) steps[firstPending] = { ...steps[firstPending], state: 'current' };
  }
  return steps;
}
