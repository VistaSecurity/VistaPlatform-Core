import { describe, expect, it } from 'vitest';
import { type ScanJob, DANGER, INFO, OK, WARN, dispatchTimeline, executorLabel, scanJobFromRecent, scanJobState } from './scan-job-state';

// Every job state the spec table names, rendered from the API's job shape
// on the two surfaces that show scans — the Active Scan page's own
// feedback and the Active Scanning settings run list: queued · awaiting
// sensor · running · completed · failed: sensor offline.

function job(over: Partial<ScanJob>): ScanJob {
  return { id: 'job-1', status: 'queued', execution_mode: 'sensors', executor: 'sensor', assigned_sensor_name: 'xps16-sensor',
    targets: ['192.0.2.10'], created_at: '2026-09-17T12:00:00Z', ...over };
}

describe('executorLabel', () => {
  it('names the tenant sensor, or the platform', () => {
    expect(executorLabel(job({}))).toBe('xps16-sensor');
    expect(executorLabel(job({ executor: 'sensor', assigned_sensor_name: undefined }))).toBe('Tenant sensor');
    expect(executorLabel(job({ executor: 'platform', execution_mode: 'async', assigned_sensor_name: undefined }))).toBe('Platform sensor');
    // An older API without `executor`: the mode still says whose job it is.
    expect(executorLabel({ execution_mode: 'sensors' })).toBe('Tenant sensor');
    expect(executorLabel({ execution_mode: 'auto' })).toBe('Platform sensor');
  });
});

describe('scanJobState', () => {
  it('queued', () => {
    expect(scanJobState(job({ status: 'queued' }))).toMatchObject({ label: 'Queued', color: WARN });
  });
  it('awaiting sensor — dispatched, not yet collected', () => {
    const s = scanJobState(job({ status: 'awaiting_sensor', dispatched_at: '2026-09-17T12:00:05Z' }));
    expect(s.label).toBe('Awaiting xps16-sensor');
    expect(s.color).toBe(WARN);
    expect(s.detail).toMatch(/dispatched/);
  });
  it('running on the sensor — the command was collected', () => {
    const s = scanJobState(job({ status: 'awaiting_sensor', dispatched_at: '2026-09-17T12:00:05Z', picked_up_at: '2026-09-17T12:00:35Z' }));
    expect(s.label).toBe('Running on xps16-sensor');
    expect(s.color).toBe(INFO);
  });
  it('running on the platform', () => {
    expect(scanJobState(job({ status: 'running', executor: 'platform', execution_mode: 'async' }))).toMatchObject({ label: 'Running', color: INFO });
  });
  it('completed', () => {
    expect(scanJobState(job({ status: 'completed' }))).toMatchObject({ label: 'Completed', color: OK });
  });
  it('failed: sensor offline, with the last heartbeat', () => {
    const s = scanJobState(job({ status: 'failed', error_message: 'sensor xps16-sensor offline; nothing was scanned (last heartbeat 2026-09-17T11:00:00Z)', assigned_sensor_last_heartbeat: '2026-09-17T11:00:00Z' }));
    expect(s.label).toBe('Failed: sensor offline');
    expect(s.color).toBe(DANGER);
    expect(s.detail).toMatch(/nothing was scanned/);
    expect(s.detail).toMatch(/last heartbeat/);
  });
  it('failed for another reason keeps the plain label and the message', () => {
    const s = scanJobState(job({ status: 'failed', error_message: 'rate limit exceeded' }));
    expect(s.label).toBe('Failed');
    expect(s.detail).toBe('rate limit exceeded');
  });
  it('cancelled', () => {
    expect(scanJobState(job({ status: 'cancelled' })).label).toBe('Cancelled');
  });
});

describe('scanJobFromRecent', () => {
  it('folds the settings run list row onto the job shape so one state rule serves both surfaces', () => {
    const s = scanJobState(scanJobFromRecent({
      id: 'auto-1', status: 'failed', target_count: 3, created_at: '2026-09-17T12:00:00Z',
      executor: 'sensor', executor_name: 'xps16-sensor', executor_last_heartbeat: '2026-09-17T11:00:00Z',
      dispatched_at: '2026-09-17T12:00:05Z', error_message: 'sensor xps16-sensor offline; nothing was scanned',
    }));
    expect(s.label).toBe('Failed: sensor offline');
    expect(s.detail).toMatch(/last heartbeat/);
    const running = scanJobState(scanJobFromRecent({
      id: 'auto-2', status: 'awaiting_sensor', target_count: 1, created_at: 'c', executor: 'sensor', executor_name: 'xps16-sensor',
      dispatched_at: 'd', picked_up_at: 'p',
    }));
    expect(running.label).toBe('Running on xps16-sensor');
    expect(scanJobState(scanJobFromRecent({ id: 'auto-3', status: 'completed', target_count: 1, created_at: 'c', executor: 'platform' })).label).toBe('Completed');
  });
});

describe('dispatchTimeline', () => {
  it('sensor job: queued → dispatched → picked up → completed', () => {
    const steps = dispatchTimeline(job({ status: 'completed', dispatched_at: 'd', picked_up_at: 'p', completed_at: 'c' }));
    expect(steps.map((s) => s.label)).toEqual(['Queued', 'Dispatched to xps16-sensor', 'Picked up by xps16-sensor', 'Completed']);
    expect(steps.every((s) => s.state === 'done')).toBe(true);
  });
  it('awaiting: the pickup is the current step', () => {
    const steps = dispatchTimeline(job({ status: 'awaiting_sensor', dispatched_at: 'd' }));
    expect(steps.map((s) => s.state)).toEqual(['done', 'done', 'current', 'pending']);
  });
  it('failed: sensor offline lands the failure on the pickup that never happened', () => {
    const steps = dispatchTimeline(job({ status: 'failed', dispatched_at: 'd', completed_at: 'c', error_message: 'sensor xps16-sensor offline; nothing was scanned' }));
    expect(steps.map((s) => s.state)).toEqual(['done', 'done', 'failed', 'pending']);
    expect(steps[2].at).toBe('c');
  });
  it('platform job: queued → started → completed', () => {
    const steps = dispatchTimeline(job({ status: 'running', executor: 'platform', execution_mode: 'async', started_at: 's' }));
    expect(steps.map((s) => s.label)).toEqual(['Queued', 'Started', 'Completed']);
    expect(steps.map((s) => s.state)).toEqual(['done', 'done', 'current']);
  });
});
