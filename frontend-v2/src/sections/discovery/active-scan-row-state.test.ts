import { describe, expect, it } from 'vitest';
import { activeScanView, anyScanning, isScanning } from './active-scan-row-state';
import { scanButtonTitle } from '../inventory/bulk-actions';

// The row states a person's scan puts an asset in, read from the API's
// `active_scan` record.

const scanning = { id: 'a', active_scan: { status: 'scanning' as const, started_at: '2026-10-04T10:00:00Z', job_ids: ['j1'] } };
const completed = { id: 'b', active_scan: { status: 'completed' as const, started_at: '2026-10-04T10:00:00Z', finished_at: '2026-10-04T10:02:00Z', job_ids: ['j1'] } };
const failed = { id: 'c', active_scan: { status: 'failed' as const, finished_at: '2026-10-04T10:03:00Z', job_ids: ['j2'] } };
const never: { id: string; active_scan?: undefined } = { id: 'd' };

describe('activeScanView', () => {
  it('reads each record status', () => {
    expect(activeScanView(scanning)).toEqual({ kind: 'scanning', since: '2026-10-04T10:00:00Z' });
    expect(activeScanView(completed)).toEqual({ kind: 'completed', at: '2026-10-04T10:02:00Z' });
    expect(activeScanView(failed)).toEqual({ kind: 'failed', at: '2026-10-04T10:03:00Z' });
  });
  it('treats no record, null and an unknown status as never scanned', () => {
    expect(activeScanView(never)).toEqual({ kind: 'none' });
    expect(activeScanView({ active_scan: null })).toEqual({ kind: 'none' });
    expect(activeScanView(undefined)).toEqual({ kind: 'none' });
    expect(activeScanView({ active_scan: { status: 'queued' as never, job_ids: [] } })).toEqual({ kind: 'none' });
  });
});

describe('the list while a scan runs', () => {
  it('only a scanning row is in flight', () => {
    expect(isScanning(scanning)).toBe(true);
    expect([completed, failed, never].some(isScanning)).toBe(false);
  });
  it('polls while any row is scanning, and stops once none is', () => {
    expect(anyScanning([never, scanning])).toBe(true);
    expect(anyScanning([never, failed, completed])).toBe(false);
    expect(anyScanning([])).toBe(false);
  });
});

describe('the drawer button tooltip', () => {
  const now = new Date('2026-10-04T10:05:00Z').getTime();
  it('says a scan is running', () => {
    expect(scanButtonTitle(activeScanView(scanning), now)).toBe('A scan of this asset is running (started 5m ago); results appear once it finishes');
  });
  it('says how the last scan ended', () => {
    expect(scanButtonTitle(activeScanView(completed), now)).toContain('Last scan finished 3m ago.');
    expect(scanButtonTitle(activeScanView(failed), now)).toContain('Last scan failed 2m ago');
    expect(scanButtonTitle(activeScanView(never), now)).toBe('Active Scan — probe this asset now and catalog its TLS crypto');
  });
});
