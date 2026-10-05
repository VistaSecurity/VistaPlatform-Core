// The scans a person started from Inventory: each
// job's executor — Platform sensor or the tenant sensor it was handed to —
// its dispatch state (queued · awaiting sensor · running on sensor · completed
// · failed: sensor offline with the sensor's last heartbeat) and the
// timeline. Polled while in flight.
//
// This is the manual scan's own job feedback, rendered immediately without
// waiting on a list refetch. Discovery Jobs (morning-notes decision 7b) also
// lists every scan alongside device interrogations, but without this panel a
// scan sent to a sensor would still vanish the moment the toast faded until
// the next poll — and "failed: sensor offline" would be visible to nobody in
// the meantime.
import { useEffect, useRef } from 'react';
import { Link } from 'react-router';
import { relTime, shortId } from './kit';
import { useScanJob } from './queries';
import { isJobLive } from './scan-plan-view';
import { DANGER, INFO, MUTED, OK, dispatchTimeline, executorLabel, scanJobState } from './scan-job-state';

/** One scan the page started, as the scan response described it. */
export interface StartedScan {
  jobId: string;
  executor: 'platform' | 'sensor';
  sensorName?: string;
  count: number;
  startedAt: string;
}

/** An asset a scan did NOT reach, and why. Every one is listed: a count with
 * the first reason hid which assets were left out, and the per-asset
 * reason is where "why is this host not scanned" plugs in. */
export interface SkippedAsset {
  assetId: string;
  reason: string;
  /** The asset's name when the caller knows it; the short id otherwise. */
  assetName?: string;
}

/** How many refused assets are listed before "+N more". */
export const SKIPPED_SHOWN = 50;

const STEP_COLOR = { done: OK, current: INFO, pending: MUTED, failed: DANGER } as const;

function ScanRow({ scan, onSettled }: { scan: StartedScan; onSettled?: (jobId: string) => void }) {
  const q = useScanJob(scan.jobId);
  const job = q.data;
  // Tell the page once, when this scan ends, so the asset list re-reads what
  // the scan did instead of showing the rows as they were before it ran.
  const ended = !!job?.status && !isJobLive(job.status);
  const told = useRef(false);
  useEffect(() => {
    if (ended && !told.current) {
      told.current = true;
      onSettled?.(scan.jobId);
    }
  }, [ended, onSettled, scan.jobId]);
  const state = job ? scanJobState(job) : q.isError
    ? { label: 'State unavailable', color: MUTED, detail: 'Could not load this scan.' }
    : { label: 'Loading…', color: MUTED };
  const executor = job ? executorLabel(job) : scan.executor === 'sensor' ? scan.sensorName ?? 'Tenant sensor' : 'Platform sensor';
  const steps = job ? dispatchTimeline(job) : [];

  return (
    <li style={{ padding: '10px 12px', borderTop: '1px solid var(--app-border)' }} aria-label={`Scan ${shortId(scan.jobId)}`}>
      <div style={{ display: 'flex', gap: 10, alignItems: 'baseline', flexWrap: 'wrap', fontSize: 12 }}>
        <span className="mono" style={{ color: MUTED }}>{shortId(scan.jobId)}</span>
        <span style={{ color: 'var(--app-t1)' }}>{scan.count} asset{scan.count === 1 ? '' : 's'}</span>
        <span style={{ color: MUTED }}>from</span>
        <span style={{ color: 'var(--app-t1)', fontWeight: 600 }}>{executor}</span>
        <span style={{ flex: 1 }} />
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5, fontWeight: 600, color: state.color }}>
          <span style={{ width: 6, height: 6, borderRadius: 50, background: state.color }} />{state.label}
        </span>
      </div>
      {state.detail && (
        <div style={{ fontSize: 11, color: state.color === DANGER ? 'var(--danger-text)' : MUTED, marginTop: 3, wordBreak: 'break-word' }}>{state.detail}</div>
      )}
      {steps.length > 0 && (
        <ol style={{ listStyle: 'none', margin: '6px 0 0', padding: 0, display: 'flex', gap: 14, flexWrap: 'wrap' }} aria-label="Dispatch timeline">
          {steps.map((s, i) => (
            <li key={i} style={{ display: 'inline-flex', gap: 6, alignItems: 'center', fontSize: 11, color: s.state === 'pending' ? MUTED : 'var(--app-t2)' }}>
              <span style={{ width: 6, height: 6, borderRadius: 50, background: STEP_COLOR[s.state] }} />
              {s.label}
              <span className="mono" style={{ color: MUTED }}>{s.at ? relTime(s.at) : s.state === 'pending' ? '—' : ''}</span>
            </li>
          ))}
        </ol>
      )}
    </li>
  );
}

export function ActiveScanJobsPanel({ scans, skipped, onScanSettled, onDismiss }: {
  scans: StartedScan[];
  skipped: SkippedAsset[];
  /** Called once per scan when its job ends (completed, failed, cancelled). */
  onScanSettled?: (jobId: string) => void;
  /** Clears the panel. */
  onDismiss?: () => void;
}) {
  if (scans.length === 0 && skipped.length === 0) return null;
  const shown = skipped.slice(0, SKIPPED_SHOWN);
  return (
    <section aria-label="Scans started here" style={{ marginBottom: 12 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 6 }}>
        <h3 style={{ margin: 0, fontSize: 13, fontWeight: 700, color: 'var(--app-t1)' }}>Scans started here</h3>
        <span style={{ fontSize: 11, color: MUTED }}>updates while a scan runs; cleared when you leave the page</span>
        <span style={{ flex: 1 }} />
        {onDismiss && <button className="ui-btn sm ghost" onClick={onDismiss} style={{ height: 24, fontSize: 11.5 }}>Dismiss</button>}
      </div>
      <div className="panel" style={{ padding: 0, borderRadius: 10, overflow: 'hidden' }}>
        <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
          {scans.map((s) => <ScanRow key={s.jobId} scan={s} onSettled={onScanSettled} />)}
        </ul>
        {skipped.length > 0 && (
          <div style={{ padding: '8px 12px', borderTop: '1px solid var(--app-border)', fontSize: 11.5 }}>
            <div style={{ color: 'var(--danger-text)', fontWeight: 600, marginBottom: 4 }}>
              {skipped.length} asset{skipped.length === 1 ? ' was' : 's were'} not scanned
            </div>
            <ul aria-label="Assets not scanned" style={{ listStyle: 'none', margin: 0, padding: 0, maxHeight: 180, overflowY: 'auto' }}>
              {shown.map((s) => (
                <li key={s.assetId} style={{ display: 'flex', gap: 8, padding: '2px 0', color: 'var(--app-t2)' }}>
                  <Link to={`/inventory/assets/${s.assetId}`} className={s.assetName ? undefined : 'mono'} style={{ color: 'var(--app-t1)', flex: 'none' }}>
                    {s.assetName ?? shortId(s.assetId)}
                  </Link>
                  <span style={{ color: MUTED }}>{s.reason}</span>
                </li>
              ))}
            </ul>
            {skipped.length > shown.length && (
              <div style={{ color: MUTED, marginTop: 4 }}>+{skipped.length - shown.length} more</div>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
