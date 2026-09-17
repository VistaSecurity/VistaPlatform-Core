// Discovery → Active Scan → the scans started from this page: each
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
import { relTime, shortId } from './kit';
import { useScanJob } from './queries';
import { DANGER, INFO, MUTED, OK, dispatchTimeline, executorLabel, scanJobState } from './scan-job-state';

/** One scan the page started, as the scan response described it. */
export interface StartedScan {
  jobId: string;
  executor: 'platform' | 'sensor';
  sensorName?: string;
  count: number;
  startedAt: string;
}

export interface SkippedAsset {
  assetId: string;
  reason: string;
}

const STEP_COLOR = { done: OK, current: INFO, pending: MUTED, failed: DANGER } as const;

function ScanRow({ scan }: { scan: StartedScan }) {
  const q = useScanJob(scan.jobId);
  const job = q.data;
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

export function ActiveScanJobsPanel({ scans, skipped }: { scans: StartedScan[]; skipped: SkippedAsset[] }) {
  if (scans.length === 0 && skipped.length === 0) return null;
  return (
    <section aria-label="Scans started from this page" style={{ marginBottom: 16 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 6 }}>
        <h3 style={{ margin: 0, fontSize: 13, fontWeight: 700, color: 'var(--app-t1)' }}>Scans started from this page</h3>
        <span style={{ fontSize: 11, color: MUTED }}>updates while a scan runs; cleared when you leave the page</span>
      </div>
      <div className="panel" style={{ padding: 0, borderRadius: 10, overflow: 'hidden' }}>
        <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
          {scans.map((s) => <ScanRow key={s.jobId} scan={s} />)}
        </ul>
        {skipped.length > 0 && (
          <div style={{ padding: '8px 12px', borderTop: '1px solid var(--app-border)', fontSize: 11.5, color: 'var(--danger-text)' }}>
            {skipped.length} asset{skipped.length === 1 ? ' was' : 's were'} not scanned: {skipped[0].reason}
            {skipped.length > 1 ? ` (+${skipped.length - 1} more)` : ''}
          </div>
        )}
      </div>
    </section>
  );
}
