// VISTA Operations — Maintenance › Run history. The last 20 backup, update
// and rollback runs: what ran, who started it, when, how it ended and — for a
// failure — the step that failed. Backups and About & Updates both mount it;
// each row links to the run's progress page (/maintenance/runs/:id).
import { Link } from 'react-router';
import { History, RefreshCw } from 'lucide-react';
import { Tag } from '../../components/ui/primitives';
import { Panel } from '../system/parts';
import { useMaintenanceRuns, type MaintenanceRun } from './maintenance-queries';

const KIND_LABEL: Record<MaintenanceRun['kind'], string> = { backup: 'Backup', update: 'Update', rollback: 'Roll back' };
const STATUS_META: Record<MaintenanceRun['status'], { label: string; color: string }> = {
  running: { label: 'Running…', color: 'var(--op-accent)' },
  succeeded: { label: 'Succeeded', color: 'var(--ok)' },
  failed: { label: 'Failed', color: 'var(--danger)' },
  cancelled: { label: 'Cancelled', color: 'var(--op-t3)' },
};

/** YYYY-MM-DD HH:MM in the viewer's time zone. */
export function formatWhen(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** The failed step and its error, for the Outcome column. */
export function failedStepSummary(run: MaintenanceRun): string | null {
  const step = run.steps.find((s) => s.status === 'failed');
  if (!step) return run.status === 'failed' ? run.error ?? null : null;
  const why = step.error ?? run.error; // the service omits an empty error
  return why ? `${step.name}: ${why}` : step.name;
}

function versions(run: MaintenanceRun): string {
  if (run.kind === 'backup') return run.from_version ? `of ${run.from_version}` : '';
  if (run.from_version && run.to_version) return `${run.from_version} → ${run.to_version}`;
  return run.to_version ?? '';
}

export function RunHistory({ limit = 20 }: { limit?: number }) {
  const q = useMaintenanceRuns(limit);
  const runs = q.data ?? [];
  return (
    <Panel title="Run history" icon={History}>
      <table className="op-table" data-testid="run-history">
        <thead><tr><th>Run</th><th>Started by</th><th>Started</th><th>Outcome</th></tr></thead>
        <tbody>
          {q.isLoading && (
            <tr><td colSpan={4}><div data-testid="runs-skeleton" style={{ height: 28, borderRadius: 'var(--r-md, 8px)', background: 'var(--op-track)', opacity: 0.55 }} /></td></tr>
          )}
          {q.isError && (
            <tr><td colSpan={4} style={{ textAlign: 'center', padding: 24, color: 'var(--op-t3)' }}>
              Couldn’t load the run history.
              <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => { void q.refetch(); }}><RefreshCw size={12} /> Retry</button>
            </td></tr>
          )}
          {!q.isLoading && !q.isError && runs.length === 0 && (
            <tr><td colSpan={4} style={{ textAlign: 'center', padding: 24, color: 'var(--op-t3)' }}>No maintenance runs yet</td></tr>
          )}
          {runs.map((run) => {
            const meta = STATUS_META[run.status];
            const failed = failedStepSummary(run);
            return (
              <tr key={run.id} data-testid="run-row" data-status={run.status}>
                <td>
                  <Link to={`/maintenance/runs/${run.id}`} data-testid="run-link" style={{ fontWeight: 600 }}>{KIND_LABEL[run.kind]}</Link>
                  {versions(run) && <span style={{ marginLeft: 6, color: 'var(--op-t3)', fontSize: 12 }}>{versions(run)}</span>}
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} title={run.started_by ?? undefined}>
                  {run.started_by ? `${run.started_by.slice(0, 8)}…` : '—'}
                </td>
                <td>{formatWhen(run.started_at)}</td>
                <td>
                  <Tag color={meta.color}>{meta.label}</Tag>
                  {failed && <div data-testid="failed-step" style={{ marginTop: 4, fontSize: 11.5, color: 'var(--danger)', maxWidth: 420 }}>{failed}</div>}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </Panel>
  );
}
