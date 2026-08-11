// VISTA Operations — Support ▸ Job Repair. Platform-wide interrogation jobs
// (GET /admin/jobs) with per-row repair actions: Retry (failed|cancelled) and
// Cancel (pending|assigned|in_progress). Both go through a confirm Modal before
// firing, then toast + invalidate the jobs query. A status filter (chips) defaults
// to the problem states. All calls go through the typed clients.devices.
import { useMemo, useState } from 'react';
import toast from 'react-hot-toast';
import { Wrench, RotateCcw, Ban } from 'lucide-react';
import { StatusTag, relTime } from '../../components/ui/primitives';
import { Modal } from '../../components/ui/modal';
import { useAdminJobs, useJobRepairMutations, errMsg, type AdminInterrogationJob } from './support-queries';

// status → StatusTag key. 'cancelled' maps to the muted job-cancel signal; the
// rest already exist in the design status table.
const statusKey = (s: string): string => (s === 'cancelled' ? 'canceled_job' : s);

const ALL_STATUSES = ['pending', 'assigned', 'in_progress', 'completed', 'failed', 'cancelled'] as const;
type StatusFilter = 'problems' | 'all' | (typeof ALL_STATUSES)[number];
const PROBLEM_STATES = new Set(['failed', 'pending', 'assigned', 'in_progress']);

const canRetry = (s: string) => s === 'failed' || s === 'cancelled';
const canCancel = (s: string) => s === 'pending' || s === 'assigned' || s === 'in_progress';

type Confirm = { action: 'retry' | 'cancel'; job: AdminInterrogationJob } | null;

export function JobRepairPage() {
  const { data, isLoading, isError, refetch } = useAdminJobs();
  const mut = useJobRepairMutations();
  const [filter, setFilter] = useState<StatusFilter>('problems');
  const [confirm, setConfirm] = useState<Confirm>(null);

  const jobs = useMemo(() => data ?? [], [data]);
  const filtered = useMemo(() => {
    if (filter === 'all') return jobs;
    if (filter === 'problems') return jobs.filter((j) => PROBLEM_STATES.has(j.status));
    return jobs.filter((j) => j.status === filter);
  }, [jobs, filter]);

  const runConfirm = () => {
    if (!confirm) return;
    const { action, job } = confirm;
    const m = action === 'retry' ? mut.retry : mut.cancel;
    m.mutate(job.id, {
      onSuccess: () => { toast.success(action === 'retry' ? 'Job queued for retry' : 'Job cancelled'); setConfirm(null); },
      onError: (e) => { toast.error(errMsg(e)); setConfirm(null); },
    });
  };

  const chips: { id: StatusFilter; label: string }[] = [
    { id: 'problems', label: 'Problems' },
    { id: 'all', label: 'All' },
    ...ALL_STATUSES.map((s) => ({ id: s as StatusFilter, label: s.replace('_', ' ') })),
  ];

  const pending = mut.retry.isPending || mut.cancel.isPending;

  return (
    <div className="op-fade" style={{ height: '100%', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
      {/* filter bar */}
      <div style={{ flex: 'none', display: 'flex', alignItems: 'center', gap: 6, padding: '12px 24px', borderBottom: '1px solid var(--op-border)', flexWrap: 'wrap' }}>
        {chips.map((c) => (
          <button key={c.id} onClick={() => setFilter(c.id)} className={'op-chip' + (filter === c.id ? ' active' : '')} style={{ textTransform: 'capitalize' }}>{c.label}</button>
        ))}
      </div>

      <div style={{ flex: 1, minHeight: 0, overflowY: 'auto' }}>
        <table className="op-table">
          <thead>
            <tr>
              <th>Tenant</th>
              <th>Type</th>
              <th>Status</th>
              <th>Device / Integration</th>
              <th>Worker</th>
              <th>Started</th>
              <th>Error</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((j) => (
              <tr key={j.id}>
                <td style={{ fontWeight: 500, color: 'var(--op-t1)' }}>{j.tenant_name || j.tenant_slug || '—'}</td>
                <td className="t-muted" style={{ fontSize: 12 }}>{j.job_type}</td>
                <td><StatusTag status={statusKey(j.status)} /></td>
                <td className="t-muted" style={{ fontSize: 12 }}>{j.device_name || j.integration_name || '—'}</td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{j.worker ? j.worker.slice(0, 8) : '—'}</td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{relTime(j.started_at ?? j.created_at)}</td>
                <td className="t-muted" style={{ fontSize: 11.5, maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: j.error_message ? 'var(--danger-text)' : 'var(--op-t3)' }} title={j.error_message || ''}>{j.error_message || '—'}</td>
                <td style={{ textAlign: 'right' }}>
                  <div style={{ display: 'inline-flex', gap: 6 }}>
                    {canRetry(j.status) && (
                      <button className="op-btn sm" disabled={pending} onClick={() => setConfirm({ action: 'retry', job: j })}><RotateCcw size={13} />Retry</button>
                    )}
                    {canCancel(j.status) && (
                      <button className="op-btn sm danger" disabled={pending} onClick={() => setConfirm({ action: 'cancel', job: j })}><Ban size={13} />Cancel</button>
                    )}
                    {!canRetry(j.status) && !canCancel(j.status) && <span className="t-muted" style={{ fontSize: 11 }}>—</span>}
                  </div>
                </td>
              </tr>
            ))}
            {isLoading && <tr><td colSpan={8} style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>Loading jobs…</td></tr>}
            {isError && !isLoading && <tr><td colSpan={8} style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>Couldn't load jobs. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => refetch()}>Retry</button></td></tr>}
            {!isLoading && !isError && filtered.length === 0 && <tr><td colSpan={8} style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>No jobs match this filter.</td></tr>}
          </tbody>
        </table>
      </div>

      <div style={{ flex: 'none', padding: '9px 24px', borderTop: '1px solid var(--op-border)', display: 'flex', alignItems: 'center', gap: 14, fontSize: 12, color: 'var(--op-t3)' }}>
        <Wrench size={13} />
        <span>{filtered.length} jobs</span>
        <span>·</span>
        <span>Retry failed or cancelled jobs; cancel stuck pending/in-progress jobs.</span>
      </div>

      {confirm && (
        <Modal
          open
          onClose={() => setConfirm(null)}
          title={confirm.action === 'retry' ? 'Retry job?' : 'Cancel job?'}
          description={
            confirm.action === 'retry'
              ? `Re-queue the ${confirm.job.job_type} job for ${confirm.job.tenant_name || confirm.job.tenant_slug || 'this tenant'}?`
              : `Cancel the ${confirm.job.job_type} job for ${confirm.job.tenant_name || confirm.job.tenant_slug || 'this tenant'}? This stops it from running.`
          }
          tone={confirm.action === 'cancel' ? 'danger' : 'blue'}
          size="sm"
          footerNote="Platform-admin · audited"
          primaryLabel={confirm.action === 'retry' ? 'Retry job' : 'Cancel job'}
          onPrimary={runConfirm}
          primaryLoading={pending}
          secondaryLabel="Dismiss"
        />
      )}
    </div>
  );
}
