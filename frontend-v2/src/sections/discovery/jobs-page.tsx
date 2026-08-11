import { useMutation, useQueryClient } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { Icon } from '../../components/ui';
import { DTable, CellMono, CellTxt, PageWrap, queryNote, jobMeta, relTime, durationFmt, shortId } from './kit';
import { useJobs } from './queries';

// Discovery → Discovery Jobs — the mock's `discovery-jobs` table, live from
// device-interrogation-service: Job · Type · Target · Source · Found · Duration
// · Status. "Source" is the device or cloud integration the job ran against.
// Adds the write surface: retry (failed/cancelled) + cancel (in-flight), both
// gated on discovery.manage.

const COLS = [
  { label: 'Job', w: '90px' },
  { label: 'Type', w: '1.2fr' },
  { label: 'Target', w: '1fr' },
  { label: 'Source', w: '1fr' },
  { label: 'Found', w: '70px', align: 'right' as const },
  { label: 'Duration', w: '90px', align: 'right' as const },
  { label: 'Status', w: '120px', align: 'right' as const },
  { label: '', w: '92px', align: 'right' as const },
];

// Jobs that are still in flight (cancellable). Mirrors the Go handler's allowed
// set: pending / assigned / in-progress.
const CANCELLABLE = new Set(['pending', 'queued', 'assigned', 'in_progress', 'in-progress', 'running', 'processing']);
// Jobs that can be retried: failed / cancelled.
const RETRYABLE = new Set(['failed', 'error', 'cancelled', 'canceled']);

function RowBtn({ icon, title, onClick, disabled }: { icon: string; title: string; onClick: () => void; disabled?: boolean }) {
  return (
    <button
      className="ui-btn sm ghost"
      title={title}
      aria-label={title}
      disabled={disabled}
      onClick={(e) => { e.stopPropagation(); onClick(); }}
      style={{ flex: 'none', padding: '0 7px' }}
    >
      <Icon name={icon} size={13} />
    </button>
  );
}

export function JobsPage() {
  const q = useJobs();
  const qc = useQueryClient();
  const jobs = q.data?.jobs ?? [];

  const invalidate = () => qc.invalidateQueries({ queryKey: ['discovery', 'jobs'] });

  const retry = useMutation({
    mutationFn: async (id: string) => {
      const { data, error } = await clients.devices.POST('/jobs/{id}/retry', { params: { path: { id } } });
      if (error || !data) throw new Error('Failed to retry job');
      return data;
    },
    onSettled: invalidate,
  });

  const cancel = useMutation({
    mutationFn: async (id: string) => {
      const { data, error } = await clients.devices.POST('/jobs/{id}/cancel', { params: { path: { id } } });
      if (error || !data) throw new Error('Failed to cancel job');
      return data;
    },
    onSettled: invalidate,
  });

  const busy = retry.isPending || cancel.isPending;

  const note = queryNote(q, jobs.length === 0, {
    thing: 'jobs',
    emptyTitle: 'No jobs',
    emptyMessage: 'No discovery / interrogation jobs have run for this tenant yet.',
  });

  return (
    <PageWrap title="Discovery Jobs" count={q.isLoading ? '' : q.data?.total ?? jobs.length}>
      {note ?? (
        <DTable
          cols={COLS}
          rows={jobs}
          rowKey={(j) => j.id}
          render={(j) => {
            const m = jobMeta(j.status);
            const s = (j.status || '').toLowerCase();
            return (
              <>
                <CellMono v={shortId(j.id)} c="var(--app-t3)" />
                <div style={{ minWidth: 0 }}>
                  <CellTxt v={j.job_type || 'Job'} c="var(--app-t1)" />
                  <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>{relTime(j.started_at || j.created_at)}</div>
                </div>
                <CellTxt v={j.device_name || j.integration_name} />
                <CellMono v={j.cloud_provider || j.device_type || (j.integration_name ? 'cloud' : null)} c="var(--app-t3)" />
                <CellMono right v={j.assets_discovered ?? '—'} />
                <CellMono right v={durationFmt(j.duration_seconds)} c="var(--app-t3)" />
                <span style={{ textAlign: 'right', display: 'inline-flex', alignItems: 'center', gap: 5, justifyContent: 'flex-end', fontSize: 11.5, fontWeight: 600, color: m.c }}>
                  <span style={{ width: 6, height: 6, borderRadius: 50, background: m.c }} />{m.l}
                </span>
                <PermissionGate permission={TENANT_PERMISSIONS.discovery.manage} fallback={<span />}>
                  <span style={{ display: 'inline-flex', gap: 4, justifyContent: 'flex-end' }}>
                    {RETRYABLE.has(s) && <RowBtn icon="history" title="Retry job" onClick={() => retry.mutate(j.id)} disabled={busy} />}
                    {CANCELLABLE.has(s) && <RowBtn icon="x-circle" title="Cancel job" onClick={() => cancel.mutate(j.id)} disabled={busy} />}
                  </span>
                </PermissionGate>
              </>
            );
          }}
        />
      )}
    </PageWrap>
  );
}
