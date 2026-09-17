// Discovery → Discovery Jobs → detail for a discovery/automatic-scan row
// (morning-notes decision 7b). Opened by clicking a row whose kind is
// "discovery" or "automatic".
//
// A device-interrogation job already has its own detail (job-detail-modal.tsx,
// against device-interrogation-service's richer per-asset results). This is
// its counterpart for cluster-sensor-service's discovery_jobs: the dispatch
// timeline (queued → dispatched to X at t → picked up → completed/failed),
// target count, and the findings/materialization split from
// GET /discovery/jobs/{id}/results — the same reconciliation the job-detail
// modal shows, told from a different job's record.
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Modal } from '../../components/ui';
import { clients } from '../../lib/clients';
import { relTime, shortId } from './kit';
import { useDiscoveryJobResults } from './queries';
import { discoveryJobKind, kindLabel } from './unified-jobs';
import { dispatchTimeline, executorLabel, scanJobState, type ScanJob, DANGER, INFO, MUTED, OK } from './scan-job-state';

const STEP_COLOR = { done: OK, current: INFO, pending: MUTED, failed: DANGER } as const;

// Mirrors the CANCELLABLE set on the device-interrogation table: a discovery
// job can be cancelled while it has not yet settled. cluster-sensor's
// CancelJob does not (yet) revoke an already-dispatched sensor command on an
// `awaiting_sensor` job — the button is still offered (cancelling still stops
// the job from being read as a live result later), but nothing here pretends
// the sensor was told to stop.
const CANCELLABLE = new Set(['queued', 'pending', 'awaiting_sensor', 'running', 'in_progress', 'processing']);

function Section({ title, right, children }: { title: string; right?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div style={{ marginTop: 18 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 8 }}>
        <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: 0.4, textTransform: 'uppercase', color: MUTED }}>{title}</div>
        {right}
      </div>
      {children}
    </div>
  );
}

function Row({ label, value, mono, color }: { label: string; value?: React.ReactNode; mono?: boolean; color?: string }) {
  if (value === null || value === undefined || value === '') return null;
  return (
    <div style={{ display: 'flex', gap: 12, padding: '4px 0', fontSize: 12 }}>
      <span style={{ width: 150, flex: 'none', color: MUTED }}>{label}</span>
      <span className={mono ? 'mono' : undefined} style={{ color: color ?? 'var(--app-t1)', minWidth: 0, wordBreak: 'break-word' }}>{value}</span>
    </div>
  );
}

function Tile({ label, value, color }: { label: string; value: React.ReactNode; color?: string }) {
  return (
    <div className="panel" style={{ padding: '10px 12px', borderRadius: 10 }}>
      <div style={{ fontSize: 10.5, color: MUTED, textTransform: 'uppercase', letterSpacing: 0.3 }}>{label}</div>
      <div style={{ fontSize: 22, fontWeight: 700, color: color ?? 'var(--app-t1)', lineHeight: 1.2 }}>{value}</div>
    </div>
  );
}

export function DiscoveryJobDetailModal({ job, onClose }: { job: ScanJob | null; onClose: () => void }) {
  const qc = useQueryClient();
  const res = useDiscoveryJobResults(job?.id);

  const cancel = useMutation({
    mutationFn: async (id: string) => {
      const { data, error } = await clients.inventory.POST('/discovery/jobs/{id}/cancel', { params: { path: { id } } });
      if (error || !data) throw new Error('Failed to cancel job');
      return data;
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['discovery', 'scan-jobs'] });
      void qc.invalidateQueries({ queryKey: ['discovery', 'scan-job'] });
    },
  });

  if (!job) return null;

  const kind = discoveryJobKind(job);
  const state = scanJobState(job);
  const steps = dispatchTimeline(job);
  const targets = job.targets ?? [];
  const m = res.data?.materialization;
  const cancellable = CANCELLABLE.has((job.status ?? '').toLowerCase());

  return (
    <Modal
      open
      onClose={onClose}
      size="lg"
      tone={job.status === 'failed' ? 'danger' : 'accent'}
      icon="radar"
      eyebrow={`Job ${shortId(job.id)}`}
      title={kindLabel(kind)}
      description={`${executorLabel(job)} · ${state.label}`}
      secondary={
        <span style={{ display: 'inline-flex', gap: 8 }}>
          {cancellable && (
            <PermissionGate permission={TENANT_PERMISSIONS.discovery.update} fallback={<span />}>
              <button className="ui-btn" disabled={cancel.isPending} onClick={() => cancel.mutate(job.id)}>
                {cancel.isPending ? 'Cancelling…' : 'Cancel'}
              </button>
            </PermissionGate>
          )}
          <button className="ui-btn" onClick={onClose}>Close</button>
        </span>
      }
    >
      <Section title="Execution">
        <Row label="Status" value={state.label} color={state.color} />
        {state.detail && <Row label="Detail" value={state.detail} color={state.color === DANGER ? 'var(--danger-text)' : undefined} />}
        <Row label="Executor" value={executorLabel(job)} />
        <Row label="Execution mode" value={job.execution_mode} mono />
        <Row label="Targets" value={targets.length} mono />
        <Row label="Created" value={relTime(job.created_at)} />
        <Row label="Job ID" value={job.id} mono />
        {job.error_message && <Row label="Error" value={job.error_message} color={DANGER} />}
      </Section>

      <Section title="Dispatch timeline">
        <ol style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 6 }} aria-label="Dispatch timeline">
          {steps.map((s, i) => (
            <li key={i} style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 12, color: s.state === 'pending' ? MUTED : 'var(--app-t1)' }}>
              <span style={{ width: 7, height: 7, borderRadius: 50, background: STEP_COLOR[s.state], flex: 'none' }} />
              {s.label}
              <span className="mono" style={{ color: MUTED, marginLeft: 'auto' }}>{s.at ? relTime(s.at) : s.state === 'pending' ? '—' : ''}</span>
            </li>
          ))}
        </ol>
      </Section>

      {targets.length > 0 && (
        <Section title="Targets" right={<span style={{ fontSize: 11, color: MUTED }}>{targets.length}</span>}>
          <div className="panel" style={{ padding: '8px 12px', borderRadius: 10, maxHeight: 140, overflowY: 'auto' }}>
            {targets.map((t, i) => (
              <div key={`${t}-${i}`} className="mono" style={{ fontSize: 11.5, color: 'var(--app-t2)', padding: '2px 0' }}>{t}</div>
            ))}
          </div>
        </Section>
      )}

      {res.isLoading && <div style={{ fontSize: 12, color: MUTED, marginTop: 16 }}>Loading findings…</div>}
      {res.isError && <div style={{ fontSize: 12, color: DANGER, marginTop: 16 }}>Could not load this job's findings.</div>}

      {m && (
        <Section title="Findings">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
            <Tile label="Found" value={m.findings ?? 0} />
            <Tile label="Auto-approved" value={m.auto_approved ?? 0} color={OK} />
            <Tile label="Pending approval" value={m.pending_approval ?? 0} />
            <Tile label="Awaiting processing" value={m.awaiting_processing ?? 0} color={MUTED} />
          </div>
          {typeof m.suppressed === 'number' && m.suppressed > 0 && (
            <div style={{ marginTop: 8, fontSize: 11.5, color: MUTED }}>
              {m.suppressed} suppressed (matched an archived or denied asset).
            </div>
          )}
        </Section>
      )}
    </Modal>
  );
}
