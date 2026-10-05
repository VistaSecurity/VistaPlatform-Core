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
//
// A scan-plan job ( WP4b — it has a `plan`) reads top to bottom: what the
// scan does and why (depth, pace, targets, where it ran, every depth
// adjustment), what answered (coverage, with reachability guidance when
// nothing did and the reason when it stopped early), what was found grouped by
// host, then where the findings went. The job is re-read every 5 s until it
// ends (useScanJob), so a long scan can be watched here. A legacy job keeps
// the sections it always had.
import { useEffect, useRef } from 'react';
import { Link } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Modal } from '../../components/ui';
import { clients } from '../../lib/clients';
import { describeMaterialization, observationsNotice } from './discover-summary';
import { jobActionError } from './job-action-error';
import { relTime, shortId } from './kit';
import { useDiscoveryJobResults, useScanJob } from './queries';
import { CoverageSection, HostResultsSection, PlanSummarySection } from './scan-plan-sections';
import { isJobLive, planJobState } from './scan-plan-view';
import { discoveryJobKind, kindLabel } from './unified-jobs';
import { dispatchTimeline, executorLabel, scanJobState, type ScanJob, DANGER, INFO, MUTED, OK } from './scan-job-state';

const STEP_COLOR = { done: OK, current: INFO, pending: MUTED, failed: DANGER } as const;

// Mirrors the CANCELLABLE set on the device-interrogation table: a discovery
// job can be cancelled while it has not yet settled. The cancel reaches
// cluster-sensor-service, which stops a running scan between hosts;
// it does NOT revoke a command already handed to a tenant sensor on an
// `awaiting_sensor` job — the button is still offered (the job is marked
// cancelled and the sensor's late result no longer changes that), but nothing
// here pretends the sensor was told to stop. A job that ended while this
// dialog was open is refused with 409, and the reason is shown.
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

// `unit` says what the number counts ("findings", "on 10 hosts"): every tile
// here counts findings — ports — never assets, and a bare number read as
// "15 new assets".
function Tile({ label, value, unit, color }: { label: string; value: React.ReactNode; unit?: string; color?: string }) {
  return (
    <div className="panel" style={{ padding: '10px 12px', borderRadius: 10 }}>
      <div style={{ fontSize: 10.5, color: MUTED, textTransform: 'uppercase', letterSpacing: 0.3 }}>{label}</div>
      <div style={{ fontSize: 22, fontWeight: 700, color: color ?? 'var(--app-t1)', lineHeight: 1.2 }}>{value}</div>
      {unit && <div style={{ fontSize: 11, color: MUTED }}>{unit}</div>}
    </div>
  );
}

const SUMMARY_TONE: Record<string, string> = { neutral: 'var(--app-t2)', ok: OK, warn: 'var(--warn)', muted: MUTED };

export function DiscoveryJobDetailModal({ job: listed, onClose }: { job: ScanJob | null; onClose: () => void }) {
  const qc = useQueryClient();
  // The row's snapshot shows at once; the job's own read replaces it and is
  // re-read until the job ends — carrying the plan, progress and coverage.
  const jobQ = useScanJob(listed?.id);
  const job = listed ? { ...listed, ...(jobQ.data ?? {}) } : null;
  const live = isJobLive(job?.status);
  const res = useDiscoveryJobResults(listed?.id, { live });

  // Once the job ends, read its results one last time: the last poll may have
  // been up to 5 s before the final hosts were stored.
  const wasLive = useRef(live);
  useEffect(() => {
    if (wasLive.current && !live && listed?.id) {
      void qc.invalidateQueries({ queryKey: ['discovery', 'scan-job-results', listed.id] });
      void qc.invalidateQueries({ queryKey: ['discovery', 'scan-job-hosts', listed.id] });
    }
    wasLive.current = live;
  }, [live, listed?.id, qc]);

  const cancel = useMutation({
    mutationFn: async (id: string) => {
      const { data, error } = await clients.inventory.POST('/discovery/jobs/{id}/cancel', { params: { path: { id } } });
      if (error || !data) throw jobActionError(error, 'Failed to cancel job');
      return data;
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['discovery', 'scan-jobs'] });
      void qc.invalidateQueries({ queryKey: ['discovery', 'scan-job'] });
    },
  });

  if (!job) return null;

  const kind = discoveryJobKind(job);
  const plan = job.plan;
  const state = plan ? planJobState(job) : scanJobState(job);
  const steps = dispatchTimeline(job);
  const targets = job.targets ?? [];
  const m = res.data?.materialization;
  const cancellable = CANCELLABLE.has((job.status ?? '').toLowerCase());
  // A job opened from a link (?job=<id>) has no snapshot until its read lands.
  const unknown = !job.status;

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
      footerNote={cancel.isError ? <span role="alert" style={{ color: 'var(--danger-text)' }}>{cancel.error.message}</span> : undefined}
    >
      {unknown && jobQ.isError && (
        <div role="alert" style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12, color: DANGER }}>
          <span style={{ flex: 1 }}>Could not load this job.</span>
          <button className="ui-btn sm" onClick={() => void jobQ.refetch()}>Retry</button>
        </div>
      )}
      {unknown && !jobQ.isError && <div aria-busy="true" style={{ fontSize: 12, color: MUTED }}>Loading job…</div>}

      {plan && (
        <>
          {state.detail && (
            <div role="status" style={{ fontSize: 12.5, color: state.color === DANGER ? 'var(--danger-text)' : 'var(--app-t2)', marginBottom: 4 }}>{state.detail}</div>
          )}
          <PlanSummarySection job={job} plan={plan} live={live} />
          <CoverageSection job={job} plan={plan} loading={jobQ.isLoading} error={jobQ.isError && !jobQ.data} onRetry={() => void jobQ.refetch()} />
          <HostResultsSection jobId={job.id} live={live} coverage={job.coverage} />
        </>
      )}

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

      {!plan && targets.length > 0 && (
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
            <Tile
              label="Open ports found"
              value={m.findings ?? 0}
              unit={typeof m.finding_hosts === 'number' ? `on ${m.finding_hosts} ${m.finding_hosts === 1 ? 'host' : 'hosts'}` : 'findings'}
            />
            <Tile label="Auto-approved" value={m.auto_approved ?? 0} unit="findings" color={OK} />
            <Tile label="Pending approval" value={m.pending_approval ?? 0} unit="findings" />
            <Tile label="Awaiting processing" value={m.awaiting_processing ?? 0} unit="findings" color={MUTED} />
          </div>
          <ObservationsNote m={m} />
          {typeof m.suppressed === 'number' && m.suppressed > 0 && (
            <div style={{ marginTop: 8, fontSize: 11.5, color: MUTED }}>
              {m.suppressed} suppressed (matched an archived or denied asset).
            </div>
          )}
          <MaterializationNote count={m.findings ?? 0} m={m} />
        </Section>
      )}
    </Modal>
  );
}

// Findings kept as observations rather than added as assets, and where to
// review them. Nothing at all when there are none — or when the count
// is unknown, which is not a zero.
function ObservationsNote({ m }: { m: Parameters<typeof observationsNotice>[0] }) {
  const notice = observationsNotice(m);
  if (!notice) return null;
  return (
    <div role="note" aria-label="Kept as observations" className="panel" style={{ marginTop: 10, padding: '8px 12px', borderRadius: 10, fontSize: 12.5, color: 'var(--app-t2)' }}>
      {notice.text} {notice.review} <Link to={notice.href}>Discovery → Observations</Link>.
    </div>
  );
}

// What became of the findings, in describeMaterialization's words (the same
// summary the Discover wizard showed), with the way to the assets awaiting a
// decision.
function MaterializationNote({ count, m }: { count: number; m: Parameters<typeof describeMaterialization>[1] }) {
  const summary = describeMaterialization(count, m);
  return (
    <div style={{ marginTop: 10, fontSize: 12.5 }}>
      <div>
        {summary.parts.map((part, i) => (
          <span key={i}>
            {i > 0 && <span style={{ color: MUTED }}> · </span>}
            <span style={{ color: SUMMARY_TONE[part.tone] }}>{part.text}</span>
          </span>
        ))}
      </div>
      <div style={{ fontSize: 11.5, color: MUTED, marginTop: 4 }}>
        {summary.note} <Link to="/discovery/approvals">Approvals</Link>
      </div>
    </div>
  );
}
