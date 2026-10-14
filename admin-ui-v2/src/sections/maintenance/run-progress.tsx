// VISTA Operations — Maintenance › a run's progress (/maintenance/runs/:id).
// Reached from the Update dialog (it navigates here when the run starts) and
// from every Run history row.
//
// The update replaces the very service this page polls: while `helm upgrade`
// rolls maintenance-service (and the edge routes to it), GET /runs/{id} fails
// for a while. That is expected, so failed polls are NOT an error for up to
// RECONNECT_WINDOW_MS: the page keeps the last steps it saw, says "Services are
// restarting — this page will reconnect", and backs off. Only after the window
// does it show an error with Retry. The run itself is unaffected either way —
// the new maintenance-service pod settles it (spec §3, reconcile-on-start).
import { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { AlertTriangle, ArrowLeft, CheckCircle2, Circle, CircleSlash, Loader2, RefreshCw, RotateCcw, XCircle, type LucideIcon } from 'lucide-react';
import { PLATFORM_PERMISSIONS, usePlatformPermissions } from '@vistasecurity/primitives/platform-auth';
import { Modal } from '../../components/ui/modal';
import { Tag } from '../../components/ui/primitives';
import { Panel } from '../system/parts';
import { formatWhen } from './run-history';
import {
  RunInProgressError,
  RunNotFoundError,
  fetchRun,
  useReleases,
  useRunMutations,
  type HelmRelease,
  type MaintenanceRun,
  type MaintenanceRunStep,
} from './maintenance-queries';

/** How long failed polls read as "restarting" before they are an error. */
export const RECONNECT_WINDOW_MS = 15 * 60 * 1000;
/** Poll interval while the run is running and the API answers. */
export const POLL_MS = 2000;
/** The longest wait between polls while reconnecting. */
export const MAX_BACKOFF_MS = 30 * 1000;

export type PollPhase = 'loading' | 'live' | 'reconnecting' | 'error' | 'not-found';

export interface PollState {
  phase: PollPhase;
  run?: MaintenanceRun;
  /** Consecutive failed polls. */
  failures: number;
  /** When the current run of failures began (ms). */
  failingSince: number | null;
}

export const INITIAL_POLL: PollState = { phase: 'loading', failures: 0, failingSince: null };

export type PollOutcome = { ok: true; run: MaintenanceRun } | { ok: false; notFound?: boolean };

/** The progress page's polling state machine (pure, for tests). */
export function nextPollState(prev: PollState, outcome: PollOutcome, now: number): PollState {
  if (outcome.ok) return { phase: 'live', run: outcome.run, failures: 0, failingSince: null };
  if (outcome.notFound) return { ...prev, phase: 'not-found', failures: prev.failures + 1 };
  const failingSince = prev.failingSince ?? now;
  const failures = prev.failures + 1;
  const phase: PollPhase = now - failingSince >= RECONNECT_WINDOW_MS ? 'error' : 'reconnecting';
  return { ...prev, phase, failures, failingSince };
}

/** Delay before the next poll, or null to stop (pure, for tests). */
export function nextPollDelay(s: PollState): number | null {
  if (s.phase === 'error' || s.phase === 'not-found') return null;
  if (s.phase === 'live' && s.run && s.run.status !== 'running') return null;
  if (s.phase === 'reconnecting') return Math.min(POLL_MS * 2 ** Math.max(0, s.failures - 1), MAX_BACKOFF_MS);
  return POLL_MS;
}

/** Polls GET /runs/{id} through the state machine. `retry` starts over. */
export function useRunPoll(id: string, opts: { fetcher?: (id: string) => Promise<MaintenanceRun>; now?: () => number } = {}) {
  const fetcher = opts.fetcher ?? fetchRun;
  const now = opts.now ?? Date.now;
  const [state, setState] = useState<PollState>(INITIAL_POLL);
  const [generation, setGeneration] = useState(0);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let current: PollState = INITIAL_POLL;
    const tick = async () => {
      let outcome: PollOutcome;
      try {
        outcome = { ok: true, run: await fetcher(id) };
      } catch (err) {
        outcome = { ok: false, notFound: err instanceof RunNotFoundError };
      }
      if (cancelled) return;
      current = nextPollState(current, outcome, now());
      setState(current);
      const delay = nextPollDelay(current);
      if (delay !== null) timer = setTimeout(() => { void tick(); }, delay);
    };
    void tick();
    return () => { cancelled = true; if (timer) clearTimeout(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- generation restarts the loop
  }, [id, generation]);

  const retry = useCallback(() => { setState(INITIAL_POLL); setGeneration((g) => g + 1); }, []);
  return { state, retry };
}

const STEP_LABEL: Record<string, string> = {
  backup: 'Back up the database',
  verify: 'Verify the chart’s signature',
  upgrade: 'Upgrade: apply the schema and restart every service',
  rollback: 'Roll back with Helm',
  smoke: 'Check every service runs the new version',
  dump: 'Dump the database',
  package: 'Package the backup',
  retention: 'Remove backups beyond the retention count',
};

const DETAIL_LABEL: Record<string, string> = {
  skipped_by_operator: 'Skipped — you confirmed you have your own backup.',
  skipped_by_configuration: 'Skipped — signature verification is turned off for this install.',
};

const STEP_META: Record<MaintenanceRunStep['status'], { icon: LucideIcon; color: string; label: string }> = {
  pending: { icon: Circle, color: 'var(--op-t3)', label: 'Waiting' },
  running: { icon: Loader2, color: 'var(--op-accent)', label: 'Running…' },
  succeeded: { icon: CheckCircle2, color: 'var(--ok)', label: 'Done' },
  failed: { icon: XCircle, color: 'var(--danger)', label: 'Failed' },
  skipped: { icon: CircleSlash, color: 'var(--op-t3)', label: 'Skipped' },
};

const KIND_TITLE: Record<MaintenanceRun['kind'], string> = { backup: 'Backup', update: 'Update', rollback: 'Roll back' };

/** Steps whose failure means the cluster may have changed (rollback is worth offering). */
const CHANGING_STEPS = new Set(['upgrade', 'smoke']);

/** Whether to offer "Roll back to <previous>" for this run (pure, for tests). */
export function offerRollback(run: MaintenanceRun | undefined, candidate: HelmRelease | null | undefined, canMaintain: boolean): boolean {
  if (!run || run.kind !== 'update' || run.status !== 'failed' || !candidate || !canMaintain) return false;
  const failed = run.steps.find((s) => s.status === 'failed');
  return failed ? CHANGING_STEPS.has(failed.name) : true;
}

function StepRow({ step }: { step: MaintenanceRunStep }) {
  const meta = STEP_META[step.status] ?? STEP_META.pending;
  const Icon = meta.icon;
  return (
    <li data-testid="run-step" data-step={step.name} data-status={step.status} style={{ listStyle: 'none', padding: '12px 16px', borderBottom: '1px solid var(--op-border)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <Icon size={16} style={{ color: meta.color, flex: 'none' }} className={step.status === 'running' ? 'spin' : undefined} />
        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--op-t1)', flex: 1 }}>{STEP_LABEL[step.name] ?? step.name}</span>
        <span style={{ fontSize: 12, color: meta.color, fontWeight: 600 }}>{meta.label}</span>
      </div>
      {step.detail && DETAIL_LABEL[step.detail] && (
        <div data-testid="step-detail" style={{ fontSize: 12, color: 'var(--op-t3)', marginTop: 4, marginLeft: 26 }}>{DETAIL_LABEL[step.detail]}</div>
      )}
      {step.error && (
        <div data-testid="step-error" style={{ fontSize: 12, color: 'var(--danger)', marginTop: 4, marginLeft: 26, lineHeight: 1.5 }}>{step.error}</div>
      )}
      {step.log_tail && (
        <pre data-testid="step-log" className="mono" style={{ margin: '8px 0 0 26px', padding: '8px 10px', maxHeight: 240, overflow: 'auto', fontSize: 11.5, lineHeight: 1.5, background: 'var(--op-panel2)', border: '1px solid var(--op-border)', borderRadius: 'var(--r-sm)', color: 'var(--op-t2)', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{step.log_tail}</pre>
      )}
    </li>
  );
}

function Outcome({ run }: { run: MaintenanceRun }) {
  if (run.status === 'running') return null;
  if (run.status === 'succeeded') {
    const text = run.kind === 'update' ? `Running Vista Platform ${run.to_version}`
      : run.kind === 'rollback' ? `Rolled back — running Vista Platform ${run.to_version}` : 'Backup ready';
    return (
      <div data-testid="run-success" style={{ display: 'flex', gap: 10, alignItems: 'center', padding: '14px 16px', color: 'var(--ok)', fontWeight: 700, fontSize: 14 }}>
        <CheckCircle2 size={18} /> {text}
      </div>
    );
  }
  const failed = run.steps.find((s) => s.status === 'failed');
  const nothingChanged = run.kind === 'update' && failed && !CHANGING_STEPS.has(failed.name);
  return (
    <div data-testid="run-failure" style={{ padding: '14px 16px' }}>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', color: 'var(--danger)', fontWeight: 700, fontSize: 14 }}>
        <XCircle size={18} /> {KIND_TITLE[run.kind]} failed{failed ? ` at “${STEP_LABEL[failed.name] ?? failed.name}”` : ''}
      </div>
      {run.error && <div data-testid="run-error" style={{ fontSize: 12.5, color: 'var(--op-t2)', marginTop: 6, lineHeight: 1.55 }}>{run.error}</div>}
      {nothingChanged && (
        <div data-testid="run-nothing-changed" style={{ fontSize: 12.5, color: 'var(--op-t3)', marginTop: 6 }}>Nothing was changed: the update stopped before Helm ran. Vista Platform {run.from_version} is still running.</div>
      )}
    </div>
  );
}

function RollbackAction({ candidate, pending, error, onConfirm }: { candidate: HelmRelease; pending: boolean; error: string | null; onConfirm: () => void }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ padding: '0 16px 16px' }}>
      <button className="op-btn primary sm" data-testid="rollback-button" onClick={() => setOpen(true)}>
        <RotateCcw size={13} /> Roll back to {candidate.chart_version}
      </button>
      {error && <div role="alert" data-testid="rollback-error" style={{ fontSize: 12, color: 'var(--danger)', marginTop: 6 }}>{error}</div>}
      {open && (
        <Modal
          open
          onClose={() => setOpen(false)}
          title={`Roll back to ${candidate.chart_version}?`}
          description={`Helm returns the release to revision ${candidate.revision} (Vista Platform ${candidate.chart_version}), restarting the services that changed. The database schema is not rolled back: the schema is additive, and ${candidate.chart_version} runs on it.`}
          tone="danger"
          primaryLabel={`Roll back to ${candidate.chart_version}`}
          primaryLoadingLabel="Starting…"
          primaryLoading={pending}
          onPrimary={() => { onConfirm(); setOpen(false); }}
          footerNote="Platform-admin · audited"
        />
      )}
    </div>
  );
}

export function RunProgressView({ id }: { id: string }) {
  const { state, retry } = useRunPoll(id);
  const navigate = useNavigate();
  const canMaintain = usePlatformPermissions().hasPermission(PLATFORM_PERMISSIONS.platform.maintenance);
  const run = state.run;
  const failedUpdate = run?.kind === 'update' && run.status === 'failed';
  const releases = useReleases({ enabled: Boolean(failedUpdate) && canMaintain });
  const candidate = releases.data?.rollback_candidate ?? null;
  const { rollback } = useRunMutations();
  const rollbackError = rollback.error instanceof RunInProgressError ? rollback.error.message : rollback.error ? rollback.error.message : null;

  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 18 }} data-testid="run-progress" data-phase={state.phase}>
      <div>
        <Link to="/maintenance" style={{ fontSize: 12.5, display: 'inline-flex', alignItems: 'center', gap: 4 }}><ArrowLeft size={13} /> About & Updates</Link>
      </div>
      {state.phase === 'reconnecting' && (
        <div data-testid="run-reconnecting" role="status" style={{ display: 'flex', gap: 10, alignItems: 'center', fontSize: 13, color: 'var(--op-t2)', background: 'color-mix(in srgb, var(--op-accent) 10%, transparent)', border: '1px solid color-mix(in srgb, var(--op-accent) 30%, transparent)', borderRadius: 'var(--r-sm)', padding: '10px 14px' }}>
          <Loader2 size={15} className="spin" style={{ color: 'var(--op-accent)' }} />
          Services are restarting — this page will reconnect. The update carries on without it; you can close this page.
        </div>
      )}
      {state.phase === 'error' && (
        <div data-testid="run-poll-error" role="alert" style={{ display: 'flex', gap: 10, alignItems: 'center', fontSize: 13, color: 'var(--danger)' }}>
          <AlertTriangle size={15} /> The maintenance service has not answered for 15 minutes. Check the cluster (kubectl get pods), then retry.
          <button className="op-btn sm" onClick={retry} data-testid="run-retry"><RefreshCw size={12} /> Retry</button>
        </div>
      )}
      {state.phase === 'not-found' && (
        <div data-testid="run-not-found" style={{ fontSize: 13, color: 'var(--op-t3)' }}>No such maintenance run.</div>
      )}
      <Panel title={run ? `${KIND_TITLE[run.kind]}${run.from_version || run.to_version ? ` · ${[run.from_version, run.to_version].filter(Boolean).join(' → ')}` : ''}` : 'Maintenance run'} icon={RotateCcw}>
        {!run && state.phase === 'loading' && (
          <div data-testid="run-loading" style={{ padding: 16 }}><div style={{ height: 32, borderRadius: 'var(--r-md, 8px)', background: 'var(--op-track)', opacity: 0.55 }} /></div>
        )}
        {run && (
          <>
            <div style={{ display: 'flex', gap: 12, alignItems: 'center', padding: '12px 16px', borderBottom: '1px solid var(--op-border)', fontSize: 12, color: 'var(--op-t3)' }}>
              <Tag color={run.status === 'succeeded' ? 'var(--ok)' : run.status === 'failed' ? 'var(--danger)' : run.status === 'running' ? 'var(--op-accent)' : 'var(--op-t3)'}>
                {run.status === 'running' ? 'Running…' : run.status[0].toUpperCase() + run.status.slice(1)}
              </Tag>
              <span>Started {formatWhen(run.started_at)}</span>
              {run.finished_at && <span>· finished {formatWhen(run.finished_at)}</span>}
            </div>
            <ol style={{ margin: 0, padding: 0 }}>
              {run.steps.map((s) => <StepRow key={s.name} step={s} />)}
            </ol>
            <Outcome run={run} />
            {offerRollback(run, candidate, canMaintain) && candidate && (
              <RollbackAction
                candidate={candidate}
                pending={rollback.isPending}
                error={rollbackError}
                onConfirm={() => rollback.mutate(candidate.revision, { onSuccess: (r) => { void navigate(`/maintenance/runs/${r.run.id}`); } })}
              />
            )}
          </>
        )}
      </Panel>
    </div>
  );
}

/** The routed page: /maintenance/runs/:id. */
export function RunProgressPage() {
  const { id = '' } = useParams();
  return <RunProgressView key={id} id={id} />;
}
