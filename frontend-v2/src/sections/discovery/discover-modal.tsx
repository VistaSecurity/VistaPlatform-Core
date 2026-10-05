// Discover Assets — "find everything on this host or network" ( WP4a).
// Discovery → Discover assets (the Command Center) opens it. Configure →
// preview → start → "started, track it in Discovery Jobs", on
// inventory-service's POST /discovery/jobs.
//
// - No protocol is picked: the person chooses a scan DEPTH and services are
//   identified from what answers. Ports are Custom's business, under Advanced,
//   parsed exactly as the platform parses them (discover-port-spec.ts, H8).
// - The preview is the same request with `dry_run: true`: the server's own
//   plan (per-target depth, where it runs and why) and a duration RANGE.
//   Debounced, stale requests cancelled, and never in the way of Start.
// - Starting hands the scan to the platform and stops there. The dialog does
//   not poll: progress, results and Cancel live on Discovery → Discovery Jobs,
//   and the dialog can be closed at any moment without affecting the scan.
//
// There is deliberately NO import step. Findings reach inventory server-side,
// through the same ingestion queue the sensors feed, and the pipeline applies
// the tenant's segment auto-approval rules.
import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useFeature } from '@vistasecurity/primitives/features';
import { clients } from '../../lib/clients';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import { useSensors } from './queries';
import { shortId } from './kit';
import { AUTO, PLATFORM, runFromOptions } from './active-scan-run-from';
import {
  DISABLED_EXPLANATION,
  TargetVerdictError,
  describeExternal,
  externalConfirmTitle,
  targetVerdict,
  type TargetVerdict,
} from './discover-targets';
import {
  DEPTHS,
  OT_PROTOCOLS,
  PACES,
  asCreatedJob,
  asPreview,
  buildJobRequest,
  checkForm,
  depthLabel,
  describeAdjustments,
  describeEstimate,
  describeExecutor,
  describeSize,
  initialForm,
  loadRememberedChoice,
  paceLabel,
  saveRememberedChoice,
  type CreateDiscoveryJobRequest,
  type DiscoverForm,
  type DiscoveryJob,
  type DiscoveryJobPreview,
} from './discover-plan';

/** How long the form must sit still before it is previewed. */
export const PREVIEW_DEBOUNCE_MS = 500;

// 'confirm-external' is the "outside your registered networks" question.
// 'started' is terminal: the scan is the platform's now.
type Phase = 'configure' | 'confirm-external' | 'started';

// How many targets a list shows before summarising.
const LIST_MAX = 20;

// Refusals the server will give a real create too: Start is not offered for
// a request the preview already knows it will refuse.
const DEFINITIVE = new Set<TargetVerdict['kind']>(['refused', 'too_large', 'disabled', 'budget', 'sensor_unsupported']);

// What a dry run answered when it did not answer with a preview. A dry run
// goes through the same checks and the same error mapping as a real create,
// so a 4xx is the answer Start would get (an offline sensor's 409, a field the
// server rejects) — a refusal, in the server's words. Only no answer, a 5xx or
// the tenant's rate limit is "couldn't estimate", which never holds Start.
class PreviewAnswer extends Error {
  constructor(readonly verdict: TargetVerdict, readonly status: number) {
    super(verdict.message);
    this.name = 'PreviewAnswer';
  }
}
const refusedByServer = (status: number) => status >= 400 && status < 500 && status !== 429;

type PreviewView =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'ready'; preview: DiscoveryJobPreview }
  | { kind: 'empty' }
  | { kind: 'refused'; verdict: TargetVerdict }
  | { kind: 'failed'; message: string };

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

function browserStorage(): Storage | undefined {
  try {
    return window.localStorage;
  } catch {
    return undefined;
  }
}

const muted = { fontSize: 11.5, color: 'var(--app-t3)' } as const;
const groupTitle = { fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)', marginBottom: 8, padding: 0 } as const;
const fieldset = { border: 'none', margin: '0 0 15px', padding: 0, minWidth: 0 } as const;

function ChoiceCard({ name, value, checked, onChange, label, description }: {
  name: string; value: string; checked: boolean; onChange: () => void; label: string; description: string;
}) {
  return (
    <label
      style={{
        display: 'flex', gap: 9, alignItems: 'flex-start', padding: '9px 11px', borderRadius: 9, cursor: 'pointer',
        border: `1px solid ${checked ? 'var(--accent)' : 'var(--app-border2)'}`,
        background: checked ? 'color-mix(in srgb, var(--accent) 8%, transparent)' : 'var(--app-panel2)',
      }}
    >
      <input type="radio" name={name} value={value} checked={checked} onChange={onChange} style={{ marginTop: 2 }} />
      <span style={{ minWidth: 0 }}>
        <span style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--app-t1)' }}>{label}</span>
        <span style={{ display: 'block', ...muted, marginTop: 2 }}>{description}</span>
      </span>
    </label>
  );
}

/** A refusal, in the server's own sentence, with the targets it names. */
function VerdictNotice({ verdict, onRunFromPlatform }: { verdict: TargetVerdict; onRunFromPlatform?: () => void }) {
  const box = (border: string, children: React.ReactNode, role: 'alert' | 'status' = 'alert') => (
    <div role={role} style={{ padding: '10px 12px', borderRadius: 9, border: `1px solid ${border}`, fontSize: 12.5 }}>{children}</div>
  );
  switch (verdict.kind) {
    case 'refused':
      return box('var(--danger)', <>
        <div style={{ fontWeight: 600, color: 'var(--danger-text)', marginBottom: 6 }}>
          {verdict.refused.length === 1 ? 'This target can never be scanned:' : `These ${verdict.refused.length} targets can never be scanned:`}
        </div>
        <ul style={{ margin: 0, paddingLeft: 18, color: 'var(--app-t2)' }}>
          {verdict.refused.map((r) => <li key={r.target}><span className="mono">{r.target}</span> — {r.reason}</li>)}
        </ul>
        <div style={{ marginTop: 6, color: 'var(--app-t3)' }}>Remove them to scan the rest.</div>
      </>);
    case 'too_large':
      return box('var(--danger)', <>
        <div style={{ fontWeight: 600, color: 'var(--danger-text)', marginBottom: 6 }}>{verdict.message}</div>
        {verdict.oversize.length > 0 && (
          <ul style={{ margin: 0, paddingLeft: 18, color: 'var(--app-t2)' }}>
            {verdict.oversize.slice(0, LIST_MAX).map((t) => <li key={t.target}><span className="mono">{t.target}</span> — {t.addresses} addresses</li>)}
          </ul>
        )}
      </>);
    case 'budget':
      return box('var(--danger)', <>
        <div style={{ fontWeight: 600, color: 'var(--danger-text)', marginBottom: 6 }}>{verdict.message}</div>
        {verdict.largest && (
          <div style={{ color: 'var(--app-t2)' }}>
            Largest: <span className="mono">{verdict.largest.target}</span> — {verdict.largest.addresses.toLocaleString('en-US')} addresses ×{' '}
            {(verdict.largest.tcp_port_count + verdict.largest.udp_port_count).toLocaleString('en-US')} ports.
          </div>
        )}
        <div style={{ marginTop: 6, color: 'var(--app-t3)' }}>Choose a lower depth, or split the targets across scans.</div>
      </>);
    case 'disabled':
      return box('var(--warn)', <>
        <div style={{ fontWeight: 600, color: 'var(--app-t1)', marginBottom: 6 }}>
          {verdict.targets.length === 1 ? '1 target is' : `${verdict.targets.length} targets are`} outside your registered networks.
        </div>
        <div style={{ color: 'var(--app-t2)' }}>{DISABLED_EXPLANATION}</div>
        {verdict.targets.length > 0 && (
          <ul style={{ margin: '6px 0 0', paddingLeft: 18, color: 'var(--app-t2)' }}>
            {verdict.targets.slice(0, LIST_MAX).map((t) => <li key={t.target} className="mono">{t.target}</li>)}
          </ul>
        )}
      </>);
    case 'sensor_unsupported':
      // The chosen sensor cannot run a scan by depth. The way out that
      // needs nobody else is the platform sensor; offered, never switched to
      // behind the person's back.
      return box('var(--danger)', <>
        <div style={{ color: 'var(--danger-text)', fontWeight: 600, marginBottom: 6 }}>{verdict.message}</div>
        {onRunFromPlatform && (
          <button type="button" className="ui-btn sm" onClick={onRunFromPlatform}>Run from the platform sensor instead</button>
        )}
      </>);
    case 'error':
      return box('var(--danger)', <>
        <div style={{ fontWeight: 600, color: 'var(--danger-text)', marginBottom: 6 }}>This scan can&apos;t start as set up:</div>
        <div style={{ color: 'var(--app-t2)' }}>{verdict.message}</div>
      </>);
    case 'plan_unavailable':
      // Not the person's mistake and not an emergency: calm, not an alert.
      return box('var(--app-border2)', <div style={{ color: 'var(--app-t2)' }}>{verdict.message}</div>, 'status');
    default:
      return null;
  }
}

function PreviewPanel({ view, onRunFromPlatform }: { view: PreviewView; onRunFromPlatform: () => void }) {
  const shell = (children: React.ReactNode, live = true) => (
    // A fixed floor so the dialog does not jump as the preview arrives.
    <div aria-live={live ? 'polite' : undefined} data-testid="discover-preview" style={{ minHeight: 92, marginBottom: 6 }}>
      <div style={{ ...groupTitle }}>Preview</div>
      {children}
    </div>
  );
  switch (view.kind) {
    case 'idle':
      return shell(<div style={muted}>Enter targets to see how big this scan is, roughly how long it may take, and where it will run.</div>);
    case 'loading':
      return shell(<div role="status" style={muted}>Estimating…</div>);
    case 'failed':
      return shell(<div role="status" style={muted}>Couldn&apos;t estimate this scan{view.message ? ` (${view.message})` : ''}. You can still start it.</div>);
    case 'empty':
      return shell(<div role="status" style={{ fontSize: 12.5, color: 'var(--app-t2)' }}>Nothing to scan: these targets name no addresses.</div>);
    case 'refused':
      return shell(<VerdictNotice verdict={view.verdict} onRunFromPlatform={onRunFromPlatform} />, false);
    case 'ready': {
      const { plan, estimate, confirmation_required, external_targets } = view.preview;
      const est = describeEstimate(estimate);
      const exec = describeExecutor(plan);
      const adj = describeAdjustments(plan);
      return shell(
        <div role="status" style={{ fontSize: 12.5, color: 'var(--app-t2)', display: 'flex', flexDirection: 'column', gap: 6 }}>
          <div>{describeSize(plan, estimate)}</div>
          <div><span style={{ color: 'var(--app-t1)', fontWeight: 600 }}>{est.duration}</span>{est.basis && <span style={muted}> — {est.basis}</span>}</div>
          <div><span style={{ color: 'var(--app-t1)' }}>{exec.where}</span>{exec.why && <span style={muted}> — {exec.why}</span>}</div>
          {adj && (
            <div style={{ padding: '8px 10px', borderRadius: 8, border: '1px solid var(--warn)' }}>
              <div style={{ color: 'var(--app-t1)' }}>{adj.headline}</div>
              <ul className="mono" style={{ margin: '4px 0 0', paddingLeft: 18, fontSize: 11.5 }}>
                {adj.targets.slice(0, LIST_MAX).map((t) => <li key={t.target} title={t.reason}>{t.target}</li>)}
              </ul>
              {adj.targets.length > LIST_MAX && <div style={muted}>and {adj.targets.length - LIST_MAX} more</div>}
              {adj.registerHint && (
                <div style={{ ...muted, marginTop: 4 }}>
                  If a range is yours, register it under Settings → Infrastructure → Network Segments and it is scanned at the depth you choose.
                </div>
              )}
            </div>
          )}
          {confirmation_required && external_targets.length > 0 && (
            <div style={muted}>
              {externalConfirmTitle(external_targets.length)} You will be asked to confirm when you start.
            </div>
          )}
        </div>,
      );
    }
  }
}

export function DiscoverAssetsModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const nav = useNavigate();
  // The tenant's OT off-switch (owner decision D1: on unless an administrator
  // turned it off). Off → the OT control is not shown at all: spec §1 says it
  // is absent, and useFeature reads false while loading, so a disabled
  // "turned off by your administrator" control would also flash at every
  // tenant whose switch is on.
  const otAvailable = useFeature('ot_active_probing');
  const sensorsQ = useSensors();
  const fleet = runFromOptions(sensorsQ.data, { loading: sensorsQ.isLoading, error: sensorsQ.isError });
  // Active Scan's control and states, with Auto worded for what Auto means for
  // free targets: a sensor that serves them all, else the platform (D7).
  const runFromChoices = fleet.options.map((o) => (o.value === AUTO ? { ...o, label: 'Auto — a sensor on those networks, else the platform sensor' } : o));

  const [phase, setPhase] = useState<Phase>('configure');
  const [form, setForm] = useState<DiscoverForm>(() => initialForm(null));
  const [advancedOpen, setAdvancedOpen] = useState(false);
  // The last real create's refusal (the preview's are derived below). Cleared
  // whenever the form changes.
  const [verdict, setVerdict] = useState<TargetVerdict | null>(null);
  const [started, setStarted] = useState<{ job: DiscoveryJob; form: DiscoverForm } | null>(null);
  // Each opening is a new session: a create that finishes after the dialog
  // was closed and reopened must not take over the new one.
  const session = useRef(0);

  useEffect(() => {
    if (open) {
      session.current += 1;
      setPhase('configure');
      setForm(initialForm(loadRememberedChoice(browserStorage())));
      setAdvancedOpen(false);
      setVerdict(null);
      setStarted(null);
    }
  }, [open]);

  const update = (patch: Partial<DiscoverForm>) => {
    setForm((f) => ({ ...f, ...patch }));
    setVerdict(null);
  };

  // What the person picked, as long as it is still on offer; otherwise the
  // fleet's default. Derived, so the select and the request never disagree.
  const runFromValue = fleet.options.some((o) => o.value === form.runFrom && !o.disabled) ? form.runFrom : fleet.defaultValue;
  const effective: DiscoverForm = { ...form, runFrom: runFromValue };
  const check = checkForm(effective, otAvailable);
  // Not while the sensors load: "Run from" would silently mean the platform.
  const valid = check.problems.length === 0 && !fleet.loading;

  // ── Preview: the same request with dry_run, once the form sits still ──
  const previewKey = valid ? JSON.stringify(buildJobRequest(effective, check, { otAvailable, dryRun: true })) : null;
  const debouncedKey = useDebounced(previewKey, PREVIEW_DEBOUNCE_MS);
  const settled = previewKey !== null && previewKey === debouncedKey;
  const previewQ = useQuery({
    queryKey: ['discovery', 'job-preview', debouncedKey],
    enabled: open && phase === 'configure' && settled,
    retry: false,
    staleTime: 30_000,
    gcTime: 60_000,
    // `signal` is what cancels a superseded preview: once the key moves on,
    // the old request has no observer and react-query aborts it.
    queryFn: async ({ signal }) => {
      const body = JSON.parse(debouncedKey as string) as CreateDiscoveryJobRequest;
      const { data, error, response } = await clients.inventory.POST('/discovery/jobs', { body, signal });
      if (error || !data) throw new PreviewAnswer(targetVerdict(response.status, error), response.status);
      const preview = asPreview(data);
      if (!preview) throw new Error('unexpected answer');
      return preview;
    },
  });

  let preview: PreviewView = { kind: 'idle' };
  if (previewKey !== null) {
    if (!settled || previewQ.isPending) preview = { kind: 'loading' };
    else if (previewQ.isError) {
      const e = previewQ.error;
      const v = e instanceof PreviewAnswer ? e.verdict : null;
      const definitive = v !== null && (DEFINITIVE.has(v.kind) || v.kind === 'plan_unavailable' || (v.kind === 'error' && refusedByServer((e as PreviewAnswer).status)));
      preview = v && definitive ? { kind: 'refused', verdict: v } : { kind: 'failed', message: v?.message ?? '' };
    } else if (previewQ.data) {
      preview = previewQ.data.estimate.addresses === 0 ? { kind: 'empty' } : { kind: 'ready', preview: previewQ.data };
    }
  }
  const knownRefused = preview.kind === 'refused' && (DEFINITIVE.has(preview.verdict.kind) || preview.verdict.kind === 'error');

  // ── Start ──
  const create = useMutation({
    mutationFn: async ({ body }: { body: CreateDiscoveryJobRequest; form: DiscoverForm; session: number }) => {
      const { data, error, response } = await clients.inventory.POST('/discovery/jobs', { body });
      if (error || !data) throw new TargetVerdictError(targetVerdict(response.status, error));
      const job = asCreatedJob(data);
      if (!job) throw new Error('Unexpected response while starting discovery');
      return job;
    },
    onMutate: () => setVerdict(null),
    onSuccess: (job, vars) => {
      void qc.invalidateQueries({ queryKey: ['discovery', 'scan-jobs'] });
      void qc.invalidateQueries({ queryKey: ['discovery', 'jobs'] });
      saveRememberedChoice(browserStorage(), vars.form);
      if (vars.session !== session.current) return;
      setStarted({ job, form: vars.form });
      setPhase('started');
    },
    onError: (e, vars) => {
      if (vars.session !== session.current) return;
      const v: TargetVerdict = e instanceof TargetVerdictError ? e.verdict : { kind: 'error', message: e instanceof Error ? e.message : 'Failed to start discovery' };
      setVerdict(v);
      setPhase(v.kind === 'unconfirmed' ? 'confirm-external' : 'configure');
    },
  });

  // `confirmed` is the person's answer to "N targets are outside your
  // registered networks". It is only ever true from the confirmation's "Scan
  // anyway" — never pre-set — so a first Start always lets the server decide.
  const start = (confirmed: boolean) =>
    create.mutate({ body: buildJobRequest(effective, check, { otAvailable, confirmed }), form: effective, session: session.current });

  const onStart = () => {
    // The preview already knows what needs confirming: ask now rather than
    // send a request the server will answer with the same question.
    if (preview.kind === 'ready' && preview.preview.confirmation_required && preview.preview.external_targets.length > 0) {
      setVerdict({ kind: 'unconfirmed', targets: preview.preview.external_targets, message: '' });
      setPhase('confirm-external');
      return;
    }
    start(false);
  };

  // The Jobs page opens ?job=<id> straight on that job's detail.
  const goToJobs = () => {
    onClose();
    void nav(started ? `/discovery/jobs?job=${encodeURIComponent(started.job.id)}` : '/discovery/jobs');
  };
  const runFromPlatform = () => update({ runFrom: PLATFORM });

  let primary: React.ReactNode;
  let secondary: React.ReactNode;
  if (phase === 'configure') {
    primary = (
      <button className="ui-btn accent" disabled={!valid || knownRefused || create.isPending} onClick={onStart}>
        {create.isPending ? 'Starting…' : 'Start discovery'}
      </button>
    );
    secondary = <button className="ui-btn" onClick={onClose}>Cancel</button>;
  } else if (phase === 'confirm-external') {
    primary = (
      <button className="ui-btn accent" disabled={create.isPending} onClick={() => start(true)}>
        {create.isPending ? 'Starting…' : 'Scan anyway'}
      </button>
    );
    secondary = (
      <button className="ui-btn" disabled={create.isPending} onClick={() => { setVerdict(null); setPhase('configure'); }}>
        Cancel
      </button>
    );
  } else {
    primary = <button className="ui-btn accent" onClick={goToJobs}>View in Discovery Jobs</button>;
    secondary = <button className="ui-btn" onClick={onClose}>Close</button>;
  }

  const problem = (field: string) => check.problems.find((p) => p.field === field)?.message;
  const targetCount = check.targets.length;
  const custom = form.depth === 'custom';
  // A preset's ports, read-only, from the server's own plan once a preview
  // for this depth has come back — never a copy of the preset kept here.
  const shownPlan = preview.kind === 'ready' && preview.preview.plan.depth === form.depth ? preview.preview.plan : null;

  return (
    <Modal
      open={open}
      // Closable at every moment, a pending Start included: the scan never
      // depends on this dialog being open.
      onClose={onClose}
      dismissible
      size="lg"
      tone="accent"
      icon="radar"
      eyebrow="Discovery"
      title="Discover assets"
      description="Find everything that answers on a host or a network. Services are identified from what answers, and what is found flows into your inventory automatically."
      primary={primary}
      secondary={secondary}
      footerNote={verdict?.kind === 'error' ? <span style={{ color: 'var(--danger-text)' }}>{verdict.message}</span> : undefined}
    >
      {phase === 'configure' && (
        <>
          <ModalField
            label="Targets"
            hint={`One per line or comma-separated: IP addresses, CIDR blocks, ranges, hostnames or URLs (max 1000). For IPv6, list addresses — an IPv6 network is too large to sweep.${targetCount > 0 ? ` ${targetCount} entered.` : ''}`}
          >
            <textarea
              data-autofocus
              aria-label="Targets"
              aria-invalid={targetCount > 1000 || undefined}
              value={form.targets}
              onChange={(e) => update({ targets: e.target.value })}
              rows={4}
              spellCheck={false}
              className="mono"
              placeholder={'10.0.0.0/24\nweb-prod-01.example.com\nhttps://portal.example.com/'}
              style={{ width: '100%', padding: '10px 12px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12, outline: 'none', resize: 'vertical' }}
            />
          </ModalField>
          {targetCount > 1000 && <div role="alert" style={{ margin: '-8px 0 12px', fontSize: 11.5, color: 'var(--danger-text)' }}>{problem('targets')}</div>}

          <fieldset style={fieldset}>
            <legend style={groupTitle}>Scan depth</legend>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              {DEPTHS.map((d) => (
                <ChoiceCard
                  key={d.value}
                  name="discover-depth"
                  value={d.value}
                  checked={form.depth === d.value}
                  label={d.label}
                  description={d.description}
                  onChange={() => {
                    update({ depth: d.value });
                    // Custom means "you choose the ports", and the ports are under Advanced.
                    if (d.value === 'custom') setAdvancedOpen(true);
                  }}
                />
              ))}
            </div>
          </fieldset>

          <ModalField
            label="Run from"
            hint="Auto runs the scan from one of your sensors when it serves every target, and from the platform sensor otherwise. The platform sensor reaches only what the platform can route to."
          >
            <ModalSelect aria-label="Run from" value={runFromValue} disabled={fleet.loading} onChange={(e) => update({ runFrom: e.target.value })}>
              {runFromChoices.map((o) => (
                <option key={o.value} value={o.value} disabled={o.disabled} title={o.hint}>{o.label}</option>
              ))}
            </ModalSelect>
          </ModalField>
          {fleet.loading && <div role="status" style={{ ...muted, margin: '-8px 0 12px' }}>Loading your sensors…</div>}
          {fleet.error && (
            <div style={{ margin: '-8px 0 12px', fontSize: 11.5, color: 'var(--warn)' }}>
              The sensor list could not be loaded, so this scan runs from the platform sensor. Reopen the dialog to choose one of your sensors.
            </div>
          )}
          {fleet.noTenantSensors && (
            <div style={{ ...muted, margin: '-8px 0 12px' }}>
              You have no sensors registered, so this scan runs from the platform sensor. To scan from inside your network, register one under Discovery → Sensors &amp; Agents.
            </div>
          )}

          <div style={{ marginBottom: 15 }}>
            <button
              type="button"
              className="ui-btn ghost sm"
              aria-expanded={advancedOpen}
              aria-controls="discover-advanced"
              onClick={() => setAdvancedOpen((v) => !v)}
              style={{ padding: '0 6px', marginLeft: -6 }}
            >
              <Icon name={advancedOpen ? 'chevron-down' : 'chevron-right'} size={13} />Advanced
            </button>
            {advancedOpen && (
              <div id="discover-advanced" role="group" aria-label="Advanced" style={{ marginTop: 10, paddingLeft: 12, borderLeft: '2px solid var(--app-border)' }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 14px' }}>
                  <ModalField label="TCP ports" hint={custom ? (check.tcp?.ok ? `${check.tcp.ports.length.toLocaleString('en-US')} TCP ports` : 'Ports and ranges, e.g. 22,443,8000-8100.') : 'Set by the scan depth. Choose Custom to change.'}>
                    <ModalInput
                      aria-label="TCP ports"
                      className="mono"
                      readOnly={!custom}
                      aria-invalid={(custom && !!problem('tcp')) || undefined}
                      value={custom ? form.tcpPorts : shownPlan?.tcp_ports ?? ''}
                      placeholder={custom ? '22,443,8000-8100' : 'Set by the scan depth'}
                      onChange={(e) => update({ tcpPorts: e.target.value })}
                    />
                  </ModalField>
                  <ModalField label="UDP ports" hint={custom ? (check.udp?.ok ? `${check.udp.ports.length.toLocaleString('en-US')} UDP ports` : 'A port with no known probe reports “no answer”, never “closed”.') : 'Set by the scan depth. Choose Custom to change.'}>
                    <ModalInput
                      aria-label="UDP ports"
                      className="mono"
                      readOnly={!custom}
                      aria-invalid={(custom && !!problem('udp')) || undefined}
                      value={custom ? form.udpPorts : shownPlan?.udp_ports ?? ''}
                      placeholder={custom ? '53,123,161' : 'Set by the scan depth'}
                      onChange={(e) => update({ udpPorts: e.target.value })}
                    />
                  </ModalField>
                </div>
                {custom && (problem('tcp') ?? problem('udp') ?? problem('ports')) && (
                  <div role="alert" style={{ margin: '-6px 0 12px', fontSize: 11.5, color: 'var(--danger-text)' }}>
                    {problem('tcp') && <div>TCP ports: {problem('tcp')}</div>}
                    {problem('udp') && <div>UDP ports: {problem('udp')}</div>}
                    {problem('ports') && <div>{problem('ports')}</div>}
                  </div>
                )}

                <fieldset style={fieldset}>
                  <legend style={groupTitle}>Pace</legend>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
                    {PACES.map((p) => (
                      <ChoiceCard key={p.value} name="discover-pace" value={p.value} checked={form.pace === p.value} label={p.label} description={p.hint} onChange={() => update({ pace: p.value })} />
                    ))}
                  </div>
                </fieldset>

                {otAvailable && (
                  <div style={{ marginBottom: 15 }}>
                    <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--app-t1)', cursor: 'pointer' }}>
                      <input type="checkbox" checked={form.ot} onChange={(e) => update({ ot: e.target.checked, otProtocols: e.target.checked ? form.otProtocols : [] })} />
                      Probe industrial (OT/ICS) devices
                    </label>
                    <div id="discover-ot-ack" style={{ ...muted, marginTop: 4, paddingLeft: 24 }}>
                      Off unless you tick it, and never part of a scan depth. Sends only each chosen protocol&apos;s documented, read-only
                      identification request, to its standard port only, one connection at a time per device. Industrial controllers can be
                      fragile: probe them only with their owner&apos;s agreement.
                    </div>
                    {form.ot && (
                      <div role="group" aria-label="Industrial protocols" aria-describedby="discover-ot-ack" style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginTop: 8, paddingLeft: 24 }}>
                        {OT_PROTOCOLS.map((p) => (
                          <label key={p.value} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12.5, color: 'var(--app-t1)', cursor: 'pointer' }}>
                            <input
                              type="checkbox"
                              checked={form.otProtocols.includes(p.value)}
                              onChange={(e) => update({ otProtocols: e.target.checked ? [...form.otProtocols, p.value] : form.otProtocols.filter((x) => x !== p.value) })}
                            />
                            {p.label}
                          </label>
                        ))}
                      </div>
                    )}
                    {problem('ot') && <div role="alert" style={{ marginTop: 6, paddingLeft: 24, fontSize: 11.5, color: 'var(--danger-text)' }}>{problem('ot')}</div>}
                  </div>
                )}
              </div>
            )}
          </div>

          {verdict && verdict.kind !== 'error' && verdict.kind !== 'unconfirmed'
            ? <div style={{ minHeight: 92, marginBottom: 6 }}><VerdictNotice verdict={verdict} onRunFromPlatform={runFromPlatform} /></div>
            : <PreviewPanel view={preview} onRunFromPlatform={runFromPlatform} />}
        </>
      )}

      {phase === 'confirm-external' && verdict?.kind === 'unconfirmed' && (
        <div role="alertdialog" aria-labelledby="discover-external-title" aria-describedby="discover-external-body">
          <div id="discover-external-title" style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--app-t1)', marginBottom: 10 }}>
            {externalConfirmTitle(verdict.targets.length)}
          </div>
          <div id="discover-external-body">
            <ul className="mono" style={{ margin: '0 0 10px', paddingLeft: 18, fontSize: 12, color: 'var(--app-t2)', maxHeight: 220, overflowY: 'auto' }}>
              {verdict.targets.slice(0, LIST_MAX).map((t) => <li key={t.target}>{describeExternal(t)}</li>)}
            </ul>
            {verdict.targets.length > LIST_MAX && (
              <div style={{ ...muted, marginBottom: 10 }}>and {verdict.targets.length - LIST_MAX} more</div>
            )}
            <div style={muted}>
              Nothing outside your registered networks is ever scanned automatically — only when you confirm it here.
              They are scanned at Standard depth at most, against the addresses listed, and the scan is recorded in your organization&apos;s audit log.
            </div>
          </div>
        </div>
      )}

      {phase === 'started' && started && <StartedPanel job={started.job} form={started.form} />}
    </Modal>
  );
}

function StartedPanel({ job, form }: { job: DiscoveryJob; form: DiscoverForm }) {
  const plan = job.plan;
  const exec = plan ? describeExecutor(plan) : null;
  const row = (label: string, value: React.ReactNode) => (
    <div style={{ display: 'flex', gap: 12, padding: '3px 0', fontSize: 12.5 }}>
      <span style={{ width: 110, flex: 'none', color: 'var(--app-t3)' }}>{label}</span>
      <span style={{ color: 'var(--app-t1)', minWidth: 0 }}>{value}</span>
    </div>
  );
  const targets = job.targets?.length ?? 0;
  return (
    <div role="status">
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 14, fontWeight: 600, color: 'var(--app-t1)', marginBottom: 10 }}>
        <Icon name="check" size={16} style={{ color: 'var(--app-ok)' }} />
        Started — track it in Discovery Jobs
      </div>
      {row('Scan depth', depthLabel(plan?.depth ?? form.depth))}
      {row('Pace', paceLabel(plan?.pace ?? form.pace))}
      {row('Runs from', exec ? <>{exec.where.replace(/^Runs from /, '')}{exec.why && <span style={{ color: 'var(--app-t3)' }}> — {exec.why}</span>}</> : 'Decided by the platform when the scan is picked up')}
      {targets > 0 && row('Targets', targets.toLocaleString('en-US'))}
      {row('Job', <span className="mono">{shortId(job.id)}</span>)}
      <div style={{ ...muted, marginTop: 12, lineHeight: 1.55 }}>
        You can close this dialog — the scan does not depend on it. Discovery Jobs shows its progress and lets you stop it.
        What it finds flows into your inventory as it is processed: hosts on a network segment marked auto-approve are monitored
        straight away, everything else waits in Discovery → Approvals. An address that sends no answer is reported as no answer,
        not as empty — it may be down, filtered, or out of the scanner&apos;s reach.
      </div>
    </div>
  );
}
