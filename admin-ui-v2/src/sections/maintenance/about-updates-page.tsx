// VISTA Operations — Maintenance › About & Updates (left-rail default).
//
// Three cards. The first and third read GET /admin/maintenance/status, the
// second GET /admin/maintenance/updates:
//   1. How this install is managed — the capability object in plain language
//      (Kubernetes or not, Helm or GitOps, single node), so an operator knows
//      before anything is offered why it is or is not.
//   2. Updates — what the last update check found (up to date, a release is
//      available, the registry could not be reached, the check is off), with
//      "Check now" for an operator holding platform.maintenance, and **Update
//      to <version>**, which opens the confirmation dialog (update-dialog.tsx:
//      pre-flight, what will happen, the typed version) and then the run's
//      progress page. With the check off, a maintainer can type a version to
//      update to from their mirror.
//   3. Running versions — the per-service table and the four-state alignment
//      badge, ported from the tenant console's About page
//      (frontend-v2/src/pages/about-page.tsx). The data is the same
//      monitoring-service GET /version body, proxied by maintenance-service, so
//      the two pages can never disagree.
//   4. Run history — the last update, rollback and backup runs, each linking
//      to its progress page.
import { useState } from 'react';
import { useNavigate } from 'react-router';
import { AlertTriangle, CheckCheck, CircleAlert, Layers, PackageCheck, RefreshCw, Server, ShieldAlert, type LucideIcon } from 'lucide-react';
import { PLATFORM_PERMISSIONS, usePlatformPermissions } from '@vistasecurity/primitives/platform-auth';
import { Panel } from '../system/parts';
import { RunHistory } from './run-history';
import { UpdateDialog } from './update-dialog';
import {
  UpdateCheckConflictError,
  useCheckForUpdates,
  useMaintenanceStatus,
  useUpdateStatus,
  type MaintenanceCapabilities,
  type MaintenanceStatus,
  type UpdateStatus,
  type VersionReport,
} from './maintenance-queries';

/** The four alignment states the badge renders (monitoring-service VersionResponse.status). */
export const ALIGNMENT_META: Record<VersionReport['status'], { color: string; bg: string; icon: LucideIcon; label: string; note: string }> = {
  aligned: { color: 'var(--ok)', bg: 'color-mix(in srgb, var(--ok) 13%, transparent)', icon: CheckCheck, label: 'All services aligned', note: 'Every reachable service reports the same version.' },
  skew: { color: 'var(--danger)', bg: 'color-mix(in srgb, var(--danger) 13%, transparent)', icon: AlertTriangle, label: 'Version skew detected', note: 'Two or more services report different versions — usually a partial or interrupted upgrade.' },
  degraded: { color: 'var(--warn)', bg: 'color-mix(in srgb, var(--warn) 14%, transparent)', icon: ShieldAlert, label: 'Degraded', note: 'Reporting services agree, but a service is unreachable.' },
  unknown: { color: 'var(--op-t3)', bg: 'var(--op-panel2)', icon: CircleAlert, label: 'Version unknown', note: 'No service reported a real version (normal in local development).' },
};

/** Plain-language explanation of how this install is managed, by capability reason. */
export function managementNotice(caps: MaintenanceCapabilities, release: MaintenanceStatus['release']): { title: string; body: string; tone: 'ok' | 'info' | 'warn' } {
  switch (caps.reason) {
    case 'not_kubernetes':
      return {
        title: 'Not available in this deployment',
        body: 'This install is not running on Kubernetes (Docker Compose is for evaluation only). Backups and updates from the console need the Helm chart install.',
        tone: 'info',
      };
    case 'gitops':
      return {
        title: 'Managed by GitOps',
        body: 'A GitOps controller (Argo CD or Flux) manages this install. Update it from your values repository — an update made from this console would be undone on the controller’s next sync.',
        tone: 'info',
      };
    case 'not_helm_managed':
      return {
        title: 'Not installed with Helm',
        body: 'No Helm release was found for this install, so the chart was applied by something other than helm install (Argo CD renders it itself, for example). Update it the same way it was installed.',
        tone: 'info',
      };
    case 'cluster_api_unavailable':
      return {
        title: 'Cannot read the cluster',
        body: 'The maintenance service could not reach the Kubernetes API, so it cannot tell how this install is managed. Check its ServiceAccount, Role and RoleBinding (all named maintenance-service).',
        tone: 'warn',
      };
    case 'release_unknown':
      return {
        title: 'Release not identified',
        body: 'The maintenance service was not told its Helm release name or namespace. Re-apply the chart so its deployment carries them.',
        tone: 'warn',
      };
    default:
      return {
        title: 'Managed by Helm',
        body: `Helm manages this install as release ${release.name || '—'} in namespace ${release.namespace || '—'}.`,
        tone: 'ok',
      };
  }
}

const TONE: Record<'ok' | 'info' | 'warn', string> = { ok: 'var(--ok)', info: 'var(--op-t3)', warn: 'var(--warn)' };

function SkeletonBlock({ h = 14, w = '100%' }: { h?: number; w?: number | string }) {
  return <div data-testid="skeleton" style={{ height: h, width: w, borderRadius: 'var(--r-md, 8px)', background: 'var(--op-track)', opacity: 0.55 }} />;
}

function ManagementCard({ status }: { status: MaintenanceStatus }) {
  const n = managementNotice(status.capabilities, status.release);
  return (
    <Panel title="How this install is managed" icon={Server}>
      <div data-testid="maintenance-management" style={{ padding: '14px 16px', display: 'flex', gap: 12, alignItems: 'flex-start' }}>
        <span style={{ width: 8, height: 8, borderRadius: 50, marginTop: 6, flex: 'none', background: TONE[n.tone] }} />
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--op-t1)' }}>{n.title}</div>
          <div style={{ fontSize: 12.5, color: 'var(--op-t3)', marginTop: 3, lineHeight: 1.55 }}>{n.body}</div>
          {status.single_node && (
            <div data-testid="maintenance-single-node" style={{ fontSize: 12, color: 'var(--warn)', marginTop: 8 }}>
              Single-node cluster: an upgrade restarts services one after another and some are briefly unavailable.
            </div>
          )}
        </div>
      </div>
    </Panel>
  );
}

/** "5 minutes ago" for a timestamp; pure so tests can pin `now`. */
export function relativeTime(iso: string, now: number = Date.now()): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return 'at an unknown time';
  const secs = Math.max(0, Math.round((now - t) / 1000));
  if (secs < 60) return 'just now';
  const units: [number, string][] = [[86400, 'day'], [3600, 'hour'], [60, 'minute']];
  for (const [size, name] of units) {
    if (secs >= size) {
      const n = Math.floor(secs / size);
      return `${n} ${name}${n === 1 ? '' : 's'} ago`;
    }
  }
  return 'just now';
}

/** The update card's state, from the stored row (pure, for tests). */
export type UpdateCardState =
  | { kind: 'loading' }
  | { kind: 'load-error' }
  | { kind: 'unsupported' }
  | { kind: 'disabled' }
  | { kind: 'never-checked' }
  | { kind: 'error'; message: string }
  | { kind: 'available'; version: string; notesUrl: string | null }
  | { kind: 'current'; checkedAt: string | null };

export function updateCardState(
  q: { isLoading: boolean; isError: boolean; data?: UpdateStatus },
  caps: MaintenanceCapabilities | undefined,
  checking: boolean,
): UpdateCardState {
  if (caps?.reason === 'not_kubernetes') return { kind: 'unsupported' };
  if (checking || q.isLoading) return { kind: 'loading' };
  if (q.isError || !q.data) return { kind: 'load-error' };
  const d = q.data;
  if (d.update_available && d.latest_version) return { kind: 'available', version: d.latest_version, notesUrl: d.notes_url };
  if (!d.check_enabled) return { kind: 'disabled' };
  if (d.error) return { kind: 'error', message: d.error };
  if (!d.checked_at) return { kind: 'never-checked' };
  return { kind: 'current', checkedAt: d.checked_at };
}

/**
 * Whether the Update button is live, and why not (pure, for tests). It needs
 * an install the console may change (capabilities.updates: Helm-managed, not
 * GitOps) and an operator holding platform.maintenance.
 */
export function updateButtonState(caps: MaintenanceCapabilities | undefined, canMaintain: boolean): { enabled: boolean; reason: string | null } {
  if (!caps?.updates) {
    return {
      enabled: false,
      reason: caps?.reason === 'gitops'
        ? 'This install is managed outside Helm (GitOps). Update it from your values repository.'
        : 'This install cannot be updated from the console — see “How this install is managed”.',
    };
  }
  if (!canMaintain) return { enabled: false, reason: 'Updating needs the platform.maintenance permission.' };
  return { enabled: true, reason: null };
}

function UpdatesCard({ caps, canCheck, currentVersion }: { caps: MaintenanceCapabilities | undefined; canCheck: boolean; currentVersion?: string }) {
  const q = useUpdateStatus();
  const check = useCheckForUpdates();
  const navigate = useNavigate();
  const [dialogVersion, setDialogVersion] = useState<string | null>(null);
  const [manualVersion, setManualVersion] = useState('');
  const button = updateButtonState(caps, canCheck);
  const state = updateCardState(q, caps, check.isPending);
  const data = q.data;
  const checkNow = canCheck && data?.check_enabled !== false && (state.kind === 'current' || state.kind === 'error' || state.kind === 'never-checked' || state.kind === 'available');
  const conflict = check.error instanceof UpdateCheckConflictError ? check.error.message : check.error ? 'The update check failed. Try again.' : null;

  return (
    <Panel title="Updates" icon={PackageCheck}>
      <div data-testid="maintenance-updates" data-state={state.kind} style={{ padding: '14px 16px', display: 'flex', alignItems: 'flex-start', gap: 12 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          {state.kind === 'loading' && <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--op-t1)' }}>Checking…</div>}
          {state.kind === 'load-error' && (
            <div style={{ fontSize: 12.5, color: 'var(--op-t3)' }}>
              Couldn’t load the update status.
              <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => { void q.refetch(); }}><RefreshCw size={12} /> Retry</button>
            </div>
          )}
          {state.kind === 'unsupported' && (
            <div style={{ fontSize: 12.5, color: 'var(--op-t3)', lineHeight: 1.55 }}>Update checks need the Helm chart install; this deployment cannot be updated from the console.</div>
          )}
          {state.kind === 'disabled' && (
            <div style={{ fontSize: 12.5, color: 'var(--op-t3)', lineHeight: 1.55 }}>
              <span style={{ fontWeight: 700, color: 'var(--op-t1)', fontSize: 13.5 }}>Update check is off</span>
              <div style={{ marginTop: 3 }}>
                <code>maintenance.updateCheck.enabled=false</code> in the chart values. Turn it on to be told when a new Vista Platform release is out.
              </div>
              {button.enabled && (
                <form
                  data-testid="maintenance-manual-update"
                  style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 10 }}
                  onSubmit={(e) => { e.preventDefault(); if (manualVersion.trim()) setDialogVersion(manualVersion.trim().replace(/^v/, '')); }}
                >
                  <span>Enter a version to update to from your mirror:</span>
                  <input aria-label="Version to update to" data-testid="manual-version" value={manualVersion} onChange={(e) => setManualVersion(e.target.value)} placeholder="4.6.0"
                    style={{ height: 28, width: 110, borderRadius: 'var(--r-btn)', border: '1px solid var(--op-border2)', background: 'var(--op-panel2)', color: 'var(--op-t1)', padding: '0 8px', fontSize: 12.5 }} />
                  <button className="op-btn sm" type="submit" disabled={!manualVersion.trim()}>Update…</button>
                </form>
              )}
            </div>
          )}
          {state.kind === 'never-checked' && (
            <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--op-t1)' }}>No update check has run yet</div>
          )}
          {state.kind === 'error' && (
            <div style={{ fontSize: 12.5, color: 'var(--danger)', lineHeight: 1.55 }}>
              Could not reach the chart registry: {state.message}
            </div>
          )}
          {state.kind === 'current' && (
            <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--op-t1)' }}>
              Up to date <span style={{ fontWeight: 400, color: 'var(--op-t3)', fontSize: 12.5 }}>· checked {state.checkedAt ? relativeTime(state.checkedAt) : 'never'}</span>
            </div>
          )}
          {state.kind === 'available' && (
            <>
              <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--op-t1)' }}>
                Vista Platform {state.version} available
                {state.notesUrl && (
                  <>
                    {' '}<span style={{ fontWeight: 400, color: 'var(--op-t3)' }}>·</span>{' '}
                    <a href={state.notesUrl} target="_blank" rel="noopener noreferrer" data-testid="maintenance-update-notes" style={{ fontWeight: 400, fontSize: 12.5 }}>What’s new</a>
                  </>
                )}
              </div>
              {button.reason && <div data-testid="maintenance-update-reason" style={{ fontSize: 12, color: 'var(--op-t3)', marginTop: 4 }}>{button.reason}</div>}
              {data?.error && (
                <div data-testid="maintenance-update-stale-error" style={{ fontSize: 12, color: 'var(--warn)', marginTop: 4 }}>
                  The last check failed ({data.error}); this is the last version it saw.
                </div>
              )}
            </>
          )}
          {conflict && <div data-testid="maintenance-update-check-error" role="alert" style={{ fontSize: 12, color: 'var(--danger)', marginTop: 6 }}>{conflict}</div>}
        </div>
        <div style={{ display: 'flex', gap: 8, flex: 'none' }}>
          {state.kind === 'available' && (
            <button
              className="op-btn primary sm"
              disabled={!button.enabled}
              title={button.reason ?? undefined}
              data-testid="maintenance-update-button"
              onClick={() => setDialogVersion(state.version)}
            >Update to {state.version}</button>
          )}
          {checkNow && (
            <button className="op-btn sm" data-testid="maintenance-check-now" onClick={() => check.mutate()}>
              <RefreshCw size={12} /> Check now
            </button>
          )}
        </div>
      </div>
      {dialogVersion && (
        <UpdateDialog
          version={dialogVersion}
          currentVersion={currentVersion}
          onClose={() => setDialogVersion(null)}
          onStarted={(runId) => { setDialogVersion(null); void navigate(`/maintenance/runs/${runId}`); }}
        />
      )}
    </Panel>
  );
}

type VersionsState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'empty'; report: VersionReport }
  | { kind: 'success'; report: VersionReport };

/** The versions card's state from the status query (pure, for tests). */
export function versionsState(q: { isLoading: boolean; isError: boolean; data?: MaintenanceStatus }): VersionsState {
  if (q.isLoading) return { kind: 'loading' };
  if (q.isError || !q.data) return { kind: 'error', message: 'Couldn’t load the platform status.' };
  const report = q.data.versions;
  if (!report) return { kind: 'error', message: 'Couldn’t read the running versions from the monitoring service.' };
  if (!report.services?.length) return { kind: 'empty', report };
  return { kind: 'success', report };
}

function VersionsCard({ state, onRetry }: { state: VersionsState; onRetry: () => void }) {
  const report = state.kind === 'empty' || state.kind === 'success' ? state.report : null;
  const meta = report ? (ALIGNMENT_META[report.status] ?? ALIGNMENT_META.unknown) : null;
  const MetaIcon = meta?.icon;
  return (
    <Panel title="Running versions" icon={Layers}>
      {report && meta && MetaIcon && (
        <div data-testid="maintenance-alignment" data-status={report.status} style={{ padding: '14px 16px', display: 'flex', alignItems: 'center', gap: 14, borderBottom: '1px solid var(--op-border)' }}>
          <span style={{ width: 38, height: 38, borderRadius: 10, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: meta.bg, color: meta.color }}>
            <MetaIcon size={18} />
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 13.5, fontWeight: 700, color: meta.color }}>{meta.label}</div>
            <div style={{ fontSize: 12, color: 'var(--op-t3)', marginTop: 2 }}>{meta.note}</div>
          </div>
          <div style={{ textAlign: 'right' }}>
            {report.self?.app_version && report.self.app_version !== 'unknown' && (
              <div className="mono" style={{ fontSize: 15, fontWeight: 700, color: 'var(--op-t1)' }}>Vista Platform {report.self.app_version}</div>
            )}
            <div className="mono" style={{ fontSize: 11.5, color: 'var(--op-t3)' }}>
              {report.summary.reachable}/{report.summary.total} reachable · {report.summary.reporting} reporting
            </div>
          </div>
        </div>
      )}
      {report?.status === 'skew' && (report.skew?.length ?? 0) > 0 && (
        <div data-testid="maintenance-skew" style={{ padding: '10px 16px', borderBottom: '1px solid var(--op-border)' }}>
          {report.skew!.map((s) => (
            <div key={s.field} style={{ display: 'flex', gap: 12, padding: '3px 0', fontSize: 12 }}>
              <span style={{ width: 90, flex: 'none', color: 'var(--op-t3)' }}>{s.field}</span>
              <span className="mono" style={{ color: 'var(--op-t1)' }}>{s.values.join('  ·  ')}</span>
            </div>
          ))}
        </div>
      )}
      <table className="op-table" data-testid="maintenance-versions">
        <thead><tr><th>Service</th><th>Version</th><th>Chart</th><th>Status</th></tr></thead>
        <tbody>
          {state.kind === 'loading' && [0, 1, 2, 3].map((i) => (
            <tr key={i} data-testid="skeleton-row"><td colSpan={4}><SkeletonBlock /></td></tr>
          ))}
          {state.kind === 'error' && (
            <tr><td colSpan={4} data-testid="maintenance-versions-error" style={{ textAlign: 'center', padding: 32, color: 'var(--op-t3)' }}>
              {state.message}
              <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={onRetry}><RefreshCw size={12} /> Retry</button>
            </td></tr>
          )}
          {state.kind === 'empty' && (
            <tr><td colSpan={4} data-testid="maintenance-versions-empty" style={{ textAlign: 'center', padding: 32, color: 'var(--op-t3)' }}>No services reported</td></tr>
          )}
          {state.kind === 'success' && state.report.services!.map((s) => {
            const healthy = s.status === 'healthy';
            return (
              <tr key={s.service} data-testid="maintenance-version-row">
                <td style={{ fontWeight: 500, color: 'var(--op-t1)' }}>{s.service}</td>
                <td className="mono t-muted">{s.tag || s.app_version || '—'}</td>
                <td className="mono t-muted">{s.chart || '—'}</td>
                <td style={{ color: healthy ? 'var(--ok)' : 'var(--danger)', fontWeight: 600, fontSize: 12 }}>{healthy ? 'Healthy' : 'Unreachable'}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </Panel>
  );
}

export function AboutUpdatesPage() {
  const q = useMaintenanceStatus();
  const state = versionsState(q);
  const canCheck = usePlatformPermissions().hasPermission(PLATFORM_PERMISSIONS.platform.maintenance);
  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 18 }}>
      {q.data ? <ManagementCard status={q.data} /> : q.isLoading ? (
        <Panel title="How this install is managed" icon={Server}><div style={{ padding: 16 }}><SkeletonBlock h={32} /></div></Panel>
      ) : null}
      <UpdatesCard caps={q.data?.capabilities} canCheck={canCheck} currentVersion={q.data?.versions?.self?.chart} />
      <VersionsCard state={state} onRetry={() => { void q.refetch(); }} />
      <RunHistory />
    </div>
  );
}
