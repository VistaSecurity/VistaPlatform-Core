// The shared frame for managing one agent — a sensor or a discovery agent —
// from Discovery → Sensors & Agents.
//
// The two drawers were built separately and looked it: different tab sets,
// different section order, and a command history only the sensor had, printed
// as raw JSON that grew without bound. The runtimes do different jobs, so they
// will never have identical features, but everything they share is rendered by
// THIS file so the two cannot drift apart again:
//
//   - the header and tab bar (one tab order, RUNTIME_TABS; a drawer picks the
//     tabs it has, never reorders or renames them);
//   - the Connection block that opens both Health tabs;
//   - the job history list (last N, one line each, click to expand);
//   - the restart control.
//
// Nothing here fetches. Each drawer owns its queries, because the two talk to
// different services with separately generated clients.
import { useState } from 'react';
import { Icon, DrawerShell, DrawerCloseBtn, MetaRow, SectionLabel, Pill } from '../../components/ui';
import { jobMeta, relTime } from './kit';
import { stateNote, type ConfigStatus } from './agent-config';

// ---- Tabs -----------------------------------------------------------------

export type RuntimeTabKey = 'overview' | 'discoveries' | 'health' | 'jobs' | 'logs' | 'settings';

/** The one tab order both drawers use. A tab a runtime cannot support is left
 *  out, not shown empty; the rest keep their place and their name. */
export const RUNTIME_TABS: readonly { key: RuntimeTabKey; label: string; icon: string }[] = [
  { key: 'overview', label: 'Overview', icon: 'info' },
  { key: 'discoveries', label: 'Discoveries', icon: 'radar' },
  { key: 'health', label: 'Health', icon: 'activity' },
  { key: 'jobs', label: 'Jobs', icon: 'list-checks' },
  { key: 'logs', label: 'Logs', icon: 'file-text' },
  { key: 'settings', label: 'Settings', icon: 'settings' },
];

export function runtimeTabs(keys: readonly RuntimeTabKey[]) {
  return RUNTIME_TABS.filter((t) => keys.includes(t.key));
}

export function RuntimeDrawer({
  icon, eyebrow, name, online, status, badges, tabs, tab, onTab, onClose, children,
}: {
  icon: string;
  eyebrow: string;
  name: string;
  online: boolean;
  status?: string | null;
  /** Extra header chips after the status pill (version, address, air-gapped). */
  badges?: React.ReactNode;
  tabs: readonly RuntimeTabKey[];
  tab: RuntimeTabKey;
  onTab: (t: RuntimeTabKey) => void;
  onClose: () => void;
  children: React.ReactNode;
}) {
  const tone = online ? 'var(--ok)' : status === 'pending' ? 'var(--warn)' : 'var(--danger)';
  return (
    <DrawerShell onClose={onClose} width={560}>
      <div style={{ padding: '18px 22px 0', borderBottom: '1px solid var(--app-border)' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
          <span style={{ flex: 'none', width: 34, height: 34, borderRadius: 9, display: 'flex', alignItems: 'center', justifyContent: 'center', background: `color-mix(in srgb, ${online ? 'var(--ok)' : 'var(--danger)'} 12%, transparent)`, color: online ? 'var(--ok)' : 'var(--danger)' }}>
            <Icon name={icon} size={16} />
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="eyebrow-app">{eyebrow}</div>
            <h2 style={{ margin: '4px 0 6px', fontSize: 16.5, fontWeight: 700, fontFamily: 'var(--font-head)', color: 'var(--app-t1)', lineHeight: 1.25, wordBreak: 'break-word' }}>{name}</h2>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
              <Pill color={tone} style={{ fontSize: 10.5 }}>{(status || 'unknown').replace('_', ' ')}</Pill>
              {badges}
            </div>
          </div>
          <DrawerCloseBtn onClose={onClose} />
        </div>
        <div role="tablist" style={{ display: 'flex', gap: 2, marginTop: 16, overflowX: 'auto' }}>
          {runtimeTabs(tabs).map((t) => (
            <button
              key={t.key}
              role="tab"
              aria-selected={tab === t.key}
              onClick={() => onTab(t.key)}
              style={{
                display: 'flex', alignItems: 'center', gap: 6, padding: '8px 11px', border: 'none', background: 'transparent', cursor: 'pointer', flex: 'none',
                fontSize: 12.5, fontWeight: 600, color: tab === t.key ? 'var(--app-t1)' : 'var(--app-t3)',
                borderBottom: tab === t.key ? '2px solid var(--accent)' : '2px solid transparent', marginBottom: -1,
              }}
            >
              <Icon name={t.icon} size={13} />{t.label}
            </button>
          ))}
        </div>
      </div>
      <div style={{ flex: 1, padding: '4px 22px 30px' }}>{children}</div>
    </DrawerShell>
  );
}

// ---- Small shared pieces --------------------------------------------------

export function MetricCard({ icon, label, value, tone }: { icon: string; label: string; value: string; tone?: string }) {
  return (
    <div className="panel" style={{ borderRadius: 12, padding: '12px 14px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--app-t3)' }}>
        <Icon name={icon} size={13} /><span className="eyebrow-app">{label}</span>
      </div>
      <div style={{ fontSize: 18, fontWeight: 700, fontFamily: 'var(--font-head)', color: tone ?? 'var(--app-t1)', marginTop: 6 }}>{value}</div>
    </div>
  );
}

export function Muted({ children, danger }: { children: React.ReactNode; danger?: boolean }) {
  return <div style={{ fontSize: 12, color: danger ? 'var(--danger-text)' : 'var(--app-t3)', padding: '6px 0', lineHeight: 1.6 }}>{children}</div>;
}

export function fmtTs(iso?: string | null): string {
  return iso ? iso.slice(0, 19).replace('T', ' ') : '—';
}

const TONE_COLOR: Record<string, string> = { ok: 'var(--ok)', warn: 'var(--warn)', danger: 'var(--danger)', muted: 'var(--app-t3)' };

/** The block that opens BOTH Health tabs: is it talking to us, what is it
 *  running, and has it taken the settings we gave it. Everything a sensor and
 *  an agent can both answer, in the same words. */
export function ConnectionHealth({ online, lastHeartbeat, version, configStatus, configLoading, noun }: {
  online: boolean;
  lastHeartbeat?: string | null;
  version?: string | null;
  configStatus?: ConfigStatus;
  configLoading?: boolean;
  noun: 'sensor' | 'agent';
}) {
  const sync = stateNote(configStatus);
  return (
    <>
      <SectionLabel icon="plug">Connection</SectionLabel>
      <MetaRow k="State" v={<span style={{ color: online ? 'var(--ok)' : 'var(--danger)', fontWeight: 600 }}>{online ? 'Online' : 'Offline'}</span>} />
      <MetaRow k={online ? 'Last heartbeat' : 'Last seen'} v={relTime(lastHeartbeat)} title={fmtTs(lastHeartbeat)} />
      <MetaRow k="Version" v={version ? `v${version.replace(/^v/, '')}` : null} mono />
      <MetaRow
        k="Settings"
        v={configLoading ? '…' : <span style={{ color: TONE_COLOR[sync.tone] ?? 'var(--app-t1)', fontWeight: 600 }}>{sync.label}</span>}
        title={sync.detail}
      />
      {configStatus?.reported_at && <MetaRow k="Settings reported" v={relTime(configStatus.reported_at)} title={fmtTs(configStatus.reported_at)} />}
      {!online && (
        <Muted>
          This {noun} has not checked in for over 15 minutes. Queued jobs and setting changes wait until it does.
        </Muted>
      )}
    </>
  );
}

// ---- Job history ----------------------------------------------------------

/** One row of a runtime's job history, in terms both runtimes can supply. */
export interface RecentJob {
  id: string;
  /** What ran — a command verb or a job type, already humanised. */
  title: string;
  /** Who or what it ran against, when there is one. */
  target?: string | null;
  status?: string | null;
  createdAt?: string | null;
  error?: string | null;
}

/** Status words for a job or command. The sensor's command lifecycle adds two
 *  in-flight states the interrogation jobs do not have, so they are named here
 *  rather than falling through to the raw word. */
export function recentJobMeta(status?: string | null) {
  const s = (status || '').toLowerCase();
  if (s === 'delivered') return { c: 'var(--info)', l: 'Delivered', icon: 'send' };
  if (s === 'acknowledged') return { c: 'var(--info)', l: 'Running', icon: 'loader' };
  if (s === 'expired') return { c: 'var(--app-t3)', l: 'Expired', icon: 'clock' };
  return jobMeta(status);
}

export const JOB_HISTORY_LIMIT = 10;

/** The last few jobs, one line each; a click opens the detail. Capped so the
 *  list cannot take over the drawer the way the old command history did. */
export function JobHistoryList({ jobs, total, isLoading, isError, emptyText, renderDetail, limit = JOB_HISTORY_LIMIT }: {
  jobs: RecentJob[];
  /** All the runtime has, when known — shown as "last 10 of N". */
  total?: number;
  isLoading: boolean;
  isError: boolean;
  emptyText: string;
  renderDetail: (id: string) => React.ReactNode;
  limit?: number;
}) {
  const [open, setOpen] = useState<string | null>(null);
  const shown = jobs.slice(0, limit);
  const of = total ?? jobs.length;

  return (
    <>
      <SectionLabel icon="history">
        Recent jobs{!isLoading && !isError && shown.length > 0 && (
          <span style={{ textTransform: 'none', letterSpacing: 0, fontWeight: 500, color: 'var(--app-t3)', marginLeft: 4 }}>
            {of > shown.length ? `· last ${shown.length} of ${of}` : `· ${shown.length}`}
          </span>
        )}
      </SectionLabel>
      {isError ? (
        <Muted danger>Couldn't load the job history.</Muted>
      ) : isLoading ? (
        <Muted>Loading jobs…</Muted>
      ) : shown.length === 0 ? (
        <Muted>{emptyText}</Muted>
      ) : (
        <div style={{ border: '1px solid var(--app-border)', borderRadius: 10, overflow: 'hidden', marginTop: 4 }}>
          {shown.map((j, i) => {
            const m = recentJobMeta(j.status);
            const isOpen = open === j.id;
            return (
              <div key={j.id} style={{ borderTop: i === 0 ? 'none' : '1px solid var(--app-border)' }}>
                <button
                  type="button"
                  aria-expanded={isOpen}
                  onClick={() => setOpen(isOpen ? null : j.id)}
                  style={{ width: '100%', display: 'flex', alignItems: 'center', gap: 10, padding: '9px 12px', border: 'none', background: isOpen ? 'var(--app-panel2)' : 'transparent', cursor: 'pointer', textAlign: 'left' }}
                >
                  <Icon name={isOpen ? 'chevron-down' : 'chevron-right'} size={13} style={{ color: 'var(--app-t3)', flex: 'none' }} />
                  <span style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
                    <span className="mono" style={{ fontSize: 12.5, color: 'var(--app-t1)', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{j.title}</span>
                    {j.target && <span style={{ fontSize: 11, color: 'var(--app-t3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{j.target}</span>}
                  </span>
                  <span style={{ fontSize: 11, color: 'var(--app-t3)', flex: 'none' }} title={fmtTs(j.createdAt)}>{relTime(j.createdAt)}</span>
                  <Pill color={m.c} style={{ fontSize: 10, flex: 'none' }}>{m.l}</Pill>
                </button>
                {isOpen && (
                  <div style={{ padding: '4px 14px 12px 35px', background: 'var(--app-panel2)' }}>
                    {j.error && <div style={{ fontSize: 11.5, color: 'var(--danger-text)', margin: '4px 0 6px', lineHeight: 1.5 }}>{j.error}</div>}
                    {renderDetail(j.id)}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </>
  );
}

/** A labelled JSON block inside an expanded job. Hidden when there is nothing
 *  in it: an empty `{}` box says nothing a reader needs. */
export function PayloadBlock({ label, value }: { label: string; value: unknown }) {
  if (value == null) return null;
  if (typeof value === 'object' && Object.keys(value).length === 0) return null;
  return (
    <div style={{ marginTop: 8 }}>
      <div style={{ fontSize: 10.5, color: 'var(--app-t3)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '.04em' }}>{label}</div>
      <pre className="mono" style={{ margin: 0, padding: '8px 10px', borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel)', color: 'var(--app-t2)', fontSize: 11, lineHeight: 1.5, whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 220, overflowY: 'auto' }}>
        {JSON.stringify(value, null, 2)}
      </pre>
    </div>
  );
}

/** Compact key/value lines inside an expanded job. */
export function DetailRow({ k, v, mono }: { k: string; v?: React.ReactNode; mono?: boolean }) {
  if (v === null || v === undefined || v === '') return null;
  return (
    <div style={{ display: 'flex', gap: 10, fontSize: 11.5, padding: '2px 0' }}>
      <span style={{ color: 'var(--app-t3)', width: 96, flex: 'none' }}>{k}</span>
      <span className={mono ? 'mono' : ''} style={{ color: 'var(--app-t1)', wordBreak: 'break-word' }}>{v}</span>
    </div>
  );
}

// ---- Logs -----------------------------------------------------------------

/** Where a device's log export stands, in terms both runtimes can supply. */
export type LogExportState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'unsupported' }
  | { kind: 'none' }
  | { kind: 'waiting'; requestedAt?: string | null }
  | { kind: 'failed'; message: string }
  | { kind: 'ready'; lines: string[]; receivedAt?: string | null };

export const LOG_LINE_CHOICES = [100, 200, 500] as const;

/** The Logs tab both drawers render. The device answers at its next check-in,
 *  so a fetch is a request, and the panel says so while it waits. */
export function LogExportPanel({ noun, state, canRequest, lineCount, onLineCount, onFetch, fetching, fetchError, unsupportedText }: {
  noun: 'sensor' | 'agent';
  state: LogExportState;
  canRequest: boolean;
  lineCount: number;
  onLineCount: (n: number) => void;
  onFetch: () => void;
  fetching: boolean;
  fetchError?: string | null;
  unsupportedText?: string;
}) {
  const waiting = state.kind === 'waiting';
  const hasLines = state.kind === 'ready';
  return (
    <>
      <SectionLabel icon="file-text">Recent log lines</SectionLabel>
      <div style={{ fontSize: 11, color: 'var(--app-t3)', lineHeight: 1.6, margin: '2px 0 10px' }}>
        The {noun} sends its most recent log lines at its next check-in. Credentials in a line are masked before it is shown.
      </div>
      {canRequest && state.kind !== 'unsupported' && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
          <select aria-label="Lines" value={lineCount} onChange={(e) => onLineCount(Number(e.target.value))} style={{ height: 30, padding: '0 8px', borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12, cursor: 'pointer' }}>
            {LOG_LINE_CHOICES.map((n) => <option key={n} value={n}>{n} lines</option>)}
          </select>
          <button className="ui-btn sm" disabled={fetching || waiting || state.kind === 'loading'} onClick={onFetch}>
            <Icon name="download" size={13} />{hasLines || state.kind === 'failed' ? 'Fetch again' : 'Fetch logs'}
          </button>
          {fetchError && <span style={{ fontSize: 11, color: 'var(--danger-text)' }}>{fetchError}</span>}
        </div>
      )}
      {state.kind === 'loading' && <Muted>Loading…</Muted>}
      {state.kind === 'error' && <Muted danger>{state.message}</Muted>}
      {state.kind === 'unsupported' && <Muted>{unsupportedText ?? `This ${noun} cannot send its logs.`}</Muted>}
      {state.kind === 'none' && <Muted>No logs have been fetched from this {noun} yet.</Muted>}
      {state.kind === 'waiting' && <Muted>Requested {relTime(state.requestedAt)} — waiting for the {noun} to check in.</Muted>}
      {state.kind === 'failed' && <Muted danger>{state.message}</Muted>}
      {state.kind === 'ready' && (
        <>
          <div style={{ fontSize: 10.5, color: 'var(--app-t3)', marginBottom: 6 }}>
            {state.lines.length} line{state.lines.length === 1 ? '' : 's'} · received {fmtTs(state.receivedAt)}
          </div>
          <pre className="mono" style={{ margin: 0, padding: '10px 12px', borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t2)', fontSize: 11, lineHeight: 1.55, whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 460, overflowY: 'auto' }}>
            {state.lines.join('\n')}
          </pre>
        </>
      )}
    </>
  );
}

// ---- Restart --------------------------------------------------------------

/** The restart control both runtimes render. The caveat is the caller's,
 *  because what can go wrong differs; it is shown BEFORE the click, while the
 *  operator can still change their mind. */
export function RestartControl({ noun, caveat, pending, onConfirm, successNote, error }: {
  noun: 'sensor' | 'agent';
  caveat: React.ReactNode;
  pending: boolean;
  onConfirm: () => void;
  successNote?: React.ReactNode;
  error?: string | null;
}) {
  const [confirming, setConfirming] = useState(false);
  return (
    <div style={{ marginTop: 20, paddingTop: 14, borderTop: '1px solid var(--app-border)' }}>
      <SectionLabel icon="refresh">Restart</SectionLabel>
      <div style={{ fontSize: 11, color: 'var(--app-t3)', lineHeight: 1.6, margin: '6px 0 10px' }}>
        Settings marked “takes effect on restart” are adopted when the {noun} restarts.
      </div>
      {!confirming && (
        <button className="ui-btn sm ghost" disabled={pending} onClick={() => setConfirming(true)}>
          <Icon name="refresh" size={13} />Restart {noun}
        </button>
      )}
      {confirming && (
        <div style={{ padding: 12, border: '1px solid var(--warn)', borderLeft: '3px solid var(--warn)', borderRadius: 0 }}>
          <div style={{ fontSize: 11.5, color: 'var(--app-t2)', lineHeight: 1.6, marginBottom: 8 }}>{caveat}</div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="ui-btn sm" disabled={pending} onClick={() => { setConfirming(false); onConfirm(); }}>
              {pending ? 'Requesting…' : 'Restart it'}
            </button>
            <button className="ui-btn sm ghost" disabled={pending} onClick={() => setConfirming(false)}>Cancel</button>
          </div>
        </div>
      )}
      {successNote && <div style={{ fontSize: 11.5, color: 'var(--app-t2)', marginTop: 10, lineHeight: 1.6 }}>{successNote}</div>}
      {error && <div style={{ fontSize: 11.5, color: 'var(--danger-text)', marginTop: 10 }}>{error}</div>}
    </div>
  );
}

/** The line under both managed-settings panels. */
export function ManagedHereNote({ noun, canEdit }: { noun: 'sensor' | 'agent'; canEdit: boolean }) {
  return (
    <div style={{ fontSize: 11, color: 'var(--app-t3)', margin: '12px 0 4px', lineHeight: 1.6 }}>
      {canEdit
        ? `These settings are managed here, not on the ${noun}'s host. A local edit to its config file is overwritten at its next check-in.`
        : 'You can view these settings but not change them. Changing them needs the Update sensors permission.'}
    </div>
  );
}
