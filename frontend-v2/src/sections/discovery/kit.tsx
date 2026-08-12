import { Icon } from '../../components/ui';

// Shared bits for the Discovery section — the job-status palette, time/duration
// formatters, the DTable grid (ported from the mock's Discovery.jsx), and the
// loading/error/empty Note. Pages compose these; nothing here fetches.

export interface JobMeta {
  c: string;
  l: string;
  icon: string;
}

// Live statuses (pending / in_progress / completed / failed) mapped onto the
// mock's palette (queued / running / completed / failed).
export function jobMeta(status?: string | null): JobMeta {
  const s = (status || '').toLowerCase();
  if (s === 'running' || s === 'in_progress' || s === 'processing') return { c: 'var(--info)', l: 'Running', icon: 'loader' };
  if (s === 'completed' || s === 'success') return { c: 'var(--ok)', l: 'Completed', icon: 'check' };
  if (s === 'failed' || s === 'error') return { c: 'var(--danger)', l: 'Failed', icon: 'x' };
  if (s === 'cancelled') return { c: 'var(--app-t3)', l: 'Cancelled', icon: 'x' };
  return { c: 'var(--warn)', l: s === 'pending' || s === 'queued' || !s ? 'Queued' : status!, icon: 'clock' };
}

// A subject is only "online" if its status says so AND it has actually checked
// in recently. The heartbeat guard exists because the two runtimes maintain
// their status columns differently: sensor-manager runs a reaper that flips a
// silent sensor to 'offline', but nothing ever rewrites device_agents.status —
// it is hard-coded 'active' at enrollment and never touched again, so a dead
// discovery agent would otherwise render with a green dot forever.
//
// The window matches the dwell the discovery-agent offline ALERT uses, so the
// fleet list can never disagree with the alert an operator just received.
// Pass lastHeartbeat wherever it is available; omitting it keeps the old
// status-only behaviour.
const OFFLINE_AFTER_MS = 15 * 60 * 1000;

export function sensorOnline(status?: string | null, lastHeartbeat?: string | null): boolean {
  const s = (status || '').toLowerCase();
  const statusSaysUp = s === 'active' || s === 'online' || s === 'connected';
  if (!statusSaysUp) return false;

  if (lastHeartbeat === undefined) return true;
  if (!lastHeartbeat) return false;

  const age = Date.now() - new Date(lastHeartbeat).getTime();
  return Number.isFinite(age) && age < OFFLINE_AFTER_MS;
}

export function relTime(iso?: string | null): string {
  if (!iso) return 'never';
  const mins = (Date.now() - new Date(iso).getTime()) / 60000;
  if (mins < 1) return 'just now';
  if (mins < 60) return `${Math.floor(mins)}m ago`;
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`;
  return `${Math.floor(mins / 1440)}d ago`;
}

export function durationFmt(sec?: number | null): string {
  if (sec == null) return '—';
  if (sec < 60) return `${Math.round(sec)}s`;
  if (sec < 3600) return `${Math.round(sec / 60)}m`;
  return `${(sec / 3600).toFixed(1)}h`;
}

export function shortId(id?: string | null): string {
  return id ? id.slice(0, 8) : '—';
}

// ---- DTable — the mock's discovery grid table ----------------------------
export interface DCol {
  label: string;
  w?: string;
  align?: 'left' | 'right';
}

export function DTable<T>({ cols, rows, render, rowKey, onRow }: {
  cols: DCol[];
  rows: T[];
  render: (row: T) => React.ReactNode;
  rowKey: (row: T) => string;
  onRow?: (row: T) => void;
}) {
  const grid = cols.map((c) => c.w || '1fr').join(' ');
  return (
    <div className="panel" style={{ overflow: 'auto', borderRadius: 14 }}>
      <div style={{ display: 'grid', gridTemplateColumns: grid, gap: 12, padding: '0 16px', height: 36, alignItems: 'center', borderBottom: '1px solid var(--app-border2)', position: 'sticky', top: 0, background: 'var(--app-panel)', zIndex: 1 }}>
        {cols.map((c, i) => <span key={i} className="eyebrow-app" style={{ textAlign: c.align || 'left' }}>{c.label}</span>)}
      </div>
      {rows.map((r) => (
        <div key={rowKey(r)} onClick={onRow ? () => onRow(r) : undefined} className="row-hover" style={{ display: 'grid', gridTemplateColumns: grid, gap: 12, padding: '0 16px', minHeight: 46, alignItems: 'center', borderBottom: '1px solid var(--app-border)', cursor: onRow ? 'pointer' : 'default' }}>
          {render(r)}
        </div>
      ))}
    </div>
  );
}

export function CellMono({ v, c, right }: { v?: string | number | null; c?: string; right?: boolean }) {
  return <span className="mono" style={{ fontSize: 12, color: c || 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', textAlign: right ? 'right' : 'left' }}>{v ?? '—'}</span>;
}
export function CellTxt({ v, c }: { v?: string | null; c?: string }) {
  return <span style={{ fontSize: 12.5, color: c || 'var(--app-t2)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{v || '—'}</span>;
}

// ---- page scaffolding -----------------------------------------------------
export function PageWrap({ title, count, children }: { title?: string; count?: number | string; children: React.ReactNode }) {
  return (
    <div style={{ padding: '20px 26px 40px', height: '100%', overflowY: 'auto' }}>
      {title && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
          <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 16, color: 'var(--app-t1)' }}>{title}</h2>
          {count != null && <span className="mono" style={{ fontSize: 12, color: 'var(--app-t3)' }}>{count}</span>}
        </div>
      )}
      {children}
    </div>
  );
}

export function Note({ icon, tone, title, message, panel }: { icon: string; tone: string; title: string; message: string; panel?: boolean }) {
  const body = (
    <div style={{ padding: '56px 24px', textAlign: 'center', color: 'var(--app-t3)' }}>
      <Icon name={icon} size={26} style={{ color: tone, opacity: 0.8 }} />
      <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--app-t1)', marginTop: 12 }}>{title}</div>
      <div style={{ fontSize: 12.5, marginTop: 4 }}>{message}</div>
    </div>
  );
  return panel ? <div className="panel" style={{ borderRadius: 14 }}>{body}</div> : body;
}

// Standard query-state guard: returns the Note to render, or null when data is ready.
export function queryNote(q: { isLoading: boolean; isError: boolean; error: unknown }, empty: boolean, names: { thing: string; emptyTitle?: string; emptyMessage?: string }): React.ReactNode | null {
  if (q.isError) return <Note panel icon="alert-triangle" tone="var(--danger-text)" title={`Couldn't load ${names.thing}`} message={q.error instanceof Error ? q.error.message : 'Request failed'} />;
  if (q.isLoading) return <Note panel icon="loader" tone="var(--app-t3)" title={`Loading ${names.thing}…`} message=" " />;
  if (empty) return <Note panel icon="radar" tone="var(--app-t3)" title={names.emptyTitle || `No ${names.thing}`} message={names.emptyMessage || `No ${names.thing} for this tenant yet.`} />;
  return null;
}
