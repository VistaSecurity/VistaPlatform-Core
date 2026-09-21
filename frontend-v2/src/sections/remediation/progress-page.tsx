// Remediation → Progress.
//
// GET /tickets/progress had ZERO consumers before. A fully-built
// endpoint — opened and resolved per day, average resolution time, a
// per-category breakdown — that nothing in either UI called. The original
// design doc specified a progress view in this section and it never landed
// during the v1→v2 cutover, so the endpoint shipped and sat.
//
// Two questions, deliberately on one page:
//   "are we keeping up?"  — the ticket trend and the average resolution time
//   "what is left?"       — the per-category backlog, and the PQC migration
//                           picture, which is the one piece of remediation
//                           work measured in years rather than days.
//
// The per-category breakdown is what the category split (one per finding
// producer) makes legible: before it, four producers shared one bar.
import { useState } from 'react';
import { useNavigate } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { ticketCategory } from '@vistasecurity/primitives/tickets';
import { clients } from '../../lib/clients';
import { Icon, MiniBar, PercentageGauge } from '../../components/ui';

const WINDOWS = [7, 30, 90] as const;

export function ProgressPage() {
  const go = useNavigate();
  const [days, setDays] = useState<number>(30);

  const progressQ = useQuery({
    queryKey: ['remediation', 'progress', days],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/tickets/progress', {
        params: { query: { days } },
      });
      if (error || !data) throw new Error('Failed to load remediation progress');
      return data.progress;
    },
  });

  const pqcQ = useQuery({
    queryKey: ['remediation', 'pqc-progress'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/pqc/progress', {});
      if (error || !data) throw new Error('Failed to load PQC progress');
      return data.progress;
    },
  });

  const p = progressQ.data;
  const trend = p?.trend ?? [];
  const opened = trend.reduce((n, d) => n + d.opened, 0);
  const resolved = trend.reduce((n, d) => n + d.resolved, 0);
  // Resolved-per-opened over the window. Above 1 means the backlog is
  // shrinking; below means it is growing. Undefined when nothing was opened,
  // rather than Infinity — "we resolved 4 and opened 0" is not a ratio.
  const ratio = opened > 0 ? resolved / opened : null;
  const peak = Math.max(1, ...trend.map((d) => Math.max(d.opened, d.resolved)));

  return (
    <div style={{ padding: '20px 26px 40px', height: '100%', overflow: 'auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 16, color: 'var(--app-t1)' }}>Progress</h2>
        <div style={{ flex: 1 }} />
        {WINDOWS.map((w) => (
          <button
            key={w}
            className="ui-btn sm"
            onClick={() => setDays(w)}
            style={{ height: 28, fontSize: 12, borderColor: days === w ? 'var(--accent)' : undefined, color: days === w ? 'var(--accent)' : undefined }}
          >
            {w}d
          </button>
        ))}
      </div>

      {progressQ.isError ? (
        <Note icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load progress" message={progressQ.error instanceof Error ? progressQ.error.message : 'Request failed'} />
      ) : progressQ.isLoading ? (
        <Note icon="loader" tone="var(--app-t3)" title="Loading progress…" message="Fetching remediation throughput." />
      ) : (
        <>
          <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', marginBottom: 18 }}>
            <Stat label="Opened" value={String(opened)} sub={`in the last ${days} days`} />
            <Stat label="Resolved" value={String(resolved)} sub={`in the last ${days} days`} color="var(--ok)" />
            <Stat
              label="Keeping up"
              value={ratio == null ? '—' : `${ratio.toFixed(2)}×`}
              sub={ratio == null ? 'nothing opened' : ratio >= 1 ? 'backlog shrinking' : 'backlog growing'}
              color={ratio == null ? undefined : ratio >= 1 ? 'var(--ok)' : 'var(--warn-strong)'}
            />
            <Stat
              label="Avg resolution"
              value={p?.avg_resolution_hours ? formatHours(p.avg_resolution_hours) : '—'}
              sub={p?.avg_resolution_hours ? 'open to resolved' : 'nothing resolved yet'}
            />
          </div>

          <Panel title="Opened vs resolved" icon="activity">
            {trend.length === 0 ? (
              <Blank>No ticket activity in this window.</Blank>
            ) : (
              <div style={{ display: 'flex', alignItems: 'flex-end', gap: 3, height: 130, padding: '8px 0 0' }}>
                {trend.map((d) => (
                  <div key={d.date} title={`${d.date} · ${d.opened} opened, ${d.resolved} resolved`} style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', justifyContent: 'flex-end', gap: 2 }}>
                    <div style={{ height: `${(d.opened / peak) * 55}%`, background: 'var(--warn-strong)', borderRadius: '3px 3px 0 0', opacity: 0.85 }} />
                    <div style={{ height: `${(d.resolved / peak) * 55}%`, background: 'var(--ok)', borderRadius: '0 0 3px 3px', opacity: 0.85 }} />
                  </div>
                ))}
              </div>
            )}
            <div style={{ display: 'flex', gap: 16, marginTop: 10, fontSize: 11.5, color: 'var(--app-t3)' }}>
              <Key color="var(--warn-strong)">opened</Key>
              <Key color="var(--ok)">resolved</Key>
            </div>
          </Panel>

          <Panel title="Where the work is" icon="list-checks">
            <CategoryBreakdown byCategory={p?.by_category} onPick={(c) => { void go(`/remediation/queue?category=${c}`); }} />
          </Panel>
        </>
      )}

      <Panel title="Quantum readiness" icon="layers">
        {pqcQ.isError ? (
          <Blank>Couldn't load PQC progress.</Blank>
        ) : pqcQ.isLoading ? (
          <Blank>Loading…</Blank>
        ) : !pqcQ.data || pqcQ.data.total_implementations === 0 ? (
          <Blank>No cryptographic configurations discovered yet.</Blank>
        ) : (
          <div style={{ display: 'flex', gap: 24, alignItems: 'center', flexWrap: 'wrap' }}>
            <PercentageGauge value={pqcQ.data.pqc_percentage} label="quantum safe" />
            <div style={{ flex: 1, minWidth: 220, display: 'flex', flexDirection: 'column', gap: 9 }}>
              <PqcRow label="PQC-ready" n={pqcQ.data.pqc_ready} total={pqcQ.data.total_implementations} color="var(--ok)" />
              <PqcRow label="Symmetric — no migration needed" n={pqcQ.data.symmetric_safe} total={pqcQ.data.total_implementations} color="var(--info)" />
              <PqcRow label="Needs migration" n={pqcQ.data.non_pqc} total={pqcQ.data.total_implementations} color="var(--danger)" />
              {/* Unclassified counts AGAINST readiness rather than being
                  assumed safe, so it is shown rather than folded away. */}
              <PqcRow label="Unclassified" n={pqcQ.data.unclassified} total={pqcQ.data.total_implementations} color="var(--neutral)" />
            </div>
          </div>
        )}
      </Panel>
    </div>
  );
}

/** Per-category open vs resolved, as a backlog worklist. */
export function CategoryBreakdown({
  byCategory,
  onPick,
}: {
  byCategory?: { [k: string]: { [s: string]: number } } | null;
  onPick?: (category: string) => void;
}) {
  const rows = Object.entries(byCategory ?? {})
    .map(([key, statuses]) => {
      const open = (statuses.open ?? 0) + (statuses.in_progress ?? 0);
      const done = (statuses.resolved ?? 0) + (statuses.closed ?? 0);
      return { key, open, done, total: open + done };
    })
    .filter((r) => r.total > 0)
    .sort((a, b) => b.open - a.open || b.total - a.total);

  if (rows.length === 0) return <Blank>No tickets in this window.</Blank>;
  const widest = Math.max(...rows.map((r) => r.total));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {rows.map((r) => {
        const cat = ticketCategory(r.key);
        return (
          <button
            key={r.key}
            onClick={() => onPick?.(r.key)}
            style={{ display: 'grid', gridTemplateColumns: '170px 1fr 74px', gap: 12, alignItems: 'center', background: 'none', border: 'none', padding: 0, cursor: onPick ? 'pointer' : 'default', textAlign: 'left' }}
          >
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 7, fontSize: 12.5, color: 'var(--app-t2)', minWidth: 0 }}>
              <Icon name={cat?.icon ?? 'wrench'} size={13} style={{ color: 'var(--app-t3)', flex: 'none' }} />
              <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{cat?.label ?? r.key}</span>
            </span>
            <MiniBar pct={Math.round((r.total / widest) * 100)} color={r.open ? 'var(--warn-strong)' : 'var(--ok)'} h={7} />
            <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)', textAlign: 'right' }}>
              {r.open} open
            </span>
          </button>
        );
      })}
    </div>
  );
}

/** Hours as the coarsest unit that stays readable. */
export function formatHours(hours: number): string {
  if (hours < 1) return `${Math.round(hours * 60)}m`;
  if (hours < 48) return `${hours.toFixed(1)}h`;
  return `${(hours / 24).toFixed(1)}d`;
}

function PqcRow({ label, n, total, color }: { label: string; n: number; total: number; color: string }) {
  const pct = total ? Math.round((n / total) * 100) : 0;
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 80px 52px', gap: 10, alignItems: 'center' }}>
      <span style={{ fontSize: 12.5, color: 'var(--app-t2)' }}>{label}</span>
      <MiniBar pct={pct} color={color} h={7} />
      <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)', textAlign: 'right' }}>{n}</span>
    </div>
  );
}

function Stat({ label, value, sub, color }: { label: string; value: string; sub: string; color?: string }) {
  return (
    <div className="panel" style={{ padding: '13px 16px', flex: 1, minWidth: 130 }}>
      <div className="eyebrow-app">{label}</div>
      <div className="mono" style={{ fontSize: 24, fontWeight: 700, color: color ?? 'var(--app-t1)', marginTop: 6 }}>{value}</div>
      <div style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 2 }}>{sub}</div>
    </div>
  );
}

function Panel({ title, icon, children }: { title: string; icon: string; children: React.ReactNode }) {
  return (
    <div className="panel" style={{ padding: 18, marginBottom: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 12 }}>
        <Icon name={icon} size={14} style={{ color: 'var(--app-t3)' }} />
        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--app-t1)' }}>{title}</span>
      </div>
      {children}
    </div>
  );
}

function Key({ color, children }: { color: string; children: React.ReactNode }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
      <span style={{ width: 8, height: 8, borderRadius: 2, background: color }} />{children}
    </span>
  );
}

function Blank({ children }: { children: React.ReactNode }) {
  return <div style={{ fontSize: 12.5, color: 'var(--app-t3)', padding: '18px 0' }}>{children}</div>;
}

function Note({ icon, tone, title, message }: { icon: string; tone: string; title: string; message: string }) {
  return (
    <div className="panel" style={{ padding: '56px 24px', textAlign: 'center', color: 'var(--app-t3)' }}>
      <Icon name={icon} size={26} style={{ color: tone, opacity: 0.8 }} />
      <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--app-t1)', marginTop: 12 }}>{title}</div>
      <div style={{ fontSize: 12.5, marginTop: 4 }}>{message}</div>
    </div>
  );
}
