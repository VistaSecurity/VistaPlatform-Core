// VISTA Operations — Security ▸ Dashboard (index sub-page). The platform's
// security posture, read from the ACTIVITY TRAIL (audit.activity_logs via
// admin-service /admin/security/*), plus impersonation activity from auth-service.
//
// This page used to read public.security_events and public.compliance_framework_status.
// Neither table has a writer anywhere in the product, so half the page rendered
// "Total events 0 / Anomalies detected 0 / High-risk events 0" and an empty
// framework table on every deployment forever — behind an HTTP 200, which reads
// as "nothing happened" rather than "nothing is recorded". Both are repointed or
// gone:
//
//   - Events + stats now come from audit.activity_logs, which every service
//     writes to. The panels show what that table actually holds: counts, outcome
//     (succeeded / failed), category, and the producer's requires_attention flag.
//     There is no severity or anomaly breakdown, because nothing measures either.
//   - The compliance-framework panel is removed outright (no source). Tenant
//     framework scores are a different question and live in compliance-engine.
import { useState } from 'react';
import { ChartBar, AlertTriangle, ShieldAlert, KeyRound, UserCog, RefreshCw, Layers } from 'lucide-react';
import { StatTile, StatusTag, MiniBar, relTime } from '../../components/ui/primitives';
import { useSecurityStats, useSecurityEvents, useImpersonationAudit } from './queries';

const TIME_RANGES = [
  { id: '1h', label: 'Last hour' },
  { id: '24h', label: 'Last 24 hours' },
  { id: '7d', label: 'Last 7 days' },
  { id: '30d', label: 'Last 30 days' },
];

// Category colours are presentation only — the platform assigns no risk ranking
// to an event category, and this palette must not be read as one.
const CATEGORY_COLOR: Record<string, string> = {
  authentication: 'var(--info)',
  user: 'var(--ok-lime)',
  tenant: 'var(--warn)',
  config: 'var(--warn-strong)',
};

const OUTCOME_COLOR: Record<string, string> = { succeeded: 'var(--ok)', failed: 'var(--danger)' };

function Panel({ title, icon: Icon, right, children }: { title: string; icon?: typeof ChartBar; right?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="op-panel" style={{ overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '13px 16px', borderBottom: '1px solid var(--op-border)', fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>
        {Icon && <Icon size={16} style={{ color: 'var(--op-t3)' }} />}{title}
        <div style={{ flex: 1 }} />{right}
      </div>
      {children}
    </div>
  );
}

const actorOf = (email?: string | null, userType?: string) => email || userType || 'system';

export function SecurityDashboardPage() {
  const [range, setRange] = useState('24h');
  const statsQ = useSecurityStats(range);
  const eventsQ = useSecurityEvents(25);
  const impQ = useImpersonationAudit();

  const stats = statsQ.data ?? {};
  const byCategory = stats.events_by_category ?? {};
  const byOutcome = stats.events_by_outcome ?? {};
  const events = eventsQ.data ?? [];
  const imps = impQ.data ?? [];

  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 18 }}>
      {/* range selector */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span className="op-eyebrow">Time range</span>
        <select value={range} onChange={(e) => setRange(e.target.value)} style={{ height: 30, borderRadius: 'var(--r-btn)', border: '1px solid var(--op-border2)', background: 'var(--op-panel2)', color: 'var(--op-t1)', fontSize: 12.5, padding: '0 8px' }}>
          {TIME_RANGES.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
        </select>
        <button className="op-btn icon sm" title="Refresh" onClick={() => { statsQ.refetch(); eventsQ.refetch(); }}><RefreshCw size={14} /></button>
        {statsQ.isError && <span style={{ fontSize: 11.5, color: 'var(--warn)' }}>Security service unavailable — stats may be unavailable.</span>}
      </div>

      {/* stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12 }}>
        <StatTile label="Security events" value={statsQ.isLoading ? '…' : (stats.total_events ?? 0)} sub="in range" icon={ChartBar} />
        <StatTile label="Failed events" value={statsQ.isLoading ? '…' : (stats.failed_events ?? 0)} sub="did not succeed" icon={AlertTriangle} accent={(stats.failed_events ?? 0) > 0 ? 'var(--warn)' : undefined} />
        <StatTile label="Failed sign-ins" value={statsQ.isLoading ? '…' : (stats.failed_logins ?? 0)} sub="authentication" icon={KeyRound} accent={(stats.failed_logins ?? 0) > 0 ? 'var(--warn)' : undefined} />
        <StatTile label="Needs attention" value={statsQ.isLoading ? '…' : (stats.requires_attention ?? 0)} sub="flagged by producer" icon={ShieldAlert} accent={(stats.requires_attention ?? 0) > 0 ? 'var(--danger)' : undefined} />
      </div>

      {/* breakdowns */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <Panel title="Events by category" icon={Layers}>
          <div style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 10 }}>
            {statsQ.isLoading && <div style={{ color: 'var(--op-t3)', fontSize: 12.5 }}>Loading…</div>}
            {!statsQ.isLoading && Object.keys(byCategory).length === 0 && <div style={{ color: 'var(--op-t3)', fontSize: 12.5 }}>No events in this time range.</div>}
            {Object.entries(byCategory).map(([cat, n]) => (
              <div key={cat} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ width: 100, fontSize: 11.5, fontWeight: 600, color: CATEGORY_COLOR[cat] ?? 'var(--op-t2)', textTransform: 'uppercase' }}>{cat}</span>
                <div style={{ flex: 1 }}><MiniBar pct={stats.total_events ? (Number(n) / Number(stats.total_events)) * 100 : 0} color={CATEGORY_COLOR[cat] ?? 'var(--neutral)'} /></div>
                <span className="op-num" style={{ fontSize: 14, fontWeight: 700, color: 'var(--op-t1)', minWidth: 30, textAlign: 'right' }}>{Number(n)}</span>
              </div>
            ))}
          </div>
        </Panel>
        <Panel title="Events by outcome" icon={ShieldAlert}>
          <div style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 10 }}>
            {statsQ.isLoading && <div style={{ color: 'var(--op-t3)', fontSize: 12.5 }}>Loading…</div>}
            {!statsQ.isLoading && Object.keys(byOutcome).length === 0 && <div style={{ color: 'var(--op-t3)', fontSize: 12.5 }}>No events in this time range.</div>}
            {Object.entries(byOutcome).map(([outcome, n]) => (
              <div key={outcome} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ width: 100, fontSize: 11.5, fontWeight: 600, color: OUTCOME_COLOR[outcome] ?? 'var(--op-t2)', textTransform: 'uppercase' }}>{outcome}</span>
                <div style={{ flex: 1 }}><MiniBar pct={stats.total_events ? (Number(n) / Number(stats.total_events)) * 100 : 0} color={OUTCOME_COLOR[outcome] ?? 'var(--neutral)'} /></div>
                <span className="op-num" style={{ fontSize: 14, fontWeight: 700, color: 'var(--op-t1)', minWidth: 30, textAlign: 'right' }}>{Number(n)}</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      {/* recent security events */}
      <Panel title="Recent security events" icon={ShieldAlert}>
        <table className="op-table">
          <thead><tr><th>Action</th><th>Category</th><th>Actor</th><th>Outcome</th><th>Source IP</th><th>When</th></tr></thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id}>
                <td style={{ fontWeight: 500, color: 'var(--op-t1)', maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {e.action}
                  {e.requires_attention && <span title="Flagged as needing attention" style={{ marginLeft: 7, fontSize: 10.5, fontWeight: 700, color: 'var(--danger)' }}>ATTN</span>}
                  {e.description && <div className="t-muted" style={{ fontSize: 11, fontWeight: 400 }}>{e.description}</div>}
                </td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{e.category}</td>
                <td className="t-muted" style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{actorOf(e.user_email, e.user_type)}</td>
                <td><StatusTag status={e.success ? 'success' : 'failed'} /></td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{e.source_ip || '—'}</td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{relTime(e.timestamp)}</td>
              </tr>
            ))}
            {(eventsQ.isLoading || eventsQ.isError || events.length === 0) && (
              <tr><td colSpan={6} style={{ textAlign: 'center', padding: 36, color: 'var(--op-t3)' }}>{eventsQ.isLoading ? 'Loading…' : eventsQ.isError ? <>Couldn't load. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => eventsQ.refetch()}>Retry</button></> : 'No security events in range.'}</td></tr>
            )}
          </tbody>
        </table>
      </Panel>

      {/* impersonation activity */}
      <Panel title="Impersonation activity" icon={UserCog}>
        <table className="op-table">
          <thead><tr><th>Event</th><th>Status</th><th>IP address</th><th>User agent</th><th>When</th></tr></thead>
          <tbody>
            {imps.map((e, i) => (
              <tr key={`${e.occurred_at}-${i}`}>
                <td style={{ fontWeight: 500, color: 'var(--op-t1)' }}>{e.event_type}</td>
                <td><StatusTag status={e.event_status === 'success' ? 'success' : e.event_status === 'failed' ? 'failed' : e.event_status} /></td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{e.ip_address || '—'}</td>
                <td className="t-muted" style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 11 }}>{e.user_agent || '—'}</td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{relTime(e.occurred_at)}</td>
              </tr>
            ))}
            {(impQ.isLoading || impQ.isError || imps.length === 0) && (
              <tr><td colSpan={5} style={{ textAlign: 'center', padding: 36, color: 'var(--op-t3)' }}>{impQ.isLoading ? 'Loading…' : impQ.isError ? <>Couldn't load. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => impQ.refetch()}>Retry</button></> : 'No impersonation activity recorded.'}</td></tr>
            )}
          </tbody>
        </table>
      </Panel>

      <div style={{ fontSize: 11.5, color: 'var(--op-t3)' }}>
        Security events are the authentication, user, tenant and configuration slice of the platform activity trail, plus every failed action and anything a service flagged for attention. The full unfiltered trail — with search, filters and export — is under <strong>Activity Log</strong>.
      </div>
    </div>
  );
}
