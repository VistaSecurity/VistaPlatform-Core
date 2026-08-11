// VISTA Operations — Security ▸ Dashboard (index sub-page). Platform security posture:
// event stat cards, by-severity / by-status breakdowns, compliance framework status,
// recent security events, and impersonation activity. Wired to admin-service
// (/admin/security/*) + auth-service (/admin/impersonations/audit) via typed clients.
// Ported from _legacy/admin-ui security-dashboard-page.tsx into the v2 op-* design.
import { useState } from 'react';
import { ChartBar, AlertTriangle, ShieldAlert, Clock, ShieldCheck, UserCog, RefreshCw } from 'lucide-react';
import { StatTile, StatusTag, MiniBar, relTime } from '../../components/ui/primitives';
import {
  useSecurityStats, useSecurityEvents, useComplianceFrameworks, useImpersonationAudit,
} from './queries';

const TIME_RANGES = [
  { id: '1h', label: 'Last hour' },
  { id: '24h', label: 'Last 24 hours' },
  { id: '7d', label: 'Last 7 days' },
  { id: '30d', label: 'Last 30 days' },
];

const SEV_COLOR: Record<string, string> = { critical: 'var(--danger)', high: 'var(--warn-strong)', medium: 'var(--warn)', low: 'var(--info)' };

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

function complianceColor(score: number): string {
  if (score >= 90) return 'var(--ok)';
  if (score >= 70) return 'var(--ok-lime)';
  if (score >= 50) return 'var(--warn)';
  return 'var(--danger)';
}

export function SecurityDashboardPage() {
  const [range, setRange] = useState('24h');
  const statsQ = useSecurityStats(range);
  const eventsQ = useSecurityEvents(25);
  const complianceQ = useComplianceFrameworks();
  const impQ = useImpersonationAudit();

  const stats = statsQ.data ?? {};
  const bySeverity = stats.events_by_severity ?? {};
  const byStatus = stats.events_by_status ?? {};
  const events = eventsQ.data ?? [];
  const frameworks = complianceQ.data ?? [];
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
        <StatTile label="Total events" value={statsQ.isLoading ? '…' : (stats.total_events ?? 0)} sub="in range" icon={ChartBar} />
        <StatTile label="Anomalies detected" value={statsQ.isLoading ? '…' : (stats.anomalies_detected ?? 0)} sub="flagged" icon={AlertTriangle} accent={(stats.anomalies_detected ?? 0) > 0 ? 'var(--warn)' : undefined} />
        <StatTile label="High-risk events" value={statsQ.isLoading ? '…' : (stats.high_risk_events ?? 0)} sub="elevated risk" icon={ShieldAlert} accent={(stats.high_risk_events ?? 0) > 0 ? 'var(--danger)' : undefined} />
        <StatTile label="Open events" value={statsQ.isLoading ? '…' : (byStatus.open ?? 0)} sub="unresolved" icon={Clock} accent={(byStatus.open ?? 0) > 0 ? 'var(--warn)' : undefined} />
      </div>

      {/* breakdowns */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <Panel title="Events by severity" icon={ShieldAlert}>
          <div style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 10 }}>
            {statsQ.isLoading && <div style={{ color: 'var(--op-t3)', fontSize: 12.5 }}>Loading…</div>}
            {!statsQ.isLoading && Object.keys(bySeverity).length === 0 && <div style={{ color: 'var(--op-t3)', fontSize: 12.5 }}>No events in this time range.</div>}
            {Object.entries(bySeverity).map(([sev, n]) => (
              <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ width: 70, fontSize: 11.5, fontWeight: 600, color: SEV_COLOR[sev.toLowerCase()] ?? 'var(--op-t2)', textTransform: 'uppercase' }}>{sev}</span>
                <div style={{ flex: 1 }}><MiniBar pct={stats.total_events ? (Number(n) / Number(stats.total_events)) * 100 : 0} color={SEV_COLOR[sev.toLowerCase()] ?? 'var(--neutral)'} /></div>
                <span className="op-num" style={{ fontSize: 14, fontWeight: 700, color: 'var(--op-t1)', minWidth: 30, textAlign: 'right' }}>{Number(n)}</span>
              </div>
            ))}
          </div>
        </Panel>
        <Panel title="Events by status" icon={Clock}>
          <div style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 10 }}>
            {statsQ.isLoading && <div style={{ color: 'var(--op-t3)', fontSize: 12.5 }}>Loading…</div>}
            {!statsQ.isLoading && Object.keys(byStatus).length === 0 && <div style={{ color: 'var(--op-t3)', fontSize: 12.5 }}>No events in this time range.</div>}
            {Object.entries(byStatus).map(([st, n]) => (
              <div key={st} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10 }}>
                <StatusTag status={st === 'open' ? 'open' : st === 'resolved' ? 'success' : st === 'investigating' ? 'investigating' : 'unknown'} />
                <span className="op-num" style={{ fontSize: 14, fontWeight: 700, color: 'var(--op-t1)' }}>{Number(n)}</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      {/* compliance frameworks */}
      <Panel title="Compliance frameworks" icon={ShieldCheck}>
        <table className="op-table">
          <thead><tr><th>Framework</th><th>Status</th><th className="num">Score</th><th className="num">Compliant</th><th>Last assessed</th></tr></thead>
          <tbody>
            {frameworks.map((f) => (
              <tr key={f.id}>
                <td style={{ fontWeight: 500, color: 'var(--op-t1)' }}>{f.framework_name}{f.framework_version ? <span className="t-muted" style={{ fontWeight: 400 }}> {f.framework_version}</span> : null}</td>
                <td><StatusTag status={f.overall_status === 'compliant' ? 'success' : f.overall_status === 'non_compliant' ? 'failed' : 'pending'} /></td>
                <td className="num" style={{ color: complianceColor(f.compliance_score), fontWeight: 700 }}>{Math.round(f.compliance_score)}%</td>
                <td className="num t-muted">{f.compliant_requirements}/{f.total_requirements}</td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{relTime(f.last_assessed_at)}</td>
              </tr>
            ))}
            {(complianceQ.isLoading || complianceQ.isError || frameworks.length === 0) && (
              <tr><td colSpan={5} style={{ textAlign: 'center', padding: 36, color: 'var(--op-t3)' }}>{complianceQ.isLoading ? 'Loading…' : complianceQ.isError ? <>Couldn't load. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => complianceQ.refetch()}>Retry</button></> : 'No compliance frameworks assessed.'}</td></tr>
            )}
          </tbody>
        </table>
      </Panel>

      {/* recent security events */}
      <Panel title="Recent security events" icon={ShieldAlert}>
        <table className="op-table">
          <thead><tr><th>Event</th><th>Type</th><th>Severity</th><th>Service</th><th>Status</th><th>When</th></tr></thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id}>
                <td style={{ fontWeight: 500, color: 'var(--op-t1)', maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.title}</td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{e.event_type}</td>
                <td><StatusTag status={(e.severity || 'unknown').toLowerCase()} /></td>
                <td className="t-muted">{e.service_name}</td>
                <td><StatusTag status={e.status === 'open' ? 'open' : e.status === 'resolved' ? 'success' : e.status} /></td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{relTime(e.timestamp || e.detected_at)}</td>
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
    </div>
  );
}
