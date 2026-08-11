// VISTA Operations — Support ▸ Tenant Health. A read-only, sortable cross-tenant
// health board (GET /tenants). Clicking a row opens a drawer-modal that fetches
// that tenant's full record (/tenants/{id}) + active alerts (/tenants/{id}/alerts)
// on open and renders the score breakdown, alerts, and recommendations. All calls
// go through the typed clients.tenantHealth.
import { useMemo, useState } from 'react';
import { Activity, ChevronUp, ChevronDown, AlertTriangle, Lightbulb } from 'lucide-react';
import { MiniBar, StatusTag, Tag, healthColor, relTime } from '../../components/ui/primitives';
import { Modal } from '../../components/ui/modal';
import {
  useTenantHealthList,
  useTenantHealthDetail,
  useTenantHealthAlerts,
  type TenantHealthSummary,
} from './support-queries';

type SortKey = 'tenant' | 'score' | 'status' | 'alerts';
type SortDir = 'asc' | 'desc';

// health_status → the design StatusTag key (StatusTag falls back to the raw key,
// so map the health vocabulary onto known operational signals where it helps).
const STATUS_KEY: Record<string, string> = {
  excellent: 'healthy', good: 'active', fair: 'degraded', poor: 'past_due', critical: 'failed',
};
const statusKey = (s: string) => STATUS_KEY[s] ?? s;

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'var(--danger)', high: 'var(--warn-strong)', medium: 'var(--warn)', low: 'var(--neutral)',
};
const sevColor = (s: string) => SEVERITY_COLOR[s] ?? 'var(--neutral)';

/* ------------------------------- breakdown ------------------------------- */

const BREAKDOWN_LABELS: { key: keyof import('./support-queries').HealthBreakdown; label: string }[] = [
  { key: 'resource_efficiency', label: 'Resource efficiency' },
  { key: 'performance_metrics', label: 'Performance' },
  { key: 'security_posture', label: 'Security posture' },
  { key: 'business_activity', label: 'Business activity' },
  { key: 'cost_optimization', label: 'Cost optimization' },
];

function TenantHealthDrawer({ summary, onClose }: { summary: TenantHealthSummary; onClose: () => void }) {
  const id = summary.tenant_id;
  const detailQ = useTenantHealthDetail(id);
  const alertsQ = useTenantHealthAlerts(id);
  const detail = detailQ.data;
  const alerts = alertsQ.data ?? [];
  const recommendations = detail?.recommendations ?? [];

  return (
    <Modal
      open
      onClose={onClose}
      title={summary.tenant_name || summary.tenant_id}
      description={`Tenant ${summary.tenant_id}`}
      size="lg"
      secondaryLabel="Close"
    >
      {/* score header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 30, color: healthColor(summary.overall_score), lineHeight: 1 }}>
          {Math.round(summary.overall_score)}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <StatusTag status={statusKey(summary.health_status)} />
          <span className="t-muted" style={{ fontSize: 11.5 }}>Last calculated {relTime(detail?.last_calculated ?? summary.last_calculated)}</span>
        </div>
      </div>

      {/* score breakdown */}
      <div>
        <div className="op-eyebrow" style={{ marginBottom: 8 }}>Score breakdown</div>
        {detailQ.isLoading && <div style={{ fontSize: 12, color: 'var(--op-t3)' }}>Loading breakdown…</div>}
        {detailQ.isError && !detailQ.isLoading && <div style={{ fontSize: 12, color: 'var(--op-t3)' }}>Breakdown unavailable.</div>}
        {detail && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {BREAKDOWN_LABELS.map(({ key, label }) => {
              const v = detail.score_breakdown[key] ?? 0;
              return (
                <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span style={{ fontSize: 12, color: 'var(--op-t2)', width: 150, flex: 'none' }}>{label}</span>
                  <MiniBar pct={v} color={healthColor(v)} />
                  <span className="mono" style={{ fontSize: 11.5, color: 'var(--op-t1)', width: 32, textAlign: 'right', flex: 'none' }}>{Math.round(v)}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* active alerts */}
      <div>
        <div className="op-eyebrow" style={{ marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
          <AlertTriangle size={12} />Active alerts
        </div>
        {alertsQ.isLoading && <div style={{ fontSize: 12, color: 'var(--op-t3)' }}>Loading alerts…</div>}
        {!alertsQ.isLoading && alerts.length === 0 && <div style={{ fontSize: 12, color: 'var(--op-t3)' }}>No active alerts.</div>}
        {alerts.length > 0 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {alerts.map((a) => (
              <div key={a.id} style={{ padding: '10px 12px', borderRadius: 'var(--r-sm)', border: '1px solid var(--op-border)', background: 'var(--op-panel2)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <Tag color={sevColor(a.severity)} style={{ textTransform: 'capitalize' }}>{a.severity}</Tag>
                  <span style={{ fontWeight: 600, fontSize: 12.5, color: 'var(--op-t1)' }}>{a.title}</span>
                  <span className="t-muted" style={{ fontSize: 11, marginLeft: 'auto', textTransform: 'capitalize' }}>{a.category}</span>
                </div>
                <div style={{ fontSize: 12, color: 'var(--op-t2)' }}>{a.description}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* recommendations */}
      <div>
        <div className="op-eyebrow" style={{ marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
          <Lightbulb size={12} />Recommendations
        </div>
        {recommendations.length === 0 && <div style={{ fontSize: 12, color: 'var(--op-t3)' }}>No recommendations.</div>}
        {recommendations.length > 0 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {recommendations.map((r) => (
              <div key={r.id} style={{ padding: '10px 12px', borderRadius: 'var(--r-sm)', border: '1px solid var(--op-border)', background: 'var(--op-panel2)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <Tag color="var(--info)" style={{ textTransform: 'capitalize' }}>{r.priority}</Tag>
                  <span style={{ fontWeight: 600, fontSize: 12.5, color: 'var(--op-t1)' }}>{r.title}</span>
                  {r.potential_gain > 0 && <span className="t-muted" style={{ fontSize: 11, marginLeft: 'auto' }}>+{Math.round(r.potential_gain)} pts</span>}
                </div>
                <div style={{ fontSize: 12, color: 'var(--op-t2)' }}>{r.description}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </Modal>
  );
}

/* --------------------------------- page ---------------------------------- */

function SortHeader({ label, k, sort, dir, onSort, align }: { label: string; k: SortKey; sort: SortKey; dir: SortDir; onSort: (k: SortKey) => void; align?: 'right' }) {
  const active = sort === k;
  return (
    <th onClick={() => onSort(k)} style={{ cursor: 'pointer', userSelect: 'none', textAlign: align }}>
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, justifyContent: align === 'right' ? 'flex-end' : 'flex-start' }}>
        {label}
        {active && (dir === 'asc' ? <ChevronUp size={12} /> : <ChevronDown size={12} />)}
      </span>
    </th>
  );
}

export function TenantHealthPage() {
  const { data, isLoading, isError, refetch } = useTenantHealthList();
  const rows = useMemo(() => data ?? [], [data]);
  const [sort, setSort] = useState<SortKey>('score');
  const [dir, setDir] = useState<SortDir>('asc');
  const [selected, setSelected] = useState<TenantHealthSummary | null>(null);

  const onSort = (k: SortKey) => {
    if (k === sort) setDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else { setSort(k); setDir(k === 'tenant' ? 'asc' : 'desc'); }
  };

  const sorted = useMemo(() => {
    const cmp = (a: TenantHealthSummary, b: TenantHealthSummary): number => {
      switch (sort) {
        case 'tenant': return (a.tenant_name || a.tenant_id).localeCompare(b.tenant_name || b.tenant_id);
        case 'score': return a.overall_score - b.overall_score;
        case 'status': return a.health_status.localeCompare(b.health_status);
        case 'alerts': return a.critical_alerts - b.critical_alerts;
        default: return 0;
      }
    };
    const out = [...rows].sort(cmp);
    return dir === 'asc' ? out : out.reverse();
  }, [rows, sort, dir]);

  return (
    <div className="op-fade" style={{ height: '100%', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
      <div style={{ flex: 1, minHeight: 0, overflowY: 'auto' }}>
        <table className="op-table">
          <thead>
            <tr>
              <SortHeader label="Tenant" k="tenant" sort={sort} dir={dir} onSort={onSort} />
              <SortHeader label="Score" k="score" sort={sort} dir={dir} onSort={onSort} align="right" />
              <SortHeader label="Status" k="status" sort={sort} dir={dir} onSort={onSort} />
              <SortHeader label="Active alerts" k="alerts" sort={sort} dir={dir} onSort={onSort} align="right" />
              <th>Trend</th>
              <th>Last calculated</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((t) => (
              <tr key={t.tenant_id} onClick={() => setSelected(t)} style={{ cursor: 'pointer' }}>
                <td style={{ fontWeight: 500, color: 'var(--op-t1)' }}>
                  {t.tenant_name || <span className="mono" style={{ fontSize: 11 }}>{t.tenant_id.slice(0, 8)}</span>}
                </td>
                <td style={{ textAlign: 'right' }}>
                  <span className="mono" style={{ fontWeight: 700, color: healthColor(t.overall_score) }}>{Math.round(t.overall_score)}</span>
                </td>
                <td><StatusTag status={statusKey(t.health_status)} /></td>
                <td style={{ textAlign: 'right' }}>
                  {t.critical_alerts > 0
                    ? <Tag color="var(--danger)">{t.critical_alerts}</Tag>
                    : <span className="t-muted">0</span>}
                </td>
                <td className="t-muted" style={{ fontSize: 12, textTransform: 'capitalize' }}>{t.trend_direction || '—'}</td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{relTime(t.last_calculated)}</td>
              </tr>
            ))}
            {isLoading && <tr><td colSpan={6} style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>Loading tenant health…</td></tr>}
            {isError && !isLoading && <tr><td colSpan={6} style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>Couldn't load tenant health. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => refetch()}>Retry</button></td></tr>}
            {!isLoading && !isError && sorted.length === 0 && <tr><td colSpan={6} style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>No tenant health records yet.</td></tr>}
          </tbody>
        </table>
      </div>

      <div style={{ flex: 'none', padding: '9px 24px', borderTop: '1px solid var(--op-border)', display: 'flex', alignItems: 'center', gap: 14, fontSize: 12, color: 'var(--op-t3)' }}>
        <Activity size={13} />
        <span>{sorted.length} tenants</span>
        <span>·</span>
        <span>Click a tenant to inspect its score breakdown, active alerts, and recommendations.</span>
      </div>

      {selected && <TenantHealthDrawer summary={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
