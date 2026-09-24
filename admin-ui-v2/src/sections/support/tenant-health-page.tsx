// VISTA Operations — Support ▸ Tenant Health. A read-only, sortable cross-tenant
// health board (GET /tenants). Clicking a row opens a drawer-modal that fetches
// that tenant's full record (/tenants/{id}) + active alerts (/tenants/{id}/alerts)
// on open and renders the score breakdown, alerts, and recommendations. All calls
// go through the typed clients.tenantHealth.
import { useMemo, useState } from 'react';
import { Activity, ChevronUp, ChevronDown, AlertTriangle, Lightbulb } from 'lucide-react';
import { MiniBar, Tag, healthColor, healthIndexPresentation, relTime } from '../../components/ui/primitives';
import { Modal } from '../../components/ui/modal';
import {
  useTenantHealthList,
  useTenantHealthDetail,
  useTenantHealthAlerts,
  type TenantHealthSummary,
} from './support-queries';

type SortKey = 'tenant' | 'score' | 'status' | 'alerts';
type SortDir = 'asc' | 'desc';

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'var(--danger)', high: 'var(--warn-strong)', medium: 'var(--warn)', low: 'var(--neutral)',
};
const sevColor = (s: string) => SEVERITY_COLOR[s] ?? 'var(--neutral)';

/* ------------------------------- breakdown ------------------------------- */

type FactorKey = 'resource_efficiency' | 'performance_metrics' | 'security_posture' | 'business_activity' | 'cost_optimization';

const BREAKDOWN_LABELS: { key: FactorKey; label: string }[] = [
  { key: 'resource_efficiency', label: 'Resource efficiency' },
  { key: 'performance_metrics', label: 'Performance' },
  { key: 'security_posture', label: 'Security posture' },
  { key: 'business_activity', label: 'Business activity' },
  { key: 'cost_optimization', label: 'Cost optimization' },
];

// A factor is null when the peer service supplying it was unreachable. That is
// NOT a zero — rendering it as an empty bar would restate the very bug this
// replaced (an unreachable peer showing as a plausible number). Show the gap.
const UNAVAILABLE = 'Unavailable';

// `resource-metering` in unavailable_sources is not a service that failed: it
// is the per-tenant CPU/memory producer that does not exist. Resource
// efficiency is therefore never measured and carries no weight in the index
// (owner decision 8, RC-14) — say "not measured", not "unreachable".
const RESOURCE_METERING_SOURCE = 'resource-metering';
const NOT_MEASURED = 'Not measured';

export function TenantHealthDrawer({ summary, onClose }: { summary: TenantHealthSummary; onClose: () => void }) {
  const id = summary.tenant_id;
  const detailQ = useTenantHealthDetail(id);
  const alertsQ = useTenantHealthAlerts(id);
  const detail = detailQ.data;
  const alerts = alertsQ.data ?? [];
  const recommendations = detail?.recommendations ?? [];
  // health_status 'unknown' means NOTHING could be measured — overall_score is
  // 0 for want of data, not because the tenant is unwell. Never render it as a
  // score.
  const unmeasured = summary.health_status === 'unknown';
  const healthIndex = healthIndexPresentation(summary.overall_score, !unmeasured);
  const reported = detail?.score_breakdown.unavailable_sources ?? [];
  // Real peers that failed this calculation — distinct from the factor no
  // producer measures at all.
  const unavailableSources = reported.filter((s) => s !== RESOURCE_METERING_SOURCE);
  const notMeasured = (key: FactorKey) =>
    key === 'resource_efficiency' && reported.includes(RESOURCE_METERING_SOURCE);

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
        <div data-testid="tenant-health-index" style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 30, color: healthIndex?.color ?? 'var(--op-t3)', lineHeight: 1 }}>
          {healthIndex ? `${healthIndex.score}/100` : '—'}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {healthIndex ? <Tag color={healthIndex.color}>{healthIndex.label}</Tag> : <Tag color="var(--neutral)">Unknown</Tag>}
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
              const v = detail.score_breakdown[key];
              const measured = typeof v === 'number';
              return (
                <div key={key} data-testid={`factor-${key}`} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span style={{ fontSize: 12, color: 'var(--op-t2)', width: 150, flex: 'none' }}>{label}</span>
                  {measured
                    ? <MiniBar pct={v} color={healthColor(v)} />
                    : <span style={{ flex: 1, fontSize: 11.5, color: 'var(--op-t3)', fontStyle: 'italic' }}>{notMeasured(key) ? NOT_MEASURED : UNAVAILABLE}</span>}
                  <span className="mono" style={{ fontSize: 11.5, color: measured ? 'var(--op-t1)' : 'var(--op-t3)', width: 32, textAlign: 'right', flex: 'none' }}>
                    {measured ? `${Math.round(v)}/100` : '—'}
                  </span>
                </div>
              );
            })}
            {reported.includes(RESOURCE_METERING_SOURCE) && (
              <div className="t-muted" style={{ fontSize: 11.5, marginTop: 2 }}>
                Resource efficiency is not measured: nothing meters per-tenant CPU and memory, so it is
                left out of the health index rather than estimated.
              </div>
            )}
            {unavailableSources.length > 0 && (
              <div style={{ fontSize: 11.5, color: 'var(--warn)', marginTop: 2 }}>
                {unmeasured
                  ? 'No health factor could be measured — these services were unreachable: '
                  : 'Some factors could not be measured — these services were unreachable: '}
                <span className="mono">{unavailableSources.join(', ')}</span>
                {!unmeasured && ` (score reflects ${Math.round((detail.score_breakdown.data_completeness ?? 0) * 100)}% of the factor weight).`}
              </div>
            )}
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
        case 'alerts': return a.active_alerts - b.active_alerts || a.critical_alerts - b.critical_alerts;
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
              <SortHeader label="Health index" k="score" sort={sort} dir={dir} onSort={onSort} align="right" />
              <SortHeader label="Band" k="status" sort={sort} dir={dir} onSort={onSort} />
              <SortHeader label="Active alerts" k="alerts" sort={sort} dir={dir} onSort={onSort} align="right" />
              <th>Trend</th>
              <th>Last calculated</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((t) => {
              const index = healthIndexPresentation(t.overall_score, t.health_status !== 'unknown');
              return (
              <tr key={t.tenant_id} onClick={() => setSelected(t)} style={{ cursor: 'pointer' }}>
                <td style={{ fontWeight: 500, color: 'var(--op-t1)' }}>
                  {t.tenant_name || <span className="mono" style={{ fontSize: 11 }}>{t.tenant_id.slice(0, 8)}</span>}
                </td>
                <td style={{ textAlign: 'right' }}>
                  {/* 'unknown' = no factor could be measured. Showing 0 would
                      read as "critically unhealthy" for a tenant we simply
                      failed to poll. */}
                  {!index
                    ? <span className="mono t-muted" title="No health factor could be measured">—</span>
                    : <span className="mono" style={{ fontWeight: 700, color: index.color }}>{index.score}/100</span>}
                </td>
                <td>{index ? <Tag color={index.color}>{index.label}</Tag> : <Tag color="var(--neutral)">Unknown</Tag>}</td>
                <td style={{ textAlign: 'right' }} data-testid="active-alerts">
                  {/* Every active alert — this column used to count only the
                      critical ones, so an open high-severity alert showed 0. */}
                  {t.active_alerts > 0
                    ? <Tag color={t.critical_alerts > 0 ? 'var(--danger)' : 'var(--warn)'}>{t.active_alerts}</Tag>
                    : <span className="t-muted">0</span>}
                </td>
                <td className="t-muted" style={{ fontSize: 12, textTransform: 'capitalize' }}>{t.trend_direction || '—'}</td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{relTime(t.last_calculated)}</td>
              </tr>
              );
            })}
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
