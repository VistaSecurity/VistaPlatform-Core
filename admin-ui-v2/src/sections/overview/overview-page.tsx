// VISTA Operations — Mission Control (Overview). Assembled from real sources:
// billing analytics (MRR), the tenant list + cross-tenant health, and
// monitoring (services). Query keys match the section pages so the cache is
// shared (no double fetch). Honest: no fabricated deltas/aggregates — only what
// the existing endpoints provide. Richer hero metrics arrive as gaps close.
import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router';
import { CircleDollarSign, Building2, Activity, AlertTriangle, ChevronRight } from 'lucide-react';
import { clients } from '../../lib/clients';
import { Avatar, AreaChart, MiniBar, PlanTag, StatTile, StatusTag, healthColor, initialsFromName, moneyK, num } from '../../components/ui/primitives';
import { useTenants, useTenantHealthMap, tenantStatus } from '../tenants/queries';
import { usePlatformEdition } from '../../lib/edition';

// Revenue analytics live in admin-service/ee/billingapi. On a Core build the
// routes are absent (404), so these two stay dormant rather than firing a doomed
// request and leaving the hero showing "loading…" forever.
function useBillingDashboard(enabled: boolean) {
  return useQuery({
    queryKey: ['platform', 'billing', 'dashboard'],
    enabled,
    queryFn: async () => {
      const { data, error } = await clients.admin.GET('/admin/billing/analytics/dashboard', {});
      if (error || !data) throw new Error('billing');
      return data;
    },
    staleTime: 5 * 60 * 1000, retry: 0,
  });
}
function useMrrSeries(enabled: boolean) {
  return useQuery({
    queryKey: ['platform', 'billing', 'mrr'],
    enabled,
    queryFn: async () => {
      const { data, error } = await clients.admin.GET('/admin/billing/analytics/mrr', {});
      if (error || !data) throw new Error('mrr');
      return 'series' in data ? (data.series ?? []) : [];
    },
    staleTime: 5 * 60 * 1000, retry: 0,
  });
}
function useSystemStatus() {
  return useQuery({
    queryKey: ['platform', 'system-status'],
    queryFn: async () => {
      const { data, error } = await clients.monitoring.GET('/admin/status', {});
      if (error || !data) throw new Error('status');
      return data;
    },
    staleTime: 30 * 1000, retry: 0,
  });
}

export function OverviewPage() {
  const navigate = useNavigate();
  const { data: tenants } = useTenants();
  const { data: healthMap } = useTenantHealthMap();
  const { has } = usePlatformEdition();
  const showRevenue = has('billing');
  const showTenants = has('msp');
  const { data: dash } = useBillingDashboard(showRevenue);
  const { data: series } = useMrrSeries(showRevenue);
  const { data: status } = useSystemStatus();

  // Memoised so the fallback `[]` keeps a stable identity — otherwise every
  // render produces a fresh array and the useMemo blocks below never hit.
  const all = useMemo(() => tenants ?? [], [tenants]);
  const pastDue = all.filter((t) => tenantStatus(t) === 'past_due').length;
  const suspended = all.filter((t) => tenantStatus(t) === 'suspended').length;
  const services = status?.services ?? [];
  const degraded = services.filter((s) => s.status !== 'healthy').length;

  // Tenants needing attention: suspended > past_due > low health.
  const attention = useMemo(() => {
    const sev = (t: (typeof all)[number]) => {
      const st = tenantStatus(t);
      const h = healthMap?.get(t.id);
      if (st === 'suspended') return 100;
      if (st === 'past_due') return 80;
      if (h && h.overall_score < 55) return 60 + (55 - h.overall_score);
      return 0;
    };
    return [...all].map((t) => ({ t, s: sev(t) })).filter((x) => x.s > 0).sort((a, b) => b.s - a.s).slice(0, 6).map((x) => x.t);
  }, [all, healthMap]);

  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 18 }}>
      {/* revenue hero — Enterprise billing only. Mission Control has no
          `edition` marker in nav.ts because most of it (service health) is Core;
          the paid pieces are gated here instead of hiding the whole page. */}
      {showRevenue && (
      <div className="op-panel" style={{ padding: '20px 22px', background: 'var(--op-hero)', display: 'grid', gridTemplateColumns: '300px 1fr', gap: 24, alignItems: 'center' }}>
        <div>
          <div className="op-eyebrow">Recurring revenue</div>
          <div className="op-num accent-text" style={{ fontSize: 46, fontWeight: 700, letterSpacing: '-.02em', lineHeight: 1.1, marginTop: 6 }}>{dash ? moneyK(dash.mrr) : '—'}</div>
          <div style={{ fontSize: 12, color: 'var(--op-t3)', marginTop: 4 }}>{dash ? `${moneyK(dash.mrr * 12)} ARR · ${num(dash.active_tenants)} active` : 'loading…'}</div>
        </div>
        <div style={{ minWidth: 0 }}>
          <div className="op-eyebrow" style={{ marginBottom: 8 }}>MRR · trailing</div>
          {series && series.length > 1
            ? <AreaChart series={[{ data: series.map((p) => p.mrr), color: 'var(--accent)' }]} h={120} />
            : <div style={{ height: 120, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--op-t3)', fontSize: 12 }}>No MRR history yet.</div>}
        </div>
      </div>
      )}

      {/* needs attention */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <AlertTriangle size={16} style={{ color: 'var(--op-t2)' }} />
        <span style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14.5, color: 'var(--op-t1)' }}>Needs attention</span>
      </div>
      {/* Tenant-derived tiles read /admin/tenants (MSP) and link to sections a
          Core build does not have; only "Degraded services" is Core. */}
      <div style={{ display: 'grid', gridTemplateColumns: `repeat(${showTenants ? 4 : 1},1fr)`, gap: 12 }}>
        {showTenants && <StatTile label="Past-due tenants" value={pastDue} icon={CircleDollarSign} accent={pastDue ? 'var(--danger)' : undefined} onClick={() => navigate('/billing')} />}
        {showTenants && <StatTile label="Suspended" value={suspended} icon={Building2} accent={suspended ? 'var(--warn)' : undefined} onClick={() => navigate('/tenants')} />}
        <StatTile label="Degraded services" value={degraded} icon={Activity} accent={degraded ? 'var(--warn)' : undefined} onClick={() => navigate('/system')} />
        {showTenants && <StatTile label="Total tenants" value={num(all.length)} icon={Building2} onClick={() => navigate('/tenants')} />}
      </div>

      {/* tenants needing attention */}
      {showTenants && (
      <div className="op-panel" style={{ overflow: 'hidden' }}>
        <div style={{ padding: '13px 16px', borderBottom: '1px solid var(--op-border)', fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>Tenants needing attention</div>
        <table className="op-table">
          <thead><tr><th>Tenant</th><th>Plan</th><th>Status</th><th>Health</th><th /></tr></thead>
          <tbody>
            {attention.map((t) => {
              const h = healthMap?.get(t.id);
              const score = h ? Math.round(h.overall_score) : null;
              const plan = t.subscription_tier ?? 'Trial';
              return (
                <tr key={t.id} style={{ cursor: 'pointer' }} onClick={() => navigate('/tenants')}>
                  <td><div style={{ display: 'flex', alignItems: 'center', gap: 10 }}><Avatar initials={initialsFromName(t.name)} size={26} brand={plan === 'Sovereign'} square /><span style={{ fontWeight: 600, color: 'var(--op-t1)' }}>{t.name}</span></div></td>
                  <td><PlanTag plan={plan} /></td>
                  <td><StatusTag status={tenantStatus(t)} /></td>
                  <td>{score === null ? <span className="t-muted">—</span> : <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><span className="op-num" style={{ color: healthColor(score), fontWeight: 700, width: 20 }}>{score}</span><div style={{ width: 40 }}><MiniBar pct={score} color={healthColor(score)} h={5} /></div></div>}</td>
                  <td><ChevronRight size={15} style={{ color: 'var(--op-t3)' }} /></td>
                </tr>
              );
            })}
            {attention.length === 0 && <tr><td colSpan={5} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>All clear — no tenants need attention.</td></tr>}
          </tbody>
        </table>
      </div>
      )}
    </div>
  );
}
