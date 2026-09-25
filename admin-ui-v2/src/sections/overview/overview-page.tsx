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
import { Avatar, MiniBar, PlanTag, StatTile, StatusTag, healthIndexPresentation, initialsFromName, moneyK, num } from '../../components/ui/primitives';
import { useTenants, useTenantHealthMap, tenantStatus, planLabel } from '../tenants/queries';
import { usePlatformEdition } from '../../lib/edition';
import { BillingNotConfigured } from '../billing/billing-not-configured';

// Revenue analytics live in admin-service/ee/billingapi. On a Core build the
// routes are absent (404), so this stays dormant rather than firing a doomed
// request and leaving the hero showing "loading…" forever. There is no MRR
// series: revenue is read from billing records, which hold current state only,
// and the old "trailing" chart was today's figure projected backwards.
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
  const { has, isMsp } = usePlatformEdition();
  // Revenue and past-due are billing surfaces, and billing is MSP-only by
  // LICENCE (edition-licensing spec §1: "Billing admin — Enterprise: No").
  // The build capability alone is not enough: one ee binary serves both paid
  // editions, so an Enterprise install mounts the billing routes too.
  const showRevenue = has('billing') && isMsp;
  const showTenants = has('msp');
  const showPastDue = showTenants && showRevenue;
  const { data: dash } = useBillingDashboard(showRevenue);
  const { data: status } = useSystemStatus();

  // Memoised so the fallback `[]` keeps a stable identity — otherwise every
  // render produces a fresh array and the useMemo blocks below never hit.
  const all = useMemo(() => tenants ?? [], [tenants]);
  const pastDue = showPastDue ? all.filter((t) => tenantStatus(t) === 'past_due').length : 0;
  const suspended = all.filter((t) => tenantStatus(t) === 'suspended').length;
  const services = status?.services ?? [];
  // "disabled" means an operator intentionally opted the service out of
  // monitoring (e.g. not deployed under this edition) — it is not a problem,
  // so it must not count toward "needs attention" alongside actual
  // degraded/down services.
  const needsAttention = services.filter((s) => s.status !== 'healthy' && s.status !== 'disabled').length;

  // Tenants needing attention: suspended > past_due > low health.
  const attention = useMemo(() => {
    const sev = (t: (typeof all)[number]) => {
      const st = tenantStatus(t);
      const h = healthMap?.get(t.id);
      if (st === 'suspended') return 100;
      if (st === 'past_due' && showPastDue) return 80;
      // `unknown` is stored as score 0 for compatibility, but it means no
      // health factor could be measured. Use the same availability/range
      // adapter as the rendered Health cell so the sentinel cannot become a
      // false failing-health alert. The <55 attention threshold remains this
      // dashboard's own policy, independent of the shared health bands.
      const healthIndex = healthIndexPresentation(h?.overall_score, h?.health_status !== 'unknown');
      if (healthIndex && healthIndex.score < 55) return 60 + (55 - healthIndex.score);
      return 0;
    };
    return [...all].map((t) => ({ t, s: sev(t) })).filter((x) => x.s > 0).sort((a, b) => b.s - a.s).slice(0, 6).map((x) => x.t);
  }, [all, healthMap, showPastDue]);

  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 18 }}>
      {/* revenue hero — MSP billing only. Mission Control has no
          `edition` marker in nav.ts because most of it (service health) is Core;
          the paid pieces are gated here instead of hiding the whole page. */}
      {showRevenue && (
      <div className="op-panel" style={{ padding: '20px 22px', background: 'var(--op-hero)' }}>
        <div className="op-eyebrow">Recurring revenue</div>
        {dash && !dash.billing_configured ? (
          <div style={{ marginTop: 10 }}><BillingNotConfigured compact /></div>
        ) : (
          <>
            <div className="op-num accent-text" style={{ fontSize: 46, fontWeight: 700, letterSpacing: '-.02em', lineHeight: 1.1, marginTop: 6 }}>{dash?.mrr != null ? moneyK(dash.mrr) : '—'}</div>
            <div style={{ fontSize: 12, color: 'var(--op-t3)', marginTop: 4 }}>{dash?.mrr != null ? `${moneyK(dash.mrr * 12)} ARR · ${num(dash.paying_tenants ?? 0)} paying` : 'loading…'}</div>
          </>
        )}
      </div>
      )}

      {/* needs attention */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <AlertTriangle size={16} style={{ color: 'var(--op-t2)' }} />
        <span style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14.5, color: 'var(--op-t1)' }}>Needs attention</span>
      </div>
      {/* Tenant-derived tiles read /admin/tenants (MSP) and link to sections a
          Core build does not have; only "Degraded services" is Core. */}
      <div style={{ display: 'grid', gridTemplateColumns: `repeat(${showTenants ? (showPastDue ? 4 : 3) : 1},1fr)`, gap: 12 }}>
        {showPastDue && <StatTile label="Past-due tenants" value={pastDue} icon={CircleDollarSign} accent={pastDue ? 'var(--danger)' : undefined} onClick={() => navigate('/billing')} />}
        {showTenants && <StatTile label="Suspended" value={suspended} icon={Building2} accent={suspended ? 'var(--warn)' : undefined} onClick={() => navigate('/tenants')} />}
        <StatTile label="Services needing attention" value={needsAttention} icon={Activity} accent={needsAttention ? 'var(--warn)' : undefined} onClick={() => navigate('/system')} />
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
              const healthIndex = healthIndexPresentation(h?.overall_score, h?.health_status !== 'unknown');
              const plan = planLabel(t);
              return (
                <tr key={t.id} style={{ cursor: 'pointer' }} onClick={() => navigate('/tenants')}>
                  <td><div style={{ display: 'flex', alignItems: 'center', gap: 10 }}><Avatar initials={initialsFromName(t.name)} size={26} brand={plan === 'Sovereign'} square /><span style={{ fontWeight: 600, color: 'var(--op-t1)' }}>{t.name}</span></div></td>
                  <td><PlanTag plan={plan} /></td>
                  <td><StatusTag status={tenantStatus(t)} /></td>
                  <td>{healthIndex === null ? <span className="t-muted">—</span> : <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><span className="op-num" style={{ color: healthIndex.color, fontWeight: 700, whiteSpace: 'nowrap' }}>{healthIndex.text}</span><div style={{ width: 40 }}><MiniBar pct={healthIndex.score} color={healthIndex.color} h={5} /></div></div>}</td>
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
