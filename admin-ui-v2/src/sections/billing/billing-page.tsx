// VISTA Operations — Billing & Revenue (RevOps). Slimmed in ADR-0004 /
// Slice 5: Tiers and Billable Items moved OUT to Plans & Pricing (Tiers · Entitlements);
// what remains here is purely money — Overview · Coupons · Trials · Dunning · FinOps,
// each a LEFT-RAIL sub-route (conforms to the v2 nav rule; no more in-page tabs).
// Every sub-view is wired to a real admin-service endpoint; where a kit field has no
// endpoint we render the closest real data + an honest note — no fabricated figures.
import { Navigate, Route, Routes } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { Repeat, TrendingUp, Building2, Activity, Wallet, Ticket, Coins, FlaskConical, AlertCircle } from 'lucide-react';
import { clients } from '../../lib/clients';
import { AreaChart, Donut, StatTile, StatusTag, money, moneyK, num, planColor } from '../../components/ui/primitives';

// ---- queries ---------------------------------------------------------------
function useBillingDashboard() {
  return useQuery({
    queryKey: ['platform', 'billing', 'dashboard'],
    queryFn: async () => {
      const { data, error } = await clients.admin.GET('/admin/billing/analytics/dashboard', {});
      if (error || !data) throw new Error('Failed to load billing dashboard');
      return data;
    },
    staleTime: 5 * 60 * 1000,
  });
}
function useMrrSeries() {
  return useQuery({
    queryKey: ['platform', 'billing', 'mrr'],
    queryFn: async () => {
      const { data, error } = await clients.admin.GET('/admin/billing/analytics/mrr', {});
      if (error || !data) throw new Error('Failed to load MRR series');
      return 'series' in data ? (data.series ?? []) : [];
    },
    staleTime: 5 * 60 * 1000,
    retry: 0,
  });
}
function useAdminInvoices() {
  return useQuery({
    queryKey: ['platform', 'billing', 'invoices'],
    queryFn: async () => {
      const { data, error } = await clients.admin.GET('/admin/billing/invoices', {});
      if (error || !data) throw new Error('Failed to load invoices');
      return data.invoices ?? [];
    },
    staleTime: 60 * 1000,
    retry: 0,
  });
}
function useCoupons() {
  return useQuery({
    queryKey: ['platform', 'billing', 'coupons'],
    queryFn: async () => {
      const { data, error } = await clients.admin.GET('/admin/billing/coupons', {});
      if (error || !data) throw new Error('Failed to load coupons');
      return data.coupons ?? [];
    },
    staleTime: 60 * 1000,
    retry: 0,
  });
}
function usePlatformCost() {
  return useQuery({
    queryKey: ['platform', 'billing', 'cost-platform'],
    queryFn: async () => {
      const { data, error } = await clients.admin.GET('/admin/costs/platform', {});
      if (error || !data) throw new Error('Failed to load platform cost');
      return data;
    },
    staleTime: 5 * 60 * 1000,
    retry: 0,
  });
}
function useTrialConversion() {
  return useQuery({
    queryKey: ['platform', 'billing', 'trial-conversion'],
    queryFn: async () => {
      const { data, error } = await clients.admin.GET('/admin/billing/analytics/trial-conversion', {});
      if (error || !data) throw new Error('Failed to load trial conversion');
      return data as Record<string, unknown>;
    },
    staleTime: 5 * 60 * 1000,
    retry: 0,
  });
}

// ---- shared bits -----------------------------------------------------------
function Panel({ title, icon: Icon, children }: { title: string; icon?: typeof Wallet; children: React.ReactNode }) {
  return (
    <div className="op-panel" style={{ overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '13px 16px', borderBottom: '1px solid var(--op-border)', fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>
        {Icon && <Icon size={16} style={{ color: 'var(--op-t3)' }} />}{title}
      </div>
      {children}
    </div>
  );
}
function EmptyRow({ cols, loading, label }: { cols: number; loading?: boolean; label: string }) {
  return <tr><td colSpan={cols} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>{loading ? 'Loading…' : label}</td></tr>;
}
function Note({ children }: { children: React.ReactNode }) {
  return <div style={{ fontSize: 11.5, color: 'var(--op-t3)', lineHeight: 1.55 }}>{children}</div>;
}
/** Padded content wrapper for each RevOps sub-route. */
function SubView({ children }: { children: React.ReactNode }) {
  return <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 16 }}>{children}</div>;
}

// ---- sub-views -------------------------------------------------------------
function OverviewTab() {
  const { data: dash, isLoading, isError, refetch } = useBillingDashboard();
  const { data: series } = useMrrSeries();
  const { data: invoices } = useAdminInvoices();
  const mrr = dash?.mrr ?? 0;
  const byTier = Object.entries(dash?.revenue_by_tier ?? {}).filter(([, v]) => Number(v) > 0);
  const donutSegments = byTier.map(([tier, v]) => ({ value: Number(v), color: planColor(tier), label: tier }));

  if (isError) {
    return <div className="op-panel" style={{ padding: 40, textAlign: 'center', color: 'var(--op-t3)' }}>Couldn't load billing analytics. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => refetch()}>Retry</button></div>;
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 12 }}>
        <StatTile label="MRR" value={isLoading ? '…' : moneyK(mrr)} sub="recurring" icon={Repeat} brand />
        <StatTile label="ARR" value={isLoading ? '…' : moneyK(mrr * 12)} sub="annualized" icon={TrendingUp} />
        <StatTile label="Active tenants" value={isLoading ? '…' : num(dash?.active_tenants ?? 0)} sub="paying" icon={Building2} />
        <StatTile label="Churn" value={isLoading ? '…' : `${(dash?.churn_rate ?? 0).toFixed(1)}%`} sub="monthly" icon={Activity} accent={(dash?.churn_rate ?? 0) > 5 ? 'var(--danger)' : undefined} />
        <StatTile label="LTV" value={isLoading ? '…' : moneyK(dash?.ltv ?? 0)} sub="lifetime value" icon={Wallet} />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr', gap: 14 }}>
        <div className="op-panel" style={{ padding: '16px 18px' }}>
          <div className="op-eyebrow" style={{ marginBottom: 12 }}>MRR · trailing series</div>
          {series && series.length > 1
            ? <AreaChart series={[{ data: series.map((p) => p.mrr), color: 'var(--accent)' }]} h={150} />
            : <div style={{ height: 150, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--op-t3)', fontSize: 12 }}>{isLoading ? 'Loading…' : 'No MRR history yet.'}</div>}
        </div>
        <div className="op-panel" style={{ padding: '16px 18px' }}>
          <div className="op-eyebrow" style={{ marginBottom: 12 }}>Revenue by plan</div>
          {donutSegments.length > 0 ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <Donut segments={donutSegments} size={120} center={<><span className="op-num" style={{ fontSize: 18, fontWeight: 700, color: 'var(--op-t1)' }}>{byTier.length}</span><span style={{ fontSize: 9.5, color: 'var(--op-t3)' }}>plans</span></>} />
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 7 }}>
                {byTier.map(([tier, v]) => (
                  <div key={tier} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
                    <span style={{ width: 9, height: 9, borderRadius: 3, background: planColor(tier), flex: 'none' }} />
                    <span style={{ flex: 1, color: 'var(--op-t2)' }}>{tier}</span>
                    <span className="op-num" style={{ color: 'var(--op-t1)', fontWeight: 600 }}>{moneyK(Number(v))}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : <div style={{ height: 120, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--op-t3)', fontSize: 12 }}>{isLoading ? 'Loading…' : 'No revenue by plan.'}</div>}
        </div>
      </div>
      <Panel title="Invoices" icon={Wallet}>
        <table className="op-table">
          <thead><tr><th>Invoice</th><th className="num">Amount</th><th>Status</th><th>Issued</th></tr></thead>
          <tbody>
            {(invoices ?? []).map((inv) => (
              <tr key={inv.invoice_id}>
                <td className="mono" style={{ fontSize: 11.5 }}>{inv.invoice_id}</td>
                <td className="num" style={{ fontWeight: 600 }}>{money(inv.amount_cents / 100)}</td>
                <td><StatusTag status={inv.status} /></td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{inv.issued_at ? new Date(inv.issued_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : '—'}</td>
              </tr>
            ))}
            {(invoices ?? []).length === 0 && <EmptyRow cols={4} loading={isLoading} label="No invoices." />}
          </tbody>
        </table>
      </Panel>
      <Note>Net-new, NRR, and past-due tiles from the kit need analytics fields the dashboard doesn't return yet; invoices carry no tenant/plan join. Tracked in BUILD_PLAN Phase 3.</Note>
    </div>
  );
}

function CouponsTab() {
  const { data, isLoading } = useCoupons();
  return (
    <Panel title="Coupons" icon={Ticket}>
      <table className="op-table">
        <thead><tr><th>Code</th><th>Name</th><th>Discount</th><th>Duration</th><th className="num">Redeemed</th><th>Valid until</th><th>Status</th></tr></thead>
        <tbody>
          {(data ?? []).map((c) => (
            <tr key={c.id}>
              <td className="mono" style={{ fontWeight: 600, color: 'var(--op-t1)' }}>{c.code}</td>
              <td className="t-muted">{c.name}</td>
              <td>{c.discount_type === 'percent' ? `${c.discount_value}%` : money(c.discount_value / 100)}</td>
              <td className="t-muted">{c.duration}{c.duration_in_months ? ` · ${c.duration_in_months}mo` : ''}</td>
              <td className="num">{c.times_redeemed}{c.max_redemptions ? ` / ${c.max_redemptions}` : ''}</td>
              <td className="t-muted mono" style={{ fontSize: 11 }}>{c.valid_until ? new Date(c.valid_until).toLocaleDateString() : '—'}</td>
              <td><StatusTag status={c.is_active ? 'active' : 'canceled'} /></td>
            </tr>
          ))}
          {(data ?? []).length === 0 && <EmptyRow cols={7} loading={isLoading} label="No coupons." />}
        </tbody>
      </table>
    </Panel>
  );
}

function FinOpsTab() {
  const { data, isLoading } = usePlatformCost();
  const byService = data?.cost_by_service ? Object.entries(data.cost_by_service) : [];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 12 }}>
        <StatTile label="Platform cost" value={isLoading ? '…' : money(data?.total_cost_usd ?? 0)} sub="this period" icon={Coins} />
        <StatTile label="Tenants billed" value={isLoading ? '…' : num(data?.tenant_count ?? 0)} icon={Building2} />
        <StatTile label="Avg / tenant" value={isLoading ? '…' : money(data?.average_cost_usd ?? 0)} icon={Activity} />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.3fr', gap: 14 }}>
        <Panel title="Cost by service">
          <div style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: 9 }}>
            {byService.length > 0 ? byService.map(([k, v]) => (
              <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12.5 }}><span style={{ color: 'var(--op-t2)' }}>{k}</span><span className="op-num" style={{ color: 'var(--op-t1)', fontWeight: 600 }}>{money(Number(v))}</span></div>
            )) : <Note>{isLoading ? 'Loading…' : 'No service-level cost breakdown.'}</Note>}
          </div>
        </Panel>
        <Panel title="Top tenants by cost">
          <table className="op-table">
            <thead><tr><th>Tenant</th><th className="num">Cost</th></tr></thead>
            <tbody>
              {(data?.top_tenants ?? []).map((t) => (
                <tr key={t.tenant_id}><td style={{ fontWeight: 500 }}>{t.tenant_name}</td><td className="num" style={{ fontWeight: 600 }}>{money(t.total_cost_usd)}</td></tr>
              ))}
              {(data?.top_tenants ?? []).length === 0 && <EmptyRow cols={2} loading={isLoading} label="No tenant cost data." />}
            </tbody>
          </table>
        </Panel>
      </div>
    </div>
  );
}

function TrialsTab() {
  const { data, isLoading } = useTrialConversion();
  const rows = data ? Object.entries(data).filter(([, v]) => typeof v === 'number' || typeof v === 'string') : [];
  return (
    <Panel title="Trial conversion" icon={FlaskConical}>
      <div style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 10 }}>
        {rows.length > 0 ? rows.map(([k, v]) => (
          <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12.5 }}>
            <span style={{ color: 'var(--op-t2)', textTransform: 'capitalize' }}>{k.replace(/_/g, ' ')}</span>
            <span className="op-num" style={{ color: 'var(--op-t1)', fontWeight: 600 }}>{String(v)}</span>
          </div>
        )) : <Note>{isLoading ? 'Loading…' : 'No trial-conversion analytics available.'}</Note>}
        <Note>Individual trial accounts (start/end, days remaining) are managed from <strong>Tenants</strong> filtered to trial status — there's no separate trials list endpoint. This view shows the platform conversion analytics.</Note>
      </div>
    </Panel>
  );
}

function DunningTab() {
  const { data: invoices, isLoading } = useAdminInvoices();
  const overdue = (invoices ?? []).filter((i) => ['past_due', 'open', 'unpaid', 'uncollectible'].includes(String(i.status).toLowerCase()));
  return (
    <Panel title="Payment recovery" icon={AlertCircle}>
      <table className="op-table">
        <thead><tr><th>Invoice</th><th className="num">Amount</th><th>Status</th><th>Issued</th></tr></thead>
        <tbody>
          {overdue.map((inv) => (
            <tr key={inv.invoice_id}>
              <td className="mono" style={{ fontSize: 11.5 }}>{inv.invoice_id}</td>
              <td className="num" style={{ fontWeight: 600 }}>{money(inv.amount_cents / 100)}</td>
              <td><StatusTag status={inv.status} /></td>
              <td className="t-muted mono" style={{ fontSize: 11 }}>{inv.issued_at ? new Date(inv.issued_at).toLocaleDateString() : '—'}</td>
            </tr>
          ))}
          {overdue.length === 0 && <EmptyRow cols={4} loading={isLoading} label="No outstanding invoices — nothing in recovery." />}
        </tbody>
      </table>
      <div style={{ padding: '12px 16px' }}><Note>Derived from open/past-due invoices. A dedicated dunning workflow (retry schedule, reminders, escalation state) is a follow-up — no dunning-state endpoint yet.</Note></div>
    </Panel>
  );
}

// ---- section ---------------------------------------------------------------
export function BillingPage() {
  return (
    <SubView>
      <Routes>
        <Route index element={<OverviewTab />} />
        <Route path="overview" element={<OverviewTab />} />
        <Route path="coupons" element={<CouponsTab />} />
        <Route path="trials" element={<TrialsTab />} />
        <Route path="dunning" element={<DunningTab />} />
        <Route path="finops" element={<FinOpsTab />} />
        <Route path="*" element={<Navigate to="/billing" replace />} />
      </Routes>
    </SubView>
  );
}
