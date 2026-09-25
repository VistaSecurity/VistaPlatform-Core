// VISTA Operations — Billing & Revenue (RevOps). Slimmed in ADR-0004 /
// Slice 5: Tiers and Billable Items moved OUT to Plans & Pricing (Tiers · Entitlements);
// what remains here is purely money — Overview · Coupons · Trials · Dunning · FinOps,
// each a LEFT-RAIL sub-route (conforms to the v2 nav rule; no more in-page tabs).
// Every sub-view is wired to a real admin-service endpoint; where a kit field has no
// endpoint we render the closest real data + an honest note — no fabricated figures.
import { useState } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { Repeat, TrendingUp, Building2, Activity, Wallet, Ticket, Coins, FlaskConical, AlertCircle } from 'lucide-react';
import { clients } from '../../lib/clients';
import { Donut, StatTile, StatusTag, money, moneyK, num, planColor } from '../../components/ui/primitives';
import { BillingNotConfigured } from './billing-not-configured';
import { StartTrialModal, TrialRowActions } from './trial-actions';

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
function useTrials() {
  return useQuery({
    queryKey: ['platform', 'billing', 'trials'],
    queryFn: async () => {
      const { data, error } = await clients.admin.GET('/admin/billing/trials', {});
      if (error || !data) throw new Error('Failed to load trials');
      return data;
    },
    staleTime: 60 * 1000,
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
/** A revenue figure, or an em dash when there is nothing to measure it from. */
const orDash = (v: number | null | undefined, fmt: (n: number) => string) => (v == null ? '—' : fmt(v));

// Every revenue figure comes from billing records (billing_subscriptions:
// subscriptions that have paid, active or past-due, never trialing,
// interval-normalised, coupons applied; churn and LTV count only paid ones).
// With no payment provider there are no records, and the tab says so rather
// than showing a number. There is no MRR history to chart — the store is
// current-state — so the "trailing" series that projected today backwards is
// gone.
function OverviewTab() {
  const { data: dash, isLoading, isError, refetch } = useBillingDashboard();
  const { data: invoices } = useAdminInvoices();

  if (isError) {
    return <div className="op-panel" style={{ padding: 40, textAlign: 'center', color: 'var(--op-t3)' }}>Couldn't load billing analytics. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => refetch()}>Retry</button></div>;
  }
  if (dash && !dash.billing_configured) {
    return <div className="op-panel"><BillingNotConfigured /></div>;
  }
  const mrr = dash?.mrr ?? null;
  const byTier = Object.entries(dash?.revenue_by_tier ?? {}).filter(([, v]) => Number(v) > 0);
  const donutSegments = byTier.map(([tier, v]) => ({ value: Number(v), color: planColor(tier), label: tier }));
  const shown = (v: string) => (isLoading ? '…' : v);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 12 }}>
        <StatTile label="MRR" value={shown(orDash(mrr, moneyK))} sub="recurring, from subscriptions" icon={Repeat} brand />
        <StatTile label="ARR" value={shown(orDash(mrr == null ? null : mrr * 12, moneyK))} sub="annualized" icon={TrendingUp} />
        <StatTile label="Paying tenants" value={shown(orDash(dash?.paying_tenants, num))} sub="live, non-trial subscription" icon={Building2} />
        <StatTile label="Churn" value={shown(orDash(dash?.churn_rate, (n) => `${n.toFixed(1)}%`))} sub="tenants that stopped paying this month" icon={Activity} accent={(dash?.churn_rate ?? 0) > 5 ? 'var(--danger)' : undefined} />
        <StatTile label="LTV" value={shown(orDash(dash?.ltv, moneyK))} sub={dash?.ltv == null && !isLoading ? 'not enough history yet' : 'lifetime value'} icon={Wallet} />
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
        ) : <div style={{ height: 120, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--op-t3)', fontSize: 12 }}>{isLoading ? 'Loading…' : 'No paying subscriptions yet.'}</div>}
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
              <td>{c.discount_type === 'percentage' ? `${c.discount_value}%` : money(c.discount_value / 100)}</td>
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

// Costing component names (shared/costing) for display.
const COST_COMPONENT_LABELS: Record<string, string> = {
  api_calls: 'API calls',
  database: 'Database',
  storage: 'Storage',
  network: 'Network',
  compute: 'Compute',
};

const costComponentLabel = (key: string) => COST_COMPONENT_LABELS[key] ?? key;

function FinOpsTab() {
  const { data, isLoading } = usePlatformCost();
  const byService = data?.cost_by_service ? Object.entries(data.cost_by_service) : [];
  // Components with no measurement this period. Listed explicitly so the
  // platform-cost tile is not read as the whole infrastructure bill.
  const notMeasured = data?.not_measured ?? [];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 12 }}>
        <StatTile label="Platform cost" value={isLoading ? '…' : money(data?.total_cost_usd ?? 0)} sub="measured components, this period" icon={Coins} />
        <StatTile label="Tenants billed" value={isLoading ? '…' : num(data?.tenant_count ?? 0)} icon={Building2} />
        <StatTile label="Avg / tenant" value={isLoading ? '…' : money(data?.average_cost_usd ?? 0)} icon={Activity} />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.3fr', gap: 14 }}>
        <Panel title="Cost by service">
          <div style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: 9 }}>
            {byService.length > 0 ? byService.map(([k, v]) => (
              <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12.5 }}><span style={{ color: 'var(--op-t2)' }}>{costComponentLabel(k)}</span><span className="op-num" style={{ color: 'var(--op-t1)', fontWeight: 600 }}>{money(Number(v))}</span></div>
            )) : <Note>{isLoading ? 'Loading…' : 'No service-level cost breakdown.'}</Note>}
            {notMeasured.map((k) => (
              <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12.5 }}><span style={{ color: 'var(--op-t2)' }}>{costComponentLabel(k)}</span><span style={{ color: 'var(--op-t3)' }}>Not measured</span></div>
            ))}
          </div>
          {notMeasured.length > 0 && (
            <div style={{ padding: '0 16px 12px', fontSize: 11, color: 'var(--op-t3)', lineHeight: 1.45 }}>
              Platform cost covers measured components only. Compute is not attributable per tenant —
              the platform runs shared service pods, so no per-tenant CPU or memory figure exists.
            </div>
          )}
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

const TRIAL_PHASE_LABEL: Record<string, string> = { full: 'Full access', soft_prompt: 'Upgrade prompt', locked: 'Locked' };

// One trial store (owner decision 6): the live billing_trial_tracking rows on
// plans the MSP marked as trials, from GET /admin/billing/trials. Phase, days
// left and the end date are the same computation the tenant's trial lock and
// banner use. The tab used to show only a conversion rate and send the
// operator to the tenant list, which read a different store. Start trial and
// each row's Extend · Convert · End are where the tenant editor sends an
// operator who tries to start or end a trial by setting a status.
function TrialsTab() {
  const { data, isLoading, isError } = useTrials();
  const { data: dash } = useBillingDashboard();
  const [starting, setStarting] = useState(false);
  const trials = data?.trials ?? [];
  const fmt = (iso: string) => new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 12 }}>
        <StatTile label="Live trials" value={isLoading ? '…' : num(data?.count ?? 0)} sub="on trial plans" icon={FlaskConical} />
        <StatTile label="Locked" value={isLoading ? '…' : num(trials.filter((t) => t.phase === 'locked').length)} sub="awaiting upgrade" icon={AlertCircle} />
        <StatTile label="Conversion" value={dash ? `${dash.trial_conversion.toFixed(1)}%` : '…'} sub="trials started this month that converted" icon={TrendingUp} />
      </div>
      <Panel title="Trials" icon={FlaskConical}>
        <div style={{ display: 'flex', justifyContent: 'flex-end', padding: '10px 16px 0' }}>
          <button className="op-btn sm primary" onClick={() => setStarting(true)}>Start trial</button>
        </div>
        <table className="op-table">
          <thead><tr><th>Tenant</th><th>Plan</th><th>Phase</th><th>Started</th><th>Ends</th><th className="num">Days left</th><th /></tr></thead>
          <tbody>
            {trials.map((t) => (
              <tr key={t.tenant_id}>
                <td style={{ fontWeight: 600, color: 'var(--op-t1)' }}>{t.tenant_name}</td>
                <td className="t-muted">{t.plan_name}</td>
                <td style={{ color: t.phase === 'locked' ? 'var(--danger)' : t.phase === 'soft_prompt' ? 'var(--warn)' : 'var(--op-t2)', fontWeight: 600 }}>{TRIAL_PHASE_LABEL[t.phase] ?? t.phase}</td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{fmt(t.trial_start)}</td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{fmt(t.ends_at)}</td>
                <td className="num">{t.phase === 'locked' ? '—' : num(t.days_remaining)}</td>
                <td><TrialRowActions trial={t} /></td>
              </tr>
            ))}
            {trials.length === 0 && <EmptyRow cols={7} loading={isLoading} label={isError ? "Couldn't load trials." : 'No live trials. Trials run only on plans marked as trials.'} />}
          </tbody>
        </table>
      </Panel>
      {starting && <StartTrialModal onClose={() => setStarting(false)} />}
    </div>
  );
}

/**
 * Invoices in payment recovery. billing_invoices is written only by the Stripe
 * webhook, which stores exactly two statuses: 'paid' (invoice.paid /
 * payment_succeeded) and 'failed' (invoice.payment_failed). The tab used to
 * filter on Stripe's own status names ('past_due', 'open', 'unpaid',
 * 'uncollectible') — none of which is ever stored — so it was always empty.
 */
export const RECOVERY_INVOICE_STATUSES: readonly string[] = ['failed'];
export const isInRecovery = (status: string) => RECOVERY_INVOICE_STATUSES.includes(String(status).toLowerCase());

function DunningTab() {
  const { data: invoices, isLoading } = useAdminInvoices();
  const overdue = (invoices ?? []).filter((i) => isInRecovery(i.status));
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
      <div style={{ padding: '12px 16px' }}><Note>Invoices whose payment failed. Stripe runs the retry schedule.</Note></div>
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
