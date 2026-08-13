// Settings · Account pages (Billing, Usage & Limits) — ported from the mock's
// settings/sectionF.jsx, wired to admin-service /my-billing (subscription +
// invoices) and auth-service /billing/usage/current. Read views: plan changes
// and payment-method updates go through the editing pass.
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { useFeature } from '@vistasecurity/primitives/features';
import { clients } from '../../lib/clients';
import { mySubscriptionQuery, myInvoicesQuery } from './billing-queries';
import { safeHttpUrl } from '../../lib/url';
import { Icon } from '../../components/ui';
import { SPage, SSection, SCard, STable, STableRow, STag, SMeter, StateNote, GREEN, AMBER, RED } from './kit';
import { ChangePlanModal, CancelSubscriptionModal, usePortalSession, useReactivate } from './billing-modals';
import type { SettingsNavItem } from './nav';

function money(cents: number, currency = 'USD'): string {
  return new Intl.NumberFormat(undefined, { style: 'currency', currency, maximumFractionDigits: 0 }).format(cents / 100);
}
function dateStr(iso?: string | null): string {
  return iso ? new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : '—';
}
const INVOICE_TONE: Record<string, string> = { paid: GREEN, open: AMBER, draft: 'var(--app-t3)', void: 'var(--app-t3)', uncollectible: RED };

export function BillingPage({ meta }: { meta: SettingsNavItem }) {
  // `/my-billing/**` is admin-service/ee/billingapi — absent from a Core build.
  // SettingsPage already renders the upgrade card instead of this component when
  // the flag is off, so reaching here means it is on; the guard is repeated on
  // the queries so a stale flag map still cannot fire a doomed request.
  const billingEntitled = useFeature('billing_portal');
  const subQ = useQuery(mySubscriptionQuery(billingEntitled));
  const invQ = useQuery(myInvoicesQuery(billingEntitled));

  const portal = usePortalSession();
  const reactivate = useReactivate();
  const [planOpen, setPlanOpen] = useState(false);
  const [cancelOpen, setCancelOpen] = useState(false);

  const openPortal = async () => {
    try {
      const url = safeHttpUrl(await portal.mutateAsync()); // Stripe-hosted portal (payment methods, etc.)
      if (url) window.location.href = url; // reject anything that isn't http(s)
    } catch { /* surfaced inline below */ }
  };

  const sub = subQ.data;
  const cancelling = !!sub?.subscription.cancel_at_period_end;
  // change-plan / cancel / portal all act on an EXISTING subscription.
  // With self-serve checkout retired there is no in-app way to create one — a
  // subscription arrives via the sales-led path — so this flag now separates
  // "nothing to manage yet" from the full set of controls.
  const hasSubscription = !!sub?.subscription.external_id;
  const actionErr = portal.error instanceof Error ? portal.error.message
    : reactivate.error instanceof Error ? reactivate.error.message : null;
  const invoices = invQ.data?.invoices ?? [];
  const invCols = [
    { label: 'Date' }, { label: 'Invoice' }, { label: 'Amount', align: 'right' as const },
    { label: 'Status', w: '120px' }, { label: '', w: '80px', align: 'right' as const },
  ];

  return (
    <SPage eyebrow="Account" title="Billing" job={meta.job}>
      <SSection>
        {subQ.isError ? (
          <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load the subscription" message="The billing subscription failed to load." /></SCard>
        ) : subQ.isLoading ? (
          <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading subscription…" message="Fetching the plan and billing status." /></SCard>
        ) : (
          <SCard style={{ display: 'flex', alignItems: 'center', gap: 18, background: 'linear-gradient(120deg, color-mix(in srgb, var(--accent) 8%, transparent), transparent 60%)' }}>
            <span style={{ width: 46, height: 46, borderRadius: 12, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--accent-gradient)', color: 'var(--accent-fg)' }}>
              <Icon name="gem" size={22} />
            </span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
                <span style={{ fontSize: 16, fontWeight: 700, color: 'var(--app-t1)' }}>{sub?.tier.display_name || sub?.tier.name || '—'}</span>
                {sub?.subscription.status && <STag color={sub.subscription.status === 'active' ? GREEN : AMBER}>{sub.subscription.status}</STag>}
                {sub?.subscription.cancel_at_period_end && <STag color={AMBER}>Cancels at period end</STag>}
              </div>
              <div style={{ fontSize: 12.5, color: 'var(--app-t3)', marginTop: 2 }}>
                {sub?.subscription.current_period_end
                  ? `Renews ${dateStr(sub.subscription.current_period_end)} · billed ${sub.subscription.billing_interval || '—'}`
                  : 'No active billing period'}
                {sub?.discount ? ` · coupon ${sub.discount.coupon_code}` : ''}
              </div>
              {sub?.subscription.contract_end && (
                <div style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 2 }}>
                  <Icon name="file-check" size={12} style={{ verticalAlign: '-2px', marginRight: 4 }} />
                  12-month agreement{sub.subscription.contract_start ? ` since ${dateStr(sub.subscription.contract_start)}` : ''} · auto-renews {dateStr(sub.subscription.contract_end)}
                </div>
              )}
            </div>
            <div style={{ textAlign: 'right' }}>
              <div className="mono" style={{ fontSize: 20, fontWeight: 700, color: 'var(--app-t1)' }}>
                {sub ? money(sub.tier.price_cents) : '—'}
              </div>
              <div style={{ fontSize: 11, color: 'var(--app-t3)' }}>per month</div>
            </div>
          </SCard>
        )}
      </SSection>

      <PermissionGate permission={TENANT_PERMISSIONS.billing.update}>
        <SSection title="Manage subscription">
          <SCard style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
              {!hasSubscription ? (
                // Self-serve checkout was retired: paid editions are sales-led
                // (contract → signed entitlement token), so a tenant cannot start
                // a subscription by entering a card. A subscription is provisioned
                // by the operator, after which every control below applies. No
                // button here rather than one that opens nothing.
                <div style={{ fontSize: 12, color: 'var(--app-t2)' }}>
                  No active subscription. Paid plans are arranged with our team — once
                  yours is in place, plan changes, invoices and payment methods appear here.
                </div>
              ) : (
                <>
                  <button className="ui-btn accent" onClick={openPortal} disabled={portal.isPending}>
                    <Icon name="external-link" size={14} />{portal.isPending ? 'Opening…' : 'Manage billing & payment methods'}
                  </button>
                  <button className="ui-btn" onClick={() => setPlanOpen(true)} disabled={subQ.isLoading}>
                    <Icon name="gem" size={14} />Change plan
                  </button>
                  {cancelling ? (
                    <button className="ui-btn" onClick={() => reactivate.mutate()} disabled={reactivate.isPending}>
                      <Icon name="badge-check" size={14} />{reactivate.isPending ? 'Reactivating…' : 'Reactivate'}
                    </button>
                  ) : (
                    <button className="ui-btn ghost" style={{ color: 'var(--danger-text)' }} onClick={() => setCancelOpen(true)} disabled={subQ.isLoading || !sub}>
                      <Icon name="octagon-alert" size={14} />Cancel subscription
                    </button>
                  )}
                </>
              )}
            </div>
            <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>
              {!hasSubscription
                ? 'Plans are a 12-month agreement, billed monthly or prepaid annually at 10× the monthly price.'
                : 'The billing portal (payment methods, billing history, tax details) is hosted securely by Stripe.'}
            </div>
            {actionErr && <div style={{ fontSize: 11.5, color: 'var(--danger-text)' }}>{actionErr}</div>}
          </SCard>
        </SSection>
      </PermissionGate>

      {sub?.next_payment && (
        <SSection title="Next payment">
          <SCard style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <Icon name="credit-card" size={20} style={{ color: 'var(--app-t2)' }} />
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--app-t1)' }}>
                {money(sub.next_payment.amount_cents)} on {dateStr(sub.next_payment.date)}
              </div>
              <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>
                {sub.next_payment.payment_method_last4 ? `Card ending ${sub.next_payment.payment_method_last4}` : 'No default payment method on file'}
              </div>
            </div>
          </SCard>
        </SSection>
      )}

      <SSection title="Invoices">
        {invQ.isError ? (
          <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load invoices" message="The invoice history failed to load." /></SCard>
        ) : invQ.isLoading ? (
          <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading invoices…" message="Fetching the invoice history." /></SCard>
        ) : invoices.length === 0 ? (
          <SCard><StateNote icon="credit-card" tone="var(--app-t3)" title="No invoices" message="No invoices have been issued yet." /></SCard>
        ) : (
          <STable cols={invCols}>
            {invoices.map((inv, i) => (
              <STableRow
                key={inv.id}
                first={i === 0}
                cols={invCols}
                cells={[
                  <span style={{ fontSize: 12.5, color: 'var(--app-t1)' }}>{dateStr(inv.issued_at)}</span>,
                  <span className="mono" style={{ fontSize: 12, color: 'var(--app-t2)' }}>{inv.invoice_number || inv.external_invoice_id || '—'}</span>,
                  <span className="mono" style={{ fontSize: 12.5, color: 'var(--app-t1)' }}>{money(inv.amount_cents, inv.currency || 'USD')}</span>,
                  <STag color={INVOICE_TONE[inv.status] ?? 'var(--app-t2)'}>{inv.status}</STag>,
                  safeHttpUrl(inv.pdf_url)
                    ? <a href={safeHttpUrl(inv.pdf_url)!} target="_blank" rel="noreferrer noopener" className="ui-btn sm ghost" title="Download PDF"><Icon name="download" size={14} /></a>
                    : <span />,
                ]}
              />
            ))}
          </STable>
        )}
      </SSection>

      {planOpen && (
        <ChangePlanModal
          open
          currentTierId={sub?.tier.id}
          currentInterval={sub?.subscription.billing_interval}
          currentPriceCents={sub?.tier.price_cents}
          onClose={() => setPlanOpen(false)}
        />
      )}
      {cancelOpen && (
        <CancelSubscriptionModal
          open
          periodEnd={sub?.subscription.current_period_end}
          contractEnd={sub?.subscription.contract_end}
          billingInterval={sub?.subscription.billing_interval}
          onClose={() => setCancelOpen(false)}
        />
      )}
    </SPage>
  );
}

function gb(bytes: number): string {
  return (bytes / 1e9).toFixed(1);
}
function fmtCount(n: number): string {
  return n >= 1000 ? `${(n / 1000).toFixed(1)}k` : `${n}`;
}

export function UsagePage({ meta }: { meta: SettingsNavItem }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['settings', 'usage'],
    queryFn: async () => {
      const { data, error } = await clients.auth.GET('/billing/usage/current', {});
      if (error || !data) throw new Error('Failed to load usage');
      return data;
    },
  });

  const meters = data ? ([
    { label: 'Assets monitored', cur: data.usage.assets_count, lim: data.limits.assets_count, fmt: fmtCount },
    { label: 'Users', cur: data.usage.users_count, lim: data.limits.users_count, fmt: fmtCount },
    { label: 'Discovery sensors', cur: data.usage.sensors_count, lim: data.limits.sensors_count, fmt: fmtCount },
    { label: 'API calls (this period)', cur: data.usage.api_requests, lim: data.limits.api_requests, fmt: fmtCount },
    { label: 'Storage', cur: data.usage.storage_bytes, lim: data.limits.storage_bytes, fmt: (n: number) => `${gb(n)} GB` },
  ]) : [];

  return (
    <SPage eyebrow="Account" title="Usage & Limits" job={meta.job}>
      {isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load usage" message="The usage metrics failed to load." /></SCard>
      ) : isLoading ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading usage…" message="Fetching consumption against plan limits." /></SCard>
      ) : (
        <SCard pad={22}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            {meters.map((m) => {
              // Only a negative (or missing) limit means unlimited — the
              // backend's convention (see resolveUsageLimits in
              // services/auth-service/internal/api/billing.go) is -1 for "no
              // cap"; a real 0 is a genuine zero cap and must render as such,
              // not be mistaken for "unlimited".
              const unlimited = m.lim == null || m.lim < 0;
              return (
                <SMeter
                  key={m.label}
                  label={m.label}
                  value={unlimited ? `${m.fmt(m.cur)} / unlimited` : `${m.fmt(m.cur)} / ${m.fmt(m.lim)}`}
                  pct={unlimited ? 0 : (m.cur / m.lim) * 100}
                />
              );
            })}
          </div>
        </SCard>
      )}
      {data?.period?.end && (
        <p style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 14 }}>
          Limits reset {dateStr(data.period.end)}. Approaching a limit? Upgrade for headroom or contact your account team.
        </p>
      )}
    </SPage>
  );
}
