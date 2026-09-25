// "Billing not configured" (owner decision 5, admin-UI data review RC-9).
//
// Revenue figures come only from billing records. On an install with no
// payment provider — no Stripe secret, and no invoice-billed plan ever
// assigned — there are none, and the console says so instead of showing a
// number. It used to multiply each tier's list price by the tenants marked
// 'active' or 'trial', which put revenue on the screen for tenants that had
// never paid anything.
import { CreditCard } from 'lucide-react';

export const BILLING_NOT_CONFIGURED = 'Billing not configured';

export function BillingNotConfigured({ compact = false }: { compact?: boolean }) {
  return (
    <div
      role="status"
      data-testid="billing-not-configured"
      style={{ display: 'flex', alignItems: 'flex-start', gap: 12, padding: compact ? 0 : '18px 20px' }}
    >
      <CreditCard size={compact ? 18 : 22} style={{ color: 'var(--op-t3)', flex: 'none', marginTop: 2 }} />
      <div>
        <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: compact ? 15 : 16, color: 'var(--op-t1)' }}>
          {BILLING_NOT_CONFIGURED}
        </div>
        <div style={{ fontSize: 12.5, color: 'var(--op-t3)', marginTop: 4, lineHeight: 1.5, maxWidth: 560 }}>
          Revenue is read from billing records, and this install has no payment provider yet. Configure Stripe,
          or assign an invoice-billed plan to a tenant, and MRR, churn and revenue by plan will appear here.
        </div>
      </div>
    </div>
  );
}
