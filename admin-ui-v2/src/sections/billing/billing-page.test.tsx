import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter, Route, Routes } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { BillingPage, isInRecovery } from './billing-page';

// Billing & Revenue sub-views rendered from mocked queries, keyed by the third
// segment of each query key (['platform', 'billing', <name>]).
const state = vi.hoisted((): { data: Record<string, unknown> } => ({ data: {} }));

vi.mock('@tanstack/react-query', () => ({
  useQuery: ({ queryKey }: { queryKey: unknown[] }) => ({
    data: state.data[String(queryKey[2])],
    isLoading: false,
    isError: false,
    refetch: () => undefined,
  }),
  // The Trials tab's actions (trial-actions.tsx); exercised against the real
  // client in trial-actions.jsdom.test.tsx.
  useMutation: () => ({ mutate: () => undefined, isPending: false }),
  useQueryClient: () => ({ invalidateQueries: () => undefined }),
}));

function render(path: string): string {
  return renderToStaticMarkup(createElement(MemoryRouter, { initialEntries: [path] },
    createElement(Routes, null, createElement(Route, { path: '/billing/*', element: createElement(BillingPage) }))));
}

const configured = {
  billing_configured: true,
  mrr: 353.33,
  paying_tenants: 5,
  churn_rate: 16.7,
  ltv: null,
  revenue_by_tier: { 'IT pro': 183.33, 'IT basic': 170 },
  trial_conversion: 0,
  calculation_time: '2026-09-23T00:00:00Z',
};

beforeEach(() => {
  state.data = { invoices: [], coupons: [], trials: { trials: [], count: 0 } };
});

// Owner decision 5: revenue only from billing records; no payment provider →
// "Billing not configured", never tier list price × tenants.
describe('Billing → Overview', () => {
  it('shows "Billing not configured" and no figures without a payment provider', () => {
    state.data.dashboard = { ...configured, billing_configured: false, mrr: null, paying_tenants: null, churn_rate: null, ltv: null, revenue_by_tier: {} };
    const html = render('/billing');
    expect(html).toContain('Billing not configured');
    expect(html).not.toContain('>MRR</span>'); // no MRR tile
    expect(html).not.toMatch(/\$\d/);
  });

  it('shows the billing-record figures, only paid plans, and no trailing series', () => {
    state.data.dashboard = configured;
    const html = render('/billing');
    expect(html).not.toContain('Billing not configured');
    expect(html).toContain('$353');
    expect(html).toContain('Paying tenants');
    expect(html).toContain('IT pro');
    expect(html).toContain('IT basic');
    expect(html).toContain('16.7%');
    expect(html).not.toContain('trailing');
    // Unknown LTV is a dash, not $0.
    expect(html).toContain('not enough history yet');
  });
});

// Owner decision 6: the Trials tab lists the one trial store
// (GET /admin/billing/trials) instead of pointing at the tenant list.
describe('Billing → Trials', () => {
  it('lists the live trials with phase, end date and days left', () => {
    state.data.dashboard = configured;
    state.data.trials = {
      count: 2,
      trials: [
        { tenant_id: 't1', tenant_name: 'Acme Trial', plan_name: 'Starter Trial', trial_start: '2026-09-01T00:00:00Z', ends_at: '2026-09-29T12:00:00Z', phase: 'soft_prompt', days_remaining: 5, extended_count: 0, payment_status: 'trial', created_at: '2026-09-01T00:00:00Z' },
        { tenant_id: 't2', tenant_name: 'Locked Co', plan_name: 'Starter Trial', trial_start: '2026-08-01T00:00:00Z', ends_at: '2026-08-29T00:00:00Z', phase: 'locked', days_remaining: 0, extended_count: 1, payment_status: 'trial', created_at: '2026-08-01T00:00:00Z' },
      ],
    };
    const html = render('/billing/trials');
    expect(html).toContain('Acme Trial');
    expect(html).toContain('Upgrade prompt');
    expect(html).toContain('Locked Co');
    expect(html).toContain('Sep 29, 2026');
    expect(html).not.toContain('filtered to trial status');
    // The controls the tenant editor's refusal sends the operator to.
    expect(html).toContain('Start trial');
    expect(html.match(/>Extend</g)).toHaveLength(2);
    expect(html.match(/>Convert</g)).toHaveLength(2);
    expect(html.match(/>End trial</g)).toHaveLength(2);
  });

  it('says so when there are no live trials', () => {
    state.data.trials = { count: 0, trials: [] };
    const html = render('/billing/trials');
    expect(html).toContain('No live trials');
  });
});

// P15: coupons store 'percentage' (not 'percent'); invoices store 'paid' or
// 'failed' (never Stripe's 'past_due'/'open').
describe('Billing → Coupons and Dunning read the stored values', () => {
  it('renders a percentage coupon as a percentage', () => {
    state.data.coupons = [{ id: 'c1', code: 'LAUNCH20', name: 'Launch', discount_type: 'percentage', discount_value: 20, duration: 'forever', times_redeemed: 0, is_active: true }];
    const html = render('/billing/coupons');
    expect(html).toContain('20%');
    expect(html).not.toContain('$0');
  });

  it('lists failed invoices in recovery and nothing else', () => {
    expect(isInRecovery('failed')).toBe(true);
    expect(isInRecovery('paid')).toBe(false);
    state.data.invoices = [
      { invoice_id: 'in_failed', amount_cents: 5000, currency: 'usd', status: 'failed', issued_at: '2026-09-01T00:00:00Z' },
      { invoice_id: 'in_paid', amount_cents: 5000, currency: 'usd', status: 'paid', issued_at: '2026-09-01T00:00:00Z' },
    ];
    const html = render('/billing/dunning');
    expect(html).toContain('in_failed');
    expect(html).not.toContain('in_paid');
  });
});
