// Settings → Billing account (edition-licensing spec PR 2): the plan block in
// every state, and billing controls only where `billing_portal` resolves on.
//
// The copy rules pinned here are the spec's: on Enterprise the page reads
// "Vista Platform Enterprise, provided by <licensee>" — no tier, no trial, no
// upgrade — and never shows billing controls; an unresolved plan hides the
// block rather than falling back to a tier name.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { TenantPlan } from '@vistasecurity/primitives/features';

const state: { plan: TenantPlan | undefined; planLoading: boolean; billing: boolean } = vi.hoisted(() => ({
  plan: undefined,
  planLoading: false,
  billing: false,
}));

vi.mock('@vistasecurity/primitives/features', async (orig) => ({
  ...(await orig<typeof import('@vistasecurity/primitives/features')>()),
  usePlan: () => ({ plan: state.plan, isLoading: state.planLoading, isError: false }),
  useFeature: (name: string) => (name === 'billing_portal' ? state.billing : false),
}));
vi.mock('@vistasecurity/primitives/rbac', () => ({
  TENANT_PERMISSIONS: { billing: { update: 'billing.update', read: 'billing.read' } },
  PermissionGate: ({ children }: { children: unknown }) => children,
}));
vi.mock('./billing-modals', () => ({
  ChangePlanModal: () => null,
  CancelSubscriptionModal: () => null,
  usePortalSession: () => ({ mutateAsync: vi.fn(), isPending: false, error: null }),
  useReactivate: () => ({ mutate: vi.fn(), isPending: false, error: null }),
}));
vi.mock('../../lib/clients', () => ({ clients: { admin: { GET: vi.fn() }, auth: { GET: vi.fn() } } }));

const { BillingPage, usageFooter } = await import('./pages-account');

const meta = { key: 'billing', label: 'Billing account', icon: 'credit-card', job: 'job' };
const render = () =>
  renderToStaticMarkup(
    createElement(QueryClientProvider, { client: new QueryClient() }, createElement(BillingPage, { meta })),
  );

const enterprise: TenantPlan = { edition: 'enterprise', display_name: 'Vista Platform Enterprise', licensee: 'Acme Corp', expires_at: '2027-06-01T12:00:00Z' };

beforeEach(() => {
  state.plan = enterprise;
  state.planLoading = false;
  state.billing = false;
});

describe('Enterprise', () => {
  it('reads "Vista Platform Enterprise, provided by <licensee>"', () => {
    expect(render()).toContain('Vista Platform Enterprise, provided by Acme Corp');
  });
  it('shows no billing controls, no upgrade, and never says community or trial', () => {
    const html = render();
    expect(html).not.toContain('Invoices');
    expect(html).not.toContain('Manage subscription');
    expect(html.toLowerCase()).not.toContain('upgrade');
    expect(html.toLowerCase()).not.toContain('trial');
    expect(html.toLowerCase()).not.toContain('community');
  });
  it('shows no trial date even if one reaches the client — Enterprise has no trials', () => {
    state.plan = { ...enterprise, trial: { ends_at: '2026-10-10T12:00:00Z' } };
    expect(render().toLowerCase()).not.toContain('trial');
  });
});

describe('Core', () => {
  it('names the edition and says there is nothing to bill', () => {
    state.plan = { edition: 'core', display_name: 'Vista Platform Core', licensee: null, expires_at: null };
    const html = render();
    expect(html).toContain('Vista Platform Core');
    expect(html).toContain('no invoices');
    expect(html).not.toContain('Invoices');
  });
});

describe('MSP', () => {
  it('shows the MSP plan, its trial, and the billing controls when billing_portal is on', () => {
    state.plan = { edition: 'msp', display_name: 'Starter', licensee: 'Acme MSP', expires_at: null, trial: { ends_at: '2026-10-10T12:00:00Z' } };
    state.billing = true;
    const html = render();
    expect(html).toContain('Starter');
    expect(html).toContain('Trial ends Oct 10, 2026');
    expect(html).not.toContain('provided by');
    expect(html).toContain('Subscription');
    expect(html).toContain('Invoices');
  });
  it('hides the controls when the plan does not include billing_portal', () => {
    state.plan = { edition: 'msp', display_name: 'Basic', licensee: 'Acme MSP', expires_at: null };
    const html = render();
    expect(html).toContain('Basic');
    expect(html).not.toContain('Invoices');
    expect(html).not.toContain('Trial ends');
  });
});

describe('loading and error', () => {
  it('loading: a placeholder, no plan name', () => {
    state.planLoading = true;
    state.plan = undefined;
    const html = render();
    expect(html).toContain('data-testid="plan-loading"');
    expect(html).not.toContain('data-testid="plan-name"');
  });
  it('unresolved plan: the block is hidden, never a tier name', () => {
    state.plan = undefined;
    const html = render();
    expect(html).not.toContain('data-testid="plan-name"');
    expect(html).not.toContain('plan-loading');
  });
});

describe('Usage & Limits footer', () => {
  it('offers an upgrade only on MSP', () => {
    const end = '2026-10-01T12:00:00Z';
    expect(usageFooter(end, enterprise).toLowerCase()).not.toContain('upgrade');
    expect(usageFooter(end, undefined).toLowerCase()).not.toContain('upgrade');
    expect(usageFooter(end, { edition: 'msp', display_name: 'Basic', licensee: null, expires_at: null })).toContain('Upgrade for headroom');
  });
});
