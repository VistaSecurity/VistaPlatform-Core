import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { OverviewPage } from './overview-page';
import type { Tenant, TenantHealthSummary } from '../tenants/queries';

const state = vi.hoisted(() => ({
  tenants: [] as Tenant[],
  health: new Map<string, TenantHealthSummary>(),
  // The ee build mounts both msp and billing on every paid install; what
  // differs is the licence.
  license: 'enterprise',
  // The billing dashboard (the only billing read on this page) plus the
  // monitoring status's `services`, merged: the mock answers every query.
  dash: { billing_configured: true, mrr: 12000, paying_tenants: 4 } as Record<string, unknown>,
}));

vi.mock('@tanstack/react-query', () => ({
  useQuery: () => ({ data: { services: [], ...state.dash } }),
}));

vi.mock('../../lib/edition', () => ({
  usePlatformEdition: () => ({
    has: () => true,
    resolved: true,
    edition: 'enterprise',
    license: state.license,
    isMsp: state.license === 'msp',
  }),
}));

vi.mock('../tenants/queries', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../tenants/queries')>();
  return {
    ...actual,
    useTenants: () => ({ data: state.tenants }),
    useTenantHealthMap: () => ({ data: state.health }),
  };
});

const now = '2026-09-17T12:00:00.000Z';

function tenant(id: string, name: string, overrides: Partial<Tenant> = {}): Tenant {
  return {
    id,
    name,
    slug: id,
    domain: null,
    subscription_tier: 'Guardian',
    subscription_tier_id: '11111111-1111-4111-8111-111111111111',
    trial_ends_at: null,
    billing_email: `${id}@example.test`,
    payment_status: 'active',
    stripe_customer_id: null,
    sso_enabled: false,
    is_active: true,
    is_operator: false,
    custom_branding: null,
    ui_config: null,
    settings: null,
    created_at: now,
    updated_at: now,
    deleted_at: null,
    ...overrides,
  };
}

function health(tenantId: string, score: number, status: TenantHealthSummary['health_status']): TenantHealthSummary {
  return {
    tenant_id: tenantId,
    tenant_name: tenantId,
    overall_score: score,
    health_status: status,
    last_calculated: now,
    trend_direction: 'stable',
    active_alerts: 0,
    critical_alerts: 0,
    recommendations: 0,
  };
}

function renderOverview(): string {
  return renderToStaticMarkup(createElement(MemoryRouter, null, createElement(OverviewPage)));
}

describe('OverviewPage tenant attention policy', () => {
  beforeEach(() => {
    state.tenants = [];
    state.health = new Map();
    state.license = 'msp';
  });

  it('excludes unknown score zero while retaining a measured zero', () => {
    state.tenants = [
      tenant('unknown-zero', 'Unknown Zero'),
      tenant('measured-zero', 'Measured Zero'),
    ];
    state.health = new Map([
      ['unknown-zero', health('unknown-zero', 0, 'unknown')],
      ['measured-zero', health('measured-zero', 0, 'failing')],
    ]);

    const html = renderOverview();

    expect(html).not.toContain('Unknown Zero');
    expect(html).toContain('Measured Zero');
    expect(html).toContain('0/100 · Failing');
  });

  it('keeps suspended and past-due tenants independent of unavailable health', () => {
    state.tenants = [
      tenant('suspended', 'Suspended Tenant', { is_active: false }),
      tenant('past-due', 'Past Due Tenant', { payment_status: 'past_due' }),
    ];
    state.health = new Map([
      ['suspended', health('suspended', 0, 'unknown')],
      ['past-due', health('past-due', 0, 'unknown')],
    ]);

    const html = renderOverview();

    expect(html).toContain('Suspended Tenant');
    expect(html).toContain('Past Due Tenant');
  });

  it('applies the existing measured-health boundary at 54 included and 55 excluded', () => {
    state.tenants = [
      tenant('score-54', 'Score Fifty Four'),
      tenant('score-55', 'Score Fifty Five'),
    ];
    state.health = new Map([
      ['score-54', health('score-54', 54, 'poor')],
      ['score-55', health('score-55', 55, 'poor')],
    ]);

    const html = renderOverview();

    expect(html).toContain('Score Fifty Four');
    expect(html).not.toContain('Score Fifty Five');
  });
});

// Billing is MSP-only by licence, and the Enterprise ee binary mounts the
// billing routes too — so Mission Control must gate its billing surfaces on
// the licence, not on the build capability.
describe('OverviewPage billing surfaces by licence', () => {
  beforeEach(() => {
    state.tenants = [
      tenant('past-due', 'Past Due Tenant', { payment_status: 'past_due' }),
      tenant('fine', 'Fine Tenant'),
    ];
    state.health = new Map();
  });

  it('Enterprise: no revenue hero, no past-due tile, no past-due attention row', () => {
    state.license = 'enterprise';
    const html = renderOverview();
    expect(html).not.toContain('Recurring revenue');
    expect(html).not.toContain('MRR');
    expect(html).not.toContain('Past-due tenants');
    expect(html).not.toContain('Past Due Tenant');
    // The Core and MSP-directory tiles stay.
    expect(html).toContain('Suspended');
    expect(html).toContain('Total tenants');
    expect(html).toContain('Services needing attention');
  });

  it('Core licence on the ee build: same as Enterprise', () => {
    state.license = 'core';
    const html = renderOverview();
    expect(html).not.toContain('Recurring revenue');
    expect(html).not.toContain('Past-due tenants');
  });

  it('MSP: revenue hero and past-due tile shown', () => {
    state.license = 'msp';
    const html = renderOverview();
    expect(html).toContain('Recurring revenue');
    expect(html).toContain('Past-due tenants');
    expect(html).toContain('Past Due Tenant');
  });
});

// Owner decision 5: revenue comes only from billing records. No payment
// provider → "Billing not configured", never a number; and there is no
// "trailing" MRR series (it was today's figure projected backwards).
describe('OverviewPage revenue hero', () => {
  beforeEach(() => {
    state.tenants = [];
    state.health = new Map();
    state.license = 'msp';
  });

  it('shows MRR, ARR and paying tenants from the billing records', () => {
    state.dash = { billing_configured: true, mrr: 12000, paying_tenants: 4 };
    const html = renderOverview();
    expect(html).toContain('$12k');
    expect(html).toContain('$144k ARR · 4 paying');
    expect(html).not.toContain('Billing not configured');
    expect(html).not.toContain('trailing');
  });

  it('says "Billing not configured" and shows no figure without a payment provider', () => {
    state.dash = { billing_configured: false, mrr: null, paying_tenants: null };
    const html = renderOverview();
    expect(html).toContain('Recurring revenue');
    expect(html).toContain('Billing not configured');
    expect(html).not.toMatch(/\$\d/);
    expect(html).not.toContain('ARR');
    expect(html).not.toContain('trailing');
  });
});
