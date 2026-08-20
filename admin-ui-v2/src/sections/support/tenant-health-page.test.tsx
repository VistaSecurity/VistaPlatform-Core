import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { TenantHealthDrawer, TenantHealthPage } from './tenant-health-page';
import type { TenantHealth, TenantHealthSummary } from './support-queries';

const queryState = vi.hoisted(() => ({
  list: {
    data: [] as TenantHealthSummary[],
    isLoading: false,
    isError: false,
    refetch: vi.fn(),
  },
  detail: {
    data: undefined as TenantHealth | undefined,
    isLoading: false,
    isError: false,
  },
  alerts: {
    data: [],
    isLoading: false,
  },
}));

vi.mock('./support-queries', () => ({
  useTenantHealthList: () => queryState.list,
  useTenantHealthDetail: () => queryState.detail,
  useTenantHealthAlerts: () => queryState.alerts,
}));

const now = '2026-08-20T05:00:00.000Z';
const tenantId = '11111111-1111-4111-8111-111111111111';

const summary = (overrides: Partial<TenantHealthSummary> = {}): TenantHealthSummary => ({
  tenant_id: tenantId,
  tenant_name: 'Acme Manufacturing',
  overall_score: 0,
  health_status: 'unknown',
  last_calculated: now,
  trend_direction: '',
  critical_alerts: 0,
  recommendations: 0,
  ...overrides,
});

const detail = (overrides: Partial<TenantHealth> = {}): TenantHealth => ({
  id: '22222222-2222-4222-8222-222222222222',
  tenant_id: tenantId,
  overall_score: 0,
  health_status: 'unknown',
  last_calculated: now,
  score_breakdown: {
    resource_efficiency: null,
    performance_metrics: null,
    security_posture: null,
    business_activity: null,
    cost_optimization: null,
    unavailable_sources: ['monitoring-service', 'auth-service'],
    data_completeness: 0,
  },
  recommendations: [],
  trends: {
    score_history: [],
    trend_direction: '',
    trend_strength: 0,
    predicted_score: 0,
  },
  created_at: now,
  updated_at: now,
  ...overrides,
});

describe('TenantHealthPage unknown health rendering', () => {
  beforeEach(() => {
    queryState.list = {
      data: [],
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    };
    queryState.detail = {
      data: undefined,
      isLoading: false,
      isError: false,
    };
    queryState.alerts = {
      data: [],
      isLoading: false,
    };
  });

  it('renders an unknown summary score as no data instead of zero', () => {
    queryState.list.data = [summary()];

    const html = renderToStaticMarkup(createElement(TenantHealthPage));

    expect(html).toContain('Acme Manufacturing');
    expect(html).toContain('title="No health factor could be measured">—</span>');
    expect(html).toContain('Unknown');
    expect(html).not.toContain('font-weight:700;color:var(--danger)">0</span>');
  });

  it('renders nullable breakdown factors as unavailable and explains partial data', () => {
    queryState.detail.data = detail({
      overall_score: 72,
      health_status: 'fair',
      score_breakdown: {
        resource_efficiency: null,
        performance_metrics: 80,
        security_posture: 70,
        business_activity: 66,
        cost_optimization: null,
        unavailable_sources: ['resource-tracker-service'],
        data_completeness: 0.6,
      },
    });

    const html = renderToStaticMarkup(
      createElement(TenantHealthDrawer, {
        summary: summary({ overall_score: 72, health_status: 'fair' }),
        onClose: vi.fn(),
      }),
    );

    expect(html).toContain('Unavailable');
    expect(html).toContain('Some factors could not be measured');
    expect(html).toContain('resource-tracker-service');
    expect(html).toContain('score reflects 60% of the factor weight');
  });
});
