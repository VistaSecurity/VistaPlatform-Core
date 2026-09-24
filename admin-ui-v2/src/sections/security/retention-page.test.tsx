// Security ▸ Retention (security-staff-16, admin-ui review decision 14).
//
// The "Cold storage" field is gone — it was stored and shown but never used —
// and the ages follow the rule audit-service now enforces: whole days, both at
// least 1, total not shorter than hot. The form disables Save and shows why
// rather than sending a policy the server will refuse with a 400.
import { describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

vi.mock('@vistasecurity/primitives/platform-auth', () => ({
  PLATFORM_PERMISSIONS: { platform: { auditManage: 'platform.audit.manage' } },
  PlatformPermissionGate: ({ children }: { children: unknown }) => children,
}));

const policies = vi.hoisted(() => ({
  list: [
    {
      id: '44444444-4444-4444-8444-444444444444', policy_name: 'Default audit retention',
      hot_storage_days: 30, total_retention_days: 365, is_active: true,
      created_at: '2026-09-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z',
    },
  ],
}));

vi.mock('./audit-queries', () => ({
  useRetentionPolicies: () => ({ data: policies.list, isLoading: false, isError: false, refetch: vi.fn() }),
  useRetentionMutations: () => ({ create: { mutate: vi.fn(), isPending: false }, update: { mutate: vi.fn(), isPending: false } }),
  errMsg: (e: unknown) => String(e),
}));

vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));

import { RetentionModal, RetentionPage, retentionFormError } from './retention-page';

const mut = { create: { mutate: vi.fn(), isPending: false }, update: { mutate: vi.fn(), isPending: false } } as never;

describe('retentionFormError', () => {
  const cases: Array<[number, number, string | null]> = [
    [30, 365, null],
    [1, 1, null],
    [30, 30, null],
    [0, 365, 'Hot storage must be at least 1 day.'],
    [-3, 365, 'Hot storage must be at least 1 day.'],
    [30, 0, 'Total retention must be at least 1 day.'],
    [30, -1, 'Total retention must be at least 1 day.'],
    [1.5, 365, 'Hot storage must be at least 1 day.'],
    [90, 30, 'Total retention cannot be shorter than hot storage.'],
  ];
  for (const [hot, total, want] of cases) {
    it(`hot ${hot}, total ${total} → ${want ?? 'valid'}`, () => {
      expect(retentionFormError({ hot_storage_days: hot, total_retention_days: total })).toBe(want);
    });
  }
});

function saveButton(html: string): string {
  return (html.match(/<button[^>]*>[^<]*(?:Save|Create)<\/button>/g) ?? [])[0] ?? '';
}

describe('Retention policy form', () => {
  it('has no cold-storage field', () => {
    const html = renderToStaticMarkup(createElement(RetentionModal, { policy: null, onClose: () => {}, mut }));
    expect(html).not.toMatch(/cold/i);
    expect(html).toContain('Hot storage (days)');
    expect(html).toContain('Total retention (days)');
  });

  it('allows saving a valid policy', () => {
    const html = renderToStaticMarkup(createElement(RetentionModal, { policy: policies.list[0], onClose: () => {}, mut }));
    expect(html).not.toContain('role="alert"');
    expect(saveButton(html)).toContain('Save');
    expect(saveButton(html)).not.toContain('disabled');
  });

  it('blocks saving a stored policy whose total is 0, and says why', () => {
    const bad = { ...policies.list[0], total_retention_days: 0 };
    const html = renderToStaticMarkup(createElement(RetentionModal, { policy: bad, onClose: () => {}, mut }));
    expect(html).toContain('Total retention must be at least 1 day.');
    expect(saveButton(html)).toContain('disabled');
  });
});

describe('Retention policy list', () => {
  it('shows Hot and Total, and no Cold column', () => {
    const html = renderToStaticMarkup(createElement(RetentionPage));
    const headers = Array.from(html.matchAll(/<th>([^<]*)<\/th>/g), (m) => m[1]).filter(Boolean);
    expect(headers).toEqual(['Policy', 'Scope', 'Hot', 'Total', 'Status']);
    expect(html).toContain('30d');
    expect(html).toContain('365d');
  });
});
