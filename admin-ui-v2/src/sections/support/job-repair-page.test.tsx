// Support ▸ Job Repair: listing jobs needs platform.health (the sub-view's
// gate); retrying or cancelling one needs tenants.manage, which is what
// device-interrogation-service enforces on POST /admin/jobs/:id/retry|cancel.
// A role without it must not be offered buttons the server will 403.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

const state = vi.hoisted(() => ({ perms: new Set<string>() }));

vi.mock('@vistasecurity/primitives/platform-auth', () => ({
  PLATFORM_PERMISSIONS: { tenants: { manage: 'tenants.manage' } },
  usePlatformPermissions: () => ({ hasPermission: (p: string) => state.perms.has(p) }),
}));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));
vi.mock('./support-queries', () => ({
  useAdminJobs: () => ({
    data: [
      { id: 'j1', status: 'failed', job_type: 'interrogate', tenant_name: 'Acme', created_at: '2026-09-01T00:00:00Z' },
      { id: 'j2', status: 'pending', job_type: 'interrogate', tenant_name: 'Acme', created_at: '2026-09-01T00:00:00Z' },
    ],
    isLoading: false,
    isError: false,
    refetch: vi.fn(),
  }),
  useJobRepairMutations: () => ({
    retry: { mutate: vi.fn(), isPending: false },
    cancel: { mutate: vi.fn(), isPending: false },
  }),
  errMsg: (e: unknown) => String(e),
}));

import { JobRepairPage } from './job-repair-page';

const render = () => renderToStaticMarkup(createElement(JobRepairPage));

beforeEach(() => {
  state.perms = new Set();
});

describe('Job Repair actions', () => {
  it('offers Retry and Cancel to a role holding tenants.manage', () => {
    state.perms = new Set(['tenants.manage']);
    const html = render();
    expect(html).toContain('Retry');
    expect(html).toContain('Cancel');
    expect(html).not.toContain('Read-only');
  });

  it('offers neither without tenants.manage, and says why', () => {
    const html = render();
    expect(html).not.toMatch(/<button[^>]*>.*Retry/);
    expect(html).not.toMatch(/<button[^>]*>.*Cancel/);
    expect(html).toContain('Read-only');
    expect(html).toContain('tenants.manage');
  });
});
