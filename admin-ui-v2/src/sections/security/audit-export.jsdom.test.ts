// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';

const GET = vi.fn();
vi.mock('../../lib/clients', () => ({ clients: { audit: { GET: (...a: unknown[]) => GET(...a) } } }));

import { exportActivityLogs } from './audit-queries';

afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); GET.mockReset(); });

describe('exportActivityLogs', () => {
  it('passes the active scope and filters (but not paging) to the export endpoint', async () => {
    GET.mockResolvedValue({ data: '{"logs":[]}', error: undefined });
    URL.createObjectURL = vi.fn(() => 'blob:x');
    URL.revokeObjectURL = vi.fn();
    await exportActivityLogs('csv', {
      page: 3, page_size: 25, tenant_id: 'tenant-1', event_category: ['auth'],
      user_type: 'platform', search: 'login', impersonation: true,
    });
    expect(GET).toHaveBeenCalledWith('/activity-logs/export', expect.objectContaining({
      params: { query: {
        tenant_id: 'tenant-1', event_category: ['auth'], user_type: 'platform',
        search: 'login', impersonation: true, format: 'csv',
      } },
    }));
  });

  it('appends the anchor before clicking and revokes the URL on a timeout', async () => {
    vi.useFakeTimers();
    GET.mockResolvedValue({ data: 'a,b', error: undefined });
    URL.createObjectURL = vi.fn(() => 'blob:x');
    URL.revokeObjectURL = vi.fn();
    let attachedAtClick = false;
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      attachedAtClick = document.body.contains(this);
    });
    await exportActivityLogs('csv');
    expect(attachedAtClick).toBe(true);
    expect(URL.revokeObjectURL).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1000);
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:x');
  });
});
