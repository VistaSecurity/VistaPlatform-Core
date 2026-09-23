// Settings ▸ License & Usage — the query layer: the not-MSP answer becomes a
// typed error (so the panel explains instead of offering Retry), server
// messages survive, a download keeps the stored bytes (parseAs blob), and the
// Generate modal offers exactly the periods the backend accepts.
import { beforeEach, describe, expect, it, vi } from 'vitest';

const admin = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { admin } }));

const q = await import('./license-usage-queries');

beforeEach(() => {
  admin.GET.mockReset();
  admin.POST.mockReset();
});

describe('fetchers', () => {
  it('maps the 404 not_msp answer to NotMSPError', async () => {
    admin.GET.mockResolvedValue({ error: { error: 'Usage reporting is available only under an active MSP licence.', reason: 'not_msp', edition: 'enterprise' } });
    await expect(q.fetchLicenseUsage()).rejects.toBeInstanceOf(q.NotMSPError);
    admin.POST.mockResolvedValue({ error: { error: 'x', reason: 'not_msp', edition: 'core' } });
    await expect(q.generateLicenseUsageReport({ period: '2026-09' })).rejects.toBeInstanceOf(q.NotMSPError);
  });

  it('keeps the server message for any other failure', async () => {
    admin.POST.mockResolvedValue({ error: { error: 'The current month is not over: generate a month-to-date preview (complete: false) instead.' } });
    const err = await q.generateLicenseUsageReport({ period: '2026-10', complete: true }).catch((e: unknown) => e);
    expect(err).not.toBeInstanceOf(q.NotMSPError);
    expect((err as Error).message).toContain('The current month is not over');
    admin.GET.mockResolvedValue({ error: {} });
    await expect(q.fetchLicenseUsageReports()).rejects.toThrow('Could not load usage reports');
  });

  it('posts the period and completeness as given', async () => {
    admin.POST.mockResolvedValue({ data: { created: true, report: { report_id: 'r' } } });
    await q.generateLicenseUsageReport({ period: '2026-09', complete: true });
    expect(admin.POST).toHaveBeenCalledWith('/admin/license/reports', { body: { period: '2026-09', complete: true } });
  });

  it('downloads the stored document as a blob, named <report_id>.json', async () => {
    const blob = new Blob(['{"format":"vista.license-usage-report"}'], { type: 'application/json' });
    admin.GET.mockResolvedValue({ data: blob, response: { ok: true } });
    const clicks: string[] = [];
    const anchor = { href: '', download: '', click: () => clicks.push(anchor.download), remove: vi.fn() };
    vi.stubGlobal('document', { createElement: () => anchor, body: { appendChild: vi.fn() } });
    vi.stubGlobal('URL', { createObjectURL: () => 'blob:x', revokeObjectURL: vi.fn() });
    try {
      await q.downloadLicenseUsageReport({ report_id: '4f8e1c2a-7d1b-4e8a-9c55-2b1d0f6e9a10' });
    } finally {
      vi.unstubAllGlobals();
    }
    expect(admin.GET).toHaveBeenCalledWith('/admin/license/reports/{id}/download', {
      params: { path: { id: '4f8e1c2a-7d1b-4e8a-9c55-2b1d0f6e9a10' } },
      parseAs: 'blob',
    });
    expect(clicks).toEqual(['4f8e1c2a-7d1b-4e8a-9c55-2b1d0f6e9a10.json']);
  });
});

describe('selectablePeriods', () => {
  it('offers the current UTC month as a preview, then closed months, newest first', () => {
    const p = q.selectablePeriods(new Date('2026-10-12T09:00:00Z'), 3);
    expect(p.map((x) => [x.value, x.preview])).toEqual([['2026-10', true], ['2026-09', false], ['2026-08', false]]);
  });

  it('uses the UTC month, not the local one, at a month boundary', () => {
    // 20:00 on Sep 30 in UTC-8 is already October in UTC.
    expect(q.selectablePeriods(new Date('2026-10-01T03:00:00Z'), 1)[0].value).toBe('2026-10');
    expect(q.utcMonth(new Date('2026-09-30T23:59:59Z'))).toBe('2026-09');
  });

  it('stops at January 2026: nothing earlier was metered', () => {
    const p = q.selectablePeriods(new Date('2026-03-05T00:00:00Z'), 12);
    expect(p.map((x) => x.value)).toEqual(['2026-03', '2026-02', '2026-01']);
  });

  it('crosses a year boundary', () => {
    expect(q.selectablePeriods(new Date('2027-01-02T00:00:00Z'), 2).map((x) => x.value)).toEqual(['2027-01', '2026-12']);
  });
});
