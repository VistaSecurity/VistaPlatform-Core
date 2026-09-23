// @vitest-environment jsdom
//
// Settings ▸ License & Usage — the MSP usage panel, MOUNTED, in every state the
// spec's screen table names: default, empty, loading, error and success for the
// usage summary, the reports table and the Generate modal, plus the delivery
// status and the development-key warning.
//
// Mounts the real LicenseUsagePanel with only the data hooks (and the toast)
// stubbed, jsdom + React's own `act`, no testing-library (the staff page's
// pattern).
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { LicenseUsage, LicenseUsageReport } from './license-usage-queries';

type MutateOpts = { onSuccess?: (data: unknown) => void; onError?: (e: unknown) => void };
type QueryState = { data: unknown; isLoading: boolean; isError: boolean; error: unknown; refetch: () => void };

const state = vi.hoisted(() => {
  const idle = (): QueryState => ({ data: undefined, isLoading: false, isError: false, error: null, refetch: vi.fn() });
  return {
  usage: idle(),
  reports: idle(),
  generate: { isPending: false, mutate: vi.fn<(body: unknown, opts: MutateOpts) => void>() },
  download: vi.fn<(r: unknown) => Promise<void>>(),
  toastSuccess: vi.fn(),
  toastError: vi.fn(),
  };
});

vi.mock('react-hot-toast', () => ({
  default: { success: state.toastSuccess, error: state.toastError },
}));

vi.mock('./license-usage-queries', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./license-usage-queries')>();
  return {
    ...actual,
    useLicenseUsage: () => state.usage,
    useLicenseUsageReports: () => state.reports,
    useGenerateLicenseUsageReport: () => state.generate,
    downloadLicenseUsageReport: state.download,
  };
});

const { LicenseUsagePanel } = await import('./license-usage-panel');
const { NotMSPError } = await import('./license-usage-queries');

const NOW = new Date('2026-10-12T09:00:00Z');
const SIGNER_FINGERPRINT = 'a1b2c3d4e5f60718'.padEnd(64, '0');

const usage = (over: Partial<LicenseUsage> = {}): LicenseUsage => ({
  edition: 'msp',
  period: { start: '2026-10-01T00:00:00Z', end: '2026-11-01T00:00:00Z' },
  licensed_tenants: 50,
  current_tenants: 43,
  customer_tenants: 42,
  operator_tenants: 1,
  peak_tenants: 44,
  peak_at: '2026-10-03T00:15:00Z',
  snapshots_taken: 12,
  snapshots_expected: 12,
  last_snapshot_at: '2026-10-12T00:15:00Z',
  next_snapshot_at: '2026-10-13T00:15:00Z',
  next_report_at: '2026-11-01T00:15:00Z',
  install_id: '0b7e2c7e-6a8f-4d53-8d51-6f3f7f0d2a11',
  signing_key_id: SIGNER_FINGERPRINT,
  signing_key_dev: false,
  delivery: { configured: false },
  ...over,
});

const report = (over: Partial<LicenseUsageReport> = {}): LicenseUsageReport => ({
  report_id: '4f8e1c2a-7d1b-4e8a-9c55-2b1d0f6e9a10',
  period: '2026-09',
  period_start: '2026-09-01T00:00:00Z',
  period_end: '2026-10-01T00:00:00Z',
  complete: true,
  generated_at: '2026-10-01T00:15:03Z',
  generated_by: 'scheduler',
  tenant_count: 42,
  signing_key_id: SIGNER_FINGERPRINT,
  delivery_status: 'pending',
  delivery_attempts: 0,
  last_error: null,
  delivered_at: null,
  ...over,
});

let container: HTMLDivElement;
let root: Root;

function mount() {
  act(() => { root.render(<LicenseUsagePanel now={NOW} />); });
}
const text = () => container.textContent ?? '';
const byText = (tag: string, t: string) =>
  Array.from(container.querySelectorAll(tag)).find((el) => el.textContent?.includes(t)) as HTMLElement | undefined;
const dialog = () => document.body.querySelector('[role="dialog"]');

beforeEach(() => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  state.usage = { data: usage(), isLoading: false, isError: false, error: null, refetch: vi.fn() };
  state.reports = {
    data: { reports: [report()], available: true, edition: 'msp', delivery: { configured: false } },
    isLoading: false, isError: false, error: null, refetch: vi.fn(),
  };
  state.generate = { isPending: false, mutate: vi.fn() };
  state.download.mockReset().mockResolvedValue(undefined);
  state.toastSuccess.mockReset();
  state.toastError.mockReset();
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

describe('usage summary', () => {
  it('default: licensed, current (operator broken out), peak and snapshot coverage, all in UTC', () => {
    mount();
    expect(text()).toContain('Licence usage');
    expect(text()).toContain('October 2026 (UTC)');
    expect(text()).toContain('Licensed tenants');
    expect(text()).toContain('50');
    expect(text()).toContain('42 customer · 1 operator');
    expect(text()).toContain('44');
    expect(text()).toContain('at 2026-10-03 00:15 UTC');
    expect(text()).toContain('12 / 12');
    expect(text()).toContain('0b7e2c7e-6a8f-4d53-8d51-6f3f7f0d2a11');
    expect(text()).toContain('a1b2 c3d4 e5f6 0718');
    expect(text()).not.toContain('development key');
  });

  it('default without a cap: says so instead of a number', () => {
    state.usage.data = usage({ licensed_tenants: null });
    mount();
    expect(text()).toContain('No cap');
  });

  it('empty: zero tenants shows zeros with an explainer', () => {
    state.usage.data = usage({ current_tenants: 0, customer_tenants: 0, operator_tenants: 0, peak_tenants: 0, peak_at: null });
    mount();
    expect(text()).toContain('No tenants yet');
    expect(text()).toContain('No snapshot yet this period');
  });

  it('loading: skeleton, no numbers', () => {
    state.usage = { ...state.usage, data: undefined, isLoading: true };
    mount();
    expect(container.querySelectorAll('[data-testid="skeleton"]').length).toBeGreaterThanOrEqual(4);
    expect(text()).not.toContain('Licensed tenants');
  });

  it('error: inline message and a Retry that refetches', () => {
    state.usage = { ...state.usage, data: undefined, isError: true, error: new Error('Could not read licence usage') };
    mount();
    expect(text()).toContain('Could not read licence usage');
    act(() => { byText('button', 'Retry')!.click(); });
    expect(state.usage.refetch).toHaveBeenCalledTimes(1);
  });

  it('not an MSP licence: an explanation, not a Retry', () => {
    state.usage = { ...state.usage, data: undefined, isError: true, error: new NotMSPError() };
    mount();
    expect(text()).toContain('MSP licences only');
    expect(byText('button', 'Retry')).toBeUndefined();
  });

  it('warns when reports are signed with a development key', () => {
    state.usage.data = usage({ signing_key_dev: true });
    mount();
    expect(text()).toContain('signed with a development key');
  });
});

describe('reports table', () => {
  it('default: period, generated, tenants, fingerprint, "Not configured" delivery and Download', async () => {
    state.reports.data = {
      reports: [report(), report({ report_id: 'b0000000-0000-4000-8000-000000000002', period: '2026-10', complete: false, generated_by: 'platform_user:x' })],
      available: true, edition: 'msp', delivery: { configured: false },
    };
    mount();
    expect(text()).toContain('September 2026');
    expect(text()).toContain('2026-10-01 00:15 UTC');
    expect(text()).toContain('Monthly schedule');
    expect(text()).toContain('On demand');
    expect(text()).toContain('Preview');
    expect(text()).toContain('Not configured');
    expect(text()).not.toContain('Pending');
    expect(text()).toContain('a1b2 c3d4 e5f6 0718');

    await act(async () => { byText('button', 'Download')!.click(); });
    expect(state.download).toHaveBeenCalledWith(expect.objectContaining({ report_id: '4f8e1c2a-7d1b-4e8a-9c55-2b1d0f6e9a10' }));
  });

  it('delivery statuses render once delivery is configured', () => {
    state.reports.data = {
      reports: [
        report({ delivery_status: 'delivered' }),
        report({ report_id: 'c0000000-0000-4000-8000-000000000003', delivery_status: 'failed', last_error: 'receiver said 422' }),
      ],
      available: true, edition: 'msp', delivery: { configured: true },
    };
    mount();
    expect(text()).toContain('Delivered');
    expect(text()).toContain('Failed');
    expect(text()).not.toContain('Not configured');
  });

  it('empty: says when the first report comes', () => {
    state.reports.data = { reports: [], available: true, edition: 'msp', delivery: { configured: false } };
    mount();
    expect(text()).toContain('No reports yet — the first is generated on the 1st of next month.');
  });

  it('loading: skeleton rows', () => {
    state.reports = { ...state.reports, data: undefined, isLoading: true };
    mount();
    expect(container.querySelectorAll('[data-testid="skeleton-row"]').length).toBe(3);
  });

  it('error: inline error with Retry', () => {
    state.reports = { ...state.reports, data: undefined, isError: true, error: new Error('Could not list usage reports') };
    mount();
    expect(text()).toContain('Could not list usage reports');
    act(() => { Array.from(container.querySelectorAll('button')).filter((b) => b.textContent?.includes('Retry')).pop()!.click(); });
    expect(state.reports.refetch).toHaveBeenCalledTimes(1);
  });

  it('a failed download is a toast, not a crash', async () => {
    state.download.mockRejectedValue(new Error('Download failed'));
    mount();
    await act(async () => { byText('button', 'Download')!.click(); });
    expect(state.toastError).toHaveBeenCalledWith('Download failed');
  });
});

describe('generate report modal', () => {
  function openModal() {
    mount();
    act(() => { byText('button', 'Generate report')!.click(); });
    expect(dialog()).not.toBeNull();
  }
  const select = () => dialog()!.querySelector('select') as HTMLSelectElement;
  const primary = () => Array.from(dialog()!.querySelectorAll('button')).find((b) => /Generate|Saving/.test(b.textContent ?? ''))!;

  it('default: closed months plus the current month marked preview; the last closed month is preselected', () => {
    openModal();
    const options = Array.from(select().options).map((o) => o.textContent);
    expect(options[0]).toBe('October 2026 — month to date (preview)');
    expect(options[1]).toBe('September 2026');
    expect(options[options.length - 1]).toBe('January 2026'); // nothing before metering existed
    expect(select().value).toBe('2026-09');
  });

  it('a closed month is generated as complete; success closes with a toast', () => {
    openModal();
    act(() => { primary().click(); });
    expect(state.generate.mutate).toHaveBeenCalledWith({ period: '2026-09', complete: true }, expect.anything());
    const opts = state.generate.mutate.mock.calls[0][1];
    act(() => { opts.onSuccess?.({ created: true, report: report() }); });
    expect(state.toastSuccess).toHaveBeenCalledWith('Report for September 2026 generated');
    expect(dialog()).toBeNull();
  });

  it('the current month is generated as a never-billed preview', () => {
    openModal();
    act(() => {
      const s = select();
      const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')!.set!;
      setter.call(s, '2026-10');
      s.dispatchEvent(new Event('change', { bubbles: true }));
    });
    expect(dialog()!.textContent).toContain('never billed');
    act(() => { primary().click(); });
    expect(state.generate.mutate).toHaveBeenCalledWith({ period: '2026-10', complete: false }, expect.anything());
  });

  it('an existing complete report is reported as unchanged', () => {
    openModal();
    act(() => { primary().click(); });
    act(() => { state.generate.mutate.mock.calls[0][1].onSuccess?.({ created: false, report: report() }); });
    expect(state.toastSuccess).toHaveBeenCalledWith('The September 2026 report already exists — it is unchanged');
  });

  it('loading: the primary button spins and is disabled', () => {
    state.generate = { isPending: true, mutate: vi.fn() };
    openModal();
    expect(primary().textContent).toContain('Saving');
    expect(primary().disabled).toBe(true);
  });

  it('error: the server message stays in the modal', () => {
    openModal();
    act(() => { primary().click(); });
    act(() => { state.generate.mutate.mock.calls[0][1].onError?.(new Error('The current month is not over')); });
    expect(dialog()).not.toBeNull();
    expect(dialog()!.textContent).toContain('The current month is not over');
    expect(state.toastSuccess).not.toHaveBeenCalled();
  });
});
