// @vitest-environment jsdom
// The Active Scan dialog — what Discovery → Active Scan did, now for a
// selection: Run from reaches the request, the outside-your-networks question
// is asked, and "Scan anyway" resends ONLY the assets it asked about. The
// retired page resent every asset, including ones a partial first pass had
// already dispatched (C.4).
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi, type Mock } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const mocks = vi.hoisted(() => ({ post: vi.fn(), toastError: vi.fn(), toastSuccess: vi.fn(), sensors: { current: [] as unknown[] } }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: { POST: mocks.post, GET: vi.fn() } } }));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: mocks.toastError, success: mocks.toastSuccess }) }));
vi.mock('react-router', () => ({ Link: ({ children }: { children: ReactNode }) => <a>{children}</a> }));
vi.mock('../discovery/queries', () => ({ useSensors: () => ({ data: mocks.sensors.current, isLoading: false, isError: false }) }));
vi.mock('../../components/ui', () => ({
  Icon: () => null,
  Modal: ({ open, children, primary, secondary, footerNote }: { open: boolean; children: ReactNode; primary: ReactNode; secondary: ReactNode; footerNote?: ReactNode }) =>
    open ? <div data-testid="modal">{children}{footerNote}{secondary}{primary}</div> : null,
}));

import { ScanDialog, confirmSelection, scanBody } from './scan-dialog';
import type { AssetSelection } from './asset-selection';
import type { ActiveScanResponse } from '../discovery/active-scan-run-from';

const STARTED = { data: { message: 'Active scan started', job_id: 'job-1', count: 1, jobs: [{ job_id: 'job-1', executor: 'platform', count: 1 }], skipped: [] }, response: { ok: true, status: 200 } };
// Two of three assets dispatched before the third was asked about.
const ASK_AFTER_PARTIAL = {
  error: {
    error: 'external_targets_unconfirmed',
    details: '1 asset(s) are outside your registered networks (partner-portal); confirm to scan them',
    external_targets: [{ target: '93.184.216.34', addresses: ['93.184.216.34'], asset_id: 'asset-ext', asset_name: 'partner-portal' }],
    job_id: 'job-0', count: 2, jobs: [{ job_id: 'job-0', executor: 'platform', count: 2 }], skipped: [],
  },
  response: { ok: false, status: 422 },
};

let host: HTMLDivElement;
let root: Root;
let onStarted: Mock<(r: ActiveScanResponse) => void>;
let onClose: Mock<() => void>;
beforeEach(() => {
  mocks.post.mockReset(); mocks.toastError.mockReset(); mocks.toastSuccess.mockReset();
  mocks.sensors.current = [];
  onStarted = vi.fn<(r: ActiveScanResponse) => void>(); onClose = vi.fn<() => void>();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

async function render(selection: AssetSelection) {
  const qc = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
  await act(async () => {
    root.render(<QueryClientProvider client={qc}><ScanDialog open selection={selection} onClose={onClose} onStarted={onStarted} /></QueryClientProvider>);
  });
}
const button = (re: RegExp) => [...host.querySelectorAll('button')].find((b) => re.test(b.textContent?.trim() ?? ''));
async function click(re: RegExp) {
  const b = button(re);
  if (!b) throw new Error(`no ${re} button in: ${host.textContent}`);
  await act(async () => { b.click(); });
}
const sent = (i: number) => (mocks.post.mock.calls[i][1] as { body: Record<string, unknown> }).body;

it('sends a query selection with its confirmed count and the executor', async () => {
  mocks.post.mockResolvedValueOnce(STARTED);
  await render({ kind: 'query', query: 'environment:staging', count: 12 });
  expect(host.textContent).toContain('Scan 12 assets');
  await click(/^Scan 12 assets$/);
  await vi.waitFor(() => expect(mocks.post).toHaveBeenCalledTimes(1));
  // No tenant sensors: the platform sensor is the only (and default) executor.
  expect(sent(0)).toEqual({ query: 'environment:staging', expected_count: 12, run_from: 'platform' });
  await vi.waitFor(() => expect(onStarted).toHaveBeenCalled());
  expect(onClose).toHaveBeenCalled();
});

it('asks about the external asset, keeps the jobs that did start, and resends ONLY the asked-about asset', async () => {
  mocks.post.mockResolvedValueOnce(ASK_AFTER_PARTIAL).mockResolvedValueOnce(STARTED);
  await render({ kind: 'ids', ids: new Set(['asset-1', 'asset-2', 'asset-ext']) });
  await click(/^Scan 3 assets$/);
  await vi.waitFor(() => expect(host.querySelector('[role="alertdialog"]')).not.toBeNull());
  expect(host.textContent).toContain('partner-portal (93.184.216.34)');
  expect(sent(0)).not.toHaveProperty('external_targets_confirmed');
  // The two dispatched before the question are reported, not dropped.
  expect(onStarted).toHaveBeenCalledWith(expect.objectContaining({ jobs: [expect.objectContaining({ job_id: 'job-0' })] }));

  await click(/^Scan anyway$/);
  await vi.waitFor(() => expect(mocks.post).toHaveBeenCalledTimes(2));
  expect(sent(1)).toEqual({ asset_ids: ['asset-ext'], run_from: 'platform', external_targets_confirmed: true });
});

it('Cancel on the question scans nothing more', async () => {
  mocks.post.mockResolvedValueOnce(ASK_AFTER_PARTIAL);
  await render({ kind: 'ids', ids: new Set(['asset-ext']) });
  await click(/^Scan 1 asset$/);
  await vi.waitFor(() => expect(host.querySelector('[role="alertdialog"]')).not.toBeNull());
  await click(/^Cancel$/);
  expect(mocks.post).toHaveBeenCalledTimes(1);
  expect(onClose).toHaveBeenCalled();
});

it('explains a refused confirmation instead of asking again', async () => {
  mocks.post
    .mockResolvedValueOnce(ASK_AFTER_PARTIAL)
    .mockResolvedValueOnce({ error: { error: 'insufficient_permissions', details: 'Scanning assets outside your registered networks also needs the discovery.create permission' }, response: { ok: false, status: 403 } });
  await render({ kind: 'ids', ids: new Set(['asset-ext']) });
  await click(/^Scan 1 asset$/);
  await vi.waitFor(() => expect(host.querySelector('[role="alertdialog"]')).not.toBeNull());
  await click(/^Scan anyway$/);
  await vi.waitFor(() => expect(host.textContent).toContain('also needs the discovery.create permission'));
  expect(mocks.post).toHaveBeenCalledTimes(2);
});

it('says the query now matches more than was confirmed, and scans nothing', async () => {
  mocks.post.mockResolvedValueOnce({ error: { error: 'selection_changed', expected_count: 12, count: 15 }, response: { ok: false, status: 409 } });
  await render({ kind: 'query', query: '', count: 12 });
  await click(/^Scan 12 assets$/);
  await vi.waitFor(() => expect(host.textContent).toContain('now matches 15 assets, more than the 12 you confirmed'));
  expect(onStarted).not.toHaveBeenCalled();
});

it('will not send a selection over the scan cap', async () => {
  await render({ kind: 'query', query: '', count: 1001 });
  expect(button(/^Scan 1,001 assets$/)?.disabled).toBe(true);
  expect(host.querySelector('[role="alert"]')?.textContent).toMatch(/at most 1,000/);
});

it('offers Auto and the tenant sensors once they load, and sends the named sensor', async () => {
  mocks.sensors.current = [{ id: 's-1', name: 'branch-sensor', status: 'online', last_heartbeat: new Date().toISOString(), tags: [] }];
  mocks.post.mockResolvedValueOnce(STARTED);
  await render({ kind: 'ids', ids: new Set(['asset-1']) });
  const select = host.querySelector('select[aria-label="Run from"]') as HTMLSelectElement;
  expect([...select.options].map((o) => o.value)).toEqual(['auto', 'platform', 'sensor:s-1']);
  expect(select.value).toBe('auto');
  await act(async () => {
    select.value = 'sensor:s-1';
    select.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await click(/^Scan 1 asset$/);
  await vi.waitFor(() => expect(mocks.post).toHaveBeenCalledTimes(1));
  expect(sent(0)).toEqual({ asset_ids: ['asset-1'], run_from: 'sensor', sensor_id: 's-1' });
});

it('builds bodies and confirmation selections from the parts', () => {
  expect(scanBody({ kind: 'ids', ids: new Set(['a']) }, 'auto', false)).toEqual({ asset_ids: ['a'], run_from: 'auto' });
  expect(confirmSelection([{ target: 't', addresses: [], asset_id: 'x' }, { target: 'u', addresses: [] }])).toEqual({ kind: 'ids', ids: new Set(['x']) });
  expect(confirmSelection([{ target: 'u', addresses: [] }])).toEqual({ kind: 'none' });
});
