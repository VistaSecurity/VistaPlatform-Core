// @vitest-environment jsdom
// Active Scan → Scan on an asset outside the registered networks (
// W5.13b, owner decision Q10): the page ASKS, then resends the same assets
// with the confirmation only when the person clicks "Scan anyway".
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const mocks = vi.hoisted(() => ({ post: vi.fn(), toastError: vi.fn(), toastSuccess: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: { POST: mocks.post, GET: vi.fn() } } }));
vi.mock('react-hot-toast', () => {
  const toast = Object.assign(vi.fn(), { error: mocks.toastError, success: mocks.toastSuccess });
  return { default: toast };
});
vi.mock('react-router', () => ({ Link: ({ children }: { children: ReactNode }) => <a>{children}</a>, useNavigate: () => vi.fn() }));
vi.mock('@vistasecurity/primitives/rbac', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@vistasecurity/primitives/rbac')>()),
  PermissionGate: ({ children }: { children: ReactNode }) => <>{children}</>,
}));
vi.mock('./queries', () => ({
  useSensors: () => ({ data: [], isLoading: false, isError: false }),
  useUnscannedAssets: () => ({
    data: [{ id: 'asset-1', hostname: 'partner-portal', primary_address: '93.184.216.34', class_key: 'server', asset_status: 'monitoring' }],
    isLoading: false, isError: false, isSuccess: true,
  }),
  useScanJob: () => ({ data: undefined }),
}));
vi.mock('./discover-modal', () => ({ DiscoverAssetsModal: () => null }));
vi.mock('../../components/ui', () => ({
  Icon: () => null,
  Modal: ({ open, children, primary, secondary }: { open: boolean; children: ReactNode; primary: ReactNode; secondary: ReactNode }) =>
    open ? <div data-testid="modal">{children}{secondary}{primary}</div> : null,
}));

import { ActiveScanPage } from './active-scan-page';

const ASK = {
  error: {
    error: 'external_targets_unconfirmed',
    details: '1 asset(s) are outside your registered networks (partner-portal); confirm to scan them',
    external_targets: [{ target: '93.184.216.34', addresses: ['93.184.216.34'], asset_id: 'asset-1', asset_name: 'partner-portal' }],
    job_id: '', count: 0, jobs: [], skipped: [],
  },
  response: { ok: false, status: 422 },
};
const STARTED = { data: { message: 'Active scan started', job_id: 'job-1', count: 1, jobs: [{ job_id: 'job-1', executor: 'platform', count: 1 }], skipped: [] }, response: { ok: true, status: 200 } };

let host: HTMLDivElement;
let root: Root;
let cache: QueryClient;
beforeEach(() => {
  mocks.post.mockReset(); mocks.toastError.mockReset(); mocks.toastSuccess.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { mutations: { retry: false }, queries: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

const render = async () => act(async () => { root.render(<QueryClientProvider client={cache}><ActiveScanPage /></QueryClientProvider>); });
const button = (label: string) => [...host.querySelectorAll('button')].find((b) => b.textContent?.trim() === label);
async function click(label: string) {
  const b = button(label);
  if (!b) throw new Error(`no "${label}" button in: ${host.textContent}`);
  await act(async () => { b.click(); });
}
const sent = (i: number) => (mocks.post.mock.calls[i][1] as { body: Record<string, unknown> }).body;

it('asks before scanning an asset outside the registered networks, then resends it confirmed', async () => {
  mocks.post.mockResolvedValueOnce(ASK).mockResolvedValueOnce(STARTED);
  await render();
  await click('Scan');
  await vi.waitFor(() => expect(host.querySelector('[role="alertdialog"]')).not.toBeNull());
  expect(host.textContent).toContain('1 target is outside your registered networks. Only scan systems you are authorized to test.');
  expect(host.textContent).toContain('partner-portal (93.184.216.34)');
  expect(sent(0)).not.toHaveProperty('external_targets_confirmed');
  expect(mocks.toastError).not.toHaveBeenCalled();

  await click('Scan anyway');
  await vi.waitFor(() => expect(mocks.post).toHaveBeenCalledTimes(2));
  expect(sent(1)).toMatchObject({ asset_ids: ['asset-1'], external_targets_confirmed: true });
  await vi.waitFor(() => expect(mocks.toastSuccess).toHaveBeenCalled());
  expect(host.querySelector('[role="alertdialog"]')).toBeNull();
});

it('Cancel scans nothing', async () => {
  mocks.post.mockResolvedValueOnce(ASK);
  await render();
  await click('Scan');
  await vi.waitFor(() => expect(host.querySelector('[role="alertdialog"]')).not.toBeNull());
  await click('Cancel');
  expect(host.querySelector('[role="alertdialog"]')).toBeNull();
  expect(mocks.post).toHaveBeenCalledTimes(1);
});

it('explains a refused confirmation (no discovery permission) instead of asking again', async () => {
  mocks.post
    .mockResolvedValueOnce(ASK)
    .mockResolvedValueOnce({ error: { error: 'insufficient_permissions', details: 'Scanning assets outside your registered networks also needs the discovery.create permission' }, response: { ok: false, status: 403 } });
  await render();
  await click('Scan');
  await vi.waitFor(() => expect(host.querySelector('[role="alertdialog"]')).not.toBeNull());
  await click('Scan anyway');
  await vi.waitFor(() => expect(mocks.toastError).toHaveBeenCalledWith('Scanning assets outside your registered networks also needs the discovery.create permission'));
  expect(host.querySelector('[role="alertdialog"]')).toBeNull();
});
