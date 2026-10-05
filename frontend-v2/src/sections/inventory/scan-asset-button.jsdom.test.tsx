// @vitest-environment jsdom
// The asset drawer's Active Scan button reads the asset's own scan record:
// disabled while a scan runs, live again once it has finished either way.
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
vi.mock('../../lib/clients', () => ({ clients: { inventory: { POST: vi.fn(), GET: vi.fn() } } }));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));
vi.mock('@vistasecurity/primitives/rbac', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@vistasecurity/primitives/rbac')>()),
  PermissionGate: ({ children }: { children: ReactNode }) => <>{children}</>,
}));
vi.mock('../../components/ui', () => ({ Icon: () => null, Modal: () => null }));

import { ScanAssetButton } from './bulk-actions';

let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

async function renderWith(activeScan: Parameters<typeof ScanAssetButton>[0]['activeScan']) {
  await act(async () => {
    root.render(<QueryClientProvider client={new QueryClient()}><ScanAssetButton assetId="asset-1" activeScan={activeScan} /></QueryClientProvider>);
  });
  return host.querySelector('button')!;
}

it('is disabled and says so while a scan of the asset runs', async () => {
  const b = await renderWith({ status: 'scanning', started_at: new Date().toISOString(), job_ids: ['j'] });
  expect(b.disabled).toBe(true);
  expect(b.textContent).toContain('Scanning…');
  expect(b.title).toContain('A scan of this asset is running');
});

it('is live once the scan finished, and says how it ended', async () => {
  const done = await renderWith({ status: 'completed', finished_at: new Date().toISOString(), job_ids: ['j'] });
  expect(done.disabled).toBe(false);
  expect(done.title).toContain('Last scan finished');
  const failed = await renderWith({ status: 'failed', finished_at: new Date().toISOString(), job_ids: ['j'] });
  expect(failed.disabled).toBe(false);
  expect(failed.title).toContain('Last scan failed');
});

it('is live for an asset nobody has scanned', async () => {
  const b = await renderWith(undefined);
  expect(b.disabled).toBe(false);
  expect(b.textContent).toContain('Active Scan');
});
