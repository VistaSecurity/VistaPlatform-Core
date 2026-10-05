// @vitest-environment jsdom
// The "Scans started here" panel under Inventory's bulk bar: every
// asset a scan did not reach is listed with its reason ( — a count and
// the first reason hid which ones), and an ended scan is reported once.
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const mocks = vi.hoisted(() => ({ jobStatus: { current: 'running' } }));
vi.mock('react-router', () => ({ Link: ({ children, to }: { children: ReactNode; to: string }) => <a href={to}>{children}</a> }));
vi.mock('./queries', () => ({
  useScanJob: (id: string) => ({ data: id ? { id, status: mocks.jobStatus.current, execution_mode: 'async' } : undefined }),
}));

import { ActiveScanJobsPanel, SKIPPED_SHOWN } from './active-scan-jobs-panel';

let host: HTMLDivElement;
let root: Root;
const cache = new QueryClient();
beforeEach(() => {
  mocks.jobStatus.current = 'running';
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

const render = (node: ReactNode) => act(async () => { root.render(<QueryClientProvider client={cache}>{node}</QueryClientProvider>); });

it('lists every asset that was not scanned, by name where known, with its own reason', async () => {
  await render(
    <ActiveScanJobsPanel
      scans={[]}
      skipped={[
        { assetId: '11111111-aaaa-bbbb-cccc-000000000001', assetName: 'web-1', reason: 'observing sensor branch-sensor is offline' },
        { assetId: '11111111-aaaa-bbbb-cccc-000000000002', reason: 'the address is reserved' },
      ]}
    />,
  );
  expect(host.textContent).toContain('2 assets were not scanned');
  const items = [...host.querySelectorAll('[aria-label="Assets not scanned"] li')].map((li) => li.textContent);
  expect(items).toHaveLength(2);
  expect(items[0]).toContain('web-1');
  expect(items[0]).toContain('observing sensor branch-sensor is offline');
  expect(items[1]).toContain('the address is reserved');
  expect(host.querySelector('a[href="/inventory/assets/11111111-aaaa-bbbb-cccc-000000000001"]')).not.toBeNull();
});

it('caps the list and says how many more', async () => {
  const many = Array.from({ length: SKIPPED_SHOWN + 3 }, (_, i) => ({ assetId: `id-${i}`, reason: 'r' }));
  await render(<ActiveScanJobsPanel scans={[]} skipped={many} />);
  expect(host.querySelectorAll('[aria-label="Assets not scanned"] li')).toHaveLength(SKIPPED_SHOWN);
  expect(host.textContent).toContain('+3 more');
});

it('reports an ended scan once, even when its callback changes on every render', async () => {
  const seen: string[] = [];
  const scans = [{ jobId: 'job-x', executor: 'platform' as const, count: 1, startedAt: new Date().toISOString() }];
  mocks.jobStatus.current = 'completed';
  for (let i = 0; i < 3; i++) {
    await render(<ActiveScanJobsPanel scans={scans} skipped={[]} onScanSettled={(id) => seen.push(id)} />);
  }
  expect(seen).toEqual(['job-x']);
});

it('renders nothing until a scan starts', async () => {
  await render(<ActiveScanJobsPanel scans={[]} skipped={[]} />);
  expect(host.textContent).toBe('');
});
