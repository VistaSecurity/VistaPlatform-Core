// @vitest-environment jsdom
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ObservationActions } from './observation-actions';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const post = vi.hoisted(() => vi.fn());
vi.mock('../../lib/clients', () => ({ clients: { inventory: { POST: post } } }));
vi.mock('@vistasecurity/primitives/rbac', () => ({
  PermissionGate: ({ children }: { children: ReactNode }) => children,
  TENANT_PERMISSIONS: { assets: { update: 'assets.update' } },
}));
vi.mock('../inventory/asset-queries', () => ({ useAssetsQuery: () => ({
  data: { assets: [{ id: 'selected-asset', display_name: 'Lab appliance' }], total: 1, pageSize: 50 },
  isPending: false, isError: false,
}) }));

let host: HTMLDivElement;
let root: Root;
let cache: QueryClient;
beforeEach(async () => {
  post.mockReset().mockResolvedValue({ response: { ok: true, status: 200 } });
  host = document.createElement('div'); document.body.appendChild(host);
  root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await act(async () => { root.render(<QueryClientProvider client={cache}><ObservationActions id="observation-1" /></QueryClientProvider>); });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

function button(label: string) {
  const found = [...host.querySelectorAll('button')].find((node) => node.textContent === label);
  expect(found).toBeTruthy();
  return found!;
}
async function reason(value: string) {
  const field = host.querySelector('textarea')!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')!.set!.call(field, value);
    field.dispatchEvent(new Event('input', { bubbles: true }));
  });
}
async function click(label: string) { await act(async () => { button(label).click(); }); }

it('requires a reason and does not send monitoring approval with confirmation', async () => {
  await click('Confirm identity');
  expect(button('Save decision').disabled).toBe(true);
  await reason('   ');
  expect(button('Save decision').disabled).toBe(true);
  await reason(' Physically verified ');
  await click('Save decision');
  expect(post).toHaveBeenCalledExactlyOnceWith('/discovery/observations/{id}/confirm', {
    params: { path: { id: 'observation-1' } }, body: { reason: 'Physically verified' },
  });
});

it('requires explicit asset selection before linking', async () => {
  await click('Link to an asset');
  await reason('Verified the controller record');
  expect(button('Save decision').disabled).toBe(true);
  await act(async () => {
    const select = host.querySelector('select')!;
    select.value = 'selected-asset'; select.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await click('Save decision');
  expect(post).toHaveBeenCalledExactlyOnceWith('/discovery/observations/{id}/link', {
    params: { path: { id: 'observation-1' } }, body: { reason: 'Verified the controller record', asset_id: 'selected-asset' },
  });
});

it('keeps a stale decision open with a refresh action', async () => {
  post.mockResolvedValue({ response: { ok: false, status: 409 } });
  await click('Dismiss'); await reason('No longer actionable'); await click('Save decision');
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 10)); });
  expect(host.querySelector('[role="alert"]')?.textContent).toContain('conflicting ownership');
  expect(button('Refresh evidence')).toBeTruthy();
  expect(host.querySelector('textarea')?.value).toBe('No longer actionable');
});
