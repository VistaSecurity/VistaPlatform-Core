// @vitest-environment jsdom
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { IdentityDiscoverySettings } from './identity-discovery-settings';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn(), canEdit: true }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));
vi.mock('@vistasecurity/primitives/rbac', () => ({ TENANT_PERMISSIONS: { settings: { update: 'settings.update' } }, PermissionGate: ({ children, fallback }: { children: ReactNode; fallback: ReactNode }) => api.canEdit ? children : fallback }));
const settings = {
  mode: 'enforce', enrichment: { enabled: true, excluded_cidrs: [], sensitive_asset_ids: [] }, version: 7,
  activated_at: '2026-09-19T01:00:00Z', capabilities: { admission: true, enrichment: true },
  limits: { max_excluded_cidrs: 128, max_sensitive_asset_ids: 256, max_reason_length: 2000 },
};
let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  api.canEdit = true; api.GET.mockReset().mockResolvedValue({ data: settings, response: { ok: true } }); api.PUT.mockReset();
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });
async function render() { await act(async () => { root.render(<QueryClientProvider client={cache}><IdentityDiscoverySettings /></QueryClientProvider>); }); await act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); }); }
function button(text: string) { return [...host.querySelectorAll('button')].find((b) => b.textContent === text)!; }
async function select(value: string) { await act(async () => { const el = host.querySelector('select')!; el.value = value; el.dispatchEvent(new Event('change', { bubbles: true })); }); }
async function setReason(value: string) { await act(async () => { const el = host.querySelectorAll('textarea')[2]; Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')!.set!.call(el, value); el.dispatchEvent(new Event('input', { bubbles: true })); }); }
it('pauses while preserving enrichment and submits a reason and saved revision', async () => {
  await render();
  expect(host.querySelector<HTMLOptionElement>('option[value="disabled"]')?.disabled).toBe(true);
  expect(host.querySelector<HTMLOptionElement>('option[value="observe"]')?.disabled).toBe(true);
  await select('paused');
  expect(button('Save identity policy').disabled).toBe(true);
  expect(button('Save identity policy').title).toContain('reason of at least 3 characters');
  expect(host.querySelector('[role="alert"]')?.textContent).toContain('Required for the audit history');
  await setReason('Investigating unexpected count growth');
  api.PUT.mockResolvedValue({ data: { ...settings, mode: 'paused', version: 8 }, response: { ok: true } });
  await act(async () => button('Save identity policy').click());
  expect(api.PUT).toHaveBeenCalledWith('/settings/identity-discovery', { body: { mode: 'paused', enrichment: settings.enrichment, version: 7, reason: 'Investigating unexpected count growth' } });
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); });
  expect(host.textContent).toContain('Current policy: Paused');
});
it('does not retry stale writes and requires reloading the current saved version', async () => {
  await render(); await select('paused'); await setReason('Pause for review');
  api.PUT.mockResolvedValue({ error: { error: 'stale_version' }, response: { ok: false, status: 409 } });
  await act(async () => button('Save identity policy').click());
  expect(host.textContent).toContain('These settings changed');
  expect(button('Save identity policy').disabled).toBe(true);
  expect(host.querySelectorAll('textarea')[2].value).toBe('Pause for review');
  api.GET.mockResolvedValue({ data: { ...settings, version: 8 }, response: { ok: true } });
  await act(async () => button('Reload saved settings').click());
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); });
  expect(host.querySelectorAll('textarea')[2].value).toBe('');
  expect(api.PUT).toHaveBeenCalledTimes(1);
});
it('keeps read-only users out of the edit form', async () => {
  api.canEdit = false;
  api.GET.mockResolvedValue({ data: { ...settings, enrichment: { ...settings.enrichment, excluded_cidrs: ['192.168.8.0/24'], sensitive_asset_ids: ['sensitive-asset'] } }, response: { ok: true } });
  await render();
  expect(host.textContent).toContain('Current policy: Identify before');
  expect(host.querySelector('form')).toBeNull();
  expect(host.textContent).toContain('settings update permission');
  expect(host.textContent).toContain('192.168.8.0/24');
  expect(host.textContent).toContain('sensitive-asset');
  expect(host.textContent).toContain('Automatic enrichmentEnabled');
});
it('preserves unsaved choices and reason when a background refresh changes the policy version', async () => {
  await render(); await select('paused'); await setReason('Retain this draft');
  await act(async () => { cache.setQueryData(['settings', 'identity-discovery'], { ...settings, version: 8 }); });
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); });
  expect(host.querySelector('select')?.value).toBe('paused');
  expect(host.querySelectorAll('textarea')[2].value).toBe('Retain this draft');
  expect(button('Save identity policy').disabled).toBe(true);
  expect(host.textContent).toContain('Your draft has been preserved');
  expect(api.PUT).not.toHaveBeenCalled();
});
it('does not offer activation or enrichment before the backend release supports them', async () => {
  api.GET.mockResolvedValue({ data: { ...settings, mode: 'disabled', activated_at: null, enrichment: { ...settings.enrichment, enabled: false }, capabilities: { admission: false, enrichment: false } }, response: { ok: true } });
  await render();
  expect(host.querySelector<HTMLOptionElement>('option[value="enforce"]')?.disabled).toBe(true);
  expect(host.querySelector<HTMLOptionElement>('option[value="paused"]')?.disabled).toBe(true);
  expect(host.querySelector<HTMLInputElement>('input[type="checkbox"]')?.disabled).toBe(true);
  expect(host.textContent).toContain('has not enabled identity admission');
});
