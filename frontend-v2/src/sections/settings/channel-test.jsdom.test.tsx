// @vitest-environment jsdom
// Test tells the truth: a channel that did not deliver comes back as a 422 with a
// sanitized `reason`, and the button shows it instead of a bare "Test failed".
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { notificationServiceComponents as NC } from '@vistasecurity/api-contract';
import { ChannelTestButton, EMAIL_NOT_CONFIGURED_NOTICE, channelNotice, testFailureReason } from './channel-test';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ POST: vi.fn() }));
const toastApi = vi.hoisted(() => ({ error: vi.fn(), success: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { notifications: api } }));
vi.mock('react-hot-toast', () => ({ default: toastApi }));

type Channel = NC['schemas']['TenantNotificationChannel'];
const channel: Channel = {
  id: 'c-1', tenant_id: 't-1', channel_name: 'Ops', channel_type: 'email', config: null,
  enabled: true, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
};

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  api.POST.mockReset();
  toastApi.error.mockReset();
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function renderAndClick() {
  await act(async () => {
    root.render(<QueryClientProvider client={cache}><ChannelTestButton channel={channel} /></QueryClientProvider>);
  });
  const button = host.querySelector('button')!;
  await act(async () => { button.click(); });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
  return host.querySelector('button')!;
}

it('shows the server-supplied reason when the test fails', async () => {
  const reason = "Email delivery isn't configured by the platform operator.";
  api.POST.mockResolvedValue({
    error: { status: 'test_failed', error: 'Test failed', reason, permanent: true },
    response: { ok: false, status: 422 },
  });
  const button = await renderAndClick();

  expect(button.textContent).toBe('Test failed');
  expect(button.title).toBe(reason);
  expect(toastApi.error).toHaveBeenCalledTimes(1);
  expect(toastApi.error.mock.calls[0][0]).toBe(reason);
});

it('says "Test sent" on success and raises no error', async () => {
  api.POST.mockResolvedValue({ data: { status: 'test_sent' }, response: { ok: true, status: 200 } });
  const button = await renderAndClick();
  expect(button.textContent).toBe('Test sent');
  expect(toastApi.error).not.toHaveBeenCalled();
});

// A 500 (a real fault) has no reason; the UI must not invent one or show "undefined".
it('falls back to a generic sentence when the failure carries no reason', async () => {
  api.POST.mockResolvedValue({ error: { error: 'Internal server error' }, response: { ok: false, status: 500 } });
  const button = await renderAndClick();
  expect(button.textContent).toBe('Test failed');
  expect(toastApi.error.mock.calls[0][0]).toBe(testFailureReason({ error: 'Internal server error' }));
  expect(toastApi.error.mock.calls[0][0]).not.toContain('undefined');
});

it('testFailureReason ignores a non-string or blank reason', () => {
  for (const bad of [undefined, null, 'x', { reason: 42 }, { reason: '   ' }]) {
    expect(testFailureReason(bad)).toBe('The test could not be completed. Try again, or check the connection settings.');
  }
  expect(testFailureReason({ reason: 'Because.' })).toBe('Because.');
});

it('channelNotice warns only for an email channel on a deployment that cannot send', () => {
  const off = { email: { configured: false } };
  const on = { email: { configured: true } };
  expect(channelNotice('email', off)).toBe(EMAIL_NOT_CONFIGURED_NOTICE);
  expect(channelNotice('email', on)).toBeNull();
  expect(channelNotice('slack', off)).toBeNull();
  // Still loading, or the lookup failed: say nothing rather than guess.
  expect(channelNotice('email', undefined)).toBeNull();
});
