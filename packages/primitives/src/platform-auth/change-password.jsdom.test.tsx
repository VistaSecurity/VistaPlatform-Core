// @vitest-environment jsdom
import { act, createElement } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createPlatformAuthClient } from './client';
import { PlatformAuthProvider, usePlatformAuth, type PlatformAuthState } from './context';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const BASE = 'http://admin.test';
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

// Stubs the admin-service: /me reports force_password_change=true; the
// change-password reply is whatever the test supplies.
function stubFetch(changePassword: () => Response) {
  const fn = vi.fn(async (input: Request | string) => {
    const url = typeof input === 'string' ? input : input.url;
    if (url.endsWith('/admin/auth/change-password')) return changePassword();
    if (url.endsWith('/admin/auth/me')) {
      return json({ user: { id: 'u1', email: 'a@b.c', force_password_change: true } });
    }
    return json({}, 404);
  });
  vi.stubGlobal('fetch', fn);
  return fn;
}

describe('platform changePassword — bodiless failures are failures', () => {
  beforeEach(() => { document.cookie = 'platform_csrf_token=t; path=/'; });
  afterEach(() => { vi.unstubAllGlobals(); document.cookie = 'platform_csrf_token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT'; });

  it('client throws on a bodiless 500', async () => {
    stubFetch(() => new Response(null, { status: 500 }));
    const client = createPlatformAuthClient(BASE);
    await expect(client.changePassword('a', 'b', 'b')).rejects.toThrow('Could not change password');
  });

  it('client surfaces the server reason on a bodied 400', async () => {
    stubFetch(() => json({ error: 'Current password is wrong' }, 400));
    await expect(createPlatformAuthClient(BASE).changePassword('a', 'b', 'b')).rejects.toThrow('Current password is wrong');
  });

  it('client resolves on 200', async () => {
    stubFetch(() => json({ message: 'ok' }));
    await expect(createPlatformAuthClient(BASE).changePassword('a', 'b', 'b')).resolves.toBeUndefined();
  });

  describe('provider', () => {
    let container: HTMLDivElement;
    let root: Root;
    beforeEach(() => { container = document.createElement('div'); root = createRoot(container); });
    afterEach(() => act(() => root.unmount()));

    it('bodiless 500 keeps force_password_change and does not say "Password changed"', async () => {
      stubFetch(() => new Response(null, { status: 500 }));
      const state: { current?: PlatformAuthState } = {};
      function Probe() { state.current = usePlatformAuth(); return null; }
      const notifier = { success: vi.fn(), error: vi.fn(), info: vi.fn(), warning: vi.fn() };
      await act(async () => {
        root.render(createElement(QueryClientProvider, { client: new QueryClient() },
          createElement(PlatformAuthProvider, { baseUrl: BASE, notifier, children: createElement(Probe) })));
      });
      await vi.waitFor(() => expect(state.current?.forcePasswordChange).toBe(true));

      await act(async () => {
        await expect(state.current!.changePassword('a', 'b', 'b')).rejects.toThrow();
      });
      expect(state.current!.forcePasswordChange).toBe(true);
      expect(notifier.success).not.toHaveBeenCalledWith('Password changed');
    });
  });
});
