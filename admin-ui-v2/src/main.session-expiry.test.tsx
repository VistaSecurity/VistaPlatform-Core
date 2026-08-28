// Entry-point regression guard for platform session-expiry redirects.
//
// The shared 401 middleware and session-expiry primitive have their own tests.
// This pins admin-ui-v2's main.tsx wiring: it must use the platform cookie
// family, platform refresh client, and platform whoami endpoint.
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { SessionExpiryHandlers } from '@vistasecurity/api-contract';

interface MainHarness {
  assign: ReturnType<typeof vi.fn>;
  clearTokens: ReturnType<typeof vi.fn>;
  refresh: ReturnType<typeof vi.fn>;
  fetchStub: ReturnType<typeof vi.fn>;
  handler: SessionExpiryHandlers;
}

async function loadMain(pathname: string, hasSession = true, whoamiStatus = 401): Promise<MainHarness> {
  vi.resetModules();

  let registeredHandler: SessionExpiryHandlers | null = null;
  const assign = vi.fn();
  const clearTokens = vi.fn();
  const refresh = vi.fn(async () => {
    throw new Error('platform refresh token dead');
  });
  // main.tsx's checkSession probe is a bare fetch to the platform whoami endpoint.
  const fetchStub = vi.fn(async () => new Response('{}', { status: whoamiStatus }));
  vi.stubGlobal('fetch', fetchStub);

  vi.stubGlobal('window', {
    location: { pathname, assign },
  });
  vi.stubGlobal('document', {
    cookie: hasSession ? 'platform_csrf_token=stale' : '',
    getElementById: vi.fn(() => ({})),
  });

  const createRoot = vi.fn(() => ({ render: vi.fn() }));
  vi.doMock('react-dom/client', () => ({
    default: { createRoot },
    createRoot,
  }));
  vi.doMock('react-hot-toast', () => ({
    default: { success: vi.fn(), error: vi.fn() },
    Toaster: 'toast-root',
  }));
  vi.doMock('./App', () => ({
    default: () => null,
  }));

  vi.doMock('@vistasecurity/api-contract', async (importOriginal) => {
    const actual = await importOriginal<typeof import('@vistasecurity/api-contract')>();
    return {
      ...actual,
      setSessionExpiredHandler: vi.fn((handler: SessionExpiryHandlers | null) => {
        registeredHandler = handler;
      }),
    };
  });

  vi.doMock('@vistasecurity/primitives/platform-auth', () => ({
    PlatformAuthProvider: ({ children }: { children: unknown }) => children,
    createPlatformAuthClient: vi.fn(() => ({ refresh })),
    platformTokenManager: {
      hasToken: vi.fn(() => hasSession),
      clearTokens,
    },
  }));

  await import('./main');

  expect(registeredHandler, 'main.tsx must register the platform session-expiry handler').toBeTypeOf('object');
  if (!registeredHandler) throw new Error('admin main.tsx did not register the session-expiry handler');
  return { assign, clearTokens, refresh, fetchStub, handler: registeredHandler };
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.doUnmock('react-dom/client');
  vi.doUnmock('react-hot-toast');
  vi.doUnmock('./App');
  vi.doUnmock('@vistasecurity/api-contract');
  vi.doUnmock('@vistasecurity/primitives/platform-auth');
});

describe('admin main session-expiry handler', () => {
  it('redirects platform app routes with the expired-session reason when refresh fails', async () => {
    const { assign, clearTokens, refresh, handler } = await loadMain('/overview');

    await expect(handler.onAuthFailure(new Request('http://api.test/api/v1/admin-service/tenants'))).resolves.toBe(false);

    expect(refresh).toHaveBeenCalledTimes(1);
    expect(clearTokens).toHaveBeenCalledTimes(1);
    expect(assign).toHaveBeenCalledWith('/login?reason=session-expired');
  });

  it('uses the signed-out reason when a protected request 401s without a platform session signal', async () => {
    const { assign, clearTokens, refresh, handler } = await loadMain('/tenants', false);

    await expect(handler.onAuthFailure(new Request('http://api.test/api/v1/admin-service/tenants'))).resolves.toBe(false);

    expect(refresh).not.toHaveBeenCalled();
    expect(clearTokens).toHaveBeenCalledTimes(1);
    expect(assign).toHaveBeenCalledWith('/login?reason=signed-out');
  });

  // Recovered-then-401 branch: the refresh "succeeded" but a replay still 401s.
  // admin-ui-v2 must confirm against admin-service's PLATFORM whoami, not the
  // tenant auth-service endpoint that frontend-v2 uses.
  it('confirms replay failures against the platform whoami endpoint before redirecting', async () => {
    const { assign, clearTokens, fetchStub, handler } = await loadMain('/billing', true, 401);

    await handler.onRecoveryFailed(new Request('http://api.test/api/v1/admin-service/billing'));

    expect(fetchStub).toHaveBeenCalledWith('/api/v1/admin-service/admin/auth/me', { credentials: 'include' });
    expect(clearTokens).toHaveBeenCalledTimes(1);
    expect(assign).toHaveBeenCalledWith('/login?reason=session-expired');
  });

  it('does not evict a platform session when the whoami probe says it is alive', async () => {
    const { assign, clearTokens, handler } = await loadMain('/billing', true, 200);

    await handler.onRecoveryFailed(new Request('http://api.test/api/v1/admin-service/billing'));

    expect(clearTokens).not.toHaveBeenCalled();
    expect(assign).not.toHaveBeenCalled();
  });
});
