// Entry-point regression guard for stale-cookie redirects.
//
// The route matcher and public-route catalogue have their own tests, but the
// bug can still return if main.tsx stops using that matcher when registering the
// global 401 handler. Import the real entry point with only the browser/root
// side effects mocked, then drive the handler it registers.
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
    throw new Error('refresh token dead');
  });
  // main.tsx's checkSession probe is a bare fetch to the whoami endpoint.
  const fetchStub = vi.fn(async () => new Response('{}', { status: whoamiStatus }));
  vi.stubGlobal('fetch', fetchStub);

  vi.stubGlobal('window', {
    location: { pathname, assign },
  });
  vi.stubGlobal('document', {
    cookie: hasSession ? 'csrf_token=stale' : '',
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

  vi.doMock('@vistasecurity/api-contract', async (importOriginal) => {
    const actual = await importOriginal<typeof import('@vistasecurity/api-contract')>();
    return {
      ...actual,
      setSessionExpiredHandler: vi.fn((handler: SessionExpiryHandlers | null) => {
        registeredHandler = handler;
      }),
    };
  });

  vi.doMock('@vistasecurity/primitives/auth', async (importOriginal) => {
    const actual = await importOriginal<typeof import('@vistasecurity/primitives/auth')>();
    return {
      ...actual,
      createAuthClient: vi.fn(() => ({ refresh })),
      tokenManager: {
        ...actual.tokenManager,
        hasToken: vi.fn(() => hasSession),
        clearTokens,
      },
    };
  });

  await import('./main');

  expect(registeredHandler, 'main.tsx must register the session-expiry handler').toBeTypeOf('object');
  if (!registeredHandler) throw new Error('main.tsx did not register the session-expiry handler');
  return { assign, clearTokens, refresh, fetchStub, handler: registeredHandler };
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.doUnmock('react-dom/client');
  vi.doUnmock('react-hot-toast');
  vi.doUnmock('@vistasecurity/api-contract');
  vi.doUnmock('@vistasecurity/primitives/auth');
});

describe('main session-expiry handler', () => {
  it.each(['/accept-invite', '/reset-password', '/register/complete', '/auth/sso/callback'])(
    'does not redirect stale sessions away from public email landing %s',
    async (pathname) => {
      const { assign, clearTokens, refresh, handler } = await loadMain(pathname);

      await expect(handler.onAuthFailure(new Request('http://api.test/api/v1/inventory-service/assets'))).resolves.toBe(false);

      expect(refresh).toHaveBeenCalledTimes(1);
      expect(clearTokens).toHaveBeenCalledTimes(1);
      expect(assign).not.toHaveBeenCalled();
    },
  );

  it('redirects stale sessions from authenticated app routes with the expired-session reason', async () => {
    const { assign, clearTokens, refresh, handler } = await loadMain('/dashboard');

    await expect(handler.onAuthFailure(new Request('http://api.test/api/v1/inventory-service/assets'))).resolves.toBe(false);

    expect(refresh).toHaveBeenCalledTimes(1);
    expect(clearTokens).toHaveBeenCalledTimes(1);
    expect(assign).toHaveBeenCalledWith('/login?reason=session-expired');
  });

  it('uses the signed-out reason when a protected request 401s without a session signal', async () => {
    const { assign, clearTokens, refresh, handler } = await loadMain('/inventory', false);

    await expect(handler.onAuthFailure(new Request('http://api.test/api/v1/inventory-service/assets'))).resolves.toBe(false);

    expect(refresh).not.toHaveBeenCalled();
    expect(clearTokens).toHaveBeenCalledTimes(1);
    expect(assign).toHaveBeenCalledWith('/login?reason=signed-out');
  });
  // The recovered-then-401 branch: the refresh "succeeded" but the replayed
  // request was rejected again. main.tsx must wire a bare-fetch whoami probe
  // and route a dead confirmation into the SAME redirect as a failed refresh.
  it('redirects when a recovered session still 401s and the whoami probe confirms it dead', async () => {
    const { assign, clearTokens, fetchStub, handler } = await loadMain('/dashboard', true, 401);

    await handler.onRecoveryFailed(new Request('http://api.test/api/v1/inventory-service/assets'));

    expect(fetchStub).toHaveBeenCalledWith('/api/v1/auth-service/auth/me', { credentials: 'include' });
    expect(clearTokens).toHaveBeenCalledTimes(1);
    expect(assign).toHaveBeenCalledWith('/login?reason=session-expired');
  });

  it('does not evict when the whoami probe says the session is alive', async () => {
    const { assign, clearTokens, handler } = await loadMain('/dashboard', true, 200);

    await handler.onRecoveryFailed(new Request('http://api.test/api/v1/inventory-service/assets'));

    expect(clearTokens).not.toHaveBeenCalled();
    expect(assign).not.toHaveBeenCalled();
  });

});
