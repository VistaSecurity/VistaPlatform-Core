// Session-expiry regression guard.
//
// When a session times out, every API call starts answering 401. Before this
// wiring existed the UI just failed to load data with no explanation. The fix
// lives in two places, both pinned here:
//   - api/clients/typescript/client.ts installs a 401 middleware in EVERY
//     factory: it defers to the app-registered handler and, when the handler
//     recovers the session (silent refresh), replays GET/HEAD once.
//   - @vistasecurity/primitives/shared createSessionExpiryHandler: one
//     in-flight refresh shared by concurrent 401s; on refresh failure it fires
//     onSessionExpired exactly once (the app clears the session and navigates
//     to /login?reason=session-expired).
// A factory that silently drops the middleware doesn't fail at runtime — the
// app just regresses to "everything fails to load" — hence this guard, in the
// same harness style as clients.csrf.test.ts.
import { describe, it, expect, vi, beforeAll, afterAll, afterEach } from 'vitest';
import { createSessionExpiryHandler } from '@vistasecurity/primitives/shared';

// Fake document: a csrf cookie exists (a session is present).
const fakeDocument = { cookie: 'csrf_token=tenant-csrf-token-for-test' };

// The clients use relative gateway base paths; Node's Request rejects relative
// URLs, so resolve them against a dummy origin (see clients.csrf.test.ts).
class RelativeUrlRequest extends Request {
  constructor(input: RequestInfo | URL, init?: RequestInit) {
    super(
      typeof input === 'string' && input.startsWith('/')
        ? `http://gateway.test${input}`
        : input,
      init,
    );
  }
}

const json = (status: number) =>
  new Response(JSON.stringify({}), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

let contract: typeof import('@vistasecurity/api-contract');

beforeAll(async () => {
  vi.stubGlobal('document', fakeDocument);
  vi.stubGlobal('Request', RelativeUrlRequest);
  contract = await import('@vistasecurity/api-contract');
});

afterAll(() => {
  vi.unstubAllGlobals();
});

afterEach(() => {
  contract.setSessionExpiredHandler(null);
});

/** A fetch stub that answers each queued status in order (repeats the last). */
function fetchQueue(...statuses: number[]) {
  let i = 0;
  return vi.fn(async () => json(statuses[Math.min(i++, statuses.length - 1)]));
}

/** Fire a request on an untyped probe path (same trick as clients.csrf.test.ts). */
async function fire(client: unknown, method: 'GET' | 'POST', path: string) {
  const c = client as Record<string, (p: string, init: object) => Promise<{ response: Response }>>;
  return c[method](path, {});
}

describe('session-expiry middleware (401 → handler → replay)', () => {
  it('a 401 GET invokes the handler; on recovery the request is replayed once', async () => {
    const fetchStub = fetchQueue(401, 200);
    const handler = vi.fn(async () => true);
    contract.setSessionExpiredHandler(handler);
    const client = contract.createAuthServiceClient({ baseUrl: 'http://api.test', fetch: fetchStub });

    const { response } = await fire(client, 'GET', '/auth/me');
    expect(handler).toHaveBeenCalledTimes(1);
    expect(fetchStub).toHaveBeenCalledTimes(2);
    expect(response.status).toBe(200);
  });

  it('when the handler cannot recover, the 401 surfaces and nothing is replayed', async () => {
    const fetchStub = fetchQueue(401);
    const handler = vi.fn(async () => false);
    contract.setSessionExpiredHandler(handler);
    const client = contract.createInventoryServiceClient({ baseUrl: 'http://api.test', fetch: fetchStub });

    const { response } = await fire(client, 'GET', '/__expiry_probe__');
    expect(handler).toHaveBeenCalledTimes(1);
    expect(fetchStub).toHaveBeenCalledTimes(1);
    expect(response.status).toBe(401);
  });

  it('mutations are never auto-replayed, even when the session recovers', async () => {
    const fetchStub = fetchQueue(401, 200);
    const handler = vi.fn(async () => true);
    contract.setSessionExpiredHandler(handler);
    const client = contract.createInventoryServiceClient({ baseUrl: 'http://api.test', fetch: fetchStub });

    const { response } = await fire(client, 'POST', '/__expiry_probe__');
    expect(handler).toHaveBeenCalledTimes(1);
    expect(fetchStub).toHaveBeenCalledTimes(1);
    expect(response.status).toBe(401);
  });

  it('auth-flow endpoints are exempt (a failed sign-in is not an expired session)', async () => {
    const handler = vi.fn(async () => true);
    contract.setSessionExpiredHandler(handler);
    const client = contract.createAuthServiceClient({ baseUrl: 'http://api.test', fetch: fetchQueue(401) });

    await fire(client, 'POST', '/auth/login');
    await fire(client, 'POST', '/auth/refresh');
    await fire(client, 'POST', '/auth/methods');
    expect(handler).not.toHaveBeenCalled();
  });

  // The regression this guards: the exemption used to be a blacklist
  // ("anything containing /auth/ except /auth/me"), which swept in the
  // session-only legal endpoints. A 401 there during the window right after
  // re-login skipped session recovery and surfaced as a bare "couldn't verify
  // legal terms" error. These sit behind RequireAuth, so a 401 IS an expired
  // session and must reach the handler.
  it('session-only /auth/* endpoints are NOT exempt (legal gate, logout, sessions)', async () => {
    const handler = vi.fn(async () => true);
    contract.setSessionExpiredHandler(handler);
    const client = contract.createAuthServiceClient({ baseUrl: 'http://api.test', fetch: fetchQueue(401, 401) });

    await fire(client, 'GET', '/auth/legal/pending');
    expect(handler).toHaveBeenCalled();
  });

  it('a 401 on the replayed request fires onRecoveryFailed (the un-latchable loop)', async () => {
    // The regression this guards: refresh 200s but the data plane rejects the
    // token it minted. The replay 401s, the error surfaces, and — before the
    // two-phase handler — NOTHING ever latched, so the user was stranded on
    // dead panels with a live-looking cookie and no redirect to sign-in.
    const fetchStub = fetchQueue(401, 401);
    const onAuthFailure = vi.fn(async () => true);
    const onRecoveryFailed = vi.fn(async () => {});
    contract.setSessionExpiredHandler({ onAuthFailure, onRecoveryFailed });
    const client = contract.createInventoryServiceClient({ baseUrl: 'http://api.test', fetch: fetchStub });

    const { response } = await fire(client, 'GET', '/__expiry_probe__');
    expect(onAuthFailure).toHaveBeenCalledTimes(1);
    expect(onRecoveryFailed).toHaveBeenCalledTimes(1);
    expect(response.status).toBe(401); // the caller still sees the failure
  });

  it('a replay that succeeds does not fire onRecoveryFailed', async () => {
    const fetchStub = fetchQueue(401, 200);
    const onAuthFailure = vi.fn(async () => true);
    const onRecoveryFailed = vi.fn(async () => {});
    contract.setSessionExpiredHandler({ onAuthFailure, onRecoveryFailed });
    const client = contract.createInventoryServiceClient({ baseUrl: 'http://api.test', fetch: fetchStub });

    const { response } = await fire(client, 'GET', '/__expiry_probe__');
    expect(onRecoveryFailed).not.toHaveBeenCalled();
    expect(response.status).toBe(200);
  });

  it('with no handler registered the 401 passes through untouched', async () => {
    const fetchStub = fetchQueue(401);
    const client = contract.createAuthServiceClient({ baseUrl: 'http://api.test', fetch: fetchStub });
    const { response } = await fire(client, 'GET', '/auth/me');
    expect(fetchStub).toHaveBeenCalledTimes(1);
    expect(response.status).toBe(401);
  });

  it('every api-contract factory wires the session-expiry middleware', async () => {
    const factories = Object.entries(contract).filter(
      ([name, value]) => typeof value === 'function' && /^create.*Client$/.test(name),
    ) as Array<[string, (opts: object) => unknown]>;
    expect(factories.length).toBeGreaterThan(0);

    for (const [name, factory] of factories) {
      const handler = vi.fn(async () => false);
      contract.setSessionExpiredHandler(handler);
      const client = factory({ baseUrl: 'http://api.test', fetch: fetchQueue(401) });
      await fire(client, 'GET', '/__expiry_probe__');
      expect(handler, name).toHaveBeenCalledTimes(1);
    }
  });
});

describe('createSessionExpiryHandler', () => {
  it('recovers via refresh and never fires onSessionExpired on success', async () => {
    const refresh = vi.fn(async () => ({}));
    const onSessionExpired = vi.fn();
    const handler = createSessionExpiryHandler({ hasSession: () => true, refresh, onSessionExpired });

    await expect(handler.onAuthFailure()).resolves.toBe(true);
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(onSessionExpired).not.toHaveBeenCalled();
  });

  it('concurrent 401s share a single refresh call', async () => {
    let release!: () => void;
    const refresh = vi.fn(() => new Promise<void>((r) => { release = r; }));
    const handler = createSessionExpiryHandler({ hasSession: () => true, refresh, onSessionExpired: vi.fn() });

    const results = Promise.all([handler.onAuthFailure(), handler.onAuthFailure(), handler.onAuthFailure()]);
    release();
    await expect(results).resolves.toEqual([true, true, true]);
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it('on refresh failure fires onSessionExpired exactly once and latches', async () => {
    const refresh = vi.fn(async () => { throw new Error('refresh token dead'); });
    const onSessionExpired = vi.fn();
    const handler = createSessionExpiryHandler({ hasSession: () => true, refresh, onSessionExpired });

    await expect(handler.onAuthFailure()).resolves.toBe(false);
    await expect(handler.onAuthFailure()).resolves.toBe(false); // latched: no second refresh, no second callback
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(onSessionExpired).toHaveBeenCalledTimes(1);
    expect(onSessionExpired).toHaveBeenCalledWith('expired');
  });

  // The bug this pins: with no session cookie the handler used to return false
  // silently — no refresh AND no callback — so a 401 burst left the user on a
  // page of "Couldn't load …" cards with nothing explaining why and no route to
  // sign-in. Skipping the refresh is right (there is no session to refresh);
  // skipping the notification is not.
  it('with no session cookie skips the refresh but still reports the dead session', async () => {
    const refresh = vi.fn();
    const onSessionExpired = vi.fn();
    const handler = createSessionExpiryHandler({ hasSession: () => false, refresh, onSessionExpired });

    await expect(handler.onAuthFailure()).resolves.toBe(false);
    await expect(handler.onAuthFailure()).resolves.toBe(false); // latched
    expect(refresh).not.toHaveBeenCalled();
    expect(onSessionExpired).toHaveBeenCalledTimes(1);
    expect(onSessionExpired).toHaveBeenCalledWith('no-session');
  });
  // onRecoveryFailed: the refresh "succeeded" but the replayed request still
  // 401'd — the session auth minted does not work. checkSession (a bare whoami
  // fetch) decides between eviction and a one-endpoint bug.
  it('onRecoveryFailed with a dead whoami latches and fires onSessionExpired(expired) once', async () => {
    const onSessionExpired = vi.fn();
    const checkSession = vi.fn(async () => false); // whoami 401'd too
    const handler = createSessionExpiryHandler({ hasSession: () => true, refresh: vi.fn(async () => ({})), onSessionExpired, checkSession });

    await handler.onRecoveryFailed();
    await handler.onRecoveryFailed(); // latched
    expect(checkSession).toHaveBeenCalledTimes(1);
    expect(onSessionExpired).toHaveBeenCalledTimes(1);
    expect(onSessionExpired).toHaveBeenCalledWith('expired');
    await expect(handler.onAuthFailure()).resolves.toBe(false); // shared latch
  });

  it('onRecoveryFailed with a live whoami does NOT evict (one buggy endpoint is not a dead session)', async () => {
    const onSessionExpired = vi.fn();
    const handler = createSessionExpiryHandler({ hasSession: () => true, refresh: vi.fn(async () => ({})), onSessionExpired, checkSession: async () => true });

    await handler.onRecoveryFailed();
    expect(onSessionExpired).not.toHaveBeenCalled();
    await expect(handler.onAuthFailure()).resolves.toBe(true); // session still usable
  });

  it('onRecoveryFailed with a rejecting whoami probe does not evict on uncertainty', async () => {
    const onSessionExpired = vi.fn();
    const handler = createSessionExpiryHandler({ hasSession: () => true, refresh: vi.fn(async () => ({})), onSessionExpired, checkSession: async () => { throw new Error('network down'); } });

    await handler.onRecoveryFailed();
    expect(onSessionExpired).not.toHaveBeenCalled();
  });

  it('onRecoveryFailed without a checkSession probe latches directly', async () => {
    const onSessionExpired = vi.fn();
    const handler = createSessionExpiryHandler({ hasSession: () => true, refresh: vi.fn(async () => ({})), onSessionExpired });

    await handler.onRecoveryFailed();
    expect(onSessionExpired).toHaveBeenCalledTimes(1);
    expect(onSessionExpired).toHaveBeenCalledWith('expired');
  });

  it('concurrent onRecoveryFailed calls share a single whoami probe', async () => {
    let release!: (alive: boolean) => void;
    const checkSession = vi.fn(() => new Promise<boolean>((r) => { release = r; }));
    const onSessionExpired = vi.fn();
    const handler = createSessionExpiryHandler({ hasSession: () => true, refresh: vi.fn(async () => ({})), onSessionExpired, checkSession });

    const results = Promise.all([handler.onRecoveryFailed(), handler.onRecoveryFailed(), handler.onRecoveryFailed()]);
    release(false);
    await results;
    expect(checkSession).toHaveBeenCalledTimes(1);
    expect(onSessionExpired).toHaveBeenCalledTimes(1);
  });

});

// RC-4 /: every service answers a live token of a suspended or deleted
// organization with 403 + a tenant code. The middleware must hand exactly those
// to the app (so it can end the session with the reason) and leave every other
// 403 — a plain permission refusal — alone.
describe('session-expiry middleware (403 tenant_suspended / tenant_deleted)', () => {
  const coded = (status: number, body: object) => vi.fn(async () =>
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }));

  it.each(['tenant_suspended', 'tenant_deleted'])('a 403 %s is handed to onTenantBlocked, from any service', async (code) => {
    const onTenantBlocked = vi.fn();
    contract.setSessionExpiredHandler({ onAuthFailure: vi.fn(async () => false), onRecoveryFailed: vi.fn(async () => {}), onTenantBlocked });
    const client = contract.createInventoryServiceClient({ baseUrl: 'http://api.test', fetch: coded(403, { code, error: 'x' }) });

    const { response } = await fire(client, 'GET', '/assets');
    expect(onTenantBlocked).toHaveBeenCalledWith(code);
    expect(response.status).toBe(403); // the caller still sees its refusal
  });

  it('a 403 on the refresh exchange itself is handed over too (auth-flow paths are not exempt from this)', async () => {
    const onTenantBlocked = vi.fn();
    contract.setSessionExpiredHandler({ onAuthFailure: vi.fn(async () => false), onRecoveryFailed: vi.fn(async () => {}), onTenantBlocked });
    const client = contract.createAuthServiceClient({ baseUrl: 'http://api.test', fetch: coded(403, { code: 'tenant_suspended', error: 'x' }) });

    await fire(client, 'POST', '/auth/refresh');
    expect(onTenantBlocked).toHaveBeenCalledWith('tenant_suspended');
  });

  it.each(['/auth/login', '/admin/auth/login'])(
    'a refused sign-in at %s does not trip the page session-expiry latch',
    async (loginPath) => {
      const onSessionExpired = vi.fn();
      const handler = createSessionExpiryHandler({
        hasSession: () => false,
        refresh: vi.fn(async () => ({})),
        onSessionExpired,
      });
      contract.setSessionExpiredHandler(handler);
      const client = contract.createAuthServiceClient({
        baseUrl: 'http://api.test',
        fetch: coded(403, { code: 'tenant_suspended', error: 'x' }),
      });

      await fire(client, 'POST', loginPath);
      expect(onSessionExpired).not.toHaveBeenCalled();

      // The ignored sign-in refusal must not consume the handler's one-shot
      // latch: a later protected refusal still ends a real session.
      await fire(client, 'GET', '/auth/me');
      expect(onSessionExpired).toHaveBeenCalledTimes(1);
      expect(onSessionExpired).toHaveBeenCalledWith('tenant_suspended');
    },
  );

  it('a plain permission 403 (no tenant code) is left alone', async () => {
    const onTenantBlocked = vi.fn();
    const onAuthFailure = vi.fn(async () => false);
    contract.setSessionExpiredHandler({ onAuthFailure, onRecoveryFailed: vi.fn(async () => {}), onTenantBlocked });
    const client = contract.createInventoryServiceClient({ baseUrl: 'http://api.test', fetch: coded(403, { error: 'Insufficient permissions' }) });

    await fire(client, 'GET', '/assets');
    expect(onTenantBlocked).not.toHaveBeenCalled();
    expect(onAuthFailure).not.toHaveBeenCalled();
  });

  it('createSessionExpiryHandler latches a tenant refusal once, with the code as the reason', () => {
    const onSessionExpired = vi.fn();
    const refresh = vi.fn(async () => ({}));
    const h = createSessionExpiryHandler({ hasSession: () => true, refresh, onSessionExpired });
    h.onTenantBlocked('tenant_deleted');
    h.onTenantBlocked('tenant_deleted');
    expect(onSessionExpired).toHaveBeenCalledTimes(1);
    expect(onSessionExpired).toHaveBeenCalledWith('tenant_deleted');
    expect(refresh).not.toHaveBeenCalled();
  });
});
