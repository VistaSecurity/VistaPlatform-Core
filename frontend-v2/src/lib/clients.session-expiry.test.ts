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

    await expect(handler()).resolves.toBe(true);
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(onSessionExpired).not.toHaveBeenCalled();
  });

  it('concurrent 401s share a single refresh call', async () => {
    let release!: () => void;
    const refresh = vi.fn(() => new Promise<void>((r) => { release = r; }));
    const handler = createSessionExpiryHandler({ hasSession: () => true, refresh, onSessionExpired: vi.fn() });

    const results = Promise.all([handler(), handler(), handler()]);
    release();
    await expect(results).resolves.toEqual([true, true, true]);
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it('on refresh failure fires onSessionExpired exactly once and latches', async () => {
    const refresh = vi.fn(async () => { throw new Error('refresh token dead'); });
    const onSessionExpired = vi.fn();
    const handler = createSessionExpiryHandler({ hasSession: () => true, refresh, onSessionExpired });

    await expect(handler()).resolves.toBe(false);
    await expect(handler()).resolves.toBe(false); // latched: no second refresh, no second callback
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

    await expect(handler()).resolves.toBe(false);
    await expect(handler()).resolves.toBe(false); // latched
    expect(refresh).not.toHaveBeenCalled();
    expect(onSessionExpired).toHaveBeenCalledTimes(1);
    expect(onSessionExpired).toHaveBeenCalledWith('no-session');
  });
});
