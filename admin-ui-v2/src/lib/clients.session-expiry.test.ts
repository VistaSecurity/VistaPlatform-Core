// Session-expiry regression guard (admin mirror of frontend-v2's
// clients.session-expiry.test.ts — the middleware behavior itself is pinned
// there; this file pins that THIS app's client instances participate).
//
// When a platform session times out, every API call answers 401. The 401
// middleware installed by the api-contract factories defers to the handler the
// app registers in main.tsx (silent refresh → else /login?reason=
// session-expired). If a client in src/lib/clients.ts ever stops going through
// the factories, it silently regresses to "everything fails to load" — this
// guard fails the suite instead.
import { describe, it, expect, vi, beforeAll, afterAll, afterEach } from 'vitest';

// Fake document carrying the platform csrf cookie (a platform session exists).
const fakeDocument = { cookie: 'platform_csrf_token=platform-csrf-token-for-test' };

// The app's clients use relative gateway base paths; Node's Request rejects
// relative URLs, so resolve them against a dummy origin (see clients.csrf.test.ts).
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

const fetch401 = vi.fn(async () =>
  new Response(JSON.stringify({}), {
    status: 401,
    headers: { 'Content-Type': 'application/json' },
  }),
);

let clients: Record<string, unknown>;
let contract: typeof import('@vistasecurity/api-contract');

beforeAll(async () => {
  vi.stubGlobal('document', fakeDocument);
  vi.stubGlobal('Request', RelativeUrlRequest);
  vi.stubGlobal('fetch', fetch401);
  contract = await import('@vistasecurity/api-contract');
  clients = (await import('./clients')).clients;
});

afterAll(() => {
  vi.unstubAllGlobals();
});

afterEach(() => {
  contract.setSessionExpiredHandler(null);
});

describe('session-expiry middleware wiring (admin clients)', () => {
  it('every client in src/lib/clients.ts routes 401s through the registered handler', async () => {
    for (const [name, client] of Object.entries(clients)) {
      const handler = vi.fn(async () => false);
      contract.setSessionExpiredHandler(handler);
      const c = client as Record<string, (p: string, init: object) => Promise<unknown>>;
      await c.GET('/__expiry_probe__', {});
      expect(handler, `clients.${name}`).toHaveBeenCalledTimes(1);
    }
  });

  it('auth-flow endpoints are exempt (bad password / dead refresh are not "session expired")', async () => {
    const handler = vi.fn(async () => true);
    contract.setSessionExpiredHandler(handler);
    const c = clients.admin as Record<string, (p: string, init: object) => Promise<unknown>>;
    await c.POST('/auth/login', {});
    await c.POST('/auth/refresh', {});
    expect(handler).not.toHaveBeenCalled();
  });

  it('actual platform auth-flow paths are exempt', async () => {
    const handler = vi.fn(async () => true);
    contract.setSessionExpiredHandler(handler);
    const c = clients.admin as Record<string, (p: string, init: object) => Promise<unknown>>;

    await c.POST('/admin/auth/login', {});
    await c.POST('/admin/auth/refresh', {});

    expect(handler).not.toHaveBeenCalled();
  });

  it('session-only platform auth paths are not exempt', async () => {
    const handler = vi.fn(async () => false);
    contract.setSessionExpiredHandler(handler);
    const c = clients.admin as Record<string, (p: string, init: object) => Promise<unknown>>;

    await c.GET('/admin/auth/me', {});

    expect(handler).toHaveBeenCalledTimes(1);
  });
});
