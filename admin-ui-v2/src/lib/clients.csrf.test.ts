// CSRF regression guard (2026-05 security audit) — platform-admin side.
//
// Platform-admin sessions use the `platform_csrf_token` cookie (NOT the
// tenant `csrf_token`), echoed as `X-CSRF-Token` on every state-mutating
// request. Two regressions would silently strip CSRF protection here:
//   - a client instance in src/lib/clients.ts created without ADMIN_CSRF
//     (it would echo the tenant cookie — or nothing — and every admin write
//     would 403 or, worse, ride an ambient tenant session), or
//   - an api-contract factory ignoring the `csrfCookie` option.
// These tests fail the suite on either. The tenant cookie is deliberately
// present alongside the platform one so a wrong-cookie regression is caught
// (both cookies coexist in a real browser during dual login).
import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';

const PLATFORM_TOKEN = 'platform-csrf-token-for-test';
const TENANT_TOKEN = 'tenant-csrf-token-for-test';
const MUTATING = ['POST', 'PUT', 'PATCH', 'DELETE'] as const;

// Both cookie families present, as in a browser with a tenant AND a platform
// session — the admin clients must pick the platform one.
const fakeDocument = {
  cookie: `csrf_token=${TENANT_TOKEN}; platform_csrf_token=${PLATFORM_TOKEN}`,
};

// Capture every request the clients emit; never touch the network.
const captured: Request[] = [];
const fetchStub = vi.fn(async (req: Request) => {
  captured.push(req);
  return new Response(JSON.stringify({}), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
});

// The app's clients use relative gateway base paths (/api/v1/...). Node's
// Request rejects relative URLs, so resolve them against a dummy origin.
// openapi-fetch captures globalThis.Request (and globalThis.fetch) at
// client-creation time, so these stubs MUST be installed before
// src/lib/clients.ts is imported — hence the dynamic import in beforeAll.
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

let clients: Record<string, unknown>;

beforeAll(async () => {
  vi.stubGlobal('document', fakeDocument);
  vi.stubGlobal('Request', RelativeUrlRequest);
  vi.stubGlobal('fetch', fetchStub);
  clients = (await import('./clients')).clients;
});

afterAll(() => {
  vi.unstubAllGlobals();
});

async function fireMutation(client: unknown, method: (typeof MUTATING)[number]): Promise<Request> {
  captured.length = 0;
  const c = client as Record<string, (path: string, init: object) => Promise<unknown>>;
  await c[method]('/__csrf_probe__', {});
  expect(captured).toHaveLength(1);
  return captured[0];
}

describe('CSRF double-submit header (X-CSRF-Token, platform cookie)', () => {
  it('the app has at least one wired service client', () => {
    expect(Object.keys(clients).length).toBeGreaterThan(0);
  });

  for (const method of MUTATING) {
    it(`every client in src/lib/clients.ts echoes platform_csrf_token on ${method}`, async () => {
      for (const [name, client] of Object.entries(clients)) {
        const req = await fireMutation(client, method);
        expect(req.headers.get('X-CSRF-Token'), `clients.${name} ${method}`).toBe(PLATFORM_TOKEN);
      }
    });
  }

  it('every api-contract factory honors the csrfCookie option', async () => {
    const contract = await import('@vistasecurity/api-contract');
    const factories = Object.entries(contract).filter(
      ([name, value]) => typeof value === 'function' && /^create.*Client$/.test(name),
    ) as Array<[string, (opts: object) => unknown]>;

    // 12 service factories exist today; a new one must not lower this bar.
    expect(factories.length).toBeGreaterThanOrEqual(12);

    for (const [name, factory] of factories) {
      const client = factory({
        baseUrl: 'http://api.test',
        fetch: fetchStub,
        csrfCookie: 'platform_csrf_token',
      });
      for (const method of MUTATING) {
        const req = await fireMutation(client, method);
        expect(req.headers.get('X-CSRF-Token'), `${name} ${method}`).toBe(PLATFORM_TOKEN);
      }
    }
  });

  it('the primitives platform-auth client overrides with the platform cookie', async () => {
    // createPlatformAuthClient layers a last-wins middleware over the shared
    // client so login/logout/refresh always carry the platform token even if
    // the base client was created with the tenant default.
    const { createPlatformAuthClient } = await import('@vistasecurity/primitives/platform-auth');
    const auth = createPlatformAuthClient();
    captured.length = 0;
    await auth.logout(); // POST /admin/auth/logout (best-effort — never throws)
    expect(captured).toHaveLength(1);
    expect(captured[0].method).toBe('POST');
    expect(captured[0].headers.get('X-CSRF-Token')).toBe(PLATFORM_TOKEN);
  });

  it('sends cookies with the request (credentials: include)', async () => {
    const [name, client] = Object.entries(clients)[0];
    const req = await fireMutation(client, 'POST');
    expect(req.credentials, `clients.${name}`).toBe('include');
  });
});
