// CSRF regression guard (2026-05 security audit).
//
// CSRF defense is double-submit: the JS-readable `csrf_token` cookie must be
// echoed as `X-CSRF-Token` on every state-mutating request. The wiring lives
// in exactly one place — the api-contract client factories
// (`makeCsrfMiddleware` in api/clients/typescript/client.ts). A code path
// that drops that middleware doesn't fail at runtime; it silently loses CSRF
// protection (the audit's P1-6 was exactly such a bypass). These tests fail
// the suite if:
//   - any client instance in src/lib/clients.ts (this app's ONLY backend
//     transport) stops echoing the cookie on POST/PUT/PATCH/DELETE, or
//   - any api-contract factory — present or future — creates a client
//     without the CSRF middleware.
import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';

const TENANT_TOKEN = 'tenant-csrf-token-for-test';
const MUTATING = ['POST', 'PUT', 'PATCH', 'DELETE'] as const;

// Fake document carrying the tenant csrf cookie (node env has no DOM).
const fakeDocument = { cookie: `csrf_token=${TENANT_TOKEN}` };

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

describe('CSRF double-submit header (X-CSRF-Token)', () => {
  it('the app has at least one wired service client', () => {
    expect(Object.keys(clients).length).toBeGreaterThan(0);
  });

  for (const method of MUTATING) {
    it(`every client in src/lib/clients.ts sends X-CSRF-Token on ${method}`, async () => {
      for (const [name, client] of Object.entries(clients)) {
        const req = await fireMutation(client, method);
        expect(req.headers.get('X-CSRF-Token'), `clients.${name} ${method}`).toBe(TENANT_TOKEN);
      }
    });
  }

  it('every api-contract client factory wires the CSRF middleware', async () => {
    const contract = await import('@vistasecurity/api-contract');
    const factories = Object.entries(contract).filter(
      ([name, value]) => typeof value === 'function' && /^create.*Client$/.test(name),
    ) as Array<[string, (opts: object) => unknown]>;

    // An exact list, not a floor: a floor only catches factories going missing,
    // and showed the reverse direction matters too — removing a service
    // must be a deliberate edit here, not a silently-satisfied inequality.
    expect(factories.map(([name]) => name).sort()).toEqual([
      'createAdminServiceClient',
      'createAuditServiceClient',
      'createAuthServiceClient',
      'createCbomServiceClient',
      'createComplianceEngineClient',
      'createDeviceInterrogationServiceClient',
      'createInventoryServiceClient',
      'createMonitoringServiceClient',
      'createNotificationServiceClient',
      'createResourceTrackerServiceClient',
      'createSensorManagerClient',
      'createTenantHealthServiceClient',
    ]);

    for (const [name, factory] of factories) {
      const client = factory({ baseUrl: 'http://api.test', fetch: fetchStub });
      for (const method of MUTATING) {
        const req = await fireMutation(client, method);
        expect(req.headers.get('X-CSRF-Token'), `${name} ${method}`).toBe(TENANT_TOKEN);
      }
    }
  });

  it('sends cookies with the request (credentials: include)', async () => {
    // httpOnly-cookie auth rides on credentials:"include"; CSRF is its
    // double-submit companion. Pin both halves of the auth wiring.
    const [name, client] = Object.entries(clients)[0];
    const req = await fireMutation(client, 'POST');
    expect(req.credentials, `clients.${name}`).toBe('include');
  });

  it('omits the header when the csrf cookie is absent (server rejects with 403)', async () => {
    const original = fakeDocument.cookie;
    try {
      fakeDocument.cookie = '';
      const [, client] = Object.entries(clients)[0];
      const req = await fireMutation(client, 'POST');
      expect(req.headers.get('X-CSRF-Token')).toBeNull();
    } finally {
      fakeDocument.cookie = original;
    }
  });
});
