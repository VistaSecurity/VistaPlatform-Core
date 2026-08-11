// The edition read-out itself: what it asks for, and what it concludes.
//
// Runs the REAL query options through a REAL QueryClient over a stubbed fetch,
// so "one request, to that path, with that conclusion" is asserted against
// react-query's actual behaviour rather than against a boolean we set ourselves.
// Same harness shape as frontend-v2/src/sections/settings/edition-gating.test.ts.
import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import { QueryClient, QueryObserver } from '@tanstack/react-query';

const requestedUrls: string[] = [];
let nextResponse: () => Response = () =>
  new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });

const fetchStub = vi.fn(async (req: Request) => {
  requestedUrls.push(new URL(req.url).pathname);
  return nextResponse();
});

// The typed clients use relative gateway paths; node's Request rejects those,
// and openapi-fetch captures globalThis.{fetch,Request} at client-creation
// time — so stubs must be installed BEFORE the module is imported.
class RelativeUrlRequest extends Request {
  constructor(input: RequestInfo | URL, init?: RequestInit) {
    super(typeof input === 'string' && input.startsWith('/') ? `http://gateway.test${input}` : input, init);
  }
}

const realFetch = globalThis.fetch;
const realRequest = globalThis.Request;

type EditionModule = typeof import('./edition');
let edition: EditionModule;

beforeAll(async () => {
  vi.stubGlobal('fetch', fetchStub);
  vi.stubGlobal('Request', RelativeUrlRequest);
  vi.stubGlobal('document', { cookie: '' });
  edition = await import('./edition');
});

afterAll(() => {
  vi.stubGlobal('fetch', realFetch);
  vi.stubGlobal('Request', realRequest);
  vi.unstubAllGlobals();
});

beforeEach(() => {
  fetchStub.mockClear();
  requestedUrls.length = 0;
});

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

async function run(options: object): Promise<{ status: string; error: unknown; data: unknown }> {
  const client = new QueryClient({ defaultOptions: { queries: { gcTime: 0 } } });
  const observer = new QueryObserver(client, options as never);
  const settled = await new Promise<{ status: string; error: unknown; data: unknown }>((resolve) => {
    const unsubscribe = observer.subscribe((result) => {
      if (result.isFetching || result.status === 'pending') return;
      unsubscribe();
      resolve({ status: result.status, error: result.error, data: result.data });
    });
  });
  client.clear();
  return settled;
}

describe('the read-out request', () => {
  it('asks admin-service, on a Core route', async () => {
    nextResponse = () => json({ edition: 'core', capabilities: { msp: false, billing: false } });
    const res = await run(edition.platformEditionQuery());

    expect(res.status).toBe('success');
    // Pinned deliberately: this path must stay one a build with no ee/ tree can
    // answer. Moving it under an Enterprise prefix would make the gate itself
    // 404 on exactly the deployments it exists to serve.
    expect(requestedUrls[0]).toBe('/api/v1/admin-service/admin/platform/edition');
    expect(fetchStub).toHaveBeenCalledTimes(1);
  });
});

describe('what the console concludes', () => {
  const state = (data: unknown, isError = false) =>
    edition.resolveEditionState(data as never, isError);

  it('hides the MSP and billing surfaces on a Core deployment', async () => {
    nextResponse = () => json({ edition: 'core', capabilities: { msp: false, billing: false } });
    const res = await run(edition.platformEditionQuery());
    const s = state(res.data);

    expect(s.edition).toBe('core');
    expect(s.has('msp')).toBe(false);
    expect(s.has('billing')).toBe(false);
    expect(s.resolved).toBe(true);
  });

  it('shows them on an Enterprise/MSP deployment', async () => {
    // The direction that a gate hard-coded to "hide" would still pass without.
    nextResponse = () => json({ edition: 'enterprise', capabilities: { msp: true, billing: true } });
    const res = await run(edition.platformEditionQuery());
    const s = state(res.data);

    expect(s.edition).toBe('enterprise');
    expect(s.has('msp')).toBe(true);
    expect(s.has('billing')).toBe(true);
  });

  it('honours a mixed read-out rather than collapsing to one flag', async () => {
    nextResponse = () => json({ edition: 'enterprise', capabilities: { msp: true, billing: false } });
    const s = state((await run(edition.platformEditionQuery())).data);

    expect(s.has('msp')).toBe(true);
    expect(s.has('billing')).toBe(false);
  });

  it('hides gated surfaces while the read-out is still in flight', () => {
    const s = state(undefined);
    expect(s.resolved).toBe(false);
    expect(s.has('msp')).toBe(false);
  });

  it('FAILS OPEN when the read-out cannot be obtained', async () => {
    // An admin-service too old to serve the route 404s it. Failing closed there
    // would blank half of a paying console over a version skew — a new outage
    // rather than a fix. Failing open degrades to the pre-fix behaviour.
    nextResponse = () => json({ error: 'not found' }, 404);
    const res = await run(edition.platformEditionQuery());

    expect(res.status).toBe('error');
    const s = state(res.data, true);
    expect(s.resolved).toBe(true);
    expect(s.has('msp')).toBe(true);
    expect(s.has('billing')).toBe(true);
    // ...but with no edition to report, the shell shows no badge rather than
    // claiming an edition it does not know.
    expect(s.edition).toBeNull();
    expect(edition.editionLabel(s.edition)).toBeNull();
  });

  it('does not hammer an absent route', async () => {
    nextResponse = () => json({ error: 'not found' }, 404);
    await run(edition.platformEditionQuery());
    // retry: 1 → at most two attempts, ever.
    expect(fetchStub.mock.calls.length).toBeLessThanOrEqual(2);
  });
});

describe('the edition badge', () => {
  it('names the build for the operator', () => {
    expect(edition.editionLabel('core')).toBe('Core');
    expect(edition.editionLabel('enterprise')).toBe('Enterprise');
  });
});
