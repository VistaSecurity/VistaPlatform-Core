// The licensed-tenant read (MSP soft cap) and what the shell banner makes of it.
//
// The request half runs the REAL query options through a REAL QueryClient over
// a stubbed fetch (edition.test.ts's harness), so the path and the error
// handling are react-query's actual behaviour. The copy half is pure.
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { QueryClient, QueryObserver } from '@tanstack/react-query';
import type { LicenseCap } from './license-cap';

const requestedUrls: string[] = [];
let nextResponse: () => Response = () => new Response('{}', { status: 200 });
const fetchStub = vi.fn(async (req: Request) => {
  requestedUrls.push(new URL(req.url).pathname);
  return nextResponse();
});
class RelativeUrlRequest extends Request {
  constructor(input: RequestInfo | URL, init?: RequestInit) {
    super(typeof input === 'string' && input.startsWith('/') ? `http://gateway.test${input}` : input, init);
  }
}
const realFetch = globalThis.fetch;
const realRequest = globalThis.Request;

let mod: typeof import('./license-cap');

beforeAll(async () => {
  vi.stubGlobal('fetch', fetchStub);
  vi.stubGlobal('Request', RelativeUrlRequest);
  vi.stubGlobal('document', { cookie: '' });
  mod = await import('./license-cap');
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

async function run(): Promise<{ status: string; error: unknown; data: unknown }> {
  const client = new QueryClient({ defaultOptions: { queries: { gcTime: 0 } } });
  const observer = new QueryObserver(client, { ...mod.licenseCapQuery(), retry: false, refetchInterval: false } as never);
  const settled = await new Promise<{ status: string; error: unknown; data: unknown }>((resolve) => {
    const unsubscribe = observer.subscribe((r) => {
      if (r.isFetching || r.status === 'pending') return;
      unsubscribe();
      resolve({ status: r.status, error: r.error, data: r.data });
    });
  });
  client.clear();
  return settled;
}

const cap = (over: Partial<LicenseCap>): LicenseCap => ({
  edition: 'msp', licensed: 10, current: 4, operator: 1,
  grace_started_at: null, grace_days: 30, grace_ends_at: null, state: 'under',
  ...over,
});

describe('the request', () => {
  it('asks admin-service on its Core route and returns the body', async () => {
    nextResponse = () => json(cap({}));
    const res = await run();
    expect(res.status).toBe('success');
    expect(requestedUrls).toEqual(['/api/v1/admin-service/admin/license/cap']);
    expect((res.data as LicenseCap).licensed).toBe(10);
  });

  it('surfaces a failed read as an error, not as "uncapped"', async () => {
    nextResponse = () => json({ error: 'nope' }, 500);
    const res = await run();
    expect(res.status).toBe('error');
    expect((res.error as Error).message).toBe('Could not read the licensed tenant limit');
  });
});

describe('capBanner — what the shell shows', () => {
  const now = new Date('2026-09-23T12:00:00Z');

  it('shows nothing while loading or after an error (no data)', () => {
    expect(mod.capBanner(undefined, now)).toBeNull();
  });

  it('shows nothing when uncapped or under the licence', () => {
    expect(mod.capBanner(cap({ edition: 'core', licensed: null, grace_days: null, state: 'uncapped' }), now)).toBeNull();
    expect(mod.capBanner(cap({ edition: 'enterprise', licensed: null, grace_days: null, state: 'uncapped' }), now)).toBeNull();
    expect(mod.capBanner(cap({ current: 10, state: 'under' }), now)).toBeNull();
  });

  it('warns with the days of grace left while in grace', () => {
    const b = mod.capBanner(cap({
      current: 12, state: 'grace',
      grace_started_at: '2026-09-20T12:00:00Z', grace_ends_at: '2026-10-20T12:00:00Z',
    }), now);
    expect(b?.tone).toBe('warn');
    expect(b?.title).toBe('12 of 10 licensed tenants — 27 days of grace left');
  });

  it('rounds a part day up and says "day" for one', () => {
    const b = mod.capBanner(cap({ current: 11, state: 'grace', grace_ends_at: '2026-09-23T13:00:00Z' }), now);
    expect(b?.title).toBe('11 of 10 licensed tenants — 1 day of grace left');
  });

  it('states that new tenants are blocked after grace', () => {
    const b = mod.capBanner(cap({ current: 11, state: 'blocked', grace_ends_at: '2026-09-01T00:00:00Z' }), now);
    expect(b?.tone).toBe('danger');
    expect(b?.title).toBe('11 of 10 licensed tenants — grace period ended, new tenants are blocked');
    expect(b?.detail).toContain('Existing tenants keep working');
  });
});

describe('graceDaysLeft', () => {
  const now = new Date('2026-09-23T12:00:00Z');
  it('is 0 without an end or once it has passed', () => {
    expect(mod.graceDaysLeft(null, now)).toBe(0);
    expect(mod.graceDaysLeft('2026-09-23T11:59:00Z', now)).toBe(0);
  });
  it('counts whole days, rounding up', () => {
    expect(mod.graceDaysLeft('2026-09-24T12:00:00Z', now)).toBe(1);
    expect(mod.graceDaysLeft('2026-09-24T12:00:01Z', now)).toBe(2);
  });
});
