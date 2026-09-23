// @vitest-environment jsdom
//
// useSetTenantOperator over the REAL typed client and a REAL QueryClient, with
// only fetch stubbed: the request it sends, that the server's own refusal text
// (the 409 on a non-MSP licence) reaches the caller unchanged, and that a
// success refreshes the licensed-tenant banner from the response's cap.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const seen: { path: string; method: string; body: string }[] = [];
let nextResponse: () => Response = () => new Response('{}', { status: 200 });
const fetchStub = vi.fn(async (req: Request) => {
  seen.push({ path: new URL(req.url).pathname, method: req.method, body: await req.clone().text() });
  return nextResponse();
});
class RelativeUrlRequest extends Request {
  constructor(input: RequestInfo | URL, init?: RequestInit) {
    super(typeof input === 'string' && input.startsWith('/') ? `http://gateway.test${input}` : input, init);
  }
}
const realFetch = globalThis.fetch;
const realRequest = globalThis.Request;

type Queries = typeof import('./queries');
type CapModule = typeof import('../../lib/license-cap');
let queries: Queries;
let capMod: CapModule;

beforeAll(async () => {
  vi.stubGlobal('fetch', fetchStub);
  vi.stubGlobal('Request', RelativeUrlRequest);
  queries = await import('./queries');
  capMod = await import('../../lib/license-cap');
});
afterAll(() => {
  vi.stubGlobal('fetch', realFetch);
  vi.stubGlobal('Request', realRequest);
  vi.unstubAllGlobals();
});
beforeEach(() => {
  seen.length = 0;
});

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const ID = '33333333-3333-4333-8333-333333333333';

async function runMutation(isOperator: boolean, seed?: (qc: QueryClient) => void) {
  const qc = new QueryClient({ defaultOptions: { queries: { gcTime: Infinity }, mutations: { retry: false } } });
  seed?.(qc);
  let mutateAsync: ReturnType<Queries['useSetTenantOperator']>['mutateAsync'] | undefined;
  function Harness() {
    mutateAsync = queries.useSetTenantOperator().mutateAsync;
    return null;
  }
  const host = document.createElement('div');
  const root: Root = createRoot(host);
  act(() => root.render(<QueryClientProvider client={qc}><Harness /></QueryClientProvider>));
  let error: unknown;
  await act(async () => {
    try {
      await mutateAsync!({ id: ID, isOperator });
    } catch (e) {
      error = e;
    }
  });
  act(() => root.unmount());
  return { qc, error };
}

describe('useSetTenantOperator', () => {
  it('PUTs the flag and seeds the banner query with the returned cap', async () => {
    const cap = { edition: 'msp', licensed: 5, current: 3, operator: 1, grace_started_at: null, grace_days: 30, grace_ends_at: null, state: 'under' };
    nextResponse = () => json({ id: ID, is_operator: true, cap });
    const { qc, error } = await runMutation(true);
    expect(error).toBeUndefined();
    expect(seen[0]).toEqual({ path: `/api/v1/admin-service/admin/tenants/${ID}/operator`, method: 'PUT', body: '{"is_operator":true}' });
    expect(qc.getQueryData(capMod.licenseCapKey)).toEqual(cap);
  });

  it('patches the saved value into every cached tenant directory at once', async () => {
    // The tenant drawer reads its tenant from these caches; patching them on
    // success is what shows the new value before the refetch lands.
    nextResponse = () => json({ id: ID, is_operator: true });
    const other = '55555555-5555-4555-8555-555555555555';
    const rows = [{ id: ID, is_operator: false }, { id: other, is_operator: false }];
    const { qc, error } = await runMutation(true, (c) => {
      c.setQueryData(['platform', 'tenants', null], rows);
      c.setQueryData(['platform', 'tenants', ID], [rows[0]]);
    });
    expect(error).toBeUndefined();
    expect(qc.getQueryData(['platform', 'tenants', null])).toEqual([{ id: ID, is_operator: true }, { id: other, is_operator: false }]);
    expect(qc.getQueryData(['platform', 'tenants', ID])).toEqual([{ id: ID, is_operator: true }]);
  });

  it("passes the server's refusal text through unchanged", async () => {
    nextResponse = () => json({ error: "Marking the operator's own tenant applies to MSP licences only" }, 409);
    const { error } = await runMutation(false);
    expect((error as Error).message).toBe("Marking the operator's own tenant applies to MSP licences only");
  });

  it('falls back to a generic message when the server gives none', async () => {
    nextResponse = () => new Response('', { status: 500 });
    const { error } = await runMutation(false);
    expect((error as Error).message).toBe('Failed to update the tenant');
  });
});
