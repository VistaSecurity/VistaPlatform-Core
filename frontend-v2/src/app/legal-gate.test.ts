// B-29 regression guard — legal re-acceptance gate must fail CLOSED.
//
// LegalGate's `blocked` computation is fail-closed by construction
// (isLoading || isError || mustAccept), but that only holds if a server-side
// failure actually reaches isError. Before the fix, fetchLegalPending's
// queryFn destructured only `data` and never threw, so a non-2xx from
// GET /auth/legal/pending resolved as `[]` — indistinguishable from "no
// documents pending" — and the gate opened straight through with acceptance
// unrecorded. This pins the fix at the source: the fetcher itself must throw
// on any non-2xx or missing body, never swallow it into an empty array.
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

const fetchStub = vi.fn(async () => nextResponse());
let nextResponse: () => Response = () => new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });

// The app's clients use relative gateway base paths (/api/v1/...); node's
// Request rejects those, and openapi-fetch captures globalThis.{fetch,Request}
// at client-creation time, so the stubs must be installed before the module
// under test (which builds `clients` transitively) is imported.
class RelativeUrlRequest extends Request {
  constructor(input: RequestInfo | URL, init?: RequestInit) {
    super(typeof input === 'string' && input.startsWith('/') ? `http://gateway.test${input}` : input, init);
  }
}

const realFetch = globalThis.fetch;
const realRequest = globalThis.Request;

let fetchLegalPending: () => Promise<unknown[]>;

beforeAll(async () => {
  vi.stubGlobal('fetch', fetchStub);
  vi.stubGlobal('Request', RelativeUrlRequest);
  vi.stubGlobal('document', { cookie: '' });
  ({ fetchLegalPending } = await import('./legal-gate'));
});

afterAll(() => {
  vi.stubGlobal('fetch', realFetch);
  vi.stubGlobal('Request', realRequest);
  vi.unstubAllGlobals();
});

afterEach(() => fetchStub.mockClear());

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

describe('B-29: fetchLegalPending fails closed on a server error', () => {
  it('throws on a 500 — must NOT resolve as "nothing pending"', async () => {
    nextResponse = () => json({ error: 'internal error' }, 500);
    await expect(fetchLegalPending()).rejects.toThrow();
  });

  it('throws on a 403 too — any non-2xx is a fail-closed condition', async () => {
    nextResponse = () => json({ error: 'forbidden' }, 403);
    await expect(fetchLegalPending()).rejects.toThrow();
  });

  it('resolves the pending documents on a real 200', async () => {
    nextResponse = () => json({ documents: [{ id: 'terms-v3', title: 'Terms of Service' }] });
    await expect(fetchLegalPending()).resolves.toEqual([{ id: 'terms-v3', title: 'Terms of Service' }]);
  });

  it('resolves [] when the tenant genuinely has nothing pending', async () => {
    nextResponse = () => json({ documents: [] });
    await expect(fetchLegalPending()).resolves.toEqual([]);
  });
});
