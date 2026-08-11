// Edition-gating regression guard.
//
// The Go backend is carved into Core and Enterprise editions. An Enterprise
// route DOES NOT EXIST in a Core build — it 404s, it is not a 403. So a
// frontend that calls one unconditionally shows the operator a broken page.
//
// Two gating mechanisms, and these tests pin BOTH directions of each:
//
//   1. FLAG-GATED (preferred) — the capability has a registered entitlement key,
//      so the flag is known before the request. Flag off ⇒ react-query is
//      `enabled: false` ⇒ ZERO requests. Covered here for `sso_saml`.
//
//   2. EDITION-PROBED (fallback) — CMDB/ITSM sync and SIEM export now have
//      registered keys, but the response probe remains as a backstop for Core
//      builds (404) and stale/unentitled calls (402). Either status ⇒
//      EditionUnavailableError ⇒ exactly ONE request (never retried) ⇒ upgrade
//      card, not a red error.
//
// Everything runs through a REAL QueryClient/QueryObserver over a stubbed fetch,
// so "no request fired" is asserted against react-query's actual behaviour
// rather than against a boolean we set ourselves.
import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import { QueryClient, QueryObserver } from '@tanstack/react-query';
import { isEditionUnavailable } from '@vistasecurity/primitives/features';

// --- fetch/Request stubs -----------------------------------------------------
// The typed clients use relative gateway paths (/api/v1/...); node's Request
// rejects those, and openapi-fetch captures globalThis.{fetch,Request} at
// client-creation time — so the stubs must be installed BEFORE the modules that
// build clients are imported (hence the dynamic import in beforeAll). Same
// pattern as clients.csrf.test.ts.
let nextResponse: () => Response = () => new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
const requestedUrls: string[] = [];

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

type IntegrationsModule = typeof import('./integrations-queries');
type SsoModule = typeof import('./sso-queries');
type BillingModule = typeof import('./billing-queries');
let integrations: IntegrationsModule;
let sso: SsoModule;
let billing: BillingModule;

beforeAll(async () => {
  vi.stubGlobal('fetch', fetchStub);
  vi.stubGlobal('Request', RelativeUrlRequest);
  vi.stubGlobal('document', { cookie: '' });
  integrations = await import('./integrations-queries');
  sso = await import('./sso-queries');
  billing = await import('./billing-queries');
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

/**
 * Mount one query through a real QueryClient and wait for it to settle.
 *
 * A fresh client per run so nothing is served from cache. `retry` comes from the
 * options under test — deliberately NOT overridden here, since the retry
 * behaviour is part of what's being asserted.
 */
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

/**
 * Mount a query that is expected to stay dormant. A disabled query never emits,
 * so there is nothing to await — subscribe, let the event loop drain, and report
 * what react-query did (which must be: nothing).
 */
async function observeDormant(options: object): Promise<{ status: string }> {
  const client = new QueryClient({ defaultOptions: { queries: { gcTime: 0 } } });
  const observer = new QueryObserver(client, options as never);
  const unsubscribe = observer.subscribe(() => {});
  await new Promise((r) => setTimeout(r, 30));
  const result = observer.getCurrentResult();
  unsubscribe();
  client.clear();
  return { status: result.status };
}

describe('flag-gated surfaces skip the request entirely (sso_saml)', () => {
  it('fires NOTHING when the entitlement is off', async () => {
    const res = await observeDormant(sso.ssoProvidersQuery(false));
    expect(fetchStub).not.toHaveBeenCalled();
    expect(requestedUrls).toEqual([]);
    // Pending-with-no-fetch is exactly what a disabled query looks like; the
    // page renders its upgrade card off the same flag, never off this result.
    expect(res.status).toBe('pending');
  });

  it('fires the request when the entitlement is on', async () => {
    nextResponse = () => json({ providers: [{ id: 'p1', provider_name: 'Okta' }] });
    const res = await run(sso.ssoProvidersQuery(true));
    expect(fetchStub).toHaveBeenCalledTimes(1);
    expect(requestedUrls[0]).toContain('/tenant/sso/providers');
    expect(res.status).toBe('success');
  });

  it('gates the authentication policy on the same flag', async () => {
    const off = await observeDormant(sso.authPolicyQuery(false));
    expect(fetchStub).not.toHaveBeenCalled();
    expect(off.status).toBe('pending');
  });
});

describe('flag-gated Enterprise integrations skip the request entirely', () => {
  it('fires NOTHING for CMDB / ITSM sync when cmdb_sync is off', async () => {
    const res = await observeDormant(integrations.cmdbProfilesQuery(false));
    expect(fetchStub).not.toHaveBeenCalled();
    expect(requestedUrls).toEqual([]);
    expect(res.status).toBe('pending');
  });

  it('fires NOTHING for SIEM export when siem_export is off', async () => {
    const res = await observeDormant(integrations.siemIntegrationsQuery(false));
    expect(fetchStub).not.toHaveBeenCalled();
    expect(requestedUrls).toEqual([]);
    expect(res.status).toBe('pending');
  });
});

describe('flag-gated tenant billing skips the request entirely (billing_portal)', () => {
  // The reported symptom: on Core, Settings → Account → Billing rendered
  // "Couldn't load the subscription" / "Couldn't load invoices" because
  // /my-billing/** lives in admin-service/ee/billingapi and is never mounted.
  it('fires NOTHING for the subscription when billing_portal is off', async () => {
    const res = await observeDormant(billing.mySubscriptionQuery(false));
    expect(fetchStub).not.toHaveBeenCalled();
    expect(requestedUrls).toEqual([]);
    expect(res.status).toBe('pending');
  });

  it('fires NOTHING for invoices when billing_portal is off', async () => {
    const res = await observeDormant(billing.myInvoicesQuery(false));
    expect(fetchStub).not.toHaveBeenCalled();
    expect(requestedUrls).toEqual([]);
    expect(res.status).toBe('pending');
  });

  it('fires the requests when the entitlement is on', async () => {
    nextResponse = () => json({ subscription: { external_id: 'sub_1' }, tier: { name: 'pro', price_cents: 9900 } });
    const sub = await run(billing.mySubscriptionQuery(true));
    expect(fetchStub).toHaveBeenCalledTimes(1);
    expect(requestedUrls[0]).toContain('/my-billing/subscription');
    expect(sub.status).toBe('success');

    fetchStub.mockClear();
    requestedUrls.length = 0;
    nextResponse = () => json({ invoices: [{ id: 'in_1', status: 'paid' }] });
    const inv = await run(billing.myInvoicesQuery(true));
    expect(fetchStub).toHaveBeenCalledTimes(1);
    expect(requestedUrls[0]).toContain('/my-billing/invoices');
    expect(inv.status).toBe('success');
  });

  it('treats a Core 404 as "not in this edition" and does not retry', async () => {
    // Backstop for a stale feature map: the call still must not become a red
    // "couldn't load", and must not be retried — an absent route is settled.
    nextResponse = () => json({ error: 'not found' }, 404);
    const res = await run(billing.mySubscriptionQuery());
    expect(fetchStub).toHaveBeenCalledTimes(1);
    expect(res.status).toBe('error');
    expect(isEditionUnavailable(res.error)).toBe(true);
  });

  it('still reports a REAL failure as an error, not as an edition gate', async () => {
    nextResponse = () => json({ error: 'boom' }, 500);
    const res = await run(billing.myInvoicesQuery());
    expect(res.status).toBe('error');
    expect(isEditionUnavailable(res.error)).toBe(false);
    expect(fetchStub.mock.calls.length).toBeGreaterThan(1);
  });
});

describe('edition-probed backstop: CMDB / ITSM sync collection failures', () => {
  it('treats a 404 on the profiles collection as "not in this edition", and does not retry', async () => {
    nextResponse = () => json({ error: 'not found' }, 404);
    const res = await run(integrations.cmdbProfilesQuery());

    // Exactly ONE request: editionAwareRetry must not re-ask a settled absence.
    expect(fetchStub).toHaveBeenCalledTimes(1);
    expect(res.status).toBe('error');
    expect(isEditionUnavailable(res.error)).toBe(true);

    // ...and that is what drives the upgrade card rather than an error card.
    expect(integrations.editionSectionState({ isLoading: false, isError: true, error: res.error })).toBe('unavailable');
  });

  it('treats a 402 on the profiles collection as "upgrade required", and does not retry', async () => {
    nextResponse = () => json({ error: 'cmdb_sync entitlement required' }, 402);
    const res = await run(integrations.cmdbProfilesQuery());

    // A stale feature map or direct caller may still reach the route. That must
    // land on the same upgrade state as a Core 404, not a generic load error.
    expect(fetchStub).toHaveBeenCalledTimes(1);
    expect(res.status).toBe('error');
    expect(isEditionUnavailable(res.error)).toBe(true);
    expect(integrations.editionSectionState({ isLoading: false, isError: true, error: res.error })).toBe('unavailable');
  });

  it('renders normally against an Enterprise build', async () => {
    nextResponse = () => json({ profiles: [{ id: 'c1', name: 'ServiceNow prod', platform_type: 'servicenow' }] });
    const res = await run(integrations.cmdbProfilesQuery());

    expect(fetchStub).toHaveBeenCalledTimes(1);
    expect(requestedUrls[0]).toContain('/cmdb/profiles');
    expect(res.status).toBe('success');
    expect((res.data as { id: string }[])[0].id).toBe('c1');
    expect(integrations.editionSectionState({ isLoading: false, isError: false, error: null })).toBe('ready');
  });

  it('still reports a REAL failure as an error, not as an edition gate', async () => {
    nextResponse = () => json({ error: 'boom' }, 500);
    const res = await run(integrations.cmdbProfilesQuery());

    expect(res.status).toBe('error');
    expect(isEditionUnavailable(res.error)).toBe(false);
    expect(integrations.editionSectionState({ isLoading: false, isError: true, error: res.error })).toBe('error');
    // A 500 IS worth retrying, so more than one attempt is expected here.
    expect(fetchStub.mock.calls.length).toBeGreaterThan(1);
  });

  it('applies the same probe to SIEM export', async () => {
    nextResponse = () => json({ error: 'not found' }, 404);
    const res = await run(integrations.siemIntegrationsQuery());

    expect(fetchStub).toHaveBeenCalledTimes(1);
    expect(requestedUrls[0]).toContain('/siem/integrations');
    expect(isEditionUnavailable(res.error)).toBe(true);
  });
});

describe('editionSectionState precedence', () => {
  it('ranks an absent capability above a load error', () => {
    const err = new (class extends Error { editionUnavailable = true as const; })('gone');
    // isError is true in both cases; the edition signal must win, or the user
    // sees "couldn't load" for something that was never there to load.
    expect(integrations.editionSectionState({ isLoading: false, isError: true, error: err })).toBe('unavailable');
  });

  it('reports loading only while nothing has settled', () => {
    expect(integrations.editionSectionState({ isLoading: true, isError: false, error: null })).toBe('loading');
  });
});
