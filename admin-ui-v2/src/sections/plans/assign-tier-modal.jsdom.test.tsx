// @vitest-environment jsdom
//
// Plans & Pricing ▸ Tiers ▸ Assign to tenant, MOUNTED over a real QueryClient
// and the real typed client with only fetch stubbed (owner decision 7,
// admin-UI data review RC-25):
//   - a reason is required — Assign stays disabled until one is typed, and it
//     is sent with the request (the audit log records it);
//   - when admin-service refuses a Stripe-billed tenant (409 "This tenant is
//     billed through Stripe — change plan through billing") that message is
//     what the operator sees, not "Failed to assign plan".
//
// Mutations run (each red, then restored green): dropping the reason from the
// body; dropping the reason check from the form; reverting the error to the
// generic message.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { adminServiceComponents } from '@vistasecurity/api-contract';

const TIER = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const TENANT = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const STRIPE_REFUSAL = 'This tenant is billed through Stripe — change plan through billing';

const server = { assignStatus: 200, bodies: [] as unknown[] };
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const fetchStub = vi.fn(async (req: Request) => {
  const path = new URL(req.url).pathname;
  if (path.endsWith(`/admin/tiers/${TIER}/assign`) && req.method === 'POST') {
    server.bodies.push(await req.json());
    return server.assignStatus === 200
      ? json({ tenant_id: TENANT, tier_id: TIER, tier_name: 'enterprise', billing_method: 'invoice', payment_status: 'active', activated: true })
      : json({ error: STRIPE_REFUSAL }, server.assignStatus);
  }
  return json({ error: 'not stubbed' }, 404);
});
class RelativeUrlRequest extends Request {
  constructor(input: RequestInfo | URL, init?: RequestInit) {
    super(typeof input === 'string' && input.startsWith('/') ? `http://gateway.test${input}` : input, init);
  }
}
const realFetch = globalThis.fetch;
const realRequest = globalThis.Request;

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock('react-hot-toast', () => ({ default: toast }));
// Core: no tenant directory, so the modal takes a pasted tenant id.
vi.mock('../../lib/edition', () => ({ usePlatformEdition: () => ({ has: () => false, isMsp: false, license: 'core' }) }));

type ModalModule = typeof import('./assign-tier-modal');
let mod: ModalModule;
beforeAll(async () => {
  vi.stubGlobal('fetch', fetchStub);
  vi.stubGlobal('Request', RelativeUrlRequest);
  mod = await import('./assign-tier-modal');
});
afterAll(() => {
  vi.stubGlobal('fetch', realFetch);
  vi.stubGlobal('Request', realRequest);
  vi.unstubAllGlobals();
});

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let root: Root | null = null;
let host: HTMLDivElement;
beforeEach(() => {
  server.assignStatus = 200;
  server.bodies = [];
  toast.success.mockReset();
  toast.error.mockReset();
});
afterEach(() => {
  act(() => root?.unmount());
  root = null;
  host?.remove();
});

const tier = { id: TIER, name: 'enterprise', display_name: 'Enterprise' } as adminServiceComponents['schemas']['SubscriptionTier'];

function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => root!.render(<QueryClientProvider client={qc}><mod.AssignTierModal tier={tier} onClose={() => {}} /></QueryClientProvider>));
}
function type(el: HTMLInputElement | HTMLTextAreaElement, value: string) {
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  act(() => {
    Object.getOwnPropertyDescriptor(proto, 'value')!.set!.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
}
const assignButton = () => Array.from(host.querySelectorAll('button')).find((b) => b.textContent === 'Assign')!;
async function settle() {
  for (let i = 0; i < 10; i++) await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
}

describe('Assign to tenant', () => {
  it('requires a reason and sends it', async () => {
    mount();
    type(host.querySelector('input')!, TENANT);
    expect(assignButton().disabled).toBe(true);
    type(host.querySelector('textarea')!, '   ');
    expect(assignButton().disabled).toBe(true);
    type(host.querySelector('textarea')!, 'PO 1234 signed');
    expect(assignButton().disabled).toBe(false);
    act(() => assignButton().click());
    await settle();
    expect(server.bodies).toEqual([{ tenant_id: TENANT, reason: 'PO 1234 signed' }]);
    expect(toast.success).toHaveBeenCalled();
  });

  it("shows admin-service's refusal for a Stripe-billed tenant", async () => {
    server.assignStatus = 409;
    mount();
    type(host.querySelector('input')!, TENANT);
    type(host.querySelector('textarea')!, 'moving to invoice');
    act(() => assignButton().click());
    await settle();
    expect(toast.error).toHaveBeenCalledWith(STRIPE_REFUSAL);
  });
});
