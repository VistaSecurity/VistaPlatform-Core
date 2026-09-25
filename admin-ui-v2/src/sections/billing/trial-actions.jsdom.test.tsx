// @vitest-environment jsdom
//
// Billing → Trials actions, MOUNTED over a real QueryClient and the real typed
// client with only fetch stubbed (owner decision 6; review of — the
// tenant editor refuses to start or end a trial by status and sends the
// operator to Billing → Trials, which had no controls):
//   - Extend sends additional_days to /extend and refuses a non-positive count;
//   - Convert POSTs /convert; End trial DELETEs the trial;
//   - End trial's dialog says what will happen before the operator confirms
// (owner decision, from admin-service's own answer
//     (GET /admin/billing/trials/end-landing): "moves the tenant to <Free
//     plan>" when the MSP has a Free plan, "suspends the tenant — no Free plan
//     is defined" when it has none; confirming is disabled until it knows, and
//     the toast reports where the tenant actually landed;
//   - Start trial POSTs the picked tenant (and the optional length — none
//     when left empty, which is the plan's length), and shows admin-service's
//     own refusals ("not a trial plan", "lasts at least 28 days") rather than a
// generic one (review of: a short length used to be silently ignored).
//
// Mutations run (each red, then restored green): pointing Convert at the
// DELETE; dropping additional_days from the extend body; accepting 0 days;
// replacing serverError with the generic message; swapping the two
// endTrialOutcome branches; hard-coding "Free" instead of the plan's name;
// dropping `!landing.data` from the confirm button's disabled state; a toast
// that ignores where the server says the tenant landed.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const TENANT = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const NOT_TRIAL_PLAN = "the tenant's plan is not a trial plan — assign a plan marked as a trial first";

const TOO_SHORT = "A trial on this plan lasts at least 28 days (14 days of full access plus 14 days of upgrade prompts); 7 is shorter. Leave the length empty for the plan's length, or change the plan's trial days.";

type Landing = { suspended: boolean; plan_id?: string; plan_name?: string };
const FREE: Landing = { suspended: false, plan_id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', plan_name: 'Starter Free' };
const NONE: Landing = { suspended: true };
const server = {
  status: 200,
  error: NOT_TRIAL_PLAN,
  landing: FREE,
  landingStatus: 200,
  calls: [] as { method: string; path: string; body: unknown }[],
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const fetchStub = vi.fn(async (req: Request) => {
  const path = new URL(req.url).pathname;
  if (path.endsWith('/admin/tenants') && req.method === 'GET') {
    return json({
      tenants: [
        { id: TENANT, name: 'Acme', slug: 'acme', subscription_tier: 'Starter Trial', payment_status: 'active' },
        { id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', name: 'Already Trialling', slug: 'already', subscription_tier: 'Starter Trial', payment_status: 'trial' },
      ],
      total: 2, page: 1, page_size: 100,
    });
  }
  if (path.endsWith('/admin/billing/trials/end-landing') && req.method === 'GET') {
    return server.landingStatus === 200 ? json(server.landing) : json({ error: 'Failed to look up the Free plan' }, server.landingStatus);
  }
  if (path.includes('/admin/billing/trials')) {
    const text = await req.text();
    server.calls.push({ method: req.method, path: path.slice(path.indexOf('/admin/')), body: text ? JSON.parse(text) : null });
    if (server.status !== 200) return json({ error: server.error }, server.status);
    return req.method === 'DELETE'
      ? json({ message: 'Trial ended', tenant_id: TENANT, landing: server.landing })
      : json({ message: 'ok', tenant_id: TENANT });
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
// Billing is MSP: the tenant directory is there to pick from.
vi.mock('../../lib/edition', () => ({ usePlatformEdition: () => ({ has: () => true, resolved: true, isMsp: true, license: 'msp' }) }));

type Mod = typeof import('./trial-actions');
let mod: Mod;
beforeAll(async () => {
  vi.stubGlobal('fetch', fetchStub);
  vi.stubGlobal('Request', RelativeUrlRequest);
  mod = await import('./trial-actions');
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
  server.status = 200;
  server.error = NOT_TRIAL_PLAN;
  server.landing = FREE;
  server.landingStatus = 200;
  server.calls = [];
  toast.success.mockReset();
  toast.error.mockReset();
});
afterEach(() => {
  act(() => root?.unmount());
  root = null;
  host?.remove();
});

function mount(node: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => root!.render(<QueryClientProvider client={qc}>{node}</QueryClientProvider>));
}
function type(el: HTMLInputElement, value: string) {
  act(() => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
}
// The dialog renders inside the host; its primary button is the last one.
const button = (label: string) => Array.from(host.querySelectorAll('button')).filter((b) => b.textContent === label).pop()!;
const click = (label: string) => act(() => button(label).click());
async function settle() {
  for (let i = 0; i < 10; i++) await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
}

const trial = { tenant_id: TENANT, tenant_name: 'Acme' };

describe('Billing → Trials row actions', () => {
  it('Extend sends additional_days and refuses a non-positive count', async () => {
    mount(<mod.TrialRowActions trial={trial} />);
    click('Extend');
    const days = host.querySelector('[role="dialog"] input') as HTMLInputElement;
    type(days, '0');
    expect(button('Extend').disabled).toBe(true);
    type(days, '10');
    expect(button('Extend').disabled).toBe(false);
    click('Extend');
    await settle();
    expect(server.calls).toEqual([{ method: 'POST', path: `/admin/billing/trials/tenants/${TENANT}/extend`, body: { additional_days: 10 } }]);
    expect(toast.success).toHaveBeenCalled();
  });

  it('Convert POSTs /convert', async () => {
    mount(<mod.TrialRowActions trial={trial} />);
    click('Convert');
    click('Convert');
    await settle();
    expect(server.calls).toEqual([{ method: 'POST', path: `/admin/billing/trials/tenants/${TENANT}/convert`, body: null }]);
  });

  const dialogText = () => host.querySelector('[role="dialog"]')?.textContent ?? '';

  it('End trial says it moves the tenant to the Free plan, then DELETEs the trial', async () => {
    mount(<mod.TrialRowActions trial={trial} />);
    click('End trial');
    await settle();
    expect(dialogText()).toContain('Moves the tenant to Starter Free, the Free plan');
    expect(dialogText()).not.toContain('Suspends');
    click('End trial');
    await settle();
    expect(server.calls).toEqual([{ method: 'DELETE', path: `/admin/billing/trials/tenants/${TENANT}`, body: null }]);
    expect(toast.success).toHaveBeenCalledWith("Ended Acme's trial — moved to Starter Free");
  });

  it('End trial says it suspends the tenant when no Free plan is defined', async () => {
    server.landing = NONE;
    mount(<mod.TrialRowActions trial={trial} />);
    click('End trial');
    await settle();
    expect(dialogText()).toContain('Suspends the tenant — no Free plan is defined');
    expect(dialogText()).not.toContain('Moves the tenant');
    click('End trial');
    await settle();
    expect(server.calls.map((c) => c.method)).toEqual(['DELETE']);
    expect(toast.success).toHaveBeenCalledWith("Ended Acme's trial — suspended (no Free plan is defined)");
  });

  it('End trial cannot be confirmed until admin-service says where the tenant goes', async () => {
    server.landingStatus = 500;
    mount(<mod.TrialRowActions trial={trial} />);
    click('End trial');
    await settle();
    expect(dialogText()).not.toContain('Moves the tenant');
    expect(dialogText()).not.toContain('Suspends');
    expect(button('End trial').disabled).toBe(true);
    click('End trial');
    await settle();
    expect(server.calls).toEqual([]);
  });
});

describe('Billing → Trials → Start trial', () => {
  it('starts a trial for the picked tenant, and lists only tenants not already trialling', async () => {
    mount(<mod.StartTrialModal onClose={() => {}} />);
    await settle();
    expect(host.textContent).toContain('Acme');
    expect(host.textContent).not.toContain('Already Trialling');
    expect(button('Start trial').disabled).toBe(true);
    click('Acme — on Starter Trial');
    type(host.querySelectorAll('[role="dialog"] input')[1] as HTMLInputElement, '21');
    click('Start trial');
    await settle();
    expect(server.calls).toEqual([{ method: 'POST', path: '/admin/billing/trials', body: { tenant_id: TENANT, duration: 21 } }]);
  });

  it("sends no length when it is left empty (the plan's length)", async () => {
    mount(<mod.StartTrialModal onClose={() => {}} />);
    await settle();
    expect((host.querySelectorAll('[role="dialog"] input')[1] as HTMLInputElement).placeholder).toBe("The plan's length");
    click('Acme — on Starter Trial');
    click('Start trial');
    await settle();
    expect(server.calls).toEqual([{ method: 'POST', path: '/admin/billing/trials', body: { tenant_id: TENANT } }]);
  });

  it("shows admin-service's refusal of a length shorter than the plan's", async () => {
    server.status = 400;
    server.error = TOO_SHORT;
    mount(<mod.StartTrialModal onClose={() => {}} />);
    await settle();
    click('Acme — on Starter Trial');
    type(host.querySelectorAll('[role="dialog"] input')[1] as HTMLInputElement, '7');
    click('Start trial');
    await settle();
    expect(toast.error).toHaveBeenCalledWith(TOO_SHORT);
    expect(toast.success).not.toHaveBeenCalled();
  });

  it("shows admin-service's refusal for a tenant not on a trial plan", async () => {
    server.status = 409;
    mount(<mod.StartTrialModal onClose={() => {}} />);
    await settle();
    click('Acme — on Starter Trial');
    click('Start trial');
    await settle();
    expect(toast.error).toHaveBeenCalledWith(NOT_TRIAL_PLAN);
  });
});
