// @vitest-environment jsdom
//
// The public (signed-out) pages: invitation accept, password reset, SSO
// callback. Each takes attacker-reachable input from the URL.
//
// MUTATIONS (recorded in the PR): delete the confirm/length checks in
// acceptWithPassword -> the invite test fails (POST is sent); delete the
// token-strip effect in either page -> the strip tests fail (the token stays in
// the URL); make getSsoCallbackError return the raw `error` again -> the SSO test
// fails (the script text is rendered).
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { createMemoryRouter, RouterProvider, Outlet, useLocation } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn() }));
vi.mock('../lib/clients', () => ({ clients: { auth: api } }));

import { AcceptInvitePage } from './accept-invite-page';
import { ResetPasswordPage } from './reset-password-page';
import { SsoCallbackPage } from './sso-callback-page';

let host: HTMLDivElement; let root: Root;
beforeEach(() => {
  api.GET.mockReset(); api.POST.mockReset();
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });
const flush = async () => { await act(async () => { await new Promise((r) => setTimeout(r, 20)); }); };

function Where() { const l = useLocation(); return <><span id="where">{l.pathname + l.search}</span><Outlet /></>; }
// A data router, like the app's: the page's mount-time navigate() must land.
async function mount(at: string, path: string, el: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const router = createMemoryRouter([{ element: <Where />, children: [{ path, element: el }] }], { initialEntries: [at] });
  await act(async () => { root.render(<QueryClientProvider client={qc}><RouterProvider router={router} /></QueryClientProvider>); });
  await flush();
}
const where = () => host.querySelector('#where')!.textContent;
/** Page text, excluding the router probe (which prints the URL). */
const pageText = () => [...host.children].filter((c) => c.id !== 'where').map((c) => c.textContent).join(' ');
async function type(el: HTMLInputElement, v: string) {
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(el, v);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
}
const input = (label: string) => host.querySelector<HTMLInputElement>(`input[aria-label="${label}"]`)!;
async function submit() {
  const form = host.querySelector('form')!;
  await act(async () => { form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); });
  await flush();
}

describe('accept-invite page', () => {
  const lookupOk = { data: { email: 'a@example.test', tenant_name: 'Acme', allow_password: true, sso_providers: [] }, response: { ok: true, status: 200 } };

  it('blocks a 7-character password and a mismatched confirmation, and strips the token from the URL', async () => {
    api.GET.mockResolvedValue(lookupOk);
    await mount('/accept-invite?token=secret-token', '/accept-invite', <AcceptInvitePage />);

    // The lookup used the token; the address bar no longer carries it.
    expect(api.GET.mock.calls[0][1].params.query.token).toBe('secret-token');
    expect(where()).toBe('/accept-invite');

    await type(input('Password'), '1234567');
    await type(input('Confirm password'), '1234567');
    await submit();
    expect(api.POST).not.toHaveBeenCalled();
    expect(host.textContent).toContain('at least 8 characters');

    await type(input('Password'), '12345678');
    await type(input('Confirm password'), '12345679');
    await submit();
    expect(api.POST).not.toHaveBeenCalled();
    expect(host.textContent).toContain('don’t match');
  });
});

describe('reset-password page', () => {
  it('reads the token once and strips it from the URL, then still submits it', async () => {
    api.POST.mockResolvedValue({ data: { ok: true }, response: { ok: true, status: 200 } });
    await mount('/reset-password?token=reset-secret', '/reset-password', <ResetPasswordPage />);

    expect(where()).toBe('/reset-password');
    expect(host.textContent).toContain('Choose a new password');

    const [pw, confirm] = [...host.querySelectorAll<HTMLInputElement>('input')];
    await type(pw, 'longenough1');
    await type(confirm, 'longenough1');
    await submit();
    expect(api.POST.mock.calls[0][1].body.token).toBe('reset-secret');
  });
});

describe('sso-callback page', () => {
  it('never renders an attacker-chosen error value; shows the generic message', async () => {
    await mount('/auth/sso/callback?error=%3Cscript%3Ephish&error_description=Call%20555-0100', '/auth/sso/callback', <SsoCallbackPage />);
    expect(pageText()).toContain('SSO sign-in failed');
    expect(pageText()).toContain('couldn’t complete single sign-on');
    expect(pageText()).not.toContain('phish');
    expect(pageText()).not.toContain('555');
    await flush();
    expect(where()).toBe('/auth/sso/callback');
  });
});
