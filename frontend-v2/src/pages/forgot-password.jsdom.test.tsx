// @vitest-environment jsdom
// The sign-in page links to /forgot-password; the page posts the email to the
// typed client once, shows ONE fixed neutral sentence on success (never the
// server's own wording), and shows an error on a server failure.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ post: vi.fn() }));
vi.mock('../lib/clients', () => ({ clients: { auth: { POST: mocks.post, GET: vi.fn() } } }));
vi.mock('@vistasecurity/primitives/auth', () => ({
  useAuth: () => ({ login: vi.fn(), isLoginLoading: false, isAuthenticated: false, isInitializing: false }),
}));

import { ForgotPasswordPage } from './forgot-password-page';
import { LoginPage } from './login-page';

let host: HTMLDivElement;
let root: Root;

function fill(el: HTMLInputElement, value: string) {
  Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set?.call(el, value);
  el.dispatchEvent(new window.Event('input', { bubbles: true }));
}

async function mount(path: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={[path]}>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/forgot-password" element={<ForgotPasswordPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
  });
}

async function submitEmail(email: string) {
  await act(async () => { fill(host.querySelector('input[type=email]') as HTMLInputElement, email); });
  await act(async () => {
    (host.querySelector('form') as HTMLFormElement).dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));
  });
  await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
}

beforeEach(() => {
  mocks.post.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

describe('forgot password', () => {
  it('the login page renders a Forgot password? link to /forgot-password', async () => {
    await mount('/login');
    const link = [...host.querySelectorAll('a')].find((a) => /Forgot password\?/.test(a.textContent ?? ''));
    expect(link).toBeTruthy();
    expect(link!.getAttribute('href')).toBe('/forgot-password');
  });

  it('posts the email once and shows the neutral message for a 200', async () => {
    mocks.post.mockResolvedValue({ data: { message: 'If the email exists, a password reset link has been sent' }, response: { ok: true, status: 200 } });
    await mount('/forgot-password');
    await submitEmail('a@example.com');
    expect(mocks.post).toHaveBeenCalledTimes(1);
    expect(mocks.post).toHaveBeenCalledWith('/auth/forgot-password', { body: { email: 'a@example.com' } });
    expect(host.textContent).toContain('If that address has an account, we sent a reset link');
  });

  it('never echoes server wording about the address (not-found style body)', async () => {
    mocks.post.mockResolvedValue({ data: { message: 'No account found for that email' }, response: { ok: true, status: 200 } });
    await mount('/forgot-password');
    await submitEmail('nobody@example.com');
    expect(host.textContent).toContain('If that address has an account, we sent a reset link');
    expect(host.textContent).not.toContain('No account found');
  });

  it('shows an error, not the neutral message, when the server fails (bodiless 500)', async () => {
    mocks.post.mockResolvedValue({ data: undefined, error: undefined, response: { ok: false, status: 500 } });
    await mount('/forgot-password');
    await submitEmail('a@example.com');
    expect(host.textContent).not.toContain('we sent a reset link');
    expect(host.textContent).toContain('Could not send the reset link');
  });

  it('links back to sign-in', async () => {
    await mount('/forgot-password');
    expect([...host.querySelectorAll('a')].some((a) => a.getAttribute('href') === '/login')).toBe(true);
  });
});
