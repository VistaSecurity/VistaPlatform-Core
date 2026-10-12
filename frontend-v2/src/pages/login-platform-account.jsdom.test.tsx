// @vitest-environment jsdom
//: a platform account typing its credentials at the tenant sign-in is told
// where to go (with a link when the server knew the admin console's address),
// not shown a generic failure.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ post: vi.fn(), login: vi.fn() }));
vi.mock('../lib/clients', () => ({ clients: { auth: { POST: mocks.post, GET: vi.fn() } } }));
vi.mock('@vistasecurity/primitives/auth', async () => {
  const actual = await vi.importActual<typeof import('@vistasecurity/primitives/auth')>('@vistasecurity/primitives/auth');
  return {
    ...actual,
    useAuth: () => ({ login: mocks.login, isLoginLoading: false, isAuthenticated: false, isInitializing: false }),
  };
});

import { PlatformAccountError } from '@vistasecurity/primitives/auth';
import { LoginPage } from './login-page';

let host: HTMLDivElement;
let root: Root;

function fill(el: HTMLInputElement, value: string) {
  Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set?.call(el, value);
  el.dispatchEvent(new window.Event('input', { bubbles: true }));
}
const submit = async () => {
  await act(async () => {
    (host.querySelector('form') as HTMLFormElement).dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));
  });
  await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
};

beforeEach(async () => {
  mocks.post.mockReset();
  mocks.login.mockReset();
  // /auth/methods: password only, so the password step shows.
  mocks.post.mockResolvedValue({ data: { methods: [{ type: 'password', enabled: true }] }, response: new Response('{}', { status: 200 }) });
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  await act(async () => { root.render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <MemoryRouter><LoginPage /></MemoryRouter>
      </QueryClientProvider>,
    ); });
  await act(async () => { fill(host.querySelector('input[type=email]') as HTMLInputElement, 'staff@example.test'); });
  await submit();
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

describe('sign-in with platform credentials', () => {
  it('shows the platform-account message and a link to the admin console', async () => {
    mocks.login.mockRejectedValue(new PlatformAccountError('This is a platform account. Sign in at admin.example.test instead.', 'https://admin.example.test/'));
    await act(async () => { fill(host.querySelector('input[type=password]') as HTMLInputElement, 'pw'); });
    await submit();
    expect(host.textContent).toContain('This is a platform account. Sign in at admin.example.test instead.');
    const link = Array.from(host.querySelectorAll('a')).find((a) => a.textContent === 'Open the admin console');
    expect(link?.getAttribute('href')).toBe('https://admin.example.test/');
  });

  it('shows no link for an ordinary failure', async () => {
    mocks.login.mockRejectedValue(new Error('Invalid email or password'));
    await act(async () => { fill(host.querySelector('input[type=password]') as HTMLInputElement, 'pw'); });
    await submit();
    expect(host.textContent).toContain('Invalid email or password');
    expect(Array.from(host.querySelectorAll('a')).some((a) => a.textContent === 'Open the admin console')).toBe(false);
  });
});
