// @vitest-environment jsdom
// The Connect / Edit cloud-integration modal shows the SERVER's error text.
//
// It used to throw a fixed "Failed to create integration" whatever the API
// said, so a 409 "An integration named "Production" already exists" — the one
// failure the user can fix themselves — read as an unexplained error.
//
// Mutation: put the literal 'Failed to create integration' back into the
// create branch's `throw new Error(...)` and the first test goes red.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { CloudIntegrationFormModal, serverErrorMessage } from './cloud-modals';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const post = vi.hoisted(() => vi.fn());
const put = vi.hoisted(() => vi.fn());
vi.mock('../../lib/clients', () => ({ clients: { devices: { POST: post, PUT: put } } }));

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  post.mockReset(); put.mockReset();
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function type(input: HTMLInputElement, value: string) {
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
}
function button(label: string) {
  const found = [...host.querySelectorAll('button')].find((b) => b.textContent === label);
  expect(found).toBeTruthy();
  return found!;
}

it('shows the server message when create is refused', async () => {
  post.mockResolvedValue({ error: { error: 'An integration named "Production" already exists' }, response: { status: 409 } });
  await act(async () => root.render(
    <QueryClientProvider client={cache}><CloudIntegrationFormModal open onClose={() => {}} /></QueryClientProvider>,
  ));

  await type(host.querySelector<HTMLInputElement>('input[placeholder="Production AWS"]')!, 'Production');
  await type(host.querySelector<HTMLInputElement>('input[placeholder="AKIA…"]')!, 'AKIAEXAMPLE');
  await type(host.querySelector<HTMLInputElement>('input[type="password"]')!, 'secret');
  await act(async () => button('Connect').click());

  expect(post).toHaveBeenCalledOnce();
  // The error renders from the mutation's onError, a tick after the click's
  // act() settles — wait for it rather than asserting on the same tick (that
  // raced under CI load).
  await vi.waitFor(() => expect(host.textContent).toContain('An integration named "Production" already exists'));
  expect(host.textContent).not.toContain('Failed to create integration');
});

it('falls back to the fixed message when the server sends none', () => {
  expect(serverErrorMessage(undefined, 'Failed to create integration')).toBe('Failed to create integration');
  expect(serverErrorMessage({ error: '  ' }, 'Failed')).toBe('Failed');
  expect(serverErrorMessage({ message: 'x' }, 'Failed')).toBe('Failed');
  expect(serverErrorMessage({ error: 'Invalid request' }, 'Failed')).toBe('Invalid request');
});
