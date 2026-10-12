// @vitest-environment jsdom
//
// The legal re-acceptance gate's "I agree" button, MOUNTED against a bodiless
// 500. The accept mutation used to be `if (error) throw`, and openapi-fetch
// gives a falsy `error` for an error response with no body — so the failed
// write looked like success, the pending query was invalidated, refetched the
// same pending documents, and the gate looped without a word. The write must
// fail visibly and the gate must stay up.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const get = vi.fn();
const post = vi.fn();
vi.mock('../lib/clients', () => ({ clients: { auth: { GET: (...a: unknown[]) => get(...a), POST: (...a: unknown[]) => post(...a) } } }));
vi.mock('../components/legal-links', () => ({ LegalLinks: () => null }));

import { LegalGate } from './legal-gate';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let container: HTMLDivElement;
let root: Root;

const flush = () => act(async () => { await new Promise((r) => setTimeout(r, 0)); });

beforeEach(() => {
  get.mockReset();
  post.mockReset();
  get.mockResolvedValue({ data: { documents: [{ id: 'd1', type: 'terms', version: '2' }] }, response: new Response(null, { status: 200 }) });
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

async function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <LegalGate><div data-testid="app">the app</div></LegalGate>
      </QueryClientProvider>,
    );
  });
  await flush();
}

const acceptButton = () => [...container.querySelectorAll('button')].find((b) => /I agree/.test(b.textContent ?? ''));

describe('LegalGate accept', () => {
  it('a bodiless 500 shows an error and the gate stays up', async () => {
    post.mockResolvedValue({ data: undefined, error: undefined, response: new Response(null, { status: 500 }) });
    await mount();
    expect(acceptButton()).toBeTruthy();

    await act(async () => { acceptButton()!.click(); });
    await flush();

    expect(post).toHaveBeenCalledTimes(1);
    expect(container.textContent).toContain('Could not record your acceptance');
    expect(container.querySelector('[data-testid="app"]')).toBeNull();
    // Nothing was accepted, so the pending list must not have been re-read as if it had been.
    expect(get).toHaveBeenCalledTimes(1);
  });

  it('a 204 accept re-checks pending and releases the gate', async () => {
    post.mockResolvedValue({ response: new Response(null, { status: 204 }) });
    await mount();
    get.mockResolvedValue({ data: { documents: [] }, response: new Response(null, { status: 200 }) });

    await act(async () => { acceptButton()!.click(); });
    await flush();

    expect(container.querySelector('[data-testid="app"]')).not.toBeNull();
  });
});
