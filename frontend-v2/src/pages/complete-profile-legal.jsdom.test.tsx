// @vitest-environment jsdom
// A failed /auth/legal/current must block registration with a visible error —
// not read as "no terms published" (which hides the checkbox and lets the form
// submit without acceptance).
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ legalOk: false }));
vi.mock('../lib/clients', () => ({
  clients: {
    auth: {
      GET: vi.fn(async () => (mocks.legalOk
        ? { data: { documents: [{ doc_type: 'tos', title: 'Terms' }] }, response: { ok: true, status: 200 } }
        : { data: undefined, error: { error: 'boom' }, response: { ok: false, status: 500 } })),
      POST: vi.fn(),
    },
  },
}));

import { CompleteProfilePage } from './complete-profile-page';

let host: HTMLDivElement;
let root: Root;

function fill(el: HTMLInputElement, value: string) {
  const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
  setter?.call(el, value);
  el.dispatchEvent(new window.Event('input', { bubbles: true }));
}

async function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={['/complete-profile?email=a@b.co']}><CompleteProfilePage /></MemoryRouter>
      </QueryClientProvider>,
    );
  });
  await act(async () => { await Promise.resolve(); });
  const inputs = [...host.querySelectorAll('input')] as HTMLInputElement[];
  // email, first, last, org, password, confirm
  await act(async () => {
    fill(inputs[1], 'Ada'); fill(inputs[2], 'Lovelace');
    fill(inputs[4], 'correct-horse'); fill(inputs[5], 'correct-horse');
  });
}

const submitButton = () => [...host.querySelectorAll('button')].find((b) => /Create account/.test(b.textContent ?? ''))!;

beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

describe('complete-profile legal terms', () => {
  it('blocks submission with a visible error when the terms fail to load', async () => {
    mocks.legalOk = false;
    await mount();
    expect(host.textContent).toContain('Could not load the terms of service');
    expect(submitButton().disabled).toBe(true);
  });

  it('still requires the checkbox when the terms load', async () => {
    mocks.legalOk = true;
    await mount();
    expect(host.textContent).not.toContain('Could not load the terms');
    expect(host.querySelector('input[type="checkbox"]')).not.toBeNull();
    expect(submitButton().disabled).toBe(true);
  });
});
