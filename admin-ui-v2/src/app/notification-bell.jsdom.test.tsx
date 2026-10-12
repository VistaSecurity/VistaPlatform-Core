// @vitest-environment jsdom
//
// Notification bell, MOUNTED: the trigger needs an accessible name and
// expanded state, Esc closes the panel, and a failed mark-read is reported.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => ({
  toastError: vi.fn(),
  put: vi.fn(),
}));

vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: h.toastError } }));
vi.mock('../lib/clients', () => ({
  clients: {
    notifications: {
      GET: async () => ({ data: { notifications: [{ id: 'n1', title: 'Hello', message: 'm', type: 'info', created_at: '2026-10-01T00:00:00Z', read_at: null }] } }),
      PUT: h.put,
    },
  },
}));

import { NotificationBell } from './notification-bell';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let root: Root | null = null;
let host: HTMLDivElement;

async function flush() {
  await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
}

beforeEach(async () => {
  h.toastError.mockReset();
  h.put.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root!.render(
      <QueryClientProvider client={qc}><MemoryRouter><NotificationBell /></MemoryRouter></QueryClientProvider>,
    );
  });
  await flush();
});
afterEach(() => {
  act(() => root?.unmount());
  host.remove();
  root = null;
});

const trigger = () => host.querySelector<HTMLButtonElement>('button[aria-haspopup]')!;

describe('notification bell', () => {
  it('has an accessible name and reflects expanded state; Esc closes', async () => {
    expect(trigger().getAttribute('aria-label')).toMatch(/^Notifications/);
    expect(trigger().getAttribute('aria-expanded')).toBe('false');
    await act(async () => { trigger().click(); });
    expect(trigger().getAttribute('aria-expanded')).toBe('true');
    expect(host.textContent).toContain('Hello');
    act(() => { document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true })); });
    expect(trigger().getAttribute('aria-expanded')).toBe('false');
    expect(host.textContent).not.toContain('Notification delivery');
  });

  it('reports a failed mark-read', async () => {
    h.put.mockResolvedValue({ error: { message: 'nope' } });
    await act(async () => { trigger().click(); });
    const row = Array.from(host.querySelectorAll('button')).find((b) => b.textContent?.includes('Hello'))!;
    await act(async () => { row.click(); });
    await flush();
    expect(h.toastError).toHaveBeenCalled();
  });
});
