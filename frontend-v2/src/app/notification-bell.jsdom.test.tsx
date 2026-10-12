// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const get = vi.hoisted(() => vi.fn());
vi.mock('../lib/clients', () => ({ clients: { notifications: { GET: get, PUT: vi.fn() } } }));

import { NotificationBell } from './notification-bell';

let host: HTMLDivElement;
let root: Root;
const bell = () => host.querySelector('button[aria-haspopup]') as HTMLButtonElement;

beforeEach(async () => {
  get.mockReset();
  get.mockResolvedValue({ data: { notifications: [] }, response: { ok: true, status: 200 } });
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  await act(async () => {
    root.render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><NotificationBell /></MemoryRouter></QueryClientProvider>);
  });
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

describe('NotificationBell', () => {
  it('has an accessible name and reports expanded state', async () => {
    expect(bell().getAttribute('aria-label')).toContain('Notifications');
    expect(bell().getAttribute('aria-expanded')).toBe('false');
    await act(async () => { bell().click(); });
    expect(bell().getAttribute('aria-expanded')).toBe('true');
    expect(host.textContent).toContain('No notifications yet');
  });

  it('closes on Escape', async () => {
    await act(async () => { bell().click(); });
    expect(host.textContent).toContain('Mark all read');
    await act(async () => { document.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true })); });
    expect(host.textContent).not.toContain('Mark all read');
    expect(bell().getAttribute('aria-expanded')).toBe('false');
  });

  it('does not refetch on open while the list is fresh', async () => {
    const before = get.mock.calls.length;
    await act(async () => { bell().click(); });
    expect(get.mock.calls.length).toBe(before);
  });
});
