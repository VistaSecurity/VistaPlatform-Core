// @vitest-environment jsdom
//
// The network segment dialog shows the server's reason when it refuses a save
// with 400 — the case that matters is a CIDR too broad to be anybody's network
// ( W5.13): the person can only fix the value if they are told the rule.
// Any other failure keeps the generic message rather than leaking a server
// string that was never written for them.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const api = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn(), POST: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));

const { NetworkSegmentModal } = await import('./infra-modals');

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const TOO_BROAD =
  'segment too broad: 0.0.0.0/0 is too broad to register as one of your networks — IPv4 ranges must be /8 or narrower and IPv6 ranges /16 or narrower; register the specific ranges you own';

const segment = {
  id: 'seg-1', tenant_id: 't', name: 'Everything', segment_type: 'cidr', value: '0.0.0.0/0', network_type: 'public',
  environment: 'production', location_id: null, is_active: true, auto_approve_discoveries: false, tags: null,
  metadata: {}, created_at: '2026-09-24T00:00:00Z', updated_at: '2026-09-24T00:00:00Z',
};

let host: HTMLDivElement; let root: Root;
beforeEach(() => {
  api.GET.mockReset().mockResolvedValue({ data: { locations: [] }, response: { ok: true, status: 200 } });
  api.PUT.mockReset();
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

async function saveAndSettle() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <NetworkSegmentModal open segment={segment} onClose={() => {}} />
      </QueryClientProvider>,
    );
  });
  const save = [...document.body.querySelectorAll('button')].find((b) => b.textContent === 'Save changes');
  expect(save).toBeTruthy();
  await act(async () => { save!.click(); });
  for (let i = 0; i < 20 && !document.body.textContent?.includes('ailed') && !document.body.textContent?.includes('too broad'); i++) {
    await act(async () => { await new Promise((r) => setTimeout(r, 5)); });
  }
}

it('shows the server reason when a too-broad CIDR is refused', async () => {
  api.PUT.mockResolvedValue({ data: undefined, error: { error: TOO_BROAD }, response: { ok: false, status: 400 } });
  await saveAndSettle();
  expect(document.body.textContent).toContain(TOO_BROAD);
});

it('keeps the generic message for a server failure', async () => {
  api.PUT.mockResolvedValue({ data: undefined, error: { error: 'Failed to update network segment' }, response: { ok: false, status: 500 } });
  await saveAndSettle();
  expect(document.body.textContent).toContain('Failed to save network segment');
  expect(document.body.textContent).not.toContain('Failed to update network segment');
});
