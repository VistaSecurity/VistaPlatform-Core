// @vitest-environment jsdom
// The WIRING test for the "email isn't configured" card notice: channelNotice()
// is pinned in channel-test.jsdom.test.tsx, and this pins that the Integrations
// page actually asks the server and renders it on the EMAIL card only —
// deleting the query or the `notice` argument must fail here.
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { IntegrationsPage } from './pages-integrations';
import { EMAIL_NOT_CONFIGURED_NOTICE } from './channel-test';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const notifications = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn() }));
const inventory = vi.hoisted(() => ({ GET: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { notifications, inventory, compliance: { GET: vi.fn() } } }));
vi.mock('@vistasecurity/primitives/features', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@vistasecurity/primitives/features')>()),
  useFeature: () => false,
}));
vi.mock('@vistasecurity/primitives/rbac', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@vistasecurity/primitives/rbac')>()),
  PermissionGate: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

const now = '2026-01-01T00:00:00Z';
const channels = [
  { id: 'e-1', tenant_id: 't', channel_name: 'Ops email', channel_type: 'email', config: { recipients: ['ops@example.test'] }, enabled: true, created_at: now, updated_at: now },
  { id: 's-1', tenant_id: 't', channel_name: 'Ops slack', channel_type: 'slack', config: { webhook_url: 'https://hooks.example.test/••••' }, enabled: true, created_at: now, updated_at: now },
];

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
let deliveryStatus: { ok: boolean; data?: unknown };
beforeEach(() => {
  deliveryStatus = { ok: true, data: { email: { configured: false } } };
  notifications.GET.mockReset().mockImplementation(async (path: string) => {
    if (path === '/tenant/channels') return { data: channels, response: { ok: true } };
    if (path === '/tenant/delivery-status') return { data: deliveryStatus.data, response: { ok: deliveryStatus.ok } };
    return { data: [], response: { ok: true } };
  });
  inventory.GET.mockReset().mockResolvedValue({ data: { connectors: [], connections: [], profiles: [] }, response: { ok: true } });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function render() {
  const meta = { key: 'integrations', label: 'Integrations', icon: 'plug', job: 'Connections' };
  await act(async () => { root.render(<QueryClientProvider client={cache}><IntegrationsPage meta={meta} /></QueryClientProvider>); });
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); });
}

/** The text of the card that names this connection. */
function cardText(name: string): string {
  const title = [...host.querySelectorAll('div')].find((d) => d.textContent === name && d.children.length === 0);
  expect(title, `no card named ${name}`).toBeTruthy();
  // title → name column → header row → the card itself.
  return title!.parentElement?.parentElement?.parentElement?.textContent ?? '';
}

it('tells the tenant on the EMAIL card that email delivery is not configured', async () => {
  await render();
  expect(notifications.GET).toHaveBeenCalledWith('/tenant/delivery-status', {});
  expect(cardText('Ops email')).toContain(EMAIL_NOT_CONFIGURED_NOTICE);
  // ...and only there.
  expect(cardText('Ops slack')).not.toContain(EMAIL_NOT_CONFIGURED_NOTICE);
  expect(host.textContent?.split(EMAIL_NOT_CONFIGURED_NOTICE).length).toBe(2); // exactly once
});

it('shows no notice when email can deliver', async () => {
  deliveryStatus = { ok: true, data: { email: { configured: true } } };
  await render();
  expect(host.textContent).not.toContain(EMAIL_NOT_CONFIGURED_NOTICE);
});

// A failed status lookup must not become a false alarm on every email card.
it('shows no notice when the status lookup fails', async () => {
  deliveryStatus = { ok: false, data: undefined };
  await render();
  expect(host.textContent).not.toContain(EMAIL_NOT_CONFIGURED_NOTICE);
  // The cards themselves still render.
  expect(host.textContent).toContain('Ops email');
});
