// @vitest-environment jsdom
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DevicesPage } from './devices-page';
import type { DeviceDiscovery } from './device-discoveries';

// Agent-routed Add device ( slice B): the attempt is a row in the Devices
// table until the agent answers. Every row state the spec's table names is
// rendered here through the REAL DevicesPage, with the API client mocked at the
// transport — so what is asserted is what the operator sees, and what is sent
// is the real request.

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const mocks = vi.hoisted(() => ({
  get: vi.fn(), post: vi.fn(), del: vi.fn(), navigate: vi.fn(),
  discoveries: [] as unknown[], devices: [] as unknown[],
}));
vi.mock('../../lib/clients', () => ({ clients: { devices: { GET: mocks.get, POST: mocks.post, DELETE: mocks.del, PUT: vi.fn() } } }));
vi.mock('react-router', () => ({ useNavigate: () => mocks.navigate }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));
vi.mock('@vistasecurity/primitives/rbac', async (importOriginal) => ({
  ...await importOriginal<typeof import('@vistasecurity/primitives/rbac')>(),
  PermissionGate: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

const AGENT = '6f1c2a52-7d0e-4d0e-9a51-1d1f4f2b0c11';
function attempt(status: DeviceDiscovery['status'], extra: Partial<DeviceDiscovery> = {}): DeviceDiscovery {
  return {
    id: `0b7a6c8e-0000-4000-8000-${status.padEnd(12, '0').slice(0, 12).replace(/[^0-9a-f]/g, 'a')}`,
    status, device_type: 'fortinet', management_url: 'https://192.0.2.10',
    agent_id: AGENT, agent_name: 'branch-agent', created_at: new Date().toISOString(), ...extra,
  };
}

let host: HTMLDivElement;
let root: Root;
let cache: QueryClient;
beforeEach(() => {
  mocks.get.mockReset(); mocks.post.mockReset(); mocks.del.mockReset();
  mocks.discoveries = []; mocks.devices = [];
  mocks.get.mockImplementation(async (path: string) => {
    if (path === '/devices') return { data: { devices: mocks.devices } };
    if (path === '/agents') return { data: { agents: [{ id: AGENT, name: 'branch-agent' }] } };
    if (path === '/devices/discoveries') return { data: { discoveries: mocks.discoveries } };
    return { error: { error: 'unexpected' } };
  });
  host = document.createElement('div'); document.body.appendChild(host);
  root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function renderPage() {
  await act(async () => { root.render(<QueryClientProvider client={cache}><DevicesPage /></QueryClientProvider>); });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
}
const pill = () => host.querySelector<HTMLElement>('[data-testid="discovery-pill"]');
const row = () => host.querySelector<HTMLElement>('[data-testid="discovery-row"]');
const button = (title: string) => host.querySelector<HTMLButtonElement>(`button[title="${title}"]`);

describe('Devices table — agent-routed Add device rows', () => {
  it('queued and running read "Discovering…"', async () => {
    for (const status of ['queued', 'running'] as const) {
      mocks.discoveries = [attempt(status)];
      cache.clear();
      await renderPage();
      expect(pill()?.textContent).toBe('Discovering…');
      expect(row()?.textContent).toContain('https://192.0.2.10');
      expect(row()?.textContent).toContain('via branch-agent');
      expect(button('Retry on branch-agent')).toBeNull();
    }
  });

  it('failed reads "Discovery failed" with the real reason on hover, and Retry re-queues it', async () => {
    const failed = attempt('failed', { error_code: 'authentication_failed', message: 'The device rejected the credentials.' });
    mocks.discoveries = [failed];
    mocks.post.mockResolvedValue({ data: { ...failed, status: 'queued' } });
    await renderPage();
    expect(pill()?.textContent).toBe('Discovery failed');
    expect(pill()?.title).toBe('The device rejected the credentials.');
    await act(async () => { button('Retry on branch-agent')!.click(); });
    expect(mocks.post).toHaveBeenCalledWith('/devices/discoveries/{id}/retry', { params: { path: { id: failed.id } } });
  });

  it('nobody picking it up is its own state, not a device failure, and can be retried', async () => {
    mocks.discoveries = [attempt('not_picked_up', { error_code: 'not_picked_up', message: "The agent didn't pick this up within 15 minutes." })];
    await renderPage();
    expect(pill()?.textContent).toBe('Not picked up');
    expect(pill()?.textContent).not.toContain('failed');
    expect(button('Retry on branch-agent')).not.toBeNull();
  });

  it('held for review links to the held identity', async () => {
    mocks.discoveries = [attempt('held_for_review', { observation_id: 'obs-1' })];
    await renderPage();
    expect(pill()?.textContent).toBe('Held for review');
    await act(async () => { button('Review the held identity in Approvals')!.click(); });
    expect(mocks.navigate).toHaveBeenCalledWith('/discovery/observations?observation_id=obs-1');
  });

  it('dismiss sends DELETE for that attempt', async () => {
    const failed = attempt('failed', { error_code: 'connection_failed', message: 'm' });
    mocks.discoveries = [failed];
    mocks.del.mockResolvedValue({ data: { message: 'ok' } });
    await renderPage();
    await act(async () => { button('Dismiss')!.click(); });
    expect(mocks.del).toHaveBeenCalledWith('/devices/discoveries/{id}', { params: { path: { id: failed.id } } });
  });

  it('success: the attempt row leaves and the device list is refetched, so the device populates in place', async () => {
    const running = attempt('running');
    mocks.discoveries = [running];
    await renderPage();
    expect(pill()?.textContent).toBe('Discovering…');
    const deviceLoads = () => mocks.get.mock.calls.filter(([p]) => p === '/devices').length;
    const before = deviceLoads();

    mocks.discoveries = [{ ...running, status: 'succeeded', asset_id: '9d3f0a52-7d0e-4d0e-9a51-1d1f4f2b0c22' }];
    mocks.devices = [{ id: '9d3f0a52-7d0e-4d0e-9a51-1d1f4f2b0c22', tenant_id: AGENT, device_type: 'fortinet', hostname: 'fw-branch-01', vendor: 'Fortinet', model: 'FortiGate 60F', connection_status: 'unknown' }];
    await act(async () => { await cache.refetchQueries({ queryKey: ['discovery', 'device-discoveries'] }); });
    for (let i = 0; i < 3; i++) await act(async () => { await new Promise((r) => setTimeout(r, 0)); });

    expect(row()).toBeNull();
    expect(deviceLoads()).toBeGreaterThan(before);
    expect(host.textContent).toContain('fw-branch-01');
  });

  it('an empty organization with only an attempt in flight still shows the table, not the empty state', async () => {
    mocks.discoveries = [attempt('queued')];
    await renderPage();
    expect(row()).not.toBeNull();
    expect(host.textContent).not.toContain('Nothing is managed yet');
  });
});
