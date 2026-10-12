// @vitest-environment jsdom
// The sensor registration badge must not claim "registered" when the request
// that decides it failed, and must stop polling on error.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const OK = { ok: true, status: 200 };
const FAIL = { data: undefined, error: { error: 'boom' }, response: { ok: false, status: 500 } };
const mocks = vi.hoisted(() => ({ pending: null as unknown, sensors: null as unknown }));
vi.mock('../../lib/clients', () => ({
  clients: {
    sensors: {
      GET: vi.fn(async (path: string) => (path === '/sensors/pending' ? mocks.pending : mocks.sensors)),
    },
  },
}));
vi.mock('./agent-downloads', () => ({
  CORE_RELEASES_URL: '', binaryUrl: () => '', installerUrl: () => '', releasePageUrl: () => '', usePlatformReleaseTag: () => ({}),
}));
vi.mock('@vistasecurity/primitives/rbac', () => ({
  PermissionGate: ({ children }: { children: unknown }) => children,
  TENANT_PERMISSIONS: {},
  usePermissions: () => ({ hasPermission: () => true }),
}));

import { useRegistrationStatus } from './sensor-modals';

let host: HTMLDivElement;
let root: Root;

function Probe() {
  const q = useRegistrationStatus({ open: true, key: 'k1', name: 'n', ip: '1.1.1.1' });
  return <span data-status={q.data ?? ''} data-error={String(q.isError)} />;
}

function latest(): { status: string; isError: boolean } {
  const el = host.querySelector('span');
  return { status: el?.getAttribute('data-status') ?? '', isError: el?.getAttribute('data-error') === 'true' };
}

async function run() {
  const qc = new QueryClient();
  await act(async () => { root.render(<QueryClientProvider client={qc}><Probe /></QueryClientProvider>); });
  // retry: 1 with a 1s delay, then the error settles.
  for (let i = 0; i < 40 && !latest().isError && !latest().status; i++) {
    await act(async () => { await new Promise((r) => setTimeout(r, 100)); });
  }
}

beforeEach(() => { host = document.createElement('div'); root = createRoot(host) ; });
afterEach(() => { act(() => root.unmount()); });

describe('useRegistrationStatus', () => {
  it('errors (does not report "registered") when /sensors/pending fails', async () => {
    mocks.pending = FAIL;
    mocks.sensors = { data: { sensors: [] }, response: OK };
    await run();
    expect(latest().isError).toBe(true);
    expect(latest().status).toBe('');
  });

  it('errors when /sensors fails after the key was consumed', async () => {
    mocks.pending = { data: { pending_sensors: [] }, response: OK };
    mocks.sensors = FAIL;
    await run();
    expect(latest().isError).toBe(true);
  });

  it('reports registered when both calls succeed and no heartbeat yet', async () => {
    mocks.pending = { data: { pending_sensors: [] }, response: OK };
    mocks.sensors = { data: { sensors: [{ name: 'n', ip_address: '1.1.1.1' }] }, response: OK };
    await run();
    expect(latest().status).toBe('registered');
  });
});
