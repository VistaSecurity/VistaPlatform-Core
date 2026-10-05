// @vitest-environment jsdom
// The asset drawer hands its Active Scan button the asset's scan record, so a
// scan in flight shows as in flight there too (not a live button inviting a
// second scan of the same host).
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const mocks = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: { POST: vi.fn(), GET: mocks.get, DELETE: vi.fn() } } }));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));
vi.mock('react-router', () => ({ Link: ({ children }: { children: ReactNode }) => <a>{children}</a>, useNavigate: () => vi.fn() }));
vi.mock('@vistasecurity/primitives/rbac', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@vistasecurity/primitives/rbac')>()),
  PermissionGate: ({ children }: { children: ReactNode }) => <>{children}</>,
}));
vi.mock('../../components/ui', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../components/ui')>()),
  DrawerShell: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  Icon: () => null,
}));

import { AssetDrawer } from './drawers';

let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  mocks.get.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

function answer(activeScan: unknown) {
  mocks.get.mockImplementation(async (path: string) => {
    if (path === '/infrastructure-assets/{id}') {
      return { data: { asset: { id: 'asset-1', hostname: 'web-1.example.test', asset_status: 'monitoring', class_key: 'server', risk_score: 0, active_scan: activeScan } } };
    }
    if (path === '/crypto-configurations') return { data: { crypto_implementations: [] } };
    return { data: {} };
  });
}

async function scanButton() {
  await act(async () => {
    root.render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <AssetDrawer assetId="asset-1" onOpenConfig={() => {}} onClose={() => {}} />
      </QueryClientProvider>,
    );
  });
  let found: HTMLButtonElement | undefined;
  await vi.waitFor(() => {
    found = [...host.querySelectorAll('button')].find((b) => /Active Scan|Scanning…/.test(b.textContent ?? ''));
    expect(found).toBeDefined();
  });
  return found!;
}

it('shows a scan in flight as in flight', async () => {
  answer({ status: 'scanning', started_at: new Date().toISOString(), job_ids: ['j'] });
  const b = await scanButton();
  expect(b.disabled).toBe(true);
  expect(b.textContent).toContain('Scanning…');
});

it('offers Active Scan once the scan has finished', async () => {
  answer({ status: 'completed', finished_at: new Date().toISOString(), job_ids: ['j'] });
  const b = await scanButton();
  expect(b.disabled).toBe(false);
  expect(b.title).toContain('Last scan finished');
});

function answerWithEndpoints(endpoints: unknown[]) {
  mocks.get.mockImplementation(async (path: string) => {
    if (path === '/infrastructure-assets/{id}') {
      return { data: { asset: { id: 'asset-1', hostname: 'web-1.example.test', asset_status: 'monitoring', class_key: 'server', risk_score: 0, endpoints } } };
    }
    if (path === '/crypto-configurations') return { data: { crypto_implementations: [] } };
    return { data: {} };
  });
}

async function renderDrawer() {
  await act(async () => {
    root.render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <AssetDrawer assetId="asset-1" onOpenConfig={() => {}} onClose={() => {}} />
      </QueryClientProvider>,
    );
  });
}

it('says "TLS, handshake refused" with its hint for an endpoint whose server ended the handshake', async () => {
  answerWithEndpoints([
    { id: 'e1', address: '198.51.100.7', port: 443, transport: 'tcp', protocol: 'TLS', tls_handshake_outcome: 'refused' },
    { id: 'e2', address: '198.51.100.7', port: 22, transport: 'tcp', protocol: 'SSH' },
  ]);
  await renderDrawer();
  await vi.waitFor(() => expect(host.querySelector('[data-testid="handshake-refused-notes"]')).not.toBeNull());
  const text = host.querySelector('[data-testid="handshake-refused-notes"]')!.textContent ?? '';
  expect(text).toContain('198.51.100.7:443');
  expect(text).toContain('TLS, handshake refused');
  expect(text).toContain('The server ended the TLS handshake. It may require a server name; scan it by name to see its configuration.');
  expect(text).not.toContain(':22');
});

it('shows no handshake note when no endpoint refused', async () => {
  answerWithEndpoints([{ id: 'e1', address: '198.51.100.7', port: 443, transport: 'tcp', protocol: 'TLS' }]);
  await renderDrawer();
  await vi.waitFor(() => expect(host.textContent).toContain('web-1.example.test'));
  expect(host.querySelector('[data-testid="handshake-refused-notes"]')).toBeNull();
});
