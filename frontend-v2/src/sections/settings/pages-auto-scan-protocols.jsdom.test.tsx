// @vitest-environment jsdom
//
// Settings → Infrastructure → Active Scanning, MOUNTED ( D1): the
// Protocols row is gone, the Ports field says how services are identified, and
// saving sends no `protocols` — the server keeps the stored value, which is
// what a sensor too old for the current scan engine still probes.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const api = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));
vi.mock('./identity-discovery-settings', () => ({ IdentityDiscoverySettings: () => null }));
vi.mock('@vistasecurity/primitives/rbac', () => ({
  PermissionGate: ({ children }: { children: React.ReactNode }) => children,
  TENANT_PERMISSIONS: { settings: { update: 'settings.update', read: 'settings.read' } },
}));

const { AutoScanPage } = await import('./pages-auto-scan');

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const response = {
  auto_scan: { enabled: true, scan_on_first_observation: true, rescan_interval_hours: 24, protocols: ['TLS'], ports: [22, 443], prefer_observing_sensor: true },
  limits: { min_rescan_interval_hours: 1, max_rescan_interval_hours: 720, max_ports: 64, supported_protocols: ['SSH', 'TLS'], default_ports: [22, 443, 8443] },
  summary: { last_sweep_jobs: 0, last_sweep_assets: 0, assets_in_scope: 2, recent_jobs: [], not_scanned: [] },
};

let host: HTMLDivElement; let root: Root; let qc: QueryClient;
beforeEach(() => {
  api.GET.mockReset().mockResolvedValue({ data: response, response: { ok: true } });
  api.PUT.mockReset().mockResolvedValue({ data: response, response: { ok: true } });
  qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); qc.clear(); });

async function render() {
  await act(async () => {
    root.render(
      <MemoryRouter>
        <QueryClientProvider client={qc}>
          <AutoScanPage meta={{ key: 'sensor-config', label: 'Active Scanning', icon: 'radar', built: true, job: '' }} />
        </QueryClientProvider>
      </MemoryRouter>,
    );
  });
  await act(async () => { await new Promise((r) => setTimeout(r, 10)); });
}

it('has no Protocols row and explains how services are identified', async () => {
  await render();
  expect(host.querySelectorAll('input[type="checkbox"]').length).toBe(0);
  expect(host.textContent).not.toMatch(/Protocols/);
  expect(host.textContent).toContain('identifies the service from what answers (TLS and SSH)');
  expect(host.textContent).toContain('Industrial (OT) probes are never run unattended');
});

it('saves without protocols, so the stored value is kept', async () => {
  await render();
  const interval = host.querySelector<HTMLInputElement>('input[type="number"]')!;
  await act(async () => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
    setter.call(interval, '48');
    interval.dispatchEvent(new Event('input', { bubbles: true }));
  });
  const save = [...host.querySelectorAll('button')].find((b) => b.textContent === 'Save policy')!;
  expect(save.disabled).toBe(false);
  await act(async () => { save.click(); });
  await act(async () => { await new Promise((r) => setTimeout(r, 10)); });
  expect(api.PUT).toHaveBeenCalledTimes(1);
  const body = (api.PUT.mock.calls[0][1] as { body: Record<string, unknown> }).body;
  expect(body.rescan_interval_hours).toBe(48);
  expect('protocols' in body).toBe(false);
});
