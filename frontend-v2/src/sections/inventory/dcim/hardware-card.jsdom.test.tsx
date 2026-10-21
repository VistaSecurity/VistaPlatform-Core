// @vitest-environment jsdom
// The asset page's Hardware card (DCIM 2.2): the five states, nothing for a
// non-hardware asset, and "Apply templates" posting the assigned type and
// saying what it did.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { HardwareCard, applySummary } from './hardware-card';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() }));
vi.mock('../../../lib/clients', () => ({ clients: { inventory: api } }));

const HW = {
  asset_id: 'a1', class_key: 'switch', is_hardware: true,
  device_type: { id: 'd1', name: 'Catalyst 9300-48P', slug: 'cisco-c9300-48p', part_number: 'C9300-48P', u_height: 1 },
  manufacturer: { id: 'm1', name: 'Cisco', slug: 'cisco' },
  device_role: { id: 'r1', name: 'Switch', slug: 'switch', color: '4caf50' },
  platform: null, serial: 'FOC1234X0YZ', asset_tag: null,
  template_counts: { 'interface-templates': 51, 'console-port-templates': 2, 'module-bay-templates': 6 },
  commercial: {
    purchase_date: null, warranty_start: null, warranty_end: null, purchase_cost: null, purchase_currency: null, purchase_order: null,
    vendor: null, support_contract: null, support_contract_end: null, installed_at: null, decommissioned_at: null,
  },
  device_type_eos: null, platform_eos: null,
  lifecycle: { warranty_state: 'unknown' as const, eos_state: 'unknown' as const, effective_end_of_support: null, source: 'none' as const, subject: null },
};
const EMPTY = { ...HW, device_type: null, manufacturer: null, device_role: null, serial: null, template_counts: {} };

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function render(perms: string[]) {
  cache.setQueryData(['user-permissions'], perms);
  await act(async () => {
    root.render(<QueryClientProvider client={cache}><PermissionProvider><HardwareCard assetId="a1" /></PermissionProvider></QueryClientProvider>);
  });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
}

it('loading', async () => {
  api.GET.mockReturnValue(new Promise(() => {}));
  await render(['dcim.read']);
  expect(host.textContent).toContain('Loading hardware');
});

it('error', async () => {
  api.GET.mockResolvedValue({ data: undefined, error: { error: { message: 'down' } } });
  await render(['dcim.read']);
  expect(host.querySelector('[data-testid="substrate-error"]')?.textContent).toContain('down');
});

it('empty: nothing recorded says so, and offers no apply', async () => {
  api.GET.mockResolvedValue({ data: { data: EMPTY } });
  await render(['dcim.read', 'dcim.manage']);
  expect(host.textContent).toContain('No hardware recorded');
  expect(host.querySelector('[data-testid="apply-templates"]')).toBeNull();
});

it('a non-hardware asset gets no card at all', async () => {
  api.GET.mockResolvedValue({ data: { data: { ...EMPTY, class_key: 'virtual_machine', is_hardware: false } } });
  await render(['dcim.read', 'dcim.manage']);
  expect(host.querySelector('[data-testid="hardware-card"]')).toBeNull();
});

it('default: the rows, the pending component kinds, and no apply for a reader', async () => {
  api.GET.mockResolvedValue({ data: { data: HW } });
  await render(['dcim.read']);
  const rows = host.querySelector('[data-testid="hardware-rows"]')!.textContent ?? '';
  for (const s of ['Cisco', 'Catalyst 9300-48P', 'C9300-48P', '1U', 'FOC1234X0YZ', 'Switch']) expect(rows).toContain(s);
  expect(rows).toContain('2 console ports');
  expect(host.querySelector('[data-testid="apply-templates"]')).toBeNull();
});

it('success: Apply templates posts the assigned type and reports what it did', async () => {
  api.GET.mockResolvedValue({ data: { data: HW } });
  api.POST.mockResolvedValue({ data: { data: {
    device_type_id: 'd1', interfaces: { created: 39, updated: 12, unchanged: 0, removed: 0, skipped: [] }, not_instantiated: {}, hardware: HW,
  } } });
  await render(['dcim.read', 'dcim.manage']);
  await act(async () => { (host.querySelector('[data-testid="apply-templates"]') as HTMLButtonElement).click(); });
  await vi.waitFor(() => expect(api.POST).toHaveBeenCalledTimes(1));
  expect(api.POST.mock.calls[0][0]).toBe('/dcim/assets/{id}/device-type');
  expect(api.POST.mock.calls[0][1]).toEqual({ params: { path: { id: 'a1' } }, body: { device_type_id: 'd1' } });
  await vi.waitFor(() => expect(host.querySelector('[data-testid="apply-result"]')?.textContent).toBe('39 interfaces added, 12 measured interfaces typed.'));
});

it('applySummary says an idempotent re-apply changed nothing', () => {
  expect(applySummary({ device_type_id: 'd', interfaces: { created: 0, updated: 0, unchanged: 51, removed: 0, skipped: [] }, components: {}, not_instantiated: {}, hardware: HW }))
    .toBe('Already applied: nothing to change.');
});
