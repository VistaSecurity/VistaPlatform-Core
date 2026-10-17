// @vitest-environment jsdom
// The asset form's hardware fields (DCIM 2.2): the device-type search select
// lists matches with their height, picking one changes the draft, and only
// changed fields are sent.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AssetHardwareFields, EMPTY_HARDWARE, hardwareChanges, isHardwareClass, type HardwareDraft } from './asset-hardware-fields';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() }));
vi.mock('../../../lib/clients', () => ({ clients: { inventory: api } }));

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

it('the device-type select lists the catalogue with heights, and a pick reaches the draft', async () => {
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/dcim/device-types') {
      return { data: { data: [{ id: 'd1', model: 'Catalyst 9300-48P', part_number: 'C9300-48P', u_height: 1, manufacturer: { id: 'm', name: 'Cisco', slug: 'cisco' } }], pagination: { total: 1 } } };
    }
    if (path === '/dcim/device-roles') return { data: { data: [{ id: 'r1', name: 'Switch' }], pagination: { total: 1 } } };
    return { data: { data: [], pagination: { total: 0 } } };
  });
  let draft: HardwareDraft = EMPTY_HARDWARE;
  const onChange = vi.fn((d: HardwareDraft) => { draft = d; });
  await act(async () => {
    root.render(<QueryClientProvider client={cache}><AssetHardwareFields draft={draft} onChange={onChange} isHardware /></QueryClientProvider>);
  });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
  const sel = host.querySelector('select[aria-label="Device type"]') as HTMLSelectElement;
  expect([...sel.options].map((o) => o.textContent)).toContain('Cisco Catalyst 9300-48P (C9300-48P) · 1U');
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')!.set!.call(sel, 'd1');
    sel.dispatchEvent(new Event('change', { bubbles: true }));
  });
  expect(onChange).toHaveBeenCalled();
  expect(draft.device_type_id).toBe('d1');
  expect(host.querySelector('select[aria-label="Device role"]')!.textContent).toContain('Switch');
});

it('a non-hardware class has no device-type field', async () => {
  api.GET.mockResolvedValue({ data: { data: [], pagination: { total: 0 } } });
  await act(async () => {
    root.render(<QueryClientProvider client={cache}><AssetHardwareFields draft={EMPTY_HARDWARE} onChange={() => undefined} isHardware={false} /></QueryClientProvider>);
  });
  expect(host.querySelector('select[aria-label="Device type"]')).toBeNull();
  expect(host.querySelector('input[aria-label="Serial"]')).not.toBeNull();
});

it('hardwareChanges sends only what changed, and "" as a clear', () => {
  const base = { ...EMPTY_HARDWARE, serial: 'A', device_role_id: 'r1' };
  expect(hardwareChanges(base, base)).toBeNull();
  expect(hardwareChanges(base, { ...base, serial: '', device_type_id: 'd1' })).toEqual({ serial: null, device_type_id: 'd1' });
});

it('isHardwareClass follows the class tree', () => {
  expect(isHardwareClass('switch')).toBe(true);
  expect(isHardwareClass('hardware')).toBe(true);
  expect(isHardwareClass('virtual_machine')).toBe(false);
  expect(isHardwareClass('')).toBe(false);
});
