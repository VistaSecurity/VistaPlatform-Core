// @vitest-environment jsdom
//
// The network segment dialog's DHCP control ( Phase 1a) — the WIRING test:
// segment-provenance.test.ts pins the helpers, and this pins that the dialog
// actually sends what they compute. Deleting `...dhcpBody(...)` from the save
// body must fail the first three tests; rendering the control for a domain
// segment must fail the last.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const api = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn(), POST: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));

const { NetworkSegmentModal } = await import('./infra-modals');

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const base = {
  id: 'seg-1', tenant_id: 't', name: 'Office LAN', segment_type: 'cidr', value: '192.0.2.0/24', network_type: 'private',
  environment: 'production', location_id: null, is_active: true, auto_approve_discoveries: false, tags: null,
  metadata: {}, created_at: '2026-09-29T00:00:00Z', updated_at: '2026-09-29T00:00:00Z',
  dynamic: null, dynamic_source: null,
};
const measured = { ...base, dynamic: true, dynamic_source: 'measured', dynamic_source_name: 'edge-router' };
const operatorOff = { ...base, dynamic: false, dynamic_source: 'operator' };

let host: HTMLDivElement; let root: Root; let qc: QueryClient;
beforeEach(() => {
  api.GET.mockReset().mockResolvedValue({ data: { locations: [] }, response: { ok: true, status: 200 } });
  api.PUT.mockReset().mockResolvedValue({ data: {}, response: { ok: true, status: 200 } });
  api.POST.mockReset().mockResolvedValue({ data: {}, response: { ok: true, status: 201 } });
  qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

async function open(segment: unknown) {
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <NetworkSegmentModal open segment={segment as never} onClose={() => {}} />
      </QueryClientProvider>,
    );
  });
}
const radio = (value: string) => document.body.querySelector<HTMLInputElement>(`input[name="segment-dhcp"][value="${value}"]`);
const saveButton = () => [...document.body.querySelectorAll('button')].find((b) => /Save changes|Create segment|Saving/.test(b.textContent ?? ''));
async function pick(value: string) { await act(async () => { radio(value)!.click(); }); }
async function save() { await act(async () => { saveButton()!.click(); }); }
const putBody = () => api.PUT.mock.calls[0][1].body as Record<string, unknown>;

it('sends dhcp: true when the operator says the network hands out addresses', async () => {
  await open(measured);
  expect(radio('auto')!.checked, 'a measured posture is not the operator’s own answer').toBe(true);
  await pick('on');
  await save();
  expect(api.PUT).toHaveBeenCalledTimes(1);
  expect(putBody().dhcp).toBe(true);
});

it('sends dhcp: null when the operator hands the segment back to automatic', async () => {
  await open(operatorOff);
  expect(radio('off')!.checked).toBe(true);
  await pick('auto');
  await save();
  expect(putBody()).toHaveProperty('dhcp', null);
});

it('sends no dhcp at all when the control was not touched', async () => {
  await open(operatorOff);
  await save();
  expect(putBody()).not.toHaveProperty('dhcp');
  api.PUT.mockClear();
  // Nor for a segment whose posture is a measurement: an unrelated edit must not rewrite it.
  await open(measured);
  await save();
  expect(putBody()).not.toHaveProperty('dhcp');
});

it('says what the segment is currently reported as', async () => {
  await open(measured);
  expect(document.body.textContent).toContain('Currently: DHCP on · measured by edge-router.');
});

it('is disabled while saving', async () => {
  let release!: (v: unknown) => void;
  api.PUT.mockReturnValue(new Promise((r) => { release = r; }));
  await open(measured);
  await pick('off');
  await save();
  await act(async () => { await new Promise((r) => setTimeout(r, 10)); });
  expect(saveButton()!.textContent).toBe('Saving…');
  // The control is one fieldset, so disabling it disables every radio inside.
  expect(document.body.querySelector('fieldset')!.disabled).toBe(true);
  await act(async () => { release({ data: {}, response: { ok: true, status: 200 } }); });
});

it("shows the server's refusal beside the control", async () => {
  api.PUT.mockResolvedValue({
    data: undefined, response: { ok: false, status: 400 },
    error: { error: 'dhcp posture applies to cidr and ip_range segments: "cloud_vpc" is neither' },
  });
  await open(measured);
  await pick('on');
  await save();
  await act(async () => { await new Promise((r) => setTimeout(r, 10)); });
  const alert = document.body.querySelector('fieldset [role="alert"]');
  expect(alert?.textContent).toContain('dhcp posture applies to cidr and ip_range segments');
});

it('offers no control for a segment that cannot hold a lease', async () => {
  await open({ ...base, segment_type: 'domain', value: '*.example.com' });
  expect(radio('auto')).toBeNull();
});

it('creates a segment with an answer only when one is chosen', async () => {
  await open(null);
  expect(radio('auto')!.checked).toBe(true);
  await act(async () => {
    const input = document.body.querySelector<HTMLInputElement>('input[data-autofocus]')!;
    const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
    set.call(input, 'Guest Wi-Fi');
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await act(async () => {
    const value = document.body.querySelector<HTMLInputElement>('input.mono')!;
    const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
    set.call(value, '198.51.100.0/24');
    value.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await pick('on');
  await save();
  expect(api.POST).toHaveBeenCalledTimes(1);
  expect((api.POST.mock.calls[0][1].body as Record<string, unknown>).dhcp).toBe(true);
});
