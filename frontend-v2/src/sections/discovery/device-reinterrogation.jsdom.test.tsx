// @vitest-environment jsdom
import { act, type ReactNode, type InputHTMLAttributes, type SelectHTMLAttributes } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DeviceFormModal, REINTERROGATION_LABEL } from './device-modals';
import { enrichmentExplanation } from './observation-details';

// The platform re-interrogation consent (the rule) in the one
// Add / Edit device flow: shown only for a device the platform interrogates,
// off by default, and round-tripped in the REAL request body (the client is
// mocked at the transport, as in device-add-flow.jsdom.test.tsx).

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const mocks = vi.hoisted(() => ({ post: vi.fn(), put: vi.fn(), navigate: vi.fn(), close: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { devices: { POST: mocks.post, PUT: mocks.put } } }));
vi.mock('react-router', () => ({ useNavigate: () => mocks.navigate }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn() } }));
vi.mock('../../components/ui', () => ({
  Modal: ({ children, primary, footerNote }: { children: ReactNode; primary: ReactNode; footerNote: ReactNode }) => (
    <div>{children}<div>{primary}{footerNote}</div></div>
  ),
  ModalField: ({ children, label }: { children: ReactNode; label: string }) => <div><span>{label}</span>{children}</div>,
  ModalInput: (props: InputHTMLAttributes<HTMLInputElement>) => <input {...props} />,
  ModalSelect: (props: SelectHTMLAttributes<HTMLSelectElement>) => <select {...props} />,
}));

let host: HTMLDivElement;
let root: Root;
let cache: QueryClient;
beforeEach(() => {
  mocks.post.mockReset(); mocks.put.mockReset(); mocks.close.mockReset();
  host = document.createElement('div'); document.body.appendChild(host);
  root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

const toggle = () => host.querySelector<HTMLInputElement>('[name="platform_reinterrogation_allowed"]');
const primary = () => host.querySelector('[data-testid="device-form-primary"]') as HTMLButtonElement;

async function render(device?: unknown) {
  await act(async () => {
    root.render(<QueryClientProvider client={cache}><DeviceFormModal open device={device as never} onClose={mocks.close} /></QueryClientProvider>);
  });
}
async function type(name: string, value: string) {
  const el = host.querySelector<HTMLInputElement>(`[name="${name}"]`)!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
}
async function click(el: HTMLElement) { await act(async () => { el.click(); }); }
const body = (fn: typeof mocks.post) => (fn.mock.calls[0] as [string, { body: Record<string, unknown> }])[1].body;

const platformDevice = { id: 'dev-1', device_type: 'unifi', management_url: 'https://192.0.2.2', discovery_method: 'device_interrogation', interrogated_by_agent: false, platform_reinterrogation_allowed: false };

describe('Platform re-interrogation consent', () => {
  it('Add device: shown, labelled, off by default, and sent with the probe', async () => {
    mocks.post.mockResolvedValue({ data: { id: 'dev-1' }, response: { ok: true, status: 201 } });
    await render();
    expect(toggle()).not.toBeNull();
    expect(toggle()!.checked).toBe(false);
    expect(host.textContent).toContain(REINTERROGATION_LABEL);
    expect(host.textContent).toContain('Off by default.');
    await type('management_url', 'https://192.0.2.10');
    await type('username', 'admin');
    await type('password', 'correct-horse');
    await click(toggle()!);
    await click(primary());
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalled());
    expect(mocks.post.mock.calls[0][0]).toBe('/devices/discover-and-create');
    expect(body(mocks.post).platform_reinterrogation_allowed).toBe(true);
  });

  it('Add device untouched: sends it off', async () => {
    mocks.post.mockResolvedValue({ data: { id: 'dev-1' }, response: { ok: true, status: 201 } });
    await render();
    await type('management_url', 'https://192.0.2.10');
    await type('username', 'admin');
    await type('password', 'correct-horse');
    await click(primary());
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalled());
    expect(body(mocks.post).platform_reinterrogation_allowed).toBe(false);
  });

  it('Edit: hydrates the stored value and round-trips a change', async () => {
    mocks.put.mockResolvedValue({ data: { id: 'dev-1' }, response: { ok: true, status: 200 } });
    await render({ ...platformDevice, platform_reinterrogation_allowed: true });
    expect(toggle()!.checked).toBe(true);
    await click(toggle()!);
    await click(primary());
    await vi.waitFor(() => expect(mocks.put).toHaveBeenCalled());
    expect(body(mocks.put).platform_reinterrogation_allowed).toBe(false);
  });

  it('Edit: hidden for an agent-interrogated device, and its stored value is left alone', async () => {
    mocks.put.mockResolvedValue({ data: { id: 'dev-1' }, response: { ok: true, status: 200 } });
    await render({ ...platformDevice, interrogated_by_agent: true, platform_reinterrogation_allowed: true });
    expect(toggle()).toBeNull();
    expect(host.textContent).not.toContain(REINTERROGATION_LABEL);
    await click(primary());
    await vi.waitFor(() => expect(mocks.put).toHaveBeenCalled());
    expect(body(mocks.put)).not.toHaveProperty('platform_reinterrogation_allowed');
  });

  it('Edit: hidden for a cloud-discovered resource', async () => {
    await render({ ...platformDevice, device_type: 'aws_alb', discovery_method: 'cloud_api' });
    expect(toggle()).toBeNull();
  });
});

describe('executor_scope_unknown explains the way out', () => {
  it('names the setting and where it lives', () => {
    const text = enrichmentExplanation('executor_scope_unknown');
    expect(text).toContain('Discovery → Devices');
    expect(text).toContain(REINTERROGATION_LABEL);
    expect(text).not.toContain('executor scope unknown');
  });
});
