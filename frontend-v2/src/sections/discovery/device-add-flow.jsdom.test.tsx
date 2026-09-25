// @vitest-environment jsdom
import { act, type ReactNode, type InputHTMLAttributes, type SelectHTMLAttributes } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DeviceFormModal, TestConnectionModal } from './device-modals';

// Add device — one flow ( slice A) — and Test connection, in every screen
// state. The Modal primitive is mocked down to its content, primary button and
// footer so these assert what the FORM renders; the API client is mocked at
// the transport, so every assertion about what is sent is about the real body.

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const mocks = vi.hoisted(() => ({ post: vi.fn(), put: vi.fn(), navigate: vi.fn(), close: vi.fn(), toastSuccess: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { devices: { POST: mocks.post, PUT: mocks.put } } }));
vi.mock('react-router', () => ({ useNavigate: () => mocks.navigate }));
vi.mock('react-hot-toast', () => ({ default: { success: mocks.toastSuccess } }));
vi.mock('../../components/ui', () => ({
  Modal: ({ children, primary, secondary, footerNote, title }: { children: ReactNode; primary: ReactNode; secondary: ReactNode; footerNote: ReactNode; title: string }) => (
    <div><h2>{title}</h2>{children}<div data-testid="footer">{primary}{secondary}{footerNote}</div></div>
  ),
  ModalField: ({ children, label }: { children: ReactNode; label: string }) => <div><span>{label}</span>{children}</div>,
  ModalInput: (props: InputHTMLAttributes<HTMLInputElement>) => <input {...props} />,
  ModalSelect: (props: SelectHTMLAttributes<HTMLSelectElement>) => <select {...props} />,
}));

let host: HTMLDivElement;
let root: Root;
let cache: QueryClient;
beforeEach(() => {
  mocks.post.mockReset();
  mocks.put.mockReset();
  mocks.navigate.mockReset(); mocks.close.mockReset(); mocks.toastSuccess.mockReset();
  host = document.createElement('div'); document.body.appendChild(host);
  root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

const REMAINING = ['hostname', 'ip_address', 'vendor', 'model', 'serial_number', 'firmware_version'];
const FOUR = ['device_type', 'management_url', 'username', 'password'];

const field = (name: string) => host.querySelector<HTMLInputElement>(`[name="${name}"]`);
const primary = () => host.querySelector('[data-testid="device-form-primary"]') as HTMLButtonElement;
const failure = () => host.querySelector<HTMLElement>('[data-testid="probe-failure"]');

async function type(name: string, value: string) {
  const el = field(name)!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
}

async function choose(deviceType: string) {
  const el = field('device_type') as unknown as HTMLSelectElement;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')!.set!.call(el, deviceType);
    el.dispatchEvent(new Event('change', { bubbles: true }));
  });
}

async function click(el: HTMLElement) {
  await act(async () => { el.click(); });
}

async function renderAdd() {
  await act(async () => { root.render(<QueryClientProvider client={cache}><DeviceFormModal open onClose={mocks.close} /></QueryClientProvider>); });
}

async function fillFour() {
  await type('management_url', 'https://192.0.2.10');
  await type('username', 'admin');
  await type('password', 'correct-horse');
}

const probeFailed = (error: string, message: string, status = 422) =>
  ({ error: { error, message }, response: { ok: false, status } });

describe('Add device', () => {
  it('default: asks for four fields only, and needs all four', async () => {
    await renderAdd();
    for (const name of FOUR) expect(field(name), name).not.toBeNull();
    for (const name of REMAINING) expect(field(name), name).toBeNull();
    expect(host.querySelector('h2')!.textContent).toBe('Add device');
    expect(primary().textContent).toBe('Add device');
    expect(primary().disabled).toBe(true);
    await type('management_url', 'https://192.0.2.10');
    await type('username', 'admin');
    expect(primary().disabled).toBe(true);
    await type('password', 'correct-horse');
    expect(primary().disabled).toBe(false);
  });

  it('loading: shows Connecting… with the primary disabled', async () => {
    mocks.post.mockReturnValue(new Promise(() => {}));
    await renderAdd();
    await fillFour();
    await click(primary());
    await vi.waitFor(() => expect(primary().textContent).toBe('Connecting…'));
    expect(primary().disabled).toBe(true);
    expect(field('management_url')!.disabled).toBe(true);
  });

  it('success: probes with the four fields and the TLS opt-in, then closes', async () => {
    mocks.post.mockResolvedValue({ data: { id: 'dev-1' }, response: { ok: true, status: 201 } });
    await renderAdd();
    await fillFour();
    await click(field('tls_insecure_skip_verify')!);
    await click(primary());
    await vi.waitFor(() => expect(mocks.close).toHaveBeenCalledOnce());
    const [path, init] = mocks.post.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(path).toBe('/devices/discover-and-create');
    expect(init.body).toEqual({
      device_type: 'f5', management_url: 'https://192.0.2.10', username: 'admin', password: 'correct-horse',
      tls_insecure_skip_verify: true,
    });
    expect(mocks.navigate).not.toHaveBeenCalled();
  });

  it('error: shows the typed reason and discloses the remaining fields', async () => {
    mocks.post.mockResolvedValueOnce(probeFailed('connection_failed', "Couldn't connect to the management address.", 502));
    await renderAdd();
    await fillFour();
    await click(primary());
    await vi.waitFor(() => expect(failure()).not.toBeNull());
    expect(failure()!.dataset.code).toBe('connection_failed');
    expect(failure()!.textContent).toContain("Couldn't reach the device");
    expect(failure()!.textContent).toContain("Couldn't connect to the management address.");
    expect(failure()!.textContent).toContain('add it by hand');
    for (const name of REMAINING) expect(field(name), name).not.toBeNull();
    // The four values survive the disclosure.
    expect(field('management_url')!.value).toBe('https://192.0.2.10');
    expect(primary().textContent).toBe('Add without connecting');
    expect(mocks.close).not.toHaveBeenCalled();
  });

  it.each([
    ['authentication_failed', 'The device rejected the credentials'],
    ['target_disallowed', "That address isn't allowed"],
    ['unsupported_response', 'Something else answered at that address'],
  ])('error: %s reads as its own reason', async (code, title) => {
    mocks.post.mockResolvedValueOnce(probeFailed(code, 'server copy'));
    await renderAdd();
    await fillFour();
    await click(primary());
    await vi.waitFor(() => expect(failure()?.dataset.code).toBe(code));
    expect(failure()!.textContent).toContain(title);
    expect(failure()!.textContent).not.toContain('add it by hand');
  });

  it('after a failure the device can be added by hand with the extra fields', async () => {
    mocks.post
      .mockResolvedValueOnce(probeFailed('connection_failed', 'unreachable', 502))
      .mockResolvedValueOnce({ data: { id: 'dev-1' }, response: { ok: true, status: 201 } });
    await renderAdd();
    await fillFour();
    await click(primary());
    await vi.waitFor(() => expect(field('hostname')).not.toBeNull());
    await type('hostname', 'edge-fw-01');
    await type('vendor', 'F5');
    await click(primary());
    await vi.waitFor(() => expect(mocks.close).toHaveBeenCalledOnce());
    const [path, init] = mocks.post.mock.calls[1] as [string, { body: Record<string, unknown> }];
    expect(path).toBe('/devices');
    expect(init.body).toMatchObject({
      device_type: 'f5', hostname: 'edge-fw-01', vendor: 'F5', management_url: 'https://192.0.2.10',
      username: 'admin', password: 'correct-horse', tls_insecure_skip_verify: false,
    });
  });

  it('an untrusted certificate is fixed by the opt-in and a retry', async () => {
    mocks.post
      .mockResolvedValueOnce(probeFailed('tls_untrusted', 'turn on Skip TLS verification', 502))
      .mockResolvedValueOnce({ data: { id: 'dev-1' }, response: { ok: true, status: 201 } });
    await renderAdd();
    await fillFour();
    await click(primary());
    await vi.waitFor(() => expect(failure()?.dataset.code).toBe('tls_untrusted'));
    await click(field('tls_insecure_skip_verify')!);
    const retry = [...failure()!.querySelectorAll('button')].find((b) => b.textContent === 'Try connecting again')!;
    await click(retry);
    await vi.waitFor(() => expect(mocks.close).toHaveBeenCalledOnce());
    const [path, init] = mocks.post.mock.calls[1] as [string, { body: { tls_insecure_skip_verify: boolean } }];
    expect(path).toBe('/devices/discover-and-create');
    expect(init.body.tls_insecure_skip_verify).toBe(true);
  });

  it('an error without a probe reason is shown as-is and does not expand the form', async () => {
    mocks.post.mockResolvedValueOnce({ error: { error: 'Device identity is contested', message: 'A merge proposal is waiting in Approvals.' }, response: { ok: false, status: 409 } });
    await renderAdd();
    await fillFour();
    await click(primary());
    await vi.waitFor(() => expect(host.textContent).toContain('A merge proposal is waiting in Approvals.'));
    expect(failure()).toBeNull();
    expect(field('hostname')).toBeNull();
  });

  it('a type that cannot be identified shows every field and adds by hand', async () => {
    mocks.post.mockResolvedValue({ data: { id: 'dev-1' }, response: { ok: true, status: 201 } });
    await renderAdd();
    await choose('other');
    for (const name of REMAINING) expect(field(name), name).not.toBeNull();
    expect(host.querySelector('[data-testid="device-form-mode-toggle"]')).toBeNull();
    await type('hostname', 'appliance-01');
    await click(primary());
    await vi.waitFor(() => expect(mocks.close).toHaveBeenCalledOnce());
    expect(mocks.post.mock.calls[0][0]).toBe('/devices');
  });

  it('Cisco is addressed over SSH and is not offered the TLS switch', async () => {
    await renderAdd();
    await choose('cisco');
    expect(host.textContent).toContain('Management address (SSH)');
    expect(field('tls_insecure_skip_verify')).toBeNull();
    expect(field('management_url')!.placeholder).toContain('ssh://');
  });

  it('the by-hand toggle reveals the fields without probing, and back', async () => {
    await renderAdd();
    const toggle = host.querySelector('[data-testid="device-form-mode-toggle"]') as HTMLButtonElement;
    await click(toggle);
    for (const name of REMAINING) expect(field(name), name).not.toBeNull();
    expect(primary().textContent).toBe('Add without connecting');
    await click(host.querySelector('[data-testid="device-form-mode-toggle"]') as HTMLButtonElement);
    for (const name of REMAINING) expect(field(name), name).toBeNull();
    expect(mocks.post).not.toHaveBeenCalled();
  });
});

describe('Edit device (unchanged)', () => {
  it('shows every field, hydrated, and saves with PUT', async () => {
    mocks.put.mockResolvedValue({ data: { id: 'dev-1' }, response: { ok: true, status: 200 } });
    const device = {
      id: 'dev-1', device_type: 'fortinet', hostname: 'fw-01', management_url: 'https://192.0.2.10',
      vendor: 'Fortinet', model: 'FortiGate 60F', ip_address: '192.0.2.10', username: 'admin', tls_insecure_skip_verify: true,
    } as never;
    await act(async () => { root.render(<QueryClientProvider client={cache}><DeviceFormModal open device={device} onClose={mocks.close} /></QueryClientProvider>); });
    for (const name of [...FOUR, ...REMAINING]) expect(field(name), name).not.toBeNull();
    expect(field('hostname')!.value).toBe('fw-01');
    expect(primary().textContent).toBe('Save changes');
    expect(host.querySelector('[data-testid="device-form-mode-toggle"]')).toBeNull();
    await click(primary());
    await vi.waitFor(() => expect(mocks.close).toHaveBeenCalledOnce());
    expect(mocks.post).not.toHaveBeenCalled();
    expect(mocks.put.mock.calls[0][0]).toBe('/devices/{id}');
  });
});

describe('Test connection', () => {
  const device = { id: 'dev-1', device_type: 'fortinet', hostname: 'fw-01' } as never;
  const run = () => host.querySelector<HTMLButtonElement>('[data-testid="test-connection-run"]')!;
  async function renderTest() {
    await act(async () => { root.render(<QueryClientProvider client={cache}><TestConnectionModal open device={device} onClose={mocks.close} /></QueryClientProvider>); });
  }

  // NB-8: every test is a real login, so nothing runs until the user asks.
  it('default: opening the modal logs in to nothing', async () => {
    await renderTest();
    expect(host.querySelector('[data-testid="test-connection-idle"]')).not.toBeNull();
    expect(run().textContent).toBe('Test');
    expect(mocks.post).not.toHaveBeenCalled();
  });

  it('loading: says it is logging in', async () => {
    mocks.post.mockReturnValue(new Promise(() => {}));
    await renderTest();
    await click(run());
    await vi.waitFor(() => expect(host.textContent).toContain('Logging in to fw-01'));
    expect(run().textContent).toBe('Testing…');
    expect(run().disabled).toBe(true);
  });

  it('success: shows the measured latency and what it read', async () => {
    mocks.post.mockResolvedValue({
      data: { device_id: 'dev-1', success: true, tested_at: '2026-09-24T00:00:00Z', latency_ms: 137, message: 'ok',
        identity: { vendor: 'Fortinet', model: 'FortiGate 60F', serial_number: 'FGT60F0000000001', firmware_version: 'v7.4.4', hostname: 'fw-01' } },
      response: { ok: true, status: 200 },
    });
    await renderTest();
    await click(run());
    await vi.waitFor(() => expect(host.querySelector('[data-testid="test-connection-success"]')).not.toBeNull());
    expect(host.textContent).toContain('137 ms');
    expect(host.textContent).toContain('FortiGate 60F');
    expect(host.textContent).toContain('serial FGT60F0000000001');
    expect(mocks.post).toHaveBeenCalledOnce();
    expect(mocks.post.mock.calls[0][0]).toBe('/devices/{id}/test-connection');
    expect(run().textContent).toBe('Test again');
  });

  it('error: shows the typed reason, not a success', async () => {
    mocks.post.mockResolvedValue(probeFailed('connection_failed', "Couldn't connect to the management address.", 502));
    await renderTest();
    await click(run());
    await vi.waitFor(() => expect(failure()?.dataset.code).toBe('connection_failed'));
    expect(host.textContent).toContain("Couldn't reach the device");
    expect(host.textContent).not.toContain('add it by hand');
    expect(host.querySelector('[data-testid="test-connection-success"]')).toBeNull();
  });

  it('error: rejected credentials read as their own reason', async () => {
    mocks.post.mockResolvedValue(probeFailed('authentication_failed', 'The device rejected the credentials.'));
    await renderTest();
    await click(run());
    await vi.waitFor(() => expect(failure()?.dataset.code).toBe('authentication_failed'));
  });

  it('error: a throttled retry says so', async () => {
    mocks.post.mockResolvedValue(probeFailed('test_throttled', 'Wait 9 seconds.', 429));
    await renderTest();
    await click(run());
    await vi.waitFor(() => expect(failure()?.dataset.code).toBe('test_throttled'));
    expect(host.textContent).toContain('This device was tested moments ago');
  });
});

// B1: the TLS switch is a TLS setting. Ticked for a TLS device and then carried
// to an SSH one, it used to be sent — and for Cisco the backend turned it into
// "skip SSH host-key checking". The REQUEST BODY is what is asserted.
describe('SSH devices never send the TLS skip flag', () => {
  it('a tick made for F5 does not ride along to Cisco', async () => {
    mocks.post.mockResolvedValue({ data: { id: 'dev-1' }, response: { ok: true, status: 201 } });
    await renderAdd();
    await click(field('tls_insecure_skip_verify')!);
    expect(field('tls_insecure_skip_verify')!.checked).toBe(true);
    await choose('cisco');
    expect(field('tls_insecure_skip_verify')).toBeNull();
    await type('management_url', 'ssh://192.0.2.20');
    await type('username', 'admin');
    await type('password', 'correct-horse');
    await click(primary());
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalled());
    const [path, init] = mocks.post.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(path).toBe('/devices/discover-and-create');
    expect(init.body.device_type).toBe('cisco');
    expect(init.body.tls_insecure_skip_verify).toBe(false);
  });

  it('switching back to a TLS device starts with the switch off', async () => {
    await renderAdd();
    await click(field('tls_insecure_skip_verify')!);
    await choose('cisco');
    await choose('f5');
    expect(field('tls_insecure_skip_verify')!.checked).toBe(false);
  });

  it('editing a Cisco device stored with the flag hides it and sends false', async () => {
    mocks.put.mockResolvedValue({ data: { id: 'dev-1' }, response: { ok: true, status: 200 } });
    const device = { id: 'dev-1', device_type: 'cisco', ip_address: '192.0.2.20', tls_insecure_skip_verify: true } as never;
    await act(async () => { root.render(<QueryClientProvider client={cache}><DeviceFormModal open device={device} onClose={mocks.close} /></QueryClientProvider>); });
    expect(field('tls_insecure_skip_verify')).toBeNull();
    await click(primary());
    await vi.waitFor(() => expect(mocks.put).toHaveBeenCalled());
    const [, init] = mocks.put.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(init.body.tls_insecure_skip_verify).toBe(false);
  });

  it('an F5 edit keeps its explicit opt-in', async () => {
    mocks.put.mockResolvedValue({ data: { id: 'dev-1' }, response: { ok: true, status: 200 } });
    const device = { id: 'dev-1', device_type: 'f5', management_url: 'https://192.0.2.30', tls_insecure_skip_verify: true } as never;
    await act(async () => { root.render(<QueryClientProvider client={cache}><DeviceFormModal open device={device} onClose={mocks.close} /></QueryClientProvider>); });
    expect(field('tls_insecure_skip_verify')!.checked).toBe(true);
    await click(primary());
    await vi.waitFor(() => expect(mocks.put).toHaveBeenCalled());
    const [, init] = mocks.put.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(init.body.tls_insecure_skip_verify).toBe(true);
  });
});

describe('Add device limits', () => {
  it('a rate-limit refusal is shown and does not fall back to the by-hand fields', async () => {
    mocks.post.mockResolvedValueOnce(probeFailed('rate_limited', 'Try again in 30 seconds.', 429));
    await renderAdd();
    await fillFour();
    await click(primary());
    await vi.waitFor(() => expect(failure()?.dataset.code).toBe('rate_limited'));
    expect(host.textContent).toContain('Too many device connections just now');
    for (const name of REMAINING) expect(field(name), name).toBeNull();
  });
});
