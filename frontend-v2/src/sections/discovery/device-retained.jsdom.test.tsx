// @vitest-environment jsdom
import { act, type ReactNode, type InputHTMLAttributes, type SelectHTMLAttributes } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { DeviceFormModal, DiscoverDeviceModal } from './device-modals';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const mocks = vi.hoisted(() => ({ post: vi.fn(), navigate: vi.fn(), close: vi.fn(), toastSuccess: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { devices: { POST: mocks.post } } }));
vi.mock('react-router', () => ({ useNavigate: () => mocks.navigate }));
vi.mock('react-hot-toast', () => ({ default: { success: mocks.toastSuccess } }));
vi.mock('../../components/ui', () => ({
  Modal: ({ children, primary, footerNote }: { children: ReactNode; primary: ReactNode; footerNote: ReactNode }) => <div>{children}{primary}{footerNote}</div>,
  ModalField: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  ModalInput: (props: InputHTMLAttributes<HTMLInputElement>) => <input {...props} />,
  ModalSelect: (props: SelectHTMLAttributes<HTMLSelectElement>) => <select {...props} />,
}));

let host: HTMLDivElement;
let root: Root;
let cache: QueryClient;
beforeEach(() => {
  mocks.post.mockReset().mockResolvedValue({ data: { outcome: 'unresolved', observation_id: 'retained-1', message: 'Management settings were saved.' }, response: { ok: true, status: 202 } });
  mocks.navigate.mockReset(); mocks.close.mockReset(); mocks.toastSuccess.mockReset();
  host = document.createElement('div'); document.body.appendChild(host);
  root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function input(placeholder: string, value: string) {
  const field = [...host.querySelectorAll('input')].find((node) => node.placeholder === placeholder)!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(field, value);
    field.dispatchEvent(new Event('input', { bubbles: true }));
  });
}

it.each(['manual', 'probe'])('opens retained evidence after %s device creation', async (mode) => {
  await act(async () => { root.render(<QueryClientProvider client={cache}>{mode === 'manual' ? <DeviceFormModal open onClose={mocks.close} /> : <DiscoverDeviceModal open onClose={mocks.close} />}</QueryClientProvider>); });
  await input('https://10.0.0.1', 'https://device.example.test');
  if (mode === 'probe') { await input('admin', 'configured-user'); await input('••••••••', 'configured-password'); }
  await act(async () => { host.querySelector('button')!.click(); });
  await vi.waitFor(() => { expect(mocks.navigate).toHaveBeenCalledWith('/discovery/observations?observation_id=retained-1'); });
  expect(mocks.close).toHaveBeenCalledOnce();
  expect(mocks.toastSuccess).toHaveBeenCalledWith('Management settings were saved.');
  expect(mocks.post.mock.calls[0][0]).toBe(mode === 'manual' ? '/devices' : '/devices/discover-and-create');
});

it('sends the explicit TLS override from discover and add', async () => {
  await act(async () => { root.render(<QueryClientProvider client={cache}><DiscoverDeviceModal open onClose={mocks.close} /></QueryClientProvider>); });
  await input('https://10.0.0.1', 'https://device.example.test');
  await input('admin', 'configured-user'); await input('••••••••', 'configured-password');
  const checkbox = host.querySelector('input[type="checkbox"]') as HTMLInputElement;
  await act(async () => { checkbox.click(); });
  await act(async () => { host.querySelector('button')!.click(); });
  await vi.waitFor(() => expect(mocks.post).toHaveBeenCalled());
  const [path, init] = mocks.post.mock.calls[0] as [string, { body: { tls_insecure_skip_verify?: boolean } }];
  expect(path).toBe('/devices/discover-and-create');
  expect(init.body.tls_insecure_skip_verify).toBe(true);
});

it('shows the safe backend discovery message', async () => {
  mocks.post.mockResolvedValueOnce({ error: { error: 'authentication_failed', message: 'The device rejected the credentials.' }, response: { ok: false, status: 422 } });
  await act(async () => { root.render(<QueryClientProvider client={cache}><DiscoverDeviceModal open onClose={mocks.close} /></QueryClientProvider>); });
  await input('https://10.0.0.1', 'https://device.example.test');
  await input('admin', 'configured-user'); await input('••••••••', 'wrong-password');
  await act(async () => { host.querySelector('button')!.click(); });
  await vi.waitFor(() => expect(host.textContent).toContain('The device rejected the credentials.'));
});
