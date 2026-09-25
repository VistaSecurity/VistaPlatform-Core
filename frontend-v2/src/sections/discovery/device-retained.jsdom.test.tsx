// @vitest-environment jsdom
import { act, type ReactNode, type InputHTMLAttributes, type SelectHTMLAttributes } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { DeviceFormModal } from './device-modals';

// Retained identity evidence: when the backend keeps the management settings
// with an observation (202) instead of creating the device, both ways of
// adding a device — the probe and the by-hand fallback — take the operator to
// that observation.

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

async function input(name: string, value: string) {
  const field = host.querySelector(`[name="${name}"]`) as HTMLInputElement;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(field, value);
    field.dispatchEvent(new Event('input', { bubbles: true }));
  });
}

it.each(['by hand', 'probe'])('opens retained evidence after %s device creation', async (mode) => {
  await act(async () => { root.render(<QueryClientProvider client={cache}><DeviceFormModal open onClose={mocks.close} /></QueryClientProvider>); });
  if (mode === 'by hand') {
    await act(async () => { (host.querySelector('[data-testid="device-form-mode-toggle"]') as HTMLButtonElement).click(); });
  }
  await input('management_url', 'https://device.example.test');
  await input('username', 'configured-user');
  await input('password', 'configured-password');
  await act(async () => { (host.querySelector('[data-testid="device-form-primary"]') as HTMLButtonElement).click(); });
  await vi.waitFor(() => { expect(mocks.navigate).toHaveBeenCalledWith('/discovery/observations?observation_id=retained-1'); });
  expect(mocks.close).toHaveBeenCalledOnce();
  expect(mocks.toastSuccess).toHaveBeenCalledWith('Management settings were saved.');
  expect(mocks.post.mock.calls[0][0]).toBe(mode === 'by hand' ? '/devices' : '/devices/discover-and-create');
});
