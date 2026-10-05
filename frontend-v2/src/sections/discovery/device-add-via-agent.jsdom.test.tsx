// @vitest-environment jsdom
import { act, type ReactNode, type InputHTMLAttributes, type SelectHTMLAttributes } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DeviceFormModal } from './device-modals';

// Add device through a device agent ( slice B). Same harness as
// device-add-flow.jsdom.test.tsx: the Modal is mocked to its content and
// buttons, the client at the transport, so the assertions are about the real
// request body.

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const mocks = vi.hoisted(() => ({ post: vi.fn(), close: vi.fn(), toastSuccess: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { devices: { POST: mocks.post, PUT: vi.fn() } } }));
vi.mock('react-router', () => ({ useNavigate: () => vi.fn() }));
vi.mock('react-hot-toast', () => ({ default: { success: mocks.toastSuccess } }));
vi.mock('../../components/ui', () => ({
  Modal: ({ children, primary, footerNote, description }: { children: ReactNode; primary: ReactNode; footerNote: ReactNode; description: string }) => (
    <div><p data-testid="description">{description}</p>{children}<div data-testid="footer">{primary}{footerNote}</div></div>
  ),
  ModalField: ({ children, label }: { children: ReactNode; label: string }) => <div><span>{label}</span>{children}</div>,
  ModalInput: (props: InputHTMLAttributes<HTMLInputElement>) => <input {...props} />,
  ModalSelect: (props: SelectHTMLAttributes<HTMLSelectElement>) => <select {...props} />,
}));

const AGENT = { id: '6f1c2a52-7d0e-4d0e-9a51-1d1f4f2b0c11', name: 'branch-agent' };

let host: HTMLDivElement;
let root: Root;
let cache: QueryClient;
beforeEach(() => {
  mocks.post.mockReset(); mocks.close.mockReset(); mocks.toastSuccess.mockReset();
  host = document.createElement('div'); document.body.appendChild(host);
  root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

const field = (name: string) => host.querySelector<HTMLInputElement>(`[name="${name}"]`);
const primary = () => host.querySelector('[data-testid="device-form-primary"]') as HTMLButtonElement;

async function setValue(name: string, value: string) {
  const el = field(name)!;
  const proto = el.tagName === 'SELECT' ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
  await act(async () => {
    Object.getOwnPropertyDescriptor(proto, 'value')!.set!.call(el, value);
    el.dispatchEvent(new Event(el.tagName === 'SELECT' ? 'change' : 'input', { bubbles: true }));
  });
}

async function render(agents: { id: string; name?: string | null }[]) {
  await act(async () => { root.render(<QueryClientProvider client={cache}><DeviceFormModal open agents={agents} onClose={mocks.close} /></QueryClientProvider>); });
}

async function fillFour() {
  await setValue('management_url', 'https://192.0.2.10');
  await setValue('username', 'admin');
  await setValue('password', 'correct-horse');
}

describe('Add device — reach it from an agent', () => {
  it('without agents there is no choice to make: four fields, no "Reach it from"', async () => {
    await render([]);
    expect(field('reach_via')).toBeNull();
  });

  it('defaults to the platform, which still probes synchronously', async () => {
    await render([AGENT]);
    expect((field('reach_via') as unknown as HTMLSelectElement).value).toBe('platform');
    await fillFour();
    mocks.post.mockResolvedValue({ data: { id: 'x' } });
    await act(async () => { primary().click(); });
    expect(mocks.post).toHaveBeenCalledTimes(1);
    expect(mocks.post.mock.calls[0][0]).toBe('/devices/discover-and-create');
  });

  it('through an agent: queues a discovery naming the agent, nothing is dialled, the modal closes', async () => {
    await render([AGENT]);
    await fillFour();
    // The platform re-interrogation consent is offered for a platform add…
    expect(field('platform_reinterrogation_allowed')).not.toBeNull();
    await setValue('reach_via', AGENT.id);
    // …and not for a device only the agent can reach: the platform cannot re-check it.
    expect(field('platform_reinterrogation_allowed')).toBeNull();
    expect(host.querySelector('[data-testid="description"]')!.textContent).toContain('branch-agent connects');
    mocks.post.mockResolvedValue({ data: { id: 'd1', status: 'queued' } });
    await act(async () => { primary().click(); });
    expect(mocks.post).toHaveBeenCalledTimes(1);
    const [path, { body }] = mocks.post.mock.calls[0] as [string, { body: unknown }];
    expect(path).toBe('/devices/discoveries');
    expect(body).toEqual({
      device_type: 'f5', management_url: 'https://192.0.2.10', username: 'admin', password: 'correct-horse',
      tls_insecure_skip_verify: false, agent_id: AGENT.id,
    });
    expect(mocks.close).toHaveBeenCalled();
    expect(mocks.toastSuccess.mock.calls[0][0]).toContain('branch-agent');
  });

  it('an unavailable agent says so and does not fall back to the by-hand fields', async () => {
    await render([AGENT]);
    await fillFour();
    await setValue('reach_via', AGENT.id);
    mocks.post.mockResolvedValue({ error: { error: 'agent_unavailable', message: "This agent hasn't checked in." }, response: { ok: false, status: 409 } });
    await act(async () => { primary().click(); });
    await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
    const failure = host.querySelector<HTMLElement>('[data-testid="probe-failure"]');
    expect(failure?.dataset.code).toBe('agent_unavailable');
    expect(failure?.textContent).toContain("That agent isn't available");
    expect(field('hostname')).toBeNull();
    expect(mocks.close).not.toHaveBeenCalled();
  });
});
