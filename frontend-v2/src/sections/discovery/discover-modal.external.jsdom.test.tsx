// @vitest-environment jsdom
// Discover wizard, explicit external targets ( W5.13b): every state the
// person can be in — loading, the "outside your registered networks"
// confirmation (Scan anyway / Cancel), refused targets with their reasons, the
// operator's switch, an unclassified error, and success. Since WP4a the
// dialog also previews with `dry_run`; the harness answers those separately so
// these behaviours are pinned exactly as before, on the real creates only.
import { act, type ReactNode, type InputHTMLAttributes, type SelectHTMLAttributes } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { DiscoverAssetsModal } from './discover-modal';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const mocks = vi.hoisted(() => ({ post: vi.fn(), create: vi.fn(), preview: vi.fn(), get: vi.fn(), sensors: vi.fn(), navigate: vi.fn(), close: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: { POST: mocks.post, GET: mocks.get }, sensors: { GET: mocks.sensors } } }));
vi.mock('react-router', () => ({ useNavigate: () => mocks.navigate }));
vi.mock('@vistasecurity/primitives/features', () => ({ useFeature: () => false }));
vi.mock('../../components/ui', () => ({
  Modal: ({ children, primary, secondary, footerNote }: { children: ReactNode; primary: ReactNode; secondary: ReactNode; footerNote: ReactNode }) => (
    <div>{children}<footer>{secondary}{primary}</footer><p data-testid="note">{footerNote}</p></div>
  ),
  ModalField: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  ModalInput: (props: InputHTMLAttributes<HTMLInputElement>) => <input {...props} />,
  ModalSelect: (props: SelectHTMLAttributes<HTMLSelectElement>) => <select {...props} />,
  Icon: () => null,
}));

const EXTERNAL = [
  { target: '93.184.216.34', addresses: ['93.184.216.34'] },
  { target: 'https://www.example.com/', addresses: ['93.184.216.34'] },
];
const created = { data: { job: { id: 'job-1', status: 'queued' } }, response: { ok: true, status: 202 } };
const PREVIEW = {
  data: {
    plan: {
      depth: 'standard', pace: 'normal', tcp_ports: '1-1024', udp_ports: '53', tcp_port_count: 1024, udp_port_count: 1,
      run_from_requested: 'auto', executor_resolved: 'platform', executor_reason: 'no sensor serves every target',
      depth_adjustments: [], targets: [], estimated_probes: 1025, probe_limit: 25000000,
    },
    estimate: { probes: 1025, addresses: 1, seconds_best: 1, seconds_worst: 30, basis: 'An estimate.' },
    confirmation_required: false,
    external_targets: [],
  },
  response: { ok: true, status: 200 },
};
const failed = (status: number, error: unknown) => ({ error, response: { ok: false, status } });

let host: HTMLDivElement;
let root: Root;
let cache: QueryClient;
beforeEach(() => {
  try { localStorage.clear(); } catch { /* no storage */ }
  mocks.create.mockReset();
  mocks.preview.mockReset().mockResolvedValue(PREVIEW);
  mocks.post.mockReset().mockImplementation((_path: string, opts: { body: { dry_run?: boolean } }): unknown =>
    (opts.body.dry_run ? mocks.preview(opts) : mocks.create(opts)));
  mocks.sensors.mockReset().mockResolvedValue({ data: { sensors: [] }, response: { ok: true, status: 200 } });
  mocks.get.mockReset().mockResolvedValue({ data: { id: 'job-1', status: 'running' }, response: { ok: true, status: 200 } });
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { mutations: { retry: false }, queries: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function openWithTargets(value: string) {
  await act(async () => { root.render(<QueryClientProvider client={cache}><DiscoverAssetsModal open onClose={mocks.close} /></QueryClientProvider>); });
  const area = host.querySelector('textarea[aria-label="Targets"]') as HTMLTextAreaElement;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')!.set!.call(area, value);
    area.dispatchEvent(new Event('input', { bubbles: true }));
  });
}
const button = (label: string) => [...host.querySelectorAll('button')].find((b) => b.textContent?.includes(label));
async function click(label: string) {
  const b = button(label);
  if (!b) throw new Error(`no "${label}" button in: ${host.textContent}`);
  await act(async () => { b.click(); });
}
// The real creates, in order — previews (dry_run) are not what these pin.
const sentBody = (call: number) => (mocks.create.mock.calls[call][0] as { body: Record<string, unknown> }).body;
const startButton = () => button('Start discovery');
async function start() {
  await vi.waitFor(() => expect(startButton()?.disabled).toBe(false));
  await click('Start discovery');
}

it('asks before scanning targets outside the registered networks, and resends with the confirmation', async () => {
  mocks.create
    .mockResolvedValueOnce(failed(422, { error: 'external_targets_unconfirmed', details: 'confirm', external_targets: EXTERNAL }))
    .mockResolvedValueOnce(created);
  await openWithTargets('10.0.0.5\n93.184.216.34\nhttps://www.example.com/');
  await start();

  await vi.waitFor(() => expect(host.textContent).toContain('2 targets are outside your registered networks. Only scan systems you are authorized to test.'));
  expect(host.querySelector('[role="alertdialog"]')).not.toBeNull();
  expect(host.textContent).toContain('https://www.example.com/ → 93.184.216.34');
  expect(sentBody(0)).not.toHaveProperty('external_targets_confirmed');

  await click('Scan anyway');
  await vi.waitFor(() => expect(mocks.create).toHaveBeenCalledTimes(2));
  expect(sentBody(1)).toMatchObject({ targets: ['10.0.0.5', '93.184.216.34', 'https://www.example.com/'], external_targets_confirmed: true });
  await vi.waitFor(() => expect(host.textContent).toContain('Started — track it in Discovery Jobs'));
});

it('Cancel on the confirmation goes back to the form and scans nothing', async () => {
  mocks.create.mockResolvedValueOnce(failed(422, { error: 'external_targets_unconfirmed', details: 'confirm', external_targets: EXTERNAL.slice(0, 1) }));
  await openWithTargets('93.184.216.34');
  await start();
  await vi.waitFor(() => expect(host.textContent).toContain('1 target is outside your registered networks'));
  await click('Cancel');
  expect(host.querySelector('[role="alertdialog"]')).toBeNull();
  expect(host.querySelector('textarea[aria-label="Targets"]')).not.toBeNull();
  expect(button('Start discovery')).toBeDefined();
  expect(mocks.create).toHaveBeenCalledTimes(1);
});

it('shows each refused target and why it can never be scanned — with no way to confirm past it', async () => {
  mocks.create.mockResolvedValueOnce(failed(400, {
    error: 'targets_refused',
    details: 'refused',
    refused_targets: [
      { target: '169.254.169.254', reason: 'link-local addresses include the cloud instance-metadata service (169.254.169.254)' },
      { target: 'metadata.example.com', reason: 'it resolves to 169.254.169.254' },
    ],
  }));
  await openWithTargets('169.254.169.254\nmetadata.example.com');
  await start();
  await vi.waitFor(() => expect(host.textContent).toContain('These 2 targets can never be scanned'));
  expect(host.textContent).toContain('metadata.example.com — it resolves to 169.254.169.254');
  expect(button('Scan anyway')).toBeUndefined();
});

it("shows the server's sentence for a target the scanner cannot fully expand, with each count (#2170)", async () => {
  const details = 'scan target too large: "10.20.0.0/19" names 8192 addresses, and one target may name at most 4096 (an IPv4 /20); split it into smaller blocks';
  mocks.create.mockResolvedValueOnce(failed(422, {
    error: 'scan_target_too_large', details, target_limit: 4096,
    oversize_targets: [{ target: '10.20.0.0/19', addresses: '8192' }],
  }));
  await openWithTargets('10.20.0.0/19');
  await start();
  await vi.waitFor(() => expect(host.querySelector('[role="alert"]')?.textContent).toContain(details));
  expect(host.querySelector('[role="alert"]')?.textContent).toContain('10.20.0.0/19 — 8192 addresses');
  expect(button('Scan anyway')).toBeUndefined();
  // Back on the form, not a dead end: the person can edit the targets and retry.
  expect(host.querySelector('textarea[aria-label="Targets"]')).not.toBeNull();
});

it('explains that the operator turned external targets off', async () => {
  mocks.create.mockResolvedValueOnce(failed(403, { error: 'external_targets_disabled', details: 'off', external_targets: EXTERNAL.slice(0, 1) }));
  await openWithTargets('93.184.216.34');
  await start();
  await vi.waitFor(() => expect(host.textContent).toContain('Your platform operator has turned off scanning targets outside your registered networks'));
  expect(button('Scan anyway')).toBeUndefined();
});

it('shows an unclassified failure in the footer', async () => {
  mocks.create.mockResolvedValueOnce(failed(409, { error: 'validation_error', details: 'sensor offline: nothing was scanned' }));
  await openWithTargets('10.0.0.5');
  await start();
  await vi.waitFor(() => expect(host.querySelector('[data-testid="note"]')?.textContent).toBe('sensor offline: nothing was scanned'));
});

it('shows the loading state while the request is in flight, then that it started', async () => {
  let resolve: (v: unknown) => void = () => {};
  mocks.create.mockReturnValueOnce(new Promise((r) => { resolve = r; }));
  await openWithTargets('10.0.0.5');
  await start();
  await vi.waitFor(() => expect(button('Starting…')?.disabled).toBe(true));
  await act(async () => { resolve(created); });
  await vi.waitFor(() => expect(host.textContent).toContain('Started — track it in Discovery Jobs'));
  expect(sentBody(0)).not.toHaveProperty('external_targets_confirmed');
});
